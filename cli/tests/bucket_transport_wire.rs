// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
//! Wire-level integration tests for the bucket transport.
//!
//! **Why this file exists.** #309 shipped a hand-rolled HTTP/TLS transport for the
//! byte path with a fully green gate — 90 suites, clippy clean, 271 web tests — and
//! two blocking defects walked straight through it, because *nothing drove the
//! transport against a server*. Every existing test exercised its pure helpers
//! (`parse_url`, `response_ceiling`, constant invariants) and none of them opened a
//! socket. A green gate is evidence only about the cases someone thought to write.
//!
//! These tests drive `bucket_transport::{put, get_range}` against real listeners on
//! loopback. Each one was written to **fail against the pre-fix code first** — a
//! test that cannot fail is theater (S126) — and the failure mode each reproduces is
//! recorded in its own doc comment.
//!
//! Hermetic by construction: ephemeral ports, no credentials, no external service,
//! so this runs in CI exactly as it runs locally. The MinIO round-trip that proves a
//! real SigV4 signature is accepted lives separately; this file pins the *wire
//! properties* those signatures depend on.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::Duration;

use signet_cli::bucket_transport::{self, TransportBounds};

/// Read a full HTTP request head (through CRLFCRLF) from an accepted socket.
fn read_head(sock: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match sock.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).to_string()
}

/// Run `f` on a worker thread and require it to finish within `budget`.
///
/// The pre-fix B1 failure mode is an unbounded hang, so the test cannot simply call
/// the transport on the test thread — it would wedge the whole suite for ~24 h. This
/// converts "hangs" into a clean, reportable failure.
fn within<T: Send + 'static>(
    budget: Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(budget).ok()
}

// ---------------------------------------------------------------------------
// B2 — the Host header must carry the port that SigV4 signed.
// ---------------------------------------------------------------------------

/// **Reproduces B2.** SigV4 presigning signs the `host` header *including* a
/// non-default port. The pre-fix transport emitted `Host: {host}` from a `Target`
/// whose `host` field had the port stripped by `parse_url`, so every request to a
/// non-443 endpoint — local MinIO on :9000, CI, any self-hosted S3-compatible store
/// — was signed for `host:port` and sent as `host`, yielding `SignatureDoesNotMatch`.
///
/// Pre-fix this asserts `Host: 127.0.0.1:PORT` against an actual `Host: 127.0.0.1`.
#[test]
fn host_header_carries_the_port_for_a_non_default_authority() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let head = read_head(&mut sock);
            let _ = sock.write_all(b"HTTP/1.1 200 OK\r\nETag: \"e\"\r\nContent-Length: 0\r\n\r\n");
            let _ = tx.send(head);
        }
    });

    let url = format!("http://127.0.0.1:{port}/bucket/key?X-Amz-Signature=deadbeef");
    let _ = bucket_transport::put(&url, b"hello", &TransportBounds::default(), None);

    let head = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("server should have received a request");

    let host_line = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("host:"))
        .expect("request must carry a Host header")
        .trim()
        .to_string();

    assert_eq!(
        host_line,
        format!("Host: 127.0.0.1:{port}"),
        "the Host header must carry the non-default port, because SigV4 signed the \
         authority WITH its port — sending it without is SignatureDoesNotMatch on \
         every non-default-port endpoint. Got: {host_line:?}"
    );
}

// The complementary *textual* authority properties — that a scheme-default port is
// omitted (SigV4 omits it from the canonical request, so appending it breaks the
// signature in the other direction) and that an IPv6 literal reaches the wire
// bracketed — are pinned as unit tests inside `bucket_transport`, because binding
// :80 needs privileges and the property under test is textual, not wire-level.

// ---------------------------------------------------------------------------
// B1 — the TLS handshake must run under the handshake bound, not the disarmed one.
// ---------------------------------------------------------------------------

/// **Reproduces B1.** rustls `StreamOwned` handshakes lazily on first I/O:
/// `ClientConnection::new` performs none. `Connection::open` armed
/// `HANDSHAKE_TIMEOUT` (15 s), but `request()` overwrote the read timeout with
/// `READ_DISARMED` (86,400 s) *before* the first write — so the ServerHello read
/// actually executed under the disarmed timer.
///
/// A peer that completes the TCP handshake and then goes silent (SYN-proxy
/// middleboxes; a bug047-class death at handshake time) therefore hung the attempt
/// for up to 24 h. Nothing rescued it: `write_gap` bounds `write()` syscalls while
/// the block is inside a `read()`, and the governor supplies no ceiling for the
/// first part of a fresh upload (`rate_est` is `None`).
///
/// Pre-fix this fails by timeout; post-fix the attempt errors in ~15 s.
#[test]
fn a_peer_that_accepts_tcp_but_never_speaks_tls_fails_within_the_handshake_bound() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();

    // Accept and hold the connection open, silently, for the life of the test.
    std::thread::spawn(move || {
        if let Ok((sock, _)) = listener.accept() {
            std::thread::sleep(Duration::from_secs(120));
            drop(sock);
        }
    });

    let url = format!("https://127.0.0.1:{port}/bucket/key");
    let bounds = TransportBounds::default();

    let outcome = within(Duration::from_secs(45), move || {
        bucket_transport::put(&url, b"payload", &bounds, None).is_err()
    });

    match outcome {
        None => panic!(
            "the attempt did not conclude within 45 s against a peer that accepts TCP \
             and never speaks TLS. The TLS handshake must run while the handshake \
             bound is armed; if reads are disarmed first, this hangs for ~24 h with no \
             governor ceiling on a first part."
        ),
        Some(errored) => assert!(
            errored,
            "a peer that never completes the TLS handshake must produce an error"
        ),
    }
}

// ---------------------------------------------------------------------------
// F2 / F3 — treated as blockers per the standing rule (every found bug is
// launch-gating unless Chris and I agree otherwise).
// ---------------------------------------------------------------------------

/// **Reproduces F2.** A trickling diagnostic body must be bounded in total time.
///
/// The diagnostic read loop tolerates a missing `Content-Length` by design, so it is
/// bounded by neither a declared length nor — before this fix — a deadline. Each read
/// only has to deliver *some* byte inside the 12 s gap to keep it alive, so one byte
/// every ~11 s streams the 64 KiB cap over roughly eight days. It was the one loop in
/// the file bounded by nothing at all.
///
/// The backstop floor is lowered here rather than waiting out the 300 s production
/// value: the property under test is that a total-time bound *exists and fires*, not
/// its magnitude (that is pinned by `response_backstop_is_derived_…`). An earlier
/// attempt at this test used the production floor and passed against unfixed code —
/// it was terminating in the header phase, never reaching the loop — so the
/// server here answers immediately and dribbles only afterwards.
#[test]
fn a_trickling_diagnostic_body_is_bounded_in_total_time() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();

    std::thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let _ = read_head(&mut sock);
            // Answer AT ONCE so the client reaches the diagnostic body loop, then
            // dribble forever, always inside the gap.
            let _ = sock.write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
            let _ = sock.flush();
            loop {
                if sock.write_all(b".").is_err() || sock.flush().is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(400));
            }
        }
    });

    let bounds = TransportBounds {
        response_backstop_floor: Duration::from_secs(3),
        ..TransportBounds::default()
    };
    let url = format!("http://127.0.0.1:{port}/bucket/key");

    let started = std::time::Instant::now();
    let outcome = within(Duration::from_secs(60), move || {
        bucket_transport::put(&url, b"x", &bounds, None).map(|t| t.status)
    });

    let status = outcome.expect(
        "a trickling diagnostic body must be bounded by the per-attempt deadline — \
         without it, one byte per gap-interval holds the connection for days on the \
         one loop bounded by neither a declared length nor a deadline",
    );
    assert_eq!(
        status.ok(),
        Some(403),
        "the status must still be delivered once the backstop cuts the trickle"
    );
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "the backstop must actually fire, not merely exist: took {:?}",
        started.elapsed()
    );
}

/// **Reproduces F3.** A redirect on a download must be reported as a redirect.
///
/// `read_response` runs before `request()`'s redirect guard, so routing a 3xx into
/// the *data* branch made its hard `Content-Length` requirement fire first: a
/// redirected GET surfaced as "no Content-Length / failed transfer" and the accurate
/// "pre-signed requests are never redirected" message was unreachable on the download
/// path. That is the same attribution inversion the body-framing split exists to kill,
/// and it quietly weakened the module's documented "redirects fail loudly" posture.
#[test]
fn a_redirect_on_a_download_is_reported_as_a_redirect_not_a_framing_complaint() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();

    std::thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let _ = read_head(&mut sock);
            // A 302 with no Content-Length — the shape a proxy or misrouted bucket
            // endpoint produces.
            let _ = sock
                .write_all(b"HTTP/1.1 302 Found\r\nLocation: https://elsewhere.example/x\r\n\r\n");
            let _ = sock.flush();
        }
    });

    let url = format!("http://127.0.0.1:{port}/bucket/key");
    let res = bucket_transport::get_range(&url, 0, 1023, &TransportBounds::default(), None);

    let msg = match res {
        Ok(t) => panic!("a 3xx must not be a success; got status {}", t.status),
        Err(e) => e.to_string().to_ascii_lowercase(),
    };
    assert!(
        msg.contains("redirect"),
        "a redirected download must say so — reporting a Content-Length framing \
         complaint instead misattributes a routing problem to the store's framing, \
         and makes the 'redirects fail loudly' posture untrue for GET. Got: {msg:?}"
    );
}

// ---------------------------------------------------------------------------
// Response-body honesty (Gus non-blocker 2, promoted into this round).
// ---------------------------------------------------------------------------

/// A store that closes mid-body must be reported as exactly that. Pre-fix the read
/// loop did `if n == 0 { break }` and returned a silently short body, which surfaced
/// downstream as "decryption failed" — an S2-class diagnosability inversion that
/// blames our crypto for the network's behaviour.
#[test]
fn a_body_truncated_by_an_early_close_is_reported_not_silently_short() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();

    std::thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let _ = read_head(&mut sock);
            let _ = sock.write_all(b"HTTP/1.1 206 Partial Content\r\nContent-Length: 4096\r\n\r\n");
            let _ = sock.write_all(&[0u8; 64]); // 64 of a promised 4096, then close
            let _ = sock.flush();
        }
    });

    let url = format!("http://127.0.0.1:{port}/bucket/key");
    let res = bucket_transport::get_range(&url, 0, 4095, &TransportBounds::default(), None);

    let msg = match res {
        Ok(t) => panic!(
            "a body cut short by an early close must be an error, not a short success \
             — a silent short body reaches the caller as a decryption failure. Got {} \
             of a promised 4096 bytes, reported as success.",
            t.body.len()
        ),
        Err(e) => e.to_string().to_ascii_lowercase(),
    };
    assert!(
        msg.contains("mid-body") || (msg.contains("closed") && msg.contains("4096")),
        "the error must name the truncation and its shape (got X of Y), so the \
         failure is attributed to storage rather than to decryption. Got: {msg:?}"
    );
}

/// An **error** response must keep its status even when its diagnostic body carries
/// no `Content-Length`.
///
/// This pins a flaw found in the *first version of the fix above*, not in the
/// original code: requiring Content-Length uniformly would have turned a
/// `403 SignatureDoesNotMatch` whose body lacked the header into a framing complaint,
/// discarding the status — the single most useful fact in the response, and precisely
/// the diagnosability S2 exists to protect. Data bodies and error bodies have
/// opposite failure semantics; the transport must treat them so.
#[test]
fn an_error_response_keeps_its_status_even_without_content_length() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();

    std::thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let _ = read_head(&mut sock);
            // A proxy-shaped 403: no Content-Length, body then close.
            let _ = sock.write_all(
                b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n\
                  <Error><Code>SignatureDoesNotMatch</Code></Error>",
            );
            let _ = sock.flush();
        }
    });

    let url = format!("http://127.0.0.1:{port}/bucket/key");
    let t = bucket_transport::put(&url, b"x", &TransportBounds::default(), None).expect(
        "an error response is a transport success carrying a status, not a transport error",
    );

    assert_eq!(
        t.status, 403,
        "the status must survive a length-less error body — reporting a framing \
         problem instead of HTTP 403 destroys the diagnosis"
    );
    assert!(
        String::from_utf8_lossy(&t.body).contains("SignatureDoesNotMatch"),
        "the diagnostic body should be read best-effort so the caller can surface it"
    );
}

/// A **data** body response with no `Content-Length` must not be silently reduced to
/// an empty body. Pre-fix, `content_length.unwrap_or(0)` set `target = 0`, the read
/// loop never ran, and `truncate(target)` discarded whatever had already arrived —
/// producing an empty success that reached the caller as a decryption failure.
#[test]
fn a_body_response_without_content_length_is_not_silently_empty() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();

    std::thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            let _ = read_head(&mut sock);
            let _ = sock.write_all(b"HTTP/1.1 206 Partial Content\r\n\r\nPAYLOAD-BYTES");
            let _ = sock.flush();
        }
    });

    let url = format!("http://127.0.0.1:{port}/bucket/key");
    let res = bucket_transport::get_range(&url, 0, 12, &TransportBounds::default(), None);

    match res {
        Err(e) => {
            let msg = e.to_string().to_ascii_lowercase();
            assert!(
                msg.contains("content-length") || msg.contains("length"),
                "rejecting a length-less body response is acceptable, but the reason \
                 must say so. Got: {msg:?}"
            );
        }
        Ok(t) => assert!(
            !t.body.is_empty(),
            "a response carrying bytes but no Content-Length must not be silently \
             emptied — that reaches the caller as a decryption failure"
        ),
    }
}

// ---------------------------------------------------------------------------
// 1c (S175) — the download pool: reuse, evict-on-failure, and the idle race.
// Gus's condition (ii): an injected failure must put the NEXT attempt on a NEW
// connection — pinned here by counting the server's accepts.
// ---------------------------------------------------------------------------

/// A tiny keep-alive-capable server: counts accepts, serves `responses_per_conn`
/// clean 206 responses on each accepted connection, then closes it.
fn pooled_test_server(
    listener: TcpListener,
    responses_per_conn: usize,
    body: &'static [u8],
) -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
    let accepts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = accepts.clone();
    std::thread::spawn(move || {
        for sock in listener.incoming() {
            let Ok(mut sock) = sock else { break };
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            for _ in 0..responses_per_conn {
                let head = read_head(&mut sock);
                if head.is_empty() {
                    break;
                }
                let response = format!(
                    "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                if sock.write_all(response.as_bytes()).is_err() || sock.write_all(body).is_err() {
                    break;
                }
            }
            // Connection closes here (socket drops) — the idle-race tests rely
            // on exactly this.
        }
    });
    accepts
}

#[test]
fn pooled_downloads_reuse_one_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let accepts = pooled_test_server(listener, 8, b"hello");

    let url = format!("http://127.0.0.1:{port}/bucket/key");
    let pool = bucket_transport::DownloadPool::new();
    for _ in 0..3 {
        let t = bucket_transport::get_range_pooled(
            &pool,
            &url,
            0,
            4,
            &TransportBounds::default(),
            None,
        )
        .expect("pooled GET must succeed");
        assert_eq!(t.status, 206);
        assert_eq!(t.body, b"hello");
    }
    assert_eq!(
        accepts.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "three pooled GETs must ride ONE connection — a second accept means the \
         pool returned nothing and 1c is not actually reusing"
    );
}

#[test]
fn a_failed_pooled_download_evicts_and_the_next_attempt_opens_fresh() {
    // Server: first connection answers with a SHORT body (declares 10 bytes,
    // sends 3, closes) — the mid-body close error. Later connections are clean.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let accepts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = accepts.clone();
    std::thread::spawn(move || {
        let mut first = true;
        for sock in listener.incoming() {
            let Ok(mut sock) = sock else { break };
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            loop {
                let head = read_head(&mut sock);
                if head.is_empty() {
                    break;
                }
                if first {
                    first = false;
                    let _ = sock.write_all(
                        b"HTTP/1.1 206 Partial Content\r\nContent-Length: 10\r\n\r\nabc",
                    );
                    break; // close mid-body
                }
                let _ = sock
                    .write_all(b"HTTP/1.1 206 Partial Content\r\nContent-Length: 5\r\n\r\nhello");
            }
        }
    });

    let url = format!("http://127.0.0.1:{port}/bucket/key");
    let pool = bucket_transport::DownloadPool::new();
    let first =
        bucket_transport::get_range_pooled(&pool, &url, 0, 9, &TransportBounds::default(), None);
    assert!(
        first.is_err(),
        "a mid-body close must surface as an error, never a short body"
    );
    // The sick connection must have been EVICTED, so this succeeds on a fresh
    // one rather than reading garbage from a half-dead socket.
    let second =
        bucket_transport::get_range_pooled(&pool, &url, 0, 4, &TransportBounds::default(), None)
            .expect("the retry must succeed on a fresh connection");
    assert_eq!(second.body, b"hello");
    assert!(
        accepts.load(std::sync::atomic::Ordering::SeqCst) >= 2,
        "the failed connection must NOT be reused — the second GET must arrive \
         on a NEW connection (Gus condition ii: stall-evicts-pool)"
    );
}

#[test]
fn a_server_closed_idle_connection_costs_a_reopen_never_an_error() {
    // The keep-alive race: the server serves ONE response per connection and
    // closes. The second pooled GET takes the (now dead) idle connection, must
    // detect the corpse, and transparently retry on a fresh one — the caller
    // sees two clean successes and never an error.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let accepts = pooled_test_server(listener, 1, b"hello");

    let url = format!("http://127.0.0.1:{port}/bucket/key");
    let pool = bucket_transport::DownloadPool::new();
    for _ in 0..2 {
        let t = bucket_transport::get_range_pooled(
            &pool,
            &url,
            0,
            4,
            &TransportBounds::default(),
            None,
        )
        .expect("a dead idle connection must cost a reopen, never an error");
        assert_eq!(t.body, b"hello");
    }
    assert_eq!(
        accepts.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "each single-response connection closes after serving, so the second GET \
         must have transparently reopened"
    );
}

// ---------------------------------------------------------------------------
// S185 — bug211 §7-3's CLI twin: an expired pre-signed URL must be
// DISTINGUISHABLE from a network fault, and must not burn retries.
// ---------------------------------------------------------------------------

/// A minimal loop-accept server that answers every request with `status` and
/// counts accepts — the accept count is the retry oracle (the same pinning idiom
/// as the pool tests above: count what the server SAW, never what the client
/// claims).
fn counting_status_server(
    status: &'static str,
    body: &'static str,
) -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let accepts = std::sync::Arc::new(AtomicUsize::new(0));
    let counter = accepts.clone();
    std::thread::spawn(move || {
        while let Ok((mut sock, _)) = listener.accept() {
            counter.fetch_add(1, Ordering::SeqCst);
            let _ = read_head(&mut sock);
            let resp = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes());
            let _ = sock.flush();
        }
    });
    (port, accepts)
}

/// **Reproduces the S185 defect at the classification layer.** Pre-fix, a 403
/// from storage (the expired-URL signature) came back as plain `network_error` —
/// byte-for-byte the same classification as a dead wifi — so the download loop
/// had no way to know a fresh URL would fix it, and `http.rs`'s own doc comment
/// stated that conflation as policy. Reverting the classification turns this
/// test red (must-fail proven at build time); the sibling 404 case below is the
/// negative control pinning that ONLY 403 moved.
#[test]
fn an_expired_presigned_url_403_is_classified_for_refresh_not_as_network() {
    let (port, accepts) = counting_status_server(
        "403 Forbidden",
        "<Error><Code>AccessDenied</Code><Message>Request has expired</Message></Error>",
    );
    let url = format!("http://127.0.0.1:{port}/bucket/key?X-Amz-Expires=3600");

    let err = within(Duration::from_secs(30), move || {
        signet_cli::http::get_presigned_range(&url, 0, 12)
    })
    .expect("must not hang")
    .expect_err("a 403 must be an error");

    assert_eq!(
        err.code, "presigned_rejected",
        "an expired-URL 403 must carry its own machine code — as `network_error` \
         the download loop cannot know a fresh URL would fix it, which is the \
         defect that shipped"
    );
    assert_eq!(
        accepts.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "a rejected signature must not burn the retry budget: re-sending the \
         identical dead signature cannot succeed (the web half measured ten \
         retries on one signature). The remedy is a fresh URL, one layer up."
    );
}

/// Negative control: a 404 (object genuinely absent) must KEEP the old
/// classification. Without this arm, the 403 test would pass equally well under
/// an over-broad rewrite that reroutes every 4xx into the refresh path — and a
/// refresh loop on a deleted object is an unbounded retry against a permanent
/// refusal.
#[test]
fn a_presigned_404_keeps_the_network_classification() {
    let (port, accepts) =
        counting_status_server("404 Not Found", "<Error><Code>NoSuchKey</Code></Error>");
    let url = format!("http://127.0.0.1:{port}/bucket/key");

    let err = within(Duration::from_secs(30), move || {
        signet_cli::http::get_presigned_range(&url, 0, 12)
    })
    .expect("must not hang")
    .expect_err("a 404 must be an error");

    assert_eq!(err.code, "network_error", "only 403 earns the refresh path");
    assert_eq!(accepts.load(std::sync::atomic::Ordering::SeqCst), 1);
}
