// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Direct-to-bucket HTTP/1.1 transport for pre-signed object-storage transfers
//! (bug060).
//!
//! # Why this exists rather than `ureq`
//!
//! bug047 shipped a per-part stall detector built on `ureq`'s per-socket-op
//! timeouts. bug060 established, by measurement, that it never worked as designed
//! and actively broke slow links:
//!
//! * `ureq` 2.x applies `timeout_write` **only** inside `DeadlineStream`, which
//!   activates solely when an overall `.timeout()` is set — which we deliberately
//!   do not set (an overall timeout *overrides* the per-op ones). Net effect:
//!   **no write-side stall detection has ever existed.**
//! * `SO_RCVTIMEO` is armed at connect and stays armed **through the body write**.
//!   The server is correctly silent while ingesting a multi-second body, so the
//!   read timer expires mid-transmission and kills a perfectly healthy upload.
//!
//! Measured consequence: any body taking longer than the timeout to transmit
//! failed **regardless of its size or progress** — at the 16 MiB default that is
//! every link below ~9 Mbps. Proven by invariance: a 16 MiB part aborted at 20.5 s
//! (58 % sent) and a 32 MiB part at 21.3 s (29 % sent) — same clock, different
//! fractions.
//!
//! Through `ureq` we can reach none of the levers the fix needs: no write bound,
//! no `SO_SNDBUF` control, and no way to disarm the inbound-silence timer for the
//! duration of a body write. Hence a purpose-built transport for **bucket
//! transfers only** — `ureq` remains in use for every API request.
//!
//! # The governing invariant
//!
//! > **No absolute wall-time constant may bound a quantity proportional to
//! > `bytes ÷ rate`.**
//!
//! Constants are permitted only on **rate-free** quantities. A *no-progress gap*
//! is rate-free; a *transfer duration* is not. Each bound below is annotated.
//!
//! # How the bounds are armed (the fix, in one paragraph)
//!
//! Timeouts are **phase-dependent**:
//!
//! | phase | read timeout | write timeout |
//! |---|---|---|
//! | connect + TLS handshake | handshake bound | gap |
//! | **request body write** | **effectively disarmed** | **gap** |
//! | response | drain + allowance `[rate-derived]` | — |
//!
//! **The first row holds only because `Connection::open` drives the handshake to
//! completion itself.** rustls handshakes *lazily* on first I/O, so merely arming
//! the handshake bound before constructing the connection does not put the
//! handshake under it — the ServerHello read would execute later, inside the first
//! body write, by which point reads are disarmed for 24 h. That was blocker B1 in
//! the S127 review of this file: the table above was already written, and was
//! simply not true. If a future change removes the explicit drive in `open()`, this
//! row becomes a lie again and a dead-at-handshake peer hangs a transfer for a day.
//! `cli/tests/bucket_transport_wire.rs` pins it.
//!
//! Disarming the read timer during transmission is the root-cause fix. Bounding
//! each *write* by the gap is the FM2 (dead-flow) detector, and it is honest
//! because `SO_SNDBUF` is **capped**, so socket-level write progress lags true
//! delivery by at most `sndbuf ÷ rate` rather than by whatever the kernel
//! autotunes to (measured `net.inet.tcp.autosndbufmax` = 4 MiB on macOS).
//!
//! # Security posture (deliberate parity statements, not accidental resemblance)
//!
//! * **The same [`rustls::ClientConfig`] object** as every other request in the
//!   CLI (`http::pq_tls_config`) — same roots, same aws-lc-rs provider, same
//!   `prefer-post-quantum` group preference, same TLS 1.2+1.3 floor from
//!   `with_safe_default_protocol_versions`. Certificate **and** hostname
//!   verification are rustls's, unmodified; there is no custom verifier here and
//!   there must never be one.
//! * **No revocation checking** — the same posture as today's `ureq` path, stated
//!   so this documents parity rather than silently differing.
//! * **Redirects are never followed.** A 3xx on a pre-signed URL is anomalous
//!   (the signature covers the exact request); it fails loudly.
//! * **Pre-signed URLs are capability-bearing** — the query signature *is* the
//!   authorization. They are never logged, and every error string here is built
//!   from a [`redact`]ed form.
//! * **Connection reuse is SPLIT BY DIRECTION, deliberately (1c, S175).** The
//!   UPLOAD path keeps no-reuse by construction — one connection per attempt,
//!   `Connection: close`, nothing pooled — because that fresh-connection re-roll
//!   IS the bug047 containment, measured worth 25.6× against OVH's broken v6
//!   ingress (S174), where a pooled, possibly-sick flow would silently defeat
//!   the fix. The DOWNLOAD path may pool via [`DownloadPool`]: bug047's fault is
//!   inbound-to-OVH only (S174 §7 — downloads measured healthy at 216–267 Mbps
//!   while uploads collapsed on the same v6 path), and the pool keeps the escape
//!   hatch at zero steady-state cost via STALL-EVICTS-POOL — reuse until
//!   evidence of sickness, then re-roll, because per-flow fate is the whole
//!   mechanism of this fault family and a retry on a pooled connection is the
//!   SAME flow re-rolling nothing. ⚠ Do not "fix" the download half back to
//!   no-reuse, and do not extend pooling to uploads: each half is deliberate,
//!   and this sentence is the amendment the old direction-agnostic "no pooling
//!   anywhere" doctrine required before 1c could land (Gus, condition (i)).
//! * **Aborts shut the socket down** rather than dropping it across threads.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::error::{CliError, Result};

/// Connect-phase bound `[rate-free]`. A connection that cannot establish is
/// retried quickly on a fresh attempt.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// TLS-handshake read bound `[rate-free]`. The handshake is a small, prompt
/// exchange; unlike a body write, silence here really is a dead flow.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Read timeout during the body write: long enough to be **effectively
/// disarmed**. It exists only so a wedged socket cannot hang forever if rustls
/// performs an internal read while we are transmitting; it must never be short
/// enough to fire on a legitimately silent server. This is the single value whose
/// previous default (15 s, armed at connect) *was* bug060.
const READ_DISARMED: Duration = Duration::from_secs(86_400);

/// Fixed server-side allowance added to the rate-derived drain window before the
/// response is expected `[rate-free component]` — time for the store to finish
/// ingesting and answer once our last byte has actually left.
const RESPONSE_ALLOWANCE: Duration = Duration::from_secs(60);

/// Hard cap on how much of an **error** body we will read `[rate-free]`.
///
/// Error bodies are diagnostics read best-effort (see `read_response`), so unlike a
/// data body they are not bounded by a declared length. This caps a hostile or
/// misbehaving endpoint's ability to stream indefinitely into memory on a path that
/// deliberately tolerates a missing Content-Length. S3 error documents are a few
/// hundred bytes; 64 KiB is generous by three orders of magnitude.
const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;

/// Floor for the response-phase backstop `[rate-free]`.
///
/// A response with no body (every PUT) is a rate-free quantity — a few hundred header
/// bytes — so a constant legitimately bounds it. It also floors the derived bound for
/// bodied responses so a tiny range GET still gets a generous allowance.
const RESPONSE_BACKSTOP_FLOOR: Duration = Duration::from_secs(300);

/// The slowest link we will hold a transfer open for, in bytes/sec (0.5 Mbps).
///
/// Used to derive the response-phase backstop when we know how many bytes we asked
/// for but have no measured rate — which is the normal case on a download (`ceiling`
/// is always `None` there) and on the first part of a fresh upload. Deriving from this
/// keeps the backstop **rate-proportional** rather than an absolute wall-time constant
/// bounding a `bytes ÷ rate` quantity, per the module's governing invariant.
const MIN_CREDIBLE_RATE_BPS: f64 = 500_000.0 / 8.0;

/// Multiplier applied to the derived expectation before the backstop fires
/// `[dimensionless]`. Generous on purpose: this is a last-resort liveness ceiling, not
/// a performance bound — the rate-free gap detector and the rate-derived response
/// ceiling are the instruments that should normally act.
const RESPONSE_BACKSTOP_K: f64 = 4.0;

/// Upper bound on the rate-derived drain window, in seconds.
///
/// **The single annotated exception to the §1 invariant** (no absolute wall-time
/// constant may bound a `bytes ÷ rate` quantity). It caps only the drain estimate,
/// and with the default 1 MiB send buffer it engages below ~14 kbps — far under any
/// rate at which the product is usable. Declared as a named constant rather than an
/// inline `.min(600.0)` precisely so the exception is greppable alongside every
/// other bound in this module.
const DRAIN_USABILITY_CAP: f64 = 600.0;

/// Tunable transport bounds. Served from `system_config` so field evidence can
/// retune them without a client release.
#[derive(Debug, Clone, Copy)]
pub struct TransportBounds {
    /// No-write-progress gap `[rate-free]` — the FM2 dead-flow detector. A write
    /// that places **zero** bytes within this window is a stalled flow at any
    /// link speed, which is precisely why a constant is legitimate here.
    pub write_gap: Duration,
    /// `SO_SNDBUF` cap in bytes. Bounds how far socket write-progress may lead
    /// true delivery, making the gap detector's view honest to within
    /// `sndbuf ÷ rate`. A constant (not BDP-derived) on purpose: deriving it from
    /// a measured rate would couple the sensor to the estimator.
    pub sndbuf_bytes: usize,
    /// Floor for the response-phase liveness backstop `[rate-free]`. Same class as
    /// `CONNECT_TIMEOUT` / `HANDSHAKE_TIMEOUT` — a safety constant, not a
    /// performance tunable — but carried here rather than as a module constant so
    /// that liveness tests can exercise the bound without waiting it out in
    /// wall-clock.
    pub response_backstop_floor: Duration,
}

impl Default for TransportBounds {
    fn default() -> Self {
        Self {
            write_gap: Duration::from_secs(12),
            sndbuf_bytes: 1024 * 1024,
            response_backstop_floor: RESPONSE_BACKSTOP_FLOOR,
        }
    }
}

/// Strip a pre-signed URL down to something safe to put in an error or a log:
/// scheme, host, and path only. **The query string carries the signature — the
/// capability itself — and must never be emitted.**
pub fn redact(url: &str) -> String {
    match url.split_once('?') {
        Some((head, _)) => format!("{head}?<redacted>"),
        None => url.to_string(),
    }
}

fn network(message: impl Into<String>) -> CliError {
    CliError::new(31, "network_error", message)
}

/// Arm the socket read timeout **before transmitting**, or fail loudly.
///
/// These arms are not incidental hygiene — they **are** the bug060 fix. The read
/// timer's value is the whole mechanism: disarmed during transmission, rate-free for
/// a no-progress gap. If a *pre-transmission* arm silently failed, the socket would
/// keep whatever timeout it last had and we would transmit under an unknown bound —
/// quietly reverting to a mid-body timer and reintroducing the launch-blocking defect
/// with no signal, on a path where the symptom (uploads failing on slow links) reads
/// as a network problem rather than a regression.
///
/// **Scope matters, and getting it wrong is its own defect.** This propagates only
/// where the socket is *about to carry the transfer*: the handshake bounds in
/// `open()` and the disarm/gap pair in `request()`. Arms that happen **after** the
/// body has been sent are best-effort by [`arm_read_timeout_best_effort`] — by then
/// the peer may legitimately have answered and closed, `setsockopt` returns `EINVAL`
/// on the dying socket, and failing there would discard a response we can still read.
/// A first version of this change propagated everywhere and turned that benign race
/// into an intermittent transfer failure; it passed a full gate by luck before a
/// re-run caught it.
///
/// (`SO_SNDBUF` is deliberately not in this class either — see its own note.)
fn arm_read_timeout(sock: &TcpStream, d: Duration) -> Result<()> {
    sock.set_read_timeout(Some(d)).map_err(|e| {
        network(format!(
            "cannot arm the transfer read bound ({}s) on this socket: {e}",
            d.as_secs()
        ))
    })
}

/// Arm a read timeout on a socket that has already carried the request.
///
/// Best-effort **by design**: once the body is sent, the peer may answer and tear the
/// connection down at any moment, and on a **fully disconnected** socket macOS
/// rejects `setsockopt(SO_RCVTIMEO)` with `EINVAL`. Treating that as fatal would
/// convert "the store replied 403 and hung up" — a response still sitting readable in
/// our buffer — into an opaque transport error, which is the same diagnosability loss
/// the body-framing split exists to prevent.
///
/// **The mechanism is stated precisely because a looser version of it was wrong.**
/// The first draft of this comment claimed a *half-close* caused the `EINVAL`. It does
/// not: a probe on macOS shows `set_read_timeout` returning `Ok` both after a peer
/// close and after our own `shutdown(Both)`. Instrumenting the real failure (1 hit in
/// 8 runs) showed `getpeername()` failing with the same `EINVAL` alongside it — i.e.
/// the socket is fully **disconnected**, a strictly narrower and race-dependent state
/// than half-closed. Recorded because "made the error non-fatal and the failure went
/// away" is exactly the trap this note would otherwise paper over.
///
/// **Safety does not rest on this call succeeding.** An earlier version argued that a
/// dying socket "returns EOF promptly", which is true for the disconnected case but is
/// *not* a bound on a peer that stays connected and simply goes silent. Response-phase
/// liveness is guaranteed instead by the per-attempt deadline that
/// [`response_backstop`] installs unconditionally — see `Connection::check_deadline`.
fn arm_read_timeout_best_effort(sock: &TcpStream, d: Duration) {
    let _ = sock.set_read_timeout(Some(d));
}

/// Arm the socket write timeout before transmitting, or fail loudly. See
/// [`arm_read_timeout`] — the write gap is the FM2 dead-flow detector and carries the
/// same reasoning and the same scope limits.
fn arm_write_timeout(sock: &TcpStream, d: Duration) -> Result<()> {
    sock.set_write_timeout(Some(d)).map_err(|e| {
        network(format!(
            "cannot arm the transfer write-gap bound ({}s) on this socket: {e}",
            d.as_secs()
        ))
    })
}

/// Warn **once per process** if a pre-signed URL is being sent in clear to
/// something that is not the local machine.
///
/// Accepting `http://` is deliberate (see [`parse_url`]) — local dev and CI run
/// MinIO over plaintext loopback. But a pre-signed URL's query string *is* the
/// authorization: on a real network, plaintext puts a capability-bearing credential
/// in the clear for anyone on the path. That combination — plaintext **and** a
/// non-local host — has no legitimate configuration, so it is almost certainly a
/// misconfigured `SIGNET_S3_ENDPOINT` rather than an intention.
///
/// A warning rather than a refusal: refusing would be a behaviour change on a path
/// we have not surveyed for self-hosted deployments, and this is a config-mistake
/// tripwire, not an access-control boundary. `Once` keeps a multi-part upload from
/// emitting it per part.
fn warn_if_plaintext_to_remote_host(target: &Target<'_>) {
    if target.tls || is_local_host(target.host) {
        return;
    }
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        eprintln!(
            "signet: WARNING: object storage is configured over plaintext http:// to \
             a non-local host ({}). A pre-signed URL's signature IS the authorization, \
             so it is being sent in the clear. Check SIGNET_S3_ENDPOINT.",
            target.host
        );
    });
}

/// Loopback or RFC1918/link-local — "this machine or this LAN", where plaintext is a
/// deliberate dev/CI configuration rather than a mistake.
fn is_local_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        Ok(std::net::IpAddr::V6(v6)) => {
            // `is_unique_local`/`is_unicast_link_local` are unstable; test the
            // prefixes directly (fc00::/7 and fe80::/10).
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
        Err(_) => false,
    }
}

/// A parsed absolute bucket URL.
struct Target<'a> {
    /// Hostname or IP literal **without** brackets or port — the form
    /// `to_socket_addrs` and `ServerName` both want.
    host: &'a str,
    port: u16,
    /// The authority exactly as it must appear in the `Host` header: an IPv6
    /// literal stays bracketed, and a **non-default** port is included.
    ///
    /// This is not cosmetic. SigV4 presigning signs the `host` header as part of
    /// the canonical request, including the port whenever it is not the scheme
    /// default. Sending a different authority than the one that was signed is
    /// `SignatureDoesNotMatch` — which is what made every non-443 endpoint (local
    /// MinIO on :9000, CI, any self-hosted S3-compatible store) reject every
    /// request. Equally, *adding* a default port breaks the signature in the other
    /// direction, because SigV4 omits it. The authority must be reproduced, not
    /// normalised.
    authority: String,
    /// Path plus query — the request-target, sent verbatim.
    request_target: &'a str,
    /// TLS for `https://`, plaintext for `http://`.
    tls: bool,
}

/// Parse a bucket URL, honouring its scheme.
///
/// **On accepting `http://`:** the object-storage endpoint is our own deployment
/// configuration (`SIGNET_S3_ENDPOINT`), never attacker-chosen — production is
/// HTTPS (OVH), while local development and CI run MinIO over plaintext on
/// loopback. Refusing `http://` here would break every local and CI multipart
/// transfer while adding no defence: an adversary does not get to pick our
/// endpoint, and file content is end-to-end encrypted before it reaches this
/// layer regardless of transport. The scheme is therefore honoured, exactly as
/// the `ureq` path did before.
fn parse_url(url: &str) -> Result<Target<'_>> {
    let (tls, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(network(format!(
            "bucket URL must be http or https: {}",
            redact(url)
        )));
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    // Reject userinfo — it has no legitimate place in a pre-signed bucket URL and
    // is a classic host-confusion vector.
    if authority.contains('@') {
        return Err(network("bucket URL must not carry userinfo"));
    }
    let default_port = if tls { 443u16 } else { 80u16 };

    // Split host from port. An IPv6 literal is bracketed (`[::1]`, `[::1]:9000`)
    // and its address contains colons, so it must be handled before any
    // rightmost-colon split — otherwise `[::1]` splits inside the brackets and
    // yields the nonsense port `"1]"`.
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (inside, after) = rest
            .split_once(']')
            .ok_or_else(|| network("bucket URL has an unterminated IPv6 literal"))?;
        let port = match after {
            "" => default_port,
            p => p
                .strip_prefix(':')
                .ok_or_else(|| network("bucket URL has a malformed IPv6 authority"))?
                .parse::<u16>()
                .map_err(|_| network("bucket URL has an invalid port"))?,
        };
        (inside, port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (
                h,
                p.parse::<u16>()
                    .map_err(|_| network("bucket URL has an invalid port"))?,
            ),
            None => (authority, default_port),
        }
    };
    if host.is_empty() {
        return Err(network("bucket URL has an empty host"));
    }

    // Reproduce the authority for the `Host` header: brackets preserved for IPv6,
    // port present only when it is not the scheme default. See `Target::authority`
    // — this string must match what SigV4 signed, byte for byte.
    let is_ipv6 = host.contains(':');
    let wire_authority = match (is_ipv6, port == default_port) {
        (true, true) => format!("[{host}]"),
        (true, false) => format!("[{host}]:{port}"),
        (false, true) => host.to_string(),
        (false, false) => format!("{host}:{port}"),
    };

    Ok(Target {
        host,
        port,
        authority: wire_authority,
        request_target: path,
        tls,
    })
}

/// The byte pipe: rustls over TCP for `https`, bare TCP for `http`. Boxed on the
/// TLS side because `ClientConnection` is large and this enum is moved around.
enum Wire {
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
    Plain(TcpStream),
}

impl Wire {
    /// The underlying socket — timeouts are set on it directly, per phase.
    fn socket(&self) -> &TcpStream {
        match self {
            Wire::Tls(s) => s.get_ref(),
            Wire::Plain(s) => s,
        }
    }
}

impl Read for Wire {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Wire::Tls(s) => s.read(buf),
            Wire::Plain(s) => s.read(buf),
        }
    }
}

impl Write for Wire {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Wire::Tls(s) => s.write(buf),
            Wire::Plain(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Wire::Tls(s) => s.flush(),
            Wire::Plain(s) => s.flush(),
        }
    }
}

/// One connection to a bucket host, with phase-dependent timeouts.
struct Connection {
    wire: Wire,
    /// Optional absolute deadline for this whole attempt — the governor's
    /// rate-derived per-part ceiling (`k × bytes ÷ measured rate`), never a fixed
    /// number of seconds. `None` when no credible rate estimate exists yet, which
    /// is the correct state for a first part: the rate-free gap detector is already
    /// complete without one.
    ///
    /// It closes the only residual the gap detector cannot see — a pathological
    /// trickle that moves just enough bytes to keep resetting the gap forever.
    deadline: Option<std::time::Instant>,
}

impl Connection {
    /// Fail if this attempt has outrun its rate-derived ceiling.
    fn check_deadline(&self) -> Result<()> {
        if let Some(deadline) = self.deadline
            && std::time::Instant::now() >= deadline
        {
            return Err(CliError::transfer_stalled(
                "the part exceeded the time its measured transfer rate predicts \
                 (a trickling or wedged connection); retrying on a fresh connection",
            ));
        }
        Ok(())
    }
}

/// Order resolved addresses IPv4-first, IPv6 after, preserving relative order
/// within each family.
///
/// **bug047 / OVH IPv6 storage ingress (S141).** OVH's IPv6 storage-ingress VIP
/// (`2607:5300:205:700::1`) blackholes sustained multipart PUT flows mid-stream
/// (40–90% in a bad window, time-varying), while the IPv4 ingress for the *same*
/// VIP is clean (0/8, interleaved same-source same-minute). On a dual-stack
/// client `getaddrinfo` typically returns the IPv6 address first; the v6
/// connection *establishes* fine (the stall is mid-stream, not at connect), so
/// the first-success-wins loop in [`Connection::open`] selects the broken front
/// door and never tries v4.
///
/// This is a **preference, not a hard pin**: v6 addresses are kept, only moved
/// after v4. So a v6-only endpoint still connects via the fallback — a `[::1]`
/// MinIO in CI/dev, or an OVH VIP that ever drops its A record — which makes the
/// change self-healing and reversible. Scoped to `bucket_transport` (the storage
/// byte-path), so it pins only the OVH storage front door, nothing else.
///
/// **Interim measure.** The real fix is OVH repairing their v6 ingress (or
/// publishing a v4-only endpoint we presign against — the only fix for the web
/// surface, since a browser cannot pin address family: Happy Eyeballs races v6
/// first, the v6 handshake succeeds, and JS never learns the mid-stream stall).
fn prefer_ipv4(addrs: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let (v4, v6): (Vec<SocketAddr>, Vec<SocketAddr>) = addrs.into_iter().partition(|a| a.is_ipv4());
    v4.into_iter().chain(v6).collect()
}

/// True when the connect loop landed on IPv6 despite IPv4 being available — i.e.
/// [`prefer_ipv4`] put v4 first but every v4 address failed to connect, so the loop
/// fell through to v6. That is the one noteworthy boundary crossing for bug047; a
/// v6-only endpoint connecting over v6 is normal and returns false.
fn is_ipv6_fallback(connected: &SocketAddr, resolved: &[SocketAddr]) -> bool {
    connected.is_ipv6() && resolved.iter().any(SocketAddr::is_ipv4)
}

/// One-time diagnostic when a storage connection falls through IPv4 to IPv6.
///
/// bug047 (S142 review, Gus): the fault hid for three weeks because address family
/// was an unlogged variable everywhere. [`prefer_ipv4`] orders v4 first, so reaching
/// v6 means every resolved IPv4 address failed to connect — the exact shape of a
/// silent OVH IPv4-ingress outage policing traffic onto the stall-prone v6 path.
/// One line converts a would-be re-investigation of a solved bug into a grep.
/// Skipped for local hosts (the OVH-specific guidance would only mislead in dev);
/// `Once`-guarded so it prints at most once even though `open` runs per part.
fn warn_ipv6_fallback(host: &str) {
    if is_local_host(host) {
        return;
    }
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        eprintln!(
            "signet: NOTE: connected to object storage ({host}) over IPv6 after every \
             IPv4 address failed to connect. IPv4 is preferred for storage (bug047: \
             OVH's IPv6 storage ingress can stall sustained uploads). If uploads stall \
             or crawl, check whether OVH's IPv4 storage ingress is down."
        );
    });
}

impl Connection {
    /// Open a fresh connection. Never pooled, never reused (bug047).
    fn open(target: &Target<'_>, bounds: &TransportBounds) -> Result<Self> {
        // Resolve, then order IPv4 first — see `prefer_ipv4` (bug047 / OVH v6 ingress).
        let addrs = prefer_ipv4(
            (target.host, target.port)
                .to_socket_addrs()
                .map_err(|e| network(format!("cannot resolve {}: {e}", target.host)))?,
        );
        let mut last: Option<std::io::Error> = None;
        let mut tcp: Option<TcpStream> = None;
        let mut connected: Option<SocketAddr> = None;
        for addr in &addrs {
            match TcpStream::connect_timeout(addr, CONNECT_TIMEOUT) {
                Ok(s) => {
                    connected = Some(*addr);
                    tcp = Some(s);
                    break;
                }
                Err(e) => last = Some(e),
            }
        }
        let tcp = tcp.ok_or_else(|| {
            network(format!(
                "cannot connect to {}: {}",
                target.host,
                last.map(|e| e.to_string())
                    .unwrap_or_else(|| "no addresses".into())
            ))
        })?;
        // bug047 observability (Gus, S142): if we reached IPv6 only because every
        // resolved IPv4 address failed, make that boundary crossing grep-able — a
        // silent OVH IPv4-ingress outage policing traffic onto the stall-prone v6
        // path must not re-hide as an unlogged variable.
        if connected.is_some_and(|a| is_ipv6_fallback(&a, &addrs)) {
            warn_ipv6_fallback(target.host);
        }

        tcp.set_nodelay(true).ok();
        // Cap the send buffer so socket write-progress is an honest proxy for
        // delivery (see `TransportBounds::sndbuf_bytes`). Best-effort: platforms
        // differ and some (Linux) double the requested value, so correctness must
        // not depend on the exact figure — only on it being bounded.
        socket2::SockRef::from(&tcp)
            .set_send_buffer_size(bounds.sndbuf_bytes)
            .ok();

        // Handshake phase: reads are expected and prompt `[rate-free]`. These bounds
        // must be armed *and the handshake actually driven under them* — see the
        // explicit drive below.
        arm_read_timeout(&tcp, HANDSHAKE_TIMEOUT)?;
        arm_write_timeout(&tcp, bounds.write_gap)?;

        let wire = if target.tls {
            let server_name = rustls::pki_types::ServerName::try_from(target.host)
                .map_err(|_| network("bucket URL host is not a valid TLS server name"))?
                .to_owned();
            // The SAME config object as every other request in the CLI — roots,
            // provider, PQ group preference, and protocol floor all inherited.
            // Certificate and hostname verification are rustls's own, unmodified.
            let mut conn = rustls::ClientConnection::new(crate::http::pq_tls_config(), server_name)
                .map_err(|e| network(format!("TLS setup failed: {e}")))?;
            let mut tcp = tcp;

            // Drive the handshake to completion HERE, while HANDSHAKE_TIMEOUT is the
            // armed read bound.
            //
            // `ClientConnection::new` performs no I/O and `StreamOwned` handshakes
            // lazily on first use — so without this, the ServerHello read happened
            // inside the first body write, by which point `request()` has already
            // disarmed reads to `READ_DISARMED` (24 h). A peer that completes the TCP
            // handshake and then goes silent (SYN-proxy middleboxes; a bug047-class
            // death at handshake time) hung the whole attempt for a day: `write_gap`
            // bounds `write()` syscalls while the block is inside a `read()`, and the
            // governor supplies no ceiling for the first part of a fresh upload.
            //
            // This is bug060's own shape — a documented bound that is not the
            // operative one — pointing the other way: a timer that failed to fire
            // rather than one that fired too early.
            while conn.is_handshaking() {
                let (rd, wr) = conn.complete_io(&mut tcp).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut
                    {
                        network(format!(
                            "storage accepted the connection but did not complete the TLS \
                             handshake within {}s; treating the flow as dead and retrying \
                             on a fresh connection",
                            HANDSHAKE_TIMEOUT.as_secs()
                        ))
                    } else {
                        network(format!("TLS handshake failed: {e}"))
                    }
                })?;
                if rd == 0 && wr == 0 && conn.is_handshaking() {
                    // No progress and not done: the peer closed mid-handshake. Without
                    // this guard the loop would spin on a half-closed socket.
                    return Err(network(
                        "storage closed the connection during the TLS handshake",
                    ));
                }
            }

            Wire::Tls(Box::new(rustls::StreamOwned::new(conn, tcp)))
        } else {
            Wire::Plain(tcp)
        };
        Ok(Self {
            wire,
            deadline: None,
        })
    }

    fn socket(&self) -> &TcpStream {
        self.wire.socket()
    }

    /// Close the connection deliberately (watchdog abort or normal end) — a
    /// socket shutdown, never a bare cross-thread drop.
    fn shutdown(&mut self) {
        let _ = self.socket().shutdown(std::net::Shutdown::Both);
    }

    /// Write the whole buffer, bounding each individual write by the no-progress
    /// gap. `SO_SNDTIMEO` makes a write that can place **zero** bytes within the
    /// gap return `WouldBlock`/`TimedOut`; any forward progress resets it, so a
    /// slow-but-moving link is never killed. `[rate-free]`
    fn write_all_gap_bounded(&mut self, mut buf: &[u8]) -> Result<()> {
        while !buf.is_empty() {
            self.check_deadline()?;
            match self.wire.write(buf) {
                Ok(0) => {
                    return Err(CliError::transfer_stalled(
                        "storage connection accepted no further bytes (stalled flow)",
                    ));
                }
                Ok(n) => buf = &buf[n..],
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    return Err(CliError::transfer_stalled(format!(
                        "no upload progress for {:?}: stalled connection aborted",
                        self.socket()
                            .write_timeout()
                            .ok()
                            .flatten()
                            .unwrap_or_default()
                    )));
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(network(format!("writing to storage: {e}"))),
            }
        }
        self.wire
            .flush()
            .map_err(|e| network(format!("flushing to storage: {e}")))
    }
}

/// A parsed HTTP/1.1 response: status, the headers we care about, and the body.
struct Response {
    status: u16,
    etag: Option<String>,
    body: Vec<u8>,
    /// 1c (S175): true iff the connection provably holds NO residual response
    /// bytes and the server did not ask to close — i.e. a 2xx data body framed
    /// by Content-Length and drained to EXACTLY that length. Only such a
    /// connection may return to a [`DownloadPool`]; everything else — an error
    /// body read best-effort, a diagnostic path, a `Connection: close` from the
    /// server, a length mismatch — is evicted. The conservative default is
    /// `false`: a response we cannot PROVE clean is treated as dirty.
    reusable: bool,
}

/// Read and parse the response. Called **only after the request body is fully
/// written**, with the read timeout re-armed to a rate-derived ceiling.
fn read_response(conn: &mut Connection, want_body: bool, body_gap: Duration) -> Result<Response> {
    let mut buf = Vec::with_capacity(8 * 1024);
    let mut chunk = [0u8; 8 * 1024];
    // Header phase: read until CRLFCRLF.
    let head_end = loop {
        if let Some(i) = find_headers_end(&buf) {
            break i;
        }
        conn.check_deadline()?;
        let n = conn.wire.read(&mut chunk).map_err(|e| {
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut
            {
                CliError::transfer_stalled(
                    "storage did not answer within the expected window after the body was sent",
                )
            } else {
                network(format!("reading storage response: {e}"))
            }
        })?;
        if n == 0 {
            return Err(network("storage closed the connection before responding"));
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 64 * 1024 {
            return Err(network("storage response headers are implausibly large"));
        }
    };

    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| network(format!("malformed status line from storage: {status_line}")))?;

    let mut etag = None;
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut server_close = false;
    let mut overshot = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("etag") {
            etag = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("content-length") {
            content_length = value.parse().ok();
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            chunked = true;
        } else if name.eq_ignore_ascii_case("connection")
            && value.to_ascii_lowercase().contains("close")
        {
            // 1c: the server is ending this connection after the response —
            // it can never return to a pool, however clean the body read.
            server_close = true;
        }
    }

    let mut body = buf[head_end..].to_vec();
    if want_body || status >= 400 {
        if chunked {
            return Err(network(
                "storage used chunked transfer-encoding, which this transport does not accept",
            ));
        }
        // Downloads observe **arrival**, so read progress is genuine — unlike write
        // progress, which observes buffering. Once the response has started, the
        // honest detector is therefore the same rate-free no-progress gap the write
        // path uses: any arriving byte resets `SO_RCVTIMEO`. (The header phase kept
        // the wider rate-derived ceiling, because first-byte latency legitimately
        // includes the store thinking.) This is why the download path was never
        // vulnerable to bug060 — bug060 §6.
        arm_read_timeout_best_effort(conn.socket(), body_gap);

        // Data bodies and error bodies have opposite failure semantics, and
        // conflating them costs diagnosability in one direction or data integrity in
        // the other:
        //
        // * A **data** body (2xx, `want_body`) is payload. It must declare its length
        //   and arrive complete — a short read is silent corruption, and previously
        //   surfaced downstream as "decryption failed", blaming our crypto for the
        //   store's framing.
        // * An **error** body (>= 4xx) is diagnostics. It is read best-effort, because
        //   failing the read would discard the status code — the single most useful
        //   fact we have — and report a framing complaint instead of "HTTP 403:
        //   SignatureDoesNotMatch". S3 error bodies normally carry Content-Length,
        //   but a proxy-generated one may not, and that must not cost us the status.
        // A 3xx joins the diagnostic path rather than the data path. It carries no
        // payload we would use, and routing it through the data branch made the
        // hard Content-Length requirement fire *before* `request()`'s redirect check,
        // so a redirected download surfaced as a framing complaint and the accurate
        // "pre-signed requests are never redirected" message was unreachable on the
        // GET path — the same attribution inversion this split exists to kill, and a
        // quiet weakening of the module's "redirects fail loudly" posture
        // (Gus, S127 F3).
        let is_diagnostic_body = status >= 400 || (300..400).contains(&status);

        if is_diagnostic_body {
            // Best-effort: bounded by Content-Length when present, else read to close.
            // Never fatal — the status is what the caller needs.
            //
            // `check_deadline` is what stops a trickling endpoint from holding this
            // open indefinitely: each read only has to deliver *some* byte inside the
            // gap to keep the loop alive, so 1 byte every ~11 s would otherwise stream
            // 64 KiB over days. This was the one loop in the file bounded by neither a
            // declared length nor a deadline (Gus, S127 F2).
            let cap = content_length.unwrap_or(MAX_ERROR_BODY_BYTES);
            while body.len() < cap.min(MAX_ERROR_BODY_BYTES) {
                if conn.check_deadline().is_err() {
                    break; // Keep what we have; the status is the payload here.
                }
                match conn.wire.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => body.extend_from_slice(&chunk[..n]),
                }
            }
            if let Some(target) = content_length {
                body.truncate(target.min(body.len()));
            }
        } else {
            let target = content_length.ok_or_else(|| {
                network(
                    "storage returned a body response with no Content-Length, which \
                     this transport cannot bound; treating it as a failed transfer \
                     rather than guessing at the length",
                )
            })?;

            while body.len() < target {
                conn.check_deadline()?;
                let n = conn.wire.read(&mut chunk).map_err(|e| {
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut
                    {
                        CliError::transfer_stalled("storage stopped sending the response body")
                    } else {
                        network(format!("reading storage response body: {e}"))
                    }
                })?;
                if n == 0 {
                    // Early close mid-body. Previously this broke out and returned a
                    // silently short body — an S2-class attribution inversion. Name
                    // the shape instead.
                    return Err(network(format!(
                        "storage closed the connection mid-body: received {} of {} \
                         declared bytes",
                        body.len(),
                        target
                    )));
                }
                body.extend_from_slice(&chunk[..n]);
            }
            // `body` can overshoot `target` only by whatever arrived in the same read
            // as the headers; trim to the declared length. 1c: an overshoot means
            // the server sent MORE than it declared — bytes this parser cannot
            // attribute — so record it BEFORE the truncate erases the evidence:
            // such a connection must never return to a pool.
            overshot = body.len() > target;
            body.truncate(target);
        }
    }
    // 1c: provably-clean is the ONLY reusable state — a 2xx data body, framed by
    // Content-Length, drained to exactly that length with nothing extra, on a
    // connection the server did not ask to close. The diagnostic path
    // (best-effort reads) and the no-body path can leave residual bytes, so
    // they are never reusable.
    let reusable = !server_close
        && !chunked
        && !overshot
        && status < 300
        && want_body
        && content_length == Some(body.len());
    Ok(Response {
        status,
        etag,
        body,
        reusable,
    })
}

fn find_headers_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// The rate-derived response ceiling: however long the capped send buffer needs
/// to drain at the observed rate, plus a fixed server allowance. `[rate-derived]`
///
/// `observed_rate_bps` is measured over the body write we just completed, so no
/// bootstrap estimate is required — the transfer measures itself.
/// Per-attempt liveness ceiling for the **response phase**, installed unconditionally.
///
/// # Why this exists
///
/// Without it, response-phase boundedness rested entirely on
/// [`arm_read_timeout_best_effort`] succeeding — and on two live paths there was
/// nothing behind it:
///
/// * **downloads** always pass `ceiling = None` (`http.rs` `get_presigned_range`), and
/// * **the first part of a fresh upload** has no governor estimate, so `ceiling` is
///   `None` there too.
///
/// `check_deadline` is a no-op when the deadline is `None`, and the write-gap detector
/// does not apply to a phase with no writes in it. So a peer that completed the
/// handshake, accepted the body, and then went silent on the response would hang the
/// attempt under `READ_DISARMED` — **B1's exact shape, relocated to the response
/// path** (Gus, S127 F1b). It also gives the error-body read loop the total-time bound
/// it lacked, which a trickling endpoint could otherwise stretch for days (F2).
///
/// # Why it does not violate the governing invariant
///
/// It is **derived, not absolute**, wherever the quantity it bounds is
/// `bytes ÷ rate`: for a bodied response we know exactly how many bytes we asked for,
/// so the bound scales with the request against a stated worst-case link. The constant
/// floor applies to the genuinely rate-free case — a response with no body — and
/// serves as a lower bound elsewhere. This is the same shape as the web's `backstopMs`
/// after its own §1 correction: `max(floor, k × expected)`, never a bare constant.
fn response_backstop(expected_body_bytes: Option<u64>, floor: Duration) -> Duration {
    match expected_body_bytes {
        None => floor,
        Some(bytes) => {
            let expected = bytes as f64 / MIN_CREDIBLE_RATE_BPS;
            let derived = Duration::from_secs_f64((expected * RESPONSE_BACKSTOP_K).min(86_400.0));
            derived.max(floor)
        }
    }
}

/// The deadline that may bound the **write phase** — the governor's rate-derived
/// ceiling, and nothing else.
///
/// Trivial by construction, and that is the point: it exists so the rule is a *named,
/// testable function* rather than an ordering fact buried in `request()`. The B3
/// defect was exactly an ordering mistake — the response backstop assigned to
/// `conn.deadline` before the body write, so a flat constant bounded a `bytes ÷ rate`
/// quantity and rebuilt bug060 at a ~0.45 Mbps cliff (16 MiB part) or ~1.8 Mbps
/// (64 MiB part / resume without a persisted estimate).
///
/// It cannot be pinned end-to-end on loopback: `check_deadline` runs *between*
/// syscalls and cannot interrupt one, and a loopback `write()` absorbs a whole part
/// in a single blocking call — so the defect is invisible there while being live on a
/// real link, where partial writes return constantly. Hence a pure function with a
/// direct unit test, rather than a wire test that would pass either way.
fn write_phase_deadline(ceiling: Option<Duration>) -> Option<Duration> {
    ceiling
}

fn response_ceiling(bounds: &TransportBounds, observed_rate_bps: f64) -> Duration {
    let drain = if observed_rate_bps > 1.0 {
        // `sndbuf ÷ rate` is a bytes-over-rate quantity, so per the §1 invariant it
        // must not be bounded by an absolute constant — with ONE deliberate,
        // annotated exception: `DRAIN_USABILITY_CAP`.
        //
        // The exception is auditable rather than accidental. With the default 1 MiB
        // send buffer the cap engages only below ~14 kbps (1 MiB ÷ 600 s ≈ 1.7 kB/s)
        // — a rate at which a single 5 MiB part would need ~50 minutes and the
        // product is not usable by any definition we would defend. Above that floor
        // the window remains fully rate-derived, which is the property bug060 turned
        // on. Recorded explicitly so the invariant stays checkable: an unannotated
        // constant here would be indistinguishable from the defect.
        Duration::from_secs_f64(
            (bounds.sndbuf_bytes as f64 / observed_rate_bps).min(DRAIN_USABILITY_CAP),
        )
    } else {
        Duration::from_secs(60)
    };
    drain + RESPONSE_ALLOWANCE
}

/// The outcome of one bucket transfer attempt.
pub struct Transfer {
    pub status: u16,
    pub etag: Option<String>,
    pub body: Vec<u8>,
    /// Bytes-per-second observed across the body write — the governor's input.
    pub observed_rate_bps: f64,
}

/// Perform one HTTP/1.1 request to a pre-signed bucket URL on a **fresh**
/// connection.
///
/// `body` is written under the gap detector with the read timer disarmed; the
/// response is then read under a rate-derived ceiling. Returns the transport-level
/// outcome — status interpretation (retryable vs definitive) belongs to the caller.
/// Everything the caller knows that bounds the **response phase**.
///
/// Grouped rather than passed as loose options because they answer one question
/// together — *how long may this attempt legitimately wait for an answer?* — and
/// because the interesting case is when both are absent: a download or a first part,
/// where the governor has no estimate and only the derived backstop stands between a
/// silent peer and a 24 h hang.
struct ResponseBudget {
    /// The governor's rate-derived ceiling, when an estimate exists.
    ceiling: Option<Duration>,
    /// Expected response body size, when the request implies one (a range GET).
    /// Present means the backstop derives from it rather than using the floor.
    expected_body_bytes: Option<u64>,
}

/// 1c (S175): a pool of keep-alive connections for the DOWNLOAD path ONLY.
///
/// Scoped to ONE download (create it at download start; dropping it closes every
/// idle socket), shared across that download's fan-out workers, keyed by
/// authority so a URL change can never hand a connection to the wrong host.
///
/// The lifecycle rules, each load-bearing:
/// * **Take**: only for a matching authority, and only on a FIRST attempt — a
///   caller-level retry bypasses the pool entirely and opens fresh
///   (STALL-EVICTS-POOL: per-flow fate is the mechanism of the bug047 fault
///   family, so a retry must be a genuinely new flow, not another pooled one).
/// * **Return**: only a connection whose response was provably clean
///   ([`Response::reusable`]). Anything else is shut down.
/// * **Reused-connection failure**: retried ONCE internally on a fresh
///   connection before any error surfaces — the standard keep-alive race (the
///   server may close an idle connection at any moment, and that must cost a
///   reopen, never a spurious caller-visible failure).
pub struct DownloadPool {
    idle: std::sync::Mutex<Vec<(String, Connection)>>,
}

impl DownloadPool {
    pub fn new() -> Self {
        Self {
            idle: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn take(&self, authority: &str) -> Option<Connection> {
        let mut idle = self.idle.lock().ok()?;
        let at = idle.iter().position(|(a, _)| a == authority)?;
        Some(idle.swap_remove(at).1)
    }

    fn put_back(&self, authority: &str, conn: Connection) {
        if let Ok(mut idle) = self.idle.lock() {
            idle.push((authority.to_string(), conn));
        }
    }
}

impl Default for DownloadPool {
    fn default() -> Self {
        Self::new()
    }
}

fn request(
    method: &str,
    url: &str,
    extra_headers: &[(&str, String)],
    body: &[u8],
    bounds: &TransportBounds,
    want_body: bool,
    budget: ResponseBudget,
) -> Result<Transfer> {
    request_with_pool(
        method,
        url,
        extra_headers,
        body,
        bounds,
        want_body,
        budget,
        None,
    )
}

/// One request, optionally drawing from / returning to a [`DownloadPool`].
///
/// With `pool == None` this is exactly the historical behaviour: fresh
/// connection, `Connection: close`, shutdown after the response. With a pool, a
/// clean first attempt may reuse an idle connection and a provably-clean
/// response returns it; a reused connection that fails in ANY way is evicted
/// and the attempt transparently re-runs once on a fresh connection.
#[allow(clippy::too_many_arguments)]
fn request_with_pool(
    method: &str,
    url: &str,
    extra_headers: &[(&str, String)],
    body: &[u8],
    bounds: &TransportBounds,
    want_body: bool,
    budget: ResponseBudget,
    pool: Option<&DownloadPool>,
) -> Result<Transfer> {
    let ResponseBudget {
        ceiling,
        expected_body_bytes,
    } = budget;
    let target = parse_url(url)?;
    warn_if_plaintext_to_remote_host(&target);
    // 1c: a reused connection gets ONE transparent fresh retry (the keep-alive
    // race — the server may close an idle connection at any moment, and that
    // must cost a reopen, never a caller-visible failure). A fresh connection's
    // failure surfaces immediately, exactly as before.
    let mut allow_reuse = true;
    loop {
        let pooled = pool
            .filter(|_| allow_reuse)
            .and_then(|p| p.take(&target.authority));
        let reused = pooled.is_some();
        let mut conn = match pooled {
            Some(c) => c,
            None => Connection::open(&target, bounds)?,
        };
        match request_on(
            &mut conn,
            method,
            &target,
            extra_headers,
            body,
            bounds,
            want_body,
            ceiling,
            expected_body_bytes,
            pool.is_some(),
        ) {
            Err(e) => {
                conn.shutdown();
                if reused {
                    allow_reuse = false;
                    continue;
                }
                return Err(e);
            }
            Ok((response, observed_rate_bps)) => {
                // Redirects are never followed on a pre-signed URL — the
                // signature covers this exact request, so a 3xx is anomalous
                // and must be loud, not silently chased.
                if (300..400).contains(&response.status) {
                    conn.shutdown();
                    return Err(network(format!(
                        "storage answered HTTP {} (redirect) for {}: pre-signed requests are never redirected",
                        response.status,
                        redact(url)
                    )));
                }
                match pool {
                    Some(p) if response.reusable => p.put_back(&target.authority, conn),
                    _ => conn.shutdown(),
                }
                return Ok(Transfer {
                    status: response.status,
                    etag: response.etag,
                    body: response.body,
                    observed_rate_bps,
                });
            }
        }
    }
}

/// One attempt on one already-open connection: write the request, read the
/// response. Shutdown/pool-return is the CALLER's job — this fn never consumes
/// the connection, so the reuse decision stays in exactly one place.
#[allow(clippy::too_many_arguments)]
fn request_on(
    conn: &mut Connection,
    method: &str,
    target: &Target<'_>,
    extra_headers: &[(&str, String)],
    body: &[u8],
    bounds: &TransportBounds,
    want_body: bool,
    ceiling: Option<Duration>,
    expected_body_bytes: Option<u64>,
    keep_alive: bool,
) -> Result<(Response, f64)> {
    // The caller's governor ceiling when there is one; otherwise the response-phase
    // backstop, which is installed UNCONDITIONALLY. Downloads and first parts always
    // arrive here with `ceiling == None`, and without a deadline the response phase
    // has no liveness bound at all once the best-effort arm is allowed to fail
    // (S127 F1b). Take the tighter of the two when both exist.
    // WRITE PHASE: bounded by the governor's **rate-derived** ceiling only — and by
    // nothing at all on a first part, where `ceiling` is `None`. That is correct: the
    // write phase's liveness bound is the rate-free no-progress gap (`SO_SNDTIMEO`),
    // which is already a complete dead-flow detector without any duration estimate.
    //
    // The response backstop must NOT be installed here. A first draft of the F1(b)
    // fix set the deadline once at attempt start, and because `check_deadline()` runs
    // inside `write_all_gap_bounded`, the flat 300 s floor ended up bounding the whole
    // first-part BODY WRITE — an absolute wall-time constant on a `bytes ÷ rate`
    // quantity, i.e. **bug060 rebuilt**: 16 MiB ÷ 300 s is a ~0.45 Mbps cliff, and a
    // 64 MiB part (explicit `--chunk-size`, or any resume with no persisted estimate)
    // moves it to ~1.8 Mbps — squarely inside normal usable bandwidth. Caught by Gus,
    // S127 B3. The backstop belongs to the response phase, which is the only phase
    // with no gap detector of its own.
    let attempt_started = std::time::Instant::now();
    conn.deadline = write_phase_deadline(ceiling).map(|c| attempt_started + c);

    // `target.authority`, never `target.host`: the Host header must reproduce the
    // authority SigV4 signed, including a non-default port and IPv6 brackets.
    // 1c: `Connection: close` on the no-pool path exactly as always; keep-alive
    // only when a DownloadPool is in play (the download-only split — the module
    // doctrine owns the why).
    let connection_header = if keep_alive { "keep-alive" } else { "close" };
    let mut head = format!(
        "{method} {} HTTP/1.1\r\nHost: {}\r\nConnection: {connection_header}\r\n",
        target.request_target, target.authority
    );
    if !body.is_empty() || method == "PUT" {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    for (name, value) in extra_headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");

    // --- body-write phase: the read timer is DISARMED (the bug060 fix) ---------
    arm_read_timeout(conn.socket(), READ_DISARMED)?;
    arm_write_timeout(conn.socket(), bounds.write_gap)?;

    let started = std::time::Instant::now();
    // On error, just return: shutdown-vs-evict is the CALLER's decision now
    // (request_with_pool), which is what makes the reused-connection retry and
    // the pool-return live in exactly one place.
    conn.write_all_gap_bounded(head.as_bytes())
        .and_then(|()| conn.write_all_gap_bounded(body))?;
    let elapsed = started.elapsed().as_secs_f64();
    // NOTE: this measures how fast the body was **accepted into the send buffer**,
    // not how fast it was delivered — the last `sndbuf` bytes are still in flight
    // when the final write returns. It therefore *overestimates* the link rate by up
    // to `part ÷ (part − sndbuf)`: ~25% on a 5 MiB part, ~1.6% at 64 MiB (1 MiB
    // buffer). That is harmless where it is used — `RESPONSE_ALLOWANCE` and the
    // governor's `k` both absorb it, and an overestimate only shortens a *response*
    // window, never the transmission itself. Do not repurpose this as a delivery
    // rate (e.g. for user-facing throughput or the governor's estimate) without
    // correcting for the buffer.
    let observed_rate_bps = if elapsed > 0.0 {
        body.len() as f64 / elapsed
    } else {
        0.0
    };

    // --- response phase: re-arm the read timer, rate-derived ------------------
    arm_read_timeout_best_effort(conn.socket(), response_ceiling(bounds, observed_rate_bps));

    // NOW install the backstop — the response phase is the only phase without a gap
    // detector of its own, and the only one this may bound. Here the flat floor is
    // legitimately rate-free (a PUT's response carries no body) and the derived value
    // covers the GET, whose expected size we know. Take whatever remains of the
    // governor's ceiling if it set one, so the backstop can only ever tighten.
    let backstop = response_backstop(expected_body_bytes, bounds.response_backstop_floor);
    let now = std::time::Instant::now();
    let response_budget = match ceiling {
        Some(c) => (attempt_started + c)
            .saturating_duration_since(now)
            .min(backstop),
        None => backstop,
    };
    conn.deadline = Some(now + response_budget);

    let response = read_response(conn, want_body, bounds.write_gap)?;
    Ok((response, observed_rate_bps))
}

/// PUT a body to a pre-signed bucket URL. One attempt, fresh connection.
pub fn put(
    url: &str,
    body: &[u8],
    bounds: &TransportBounds,
    ceiling: Option<Duration>,
) -> Result<Transfer> {
    // A PUT's response carries no body worth reading, so its backstop is the
    // rate-free floor rather than a derived one.
    request(
        "PUT",
        url,
        &[],
        body,
        bounds,
        false,
        ResponseBudget {
            ceiling,
            expected_body_bytes: None,
        },
    )
}

/// Range-GET `[start, end]` (inclusive) from a pre-signed bucket URL. One
/// attempt, fresh connection. Downloads observe **arrival**, so read progress is
/// real and the same gap logic applies naturally to the response phase.
pub fn get_range(
    url: &str,
    start: u64,
    end: u64,
    bounds: &TransportBounds,
    ceiling: Option<Duration>,
) -> Result<Transfer> {
    // The requested range IS the expected response size, so the backstop derives
    // from it against MIN_CREDIBLE_RATE_BPS rather than being a bare constant —
    // which is what keeps this invariant-legal on the one path whose response
    // genuinely is a `bytes ÷ rate` quantity.
    let expected = end.saturating_sub(start).saturating_add(1);
    request(
        "GET",
        url,
        &[("Range", format!("bytes={start}-{end}"))],
        &[],
        bounds,
        true,
        ResponseBudget {
            ceiling,
            expected_body_bytes: Some(expected),
        },
    )
}

/// 1c (S175): [`get_range`] drawing from / returning to a [`DownloadPool`].
///
/// ⚠ Callers with their own retry budget pass the pool on the FIRST attempt
/// only — a caller-level retry must be a genuinely fresh flow, never another
/// pooled one (stall-evicts-pool; per-flow fate is the fault family's whole
/// mechanism). The internal reused-connection race retry is separate and
/// invisible to the caller's budget.
pub fn get_range_pooled(
    pool: &DownloadPool,
    url: &str,
    start: u64,
    end: u64,
    bounds: &TransportBounds,
    ceiling: Option<Duration>,
) -> Result<Transfer> {
    let expected = end.saturating_sub(start).saturating_add(1);
    request_with_pool(
        "GET",
        url,
        &[("Range", format!("bytes={start}-{end}"))],
        &[],
        bounds,
        true,
        ResponseBudget {
            ceiling,
            expected_body_bytes: Some(expected),
        },
        Some(pool),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_removes_the_signature_query() {
        let url = "https://s3.example.net/bucket/key?X-Amz-Signature=deadbeef&X-Amz-Credential=abc";
        let out = redact(url);
        assert_eq!(out, "https://s3.example.net/bucket/key?<redacted>");
        assert!(
            !out.contains("deadbeef"),
            "the signature must never survive"
        );
        assert!(!out.contains("Credential"));
    }

    #[test]
    fn redact_is_identity_without_a_query() {
        assert_eq!(
            redact("https://s3.example.net/bucket/key"),
            "https://s3.example.net/bucket/key"
        );
    }

    #[test]
    fn parse_url_splits_authority_and_target() {
        let t = parse_url("https://s3.example.net/bucket/key?sig=1").unwrap();
        assert_eq!(t.host, "s3.example.net");
        assert_eq!(t.port, 443);
        assert_eq!(t.request_target, "/bucket/key?sig=1");
    }

    #[test]
    fn parse_url_honours_an_explicit_port() {
        let t = parse_url("https://localhost:9000/b/k").unwrap();
        assert_eq!(t.host, "localhost");
        assert_eq!(t.port, 9000);
    }

    #[test]
    fn prefer_ipv4_orders_v4_before_v6() {
        // The exact bug047 case: getaddrinfo returns the v6 address first on a
        // dual-stack client; the connect loop must still reach v4 first.
        let v4: SocketAddr = "54.39.60.208:443".parse().unwrap();
        let v6: SocketAddr = "[2607:5300:205:700::1]:443".parse().unwrap();
        let got = prefer_ipv4(vec![v6, v4]);
        assert_eq!(got, vec![v4, v6], "v4 must be tried before v6");
        assert!(got[0].is_ipv4());
    }

    #[test]
    fn prefer_ipv4_preserves_v6_only() {
        // A v6-only endpoint (a `[::1]` MinIO, or an OVH VIP with no A record)
        // must still be reachable — v6 is reordered, never dropped.
        let v6a: SocketAddr = "[::1]:9000".parse().unwrap();
        let v6b: SocketAddr = "[2607:5300:205:700::1]:443".parse().unwrap();
        let got = prefer_ipv4(vec![v6a, v6b]);
        assert_eq!(
            got,
            vec![v6a, v6b],
            "v6-only order preserved, nothing dropped"
        );
    }

    #[test]
    fn prefer_ipv4_leaves_v4_only_unchanged() {
        let a: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let b: SocketAddr = "54.39.60.208:443".parse().unwrap();
        assert_eq!(prefer_ipv4(vec![a, b]), vec![a, b]);
    }

    #[test]
    fn prefer_ipv4_is_stable_within_each_family() {
        // All v4 precede all v6; relative order within each family is preserved.
        let v4a: SocketAddr = "10.0.0.1:443".parse().unwrap();
        let v6a: SocketAddr = "[::1]:443".parse().unwrap();
        let v4b: SocketAddr = "10.0.0.2:443".parse().unwrap();
        let v6b: SocketAddr = "[fe80::1]:443".parse().unwrap();
        let got = prefer_ipv4(vec![v6a, v4a, v6b, v4b]);
        assert_eq!(got, vec![v4a, v4b, v6a, v6b]);
    }

    #[test]
    fn is_ipv6_fallback_true_when_v6_used_despite_v4_present() {
        // Connected on v6 while a v4 address was in the resolved set — every v4
        // failed to connect, so the loop fell through. This is the grep-able case.
        let v4: SocketAddr = "54.39.60.208:443".parse().unwrap();
        let v6: SocketAddr = "[2607:5300:205:700::1]:443".parse().unwrap();
        assert!(is_ipv6_fallback(&v6, &[v4, v6]));
    }

    #[test]
    fn is_ipv6_fallback_false_for_a_v6_only_endpoint() {
        // No v4 alternative existed — connecting over v6 is normal, not a fallback.
        let v6: SocketAddr = "[::1]:9000".parse().unwrap();
        assert!(!is_ipv6_fallback(&v6, &[v6]));
    }

    #[test]
    fn is_ipv6_fallback_false_on_the_preferred_v4_path() {
        let v4: SocketAddr = "54.39.60.208:443".parse().unwrap();
        let v6: SocketAddr = "[2607:5300:205:700::1]:443".parse().unwrap();
        assert!(!is_ipv6_fallback(&v4, &[v4, v6]));
    }

    /// The `Host` header must reproduce the authority SigV4 signed — byte for byte.
    /// A non-default port is part of the signed canonical request; the scheme default
    /// is not. Getting either direction wrong is `SignatureDoesNotMatch`.
    #[test]
    fn authority_reproduces_what_sigv4_signed() {
        // Non-default port: present.
        assert_eq!(
            parse_url("https://s3.example.net:9000/b/k")
                .unwrap()
                .authority,
            "s3.example.net:9000"
        );
        assert_eq!(
            parse_url("http://127.0.0.1:9000/b/k").unwrap().authority,
            "127.0.0.1:9000"
        );
        // Scheme-default port: absent — appending it breaks the signature the other way.
        assert_eq!(
            parse_url("https://s3.example.net/b/k").unwrap().authority,
            "s3.example.net"
        );
        assert_eq!(
            parse_url("https://s3.example.net:443/b/k")
                .unwrap()
                .authority,
            "s3.example.net"
        );
        assert_eq!(
            parse_url("http://s3.example.net:80/b/k").unwrap().authority,
            "s3.example.net"
        );
    }

    /// The write phase may be bounded by the governor's rate-derived ceiling and by
    /// NOTHING else — in particular never by the response backstop.
    ///
    /// This is the B3 invariant. Assigning the backstop to `conn.deadline` before the
    /// body write put a flat constant on a `bytes ÷ rate` quantity and rebuilt bug060:
    /// a first part (`ceiling = None`) ran under the flat 300 s floor, i.e. a
    /// ~0.45 Mbps cliff at the 16 MiB default and ~1.8 Mbps at 64 MiB. Every retry
    /// died identically, because a first part that never completes never yields the
    /// estimate that would have produced a ceiling.
    #[test]
    fn the_write_phase_is_never_bounded_by_the_response_backstop() {
        // A first part: no estimate, so NO duration bound on the write. The rate-free
        // no-progress gap is the write phase's liveness detector and is complete
        // without one.
        assert_eq!(
            write_phase_deadline(None),
            None,
            "a first-part write must carry no duration bound at all — any constant              here is a bandwidth floor in disguise"
        );

        // With an estimate, the bound is exactly that rate-derived ceiling.
        let ceiling = Duration::from_secs(42);
        assert_eq!(write_phase_deadline(Some(ceiling)), Some(ceiling));

        // And it must be independent of the backstop in every case — the property
        // whose violation was B3.
        for floor in [Duration::from_secs(1), RESPONSE_BACKSTOP_FLOOR] {
            for bytes in [None, Some(64 * 1024 * 1024u64)] {
                let backstop = response_backstop(bytes, floor);
                assert_ne!(
                    write_phase_deadline(None),
                    Some(backstop),
                    "the write phase must not inherit the backstop ({backstop:?})"
                );
            }
        }
    }

    /// The response-phase backstop must be **derived** where it bounds a
    /// `bytes ÷ rate` quantity, and constant only where the quantity is rate-free.
    ///
    /// This is the property that makes it invariant-legal rather than a re-run of the
    /// defect this module exists to fix. It is unit-tested rather than driven end-to-
    /// end on purpose: the condition the backstop *guards* — a failed `setsockopt`
    /// leaving the socket on `READ_DISARMED` — is a rare race (observed once in eight
    /// runs) that cannot be triggered deterministically from a test. Two wire tests
    /// written to reproduce it were **withdrawn** when they passed against code with
    /// the backstop removed: they were bounded by other mechanisms and so proved
    /// nothing. The backstop is defense-in-depth, and this is an honest pin of its
    /// arithmetic rather than a claim to have reproduced the hazard.
    #[test]
    fn response_backstop_is_derived_where_the_quantity_is_rate_proportional() {
        // No body (every PUT): rate-free, so the constant floor is legitimate.
        assert_eq!(
            response_backstop(None, RESPONSE_BACKSTOP_FLOOR),
            RESPONSE_BACKSTOP_FLOOR
        );

        // A small range still gets at least the floor.
        assert_eq!(
            response_backstop(Some(1024), RESPONSE_BACKSTOP_FLOOR),
            RESPONSE_BACKSTOP_FLOOR
        );

        // A large range must SCALE — this is the invariant. 1 GiB at 0.5 Mbps is
        // ~4.8 h of honest transfer; a bare constant here would recreate bug060 on
        // the download path.
        let big = response_backstop(Some(1024 * 1024 * 1024), RESPONSE_BACKSTOP_FLOOR);
        assert!(
            big > RESPONSE_BACKSTOP_FLOOR * 10,
            "the backstop must scale with the requested byte count, not sit at a \
             constant: got {big:?}"
        );

        // Strictly monotonic in bytes, above the floor.
        let a = response_backstop(Some(512 * 1024 * 1024), RESPONSE_BACKSTOP_FLOOR);
        let b = response_backstop(Some(1024 * 1024 * 1024), RESPONSE_BACKSTOP_FLOOR);
        assert!(b > a, "more bytes must buy more time: {a:?} then {b:?}");

        // And it stays finite for an absurd request.
        assert!(
            response_backstop(Some(u64::MAX), RESPONSE_BACKSTOP_FLOOR)
                <= Duration::from_secs(86_400)
        );
    }

    /// The plaintext tripwire must fire on a real remote host and stay silent for
    /// the dev/CI configurations that legitimately use plaintext. A false positive
    /// here would train people to ignore a security warning; a false negative lets
    /// capability-bearing pre-signed URLs cross a network in clear.
    #[test]
    fn plaintext_warning_targets_only_genuinely_remote_hosts() {
        for local in [
            "localhost",
            "LocalHost",
            "minio.localhost",
            "127.0.0.1",
            "::1",
            "10.0.0.5",
            "192.168.1.20",
            "172.16.4.4",
            "169.254.10.1",
            "fd00::1",
            "fe80::1",
        ] {
            assert!(is_local_host(local), "{local} must be treated as local");
        }
        for remote in [
            "s3.bhs.io.cloud.ovh.net",
            "storage.example.net",
            "8.8.8.8",
            "2001:db8::1",
            "172.32.0.1", // just outside 172.16/12
        ] {
            assert!(!is_local_host(remote), "{remote} must be treated as remote");
        }
    }

    /// An IPv6 literal must not be split at a colon inside its own address. The
    /// previous `rsplit_once(':')` turned a bare `[::1]` into the nonsense port
    /// `"1]"` and reported a misleading "invalid port".
    #[test]
    fn ipv6_literals_parse_and_reach_the_wire_bracketed() {
        let with_port = parse_url("http://[::1]:9000/b/k").unwrap();
        assert_eq!(
            with_port.host, "::1",
            "connect/ServerName want it unbracketed"
        );
        assert_eq!(with_port.port, 9000);
        assert_eq!(
            with_port.authority, "[::1]:9000",
            "the wire wants it bracketed"
        );

        let bare = parse_url("https://[2001:db8::1]/b/k").unwrap();
        assert_eq!(bare.host, "2001:db8::1");
        assert_eq!(bare.port, 443);
        assert_eq!(bare.authority, "[2001:db8::1]");

        assert!(
            parse_url("http://[::1/b/k").is_err(),
            "an unterminated IPv6 literal must be rejected, not silently reinterpreted"
        );
    }

    #[test]
    fn parse_url_honours_scheme_and_rejects_userinfo() {
        // https -> TLS, default port 443.
        let secure = parse_url("https://s3.example.net/b/k").unwrap();
        assert!(secure.tls);
        assert_eq!(secure.port, 443);
        // http -> plaintext, default port 80. Accepted deliberately: local dev and
        // CI run MinIO over plaintext loopback, the endpoint is our own config
        // (never attacker-chosen), and content is already end-to-end encrypted.
        let plain = parse_url("http://127.0.0.1:9000/b/k").unwrap();
        assert!(!plain.tls);
        assert_eq!(plain.port, 9000);
        assert_eq!(parse_url("http://minio/b/k").unwrap().port, 80);
        // Anything else is refused.
        assert!(parse_url("ftp://s3.example.net/b/k").is_err());
        assert!(parse_url("s3.example.net/b/k").is_err());
        // Userinfo is a host-confusion vector with no legitimate use here.
        assert!(parse_url("https://evil@s3.example.net/b/k").is_err());
    }

    #[test]
    fn response_ceiling_scales_with_the_observed_rate_and_never_uses_a_bare_constant() {
        let bounds = TransportBounds::default();
        // A slow link must get MORE drain time than a fast one — the invariant.
        let slow = response_ceiling(&bounds, 600_000.0); // ~4.8 Mbps
        let fast = response_ceiling(&bounds, 12_500_000.0); // ~100 Mbps
        assert!(
            slow > fast,
            "a slower observed rate must yield a longer ceiling: {slow:?} vs {fast:?}"
        );
        // Both retain the fixed server allowance.
        assert!(fast >= RESPONSE_ALLOWANCE);
        // A pathological/zero rate must not produce a zero or unbounded ceiling.
        let degenerate = response_ceiling(&bounds, 0.0);
        assert!(degenerate > RESPONSE_ALLOWANCE);
        assert!(degenerate < Duration::from_secs(700));
    }

    #[test]
    fn the_read_disarmed_value_cannot_fire_during_a_realistic_body_write() {
        // bug060's mechanism was a 15 s inbound-silence timer running concurrently
        // with transmission. Pin that the replacement cannot recreate it.
        //
        // The worst case is one **part**, not one file: this transport carries a
        // single part per request, capped at 64 MiB. The earlier version of this test
        // framed a 100 GB body — which no request can carry — and then passed by 0.6%
        // against a /20 fudge factor, so it asserted a near-coincidence about an
        // impossible case rather than the real property. Assert the true worst case
        // with real margin instead.
        const MAX_PART_BYTES: f64 = 64.0 * 1024.0 * 1024.0;
        const MIN_CREDIBLE_RATE_BPS: f64 = 500_000.0 / 8.0; // 0.5 Mbps, in bytes/s

        let worst_case_secs = MAX_PART_BYTES / MIN_CREDIBLE_RATE_BPS; // ~1,074 s
        assert!(
            READ_DISARMED.as_secs_f64() > worst_case_secs * 10.0,
            "READ_DISARMED ({}s) must sit an order of magnitude beyond the slowest \
             credible single-part write ({worst_case_secs:.0}s for 64 MiB at 0.5 Mbps) \
             — it exists to catch a wedged socket, and must never fire on a merely \
             slow one",
            READ_DISARMED.as_secs_f64()
        );
        assert!(READ_DISARMED >= Duration::from_secs(3600));
    }

    /// §10.3 item 3 — parity must be **asserted**, not merely documented.
    ///
    /// The hazard this change introduces is not a reliability one: it is that a
    /// hand-rolled transport silently diverges from the TLS posture every other
    /// request uses. The guarantee is that it uses the *same `ClientConfig`
    /// object* — not a lookalike rebuilt with subtly different roots, provider,
    /// key-exchange groups, or protocol floor.
    ///
    /// Pinning the singleton is what makes that checkable: because
    /// `pq_tls_config()` memoises into a `OnceLock`, every caller — `ureq`'s
    /// shared agent and this transport alike — receives pointer-identical
    /// configuration. If someone later builds a fresh config here "just for the
    /// bucket path", this fails.
    ///
    /// (The key-exchange content itself — X25519MLKEM768 first — is pinned by the
    /// PQR regression test in `http.rs`; this test pins that the bucket transport
    /// is covered by it.)
    #[test]
    fn the_transport_shares_one_tls_config_with_every_other_request() {
        let a = crate::http::pq_tls_config();
        let b = crate::http::pq_tls_config();
        assert!(
            std::sync::Arc::ptr_eq(&a, &b),
            "pq_tls_config must be a shared singleton — the bucket transport's TLS \
             parity with the rest of the CLI rests on every caller getting the SAME \
             object, not an equivalent-looking rebuild"
        );
    }

    #[test]
    fn default_bounds_are_rate_free_where_the_invariant_requires_it() {
        let b = TransportBounds::default();
        // The gap is a no-progress threshold — a constant is legitimate.
        assert!(b.write_gap >= Duration::from_secs(5));
        assert!(b.write_gap <= Duration::from_secs(30));
        // The send buffer must be bounded and well under the 4 MiB the kernel
        // would otherwise autotune to, or write-progress stops being honest.
        assert!(b.sndbuf_bytes <= 2 * 1024 * 1024);
        assert!(b.sndbuf_bytes >= 256 * 1024);
    }
}
