// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! The poll-based file-channel transport (Account-and-Kit spec §f.1; validated by
//! the S055 cross-runtime spike).
//!
//! A bind-mounted folder per PRSN *is* the channel — the only mechanism uniform
//! across Docker's shared VM and Apple `container`'s per-container VM. The
//! protocol rules, all from the spike (the only ones that survived both runtimes):
//!
//! - **One request/response file per op, with a unique name** — never overwrite a
//!   fixed file (sidesteps the VirtioFS stale-read hazard, docker/for-mac #7501).
//! - **Write-temp-then-atomic-rename** for every message — a reader never observes
//!   a partially-written file (`rename(2)` is atomic within a directory).
//! - **The reader fresh-opens; the AEAD tag is the integrity check** ([`crate::auth`]).
//!   A torn/garbage/forged read fails to open and is retried (client) or dropped
//!   (host) — never trusted.
//! - **Poll, never notify** — guest inotify does not cross Apple `container`'s VM
//!   boundary. The client polls tightly while a request is in flight; the host
//!   [`ChannelServer::serve`] loop polls adaptively (tight when busy, backing off
//!   when idle) so the LaunchAgent's idle CPU stays near zero.
//!
//! File naming in the channel folder: `<req_id>.req` (container→host),
//! `<req_id>.resp` (host→container), `*.tmp` (in-flight writes, ignored by readers).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::sleep;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::auth::{self, ChannelSecret, ReplayGuard};
use crate::error::{ChannelError, Result};
use crate::wire::{Op, Response};

/// How often the client checks for its response while one op is in flight. The
/// spike measured ~5 ms RTT at a 1 ms poll; a single op is short-lived, so the
/// client stays tight rather than backing off.
const CLIENT_POLL: Duration = Duration::from_millis(1);

/// A request the client has written and is awaiting a response for.
pub struct Pending {
    req_id: String,
    req_nonce: [u8; 12],
}

/// The in-container side: seals + writes requests, polls for + opens responses.
/// Holds no keys — every op is delegated to the host-signer.
pub struct ChannelClient {
    dir: PathBuf,
    channel_id: String,
    secret: ChannelSecret,
}

impl ChannelClient {
    pub fn new(
        dir: impl Into<PathBuf>,
        channel_id: impl Into<String>,
        secret: ChannelSecret,
    ) -> Self {
        Self {
            dir: dir.into(),
            channel_id: channel_id.into(),
            secret,
        }
    }

    /// Delegate one op and wait (up to `timeout`) for the response. The blocking
    /// convenience over [`Self::send`] + [`Self::await_response`].
    pub fn request(&self, op: &Op, timeout: Duration) -> Result<Response> {
        let pending = self.send(op)?;
        self.await_response(&pending, timeout)
    }

    /// Seal + atomically write a request; return its handle (non-blocking).
    pub fn send(&self, op: &Op) -> Result<Pending> {
        let req_id = new_req_id();
        let body = op.to_bytes()?;
        let frame = auth::seal_request(&self.secret, &self.channel_id, &req_id, &body);
        let req_nonce = auth::frame_nonce(&frame)?;
        write_atomic(&self.req_path(&req_id), &frame)?;
        Ok(Pending { req_id, req_nonce })
    }

    /// Poll for + open the response to a [`Pending`] request. On success, removes
    /// both channel files; on timeout, removes the request (so it can't linger or
    /// be replay-captured) and returns [`ChannelError::Timeout`].
    pub fn await_response(&self, pending: &Pending, timeout: Duration) -> Result<Response> {
        let resp_path = self.resp_path(&pending.req_id);
        let start = Instant::now();
        loop {
            match fs::read(&resp_path) {
                Ok(frame) => {
                    // A present file is whole (atomic rename). If the open fails it
                    // is either a transient stale view (retry) or a genuine bad
                    // frame (will time out) — never trusted, never fatal mid-wait.
                    if let Ok(body) = auth::open_response(
                        &self.secret,
                        &self.channel_id,
                        &pending.req_id,
                        &pending.req_nonce,
                        &frame,
                    ) {
                        let resp = Response::from_bytes(&body)?;
                        self.cleanup(&pending.req_id);
                        return Ok(resp);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {} // not ready yet
                Err(e) => return Err(ChannelError::Io(e)),
            }
            if start.elapsed() > timeout {
                self.cleanup(&pending.req_id);
                return Err(ChannelError::Timeout);
            }
            sleep(CLIENT_POLL);
        }
    }

    fn cleanup(&self, req_id: &str) {
        let _ = fs::remove_file(self.resp_path(req_id));
        let _ = fs::remove_file(self.req_path(req_id));
    }

    fn req_path(&self, req_id: &str) -> PathBuf {
        self.dir.join(format!("{req_id}.req"))
    }
    fn resp_path(&self, req_id: &str) -> PathBuf {
        self.dir.join(format!("{req_id}.resp"))
    }
}

/// The host side: scans the channel folder, authenticates + replay-checks each
/// request, dispatches it to a handler (the host-signer's SE execution), and
/// atomically writes the sealed response. One server per channel folder.
pub struct ChannelServer {
    dir: PathBuf,
    channel_id: String,
    secret: ChannelSecret,
    replay: ReplayGuard,
}

impl ChannelServer {
    pub fn new(
        dir: impl Into<PathBuf>,
        channel_id: impl Into<String>,
        secret: ChannelSecret,
    ) -> Self {
        Self {
            dir: dir.into(),
            channel_id: channel_id.into(),
            secret,
            replay: ReplayGuard::with_default_capacity(),
        }
    }

    /// Process every request file currently in the folder once. `handler` maps an
    /// authenticated [`Op`] to a [`Response`] (the host-signer's SE dispatch).
    /// Returns the number of requests **successfully answered** (a forged or
    /// replayed request is consumed but not answered — and not counted, so the
    /// adaptive [`Self::serve`] loop treats a forged-only pass as idle).
    pub fn poll_once<H: FnMut(Op) -> Response>(&mut self, handler: &mut H) -> Result<usize> {
        // Snapshot the request paths first, then process — so removing a `.req`
        // never perturbs an in-progress directory iteration.
        let mut requests: Vec<PathBuf> = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) == Some("req") {
                requests.push(path);
            }
        }

        let mut answered = 0;
        for path in requests {
            let Some(req_id) = path.file_stem().and_then(|s| s.to_str()).map(String::from) else {
                continue;
            };
            // A `.req` the client may have already cleaned up (timeout) just vanishes.
            let Ok(frame) = fs::read(&path) else {
                continue;
            };
            // Forged / replayed / malformed requests fail here and are dropped
            // silently (no response to one we cannot authenticate). The `.req` is
            // consumed below regardless, so it never piles up or is re-read.
            if let Ok(resp_frame) = self.process(&req_id, &frame, handler) {
                let _ = write_atomic(&self.resp_path(&req_id), &resp_frame);
                answered += 1;
            }
            let _ = fs::remove_file(&path);
        }
        Ok(answered)
    }

    /// Authenticate (open) first, *then* replay-check, then dispatch + seal the
    /// response. Opening first means an unauthenticated frame never reaches the
    /// replay set (no DoS by spamming random nonces).
    fn process<H: FnMut(Op) -> Response>(
        &mut self,
        req_id: &str,
        frame: &[u8],
        handler: &mut H,
    ) -> Result<Vec<u8>> {
        let req_nonce = auth::frame_nonce(frame)?;
        let body = auth::open_request(&self.secret, &self.channel_id, req_id, frame)?;
        self.replay.check_and_record(&req_nonce)?;
        let op = Op::from_bytes(&body)?;
        let response = handler(op);
        // The serialized response can carry the confidential `ecdh` Z; wipe its heap
        // buffer on drop (the decrypted request `body` is already `Zeroizing`, from
        // `open_request`). Defense-in-depth against same-user heap reuse.
        let resp_body = Zeroizing::new(response.to_bytes()?);
        Ok(auth::seal_response(
            &self.secret,
            &self.channel_id,
            req_id,
            &req_nonce,
            &resp_body,
        ))
    }

    /// Serve until `shutdown` is set, polling adaptively. The host-signer
    /// LaunchAgent's main loop.
    pub fn serve<H: FnMut(Op) -> Response>(
        &mut self,
        handler: &mut H,
        shutdown: &AtomicBool,
    ) -> Result<()> {
        let mut idle: u32 = 0;
        while !shutdown.load(Ordering::Relaxed) {
            if self.poll_once(handler)? > 0 {
                idle = 0;
                sleep(CLIENT_POLL);
            } else {
                idle = idle.saturating_add(1);
                sleep(idle_backoff(idle));
            }
        }
        Ok(())
    }

    fn resp_path(&self, req_id: &str) -> PathBuf {
        self.dir.join(format!("{req_id}.resp"))
    }
}

/// Idle poll backoff: 2 ms → a 50 ms ceiling. The first busy pass is serviced
/// immediately (the caller polls again at [`CLIENT_POLL`]); this only governs the
/// quiet stretches, keeping the LaunchAgent's idle CPU near zero.
fn idle_backoff(idle_rounds: u32) -> Duration {
    let ms = (1u64 << idle_rounds.min(6)).min(50);
    Duration::from_millis(ms)
}

/// A unique request id (16 CSPRNG bytes, base64url) — the filename stem. Unique per
/// op is the VirtioFS stale-read mitigation (never reuse a name).
fn new_req_id() -> String {
    let mut raw = [0u8; 16];
    OsRng.fill_bytes(&mut raw);
    URL_SAFE_NO_PAD.encode(raw)
}

/// Write `bytes` to `path` atomically: write a sibling `<path>.tmp`, then rename it
/// over `path` (atomic within the directory). A reader sees either nothing or the
/// whole file, never a partial write.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{OpErr, OpOk};
    use std::sync::Arc;

    const SECRET: [u8; 32] = [7u8; 32];
    const CH: &str = "hlin-ai";

    fn client(dir: &Path) -> ChannelClient {
        ChannelClient::new(dir, CH, ChannelSecret::from_bytes(SECRET))
    }
    fn server(dir: &Path) -> ChannelServer {
        ChannelServer::new(dir, CH, ChannelSecret::from_bytes(SECRET))
    }

    /// A handler that signs (returns a canned 64-byte sig) and reports exists=true.
    fn handler(op: Op) -> Response {
        match op {
            Op::Sign { .. } => Response::Ok(OpOk::Sign {
                signature: vec![0xab; 64],
            }),
            Op::Exists { .. } => Response::Ok(OpOk::Exists { exists: true }),
            _ => Response::Err(OpErr {
                code: "unsupported".into(),
                message: "test handler".into(),
            }),
        }
    }

    #[test]
    fn single_threaded_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let c = client(dir.path());
        let mut s = server(dir.path());

        let op = Op::Sign {
            label: "hlin-ai-signing".into(),
            msg: b"sign me".to_vec(),
        };
        let pending = c.send(&op).unwrap();
        assert_eq!(s.poll_once(&mut { handler }).unwrap(), 1);
        let resp = c.await_response(&pending, Duration::from_secs(2)).unwrap();
        assert_eq!(
            resp,
            Response::Ok(OpOk::Sign {
                signature: vec![0xab; 64]
            })
        );
        // Both files cleaned up.
        assert!(fs::read_dir(dir.path()).unwrap().next().is_none());
    }

    #[test]
    fn handler_error_propagates() {
        let dir = tempfile::tempdir().unwrap();
        let c = client(dir.path());
        let mut s = server(dir.path());
        let pending = c
            .send(&Op::Meta {
                label: "hlin-ai-kem".into(),
            })
            .unwrap();
        s.poll_once(&mut { handler }).unwrap();
        let resp = c.await_response(&pending, Duration::from_secs(2)).unwrap();
        assert!(matches!(resp, Response::Err(_)));
    }

    #[test]
    fn timeout_when_no_server() {
        let dir = tempfile::tempdir().unwrap();
        let c = client(dir.path());
        let pending = c
            .send(&Op::Exists {
                label: "hlin-ai-signing".into(),
            })
            .unwrap();
        let err = c
            .await_response(&pending, Duration::from_millis(50))
            .unwrap_err();
        assert!(matches!(err, ChannelError::Timeout));
        // The request was cleaned up on timeout.
        assert!(!c.req_path(&pending.req_id).exists());
    }

    #[test]
    fn forged_request_is_dropped_without_a_response() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = server(dir.path());
        // A garbage `.req` (not sealed under the secret).
        write_atomic(&dir.path().join("forged.req"), b"not a real frame").unwrap();
        assert_eq!(s.poll_once(&mut { handler }).unwrap(), 0);
        // Consumed (removed), and no response written.
        assert!(!dir.path().join("forged.req").exists());
        assert!(!dir.path().join("forged.resp").exists());
    }

    #[test]
    fn frame_replayed_under_a_different_name_fails_the_aad_binding() {
        // A captured frame re-dropped under a DIFFERENT filename is rejected by the AAD
        // — which binds the req_id (= the filename) — NOT the ReplayGuard. (The
        // same-filename replay, which the ReplayGuard catches, is the test below.)
        let dir = tempfile::tempdir().unwrap();
        let c = client(dir.path());
        let mut s = server(dir.path());
        let pending = c
            .send(&Op::Exists {
                label: "hlin-ai-signing".into(),
            })
            .unwrap();
        let frame = fs::read(c.req_path(&pending.req_id)).unwrap();
        assert_eq!(s.poll_once(&mut { handler }).unwrap(), 1); // first time: answered
        // Re-drop the identical frame under a DIFFERENT filename → AAD req_id mismatch.
        write_atomic(&dir.path().join("replay.req"), &frame).unwrap();
        assert_eq!(s.poll_once(&mut { handler }).unwrap(), 0); // dropped (AAD mismatch)
        assert!(!dir.path().join("replay.resp").exists());
    }

    #[test]
    fn replayed_request_under_the_same_name_is_caught_by_the_replay_guard() {
        // The genuine ReplayGuard exercise: re-drop the SAME frame under the SAME
        // filename, so the AAD (req_id = filename) still verifies — the only thing left
        // to reject it is the nonce-set ReplayGuard. (Distinct from the AAD-binding test
        // above, which a different filename trips before the guard is reached.)
        let dir = tempfile::tempdir().unwrap();
        let c = client(dir.path());
        let mut s = server(dir.path());
        let pending = c
            .send(&Op::Exists {
                label: "hlin-ai-signing".into(),
            })
            .unwrap();
        let req_path = c.req_path(&pending.req_id);
        let frame = fs::read(&req_path).unwrap();
        assert_eq!(s.poll_once(&mut { handler }).unwrap(), 1); // first time: answered
        // Re-drop the identical frame under the SAME filename (AAD still matches).
        write_atomic(&req_path, &frame).unwrap();
        assert_eq!(
            s.poll_once(&mut { handler }).unwrap(),
            0,
            "the replayed nonce must be rejected by the ReplayGuard, not the AAD binding"
        );
    }

    #[test]
    fn blocking_request_against_serve_loop() {
        let dir = tempfile::tempdir().unwrap();
        let c = client(dir.path());
        let mut s = server(dir.path());
        let shutdown = Arc::new(AtomicBool::new(false));

        let server_shutdown = Arc::clone(&shutdown);
        let server_thread = std::thread::spawn(move || {
            let mut h = handler;
            let _ = s.serve(&mut h, &server_shutdown);
        });

        let resp = c
            .request(
                &Op::Sign {
                    label: "hlin-ai-signing".into(),
                    msg: b"x".to_vec(),
                },
                Duration::from_secs(2),
            )
            .unwrap();
        assert_eq!(
            resp,
            Response::Ok(OpOk::Sign {
                signature: vec![0xab; 64]
            })
        );

        shutdown.store(true, Ordering::Relaxed);
        server_thread.join().unwrap();
    }
}
