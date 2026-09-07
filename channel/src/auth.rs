// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! The per-PRSN-secret sealed channel (Account-and-Kit spec §f.4) — the
//! security-critical core of the host↔container delegation path.
//!
//! Every message crossing the (same-user-readable) channel folder is
//! authenticated-**encrypted** under the channel's per-PRSN secret, so a rogue
//! same-user process can neither forge a request the host-signer accepts, nor read
//! a confidential result (the `ecdh` shared secret Z), nor feed the container a
//! forged response. See the crate-level threat model for why this is encryption,
//! not a bare MAC.
//!
//! # Construction
//!
//! - **Keys.** Two AES-256-GCM keys are derived from the 256-bit per-PRSN secret
//!   via HKDF-SHA-256 — one per *direction* (`request` = container→host,
//!   `response` = host→container). Per-direction keys mean a request and a response
//!   can never share a `(key, nonce)` pair even if their random nonces collide
//!   (GCM nonce reuse under one key is catastrophic).
//! - **Frame.** `nonce(12) ‖ AES-256-GCM(key, nonce, body, AAD)`. The nonce is a
//!   fresh 12-byte CSPRNG draw per message and rides in the clear (nonces are not
//!   secret); the ciphertext carries the 16-byte GCM tag.
//! - **AAD (length-prefixed, domain-separated).** A request binds
//!   `DOMAIN_REQ ‖ version ‖ LP(channel_id) ‖ LP(req_id)`; a response additionally
//!   binds `‖ LP(request_nonce)` — tying each response to the exact request it
//!   answers. Length-prefixing (`u32_be(len) ‖ bytes`) makes the concatenation
//!   unambiguous (no field-boundary confusion). The distinct `DOMAIN_*` tag is
//!   belt-and-suspenders on top of the per-direction key separation.
//! - **Replay.** A fresh nonce per request plus a host-side per-channel
//!   [`ReplayGuard`]: the host opens (authenticates) a request first, then records
//!   its nonce, rejecting a re-submitted (captured) request. Responses need no
//!   separate guard — they are AAD-bound to the request nonce the client is waiting
//!   on, so a stale/foreign response fails to open.
//!
//! No raw crypto here: AES-256-GCM and HKDF go through `signet-crypto`; this module
//! owns the composition (key derivation labels, the frame layout, the AAD).

use std::collections::{HashSet, VecDeque};

use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{ChannelError, Result};
use crate::wire::PROTOCOL_VERSION;

/// The byte length of the per-PRSN secret.
pub const SECRET_LEN: usize = 32;

/// The GCM nonce length (96-bit, the AES-256-GCM standard nonce size).
const NONCE_LEN: usize = 12;

/// HKDF `info` labels — distinct per direction so the request and response keys
/// differ (the load-bearing separation; see the module doc).
const REQUEST_KEY_INFO: &[u8] = b"signet-channel/v1/request-key";
const RESPONSE_KEY_INFO: &[u8] = b"signet-channel/v1/response-key";

/// AAD domain tags — distinct per direction (belt-and-suspenders over the keys).
const DOMAIN_REQUEST: &[u8] = b"signet-channel/v1/request";
const DOMAIN_RESPONSE: &[u8] = b"signet-channel/v1/response";

/// The per-PRSN shared secret (256-bit) — the channel's trust root. Provisioned
/// into the container's *private* filesystem at container-creation and registered
/// host-side (`channel → {PRSN, key-labels, secret}`); it never sits in the
/// host-visible channel folder. Zeroized on drop; `Debug` is redacted.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ChannelSecret {
    bytes: [u8; SECRET_LEN],
}

impl ChannelSecret {
    /// Adopt existing secret bytes (the host registry / the container's provisioned
    /// material).
    pub fn from_bytes(bytes: [u8; SECRET_LEN]) -> Self {
        Self { bytes }
    }

    /// Draw a fresh secret from the OS CSPRNG (at container-creation).
    pub fn generate() -> Self {
        let mut bytes = [0u8; SECRET_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// The raw secret bytes — for provisioning into the container + the host
    /// registry. Handle with care; the caller must not log or persist these in the
    /// channel folder.
    pub fn as_bytes(&self) -> &[u8; SECRET_LEN] {
        &self.bytes
    }
}

impl std::fmt::Debug for ChannelSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ChannelSecret(<redacted>)")
    }
}

/// Seal a **request** body (container→host). Infallible (the underlying GCM seal
/// cannot fail for a valid key+nonce). The returned frame is `nonce ‖ ct‖tag`.
pub fn seal_request(
    secret: &ChannelSecret,
    channel_id: &str,
    req_id: &str,
    body: &[u8],
) -> Vec<u8> {
    let key = derive_key(secret, REQUEST_KEY_INFO);
    let aad = request_aad(channel_id, req_id);
    seal_with(&key, &aad, body)
}

/// Open a **request** frame (host side). [`ChannelError::Auth`] on any failure
/// (wrong secret / tamper / wrong channel or req_id binding).
pub fn open_request(
    secret: &ChannelSecret,
    channel_id: &str,
    req_id: &str,
    frame: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let key = derive_key(secret, REQUEST_KEY_INFO);
    let aad = request_aad(channel_id, req_id);
    open_with(&key, &aad, frame)
}

/// Seal a **response** body (host→container), bound to the request's nonce.
pub fn seal_response(
    secret: &ChannelSecret,
    channel_id: &str,
    req_id: &str,
    request_nonce: &[u8; NONCE_LEN],
    body: &[u8],
) -> Vec<u8> {
    let key = derive_key(secret, RESPONSE_KEY_INFO);
    let aad = response_aad(channel_id, req_id, request_nonce);
    seal_with(&key, &aad, body)
}

/// Open a **response** frame (container side), verifying it answers the request
/// whose `request_nonce` is supplied. [`ChannelError::Auth`] on any failure.
pub fn open_response(
    secret: &ChannelSecret,
    channel_id: &str,
    req_id: &str,
    request_nonce: &[u8; NONCE_LEN],
    frame: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let key = derive_key(secret, RESPONSE_KEY_INFO);
    let aad = response_aad(channel_id, req_id, request_nonce);
    open_with(&key, &aad, frame)
}

/// The 12-byte nonce at the head of a frame. The host reads a request's nonce to
/// (a) check it against the [`ReplayGuard`] and (b) bind the response's AAD; the
/// client reads its own request frame's nonce to open the matching response.
pub fn frame_nonce(frame: &[u8]) -> Result<[u8; NONCE_LEN]> {
    if frame.len() < NONCE_LEN {
        return Err(ChannelError::MalformedFrame);
    }
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&frame[..NONCE_LEN]);
    Ok(nonce)
}

// ── internals ────────────────────────────────────────────────────────────────

/// HKDF-SHA-256 (empty salt) the per-PRSN secret into a direction key. Infallible
/// for a 32-byte output (HKDF only errors past 255×32 bytes). The intermediate
/// OKM is zeroized; the returned key is `Zeroizing`.
fn derive_key(secret: &ChannelSecret, info: &[u8]) -> Zeroizing<[u8; 32]> {
    let okm = Zeroizing::new(
        signet_crypto::kdf::hkdf_sha256(secret.as_bytes(), &[], info, 32)
            .expect("HKDF-SHA-256 with a 32-byte output is infallible"),
    );
    let mut key = [0u8; 32];
    key.copy_from_slice(&okm);
    Zeroizing::new(key)
}

fn seal_with(key: &[u8; 32], aad: &[u8], body: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let ct = signet_crypto::aead::seal(key, &nonce, body, aad)
        .expect("AES-256-GCM seal is infallible for a valid key + nonce");
    let mut frame = Vec::with_capacity(NONCE_LEN + ct.len());
    frame.extend_from_slice(&nonce);
    frame.extend_from_slice(&ct);
    frame
}

fn open_with(key: &[u8; 32], aad: &[u8], frame: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if frame.len() < NONCE_LEN {
        return Err(ChannelError::MalformedFrame);
    }
    let (nonce_bytes, ct) = frame.split_at(NONCE_LEN);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(nonce_bytes);
    // The decrypted plaintext is returned `Zeroizing`: a response body carries the
    // confidential `ecdh` shared secret Z, so its heap buffer is wiped on drop
    // rather than left for a later same-user allocation to read (defense-in-depth;
    // same-process disclosure is the channel's conceded threat-model residual).
    signet_crypto::aead::open(key, &nonce, ct, aad)
        .map(Zeroizing::new)
        .map_err(|_| ChannelError::Auth)
}

/// `u32_be(len) ‖ bytes` — unambiguous field framing for the AAD.
fn push_lp(buf: &mut Vec<u8>, field: &[u8]) {
    buf.extend_from_slice(&(field.len() as u32).to_be_bytes());
    buf.extend_from_slice(field);
}

fn request_aad(channel_id: &str, req_id: &str) -> Vec<u8> {
    let mut aad = Vec::new();
    push_lp(&mut aad, DOMAIN_REQUEST);
    aad.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    push_lp(&mut aad, channel_id.as_bytes());
    push_lp(&mut aad, req_id.as_bytes());
    aad
}

fn response_aad(channel_id: &str, req_id: &str, request_nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let mut aad = Vec::new();
    push_lp(&mut aad, DOMAIN_RESPONSE);
    aad.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    push_lp(&mut aad, channel_id.as_bytes());
    push_lp(&mut aad, req_id.as_bytes());
    push_lp(&mut aad, request_nonce);
    aad
}

/// Per-channel replay guard: a bounded set of request nonces already served on a
/// channel. Call [`ReplayGuard::check_and_record`] **after** [`open_request`]
/// succeeds, so unauthenticated frames never enter the set (no DoS-by-spamming
/// random nonces).
///
/// The bound is an eviction window, not a perfect history — the realistic replay
/// is a *recently* captured request file re-dropped into the folder (the files are
/// ephemeral), which the window covers. The host-signer owns synchronization (its
/// per-channel poll loop is single-consumer).
pub struct ReplayGuard {
    seen: HashSet<[u8; NONCE_LEN]>,
    order: VecDeque<[u8; NONCE_LEN]>,
    capacity: usize,
}

impl ReplayGuard {
    /// A guard holding up to `capacity` recent nonces (must be ≥ 1).
    pub fn new(capacity: usize) -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
            capacity: capacity.max(1),
        }
    }

    /// The default eviction window (4096 recent request nonces).
    pub fn with_default_capacity() -> Self {
        Self::new(4096)
    }

    /// Record a freshly-authenticated request nonce. [`ChannelError::Replay`] if it
    /// was already in the window (a replayed request).
    pub fn check_and_record(&mut self, nonce: &[u8; NONCE_LEN]) -> Result<()> {
        if self.seen.contains(nonce) {
            return Err(ChannelError::Replay);
        }
        if self.order.len() >= self.capacity
            && let Some(evicted) = self.order.pop_front()
        {
            self.seen.remove(&evicted);
        }
        self.seen.insert(*nonce);
        self.order.push_back(*nonce);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret() -> ChannelSecret {
        ChannelSecret::from_bytes([7u8; SECRET_LEN])
    }

    const CH: &str = "hlin-ai";
    const REQ: &str = "req-abc123";

    #[test]
    fn request_roundtrips() {
        let s = secret();
        let body = b"the-request-body";
        let frame = seal_request(&s, CH, REQ, body);
        assert_eq!(open_request(&s, CH, REQ, &frame).unwrap().as_slice(), body);
    }

    #[test]
    fn response_roundtrips_bound_to_request_nonce() {
        let s = secret();
        let req_frame = seal_request(&s, CH, REQ, b"req");
        let req_nonce = frame_nonce(&req_frame).unwrap();
        let body = b"the-response-body-with-Z";
        let resp = seal_response(&s, CH, REQ, &req_nonce, body);
        assert_eq!(
            open_response(&s, CH, REQ, &req_nonce, &resp)
                .unwrap()
                .as_slice(),
            body
        );
    }

    #[test]
    fn wrong_secret_fails_both_directions() {
        let s = secret();
        let other = ChannelSecret::from_bytes([9u8; SECRET_LEN]);
        let req = seal_request(&s, CH, REQ, b"x");
        assert!(matches!(
            open_request(&other, CH, REQ, &req),
            Err(ChannelError::Auth)
        ));
        let n = frame_nonce(&req).unwrap();
        let resp = seal_response(&s, CH, REQ, &n, b"y");
        assert!(matches!(
            open_response(&other, CH, REQ, &n, &resp),
            Err(ChannelError::Auth)
        ));
    }

    #[test]
    fn tampered_frame_fails() {
        let s = secret();
        let frame = seal_request(&s, CH, REQ, b"payload");
        // Flip a ciphertext/tag byte.
        let mut ct_tampered = frame.clone();
        let last = ct_tampered.len() - 1;
        ct_tampered[last] ^= 0x01;
        assert!(matches!(
            open_request(&s, CH, REQ, &ct_tampered),
            Err(ChannelError::Auth)
        ));
        // Flip a nonce byte.
        let mut nonce_tampered = frame.clone();
        nonce_tampered[0] ^= 0x01;
        assert!(matches!(
            open_request(&s, CH, REQ, &nonce_tampered),
            Err(ChannelError::Auth)
        ));
    }

    #[test]
    fn wrong_channel_or_req_id_fails() {
        let s = secret();
        let frame = seal_request(&s, CH, REQ, b"x");
        assert!(matches!(
            open_request(&s, "other-ai", REQ, &frame),
            Err(ChannelError::Auth)
        ));
        assert!(matches!(
            open_request(&s, CH, "req-different", &frame),
            Err(ChannelError::Auth)
        ));
    }

    #[test]
    fn response_with_wrong_request_nonce_fails() {
        let s = secret();
        let req_frame = seal_request(&s, CH, REQ, b"req");
        let req_nonce = frame_nonce(&req_frame).unwrap();
        let resp = seal_response(&s, CH, REQ, &req_nonce, b"resp");
        let wrong_nonce = [0u8; NONCE_LEN];
        assert!(matches!(
            open_response(&s, CH, REQ, &wrong_nonce, &resp),
            Err(ChannelError::Auth)
        ));
    }

    #[test]
    fn direction_keys_are_separated() {
        // A request frame must not open as a response (distinct HKDF keys), even
        // with otherwise-matching context.
        let s = secret();
        let req_frame = seal_request(&s, CH, REQ, b"x");
        let n = frame_nonce(&req_frame).unwrap();
        assert!(matches!(
            open_response(&s, CH, REQ, &n, &req_frame),
            Err(ChannelError::Auth)
        ));
    }

    #[test]
    fn malformed_frame_is_rejected() {
        let s = secret();
        assert!(matches!(
            open_request(&s, CH, REQ, &[0u8; 5]),
            Err(ChannelError::MalformedFrame)
        ));
        assert!(matches!(
            frame_nonce(&[0u8; 5]),
            Err(ChannelError::MalformedFrame)
        ));
    }

    #[test]
    fn each_seal_uses_a_fresh_nonce() {
        let s = secret();
        let a = seal_request(&s, CH, REQ, b"same");
        let b = seal_request(&s, CH, REQ, b"same");
        assert_ne!(a, b, "two seals of the same body must differ (fresh nonce)");
        assert_ne!(frame_nonce(&a).unwrap(), frame_nonce(&b).unwrap());
    }

    #[test]
    fn replay_guard_rejects_duplicates_and_evicts() {
        let mut g = ReplayGuard::new(2);
        let a = [1u8; NONCE_LEN];
        let b = [2u8; NONCE_LEN];
        let c = [3u8; NONCE_LEN];
        assert!(g.check_and_record(&a).is_ok());
        assert!(matches!(g.check_and_record(&a), Err(ChannelError::Replay)));
        assert!(g.check_and_record(&b).is_ok());
        // Adding c evicts a (window = 2).
        assert!(g.check_and_record(&c).is_ok());
        // a was evicted → accepted again; c is still in-window → rejected.
        assert!(g.check_and_record(&a).is_ok());
        assert!(matches!(g.check_and_record(&c), Err(ChannelError::Replay)));
    }

    #[test]
    fn secret_debug_is_redacted() {
        let s = secret();
        assert_eq!(format!("{s:?}"), "ChannelSecret(<redacted>)");
    }
}
