// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Server-signed attestation verification response canonical bytes (Envelope §9).
//!
//! When a verifier calls `GET /v1/attestations/{id}/verification`, the server
//! returns a signed JSON statement. The signature covers the `attestation` object
//! plus `server_key_id` and `signed_at` — and **only** those (the top-level
//! `server_signature` is a sibling, necessarily excluded; the inline log receipts
//! are each independently signed per §10a, not covered here). This is the single
//! builder shared by the server signer and the (B6) `signet attestation-verify`
//! CLI, so both produce identical bytes.

use serde_json::Value;

use crate::error::Result;
use crate::jcs;

/// The domain-separation prefix for verification-response signatures (Envelope §9).
const VERIFY_PREFIX: &[u8] = b"signet-server-attestation-verify-v1\n";

/// The FIPS 204 context for the ML-DSA-87 half of the server's §9 response
/// dual-signature (PQR Spec §8 point 4 — "the existing Envelope-Format
/// domain-separation prefix", item 7c). The ctx is the purpose LABEL — the
/// prefix name WITHOUT the trailing `\n` (the newline is `M`'s byte-framing
/// artifact, not part of the label). Both halves sign the identical `M`
/// ([`verification_signing_input`], §8.7); the ML-DSA half takes this as the
/// FIPS 204 context *parameter*, never prepended. Pinned by the §11.5b KAT.
pub const SERVER_VERIFY_MLDSA_CTX: &[u8] = b"signet-server-attestation-verify-v1";

/// The bytes the server ES256-signs to produce a verification response's
/// `server_signature` (Envelope §9):
///
/// ```text
/// "signet-server-attestation-verify-v1\n"
///   || JCS(attestation)
///   || "\n" || server_key_id
///   || "\n" || str(signed_at)
/// ```
///
/// `attestation` is the response's signed `attestation` object (its keys are
/// sorted by JCS, so the caller's field order is irrelevant). `server_key_id` is
/// the hyphenated-lowercase UUID of the `server_keys` row; `signed_at` is unix
/// seconds. No trailing newline.
pub fn verification_signing_input(
    attestation: &Value,
    server_key_id: &str,
    signed_at: i64,
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(VERIFY_PREFIX.len() + 512);
    out.extend_from_slice(VERIFY_PREFIX);
    out.extend_from_slice(&jcs::to_canonical_bytes(attestation)?);
    out.push(b'\n');
    out.extend_from_slice(server_key_id.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(signed_at.to_string().as_bytes());
    Ok(out)
}

/// The FIPS 204 context for the ML-DSA-87 half of the per-request
/// dual-signature (PQR Spec §8 point 4 — item 7b). Both halves sign the
/// identical SIGNET-V1 canonical bytes (Envelope §6.2, built by
/// `signing::signet_v1_canonical_bytes` — its `SIGNET-V1` first element is the
/// surface's domain prefix); the ML-DSA half takes this as the FIPS 204 context
/// *parameter*, never prepended. Shared by the `signet` CLI signer and the
/// server verifier so the two can never drift. Pinned by the §11.5b KAT.
pub const REQUEST_MLDSA_CTX: &[u8] = b"signet:req:v1";

/// The ML-DSA-87 signature length (FIPS 204): every dual-signature's second
/// half is exactly this long.
pub const MLDSA87_SIG_LEN: usize = 4627;

/// The per-request dual-signature wire length (PQR Spec §8 point 1): the
/// fixed-width concatenation `sig_es256 (64 B, raw r‖s) ‖ sig_mldsa87 (4627 B)`.
/// Inside a dual the ES256 half is ALWAYS raw — DER is a classical-signature
/// wire form only — so the split needs no framing and the total length (4691)
/// is unambiguous against both classical forms (64 raw / ≤72 DER).
pub const REQUEST_DUAL_SIG_LEN: usize = 64 + MLDSA87_SIG_LEN;

/// The domain-separation prefix of the enrollment proof-of-possession signing
/// base (PQR item 7a — Enrollment-Ceremony ops doc §3). Enrollment PoP
/// signatures can never be confused with any other ES256/ML-DSA surface
/// (requests, receipts, responses each carry their own prefix).
pub const ENROLL_POP_PREFIX: &[u8] = b"signet-enroll-pop-v1\n";

/// The FIPS 204 context for identity/enrollment dual-signs (PQR Spec §8
/// point 4) — supplied as the FIPS 204 context *parameter*, never prepended.
pub const ENROLL_POP_MLDSA_CTX: &[u8] = b"signet:attest:v1";

/// The message bytes `M` BOTH enrollment-PoP halves sign (PQR Spec §8.7 —
/// identical bytes for the `ES256` and `ML-DSA-87` halves): the fixed prefix
/// followed by the raw 32-byte server challenge. One builder shared by the
/// server verifier and the `signet enroll` client, so both produce identical
/// bytes.
pub fn enroll_pop_signing_base(challenge: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(ENROLL_POP_PREFIX.len() + challenge.len());
    m.extend_from_slice(ENROLL_POP_PREFIX);
    m.extend_from_slice(challenge);
    m
}
