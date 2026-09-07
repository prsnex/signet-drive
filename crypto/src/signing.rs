// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! SIGNET-V1 per-request canonical bytes (Envelope §6.2 / Strawman v09 §4 /
//! test-vector Cat 03).
//!
//! Every PRSN API request is ECDSA-signed (`ES256`) over a deterministic,
//! line-based string built from the request's method, path-with-query, body
//! hash, timestamp, nonce, and signing-key fingerprint. The signer (the `signet`
//! CLI) and the server's verifier MUST build identical bytes or signatures will
//! not verify — so this one function is the single source of truth for both.
//!
//! ```text
//! SIGNET-V1
//! <HTTP method, uppercase>
//! <request path including query string, as-sent>
//! <lowercase hex SHA-256 of request body bytes>
//! <Signet-Timestamp value>
//! <Signet-Nonce value>
//! <Signet-Fingerprint value>
//! ```
//!
//! Seven elements, joined by a single `LF` (`0x0a`), **no trailing newline**.
//! The body hash is computed here from the raw body bytes (there is no
//! `Signet-Body-Hash` header to trust); the timestamp, nonce, and fingerprint
//! are taken **verbatim** — the exact header values sent and received — so the
//! two sides agree byte-for-byte even when a value is non-canonically formatted.
//! Element-level conventions (uppercase method, no-leading-zero timestamp,
//! 32-hex nonce, 64-hex fingerprint) are construction/validation rules enforced
//! at the signer and the verifier, not here.

use crate::hash;

/// The literal version marker — element 1 (9 ASCII bytes).
pub const SIGNET_V1: &str = "SIGNET-V1";

/// Build the SIGNET-V1 canonical bytes to sign for one request. `body` is the
/// raw request body (empty slice for a bodyless request → the SHA-256 of zero
/// bytes); `timestamp`, `nonce`, and `fingerprint` are the header values
/// verbatim. The result is the message passed to `ecdsa::sign_es256` /
/// `ecdsa::verify_es256` (which apply the `ES256` SHA-256 internally).
pub fn signet_v1_canonical_bytes(
    method: &str,
    path_and_query: &str,
    body: &[u8],
    timestamp: &str,
    nonce: &str,
    fingerprint: &str,
) -> Vec<u8> {
    let body_hash = hex::encode(hash::sha256(body));
    [
        SIGNET_V1,
        method,
        path_and_query,
        body_hash.as_str(),
        timestamp,
        nonce,
        fingerprint,
    ]
    .join("\n")
    .into_bytes()
}
