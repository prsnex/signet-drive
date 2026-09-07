// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! JSON Canonicalization Scheme (RFC 8785 / JCS) — the canonical-JSON bytes that
//! the B4 signatures are computed over: the server-signed attestation
//! verification response (Envelope §9), the transparency-log receipt (§10a), and
//! the attestation-ceremony operation-bound challenge (§6.1,
//! `SHA-256(JCS(challenge_context))`). This is the single canonicalization
//! chokepoint shared by the server signer and the (B6) `signet` CLI verifier, so
//! both produce byte-identical signing input — and any third-party verifier that
//! follows RFC 8785 agrees on the same bytes.
//!
//! Backed by `serde_jcs`. **Domain constraint (load-bearing, ENFORCED):** every
//! JSON object SigDrive signs uses **plain ASCII keys — no control characters,
//! no `"` or `\`** — and **i64/u64 (never i128/u128 or arbitrary-precision)
//! numbers**. Within that domain serde_jcs is RFC-8785-exact: it delegates
//! string escaping to serde_json (the required short escapes + raw UTF-8, `/`
//! left unescaped), formats integers minimally, and formats floats via
//! ECMAScript `ryu_js`. Outside it, known gaps bite: serde_jcs orders object
//! keys by their ESCAPED serialized form, not the raw code units RFC 8785
//! requires — which diverges not only for non-ASCII keys but for any ASCII key
//! containing an escape-class character (found empirically by the S112
//! differential corpus: `{"\t":_, "0":_}` sorts `0` first here, `\t` first
//! under the RFC and the web port) — and it panics on i128/u128. SigDrive's
//! protocol never produces such keys (all keys are fixed snake_case protocol
//! identifiers), and `to_canonical_bytes` REFUSES them rather than trusting
//! that by convention: the divergent input is unrepresentable, both lineages
//! fail closed on it (the web port enforces the same bound). Keeping this the
//! one chokepoint means a future swap to a fully-compliant crate is a
//! single-file change. KAT'd in `tests/jcs.rs` + the committed cross-impl
//! golden (named cases + the seeded differential corpus).

use serde_json::Value;

use crate::error::{CryptoError, Result};
use crate::hash;

/// The enforced key domain: plain ASCII, no control characters, no `"` or
/// `\` — exactly the range where serde_jcs's escaped-form key ordering agrees
/// with RFC 8785's raw code-unit ordering (and with the web port).
fn key_in_domain(key: &str) -> bool {
    key.bytes()
        .all(|b| (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\')
}

fn check_keys(value: &Value) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (key, v) in map {
                if !key_in_domain(key) {
                    return Err(CryptoError::InvalidInput(
                        "jcs: object key outside the enforced domain (plain \
                         ASCII, no control chars, no quote/backslash)",
                    ));
                }
                check_keys(v)?;
            }
            Ok(())
        }
        Value::Array(items) => items.iter().try_for_each(check_keys),
        _ => Ok(()),
    }
}

/// Canonical RFC 8785 (JCS) bytes for `value`. See the module-level domain
/// constraint (enforced here — out-of-domain keys are refused, never
/// canonicalized divergently).
pub fn to_canonical_bytes(value: &Value) -> Result<Vec<u8>> {
    check_keys(value)?;
    serde_jcs::to_vec(value).map_err(|_| CryptoError::InvalidInput("jcs canonicalization"))
}

/// `SHA-256(JCS(value))` — the attestation-ceremony operation-bound challenge
/// (Envelope §6.1). The Guardian's passkey signs over this, binding the assertion
/// to the exact operation + its parameters (forensically stronger than a random
/// nonce: the server cannot later claim the gesture authorized a different op).
pub fn digest(value: &Value) -> Result<[u8; 32]> {
    Ok(hash::sha256(&to_canonical_bytes(value)?))
}
