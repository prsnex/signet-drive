// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! HKDF-SHA-256 (RFC 5869).
//!
//! Used for the human-side wrap-key derivation (Envelope §8.2:
//! `info = "signet-drive-kem-wrap-v1"`, empty salt) and the multipart per-chunk
//! IV derivation (§4.2). The `ECDH-ES+A256KW` KEK uses Concat-KDF (NIST SP
//! 800-56A), *not* HKDF — that is a separate construction and lands with the
//! wrap-chain composition.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{CryptoError, Result};

/// HKDF-SHA-256 extract-then-expand (RFC 5869). `salt` may be empty (the §8.2
/// derivation uses an empty salt); `info` is the context label; returns `out_len`
/// bytes. `out_len` must be ≤ 255 × 32 = 8160.
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; out_len];
    hk.expand(info, &mut okm)
        .map_err(|_| CryptoError::InvalidInput("hkdf output length"))?;
    Ok(okm)
}
