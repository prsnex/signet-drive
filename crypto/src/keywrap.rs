// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! AES-256 Key Wrap (RFC 3394).
//!
//! The final step of the `ECDH-ES+A256KW` DEK/metadata-key wrap (Envelope §5):
//! the 256-bit KEK derived by Concat-KDF wraps a 32-byte DEK to 40 bytes. AES-KW
//! has a built-in integrity check (the RFC 3394 IV), so a wrap unwrapped under
//! the wrong KEK fails cleanly — this is what makes the `root_folder_id`-bound
//! KEK (P-015) reject a blob moved between folders.

use aes_kw::KekAes256;

use crate::error::{CryptoError, Result};

/// Wrap `key_data` under the 256-bit `kek` (RFC 3394). Output is
/// `key_data.len() + 8` bytes (a 32-byte DEK wraps to 40). `key_data` must be a
/// multiple of 8 bytes and at least 16.
pub fn wrap(kek: &[u8; 32], key_data: &[u8]) -> Result<Vec<u8>> {
    if key_data.len() < 16 || !key_data.len().is_multiple_of(8) {
        return Err(CryptoError::InvalidInput("aes-kw key_data length"));
    }
    let mut out = vec![0u8; key_data.len() + 8];
    KekAes256::from(*kek)
        .wrap(key_data, &mut out)
        .map_err(|_| CryptoError::InvalidInput("aes-kw wrap"))?;
    Ok(out)
}

/// Unwrap `wrapped` under `kek`. Returns the unwrapped key material, or
/// [`CryptoError::Authentication`] if the RFC 3394 integrity check fails (wrong
/// KEK or tampered wrap). A malformed length is [`CryptoError::InvalidInput`] —
/// never conflated with an integrity failure.
pub fn unwrap(kek: &[u8; 32], wrapped: &[u8]) -> Result<Vec<u8>> {
    if wrapped.len() < 24 || !wrapped.len().is_multiple_of(8) {
        return Err(CryptoError::InvalidInput("aes-kw wrapped length"));
    }
    let mut out = vec![0u8; wrapped.len() - 8];
    KekAes256::from(*kek)
        .unwrap(wrapped, &mut out)
        .map_err(|_| CryptoError::Authentication)?;
    Ok(out)
}
