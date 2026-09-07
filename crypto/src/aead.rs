// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! AES-256-GCM (`A256GCM`, RFC 7518 §5.3 / NIST SP 800-38D).
//!
//! The authenticated-encryption primitive for file ciphertext (Envelope §4),
//! encrypted names (§7.3), and the human-side wrap blob (§8.3). AAD binds a
//! ciphertext to its semantic context (file_id, folder scope) so the storage
//! layer cannot substitute one blob for another — the binding is the caller's
//! responsibility; this module just threads the AAD through.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};

use crate::error::{CryptoError, Result};

/// Seal `plaintext` under `key` (256-bit) and `nonce` (96-bit) with the given
/// AAD. Returns `ciphertext || tag` (the trailing 16 bytes are the GCM tag),
/// matching the on-disk envelope layout (Envelope §4.1: `[IV][ct][tag]`).
///
/// The caller MUST use a unique nonce per (key, message); GCM nonce reuse is
/// catastrophic. This module does not generate nonces — that is the envelope
/// layer's job (fresh random per file, or HKDF-derived per multipart chunk).
pub fn seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::InvalidInput("aes-256-gcm seal"))
}

/// Open `ciphertext_and_tag` (`ciphertext || tag`) under `key`, `nonce`, and AAD.
/// Returns the plaintext, or [`CryptoError::Authentication`] on tag mismatch,
/// wrong key, wrong AAD, or tampering — the caller MUST NOT distinguish these.
pub fn open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext_and_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext_and_tag,
                aad,
            },
        )
        .map_err(|_| CryptoError::Authentication)
}
