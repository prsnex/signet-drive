// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! The crate's error type.
//!
//! Cryptographic errors are deliberately coarse: a caller learns *that* an
//! operation failed, not *why* in a way that could leak oracle information
//! (e.g. distinguishing a bad tag from a bad length on a decrypt path). Where a
//! distinction is safe and useful at the API boundary it is surfaced; where it
//! could become a padding/tag oracle it is collapsed to `Authentication`.

use core::fmt;

/// The result type used throughout the crate.
pub type Result<T> = core::result::Result<T, CryptoError>;

/// A cryptographic operation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Authenticated decryption or key-unwrap failed its integrity check
    /// (GCM tag mismatch, AES-KW integrity-check failure). Callers MUST treat
    /// this as "wrong key or tampered ciphertext" and reveal nothing finer.
    Authentication,
    /// An input was structurally invalid (wrong length, malformed encoding, a
    /// point not on the curve). The static string names the offending input;
    /// it never carries secret-derived data.
    InvalidInput(&'static str),
    /// An algorithm identifier was absent from the v1 registry.
    UnknownAlgorithm,
    /// A signature did not verify against the message and public key.
    SignatureInvalid,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::Authentication => f.write_str("authentication failed"),
            CryptoError::InvalidInput(what) => write!(f, "invalid input: {what}"),
            CryptoError::UnknownAlgorithm => f.write_str("unknown algorithm identifier"),
            CryptoError::SignatureInvalid => f.write_str("signature verification failed"),
        }
    }
}

impl std::error::Error for CryptoError {}
