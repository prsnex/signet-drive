// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! SHA-256 (FIPS 180-4).
//!
//! The one hash used everywhere in v1: the per-request body hash (SIGNET-V1
//! canonical bytes), public-key fingerprints (SHA-256 of DER SubjectPublicKeyInfo),
//! the transparency-log `entry_hash`, and the RFC 6962 Merkle leaf/internal hashes.
//! Those higher-level constructions live in later modules; this is the primitive.

use sha2::{Digest, Sha256};

/// SHA-256 of `input`. 32 raw bytes.
pub fn sha256(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}
