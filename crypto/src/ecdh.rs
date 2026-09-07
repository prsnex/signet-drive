// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! ECDH P-256 key agreement (NIST P-256 / secp256r1).
//!
//! The key-agreement step of the `ECDH-ES+A256KW` wrap chain (Envelope §5): the
//! sender's ephemeral private scalar and the recipient's KEM public key agree on
//! a shared secret Z (the x-coordinate of the shared point), which Concat-KDF then
//! turns into the AES-KW KEK. This module is the raw agreement; ephemeral keygen
//! and the KDF live with the wrap-chain composition.

use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use rand_core::OsRng;

use crate::error::{CryptoError, Result};

/// Generate a fresh P-256 **KEM** keypair from the OS CSPRNG. Returns the 32-byte
/// private scalar (the input to [`ecdh_p256`]) and the 65-byte X9.63 uncompressed
/// public key (`0x04 ‖ X ‖ Y`). The KEM-key counterpart to
/// [`crate::ecdsa::generate_keypair`]; used by the (B6) `signet` CLI to mint a
/// PRSN's `ECDH-ES+A256KW` KEM keypair. Same curve/encoding as the signing key —
/// the distinction is purpose, not representation.
pub fn generate_keypair() -> ([u8; 32], Vec<u8>) {
    let sk = SecretKey::random(&mut OsRng);
    let scalar: [u8; 32] = sk.to_bytes().into();
    let pubkey = sk.public_key().to_encoded_point(false).as_bytes().to_vec();
    (scalar, pubkey)
}

/// ECDH P-256 agreement. `secret_scalar` is the 32-byte private scalar (big-endian);
/// `peer_public_x963` is the peer's public key as a 65-byte X9.63 uncompressed
/// point (`0x04 || X || Y`). Returns the 32-byte shared secret Z (the shared
/// point's x-coordinate), per RFC 7518 §4.6 / NIST SP 800-56A.
pub fn ecdh_p256(secret_scalar: &[u8; 32], peer_public_x963: &[u8]) -> Result<[u8; 32]> {
    let secret = SecretKey::from_slice(secret_scalar)
        .map_err(|_| CryptoError::InvalidInput("ecdh secret scalar"))?;
    let peer = PublicKey::from_sec1_bytes(peer_public_x963)
        .map_err(|_| CryptoError::InvalidInput("ecdh peer public key"))?;
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    Ok((*shared.raw_secret_bytes()).into())
}
