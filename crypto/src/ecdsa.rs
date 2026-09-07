// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! ECDSA P-256 with SHA-256 (`ES256`, RFC 7518 §3.4).
//!
//! Per-request signing on the PRSN side (Envelope §6.2) and server-signed
//! verification responses (§9). The server accepts both signature encodings a
//! signer might produce — raw `r‖s` (64 bytes, JOSE-canonical) and DER (~70-72
//! bytes) — dispatching on length (§6.2 step 5/6).
//!
//! v1 ECDSA is non-deterministic in production (the Apple Silicon Secure Enclave
//! / OS CSPRNG supplies `k`). The software signer here is deterministic (RFC 6979);
//! both produce valid `ES256` signatures a verifier accepts, and the wire format
//! is identical 64-byte `r‖s`. Differential testing therefore cross-*verifies*
//! (our sign ↔ OpenSSL verify, and vice-versa) rather than comparing signature
//! bytes, which would differ by nonce.

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rand_core::OsRng;

use crate::error::{CryptoError, Result};

/// Generate a fresh `ES256` (P-256) signing keypair from the OS CSPRNG. Returns
/// the 32-byte private scalar (the input to [`sign_es256`]) and the 65-byte X9.63
/// uncompressed public key (`0x04 ‖ X ‖ Y`, the input to [`verify_es256`]). Used
/// to mint the server's `attestation_verification` signing key at bootstrap, and
/// (B6) the `signet` CLI's PRSN keypairs.
pub fn generate_keypair() -> ([u8; 32], Vec<u8>) {
    let sk = SigningKey::random(&mut OsRng);
    let scalar: [u8; 32] = sk.to_bytes().into();
    let pubkey = sk
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    (scalar, pubkey)
}

/// Encode a 32-byte P-256 private scalar as a PKCS#8 `PrivateKeyInfo` DER document — the form a
/// TLS stack (rustls) loads an **in-memory** private key from. For **software / test** keys only:
/// the production broker's K3 server key and every PRSN key are Secure-Enclave-backed and **never**
/// exported (the SE signs in-place). Used by the Garnet broker's mutual-TLS tests + a non-SE dev
/// server identity.
pub fn p256_scalar_to_pkcs8_der(scalar: &[u8; 32]) -> Result<Vec<u8>> {
    use p256::pkcs8::EncodePrivateKey;
    let sk = p256::SecretKey::from_slice(scalar)
        .map_err(|_| CryptoError::InvalidInput("p256 scalar"))?;
    Ok(sk
        .to_pkcs8_der()
        .map_err(|_| CryptoError::InvalidInput("p256 pkcs8 encode"))?
        .as_bytes()
        .to_vec())
}

/// The public half (65-byte X9.63 uncompressed) of a P-256 private key in PKCS#8 DER — the
/// pairing check for [`p256_scalar_to_pkcs8_der`]-shaped keys. Used by the broker's
/// serve-start **K3 binding self-check** (bug087 fix 3, software tier): prove the
/// credential's stored key is the key its certificate names, before serving.
pub fn p256_pkcs8_public_x963(pkcs8_der: &[u8]) -> Result<Vec<u8>> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::pkcs8::DecodePrivateKey;
    let sk = p256::SecretKey::from_pkcs8_der(pkcs8_der)
        .map_err(|_| CryptoError::InvalidInput("p256 pkcs8"))?;
    Ok(sk.public_key().to_encoded_point(false).as_bytes().to_vec())
}

/// Sign `msg` with `ES256` under the 32-byte private scalar, returning the
/// 64-byte raw `r‖s` signature (JOSE-canonical).
pub fn sign_es256(secret_scalar: &[u8; 32], msg: &[u8]) -> Result<[u8; 64]> {
    let sk = SigningKey::from_slice(secret_scalar)
        .map_err(|_| CryptoError::InvalidInput("es256 secret scalar"))?;
    let signature: Signature = sk.sign(msg);
    Ok(signature.to_bytes().into())
}

/// Convert a raw `r‖s` (64-byte) `ES256` signature to its DER `SEQUENCE`
/// encoding (~70-72 bytes), for `signet sign --output-format der`. The server
/// accepts both encodings, dispatching on length (Envelope §6.2).
pub fn sig_raw_to_der(raw: &[u8; 64]) -> Result<Vec<u8>> {
    let signature =
        Signature::from_slice(raw).map_err(|_| CryptoError::InvalidInput("es256 raw r‖s"))?;
    Ok(signature.to_der().as_bytes().to_vec())
}

/// Convert a DER `SEQUENCE` `ES256` signature (~70-72 bytes) to raw `r‖s`
/// (64 bytes, JOSE-canonical) — the inverse of [`sig_raw_to_der`]. The macOS
/// Secure Enclave emits DER (`SecKeyCreateSignature`), but the keystore `sign`
/// contract is raw `r‖s`, so the `secure_enclave` backend converts via this.
pub fn sig_der_to_raw(der: &[u8]) -> Result<[u8; 64]> {
    let signature = Signature::from_der(der).map_err(|_| CryptoError::InvalidInput("es256 DER"))?;
    Ok(signature.to_bytes().into())
}

/// Verify an `ES256` signature over `msg`. `pubkey_x963` is the 65-byte X9.63
/// uncompressed public key; `sig` is accepted as raw `r‖s` (64 bytes) or DER
/// (variable-length, ≤72 bytes — see [`parse_signature`]) per Envelope §6.2.
/// Returns [`CryptoError::SignatureInvalid`] if verification fails.
pub fn verify_es256(pubkey_x963: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    let vk = VerifyingKey::from_sec1_bytes(pubkey_x963)
        .map_err(|_| CryptoError::InvalidInput("es256 public key"))?;
    let signature = parse_signature(sig)?;
    vk.verify(msg, &signature)
        .map_err(|_| CryptoError::SignatureInvalid)
}

/// Parse an ECDSA signature as raw `r‖s` (exactly 64 bytes, JOSE-canonical) or
/// DER. DER ECDSA signatures are **variable-length** — at most 72 bytes for
/// P-256, but *shorter* (e.g. 68–69) whenever `r` or `s` has a leading zero byte
/// — so DER must NOT be gated on a fixed length: the DER decoder is the real
/// validator. We keep only the cheap upper bound (Envelope §6.2 step 5's
/// defensive check): nothing over 72 bytes can be a valid P-256 signature.
fn parse_signature(sig: &[u8]) -> Result<Signature> {
    match sig.len() {
        64 => Signature::from_slice(sig).map_err(|_| CryptoError::InvalidInput("es256 raw r‖s")),
        n if n <= 72 => {
            Signature::from_der(sig).map_err(|_| CryptoError::InvalidInput("es256 DER"))
        }
        _ => Err(CryptoError::InvalidInput("es256 signature length")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_keypair_round_trips() {
        let (scalar, pubkey) = generate_keypair();
        assert_eq!(pubkey.len(), 65, "X9.63 uncompressed P-256");
        assert_eq!(pubkey[0], 0x04, "uncompressed point prefix");
        let msg = b"signet-server-attestation-verify-v1\n...canonical bytes...";
        let sig = sign_es256(&scalar, msg).expect("sign");
        verify_es256(&pubkey, msg, &sig).expect("verify own signature");
        // A different key must not verify it.
        let (_, other_pubkey) = generate_keypair();
        assert!(verify_es256(&other_pubkey, msg, &sig).is_err());
    }

    #[test]
    fn der_raw_conversions_round_trip() {
        let (scalar, pubkey) = generate_keypair();
        let msg = b"der <-> raw round trip";
        let raw = sign_es256(&scalar, msg).expect("sign");
        let der = sig_raw_to_der(&raw).expect("raw -> der");
        assert!(
            der.len() <= 72,
            "DER is at most 72 bytes (shorter when r or s has a leading zero)"
        );
        let raw2 = sig_der_to_raw(&der).expect("der -> raw");
        assert_eq!(raw, raw2, "raw -> der -> raw is the identity");
        // The recovered raw still verifies, and the DER verifies directly.
        verify_es256(&pubkey, msg, &raw2).expect("recovered raw verifies");
        verify_es256(&pubkey, msg, &der).expect("der verifies");
        // Junk is rejected, not panicked on.
        assert!(sig_der_to_raw(b"not der at all").is_err());
    }

    /// Regression (S036): a *valid* P-256 ECDSA DER signature is variable-length
    /// and can be < 70 bytes when `r` or `s` has a leading zero byte.
    /// `verify_es256` must accept them — the previous fixed `70..=72` length gate
    /// rejected ~0.8% of valid DER signatures (an intermittent `signature_invalid`
    /// for any DER-signing client; the canonical raw `r‖s` path was unaffected).
    /// This is a real 69-byte DER signature (its `s` integer is 31 bytes) produced
    /// by OpenSSL over SHA-256(`"short-der-regression"`) — a deterministic,
    /// cross-implementation KAT (OpenSSL signs; we verify).
    #[test]
    fn verify_es256_accepts_short_der_signature() {
        let pubkey = hex::decode(
            "0460f31cbf355dcaa2385780dbac0cdac8d82c787697abb2114e396a572b2e2f286bdf7feb1939bc96cf5689feb0a617b9938acf9449910f9021da0f0900c8a87f",
        )
        .unwrap();
        let sig_der = hex::decode(
            "304302206f33e3678e3b1686fdff8311476aaf3d1a7be30a37c417965f34ece07fafaf40021f31467565ddbca619418b9e56abf2e7b63fcd97395424043a51e8e683fddaa3",
        )
        .unwrap();
        assert!(
            sig_der.len() < 70,
            "vector must exercise the short-DER path (len = {})",
            sig_der.len()
        );
        verify_es256(&pubkey, b"short-der-regression", &sig_der)
            .expect("a valid short (<70-byte) DER ES256 signature must verify");
    }
}
