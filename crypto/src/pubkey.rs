// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Public-key fingerprints (Schema v10 §1/§4 column definition).
//!
//! The canonical fingerprint of a P-256 public key is the **lowercase-hex
//! SHA-256 of its DER-encoded `SubjectPublicKeyInfo`** — *not* of the raw
//! 65-byte X9.63 point. The same definition is used everywhere: the KEM-wrap
//! routing field (`rfp`), the per-request `Signet-Fingerprint`, the
//! `attestations` rows, and the `pubkey_log` entries. Computing it via the
//! `spki` DER encoding (rather than hand-rolling the ASN.1) keeps it correct.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::PublicKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::{DecodePublicKey, EncodePublicKey, LineEnding};

use crate::error::{CryptoError, Result};
use crate::hash;

/// Lowercase-hex SHA-256 of the DER `SubjectPublicKeyInfo` of a P-256 public
/// key, given as a 65-byte X9.63 uncompressed point (`0x04 || X || Y`). Works
/// for both signing (ECDSA) and KEM (ECDH) keys — same curve, same encoding.
pub fn fingerprint(pubkey_x963: &[u8]) -> Result<String> {
    let key = PublicKey::from_sec1_bytes(pubkey_x963)
        .map_err(|_| CryptoError::InvalidInput("fingerprint public key"))?;
    let der = key
        .to_public_key_der()
        .map_err(|_| CryptoError::InvalidInput("spki der encoding"))?;
    Ok(hex::encode(hash::sha256(der.as_bytes())))
}

/// Lowercase-hex SHA-256 over the **raw** public-key bytes — the PQ-component
/// fingerprint (PQR Crypto Spec §8.5): the FIPS 203 `ek` bytes for ML-KEM-1024,
/// the FIPS 204 `vk` bytes for ML-DSA-87. Deliberately distinct from
/// [`fingerprint`]'s SPKI-DER convention: the PQ keys have no SPKI form in our
/// stack, and §8.5 pins "the exact §4.3 field encodings" as the digest input.
pub fn fingerprint_raw(public_key: &[u8]) -> String {
    hex::encode(hash::sha256(public_key))
}

/// DER-encoded `SubjectPublicKeyInfo` of a P-256 public key (X9.63 in). The same
/// bytes whose SHA-256 is the [`fingerprint`]; used by `signet pubkey --format der`.
pub fn spki_der(pubkey_x963: &[u8]) -> Result<Vec<u8>> {
    let key = PublicKey::from_sec1_bytes(pubkey_x963)
        .map_err(|_| CryptoError::InvalidInput("public key"))?;
    Ok(key
        .to_public_key_der()
        .map_err(|_| CryptoError::InvalidInput("spki der encoding"))?
        .as_bytes()
        .to_vec())
}

/// PEM-encoded `SubjectPublicKeyInfo` (LF line endings); `signet pubkey --format pem`.
pub fn spki_pem(pubkey_x963: &[u8]) -> Result<String> {
    let key = PublicKey::from_sec1_bytes(pubkey_x963)
        .map_err(|_| CryptoError::InvalidInput("public key"))?;
    key.to_public_key_pem(LineEnding::LF)
        .map_err(|_| CryptoError::InvalidInput("spki pem encoding"))
}

/// JWK public-key object (RFC 7517/7518) for a P-256 point; `signet pubkey
/// --format jwk`. `x`/`y` are the affine coordinates base64url-no-pad encoded,
/// sliced from the 65-byte X9.63 uncompressed point (`0x04 ‖ x(32) ‖ y(32)`).
pub fn jwk(pubkey_x963: &[u8]) -> Result<serde_json::Value> {
    if pubkey_x963.len() != 65 || pubkey_x963[0] != 0x04 {
        return Err(CryptoError::InvalidInput("x9.63 uncompressed point"));
    }
    Ok(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(&pubkey_x963[1..33]),
        "y": URL_SAFE_NO_PAD.encode(&pubkey_x963[33..65]),
    }))
}

/// Parse a P-256 public key from PEM `SubjectPublicKeyInfo` into a 65-byte X9.63
/// uncompressed point. The inverse of [`spki_pem`]; for `signet`'s
/// `--to-pubkey` recipient-key input.
pub fn x963_from_pem(pem: &str) -> Result<Vec<u8>> {
    let key = PublicKey::from_public_key_pem(pem)
        .map_err(|_| CryptoError::InvalidInput("public key pem"))?;
    Ok(key.to_encoded_point(false).as_bytes().to_vec())
}

/// Parse a P-256 public key from a JWK object (`{kty:EC, crv:P-256, x, y}`) into
/// a 65-byte X9.63 uncompressed point, validating the point is on the curve. The
/// inverse of [`jwk`].
pub fn x963_from_jwk(jwk: &serde_json::Value) -> Result<Vec<u8>> {
    if jwk.get("kty").and_then(|v| v.as_str()) != Some("EC")
        || jwk.get("crv").and_then(|v| v.as_str()) != Some("P-256")
    {
        return Err(CryptoError::InvalidInput("jwk must be EC P-256"));
    }
    let x = jwk
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or(CryptoError::InvalidInput("jwk missing x"))?;
    let y = jwk
        .get("y")
        .and_then(|v| v.as_str())
        .ok_or(CryptoError::InvalidInput("jwk missing y"))?;
    let xb = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|_| CryptoError::InvalidInput("jwk x base64url"))?;
    let yb = URL_SAFE_NO_PAD
        .decode(y)
        .map_err(|_| CryptoError::InvalidInput("jwk y base64url"))?;
    if xb.len() != 32 || yb.len() != 32 {
        return Err(CryptoError::InvalidInput(
            "jwk coordinates must be 32 bytes",
        ));
    }
    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(&xb);
    point.extend_from_slice(&yb);
    PublicKey::from_sec1_bytes(&point)
        .map_err(|_| CryptoError::InvalidInput("jwk not on curve"))?;
    Ok(point)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_and_jwk_round_trip_through_x963() {
        let (_scalar, x963) = crate::ecdh::generate_keypair();
        assert_eq!(x963_from_pem(&spki_pem(&x963).unwrap()).unwrap(), x963);
        assert_eq!(x963_from_jwk(&jwk(&x963).unwrap()).unwrap(), x963);
    }

    #[test]
    fn jwk_rejects_non_p256() {
        let bad = serde_json::json!({"kty": "EC", "crv": "P-384", "x": "AA", "y": "AA"});
        assert!(x963_from_jwk(&bad).is_err());
    }
}
