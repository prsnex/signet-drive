// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! `ECDH-ES+A256KW` key wrapping (Envelope §5 DEK wrap + §7.2 metadata-key wrap).
//!
//! Wraps a 32-byte key — a file DEK, or a per-folder metadata key — to a
//! recipient's ECDH P-256 KEM public key: a fresh ephemeral-static ECDH →
//! Concat-KDF-SHA-256 → AES-256 Key Wrap, serialized as the JOSE-shaped JSON
//! envelope. This is the **composition** step (the genuinely novel surface):
//! it reuses the validated [`ecdh`], [`concatkdf`], and [`keywrap`] primitives
//! and adds only the glue and the on-the-wire shape — no new cryptography.
//!
//! The DEK wrap and the metadata-key wrap are the *same* construction; they
//! differ only in the Concat-KDF `PartyVInfo`: empty for a DEK, the
//! `root_folder_id` for a metadata key (P-015). The folder binding means a
//! metadata-key blob moved to another folder derives a different KEK and fails
//! AES-KW's integrity check (Envelope §7.2).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::alg::AlgId;
use crate::error::{CryptoError, Result};
use crate::{concatkdf, ecdh, keywrap, pubkey};

/// The ephemeral public key in JWK form (RFC 7517 §3), as it appears in the
/// wrap envelope's `epk` field.
///
/// `deny_unknown_fields`: both envelope emitters (this crate and the web
/// client) produce exactly `kty`/`crv`/`x`/`y`, so extra JWK members (`kid`,
/// `use`, …) are rejected rather than silently carried — the same strict-parse
/// posture as the envelopes themselves (PQR Spec §5.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpkJwk {
    pub kty: String,
    pub crv: String,
    /// base64url(no-pad) of the 32-byte X coordinate.
    pub x: String,
    /// base64url(no-pad) of the 32-byte Y coordinate.
    pub y: String,
}

/// A wrapped-key envelope (Envelope §5 for a DEK, §7.2 for a metadata key —
/// identical shape). Stored opaquely server-side in `file_recipients.wrapped_dek`
/// / `wrapped_metadata_keys.wrapped_key`; the server never parses it.
///
/// `deny_unknown_fields` enforces the classical side of the PQR-Spec §5.2
/// symmetric field validation: a classical `ECDH-ES+A256KW` envelope MUST NOT
/// carry a hybrid `ek`/`wk` — an injected field is rejected at parse time
/// (negative test N5), so no field-smuggling across algs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrapEnvelope {
    pub v: u32,
    pub alg: String,
    pub epk: EpkJwk,
    /// base64url(no-pad) of the 40-byte AES-KW output.
    pub ct: String,
    /// Recipient KEM pubkey fingerprint, lowercase hex (routing only).
    pub rfp: String,
}

impl WrapEnvelope {
    /// The ephemeral public key from `epk`, as a validated 65-byte X9.63 point.
    /// The `signet` keystore feeds this to its ECDH-as-a-service (the SE/software
    /// backend computes the shared secret Z) so the recipient's private scalar
    /// never leaves the keystore — see [`unwrap_dek_with_shared_secret`].
    pub fn ephemeral_pubkey_x963(&self) -> Result<Vec<u8>> {
        x963_from_epk(&self.epk)
    }
}

/// Wrap a 32-byte DEK to a recipient's KEM public key (Envelope §5). No folder
/// binding (the §4.1 file envelope already binds content to `file_id` via AAD).
pub fn wrap_dek(recipient_kem_pub_x963: &[u8], dek: &[u8; 32]) -> Result<WrapEnvelope> {
    wrap_to(recipient_kem_pub_x963, dek, &[])
}

/// Unwrap a DEK wrap with the recipient's ECDH private scalar (Envelope §5).
pub fn unwrap_dek(recipient_priv_scalar: &[u8; 32], envelope: &WrapEnvelope) -> Result<[u8; 32]> {
    fixed32(unwrap_with(recipient_priv_scalar, envelope, &[])?)
}

/// Wrap a 32-byte metadata key to a recipient, bound to `root_folder_id`
/// (the 16-byte UUID) via the Concat-KDF `PartyVInfo` — P-015 (Envelope §7.2).
pub fn wrap_metadata_key(
    recipient_kem_pub_x963: &[u8],
    metadata_key: &[u8; 32],
    root_folder_id: &[u8; 16],
) -> Result<WrapEnvelope> {
    wrap_to(recipient_kem_pub_x963, metadata_key, root_folder_id)
}

/// Unwrap a metadata-key wrap. `root_folder_id` MUST match the folder the wrap
/// was created for; a mismatch derives a different KEK and AES-KW's integrity
/// check rejects it ([`CryptoError::Authentication`]) — the P-015 property.
pub fn unwrap_metadata_key(
    recipient_priv_scalar: &[u8; 32],
    envelope: &WrapEnvelope,
    root_folder_id: &[u8; 16],
) -> Result<[u8; 32]> {
    fixed32(unwrap_with(
        recipient_priv_scalar,
        envelope,
        root_folder_id,
    )?)
}

/// Unwrap a DEK wrap when the ECDH shared secret Z is supplied externally — the
/// `signet` keystore computes Z via its SE/software backend so the recipient's
/// private scalar never leaves the keystore (Envelope §5). Pair with
/// [`WrapEnvelope::ephemeral_pubkey_x963`] + the keystore's ECDH op.
pub fn unwrap_dek_with_shared_secret(z: &[u8; 32], envelope: &WrapEnvelope) -> Result<[u8; 32]> {
    fixed32(finish_unwrap(z, envelope, &[])?)
}

/// Unwrap a metadata-key wrap with an externally-supplied Z. `root_folder_id`
/// (the P-015 `party_v`) MUST match the wrap-time folder, or AES-KW rejects it.
pub fn unwrap_metadata_key_with_shared_secret(
    z: &[u8; 32],
    envelope: &WrapEnvelope,
    root_folder_id: &[u8; 16],
) -> Result<[u8; 32]> {
    fixed32(finish_unwrap(z, envelope, root_folder_id)?)
}

/// The shared wrap construction: ephemeral ECDH → Concat-KDF KEK (bound to
/// `party_v`) → AES-KW.
fn wrap_to(recipient_kem_pub_x963: &[u8], key: &[u8; 32], party_v: &[u8]) -> Result<WrapEnvelope> {
    // Validate the recipient key up front (also gives us the JWK source for the
    // `rfp` fingerprint).
    PublicKey::from_sec1_bytes(recipient_kem_pub_x963)
        .map_err(|_| CryptoError::InvalidInput("recipient kem public key"))?;

    let ephemeral = SecretKey::random(&mut OsRng);
    // §4.6 zeroization: the scalar copy, Z, and the KEK are all wiped on drop
    // (`SecretKey` itself zeroizes internally).
    let eph_scalar: Zeroizing<[u8; 32]> = Zeroizing::new(ephemeral.to_bytes().into());

    let z = Zeroizing::new(ecdh::ecdh_p256(&eph_scalar, recipient_kem_pub_x963)?);
    let kek = concatkdf::ecdh_es_a256kw_kek(&*z, party_v);
    let wrapped = keywrap::wrap(&kek, key)?; // 40 bytes for a 32-byte key

    Ok(WrapEnvelope {
        v: 1,
        alg: AlgId::EcdhEsA256Kw.as_jose().to_string(),
        epk: epk_jwk(&ephemeral.public_key()),
        ct: URL_SAFE_NO_PAD.encode(&wrapped),
        rfp: pubkey::fingerprint(recipient_kem_pub_x963)?,
    })
}

/// The shared unwrap construction (this crate computes Z from the private
/// scalar). `party_v` must match the wrap-time value.
fn unwrap_with(
    recipient_priv_scalar: &[u8; 32],
    envelope: &WrapEnvelope,
    party_v: &[u8],
) -> Result<Vec<u8>> {
    let eph_pub_x963 = x963_from_epk(&envelope.epk)?;
    let z = Zeroizing::new(ecdh::ecdh_p256(recipient_priv_scalar, &eph_pub_x963)?);
    finish_unwrap(&z, envelope, party_v)
}

/// The unwrap tail once the ECDH shared secret Z is known: check the alg, derive
/// the KEK (bound to `party_v`), AES-KW-unwrap. Shared by the scalar-based path
/// ([`unwrap_with`]) and the keystore-supplied-Z path
/// ([`unwrap_dek_with_shared_secret`] / [`unwrap_metadata_key_with_shared_secret`]).
fn finish_unwrap(z: &[u8; 32], envelope: &WrapEnvelope, party_v: &[u8]) -> Result<Vec<u8>> {
    if AlgId::from_jose(&envelope.alg)? != AlgId::EcdhEsA256Kw {
        return Err(CryptoError::UnknownAlgorithm);
    }
    let kek = concatkdf::ecdh_es_a256kw_kek(z, party_v);
    let wrapped = URL_SAFE_NO_PAD
        .decode(envelope.ct.as_bytes())
        .map_err(|_| CryptoError::InvalidInput("wrap ct base64url"))?;
    keywrap::unwrap(&kek, &wrapped)
}

/// The EC public key as the wrap envelope's `epk` JWK (uncompressed `0x04‖X‖Y`).
pub(crate) fn epk_jwk(pubkey: &PublicKey) -> EpkJwk {
    let point = pubkey.to_encoded_point(false);
    EpkJwk {
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        x: URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed point has X").as_slice()),
        y: URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed point has Y").as_slice()),
    }
}

/// Reconstruct + validate the 65-byte X9.63 point from an `epk` JWK.
pub(crate) fn x963_from_epk(epk: &EpkJwk) -> Result<Vec<u8>> {
    if epk.kty != "EC" || epk.crv != "P-256" {
        return Err(CryptoError::InvalidInput("epk must be EC P-256"));
    }
    let x = URL_SAFE_NO_PAD
        .decode(epk.x.as_bytes())
        .map_err(|_| CryptoError::InvalidInput("epk x base64url"))?;
    let y = URL_SAFE_NO_PAD
        .decode(epk.y.as_bytes())
        .map_err(|_| CryptoError::InvalidInput("epk y base64url"))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(CryptoError::InvalidInput(
            "epk coordinates must be 32 bytes",
        ));
    }
    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(&x);
    point.extend_from_slice(&y);
    // Reject a point that isn't actually on the curve before it reaches ECDH.
    PublicKey::from_sec1_bytes(&point)
        .map_err(|_| CryptoError::InvalidInput("epk not on curve"))?;
    Ok(point)
}

/// Convert unwrapped key material to `[u8; 32]`, wiping the source buffer in
/// both the success and the failure path (§4.6 — the buffer held key material
/// either way).
pub(crate) fn fixed32(mut bytes: Vec<u8>) -> Result<[u8; 32]> {
    let result = <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| CryptoError::InvalidInput("unwrapped key is not 32 bytes"));
    bytes.zeroize();
    result
}
