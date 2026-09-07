// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Human-side KEM-key wrap chain (Envelope Format v09 §8 / WebAuthn-PRF v07).
//!
//! The chain that lets a human recover their ECDH KEM private key from a
//! WebAuthn passkey: the passkey's PRF output is run through HKDF-SHA-256 to a
//! 32-byte wrap key `W` (§8.2), which AES-256-GCM-wraps the PKCS#8 ECDH private
//! key into the `{v,alg,iv,ct,tag}` envelope stored as
//! `accounts.wrapped_kem_privkey_blob` (§8.3).
//!
//! In production this runs **entirely in the browser** (WebCrypto): the server
//! never sees the PRF output, `W`, or the private key (INV-1..3, INV-13). This
//! crate holds the *reference* impl plus the golden vectors that pin it
//! byte-for-byte to what WebCrypto produces, so the SvelteKit web client
//! (Phase 3) can be validated against a frozen oracle. It composes the validated
//! [`crate::kdf`] (HKDF) and [`crate::aead`] (AES-GCM) primitives and adds only
//! the label constants and the on-the-wire shape — no new cryptography.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::alg::AlgId;
use crate::error::{CryptoError, Result};
use crate::{aead, hash, kdf};

/// The version-tagged label that scopes the wrap chain, used three ways
/// (WebAuthn-PRF INV-7/INV-8/INV-9):
/// - the WebAuthn PRF eval salt is `SHA-256(LABEL)` — see [`prf_salt`],
/// - the HKDF `info` is `LABEL` itself,
/// - the AES-256-GCM AAD is `LABEL` itself.
///
/// The `-v1` suffix is the migration hook: a future chain bumps to `-v2` and old
/// blobs keep decrypting under `-v1` until a re-wrap runs.
pub const KEM_WRAP_LABEL: &[u8] = b"signet-drive-kem-wrap-v1";

/// The fixed WebAuthn PRF eval salt: `SHA-256("signet-drive-kem-wrap-v1")`
/// (INV-7; Test Vector Category 01 TC01-01). The server sends this (base64url)
/// as `prf.eval.first` in the assertion options. It is **not** the raw label —
/// passing the label directly is the INV-7 bug this constant exists to prevent.
pub fn prf_salt() -> [u8; 32] {
    hash::sha256(KEM_WRAP_LABEL)
}

/// The human-side wrap blob (Envelope §8.3), stored opaquely in
/// `accounts.wrapped_kem_privkey_blob`. `iv`/`ct`/`tag` are base64url-no-pad;
/// `ct` is the ciphertext **without** the GCM tag (the tag is a sibling field).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KemPrivkeyWrap {
    pub v: u32,
    pub alg: String,
    /// base64url(no-pad) of the 12-byte AES-GCM IV.
    pub iv: String,
    /// base64url(no-pad) of the PKCS#8 ciphertext, WITHOUT the tag.
    pub ct: String,
    /// base64url(no-pad) of the 16-byte GCM tag.
    pub tag: String,
}

/// Derive the 32-byte wrap key `W` from a 32-byte WebAuthn PRF output
/// (Envelope §8.2): `HKDF-SHA-256(ikm=prf_output, salt=empty, info=LABEL, 32)`.
///
/// The PRF output MUST be exactly 32 bytes; a truncated output silently weakens
/// `W` (WebAuthn-PRF failure-modes table), so it is rejected rather than padded.
pub fn derive_wrap_key(prf_output: &[u8]) -> Result<[u8; 32]> {
    if prf_output.len() != 32 {
        return Err(CryptoError::InvalidInput("prf output must be 32 bytes"));
    }
    kdf::hkdf_sha256(prf_output, &[], KEM_WRAP_LABEL, 32)?
        .try_into()
        .map_err(|_| CryptoError::InvalidInput("derived wrap key length"))
}

/// Wrap a PKCS#8-encoded ECDH private key under `wrap_key` with a caller-supplied
/// 12-byte `iv` (Envelope §8.3). AAD is the fixed [`KEM_WRAP_LABEL`]. The `iv`
/// MUST be unique per `wrap_key` (fresh random per wrap event — signup, passkey
/// rotation); GCM nonce reuse under one key is catastrophic.
pub fn wrap_kem_privkey(
    wrap_key: &[u8; 32],
    pkcs8: &[u8],
    iv: &[u8; 12],
) -> Result<KemPrivkeyWrap> {
    let sealed = aead::seal(wrap_key, iv, pkcs8, KEM_WRAP_LABEL)?; // ciphertext || tag
    let split = sealed.len() - 16;
    Ok(KemPrivkeyWrap {
        v: 1,
        alg: AlgId::A256Gcm.as_jose().to_string(),
        iv: URL_SAFE_NO_PAD.encode(iv),
        ct: URL_SAFE_NO_PAD.encode(&sealed[..split]),
        tag: URL_SAFE_NO_PAD.encode(&sealed[split..]),
    })
}

/// Unwrap a [`KemPrivkeyWrap`] under `wrap_key`, recovering the PKCS#8 bytes
/// (Envelope §8.5 step 4). Returns [`CryptoError::Authentication`] on a wrong key
/// (wrong passkey/PRF output), tampered ciphertext, or AAD mismatch — the caller
/// MUST NOT distinguish these. The `ct` and `tag` fields are re-concatenated
/// before the AEAD open (WebCrypto stores them joined; we store them split).
pub fn unwrap_kem_privkey(wrap_key: &[u8; 32], envelope: &KemPrivkeyWrap) -> Result<Vec<u8>> {
    if AlgId::from_jose(&envelope.alg)? != AlgId::A256Gcm {
        return Err(CryptoError::UnknownAlgorithm);
    }
    let iv: [u8; 12] = decode_field(&envelope.iv, "kem wrap iv base64url")?
        .try_into()
        .map_err(|_| CryptoError::InvalidInput("kem wrap iv must be 12 bytes"))?;
    let tag = decode_field(&envelope.tag, "kem wrap tag base64url")?;
    if tag.len() != 16 {
        return Err(CryptoError::InvalidInput("kem wrap tag must be 16 bytes"));
    }
    let mut ct_and_tag = decode_field(&envelope.ct, "kem wrap ct base64url")?;
    ct_and_tag.extend_from_slice(&tag);
    aead::open(wrap_key, &iv, &ct_and_tag, KEM_WRAP_LABEL)
}

fn decode_field(field: &str, what: &'static str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(field.as_bytes())
        .map_err(|_| CryptoError::InvalidInput(what))
}
