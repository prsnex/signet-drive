// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Hybrid content-wrap — `ECDH-ES+ML-KEM-1024+A256KW` (PQR Crypto Spec §3–§5).
//!
//! Wraps a 32-byte key (a file DEK, or a per-folder metadata key) to a recipient's
//! **hybrid** KEM public keys — `rk_ec` (P-256, X9.63) + `rk_pq` (ML-KEM-1024
//! encapsulation key) — via the NIST **SP 800-227 §4.6** two-step HKDF KDM:
//!
//! ```text
//! IKM = Z_ecdh ‖ Z_mlkem                    (the SP 800-56A secret first; PQR §4.2)
//! PRK = HKDF-Extract(salt = zero-length, IKM)
//! KEK = HKDF-Expand(PRK, FixedInfo, 32)     (FixedInfo per §4.3)
//! wk  = AES-256-KW(KEK, key)                (RFC 3394, 40 bytes)
//! ```
//!
//! This module is the **combiner + the on-the-wire envelope**. Like the classical
//! [`crate::wrap::unwrap_dek_with_shared_secret`] seam, it takes the two shared
//! secrets as *inputs*: the ML-KEM encaps/decaps and the ECDH are performed by the
//! keystore/SE (unwrap) or the CLI/WASM `ml-kem` + `ecdh` (wrap), which hand this
//! module `Z_ecdh` and `Z_mlkem`. So the crypto-correctness core here is pure HKDF
//! plus AES-KW plus byte assembly — no `ml-kem` dependency, no Secure Enclave —
//! which is exactly what the KeyCombine KAT (PQR §11.5, byte-matched at A3) pins.
//!
//! # What is bound, and why (PQR §4.4)
//!
//! `FixedInfo` binds the alg-ID, the ML-KEM ciphertext `ek`, the ephemeral `epk`,
//! and *both* recipient public keys. Binding the ciphertexts is not
//! downgrade-hygiene alone — per SP 800-227 §4.6.3 a secrets-only combiner does not
//! preserve IND-CCA security, so `ek ∈ FixedInfo` is what makes the composite
//! generically IND-CCA. Binding the recipient keys defeats cross-recipient
//! block-swapping (negative test N4). The alg-ID in `FixedInfo` + per-alg field
//! validation is the downgrade defense (N1/N2). There is **no `enc` field** — v1's
//! classical Concat-KDF binds the wrap-alg + keydatalen only (§4.3).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::PublicKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::alg::AlgId;
use crate::error::{CryptoError, Result};
use crate::wrap::{EpkJwk, epk_jwk, fixed32, x963_from_epk};
use crate::{kdf, keywrap};

/// The derived KEK length in bits, bound into `FixedInfo`'s `L` field (PQR §4.3).
const KEYDATALEN_BITS: u32 = 256;

/// The ML-KEM-1024 ciphertext length in bytes (FIPS 203); validated on parse.
/// Public: the keystore wire dispatch validates `ek` against it too (PQR item 2).
pub const MLKEM1024_CT_LEN: usize = 1568;

/// The ML-KEM-1024 encapsulation-key length in bytes (FIPS 203) — the same
/// number as the ciphertext, kept as its own name because it validates a
/// different thing (`rk_pq`, the recipient's static key, vs `ek`).
pub const MLKEM1024_EK_LEN: usize = 1568;

const HYBRID_ALG: AlgId = AlgId::EcdhEsMlKem1024A256Kw;

/// A hybrid wrapped-key envelope (PQR Spec §5.2). Distinct shape from the classical
/// [`crate::wrap::WrapEnvelope`]: it carries **both** `epk` (the classical ephemeral
/// public key) and `ek` (the ML-KEM ciphertext), plus `wk` (the AES-KW output — a
/// disambiguated name, never a bare `ct` in an object that also holds a KEM
/// ciphertext). Stored opaquely server-side; the server never parses it.
///
/// `deny_unknown_fields` enforces the hybrid side of the §5.2 symmetric field
/// validation: the required fields must be exactly present — a missing `ek`/`epk`
/// or a smuggled extra field is rejected at parse time (negative tests N1/N2/N5).
/// The unwrap path additionally selects the code path from `alg` **alone** (never
/// from field presence) and rejects any alg but the hybrid one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HybridWrapEnvelope {
    pub v: u32,
    pub alg: String,
    pub epk: EpkJwk,
    /// base64url(no-pad) of the 1568-byte ML-KEM-1024 ciphertext.
    pub ek: String,
    /// base64url(no-pad) of the 40-byte AES-KW output.
    pub wk: String,
    /// Recipient **hybrid** KEM pair-fingerprint (§8.5), lowercase hex.
    pub rfp: String,
}

impl HybridWrapEnvelope {
    /// The ephemeral public key as a 65-byte X9.63 uncompressed point — what a
    /// recipient hands its keystore's ECDH op (mirrors
    /// [`crate::wrap::WrapEnvelope::ephemeral_pubkey_x963`]).
    pub fn ephemeral_pubkey_x963(&self) -> Result<Vec<u8>> {
        x963_from_epk(&self.epk)
    }
}

/// Append one length-prefixed field: a big-endian `u32` length followed by the
/// bytes (PQR §4.3 — the same JOSE-`Datum` encoding the classical Concat-KDF uses,
/// so the `FixedInfo` has no field-boundary ambiguity).
fn push_field(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Build the SP 800-227 §4.6 `FixedInfo` (PQR §4.3), length-prefixed fields in this
/// exact order:
///
/// ```text
/// alg ‖ epk ‖ ek ‖ rk_ec ‖ rk_pq ‖ L(=256) ‖ party_v
/// ```
///
/// `party_v` is empty for a file-DEK wrap, or the 16-byte `root_folder_id` for a
/// metadata-key wrap (the P-015 folder binding; negative test N7). No `enc` field.
/// `rk_ec` / `rk_pq` MUST be the canonical encodings (X9.63 uncompressed for the EC
/// key; the FIPS 203 `ek` bytes for the ML-KEM key) — the wrapper and the recipient
/// bind the same bytes or the derived KEK diverges.
pub fn build_fixed_info(
    epk_x963: &[u8],
    ek: &[u8],
    rk_ec_x963: &[u8],
    rk_pq: &[u8],
    party_v: &[u8],
) -> Vec<u8> {
    let mut info = Vec::new();
    push_field(&mut info, HYBRID_ALG.as_jose().as_bytes());
    push_field(&mut info, epk_x963);
    push_field(&mut info, ek);
    push_field(&mut info, rk_ec_x963);
    push_field(&mut info, rk_pq);
    push_field(&mut info, &KEYDATALEN_BITS.to_be_bytes());
    push_field(&mut info, party_v);
    info
}

/// The SP 800-227 §4.6.2 KDM (PQR §4.2): `IKM = Z_ecdh ‖ Z_mlkem` (the SP 800-56A
/// secret first, normative), a zero-length HKDF-Extract salt (RFC 5869 §2.2 → 32
/// zero bytes), `FixedInfo` as the Expand `info`, `L = 32`. Both shared secrets
/// enter Extract as IKM; neither appears in the salt or FixedInfo.
///
/// §4.6 zeroization: the IKM buffer and the KDF output buffer are wiped, and the
/// KEK is returned [`Zeroizing`]. Named residual: the `hkdf` crate keeps its own
/// internal PRK copy that is not reachable to wipe (and Rust move semantics can
/// leave stack copies) — the boundary we own is zeroized; crate-internal residue
/// is the same best-effort posture the spec names for the web surface.
pub fn content_wrap_kek(
    z_ecdh: &[u8; 32],
    z_mlkem: &[u8; 32],
    fixed_info: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(z_ecdh);
    ikm[32..].copy_from_slice(z_mlkem);
    // salt = zero-length (== HashLen zeros, RFC 5869 §2.2); FixedInfo is the info.
    let mut kek = kdf::hkdf_sha256(&*ikm, &[], fixed_info, 32)?;
    let out =
        <[u8; 32]>::try_from(&kek[..]).map_err(|_| CryptoError::InvalidInput("hybrid kek length"));
    kek.zeroize();
    Ok(Zeroizing::new(out?))
}

/// The recipient **hybrid** KEM pair-fingerprint (PQR §8.5): a single commitment
/// over *both* recipient KEM public keys — `SHA-256(len(rk_ec) ‖ len(rk_pq))`,
/// lowercase hex. Because it commits to both keys, a PQ-stripped directory bundle
/// changes it (the transparency-layer detection property).
///
/// The commitment is only meaningful over the **canonical** encodings (§4.3 /
/// §8.5: X9.63 uncompressed for the EC key, the FIPS 203 `ek` bytes for the
/// ML-KEM key), so the inputs are validated — a non-canonical encoding would
/// silently produce a fingerprint no other party derives.
pub fn hybrid_rfp(rk_ec_x963: &[u8], rk_pq: &[u8]) -> Result<String> {
    validate_recipient_keys(rk_ec_x963, rk_pq)?;
    let mut lp = Vec::new();
    push_field(&mut lp, rk_ec_x963);
    push_field(&mut lp, rk_pq);
    Ok(hex::encode(Sha256::digest(&lp)))
}

/// Validate the recipient's hybrid KEM public keys are in the exact §4.3
/// canonical encodings: `rk_ec` a 65-byte X9.63 *uncompressed* P-256 point on
/// the curve; `rk_pq` a 1568-byte ML-KEM-1024 encapsulation key. The classical
/// wrap validates its recipient key up front (`wrap_to`); the hybrid seams do
/// the same. A wrong encoding here is fail-closed downstream (the KEK diverges),
/// but it would also bind a non-canonical `rfp`/`FixedInfo` — reject it at the
/// seam instead.
fn validate_recipient_keys(rk_ec_x963: &[u8], rk_pq: &[u8]) -> Result<()> {
    if rk_ec_x963.len() != 65 || rk_ec_x963[0] != 0x04 {
        return Err(CryptoError::InvalidInput(
            "rk_ec must be a 65-byte uncompressed x9.63 point",
        ));
    }
    PublicKey::from_sec1_bytes(rk_ec_x963)
        .map_err(|_| CryptoError::InvalidInput("rk_ec not on curve"))?;
    if rk_pq.len() != MLKEM1024_EK_LEN {
        return Err(CryptoError::InvalidInput(
            "rk_pq must be a 1568-byte ml-kem-1024 encapsulation key",
        ));
    }
    Ok(())
}

/// Validate `party_v` is one of the exactly two legal §4.3 values: empty (a
/// file-DEK wrap) or a 16-byte `root_folder_id` (a metadata-key wrap). The
/// classical API enforces this by type (`&[u8; 16]` at the metadata entry
/// points); the hybrid seam takes the generic slice, so it validates instead.
fn validate_party_v(party_v: &[u8]) -> Result<()> {
    if party_v.is_empty() || party_v.len() == 16 {
        Ok(())
    } else {
        Err(CryptoError::InvalidInput(
            "party_v must be empty or a 16-byte root_folder_id",
        ))
    }
}

/// Assemble a hybrid recipient block from the already-computed shared secrets and
/// wrap inputs (PQR §4.5 wrap). The caller computes `Z_ecdh` (an ephemeral-static
/// ECDH) and `(Z_mlkem, ek)` (ML-KEM-1024 encaps); this runs the combiner + AES-KW
/// and serializes the envelope. `epk_x963` is the sender's ephemeral P-256 public
/// key (validated + canonicalized to uncompressed X9.63 so wrap and unwrap bind
/// identical bytes); `party_v` is empty for a DEK, `root_folder_id` for a metadata
/// key.
#[allow(clippy::too_many_arguments)]
pub fn wrap_from_secrets(
    z_ecdh: &[u8; 32],
    z_mlkem: &[u8; 32],
    epk_x963: &[u8],
    ek: &[u8],
    rk_ec_x963: &[u8],
    rk_pq: &[u8],
    key: &[u8; 32],
    party_v: &[u8],
) -> Result<HybridWrapEnvelope> {
    validate_recipient_keys(rk_ec_x963, rk_pq)?;
    validate_party_v(party_v)?;
    if ek.len() != MLKEM1024_CT_LEN {
        return Err(CryptoError::InvalidInput("ml-kem ciphertext length"));
    }
    let pk = p256_pub(epk_x963)?;
    let epk_canon = pk.to_encoded_point(false).as_bytes().to_vec(); // 65-byte uncompressed
    let fixed_info = build_fixed_info(&epk_canon, ek, rk_ec_x963, rk_pq, party_v);
    let kek = content_wrap_kek(z_ecdh, z_mlkem, &fixed_info)?;
    let wk = keywrap::wrap(&kek, key)?;
    Ok(HybridWrapEnvelope {
        v: 1,
        alg: HYBRID_ALG.as_jose().to_string(),
        epk: epk_jwk(&pk),
        ek: URL_SAFE_NO_PAD.encode(ek),
        wk: URL_SAFE_NO_PAD.encode(&wk),
        rfp: hybrid_rfp(rk_ec_x963, rk_pq)?,
    })
}

/// Unwrap a hybrid recipient block given the two shared secrets (PQR §5.3). Both
/// `Z_ecdh` (the keystore's ECDH op) and `Z_mlkem` (the keystore's ML-KEM decap op)
/// are computed by the SE/keystore so the recipient's private keys never leave it.
/// The recipient supplies their own static KEM public keys (`rk_ec`, `rk_pq`) to
/// reconstruct the `FixedInfo` — the recipient binding (negative test N4). `party_v`
/// MUST match the wrap-time value or AES-KW's integrity check rejects (N7).
///
/// The code path is selected from `alg` **alone** (§5.2): any alg but the hybrid
/// one is rejected before any key material is derived.
pub fn unwrap_with_shared_secrets(
    z_ecdh: &[u8; 32],
    z_mlkem: &[u8; 32],
    envelope: &HybridWrapEnvelope,
    rk_ec_x963: &[u8],
    rk_pq: &[u8],
    party_v: &[u8],
) -> Result<[u8; 32]> {
    if AlgId::from_jose(&envelope.alg)? != HYBRID_ALG {
        return Err(CryptoError::UnknownAlgorithm);
    }
    validate_recipient_keys(rk_ec_x963, rk_pq)?;
    validate_party_v(party_v)?;
    let epk_x963 = x963_from_epk(&envelope.epk)?;
    let ek = URL_SAFE_NO_PAD
        .decode(envelope.ek.as_bytes())
        .map_err(|_| CryptoError::InvalidInput("ek base64url"))?;
    if ek.len() != MLKEM1024_CT_LEN {
        return Err(CryptoError::InvalidInput("ml-kem ciphertext length"));
    }
    let fixed_info = build_fixed_info(&epk_x963, &ek, rk_ec_x963, rk_pq, party_v);
    let kek = content_wrap_kek(z_ecdh, z_mlkem, &fixed_info)?;
    let wrapped = URL_SAFE_NO_PAD
        .decode(envelope.wk.as_bytes())
        .map_err(|_| CryptoError::InvalidInput("wk base64url"))?;
    fixed32(keywrap::unwrap(&kek, &wrapped)?)
}

/// Validate a 65-byte X9.63 P-256 point (on the curve) for the ephemeral `epk`.
fn p256_pub(x963: &[u8]) -> Result<PublicKey> {
    PublicKey::from_sec1_bytes(x963).map_err(|_| CryptoError::InvalidInput("epk not on curve"))
}
