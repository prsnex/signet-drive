// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! The human surface's ML-KEM-1024 module (PQR item 4 — the wasm32 half of the
//! hybrid content-wrap, PQR Crypto Spec §7).
//!
//! **One implementation, two compile targets:** this is the same RustCrypto
//! `ml-kem` crate the CLI's Secure-Enclave differential tests validate against
//! (spec §11.2), compiled to wasm32 for the browser — so the §11.3 cross-target
//! byte-equality goldens come free (the KATs below run natively on CI *and* in
//! wasm via `wasm-pack test`).
//!
//! **Key custody (spec §7):** the browser stores only the **64-byte (d,z)
//! seed**, riding the PRF-wrapped blob (layout v2, version byte `0x02`); the
//! ~3 KB decapsulation key regenerates from the seed at sign-in (FIPS 203
//! KeyGen determinism) and lives in WASM memory for the session. Zeroization
//! is best-effort across the JS boundary — the same posture the 1-Pager
//! documents for the web surface (the DEK already transits JS memory).
//!
//! **What this module deliberately is NOT:** the hybrid combiner. KeyCombine +
//! FixedInfo + AES-KW live in the web's TypeScript wrap path (`wrap.ts`,
//! S107) exactly as they live in `crypto/src/hybrid_wrap.rs` for the CLI —
//! this module only supplies the ML-KEM primitive operations, mirroring the
//! keystore's role on the PRSN side.
//!
//! **Structure:** the core functions are pure Rust (`Result<_, &'static str>`)
//! so they compile and test identically on both targets; the `#[wasm_bindgen]`
//! exports are thin wasm32-only wrappers (a `JsError` cannot even be
//! constructed off-wasm). JS boundary + vite/CSP/manifest wiring: item 6 +
//! the item-4 continuation (S107). This crate is the primitive layer those
//! build on.

use kem::{Decapsulate, Encapsulate};
use ml_kem::{B32, EncodedSizeUser, KemCore, MlKem1024};
use zeroize::Zeroizing;

/// FIPS 203 ML-KEM-1024 sizes (PQR Spec §2).
pub const EK_LEN: usize = 1568;
pub const CT_LEN: usize = 1568;
pub const SS_LEN: usize = 32;
/// The stored secret: the (d,z) seed — 2 × 32 bytes (spec §7).
pub const SEED_LEN: usize = 64;

/// Split a 64-byte seed into (d, z).
fn split_seed(seed: &[u8]) -> Result<(B32, B32), &'static str> {
    if seed.len() != SEED_LEN {
        return Err("ml-kem seed must be 64 bytes (d ‖ z)");
    }
    let d = B32::try_from(&seed[..32]).expect("32-byte slice");
    let z = B32::try_from(&seed[32..]).expect("32-byte slice");
    Ok((d, z))
}

/// Regenerate the keypair from the stored seed (FIPS 203 KeyGen determinism —
/// the spec §7 custody model).
#[allow(clippy::type_complexity)]
fn keypair_from_seed(
    seed: &[u8],
) -> Result<
    (
        <MlKem1024 as KemCore>::DecapsulationKey,
        <MlKem1024 as KemCore>::EncapsulationKey,
    ),
    &'static str,
> {
    let (d, z) = split_seed(seed)?;
    Ok(MlKem1024::generate_deterministic(&d, &z))
}

/// Generate a fresh ML-KEM-1024 identity: 64 random seed bytes from the
/// platform CSPRNG (`crypto.getRandomValues` in the browser via getrandom's
/// js backend). Returns `seed(64) ‖ ek(1568)` — the caller splits, PRF-wraps
/// the seed (blob layout v2) and publishes the ek.
pub fn keygen() -> Result<Vec<u8>, &'static str> {
    let mut seed = Zeroizing::new([0u8; SEED_LEN]);
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, seed.as_mut());
    let (_dk, ek) = keypair_from_seed(seed.as_ref())?;
    let mut out = Vec::with_capacity(SEED_LEN + EK_LEN);
    out.extend_from_slice(seed.as_ref());
    out.extend_from_slice(&ek.as_bytes());
    Ok(out)
}

/// Recompute the encapsulation key (1568 B) from a stored seed — the sign-in
/// path's self-check that the unwrapped seed matches the published directory ek.
pub fn ek_from_seed(seed: &[u8]) -> Result<Vec<u8>, &'static str> {
    let (_dk, ek) = keypair_from_seed(seed)?;
    Ok(ek.as_bytes().to_vec())
}

/// Encapsulate to a recipient's ek (the writer side of the hybrid wrap, spec
/// §4.1): returns `ct(1568) ‖ ss(32)`. Randomness from the platform CSPRNG.
pub fn encapsulate(recipient_ek: &[u8]) -> Result<Vec<u8>, &'static str> {
    if recipient_ek.len() != EK_LEN {
        return Err("ml-kem encapsulation key must be 1568 bytes");
    }
    let ek_arr =
        ml_kem::Encoded::<<MlKem1024 as KemCore>::EncapsulationKey>::try_from(recipient_ek)
            .map_err(|_| "ml-kem encapsulation key size")?;
    let ek = <MlKem1024 as KemCore>::EncapsulationKey::from_bytes(&ek_arr);
    let (ct, ss) = ek
        .encapsulate(&mut rand_core::OsRng)
        .map_err(|_| "ml-kem encapsulation failed")?;
    let mut out = Vec::with_capacity(CT_LEN + SS_LEN);
    out.extend_from_slice(ct.as_slice());
    out.extend_from_slice(ss.as_slice());
    Ok(out)
}

/// Decapsulate a 1568-byte ciphertext with the seed-regenerated key → the
/// 32-byte shared secret. Per FIPS 203 implicit rejection (spec §10) a
/// tampered ciphertext does NOT error — it yields a pseudorandom secret; the
/// failure surfaces downstream at AES-KW.
pub fn decapsulate(seed: &[u8], ct: &[u8]) -> Result<Vec<u8>, &'static str> {
    if ct.len() != CT_LEN {
        return Err("ml-kem ciphertext must be 1568 bytes");
    }
    let (dk, _ek) = keypair_from_seed(seed)?;
    let ct_arr =
        ml_kem::Ciphertext::<MlKem1024>::try_from(ct).map_err(|_| "ml-kem ciphertext size")?;
    let ss = dk
        .decapsulate(&ct_arr)
        .map_err(|_| "ml-kem decapsulation failed")?;
    Ok(ss.as_slice().to_vec())
}

/// The VRF input for an account: `signet_crypto::vrf::alpha`, byte for byte
/// (domain ‖ 0x00 ‖ the UUID's 16 bytes; the native test pins the two).
const VRF_ALPHA_DOMAIN: &[u8] = b"signet-pubkey-log-v3-account-index";

/// The transparency log's v3 account index that `proof` proves for
/// `account_id` (a UUID's 16 bytes) under the epoch's VRF `public_key`
/// (Transparency-Log Epoch-2 design §2, §10.6): ECVRF-RISTRETTO255-SHA512
/// through the same pinned `vrf-r255` the server and the CLI use. Fails
/// closed: a malformed key or proof, and a proof that does not verify, return
/// no index.
pub fn vrf_verify(
    public_key: &[u8],
    account_id: &[u8],
    proof: &[u8],
) -> Result<Vec<u8>, &'static str> {
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| "vrf public key must be 32 bytes")?;
    let account_id: &[u8; 16] = account_id
        .try_into()
        .map_err(|_| "account id must be 16 bytes")?;
    let proof: [u8; 80] = proof.try_into().map_err(|_| "vrf proof must be 80 bytes")?;
    let pk = vrf_r255::PublicKey::from_bytes(public_key).ok_or("malformed vrf public key")?;
    let pi = vrf_r255::Proof::from_bytes(proof).ok_or("malformed vrf proof")?;
    let mut alpha = Vec::with_capacity(VRF_ALPHA_DOMAIN.len() + 1 + 16);
    alpha.extend_from_slice(VRF_ALPHA_DOMAIN);
    alpha.push(0x00);
    alpha.extend_from_slice(account_id);
    Option::<[u8; 64]>::from(pk.verify(&alpha, &pi))
        .map(|index| index.to_vec())
        .ok_or("vrf proof does not verify")
}

/// The wasm32-only JS exports — thin wrappers mapping the core's errors to
/// `JsError` (which cannot be constructed on non-wasm targets).
#[cfg(target_arch = "wasm32")]
mod js {
    use wasm_bindgen::prelude::*;

    fn err(msg: &str) -> JsError {
        JsError::new(msg)
    }

    #[wasm_bindgen]
    pub fn mlkem1024_keygen() -> Result<Vec<u8>, JsError> {
        super::keygen().map_err(err)
    }

    #[wasm_bindgen]
    pub fn mlkem1024_ek_from_seed(seed: &[u8]) -> Result<Vec<u8>, JsError> {
        super::ek_from_seed(seed).map_err(err)
    }

    #[wasm_bindgen]
    pub fn mlkem1024_encapsulate(recipient_ek: &[u8]) -> Result<Vec<u8>, JsError> {
        super::encapsulate(recipient_ek).map_err(err)
    }

    #[wasm_bindgen]
    pub fn mlkem1024_decapsulate(seed: &[u8], ct: &[u8]) -> Result<Vec<u8>, JsError> {
        super::decapsulate(seed, ct).map_err(err)
    }

    #[wasm_bindgen]
    pub fn vrf_r255_verify(
        public_key: &[u8],
        account_id: &[u8],
        proof: &[u8],
    ) -> Result<Vec<u8>, JsError> {
        super::vrf_verify(public_key, account_id, proof).map_err(err)
    }
}

#[cfg(test)]
mod tests {
    //! The §11.3 cross-target KATs: these run natively on CI AND in wasm
    //! (`wasm-pack test --node` runs this same module via wasm-bindgen-test's
    //! test runner) — the same pinned bytes on both compile targets is the
    //! byte-equality leg. The pin detects MISCOMPILES across targets; FIPS
    //! correctness of the crate itself is the ACVP harness's job (item 9).
    use super::*;
    use sha2::{Digest, Sha256};

    #[cfg(target_arch = "wasm32")]
    use wasm_bindgen_test::wasm_bindgen_test;

    /// A fixed all-0x42 seed → the ek's SHA-256, pinned. Derived natively from
    /// ml-kem 0.2.3 (S106); the wasm leg must reproduce it byte-for-byte.
    const KAT_SEED_BYTE: u8 = 0x42;
    const KAT_EK_SHA256: &str = "dd2e8fe4ffe00e224daab15f6d5f90516754ef13aa25cea525f5d55f520d0137";

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn kat_seed_keygen_is_deterministic_and_pinned() {
        let seed = [KAT_SEED_BYTE; SEED_LEN];
        let ek1 = ek_from_seed(&seed).unwrap();
        let ek2 = ek_from_seed(&seed).unwrap();
        assert_eq!(ek1, ek2, "FIPS 203 KeyGen must be deterministic");
        assert_eq!(ek1.len(), EK_LEN);
        assert_eq!(
            hex::encode(Sha256::digest(&ek1)),
            KAT_EK_SHA256,
            "the pinned cross-target ek digest"
        );
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn keygen_roundtrip_encaps_decaps() {
        let out = keygen().unwrap();
        assert_eq!(out.len(), SEED_LEN + EK_LEN);
        let (seed, ek) = out.split_at(SEED_LEN);

        let enc = encapsulate(ek).unwrap();
        assert_eq!(enc.len(), CT_LEN + SS_LEN);
        let (ct, ss_writer) = enc.split_at(CT_LEN);

        let ss_recipient = decapsulate(seed, ct).unwrap();
        assert_eq!(ss_writer, ss_recipient.as_slice());

        // Implicit rejection (spec §10): a tampered ct decapsulates without
        // error to a different secret.
        let mut ct_bad = ct.to_vec();
        ct_bad[0] ^= 0x01;
        let ss_bad = decapsulate(seed, &ct_bad).unwrap();
        assert_ne!(ss_bad.as_slice(), ss_writer);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn input_validation_fails_fast() {
        assert!(ek_from_seed(&[0u8; 63]).is_err());
        assert!(encapsulate(&[0u8; 1567]).is_err());
        assert!(decapsulate(&[0u8; 64], &[0u8; 1569]).is_err());
    }

    // ---- the VRF account index (Transparency-Log Epoch-2 design §10.6) ----

    /// A known answer from the server's own implementation (`signet_crypto::vrf`,
    /// secret key 0x01 × 32): the same bytes on both compile targets.
    const VRF_PK: &str = "3e440469a098036d89ffb2d77a4542928f2f74c2b5769da7480736ace829dc10";
    const VRF_ACCOUNT: [u8; 16] = [
        0xCA, 0xFE, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0xBE, 0xEF,
    ];
    const VRF_PROOF: &str = "02ea537b0797536f1c299db70c48b77ac1a2fba463e45602b3216adea310be06\
                             a207adf81c21914edb94d9c0581f111145df4282e0ab7ef331d9e03d65431897\
                             ab5becdf48a56bd9b26875661db6ba00";
    const VRF_INDEX: &str = "69f8f2ca9cc69e6e18aa9bef8dcbb0f6df0ff32e46b9c60f7b6da89850f82f98\
                             b9a038a32b8c22204821abcfdfd5ae5f2d1bcf55ff3c6d6300accbfa2e1cad55";

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn kat_vrf_index_is_pinned() {
        let index = vrf_verify(
            &hex::decode(VRF_PK).unwrap(),
            &VRF_ACCOUNT,
            &hex::decode(VRF_PROOF).unwrap(),
        )
        .unwrap();
        assert_eq!(hex::encode(index), VRF_INDEX);
    }

    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    #[cfg_attr(not(target_arch = "wasm32"), test)]
    fn vrf_refuses_another_account_an_altered_proof_and_bad_lengths() {
        let pk = hex::decode(VRF_PK).unwrap();
        let proof = hex::decode(VRF_PROOF).unwrap();
        let mut other = VRF_ACCOUNT;
        other[15] ^= 1;
        assert!(vrf_verify(&pk, &other, &proof).is_err());
        let mut altered = proof.clone();
        altered[40] ^= 1;
        assert!(vrf_verify(&pk, &VRF_ACCOUNT, &altered).is_err());
        assert!(vrf_verify(&pk[..31], &VRF_ACCOUNT, &proof).is_err());
        assert!(vrf_verify(&pk, &VRF_ACCOUNT[..15], &proof).is_err());
        assert!(vrf_verify(&pk, &VRF_ACCOUNT, &proof[..79]).is_err());
    }

    /// The native cross-check: what the server proves, this module verifies to
    /// the same index, so the framing here is `signet_crypto::vrf::alpha`'s.
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn vrf_matches_signet_crypto_byte_for_byte() {
        for seed in 1u8..=8 {
            let sk = signet_crypto::vrf::VrfSecretKey::from_bytes(&[seed; 32]).unwrap();
            let account = [seed.wrapping_mul(37); 16];
            let (index, proof) = sk.prove(&account).unwrap();
            assert_eq!(
                vrf_verify(&sk.public_key(), &account, &proof).unwrap(),
                index.to_vec()
            );
        }
    }
}
