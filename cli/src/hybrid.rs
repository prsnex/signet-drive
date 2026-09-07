// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! CLI-side hybrid content-wrap plumbing (PQR Spec §4.5 / §5.3 — the PRSN
//! surface's half of item 4, plus the §9.2 writer discipline).
//!
//! **Writer** ([`wrap_key_hybrid`]): a fresh ephemeral P-256 ECDH + a software
//! ML-KEM-1024 encapsulation to the RECIPIENT's keys — both public-key
//! operations with no Secure-Enclave or broker role — feeding signet-crypto's
//! co-signed combiner (`hybrid_wrap::wrap_from_secrets`). The ML-KEM crate is
//! the same RustCrypto `ml-kem` the wasm module and the §11.2 differential
//! tests pin: one implementation across every writer surface.
//!
//! **Reader** ([`unwrap_key_hybrid`]): the recipient's private keys never
//! surface — `Z_ecdh` comes from the keystore's `ecdh` op and `Z_mlkem` from
//! its `ml_kem_decapsulate` op (broker → Secure Enclave, or the mount
//! fallback), then the §5.3 two-shared-secret unwrap runs in-process. Per
//! FIPS 203 implicit rejection (§10), a tampered `ek` yields a pseudorandom
//! secret and the failure surfaces at AES-KW integrity — never at decap.

use kem::Encapsulate;
use ml_kem::{EncodedSizeUser, KemCore, MlKem1024};
use rand_core::OsRng;
use signet_crypto::hybrid_wrap::{self, HybridWrapEnvelope, MLKEM1024_EK_LEN};
use zeroize::Zeroizing;

use crate::error::{CliError, Result};
use crate::keystore::{KeyLabel, Keystore};

/// Encapsulate to a recipient's ML-KEM-1024 encapsulation key: `(ek, Z_mlkem)`
/// per §4.1 step 2. Public-key op; randomness from the OS CSPRNG.
fn encapsulate(rk_pq: &[u8]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    if rk_pq.len() != MLKEM1024_EK_LEN {
        return Err(CliError::invalid_data(
            "recipient ML-KEM key must be 1568 bytes",
        ));
    }
    let ek_arr = ml_kem::Encoded::<<MlKem1024 as KemCore>::EncapsulationKey>::try_from(rk_pq)
        .map_err(|_| CliError::invalid_data("recipient ML-KEM key size"))?;
    let ek = <MlKem1024 as KemCore>::EncapsulationKey::from_bytes(&ek_arr);
    let (ct, ss) = ek
        .encapsulate(&mut OsRng)
        .map_err(|_| CliError::encryption_failed("ml-kem encapsulation failed"))?;
    let mut z = Zeroizing::new([0u8; 32]);
    z.copy_from_slice(ss.as_slice());
    Ok((ct.as_slice().to_vec(), z))
}

/// Wrap a 32-byte key (DEK or metadata key) to a recipient's HYBRID KEM public
/// keys (§4.5): ephemeral ECDH + ML-KEM encaps → the SP 800-227 §4.6 combiner →
/// AES-KW → the §5.2 recipient block. `party_v` is empty for a DEK, the
/// 16-byte `root_folder_id` for a metadata key.
pub fn wrap_key_hybrid(
    rk_ec_x963: &[u8],
    rk_pq: &[u8],
    key: &[u8; 32],
    party_v: &[u8],
) -> Result<HybridWrapEnvelope> {
    let (eph_scalar, eph_pub) = signet_crypto::ecdh::generate_keypair();
    let eph_scalar = Zeroizing::new(eph_scalar);
    let z_ecdh = Zeroizing::new(
        signet_crypto::ecdh::ecdh_p256(&eph_scalar, rk_ec_x963)
            .map_err(|_| CliError::encryption_failed("ephemeral ECDH failed"))?,
    );
    let (ek, z_mlkem) = encapsulate(rk_pq)?;
    hybrid_wrap::wrap_from_secrets(
        &z_ecdh, &z_mlkem, &eph_pub, &ek, rk_ec_x963, rk_pq, key, party_v,
    )
    .map_err(|_| CliError::encryption_failed("hybrid wrap failed"))
}

/// Unwrap a §5.2 hybrid recipient block addressed to ME (§5.3): both shared
/// secrets come from the keystore (`ecdh` + `ml_kem_decapsulate` — the private
/// keys stay in the Enclave), and my own static public keys (keystore `meta`)
/// reconstruct the FixedInfo recipient binding (N4).
pub fn unwrap_key_hybrid(
    keystore: &dyn Keystore,
    kem_label: &KeyLabel,
    kem_pq_label: &KeyLabel,
    envelope: &HybridWrapEnvelope,
    party_v: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let epk = envelope
        .ephemeral_pubkey_x963()
        .map_err(|_| CliError::invalid_data("hybrid wrap epk"))?;
    let ek = base64_decode_field(&envelope.ek, "ek")?;
    let z_ecdh = Zeroizing::new(keystore.ecdh(kem_label, &epk)?);
    let z_mlkem = Zeroizing::new(keystore.ml_kem_decapsulate(kem_pq_label, &ek)?);
    let rk_ec = keystore.meta(kem_label)?.public_key;
    let rk_pq = keystore.meta(kem_pq_label)?.public_key;
    Ok(Zeroizing::new(hybrid_wrap::unwrap_with_shared_secrets(
        &z_ecdh, &z_mlkem, envelope, &rk_ec, &rk_pq, party_v,
    )?))
}

fn base64_decode_field(value: &str, field: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| CliError::invalid_data(format!("hybrid wrap {field} is not base64url")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writer-side round-trip against a software recipient: the CLI's
    /// ephemeral-ECDH + encaps feed the combiner such that the recipient's
    /// software decap + ECDH recover the same key (the keystore-free half;
    /// the keystore reader path is covered by the crossover golden test).
    #[test]
    fn wrap_key_hybrid_round_trips_against_software_recipient() {
        use kem::Decapsulate;

        // A software hybrid recipient.
        let (rk_scalar, rk_ec) = signet_crypto::ecdh::generate_keypair();
        let d = ml_kem::B32::try_from(&[0x11u8; 32][..]).unwrap();
        let z = ml_kem::B32::try_from(&[0x22u8; 32][..]).unwrap();
        let (dk, ek_obj) = MlKem1024::generate_deterministic(&d, &z);
        let rk_pq = ek_obj.as_bytes().to_vec();

        let key = [0x42u8; 32];
        let env = wrap_key_hybrid(&rk_ec, &rk_pq, &key, &[]).expect("wrap");
        assert_eq!(env.alg, "ECDH-ES+ML-KEM-1024+A256KW");

        // Recipient side, in software: Z_ecdh + Z_mlkem → the §5.3 unwrap.
        let epk = env.ephemeral_pubkey_x963().unwrap();
        let z_ecdh = signet_crypto::ecdh::ecdh_p256(&rk_scalar, &epk).unwrap();
        let ek = base64_decode_field(&env.ek, "ek").unwrap();
        let ct = ml_kem::Ciphertext::<MlKem1024>::try_from(&ek[..]).unwrap();
        let z_mlkem: [u8; 32] = dk.decapsulate(&ct).unwrap().into();
        let got =
            hybrid_wrap::unwrap_with_shared_secrets(&z_ecdh, &z_mlkem, &env, &rk_ec, &rk_pq, &[])
                .expect("unwrap");
        assert_eq!(got, key);
    }
}
