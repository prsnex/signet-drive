// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Tier-1 differential tests vs OpenSSL (the assurance backbone, layer 2 of 2).
//!
//! For each primitive, run our RustCrypto implementation and OpenSSL on the same
//! inputs and assert byte-for-byte agreement (or, for non-deterministic ECDSA,
//! cross-verification). OpenSSL is a separate C codebase of a different lineage
//! from RustCrypto, so agreement is genuine evidence — not the self-consistency
//! that testing RustCrypto against RustCrypto would give. Inputs are randomized
//! across a range of lengths so the check covers more than the fixed KAT points.
//!
//! OpenSSL here is a **dev-dependency only** (never shipped). It builds against
//! system OpenSSL (ubuntu-latest CI has it; macOS via auto-detected Homebrew, or
//! `OPENSSL_DIR=/opt/homebrew/opt/openssl@3`).

use rand_core::{OsRng, RngCore};
use signet_crypto::{aead, hash, keywrap};

// HKDF-SHA-256 is not differential-tested here: its authoritative answer key is
// the RFC 5869 published vector suite (see `kat.rs`, incl. the empty-salt TC3
// that matches the §8.2 wrap-key derivation), which is a stronger reference than
// re-deriving against OpenSSL's EVP HKDF would be.

fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    OsRng.fill_bytes(&mut v);
    v
}

fn arr<const N: usize>(v: &[u8]) -> [u8; N] {
    v.try_into().expect("fixed-length slice")
}

// ---------------------------------------------------------------------------
// SHA-256 vs openssl::sha::sha256.
// ---------------------------------------------------------------------------

#[test]
fn sha256_matches_openssl() {
    for len in [0usize, 1, 31, 32, 33, 64, 1000] {
        let input = random_bytes(len);
        assert_eq!(
            hash::sha256(&input),
            openssl::sha::sha256(&input),
            "SHA-256 disagreement at len {len}",
        );
    }
}

// ---------------------------------------------------------------------------
// AES-256-GCM vs openssl::symm. Byte-equal ciphertext+tag, and cross-decrypt
// each direction.
// ---------------------------------------------------------------------------

#[test]
fn aes_256_gcm_matches_openssl() {
    let cipher = openssl::symm::Cipher::aes_256_gcm();
    for pt_len in [0usize, 1, 16, 60, 256] {
        let key = random_bytes(32);
        let iv = random_bytes(12);
        let aad = random_bytes(20);
        let pt = random_bytes(pt_len);
        let key32 = arr::<32>(&key);
        let iv12 = arr::<12>(&iv);

        // ours: sealed == ct || tag.
        let sealed = aead::seal(&key32, &iv12, &pt, &aad).unwrap();
        let (our_ct, our_tag) = sealed.split_at(sealed.len() - 16);

        // openssl seal.
        let mut ossl_tag = [0u8; 16];
        let ossl_ct =
            openssl::symm::encrypt_aead(cipher, &key, Some(&iv), &aad, &pt, &mut ossl_tag).unwrap();
        assert_eq!(our_ct, ossl_ct.as_slice(), "GCM ciphertext at len {pt_len}");
        assert_eq!(our_tag, ossl_tag, "GCM tag at len {pt_len}");

        // cross-decrypt: openssl opens ours; ours opens openssl's.
        let ossl_open =
            openssl::symm::decrypt_aead(cipher, &key, Some(&iv), &aad, our_ct, our_tag).unwrap();
        assert_eq!(ossl_open, pt);
        let mut ossl_sealed = ossl_ct.clone();
        ossl_sealed.extend_from_slice(&ossl_tag);
        assert_eq!(aead::open(&key32, &iv12, &ossl_sealed, &aad).unwrap(), pt);
    }
}

// ---------------------------------------------------------------------------
// AES-256 Key Wrap vs openssl::aes (RFC 3394, default IV). Byte-equal wrap, and
// cross-unwrap each direction.
// ---------------------------------------------------------------------------

#[test]
fn aes_256_kw_matches_openssl() {
    for kd_len in [16usize, 24, 32, 64] {
        let kek = random_bytes(32);
        let kek32 = arr::<32>(&kek);
        let key_data = random_bytes(kd_len);

        let our_wrapped = keywrap::wrap(&kek32, &key_data).unwrap();

        // openssl wrap — `None` IV selects the RFC 3394 default (0xA6A6A6A6A6A6A6A6).
        let enc = openssl::aes::AesKey::new_encrypt(&kek).unwrap();
        let mut ossl_wrapped = vec![0u8; kd_len + 8];
        let n = openssl::aes::wrap_key(&enc, None, &mut ossl_wrapped, &key_data).unwrap();
        assert_eq!(n, kd_len + 8);
        assert_eq!(our_wrapped, ossl_wrapped, "AES-KW wrap at len {kd_len}");

        // cross-unwrap.
        assert_eq!(keywrap::unwrap(&kek32, &ossl_wrapped).unwrap(), key_data);
        let dec = openssl::aes::AesKey::new_decrypt(&kek).unwrap();
        let mut ossl_unwrapped = vec![0u8; kd_len];
        openssl::aes::unwrap_key(&dec, None, &mut ossl_unwrapped, &our_wrapped).unwrap();
        assert_eq!(ossl_unwrapped, key_data);
    }
}

// ---------------------------------------------------------------------------
// ECDH P-256 vs openssl::derive::Deriver. Same key material both sides; the
// derived shared secret Z (the shared point's x-coordinate) must match.
// ---------------------------------------------------------------------------

#[test]
fn ecdh_p256_matches_openssl() {
    use openssl::bn::{BigNum, BigNumContext};
    use openssl::derive::Deriver;
    use openssl::ec::{EcGroup, EcKey, EcPoint};
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use p256::SecretKey;

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let mut ctx = BigNumContext::new().unwrap();

    for _ in 0..8 {
        let ours = SecretKey::random(&mut OsRng);
        let peer = SecretKey::random(&mut OsRng);
        let our_scalar: [u8; 32] = ours.to_bytes().into();
        let our_pub = ours.public_key().to_sec1_bytes().to_vec();
        let peer_pub = peer.public_key().to_sec1_bytes().to_vec();

        let our_z = signet_crypto::ecdh::ecdh_p256(&our_scalar, &peer_pub).unwrap();

        // Rebuild the same private + peer-public keys in OpenSSL and derive.
        let our_point = EcPoint::from_bytes(&group, &our_pub, &mut ctx).unwrap();
        let our_ec = EcKey::from_private_components(
            &group,
            &BigNum::from_slice(&our_scalar).unwrap(),
            &our_point,
        )
        .unwrap();
        let our_pkey = PKey::from_ec_key(our_ec).unwrap();
        let peer_point = EcPoint::from_bytes(&group, &peer_pub, &mut ctx).unwrap();
        let peer_pkey =
            PKey::from_ec_key(EcKey::from_public_key(&group, &peer_point).unwrap()).unwrap();

        let mut deriver = Deriver::new(&our_pkey).unwrap();
        deriver.set_peer(&peer_pkey).unwrap();
        let ossl_z = deriver.derive_to_vec().unwrap();

        assert_eq!(
            our_z.as_slice(),
            ossl_z.as_slice(),
            "ECDH Z mismatch vs OpenSSL"
        );
    }
}

// ---------------------------------------------------------------------------
// ECDSA P-256 (ES256) cross-verification vs OpenSSL. Signatures are
// non-deterministic, so we cross-*verify* rather than compare bytes: OpenSSL
// accepts our raw r‖s, and we accept OpenSSL's DER (exercising the §6.2 dual
// signature-encoding acceptance).
// ---------------------------------------------------------------------------

#[test]
fn ecdsa_es256_cross_verifies_with_openssl() {
    use openssl::bn::{BigNum, BigNumContext};
    use openssl::ec::{EcGroup, EcKey, EcPoint};
    use openssl::ecdsa::EcdsaSig;
    use openssl::nid::Nid;
    use p256::SecretKey;
    use signet_crypto::ecdsa;

    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let mut ctx = BigNumContext::new().unwrap();

    for _ in 0..8 {
        let sk = SecretKey::random(&mut OsRng);
        let scalar: [u8; 32] = sk.to_bytes().into();
        let pub_x963 = sk.public_key().to_sec1_bytes().to_vec();
        let msg = b"differential ES256 message";
        let digest = openssl::sha::sha256(msg);

        let point = EcPoint::from_bytes(&group, &pub_x963, &mut ctx).unwrap();
        let ec_pub = EcKey::from_public_key(&group, &point).unwrap();
        let ec_priv =
            EcKey::from_private_components(&group, &BigNum::from_slice(&scalar).unwrap(), &point)
                .unwrap();

        // ours -> OpenSSL: our raw r‖s, reassembled as an EcdsaSig and verified.
        let our_sig = ecdsa::sign_es256(&scalar, msg).unwrap();
        let r = BigNum::from_slice(&our_sig[..32]).unwrap();
        let s = BigNum::from_slice(&our_sig[32..]).unwrap();
        let our_as_ossl = EcdsaSig::from_private_components(r, s).unwrap();
        assert!(
            our_as_ossl.verify(&digest, &ec_pub).unwrap(),
            "OpenSSL rejected our ES256 signature",
        );

        // OpenSSL -> ours: OpenSSL's DER signature, verified by us.
        let ossl_sig = EcdsaSig::sign(&digest, &ec_priv).unwrap();
        let der = ossl_sig.to_der().unwrap();
        assert!(
            ecdsa::verify_es256(&pub_x963, msg, &der).is_ok(),
            "we rejected OpenSSL's ES256 DER signature",
        );
    }
}
