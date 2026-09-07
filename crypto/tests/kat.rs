// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Tier-1 known-answer tests (the assurance backbone, layer 1 of 2).
//!
//! Each primitive is pinned against a **published** vector — NIST or IETF, an
//! authoritative answer key independent of any implementation — plus round-trip
//! and negative tests that need no oracle. The differential-vs-OpenSSL layer
//! (`differential.rs`) complements these on arbitrary inputs. A KAT that fails
//! while the differential passes means *this file's expected bytes* are wrong,
//! not the implementation — that diagnosis split is the point of running both.

use signet_crypto::{aead, concatkdf, ecdh, ecdsa, hash, kdf, keywrap};

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s).expect("test vector hex")
}

fn hx32(s: &str) -> [u8; 32] {
    hx(s).try_into().expect("32-byte test vector")
}

// ---------------------------------------------------------------------------
// SHA-256 — FIPS 180-4 (the canonical empty and "abc" digests).
// ---------------------------------------------------------------------------

#[test]
fn sha256_empty_fips_180_4() {
    // The empty-input digest also appears in Envelope §6.2 (the SIGNET-V1
    // empty-body hash) and test-vectors Cat 04.
    assert_eq!(
        hash::sha256(b""),
        hx32("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    );
}

#[test]
fn sha256_abc_fips_180_4() {
    assert_eq!(
        hash::sha256(b"abc"),
        hx32("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    );
}

// ---------------------------------------------------------------------------
// AES-256-GCM — McGrew & Viega GCM spec / NIST SP 800-38D, Test Case 16.
// ---------------------------------------------------------------------------

#[test]
fn aes_256_gcm_nist_test_case_16() {
    let key = hx32("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
    let iv: [u8; 12] = hx("cafebabefacedbaddecaf888").try_into().unwrap();
    let pt = hx(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0\
         e2449a6b525b16aedf5aa0de657ba637b39",
    );
    let aad = hx("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    let expected_ct = hx(
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08\
         b1056828838c5f61e6393ba7a0abcc9f662",
    );
    let expected_tag = hx("76fc6ece0f4e1768cddf8853bb2d551b");

    // seal returns ct || tag.
    let sealed = aead::seal(&key, &iv, &pt, &aad).unwrap();
    let (ct, tag) = sealed.split_at(sealed.len() - 16);
    assert_eq!(ct, expected_ct.as_slice(), "ciphertext");
    assert_eq!(tag, expected_tag.as_slice(), "tag");

    // open recovers the plaintext.
    assert_eq!(aead::open(&key, &iv, &sealed, &aad).unwrap(), pt);
}

#[test]
fn aes_256_gcm_round_trip_and_negatives() {
    let key = [7u8; 32];
    let iv = [9u8; 12];
    let pt = b"signet drive opaque ciphertext payload";
    let aad = b"file-id-aad";

    let sealed = aead::seal(&key, &iv, pt, aad).unwrap();
    assert_eq!(aead::open(&key, &iv, &sealed, aad).unwrap(), pt);

    // Wrong AAD, wrong key, and a flipped ciphertext bit all fail as
    // Authentication — indistinguishable, by design.
    assert!(aead::open(&key, &iv, &sealed, b"different-aad").is_err());
    assert!(aead::open(&[8u8; 32], &iv, &sealed, aad).is_err());
    let mut tampered = sealed.clone();
    tampered[0] ^= 1;
    assert!(aead::open(&key, &iv, &tampered, aad).is_err());
}

// ---------------------------------------------------------------------------
// AES-256 Key Wrap — RFC 3394 §4.6 ("Wrap 256 bits of Key Data with a
// 256-bit KEK"). The exact wrap chain the DEK/metadata-key wrap ends in.
// ---------------------------------------------------------------------------

#[test]
fn aes_256_kw_rfc_3394_section_4_6() {
    let kek = hx32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    let key_data = hx("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f");
    let expected =
        hx("28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21");

    let wrapped = keywrap::wrap(&kek, &key_data).unwrap();
    assert_eq!(wrapped, expected, "RFC 3394 §4.6 wrapped output (40 bytes)");
    assert_eq!(keywrap::unwrap(&kek, &wrapped).unwrap(), key_data);

    // A wrong KEK fails the RFC 3394 integrity check (Authentication, not a
    // length error) — this is what makes the folder-bound KEK reject a moved blob.
    let wrong = [0xAAu8; 32];
    assert!(keywrap::unwrap(&wrong, &wrapped).is_err());
}

// ---------------------------------------------------------------------------
// HKDF-SHA-256 — RFC 5869 Appendix A, Test Case 1.
// ---------------------------------------------------------------------------

#[test]
fn hkdf_sha256_rfc_5869_test_case_1() {
    let ikm = hx("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let salt = hx("000102030405060708090a0b0c");
    let info = hx("f0f1f2f3f4f5f6f7f8f9");
    let expected_okm =
        hx("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");

    let okm = kdf::hkdf_sha256(&ikm, &salt, &info, 42).unwrap();
    assert_eq!(okm, expected_okm, "RFC 5869 TC1 OKM (L=42)");
}

#[test]
fn hkdf_sha256_rfc_5869_test_case_3_empty_salt() {
    // Empty salt and empty info — the exact configuration the human-side
    // wrap-key derivation uses (Envelope §8.2: empty salt), so this vector
    // pins the precise SigDrive case, not just a generic one.
    let ikm = hx("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let expected_okm =
        hx("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");

    let okm = kdf::hkdf_sha256(&ikm, b"", b"", 42).unwrap();
    assert_eq!(
        okm, expected_okm,
        "RFC 5869 TC3 OKM (empty salt/info, L=42)"
    );
}

// ---------------------------------------------------------------------------
// Concat KDF (SP 800-56A single-step, JOSE OtherInfo) — RFC 7518 Appendix C.
// The ECDH-ES Direct-Agreement worked example (alg="ECDH-ES", enc="A128GCM"):
// derive a 128-bit key from the published Z with apu="Alice", apv="Bob". Pins
// the single-step KDF AND the OtherInfo Datum encoding — including the
// non-empty PartyVInfo (apv) path that the P-015 folder binding rides on.
// ---------------------------------------------------------------------------

#[test]
fn concat_kdf_rfc_7518_appendix_c() {
    // Z = the ECDH-ES key-agreement output (App C octet sequence).
    let z = hx("9e56d91d817135d372834283bf84269cfb316ea3da806a48f6daa7798cfe90c4");

    // OtherInfo = Datum("A128GCM") || Datum("Alice") || Datum("Bob") || uint32_be(128).
    let other_info = concatkdf::jose_other_info(b"A128GCM", b"Alice", b"Bob", 128);
    assert_eq!(
        other_info,
        hx("000000074131323847434d00000005416c69636500000003426f6200000080"),
        "App C OtherInfo bytes",
    );

    // Derived key = first 128 bits of the round-1 hash output.
    let derived = concatkdf::concat_kdf_sha256(&z, &other_info, 16);
    assert_eq!(
        derived,
        hx("56aa8deaf8236d205c2228cd71a7101a"),
        "App C derived key (base64url VqqN6vgjbSBcIijNcacQGg)",
    );
}

// ---------------------------------------------------------------------------
// ECDH P-256 — functional KAT: two independently-generated keypairs agree on
// the same shared secret (the property the wrap chain depends on). The
// fixed-vector cross-check vs an independent impl is in differential.rs.
// ---------------------------------------------------------------------------

#[test]
fn ecdh_p256_agreement_is_symmetric() {
    use p256::SecretKey;
    use rand_core::OsRng;

    let alice = SecretKey::random(&mut OsRng);
    let bob = SecretKey::random(&mut OsRng);

    let alice_scalar: [u8; 32] = alice.to_bytes().into();
    let bob_scalar: [u8; 32] = bob.to_bytes().into();
    let alice_pub = alice.public_key().to_sec1_bytes().to_vec();
    let bob_pub = bob.public_key().to_sec1_bytes().to_vec();

    let z_ab = ecdh::ecdh_p256(&alice_scalar, &bob_pub).unwrap();
    let z_ba = ecdh::ecdh_p256(&bob_scalar, &alice_pub).unwrap();
    assert_eq!(z_ab, z_ba, "ECDH must be symmetric");
}

// ---------------------------------------------------------------------------
// ECDSA P-256 (ES256) — sign/verify round-trip + negatives. The raw-r‖s and
// DER dual-acceptance and the cross-impl check are in differential.rs.
// ---------------------------------------------------------------------------

#[test]
fn ecdsa_es256_sign_verify_round_trip() {
    use p256::SecretKey;
    use rand_core::OsRng;

    let sk = SecretKey::random(&mut OsRng);
    let scalar: [u8; 32] = sk.to_bytes().into();
    let pubkey = sk.public_key().to_sec1_bytes().to_vec();
    let msg = b"SIGNET-V1 canonical request bytes stand-in";

    let sig = ecdsa::sign_es256(&scalar, msg).unwrap();
    assert_eq!(sig.len(), 64, "ES256 wire signature is 64-byte raw r||s");
    assert!(ecdsa::verify_es256(&pubkey, msg, &sig).is_ok());

    // A flipped message bit and a wrong key both fail verification.
    assert!(ecdsa::verify_es256(&pubkey, b"tampered", &sig).is_err());
    let other = SecretKey::random(&mut OsRng)
        .public_key()
        .to_sec1_bytes()
        .to_vec();
    assert!(ecdsa::verify_es256(&other, msg, &sig).is_err());

    // A signature of an unsupported length is rejected before verification.
    assert!(ecdsa::verify_es256(&pubkey, msg, &[0u8; 65]).is_err());
}
