// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Functional tests for the hybrid content-wrap `ECDH-ES+ML-KEM-1024+A256KW`
//! (PQR Crypto Spec §3–§9).
//!
//! The load-bearing test is [`keycombine_kat`]: a byte-for-byte pin of the SP
//! 800-227 §4.6 combiner against the two vectors that Hlin and Gus generated
//! **independently** from the merged spec text and byte-matched at A3 (PQR §11.5).
//! A green KAT here means the Rust combiner is byte-identical to the co-signed
//! construction — provably correct-to-spec, not merely self-consistent.
//!
//! The rest cover the round-trip (DEK + metadata-key) and the wrap-path downgrade
//! / tamper inventory N1–N5 + N7 (PQR §9.4). N6 (the client refuse-to-downgrade)
//! and N8/N9 (the signature path) live above this crate.
//!
//! The S105 fresh-eyes review added: the *deep* N1 (a fully-reshaped blob that
//! parses as classical still rejects — the §9.1 KDF-binding pinned end-to-end),
//! the reserved-pure-endpoint rejection pin (§3), a pinned `rfp` vector (§8.5,
//! independently derived), and the seam-validation negatives (canonical `rk_ec`
//! / `rk_pq` / `party_v`, wrong-length `ek`, malformed base64).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::OsRng;
use signet_crypto::AlgId;
use signet_crypto::error::CryptoError;
use signet_crypto::hybrid_wrap::{self, HybridWrapEnvelope};
use signet_crypto::keywrap;
use signet_crypto::wrap::{self, WrapEnvelope};

/// A fresh P-256 keypair: (32-byte scalar, 65-byte X9.63 uncompressed public key).
fn keypair() -> ([u8; 32], Vec<u8>) {
    let sk = SecretKey::random(&mut OsRng);
    let scalar: [u8; 32] = sk.to_bytes().into();
    let public = sk.public_key().to_encoded_point(false).as_bytes().to_vec();
    (scalar, public)
}

/// A fresh 65-byte X9.63 public key as the fixed-size array the fixtures use.
/// (The seams validate `rk_ec` is a real on-curve point, so fixtures use real
/// points — synthetic byte-fill only appears where the pure encoder is pinned,
/// in the KAT.)
fn real_point() -> [u8; 65] {
    keypair()
        .1
        .try_into()
        .expect("x9.63 uncompressed is 65 bytes")
}

/// The P-256 generator point (a fixed, well-known constant) in X9.63
/// uncompressed form — for vectors that need a *pinned* on-curve point.
fn generator_x963() -> [u8; 65] {
    let mut g = [0u8; 65];
    hex::decode_to_slice(
        "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
         4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
        &mut g,
    )
    .expect("generator hex");
    g
}

/// A valid hybrid envelope over fixed shared secrets + a real ephemeral `epk`.
/// Returns the envelope plus everything an unwrap needs (`rk_ec`, `rk_pq`, the two
/// Z's, the DEK).
struct Sample {
    env: HybridWrapEnvelope,
    z_ecdh: [u8; 32],
    z_mlkem: [u8; 32],
    rk_ec: [u8; 65],
    rk_pq: [u8; 1568],
    dek: [u8; 32],
}

fn sample(party_v: &[u8]) -> Sample {
    let (_s, epk_x963) = keypair();
    let z_ecdh = [0x11u8; 32];
    let z_mlkem = [0x22u8; 32];
    let rk_ec = real_point();
    let rk_pq = [0x44u8; 1568];
    let dek = [0x66u8; 32];
    let ek = [0x55u8; 1568];
    let env = hybrid_wrap::wrap_from_secrets(
        &z_ecdh, &z_mlkem, &epk_x963, &ek, &rk_ec, &rk_pq, &dek, party_v,
    )
    .expect("wrap");
    Sample {
        env,
        z_ecdh,
        z_mlkem,
        rk_ec,
        rk_pq,
        dek,
    }
}

#[test]
fn keycombine_kat() {
    // The A3 byte-matched vectors (PQR §11.5). Inputs per the merged spec:
    //   Z_ecdh = 0x00..0x1F, Z_mlkem = 0x20..0x3F, alg fixed, epk=65×E1, ek=1568×E2,
    //   rk_ec=65×E3, rk_pq=1568×E4, L=256, DEK=32×0x42; party_v empty / 16×0xF0.
    let z_ecdh: [u8; 32] = core::array::from_fn(|i| i as u8);
    let z_mlkem: [u8; 32] = core::array::from_fn(|i| i as u8 + 0x20);
    let epk = [0xE1u8; 65];
    let ek = [0xE2u8; 1568];
    let rk_ec = [0xE3u8; 65];
    let rk_pq = [0xE4u8; 1568];
    let dek = [0x42u8; 32];

    // VEC-1 — party_v empty (a file-DEK wrap).
    let fi1 = hybrid_wrap::build_fixed_info(&epk, &ek, &rk_ec, &rk_pq, &[]);
    assert_eq!(fi1.len(), 3324, "FixedInfo length (vec-1)");
    let kek1 = hybrid_wrap::content_wrap_kek(&z_ecdh, &z_mlkem, &fi1).unwrap();
    assert_eq!(
        hex::encode(&kek1[..]),
        "5796f7961352b3b74e130dff668703a68611e64cc271351af22fa6b5a8b50363",
        "KEK vec-1"
    );
    assert_eq!(
        hex::encode(keywrap::wrap(&kek1, &dek).unwrap()),
        "538726e2887539c6810d8aa1f0e5891abc8d472ec4722c6d59446c8cb36a747d9b775df7171fed80",
        "wk vec-1"
    );

    // VEC-2 — party_v = 16 × 0xF0 (a metadata-key wrap, P-015).
    let fi2 = hybrid_wrap::build_fixed_info(&epk, &ek, &rk_ec, &rk_pq, &[0xF0u8; 16]);
    assert_eq!(fi2.len(), 3340, "FixedInfo length (vec-2)");
    let kek2 = hybrid_wrap::content_wrap_kek(&z_ecdh, &z_mlkem, &fi2).unwrap();
    assert_eq!(
        hex::encode(&kek2[..]),
        "4a0660ef7afe242e900f8bf8325aa9de4baba28b8384cebcd36323df160ef3ce",
        "KEK vec-2"
    );
    assert_eq!(
        hex::encode(keywrap::wrap(&kek2, &dek).unwrap()),
        "20ec7c1ec86a3290c5a17462fb2bdc70bf21eb59f5236a818f9f47fde7e65e513b1e16139eeee6f2",
        "wk vec-2"
    );
}

#[test]
fn round_trip_dek() {
    let s = sample(&[]);
    let got = hybrid_wrap::unwrap_with_shared_secrets(
        &s.z_ecdh,
        &s.z_mlkem,
        &s.env,
        &s.rk_ec,
        &s.rk_pq,
        &[],
    )
    .unwrap();
    assert_eq!(got, s.dek);
    // Envelope shape: hybrid carries both epk and ek + wk (never a bare ct).
    assert_eq!(s.env.alg, "ECDH-ES+ML-KEM-1024+A256KW");
    assert_eq!(
        URL_SAFE_NO_PAD.decode(s.env.wk.as_bytes()).unwrap().len(),
        40
    );
    assert_eq!(
        URL_SAFE_NO_PAD.decode(s.env.ek.as_bytes()).unwrap().len(),
        1568
    );
}

#[test]
fn round_trip_metadata_key() {
    let folder = [0xABu8; 16];
    let s = sample(&folder);
    // Correct folder unwraps.
    let got = hybrid_wrap::unwrap_with_shared_secrets(
        &s.z_ecdh, &s.z_mlkem, &s.env, &s.rk_ec, &s.rk_pq, &folder,
    )
    .unwrap();
    assert_eq!(got, s.dek);
}

// ---- Downgrade / tamper inventory (PQR §9.4) ----

#[test]
fn n1_strip_ek_rewrite_alg_classical_rejected() {
    // A hybrid envelope with ek removed + alg rewritten to classical must not parse
    // as the classical WrapEnvelope (it has `wk`, not `ct`; deny_unknown_fields).
    let s = sample(&[]);
    let mut val: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&s.env).unwrap()).unwrap();
    val["alg"] = serde_json::json!("ECDH-ES+A256KW");
    val.as_object_mut().unwrap().remove("ek");
    assert!(serde_json::from_value::<WrapEnvelope>(val).is_err());
}

#[test]
fn n2_rewrite_alg_fields_intact_rejected() {
    let s = sample(&[]);
    // As a classical envelope: unknown ek/wk + missing ct → parse error.
    let mut val: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&s.env).unwrap()).unwrap();
    val["alg"] = serde_json::json!("ECDH-ES+A256KW");
    assert!(serde_json::from_value::<WrapEnvelope>(val).is_err());
    // As a hybrid envelope: the unwrap dispatch rejects any non-hybrid alg (§5.2).
    let mut e = s.env.clone();
    e.alg = "ECDH-ES+A256KW".to_string();
    assert_eq!(
        hybrid_wrap::unwrap_with_shared_secrets(&s.z_ecdh, &s.z_mlkem, &e, &s.rk_ec, &s.rk_pq, &[])
            .unwrap_err(),
        CryptoError::UnknownAlgorithm
    );
}

#[test]
fn n3_ek_swapped_rejected() {
    // A different (valid-length) ek changes the FixedInfo → different KEK → AES-KW
    // integrity failure (never conflated with a length error).
    let s = sample(&[]);
    let mut tampered = s.env.clone();
    tampered.ek = URL_SAFE_NO_PAD.encode([0x77u8; 1568]);
    assert_eq!(
        hybrid_wrap::unwrap_with_shared_secrets(
            &s.z_ecdh,
            &s.z_mlkem,
            &tampered,
            &s.rk_ec,
            &s.rk_pq,
            &[]
        )
        .unwrap_err(),
        CryptoError::Authentication
    );
}

#[test]
fn n4_recipient_block_transplant_rejected() {
    // Unwrapping against a different recipient's static keys reconstructs a
    // different FixedInfo → the KEK diverges → AES-KW rejects (recipient binding).
    let s = sample(&[]);
    let wrong_rk_ec = real_point();
    assert_eq!(
        hybrid_wrap::unwrap_with_shared_secrets(
            &s.z_ecdh,
            &s.z_mlkem,
            &s.env,
            &wrong_rk_ec,
            &s.rk_pq,
            &[]
        )
        .unwrap_err(),
        CryptoError::Authentication
    );
    let wrong_rk_pq = [0x88u8; 1568];
    assert_eq!(
        hybrid_wrap::unwrap_with_shared_secrets(
            &s.z_ecdh,
            &s.z_mlkem,
            &s.env,
            &s.rk_ec,
            &wrong_rk_pq,
            &[]
        )
        .unwrap_err(),
        CryptoError::Authentication
    );
}

#[test]
fn n5_classical_with_ek_injected_rejected() {
    // The symmetric direction: a genuine classical envelope with a smuggled hybrid
    // `ek` field must fail to parse (WrapEnvelope deny_unknown_fields).
    let (_s, recipient_pub) = keypair();
    let classical = wrap::wrap_dek(&recipient_pub, &[0x42u8; 32]).unwrap();
    let mut val: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&classical).unwrap()).unwrap();
    val["ek"] = serde_json::json!("AAAAAAAA");
    assert!(serde_json::from_value::<WrapEnvelope>(val).is_err());
}

#[test]
fn n7_metadata_wrap_confusion_rejected() {
    // A metadata-key wrap (party_v = root_folder_id) must not unwrap as a DEK
    // (party_v empty) or under a different folder — the P-015 binding.
    let folder = [0xABu8; 16];
    let s = sample(&folder);
    // As a DEK (empty party_v) → reject.
    assert_eq!(
        hybrid_wrap::unwrap_with_shared_secrets(
            &s.z_ecdh,
            &s.z_mlkem,
            &s.env,
            &s.rk_ec,
            &s.rk_pq,
            &[]
        )
        .unwrap_err(),
        CryptoError::Authentication
    );
    // Under a different folder → reject.
    let other = [0xCDu8; 16];
    assert_eq!(
        hybrid_wrap::unwrap_with_shared_secrets(
            &s.z_ecdh, &s.z_mlkem, &s.env, &s.rk_ec, &s.rk_pq, &other
        )
        .unwrap_err(),
        CryptoError::Authentication
    );
}

#[test]
fn hybrid_rfp_is_pair_commitment() {
    // §8.5: the rfp commits to BOTH recipient keys; changing either changes it.
    let p1 = real_point();
    let p2 = real_point();
    let a = hybrid_wrap::hybrid_rfp(&p1, &[0x44u8; 1568]).unwrap();
    let b = hybrid_wrap::hybrid_rfp(&p1, &[0x45u8; 1568]).unwrap();
    let c = hybrid_wrap::hybrid_rfp(&p2, &[0x44u8; 1568]).unwrap();
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert_eq!(a.len(), 64); // SHA-256 lowercase hex
}

#[test]
fn hybrid_rfp_pinned_vector() {
    // A pinned §8.5 vector over fixed inputs (the P-256 generator point +
    // 1568×0xE4), independently derived from the spec text in Python
    // (hashlib: SHA-256(lp(G) ‖ lp(rk_pq))) at the S105 review — so the
    // commitment encoding (u32-BE length prefixes, §4.3 convention) is pinned
    // cross-lineage like the KeyCombine KAT, not merely property-tested.
    let rfp = hybrid_wrap::hybrid_rfp(&generator_x963(), &[0xE4u8; 1568]).unwrap();
    assert_eq!(
        rfp,
        "bd2fd90ff413e4eed8fbc07b81e50f52d336f0e4e27932d3022c34c54700581d"
    );
}

// ---- Review follow-ups (S105): seam validation + deeper downgrade pins ----

#[test]
fn n1_deep_full_reshape_downgrade_rejected() {
    // Beyond the parse-shape defense (n1): an attacker who FULLY reshapes the
    // blob — strips `ek`, renames `wk`→`ct`, rewrites `alg` — produces a
    // structurally valid classical envelope. The §9.1 defense is then purely
    // cryptographic: the classical Concat-KDF KEK (over Z_ecdh alone, classical
    // OtherInfo) differs from the hybrid HKDF KEK the key was wrapped under, so
    // AES-KW's integrity check rejects. This pins the alg-ID-bound-in-KDF
    // property end-to-end, against an adversary not bound by our struct shapes.
    let s = sample(&[]);
    let mut val = serde_json::to_value(&s.env).unwrap();
    let obj = val.as_object_mut().unwrap();
    obj.remove("ek");
    let wk = obj.remove("wk").unwrap();
    obj.insert("ct".to_string(), wk);
    obj.insert("alg".to_string(), serde_json::json!("ECDH-ES+A256KW"));
    let reshaped: WrapEnvelope =
        serde_json::from_value(val).expect("fully-reshaped envelope parses as classical");
    assert_eq!(
        wrap::unwrap_dek_with_shared_secret(&s.z_ecdh, &reshaped).unwrap_err(),
        CryptoError::Authentication
    );
}

#[test]
fn reserved_pure_mlkem_endpoint_rejected() {
    // §3 dispatch rule: the reserved pure `ML-KEM-1024+A256KW` endpoint (v3
    // horizon) is absent from the active registry — known-but-disabled → reject.
    // This pin makes a future activation a deliberate, test-visible act.
    assert_eq!(
        AlgId::from_jose("ML-KEM-1024+A256KW").unwrap_err(),
        CryptoError::UnknownAlgorithm
    );
    let s = sample(&[]);
    let mut e = s.env.clone();
    e.alg = "ML-KEM-1024+A256KW".to_string();
    assert_eq!(
        hybrid_wrap::unwrap_with_shared_secrets(&s.z_ecdh, &s.z_mlkem, &e, &s.rk_ec, &s.rk_pq, &[])
            .unwrap_err(),
        CryptoError::UnknownAlgorithm
    );
}

#[test]
fn wrong_length_ek_rejected_at_wrap_and_unwrap() {
    // Wrap side: a 1567-byte ek is rejected before any derivation.
    let (_s, epk) = keypair();
    let rk_ec = real_point();
    let err = hybrid_wrap::wrap_from_secrets(
        &[0x11u8; 32],
        &[0x22u8; 32],
        &epk,
        &[0x55u8; 1567],
        &rk_ec,
        &[0x44u8; 1568],
        &[0x66u8; 32],
        &[],
    )
    .unwrap_err();
    assert!(matches!(err, CryptoError::InvalidInput(_)));
    // Unwrap side: a valid envelope whose ek is re-encoded at the wrong length.
    let s = sample(&[]);
    let mut e = s.env.clone();
    e.ek = URL_SAFE_NO_PAD.encode([0x55u8; 1567]);
    assert!(matches!(
        hybrid_wrap::unwrap_with_shared_secrets(&s.z_ecdh, &s.z_mlkem, &e, &s.rk_ec, &s.rk_pq, &[])
            .unwrap_err(),
        CryptoError::InvalidInput(_)
    ));
}

#[test]
fn malformed_base64_rejected() {
    let s = sample(&[]);
    let mut bad_ek = s.env.clone();
    bad_ek.ek = "!!!not-base64url!!!".to_string();
    assert!(matches!(
        hybrid_wrap::unwrap_with_shared_secrets(
            &s.z_ecdh,
            &s.z_mlkem,
            &bad_ek,
            &s.rk_ec,
            &s.rk_pq,
            &[]
        )
        .unwrap_err(),
        CryptoError::InvalidInput(_)
    ));
    let mut bad_wk = s.env.clone();
    bad_wk.wk = "!!!not-base64url!!!".to_string();
    assert!(matches!(
        hybrid_wrap::unwrap_with_shared_secrets(
            &s.z_ecdh,
            &s.z_mlkem,
            &bad_wk,
            &s.rk_ec,
            &s.rk_pq,
            &[]
        )
        .unwrap_err(),
        CryptoError::InvalidInput(_)
    ));
}

#[test]
fn non_canonical_recipient_keys_rejected() {
    // §4.3 canonical encodings are enforced at the seams (both directions):
    // rk_ec must be a 65-byte uncompressed on-curve point; rk_pq exactly 1568 B.
    let s = sample(&[]);
    // Wrong-length rk_ec (a compressed point is 33 B).
    assert!(matches!(
        hybrid_wrap::unwrap_with_shared_secrets(
            &s.z_ecdh,
            &s.z_mlkem,
            &s.env,
            &[0x02u8; 33],
            &s.rk_pq,
            &[]
        )
        .unwrap_err(),
        CryptoError::InvalidInput(_)
    ));
    // Right length + tag, but not on the curve.
    let mut off_curve = [0xAAu8; 65];
    off_curve[0] = 0x04;
    assert!(matches!(
        hybrid_wrap::unwrap_with_shared_secrets(
            &s.z_ecdh,
            &s.z_mlkem,
            &s.env,
            &off_curve,
            &s.rk_pq,
            &[]
        )
        .unwrap_err(),
        CryptoError::InvalidInput(_)
    ));
    // Wrong-length rk_pq.
    assert!(matches!(
        hybrid_wrap::unwrap_with_shared_secrets(
            &s.z_ecdh,
            &s.z_mlkem,
            &s.env,
            &s.rk_ec,
            &[0x44u8; 1567],
            &[]
        )
        .unwrap_err(),
        CryptoError::InvalidInput(_)
    ));
    // And at the rfp commitment itself.
    assert!(matches!(
        hybrid_wrap::hybrid_rfp(&[0x99u8; 65], &[0x44u8; 1568]).unwrap_err(),
        CryptoError::InvalidInput(_)
    ));
}

#[test]
fn malformed_party_v_rejected() {
    // §4.3: party_v is exactly empty (DEK) or 16 bytes (root_folder_id) — the
    // classical API enforces this by type; the hybrid seam validates it.
    let s = sample(&[]);
    assert!(matches!(
        hybrid_wrap::unwrap_with_shared_secrets(
            &s.z_ecdh,
            &s.z_mlkem,
            &s.env,
            &s.rk_ec,
            &s.rk_pq,
            &[0xABu8; 5]
        )
        .unwrap_err(),
        CryptoError::InvalidInput(_)
    ));
    let (_s2, epk) = keypair();
    let rk_ec = real_point();
    assert!(matches!(
        hybrid_wrap::wrap_from_secrets(
            &[0x11u8; 32],
            &[0x22u8; 32],
            &epk,
            &[0x55u8; 1568],
            &rk_ec,
            &[0x44u8; 1568],
            &[0x66u8; 32],
            &[0xABu8; 5],
        )
        .unwrap_err(),
        CryptoError::InvalidInput(_)
    ));
}
