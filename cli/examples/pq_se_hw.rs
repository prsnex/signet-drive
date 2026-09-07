// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! `pq_se_hw` — the PQR item-1 hardware proof: the full **persistent** SE-PQC
//! keystore cycle on the real Secure Enclave, through the `Keystore` trait
//! (the same seams `host_signer::dispatch` and the broker drive in production).
//!
//! The persistent path stores the SE-sealed blobs in the data-protection
//! keychain, which requires a provisioning-profile-entitled binary — wrap the
//! built example with the dev entitle recipe (the #208 pattern):
//!
//! ```text
//! cargo build --release --example pq_se_hw
//! infrastructure/scripts/sign-example-for-se.sh target/release/examples/pq_se_hw
//! target/release-se/pq_se_hw.app/Contents/MacOS/pq_se_hw
//! ```
//!
//! Needs Apple Silicon + macOS 26 (the SE-PQC floor) + an unlocked session.
//! Exercises: keygen → meta → list → SE decap (vs a RustCrypto encaps — the
//! spec §11.2 two-lineage differential) → the hybrid wrap/unwrap round-trip
//! (spec §4/§5) → SE hedged ML-DSA sign (verified under RustCrypto, context
//! bound) → delete. The unsigned-tier crypto tests live in
//! `cli/src/keystore/secure_enclave.rs` (`cargo test -- --ignored`).

#[cfg(target_os = "macos")]
fn main() {
    use kem::Encapsulate;
    use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa87, Signature, VerifyingKey};
    use ml_kem::{EncodedSizeUser, KemCore, MlKem1024};
    use signet_cli::keystore::{KeyLabel, Keystore, Purpose, SecureEnclaveKeystore};
    use signet_crypto::hybrid_wrap;

    let ks = SecureEnclaveKeystore::open().expect("open SE keystore");
    let kem_label = KeyLabel::parse("pqhw-ai-kem-pq", Some(Purpose::KemPq)).unwrap();
    let sig_label = KeyLabel::parse("pqhw-ai-signing-pq", Some(Purpose::SigningPq)).unwrap();

    // Clean any prior run.
    let _ = ks.delete(&kem_label);
    let _ = ks.delete(&sig_label);

    // 1. Keygen — in-Enclave, sealed blobs persisted to the DP keychain.
    let kem_meta = ks
        .generate(&kem_label, "ML-KEM-1024")
        .expect("SE ML-KEM keygen");
    assert_eq!(kem_meta.public_key.len(), 1568);
    println!("✓ keygen {}  fp={}", kem_meta.label, kem_meta.fingerprint);
    let sig_meta = ks
        .generate(&sig_label, "ML-DSA-87")
        .expect("SE ML-DSA keygen");
    assert_eq!(sig_meta.public_key.len(), 2592);
    println!("✓ keygen {}  fp={}", sig_meta.label, sig_meta.fingerprint);

    // Duplicate keygen refused; wrong algorithm refused.
    assert!(ks.generate(&kem_label, "ML-KEM-1024").is_err());
    assert!(ks.generate(&sig_label, "ES256").is_err());
    println!("✓ duplicate + wrong-algorithm keygen refused");

    // 2. Meta — the public key restores from the sealed blob alone.
    let m = ks.meta(&kem_label).expect("meta");
    assert_eq!(m.public_key, kem_meta.public_key);
    assert_eq!(m.fingerprint, kem_meta.fingerprint);
    assert_eq!(m.algorithm, "ML-KEM-1024");
    println!("✓ meta restores ek from the sealed blob (fingerprint stable)");

    // 3. List — both PQ keys enumerate alongside any classical keys.
    let listed = ks.list().expect("list");
    assert!(listed.iter().any(|k| k.label == "pqhw-ai-kem-pq"));
    assert!(listed.iter().any(|k| k.label == "pqhw-ai-signing-pq"));
    println!("✓ list shows both PQ keys ({} keys total)", listed.len());

    // 4. Decap differential (spec §11.2): RustCrypto encapsulates; the Enclave
    //    decapsulates via the trait op; the lineages must agree.
    let ek_arr = ml_kem::Encoded::<<MlKem1024 as KemCore>::EncapsulationKey>::try_from(
        kem_meta.public_key.as_slice(),
    )
    .expect("ek size");
    let ek = <MlKem1024 as KemCore>::EncapsulationKey::from_bytes(&ek_arr);
    let (ct, ss_rust) = ek.encapsulate(&mut rand_core::OsRng).expect("encaps");
    let z_mlkem = ks
        .ml_kem_decapsulate(&kem_label, ct.as_slice())
        .expect("SE decapsulation via the trait");
    assert_eq!(z_mlkem.as_slice(), ss_rust.as_slice());
    println!("✓ ml_kem_decapsulate agrees with the RustCrypto lineage");

    // 5. The hybrid content-wrap round-trip (spec §4/§5) fed by the REAL SE leg.
    let (rk_scalar, rk_ec) = signet_crypto::ecdh::generate_keypair();
    let (eph_scalar, eph_pub) = signet_crypto::ecdh::generate_keypair();
    let z_ecdh_w = signet_crypto::ecdh::ecdh_p256(&eph_scalar, &rk_ec).unwrap();
    let z_mlkem_w: [u8; 32] = ss_rust.as_slice().try_into().unwrap();
    let dek = [0x42u8; 32];
    let env = hybrid_wrap::wrap_from_secrets(
        &z_ecdh_w,
        &z_mlkem_w,
        &eph_pub,
        ct.as_slice(),
        &rk_ec,
        &kem_meta.public_key,
        &dek,
        b"",
    )
    .expect("hybrid wrap");
    let z_ecdh_r = signet_crypto::ecdh::ecdh_p256(&rk_scalar, &eph_pub).unwrap();
    let dek2 = hybrid_wrap::unwrap_with_shared_secrets(
        &z_ecdh_r,
        &z_mlkem,
        &env,
        &rk_ec,
        &kem_meta.public_key,
        b"",
    )
    .expect("hybrid unwrap");
    assert_eq!(dek, dek2);
    println!("✓ hybrid wrap/unwrap round-trip with the real SE Z_mlkem");

    // 6. SE hedged ML-DSA sign via the trait, context bound, RustCrypto-verified.
    let msg = b"SIGNET-V1 canonical dual-sign base";
    let ctx = b"signet:attest:v1";
    let sig = ks
        .ml_dsa_sign(&sig_label, msg, ctx)
        .expect("SE sign via the trait");
    assert_eq!(sig.len(), 4627);
    let vk_arr =
        EncodedVerifyingKey::<MlDsa87>::try_from(sig_meta.public_key.as_slice()).expect("vk size");
    let vk = VerifyingKey::<MlDsa87>::decode(&vk_arr);
    let sig_arr = EncodedSignature::<MlDsa87>::try_from(sig.as_slice()).expect("sig size");
    let sig_dec = Signature::<MlDsa87>::decode(&sig_arr).expect("sig decode");
    assert!(vk.verify_with_context(msg, ctx, &sig_dec));
    assert!(!vk.verify_with_context(msg, b"signet:req:v1", &sig_dec));
    println!("✓ ml_dsa_sign verifies under RustCrypto; FIPS 204 context bound");

    // 7. Purpose guards at the trait seams.
    assert!(ks.ml_kem_decapsulate(&sig_label, ct.as_slice()).is_err());
    assert!(ks.ml_dsa_sign(&kem_label, msg, ctx).is_err());
    println!("✓ purpose guards hold (decap needs kem-pq; sign needs signing-pq)");

    // 8. R6 (item 7b) — the per-request dual-sign burst on real hardware: 20
    //    sequential (SE ES256 + SE hedged ML-DSA-87) pairs over request-shaped
    //    canonical bytes, per-op wall time. This is the keystore-layer floor of
    //    the accepted ~13–18 ms/op (B1); the broker adds sub-ms mTLS round-trips
    //    on top (the full signed-request burst rides Wave A/B per Build-Plan R6).
    let es_label = KeyLabel::parse("pqhw-ai-signing", Some(Purpose::Signing)).unwrap();
    let _ = ks.delete(&es_label);
    ks.generate(&es_label, "ES256").expect("SE ES256 keygen");
    let canonical = b"SIGNET-V1\nGET\n/v1/quota\ne3b0c44298fc1c149afbf4c8996fb92427ae41e464\
9b934ca495991b7852b855\n1751760000\n0123456789abcdef0123456789abcdef\nfp";
    let burst = std::time::Instant::now();
    const BURST_N: u32 = 20;
    for _ in 0..BURST_N {
        ks.sign(&es_label, canonical).expect("burst ES256 sign");
        ks.ml_dsa_sign(&sig_label, canonical, b"signet:req:v1")
            .expect("burst ML-DSA sign");
    }
    let per_op = burst.elapsed() / BURST_N;
    println!("✓ R6 burst: {BURST_N} sequential dual-sign pairs — per-op {per_op:?}");
    ks.delete(&es_label).expect("delete es");

    // 9. Delete + exists.
    ks.delete(&kem_label).expect("delete kem");
    ks.delete(&sig_label).expect("delete signing");
    assert!(!ks.exists(&kem_label).unwrap());
    assert!(!ks.exists(&sig_label).unwrap());
    assert!(ks.delete(&kem_label).is_err());
    println!("✓ delete + exists; double-delete refused");

    println!("\nPQ SE hardware proof complete — all steps passed.");
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("pq_se_hw is macOS-only (the Secure-Enclave PQC hardware proof).");
}
