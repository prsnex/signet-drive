// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Integration tests for the `software` keystore backend + the key model.
//!
//! Each test uses its own `TempDir`, so they're isolated under parallel `cargo
//! test`. They exercise the keystore through its public trait — generate, sign,
//! ECDH, list, delete — and the load-bearing at-rest property (the scalar is
//! sealed, AAD-bound to its label).

use signet_cli::keystore::{KeyLabel, Keystore, Purpose, SoftwareKeystore};
use tempfile::TempDir;

fn open() -> (TempDir, SoftwareKeystore) {
    let dir = TempDir::new().unwrap();
    let ks = SoftwareKeystore::open(dir.path().to_path_buf()).unwrap();
    (dir, ks)
}

fn signing(handle_label: &str) -> KeyLabel {
    KeyLabel::parse(handle_label, Some(Purpose::Signing)).unwrap()
}

fn kem(handle_label: &str) -> KeyLabel {
    KeyLabel::parse(handle_label, Some(Purpose::Kem)).unwrap()
}

#[test]
fn generate_sign_verify_roundtrip() {
    let (_dir, ks) = open();
    let label = signing("hlin-ai-signing");
    let meta = ks.generate(&label, "ES256").unwrap();
    assert_eq!(meta.storage, "software");
    assert_eq!(meta.purpose, "signing");
    assert_eq!(meta.public_key.len(), 65);
    assert_eq!(meta.public_key[0], 0x04);
    // The fingerprint matches signet-crypto's definition (lowercase hex SHA-256 SPKI).
    assert_eq!(
        meta.fingerprint,
        signet_crypto::pubkey::fingerprint(&meta.public_key).unwrap()
    );

    let msg = b"signet-v1 canonical bytes to sign";
    let sig = ks.sign(&label, msg).unwrap();
    signet_crypto::ecdsa::verify_es256(&meta.public_key, msg, &sig).expect("self-verify");
}

#[test]
fn kem_ecdh_agrees_both_directions() {
    let (_dir, ks) = open();
    let a = kem("hlin-ai-kem");
    let b = kem("mira-ai-kem");
    let ma = ks.generate(&a, "ECDH-ES+A256KW").unwrap();
    let mb = ks.generate(&b, "ECDH-ES+A256KW").unwrap();
    let z_ab = ks.ecdh(&a, &mb.public_key).unwrap();
    let z_ba = ks.ecdh(&b, &ma.public_key).unwrap();
    assert_eq!(z_ab, z_ba, "ECDH must agree in both directions");
}

#[test]
fn duplicate_keygen_rejected() {
    let (_dir, ks) = open();
    let label = signing("hlin-ai-signing");
    ks.generate(&label, "ES256").unwrap();
    let err = ks.generate(&label, "ES256").unwrap_err();
    assert_eq!(err.exit_code, 11, "key already exists");
}

#[test]
fn sign_rejects_a_kem_key_and_ecdh_rejects_a_signing_key() {
    let (_dir, ks) = open();
    let s = signing("hlin-ai-signing");
    let k = kem("hlin-ai-kem");
    ks.generate(&s, "ES256").unwrap();
    ks.generate(&k, "ECDH-ES+A256KW").unwrap();
    assert_eq!(ks.sign(&k, b"x").unwrap_err().exit_code, 41);
    assert_eq!(ks.ecdh(&s, &[0x04; 65]).unwrap_err().exit_code, 41);
}

#[test]
fn list_and_delete() {
    let (_dir, ks) = open();
    let s = signing("hlin-ai-signing");
    let k = kem("hlin-ai-kem");
    ks.generate(&s, "ES256").unwrap();
    ks.generate(&k, "ECDH-ES+A256KW").unwrap();

    let listed = ks.list().unwrap();
    assert_eq!(listed.len(), 2);
    // Sorted by label: hlin-ai-kem before hlin-ai-signing.
    assert_eq!(listed[0].label, "hlin-ai-kem");
    assert_eq!(listed[1].label, "hlin-ai-signing");

    ks.delete(&s).unwrap();
    assert!(!ks.exists(&s).unwrap());
    assert!(ks.exists(&k).unwrap());
    assert_eq!(ks.delete(&s).unwrap_err().exit_code, 12, "already gone");
}

#[test]
fn scalar_is_sealed_at_rest_and_survives_reopen() {
    let dir = TempDir::new().unwrap();
    let ks = SoftwareKeystore::open(dir.path().to_path_buf()).unwrap();
    let label = signing("hlin-ai-signing");
    let meta = ks.generate(&label, "ES256").unwrap();

    let on_disk = std::fs::read_to_string(dir.path().join("hlin-ai-signing.json")).unwrap();
    assert!(on_disk.contains("scalar_blob_b64"));
    assert!(
        !on_disk.contains("\"scalar\""),
        "no plaintext scalar field on disk"
    );

    // Reopen (reloads the persisted KEK) and the key still signs.
    let reopened = SoftwareKeystore::open(dir.path().to_path_buf()).unwrap();
    let sig = reopened.sign(&label, b"persisted").unwrap();
    signet_crypto::ecdsa::verify_es256(&meta.public_key, b"persisted", &sig).unwrap();
}

#[test]
fn at_rest_aad_binds_the_blob_to_its_label() {
    // A malicious swap of one key file's ciphertext under another label must
    // fail closed: the scalar blob is AES-GCM-bound (AAD) to its own label.
    let dir = TempDir::new().unwrap();
    let ks = SoftwareKeystore::open(dir.path().to_path_buf()).unwrap();
    ks.generate(&signing("hlin-ai-signing"), "ES256").unwrap();
    ks.generate(&signing("mira-ai-signing"), "ES256").unwrap();

    let a_record = std::fs::read_to_string(dir.path().join("hlin-ai-signing.json")).unwrap();
    std::fs::write(dir.path().join("mira-ai-signing.json"), &a_record).unwrap();

    // Signing as mira-ai now reads hlin-ai's sealed blob; the AAD (mira's label)
    // won't match the seal (hlin's label) → fail-closed decrypt error.
    let err = ks.sign(&signing("mira-ai-signing"), b"x").unwrap_err();
    assert_eq!(err.exit_code, 42, "AAD mismatch must fail closed");
}
