// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! P-015 metadata-key wrap folder binding (Envelope §7.2; Test Strategy v07
//! §"Container key custody" P-015 row).
//!
//! The metadata-key wrap is `ECDH-ES+A256KW` with `root_folder_id` folded into
//! the Concat-KDF `PartyVInfo` (apv). These tests prove the binding is
//! load-bearing: the KEK is folder-specific, so a `wrapped_metadata_keys` blob
//! moved to a different folder is unwrapped under a different KEK and AES-KW's
//! integrity check rejects it — defending against a malicious server swapping
//! blobs between folders for the same recipient.

use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::OsRng;
use signet_crypto::error::CryptoError;
use signet_crypto::wrap;

fn keypair() -> ([u8; 32], Vec<u8>) {
    let sk = SecretKey::random(&mut OsRng);
    let scalar: [u8; 32] = sk.to_bytes().into();
    let public = sk.public_key().to_encoded_point(false).as_bytes().to_vec();
    (scalar, public)
}

const FOLDER_A: [u8; 16] = [
    0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];
const FOLDER_B: [u8; 16] = [
    0xbb, 0xbb, 0xbb, 0xbb, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
];

#[test]
fn metadata_wrap_round_trip_same_folder() {
    let (recipient_priv, recipient_pub) = keypair();
    let metadata_key = [0x33u8; 32];

    let envelope = wrap::wrap_metadata_key(&recipient_pub, &metadata_key, &FOLDER_A).unwrap();
    let recovered = wrap::unwrap_metadata_key(&recipient_priv, &envelope, &FOLDER_A).unwrap();
    assert_eq!(
        recovered, metadata_key,
        "same-folder unwrap recovers the key"
    );
}

#[test]
fn metadata_wrap_wrong_folder_fails() {
    // P-015: a blob created for folder A, unwrapped claiming folder B, derives a
    // different KEK → AES-KW integrity check rejects it.
    let (recipient_priv, recipient_pub) = keypair();
    let metadata_key = [0x44u8; 32];

    let envelope = wrap::wrap_metadata_key(&recipient_pub, &metadata_key, &FOLDER_A).unwrap();
    assert_eq!(
        wrap::unwrap_metadata_key(&recipient_priv, &envelope, &FOLDER_B),
        Err(CryptoError::Authentication),
        "a blob moved to a different folder must fail to unwrap",
    );
}

#[test]
fn folder_binding_actually_enters_the_kek() {
    // The DEK wrap uses an empty PartyVInfo; the metadata-key wrap uses
    // root_folder_id. If the binding is real, a metadata-key wrap cannot be
    // unwrapped as a plain DEK (and vice versa) — different KEKs.
    let (recipient_priv, recipient_pub) = keypair();
    let key = [0x55u8; 32];

    let meta = wrap::wrap_metadata_key(&recipient_pub, &key, &FOLDER_A).unwrap();
    assert_eq!(
        wrap::unwrap_dek(&recipient_priv, &meta),
        Err(CryptoError::Authentication),
        "metadata wrap (apv=folder) must not unwrap as a DEK (apv empty)",
    );

    let dek = wrap::wrap_dek(&recipient_pub, &key).unwrap();
    assert_eq!(
        wrap::unwrap_metadata_key(&recipient_priv, &dek, &FOLDER_A),
        Err(CryptoError::Authentication),
        "DEK wrap (apv empty) must not unwrap as a metadata key (apv=folder)",
    );
}

#[test]
fn wrong_recipient_fails_for_metadata_wrap() {
    let (_alice_priv, alice_pub) = keypair();
    let (bob_priv, _bob_pub) = keypair();

    let envelope = wrap::wrap_metadata_key(&alice_pub, &[0x66u8; 32], &FOLDER_A).unwrap();
    assert_eq!(
        wrap::unwrap_metadata_key(&bob_priv, &envelope, &FOLDER_A),
        Err(CryptoError::Authentication),
    );
}
