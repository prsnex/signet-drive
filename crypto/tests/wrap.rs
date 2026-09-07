// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Functional tests for the `ECDH-ES+A256KW` wrap composition (Envelope §5 +
//! §7.2). These cover the Test Strategy v07 §"JOSE-conformant DEK wrap"
//! checklist — round-trip, wrong-recipient rejection, 40-byte AES-KW output,
//! `epk` JWK validation, algorithm-ID dispatch — plus the JSON envelope shape.
//! The Concat-KDF itself is pinned to RFC 7518 App C in `kat.rs`; conformance of
//! the full composition to an independent JOSE library is the tier-3 golden
//! vectors. The P-015 metadata-key folder binding is in `metadata_wrap.rs`.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::SecretKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::OsRng;
use signet_crypto::error::CryptoError;
use signet_crypto::pubkey;
use signet_crypto::wrap::{self, WrapEnvelope};

/// A fresh P-256 keypair: (32-byte private scalar, 65-byte X9.63 uncompressed
/// public key) — the shapes the wrap API and the CLI/Secure-Enclave use.
fn keypair() -> ([u8; 32], Vec<u8>) {
    let sk = SecretKey::random(&mut OsRng);
    let scalar: [u8; 32] = sk.to_bytes().into();
    let public = sk.public_key().to_encoded_point(false).as_bytes().to_vec();
    (scalar, public)
}

#[test]
fn wrap_unwrap_round_trip() {
    let (recipient_priv, recipient_pub) = keypair();
    let dek = [0x5au8; 32];

    let envelope = wrap::wrap_dek(&recipient_pub, &dek).unwrap();
    let recovered = wrap::unwrap_dek(&recipient_priv, &envelope).unwrap();
    assert_eq!(recovered, dek, "DEK must round-trip through wrap/unwrap");
}

#[test]
fn wrong_recipient_key_fails() {
    let (_alice_priv, alice_pub) = keypair();
    let (bob_priv, _bob_pub) = keypair();
    let dek = [0x11u8; 32];

    // Wrapped to Alice; Bob's private key derives a different KEK → AES-KW
    // integrity check fails (Authentication, not a leaky distinct error).
    let envelope = wrap::wrap_dek(&alice_pub, &dek).unwrap();
    assert_eq!(
        wrap::unwrap_dek(&bob_priv, &envelope),
        Err(CryptoError::Authentication),
    );
}

#[test]
fn aes_kw_output_is_40_bytes() {
    let (_priv, recipient_pub) = keypair();
    let envelope = wrap::wrap_dek(&recipient_pub, &[7u8; 32]).unwrap();
    let ct = URL_SAFE_NO_PAD.decode(envelope.ct.as_bytes()).unwrap();
    assert_eq!(ct.len(), 40, "AES-KW of a 32-byte key is 40 bytes (32 + 8)");
}

#[test]
fn envelope_fields_are_well_formed() {
    let (_priv, recipient_pub) = keypair();
    let envelope = wrap::wrap_dek(&recipient_pub, &[1u8; 32]).unwrap();

    assert_eq!(envelope.v, 1);
    assert_eq!(envelope.alg, "ECDH-ES+A256KW");
    assert_eq!(envelope.epk.kty, "EC");
    assert_eq!(envelope.epk.crv, "P-256");
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(envelope.epk.x.as_bytes())
            .unwrap()
            .len(),
        32
    );
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(envelope.epk.y.as_bytes())
            .unwrap()
            .len(),
        32
    );
    // `rfp` is the recipient's canonical fingerprint (routing field).
    assert_eq!(envelope.rfp, pubkey::fingerprint(&recipient_pub).unwrap());
}

#[test]
fn unknown_algorithm_is_rejected() {
    let (recipient_priv, recipient_pub) = keypair();
    let mut envelope = wrap::wrap_dek(&recipient_pub, &[2u8; 32]).unwrap();

    // A bogus alg → UnknownAlgorithm (the v1/v2 dispatch point).
    envelope.alg = "ECDH-ES+A999KW".to_string();
    assert_eq!(
        wrap::unwrap_dek(&recipient_priv, &envelope),
        Err(CryptoError::UnknownAlgorithm),
    );

    // A known-but-wrong alg (A256GCM is not a key-wrap alg) is also rejected.
    envelope.alg = "A256GCM".to_string();
    assert_eq!(
        wrap::unwrap_dek(&recipient_priv, &envelope),
        Err(CryptoError::UnknownAlgorithm),
    );
}

#[test]
fn malformed_epk_is_rejected() {
    let (recipient_priv, recipient_pub) = keypair();
    let base = wrap::wrap_dek(&recipient_pub, &[3u8; 32]).unwrap();

    // Wrong key type.
    let mut bad_kty = base.clone();
    bad_kty.epk.kty = "RSA".to_string();
    assert!(matches!(
        wrap::unwrap_dek(&recipient_priv, &bad_kty),
        Err(CryptoError::InvalidInput(_)),
    ));

    // Wrong curve.
    let mut bad_crv = base.clone();
    bad_crv.epk.crv = "P-384".to_string();
    assert!(matches!(
        wrap::unwrap_dek(&recipient_priv, &bad_crv),
        Err(CryptoError::InvalidInput(_)),
    ));

    // Truncated X coordinate (not 32 bytes after decode).
    let mut bad_x = base.clone();
    bad_x.epk.x = URL_SAFE_NO_PAD.encode([0u8; 16]);
    assert!(matches!(
        wrap::unwrap_dek(&recipient_priv, &bad_x),
        Err(CryptoError::InvalidInput(_)),
    ));
}

#[test]
fn tampered_ciphertext_fails_authentication() {
    let (recipient_priv, recipient_pub) = keypair();
    let envelope = wrap::wrap_dek(&recipient_pub, &[4u8; 32]).unwrap();

    let mut ct = URL_SAFE_NO_PAD.decode(envelope.ct.as_bytes()).unwrap();
    ct[0] ^= 1;
    let mut tampered = envelope.clone();
    tampered.ct = URL_SAFE_NO_PAD.encode(&ct);

    assert_eq!(
        wrap::unwrap_dek(&recipient_priv, &tampered),
        Err(CryptoError::Authentication),
    );
}

#[test]
fn envelope_survives_json_round_trip() {
    let (recipient_priv, recipient_pub) = keypair();
    let dek = [0x9cu8; 32];
    let envelope = wrap::wrap_dek(&recipient_pub, &dek).unwrap();

    // Serialize to JSON (what the CLI/web client send; the server stores opaque)
    // and back; the recovered envelope still unwraps to the same DEK.
    let json = serde_json::to_string(&envelope).unwrap();
    let parsed: WrapEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, envelope);
    assert_eq!(wrap::unwrap_dek(&recipient_priv, &parsed).unwrap(), dek);

    // Field names are the on-the-wire contract (Envelope §5).
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    for key in ["v", "alg", "epk", "ct", "rfp"] {
        assert!(value.get(key).is_some(), "envelope JSON missing `{key}`");
    }
    for key in ["kty", "crv", "x", "y"] {
        assert!(value["epk"].get(key).is_some(), "epk JSON missing `{key}`");
    }
}

#[test]
fn keystore_z_path_matches_scalar_path() {
    // The `signet` keystore never exposes the private scalar: its SE/software
    // backend computes the ECDH shared secret Z and calls
    // unwrap_dek_with_shared_secret. That path must yield the same DEK as the
    // scalar-based unwrap (the cross-check for the CLI's decrypt/rewrap).
    let (recipient_priv, recipient_pub) = keypair();
    let dek = [0x42u8; 32];
    let envelope = wrap::wrap_dek(&recipient_pub, &dek).unwrap();

    let via_scalar = wrap::unwrap_dek(&recipient_priv, &envelope).unwrap();

    let epk = envelope.ephemeral_pubkey_x963().unwrap();
    let z = signet_crypto::ecdh::ecdh_p256(&recipient_priv, &epk).unwrap();
    let via_z = wrap::unwrap_dek_with_shared_secret(&z, &envelope).unwrap();

    assert_eq!(via_scalar, dek);
    assert_eq!(
        via_z, via_scalar,
        "keystore Z-path must match the scalar path"
    );
}

#[test]
fn keystore_z_path_metadata_key_keeps_folder_binding() {
    let (recipient_priv, recipient_pub) = keypair();
    let metadata_key = [0x7eu8; 32];
    let root = [0xabu8; 16];
    let envelope = wrap::wrap_metadata_key(&recipient_pub, &metadata_key, &root).unwrap();

    let epk = envelope.ephemeral_pubkey_x963().unwrap();
    let z = signet_crypto::ecdh::ecdh_p256(&recipient_priv, &epk).unwrap();
    assert_eq!(
        wrap::unwrap_metadata_key_with_shared_secret(&z, &envelope, &root).unwrap(),
        metadata_key,
    );
    // The P-015 folder binding survives the Z-path: a wrong root rejects.
    assert_eq!(
        wrap::unwrap_metadata_key_with_shared_secret(&z, &envelope, &[0xcdu8; 16]),
        Err(CryptoError::Authentication),
    );
}
