// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Known-answer tests for the transparency-log canonical bytes
//! (`signet_crypto::translog`): the `entry_hash` composition (test-vector Cat 07)
//! and the §10a receipt signing input (Cat 05). The `entry_hash` test rebuilds the
//! canonical preimage byte-by-byte from the spec and checks the function hashes the
//! same bytes — catching exactly Cat 07's TC07-04 mistakes (endianness, UUID
//! encoding, enum mapping, length-prefix width, ms-vs-s).

use serde_json::json;
use signet_crypto::hash;
use signet_crypto::translog::{self, KeyPurpose};

/// 65-byte X9.63 uncompressed form (`0x04 || X || Y`). Not a real curve point —
/// `entry_hash` hashes the bytes; it does not validate the point.
fn test_pubkey() -> Vec<u8> {
    std::iter::once(0x04u8).chain(1u8..=64).collect()
}

/// `00000000-0000-4000-8000-000000000001` (Cat 07 HUMAN_1) raw 16 bytes.
const HUMAN_1: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

#[test]
fn key_purpose_byte_mapping() {
    assert_eq!(KeyPurpose::Epoch.as_byte(), 0x00);
    assert_eq!(KeyPurpose::Signing.as_byte(), 0x01);
    assert_eq!(KeyPurpose::Kem.as_byte(), 0x02);
    assert_eq!(KeyPurpose::SigningPq.as_byte(), 0x03);
    assert_eq!(KeyPurpose::KemPq.as_byte(), 0x04);
}

#[test]
fn entry_hash_v2_matches_hand_built_canonical_bytes() {
    // The v2 preimage (PQR Transparency-Log ops doc §2): a kem_pq entry carrying
    // a 1568-byte ML-KEM-1024 ek, chained mid-log. Built byte-by-byte from the
    // ops doc, independently of the function.
    let ek: Vec<u8> = (0..1568u32).map(|i| (i % 251) as u8).collect();
    let prev = [0xABu8; 32];

    let mut canonical = Vec::new();
    canonical.push(0x02); // entry_version = 2 — FIRST, inside the hashed bytes
    canonical.extend_from_slice(&7u64.to_be_bytes()); // entry_id = 7
    canonical.extend_from_slice(&HUMAN_1); // account_id raw (16)
    canonical.push(0x04); // key_purpose = kem_pq
    canonical.extend_from_slice(&11u32.to_be_bytes()); // "ML-KEM-1024" length
    canonical.extend_from_slice(b"ML-KEM-1024");
    canonical.extend_from_slice(&1568u32.to_be_bytes()); // public_key LENGTH PREFIX (new in v2)
    canonical.extend_from_slice(&ek);
    canonical.extend_from_slice(&1_700_000_120u64.to_be_bytes()); // created_at
    canonical.extend_from_slice(&prev);
    assert_eq!(
        canonical.len(),
        1 + 8 + 16 + 1 + 4 + 11 + 4 + 1568 + 8 + 32,
        "v2 preimage layout"
    );

    let got = translog::entry_hash_v2(
        7,
        Some(&HUMAN_1),
        KeyPurpose::KemPq,
        "ML-KEM-1024",
        &ek,
        1_700_000_120,
        &prev,
    );
    assert_eq!(got, hash::sha256(&canonical));
}

#[test]
fn entry_hash_v2_epoch_checkpoint_hashes_null_account_as_zero_uuid() {
    // The account-less epoch checkpoint (ops doc §2/§3a): account_id = None
    // hashes as 16 zero bytes; the payload is the fixed descriptive tag.
    let prev = [0x11u8; 32];
    let mut canonical = Vec::new();
    canonical.push(0x02);
    canonical.extend_from_slice(&42u64.to_be_bytes());
    canonical.extend_from_slice(&[0u8; 16]); // NULL account → zero UUID
    canonical.push(0x00); // key_purpose = epoch
    canonical.extend_from_slice(&(translog::EPOCH_ALGORITHM.len() as u32).to_be_bytes());
    canonical.extend_from_slice(translog::EPOCH_ALGORITHM.as_bytes());
    canonical.extend_from_slice(&(translog::EPOCH_PAYLOAD.len() as u32).to_be_bytes());
    canonical.extend_from_slice(translog::EPOCH_PAYLOAD);
    canonical.extend_from_slice(&1_700_000_300u64.to_be_bytes());
    canonical.extend_from_slice(&prev);

    let got = translog::entry_hash_v2(
        42,
        None,
        KeyPurpose::Epoch,
        translog::EPOCH_ALGORITHM,
        translog::EPOCH_PAYLOAD,
        1_700_000_300,
        &prev,
    );
    assert_eq!(got, hash::sha256(&canonical));
}

#[test]
fn entry_hash_v1_and_v2_never_collide_on_identical_fields() {
    // The version byte inside the preimage separates the two rules even for a
    // classical-shaped entry with identical field values (the canonicalization-
    // ambiguity defense, ops doc §2 / Gus C2 A1).
    let pubkey = test_pubkey();
    let v1 = translog::entry_hash(
        1,
        &HUMAN_1,
        KeyPurpose::Kem,
        "ECDH-ES+A256KW",
        &pubkey,
        1_700_000_000,
        &[0u8; 32],
    );
    let v2 = translog::entry_hash_v2(
        1,
        Some(&HUMAN_1),
        KeyPurpose::Kem,
        "ECDH-ES+A256KW",
        &pubkey,
        1_700_000_000,
        &[0u8; 32],
    );
    assert_ne!(v1, v2);
}

#[test]
fn entry_hash_matches_hand_built_canonical_bytes() {
    // Cat 07 TC07-01: genesis entry — HUMAN_1's KEM key, ECDH-ES+A256KW, TS_T0.
    let pubkey = test_pubkey();
    let mut canonical = Vec::new();
    canonical.extend_from_slice(&1u64.to_be_bytes()); // entry_id = 1
    canonical.extend_from_slice(&HUMAN_1); // account_id raw (16)
    canonical.push(0x02); // key_purpose = kem
    // "ECDH-ES+A256KW" is 14 bytes — the Cat 07 doc miscounts it as 15 (it labels
    // "[15 bytes]" / 0x0000000f while its own hex dump lists 14 bytes; the doc's
    // 149 total inherits the error). The length prefix is the *actual* byte count.
    canonical.extend_from_slice(&14u32.to_be_bytes()); // algorithm byte length
    canonical.extend_from_slice(b"ECDH-ES+A256KW"); // 14 bytes
    canonical.extend_from_slice(&pubkey); // 65 bytes
    canonical.extend_from_slice(&1_700_000_000u64.to_be_bytes()); // created_at (TS_T0)
    canonical.extend_from_slice(&[0u8; 32]); // prev_entry_hash (genesis)
    assert_eq!(canonical.len(), 148, "8+16+1+4+14+65+8+32 = 148 bytes");

    let got = translog::entry_hash(
        1,
        &HUMAN_1,
        KeyPurpose::Kem,
        "ECDH-ES+A256KW",
        &pubkey,
        1_700_000_000,
        &[0u8; 32],
    );
    assert_eq!(got, hash::sha256(&canonical));
}

#[test]
fn entry_hash_is_sensitive_to_every_field() {
    let pubkey = test_pubkey();
    let genesis = translog::entry_hash(
        1,
        &HUMAN_1,
        KeyPurpose::Kem,
        "ECDH-ES+A256KW",
        &pubkey,
        1_700_000_000,
        &[0u8; 32],
    );
    // A second entry that chains off the genesis hash (prev = genesis).
    let chained = translog::entry_hash(
        2,
        &HUMAN_1,
        KeyPurpose::Signing,
        "ES256",
        &pubkey,
        1_700_000_060,
        &genesis,
    );
    assert_ne!(genesis, chained);

    // key_purpose is in the preimage.
    let flipped_purpose = translog::entry_hash(
        1,
        &HUMAN_1,
        KeyPurpose::Signing,
        "ECDH-ES+A256KW",
        &pubkey,
        1_700_000_000,
        &[0u8; 32],
    );
    assert_ne!(genesis, flipped_purpose);

    // prev_entry_hash is in the preimage — a different chain head breaks the link.
    let broken_chain = translog::entry_hash(
        2,
        &HUMAN_1,
        KeyPurpose::Signing,
        "ES256",
        &pubkey,
        1_700_000_060,
        &[0xFFu8; 32],
    );
    assert_ne!(chained, broken_chain);
}

#[test]
fn receipt_signing_input_pins_prefix_and_shape() {
    // The §10a receipt (excluding server_signature), Envelope-Format shape.
    let receipt = json!({
        "v": 1,
        "type": "signet-pubkey-log-receipt",
        "entry_id": 1,
        "account_id": "00000000-0000-4000-8000-000000000001",
        "key_purpose": "kem",
        "algorithm": "ECDH-ES+A256KW",
        "public_key_fingerprint": "ff",
        "entry_hash": "ee",
        "log_size_at_insertion": 1,
        "issued_at": 1_700_000_000_i64,
        "max_merge_delay_seconds": 86400_i64,
        "server_key_id": "00000000-0000-4000-8000-0000000000aa"
    });

    // JCS sorts the keys alphabetically; integers stay unquoted.
    let expected_jcs = concat!(
        r#"{"account_id":"00000000-0000-4000-8000-000000000001","#,
        r#""algorithm":"ECDH-ES+A256KW","#,
        r#""entry_hash":"ee","#,
        r#""entry_id":1,"#,
        r#""issued_at":1700000000,"#,
        r#""key_purpose":"kem","#,
        r#""log_size_at_insertion":1,"#,
        r#""max_merge_delay_seconds":86400,"#,
        r#""public_key_fingerprint":"ff","#,
        r#""server_key_id":"00000000-0000-4000-8000-0000000000aa","#,
        r#""type":"signet-pubkey-log-receipt","#,
        r#""v":1}"#
    );
    let mut expected = Vec::from(&b"signet-pubkey-log-receipt-v1\n"[..]);
    expected.extend_from_slice(expected_jcs.as_bytes());

    assert_eq!(translog::receipt_signing_input(&receipt).unwrap(), expected);
}

#[test]
fn server_dual_sign_ctx_constants_are_the_prefix_labels() {
    // §11.5b (item 7c): the FIPS 204 ctx for each server dual-sign surface is
    // the surface's domain-prefix LABEL — the prefix bytes minus the trailing
    // framing newline. Pinned byte-for-byte so no implementer re-derives them.
    assert_eq!(
        signet_crypto::translog::RECEIPT_MLDSA_CTX,
        b"signet-pubkey-log-receipt-v1"
    );
    assert_eq!(
        signet_crypto::attest::SERVER_VERIFY_MLDSA_CTX,
        b"signet-server-attestation-verify-v1"
    );
    // The label↔prefix relationship: prefix == label ‖ b"\n" (the §9/§10a
    // signing inputs start with the prefix; the ctx carries no newline).
    let mut receipt_prefix = signet_crypto::translog::RECEIPT_MLDSA_CTX.to_vec();
    receipt_prefix.push(b'\n');
    let input = signet_crypto::translog::receipt_signing_input(&serde_json::json!({})).unwrap();
    assert!(input.starts_with(&receipt_prefix));
}
