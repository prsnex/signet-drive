// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Tests for the verification commands (attestation-verify / transparency-verify),
//! driving the built `signet` binary against **fixtures** generated with
//! `signet-crypto` — a server-signed §9 response and a real RFC-6962 inclusion
//! proof — so the verification logic is exercised end-to-end without a live
//! server. (The HTTP fetch paths + audit/update are manually verified.)

use std::process::{Command, Output};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};
use tempfile::TempDir;

/// Run `signet <args>` with config forced to defaults (no real home access).
fn signet(config_dir: &std::path::Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_signet"))
        .env("SIGNET_CONFIG", config_dir.join("absent.toml"))
        .args(args)
        .output()
        .expect("spawn signet")
}

// ── attestation-verify ──────────────────────────────────────────────────────

const TEST_SERVER_KEY_ID: &str = "00000000-0000-4000-8000-0000000000aa";

/// Build a §9 verification response over `attestation`, signed with a fresh server
/// key; return (response JSON, server pubkey b64url, server scalar) so a caller can
/// also sign matching §10a receipts with the same key.
fn signed_response_full(attestation: &Value) -> (Value, String, [u8; 32]) {
    let (scalar, pubkey) = signet_crypto::ecdsa::generate_keypair();
    let signed_at = 1_700_000_000i64;
    let input = signet_crypto::attest::verification_signing_input(
        attestation,
        TEST_SERVER_KEY_ID,
        signed_at,
    )
    .unwrap();
    let sig = signet_crypto::ecdsa::sign_es256(&scalar, &input).unwrap();
    let response = json!({
        "v": 1,
        "attestation": attestation,
        "server_key_id": TEST_SERVER_KEY_ID,
        "server_signature": URL_SAFE_NO_PAD.encode(sig),
        "signed_at": signed_at,
    });
    (response, URL_SAFE_NO_PAD.encode(&pubkey), scalar)
}

fn signed_response(attestation: &Value) -> (Value, String) {
    let (response, pubkey, _scalar) = signed_response_full(attestation);
    (response, pubkey)
}

/// Build a §10a transparency-log receipt for `(fingerprint, purpose)`, signed with
/// `scalar` (the same server key as the §9 response), mirroring the server schema
/// (`pubkey_log::latest_receipt`).
fn signed_receipt(scalar: &[u8; 32], fingerprint: &str, purpose: &str) -> Value {
    let mut receipt = json!({
        "v": 1,
        "type": "pubkey_log_receipt",
        "entry_id": 1,
        "account_id": "00000000-0000-4000-8000-000000000002",
        "key_purpose": purpose,
        "algorithm": if purpose == "signing" { "ES256" } else { "ECDH-ES+A256KW" },
        "public_key_fingerprint": fingerprint,
        "entry_hash": "00",
        "log_size_at_insertion": 1,
        "issued_at": 1_700_000_000i64,
        "max_merge_delay_seconds": 86400,
        "server_key_id": TEST_SERVER_KEY_ID,
    });
    let input = signet_crypto::translog::receipt_signing_input(&receipt).unwrap();
    let sig = signet_crypto::ecdsa::sign_es256(scalar, &input).unwrap();
    receipt["server_signature"] = json!(URL_SAFE_NO_PAD.encode(sig));
    receipt
}

fn attestation(status: &str) -> Value {
    json!({
        "attestation_id": "00000000-0000-4000-8000-000000000001",
        "subject_account_id": "00000000-0000-4000-8000-000000000002",
        "subject_handle": "hlin-ai",
        "subject_signing_pubkey_fingerprint": "aa",
        "subject_kem_pubkey_fingerprint": "bb",
        "expires_at": null,
        "status": status,
        "prsn_sharing_capability": "read_only",
    })
}

#[test]
fn attestation_verify_accepts_a_valid_active_response() {
    let dir = TempDir::new().unwrap();
    let (response, server_pub) = signed_response(&attestation("active"));
    let path = dir.path().join("resp.json");
    std::fs::write(&path, serde_json::to_vec(&response).unwrap()).unwrap();

    let out = signet(
        dir.path(),
        &[
            "attestation-verify",
            "--in",
            path.to_str().unwrap(),
            "--server-pubkey",
            &server_pub,
        ],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["valid"], true);
    assert_eq!(parsed["status"], "active");
    assert_eq!(parsed["subject_handle"], "hlin-ai");
    // No inline receipts in this fixture → §10a degrades gracefully.
    assert_eq!(parsed["transparency"], "absent");
}

#[test]
fn attestation_verify_reports_revoked_with_exit_15() {
    let dir = TempDir::new().unwrap();
    let (response, server_pub) = signed_response(&attestation("revoked"));
    let path = dir.path().join("resp.json");
    std::fs::write(&path, serde_json::to_vec(&response).unwrap()).unwrap();

    let out = signet(
        dir.path(),
        &[
            "attestation-verify",
            "--in",
            path.to_str().unwrap(),
            "--server-pubkey",
            &server_pub,
        ],
    );
    assert_eq!(out.status.code(), Some(15));
    let parsed: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["valid"], false);
    assert_eq!(parsed["status"], "revoked");
}

#[test]
fn attestation_verify_rejects_a_tampered_signature_with_exit_13() {
    let dir = TempDir::new().unwrap();
    let (mut response, server_pub) = signed_response(&attestation("active"));
    // Flip the signed_at so the canonical bytes no longer match the signature.
    response["signed_at"] = json!(1_700_000_001i64);
    let path = dir.path().join("resp.json");
    std::fs::write(&path, serde_json::to_vec(&response).unwrap()).unwrap();

    let out = signet(
        dir.path(),
        &[
            "attestation-verify",
            "--in",
            path.to_str().unwrap(),
            "--server-pubkey",
            &server_pub,
        ],
    );
    assert_eq!(out.status.code(), Some(13));
}

#[test]
fn attestation_verify_verifies_inline_receipts() {
    let dir = TempDir::new().unwrap();
    let (mut response, server_pub, scalar) = signed_response_full(&attestation("active"));
    // Receipts whose fingerprints match the attested keys ("aa"/"bb"), signed by
    // the same server key as the §9 response.
    response["subject_signing_pubkey_receipt"] = signed_receipt(&scalar, "aa", "signing");
    response["subject_kem_pubkey_receipt"] = signed_receipt(&scalar, "bb", "kem");
    let path = dir.path().join("resp.json");
    std::fs::write(&path, serde_json::to_vec(&response).unwrap()).unwrap();

    let out = signet(
        dir.path(),
        &[
            "attestation-verify",
            "--in",
            path.to_str().unwrap(),
            "--server-pubkey",
            &server_pub,
        ],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["valid"], true);
    assert_eq!(parsed["transparency"], "verified");
}

#[test]
fn attestation_verify_rejects_a_tampered_receipt_with_exit_60() {
    let dir = TempDir::new().unwrap();
    let (mut response, server_pub, scalar) = signed_response_full(&attestation("active"));
    let mut receipt = signed_receipt(&scalar, "aa", "signing");
    // Corrupt the receipt signature so it no longer verifies → §10a fails closed.
    let mut sig = URL_SAFE_NO_PAD
        .decode(receipt["server_signature"].as_str().unwrap())
        .unwrap();
    sig[0] ^= 0x01;
    receipt["server_signature"] = json!(URL_SAFE_NO_PAD.encode(&sig));
    response["subject_signing_pubkey_receipt"] = receipt;
    let path = dir.path().join("resp.json");
    std::fs::write(&path, serde_json::to_vec(&response).unwrap()).unwrap();

    let out = signet(
        dir.path(),
        &[
            "attestation-verify",
            "--in",
            path.to_str().unwrap(),
            "--server-pubkey",
            &server_pub,
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(60),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ── transparency-verify ───────────────────────────────────────────────────────

/// Build an inclusion-proof document (the server's §6.2 shape) for the entry at
/// `index` in a synthetic log of `n` leaves; return (proof JSON, root hex).
fn inclusion_proof_doc(n: usize, index: usize) -> (Value, String) {
    let leaves: Vec<[u8; 32]> = (0..n).map(|i| [(i as u8).wrapping_add(1); 32]).collect();
    let proof = signet_crypto::merkle::inclusion_proof(&leaves, index);
    let root = signet_crypto::merkle::merkle_root(&leaves);
    let doc = json!({
        "entry_id": (index + 1) as u64,
        "public_key_fingerprint": "abcd",
        "key_purpose": "kem",
        "entry_hash": hex::encode(leaves[index]),
        "log_size_at_proof": n as u64,
        "merkle_root_at_proof": hex::encode(root),
        "inclusion_proof": proof.iter().map(hex::encode).collect::<Vec<_>>(),
    });
    (doc, hex::encode(root))
}

#[test]
fn transparency_verify_accepts_a_valid_proof_against_published_root() {
    let dir = TempDir::new().unwrap();
    let (doc, root_hex) = inclusion_proof_doc(7, 3);
    let path = dir.path().join("proof.json");
    std::fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();

    let out = signet(
        dir.path(),
        &[
            "transparency-verify",
            "--inclusion-proof",
            path.to_str().unwrap(),
            "--published-root",
            &root_hex,
            "--published-size",
            "7",
        ],
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["valid"], true);
    assert_eq!(parsed["match"], true);
}

#[test]
fn transparency_verify_flags_a_root_mismatch_with_exit_60() {
    let dir = TempDir::new().unwrap();
    let (doc, _root_hex) = inclusion_proof_doc(7, 3);
    let path = dir.path().join("proof.json");
    std::fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();

    // A valid proof but a DIFFERENT root claimed for the SAME size — two roots
    // for one size is a fork, the violation exit 60 is reserved for (bug149:
    // between-publish growth no longer lands here; it verifies by consistency
    // proof instead).
    let wrong_root = hex::encode([0xffu8; 32]);
    let out = signet(
        dir.path(),
        &[
            "transparency-verify",
            "--inclusion-proof",
            path.to_str().unwrap(),
            "--published-root",
            &wrong_root,
            "--published-size",
            "7",
        ],
    );
    assert_eq!(out.status.code(), Some(60));
    let parsed: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["valid"], true);
    assert_eq!(parsed["match"], false);
}

#[test]
fn transparency_verify_refuses_published_root_without_its_size() {
    // bug149: a published root is a snapshot AT A SIZE — without the size the
    // extension question cannot be asked, so the pair is mandatory (clap
    // `requires`). Pinned here so the contract cannot loosen silently.
    let dir = TempDir::new().unwrap();
    let (doc, root_hex) = inclusion_proof_doc(7, 3);
    let path = dir.path().join("proof.json");
    std::fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();

    let out = signet(
        dir.path(),
        &[
            "transparency-verify",
            "--inclusion-proof",
            path.to_str().unwrap(),
            "--published-root",
            &root_hex,
        ],
    );
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--published-size"),
        "the refusal must name the missing flag; stderr: {stderr}"
    );
}

#[test]
fn transparency_verify_rejects_a_tampered_proof_with_exit_13() {
    let dir = TempDir::new().unwrap();
    let (mut doc, root_hex) = inclusion_proof_doc(7, 3);
    // Corrupt the leaf so it no longer reconstructs to the root.
    doc["entry_hash"] = json!(hex::encode([0x99u8; 32]));
    let path = dir.path().join("proof.json");
    std::fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();

    let out = signet(
        dir.path(),
        &[
            "transparency-verify",
            "--inclusion-proof",
            path.to_str().unwrap(),
            "--published-root",
            &root_hex,
            "--published-size",
            "7",
        ],
    );
    assert_eq!(out.status.code(), Some(13));
    let parsed: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["valid"], false);
}
