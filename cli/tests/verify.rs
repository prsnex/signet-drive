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

/// Build an inclusion-proof document (the design v05 §10.4 shape: the stored
/// entry whole, bug256) for the entry at `index` in a log of `n` real v3
/// entries; return (proof JSON, root hex). Each leaf is the entry's own
/// `entry_hash_v3`, so the CLI's recomputation binds it.
fn inclusion_proof_doc(n: usize, index: usize) -> (Value, String) {
    use base64::Engine;
    let b64u = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut prev = [0u8; 32];
    let mut leaves = Vec::with_capacity(n);
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let id = (i + 1) as u64;
        let pk = vec![(i as u8).wrapping_add(1); 1568];
        let idx = [(i as u8).wrapping_add(0x40); 64];
        let h = signet_crypto::translog::entry_hash_v3(
            id,
            Some(&idx),
            signet_crypto::translog::KeyPurpose::KemPq,
            "ML-KEM-1024",
            &pk,
            1_793_000_000,
            &prev,
        );
        entries.push(json!({
            "epoch": 2, "entry_id": id, "entry_version": 3,
            "account_index": hex::encode(idx), "key_purpose": "kem_pq",
            "algorithm": "ML-KEM-1024", "public_key": b64u.encode(&pk),
            "public_key_fingerprint": signet_crypto::pubkey::fingerprint_raw(&pk),
            "created_at": 1_793_000_000u64, "prev_entry_hash": hex::encode(prev),
            "entry_hash": hex::encode(h),
        }));
        leaves.push(h);
        prev = h;
    }
    let proof = signet_crypto::merkle::inclusion_proof(&leaves, index);
    let root = signet_crypto::merkle::merkle_root(&leaves);
    let mut doc = entries[index].clone();
    doc["log_size_at_proof"] = json!(n as u64);
    doc["merkle_root_at_proof"] = json!(hex::encode(root));
    doc["inclusion_proof"] = json!(proof.iter().map(hex::encode).collect::<Vec<_>>());
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
    // The inclusion holds, but the root is not the published one: not valid.
    assert_eq!(parsed["valid"], false);
    assert_eq!(parsed["inclusion_holds"], true);
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
    // Corrupt a sibling in the proof path so the (correctly bound) leaf no
    // longer reconstructs to the root. (Corrupting `entry_hash` itself is now
    // caught one step earlier, by the bug256 leaf binding, as a violation.)
    doc["inclusion_proof"][0] = json!(hex::encode([0x99u8; 32]));
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

#[test]
fn transparency_verify_refuses_a_proof_whose_entry_does_not_hash_to_its_leaf() {
    // bug256: a self-consistent tree over a leaf that is not this entry.
    let dir = TempDir::new().unwrap();
    let (mut doc, root_hex) = inclusion_proof_doc(7, 3);
    doc["algorithm"] = json!("ML-KEM-768");
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
    assert_eq!(
        out.status.code(),
        Some(60),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A loopback server answering every request with `body` (here: a
/// `/v1/server-info` with no `translog`, so the server is in epoch 1).
fn spawn_server(body: &'static str) -> u16 {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut sock) = conn else { break };
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf);
            let _ = sock.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            );
        }
    });
    port
}

#[test]
fn an_unanchored_result_is_never_valid_and_exits_62() {
    // Bob, #650: inclusion without a public anchor must not read as a pass in
    // the field or the exit code. A loopback server is one this CLI knows no
    // anchor repository for, and no --published-root is given.
    let dir = TempDir::new().unwrap();
    let (doc, _root_hex) = inclusion_proof_doc(7, 3);
    let path = dir.path().join("proof.json");
    std::fs::write(&path, serde_json::to_vec(&doc).unwrap()).unwrap();
    let port = spawn_server(r#"{"current_signing_keys":[]}"#);
    let out = Command::new(env!("CARGO_BIN_EXE_signet"))
        .env("SIGNET_CONFIG", dir.path().join("absent.toml"))
        .env("SIGNET_SERVER_URL", format!("http://127.0.0.1:{port}"))
        .env("XDG_CONFIG_HOME", dir.path())
        .env_remove("SIGNET_ANCHOR_REPO")
        .args([
            "transparency-verify",
            "--inclusion-proof",
            path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn signet");
    assert_eq!(
        out.status.code(),
        Some(62),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["valid"], false);
    assert_eq!(parsed["inclusion_holds"], true);
    assert_eq!(parsed["published_root_status"], "unanchored");
}

/// `attestation-verify` online against a loopback server whose server-info
/// carries the response's signing key and, optionally, an epoch.
fn attestation_verify_online(translog: Option<Value>) -> Output {
    let dir = TempDir::new().unwrap();
    let (response, server_pub) = signed_response(&attestation("active"));
    let path = dir.path().join("resp.json");
    std::fs::write(&path, serde_json::to_vec(&response).unwrap()).unwrap();
    let mut info = json!({ "current_signing_keys": [{
        "key_id": TEST_SERVER_KEY_ID, "public_key": server_pub,
        "purpose": "attestation_verification",
    }]});
    if let Some(t) = translog {
        info["translog"] = t;
    }
    let port = spawn_server(Box::leak(info.to_string().into_boxed_str()));
    Command::new(env!("CARGO_BIN_EXE_signet"))
        .env("SIGNET_CONFIG", dir.path().join("absent.toml"))
        .env("SIGNET_SERVER_URL", format!("http://127.0.0.1:{port}"))
        .env("XDG_CONFIG_HOME", dir.path())
        .env_remove("SIGNET_ANCHOR_REPO")
        .args(["attestation-verify", "--in", path.to_str().unwrap()])
        .output()
        .expect("spawn signet")
}

#[test]
fn attestation_verify_online_in_an_unanchorable_epoch_2_exits_62() {
    // Gus, #651 ruling 1: online, the receipts are bound by index in an
    // anchored epoch ≥ 2. A loopback server has no anchor repository, so its
    // epoch 2 cannot be anchored and nothing is bound: 62, never a pass.
    let out = attestation_verify_online(Some(json!({
        "epoch": 2, "vrf_suite": signet_crypto::vrf::VRF_SUITE,
        "vrf_public_key": "07".repeat(32),
    })));
    assert_eq!(
        out.status.code(),
        Some(62),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn attestation_verify_online_in_epoch_1_keeps_the_attestations_binding() {
    let out = attestation_verify_online(None);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["valid"], true);
    assert_eq!(parsed["receipt_binding"], "attestation");
}
