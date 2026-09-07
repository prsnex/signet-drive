// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! End-to-end tests for the crypto-op + utility commands, driving the built
//! `signet` binary (clap → dispatch → commands → signet-crypto) against a temp
//! keystore. Each test is isolated in its own `TempDir`.

use std::path::Path;
use std::process::{Command, Output};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use tempfile::TempDir;

/// Run `signet <args>` against a temp keystore (software tier; defaults config).
fn run(keys: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_signet"))
        .env("SIGNET_KEYS_DIR", keys)
        .env("SIGNET_CONFIG", keys.join("absent-config.toml"))
        .env("SIGNET_KEY_TIER", "software")
        .args(args)
        .output()
        .expect("spawn signet")
}

/// Run, assert success, return stdout bytes.
fn ok(keys: &Path, args: &[&str]) -> Vec<u8> {
    let out = run(keys, args);
    assert!(
        out.status.success(),
        "signet {args:?} failed (code {:?}): {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

fn pubkey_b64(keys: &Path, purpose: &str, label: &str) -> String {
    let raw = ok(keys, &["pubkey", purpose, "--key", label, "--base64url"]);
    String::from_utf8(raw).unwrap().trim().to_string()
}

/// Mint a hybrid recipient identity (classical KEM + ML-KEM sibling) in the
/// keystore and return (classical_pubkey_b64, mlkem_ek_b64) — every offline
/// wrap is hybrid (mandatory hybrid write, PQR §9.2).
fn hybrid_recipient(keys: &Path, handle: &str) -> (String, String) {
    let kem_label = format!("{handle}-kem");
    let pq_label = format!("{handle}-kem-pq");
    ok(keys, &["keygen", "--kem", "--label", &kem_label]);
    ok(keys, &["keygen", "--kem-pq", "--label", &pq_label]);
    (
        pubkey_b64(keys, "--kem", &kem_label),
        pubkey_b64(keys, "--kem-pq", &pq_label),
    )
}

#[test]
fn encrypt_then_decrypt_round_trips() {
    let dir = TempDir::new().unwrap();
    let keys = dir.path().join("keys");
    let p = |name: &str| dir.path().join(name).to_str().unwrap().to_string();

    let (recipient, recipient_pq) = hybrid_recipient(&keys, "hlin-ai");

    std::fs::write(p("plain.txt"), b"hello signet drive").unwrap();
    let file_id = "00000000-0000-4000-8000-000000000001";
    ok(
        &keys,
        &[
            "encrypt",
            "--in",
            &p("plain.txt"),
            "--out",
            &p("cipher.bin"),
            "--aad-file-id",
            file_id,
            "--to-pubkey",
            &recipient,
            "--to-pq-pubkey",
            &recipient_pq,
            "--wraps-out",
            &p("wraps.json"),
        ],
    );

    // The wraps file is an array (one per recipient); decrypt takes one envelope.
    let wraps: serde_json::Value =
        serde_json::from_slice(&std::fs::read(p("wraps.json")).unwrap()).unwrap();
    std::fs::write(p("wrap0.json"), serde_json::to_vec(&wraps[0]).unwrap()).unwrap();

    ok(
        &keys,
        &[
            "decrypt",
            "--in",
            &p("cipher.bin"),
            "--out",
            &p("out.txt"),
            "--aad-file-id",
            file_id,
            "--wrap-envelope",
            &p("wrap0.json"),
            "--key",
            "hlin-ai-kem",
        ],
    );
    assert_eq!(std::fs::read(p("out.txt")).unwrap(), b"hello signet drive");
}

#[test]
fn decrypt_with_wrong_file_id_fails() {
    let dir = TempDir::new().unwrap();
    let keys = dir.path().join("keys");
    let p = |name: &str| dir.path().join(name).to_str().unwrap().to_string();

    let (recipient, recipient_pq) = hybrid_recipient(&keys, "hlin-ai");
    std::fs::write(p("plain.txt"), b"bound to its file_id").unwrap();
    ok(
        &keys,
        &[
            "encrypt",
            "--in",
            &p("plain.txt"),
            "--out",
            &p("cipher.bin"),
            "--aad-file-id",
            "00000000-0000-4000-8000-000000000001",
            "--to-pubkey",
            &recipient,
            "--to-pq-pubkey",
            &recipient_pq,
            "--wraps-out",
            &p("wraps.json"),
        ],
    );
    let wraps: serde_json::Value =
        serde_json::from_slice(&std::fs::read(p("wraps.json")).unwrap()).unwrap();
    std::fs::write(p("wrap0.json"), serde_json::to_vec(&wraps[0]).unwrap()).unwrap();

    // A different file_id (the AAD) must fail the GCM tag (exit 42).
    let out = run(
        &keys,
        &[
            "decrypt",
            "--in",
            &p("cipher.bin"),
            "--out",
            &p("out.txt"),
            "--aad-file-id",
            "00000000-0000-4000-8000-000000000099",
            "--wrap-envelope",
            &p("wrap0.json"),
            "--key",
            "hlin-ai-kem",
        ],
    );
    assert_eq!(out.status.code(), Some(42));
}

#[test]
fn sign_output_verifies_with_crypto() {
    let dir = TempDir::new().unwrap();
    let keys = dir.path().join("keys");
    let p = |name: &str| dir.path().join(name).to_str().unwrap().to_string();

    ok(
        &keys,
        &["keygen", "--signing", "--label", "hlin-ai-signing"],
    );
    let pubkey = URL_SAFE_NO_PAD
        .decode(pubkey_b64(&keys, "--signing", "hlin-ai-signing"))
        .unwrap();

    let message = b"SIGNET-V1\nGET\n/v1/me\n...";
    std::fs::write(p("msg.bin"), message).unwrap();
    let sig = ok(
        &keys,
        &["sign", "--key", "hlin-ai-signing", "--in", &p("msg.bin")],
    );
    assert_eq!(sig.len(), 64, "default --output-format raw is 64-byte r‖s");
    signet_crypto::ecdsa::verify_es256(&pubkey, message, &sig).expect("CLI signature verifies");

    // base64url-der output decodes + verifies too.
    let der_b64 = ok(
        &keys,
        &[
            "sign",
            "--key",
            "hlin-ai-signing",
            "--in",
            &p("msg.bin"),
            "--output-format",
            "base64url-der",
        ],
    );
    let der = URL_SAFE_NO_PAD
        .decode(String::from_utf8(der_b64).unwrap().trim())
        .unwrap();
    signet_crypto::ecdsa::verify_es256(&pubkey, message, &der).expect("DER signature verifies");
}

#[test]
fn encrypt_name_then_decrypt_name_round_trips() {
    let dir = TempDir::new().unwrap();
    let keys = dir.path().join("keys");
    let p = |name: &str| dir.path().join(name).to_str().unwrap().to_string();

    ok(&keys, &["keygen", "--kem", "--label", "hlin-ai-kem"]);
    let kem_pub = URL_SAFE_NO_PAD
        .decode(pubkey_b64(&keys, "--kem", "hlin-ai-kem"))
        .unwrap();

    // Build a metadata-key wrap addressed to the PRSN's KEM key, bound to root.
    let root = "00000000-0000-4000-8000-000000000010";
    let target = "00000000-0000-4000-8000-000000000011";
    let root16 = *uuid::Uuid::parse_str(root).unwrap().as_bytes();
    let metadata_key = [0x33u8; 32];
    let mk_wrap = signet_crypto::wrap::wrap_metadata_key(&kem_pub, &metadata_key, &root16).unwrap();
    std::fs::write(p("mkwrap.json"), serde_json::to_vec(&mk_wrap).unwrap()).unwrap();

    let name_env = ok(
        &keys,
        &[
            "encrypt-name",
            "--metadata-key-wrap",
            &p("mkwrap.json"),
            "--root-folder-id",
            root,
            "--target-id",
            target,
            "--name",
            "schema.md",
            "--key",
            "hlin-ai-kem",
        ],
    );
    std::fs::write(p("name.json"), &name_env).unwrap();

    let decrypted = ok(
        &keys,
        &[
            "decrypt-name",
            "--metadata-key-wrap",
            &p("mkwrap.json"),
            "--root-folder-id",
            root,
            "--target-id",
            target,
            "--in",
            &p("name.json"),
            "--key",
            "hlin-ai-kem",
        ],
    );
    assert_eq!(String::from_utf8(decrypted).unwrap(), "schema.md");
}

#[test]
fn rewrap_from_self_to_new_recipient() {
    let dir = TempDir::new().unwrap();
    let keys = dir.path().join("keys");
    let p = |name: &str| dir.path().join(name).to_str().unwrap().to_string();

    let (hlin, hlin_pq) = hybrid_recipient(&keys, "hlin-ai");
    let (mira, mira_pq) = hybrid_recipient(&keys, "mira-ai");

    std::fs::write(p("plain.txt"), b"rewrap me").unwrap();
    let file_id = "00000000-0000-4000-8000-000000000002";
    ok(
        &keys,
        &[
            "encrypt",
            "--in",
            &p("plain.txt"),
            "--out",
            &p("cipher.bin"),
            "--aad-file-id",
            file_id,
            "--to-pubkey",
            &hlin,
            "--to-pq-pubkey",
            &hlin_pq,
            "--wraps-out",
            &p("wraps.json"),
        ],
    );
    let wraps: serde_json::Value =
        serde_json::from_slice(&std::fs::read(p("wraps.json")).unwrap()).unwrap();
    std::fs::write(p("wrap_hlin.json"), serde_json::to_vec(&wraps[0]).unwrap()).unwrap();

    // Rewrap hlin's DEK wrap to mira (without exposing the DEK) — hybrid in,
    // hybrid out.
    ok(
        &keys,
        &[
            "rewrap",
            "--wrap-envelope-in",
            &p("wrap_hlin.json"),
            "--to-pubkey",
            &mira,
            "--to-pq-pubkey",
            &mira_pq,
            "--wrap-out",
            &p("wrap_mira.json"),
            "--key",
            "hlin-ai-kem",
        ],
    );
    // mira can now decrypt the same ciphertext with her rewrapped DEK.
    ok(
        &keys,
        &[
            "decrypt",
            "--in",
            &p("cipher.bin"),
            "--out",
            &p("out.txt"),
            "--aad-file-id",
            file_id,
            "--wrap-envelope",
            &p("wrap_mira.json"),
            "--key",
            "mira-ai-kem",
        ],
    );
    assert_eq!(std::fs::read(p("out.txt")).unwrap(), b"rewrap me");
}

#[test]
fn utilities_smoke() {
    let dir = TempDir::new().unwrap();
    let keys = dir.path().join("keys");

    // rand --hex 16 → 32 hex chars.
    let hex = String::from_utf8(ok(&keys, &["rand", "--hex", "16"])).unwrap();
    assert_eq!(hex.trim().len(), 32);
    assert!(hex.trim().chars().all(|c| c.is_ascii_hexdigit()));

    // base64url-no-pad encode then decode round-trips through stdin? Use --in files.
    std::fs::write(dir.path().join("raw.bin"), [0xde, 0xad, 0xbe, 0xef]).unwrap();
    let encoded = String::from_utf8(ok(
        &keys,
        &[
            "base64url-no-pad",
            "encode",
            "--in",
            dir.path().join("raw.bin").to_str().unwrap(),
        ],
    ))
    .unwrap();
    std::fs::write(dir.path().join("enc.txt"), encoded.trim()).unwrap();
    let decoded = ok(
        &keys,
        &[
            "base64url-no-pad",
            "decode",
            "--in",
            dir.path().join("enc.txt").to_str().unwrap(),
        ],
    );
    assert_eq!(decoded, vec![0xde, 0xad, 0xbe, 0xef]);

    // version exits 0 and names the platform.
    let v = String::from_utf8(ok(&keys, &["version"])).unwrap();
    assert!(v.starts_with("signet "), "version line: {v}");
}

#[test]
fn encrypt_refuses_a_classical_only_recipient() {
    // F-DOWNGRADE(a) on the OFFLINE writer: `encrypt` with a --to-pubkey and
    // no paired --to-pq-pubkey must refuse — the shipped binary emits no
    // classical-only wrap from any path (mandatory hybrid write, PQR §9.2).
    let dir = TempDir::new().unwrap();
    let keys = dir.path().join("keys");
    let p = |name: &str| dir.path().join(name).to_str().unwrap().to_string();

    ok(&keys, &["keygen", "--kem", "--label", "hlin-ai-kem"]);
    let recipient = pubkey_b64(&keys, "--kem", "hlin-ai-kem");
    std::fs::write(p("plain.txt"), b"never classical").unwrap();
    let out = run(
        &keys,
        &[
            "encrypt",
            "--in",
            &p("plain.txt"),
            "--out",
            &p("cipher.bin"),
            "--aad-file-id",
            "00000000-0000-4000-8000-000000000003",
            "--to-pubkey",
            &recipient,
            "--wraps-out",
            &p("wraps.json"),
        ],
    );
    assert!(!out.status.success(), "classical-only encrypt must refuse");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("ML-KEM"),
        "the refusal must name the missing ML-KEM half: {stderr}"
    );
}

/// Bug036: a REAL hyphen-first ML-KEM ek must round-trip end-to-end when passed
/// space-separated. base64url's index 62 is `-`, so ~1/64 of random eks encode
/// hyphen-first; keygen until one appears (expected ~64 draws, bounded), then
/// run the full hybrid encrypt→decrypt through the space-separated form that
/// clap used to eat as a flag. (The deterministic parse-only pin lives in
/// cli_args.rs; this proves the accepted value flows through the whole crypto
/// path unmangled.)
#[test]
fn encrypt_hyphen_first_mlkem_ek_round_trips() {
    let dir = TempDir::new().unwrap();
    let keys = dir.path().join("keys");
    let p = |name: &str| dir.path().join(name).to_str().unwrap().to_string();

    // Draw ML-KEM identities until the ek encodes hyphen-first. 2000 draws
    // bounds the miss probability at (63/64)^2000 ≈ 2e-14 — never in practice.
    let mut found: Option<(String, String)> = None; // (handle, hyphen-first ek)
    for i in 0..2000 {
        let handle = format!("r{i}-ai");
        let pq_label = format!("{handle}-kem-pq");
        ok(&keys, &["keygen", "--kem-pq", "--label", &pq_label]);
        let ek = pubkey_b64(&keys, "--kem-pq", &pq_label);
        if ek.starts_with('-') {
            found = Some((handle, ek));
            break;
        }
    }
    let (handle, ek) = found.expect("no hyphen-first ek in 2000 draws (P ≈ 2e-14)");
    let kem_label = format!("{handle}-kem");
    ok(&keys, &["keygen", "--kem", "--label", &kem_label]);
    let classical = pubkey_b64(&keys, "--kem", &kem_label);

    std::fs::write(p("plain.txt"), b"hyphen-first ek, space-separated").unwrap();
    let file_id = "00000000-0000-4000-8000-000000000036";
    ok(
        &keys,
        &[
            "encrypt",
            "--in",
            &p("plain.txt"),
            "--out",
            &p("cipher.bin"),
            "--aad-file-id",
            file_id,
            "--to-pubkey",
            &classical,
            "--to-pq-pubkey",
            &ek, // space-separated on purpose — the Bug036 failing form
            "--wraps-out",
            &p("wraps.json"),
        ],
    );
    let wraps: serde_json::Value =
        serde_json::from_slice(&std::fs::read(p("wraps.json")).unwrap()).unwrap();
    std::fs::write(p("wrap0.json"), serde_json::to_vec(&wraps[0]).unwrap()).unwrap();
    ok(
        &keys,
        &[
            "decrypt",
            "--in",
            &p("cipher.bin"),
            "--out",
            &p("out.txt"),
            "--aad-file-id",
            file_id,
            "--wrap-envelope",
            &p("wrap0.json"),
            "--key",
            &kem_label,
        ],
    );
    assert_eq!(
        std::fs::read(p("out.txt")).unwrap(),
        b"hyphen-first ek, space-separated"
    );
}
