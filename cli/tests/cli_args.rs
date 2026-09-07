// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Argument-surface tests (Bug034 + Bug036): the S040 path-first convention's
//! parse shapes (conflict + shape errors are deterministic and pre-network) and
//! hyphen-first base64url values. Codes and keys are base64url-no-pad, whose
//! alphabet includes `-` (index 62) — any random value has a ~1/64 chance of
//! encoding hyphen-first, and clap's default parsing would eat it as a flag.
//! These tests pin the discriminator: a hyphen-first VALUE must never produce
//! clap's "unexpected argument" — it flows through to the command's own
//! (network/validation) error instead.

use std::path::Path;
use std::process::{Command, Output};

use tempfile::TempDir;

/// Run `signet <args>` against a temp keystore, an absent config, and an
/// unroutable server (nothing listens on 127.0.0.1:9) — network-reaching
/// commands fail at the connection, never silently succeed.
fn run(keys: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_signet"))
        .env("SIGNET_KEYS_DIR", keys)
        .env("SIGNET_CONFIG", keys.join("absent-config.toml"))
        .env("SIGNET_KEY_TIER", "software")
        .env("SIGNET_SERVER_URL", "http://127.0.0.1:9")
        .args(args)
        .output()
        .expect("spawn signet")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// The Bug036 pin: a hyphen-first value reached the command (not clap's
/// unexpected-argument rejection).
fn assert_parsed_past_clap(out: &Output, what: &str) {
    let err = stderr(out);
    assert!(
        !err.contains("unexpected argument"),
        "{what}: clap ate the hyphen-first value as a flag: {err}"
    );
    assert!(
        !out.status.success(),
        "{what}: expected a downstream (network/validation) failure against the dead server"
    );
}

// ---- Bug036: hyphen-first base64url positional codes ----

#[test]
fn enroll_accepts_hyphen_first_code() {
    let dir = TempDir::new().unwrap();
    let keys = dir.path().join("keys");
    // 256-bit enrollment codes are base64url-no-pad; ~1/64 begin with `-`.
    let out = run(
        &keys,
        &["enroll", "-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdef"],
    );
    assert_parsed_past_clap(&out, "enroll <hyphen-first CODE>");
}

#[test]
fn garnet_pickup_takes_no_positional_code() {
    // bug084 flag-day: pickup is signature-authenticated — there is NO pairing code, and a
    // leftover positional argument (an old script passing one) must be a clap parse error,
    // never silently ignored.
    let dir = TempDir::new().unwrap();
    let keys = dir.path().join("keys");
    let out = run(&keys, &["garnet", "pickup", "-AbCdEfGhIjKlMnOpQrStUvWxYz"]);
    assert!(
        !out.status.success(),
        "a positional code must be refused by clap"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unexpected argument") || stderr.contains("error:"),
        "clap refuses the retired positional: {stderr}"
    );
}

#[test]
fn broker_provision_accepts_hyphen_first_code() {
    let dir = TempDir::new().unwrap();
    let keys = dir.path().join("keys");
    let out = run(
        &keys,
        &["broker", "provision", "-AbCdEfGhIjKlMnOpQrStUvWxYz"],
    );
    assert_parsed_past_clap(&out, "broker provision <hyphen-first CODE>");
}

// ---- Bug036: hyphen-first base64url flag values ----

#[test]
fn encrypt_accepts_hyphen_first_pq_pubkey_value() {
    let dir = TempDir::new().unwrap();
    let keys = dir.path().join("keys");
    let p = |name: &str| dir.path().join(name).to_str().unwrap().to_string();
    std::fs::write(p("plain.txt"), b"x").unwrap();

    // A syntactically hyphen-first (deliberately invalid-length) ML-KEM ek: the
    // parse must accept it space-separated and fail later on ek validation —
    // never as clap's "unexpected argument". (The full valid-key round trip
    // lives in crypto_ops::encrypt_hyphen_first_mlkem_ek_round_trips.)
    let out = run(
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
            "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "--to-pq-pubkey",
            "-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "--wraps-out",
            &p("wraps.json"),
        ],
    );
    let err = stderr(&out);
    assert!(
        !err.contains("unexpected argument"),
        "clap ate the hyphen-first --to-pq-pubkey value: {err}"
    );
    assert!(!out.status.success());
}

// ---- Bug034: `share create` path-first shapes (pre-network, deterministic) ----

#[test]
fn share_create_rejects_path_and_name_together() {
    let dir = TempDir::new().unwrap();
    let keys = dir.path().join("keys");
    let out = run(&keys, &["share", "create", "Projects", "--name", "Other"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("not both"), "got: {}", stderr(&out));
}

#[test]
fn share_create_rejects_nested_path() {
    let dir = TempDir::new().unwrap();
    let keys = dir.path().join("keys");
    let out = run(&keys, &["share", "create", "/a/b"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("top-level"), "got: {}", stderr(&out));
}

#[test]
fn share_create_requires_a_name() {
    let dir = TempDir::new().unwrap();
    let keys = dir.path().join("keys");
    let out = run(&keys, &["share", "create"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("give a <name> or --name"),
        "got: {}",
        stderr(&out)
    );
}

// ---- Bug034: `file upload` destination-path shapes ----

/// Mint the two keys upload's label resolution needs, so the destination checks
/// (which run after label resolution) are reached deterministically.
fn upload_keys(keys: &Path) {
    for args in [
        ["keygen", "--signing", "--label", "u-ai-signing"],
        ["keygen", "--kem", "--label", "u-ai-kem"],
    ] {
        let out = run(keys, &args);
        assert!(out.status.success(), "keygen failed: {}", stderr(&out));
    }
}

#[test]
fn upload_rejects_path_and_flag_destination_together() {
    let dir = TempDir::new().unwrap();
    let keys = dir.path().join("keys");
    upload_keys(&keys);
    let p = dir.path().join("f.txt");
    std::fs::write(&p, b"x").unwrap();
    let out = run(
        &keys,
        &[
            "file",
            "upload",
            "/Finance/report.pdf",
            "--name",
            "other.pdf",
            "--in",
            p.to_str().unwrap(),
            "--key",
            "u-ai-signing",
            "--kem-key",
            "u-ai-kem",
        ],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("not both"), "got: {}", stderr(&out));
}

#[test]
fn upload_rejects_top_level_destination_path() {
    let dir = TempDir::new().unwrap();
    let keys = dir.path().join("keys");
    upload_keys(&keys);
    let p = dir.path().join("f.txt");
    std::fs::write(&p, b"x").unwrap();
    // A single-segment path has no destination folder — files cannot live at
    // the top level; the error is local (no network).
    let out = run(
        &keys,
        &[
            "file",
            "upload",
            "/report.pdf",
            "--in",
            p.to_str().unwrap(),
            "--key",
            "u-ai-signing",
            "--kem-key",
            "u-ai-kem",
        ],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("destination folder"),
        "got: {}",
        stderr(&out)
    );
}

#[test]
fn upload_requires_name_with_flag_destination() {
    let dir = TempDir::new().unwrap();
    let keys = dir.path().join("keys");
    upload_keys(&keys);
    let p = dir.path().join("f.txt");
    std::fs::write(&p, b"x").unwrap();
    let out = run(
        &keys,
        &[
            "file",
            "upload",
            "--to",
            "/Finance",
            "--in",
            p.to_str().unwrap(),
            "--key",
            "u-ai-signing",
            "--kem-key",
            "u-ai-kem",
        ],
    );
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("give --name"),
        "got: {}",
        stderr(&out)
    );
}

// ---- Bug025: the delete confirmation guard (file + folder) ----
// The subprocess's stdin is a pipe (non-TTY), so these pin the non-interactive
// branch deterministically: without --yes the guard REFUSES before any keystore
// or network touch; with --yes it opens (the command then fails downstream at
// the empty keystore / dead server — proving the guard, not the delete).

#[test]
fn file_delete_refuses_without_yes_when_non_interactive() {
    let dir = TempDir::new().unwrap();
    let keys = dir.path().join("keys");
    let out = run(&keys, &["file", "delete", "/Finance/q.pdf"]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(
        err.contains("Re-run with --yes"),
        "expected the Bug025 guard refusal, got: {err}"
    );
}

#[test]
fn file_delete_with_yes_passes_the_guard() {
    let dir = TempDir::new().unwrap();
    let keys = dir.path().join("keys");
    let out = run(&keys, &["file", "delete", "/Finance/q.pdf", "--yes"]);
    let err = stderr(&out);
    assert!(
        !err.contains("Re-run with --yes"),
        "--yes must open the guard, got: {err}"
    );
    assert!(
        !out.status.success(),
        "expected a downstream failure against the empty keystore / dead server"
    );
}

#[test]
fn folder_delete_refuses_without_yes_when_non_interactive() {
    let dir = TempDir::new().unwrap();
    let keys = dir.path().join("keys");
    let out = run(&keys, &["folder", "delete", "/Finance"]);
    assert!(!out.status.success());
    let err = stderr(&out);
    assert!(
        err.contains("Re-run with --yes"),
        "expected the Bug025 guard refusal, got: {err}"
    );
}

#[test]
fn folder_delete_with_yes_passes_the_guard() {
    let dir = TempDir::new().unwrap();
    let keys = dir.path().join("keys");
    let out = run(&keys, &["folder", "delete", "/Finance", "--yes"]);
    let err = stderr(&out);
    assert!(
        !err.contains("Re-run with --yes"),
        "--yes must open the guard, got: {err}"
    );
    assert!(
        !out.status.success(),
        "expected a downstream failure against the empty keystore / dead server"
    );
}

// ---- S121 (W6 parity): the pending-invitation verbs ----

#[test]
fn share_invitations_parses_path_and_json_flag() {
    let dir = TempDir::new().unwrap();
    let keys = dir.path().join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    let out = run(&keys, &["share", "invitations", "/Finance", "--json"]);
    assert_parsed_past_clap(&out, "share invitations with a path");
}

#[test]
fn share_cancel_invite_requires_and_accepts_invitation_id() {
    let dir = TempDir::new().unwrap();
    let keys = dir.path().join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    // Missing --invitation-id is a deterministic clap error naming the flag…
    let out = run(&keys, &["share", "cancel-invite", "/Finance"]);
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("--invitation-id"),
        "the missing required flag is named: {}",
        stderr(&out)
    );
    // …and the full shape parses past clap to the downstream failure.
    let out = run(
        &keys,
        &[
            "share",
            "cancel-invite",
            "/Finance",
            "--invitation-id",
            "3fa85f64-5717-4562-b3fc-2c963f66afa6",
        ],
    );
    assert_parsed_past_clap(&out, "share cancel-invite with an id");
}
