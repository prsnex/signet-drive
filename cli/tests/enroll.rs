// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! `signet enroll [code]` orchestration tests (S052 Inc 2; S063 human-initiated; S076
//! Kit-retirement + idempotency), driving the built binary against a tiny in-process
//! **mock** of the agent-side enrollment endpoints (`join` / `status` / `keys`). This
//! exercises the agent-side state machine — the human hands over the code, the agent
//! joins (claims its submit_token), polls to `confirmed`, keygen (software tier in
//! tests) + submit, polls to `completed`, writes the optional hidden config (the Kit is
//! retired, S076) — plus the **idempotent no-op** when already enrolled, the never-guess
//! refusal when neither a code nor an identity is given, and the orphaned-key cleanup on
//! a post-keygen failure, without a live server or real Secure Enclave. (The real-server
//! + real-SE path is the partnered live test.)

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

use serde_json::Value;
use tempfile::TempDir;

/// What the mock reports: the status before keys are submitted, and after.
#[derive(Clone, Copy)]
struct MockScript {
    /// before `submit-keys` (the agent waits for `confirmed`).
    confirm_status: &'static str,
    /// after `submit-keys` (the agent waits for `completed`).
    complete_status: &'static str,
}

const HANDLE: &str = "tester-ai";
const ATTESTATION_ID: &str = "11111111-1111-4111-8111-111111111111";

/// Spawn the mock server on an ephemeral port; return the port. The thread is
/// detached (it dies with the test process).
fn start_mock(script: MockScript) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock");
    let port = listener.local_addr().unwrap().port();
    let submitted = Arc::new(Mutex::new(false));
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let (method, path, body) = read_request(&mut stream);
            let (status_line, body) = route(&script, &submitted, &method, &path, &body);
            let resp = format!(
                "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
        }
    });
    port
}

fn route(
    script: &MockScript,
    submitted: &Mutex<bool>,
    method: &str,
    path: &str,
    body: &str,
) -> (&'static str, String) {
    match (method, path) {
        ("POST", "/v1/prsn-enrollments/join") => (
            "200 OK",
            r#"{"submit_token":"testsubmittoken"}"#.to_string(),
        ),
        ("POST", "/v1/prsn-enrollments/keys") => {
            // The PoP begin (item 7a): wrap a real nonce to the SUBMITTED hybrid
            // KEM pair — through the CLI's own writer — so the binary's keystore
            // unwrap (the hybrid self-test) genuinely exercises end-to-end.
            let parsed: Value = match serde_json::from_str(body) {
                Ok(v) => v,
                Err(_) => return ("400 Bad Request", r#"{"error":"bad json"}"#.to_string()),
            };
            use base64::Engine;
            let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let rk_ec = b64
                .decode(parsed["subject_kem_pubkey"].as_str().unwrap_or_default())
                .unwrap_or_default();
            let rk_pq = b64
                .decode(parsed["subject_kem_pq_pubkey"].as_str().unwrap_or_default())
                .unwrap_or_default();
            let nonce = [0x5Au8; 32];
            let envelope = match signet_cli::hybrid::wrap_key_hybrid(&rk_ec, &rk_pq, &nonce, &[]) {
                Ok(env) => env,
                Err(_) => {
                    return (
                        "400 Bad Request",
                        r#"{"error":"submitted KEM keys do not wrap"}"#.to_string(),
                    );
                }
            };
            let challenge = b64.encode([0xC7u8; 32]);
            (
                "200 OK",
                format!(
                    r#"{{"pop_challenge":"{challenge}","pop_nonce_envelope":{}}}"#,
                    serde_json::to_string(&envelope).unwrap()
                ),
            )
        }
        ("POST", "/v1/prsn-enrollments/keys/pop") => {
            // The mock accepts any well-formed PoP (the server-side verification
            // is covered by the server integration tests); reaching this leg at
            // all means the binary dual-signed AND unwrapped the nonce.
            let parsed: Value = match serde_json::from_str(body) {
                Ok(v) => v,
                Err(_) => return ("400 Bad Request", r#"{"error":"bad json"}"#.to_string()),
            };
            for field in ["pop_signature_es256", "pop_signature_mldsa87", "pop_nonce"] {
                if !parsed[field].is_string() {
                    return (
                        "400 Bad Request",
                        format!(r#"{{"error":"missing {field}"}}"#),
                    );
                }
            }
            *submitted.lock().unwrap() = true;
            ("204 No Content", String::new())
        }
        ("GET", p) if p.starts_with("/v1/prsn-enrollments/status") => {
            let done = *submitted.lock().unwrap();
            let status = if done {
                script.complete_status
            } else {
                script.confirm_status
            };
            let handle = if status == "confirmed" {
                format!(r#","handle":"{HANDLE}""#)
            } else {
                String::new()
            };
            let attestation = if status == "completed" {
                format!(r#","handle":"{HANDLE}","attestation_id":"{ATTESTATION_ID}""#)
            } else {
                String::new()
            };
            (
                "200 OK",
                format!(r#"{{"status":"{status}"{handle}{attestation}}}"#),
            )
        }
        _ => (
            "404 Not Found",
            r#"{"error":"unexpected mock path"}"#.to_string(),
        ),
    }
}

/// Read one HTTP request; return (method, path, body). Drains the body so the
/// client's write completes cleanly.
fn read_request(stream: &mut TcpStream) -> (String, String, String) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    loop {
        let n = stream.read(&mut tmp).unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = window_pos(&buf, b"\r\n\r\n") {
            let content_length = content_length(&buf[..pos]);
            if buf.len() - (pos + 4) >= content_length {
                break;
            }
        }
    }
    let text = String::from_utf8_lossy(&buf);
    let mut parts = text.lines().next().unwrap_or("").split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let body = window_pos(&buf, b"\r\n\r\n")
        .map(|pos| String::from_utf8_lossy(&buf[pos + 4..]).to_string())
        .unwrap_or_default();
    (method, path, body)
}

fn window_pos(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn content_length(headers: &[u8]) -> usize {
    String::from_utf8_lossy(headers)
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim()
                .eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0)
}

/// Run `signet --server-url <mock> enroll <extra args>` with the software keystore.
fn run_enroll(tmp: &TempDir, port: u16, extra: &[&str]) -> Output {
    let keys = tmp.path().join("keys");
    let server = format!("http://127.0.0.1:{port}");
    let mut args = vec!["--server-url", &server, "enroll"];
    args.extend_from_slice(extra);
    Command::new(env!("CARGO_BIN_EXE_signet"))
        .env("SIGNET_KEY_TIER", "software")
        .env("SIGNET_KEYS_DIR", &keys)
        .env("SIGNET_CONFIG", tmp.path().join("absent.toml"))
        .env("SIGNET_ENROLL_POLL_MS", "20")
        .args(&args)
        .output()
        .expect("spawn signet enroll")
}

fn happy() -> MockScript {
    MockScript {
        confirm_status: "confirmed",
        complete_status: "completed",
    }
}

/// Like [`run_enroll`], but with `SIGNET_HANDLE` set — the harness-injected identity the
/// idempotency fast-path uses to answer "which PRSN am I" without a code.
fn run_enroll_with_handle(tmp: &TempDir, port: u16, handle: &str, extra: &[&str]) -> Output {
    let keys = tmp.path().join("keys");
    let server = format!("http://127.0.0.1:{port}");
    let mut args = vec!["--server-url", &server, "enroll"];
    args.extend_from_slice(extra);
    Command::new(env!("CARGO_BIN_EXE_signet"))
        .env("SIGNET_KEY_TIER", "software")
        .env("SIGNET_KEYS_DIR", &keys)
        .env("SIGNET_CONFIG", tmp.path().join("absent.toml"))
        .env("SIGNET_ENROLL_POLL_MS", "20")
        .env("SIGNET_HANDLE", handle)
        .args(&args)
        .output()
        .expect("spawn signet enroll")
}

#[test]
fn enroll_happy_path_writes_the_hidden_config() {
    let tmp = TempDir::new().unwrap();
    let port = start_mock(happy());

    // The Kit is retired (S076): no --kit-dir, no visible folder.
    let out = run_enroll(&tmp, port, &["testcode"]);
    assert!(
        out.status.success(),
        "enroll should succeed; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // stdout is the machine-readable result — no kit_path, not a no-op.
    let result: Value = serde_json::from_slice(&out.stdout).expect("stdout is JSON");
    assert_eq!(result["handle"], HANDLE);
    assert_eq!(result["attestation_id"], ATTESTATION_ID);
    assert_eq!(result["key_protection"], "software"); // the test tier
    assert_eq!(result["already_enrolled"], false);
    assert!(
        result.get("kit_path").is_none(),
        "the Kit is retired — there is no kit_path"
    );

    // The only artifact is the hidden config default (at $SIGNET_CONFIG), carrying the
    // PRSN's default key labels — no SIGDRIVE-MANUAL.md / keys.pub / container folder.
    let config_path = tmp.path().join("absent.toml");
    assert_eq!(result["config_path"], config_path.to_str().unwrap());
    let config = std::fs::read_to_string(&config_path).unwrap();
    assert!(config.contains(&format!("default_signing_key = \"{HANDLE}-signing\"")));
    assert!(config.contains(&format!("default_kem_key = \"{HANDLE}-kem\"")));
}

#[test]
fn enroll_is_idempotent_when_already_enrolled() {
    let tmp = TempDir::new().unwrap();
    let port = start_mock(happy());

    // First enroll (with a code) generates the keys.
    let first = run_enroll(&tmp, port, &["testcode"]);
    assert!(
        first.status.success(),
        "first enroll should succeed; stderr:\n{}",
        String::from_utf8_lossy(&first.stderr)
    );

    // Re-run with SIGNET_HANDLE and NO code → a success no-op (the every-wake routine,
    // Zain F6): identity comes from the handle, the keys already exist, nothing to do.
    let again = run_enroll_with_handle(&tmp, port, HANDLE, &[]);
    assert!(
        again.status.success(),
        "idempotent re-enroll should succeed; stderr:\n{}",
        String::from_utf8_lossy(&again.stderr)
    );
    let result: Value = serde_json::from_slice(&again.stdout).expect("stdout is JSON");
    assert_eq!(result["handle"], HANDLE);
    assert_eq!(result["already_enrolled"], true);
}

#[test]
fn no_code_and_not_enrolled_is_an_actionable_error() {
    let tmp = TempDir::new().unwrap();
    let port = start_mock(happy());

    // No code, not enrolled, no SIGNET_HANDLE → a clear refusal (never a silent attempt).
    let out = run_enroll(&tmp, port, &[]);
    assert!(
        !out.status.success(),
        "enroll with no code while not enrolled must fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr).to_lowercase();
    assert!(
        stderr.contains("code"),
        "the error should point at the missing enrollment code:\n{stderr}"
    );
}

#[test]
fn expired_before_confirm_aborts_with_no_keys() {
    let tmp = TempDir::new().unwrap();
    let port = start_mock(MockScript {
        confirm_status: "expired",
        complete_status: "completed",
    });

    let out = run_enroll(&tmp, port, &["testcode"]);
    assert!(!out.status.success(), "an expired enrollment must fail");
    assert!(
        !has_handle_keys(&tmp),
        "no keys should exist (keygen never ran)"
    );
}

#[test]
fn failure_after_keygen_cleans_up_the_keys() {
    let tmp = TempDir::new().unwrap();
    // confirmed → keygen + submit → then the attestation poll reports `failed`.
    let port = start_mock(MockScript {
        confirm_status: "confirmed",
        complete_status: "failed",
    });

    let out = run_enroll(&tmp, port, &["testcode"]);
    assert!(!out.status.success(), "a failed enrollment must fail");
    assert!(
        !has_handle_keys(&tmp),
        "the keys generated before the failure must be cleaned up"
    );
}

/// Does the software keystore dir hold any key files for our test handle?
fn has_handle_keys(tmp: &TempDir) -> bool {
    let keys = tmp.path().join("keys");
    let Ok(entries) = std::fs::read_dir(&keys) else {
        return false;
    };
    entries
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().contains(HANDLE))
}
