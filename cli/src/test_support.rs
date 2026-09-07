// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Shared fixtures for the degrade tests (S163). `#[cfg(test)]` only — never compiled
//! into a shipped binary.
//!
//! **Why a shared module rather than per-file helpers.** The degrade-on-a-bad-row property
//! is implemented at THREE homes (`resolve_entry_name`, `list_files`'s inline pair, and
//! `share_list`'s inline match) across two source files. Duplicating the scaffolding per
//! file would make the tests differ in their setup as well as in the condition under test,
//! which is precisely the shape that lets one surface's guard drift from its sibling's —
//! the same §3.5 hazard the tests exist to catch. One home here; the tests differ only in
//! what they poison.
//!
//! ⚠ **SCOPE OF WHAT THESE FIXTURES PROVE (Gus, S163 review).** Tests that pre-seed the
//! resolver's `metadata_keys` cache deliberately bypass the real ML-KEM unwrap by planting a
//! known metadata key. They therefore prove the **degrade** property ONLY
//! — that a row which cannot be read degrades instead of killing the listing. They are
//! **NOT** evidence that the unwrap path works, and must never be cited as such.
//!
//! That split is legitimate here because the two properties have two different witnesses:
//! the degrade property's witness is CI (correctly, since the only malformed row in
//! existence is being deleted and bug132(i) forecloses making another), while the
//! real-unwrap property's witness is **production itself** — every honest `folder list`
//! exercises the full unwrap continuously, and a rotted unwrap is maximally LOUD (every
//! listing fails at once). bug140's shape requires rot to be *silent* under a green suite;
//! an unwrap that breaks here cannot be silent.

use crate::keystore::{KeyLabel, Keystore, Purpose, SoftwareKeystore};

/// A loopback JSON server: any request whose head mentions `metadata-key-wrap` gets `wrap`,
/// everything else gets `listing`. Returns the port. Serves until the test process ends.
pub(crate) fn spawn_json_server(listing: String, wrap: String) -> u16 {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let Ok(mut sock) = conn else { break };
            let mut buf = [0u8; 4096];
            let n = sock.read(&mut buf).unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            let body = if head.contains("metadata-key-wrap") {
                &wrap
            } else {
                &listing
            };
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

/// The handle these fixtures act as.
///
/// ⚠ **Derived from the AMBIENT `SIGNET_HANDLE` when one is set, not hardcoded.** Any test
/// that reaches `commands::resolve_label` is checked against `SIGNET_HANDLE`, and a
/// hardcoded handle would raise `identity_mismatch` for any developer who happens to have
/// one exported — a test that fails on ambient environment rather than on the property it
/// guards. Deriving it makes the fixture agree with whatever identity is asserted, so the
/// test is deterministic under any environment. Mutating the env instead was rejected: it
/// is process-global, and only `nextest` gives us process-per-test.
pub(crate) fn test_handle() -> String {
    std::env::var("SIGNET_HANDLE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "degrade-test-ai".to_string())
}

/// A software keystore with real signing + KEM keys — enough for `get_json_signed` to
/// produce a signature. The test server does not verify it; what matters is that the
/// request travels the REAL signed-call path rather than a bypass.
pub(crate) fn test_keystore() -> (tempfile::TempDir, SoftwareKeystore, KeyLabel, KeyLabel) {
    let dir = tempfile::TempDir::new().unwrap();
    let ks = SoftwareKeystore::open(dir.path().to_path_buf()).unwrap();
    let handle = test_handle();
    let signing = KeyLabel::from_handle(&handle, Purpose::Signing).expect("fixture: signing label");
    let kem = KeyLabel::from_handle(&handle, Purpose::Kem).expect("fixture: kem label");
    ks.generate(&signing, "ES256")
        .expect("fixture: signing key");
    ks.generate(&kem, "ECDH-ES+A256KW")
        .expect("fixture: kem key");
    (dir, ks, signing, kem)
}

/// A wrap the client cannot unwrap — the `unknown wrap alg` condition the legacy
/// `a2ddad8b` folder carried, and the exact error the pre-bug139 code aborted whole
/// listings with (`CliError { exit_code: 24, invalid_data, "unknown wrap alg" }`).
pub(crate) fn junk_wrap_body() -> String {
    serde_json::json!({ "wrapped_key": { "alg": "not-a-real-wrap-alg", "v": 1 } }).to_string()
}
