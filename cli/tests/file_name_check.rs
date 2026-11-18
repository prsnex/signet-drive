// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! bug283: `signet file rename` and `signet file move` check the folder for a file of the
//! same name before they change anything, through `GET /v1/files/{id}` (new in 1.2.1).
//! These drive the built binary against a stub that answers that read with a 405, as a
//! 1.2.0 server does in the minutes between CLI 1.2.1's publish and the server's deploy
//! (Gus's condition 2): the command must refuse with a clear line and send nothing that
//! changes state. The name checks themselves are unit-tested (`names::collides`, the
//! repair path in `commands`), and the live check is the release's (condition 3).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex};

use tempfile::TempDir;

const HANDLE: &str = "tester-ai";

/// A stub server: `GET /v1/files/*` → 405, anything else → 404. Records each request
/// line so a test can assert nothing state-changing was sent.
fn start_stub() -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 8192];
            let n = stream.read(&mut buf).unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]);
            let line = head.lines().next().unwrap_or_default().to_string();
            log.lock().unwrap().push(line.clone());
            let status = if line.starts_with("GET /v1/files/") {
                "405 Method Not Allowed"
            } else {
                "404 Not Found"
            };
            let resp =
                format!("HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
        }
    });
    (port, seen)
}

fn signet(tmp: &TempDir, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_signet"))
        .env("SIGNET_KEY_TIER", "software")
        .env("SIGNET_KEYS_DIR", tmp.path().join("keys"))
        .env("SIGNET_CONFIG", tmp.path().join("absent.toml"))
        .env("SIGNET_HANDLE", HANDLE)
        .args(args)
        .output()
        .expect("spawn signet")
}

fn with_keys() -> TempDir {
    let tmp = TempDir::new().unwrap();
    for (flag, purpose) in [("--signing", "signing"), ("--kem", "kem")] {
        let label = format!("{HANDLE}-{purpose}");
        let out = signet(&tmp, &["keygen", flag, "--label", &label]);
        assert!(
            out.status.success(),
            "keygen {label}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    tmp
}

fn assert_refused_unchanged(out: &Output, seen: &Mutex<Vec<String>>) {
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(31),
        "exit 31, retry later; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("does not offer the file lookup") && stderr.contains("Nothing was changed"),
        "a clear line: {stderr}"
    );
    let seen = seen.lock().unwrap();
    assert!(
        seen.iter().all(|l| l.starts_with("GET ")),
        "nothing but reads reached the server: {seen:?}"
    );
    assert!(
        seen.iter().any(|l| l.starts_with("GET /v1/files/")),
        "the lookup was tried: {seen:?}"
    );
}

#[test]
fn rename_against_a_server_without_the_lookup_refuses_and_changes_nothing() {
    let tmp = with_keys();
    let (port, seen) = start_stub();
    let server = format!("http://127.0.0.1:{port}");
    let (file, root) = (
        uuid::Uuid::new_v4().to_string(),
        uuid::Uuid::new_v4().to_string(),
    );
    let out = signet(
        &tmp,
        &[
            "--server-url",
            &server,
            "file",
            "rename",
            "--file-id",
            &file,
            "--root-folder-id",
            &root,
            "--name",
            "new.txt",
        ],
    );
    assert_refused_unchanged(&out, &seen);
}

#[test]
fn move_against_a_server_without_the_lookup_refuses_and_changes_nothing() {
    let tmp = with_keys();
    let (port, seen) = start_stub();
    let server = format!("http://127.0.0.1:{port}");
    let (file, dest) = (
        uuid::Uuid::new_v4().to_string(),
        uuid::Uuid::new_v4().to_string(),
    );
    let out = signet(
        &tmp,
        &[
            "--server-url",
            &server,
            "file",
            "move",
            "--file-id",
            &file,
            "--to-folder-id",
            &dest,
        ],
    );
    assert_refused_unchanged(&out, &seen);
}
