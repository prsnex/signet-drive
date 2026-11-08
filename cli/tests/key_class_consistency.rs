// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Every Secure Enclave key this client makes carries one class (v1.2.0, Chris 2026-11-07):
//! the P-256 keys and the PQ keys' sealed-blob items through `access_control()` in
//! `src/keystore/secure_enclave.rs`, and the PQ keys themselves through the Swift shim's
//! `suiteAccessControl()`. If the two ever differed, a locked Mac would answer one half of
//! a hybrid and refuse the other: a hybrid that silently stops being one (Gus). The SE
//! module compiles only on macOS, so this reads both sources as text, which runs on every
//! platform the suite runs on, Linux CI included.

use std::path::Path;

/// The class both sources must name, in Rust's spelling and in Swift's.
const RUST_CLASS: &str = "ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly";
const SWIFT_CLASS: &str = "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly";

fn source(rel: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// The body of the first function named `name`: from its signature to the next line that
/// closes a top-level item. Enough for these two short functions, and it fails loudly when
/// the function is gone.
fn fn_body<'a>(src: &'a str, signature: &str) -> &'a str {
    let start = src
        .find(signature)
        .unwrap_or_else(|| panic!("`{signature}` not found: the class guard lost its subject"));
    let rest = &src[start..];
    let end = rest.find("\n}").map_or(rest.len(), |i| i + 2);
    &rest[..end]
}

/// Lines that are code, not comments, so a class named in prose cannot satisfy the guard.
fn code_lines(body: &str) -> Vec<&str> {
    body.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("//"))
        .collect()
}

#[test]
fn the_rust_and_swift_key_classes_are_the_same_class() {
    let rust = source("src/keystore/secure_enclave.rs");
    let swift = source("shim/SignetSeShim.swift");

    let rust_ac = code_lines(fn_body(&rust, "fn access_control()"));
    let swift_ac = code_lines(fn_body(&swift, "private func suiteAccessControl()"));

    assert!(
        rust_ac.iter().any(|l| l.contains(RUST_CLASS)),
        "access_control() does not set {RUST_CLASS}: {rust_ac:#?}"
    );
    assert!(
        swift_ac.iter().any(|l| l.contains(SWIFT_CLASS)),
        "suiteAccessControl() does not set {SWIFT_CLASS}: {swift_ac:#?}"
    );
    // Neither still names the class v1.2.0 left, in code.
    for (what, lines) in [
        ("access_control()", &rust_ac),
        ("suiteAccessControl()", &swift_ac),
    ] {
        assert!(
            !lines.iter().any(|l| l.contains("WhenUnlocked")),
            "{what} still names a WhenUnlocked class in code: {lines:#?}"
        );
    }
}

#[test]
fn the_pq_blob_items_take_the_shared_class() {
    // The sealed-blob items must carry `access_control()`'s class, or they take the
    // data-protection keychain's default (`WhenUnlocked`) and a locked Mac refuses the PQ
    // half of a hybrid while the classical half answers.
    let rust = source("src/keystore/secure_enclave.rs");
    let store = code_lines(fn_body(&rust, "fn pq_blob_store("));
    assert!(
        store.iter().any(|l| l.contains("access_control()")),
        "pq_blob_store does not build its access control from access_control(): {store:#?}"
    );
    assert!(
        store.iter().any(|l| l.contains("kSecAttrAccessControl")),
        "pq_blob_store does not set kSecAttrAccessControl on the item: {store:#?}"
    );
    assert!(
        !store
            .iter()
            .any(|l| l.contains("set_generic_password_options")),
        "pq_blob_store must not use the crate's create-or-update add: {store:#?}"
    );
}
