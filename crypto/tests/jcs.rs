// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Known-answer tests for JCS canonicalization (`signet_crypto::jcs`, RFC 8785).
//!
//! The expected canonical strings are hand-verifiable against RFC 8785: object
//! keys sorted, all insignificant whitespace removed, arrays left in order,
//! integers minimal, the required short string-escapes, `/` left unescaped. These
//! exercise SigDrive's actual input domain (ASCII keys; i64/u64 numbers; string /
//! null / bool values; nesting). The pinned strings double as drift guards — a
//! `serde_jcs` upgrade that changes the bytes a signature is computed over fails
//! here, loudly, rather than as a silent interop break with third-party verifiers.

use serde_json::{Value, json};
use signet_crypto::{hash, jcs};

fn canon(value: &Value) -> String {
    String::from_utf8(jcs::to_canonical_bytes(value).expect("canonicalize")).expect("utf-8")
}

#[test]
fn object_keys_are_sorted() {
    assert_eq!(
        canon(&json!({"b": 1, "a": 2, "c": 3})),
        r#"{"a":2,"b":1,"c":3}"#
    );
}

#[test]
fn insignificant_whitespace_is_removed() {
    let parsed: Value = serde_json::from_str("{ \"a\" : 1 , \"b\" : [ 1 , 2 ] }").unwrap();
    assert_eq!(canon(&parsed), r#"{"a":1,"b":[1,2]}"#);
}

#[test]
fn nested_objects_sort_but_arrays_keep_order() {
    let v = json!({ "z": { "y": 1, "x": 2 }, "a": [3, 1, 2] });
    assert_eq!(canon(&v), r#"{"a":[3,1,2],"z":{"x":2,"y":1}}"#);
}

#[test]
fn integers_are_minimal() {
    // unix-seconds magnitude, a negative, and zero — sorted keys n, t, zero.
    let v = json!({ "t": 1716595200_i64, "n": -5_i64, "zero": 0_i64 });
    assert_eq!(canon(&v), r#"{"n":-5,"t":1716595200,"zero":0}"#);
}

#[test]
fn strings_use_required_escapes_and_leave_solidus_raw() {
    // Quote + backslash get the short escapes; `/` is NOT escaped (RFC 8785).
    assert_eq!(canon(&json!({ "s": "a\"b\\c" })), r#"{"s":"a\"b\\c"}"#);
    assert_eq!(canon(&json!({ "u": "a/b" })), r#"{"u":"a/b"}"#);
    // Control chars use the short forms where defined (newline -> \n).
    assert_eq!(canon(&json!({ "s": "x\ny" })), r#"{"s":"x\ny"}"#);
}

#[test]
fn null_and_bool_pass_through_sorted() {
    let v = json!({ "c": false, "a": null, "b": true });
    assert_eq!(canon(&v), r#"{"a":null,"b":true,"c":false}"#);
}

#[test]
fn float_uses_ecmascript_formatting() {
    // SigDrive signs no floats, but confirm ryu_js is wired (defensive).
    assert_eq!(canon(&json!({ "x": 1.5 })), r#"{"x":1.5}"#);
}

#[test]
fn sigdrive_challenge_context_canonicalizes_as_expected() {
    // The Envelope §6.1 operation-bound challenge context (shape, not real keys).
    let ctx = json!({
        "operation": "issue_attestation",
        "ceremony_id": "00000000-0000-0000-0000-000000000001",
        "operation_parameters": {
            "subject_account_id": "acct",
            "subject_signing_pubkey_fingerprint": "aa",
            "subject_kem_pubkey_fingerprint": "bb",
            "key_protection": "software",
            "expires_at": Value::Null
        },
        "issued_at": 1716595200_i64
    });

    // Top-level keys sort to ceremony_id, issued_at, operation, operation_parameters;
    // the inner object's keys sort to expires_at, key_protection, subject_account_id,
    // subject_kem_pubkey_fingerprint, subject_signing_pubkey_fingerprint.
    let expected = concat!(
        r#"{"ceremony_id":"00000000-0000-0000-0000-000000000001","#,
        r#""issued_at":1716595200,"#,
        r#""operation":"issue_attestation","#,
        r#""operation_parameters":{"#,
        r#""expires_at":null,"#,
        r#""key_protection":"software","#,
        r#""subject_account_id":"acct","#,
        r#""subject_kem_pubkey_fingerprint":"bb","#,
        r#""subject_signing_pubkey_fingerprint":"aa"}}"#
    );
    assert_eq!(canon(&ctx), expected);

    // digest() is SHA-256 over exactly those canonical bytes (the challenge value).
    assert_eq!(
        jcs::digest(&ctx).expect("digest"),
        hash::sha256(expected.as_bytes()),
    );
}

#[test]
fn out_of_domain_keys_are_refused_not_canonicalized() {
    // The S112 corpus finding: serde_jcs orders keys by their ESCAPED form,
    // which diverges from RFC 8785 for any key containing an escape-class
    // character. Both chokepoints now REFUSE such keys (jcs.ts asserts the
    // same) — the divergent input is unrepresentable, never signed over.
    assert!(jcs::to_canonical_bytes(&json!({ "a\tb": 1 })).is_err());
    assert!(jcs::to_canonical_bytes(&json!({ "a\"b": 1 })).is_err());
    assert!(jcs::to_canonical_bytes(&json!({ "a\\b": 1 })).is_err());
    assert!(jcs::to_canonical_bytes(&json!({ "clé": 1 })).is_err());
    // Nested objects are walked too — a hazard key can't hide one level down.
    assert!(jcs::to_canonical_bytes(&json!({ "ok": { "a\u{1f}b": 1 } })).is_err());
    // The plain-ASCII range itself stays fully accepted.
    assert!(jcs::to_canonical_bytes(&json!({ "a zZ0_~/.-:!@`{|}": 1 })).is_ok());
}

#[test]
fn canonicalization_is_deterministic() {
    let v = json!({ "b": [1, 2, 3], "a": { "d": 4, "c": 3 } });
    assert_eq!(
        jcs::to_canonical_bytes(&v).unwrap(),
        jcs::to_canonical_bytes(&v).unwrap()
    );
}

#[test]
fn cross_impl_golden_reasserts() {
    // The committed JCS cross-impl golden (generated by
    // crypto/examples/gen_jcs_golden.rs) — the byte anchor shared with the web
    // port (`web/src/lib/crypto/jcs.ts`, an independent implementation over
    // ECMAScript JSON.stringify primitives). Both sides assert byte-identical
    // canonicalization for every case, so neither lineage can drift from the
    // committed truth the F-DOWNGRADE(b) web verification path signs against.
    let golden: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../docs/design/test-vectors/golden/jcs-cross-impl.json"
    )))
    .expect("golden parses");
    let cases = golden["cases"].as_array().expect("cases array");
    assert!(
        cases.len() >= 72,
        "the golden must keep its full case set (8 named + the 64-case corpus)"
    );
    for case in cases {
        let name = case["name"].as_str().expect("name");
        let expected = case["canonical"].as_str().expect("canonical");
        assert_eq!(
            canon(&case["input"]),
            expected,
            "case '{name}' must canonicalize byte-identically"
        );
        assert_eq!(
            hex::encode(hash::sha256(expected.as_bytes())),
            case["canonical_sha256"].as_str().expect("sha"),
            "case '{name}' committed digest must match its committed bytes"
        );
    }
}

#[test]
fn asymmetry_direction_is_pinned() {
    // The committed asymmetry pairs (D2 increment review): inputs OUTSIDE the
    // web port's documented domain. The Rust side (full serde_jcs) formats
    // them; the web side THROWS (asserted in jcs.test.ts against the same
    // committed entries). Pinning both directions records fail-closed as
    // intent, not accident.
    let golden: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../docs/design/test-vectors/golden/jcs-cross-impl.json"
    )))
    .expect("golden parses");
    let cases = golden["asymmetry_cases"]
        .as_array()
        .expect("asymmetry array");
    assert!(
        cases.len() >= 4,
        "the asymmetry set must keep its full pairs"
    );
    for case in cases {
        let name = case["name"].as_str().expect("name");
        assert_eq!(
            canon(&case["input"]),
            case["rust_canonical"].as_str().expect("rust_canonical"),
            "asymmetry case '{name}': the Rust lineage must format this input"
        );
    }
}
