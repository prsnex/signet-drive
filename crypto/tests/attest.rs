// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Known-answer test for the §9 server-signed verification-response signing input
//! (`signet_crypto::attest`, test-vector Cat 06). Pins the domain-separation
//! prefix, the JCS-canonicalized `attestation` object (keys sorted), and the
//! `\n server_key_id \n signed_at` suffix — the exact bytes a third-party verifier
//! reconstructs and checks the server's ECDSA signature against.

use serde_json::{Value, json};
use signet_crypto::attest;

#[test]
fn verification_signing_input_pins_prefix_shape_and_suffix() {
    // Cat 06 TC06-01 shape (placeholder pubkey/fingerprint values).
    let attestation = json!({
        "attestation_id": "00000000-0000-4000-8000-000000000abc",
        "subject_account_id": "00000000-0000-4000-8000-00000000000a",
        "subject_handle": "hlin-ai",
        "subject_signing_pubkey": "Asig",
        "subject_signing_pubkey_fingerprint": "11",
        "subject_signing_alg": "ES256",
        "subject_kem_pubkey": "Akem",
        "subject_kem_pubkey_fingerprint": "22",
        "subject_kem_alg": "ECDH-ES+A256KW",
        "created_at": 1_700_000_060_i64,
        "expires_at": Value::Null,
        "status": "active",
        "revoked_at": Value::Null,
        "prsn_sharing_capability": "read_only",
        "key_protection": "software_se_sealed"
    });
    let server_key_id = "00000000-0000-4000-8000-0000000000aa";
    let signed_at = 1_700_000_100_i64;

    // JCS sorts the attestation keys; nulls are preserved as literal `null`.
    let expected_attestation_jcs = concat!(
        r#"{"attestation_id":"00000000-0000-4000-8000-000000000abc","#,
        r#""created_at":1700000060,"#,
        r#""expires_at":null,"#,
        r#""key_protection":"software_se_sealed","#,
        r#""prsn_sharing_capability":"read_only","#,
        r#""revoked_at":null,"#,
        r#""status":"active","#,
        r#""subject_account_id":"00000000-0000-4000-8000-00000000000a","#,
        r#""subject_handle":"hlin-ai","#,
        r#""subject_kem_alg":"ECDH-ES+A256KW","#,
        r#""subject_kem_pubkey":"Akem","#,
        r#""subject_kem_pubkey_fingerprint":"22","#,
        r#""subject_signing_alg":"ES256","#,
        r#""subject_signing_pubkey":"Asig","#,
        r#""subject_signing_pubkey_fingerprint":"11"}"#
    );
    let mut expected = Vec::from(&b"signet-server-attestation-verify-v1\n"[..]);
    expected.extend_from_slice(expected_attestation_jcs.as_bytes());
    expected.push(b'\n');
    expected.extend_from_slice(server_key_id.as_bytes());
    expected.push(b'\n');
    expected.extend_from_slice(b"1700000100");

    assert_eq!(
        attest::verification_signing_input(&attestation, server_key_id, signed_at).unwrap(),
        expected
    );
}

/// §11.5b (item 7b) — the per-request dual-sign constants, byte-pinned so no
/// implementer re-derives them: the FIPS 204 request context is the literal
/// `signet:req:v1` (distinct from every other purpose — §8 point 4 "contexts
/// MUST NOT be reused"), and the dual wire length is the fixed-width
/// 64 + 4627 = 4691 (spec §8 point 1 — raw ES256 r‖s ‖ ML-DSA-87, no framing).
/// The signing base each half signs is the SIGNET-V1 §6.2 canonical bytes,
/// already pinned by `signing.rs`'s own vectors (Cat 03) — identical bytes for
/// both halves, the ctx never prepended (§8.7).
#[test]
fn request_dual_sign_constants_are_pinned() {
    assert_eq!(attest::REQUEST_MLDSA_CTX, b"signet:req:v1");
    assert_eq!(attest::MLDSA87_SIG_LEN, 4627);
    assert_eq!(attest::REQUEST_DUAL_SIG_LEN, 4691);
    // The three active FIPS 204 signature-surface contexts are pairwise
    // distinct (requests / enrollment / server-response) — the domain
    // separation §8 point 4 requires.
    assert_ne!(attest::REQUEST_MLDSA_CTX, attest::ENROLL_POP_MLDSA_CTX);
    assert_ne!(attest::REQUEST_MLDSA_CTX, attest::SERVER_VERIFY_MLDSA_CTX);
    assert_ne!(
        attest::ENROLL_POP_MLDSA_CTX,
        attest::SERVER_VERIFY_MLDSA_CTX
    );
}
