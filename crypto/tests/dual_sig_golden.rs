// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! §11.5b — the dual-sig signing-base golden, M-byte half (PQR Crypto-Spec
//! §8.7: both halves sign the IDENTICAL bytes `M`; the FIPS 204 `ctx` is the
//! context *parameter*, never prepended).
//!
//! The golden (`docs/design/test-vectors/golden/dual-sig-signing-base.json`,
//! generated once by `cli/examples/gen_dual_sig_golden.rs`) commits, for all
//! four dual-sign surfaces, fixed example inputs AND the exact `M` bytes they
//! must produce. These tests rebuild each `M` through the SHIPPED builders and
//! byte-compare — so no implementer can diverge on *which bytes each half
//! signs* without a red gate. The ctx-string fields are pinned against the
//! shipped constants for the same reason. (The fixed-key verify vectors are
//! exercised server-side, where the AND-verifier lives:
//! `server/tests/dual_sig_golden.rs`.)

use serde_json::Value;
use signet_crypto::{attest, signing, translog};

const GOLDEN: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../docs/design/test-vectors/golden/dual-sig-signing-base.json"
));

fn golden() -> Value {
    serde_json::from_str(GOLDEN).expect("parse committed golden")
}

fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex field")).expect("valid hex")
}

#[test]
fn request_signing_base_matches_golden() {
    let golden = golden();
    let s = &golden["surfaces"]["request"];
    let m = signing::signet_v1_canonical_bytes(
        s["method"].as_str().unwrap(),
        s["path_and_query"].as_str().unwrap(),
        s["body_utf8"].as_str().unwrap().as_bytes(),
        s["timestamp"].as_str().unwrap(),
        s["nonce"].as_str().unwrap(),
        s["fingerprint"].as_str().unwrap(),
    );
    assert_eq!(m, hx(&s["m_hex"]), "SIGNET-V1 §6.2 canonical bytes");
    assert_eq!(
        s["ctx_utf8"].as_str().unwrap().as_bytes(),
        attest::REQUEST_MLDSA_CTX
    );
}

#[test]
fn enroll_pop_signing_base_matches_golden() {
    let golden = golden();
    let s = &golden["surfaces"]["enroll_pop"];
    let m = attest::enroll_pop_signing_base(&hx(&s["challenge_hex"]));
    assert_eq!(m, hx(&s["m_hex"]), "enroll-PoP signing base");
    assert_eq!(
        s["ctx_utf8"].as_str().unwrap().as_bytes(),
        attest::ENROLL_POP_MLDSA_CTX
    );
}

#[test]
fn server_verification_signing_base_matches_golden() {
    let golden = golden();
    let s = &golden["surfaces"]["server_verification"];
    let m = attest::verification_signing_input(
        &s["attestation"],
        s["server_key_id"].as_str().unwrap(),
        s["signed_at"].as_i64().unwrap(),
    )
    .expect("verification signing input");
    assert_eq!(
        m,
        hx(&s["m_hex"]),
        "§9 verification-response signing base (hybrid attestation shape)"
    );
    assert_eq!(
        s["ctx_utf8"].as_str().unwrap().as_bytes(),
        attest::SERVER_VERIFY_MLDSA_CTX
    );
}

#[test]
fn log_receipt_signing_base_matches_golden() {
    let golden = golden();
    let s = &golden["surfaces"]["log_receipt"];
    let m = translog::receipt_signing_input(&s["receipt"]).expect("receipt signing input");
    assert_eq!(m, hx(&s["m_hex"]), "§10a receipt signing base");
    assert_eq!(
        s["ctx_utf8"].as_str().unwrap().as_bytes(),
        translog::RECEIPT_MLDSA_CTX
    );
}

/// §8 point 4: the four surface contexts in the golden are pairwise distinct —
/// the domain-separation property, asserted over the COMMITTED values (the
/// code-constant version of this pin lives in `attest.rs`'s constants KAT).
#[test]
fn golden_ctx_strings_are_pairwise_distinct() {
    let golden = golden();
    let surfaces = golden["surfaces"].as_object().expect("surfaces object");
    let ctxs: Vec<&str> = surfaces
        .values()
        .map(|s| s["ctx_utf8"].as_str().expect("ctx_utf8"))
        .collect();
    assert_eq!(ctxs.len(), 4, "all four dual-sign surfaces present");
    for (i, a) in ctxs.iter().enumerate() {
        for b in ctxs.iter().skip(i + 1) {
            assert_ne!(a, b, "contexts must never be reused across purposes");
        }
    }
}
