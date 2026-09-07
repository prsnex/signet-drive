// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Generate the §11.5b dual-sig signing-base golden (run once, output
//! committed):
//!
//! ```text
//! cargo run -p signet-cli --example gen_dual_sig_golden
//! # → docs/design/test-vectors/golden/dual-sig-signing-base.json
//! ```
//!
//! The golden pins, for all four dual-sign surfaces (PQR Crypto-Spec §8.7 /
//! §11.5b), the exact message bytes `M` both halves sign and the per-purpose
//! FIPS 204 `ctx`, from fixed example inputs — plus fixed-key verify vectors
//! (request + server-verification surfaces) that the shipped AND-verifier
//! must accept. Hedged signatures cannot be byte-pinned; the committed
//! signatures are generated in DETERMINISTIC mode purely so this generator
//! reproduces byte-identically (production signing is hedged — spec §8
//! point 3; verification is mode-agnostic, so the vector exercises the same
//! verify path either way).
//!
//! **Lineage:** the ML-DSA-87 signatures and verifying key are produced by
//! OpenSSL (3.5+ implements ML-DSA natively) from the same 32-byte ξ seed and
//! cross-checked against the shipped RustCrypto `ml-dsa` at generation time —
//! an independent-lineage vector in the KeyCombine-KAT tradition. If OpenSSL
//! lacks ML-DSA the generator falls back to RustCrypto signing and records
//! the lineage in `_provenance`. The ES256 half is the shipped signer
//! (RFC 6979 deterministic; its OpenSSL cross-impl already lives in
//! `crypto/tests/differential.rs`).
//!
//! Everything here is a VECTOR key — fixed, public, never used for anything
//! but these tests (the same posture as every committed golden's `d`/JWK).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ml_dsa::{MlDsa87, Seed, SigningKey};
use serde_json::{Value, json};
use std::process::Command;

use signet_crypto::{attest, ecdsa, hybrid_wrap, pubkey, signing, translog};

/// Fixed vector-key material (arbitrary, committed, audit-friendly patterns).
const ES256_SCALAR: [u8; 32] = [0x40; 32]; // valid P-256 scalar (< n)
const MLDSA_SEED: [u8; 32] = [0x51; 32]; // FIPS 204 ξ
const KEM_EC_SCALAR: [u8; 32] = [0x42; 32]; // attestation KEM fixture (classical half)
const KEM_PQ_D: [u8; 32] = [0x43; 32]; // attestation KEM fixture (ML-KEM d)
const KEM_PQ_Z: [u8; 32] = [0x44; 32]; // attestation KEM fixture (ML-KEM z)
const ENROLL_CHALLENGE: [u8; 32] = [0x77; 32];

fn ec_pubkey_x963(scalar: &[u8; 32]) -> Vec<u8> {
    let sk = p256::SecretKey::from_bytes(scalar.into()).expect("valid fixed scalar");
    sk.public_key().to_sec1_bytes().to_vec()
}

fn mlkem_ek(d: &[u8; 32], z: &[u8; 32]) -> Vec<u8> {
    use ml_kem::{B32, EncodedSizeUser, KemCore, MlKem1024};
    let (_dk, ek) = MlKem1024::generate_deterministic(
        &B32::try_from(&d[..]).unwrap(),
        &B32::try_from(&z[..]).unwrap(),
    );
    ek.as_bytes().to_vec()
}

/// Sign `m` with OpenSSL ML-DSA-87 (deterministic mode, FIPS 204 external
/// interface with `ctx`) from the fixed ξ seed. Returns (vk_raw, signature)
/// or None if the local OpenSSL cannot (no ML-DSA / unknown options).
fn openssl_mldsa_sign(m: &[u8], ctx: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let dir = std::env::temp_dir().join("signet-dual-sig-golden-gen");
    std::fs::create_dir_all(&dir).ok()?;
    let key = dir.join("mldsa87.pem");
    let m_path = dir.join("m.bin");
    let sig_path = dir.join("sig.bin");
    std::fs::write(&m_path, m).ok()?;

    let keygen_out = Command::new("openssl")
        .args([
            "genpkey",
            "-algorithm",
            "ML-DSA-87",
            "-pkeyopt",
            &format!("hexseed:{}", hex::encode(MLDSA_SEED)),
            "-out",
        ])
        .arg(&key)
        .output()
        .ok()?;
    if !keygen_out.status.success() {
        return None;
    }

    // The raw FIPS 204 vk is the tail of the SPKI DER (2592 bytes).
    let spki = Command::new("openssl")
        .args(["pkey", "-pubout", "-outform", "DER", "-in"])
        .arg(&key)
        .output()
        .ok()?;
    if !spki.status.success() || spki.stdout.len() < 2592 {
        return None;
    }
    let vk = spki.stdout[spki.stdout.len() - 2592..].to_vec();

    let sign = Command::new("openssl")
        .args([
            "pkeyutl",
            "-sign",
            "-rawin",
            "-pkeyopt",
            &format!("hexcontext-string:{}", hex::encode(ctx)),
            "-pkeyopt",
            "deterministic:1",
            "-inkey",
        ])
        .arg(&key)
        .arg("-in")
        .arg(&m_path)
        .arg("-out")
        .arg(&sig_path)
        .output()
        .ok()?;
    if !sign.status.success() {
        return None;
    }
    let sig = std::fs::read(&sig_path).ok()?;
    (sig.len() == 4627).then_some((vk, sig))
}

/// One dual verify-vector over `m` with `ctx`: the shipped ES256 signer +
/// OpenSSL-lineage ML-DSA (RustCrypto fallback), cross-verified both ways
/// before being committed.
fn dual_vector(m: &[u8], ctx: &[u8], rust_vk: &[u8]) -> (Value, &'static str) {
    let sig_es = ecdsa::sign_es256(&ES256_SCALAR, m).expect("ES256 sign");

    let (lineage, sig_pq) = match openssl_mldsa_sign(m, ctx) {
        Some((openssl_vk, sig)) => {
            assert_eq!(
                openssl_vk, rust_vk,
                "OpenSSL and RustCrypto derive different vks from the same ξ — lineages disagree"
            );
            ("openssl-deterministic", sig)
        }
        None => {
            let sk = SigningKey::<MlDsa87>::from_seed(&Seed::from(MLDSA_SEED));
            let sig = sk
                .expanded_key()
                .sign_deterministic(m, ctx)
                .expect("ctx ≤ 255")
                .encode()
                .to_vec();
            ("rustcrypto-deterministic (openssl unavailable)", sig)
        }
    };

    // Cross-verify with the SHIPPED verifier stack before committing.
    ecdsa::verify_es256(&ec_pubkey_x963(&ES256_SCALAR), m, &sig_es).expect("ES256 verifies");
    {
        use ml_dsa::{EncodedSignature, EncodedVerifyingKey, Signature, VerifyingKey};
        let vk_arr = EncodedVerifyingKey::<MlDsa87>::try_from(rust_vk).unwrap();
        let vk = VerifyingKey::<MlDsa87>::decode(&vk_arr);
        let sig_arr = EncodedSignature::<MlDsa87>::try_from(&sig_pq[..]).unwrap();
        let sig = Signature::<MlDsa87>::decode(&sig_arr).expect("signature decodes");
        assert!(
            vk.verify_with_context(m, ctx, &sig),
            "RustCrypto rejects the generated ML-DSA signature — lineages disagree"
        );
    }

    (
        json!({
            "sig_es256_hex": hex::encode(sig_es),
            "sig_mldsa87_hex": hex::encode(&sig_pq),
        }),
        lineage,
    )
}

fn main() {
    // ---- fixed identities -------------------------------------------------
    let es_pub = ec_pubkey_x963(&ES256_SCALAR);
    let es_fp = pubkey::fingerprint(&es_pub).expect("fingerprint");
    let mldsa_sk = SigningKey::<MlDsa87>::from_seed(&Seed::from(MLDSA_SEED));
    let mldsa_vk = mldsa_sk.expanded_key().verifying_key().encode().to_vec();

    let kem_ec_pub = ec_pubkey_x963(&KEM_EC_SCALAR);
    let kem_pq_ek = mlkem_ek(&KEM_PQ_D, &KEM_PQ_Z);

    // ---- surface 1: per-request (Envelope §6.2, ctx signet:req:v1) --------
    let (method, path) = (
        "POST",
        "/v1/folders?parent=00000000-0000-4000-8000-00000000000f",
    );
    let body = br#"{"name":"golden-folder"}"#;
    let (timestamp, nonce) = ("1783468800", "0123456789abcdef0123456789abcdef");
    let m_request =
        signing::signet_v1_canonical_bytes(method, path, body, timestamp, nonce, &es_fp);

    // ---- surface 2: enrollment PoP (ctx signet:attest:v1) ------------------
    let m_enroll = attest::enroll_pop_signing_base(&ENROLL_CHALLENGE);

    // ---- surface 3: server verification response (Envelope §9) ------------
    // The launch-true HYBRID attestation shape (server/src/attestation.rs —
    // the sixteen classical fields + the six PQ fields + the §8.5 rfp).
    let attestation = json!({
        "attestation_id": "00000000-0000-4000-8000-000000000abc",
        "subject_account_id": "00000000-0000-4000-8000-00000000000a",
        "subject_handle": "hlin-golden-ai",
        "subject_signing_pubkey": URL_SAFE_NO_PAD.encode(&es_pub),
        "subject_signing_pubkey_fingerprint": es_fp,
        "subject_signing_alg": "ES256",
        "subject_kem_pubkey": URL_SAFE_NO_PAD.encode(&kem_ec_pub),
        "subject_kem_pubkey_fingerprint": pubkey::fingerprint(&kem_ec_pub).unwrap(),
        "subject_kem_alg": "ECDH-ES+A256KW",
        "created_at": 1_783_468_700_i64,
        "expires_at": Value::Null,
        "status": "active",
        "revoked_at": Value::Null,
        "prsn_sharing_capability": "read_only",
        "key_protection": "secure_enclave",
        "subject_signing_pq_pubkey": URL_SAFE_NO_PAD.encode(&mldsa_vk),
        "subject_signing_pq_pubkey_fingerprint": pubkey::fingerprint_raw(&mldsa_vk),
        "subject_signing_pq_alg": "ML-DSA-87",
        "subject_kem_pq_pubkey": URL_SAFE_NO_PAD.encode(&kem_pq_ek),
        "subject_kem_pq_pubkey_fingerprint": pubkey::fingerprint_raw(&kem_pq_ek),
        "subject_kem_pq_alg": "ML-KEM-1024",
        "rfp": hybrid_wrap::hybrid_rfp(&kem_ec_pub, &kem_pq_ek).unwrap(),
    });
    let server_key_id = "00000000-0000-4000-8000-0000000000aa";
    let signed_at = 1_783_468_800_i64;
    let m_verify = attest::verification_signing_input(&attestation, server_key_id, signed_at)
        .expect("verification signing input");

    // ---- surface 4: transparency-log receipt (Envelope §10a) --------------
    let receipt = json!({
        "v": 1,
        "type": "signet-pubkey-log-receipt",
        "entry_id": 7,
        "entry_version": 2,
        "account_id": "00000000-0000-4000-8000-00000000000a",
        "key_purpose": "signing_pq",
        "algorithm": "ML-DSA-87",
        "public_key_fingerprint": pubkey::fingerprint_raw(&mldsa_vk),
        "entry_hash": hex::encode(signet_crypto::hash::sha256(b"dual-sig-golden-entry")),
        "log_size_at_insertion": 7,
        "issued_at": 1_783_468_800_i64,
        "max_merge_delay_seconds": 86_400,
        "server_key_id": server_key_id,
        "server_pq_key_id": "00000000-0000-4000-8000-0000000000ab",
    });
    let m_receipt = translog::receipt_signing_input(&receipt).expect("receipt signing input");

    // ---- verify vectors (request + server-verification surfaces) ----------
    let (vec_request, lineage_req) = dual_vector(&m_request, attest::REQUEST_MLDSA_CTX, &mldsa_vk);
    let (vec_verify, lineage_ver) =
        dual_vector(&m_verify, attest::SERVER_VERIFY_MLDSA_CTX, &mldsa_vk);

    let golden = json!({
        "_provenance": {
            "generator": "cli/examples/gen_dual_sig_golden.rs (cargo run -p signet-cli --example gen_dual_sig_golden)",
            "spec": "PQR Crypto-Spec §8.7 (signing base) + §11.5b (this golden)",
            "generated": "2026-07-06 (S111)",
            "es256_lineage": "signet_crypto::ecdsa (RFC 6979 deterministic; OpenSSL cross-impl in crypto/tests/differential.rs)",
            "mldsa87_lineage_request": lineage_req,
            "mldsa87_lineage_server_verification": lineage_ver,
            "note": "Signatures generated in DETERMINISTIC mode so regeneration is byte-identical; production signing is hedged (spec §8 point 3) — verification is mode-agnostic.",
        },
        "identity": {
            "es256_scalar_hex": hex::encode(ES256_SCALAR),
            "es256_pubkey_x963_hex": hex::encode(&es_pub),
            "mldsa87_seed_hex": hex::encode(MLDSA_SEED),
            "mldsa87_vk_hex": hex::encode(&mldsa_vk),
        },
        "surfaces": {
            "request": {
                "method": method,
                "path_and_query": path,
                "body_utf8": String::from_utf8_lossy(body),
                "timestamp": timestamp,
                "nonce": nonce,
                "fingerprint": es_fp,
                "ctx_utf8": "signet:req:v1",
                "m_hex": hex::encode(&m_request),
            },
            "enroll_pop": {
                "challenge_hex": hex::encode(ENROLL_CHALLENGE),
                "ctx_utf8": "signet:attest:v1",
                "m_hex": hex::encode(&m_enroll),
            },
            "server_verification": {
                "attestation": attestation,
                "server_key_id": server_key_id,
                "signed_at": signed_at,
                "ctx_utf8": "signet-server-attestation-verify-v1",
                "m_hex": hex::encode(&m_verify),
            },
            "log_receipt": {
                "receipt": receipt,
                "ctx_utf8": "signet-pubkey-log-receipt-v1",
                "m_hex": hex::encode(&m_receipt),
            },
        },
        "verify_vectors": {
            "request": vec_request,
            "server_verification": vec_verify,
        },
    });

    let out = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../docs/design/test-vectors/golden/dual-sig-signing-base.json"
    );
    let pretty = serde_json::to_string_pretty(&golden).expect("serialize") + "\n";
    std::fs::write(out, pretty).expect("write golden");
    println!("wrote {out}");
    println!(
        "  request M: {} B · verify M: {} B · enroll M: {} B · receipt M: {} B",
        m_request.len(),
        m_verify.len(),
        m_enroll.len(),
        m_receipt.len()
    );
    println!("  ML-DSA lineage: {lineage_req} / {lineage_ver}");
}
