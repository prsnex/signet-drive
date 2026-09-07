// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Tier-3 (JOSE conformance) + tier-4 (our novel bytes) golden vectors.
//!
//! The vectors are committed at `docs/design/test-vectors/golden/wrap-chain.json`,
//! generated once by `docs/design/test-vectors/gen/` (panva/jose for the
//! ECDH-ES+A256KW composition; Node WebCrypto AES-GCM for the file envelope) —
//! never a CI runtime dependency (Chris's S017 call). Re-running CI re-verifies
//! our impl against these frozen reference bytes.
//!
//! **Tier-3 conformance trick:** panva/jose's CEK is internal, so we prove our
//! unwrap recovered the *exact* CEK JOSE used by then AES-256-GCM-decrypting the
//! JWE payload with it — only the right CEK yields the known plaintext. This
//! validates the whole composition (ECDH P-256 → Concat-KDF-SHA-256 with the
//! A256KW constants → AES-KW), not mere self-consistency.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use signet_crypto::wrap::{EpkJwk, WrapEnvelope};
use signet_crypto::{aead, envelope, pubkey, wrap};

const GOLDEN: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../docs/design/test-vectors/golden/wrap-chain.json"
));

fn golden() -> Value {
    serde_json::from_str(GOLDEN).expect("parse committed golden vectors")
}

fn b64u(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(s.as_bytes()).expect("base64url")
}

fn recipient_scalar(jwk: &Value) -> [u8; 32] {
    b64u(jwk["d"].as_str().unwrap())
        .try_into()
        .expect("32-byte scalar")
}

fn recipient_pub_x963(jwk: &Value) -> Vec<u8> {
    let mut point = vec![0x04];
    point.extend_from_slice(&b64u(jwk["x"].as_str().unwrap()));
    point.extend_from_slice(&b64u(jwk["y"].as_str().unwrap()));
    point
}

/// A committed JWE, decomposed into our [`WrapEnvelope`] (the key-management
/// layer) plus the content-layer pieces needed to confirm the recovered CEK.
struct JwePieces {
    envelope: WrapEnvelope,
    /// The `apv` (P-015 root_folder_id binding), present only on metadata wraps.
    apv: Option<Vec<u8>>,
    iv: [u8; 12],
    ct_and_tag: Vec<u8>,
    /// The content-encryption AAD: the base64url protected header (RFC 7516 §5.1).
    aad: Vec<u8>,
}

/// Map a committed JWE into [`JwePieces`], reading `epk`/`apv` from the
/// protected header and `ct` from `encrypted_key`.
fn jwe_pieces(vector: &Value, recipient_pub: &[u8]) -> JwePieces {
    let jwe = &vector["jwe"];
    let protected_b64 = jwe["protected"].as_str().unwrap();
    let header: Value = serde_json::from_slice(&b64u(protected_b64)).unwrap();
    let epk = &header["epk"];

    let envelope = WrapEnvelope {
        v: 1,
        alg: header["alg"].as_str().unwrap().to_string(),
        epk: EpkJwk {
            kty: epk["kty"].as_str().unwrap().to_string(),
            crv: epk["crv"].as_str().unwrap().to_string(),
            x: epk["x"].as_str().unwrap().to_string(),
            y: epk["y"].as_str().unwrap().to_string(),
        },
        ct: jwe["encrypted_key"].as_str().unwrap().to_string(),
        rfp: pubkey::fingerprint(recipient_pub).unwrap(),
    };

    let mut ct_and_tag = b64u(jwe["ciphertext"].as_str().unwrap());
    ct_and_tag.extend_from_slice(&b64u(jwe["tag"].as_str().unwrap()));

    JwePieces {
        envelope,
        apv: header.get("apv").and_then(Value::as_str).map(b64u),
        iv: b64u(jwe["iv"].as_str().unwrap())
            .try_into()
            .expect("12-byte IV"),
        ct_and_tag,
        aad: protected_b64.as_bytes().to_vec(),
    }
}

#[test]
fn tier3_ecdh_es_a256kw_dek_matches_jose() {
    let golden = golden();
    let v = &golden["ecdh_es_a256kw_dek"];
    let scalar = recipient_scalar(&v["recipient_jwk"]);
    let recipient_pub = recipient_pub_x963(&v["recipient_jwk"]);
    let jwe = jwe_pieces(v, &recipient_pub);
    assert!(jwe.apv.is_none(), "DEK wrap carries no apv");

    // Our unwrap recovers the CEK panva/jose generated...
    let cek = wrap::unwrap_dek(&scalar, &jwe.envelope).expect("unwrap JOSE-produced DEK wrap");
    // ...proven by AES-256-GCM-decrypting the JWE payload with it.
    let plaintext = aead::open(&cek, &jwe.iv, &jwe.ct_and_tag, &jwe.aad)
        .expect("recovered CEK decrypts payload");
    assert_eq!(plaintext, v["payload_utf8"].as_str().unwrap().as_bytes());
}

#[test]
fn tier3_ecdh_es_a256kw_metadata_matches_jose() {
    let golden = golden();
    let v = &golden["ecdh_es_a256kw_metadata"];
    let scalar = recipient_scalar(&v["recipient_jwk"]);
    let recipient_pub = recipient_pub_x963(&v["recipient_jwk"]);
    let jwe = jwe_pieces(v, &recipient_pub);

    // The apv in JOSE's header is our root_folder_id binding (P-015).
    let apv = jwe.apv.clone().expect("metadata wrap carries apv");
    assert_eq!(
        hex::encode(&apv),
        v["root_folder_id_hex"].as_str().unwrap(),
        "apv must equal the committed root_folder_id",
    );
    let root_folder_id: [u8; 16] = apv.try_into().expect("16-byte root_folder_id");

    let cek = wrap::unwrap_metadata_key(&scalar, &jwe.envelope, &root_folder_id)
        .expect("unwrap JOSE-produced metadata-key wrap (P-015 apv)");
    let plaintext = aead::open(&cek, &jwe.iv, &jwe.ct_and_tag, &jwe.aad)
        .expect("recovered CEK decrypts payload");
    assert_eq!(plaintext, v["payload_utf8"].as_str().unwrap().as_bytes());
}

#[test]
fn tier4_file_envelope_matches_golden() {
    let golden = golden();
    let v = &golden["file_envelope_cat02"];
    let dek: [u8; 32] = hex::decode(v["dek_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let iv: [u8; 12] = hex::decode(v["iv_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let file_id: [u8; 16] = hex::decode(v["file_id_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let plaintext = v["plaintext_utf8"].as_str().unwrap().as_bytes();

    // Our framing + AES-GCM must produce the independently-generated bytes.
    let produced = envelope::seal_file(&dek, &iv, &file_id, plaintext).unwrap();
    assert_eq!(
        hex::encode(&produced),
        v["envelope_hex"].as_str().unwrap(),
        "file envelope bytes must match the golden (Node WebCrypto AES-GCM)",
    );
    assert_eq!(
        envelope::open_file(&dek, &file_id, &produced).unwrap(),
        plaintext
    );
}
