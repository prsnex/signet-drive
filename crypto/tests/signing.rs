// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Tier-4 golden vectors for the SIGNET-V1 per-request canonical bytes
//! (test-vector Cat 03 / Envelope §6.2 / Strawman v09 §4).
//!
//! These prove **impl-matches-spec**: the canonical bytes are asserted
//! byte-for-byte against hand-written expected strings (independent of the
//! builder's own `join`), their SHA-256 (the input to ECDSA signing) is pinned
//! to published constants, and the construction round-trips through the real
//! `ES256` sign/verify path. There is no independent external generator for this
//! SigDrive-specific layout, so this is tier-4, not a published KAT — the named
//! residual the assurance model carries to the pre-launch cross-family review.
//!
//! Reference signing key (Layer-2 fixture): the deterministic P-256 scalar
//! `0x0102…20` (bytes 1..=32). Its X9.63 public key and SPKI fingerprint are
//! the Cat 03 reference values, recorded in `docs/design/test-vectors/03-*`.

use p256::SecretKey;
use signet_crypto::{ecdsa, hash, pubkey, signing};

/// The Cat 03 reference signing scalar (bytes 1..=32).
fn ref_scalar() -> [u8; 32] {
    core::array::from_fn(|i| (i + 1) as u8)
}

fn ref_pubkey_x963() -> Vec<u8> {
    SecretKey::from_slice(&ref_scalar())
        .expect("valid P-256 scalar")
        .public_key()
        .to_sec1_bytes()
        .to_vec()
}

/// SHA-256 of zero bytes (the empty-body hash, test-vector Cat 04).
const EMPTY_BODY_SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// Published Layer-2 goldens for the reference scalar `0x0102…20` (recorded in
// docs/design/test-vectors/03-signet-v1-canonical-bytes.md). The *_SHA values
// are the SHA-256 of the canonical bytes — the message ECDSA actually signs —
// so a third-party verifier can confirm agreement without an ECDSA step.
const REF_PUBKEY_X963_HEX: &str = "04515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f4536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f9354";
const REF_FINGERPRINT: &str = "f1d59449b727165de732bf283338122b99628a615918fedc67d878fffcf47da7";
const TC03_01_CANONICAL_SHA: &str =
    "e071f84adc329a236eb377807ac060a13ad6dd0dd6c97170239773c620b968c1";
const TC03_02_BODY_SHA: &str = "6a46adce15c6d3cdf17434e82c3feb8f28ab51bffc85636636c195133c157f01";
const TC03_02_CANONICAL_SHA: &str =
    "8f35b76a0673dc1a07af95b6a055143e67fb10efe640975f2a4f7fe364c14767";
const TC03_03_CANONICAL_SHA: &str =
    "6c5f18e7e786ea8bcc298d322b7d40de02c876d1022fac9770fb76c1467cf94f";

#[test]
fn ref_key_values_are_published() {
    // Pin the reference key's public material so the doc + any third-party
    // verifier can reproduce the canonical bytes exactly. (Captured then baked.)
    let pubkey = ref_pubkey_x963();
    let fp = pubkey::fingerprint(&pubkey).unwrap();
    assert_eq!(
        hex::encode(&pubkey),
        REF_PUBKEY_X963_HEX,
        "reference pubkey"
    );
    assert_eq!(fp, REF_FINGERPRINT, "reference fingerprint");
}

#[test]
fn tc03_01_get_no_body() {
    let fp = pubkey::fingerprint(&ref_pubkey_x963()).unwrap();
    let canonical = signing::signet_v1_canonical_bytes(
        "GET",
        "/v1/me",
        b"",
        "1700000000",
        "0102030405060708090a0b0c0d0e0f10",
        &fp,
    );

    // Byte-exact against a hand-written expected (not built via the same join).
    let expected = format!(
        "SIGNET-V1\nGET\n/v1/me\n{EMPTY_BODY_SHA}\n1700000000\n0102030405060708090a0b0c0d0e0f10\n{fp}"
    );
    assert_eq!(canonical, expected.as_bytes(), "TC03-01 canonical bytes");

    // Structural invariants (the TC03-04 negatives, as properties).
    assert!(!canonical.ends_with(b"\n"), "no trailing newline");
    assert!(
        !canonical.contains(&b'\r'),
        "LF-only separators, never CRLF"
    );
    assert_eq!(
        canonical.iter().filter(|&&b| b == b'\n').count(),
        6,
        "six LF separators between seven elements"
    );

    assert_eq!(
        hex::encode(hash::sha256(&canonical)),
        TC03_01_CANONICAL_SHA,
        "TC03-01 canonical-bytes SHA-256"
    );
}

#[test]
fn tc03_02_put_with_body() {
    let fp = pubkey::fingerprint(&ref_pubkey_x963()).unwrap();
    let body = br#"{"folder_id":"00000000-0000-4000-8000-000000000222","encrypted_name":{"alg":"A256GCM","iv":"AAAAAAAAAAAAAAAA","ct":"AAA","tag":"AAAAAAAAAAAAAAAAAAAAAA"},"wrapped_deks":[],"ciphertext_b64":""}"#;
    let body_hash = hex::encode(hash::sha256(body));

    let canonical = signing::signet_v1_canonical_bytes(
        "PUT",
        "/v1/files/00000000-0000-4000-8000-000000000111",
        body,
        "1700000060",
        "1112131415161718191a1b1c1d1e1f20",
        &fp,
    );

    let expected = format!(
        "SIGNET-V1\nPUT\n/v1/files/00000000-0000-4000-8000-000000000111\n{body_hash}\n1700000060\n1112131415161718191a1b1c1d1e1f20\n{fp}"
    );
    assert_eq!(canonical, expected.as_bytes(), "TC03-02 canonical bytes");

    // The body hash is over the bytes as-sent — NOT a JSON-canonicalized form.
    assert_ne!(body_hash, EMPTY_BODY_SHA, "non-empty body hashes to itself");
    assert_eq!(body_hash, TC03_02_BODY_SHA, "TC03-02 body SHA-256");
    assert_eq!(
        hex::encode(hash::sha256(&canonical)),
        TC03_02_CANONICAL_SHA,
        "TC03-02 canonical-bytes SHA-256"
    );
}

#[test]
fn tc03_03_query_string_preserved_verbatim() {
    let fp = pubkey::fingerprint(&ref_pubkey_x963()).unwrap();
    let path = "/v1/me/audit?since=00000000-0000-7000-8000-000000000001&limit=50";
    let canonical = signing::signet_v1_canonical_bytes(
        "GET",
        path,
        b"",
        "1700001000",
        "2122232425262728292a2b2c2d2e2f30",
        &fp,
    );

    let expected = format!(
        "SIGNET-V1\nGET\n{path}\n{EMPTY_BODY_SHA}\n1700001000\n2122232425262728292a2b2c2d2e2f30\n{fp}"
    );
    assert_eq!(canonical, expected.as_bytes(), "TC03-03 canonical bytes");

    // The path (incl. the exact query string) appears verbatim — no reordering
    // or normalization of query parameters.
    let text = String::from_utf8(canonical.clone()).unwrap();
    assert!(text.contains(path), "query string preserved as-sent");

    assert_eq!(
        hex::encode(hash::sha256(&canonical)),
        TC03_03_CANONICAL_SHA,
        "TC03-03 canonical-bytes SHA-256"
    );
}

#[test]
fn negative_constructions_differ() {
    let fp = pubkey::fingerprint(&ref_pubkey_x963()).unwrap();
    let base = signing::signet_v1_canonical_bytes("GET", "/v1/me", b"", "1700000000", "abcd", &fp);

    // Lowercase method, dropped query string, and a changed body all change the
    // bytes (and therefore the signature) — the TC03-04 mistakes.
    let lower = signing::signet_v1_canonical_bytes("get", "/v1/me", b"", "1700000000", "abcd", &fp);
    assert_ne!(base, lower, "method case is significant");

    let with_body =
        signing::signet_v1_canonical_bytes("GET", "/v1/me", b"x", "1700000000", "abcd", &fp);
    assert_ne!(base, with_body, "body hash is part of the bytes");
}

#[test]
fn round_trips_through_es256() {
    let scalar = ref_scalar();
    let pubkey = ref_pubkey_x963();
    let fp = pubkey::fingerprint(&pubkey).unwrap();

    let canonical = signing::signet_v1_canonical_bytes(
        "GET",
        "/v1/me",
        b"",
        "1700000000",
        "0102030405060708090a0b0c0d0e0f10",
        &fp,
    );

    // Sign the canonical bytes with the reference key; the matching pubkey
    // verifies (ES256 applies SHA-256 internally).
    let sig = ecdsa::sign_es256(&scalar, &canonical).unwrap();
    assert!(
        ecdsa::verify_es256(&pubkey, &canonical, &sig).is_ok(),
        "reference key verifies its own SIGNET-V1 signature"
    );

    // A tampered request (lowercase method) does not verify against that sig.
    let tampered = signing::signet_v1_canonical_bytes(
        "get",
        "/v1/me",
        b"",
        "1700000000",
        "0102030405060708090a0b0c0d0e0f10",
        &fp,
    );
    assert!(
        ecdsa::verify_es256(&pubkey, &tampered, &sig).is_err(),
        "a different request must not verify against the original signature"
    );
}
