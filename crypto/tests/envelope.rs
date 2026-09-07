// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Functional tests for the file ciphertext envelope. Single-PUT (Envelope §4.1):
//! round-trip plus the test-vectors Cat 02 TC02-04 AEAD-integrity negatives (wrong
//! `file_id` AAD, wrong DEK, flipped ciphertext/IV/tag, wrong magic/alg byte). The
//! deterministic byte-for-byte golden vector (Cat 02 TC02-01) is generated + pinned
//! in `golden_vectors.rs`. Multipart (§4.2): round-trip, a reconstruction golden
//! (seal_chunk == an independent rebuild from the KAT'd HKDF + the Node-golden'd
//! AES-GCM), and the negative-crypto suite (reorder / duplicate-at-wrong-position /
//! substitution / tamper). The cross-implementation Rust↔web golden lands with the
//! web-parity build.

use signet_crypto::envelope::{
    self, FILE_ALG_A256GCM, FILE_MAGIC_MULTIPART, FILE_MAGIC_SINGLE_PUT,
};
use signet_crypto::error::CryptoError;
use signet_crypto::{aead, kdf};

const DEK: [u8; 32] = [0x42u8; 32];
const IV: [u8; 12] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
];
const FILE_ID: [u8; 16] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x11,
];

#[test]
fn seal_open_round_trip() {
    let plaintext = b"hello signet drive";
    let sealed = envelope::seal_file(&DEK, &IV, &FILE_ID, plaintext).unwrap();

    // Layout: [magic][alg][12 IV][ct][16 tag]; ct length == plaintext length.
    assert_eq!(sealed[0], FILE_MAGIC_SINGLE_PUT);
    assert_eq!(sealed[1], FILE_ALG_A256GCM);
    assert_eq!(&sealed[2..14], &IV);
    assert_eq!(sealed.len(), 2 + 12 + plaintext.len() + 16);

    let opened = envelope::open_file(&DEK, &FILE_ID, &sealed).unwrap();
    assert_eq!(opened, plaintext);
}

#[test]
fn empty_file_round_trips() {
    let sealed = envelope::seal_file(&DEK, &IV, &FILE_ID, b"").unwrap();
    assert_eq!(
        sealed.len(),
        2 + 12 + 16,
        "empty plaintext: header + tag only"
    );
    assert_eq!(envelope::open_file(&DEK, &FILE_ID, &sealed).unwrap(), b"");
}

#[test]
fn wrong_file_id_aad_fails() {
    // The AAD binding: a blob decrypted under a different file_id fails the tag.
    let sealed = envelope::seal_file(&DEK, &IV, &FILE_ID, b"contents").unwrap();
    let mut other_id = FILE_ID;
    other_id[15] ^= 0xff;
    assert_eq!(
        envelope::open_file(&DEK, &other_id, &sealed),
        Err(CryptoError::Authentication),
    );
}

#[test]
fn wrong_dek_fails() {
    let sealed = envelope::seal_file(&DEK, &IV, &FILE_ID, b"contents").unwrap();
    let wrong_dek = [0x43u8; 32];
    assert_eq!(
        envelope::open_file(&wrong_dek, &FILE_ID, &sealed),
        Err(CryptoError::Authentication),
    );
}

#[test]
fn flipped_ciphertext_iv_or_tag_fails() {
    let sealed = envelope::seal_file(&DEK, &IV, &FILE_ID, b"some longer contents here").unwrap();

    // A flipped bit anywhere past the magic/alg header (IV, ct, or tag) breaks
    // the AEAD: every one fails as Authentication.
    for pos in [2usize, 14, sealed.len() - 1] {
        let mut tampered = sealed.clone();
        tampered[pos] ^= 1;
        assert_eq!(
            envelope::open_file(&DEK, &FILE_ID, &tampered),
            Err(CryptoError::Authentication),
            "tamper at byte {pos} must fail authentication",
        );
    }
}

#[test]
fn wrong_magic_or_alg_byte_is_rejected() {
    let sealed = envelope::seal_file(&DEK, &IV, &FILE_ID, b"contents").unwrap();

    let mut bad_magic = sealed.clone();
    bad_magic[0] = 0x02; // multipart magic — not accepted by the single-PUT opener
    assert!(matches!(
        envelope::open_file(&DEK, &FILE_ID, &bad_magic),
        Err(CryptoError::InvalidInput(_)),
    ));

    let mut bad_alg = sealed.clone();
    bad_alg[1] = 0x02;
    assert!(matches!(
        envelope::open_file(&DEK, &FILE_ID, &bad_alg),
        Err(CryptoError::InvalidInput(_)),
    ));
}

#[test]
fn too_short_envelope_is_rejected() {
    // Anything shorter than header + tag can't be a valid envelope.
    for len in [0usize, 1, 13, 27] {
        assert!(matches!(
            envelope::open_file(&DEK, &FILE_ID, &vec![0u8; len]),
            Err(CryptoError::InvalidInput(_)),
        ));
    }
}

// --- §4.2 Multipart -----------------------------------------------------------

const MULTIPART_HEADER_LEN: usize = 2 + 4 + 12; // magic + alg + index + IV

/// Independently re-derive the §4.2 per-chunk IV per the spec, for cross-checking.
fn expected_chunk_iv(dek: &[u8; 32], chunk_index: u32) -> [u8; 12] {
    let mut info = b"signet-drive-multipart-iv-v1".to_vec();
    info.extend_from_slice(&chunk_index.to_be_bytes());
    kdf::hkdf_sha256(dek, &[], &info, 12)
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn seal_chunk_open_chunk_round_trip() {
    let idx: u32 = 3;
    let count: u32 = 4; // idx 3 is the terminal chunk
    let plaintext = b"the third chunk of a large file";
    let sealed = envelope::seal_chunk(&DEK, &FILE_ID, idx, count, plaintext).unwrap();

    // Layout: [0x02][0x01][4 index BE][12 IV][ct][16 tag] — unchanged by the is_last
    // AAD flag (the flag is authenticated, not stored on disk).
    assert_eq!(sealed[0], FILE_MAGIC_MULTIPART);
    assert_eq!(sealed[1], FILE_ALG_A256GCM);
    assert_eq!(&sealed[2..6], &idx.to_be_bytes());
    assert_eq!(&sealed[6..18], &expected_chunk_iv(&DEK, idx));
    assert_eq!(sealed.len(), MULTIPART_HEADER_LEN + plaintext.len() + 16);

    assert_eq!(
        envelope::open_chunk(&DEK, &FILE_ID, idx, count, &sealed).unwrap(),
        plaintext
    );
}

/// The cross-impl §4.2 golden inputs (shared with the web `CHUNK_GOLDEN`): a
/// non-terminal chunk (idx 7 of 10 → `is_last = false`).
const GOLDEN_CHUNK_IDX: u32 = 7;
const GOLDEN_CHUNK_COUNT: u32 = 10;
const GOLDEN_CHUNK_PLAINTEXT: &[u8] = b"chunk seven payload";

#[test]
fn chunk_bytes_match_independent_reconstruction() {
    // The reconstruction golden: rebuild the expected envelope from the spec'd
    // primitives independently — IV = HKDF-SHA-256(DEK, empty salt, label||idx_be);
    // AAD = file_id || idx_be || is_last; body = AES-256-GCM(DEK, IV, plaintext, AAD)
    // — and assert seal_chunk's framing produces exactly those bytes. The HKDF is
    // RFC-5869 KAT'd and the AES-GCM is Node-golden'd (golden_vectors.rs), so this
    // validates the §4.2 *composition* (the IV label, the AAD construction incl. the
    // is_last byte, the byte layout), not mere self-consistency. Deterministic, so it
    // also pins the bytes (these inputs back the web cross-impl CHUNK_GOLDEN).
    let idx = GOLDEN_CHUNK_IDX;
    let count = GOLDEN_CHUNK_COUNT;
    let plaintext = GOLDEN_CHUNK_PLAINTEXT;

    let iv = expected_chunk_iv(&DEK, idx);
    let mut aad = FILE_ID.to_vec();
    aad.extend_from_slice(&idx.to_be_bytes());
    aad.push(0); // is_last = false (idx 7 of 10)
    let body = aead::seal(&DEK, &iv, plaintext, &aad).unwrap();
    let mut expected = vec![FILE_MAGIC_MULTIPART, FILE_ALG_A256GCM];
    expected.extend_from_slice(&idx.to_be_bytes());
    expected.extend_from_slice(&iv);
    expected.extend_from_slice(&body);

    let produced = envelope::seal_chunk(&DEK, &FILE_ID, idx, count, plaintext).unwrap();
    assert_eq!(
        produced, expected,
        "seal_chunk framing must match the independent §4.2 reconstruction"
    );
}

/// The committed §4.2 cross-impl golden — generated by an INDEPENDENT lineage
/// (`gen/chunk_envelope_gen.mjs`, Node WebCrypto), consumed by both this suite and
/// the web suite. Supersedes the hand-paste flow (the prior `#[ignore]`d emitter
/// whose hex was copied into the web test). Regenerate:
///   `cd docs/design/test-vectors/gen && npm run gen:chunk`
const CHUNK_GOLDEN: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../docs/design/test-vectors/golden/chunk-envelope.json"
));

#[test]
fn chunk_bytes_match_node_webcrypto_golden() {
    // `seal_chunk` (RustCrypto) must reproduce the committed bytes generated by an
    // independent Node-WebCrypto (OpenSSL) implementation of §4.2 — a genuine
    // cross-stack reference, not self-consistency. The web suite checks the same
    // file against browser WebCrypto, so all three lineages are pinned to it. The
    // golden's inputs MUST stay identical to the `GOLDEN_CHUNK_*` constants here.
    let g: serde_json::Value = serde_json::from_str(CHUNK_GOLDEN).expect("parse chunk golden");
    let dek: [u8; 32] = hex_to_vec(g["dek_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let file_id: [u8; 16] = hex_to_vec(g["file_id_hex"].as_str().unwrap())
        .try_into()
        .unwrap();
    let idx = g["chunk_index"].as_u64().unwrap() as u32;
    let count = g["chunk_count"].as_u64().unwrap() as u32;
    let plaintext = g["plaintext_utf8"].as_str().unwrap().as_bytes();
    let expected = hex_to_vec(g["envelope_hex"].as_str().unwrap());

    // The committed golden's inputs are the same fixed vector this file builds on.
    assert_eq!(dek, DEK);
    assert_eq!(file_id, FILE_ID);
    assert_eq!((idx, count), (GOLDEN_CHUNK_IDX, GOLDEN_CHUNK_COUNT));
    assert_eq!(plaintext, GOLDEN_CHUNK_PLAINTEXT);

    let produced = envelope::seal_chunk(&dek, &file_id, idx, count, plaintext).unwrap();
    assert_eq!(
        produced, expected,
        "seal_chunk must match the Node-WebCrypto §4.2 golden byte-for-byte"
    );
}

/// Lowercase-hex → bytes (test-local; the golden encodes its byte fields as hex).
fn hex_to_vec(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

#[test]
fn chunk_iv_is_unique_per_index() {
    // The whole point of the HKDF-derived nonce: distinct chunk indices yield
    // distinct IVs under one DEK (GCM nonce reuse under one key is catastrophic).
    let a = expected_chunk_iv(&DEK, 0);
    let b = expected_chunk_iv(&DEK, 1);
    let c = expected_chunk_iv(&DEK, 10_000);
    assert_ne!(a, b);
    assert_ne!(b, c);
    assert_ne!(a, c);
}

#[test]
fn empty_final_chunk_round_trips() {
    let sealed = envelope::seal_chunk(&DEK, &FILE_ID, 42, 43, b"").unwrap();
    assert_eq!(sealed.len(), MULTIPART_HEADER_LEN + 16, "header + tag only");
    assert_eq!(
        envelope::open_chunk(&DEK, &FILE_ID, 42, 43, &sealed).unwrap(),
        b""
    );
}

#[test]
fn chunk_reorder_is_rejected_by_stored_index() {
    // A chunk sealed for position 2, presented at position 5: the stored-index
    // structural check rejects it before the crypto runs.
    let sealed = envelope::seal_chunk(&DEK, &FILE_ID, 2, 6, b"position two").unwrap();
    assert!(matches!(
        envelope::open_chunk(&DEK, &FILE_ID, 5, 6, &sealed),
        Err(CryptoError::InvalidInput(_)),
    ));
}

#[test]
fn chunk_forged_position_fails_the_aad() {
    // Defeat the structural index check by rewriting the stored index to the
    // attacker's target position — the AAD (file_id || chunk_index || is_last) is the
    // real binding, so the tag still fails: a chunk cannot be moved without detection.
    let mut sealed = envelope::seal_chunk(&DEK, &FILE_ID, 2, 6, b"position two").unwrap();
    sealed[2..6].copy_from_slice(&5u32.to_be_bytes()); // forge stored index 2 → 5
    assert_eq!(
        envelope::open_chunk(&DEK, &FILE_ID, 5, 6, &sealed),
        Err(CryptoError::Authentication),
    );
}

#[test]
fn chunk_truncation_is_detected_by_is_last() {
    // A 3-chunk file. Drop the real terminal chunk (idx 2) and claim chunk_count = 2:
    // the reader opens the new "last" chunk (idx 1) expecting is_last = true, but it
    // was sealed is_last = false (not originally terminal) → the AAD, and so the GCM
    // tag, mismatch. This is the truncation defence the is_last flag adds.
    let c0 = envelope::seal_chunk(&DEK, &FILE_ID, 0, 3, b"chunk zero").unwrap();
    let c1 = envelope::seal_chunk(&DEK, &FILE_ID, 1, 3, b"chunk one").unwrap();

    // Honest full read (the true count) verifies.
    assert!(envelope::open_chunk(&DEK, &FILE_ID, 1, 3, &c1).is_ok());

    // Truncated read (lowered count) — chunk 1 now claimed terminal — is rejected.
    assert_eq!(
        envelope::open_chunk(&DEK, &FILE_ID, 1, 2, &c1),
        Err(CryptoError::Authentication),
    );
    // A non-boundary chunk under the lowered count still opens (its is_last is
    // unchanged) — detection is precisely at the forged boundary.
    assert!(envelope::open_chunk(&DEK, &FILE_ID, 0, 2, &c0).is_ok());
}

#[test]
fn chunk_index_out_of_range_is_rejected() {
    // chunk_index must be in 0..chunk_count, and chunk_count ≥ 1 — on both seal+open.
    assert!(matches!(
        envelope::seal_chunk(&DEK, &FILE_ID, 5, 3, b"x"),
        Err(CryptoError::InvalidInput(_)),
    ));
    assert!(matches!(
        envelope::seal_chunk(&DEK, &FILE_ID, 0, 0, b"x"),
        Err(CryptoError::InvalidInput(_)),
    ));
    let sealed = envelope::seal_chunk(&DEK, &FILE_ID, 0, 1, b"x").unwrap();
    assert!(matches!(
        envelope::open_chunk(&DEK, &FILE_ID, 3, 3, &sealed),
        Err(CryptoError::InvalidInput(_)),
    ));
}

#[test]
fn chunk_substitution_wrong_file_fails() {
    // The AAD binds the chunk to its file: opening under a different file_id (same
    // index) fails — defends against cross-file chunk substitution at the store.
    let sealed = envelope::seal_chunk(&DEK, &FILE_ID, 0, 1, b"contents").unwrap();
    let mut other_id = FILE_ID;
    other_id[0] ^= 0xff;
    assert_eq!(
        envelope::open_chunk(&DEK, &other_id, 0, 1, &sealed),
        Err(CryptoError::Authentication),
    );
}

#[test]
fn chunk_wrong_dek_fails() {
    let sealed = envelope::seal_chunk(&DEK, &FILE_ID, 0, 1, b"contents").unwrap();
    let wrong_dek = [0x43u8; 32];
    assert_eq!(
        envelope::open_chunk(&wrong_dek, &FILE_ID, 0, 1, &sealed),
        Err(CryptoError::Authentication),
    );
}

#[test]
fn chunk_tamper_fails() {
    let sealed = envelope::seal_chunk(&DEK, &FILE_ID, 1, 2, b"some longer chunk contents").unwrap();
    // A flipped bit anywhere past the index header (IV, ct, or tag) breaks the AEAD.
    for pos in [6usize, MULTIPART_HEADER_LEN, sealed.len() - 1] {
        let mut tampered = sealed.clone();
        tampered[pos] ^= 1;
        assert_eq!(
            envelope::open_chunk(&DEK, &FILE_ID, 1, 2, &tampered),
            Err(CryptoError::Authentication),
            "tamper at byte {pos} must fail authentication",
        );
    }
}

#[test]
fn chunk_wrong_magic_or_alg_is_rejected() {
    let sealed = envelope::seal_chunk(&DEK, &FILE_ID, 0, 1, b"contents").unwrap();

    let mut bad_magic = sealed.clone();
    bad_magic[0] = FILE_MAGIC_SINGLE_PUT; // single-PUT magic — not a multipart chunk
    assert!(matches!(
        envelope::open_chunk(&DEK, &FILE_ID, 0, 1, &bad_magic),
        Err(CryptoError::InvalidInput(_)),
    ));

    let mut bad_alg = sealed.clone();
    bad_alg[1] = 0x02;
    assert!(matches!(
        envelope::open_chunk(&DEK, &FILE_ID, 0, 1, &bad_alg),
        Err(CryptoError::InvalidInput(_)),
    ));
}

#[test]
fn chunk_too_short_is_rejected() {
    for len in [
        0usize,
        1,
        17,
        MULTIPART_HEADER_LEN,
        MULTIPART_HEADER_LEN + 15,
    ] {
        assert!(matches!(
            envelope::open_chunk(&DEK, &FILE_ID, 0, 1, &vec![0u8; len]),
            Err(CryptoError::InvalidInput(_)),
        ));
    }
}

#[test]
fn single_put_and_multipart_magics_do_not_cross_open() {
    // A single-PUT envelope must not open as a chunk, and vice versa (magic guard).
    let single = envelope::seal_file(&DEK, &IV, &FILE_ID, b"x").unwrap();
    assert!(matches!(
        envelope::open_chunk(&DEK, &FILE_ID, 0, 1, &single),
        Err(CryptoError::InvalidInput(_)),
    ));
    let chunk = envelope::seal_chunk(&DEK, &FILE_ID, 0, 1, b"x").unwrap();
    assert!(matches!(
        envelope::open_file(&DEK, &FILE_ID, &chunk),
        Err(CryptoError::InvalidInput(_)),
    ));
}
