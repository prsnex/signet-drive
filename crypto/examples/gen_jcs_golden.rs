// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Generate the JCS cross-implementation golden (run once, output committed):
//!
//! ```text
//! cargo run -p signet-crypto --example gen_jcs_golden
//! # → docs/design/test-vectors/golden/jcs-cross-impl.json
//! ```
//!
//! The golden pins, for a set of SigDrive-domain-representative JSON values
//! (ASCII keys, integer numbers — the documented `jcs.rs` domain, shared with
//! the web port), the exact RFC 8785 canonical serialization the Rust
//! chokepoint (`signet_crypto::jcs`, backed by serde_jcs) produces. The web's
//! `jcs.ts` (an independent implementation over ECMAScript `JSON.stringify`
//! primitives) must produce byte-identical output for every case — the
//! cross-impl anchor for the F-DOWNGRADE(b) web verification path, in the
//! KeyCombine-KAT tradition: two independent lineages, one committed byte
//! truth. `crypto/tests/jcs.rs` re-asserts the Rust side against the
//! committed file so neither side can drift.
//!
//! Every case stays inside BOTH domains (integers ≤ 2^53 − 1: the Rust side
//! accepts full i64, the web REJECTS unsafe-range loudly — a documented,
//! deliberate divergence outside the protocol's value range).

use serde_json::{Value, json};

fn cases() -> Vec<(&'static str, Value)> {
    vec![
        ("empty_object", json!({})),
        ("empty_array_and_string", json!({"a": [], "b": ""})),
        (
            "key_sorting_ascii",
            // UTF-16-code-unit order == UTF-8 byte order for ASCII: digits <
            // uppercase < underscore < lowercase.
            json!({"b": 1, "a": 2, "A": 3, "a0": 4, "aA": 5, "_a": 6, "0": 7, "aa": 8}),
        ),
        (
            "string_escapes",
            json!({
                "quote": "he said \"hi\"",
                "backslash": "C:\\path\\to",
                "controls": "\u{0}\u{1}\u{8}\u{9}\u{a}\u{c}\u{d}\u{1f}",
                "slash_unescaped": "a/b",
                "unicode_raw": "héllo — ✓ 日本語",
            }),
        ),
        (
            "numbers_integer_domain",
            json!({"zero": 0, "neg": -1, "big": 9_007_199_254_740_991i64, "negbig": -9_007_199_254_740_991i64, "small": 42}),
        ),
        (
            "nested_mixed",
            json!({
                "z": {"y": [1, {"x": null}, true, false, "s"], "w": {}},
                "a": [[]],
            }),
        ),
        (
            // A §9-shaped attestation object (the real signing-base shape),
            // keys deliberately out of order.
            "attestation_shaped",
            json!({
                "subject_signing_pubkey_fingerprint": "0f0e0d0c0b0a09080706050403020100",
                "attestation_id": "b62be86f-8e40-49b5-b12b-5ea6d2d0e01c",
                "status": "active",
                "created_at": 1_751_800_000i64,
                "expires_at": null,
                "subject_account_id": "6bd0f19b-1a67-42d5-9c60-0d4a8de1a001",
                "subject_handle": "jane-ai",
                "key_protection": "secure_enclave",
                "rfp": "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
                "prsn_sharing_capability": "read_only",
            }),
        ),
        (
            // A §10a-receipt-shaped object (the other web-verified surface).
            "receipt_shaped",
            json!({
                "v": 1,
                "type": "signet-pubkey-log-receipt",
                "entry_id": 42,
                "entry_version": 2,
                "account_id": "6bd0f19b-1a67-42d5-9c60-0d4a8de1a001",
                "key_purpose": "kem_pq",
                "algorithm": "ML-KEM-1024",
                "public_key_fingerprint": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                "entry_hash": "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
                "log_size_at_insertion": 42,
                "issued_at": 1_751_800_000i64,
                "max_merge_delay_seconds": 86_400,
                "server_key_id": "0a418cf1-11f9-4a72-8f9c-2f6f1a34be0d",
                "server_pq_key_id": "e3b1b6a5-2f4b-4bfa-9d0e-7f30c58a11aa",
            }),
        ),
    ]
}

// ---------------------------------------------------------------------------
// The differential corpus (D2 increment review, Gus rider ii): seeded,
// regenerates byte-identically, and leans into exactly the surfaces where an
// RFC 8785 port would silently diverge — sort-adversarial in-domain keys,
// escape-heavy VALUES (quote, backslash, control characters, multi-byte
// UTF-8), and safe-integer edges. Corpus entries ride the same `cases` array,
// so both suites cover them through their existing iteration.
//
// Corpus finding, first run (S112): with escape-class characters in KEYS, the
// two lineages sorted differently — serde_jcs orders by the ESCAPED key form,
// not RFC 8785's raw code units. Resolution: the key domain is now ENFORCED
// at both chokepoints (plain ASCII, no control chars, no quote/backslash —
// every protocol key is snake_case, so production is untouched) and the
// corpus generates keys inside it. Out-of-domain keys are refused by BOTH
// lineages — unrepresentable, not pinned.
// ---------------------------------------------------------------------------

/// xorshift64 with a fixed seed — deterministic by construction (no external
/// RNG dep; the corpus must regenerate byte-identically forever).
struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// A hazard-alphabet VALUE string: every character class RFC 8785 treats
/// specially (escapes, control chars, multi-byte UTF-8) — values carry the
/// full hazard set; both lineages must escape them identically.
fn hazard_string(rng: &mut XorShift, len: usize, ascii_only: bool) -> String {
    const HAZARDS: &[&str] = &[
        "\"", "\\", "/", "\u{0}", "\u{1}", "\u{8}", "\u{9}", "\u{a}", "\u{c}", "\u{d}", "\u{1f}",
        "a", "Z", "0", "_", " ", "~",
    ];
    const NON_ASCII: &[&str] = &["é", "日", "—", "✓", "\u{7f}", "𝄞"];
    let mut s = String::new();
    for _ in 0..len {
        let pool_hazard = rng.below(100) < 70 || ascii_only;
        let piece = if pool_hazard {
            HAZARDS[rng.below(HAZARDS.len() as u64) as usize]
        } else {
            NON_ASCII[rng.below(NON_ASCII.len() as u64) as usize]
        };
        s.push_str(piece);
    }
    s
}

/// A KEY string from the ENFORCED key domain (plain ASCII, no control chars,
/// no quote/backslash — jcs.rs/jcs.ts refuse anything else; the S112 corpus
/// found serde_jcs orders escaped-form keys non-RFC, so out-of-domain keys are
/// unrepresentable rather than pinned). Still sort-adversarial: mixed case,
/// digits, punctuation straddling the case ranges.
fn key_string(rng: &mut XorShift, len: usize) -> String {
    const KEY_CHARS: &[&str] = &[
        "a", "z", "A", "Z", "0", "9", "_", " ", "~", "/", ".", "-", ":", "!", "@", "`", "{", "|",
    ];
    let mut s = String::new();
    for _ in 0..len {
        s.push_str(KEY_CHARS[rng.below(KEY_CHARS.len() as u64) as usize]);
    }
    s
}

fn corpus_int(rng: &mut XorShift) -> i64 {
    const MAX_SAFE: i64 = 9_007_199_254_740_991; // 2^53 - 1
    match rng.below(6) {
        0 => 0,
        1 => MAX_SAFE,
        2 => -MAX_SAFE,
        3 => rng.below(1000) as i64 - 500,
        4 => MAX_SAFE - rng.below(1000) as i64,
        _ => -(MAX_SAFE - rng.below(1000) as i64),
    }
}

fn corpus_value(rng: &mut XorShift, depth: u32) -> Value {
    match rng.below(if depth == 0 { 5 } else { 7 }) {
        0 => {
            let len = 1 + rng.below(8) as usize;
            json!(hazard_string(rng, len, false))
        }
        1 => json!(corpus_int(rng)),
        2 => Value::Null,
        3 => json!(rng.below(2) == 0),
        4 => {
            let len = rng.below(4) as usize;
            json!(hazard_string(rng, len, false))
        }
        5 => {
            let n = rng.below(4);
            Value::Array((0..n).map(|_| corpus_value(rng, depth - 1)).collect())
        }
        _ => {
            let n = rng.below(4);
            let mut map = serde_json::Map::new();
            for i in 0..n {
                // ASCII-only keys (the shared domain), hazard-heavy, made
                // unique by the index suffix so last-wins never fires.
                let len = 1 + rng.below(5) as usize;
                let key = format!("{}{}", key_string(rng, len), i);
                map.insert(key, corpus_value(rng, depth - 1));
            }
            Value::Object(map)
        }
    }
}

/// The asymmetry pairs (D2 increment review, Gus rider ii-b): inputs OUTSIDE
/// the web port's documented domain, where the two lineages deliberately
/// diverge — the Rust side (full serde_jcs) float-formats, the web side
/// throws. Pinned so fail-closed is recorded as intent, not accident.
fn asymmetry_cases() -> Vec<(&'static str, Value)> {
    vec![
        ("float_fraction", json!({"x": 0.1})),
        ("float_large_exponent", json!({"x": 1.5e300})),
        (
            "unsafe_integer_positive",
            json!({"x": 9_007_199_254_740_994i64}),
        ), // 2^53 + 2
        (
            "unsafe_integer_negative",
            json!({"x": -9_007_199_254_740_994i64}),
        ),
    ]
}

fn main() {
    let mut entries = Vec::new();
    for (name, value) in cases() {
        let canonical = signet_crypto::jcs::to_canonical_bytes(&value).expect("in-domain value");
        let canonical_str = String::from_utf8(canonical.clone()).expect("JCS output is UTF-8");
        entries.push(json!({
            "name": name,
            "input": value,
            "canonical": canonical_str,
            "canonical_sha256": hex::encode(signet_crypto::hash::sha256(&canonical)),
        }));
    }
    let mut rng = XorShift(0x5147_D2A5_0112_2026);
    for i in 0..64 {
        // Top-level corpus cases are always objects (the signing bases are).
        let mut map = serde_json::Map::new();
        let n = 1 + rng.below(5);
        for k in 0..n {
            let len = 1 + rng.below(6) as usize;
            let key = format!("{}{}", key_string(&mut rng, len), k);
            map.insert(key, corpus_value(&mut rng, 2));
        }
        let value = Value::Object(map);
        let canonical = signet_crypto::jcs::to_canonical_bytes(&value).expect("in-domain corpus");
        let canonical_str = String::from_utf8(canonical.clone()).expect("JCS output is UTF-8");
        entries.push(json!({
            "name": format!("corpus_{i:02}"),
            "input": value,
            "canonical": canonical_str,
            "canonical_sha256": hex::encode(signet_crypto::hash::sha256(&canonical)),
        }));
    }
    let mut asymmetry = Vec::new();
    for (name, value) in asymmetry_cases() {
        let canonical = signet_crypto::jcs::to_canonical_bytes(&value).expect("rust-side value");
        asymmetry.push(json!({
            "name": name,
            "input": value,
            "rust_canonical": String::from_utf8(canonical).expect("utf-8"),
            "web": "throws — outside the web port's documented domain (fail-closed)",
        }));
    }
    let golden = json!({
        "_provenance": {
            "generator": "crypto/examples/gen_jcs_golden.rs",
            "rust_lineage": "signet_crypto::jcs (serde_jcs)",
            "consumers": [
                "crypto/tests/jcs.rs (Rust re-assertion)",
                "web/src/lib/crypto/jcs.test.ts (TS cross-impl assertion)"
            ],
            "domain": "ASCII keys; integer numbers within ±(2^53 - 1)",
            "corpus": "64 seeded differential cases (xorshift64, fixed seed) — escape-heavy keys, control chars, safe-int edges",
            "asymmetry": "inputs outside the web domain: Rust float-formats, the web THROWS (the pinned direction)"
        },
        "cases": entries,
        "asymmetry_cases": asymmetry,
    });
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../docs/design/test-vectors/golden/jcs-cross-impl.json"
    );
    std::fs::write(path, serde_json::to_string_pretty(&golden).unwrap()).unwrap();
    println!("wrote {path}");
}
