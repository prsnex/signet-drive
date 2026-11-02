// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Generate the VRF account-index golden (run once, output committed):
//!
//! ```text
//! cargo run -p signet-crypto --example gen_vrf_golden
//! # → docs/design/test-vectors/golden/vrf-account-index.json
//! ```
//!
//! Every proof and index here is the server's own: `signet_crypto::vrf`
//! (ECVRF-RISTRETTO255-SHA512 through the pinned `vrf-r255`), from fixed test
//! secret keys. The browser verifies with a separate artifact, the committed
//! VRF wasm module built from `crypto-wasm`'s `vrf` feature (Launch Punch-List
//! §1-67), so the golden is the cross-target anchor between them:
//! `crypto-wasm/tests/vrf_golden.rs` re-proves every case natively and verifies
//! it through the crate's own `vrf_verify`, and
//! `web/src/lib/crypto/committed_vrf.test.ts` verifies every case through
//! the committed `.wasm` bytes the browser fetches (Bob, Gus: the shipped
//! module had been checked by one known answer only).
//!
//! The refusal cases must yield no index on any side.

use serde_json::{Value, json};
use signet_crypto::vrf::VrfSecretKey;

fn account(seed: u8, which: u8) -> [u8; 16] {
    match which {
        0 => [0x00; 16],
        1 => [0xff; 16],
        // A UUID-shaped account (version 4, variant 10) distinct per key.
        _ => {
            let mut a = [0u8; 16];
            for (i, b) in a.iter_mut().enumerate() {
                *b = seed.wrapping_mul(37).wrapping_add(i as u8 * 11);
            }
            a[6] = 0x40 | (a[6] & 0x0f);
            a[8] = 0x80 | (a[8] & 0x3f);
            a
        }
    }
}

fn case(sk_byte: u8, acct: [u8; 16]) -> Value {
    let sk = VrfSecretKey::from_bytes(&[sk_byte; 32]).expect("test key");
    let (index, proof) = sk.prove(&acct).expect("prove");
    json!({
        "secret_key": hex::encode([sk_byte; 32]),
        "public_key": hex::encode(sk.public_key()),
        "account_id": hex::encode(acct),
        "proof": hex::encode(proof),
        "index": hex::encode(index),
    })
}

fn main() {
    let mut cases = Vec::new();
    // crypto-wasm's known answer (secret key 0x01 × 32), first.
    cases.push(case(
        0x01,
        [
            0xCA, 0xFE, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0xBE, 0xEF,
        ],
    ));
    for seed in 1u8..=8 {
        for which in 0u8..3 {
            cases.push(case(seed, account(seed, which)));
        }
    }

    // Refusals, from the first case: each must verify to nothing.
    let kat = &cases[0];
    let s = |k: &str| kat[k].as_str().unwrap().to_string();
    let (pk, acct, proof) = (s("public_key"), s("account_id"), s("proof"));
    let flip = |h: &str, byte: usize| {
        let mut b = hex::decode(h).unwrap();
        b[byte] ^= 0x01;
        hex::encode(b)
    };
    let other_pk = cases[4]["public_key"].as_str().unwrap().to_string();
    let refusals = json!([
        {"why": "another account", "public_key": pk, "account_id": flip(&acct, 15), "proof": proof},
        {"why": "an altered proof", "public_key": pk, "account_id": acct, "proof": flip(&proof, 40)},
        {"why": "another key", "public_key": other_pk, "account_id": acct, "proof": proof},
        {"why": "a 31-byte public key", "public_key": &pk[..62], "account_id": acct, "proof": proof},
        {"why": "a 15-byte account", "public_key": pk, "account_id": &acct[..30], "proof": proof},
        {"why": "a 79-byte proof", "public_key": pk, "account_id": acct, "proof": &proof[..158]},
        // Bob: the two decode-level refusals. The identity is Ristretto's one degenerate
        // key (secret 0: every account would map to one index, bug256's class), refused at
        // PublicKey::from_bytes; 0xff × 32 is no point at all.
        {"why": "the identity public key", "public_key": "00".repeat(32), "account_id": acct, "proof": proof},
        {"why": "a public key that is no point", "public_key": "ff".repeat(32), "account_id": acct, "proof": proof},
    ]);

    let golden = json!({
        "_comment": "GENERATED — do not hand-edit. Run `cargo run -p signet-crypto --example gen_vrf_golden`. Every proof and index is signet_crypto::vrf's (the server's). Consumed by crypto-wasm/tests/vrf_golden.rs and web/src/lib/crypto/committed_vrf.test.ts.",
        "suite": "ECVRF-RISTRETTO255-SHA512",
        "alpha": "\"signet-pubkey-log-v3-account-index\" || 0x00 || account_id (16 bytes)",
        "cases": cases,
        "refusals": refusals,
    });
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../docs/design/test-vectors/golden/vrf-account-index.json"
    );
    std::fs::write(path, serde_json::to_string_pretty(&golden).unwrap() + "\n").unwrap();
    println!("wrote {path}");
}
