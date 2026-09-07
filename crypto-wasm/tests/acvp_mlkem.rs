// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! §11.1 ACVP known-answer tests — ML-KEM-1024, both compile targets.
//!
//! The NIST ACVP demo vectors (vendored at `docs/design/test-vectors/acvp/`,
//! provenance in its README) driven through the SHIPPED `ml-kem` crate — this
//! crate's own seed-custody wrappers where the product has one, the crate's
//! public API directly where custody deliberately hides a surface (dk
//! encoding, per-test dk decapsulation). Like every §11.3 KAT in this crate,
//! the tests are dual-annotated: the same assertions run natively (workspace
//! suite) AND in real wasm32 (`wasm-pack test --node`) — FIPS correctness and
//! the cross-target miscompile check from one file.
//!
//! Decapsulation includes the implicit-rejection cases: per FIPS 203 (and
//! Crypto-Spec §10) a tampered ciphertext does NOT error — the assertion is on
//! the expected pseudorandom shared secret, never on an error that never comes.
//!
//! The `acvp_vector_accounting_is_exact` test pins the exclusions ledger
//! (README): if a crate upgrade makes an excluded class expressible, the pin
//! fails loudly and the ledger must be re-decided rather than silently rot.

use kem::Decapsulate;
use ml_kem::{B32, EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem1024};
use serde_json::Value;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;

type Ek = <MlKem1024 as KemCore>::EncapsulationKey;
type Dk = <MlKem1024 as KemCore>::DecapsulationKey;

const KEYGEN_PROMPT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../docs/design/test-vectors/acvp/ml-kem-1024.keygen.prompt.json"
));
const KEYGEN_RESULTS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../docs/design/test-vectors/acvp/ml-kem-1024.keygen.results.json"
));
const ENCDEC_PROMPT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../docs/design/test-vectors/acvp/ml-kem-1024.encap-decap.prompt.json"
));
const ENCDEC_RESULTS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../docs/design/test-vectors/acvp/ml-kem-1024.encap-decap.results.json"
));

fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string field")).expect("valid hex")
}

/// Parse a prompt/results pair and zip their test cases by (tgId, tcId).
/// Returns (group meta, prompt test, expected test) triples for every case.
fn zip_cases<'a>(prompt: &'a Value, results: &'a Value) -> Vec<(&'a Value, &'a Value, &'a Value)> {
    let result_groups: Vec<&Value> = results["testGroups"]
        .as_array()
        .expect("groups")
        .iter()
        .collect();
    let mut out = Vec::new();
    for group in prompt["testGroups"].as_array().expect("groups") {
        let tg_id = group["tgId"].as_i64().expect("tgId");
        let expected_group = result_groups
            .iter()
            .find(|g| g["tgId"].as_i64() == Some(tg_id))
            .expect("results group for every prompt group");
        let expected_tests = expected_group["tests"].as_array().expect("tests");
        for test in group["tests"].as_array().expect("tests") {
            let tc_id = test["tcId"].as_i64().expect("tcId");
            let expected = expected_tests
                .iter()
                .find(|t| t["tcId"].as_i64() == Some(tc_id))
                .expect("expected result for every prompt case");
            out.push((group, test, expected));
        }
    }
    out
}

fn parse(s: &str) -> Value {
    serde_json::from_str(s).expect("vendored ACVP JSON parses")
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn acvp_mlkem1024_keygen() {
    let (prompt, results) = (parse(KEYGEN_PROMPT), parse(KEYGEN_RESULTS));
    let cases = zip_cases(&prompt, &results);
    assert_eq!(cases.len(), 25, "the full ML-KEM-1024 keyGen set");
    for (_group, test, expected) in cases {
        let (d, z) = (hx(&test["d"]), hx(&test["z"]));

        // The shipped custody wrapper: seed = d ‖ z (the exact split
        // `keypair_from_seed` performs) → the published ek must be NIST's.
        let mut seed = d.clone();
        seed.extend_from_slice(&z);
        let ek = signet_crypto_wasm::ek_from_seed(&seed).expect("keygen from vector seed");
        assert_eq!(ek, hx(&expected["ek"]), "tcId {} ek", test["tcId"]);

        // The dk encoding never leaves custody in the product (the seed is the
        // stored secret), so the dk half drives the crate call the wrapper
        // makes internally.
        let d_arr = B32::try_from(&d[..]).expect("32-byte d");
        let z_arr = B32::try_from(&z[..]).expect("32-byte z");
        let (dk, _ek) = MlKem1024::generate_deterministic(&d_arr, &z_arr);
        assert_eq!(
            dk.as_bytes().as_slice(),
            &hx(&expected["dk"])[..],
            "tcId {} dk",
            test["tcId"]
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn acvp_mlkem1024_encapsulation() {
    let (prompt, results) = (parse(ENCDEC_PROMPT), parse(ENCDEC_RESULTS));
    let cases = zip_cases(&prompt, &results);
    let enc: Vec<_> = cases
        .iter()
        .filter(|(g, ..)| g["function"] == "encapsulation")
        .collect();
    assert_eq!(enc.len(), 25, "the full ML-KEM-1024 encapsulation set");
    for (_, test, expected) in enc {
        let ek_bytes = hx(&test["ek"]);
        let ek_arr = ml_kem::Encoded::<Ek>::try_from(&ek_bytes[..]).expect("1568-byte ek");
        let ek = Ek::from_bytes(&ek_arr);
        let m = B32::try_from(&hx(&test["m"])[..]).expect("32-byte m");
        // The deterministic variant of the exact trait call the product's
        // `encapsulate` wrapper makes with OsRng.
        let (ct, ss) = ek
            .encapsulate_deterministic(&m)
            .expect("encapsulation never fails on a well-formed ek");
        assert_eq!(
            ct.as_slice(),
            &hx(&expected["c"])[..],
            "tcId {} c",
            test["tcId"]
        );
        assert_eq!(
            ss.as_slice(),
            &hx(&expected["k"])[..],
            "tcId {} k",
            test["tcId"]
        );
    }
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn acvp_mlkem1024_decapsulation_including_implicit_rejection() {
    let (prompt, results) = (parse(ENCDEC_PROMPT), parse(ENCDEC_RESULTS));
    let cases = zip_cases(&prompt, &results);
    let dec: Vec<_> = cases
        .iter()
        .filter(|(g, ..)| g["function"] == "decapsulation")
        .collect();
    assert_eq!(dec.len(), 10, "the full ML-KEM-1024 decapsulation set");
    for (_, test, expected) in dec {
        let dk_bytes = hx(&test["dk"]);
        let dk_arr = ml_kem::Encoded::<Dk>::try_from(&dk_bytes[..]).expect("3168-byte dk");
        let dk = Dk::from_bytes(&dk_arr);
        let ct = ml_kem::Ciphertext::<MlKem1024>::try_from(&hx(&test["c"])[..])
            .expect("1568-byte ciphertext");
        // Implicit rejection (FIPS 203 / Crypto-Spec §10): decapsulation never
        // errors — a tampered ct yields the vector's expected PSEUDORANDOM
        // secret, and the assertion is on that value, not on an error.
        let ss = dk.decapsulate(&ct).expect("decapsulation is total");
        assert_eq!(
            ss.as_slice(),
            &hx(&expected["k"])[..],
            "tcId {} k",
            test["tcId"]
        );
    }
}

/// The exclusions-ledger pin (README "Exclusions ledger"): the vendored file
/// must contain EXACTLY the four known groups — the two we run and the two
/// keyCheck groups `ml-kem 0.2.3` cannot express (`from_bytes` is unchecked;
/// no FIPS 203 §7.2/§7.3 validation API). If the vendored set or the crate's
/// expressible surface changes, this fails loudly and the ledger gets
/// re-decided instead of silently drifting.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
#[cfg_attr(not(target_arch = "wasm32"), test)]
fn acvp_vector_accounting_is_exact() {
    let prompt = parse(ENCDEC_PROMPT);
    let mut functions: Vec<(i64, String, usize)> = prompt["testGroups"]
        .as_array()
        .expect("groups")
        .iter()
        .map(|g| {
            (
                g["tgId"].as_i64().unwrap(),
                g["function"].as_str().unwrap_or("?").to_string(),
                g["tests"].as_array().map_or(0, Vec::len),
            )
        })
        .collect();
    functions.sort();
    assert_eq!(
        functions,
        vec![
            (3, "encapsulation".into(), 25),
            (6, "decapsulation".into(), 10),
            (11, "decapsulationKeyCheck".into(), 10), // excluded — see README
            (12, "encapsulationKeyCheck".into(), 10), // excluded — see README
        ],
        "the encapDecap group set drifted — re-decide the exclusions ledger"
    );

    let keygen = parse(KEYGEN_PROMPT);
    let groups = keygen["testGroups"].as_array().expect("groups");
    assert_eq!(groups.len(), 1, "keyGen: exactly the one AFT group");
    assert_eq!(groups[0]["tests"].as_array().map_or(0, Vec::len), 25);
}
