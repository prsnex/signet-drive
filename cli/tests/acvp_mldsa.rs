// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! §11.1 ACVP known-answer tests — ML-DSA-87, native target.
//!
//! The NIST ACVP demo vectors (vendored at `docs/design/test-vectors/acvp/`,
//! provenance + exclusions ledger in its README) driven through the SHIPPED
//! `ml-dsa` crate — the same `ExpandedSigningKey` / `VerifyingKey` calls the
//! product makes (software keystore keygen/sign, `server::dual_sig`
//! verification, the CLI's MF-2 response check). Native-only by design: wasm32
//! ships no ML-DSA (human signing is the classical WebAuthn passkey —
//! PQ-WebAuthn is outside v1 for vendor-gating reasons).
//!
//! Hedged (`deterministic: false`) cases inject the vector's `rnd` through a
//! fixed-output RNG handed to the crate's own `sign_randomized` /
//! `sign_mu_randomized` — the same external-interface framing the product
//! uses, no test-side reimplementation of the FIPS 204 message framing.
//!
//! `acvp_vector_accounting_is_exact` pins the exclusions ledger (the preHash /
//! HashML-DSA groups — not implemented by `ml-dsa 0.1.1`, not shipped by any
//! product surface): a crate upgrade that changes the expressible surface
//! fails the pin loudly instead of letting the ledger rot.

use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, ExpandedSigningKeyBytes, MlDsa87,
    Seed, Signature, SigningKey, VerifyingKey,
};
use serde_json::Value;

/// The FIPS 204 μ type (`B64` is crate-private in ml-dsa; the underlying
/// hybrid-array type is public through the crate's own `common` re-export).
type B64 = ml_dsa::common::array::Array<u8, ml_dsa::common::typenum::U64>;
type B32 = ml_dsa::B32;

const KEYGEN_PROMPT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../docs/design/test-vectors/acvp/ml-dsa-87.keygen.prompt.json"
));
const KEYGEN_RESULTS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../docs/design/test-vectors/acvp/ml-dsa-87.keygen.results.json"
));
const SIGGEN_PROMPT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../docs/design/test-vectors/acvp/ml-dsa-87.siggen.prompt.json"
));
const SIGGEN_RESULTS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../docs/design/test-vectors/acvp/ml-dsa-87.siggen.results.json"
));
const SIGVER_PROMPT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../docs/design/test-vectors/acvp/ml-dsa-87.sigver.prompt.json"
));
const SIGVER_RESULTS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../docs/design/test-vectors/acvp/ml-dsa-87.sigver.results.json"
));

/// A fixed-output RNG: yields exactly the vector's `rnd` bytes, then panics —
/// so a hedged ACVP case consumes precisely its 32 hedging bytes through the
/// crate's own randomized-signing entry points (rand_core 0.10 via ml-dsa's
/// `common` re-export, the same lineage the product's `SysRng` rides).
struct FixedRng<'a>(&'a [u8]);

impl ml_dsa::common::rand_core::TryRng for FixedRng<'_> {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        unreachable!("ACVP hedged signing consumes rnd via fill_bytes only")
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        unreachable!("ACVP hedged signing consumes rnd via fill_bytes only")
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        assert!(
            dst.len() <= self.0.len(),
            "signing asked for {} bytes but the vector's rnd has {}",
            dst.len(),
            self.0.len()
        );
        let (take, rest) = self.0.split_at(dst.len());
        dst.copy_from_slice(take);
        self.0 = rest;
        Ok(())
    }
}

impl ml_dsa::common::rand_core::TryCryptoRng for FixedRng<'_> {}

fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex string field")).expect("valid hex")
}

fn parse(s: &str) -> Value {
    serde_json::from_str(s).expect("vendored ACVP JSON parses")
}

/// Zip prompt/results test cases by (tgId, tcId) → (group, prompt, expected).
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

// `from_expanded`/`to_expanded` are deprecated in favor of seed custody —
// correct for product code (the product stores ξ seeds, §8.8), but the ACVP
// vectors are DEFINED over the FIPS 204 expanded encoding (sigGen provides
// `sk` as expanded bytes, never a seed), so these are the only entry points
// that can drive them.
#[allow(deprecated)]
fn sk_from_vector(test: &Value) -> ExpandedSigningKey<MlDsa87> {
    let sk_bytes = hx(&test["sk"]);
    let enc = ExpandedSigningKeyBytes::<MlDsa87>::try_from(&sk_bytes[..])
        .expect("4896-byte expanded signing key");
    ExpandedSigningKey::from_expanded(&enc)
}

fn is_prehash(group: &Value) -> bool {
    group["preHash"] == "preHash"
}

#[test]
#[allow(deprecated)] // to_expanded: the ACVP expected `sk` IS the expanded encoding (see sk_from_vector).
fn acvp_mldsa87_keygen() {
    let (prompt, results) = (parse(KEYGEN_PROMPT), parse(KEYGEN_RESULTS));
    let cases = zip_cases(&prompt, &results);
    assert_eq!(cases.len(), 25, "the full ML-DSA-87 keyGen set");
    for (_group, test, expected) in cases {
        let seed = Seed::try_from(&hx(&test["seed"])[..]).expect("32-byte seed");
        // The product's keygen path: seed → expanded key (software keystore
        // Purpose::SigningPq; §8.8 server key custody stores this ξ seed).
        let sk = SigningKey::<MlDsa87>::from_seed(&seed);
        let esk = sk.expanded_key();
        assert_eq!(
            esk.verifying_key().encode().as_slice(),
            &hx(&expected["pk"])[..],
            "tcId {} pk",
            test["tcId"]
        );
        assert_eq!(
            esk.to_expanded().as_slice(),
            &hx(&expected["sk"])[..],
            "tcId {} sk",
            test["tcId"]
        );
    }
}

#[test]
fn acvp_mldsa87_siggen_all_expressible_groups() {
    let (prompt, results) = (parse(SIGGEN_PROMPT), parse(SIGGEN_RESULTS));
    let cases = zip_cases(&prompt, &results);
    let mut ran = 0usize;
    for (group, test, expected) in cases {
        if is_prehash(group) {
            continue; // HashML-DSA — excluded, see the README ledger + accounting pin.
        }
        let sk = sk_from_vector(test);
        let deterministic = group["deterministic"]
            .as_bool()
            .expect("deterministic flag");
        let external = group["signatureInterface"] == "external";
        let external_mu = group["externalMu"].as_bool().unwrap_or(false);

        let sig: Signature<MlDsa87> = if external {
            // FIPS 204 Algorithm 2 (the product's signing surface): ctx framed
            // by the crate itself; hedged cases feed the vector's rnd through
            // the crate's own randomized entry point.
            let (message, ctx) = (hx(&test["message"]), hx(&test["context"]));
            if deterministic {
                sk.sign_deterministic(&message, &ctx).expect("ctx ≤ 255 B")
            } else {
                let rnd = hx(&test["rnd"]);
                sk.sign_randomized(&message, &ctx, &mut FixedRng(&rnd))
                    .expect("ctx ≤ 255 B; rnd supplied")
            }
        } else if external_mu {
            // Algorithm 7 over a pre-computed μ.
            let mu = B64::try_from(&hx(&test["mu"])[..]).expect("64-byte mu");
            if deterministic {
                sk.sign_mu_deterministic(&mu)
            } else {
                let rnd = hx(&test["rnd"]);
                sk.sign_mu_randomized(&mu, &mut FixedRng(&rnd))
                    .expect("rnd supplied")
            }
        } else {
            // Algorithm 7 over the raw message (rnd = 0³² when deterministic).
            let message = hx(&test["message"]);
            let rnd = if deterministic {
                B32::default()
            } else {
                B32::try_from(&hx(&test["rnd"])[..]).expect("32-byte rnd")
            };
            sk.sign_internal(&[&message], &rnd)
        };

        assert_eq!(
            sig.encode().as_slice(),
            &hx(&expected["signature"])[..],
            "tcId {} signature",
            test["tcId"]
        );
        ran += 1;
    }
    assert_eq!(ran, 90, "6 expressible sigGen groups × 15 cases");
}

#[test]
fn acvp_mldsa87_sigver_all_expressible_groups() {
    let (prompt, results) = (parse(SIGVER_PROMPT), parse(SIGVER_RESULTS));
    let cases = zip_cases(&prompt, &results);
    let mut ran = 0usize;
    for (group, test, expected) in cases {
        if is_prehash(group) {
            continue; // HashML-DSA — excluded, see the README ledger + accounting pin.
        }
        let pk_bytes = hx(&test["pk"]);
        let vk_arr = EncodedVerifyingKey::<MlDsa87>::try_from(&pk_bytes[..]).expect("2592-byte pk");
        let vk = VerifyingKey::<MlDsa87>::decode(&vk_arr);

        // The shipped decode chain (server::dual_sig / the CLI MF-2 check):
        // a signature that fails length or decode is simply invalid.
        let sig_bytes = hx(&test["signature"]);
        let verified = match EncodedSignature::<MlDsa87>::try_from(&sig_bytes[..])
            .ok()
            .and_then(|arr| Signature::<MlDsa87>::decode(&arr))
        {
            None => false,
            Some(sig) => {
                if group["signatureInterface"] == "external" {
                    vk.verify_with_context(&hx(&test["message"]), &hx(&test["context"]), &sig)
                } else if group["externalMu"].as_bool().unwrap_or(false) {
                    let mu = B64::try_from(&hx(&test["mu"])[..]).expect("64-byte mu");
                    vk.verify_mu(&mu, &sig)
                } else {
                    vk.verify_internal(&hx(&test["message"]), &sig)
                }
            }
        };

        assert_eq!(
            verified,
            expected["testPassed"].as_bool().expect("testPassed"),
            "tcId {} verdict (reason: {})",
            test["tcId"],
            test.get("reason").and_then(Value::as_str).unwrap_or("-"),
        );
        ran += 1;
    }
    assert_eq!(ran, 45, "3 expressible sigVer groups × 15 cases");
}

/// The exclusions-ledger pin (README): the vendored ML-DSA-87 sets must be
/// EXACTLY the known groups — six runnable sigGen groups + two preHash
/// (excluded), three runnable sigVer groups + one preHash (excluded), one
/// 25-case keyGen group. Any drift = re-decide the ledger, loudly.
#[test]
fn acvp_vector_accounting_is_exact() {
    let siggen = parse(SIGGEN_PROMPT);
    let mut groups: Vec<(i64, String, bool, String)> = siggen["testGroups"]
        .as_array()
        .expect("groups")
        .iter()
        .map(|g| {
            (
                g["tgId"].as_i64().unwrap(),
                g["signatureInterface"].as_str().unwrap_or("?").to_string(),
                g["deterministic"].as_bool().unwrap_or(false),
                if is_prehash(g) {
                    "preHash-EXCLUDED".to_string()
                } else if g["externalMu"].as_bool().unwrap_or(false) {
                    "externalMu".to_string()
                } else {
                    "pure".to_string()
                },
            )
        })
        .collect();
    groups.sort();
    assert_eq!(
        groups,
        vec![
            (5, "external".into(), true, "pure".into()),
            (6, "external".into(), true, "preHash-EXCLUDED".into()),
            (11, "internal".into(), true, "externalMu".into()),
            (12, "internal".into(), true, "pure".into()),
            (17, "external".into(), false, "pure".into()),
            (18, "external".into(), false, "preHash-EXCLUDED".into()),
            (23, "internal".into(), false, "externalMu".into()),
            (24, "internal".into(), false, "pure".into()),
        ],
        "the sigGen group set drifted — re-decide the exclusions ledger"
    );

    let sigver = parse(SIGVER_PROMPT);
    let mut vgroups: Vec<(i64, String, String)> = sigver["testGroups"]
        .as_array()
        .expect("groups")
        .iter()
        .map(|g| {
            (
                g["tgId"].as_i64().unwrap(),
                g["signatureInterface"].as_str().unwrap_or("?").to_string(),
                if is_prehash(g) {
                    "preHash-EXCLUDED".to_string()
                } else if g["externalMu"].as_bool().unwrap_or(false) {
                    "externalMu".to_string()
                } else {
                    "pure".to_string()
                },
            )
        })
        .collect();
    vgroups.sort();
    assert_eq!(
        vgroups,
        vec![
            (5, "external".into(), "pure".into()),
            (6, "external".into(), "preHash-EXCLUDED".into()),
            (11, "internal".into(), "externalMu".into()),
            (12, "internal".into(), "pure".into()),
        ],
        "the sigVer group set drifted — re-decide the exclusions ledger"
    );

    let keygen = parse(KEYGEN_PROMPT);
    let kgroups = keygen["testGroups"].as_array().expect("groups");
    assert_eq!(kgroups.len(), 1, "keyGen: exactly the one AFT group");
    assert_eq!(kgroups[0]["tests"].as_array().map_or(0, Vec::len), 25);
}
