// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! The hybrid content-wrap **cross-surface goldens** (PQR Spec §11.4 — the P2
//! exit gate): one committed fixture
//! (`docs/design/test-vectors/golden/hybrid-crossover.json`) holding a fixed
//! hybrid recipient, a fixed key, and envelopes produced independently by
//! BOTH surfaces — the Rust writer (`cli::hybrid::wrap_key_hybrid`, the same
//! path `signet upload` runs) and the web writer (`hybrid_wrap.ts`, generated
//! by its vitest twin `hybrid.crossover.test.ts`). Each surface's suite
//! unwraps the OTHER surface's envelopes byte-for-byte — the S059/S068
//! byte-identical human↔PRSN crossover, re-run over the hybrid alg-ID.
//!
//! The recipient's software keys stand in for the keystore here (this is the
//! crypto crossover, not a keystore test — the keystore reader path is
//! `cli::hybrid::unwrap_key_hybrid`, covered by the in-crate round-trip and
//! the E2E harness). Regenerate the fixture with the `#[ignore]`d generator
//! below (`cargo test -p signet-cli --test hybrid_crossover -- --ignored
//! --nocapture`) + the web twin's skipped generator; envelopes embed random
//! ephemerals, so regenerated fixtures differ — any valid sample pins the
//! crossover equally.

use kem::Decapsulate;
use ml_kem::{EncodedSizeUser, KemCore, MlKem1024};
use signet_crypto::hybrid_wrap::{self, HybridWrapEnvelope};

const GOLDEN: &str = include_str!("../../docs/design/test-vectors/golden/hybrid-crossover.json");

/// The committed recipient: scalar/seed are fixed test constants (see the
/// generator), never production key material.
struct Recipient {
    scalar: [u8; 32],
    pub_x963: Vec<u8>,
    seed_d: ml_kem::B32,
    seed_z: ml_kem::B32,
    ek: Vec<u8>,
}

fn recipient(golden: &serde_json::Value) -> Recipient {
    let r = &golden["recipient"];
    let scalar: [u8; 32] = hex::decode(r["p256_private_scalar_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let seed = hex::decode(r["mlkem_seed_hex"].as_str().unwrap()).unwrap();
    Recipient {
        scalar,
        pub_x963: hex::decode(r["p256_public_x963_hex"].as_str().unwrap()).unwrap(),
        seed_d: ml_kem::B32::try_from(&seed[..32]).unwrap(),
        seed_z: ml_kem::B32::try_from(&seed[32..]).unwrap(),
        ek: hex::decode(r["mlkem_ek_hex"].as_str().unwrap()).unwrap(),
    }
}

/// Software recipient-side unwrap: ECDH with the committed scalar + ML-KEM
/// decap with the seed-regenerated key, then the §5.3 two-shared-secret path.
fn unwrap(env: &HybridWrapEnvelope, r: &Recipient, party_v: &[u8]) -> [u8; 32] {
    use base64::Engine;
    let epk = env.ephemeral_pubkey_x963().expect("epk");
    let z_ecdh = signet_crypto::ecdh::ecdh_p256(&r.scalar, &epk).expect("ecdh");
    let ek_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(env.ek.as_bytes())
        .expect("ek b64u");
    let (dk, _) = MlKem1024::generate_deterministic(&r.seed_d, &r.seed_z);
    let ct = ml_kem::Ciphertext::<MlKem1024>::try_from(&ek_bytes[..]).expect("ct");
    let z_mlkem: [u8; 32] = dk.decapsulate(&ct).expect("decap").into();
    hybrid_wrap::unwrap_with_shared_secrets(&z_ecdh, &z_mlkem, env, &r.pub_x963, &r.ek, party_v)
        .expect("unwrap")
}

#[test]
fn both_surfaces_envelopes_unwrap_to_the_committed_key() {
    let golden: serde_json::Value = serde_json::from_str(GOLDEN).expect("golden json");
    let r = recipient(&golden);
    let key: [u8; 32] = hex::decode(golden["key_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let root: [u8; 16] = hex::decode(golden["root_folder_id_hex"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();

    // The four committed envelopes: {rust, web} × {dek, metadata}. The web
    // pair is the CROSSOVER (TS-produced, Rust-unwrapped); the rust pair is
    // the same-surface regression baseline.
    for (name, party_v) in [
        ("rust_envelope_dek", &[][..]),
        ("web_envelope_dek", &[][..]),
        ("rust_envelope_metadata", &root[..]),
        ("web_envelope_metadata", &root[..]),
    ] {
        let env: HybridWrapEnvelope = serde_json::from_value(golden[name].clone())
            .unwrap_or_else(|e| panic!("{name} parse: {e}"));
        assert_eq!(env.alg, "ECDH-ES+ML-KEM-1024+A256KW", "{name} alg");
        assert_eq!(unwrap(&env, &r, party_v), key, "{name} key bytes");
    }
}

/// Regenerates the RUST half of the fixture (prints JSON to stdout). The web
/// half comes from the skipped generator in `hybrid.crossover.test.ts`.
#[test]
#[ignore = "fixture generator — run manually with --nocapture"]
fn generate_rust_fixture_half() {
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    let scalar = [0x11u8; 32];
    let sk = p256::SecretKey::from_slice(&scalar).expect("scalar");
    let public = sk.public_key().to_encoded_point(false);
    let pub_x963 = public.as_bytes().to_vec();

    let seed = [0x24u8; 64];
    let d = ml_kem::B32::try_from(&seed[..32]).unwrap();
    let z = ml_kem::B32::try_from(&seed[32..]).unwrap();
    let (_dk, ek_obj) = MlKem1024::generate_deterministic(&d, &z);
    let ek = ek_obj.as_bytes().to_vec();

    let key = [0x0fu8; 32];
    let root = [0xabu8; 16];

    let env_dek = signet_cli::hybrid::wrap_key_hybrid(&pub_x963, &ek, &key, &[]).expect("wrap dek");
    let env_meta =
        signet_cli::hybrid::wrap_key_hybrid(&pub_x963, &ek, &key, &root).expect("wrap meta");

    // The recipient JWK the web side imports (d + x + y, base64url).
    use base64::Engine;
    let b64 = |b: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b);
    let jwk = serde_json::json!({
        "kty": "EC", "crv": "P-256",
        "d": b64(&scalar),
        "x": b64(&pub_x963[1..33]),
        "y": b64(&pub_x963[33..65]),
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "recipient": {
                "p256_private_scalar_hex": hex::encode(scalar),
                "p256_private_jwk": jwk,
                "p256_public_x963_hex": hex::encode(&pub_x963),
                "mlkem_seed_hex": hex::encode(seed),
                "mlkem_ek_hex": hex::encode(&ek),
            },
            "key_hex": hex::encode(key),
            "root_folder_id_hex": hex::encode(root),
            "rust_envelope_dek": env_dek,
            "rust_envelope_metadata": env_meta,
        }))
        .unwrap()
    );
}
