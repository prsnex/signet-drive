// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

use super::*;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;
use signet_crypto::translog::{self, KeyPurpose};

const MINUTE: Duration = Duration::from_secs(60);

fn vrf_pk() -> [u8; 32] {
    signet_crypto::vrf::VrfSecretKey::from_bytes(&[7u8; 32])
        .expect("a canonical scalar")
        .public_key()
}

fn h32(b: u8) -> [u8; 32] {
    [b; 32]
}

/// Epoch 1 published to size 11 and ended; epoch 2 keyed with `pk`.
fn cut_anchors(pk: [u8; 32], genesis: [u8; 32]) -> Anchors {
    let roots = format!(
        "{}\n{}\n",
        json!({"log_size": 11, "merkle_root": hex::encode(h32(0xa4)), "committed_at": "x"}),
        json!({"epoch": 1, "epoch_end": true, "log_size": 11, "merkle_root": hex::encode(h32(0xa4))})
    );
    let keys = format!(
        "{}\n",
        json!({"epoch": 2, "vrf_suite": signet_crypto::vrf::VRF_SUITE,
               "vrf_public_key": hex::encode(pk), "genesis_entry_hash": hex::encode(genesis)})
    );
    Anchors::parse(&roots, &keys).unwrap()
}

fn epoch1_anchors() -> Anchors {
    Anchors::parse(
        &format!(
            "{}\n",
            json!({"log_size": 11, "merkle_root": hex::encode(h32(0xa4))})
        ),
        "",
    )
    .unwrap()
}

fn served(epoch: u16, key: Option<[u8; 32]>) -> ServedEpoch {
    ServedEpoch {
        epoch,
        vrf_public_key: key,
    }
}

// ---- the map and the origin -------------------------------------------------

#[test]
fn origins_normalize_and_map_to_their_anchor_repositories() {
    assert_eq!(
        normalize_origin("https://Drive.MySignet.ca/"),
        "https://drive.mysignet.ca"
    );
    assert_eq!(
        normalize_origin("https://drive.mysignet.ca/v1/x"),
        "https://drive.mysignet.ca"
    );
    assert_eq!(
        anchor_repo_for("https://drive.mysignet.ca", None).as_deref(),
        Some("prsnex/signet-drive-transparency-log")
    );
    assert_eq!(
        anchor_repo_for("https://staging.drive.mysignet.ca/", None).as_deref(),
        Some("prsnex/signet-drive-transparency-log-staging")
    );
    assert_eq!(anchor_repo_for("http://localhost:8080", None), None);
    assert_eq!(
        anchor_repo_for("http://localhost:8080", Some("me/my-log")).as_deref(),
        Some("me/my-log")
    );
}

// ---- parsing ----------------------------------------------------------------

#[test]
fn a_roots_line_without_epoch_is_epoch_1_and_end_lines_are_read() {
    let a = cut_anchors(vrf_pk(), h32(1));
    assert_eq!(a.roots[0].epoch, 1);
    assert!(!a.roots[0].epoch_end);
    assert_eq!(a.epoch_end(1).map(|r| r.log_size), Some(11));
    assert_eq!(a.latest_root(1).map(|r| r.log_size), Some(11));
    assert_eq!(a.max_epoch(), 2);
    assert!(a.carries(2).unwrap());
    assert_eq!(epoch1_anchors().max_epoch(), 1);
}

#[test]
fn a_malformed_or_foreign_suite_line_refuses_the_whole_file() {
    assert!(Anchors::parse("{not json}\n", "").is_err());
    let bad_suite = format!(
        "{}\n",
        json!({"epoch": 2, "vrf_suite": "ECVRF-EDWARDS25519-SHA512-TAI",
               "vrf_public_key": hex::encode(vrf_pk()), "genesis_entry_hash": hex::encode(h32(1))})
    );
    assert!(Anchors::parse("", &bad_suite).is_err());
}

// ---- the epoch judgement ----------------------------------------------------

#[test]
fn epoch_1_with_the_files_at_epoch_1_or_unreadable_is_legacy() {
    let a = epoch1_anchors();
    assert_eq!(
        judge_epoch(&served(1, None), Some(&a), 0, None),
        EpochVerdict::Anchored(LogMode::Legacy)
    );
    assert_eq!(
        judge_epoch(&served(1, None), None, 1, None),
        EpochVerdict::Anchored(LogMode::Legacy)
    );
}

#[test]
fn epoch_2_carried_by_both_files_with_the_same_key_anchors_v3() {
    let pk = vrf_pk();
    let a = cut_anchors(pk, h32(9));
    assert_eq!(
        judge_epoch(&served(2, Some(pk)), Some(&a), 1, None),
        EpochVerdict::Anchored(LogMode::V3 {
            epoch: 2,
            vrf_public_key: pk,
            genesis_entry_hash: h32(9)
        })
    );
}

#[test]
fn a_served_key_the_file_does_not_publish_is_a_violation() {
    let a = cut_anchors(vrf_pk(), h32(9));
    assert!(matches!(
        judge_epoch(&served(2, Some(h32(0x55))), Some(&a), 1, None),
        EpochVerdict::Violation(_)
    ));
    assert!(matches!(
        judge_epoch(&served(2, None), Some(&a), 1, None),
        EpochVerdict::Violation(_)
    ));
}

#[test]
fn a_server_ahead_of_the_files_is_unanchored_inside_the_bound_and_a_violation_past_it() {
    let a = epoch1_anchors();
    let s = served(2, Some(vrf_pk()));
    assert!(matches!(
        judge_epoch(&s, Some(&a), 1, None),
        EpochVerdict::Unanchored(_)
    ));
    assert!(matches!(
        judge_epoch(&s, Some(&a), 1, Some(14 * MINUTE)),
        EpochVerdict::Unanchored(_)
    ));
    assert!(matches!(
        judge_epoch(&s, Some(&a), 1, Some(15 * MINUTE)),
        EpochVerdict::Violation(_)
    ));
}

#[test]
fn a_key_line_without_its_end_line_is_not_yet_carried() {
    // The two files are cached separately: vrf-keys.jsonl may be fresh while
    // roots.jsonl is still the old copy.
    let keys = format!(
        "{}\n",
        json!({"epoch": 2, "vrf_suite": signet_crypto::vrf::VRF_SUITE,
               "vrf_public_key": hex::encode(vrf_pk()), "genesis_entry_hash": hex::encode(h32(9))})
    );
    let a = Anchors::parse(
        &format!(
            "{}\n",
            json!({"log_size": 11, "merkle_root": hex::encode(h32(0xa4))})
        ),
        &keys,
    )
    .unwrap();
    assert!(!a.carries(2).unwrap());
    assert!(matches!(
        judge_epoch(&served(2, Some(vrf_pk())), Some(&a), 1, None),
        EpochVerdict::Unanchored(_)
    ));
}

#[test]
fn a_server_behind_the_files_is_the_cuts_own_window_then_a_violation() {
    // Between publishing (cut step ii) and serving (iv) the files lead the box.
    let a = cut_anchors(vrf_pk(), h32(9));
    assert!(matches!(
        judge_epoch(&served(1, None), Some(&a), 1, Some(MINUTE)),
        EpochVerdict::Unanchored(_)
    ));
    assert!(matches!(
        judge_epoch(&served(1, None), Some(&a), 1, Some(15 * MINUTE)),
        EpochVerdict::Violation(_)
    ));
}

#[test]
fn the_ratchet_refuses_a_rollback_even_with_the_files_unreadable() {
    assert!(matches!(
        judge_epoch(&served(1, None), None, 2, None),
        EpochVerdict::Violation(_)
    ));
}

#[test]
fn a_later_epoch_with_the_files_unreadable_is_unanchored_never_valid() {
    assert!(matches!(
        judge_epoch(&served(2, Some(vrf_pk())), None, 1, None),
        EpochVerdict::Unanchored(_)
    ));
}

#[test]
fn two_key_lines_for_one_epoch_are_a_violation() {
    let line = json!({"epoch": 2, "vrf_suite": signet_crypto::vrf::VRF_SUITE,
                      "vrf_public_key": hex::encode(vrf_pk()), "genesis_entry_hash": hex::encode(h32(9))});
    let roots = format!(
        "{}\n",
        json!({"epoch": 1, "epoch_end": true, "log_size": 11, "merkle_root": hex::encode(h32(0xa4))})
    );
    let a = Anchors::parse(&roots, &format!("{line}\n{line}\n")).unwrap();
    assert!(matches!(
        judge_epoch(&served(2, Some(vrf_pk())), Some(&a), 1, None),
        EpochVerdict::Violation(_)
    ));
}

// ---- the genesis check ------------------------------------------------------

fn genesis_entry(payload: &[u8], created_at: u64) -> (Value, [u8; 32]) {
    let hash = translog::entry_hash_v3(
        1,
        None,
        KeyPurpose::Epoch,
        translog::EPOCH_ALGORITHM_V3,
        payload,
        created_at,
        &[0u8; 32],
    );
    let entry = json!({
        "epoch": 2, "entry_id": 1, "entry_version": 3, "account_index": null,
        "key_purpose": "epoch", "algorithm": translog::EPOCH_ALGORITHM_V3,
        "public_key": URL_SAFE_NO_PAD.encode(payload), "created_at": created_at,
        "prev_entry_hash": hex::encode([0u8; 32]), "entry_hash": hex::encode(hash),
    });
    (entry, hash)
}

fn v3_mode(pk: [u8; 32], genesis: [u8; 32]) -> LogMode {
    LogMode::V3 {
        epoch: 2,
        vrf_public_key: pk,
        genesis_entry_hash: genesis,
    }
}

#[test]
fn the_genesis_that_binds_the_end_line_and_the_key_passes() {
    let pk = vrf_pk();
    let payload = translog::epoch_payload_v3(2, 11, &h32(0xa4), &pk);
    let (entry, hash) = genesis_entry(&payload, 1_793_000_000);
    let a = cut_anchors(pk, hash);
    check_genesis(&v3_mode(pk, hash), &a, &entry).unwrap();
}

#[test]
fn a_genesis_binding_another_previous_root_is_a_violation() {
    let pk = vrf_pk();
    let payload = translog::epoch_payload_v3(2, 11, &h32(0x00), &pk);
    let (entry, hash) = genesis_entry(&payload, 1_793_000_000);
    let a = cut_anchors(pk, hash);
    assert_eq!(
        check_genesis(&v3_mode(pk, hash), &a, &entry)
            .unwrap_err()
            .code,
        "transparency_violation"
    );
}

#[test]
fn a_genesis_that_is_not_the_pinned_hash_is_a_violation() {
    let pk = vrf_pk();
    let payload = translog::epoch_payload_v3(2, 11, &h32(0xa4), &pk);
    let (entry, _) = genesis_entry(&payload, 1_793_000_000);
    let a = cut_anchors(pk, h32(0x77));
    assert!(check_genesis(&v3_mode(pk, h32(0x77)), &a, &entry).is_err());
}

#[test]
fn a_genesis_carrying_an_account_index_is_a_violation() {
    let pk = vrf_pk();
    let payload = translog::epoch_payload_v3(2, 11, &h32(0xa4), &pk);
    let (mut entry, hash) = genesis_entry(&payload, 1_793_000_000);
    entry["account_index"] = json!(hex::encode([1u8; 64]));
    let a = cut_anchors(pk, hash);
    assert!(check_genesis(&v3_mode(pk, hash), &a, &entry).is_err());
}

// ---- the state --------------------------------------------------------------

#[test]
fn anchoring_raises_the_ratchet_and_clears_the_sighting() {
    let mut st = OriginState::default();
    update_state(&mut st, 2, &EpochVerdict::Unanchored("x".into()), 100);
    update_state(&mut st, 2, &EpochVerdict::Unanchored("x".into()), 900);
    assert_eq!(
        st.first_unanchored.get(&2),
        Some(&100),
        "the FIRST sighting is kept"
    );
    update_state(
        &mut st,
        2,
        &EpochVerdict::Anchored(v3_mode(vrf_pk(), h32(9))),
        1000,
    );
    assert_eq!(st.highest_epoch, 2);
    assert!(
        st.first_unanchored.is_empty(),
        "a completed cut leaves no sighting behind"
    );
}

#[test]
fn the_state_round_trips_and_keeps_other_origins() {
    let dir = std::env::temp_dir().join(format!("signet-anchors-test-{}", std::process::id()));
    let path = dir.join("translog-state.json");
    let _ = std::fs::remove_dir_all(&dir);
    let mut a = OriginState {
        highest_epoch: 2,
        ..Default::default()
    };
    a.first_unanchored.insert(3, 42);
    save_state(&path, "https://a.example", &a).unwrap();
    save_state(&path, "https://b.example", &OriginState::default()).unwrap();
    assert_eq!(load_state(&path, "https://a.example"), a);
    assert_eq!(
        load_state(&path, "https://c.example"),
        OriginState::default()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---- bug256: the leaf bound to the key asked about --------------------------

/// The P-256 base point G, X9.63 uncompressed: a valid point, so the SPKI
/// fingerprint rule applies to it.
fn p256_g() -> Vec<u8> {
    hex::decode(
        "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
         4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
    )
    .unwrap()
}

fn v3_entry(pk: &[u8], purpose: &str, kp: KeyPurpose) -> Value {
    let index = [0x5au8; 64];
    let prev = h32(0x11);
    let hash = translog::entry_hash_v3(
        7,
        Some(&index),
        kp,
        "ECDH-ES+A256KW",
        pk,
        1_793_000_000,
        &prev,
    );
    json!({
        "epoch": 2, "entry_id": 7, "entry_version": 3, "account_index": hex::encode(index),
        "key_purpose": purpose, "algorithm": "ECDH-ES+A256KW",
        "public_key": URL_SAFE_NO_PAD.encode(pk),
        "public_key_fingerprint": fingerprint_for(purpose, pk).unwrap(),
        "created_at": 1_793_000_000u64, "prev_entry_hash": hex::encode(prev),
        "entry_hash": hex::encode(hash),
    })
}

#[test]
fn a_served_entry_for_the_asked_key_binds_and_returns_the_recomputed_leaf() {
    let g = p256_g();
    let e = v3_entry(&g, "kem", KeyPurpose::Kem);
    let fp = signet_crypto::pubkey::fingerprint(&g).unwrap();
    let leaf = bind_leaf(&e, Some(&fp), Some("kem")).unwrap();
    assert_eq!(hex::encode(leaf), e["entry_hash"].as_str().unwrap());
}

#[test]
fn a_genuine_entry_for_another_key_is_refused() {
    // bug256 control 1: the server answers a question about key X with a real,
    // self-consistent entry for some other key.
    let e = v3_entry(&p256_g(), "kem", KeyPurpose::Kem);
    let other = "ab".repeat(32);
    assert_eq!(
        bind_leaf(&e, Some(&other), Some("kem")).unwrap_err().code,
        "transparency_violation"
    );
}

#[test]
fn an_altered_public_key_is_refused() {
    // bug256 control 2: the key in the response is not the key that was hashed.
    let mut e = v3_entry(&p256_g(), "kem", KeyPurpose::Kem);
    let mut pk = p256_g();
    pk[40] ^= 1;
    e["public_key"] = json!(URL_SAFE_NO_PAD.encode(&pk));
    assert!(bind_leaf(&e, None, None).is_err());
}

#[test]
fn an_entry_of_another_purpose_is_refused() {
    // bug256 control 3: right key bytes, wrong purpose.
    let g = p256_g();
    let e = v3_entry(&g, "signing", KeyPurpose::Signing);
    let fp = signet_crypto::pubkey::fingerprint(&g).unwrap();
    assert_eq!(
        bind_leaf(&e, Some(&fp), Some("kem")).unwrap_err().code,
        "transparency_violation"
    );
}

#[test]
fn a_fingerprint_that_is_not_the_keys_own_is_refused() {
    let mut e = v3_entry(&p256_g(), "kem", KeyPurpose::Kem);
    e["public_key_fingerprint"] = json!("cd".repeat(32));
    assert!(bind_leaf(&e, None, None).is_err());
}

#[test]
fn an_old_server_that_serves_no_entry_is_not_verified() {
    let mut e = v3_entry(&p256_g(), "kem", KeyPurpose::Kem);
    e.as_object_mut().unwrap().remove("public_key");
    let err = bind_leaf(&e, None, None).unwrap_err();
    assert_eq!(err.code, "invalid_data");
    assert!(err.message.contains("NOT verified"), "{}", err.message);
}

#[test]
fn a_v2_entry_binds_under_the_v2_rule() {
    let g = p256_g();
    let acct = uuid::Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
    let prev = h32(0x22);
    let hash = translog::entry_hash_v2(
        4,
        Some(acct.as_bytes()),
        KeyPurpose::Kem,
        "ECDH-ES+A256KW",
        &g,
        9,
        &prev,
    );
    let e = json!({
        "entry_id": 4, "entry_version": 2, "account_id": acct.to_string(),
        "key_purpose": "kem", "algorithm": "ECDH-ES+A256KW",
        "public_key": URL_SAFE_NO_PAD.encode(&g),
        "public_key_fingerprint": signet_crypto::pubkey::fingerprint(&g).unwrap(),
        "created_at": 9, "prev_entry_hash": hex::encode(prev), "entry_hash": hex::encode(hash),
    });
    assert_eq!(bind_leaf(&e, None, Some("kem")).unwrap(), hash);
}

#[test]
fn the_pq_and_epoch_purposes_use_the_raw_fingerprint() {
    let raw = vec![9u8; 1568];
    assert_eq!(
        fingerprint_for("kem_pq", &raw).unwrap(),
        signet_crypto::pubkey::fingerprint_raw(&raw)
    );
    assert_eq!(
        fingerprint_for("epoch", b"x").unwrap(),
        signet_crypto::pubkey::fingerprint_raw(b"x")
    );
    assert!(
        fingerprint_for("kem", &raw).is_err(),
        "a PQ-sized key is not a P-256 point"
    );
}

// ---- an account's index (§10.6) ---------------------------------------------

const ACCOUNT: &str = "00000000-0000-4000-8000-00000000cafe";

fn vrf_sk() -> signet_crypto::vrf::VrfSecretKey {
    signet_crypto::vrf::VrfSecretKey::from_bytes(&[7u8; 32]).expect("a canonical scalar")
}

#[test]
fn an_accounts_index_is_what_its_proof_yields_under_the_pinned_key() {
    let account = uuid::Uuid::parse_str(ACCOUNT).unwrap();
    let (index, proof) = vrf_sk().prove(account.as_bytes()).unwrap();
    let got = account_index(&vrf_pk(), ACCOUNT, Some(&hex::encode(proof)), "t").unwrap();
    assert_eq!(got, index);
}

#[test]
fn a_proof_under_another_epoch_key_is_a_substitution() {
    let account = uuid::Uuid::parse_str(ACCOUNT).unwrap();
    let other = signet_crypto::vrf::VrfSecretKey::from_bytes(&[9u8; 32]).unwrap();
    let (_, proof) = other.prove(account.as_bytes()).unwrap();
    let err = account_index(&vrf_pk(), ACCOUNT, Some(&hex::encode(proof)), "t").unwrap_err();
    assert_eq!(err.exit_code, 60);
}

#[test]
fn a_missing_or_malformed_proof_binds_nothing() {
    let err = account_index(&vrf_pk(), ACCOUNT, None, "t").unwrap_err();
    assert_eq!(err.exit_code, 60);
    let err = account_index(&vrf_pk(), ACCOUNT, Some("abcd"), "t").unwrap_err();
    assert_eq!(err.exit_code, 60);
    let err = account_index(&vrf_pk(), "not-a-uuid", Some(&"00".repeat(80)), "t").unwrap_err();
    assert_eq!(err.code, "invalid_data");
}

// ---- the owner's watch (§2b) --------------------------------------------------

const OWN: [u8; 64] = [0x0a; 64];
const OTHER: [u8; 64] = [0x0b; 64];

fn p256_key() -> Vec<u8> {
    signet_crypto::ecdsa::generate_keypair().1
}

/// A self-consistent v3 entry at `id`, under `index` (None: account-less).
fn epoch_entry(
    id: u64,
    index: Option<[u8; 64]>,
    purpose: &str,
    kp: KeyPurpose,
    pk: &[u8],
) -> Value {
    let prev = h32(id as u8);
    let hash = translog::entry_hash_v3(id, index.as_ref(), kp, "alg", pk, 1_793_000_000, &prev);
    json!({
        "epoch": 2, "entry_id": id, "entry_version": 3, "account_index": index.map(hex::encode),
        "key_purpose": purpose, "algorithm": "alg", "public_key": URL_SAFE_NO_PAD.encode(pk),
        "public_key_fingerprint": fingerprint_for(purpose, pk).unwrap(),
        "created_at": 1_793_000_000u64, "prev_entry_hash": hex::encode(prev),
        "entry_hash": hex::encode(hash),
    })
}

fn published_over(entries: &[Value]) -> RootLine {
    let leaves: Vec<[u8; 32]> = entries
        .iter()
        .map(|e| bind_leaf(e, None, None).unwrap())
        .collect();
    RootLine {
        epoch: 2,
        log_size: entries.len() as u64,
        merkle_root: signet_crypto::merkle::merkle_root(&leaves),
        epoch_end: false,
    }
}

/// An epoch of four: the genesis, my signing key, another account's KEM key,
/// my KEM key. I hold my two.
fn watched_epoch() -> (Vec<Value>, Vec<(&'static str, String)>) {
    let (mine_s, other_k, mine_k) = (p256_key(), p256_key(), p256_key());
    let entries = vec![
        epoch_entry(1, None, "epoch", KeyPurpose::Epoch, b"genesis payload"),
        epoch_entry(2, Some(OWN), "signing", KeyPurpose::Signing, &mine_s),
        epoch_entry(3, Some(OTHER), "kem", KeyPurpose::Kem, &other_k),
        epoch_entry(4, Some(OWN), "kem", KeyPurpose::Kem, &mine_k),
    ];
    let held = vec![
        ("signing", fingerprint_for("signing", &mine_s).unwrap()),
        ("kem", fingerprint_for("kem", &mine_k).unwrap()),
    ];
    (entries, held)
}

#[test]
fn the_watch_is_clean_when_every_key_under_my_index_is_mine() {
    let (entries, held) = watched_epoch();
    let w = owner_watch(&entries, 2, &published_over(&entries), &OWN, &held).unwrap();
    assert_eq!(w.verdict, "clean");
    assert_eq!(w.entries.len(), 2, "only my two entries are reported");
    assert!(w.entries.iter().all(|e| e["held"] == true));
}

#[test]
fn a_key_under_my_index_that_i_do_not_hold_is_reported_foreign() {
    let (mut entries, held) = watched_epoch();
    let rogue = p256_key();
    entries.push(epoch_entry(5, Some(OWN), "kem", KeyPurpose::Kem, &rogue));
    let w = owner_watch(&entries, 2, &published_over(&entries), &OWN, &held).unwrap();
    assert_eq!(w.verdict, "foreign_key");
    assert_eq!(w.foreign, vec![fingerprint_for("kem", &rogue).unwrap()]);
}

#[test]
fn a_held_key_outside_the_published_prefix_is_not_yet_published() {
    let (entries, mut held) = watched_epoch();
    held.push((
        "signing_pq",
        fingerprint_for("signing_pq", b"a later key").unwrap(),
    ));
    let w = owner_watch(&entries, 2, &published_over(&entries), &OWN, &held).unwrap();
    assert_eq!(w.verdict, "not_yet_published");
    assert_eq!(w.unlogged.len(), 1);
}

#[test]
fn a_server_that_swaps_out_my_rogue_entry_fails_the_published_root() {
    // The log as published holds a rogue key under my index at 5. Serving me a
    // self-consistent entry for another account in its place hides it from a
    // scan that does not hold the scan to the published root.
    let (mut entries, held) = watched_epoch();
    entries.push(epoch_entry(
        5,
        Some(OWN),
        "kem",
        KeyPurpose::Kem,
        &p256_key(),
    ));
    let published = published_over(&entries);
    entries[4] = epoch_entry(5, Some(OTHER), "kem", KeyPurpose::Kem, &p256_key());
    let err = owner_watch(&entries, 2, &published, &OWN, &held).unwrap_err();
    assert_eq!(err.code, "transparency_violation");
    assert!(err.message.contains("published root"), "{}", err.message);
}

#[test]
fn a_short_or_out_of_order_scan_is_refused() {
    let (entries, held) = watched_epoch();
    let published = published_over(&entries);
    let err = owner_watch(&entries[..3], 2, &published, &OWN, &held).unwrap_err();
    assert_eq!(err.code, "transparency_violation");
    let mut swapped = entries.clone();
    swapped.swap(1, 2);
    let err = owner_watch(&swapped, 2, &published, &OWN, &held).unwrap_err();
    assert_eq!(err.code, "transparency_violation");
}

// ---- the write path's cache (#651 ruling 3) -----------------------------------

const REPO: &str = "prsnex/test-anchors";
const NOW: u64 = 1_800_000_000;

/// Epoch 1 published three times, as `roots.jsonl` reads before any cut.
fn epoch1_roots() -> String {
    [5u64, 9, 11]
        .iter()
        .map(|n| {
            json!({"log_size": n, "merkle_root": hex::encode(h32(*n as u8)), "committed_at": "x"})
                .to_string()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// After the cut: epoch 1 ended at 11, epoch 2 published twice, keyed with `pk`.
fn cut_files(pk: [u8; 32], genesis: [u8; 32]) -> (String, String) {
    let roots = format!(
        "{}\n{}\n{}\n{}\n",
        epoch1_roots(),
        json!({"epoch": 1, "epoch_end": true, "log_size": 11, "merkle_root": hex::encode(h32(11))}),
        json!({"epoch": 2, "log_size": 1, "merkle_root": hex::encode(h32(0x21))}),
        json!({"epoch": 2, "log_size": 3, "merkle_root": hex::encode(h32(0x23))}),
    );
    let keys = format!(
        "{}\n",
        json!({"epoch": 2, "vrf_suite": signet_crypto::vrf::VRF_SUITE,
               "vrf_public_key": hex::encode(pk), "genesis_entry_hash": hex::encode(genesis)})
    );
    (roots, keys)
}

fn cached_state(roots: &str, keys: &str, age: u64, genesis_checked: Option<u16>) -> OriginState {
    let mut cache = AnchorCache::new(REPO, NOW - age, roots, keys).expect("the files parse");
    cache.genesis_checked = genesis_checked;
    OriginState {
        anchor_cache: Some(cache),
        ..Default::default()
    }
}

#[test]
fn the_cache_keeps_end_lines_and_each_epochs_latest_root_and_judges_as_the_files() {
    let (roots, keys) = cut_files(vrf_pk(), h32(0x99));
    let cache = AnchorCache::new(REPO, NOW, &roots, &keys).unwrap();
    assert_eq!(
        cache.roots_jsonl.lines().count(),
        3,
        "{}",
        cache.roots_jsonl
    );
    let (cached, full) = (
        cache.anchors().unwrap(),
        Anchors::parse(&roots, &keys).unwrap(),
    );
    assert_eq!(cached.max_epoch(), full.max_epoch());
    assert_eq!(cached.carries(2).unwrap(), full.carries(2).unwrap());
    assert_eq!(cached.epoch_end(1), full.epoch_end(1));
}

#[test]
fn a_young_cache_answers_epoch_1_without_a_read() {
    let state = cached_state(&epoch1_roots(), "", 60, None);
    let (verdict, _) = cached_verdict(&state, &served(1, None), REPO, NOW).expect("cached");
    assert_eq!(verdict, EpochVerdict::Anchored(LogMode::Legacy));
}

#[test]
fn a_cache_as_old_as_the_max_merge_delay_reads_fresh() {
    let state = cached_state(&epoch1_roots(), "", ANCHOR_CACHE_MAX_AGE.as_secs(), None);
    assert!(cached_verdict(&state, &served(1, None), REPO, NOW).is_none());
}

#[test]
fn a_cache_from_another_repository_reads_fresh() {
    let state = cached_state(&epoch1_roots(), "", 60, None);
    assert!(cached_verdict(&state, &served(1, None), "prsnex/other", NOW).is_none());
}

#[test]
fn a_server_ahead_of_the_cache_reads_fresh() {
    let state = cached_state(&epoch1_roots(), "", 60, None);
    assert!(cached_verdict(&state, &served(2, Some(vrf_pk())), REPO, NOW).is_none());
}

#[test]
fn a_server_behind_the_cache_reads_fresh() {
    // The case the bounded age exists for: the cache knows epoch 2 and the
    // server still serves epoch 1, so the cache must not answer.
    let (roots, keys) = cut_files(vrf_pk(), h32(0x99));
    let state = cached_state(&roots, &keys, 60, Some(2));
    assert!(cached_verdict(&state, &served(1, None), REPO, NOW).is_none());
}

#[test]
fn a_served_key_unlike_the_cached_line_reads_fresh() {
    let (roots, keys) = cut_files(vrf_pk(), h32(0x99));
    let state = cached_state(&roots, &keys, 60, Some(2));
    assert!(cached_verdict(&state, &served(2, Some([8u8; 32])), REPO, NOW).is_none());
}

#[test]
fn an_epoch_2_cache_answers_only_once_its_genesis_is_checked() {
    let (roots, keys) = cut_files(vrf_pk(), h32(0x99));
    let unchecked = cached_state(&roots, &keys, 60, None);
    assert!(cached_verdict(&unchecked, &served(2, Some(vrf_pk())), REPO, NOW).is_none());
    let checked = cached_state(&roots, &keys, 60, Some(2));
    let (verdict, _) =
        cached_verdict(&checked, &served(2, Some(vrf_pk())), REPO, NOW).expect("cached");
    assert_eq!(
        verdict,
        EpochVerdict::Anchored(v3_mode(vrf_pk(), h32(0x99)))
    );
}

#[test]
fn the_cache_round_trips_through_the_state_file() {
    let dir = std::env::temp_dir().join(format!("signet-anchors-cache-{}", std::process::id()));
    let path = dir.join("translog-state.json");
    let _ = std::fs::remove_dir_all(&dir);
    let (roots, keys) = cut_files(vrf_pk(), h32(0x99));
    let state = cached_state(&roots, &keys, 60, Some(2));
    save_state(&path, "https://a.example", &state).unwrap();
    assert_eq!(load_state(&path, "https://a.example"), state);
    let _ = std::fs::remove_dir_all(&dir);
}
