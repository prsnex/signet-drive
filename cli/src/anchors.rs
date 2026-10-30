// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! The transparency log's public anchors, and the epoch a server may be in
//! (Transparency-Log Epoch-2 design v05 §2a, §5, §10.7–§10.9).
//!
//! The anchors are two append-only files in a public repository the CLI knows
//! by itself, never one the server names: `roots.jsonl` (published Merkle roots,
//! one end line per retired epoch) and `vrf-keys.jsonl` (each epoch's VRF public
//! key and the hash of its genesis entry). The CLI reads them without a
//! credential from `raw.githubusercontent.com`.
//!
//! [`judge_epoch`] decides, from the epoch the server serves and what the files
//! carry, which receipt rule applies:
//! - **Legacy** (epoch 1: v1-shape receipts, bound by `account_id`), while
//!   neither the files nor this CLI's own memory show a later epoch;
//! - **V3** (epoch ≥ 2: v2-shape receipts, bound through the epoch's pinned VRF
//!   key), only when both files carry the epoch;
//! - **Unanchored**, a stated, non-alarming verdict, while the files and the
//!   server disagree for less than [`TRANSITION_BOUND`] (the anchor files are
//!   CDN-cached for ~5 minutes, and a cut publishes before it serves);
//! - **Violation** past that bound, on a served VRF key the file does not carry,
//!   or on a server serving an epoch below one this CLI has already seen.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::Value;

use crate::error::{CliError, Result};

/// How long the files and the server may disagree about the epoch before the
/// disagreement is a violation (Gus, design v05 build terms). The first
/// sighting is kept in local state per `(origin, epoch)`, because the server's
/// clock cannot bound the server.
pub const TRANSITION_BOUND: Duration = Duration::from_secs(15 * 60);

/// The anchor repository for each server origin this CLI ships knowing.
/// A self-run server passes `--anchor-repo` / `SIGNET_ANCHOR_REPO` instead.
const KNOWN_ANCHORS: &[(&str, &str)] = &[
    (
        "https://drive.mysignet.ca",
        "prsnex/signet-drive-transparency-log",
    ),
    (
        "https://staging.drive.mysignet.ca",
        "prsnex/signet-drive-transparency-log-staging",
    ),
];

/// The anchor repository for `server_url`: the explicit override if given,
/// else the compiled-in map. `None` for a server this CLI does not know.
pub fn anchor_repo_for(server_url: &str, override_repo: Option<&str>) -> Option<String> {
    if let Some(repo) = override_repo.filter(|r| !r.trim().is_empty()) {
        return Some(repo.trim().to_string());
    }
    let origin = normalize_origin(server_url);
    KNOWN_ANCHORS
        .iter()
        .find(|(o, _)| *o == origin)
        .map(|(_, repo)| (*repo).to_string())
}

/// `https://Host/…/` → `https://host`, the key the map and the state use.
pub fn normalize_origin(server_url: &str) -> String {
    let trimmed = server_url.trim().trim_end_matches('/');
    let (scheme, rest) = trimmed.split_once("://").unwrap_or(("https", trimmed));
    let host = rest.split('/').next().unwrap_or(rest);
    format!(
        "{}://{}",
        scheme.to_ascii_lowercase(),
        host.to_ascii_lowercase()
    )
}

/// One `roots.jsonl` line. A line without `epoch` is epoch 1 (§4: existing
/// lines are never rewritten).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootLine {
    pub epoch: u16,
    pub log_size: u64,
    pub merkle_root: [u8; 32],
    pub epoch_end: bool,
}

/// One `vrf-keys.jsonl` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochKey {
    pub epoch: u16,
    pub vrf_public_key: [u8; signet_crypto::vrf::PUBLIC_KEY_LEN],
    pub genesis_entry_hash: [u8; 32],
}

/// Both files, parsed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Anchors {
    pub roots: Vec<RootLine>,
    pub keys: Vec<EpochKey>,
}

fn hex32(v: Option<&Value>, what: &str) -> Result<[u8; 32]> {
    let s = v
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::invalid_data(format!("anchor line missing {what}")))?;
    hex::decode(s)
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| CliError::invalid_data(format!("anchor line {what} is not 32-byte hex")))
}

fn epoch_of(line: &Value) -> Result<u16> {
    match line.get("epoch") {
        None => Ok(1),
        Some(v) => v
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .filter(|n| *n >= 1)
            .ok_or_else(|| CliError::invalid_data("anchor line epoch is not a positive u16")),
    }
}

impl Anchors {
    /// Parse both files. `keys_jsonl` is empty before the first cut (the file
    /// does not exist yet). Blank lines are skipped; any malformed line fails
    /// the whole parse, since a file we cannot read whole anchors nothing.
    pub fn parse(roots_jsonl: &str, keys_jsonl: &str) -> Result<Self> {
        let mut roots = Vec::new();
        for line in roots_jsonl.lines().filter(|l| !l.trim().is_empty()) {
            let v: Value = serde_json::from_str(line)
                .map_err(|e| CliError::invalid_data(format!("roots.jsonl line: {e}")))?;
            roots.push(RootLine {
                epoch: epoch_of(&v)?,
                log_size: v
                    .get("log_size")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| CliError::invalid_data("roots.jsonl line missing log_size"))?,
                merkle_root: hex32(v.get("merkle_root"), "merkle_root")?,
                epoch_end: v.get("epoch_end").and_then(Value::as_bool) == Some(true),
            });
        }
        let mut keys = Vec::new();
        for line in keys_jsonl.lines().filter(|l| !l.trim().is_empty()) {
            let v: Value = serde_json::from_str(line)
                .map_err(|e| CliError::invalid_data(format!("vrf-keys.jsonl line: {e}")))?;
            if v.get("vrf_suite").and_then(Value::as_str) != Some(signet_crypto::vrf::VRF_SUITE) {
                return Err(CliError::invalid_data(
                    "vrf-keys.jsonl line names a suite this CLI does not implement",
                ));
            }
            keys.push(EpochKey {
                epoch: epoch_of(&v)?,
                vrf_public_key: hex32(v.get("vrf_public_key"), "vrf_public_key")?,
                genesis_entry_hash: hex32(v.get("genesis_entry_hash"), "genesis_entry_hash")?,
            });
        }
        Ok(Self { roots, keys })
    }

    /// The epoch's VRF key line. Two lines for one epoch is itself a
    /// disagreement, so it answers `Err`.
    pub fn key(&self, epoch: u16) -> Result<Option<&EpochKey>> {
        let mut found = self.keys.iter().filter(|k| k.epoch == epoch);
        let first = found.next();
        if found.next().is_some() {
            return Err(CliError::transparency_violation(format!(
                "vrf-keys.jsonl carries two lines for epoch {epoch}"
            )));
        }
        Ok(first)
    }

    /// The end line of `epoch`, if it has ended.
    pub fn epoch_end(&self, epoch: u16) -> Option<&RootLine> {
        self.roots.iter().find(|r| r.epoch == epoch && r.epoch_end)
    }

    /// The latest published (non-end) root of `epoch`.
    pub fn latest_root(&self, epoch: u16) -> Option<&RootLine> {
        self.roots
            .iter()
            .filter(|r| r.epoch == epoch && !r.epoch_end)
            .max_by_key(|r| r.log_size)
    }

    /// The highest epoch either file shows: a key line, or an end line, which
    /// implies its successor exists.
    pub fn max_epoch(&self) -> u16 {
        let from_keys = self.keys.iter().map(|k| k.epoch).max().unwrap_or(1);
        let from_ends = self
            .roots
            .iter()
            .filter(|r| r.epoch_end)
            .map(|r| r.epoch.saturating_add(1))
            .max()
            .unwrap_or(1);
        let from_roots = self.roots.iter().map(|r| r.epoch).max().unwrap_or(1);
        from_keys.max(from_ends).max(from_roots)
    }

    /// Whether both files carry `epoch` (a key line, and the end line of the
    /// epoch before it). Epoch 1 needs neither.
    pub fn carries(&self, epoch: u16) -> Result<bool> {
        if epoch <= 1 {
            return Ok(true);
        }
        Ok(self.key(epoch)?.is_some() && self.epoch_end(epoch - 1).is_some())
    }
}

/// Which receipt rule applies to a server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogMode {
    /// Epoch 1: v1-shape receipts, bound by `account_id`.
    Legacy,
    /// Epoch ≥ 2: v2-shape receipts, bound through the pinned VRF key.
    V3 {
        epoch: u16,
        vrf_public_key: [u8; signet_crypto::vrf::PUBLIC_KEY_LEN],
        genesis_entry_hash: [u8; 32],
    },
}

/// The epoch judgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochVerdict {
    Anchored(LogMode),
    /// The files and the server disagree, inside the bound: say so, retry later.
    Unanchored(String),
    Violation(String),
}

/// What the server serves about its epoch (`/v1/server-info` `translog`;
/// absent = epoch 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServedEpoch {
    pub epoch: u16,
    pub vrf_public_key: Option<[u8; signet_crypto::vrf::PUBLIC_KEY_LEN]>,
}

impl ServedEpoch {
    /// Read the `translog` object of a `/v1/server-info` body.
    pub fn from_server_info(info: &Value) -> Result<Self> {
        let Some(t) = info.get("translog") else {
            return Ok(Self {
                epoch: 1,
                vrf_public_key: None,
            });
        };
        let epoch = epoch_of(t)?;
        let vrf_public_key = match t.get("vrf_public_key") {
            None | Some(Value::Null) => None,
            v => Some(hex32(v, "translog.vrf_public_key")?),
        };
        if let Some(suite) = t.get("vrf_suite").and_then(Value::as_str)
            && suite != signet_crypto::vrf::VRF_SUITE
        {
            return Err(CliError::transparency_violation(format!(
                "server-info names VRF suite {suite}, which this CLI does not implement"
            )));
        }
        Ok(Self {
            epoch,
            vrf_public_key,
        })
    }
}

/// The pure decision. `highest_seen` is the highest epoch this CLI has ever
/// anchored for the origin (the ratchet); `first_unanchored_age` is how long
/// ago this CLI first saw the current disagreement for the served epoch
/// (`None` when it has not before).
pub fn judge_epoch(
    served: &ServedEpoch,
    anchors: Option<&Anchors>,
    highest_seen: u16,
    first_unanchored_age: Option<Duration>,
) -> EpochVerdict {
    // The ratchet: a server below an epoch this CLI has anchored is rolling
    // back, whatever the files say or whether they can be read.
    if served.epoch < highest_seen {
        return EpochVerdict::Violation(format!(
            "the server serves epoch {} but this CLI has already anchored epoch {highest_seen} \
             for it: a log cannot go back an epoch",
            served.epoch
        ));
    }
    let past_bound = first_unanchored_age.is_some_and(|age| age >= TRANSITION_BOUND);
    let soft_or_hard = |why: String| {
        if past_bound {
            EpochVerdict::Violation(format!(
                "{why}, for longer than {} minutes",
                TRANSITION_BOUND.as_secs() / 60
            ))
        } else {
            EpochVerdict::Unanchored(why)
        }
    };

    let Some(anchors) = anchors else {
        // Files unreadable. Epoch 1 behaves as before the cut; a later epoch
        // cannot pin its key, so it cannot be verified.
        // ⚠ `Anchored(Legacy)` here selects the LEGACY RECEIPT RULE; it does not
        // mean a root was anchored. `transparency verify` reports this case as
        // `unanchored`, exit 62 (Bob, #650; `cli/tests/verify.rs`), and the
        // ratchet above has already refused it for a CLI that has seen epoch 2.
        return if served.epoch <= 1 {
            EpochVerdict::Anchored(LogMode::Legacy)
        } else {
            EpochVerdict::Unanchored(format!(
                "the anchor files could not be read, so epoch {}'s VRF key cannot be pinned",
                served.epoch
            ))
        };
    };

    let carried_max = anchors.max_epoch();
    if served.epoch < carried_max {
        return soft_or_hard(format!(
            "the anchor files show epoch {carried_max} but the server serves epoch {}",
            served.epoch
        ));
    }
    if served.epoch == 1 {
        return EpochVerdict::Anchored(LogMode::Legacy);
    }
    let carried = match anchors.carries(served.epoch) {
        Ok(c) => c,
        Err(e) => return EpochVerdict::Violation(e.message),
    };
    if !carried {
        return soft_or_hard(format!(
            "the server serves epoch {} but the anchor files do not carry it yet",
            served.epoch
        ));
    }
    let key = match anchors.key(served.epoch) {
        Ok(Some(k)) => k,
        Ok(None) => unreachable!("carries() checked the key line"),
        Err(e) => return EpochVerdict::Violation(e.message),
    };
    match served.vrf_public_key {
        Some(served_key) if served_key == key.vrf_public_key => {
            EpochVerdict::Anchored(LogMode::V3 {
                epoch: served.epoch,
                vrf_public_key: key.vrf_public_key,
                genesis_entry_hash: key.genesis_entry_hash,
            })
        }
        Some(_) => EpochVerdict::Violation(format!(
            "the server's epoch-{} VRF key is not the key vrf-keys.jsonl publishes for that epoch",
            served.epoch
        )),
        None => EpochVerdict::Violation(format!(
            "the server serves epoch {} without naming its VRF key",
            served.epoch
        )),
    }
}

/// The genesis check (§10.7): the epoch's first entry must be the genesis the
/// key line pins, and its payload must bind the previous epoch's end line and
/// this epoch's key. `genesis` is that entry as `/range` serves it (§10.3).
pub fn check_genesis(mode: &LogMode, anchors: &Anchors, genesis: &Value) -> Result<()> {
    let LogMode::V3 {
        epoch,
        vrf_public_key,
        genesis_entry_hash,
    } = mode
    else {
        return Ok(());
    };
    let end = anchors.epoch_end(epoch - 1).ok_or_else(|| {
        CliError::transparency_violation(format!("no end line for epoch {}", epoch - 1))
    })?;
    let expected_payload = signet_crypto::translog::epoch_payload_v3(
        *epoch,
        end.log_size,
        &end.merkle_root,
        vrf_public_key,
    );
    let violation = |what: &str| {
        CliError::transparency_violation(format!("epoch {epoch}'s genesis entry {what}"))
    };
    if genesis.get("entry_id").and_then(Value::as_u64) != Some(1)
        || genesis.get("entry_version").and_then(Value::as_u64) != Some(3)
        || genesis.get("key_purpose").and_then(Value::as_str) != Some("epoch")
        || !genesis.get("account_index").is_none_or(Value::is_null)
    {
        return Err(violation("is not a v3, account-less, first entry"));
    }
    let payload = genesis
        .get("public_key")
        .and_then(Value::as_str)
        .and_then(|s| {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(s)
                .ok()
        })
        .ok_or_else(|| violation("has no readable payload"))?;
    if payload != expected_payload {
        return Err(violation(
            "does not bind the published end of the previous epoch and this epoch's key",
        ));
    }
    let created_at = genesis
        .get("created_at")
        .and_then(Value::as_u64)
        .ok_or_else(|| violation("has no created_at"))?;
    let recomputed = signet_crypto::translog::entry_hash_v3(
        1,
        None,
        signet_crypto::translog::KeyPurpose::Epoch,
        signet_crypto::translog::EPOCH_ALGORITHM_V3,
        &payload,
        created_at,
        &[0u8; 32],
    );
    if &recomputed != genesis_entry_hash {
        return Err(violation(
            "does not hash to the genesis_entry_hash vrf-keys.jsonl pins",
        ));
    }
    Ok(())
}

// ---- local state: the ratchet and the first sightings ----------------------

/// Per-origin memory: the highest epoch anchored, and when each unanchored
/// epoch was first seen (unix seconds). A sighting is cleared the moment its
/// epoch anchors, so a completed cut can never fire the bound later (Gus).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OriginState {
    pub highest_epoch: u16,
    pub first_unanchored: BTreeMap<u16, u64>,
    /// The write path's cache of the files (#651 ruling 3); see
    /// [`cached_verdict`].
    pub anchor_cache: Option<AnchorCache>,
}

/// The state file: `<config_dir>/translog-state.json`.
pub fn state_path() -> PathBuf {
    crate::config::config_dir().join("translog-state.json")
}

pub fn load_state(path: &Path, origin: &str) -> OriginState {
    let Ok(text) = std::fs::read_to_string(path) else {
        return OriginState::default();
    };
    let Ok(all) = serde_json::from_str::<Value>(&text) else {
        return OriginState::default();
    };
    let Some(o) = all.get(origin) else {
        return OriginState::default();
    };
    let highest_epoch = o
        .get("highest_epoch")
        .and_then(Value::as_u64)
        .and_then(|n| u16::try_from(n).ok())
        .unwrap_or(0);
    let mut first_unanchored = BTreeMap::new();
    if let Some(map) = o.get("first_unanchored").and_then(Value::as_object) {
        for (k, v) in map {
            if let (Ok(e), Some(t)) = (k.parse::<u16>(), v.as_u64()) {
                first_unanchored.insert(e, t);
            }
        }
    }
    let anchor_cache = o.get("anchor_cache").and_then(|c| {
        Some(AnchorCache {
            repo: c.get("repo")?.as_str()?.to_string(),
            fetched_at: c.get("fetched_at")?.as_u64()?,
            roots_jsonl: c.get("roots_jsonl")?.as_str()?.to_string(),
            vrf_keys_jsonl: c.get("vrf_keys_jsonl")?.as_str()?.to_string(),
            genesis_checked: c
                .get("genesis_checked")
                .and_then(Value::as_u64)
                .and_then(|n| u16::try_from(n).ok()),
        })
    });
    OriginState {
        highest_epoch,
        first_unanchored,
        anchor_cache,
    }
}

pub fn save_state(path: &Path, origin: &str, state: &OriginState) -> Result<()> {
    let mut all: Value = std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .filter(Value::is_object)
        .unwrap_or_else(|| Value::Object(Default::default()));
    let first: serde_json::Map<String, Value> = state
        .first_unanchored
        .iter()
        .map(|(e, t)| (e.to_string(), Value::from(*t)))
        .collect();
    all[origin] = serde_json::json!({
        "highest_epoch": state.highest_epoch,
        "first_unanchored": first,
        "anchor_cache": state.anchor_cache.as_ref().map(|c| serde_json::json!({
            "repo": c.repo,
            "fetched_at": c.fetched_at,
            "roots_jsonl": c.roots_jsonl,
            "vrf_keys_jsonl": c.vrf_keys_jsonl,
            "genesis_checked": c.genesis_checked,
        })),
    });
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .map_err(|e| CliError::filesystem(format!("creating {}: {e}", dir.display())))?;
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&all).unwrap_or_default())
        .map_err(|e| CliError::filesystem(format!("writing {}: {e}", tmp.display())))?;
    std::fs::rename(&tmp, path)
        .map_err(|e| CliError::filesystem(format!("replacing {}: {e}", path.display())))
}

/// Fold a verdict into the state: an anchored epoch raises the ratchet and
/// clears its sighting; an unanchored one records its first sighting.
pub fn update_state(state: &mut OriginState, served_epoch: u16, verdict: &EpochVerdict, now: u64) {
    match verdict {
        EpochVerdict::Anchored(mode) => {
            let e = match mode {
                LogMode::Legacy => 1,
                LogMode::V3 { epoch, .. } => *epoch,
            };
            state.highest_epoch = state.highest_epoch.max(e);
            state.first_unanchored.retain(|k, _| *k > e);
        }
        EpochVerdict::Unanchored(_) => {
            state.first_unanchored.entry(served_epoch).or_insert(now);
        }
        EpochVerdict::Violation(_) => {}
    }
}

// ---- fetching the files ----------------------------------------------------

/// Read both files from `repo`'s `main` branch. `vrf-keys.jsonl` not existing
/// yet (before the first cut) reads as empty; any other failure is `None`, the
/// caller's `unanchored`.
pub fn fetch(repo: &str) -> Option<Anchors> {
    let (roots, keys) = fetch_raw(repo)?;
    Anchors::parse(&roots, &keys).ok()
}

/// Both files' text, as [`fetch`] reads them.
fn fetch_raw(repo: &str) -> Option<(String, String)> {
    let base = format!("https://raw.githubusercontent.com/{repo}/main");
    let roots =
        crate::http::get_text_once(&format!("{base}/roots.jsonl"), Duration::from_secs(10)).ok()?;
    let keys = match crate::http::get_text_once(
        &format!("{base}/vrf-keys.jsonl"),
        Duration::from_secs(10),
    ) {
        Ok(text) => text,
        Err(e) if e.code == "not_found" => String::new(),
        Err(_) => return None,
    };
    Some((roots, keys))
}

// ---- the write path's cache of the anchor files (#651 ruling 3) -------------

/// How long the write path may judge by the anchor files as last read: the
/// log's max-merge-delay (receipts carry `max_merge_delay_seconds` 86 400), so
/// the window in which a server could hold a CLI on an epoch the files have
/// ended never exceeds the publication window the log already promises (Bob;
/// Gus, #651 ruling 3). A bound with that reason, not a tuning knob.
pub const ANCHOR_CACHE_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// The anchor files as last read whole from one repository, cut to the lines
/// the write path judges by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorCache {
    pub repo: String,
    /// Unix seconds.
    pub fetched_at: u64,
    pub roots_jsonl: String,
    pub vrf_keys_jsonl: String,
    /// The epoch whose genesis was checked against these files, if any.
    pub genesis_checked: Option<u16>,
}

impl AnchorCache {
    /// Cache the files `repo` just served: every end line and each epoch's
    /// latest root of `roots.jsonl` (so [`Anchors::max_epoch`] and
    /// [`Anchors::carries`] read as they did from the whole file), and all of
    /// `vrf-keys.jsonl`. `None` if the files do not parse.
    pub fn new(
        repo: &str,
        fetched_at: u64,
        roots_jsonl: &str,
        vrf_keys_jsonl: &str,
    ) -> Option<Self> {
        let lines: Vec<&str> = roots_jsonl
            .lines()
            .filter(|l| !l.trim().is_empty())
            .collect();
        let parsed = Anchors::parse(roots_jsonl, "").ok()?;
        let keep: Vec<&str> = lines
            .iter()
            .zip(&parsed.roots)
            .enumerate()
            .filter(|(i, (_, r))| {
                r.epoch_end
                    || !parsed.roots[i + 1..]
                        .iter()
                        .any(|later| later.epoch == r.epoch && !later.epoch_end)
            })
            .map(|(_, (line, _))| *line)
            .collect();
        let cache = Self {
            repo: repo.to_string(),
            fetched_at,
            roots_jsonl: keep.join("\n"),
            vrf_keys_jsonl: vrf_keys_jsonl.to_string(),
            genesis_checked: None,
        };
        cache.anchors().map(|_| cache)
    }

    pub fn anchors(&self) -> Option<Anchors> {
        Anchors::parse(&self.roots_jsonl, &self.vrf_keys_jsonl).ok()
    }
}

/// The write path's verdict from the cache, or `None` to read the files fresh.
/// The cache answers only when it is from `repo`, younger than
/// [`ANCHOR_CACHE_MAX_AGE`], and anchors the served epoch outright (for an
/// epoch ≥ 2, with its genesis already checked against these files). Every
/// other case goes to a fresh read: a server ahead of the cache, a served key
/// that disagrees with the cached line, a server behind the cached files, an
/// old cache.
pub fn cached_verdict(
    state: &OriginState,
    served: &ServedEpoch,
    repo: &str,
    now: u64,
) -> Option<(EpochVerdict, Anchors)> {
    let cache = state.anchor_cache.as_ref()?;
    if cache.repo != repo || now.saturating_sub(cache.fetched_at) >= ANCHOR_CACHE_MAX_AGE.as_secs()
    {
        return None;
    }
    let anchors = cache.anchors()?;
    let age = state
        .first_unanchored
        .get(&served.epoch)
        .map(|t| Duration::from_secs(now.saturating_sub(*t)));
    let verdict = judge_epoch(served, Some(&anchors), state.highest_epoch, age);
    match &verdict {
        EpochVerdict::Anchored(LogMode::Legacy) => Some((verdict, anchors)),
        EpochVerdict::Anchored(LogMode::V3 { epoch, .. })
            if cache.genesis_checked == Some(*epoch) =>
        {
            Some((verdict, anchors))
        }
        _ => None,
    }
}

// ---- an account's index in a V3 epoch (§10.6) -------------------------------

/// An account's index in a V3 epoch: the response's VRF proof must verify for
/// `account_id` under the epoch key pinned from `vrf-keys.jsonl`, and the index
/// is what that proof yields, never a value the server states. A missing or
/// failing proof is a substitution: the keys beside it cannot be bound.
pub fn account_index(
    vrf_public_key: &[u8; signet_crypto::vrf::PUBLIC_KEY_LEN],
    account_id: &str,
    proof_hex: Option<&str>,
    who: &str,
) -> Result<[u8; signet_crypto::vrf::INDEX_LEN]> {
    let account = uuid::Uuid::parse_str(account_id)
        .map_err(|_| CliError::invalid_data(format!("{who}: the account id is not a UUID")))?;
    let proof_hex = proof_hex.ok_or_else(|| {
        CliError::transparency_violation(format!(
            "{who}: the response names an account but carries no VRF proof for it, so its \
             keys cannot be bound to the log in this epoch"
        ))
    })?;
    let proof = hex::decode(proof_hex)
        .ok()
        .and_then(|b| <[u8; signet_crypto::vrf::PROOF_LEN]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| {
            CliError::transparency_violation(format!(
                "{who}: the account's VRF proof is not {}-byte hex",
                signet_crypto::vrf::PROOF_LEN
            ))
        })?;
    signet_crypto::vrf::verify(vrf_public_key, account.as_bytes(), &proof).map_err(|_| {
        CliError::transparency_violation(format!(
            "{who}: the account's VRF proof does not verify under the pinned epoch key: \
             substitution"
        ))
    })
}

/// The receipt rule an epoch verdict selects wherever keys are bound (the
/// write path and `attestation verify`). Only an anchored epoch binds keys.
/// `Anchored(Legacy)` includes the anchor files being unreadable while the
/// server is in epoch 1 (Gus, #650 ruling 3): the epoch-1 rule then applies as
/// before the cut, so an unreachable GitHub does not stop every share, and the
/// ratchet holds after the cut. A later epoch that cannot be anchored cannot
/// pin its VRF key, so nothing is bound: exit 62, retry later.
pub fn receipt_rule(verdict: EpochVerdict) -> Result<LogMode> {
    match verdict {
        EpochVerdict::Anchored(mode) => Ok(mode),
        EpochVerdict::Unanchored(why) => Err(CliError::unanchored(format!(
            "keys cannot be bound to the transparency log yet: {why}"
        ))),
        EpochVerdict::Violation(why) => Err(CliError::transparency_violation(why)),
    }
}

/// What a receipt for `account_id` must name under `mode`: the epoch and the
/// account's index in a V3 epoch ([`account_index`]), `None` in epoch 1.
pub fn index_under(
    mode: &LogMode,
    account_id: &str,
    proof: Option<&str>,
    who: &str,
) -> Result<Option<(u16, [u8; signet_crypto::vrf::INDEX_LEN])>> {
    match mode {
        LogMode::Legacy => Ok(None),
        LogMode::V3 {
            epoch,
            vrf_public_key,
            ..
        } => Ok(Some((
            *epoch,
            account_index(vrf_public_key, account_id, proof, who)?,
        ))),
    }
}

// ---- the owner's watch (§2b) ------------------------------------------------

/// What `transparency verify --self` reports for one epoch's published prefix.
#[derive(Debug)]
pub struct OwnerWatch {
    /// `clean`, `foreign_key` or `not_yet_published`.
    pub verdict: &'static str,
    /// Every entry under the account's index, each marked `held`.
    pub entries: Vec<Value>,
    /// Fingerprints logged under the index that this CLI does not hold.
    pub foreign: Vec<String>,
    /// Fingerprints this CLI holds that the published prefix does not carry.
    pub unlogged: Vec<String>,
}

/// Judge the owner's watch (design v05 §2b). `scanned` must be the epoch's
/// entries 1..=`published.log_size` in order, each a v3 entry whose leaf
/// recomputes, and the Merkle root over those leaves must be the published
/// root, so nothing can be left out of what was scanned (the check a
/// certificate-transparency monitor makes). Then every entry under `index` is
/// matched against the `(purpose, fingerprint)` pairs this CLI holds.
pub fn owner_watch(
    scanned: &[Value],
    epoch: u16,
    published: &RootLine,
    index: &[u8; signet_crypto::vrf::INDEX_LEN],
    held: &[(&str, String)],
) -> Result<OwnerWatch> {
    let size = published.log_size;
    if scanned.len() as u64 != size {
        return Err(CliError::transparency_violation(format!(
            "the server served {} entries for epoch {epoch}, whose published size is {size}",
            scanned.len()
        )));
    }
    let mut leaves = Vec::with_capacity(scanned.len());
    let mut mine = Vec::new();
    for (position, entry) in (1u64..).zip(scanned) {
        if entry.get("entry_id").and_then(Value::as_u64) != Some(position)
            || entry.get("entry_version").and_then(Value::as_u64) != Some(3)
        {
            return Err(CliError::transparency_violation(format!(
                "the entry at position {position} of epoch {epoch} is not the v3 entry {position}"
            )));
        }
        leaves.push(bind_leaf(entry, None, None)?);
        let under_index = entry
            .get("account_index")
            .and_then(Value::as_str)
            .and_then(|s| hex::decode(s).ok())
            .is_some_and(|b| b.as_slice() == index.as_slice());
        if under_index {
            mine.push(entry);
        }
    }
    if signet_crypto::merkle::merkle_root(&leaves) != published.merkle_root {
        return Err(CliError::transparency_violation(format!(
            "the {size} entries the server served for epoch {epoch} do not produce its \
             published root: what was scanned is not the log"
        )));
    }

    let same_key = |entry: &Value, purpose: &str, fp: &str| {
        entry.get("key_purpose").and_then(Value::as_str) == Some(purpose)
            && entry
                .get("public_key_fingerprint")
                .and_then(Value::as_str)
                .is_some_and(|served| served.eq_ignore_ascii_case(fp))
    };
    let mut foreign = Vec::new();
    let entries = mine
        .iter()
        .map(|e| {
            let is_held = held.iter().any(|(p, f)| same_key(e, p, f));
            let fp = e.get("public_key_fingerprint").and_then(Value::as_str);
            if !is_held {
                foreign.push(fp.unwrap_or_default().to_string());
            }
            serde_json::json!({
                "entry_id": e.get("entry_id"),
                "key_purpose": e.get("key_purpose"),
                "public_key_fingerprint": fp,
                "created_at": e.get("created_at"),
                "held": is_held,
            })
        })
        .collect();
    let unlogged: Vec<String> = held
        .iter()
        .filter(|(p, f)| !mine.iter().any(|e| same_key(e, p, f)))
        .map(|(_, f)| f.clone())
        .collect();
    let verdict = if !foreign.is_empty() {
        "foreign_key"
    } else if !unlogged.is_empty() {
        "not_yet_published"
    } else {
        "clean"
    };
    Ok(OwnerWatch {
        verdict,
        entries,
        foreign,
        unlogged,
    })
}

// ---- binding a served entry to the key asked about (bug256) ----------------

/// The fingerprint rule for a key purpose: the P-256 keys use SHA-256 of the
/// DER SubjectPublicKeyInfo; the PQ keys and the epoch payload use SHA-256 of
/// the raw bytes (PQR Crypto Spec §8.5), exactly as the server computes them.
pub fn fingerprint_for(purpose: &str, public_key: &[u8]) -> Result<String> {
    match purpose {
        "signing" | "kem" => signet_crypto::pubkey::fingerprint(public_key)
            .map_err(|_| CliError::invalid_data("entry public_key is not a P-256 point")),
        "signing_pq" | "kem_pq" | "epoch" => Ok(signet_crypto::pubkey::fingerprint_raw(public_key)),
        other => Err(CliError::invalid_data(format!(
            "unknown key_purpose {other}"
        ))),
    }
}

fn purpose_of(name: &str) -> Result<signet_crypto::translog::KeyPurpose> {
    use signet_crypto::translog::KeyPurpose;
    Ok(match name {
        "epoch" => KeyPurpose::Epoch,
        "signing" => KeyPurpose::Signing,
        "kem" => KeyPurpose::Kem,
        "signing_pq" => KeyPurpose::SigningPq,
        "kem_pq" => KeyPurpose::KemPq,
        other => {
            return Err(CliError::invalid_data(format!(
                "unknown key_purpose {other}"
            )));
        }
    })
}

/// Recompute a served entry's `entry_hash` from its own fields, under the rule
/// its version names (v2: the 16-byte account id; v3: the 64-byte index), and
/// bind it to the key that was asked about: the recomputed hash must equal the
/// served one, the served fingerprint must be the key's own, and, when the
/// caller asked about a key, both fingerprint and purpose must be that key's.
/// Returns the recomputed leaf, which is what the inclusion check then proves.
pub fn bind_leaf(
    entry: &Value,
    asked_fingerprint: Option<&str>,
    asked_purpose: Option<&str>,
) -> Result<[u8; 32]> {
    use base64::Engine;
    let unbound = |what: &str| {
        CliError::invalid_data(format!(
            "the server did not serve the stored entry ({what}), so the proven leaf cannot \
             be bound to the key asked about (bug256): NOT verified"
        ))
    };
    let field = |k: &str| entry.get(k).ok_or_else(|| unbound(k));
    let version = field("entry_version")?
        .as_u64()
        .ok_or_else(|| unbound("entry_version"))?;
    let entry_id = field("entry_id")?
        .as_u64()
        .ok_or_else(|| unbound("entry_id"))?;
    let purpose = field("key_purpose")?
        .as_str()
        .ok_or_else(|| unbound("key_purpose"))?;
    let algorithm = field("algorithm")?
        .as_str()
        .ok_or_else(|| unbound("algorithm"))?;
    let public_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(
            field("public_key")?
                .as_str()
                .ok_or_else(|| unbound("public_key"))?,
        )
        .map_err(|_| CliError::invalid_data("entry public_key is not base64url"))?;
    let created_at = field("created_at")?
        .as_u64()
        .ok_or_else(|| unbound("created_at"))?;
    let prev = hex32(entry.get("prev_entry_hash"), "prev_entry_hash")
        .map_err(|_| unbound("prev_entry_hash"))?;
    let served_hash = hex32(entry.get("entry_hash"), "entry_hash")?;
    let kp = purpose_of(purpose)?;
    let recomputed = match version {
        2 => {
            let account = match entry.get("account_id") {
                None | Some(Value::Null) => None,
                Some(v) => Some(
                    v.as_str()
                        .and_then(|s| uuid::Uuid::parse_str(s).ok())
                        .ok_or_else(|| CliError::invalid_data("entry account_id is not a UUID"))?,
                ),
            };
            signet_crypto::translog::entry_hash_v2(
                entry_id,
                account.as_ref().map(uuid::Uuid::as_bytes),
                kp,
                algorithm,
                &public_key,
                created_at,
                &prev,
            )
        }
        3 => {
            let index = match entry.get("account_index") {
                None | Some(Value::Null) => None,
                Some(v) => Some(
                    v.as_str()
                        .and_then(|s| hex::decode(s).ok())
                        .and_then(|b| {
                            <[u8; signet_crypto::vrf::INDEX_LEN]>::try_from(b.as_slice()).ok()
                        })
                        .ok_or_else(|| {
                            CliError::invalid_data("entry account_index is not 64-byte hex")
                        })?,
                ),
            };
            signet_crypto::translog::entry_hash_v3(
                entry_id,
                index.as_ref(),
                kp,
                algorithm,
                &public_key,
                created_at,
                &prev,
            )
        }
        other => {
            return Err(CliError::invalid_data(format!(
                "entry_version {other} is not one this CLI can recompute"
            )));
        }
    };
    if recomputed != served_hash {
        return Err(CliError::transparency_violation(
            "the served entry does not hash to its entry_hash: the leaf is not this entry",
        ));
    }
    let own_fp = fingerprint_for(purpose, &public_key)?;
    if entry.get("public_key_fingerprint").and_then(Value::as_str) != Some(own_fp.as_str()) {
        return Err(CliError::transparency_violation(
            "the served fingerprint is not the served key's own",
        ));
    }
    if let Some(asked) = asked_fingerprint
        && !asked.eq_ignore_ascii_case(&own_fp)
    {
        return Err(CliError::transparency_violation(
            "the proven entry is for a DIFFERENT key than the one asked about",
        ));
    }
    if let Some(asked) = asked_purpose
        && asked != purpose
    {
        return Err(CliError::transparency_violation(format!(
            "the proven entry is a {purpose} key, not the {asked} key asked about"
        )));
    }
    Ok(recomputed)
}

// ---- anchoring a live server ----------------------------------------------

/// Held only inside a command's epoch-bound attempt:
/// [`once_more_on_epoch_change`] makes one and lends it to the attempt, and
/// anchoring takes it, so an anchoring outside the retry does not compile (Bob
/// and Gus, on unit 1). What anchoring returns borrows it, so a trust cannot
/// be carried out of the attempt and used under a later epoch either.
pub struct EpochAttempt {
    _private: (),
}

/// The anchoring of one server, for one command's attempt.
pub struct Anchoring<'a> {
    pub served: ServedEpoch,
    pub anchors: Option<Anchors>,
    pub verdict: EpochVerdict,
    /// Whether a public anchor repository is known for the server at all.
    pub repo_known: bool,
    /// The attempt this anchoring belongs to (private, so only anchoring
    /// makes one; Bob, on unit 1c).
    attempt: std::marker::PhantomData<&'a EpochAttempt>,
}

#[cfg(test)]
impl Anchoring<'_> {
    /// An anchoring made by hand, for the seam tests' injected anchoring.
    pub(crate) fn for_test(
        served: ServedEpoch,
        anchors: Option<Anchors>,
        verdict: EpochVerdict,
        repo_known: bool,
    ) -> Self {
        Self {
            served,
            anchors,
            verdict,
            repo_known,
            attempt: std::marker::PhantomData,
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Judge `server_url`'s epoch against its public anchors, retrying the files
/// briefly inside this run while they and the server disagree, folding the
/// verdict into local state, and running the genesis check on a V3 anchor.
pub fn anchor_log<'a>(
    attempt: &'a EpochAttempt,
    server_url: &str,
    anchor_repo: Option<&str>,
) -> Result<Anchoring<'a>> {
    let info = crate::http::get_json(&format!("{server_url}/v1/server-info"), &[])?;
    anchor_served(attempt, server_url, &info, anchor_repo, false)
}

/// [`anchor_log`] over a `/v1/server-info` body the caller already holds, so a
/// command that takes its signing keys from that read judges the epoch of the
/// same read (the write path's `ServerTrust`, which anchors once per command).
/// `use_cache` lets the write path judge by the files as last read
/// ([`cached_verdict`]); the verify commands pass `false` and read fresh. Every
/// fresh read that parses refreshes the cache.
pub fn anchor_served<'a>(
    _attempt: &'a EpochAttempt,
    server_url: &str,
    info: &Value,
    anchor_repo: Option<&str>,
    use_cache: bool,
) -> Result<Anchoring<'a>> {
    let served = ServedEpoch::from_server_info(info)?;
    let env_repo = std::env::var("SIGNET_ANCHOR_REPO").ok();
    let repo = anchor_repo_for(server_url, anchor_repo.or(env_repo.as_deref()));
    let origin = normalize_origin(server_url);
    let path = state_path();
    let mut state = load_state(&path, &origin);
    let now = now_unix();

    let judge = |anchors: Option<&Anchors>, state: &OriginState| {
        let age = state
            .first_unanchored
            .get(&served.epoch)
            .map(|t| Duration::from_secs(now.saturating_sub(*t)));
        judge_epoch(&served, anchors, state.highest_epoch, age)
    };

    if use_cache
        && let Some(repo) = repo.as_deref()
        && let Some((verdict, anchors)) = cached_verdict(&state, &served, repo, now)
    {
        update_state(&mut state, served.epoch, &verdict, now);
        save_or_warn(&path, &origin, &state);
        return Ok(Anchoring {
            served,
            anchors: Some(anchors),
            verdict,
            repo_known: true,
            attempt: std::marker::PhantomData,
        });
    }

    // A fresh read keeps the files' text, so a parse can refresh the cache.
    let read = |repo: &str| {
        let (roots, keys) = fetch_raw(repo)?;
        let anchors = Anchors::parse(&roots, &keys).ok()?;
        Some((anchors, roots, keys))
    };
    let mut fresh = repo.as_deref().and_then(read);
    let mut verdict = judge(fresh.as_ref().map(|f| &f.0), &state);
    // A short retry inside one run (Bob): the files are CDN-cached ~5 minutes.
    for _ in 0..3 {
        if !matches!(verdict, EpochVerdict::Unanchored(_)) || repo.is_none() {
            break;
        }
        std::thread::sleep(Duration::from_secs(15));
        fresh = repo.as_deref().and_then(read);
        verdict = judge(fresh.as_ref().map(|f| &f.0), &state);
    }

    let mut genesis_checked = None;
    if let (EpochVerdict::Anchored(mode @ LogMode::V3 { epoch, .. }), Some((a, _, _))) =
        (&verdict, fresh.as_ref())
    {
        let page = crate::http::get_json(
            &format!("{server_url}/v1/transparency/log/range?epoch={epoch}&start=1&end=1"),
            &[],
        )?;
        let genesis = page
            .get("entries")
            .and_then(Value::as_array)
            .and_then(|e| e.first())
            .ok_or_else(|| CliError::transparency_violation("the epoch serves no genesis entry"))?;
        match check_genesis(mode, a, genesis) {
            Ok(()) => genesis_checked = Some(*epoch),
            Err(e) => verdict = EpochVerdict::Violation(e.message),
        }
    }

    // The files are authentic whatever the server did, so a parsed read
    // refreshes the cache; the cache re-judges the server on every use.
    if let (Some(repo), Some((_, roots, keys))) = (repo.as_deref(), fresh.as_ref())
        && let Some(mut cache) = AnchorCache::new(repo, now, roots, keys)
    {
        cache.genesis_checked = genesis_checked;
        state.anchor_cache = Some(cache);
    }
    update_state(&mut state, served.epoch, &verdict, now);
    save_or_warn(&path, &origin, &state);
    Ok(Anchoring {
        served,
        anchors: fresh.map(|f| f.0),
        verdict,
        repo_known: repo.is_some(),
        attempt: std::marker::PhantomData,
    })
}

/// Run a command's epoch-bound reads, and run them once more from a fresh
/// anchor when the server's epoch moved under the first attempt (design §10.4:
/// Bob's race across requests, ruled by Gus). Each attempt is lent the
/// [`EpochAttempt`] every anchoring needs, anchors for itself, and runs
/// read-only ([`crate::http::read_only`]), so the retry cannot repeat a write:
/// the caller writes only after this returns. On the retry nothing is caught:
/// a refusal of the epoch just anchored is exit 62 (`epoch_changed`), and a
/// part naming another epoch is exit 60, since it then contradicts a fresh
/// anchor.
pub fn once_more_on_epoch_change<T>(
    mut attempt: impl FnMut(&EpochAttempt) -> Result<T>,
) -> Result<T> {
    let token = EpochAttempt { _private: () };
    match crate::http::read_only(|| attempt(&token)) {
        Err(e) if e.epoch_moved => crate::http::read_only(|| attempt(&token)),
        other => other,
    }
}

/// A receipt answers for one epoch: its `epoch`, or 1 when it names none (the
/// shape before epoch 2). Another than the anchored one means the server's
/// epoch moved under the command.
pub fn check_receipt_epoch(receipt: &Value, epoch: u16, who: &str) -> Result<()> {
    let named = receipt.get("epoch").map_or(Some(1), Value::as_u64);
    if named == Some(u64::from(epoch)) {
        return Ok(());
    }
    let named = receipt
        .get("epoch")
        .map_or_else(|| "1".to_string(), Value::to_string);
    Err(CliError::transparency_violation(format!(
        "{who}: a log receipt answers for epoch {named}, but the anchored epoch is {epoch}"
    ))
    .as_epoch_move())
}

/// State is a convenience for the bound, the ratchet and the cache; failing to
/// save it must not fail the command, but it must not pass silently either.
fn save_or_warn(path: &Path, origin: &str, state: &OriginState) {
    if let Err(e) = save_state(path, origin, state) {
        eprintln!(
            "signet: warning: could not save transparency-log state: {}",
            e.message
        );
    }
}

#[cfg(test)]
mod tests;
