// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! bug047: CLI upload resume state.
//!
//! When a direct-to-storage upload is interrupted — a `transfer_stalled`
//! exhaustion (a bad network window), a crash, a ^C — a small state file lets
//! the NEXT `signet file upload` of the same source to the same destination
//! **resume from the parts storage already holds** instead of restarting from
//! zero. The state carries **no secrets**: ids + geometry + the source
//! signature only — never the DEK and never pre-signed URLs (resume re-obtains
//! both from the server's `/resume` endpoint, which is authoritative for the
//! uploaded-part set too).
//!
//! Files live under `<config_dir>/uploads/`, mode 0600, one per in-flight
//! upload: written right after initiate (so even a hard crash leaves a
//! resumable trail), removed on complete or abort. A state whose source
//! signature (path + size + mtime) no longer matches is ignored and cleaned —
//! a changed file must upload fresh (the §4.2 chunk seal is deterministic per
//! DEK + content, so resuming with changed bytes would corrupt the assembly).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config;
use crate::error::{CliError, Result};

/// One in-flight upload's resumable identity. `source_path` is canonicalized;
/// `file_size`/`file_mtime_unix` are the change-detection signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UploadState {
    pub file_id: String,
    pub upload_id: String,
    pub server_url: String,
    pub folder_id: String,
    pub root_folder_id: String,
    pub name: String,
    pub source_path: String,
    pub file_size: u64,
    pub file_mtime_unix: i64,
    pub chunk_size: usize,
    pub chunk_count: i32,
    /// bug129 (audit F-003) — a CONTENT anchor over the first + last chunk, so resuming
    /// proves the source bytes are unchanged rather than inferring it from a second-granular
    /// mtime.
    ///
    /// ⚠ `Option` + `serde(default)` so a state file written before this field self-heals —
    /// but **absence is treated as NOT resumable** (see [`find_match_in`]). Costing one
    /// restarted upload after upgrade is the right trade against silently assembling a file
    /// from two different contents.
    #[serde(default)]
    pub content_anchor: Option<String>,
    /// bug060: the transfer rate (bytes/sec) this upload last measured, so a
    /// resume starts warm instead of re-deriving bounds from nothing. **Never a
    /// secret and never load-bearing** — a missing or stale value simply falls
    /// back to the bootstrap path.
    #[serde(default)]
    pub rate_estimate_bps: Option<f64>,
    /// Unix seconds at which `rate_estimate_bps` was measured. A rate is only
    /// meaningful about the link it was measured on, so it expires (see
    /// [`crate::transfer_governor::RATE_FRESHNESS`]) rather than being trusted
    /// indefinitely — today's upload must not be sized from yesterday's café wifi.
    #[serde(default)]
    pub rate_measured_at_unix: Option<i64>,
}

impl UploadState {
    /// How long ago the persisted rate was measured. A missing timestamp reads as
    /// "infinitely old", which routes to the bootstrap path — fail safe, not fail
    /// optimistic.
    pub fn rate_measured_age(&self) -> std::time::Duration {
        let Some(measured_at) = self.rate_measured_at_unix else {
            return std::time::Duration::MAX;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        std::time::Duration::from_secs((now - measured_at).max(0) as u64)
    }
}

/// The state directory: `<config_dir>/uploads`.
pub fn state_dir() -> PathBuf {
    config::config_dir().join("uploads")
}

fn path_for(dir: &Path, file_id: &str) -> PathBuf {
    dir.join(format!("{file_id}.json"))
}

/// Persist `state` into `dir` (created 0700 if absent; the file 0600).
pub fn save_in(dir: &Path, state: &UploadState) -> Result<()> {
    std::fs::create_dir_all(dir)
        .map_err(|e| CliError::filesystem(format!("creating {}: {e}", dir.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    let path = path_for(dir, &state.file_id);
    let json = serde_json::to_vec_pretty(state)
        .map_err(|e| CliError::generic(format!("serializing upload state: {e}")))?;
    std::fs::write(&path, json)
        .map_err(|e| CliError::filesystem(format!("writing {}: {e}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Persist `state` in the standard state dir.
pub fn save(state: &UploadState) -> Result<()> {
    save_in(&state_dir(), state)
}

/// Remove the state for `file_id` (best-effort; absent is fine).
pub fn remove_in(dir: &Path, file_id: &str) {
    let _ = std::fs::remove_file(path_for(dir, file_id));
}

/// Remove from the standard state dir.
pub fn remove(file_id: &str) {
    remove_in(&state_dir(), file_id);
}

/// Find a state matching this exact re-run: same server, destination folder,
/// name, and source signature (canonical path + size + mtime). Corrupt or
/// unreadable state files are skipped (never fatal — worst case is a fresh
/// upload); a state for the same destination whose source signature CHANGED
/// is removed (the §4.2 seal is content-deterministic, so it can never be
/// safely resumed).
#[allow(clippy::too_many_arguments)]
/// bug129 (audit F-003) — the resume CONTENT anchor: SHA-256 over the first and last chunk of
/// the source.
///
/// **Why an anchor and not a finer clock.** The prior resume signature was
/// `(path, size, mtime)`, and mtime is second-granular: a file replaced within the same second
/// as an interrupted upload, at the same size, matched — and the upload resumed against
/// *different content*. The failure is **silent and invisible to the integrity layer**, because
/// every chunk is individually valid AES-GCM; nothing downstream can notice that chunk 3 came
/// from one file and chunk 9 from another. A finer timestamp would only narrow the window;
/// hashing the bytes closes it.
///
/// First **and** last chunk deliberately: a same-size replacement most often differs at the
/// tail (append/truncate-and-rewrite), while a header-only edit differs at the front. Reading
/// the whole file would be correct but turns every resume into a full re-read of a
/// possibly-100 GB source — the anchor is a cheap, seek-bounded read at both ends.
///
/// Returns `None` if the source cannot be read; the caller treats that as not-resumable.
pub fn content_anchor(path: &Path, file_size: u64, chunk_size: usize) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).ok()?;
    let span = (chunk_size as u64).min(file_size) as usize;

    // Domain-separated, and the size is bound in so a truncation cannot collide with a prefix.
    let mut buf = Vec::with_capacity(span * 2 + 32);
    buf.extend_from_slice(b"signet:resume-anchor:v1");
    buf.extend_from_slice(&file_size.to_be_bytes());

    let mut head = vec![0u8; span];
    f.read_exact(&mut head).ok()?;
    buf.extend_from_slice(&head);

    // The tail: the last `span` bytes. Overlaps the head on a small file, which is harmless.
    let tail_start = file_size.saturating_sub(span as u64);
    f.seek(SeekFrom::Start(tail_start)).ok()?;
    let mut tail = vec![0u8; span];
    f.read_exact(&mut tail).ok()?;
    buf.extend_from_slice(&tail);

    Some(signet_crypto::pubkey::fingerprint_raw(&buf))
}

/// The identity of "this exact upload, from this exact source" — the tuple every resume
/// decision is made against.
///
/// Grouped into a struct rather than passed as eight positional arguments: bug129 added the
/// content anchor to a signature that was already at the limit, and a caller transposing two
/// adjacent `&str`s here would silently resume the wrong upload. Named fields make that
/// unrepresentable at the call site.
pub struct ResumeKey<'a> {
    pub server_url: &'a str,
    pub folder_id: &'a str,
    pub name: &'a str,
    pub source_path: &'a str,
    pub file_size: u64,
    pub file_mtime_unix: i64,
    /// bug129 (F-003) — the content anchor; `None` is deliberately NOT resumable.
    pub content_anchor: Option<&'a str>,
}

pub fn find_match_in(dir: &Path, key: &ResumeKey<'_>) -> Option<UploadState> {
    let ResumeKey {
        server_url,
        folder_id,
        name,
        source_path,
        file_size,
        file_mtime_unix,
        content_anchor,
    } = *key;
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let Ok(bytes) = std::fs::read(entry.path()) else {
            continue;
        };
        let Ok(state) = serde_json::from_slice::<UploadState>(&bytes) else {
            continue;
        };
        let same_dest =
            state.server_url == server_url && state.folder_id == folder_id && state.name == name;
        if !same_dest {
            continue;
        }
        // bug129 (F-003): the CONTENT anchor decides, not the second-granular mtime. A state
        // written before this field carries None and is deliberately NOT resumable — one
        // restarted upload after upgrade is the right price against silently assembling a file
        // from two different contents, which no downstream check could detect.
        let same_content = match (state.content_anchor.as_deref(), content_anchor) {
            (Some(stored), Some(current)) => stored == current,
            _ => false,
        };
        let same_source = state.source_path == source_path
            && state.file_size == file_size
            && state.file_mtime_unix == file_mtime_unix
            && same_content;
        if same_source {
            return Some(state);
        }
        // Same destination, changed source: this in-flight upload can never be
        // resumed correctly — drop the stale state so it stops matching.
        let _ = std::fs::remove_file(entry.path());
    }
    None
}

/// Find in the standard state dir.
pub fn find_match(key: &ResumeKey<'_>) -> Option<UploadState> {
    find_match_in(&state_dir(), key)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("signet-upload-state-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    pub(crate) fn state() -> UploadState {
        UploadState {
            file_id: "11111111-1111-4111-8111-111111111111".into(),
            upload_id: "22222222-2222-4222-8222-222222222222".into(),
            server_url: "https://staging.example".into(),
            folder_id: "33333333-3333-4333-8333-333333333333".into(),
            root_folder_id: "33333333-3333-4333-8333-333333333333".into(),
            name: "report.pdf".into(),
            source_path: "/tmp/report.pdf".into(),
            file_size: 1_048_576,
            file_mtime_unix: 1_784_000_000,
            chunk_size: 16 * 1024 * 1024,
            chunk_count: 1,
            rate_estimate_bps: None,
            rate_measured_at_unix: None,
            // bug129: the fixtures carry an anchor, because a state WITHOUT one is now
            // deliberately not resumable — see `a_state_without_a_content_anchor_never_matches`.
            content_anchor: Some(TEST_ANCHOR.into()),
        }
    }

    /// The content anchor the fixtures agree on. Fixed rather than computed: these tests
    /// exercise the MATCHING rule, not the hashing (which `content_anchor` owns).
    const TEST_ANCHOR: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn save_find_remove_round_trip() {
        let dir = temp_dir("roundtrip");
        let s = state();
        save_in(&dir, &s).expect("save");

        let found = find_match_in(
            &dir,
            &ResumeKey {
                server_url: &s.server_url,
                folder_id: &s.folder_id,
                name: &s.name,
                source_path: &s.source_path,
                file_size: s.file_size,
                file_mtime_unix: s.file_mtime_unix,
                content_anchor: Some(TEST_ANCHOR),
            },
        )
        .expect("exact re-run signature matches");
        assert_eq!(found, s);

        remove_in(&dir, &s.file_id);
        assert!(
            find_match_in(
                &dir,
                &ResumeKey {
                    server_url: &s.server_url,
                    folder_id: &s.folder_id,
                    name: &s.name,
                    source_path: &s.source_path,
                    file_size: s.file_size,
                    file_mtime_unix: s.file_mtime_unix,
                    content_anchor: Some(TEST_ANCHOR),
                },
            )
            .is_none(),
            "removed state must not match"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn changed_source_never_matches_and_is_cleaned() {
        // The §4.2 seal is content-deterministic: a changed source must never
        // resume into the old upload. A same-destination state with a changed
        // signature is dropped entirely.
        let dir = temp_dir("changed");
        let s = state();
        save_in(&dir, &s).expect("save");

        let found = find_match_in(
            &dir,
            &ResumeKey {
                server_url: &s.server_url,
                folder_id: &s.folder_id,
                name: &s.name,
                source_path: &s.source_path,
                file_size: s.file_size,
                file_mtime_unix: s.file_mtime_unix + 60, // the file was touched since
                content_anchor: Some(TEST_ANCHOR),
            },
        );
        assert!(found.is_none(), "a changed mtime must not resume");
        assert!(
            !path_for(&dir, &s.file_id).exists(),
            "the stale state is cleaned so it never matches again"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn different_destination_does_not_match_and_survives() {
        let dir = temp_dir("dest");
        let s = state();
        save_in(&dir, &s).expect("save");

        let found = find_match_in(
            &dir,
            &ResumeKey {
                server_url: &s.server_url,
                folder_id: &s.folder_id,
                name: "other-name.pdf",
                source_path: &s.source_path,
                file_size: s.file_size,
                file_mtime_unix: s.file_mtime_unix,
                content_anchor: Some(TEST_ANCHOR),
            },
        );
        assert!(found.is_none());
        assert!(
            path_for(&dir, &s.file_id).exists(),
            "a different destination leaves the state alone (it may still be resumed by ITS re-run)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_state_is_skipped_not_fatal() {
        let dir = temp_dir("corrupt");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("garbage.json"), b"{ not json").unwrap();
        let s = state();
        save_in(&dir, &s).expect("save");

        let found = find_match_in(
            &dir,
            &ResumeKey {
                server_url: &s.server_url,
                folder_id: &s.folder_id,
                name: &s.name,
                source_path: &s.source_path,
                file_size: s.file_size,
                file_mtime_unix: s.file_mtime_unix,
                content_anchor: Some(TEST_ANCHOR),
            },
        );
        assert_eq!(
            found,
            Some(s),
            "a corrupt sibling never blocks a real match"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod content_anchor_tests {
    //! bug129 (audit F-003) — the resume CONTENT anchor.
    //!
    //! The prior resume signature was `(path, size, mtime)`, and mtime is **second-granular**:
    //! a file replaced within the same second as an interrupted upload, at the same size,
    //! matched — and the upload resumed against DIFFERENT content. The failure is silent and
    //! invisible to the integrity layer, because every chunk is individually valid AES-GCM;
    //! nothing downstream can notice that chunk 3 came from one file and chunk 9 from another.
    use super::*;

    fn write(path: &Path, bytes: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn the_anchor_distinguishes_same_size_different_content() {
        // ⭐ THE case the finding is about: identical size, and (in the real failure) an
        // identical second on the clock. Only the bytes differ — so only the bytes can catch it.
        let dir = std::env::temp_dir().join(format!("signet-anchor-{}", std::process::id()));
        let a = dir.join("a.bin");
        let b = dir.join("b.bin");
        let size = 4096;
        write(&a, &vec![0xAAu8; size]);
        let mut other = vec![0xAAu8; size];
        other[size - 1] = 0xBB; // differs only in the LAST byte — the tail half of the anchor
        write(&b, &other);

        let anchor_a = content_anchor(&a, size as u64, 1024).expect("anchor a");
        let anchor_b = content_anchor(&b, size as u64, 1024).expect("anchor b");
        assert_ne!(
            anchor_a, anchor_b,
            "same size, different content must produce different anchors — a tail-only \
             difference is the common same-size replacement shape"
        );

        // A head-only difference must also be caught (the other common shape).
        let mut head_diff = vec![0xAAu8; size];
        head_diff[0] = 0xCC;
        let c = dir.join("c.bin");
        write(&c, &head_diff);
        assert_ne!(anchor_a, content_anchor(&c, size as u64, 1024).unwrap());

        // POSITIVE CONTROL: unchanged content anchors identically across calls, or resume
        // would never work at all and this defence would be a denial-of-service.
        assert_eq!(anchor_a, content_anchor(&a, size as u64, 1024).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_state_without_a_content_anchor_never_matches() {
        // ⚠ The fail-safe direction. A state file written before this field carries None, and
        // is deliberately NOT resumable: one restarted upload after upgrade is the right price
        // against silently assembling a file from two different contents.
        let dir = std::env::temp_dir().join(format!("signet-anchor-legacy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut s = super::tests::state();
        s.content_anchor = None;
        save_in(&dir, &s).expect("save");

        let found = find_match_in(
            &dir,
            &ResumeKey {
                server_url: &s.server_url,
                folder_id: &s.folder_id,
                name: &s.name,
                source_path: &s.source_path,
                file_size: s.file_size,
                file_mtime_unix: s.file_mtime_unix,
                content_anchor: Some(
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ),
            },
        );
        assert!(
            found.is_none(),
            "a pre-anchor state must not resume, even when path/size/mtime all match"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_changed_anchor_never_matches() {
        // The live case: same path, size and mtime, but the bytes changed.
        let dir = std::env::temp_dir().join(format!("signet-anchor-diff-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = super::tests::state();
        save_in(&dir, &s).expect("save");

        let found = find_match_in(
            &dir,
            &ResumeKey {
                server_url: &s.server_url,
                folder_id: &s.folder_id,
                name: &s.name,
                source_path: &s.source_path,
                file_size: s.file_size,
                file_mtime_unix: s.file_mtime_unix,
                content_anchor: Some(
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ),
            },
        );
        assert!(
            found.is_none(),
            "a different content anchor must not resume, even with an identical mtime"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
