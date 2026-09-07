// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Client-side name/path addressing for the drive surface (parity design §D2/§D3).
//!
//! Folder and file names are stored as ciphertext (Envelope §7.3); the
//! zero-knowledge server can't read them, so it can't resolve a path — the CLI
//! must. A name is bound (§7.3 AAD = `root_folder_id ‖ target_id`) and encrypted
//! under the hierarchy **root's** metadata key, so to show or match a plaintext
//! name we fetch that root's metadata key (`GET /v1/folders/{root}/metadata-key-wrap`
//! → decap with the KEM key), cache it per-root within one invocation (mirroring
//! the web `Drive`), and `decrypt_name` each entry.
//!
//! **Names are not unique** — the server can't enforce uniqueness over ciphertext
//! it can't read. So a path segment that matches more than one entry is a hard,
//! helpful error listing the candidates' ids + timestamps; the caller disambiguates
//! with `--folder-id`/`--file-id`. Resolution is never a silent pick. A name that
//! contains a literal `/` can't be path-addressed (it would split into segments) —
//! the id flags are the escape hatch.

use std::collections::HashMap;

use serde::Serialize;
use serde_json::Value;
use signet_crypto::encname::NameEnvelope;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::commands::unwrap_metadata_key_envelope;
use crate::error::{CliError, Result};
use crate::http;
use crate::keystore::{KeyLabel, Keystore};

/// A folder with its name decrypted, plus the timestamps a collision message needs.
#[derive(Debug, Serialize)]
pub struct FolderEntry {
    pub folder_id: Uuid,
    /// The hierarchy root (`root_folder_id` from the view, or the folder's own id
    /// when it is a top-level folder = its own root).
    pub root_folder_id: Uuid,
    /// The decrypted name, or `None` when this entry's name could not be decoded.
    ///
    /// ⚠ **bug132(ii): `Option` rather than a `"(unreadable)"` sentinel, deliberately.** Path
    /// resolution matches on this field, so a placeholder string would be *addressable* — an
    /// undecryptable folder could shadow, or be mistaken for, a real one named the same. `None`
    /// simply cannot match a path component, which makes the hazard unrepresentable instead of
    /// relying on a magic string never colliding with a user's chosen name.
    pub name: Option<String>,
    pub created_at: i64,
    pub modified_at: i64,
}

/// A file with its name decrypted.
#[derive(Debug, Serialize)]
pub struct FileEntry {
    pub file_id: Uuid,
    /// The decrypted name, or `None` when it could not be decoded — see
    /// [`FolderEntry::name`] for why this is an `Option` and not a sentinel string.
    pub name: Option<String>,
    /// The stored CIPHERTEXT length (storage/quota accounting).
    pub size_bytes: i64,
    /// The PLAINTEXT length — the user's "file size" (bug083; server-derived).
    /// Absent when the server cannot derive it; display falls back to
    /// `size_bytes` rather than fabricating.
    pub plaintext_bytes: Option<i64>,
    pub created_at: i64,
    pub modified_at: i64,
}

/// A folder path resolved to its ids.
pub struct ResolvedFolder {
    pub folder_id: Uuid,
    pub root_folder_id: Uuid,
}

/// A file path resolved to its ids (the parent folder + its root come along, since
/// the §7.3 name AAD needs the root and downstream ops want the parent).
pub struct ResolvedFile {
    pub file_id: Uuid,
    pub folder_id: Uuid,
    pub root_folder_id: Uuid,
}

/// Lists + decrypts drive entries and resolves name-paths to ids, holding a
/// per-invocation cache of unwrapped root metadata keys. Construct one per command;
/// it borrows the keystore + key labels + server URL for the call's lifetime, and
/// the cached keys are zeroized on drop.
pub struct Resolver<'a> {
    keystore: &'a dyn Keystore,
    signing: &'a KeyLabel,
    kem: &'a KeyLabel,
    server_url: &'a str,
    metadata_keys: HashMap<Uuid, Zeroizing<[u8; 32]>>,
    /// Roots whose metadata-key resolution has already been reported as degraded, so a
    /// listing with many rows under one bad root explains itself **once** instead of per
    /// row. Diagnostic only — it suppresses the repeated *message*, never the repeated
    /// attempt, so a transient failure on row 1 does not condemn row 2 (bug139 follow-up).
    degrade_reported: std::collections::HashSet<Uuid>,
}

impl<'a> Resolver<'a> {
    pub fn new(
        keystore: &'a dyn Keystore,
        signing: &'a KeyLabel,
        kem: &'a KeyLabel,
        server_url: &'a str,
    ) -> Self {
        Self {
            keystore,
            signing,
            kem,
            server_url,
            metadata_keys: HashMap::new(),
            degrade_reported: std::collections::HashSet::new(),
        }
    }

    /// Plant a known metadata key for `root`, so a test can drive a DECRYPTABLE row without
    /// minting a valid ML-KEM wrap. Test builds only.
    ///
    /// ⚠ Scope: this proves the **degrade** property only, never that the unwrap works — see
    /// `crate::test_support`'s module doc for why that split is legitimate (the unwrap's
    /// witness is production, where its failure is maximally loud, so it cannot rot silently).
    #[cfg(test)]
    pub(crate) fn preseed_metadata_key(&mut self, root: Uuid, key: [u8; 32]) {
        self.metadata_keys.insert(root, Zeroizing::new(key));
    }

    /// Fetch + decap (and cache) a root folder's metadata key. The wrap endpoint is
    /// folder-type-agnostic (the private-folder alias of the share-folder path), so
    /// one route serves both private and share roots. Public so the create/rename
    /// commands can reuse a folder hierarchy's existing key.
    pub fn metadata_key(&mut self, root: Uuid) -> Result<Zeroizing<[u8; 32]>> {
        if let Some(key) = self.metadata_keys.get(&root) {
            return Ok(key.clone());
        }
        let path = format!("/v1/folders/{root}/metadata-key-wrap");
        let resp = http::get_json_signed(self.keystore, self.signing, self.server_url, &path)?;
        let wrapped = resp.get("wrapped_key").ok_or_else(|| {
            CliError::invalid_data("metadata-key-wrap response missing wrapped_key")
        })?;
        let key = unwrap_metadata_key_envelope(self.keystore, wrapped, root.as_bytes(), self.kem)?;
        self.metadata_keys.insert(root, key.clone());
        Ok(key)
    }

    /// Decrypt one already-fetched entry's §7.3 name, fetching (+caching) its root
    /// metadata key. For listings where the caller already holds the `root` + `target`
    /// ids and the `encrypted_name` envelope (e.g. the share-folder list, whose
    /// `SharedFolderView` carries both). The root key route is folder-type-agnostic
    /// and recipient-keyed, so this works whether I own the folder or am a recipient.
    pub fn decrypt_name(
        &mut self,
        root: Uuid,
        target: Uuid,
        encrypted_name: &Value,
    ) -> Result<String> {
        let key = self.metadata_key(root)?;
        decrypt_entry_name(&key, root, target, encrypted_name)
    }

    /// Every file id under `folder` (the folder itself + all its subfolders),
    /// following pagination on both the file and subfolder listings — the full set
    /// `share invite` must re-wrap DEKs for. Mirrors the web `Drive.filesUnder` (a
    /// BFS). Ids only (no name decryption), so it doesn't touch the metadata-key
    /// cache. A deep tree is walked in full — never silently truncated.
    pub fn files_under(&self, folder: Uuid) -> Result<Vec<Uuid>> {
        let mut file_ids = Vec::new();
        let mut queue = vec![folder];
        while let Some(current) = queue.pop() {
            for f in self.fetch_files(current)? {
                file_ids.push(uuid_field(&f, "file_id")?);
            }
            for sub in self.fetch_folders(Some(current))? {
                queue.push(uuid_field(&sub, "folder_id")?);
            }
        }
        Ok(file_ids)
    }

    /// Every folder directly under `parent` (top-level when `None`), following the
    /// keyset pagination cursor. Raw `FolderView` JSON; names decrypted separately.
    fn fetch_folders(&self, parent: Option<Uuid>) -> Result<Vec<Value>> {
        let base = match parent {
            Some(p) => format!("/v1/folders?parent_folder_id={p}"),
            None => "/v1/folders".to_string(),
        };
        self.fetch_paginated(&base, "folders")
    }

    /// Every file under `folder`, following the pagination cursor. Raw `FileView`
    /// JSON; names decrypted separately.
    fn fetch_files(&self, folder: Uuid) -> Result<Vec<Value>> {
        self.fetch_paginated(&format!("/v1/folders/{folder}/files"), "files")
    }

    /// Drain a keyset-paginated list endpoint: GET `base` (adding the `cursor` query
    /// each round), collecting `array_field` until `next_cursor` is null. The cursor
    /// is a URL-safe base64url token, safe to interpolate verbatim.
    fn fetch_paginated(&self, base: &str, array_field: &str) -> Result<Vec<Value>> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let path = match &cursor {
                Some(c) => {
                    let sep = if base.contains('?') { '&' } else { '?' };
                    format!("{base}{sep}cursor={c}")
                }
                None => base.to_string(),
            };
            let resp = http::get_json_signed(self.keystore, self.signing, self.server_url, &path)?;
            if let Some(arr) = resp.get(array_field).and_then(|v| v.as_array()) {
                out.extend(arr.iter().cloned());
            }
            match resp.get("next_cursor").and_then(|v| v.as_str()) {
                Some(c) => cursor = Some(c.to_string()),
                None => return Ok(out),
            }
        }
    }

    /// List + decrypt the folders directly under `parent` (top-level when `None`).
    /// Each entry's root is `root_folder_id` from the view, or its own id when it is
    /// a top-level folder.
    pub fn list_folders(&mut self, parent: Option<Uuid>) -> Result<Vec<FolderEntry>> {
        let raw = self.fetch_folders(parent)?;
        let mut out = Vec::with_capacity(raw.len());
        for v in &raw {
            let folder_id = uuid_field(v, "folder_id")?;
            let root = opt_uuid_field(v, "root_folder_id").unwrap_or(folder_id);
            // bug132(ii)/bug139: degrade THIS ROW, never the listing. The degradation
            // must cover the WHOLE per-folder name resolution — the metadata-KEY lookup
            // as well as the name decrypt (see `resolve_entry_name`). bug132(ii) wrapped
            // only the name decrypt, leaving `metadata_key(root)?` here to abort the whole
            // command on a junk *wrap* — the exact `invalid_data: unknown wrap alg`,
            // zero-rows failure its own comment named, one call too early (bug139). One
            // malformed blob used to deny a user their entire Drive view.
            let name = self.resolve_entry_name(root, folder_id, v);
            out.push(FolderEntry {
                folder_id,
                root_folder_id: root,
                name,
                created_at: i64_field(v, "created_at"),
                modified_at: i64_field(v, "modified_at"),
            });
        }
        Ok(out)
    }

    /// The full per-row name resolution, degrading to `None` on ANY failure — an
    /// unresolvable root metadata key (a junk wrap → `unknown wrap alg`), a missing
    /// `encrypted_name`, an invalid envelope, or a decrypt failure. A single malformed
    /// row never aborts a listing (bug139); it renders as `(unreadable)`. Mirrors the
    /// web client, whose per-folder `try/catch` wraps the whole decryption.
    ///
    /// **Each degrade now NAMES ITS CAUSE on stderr** (Gus, S162 review of bug139).
    /// Degrading on any failure is right, but it made two very different situations
    /// look identical: a junk wrap is **permanent** and the row will never be readable,
    /// while a failed `metadata_key` fetch is **transient** — `metadata_key` goes to the
    /// network, so a blip rendered a whole listing as `(unreadable)` and still exited 0.
    /// An agent that retries on error would handle the transient case correctly, and
    /// `(unreadable)` alone taught it nothing. The row still degrades; stdout is
    /// unchanged and remains the parseable surface. This restores the diagnosability the
    /// abort used to provide, without restoring the abort — and follows the share-list
    /// path, which already names its cause this way.
    fn resolve_entry_name(&mut self, root: Uuid, target: Uuid, v: &Value) -> Option<String> {
        let key = match self.metadata_key(root) {
            Ok(key) => key,
            Err(e) => {
                // Per ROOT, not per row: one bad root under a listing of many rows
                // should explain itself once, not once per line.
                if self.degrade_reported.insert(root) {
                    eprintln!(
                        "signet: cannot resolve the metadata key for folder root {root} \
                         — names under it list as (unreadable): {}",
                        e.message
                    );
                }
                return None;
            }
        };
        let Some(encrypted_name) = v.get("encrypted_name") else {
            eprintln!("signet: {target} has no encrypted_name — listing as (unreadable)");
            return None;
        };
        match decrypt_entry_name(&key, root, target, encrypted_name) {
            Ok(name) => Some(name),
            Err(e) => {
                // Genuinely per row: this one entry's envelope is bad, its siblings
                // may be fine, and each is worth naming.
                eprintln!(
                    "signet: cannot decrypt the name of {target} — listing as (unreadable): {}",
                    e.message
                );
                None
            }
        }
    }

    /// List + decrypt the files in `folder`. Files don't carry `root_folder_id`, so
    /// the caller supplies the hierarchy `root` (from a resolved path or
    /// `--root-folder-id`); the §7.3 name AAD needs it.
    pub fn list_files(&mut self, folder: Uuid, root: Uuid) -> Result<Vec<FileEntry>> {
        let raw = self.fetch_files(folder)?;
        // bug139: degrade rather than abort if the root metadata key is unresolvable
        // (a junk wrap → `unknown wrap alg`) — the files still list, as `(unreadable)`.
        // Files share one root, so resolve it once; `None` ⇒ every name degrades.
        let key = self.metadata_key(root).ok();
        let mut out = Vec::with_capacity(raw.len());
        for v in &raw {
            let file_id = uuid_field(v, "file_id")?;
            // bug132(ii)/bug139: degrade THIS ROW, never the listing (see `list_folders`).
            let name = key.as_ref().and_then(|k| {
                let encrypted_name = v.get("encrypted_name")?;
                decrypt_entry_name(k, root, file_id, encrypted_name).ok()
            });
            out.push(FileEntry {
                file_id,
                name,
                size_bytes: i64_field(v, "size_bytes"),
                plaintext_bytes: v.get("plaintext_bytes").and_then(|x| x.as_i64()),
                created_at: i64_field(v, "created_at"),
                modified_at: i64_field(v, "modified_at"),
            });
        }
        Ok(out)
    }

    /// The (root) share folders I'm a *recipient* of ("shared with me"), decrypted
    /// to `FolderEntry` so they resolve as top-level names alongside my owned folders
    /// (`GET /v1/share-folders`). A top-level share folder is its own root, and the
    /// metadata-key route is recipient-keyed. An entry whose name can't be decrypted
    /// is skipped (still addressable by `--folder-id`), so one bad entry never breaks
    /// resolution. Owned folders are not here — they come from `GET /v1/folders` — so
    /// there is no overlap. (Closes Bug006: a folder shared *with* me must resolve by
    /// the same name `share list` shows.)
    fn list_shared_folders(&mut self) -> Result<Vec<FolderEntry>> {
        let resp = http::get_json_signed(
            self.keystore,
            self.signing,
            self.server_url,
            // bug130 (F-12): the honest path — `GET /v1/share-folders` now returns folders you
            // OWN, matching what its POST creates.
            "/v1/shared-with-me",
        )?;
        let raw = resp
            .get("folders")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut out = Vec::with_capacity(raw.len());
        for v in &raw {
            let folder_id = uuid_field(v, "folder_id")?;
            // A top-level share folder is its own root; the view's field is nullable.
            let root = opt_uuid_field(v, "root_folder_id").unwrap_or(folder_id);
            let Some(encrypted_name) = v.get("encrypted_name") else {
                continue;
            };
            // Skip an entry we can't decrypt — it stays addressable by `--folder-id`.
            let Ok(name) = self.decrypt_name(root, folder_id, encrypted_name) else {
                continue;
            };
            out.push(FolderEntry {
                folder_id,
                root_folder_id: root,
                name: Some(name),
                // SharedFolderView carries no timestamps; resolution needs only name + ids.
                created_at: 0,
                modified_at: 0,
            });
        }
        Ok(out)
    }

    /// Resolve a folder path (`/Finance/Projects`) to its ids.
    pub fn resolve_folder(&mut self, path: &str) -> Result<ResolvedFolder> {
        let segments = parse_path(path)?;
        self.resolve_folder_segments(&segments)
    }

    /// Resolve a path for *creating* a folder: the **last** segment is the new
    /// folder's name (it doesn't exist yet), the preceding segments are its parent.
    /// A single-segment path is a new top-level folder (no parent). Returns the
    /// resolved parent (if any) and the new name.
    pub fn resolve_create_parent(
        &mut self,
        path: &str,
    ) -> Result<(Option<ResolvedFolder>, String)> {
        let segments = parse_path(path)?;
        let (parent_segs, name_seg) = segments.split_at(segments.len() - 1);
        let new_name = name_seg[0].clone();
        if parent_segs.is_empty() {
            Ok((None, new_name))
        } else {
            Ok((Some(self.resolve_folder_segments(parent_segs)?), new_name))
        }
    }

    /// Resolve a file path (`/Finance/notes.txt`) to its ids — files are always
    /// inside a folder, so the path needs at least one folder segment.
    pub fn resolve_file(&mut self, path: &str) -> Result<ResolvedFile> {
        let segments = parse_path(path)?;
        if segments.len() < 2 {
            return Err(CliError::invalid_args(
                "a file path needs a containing folder (e.g. /Folder/notes.txt) — files are always inside folders",
            ));
        }
        let (folder_segs, file_seg) = segments.split_at(segments.len() - 1);
        let folder = self.resolve_folder_segments(folder_segs)?;
        // bug132(ii): an entry whose name could not be decoded is NOT addressable by name —
        // it stays reachable by id. Filtering here (rather than letting a placeholder into the
        // matcher) is what stops an unreadable entry shadowing a real one.
        let files: Vec<_> = self
            .list_files(folder.folder_id, folder.root_folder_id)?
            .into_iter()
            .filter(|f| f.name.is_some())
            .collect();
        let file = match_one(
            files,
            &file_seg[0],
            "file",
            |f| f.name.clone().unwrap_or_default(),
            |f| (f.file_id, f.modified_at),
        )?;
        Ok(ResolvedFile {
            file_id: file.file_id,
            folder_id: folder.folder_id,
            root_folder_id: folder.root_folder_id,
        })
    }

    /// Walk pre-parsed segments: segment 0 is a top-level folder (its own root),
    /// each later segment a child under the matched root.
    fn resolve_folder_segments(&mut self, segments: &[String]) -> Result<ResolvedFolder> {
        // Top-level resolution spans both my owned folders (`GET /v1/folders`) and the
        // folders shared *with* me (`GET /v1/share-folders`) — a recipient addresses a
        // shared folder by the same name `share list` shows (Bug006). Deeper segments
        // come from the matched root via `parent_folder_id` (recipient-authorized).
        let mut top = self.list_folders(None)?;
        top.extend(self.list_shared_folders()?);
        // bug132(ii): unreadable names are not addressable by name (see `resolve_file`).
        top.retain(|f| f.name.is_some());
        let mut current = match_one(
            top,
            &segments[0],
            "folder",
            |f| f.name.clone().unwrap_or_default(),
            |f| (f.folder_id, f.modified_at),
        )?;
        for seg in &segments[1..] {
            let mut children = self.list_folders(Some(current.folder_id))?;
            children.retain(|f| f.name.is_some());
            current = match_one(
                children,
                seg,
                "folder",
                |f| f.name.clone().unwrap_or_default(),
                |f| (f.folder_id, f.modified_at),
            )?;
        }
        Ok(ResolvedFolder {
            folder_id: current.folder_id,
            root_folder_id: current.root_folder_id,
        })
    }
}

/// Decrypt one entry's §7.3 name under its root's metadata key.
fn decrypt_entry_name(
    metadata_key: &[u8; 32],
    root: Uuid,
    target: Uuid,
    encrypted_name: &Value,
) -> Result<String> {
    let envelope: NameEnvelope = serde_json::from_value(encrypted_name.clone())
        .map_err(|_| CliError::invalid_data("invalid encrypted_name envelope"))?;
    Ok(signet_crypto::encname::decrypt_name(
        metadata_key,
        root.as_bytes(),
        target.as_bytes(),
        &envelope,
    )?)
}

/// Split a path into its segments. Lenient on leading/trailing `/`; an empty
/// interior segment (`a//b`) or an all-slashes/empty path is an error.
fn parse_path(path: &str) -> Result<Vec<String>> {
    let trimmed = path.trim().trim_start_matches('/').trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(CliError::invalid_args("empty path"));
    }
    let segments: Vec<String> = trimmed.split('/').map(str::to_string).collect();
    if segments.iter().any(String::is_empty) {
        return Err(CliError::invalid_args(format!(
            "path '{path}' contains an empty segment"
        )));
    }
    Ok(segments)
}

/// Pick the single entry whose name equals `name`, or fail: zero matches →
/// `name_not_found`; more than one → `ambiguous_name` listing the candidates'
/// ids + `modified_at` (the caller disambiguates with `--{kind}-id`). Never a
/// silent pick. `name_of`/`id_of` project the entry's name and (id, modified_at).
fn match_one<T>(
    entries: Vec<T>,
    name: &str,
    kind: &str,
    name_of: impl Fn(&T) -> String,
    id_of: impl Fn(&T) -> (Uuid, i64),
) -> Result<T> {
    let mut found: Vec<T> = entries.into_iter().filter(|e| name_of(e) == name).collect();
    match found.len() {
        0 => Err(CliError::new(
            2,
            "name_not_found",
            format!("no {kind} named '{name}'"),
        )),
        1 => Ok(found.pop().expect("exactly one match")),
        n => {
            let mut msg = format!("'{name}' matches {n} {kind}s; pass --{kind}-id to choose one:");
            for entry in &found {
                let (id, modified) = id_of(entry);
                msg.push_str(&format!("\n  {id}  (modified_at {modified})"));
            }
            Err(CliError::new(2, "ambiguous_name", msg))
        }
    }
}

fn uuid_field(v: &Value, field: &str) -> Result<Uuid> {
    v.get(field)
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| CliError::invalid_data(format!("response entry missing/invalid {field}")))
}

fn opt_uuid_field(v: &Value, field: &str) -> Option<Uuid> {
    v.get(field)
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
}

fn i64_field(v: &Value, field: &str) -> i64 {
    v.get(field).and_then(Value::as_i64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn folder(name: &str, modified: i64) -> FolderEntry {
        FolderEntry {
            folder_id: Uuid::new_v4(),
            root_folder_id: Uuid::new_v4(),
            name: Some(name.to_string()),
            created_at: 0,
            modified_at: modified,
        }
    }

    #[test]
    fn parse_path_is_lenient_on_edge_slashes_strict_on_interior() {
        assert_eq!(parse_path("/A/B").unwrap(), vec!["A", "B"]);
        assert_eq!(parse_path("A/B/").unwrap(), vec!["A", "B"]);
        assert_eq!(parse_path("Finance").unwrap(), vec!["Finance"]);
        // A name with a space is one segment.
        assert_eq!(parse_path("/Q3 report").unwrap(), vec!["Q3 report"]);
        // Interior empties + empty paths are errors.
        assert!(parse_path("A//B").is_err());
        assert!(parse_path("").is_err());
        assert!(parse_path("/").is_err());
    }

    fn match_folder(entries: Vec<FolderEntry>, name: &str) -> Result<FolderEntry> {
        match_one(
            entries,
            name,
            "folder",
            |f| f.name.clone().unwrap_or_default(),
            |f| (f.folder_id, f.modified_at),
        )
    }

    #[test]
    fn match_one_picks_the_unique_match() {
        let got =
            match_folder(vec![folder("Finance", 1), folder("Personal", 2)], "Finance").unwrap();
        assert_eq!(got.name.as_deref(), Some("Finance"));
    }

    #[test]
    fn match_one_errors_with_exit_2_when_absent() {
        let err = match_folder(vec![folder("Finance", 1)], "Taxes").unwrap_err();
        assert_eq!(err.exit_code, 2);
        assert_eq!(err.code, "name_not_found");
    }

    #[test]
    fn match_one_fails_helpfully_on_a_collision() {
        let a = folder("Finance", 10);
        let b = folder("Finance", 20);
        let (id_a, id_b) = (a.folder_id, b.folder_id);
        let err = match_folder(vec![a, b, folder("Personal", 3)], "Finance").unwrap_err();
        assert_eq!(err.exit_code, 2);
        assert_eq!(err.code, "ambiguous_name");
        // Both candidate ids are listed so the caller can disambiguate with --folder-id.
        assert!(err.message.contains(&id_a.to_string()));
        assert!(err.message.contains(&id_b.to_string()));
        assert!(err.message.contains("--folder-id"));
    }

    // ── bug139 regression: the READ-side degrade ────────────────────────────────
    //
    // Fixtures live in `crate::test_support` — ONE home, shared with the `share_list`
    // degrade test in `commands.rs`, so the three surfaces' tests differ only in what they
    // poison and not in their scaffolding.
    //
    // ⚠ These tests prove the DEGRADE property only. `preseed`-style fixtures bypass the
    // real ML-KEM unwrap by planting a known metadata key; see `test_support`'s module doc
    // for why that split is legitimate and why these must never be cited as evidence that
    // the unwrap path works (Gus, S163).
    use crate::test_support::{junk_wrap_body, spawn_json_server, test_keystore};

    //
    // ⚠ WHY THIS EXISTS, AND WHY IT CANNOT BE RECREATED LATER (S163).
    // Every other test of a malformed `encrypted_name` asserts the WRITE-side
    // *refusal* (`server/tests/folders.rs::a_malformed_encrypted_name_is_refused_at_create`,
    // `server/tests/guardian_wrap_validation.rs`). Nothing asserted the READ side: that a
    // row which is ALREADY malformed degrades to `(unreadable)` instead of killing the
    // whole listing — which is exactly what bug139 fixed.
    //
    // That gap was invisible because one legacy malformed folder still existed on staging
    // (`a2ddad8b…`, an S158 F-005 adversarial artifact) and was serving as the de-facto
    // test. It is being deleted, and bug132(i)'s write-side validation means **no live
    // system can ever produce this condition again** — so without this test the fix would
    // become permanently unverifiable. Written before the deletion, deliberately.
    //
    // Pre-bug139 behaviour: `list_folders` returned `Err(invalid_data: unknown wrap alg)`
    // with ZERO rows — one bad blob denied a user their entire Drive view.

    /// A root whose metadata key cannot be resolved degrades **only its own row**, and
    /// the listing still succeeds with its healthy siblings intact.
    #[test]
    fn a_root_with_an_unresolvable_metadata_key_degrades_its_row_not_the_listing() {
        let good_root = Uuid::new_v4();
        let bad_root = Uuid::new_v4();
        let good_key: [u8; 32] = [7u8; 32];

        // The healthy row's name, encrypted under the key we will pre-seed into the
        // resolver's cache. Seeding lets the test exercise the degrade without having to
        // mint a valid ML-KEM wrap for the healthy root — the wrap path is covered
        // elsewhere; what is uncovered is the DEGRADE.
        let good_name = signet_crypto::encname::encrypt_name(
            &good_key,
            good_root.as_bytes(),
            good_root.as_bytes(),
            "healthy",
        )
        .expect("fixture: encrypt a valid name");

        let listing = serde_json::json!({
            "folders": [
                { "folder_id": good_root, "root_folder_id": good_root,
                  "encrypted_name": good_name, "created_at": 1, "modified_at": 1 },
                { "folder_id": bad_root, "root_folder_id": bad_root,
                  // Shape-wise a name, but it will never be reached: the ROOT's wrap
                  // fails first, which is precisely the call bug139 moved inside the
                  // degrade (bug132(ii) had wrapped only the decrypt, one call too late).
                  "encrypted_name": { "adversarial": "F005-junkwrap-name" },
                  "created_at": 2, "modified_at": 2 },
            ]
        })
        .to_string();

        // The junk wrap is served ONLY for `bad_root`; `good_root` never reaches the
        // network because its key is pre-seeded below.
        let port = spawn_json_server(listing, junk_wrap_body());
        let (_dir, ks, signing, kem) = test_keystore();

        let url = format!("http://127.0.0.1:{port}");
        let mut resolver = Resolver::new(&ks, &signing, &kem, &url);
        resolver
            .metadata_keys
            .insert(good_root, Zeroizing::new(good_key));

        let listed = resolver.list_folders(None).expect(
            "bug139: a root whose metadata key cannot be resolved must NOT abort the \
             listing — pre-fix this was Err(unknown wrap alg) with zero rows",
        );

        assert_eq!(
            listed.len(),
            2,
            "both rows must be present: the malformed one degrades, it does not vanish \
             (a silently dropped row is the same denial as an abort, just quieter)"
        );

        let good = listed
            .iter()
            .find(|e| e.folder_id == good_root)
            .expect("the healthy folder must still be listed");
        assert_eq!(
            good.name.as_deref(),
            Some("healthy"),
            "a sibling under a DIFFERENT, resolvable root must still decrypt — the \
             degrade must be scoped to the bad root, not applied listing-wide"
        );

        let bad = listed
            .iter()
            .find(|e| e.folder_id == bad_root)
            .expect("the malformed folder must still be listed");
        assert!(
            bad.name.is_none(),
            "the unresolvable row must degrade to None (rendered `(unreadable)`), got {:?}",
            bad.name
        );
    }

    /// The other two `resolve_entry_name` degrade branches — a row with NO
    /// `encrypted_name`, and a row whose envelope is unparseable — under a root whose
    /// key resolves fine. These are per-ROW failures, so a healthy sibling under the
    /// SAME root must be unaffected.
    #[test]
    fn a_bad_row_under_a_good_root_degrades_only_itself() {
        let root = Uuid::new_v4();
        let healthy = Uuid::new_v4();
        let no_name = Uuid::new_v4();
        let bad_envelope = Uuid::new_v4();
        let key: [u8; 32] = [11u8; 32];

        let healthy_name =
            signet_crypto::encname::encrypt_name(&key, root.as_bytes(), healthy.as_bytes(), "ok")
                .expect("fixture: encrypt a valid name");

        let listing = serde_json::json!({
            "folders": [
                { "folder_id": healthy, "root_folder_id": root,
                  "encrypted_name": healthy_name, "created_at": 1, "modified_at": 1 },
                // Branch 2: the field is absent entirely.
                { "folder_id": no_name, "root_folder_id": root,
                  "created_at": 2, "modified_at": 2 },
                // Branch 3: present, but not a §7.3 envelope — `decrypt_entry_name` fails
                // at deserialization. This is the literal shape a2ddad8b carried.
                { "folder_id": bad_envelope, "root_folder_id": root,
                  "encrypted_name": { "adversarial": "F005-junkwrap-name" },
                  "created_at": 3, "modified_at": 3 },
            ]
        })
        .to_string();

        let port = spawn_json_server(listing, junk_wrap_body());
        let (_dir, ks, signing, kem) = test_keystore();
        let url = format!("http://127.0.0.1:{port}");
        let mut resolver = Resolver::new(&ks, &signing, &kem, &url);
        resolver.metadata_keys.insert(root, Zeroizing::new(key));

        let listed = resolver
            .list_folders(None)
            .expect("a per-row name failure must never abort the listing");

        assert_eq!(listed.len(), 3, "all three rows must be present");
        let by = |id: Uuid| listed.iter().find(|e| e.folder_id == id).unwrap();

        assert_eq!(
            by(healthy).name.as_deref(),
            Some("ok"),
            "a healthy row under the SAME root as two broken ones must still decrypt — \
             the degrade is per row, not per listing and not per root here"
        );
        assert!(
            by(no_name).name.is_none(),
            "a row with no encrypted_name must degrade, not panic or abort"
        );
        assert!(
            by(bad_envelope).name.is_none(),
            "a row whose encrypted_name is not an envelope must degrade"
        );
    }

    /// ⚠ `list_files` implements the degrade a SECOND time, inline, rather than sharing
    /// `resolve_entry_name` (`metadata_key(root).ok()` + `and_then`). ROOTS §3.5: a
    /// decision replicated across two surfaces will diverge, and care is not the
    /// mitigation. Until the two have one home, the second surface needs its own guard —
    /// otherwise a fix applied to the folder path leaves the file path silently behind,
    /// which is exactly how bug132(ii) left bug139 alive.
    #[test]
    fn list_files_degrades_the_same_way_as_list_folders() {
        let root = Uuid::new_v4();
        let folder = Uuid::new_v4();
        let healthy = Uuid::new_v4();
        let bad = Uuid::new_v4();
        let key: [u8; 32] = [23u8; 32];

        let healthy_name = signet_crypto::encname::encrypt_name(
            &key,
            root.as_bytes(),
            healthy.as_bytes(),
            "report.pdf",
        )
        .expect("fixture: encrypt a valid name");

        let listing = serde_json::json!({
            "files": [
                { "file_id": healthy, "encrypted_name": healthy_name,
                  "size_bytes": 10, "created_at": 1, "modified_at": 1 },
                { "file_id": bad, "encrypted_name": { "adversarial": "junk" },
                  "size_bytes": 20, "created_at": 2, "modified_at": 2 },
            ]
        })
        .to_string();

        let port = spawn_json_server(listing, junk_wrap_body());
        let (_dir, ks, signing, kem) = test_keystore();
        let url = format!("http://127.0.0.1:{port}");
        let mut resolver = Resolver::new(&ks, &signing, &kem, &url);
        resolver.metadata_keys.insert(root, Zeroizing::new(key));

        let listed = resolver
            .list_files(folder, root)
            .expect("a bad file name must not abort the file listing either");

        assert_eq!(listed.len(), 2, "both files must be listed");
        assert_eq!(
            listed
                .iter()
                .find(|f| f.file_id == healthy)
                .unwrap()
                .name
                .as_deref(),
            Some("report.pdf"),
            "the healthy file must still decrypt"
        );
        assert!(
            listed
                .iter()
                .find(|f| f.file_id == bad)
                .unwrap()
                .name
                .is_none(),
            "the malformed file must degrade to None, not abort the listing"
        );
    }

    /// The file-side twin of the root-key failure: when the ROOT key cannot be resolved
    /// at all, every file name degrades but the listing still succeeds with its rows.
    #[test]
    fn list_files_survives_a_root_whose_metadata_key_is_unresolvable() {
        let root = Uuid::new_v4();
        let folder = Uuid::new_v4();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();

        let listing = serde_json::json!({
            "files": [
                { "file_id": a, "encrypted_name": { "adversarial": "x" },
                  "size_bytes": 1, "created_at": 1, "modified_at": 1 },
                { "file_id": b, "encrypted_name": { "adversarial": "y" },
                  "size_bytes": 2, "created_at": 2, "modified_at": 2 },
            ]
        })
        .to_string();

        // No pre-seeded key ⇒ the root wrap is fetched and is junk ⇒ `unknown wrap alg`.
        let port = spawn_json_server(listing, junk_wrap_body());
        let (_dir, ks, signing, kem) = test_keystore();
        let url = format!("http://127.0.0.1:{port}");
        let mut resolver = Resolver::new(&ks, &signing, &kem, &url);

        let listed = resolver.list_files(folder, root).expect(
            "an unresolvable ROOT key must degrade every file name, not deny the user \
             their file listing",
        );

        assert_eq!(listed.len(), 2, "both files must still be listed");
        assert!(
            listed.iter().all(|f| f.name.is_none()),
            "every name degrades when the root key is unresolvable"
        );
    }
}
