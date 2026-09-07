// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Assisted in-app update for the macOS Signet app (bug039 Increment II; macOS only).
//!
//! The always-on broker daemon (Bug030(1)) offers an "Update Signet…" menu action when a newer
//! notarized release is published. This module performs the update end-to-end:
//!
//!   1. GET `/cli/latest-version`; compare to the running version ([`crate::commands::is_newer`]).
//!   2. Download the notarized zip (`/cli/signet-<v>-macos.zip`) + its `.sha256` companion.
//!   3. **Verify the download's SHA-256** against the served companion (integrity).
//!   4. Extract with `ditto` (bundle-correct).
//!   5. **Verify Gatekeeper accepts the extracted bundle** (`spctl -a -t exec`) — fail closed;
//!      never install a bundle that isn't notarized + stapled.
//!   6. Place the new bundle via the shared install path ([`crate::install::install_files_from`]).
//!
//! The caller (the menu action) then **exits the process**; launchd (`KeepAlive=true`, the
//! Increment-I always-on gate) relaunches the daemon on the new binary. No self-kickstart, no
//! bootout-blocks-on-self deadlock. macOS lets a running executable's bundle be replaced (the
//! old inode persists until the process exits), so replacing the bundle the current daemon runs
//! from is safe.
//!
//! Trust: the download rides the module's PQ-TLS agent; the `.sha256` guards integrity; and the
//! `spctl` pre-check is the security belt — a non-notarized bundle (a bad build, or a
//! substitution that somehow passed TLS) is rejected before it can replace the installed app.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::Config;
use crate::error::{CliError, Result};

/// The outcome of an assisted-update attempt.
pub enum UpdateOutcome {
    /// Already on the newest published version — nothing to do.
    AlreadyCurrent { version: String },
    /// The new bundle is installed. The caller should exit the process so launchd relaunches
    /// the daemon on the new binary.
    Installed { from: String, to: String },
}

/// Run the assisted update against the configured server. On [`UpdateOutcome::Installed`] the
/// caller exits the process (launchd relaunches on the new binary via `KeepAlive=true`).
pub fn perform_update() -> Result<UpdateOutcome> {
    let config = Config::load()?;
    let server = config.server_base_url.trim_end_matches('/').to_string();
    let current = env!("CARGO_PKG_VERSION").to_string();

    // 1. What is the latest published version?
    let latest = crate::http::get_text(&format!("{server}/cli/latest-version"), &[])?
        .trim()
        .to_string();
    if !crate::commands::is_newer(&latest, &current) {
        return Ok(UpdateOutcome::AlreadyCurrent { version: current });
    }

    // A per-run temp workdir, cleaned up on drop (success or error).
    let work = update_workdir();
    std::fs::create_dir_all(&work)
        .map_err(|e| CliError::filesystem(format!("creating {}: {e}", work.display())))?;
    let _cleanup = TempDirGuard(work.clone());

    // 2. Download the notarized zip + its .sha256 companion.
    let zip_url = format!("{server}/cli/signet-{latest}-macos.zip");
    let zip = work.join("signet-macos.zip");
    crate::http::download_to_file(&zip_url, &zip)?;
    let sha_text = crate::http::get_text(&format!("{zip_url}.sha256"), &[])?;
    let expected = parse_sha256_file(&sha_text).ok_or_else(|| {
        CliError::invalid_data("update: the server's .sha256 companion is malformed".to_string())
    })?;

    // 3. Verify download integrity BEFORE unpacking anything.
    verify_file_sha256(&zip, &expected)?;

    // 4. Extract the bundle (ditto preserves the bundle layout + code signature).
    let extracted = work.join("extracted");
    ditto_extract(&zip, &extracted)?;
    let app = find_dot_app(&extracted)?;

    // 5. Gatekeeper pre-check — never replace the installed app with a bundle Gatekeeper won't
    //    accept (notarized + stapled). Fail closed.
    spctl_assert_accepted(&app)?;

    // 6. Place the new bundle (copy + shim + plist; NO synchronous LaunchAgent reload — the
    //    caller exits and KeepAlive relaunches on the new binary).
    crate::install::install_files_from(&app)?;

    Ok(UpdateOutcome::Installed {
        from: current,
        to: latest,
    })
}

/// Parse a `shasum -a 256`-style companion (`<hex>  <filename>`): the first whitespace-separated
/// token, validated as exactly 64 hex chars. Returns lowercase hex, or `None` if malformed.
pub(crate) fn parse_sha256_file(text: &str) -> Option<String> {
    let tok = text.split_whitespace().next()?.to_ascii_lowercase();
    (tok.len() == 64 && tok.bytes().all(|b| b.is_ascii_hexdigit())).then_some(tok)
}

/// Verify `file`'s SHA-256 equals `expected_hex` (download integrity). Errors on mismatch.
fn verify_file_sha256(file: &Path, expected_hex: &str) -> Result<()> {
    let bytes = std::fs::read(file)
        .map_err(|e| CliError::filesystem(format!("reading {}: {e}", file.display())))?;
    let got = hex::encode(signet_crypto::hash::sha256(&bytes));
    if got.eq_ignore_ascii_case(expected_hex) {
        Ok(())
    } else {
        Err(CliError::invalid_data(format!(
            "update: the downloaded update failed its integrity check \
             (expected sha256 {expected_hex}, got {got})"
        )))
    }
}

/// `ditto -x -k <zip> <dst>` — the macOS bundle-correct un-archiver.
fn ditto_extract(zip: &Path, dst: &Path) -> Result<()> {
    let status = Command::new("/usr/bin/ditto")
        .args(["-x", "-k"])
        .arg(zip)
        .arg(dst)
        .status()
        .map_err(|e| CliError::filesystem(format!("running ditto: {e}")))?;
    if !status.success() {
        return Err(CliError::filesystem(format!(
            "update: extracting the download failed (ditto {status})"
        )));
    }
    Ok(())
}

/// Find `signet.app` (or the first top-level `*.app`) inside the extracted dir.
fn find_dot_app(dir: &Path) -> Result<PathBuf> {
    let signet = dir.join("signet.app");
    if signet.is_dir() {
        return Ok(signet);
    }
    let entries = std::fs::read_dir(dir)
        .map_err(|e| CliError::filesystem(format!("reading {}: {e}", dir.display())))?;
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() && p.extension().and_then(|x| x.to_str()) == Some("app") {
            return Ok(p);
        }
    }
    Err(CliError::invalid_data(
        "update: no .app was found in the downloaded archive".to_string(),
    ))
}

/// Assert Gatekeeper accepts `app` for execution (`spctl -a -t exec`). Fail closed — a bundle
/// that isn't notarized + accepted must never replace the installed one.
fn spctl_assert_accepted(app: &Path) -> Result<()> {
    let out = Command::new("/usr/sbin/spctl")
        .args(["-a", "-t", "exec", "-vv"])
        .arg(app)
        .output()
        .map_err(|e| CliError::filesystem(format!("running spctl: {e}")))?;
    if out.status.success() {
        Ok(())
    } else {
        let detail = String::from_utf8_lossy(&out.stderr);
        Err(CliError::invalid_data(format!(
            "update: the downloaded app was not accepted by Gatekeeper \
             (not notarized/stapled?): {}",
            detail.trim()
        )))
    }
}

/// The per-run temp workdir for the download + extraction.
fn update_workdir() -> PathBuf {
    std::env::temp_dir().join(format!("signet-update-{}", std::process::id()))
}

/// Best-effort recursive cleanup of the update workdir on drop.
struct TempDirGuard(PathBuf);
impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_sha256_file, verify_file_sha256};

    #[test]
    fn parse_sha256_file_takes_the_first_token_of_a_shasum_line() {
        // `shasum -a 256 file` → "<hex>  <filename>".
        let hex = "a".repeat(64);
        assert_eq!(
            parse_sha256_file(&format!("{hex}  signet-1.2.3-macos.zip\n")).as_deref(),
            Some(hex.as_str())
        );
        // Bare hex is also accepted; upper-case is normalized to lower-case.
        let upper = "AB".repeat(32); // 64 hex chars
        let lower = "ab".repeat(32);
        assert_eq!(parse_sha256_file(&upper).as_deref(), Some(lower.as_str()));
    }

    #[test]
    fn parse_sha256_file_rejects_malformed_companions() {
        assert_eq!(parse_sha256_file(""), None);
        assert_eq!(parse_sha256_file("not-a-hash  file"), None); // wrong length / non-hex
        assert_eq!(parse_sha256_file(&"a".repeat(63)), None); // too short
        assert_eq!(parse_sha256_file(&"z".repeat(64)), None); // non-hex chars
    }

    #[test]
    fn verify_file_sha256_accepts_a_matching_hash_and_rejects_a_mismatch() {
        let dir = std::env::temp_dir().join(format!("signet-update-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("payload.bin");
        std::fs::write(&f, b"the quick brown fox").unwrap();
        // sha256("the quick brown fox") — computed via the same helper the code uses.
        let good = hex::encode(signet_crypto::hash::sha256(b"the quick brown fox"));
        assert!(verify_file_sha256(&f, &good).is_ok());
        assert!(verify_file_sha256(&f, &"0".repeat(64)).is_err());
        // case-insensitive match.
        assert!(verify_file_sha256(&f, &good.to_uppercase()).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
