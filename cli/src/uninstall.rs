// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! `signet uninstall` — cleanly remove the Signet install from this Mac (macOS only).
//!
//! The reverse of [`crate::install`] / `infrastructure/scripts/install.sh`. It stops and
//! de-registers the Garnet broker LaunchAgent, deletes the app bundle, removes the
//! `signet` `PATH` shim, deletes the broker credential + logs, and retires any lingering
//! host-signer LaunchAgent from an earlier install.
//!
//! **It never touches the Secure-Enclave keys.** Those live in the login Keychain and
//! are the PRSN's identity — uninstalling removes the *install*, not the *identity*
//! (deleting the SE keys would destroy the account, which under the no-re-home model is
//! recoverable only via the Guardian). The Keychain is deliberately out of scope here.
//!
//! Confirm-before by default; `--yes` skips the prompt (scripted removal). Without a TTY
//! and without `--yes` it refuses rather than hang. macOS-only (there is no such install
//! to remove on other platforms; the bundled static-Linux `signet` never compiles it).

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use crate::config::broker_dir;
use crate::error::{CliError, Result};
use crate::host_channel::{BROKER_LAUNCHD_LABEL, HOST_SIGNER_LAUNCHD_LABEL, bootout_launchagent};

/// The filesystem locations a Signet install lays down, computed from `home` +
/// `broker_dir`. Pure (no I/O) so the path set is unit-testable without touching disk or
/// mutating the process environment.
struct Layout {
    /// `~/Library/LaunchAgents/ai.prsnex.signet.broker.plist`.
    broker_plist: PathBuf,
    /// `~/Library/LaunchAgents/ai.prsnex.signet.host-signer.plist` (retired if present).
    host_signer_plist: PathBuf,
    /// `~/Library/Application Support/Signet` — the whole support dir (ours; holds the app).
    app_support: PathBuf,
    /// `<app_support>/signet.app/Contents/MacOS/signet` — the shim's symlink target.
    app_bin: PathBuf,
    /// The two candidate `PATH` shim locations; only the one that is a symlink *into our
    /// app* is removed (never an unrelated `signet` on the `PATH`).
    shims: Vec<PathBuf>,
    /// `<config-dir>/broker` — the provisioned broker credential (re-provisionable).
    broker_dir: PathBuf,
    /// `~/Library/Logs/Signet`.
    logs_dir: PathBuf,
}

impl Layout {
    fn compute(home: &Path, broker_dir: PathBuf) -> Self {
        let launch_agents = home.join("Library/LaunchAgents");
        let app_support = home.join("Library/Application Support/Signet");
        let app_bin = app_support.join("signet.app/Contents/MacOS/signet");
        Self {
            broker_plist: launch_agents.join(format!("{BROKER_LAUNCHD_LABEL}.plist")),
            host_signer_plist: launch_agents.join(format!("{HOST_SIGNER_LAUNCHD_LABEL}.plist")),
            app_support,
            app_bin,
            shims: vec![
                PathBuf::from("/usr/local/bin/signet"),
                home.join(".local/bin/signet"),
            ],
            broker_dir,
            logs_dir: home.join("Library/Logs/Signet"),
        }
    }
}

/// What became of one removal target.
enum Outcome {
    Removed,
    Absent,
    Failed(String),
}

/// One line of the removal report.
struct Item {
    label: &'static str,
    path: PathBuf,
    outcome: Outcome,
}

/// Run `signet uninstall`. `assume_yes` skips the confirmation prompt.
pub fn run(assume_yes: bool) -> Result<()> {
    let home = home_dir()?;
    let layout = Layout::compute(&home, broker_dir());

    // ── confirm (unless --yes) ────────────────────────────────────────────────
    if !assume_yes {
        if !std::io::stdin().is_terminal() {
            return Err(CliError::invalid_args(
                "refusing to uninstall without confirmation in a non-interactive context. \
                 Re-run as `signet uninstall --yes`."
                    .to_string(),
            ));
        }
        print_plan(&layout);
        if !confirm()? {
            eprintln!("Uninstall cancelled. Nothing was changed.");
            return Ok(());
        }
    }

    // ── deregister this Mac's broker from the server (best-effort, while the credential exists) ─
    best_effort_deregister();

    // ── stop the daemons BEFORE removing their plists (best-effort) ───────────
    // Booting out first drops launchd's `KeepAlive` management; removing the plist then
    // stops it reloading at next login.
    let broker_stopped = bootout_launchagent(BROKER_LAUNCHD_LABEL);
    let _ = bootout_launchagent(HOST_SIGNER_LAUNCHD_LABEL);

    // ── remove everything (best-effort; collect outcomes) ─────────────────────
    let mut report = vec![
        remove_file_item("broker LaunchAgent", &layout.broker_plist),
        remove_file_item("host-signer LaunchAgent", &layout.host_signer_plist),
        remove_dir_item("Signet app", &layout.app_support),
    ];
    // Only remove a shim that is a symlink pointing at *our* app binary.
    for shim in &layout.shims {
        if shim_is_ours(shim, &layout.app_bin) {
            report.push(remove_file_item("signet command", shim));
        }
    }
    report.push(remove_dir_item("broker credential", &layout.broker_dir));
    report.push(remove_dir_item("logs", &layout.logs_dir));

    print_report(broker_stopped, &report);

    // Surface any hard failure as a non-zero exit so a script notices, but only after
    // doing everything else (a locked file shouldn't abort the rest of the removal).
    if report
        .iter()
        .any(|i| matches!(i.outcome, Outcome::Failed(_)))
    {
        return Err(CliError::filesystem(
            "uninstall finished with errors. See the report above (some items may need \
             manual removal)."
                .to_string(),
        ));
    }
    Ok(())
}

/// Ask the server to forget this Mac's broker before the local install is removed (#37 part a).
/// Loads the broker credential (if any) and POSTs a deregister over the Garnet mutual-TLS ingress,
/// authenticated by the broker's own K_bc leaf. **Every** failure — no credential, an unreachable
/// server, a non-2xx — is non-fatal: the local removal proceeds regardless (a stale server row is
/// still clearable from the dashboard "remove this Mac" or replaced by a re-provision). This is the
/// clean path when the Mac is alive; it never blocks or fails the uninstall.
fn best_effort_deregister() {
    let Ok(cred) =
        crate::broker_credential::BrokerCredential::load(&crate::config::broker_credential_path())
    else {
        return; // no credential (never provisioned / already removed) — nothing to deregister
    };
    match cred.grant_status_client().and_then(|c| c.deregister()) {
        Ok(()) => eprintln!("Deregistered this Mac's broker from the server."),
        Err(_) => eprintln!(
            "Note: could not reach the server to deregister the broker. Removing the local \
             install anyway. If your account still lists this Mac, remove it from the web \
             dashboard (\"Drive access\" → remove this Mac), or it is replaced when you set up \
             a new Mac."
        ),
    }
}

/// True iff `shim` is a symlink pointing at our app binary (`app_bin`). The guard that
/// keeps uninstall from deleting an unrelated `signet` that happens to be on the `PATH`:
/// the install creates the shim as `ln -sf <app_bin> <shim>`, so a genuine Signet shim
/// resolves (via `read_link`, one hop) exactly to `app_bin`. A regular file, a broken
/// non-Signet link, or a link elsewhere all return false.
fn shim_is_ours(shim: &Path, app_bin: &Path) -> bool {
    let is_symlink = std::fs::symlink_metadata(shim)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);
    is_symlink
        && std::fs::read_link(shim)
            .map(|t| t == app_bin)
            .unwrap_or(false)
}

/// `remove_file`, mapped to an [`Outcome`] (a missing target is `Absent`, not an error —
/// uninstall is idempotent). On a symlink this removes the link, never its target.
fn remove_file_item(label: &'static str, path: &Path) -> Item {
    let outcome = match std::fs::remove_file(path) {
        Ok(()) => Outcome::Removed,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Outcome::Absent,
        Err(e) => Outcome::Failed(e.to_string()),
    };
    Item {
        label,
        path: path.to_path_buf(),
        outcome,
    }
}

/// `remove_dir_all`, mapped to an [`Outcome`] (a missing target is `Absent`).
fn remove_dir_item(label: &'static str, path: &Path) -> Item {
    let outcome = match std::fs::remove_dir_all(path) {
        Ok(()) => Outcome::Removed,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Outcome::Absent,
        Err(e) => Outcome::Failed(e.to_string()),
    };
    Item {
        label,
        path: path.to_path_buf(),
        outcome,
    }
}

/// Print what uninstall will remove + what it preserves, before the confirmation prompt.
fn print_plan(layout: &Layout) {
    eprintln!("This will remove Signet from this Mac:");
    eprintln!("  • the Signet broker (stopped, then its LaunchAgent removed)");
    eprintln!("  • the app            {}", layout.app_support.display());
    eprintln!("  • the signet command (its PATH shim, if it points here)");
    eprintln!("  • the broker login   {}", layout.broker_dir.display());
    eprintln!("  • logs               {}", layout.logs_dir.display());
    eprintln!();
    eprintln!(
        "Your Secure-Enclave keys are PRESERVED (in the login Keychain): uninstalling \
         removes the install, not your PRSN identity."
    );
}

/// Prompt `y/N` on stderr; true only on an explicit yes.
fn confirm() -> Result<bool> {
    use std::io::Write;
    eprint!("\nProceed? [y/N] ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| CliError::input_read(format!("reading confirmation: {e}")))?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// Print the per-item removal report + a closing summary.
fn print_report(broker_stopped: bool, report: &[Item]) {
    eprintln!();
    if broker_stopped {
        eprintln!("✓ stopped the Signet broker");
    }
    for item in report {
        match &item.outcome {
            Outcome::Removed => eprintln!("✓ removed {}: {}", item.label, item.path.display()),
            Outcome::Absent => eprintln!("· {} already gone", item.label),
            Outcome::Failed(e) => {
                eprintln!(
                    "✗ could not remove {} ({}): {e}",
                    item.label,
                    item.path.display()
                )
            }
        }
    }
    let removed = report
        .iter()
        .filter(|i| matches!(i.outcome, Outcome::Removed))
        .count();
    let failed = report
        .iter()
        .filter(|i| matches!(i.outcome, Outcome::Failed(_)))
        .count();
    eprintln!();
    if failed == 0 {
        eprintln!(
            "Signet is uninstalled ({removed} item(s) removed). Your keys were left untouched."
        );
    } else {
        eprintln!(
            "Uninstall finished with {failed} problem(s); {removed} item(s) removed. Your keys \
             were left untouched."
        );
    }
}

/// `$HOME` as a `PathBuf`, or a config error if unset.
fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| CliError::config("HOME is not set".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_places_every_target_under_the_given_home() {
        let home = Path::new("/Users/x");
        let l = Layout::compute(home, PathBuf::from("/Users/x/.config/signet/broker"));
        assert_eq!(
            l.broker_plist,
            Path::new("/Users/x/Library/LaunchAgents/ai.prsnex.signet.broker.plist")
        );
        assert_eq!(
            l.host_signer_plist,
            Path::new("/Users/x/Library/LaunchAgents/ai.prsnex.signet.host-signer.plist")
        );
        assert_eq!(
            l.app_support,
            Path::new("/Users/x/Library/Application Support/Signet")
        );
        assert_eq!(
            l.app_bin,
            Path::new(
                "/Users/x/Library/Application Support/Signet/signet.app/Contents/MacOS/signet"
            )
        );
        assert_eq!(l.logs_dir, Path::new("/Users/x/Library/Logs/Signet"));
        // Both candidate shim locations are considered.
        assert!(l.shims.contains(&PathBuf::from("/usr/local/bin/signet")));
        assert!(
            l.shims
                .contains(&PathBuf::from("/Users/x/.local/bin/signet"))
        );
    }

    #[test]
    fn a_missing_target_is_absent_not_an_error() {
        let missing = std::env::temp_dir().join(format!(
            "signet-uninstall-test-missing-{}-{}",
            std::process::id(),
            "x"
        ));
        assert!(matches!(
            remove_file_item("x", &missing).outcome,
            Outcome::Absent
        ));
        assert!(matches!(
            remove_dir_item("x", &missing).outcome,
            Outcome::Absent
        ));
    }

    #[test]
    fn shim_is_ours_only_for_a_symlink_to_our_app_bin() {
        let base =
            std::env::temp_dir().join(format!("signet-uninstall-shimtest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();

        let app_bin = base.join("signet.app/Contents/MacOS/signet");
        std::fs::create_dir_all(app_bin.parent().unwrap()).unwrap();
        std::fs::write(&app_bin, b"binary").unwrap();

        // A symlink to our app binary → ours.
        let good = base.join("good-signet");
        std::os::unix::fs::symlink(&app_bin, &good).unwrap();
        assert!(shim_is_ours(&good, &app_bin));

        // A symlink to something else → not ours.
        let other = base.join("other-bin");
        std::fs::write(&other, b"other").unwrap();
        let bad = base.join("bad-signet");
        std::os::unix::fs::symlink(&other, &bad).unwrap();
        assert!(!shim_is_ours(&bad, &app_bin));

        // A regular file named `signet` → not ours (never delete a real binary).
        let regular = base.join("regular-signet");
        std::fs::write(&regular, b"someone-elses-signet").unwrap();
        assert!(!shim_is_ours(&regular, &app_bin));

        // A missing path → not ours.
        assert!(!shim_is_ours(&base.join("nope"), &app_bin));

        let _ = std::fs::remove_dir_all(&base);
    }
}
