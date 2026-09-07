// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Graphical self-install for the notarized `signet.app` (macOS only;
//! Launch-Punch-List §1-27).
//!
//! A human installs Signet by **double-clicking** the downloaded `signet.app` — no
//! Terminal. Finder/LaunchServices launches the binary with no subcommand and no
//! controlling terminal; [`is_gui_launch`] detects that, and `main` routes it here
//! instead of to clap. [`run`] performs the one-time setup — the Rust equivalent of
//! `infrastructure/scripts/install.sh`: copy the app into the per-user support
//! location, put `signet` on the `PATH`, and lay down + load the always-on Garnet
//! **broker LaunchAgent** (`signet broker serve`) — then shows a native confirmation.
//! Re-runnable (repair / upgrade): a second double-click just re-installs idempotently.
//!
//! **Garnet transition (S096).** The installed daemon is now the Garnet **broker**
//! (`signet broker serve`), not the mount's host-signer. The install retires any
//! host-signer LaunchAgent left by an earlier install; the host-signer stays in the
//! binary as the manual, present-but-inactive fallback (run `signet host-signer` by
//! hand for comparison testing) but is no longer auto-installed. The broker LaunchAgent is
//! **always-on** (`RunAtLoad` + `KeepAlive=true`, Bug030(1)/S120), so the menu-bar shows
//! liveness from install time; its crypto serve-loop is internally credential-gated (see
//! `main`'s `run_broker_serve_with_menubar`). The file-placement half of install is factored
//! into [`install_files_from`], which the **assisted update** ([`crate::update`]) reuses.
//!
//! A `signet` invoked with a real subcommand (including `broker serve`, which the
//! LaunchAgent runs) never reaches here; a terminal `signet` with no args still gets
//! clap's help (it has a TTY). The whole module is macOS-only — the install target is
//! a Mac `.app`, and the bundled static-Linux helper never compiles it.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::Command;

use objc2::MainThreadMarker;
use objc2_app_kit::{NSAlert, NSApplication, NSApplicationActivationPolicy};
use objc2_foundation::NSString;

use crate::broker::DEFAULT_BROKER_BIND;
use crate::config::broker_credential_path;
use crate::error::{CliError, Result};
use crate::host_channel::{BROKER_LAUNCHD_LABEL, HOST_SIGNER_LAUNCHD_LABEL};

/// True if this process was launched by a Finder/LaunchServices double-click of the
/// `.app` (running from inside a `.app` bundle, with no real subcommand and no
/// controlling terminal) rather than from a shell.
///
/// The `.app`-bundle guard is load-bearing: a `cargo`-built or test binary
/// (`target/debug/signet`) is never inside a `.app`, so the intercept can never fire
/// under `cargo test` (where stdout is piped and there's no subcommand on some
/// helpers) — and a self-install only makes sense when launched from the app itself.
pub fn is_gui_launch() -> bool {
    if running_app_bundle().is_err() {
        return false;
    }
    let extra: Vec<String> = std::env::args().skip(1).collect();
    is_gui_invocation(
        &extra,
        std::io::stdin().is_terminal(),
        std::io::stdout().is_terminal(),
    )
}

/// The pure predicate (testable): a GUI launch passes **only** Finder/LaunchServices
/// launch artifacts (or nothing) AND has **no TTY** on either stdin or stdout.
///
/// A real double-click passes no arguments on modern macOS, or at most a
/// process-serial / AppKit artifact (`-psn_…`, `-NS…`). **Any other arg is a
/// deliberate CLI invocation that must reach clap** — a subcommand (`enroll`) *or* a
/// flag (`--version`, `--help`, `--quiet`). (An earlier cut keyed only on "no
/// bare-word subcommand", which wrongly routed `signet --version` in a non-TTY
/// context — a script / agent version check — into the installer.) The TTY check is
/// the backstop for an argument-less terminal call (`signet`), which still has a TTY
/// and falls through to clap's help.
fn is_gui_invocation(extra_args: &[String], stdin_tty: bool, stdout_tty: bool) -> bool {
    let only_launch_artifacts = extra_args
        .iter()
        .all(|a| a.starts_with("-psn_") || a.starts_with("-NS"));
    only_launch_artifacts && !stdin_tty && !stdout_tty
}

/// Run the graphical self-install, then show a native confirmation. Returns the
/// process exit code. Called from `main` only on a macOS GUI launch.
pub fn run() -> i32 {
    match install() {
        Ok(summary) => {
            show_alert("Signet is set up", &summary);
            0
        }
        Err(e) => {
            show_alert(
                "Signet setup didn’t finish",
                &format!("{e}\n\nYou can double-click Signet again to retry."),
            );
            1
        }
    }
}

/// The one-time setup (the Rust port of `install.sh`): copy the running `.app` into
/// the per-user support dir, place a `PATH` shim, retire any prior host-signer
/// LaunchAgent, and lay down + load the always-on Garnet **broker** LaunchAgent.
/// Idempotent. Returns a human-readable summary for the confirmation dialog.
fn install() -> Result<String> {
    let src_app = running_app_bundle()?;
    let placed = install_files_from(&src_app)?;
    // The GUI install runs from a fresh `signet` process (the double-clicked app), not the
    // running daemon, so the synchronous bootout→bootstrap→kickstart is safe here.
    load_launchagent(&placed.plist, BROKER_LAUNCHD_LABEL);
    Ok(format!(
        "Signet is installed.\n\n\
         You won’t see a window; it works quietly whenever your AI uses Signet Drive, \
         like Touch ID. A small ◉ in the menu bar confirms Signet is running; it’s there \
         now, ready for your first PRSN.\n\n\
         App: {}\nCLI: {}",
        placed.app.display(),
        placed.shim.display(),
    ))
}

/// The placed paths from [`install_files_from`].
pub(crate) struct PlacedInstall {
    /// The installed `.app` bundle (`~/Library/Application Support/Signet/signet.app`).
    pub app: PathBuf,
    /// The `PATH` shim symlink.
    pub shim: PathBuf,
    /// The broker LaunchAgent plist path (written but NOT loaded here).
    pub plist: PathBuf,
}

/// Place the Signet app + `PATH` shim + broker LaunchAgent plist from `src_app` — the running
/// bundle for a fresh [`install`], or a freshly-downloaded, Gatekeeper-verified bundle for an
/// **assisted update** ([`crate::update::perform_update`]). This does the file placement only;
/// it does **not** (re)load the LaunchAgent. The caller decides the relaunch: a fresh `signet`
/// process ([`install`]) reloads synchronously; the running always-on daemon (assisted update)
/// exits so launchd (`KeepAlive=true`) relaunches on the new binary — avoiding the
/// bootout-blocks-on-self deadlock. Idempotent.
pub(crate) fn install_files_from(src_app: &Path) -> Result<PlacedInstall> {
    let home = home_dir()?;
    let support_dir = home.join("Library/Application Support/Signet");
    let app_dst = support_dir.join("signet.app");

    // 1. Copy the app into the support dir — unless it *is* the installed copy (a re-launch /
    //    repair: nothing to copy onto itself). macOS lets us unlink a running executable's
    //    bundle (the inode persists until the old process exits on relaunch), so an assisted
    //    update can replace the bundle the current daemon is running from.
    if !same_path(src_app, &app_dst) {
        std::fs::create_dir_all(&support_dir).map_err(|e| {
            CliError::filesystem(format!("creating {}: {e}", support_dir.display()))
        })?;
        let _ = std::fs::remove_dir_all(&app_dst);
        copy_app(src_app, &app_dst)?;
    }
    let app_bin = app_dst.join("Contents/MacOS/signet");

    // 2. PATH shim, so the agent can invoke `signet`.
    let shim = place_shim(&app_bin)?;

    // 3. The broker's credential dir (where `signet broker provision` writes the
    //    credential the daemon loads) + the log dir. The credential itself is written
    //    later, at provision time; the always-on daemon shows the menu-bar (liveness)
    //    from install (Bug030(1)) and starts its crypto serve-loop once the credential exists.
    let cred_path = broker_credential_path();
    let cred_dir = cred_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| home.clone());
    let log_dir = home.join("Library/Logs/Signet");
    for d in [&cred_dir, &log_dir] {
        std::fs::create_dir_all(d)
            .map_err(|e| CliError::filesystem(format!("creating {}: {e}", d.display())))?;
    }
    let log = log_dir.join("broker.log");

    let agents_dir = home.join("Library/LaunchAgents");
    std::fs::create_dir_all(&agents_dir)
        .map_err(|e| CliError::filesystem(format!("creating {}: {e}", agents_dir.display())))?;

    // 4. Retire any host-signer LaunchAgent from an earlier install — under Garnet the
    //    broker is the installed daemon; the host-signer is the manual fallback (run
    //    `signet host-signer` by hand for comparison testing), no longer auto-installed.
    retire_launchagent(&agents_dir, HOST_SIGNER_LAUNCHD_LABEL);

    // 5. The always-on Garnet broker LaunchAgent (RunAtLoad + KeepAlive=true — it runs
    //    from install so the menu-bar shows liveness before the first PRSN; the crypto
    //    serve-loop is internally credential-gated). Bug030(1)/S120. Written, NOT loaded here.
    let plist_path = agents_dir.join(format!("{BROKER_LAUNCHD_LABEL}.plist"));
    std::fs::write(
        &plist_path,
        broker_launchagent_plist(&app_bin, &cred_path, DEFAULT_BROKER_BIND, &log),
    )
    .map_err(|e| CliError::filesystem(format!("writing {}: {e}", plist_path.display())))?;

    Ok(PlacedInstall {
        app: app_dst,
        shim,
        plist: plist_path,
    })
}

/// The Garnet broker LaunchAgent plist (label [`BROKER_LAUNCHD_LABEL`]): runs
/// `signet broker serve --credential <cred> --bind <bind>`, logging to `log`.
///
/// **`KeepAlive` is a bare `true` — the daemon is always-on from install (Bug030(1), S120).**
/// The broker `serve` process presents the menu-bar status item (liveness + version) from
/// install time, *before* any PRSN is provisioned, so a guardian can see at a glance that
/// Signet is running (the pre-fix gap: no menu-bar at all until the first enrollment — Chris's
/// live "I don't know if it's running"). The process blocks in the AppKit run loop even with
/// no credential, so `KeepAlive=true` does **not** thrash-restart it — the earlier `PathState`
/// gate existed only because the credential-less `serve` used to exit immediately (it no
/// longer does; see [`crate::main`]'s `run_broker_serve_with_menubar`). The security-critical
/// crypto serve-loop (SE keystore + mutual-TLS listener) stays **internally credential-gated**:
/// it starts only when the credential exists, so a credential-less always-on broker opens no
/// Secure Enclave and binds no listener (the S1 local-only-broker property is preserved).
/// `signet broker provision` kickstarts the daemon to pick up a freshly-written credential;
/// `signet uninstall` boots it out and deletes this plist.
fn broker_launchagent_plist(app_bin: &Path, cred_path: &Path, bind: &str, log: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{bin}</string>
    <string>broker</string>
    <string>serve</string>
    <string>--credential</string>
    <string>{cred}</string>
    <string>--bind</string>
    <string>{bind}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>StandardErrorPath</key><string>{log}</string>
  <key>StandardOutPath</key><string>{log}</string>
</dict>
</plist>
"#,
        label = BROKER_LAUNCHD_LABEL,
        bin = app_bin.display(),
        cred = cred_path.display(),
        bind = bind,
        log = log.display(),
    )
}

/// The `.app` bundle the running binary lives in: `current_exe()` is
/// `<app>.app/Contents/MacOS/signet` (canonicalize first — a `PATH` symlink leaves
/// `current_exe()` unresolved on macOS). Errors if not run from inside a `.app`.
fn running_app_bundle() -> Result<PathBuf> {
    let exe = std::fs::canonicalize(
        std::env::current_exe()
            .map_err(|e| CliError::filesystem(format!("locating the running binary: {e}")))?,
    )
    .map_err(|e| CliError::filesystem(format!("resolving the running binary: {e}")))?;
    let app = exe
        .parent() // .../Contents/MacOS
        .and_then(Path::parent) // .../Contents
        .and_then(Path::parent) // .../signet.app
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("app"))
        .ok_or_else(|| {
            CliError::invalid_args(
                "Signet must be installed by double-clicking the Signet app, not by \
                 running a bare binary."
                    .to_string(),
            )
        })?;
    Ok(app.to_path_buf())
}

/// True when `dst` exists and resolves to the same path as `src` (so a re-launch of
/// the already-installed app doesn't try to copy it onto itself).
fn same_path(src: &Path, dst: &Path) -> bool {
    match std::fs::canonicalize(dst) {
        Ok(d) => std::fs::canonicalize(src).map(|s| s == d).unwrap_or(false),
        Err(_) => false,
    }
}

/// Copy the app bundle with `ditto` (the macOS bundle-correct copy — preserves the
/// code signature + resource layout). `dst` was removed by the caller, so `ditto`
/// creates it as a fresh copy.
fn copy_app(src: &Path, dst: &Path) -> Result<()> {
    let status = Command::new("/usr/bin/ditto")
        .arg(src)
        .arg(dst)
        .status()
        .map_err(|e| CliError::filesystem(format!("running ditto: {e}")))?;
    if !status.success() {
        return Err(CliError::filesystem(format!(
            "copying {} → {} failed (ditto {status})",
            src.display(),
            dst.display()
        )));
    }
    Ok(())
}

/// Place the `signet` `PATH` shim: prefer `/usr/local/bin` (already on most PATHs),
/// fall back to `~/.local/bin`. Returns the shim path used.
fn place_shim(app_bin: &Path) -> Result<PathBuf> {
    if let Ok(shim) = try_symlink(app_bin, Path::new("/usr/local/bin/signet")) {
        return Ok(shim);
    }
    let home = home_dir()?;
    let local_bin = home.join(".local/bin");
    std::fs::create_dir_all(&local_bin)
        .map_err(|e| CliError::filesystem(format!("creating {}: {e}", local_bin.display())))?;
    try_symlink(app_bin, &local_bin.join("signet"))
}

/// `ln -sf app_bin link`: remove any existing link, then symlink. Returns `link` on
/// success (used for the fallible `/usr/local/bin` attempt).
fn try_symlink(app_bin: &Path, link: &Path) -> Result<PathBuf> {
    let _ = std::fs::remove_file(link);
    std::os::unix::fs::symlink(app_bin, link)
        .map(|()| link.to_path_buf())
        .map_err(|e| CliError::filesystem(format!("linking {}: {e}", link.display())))
}

/// (Re)load the `label` LaunchAgent into the user's `gui/<uid>` domain — bootout any prior
/// instance (best-effort), bootstrap the new plist, then kickstart it. Best-effort:
/// failures surface in the log, not as a hard install error (the agent loads on next login
/// regardless). For the always-on broker (Bug030(1)/S120), kickstart at install time starts
/// it immediately so the menu-bar (liveness) appears before the first PRSN; with no
/// credential yet it shows the "ready — no PRSNs" state and its crypto serve-loop stays
/// dormant until `signet broker provision` writes the credential.
fn load_launchagent(plist: &Path, label: &str) {
    let Some(domain) = gui_domain() else { return };
    let label_target = format!("{domain}/{label}");
    let plist = plist.to_string_lossy().to_string();
    let _ = Command::new("launchctl")
        .args(["bootout", &domain, &plist])
        .status();
    let _ = Command::new("launchctl")
        .args(["bootstrap", &domain, &plist])
        .status();
    let _ = Command::new("launchctl")
        .args(["kickstart", "-k", &label_target])
        .status();
}

/// Retire a previously-installed LaunchAgent: bootout its running instance from the
/// `gui/<uid>` domain (best-effort) and remove its plist so it doesn't reload at next
/// login. Used to transition a machine off the host-signer auto-install now that the
/// Garnet broker is the installed daemon. Idempotent — a no-op if it was never installed.
fn retire_launchagent(agents_dir: &Path, label: &str) {
    if let Some(domain) = gui_domain() {
        let _ = Command::new("launchctl")
            .args(["bootout", &format!("{domain}/{label}")])
            .status();
    }
    let _ = std::fs::remove_file(agents_dir.join(format!("{label}.plist")));
}

/// `gui/<uid>` — the per-user launchd domain (uid via `id -u`).
fn gui_domain() -> Option<String> {
    let out = Command::new("id").arg("-u").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let uid = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!uid.is_empty()).then(|| format!("gui/{uid}"))
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| CliError::config("HOME is not set".to_string()))
}

/// A native confirmation dialog (the install runs on the main thread, so AppKit is
/// safe here). Best-effort — a missing main thread just skips the dialog.
fn show_alert(title: &str, message: &str) {
    let Some(mtm) = MainThreadMarker::new() else {
        return;
    };
    let app = NSApplication::sharedApplication(mtm);
    // Accessory == LSUIElement at runtime (no Dock icon); activate so the alert is frontmost.
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
    app.activate();
    let alert = NSAlert::new(mtm);
    alert.setMessageText(&NSString::from_str(title));
    alert.setInformativeText(&NSString::from_str(message));
    alert.runModal();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gui_invocation_needs_no_subcommand_and_no_tty() {
        // A real Finder double-click: no args, no TTY.
        assert!(is_gui_invocation(&[], false, false));
        // Finder process-serial artifacts are not subcommands.
        assert!(is_gui_invocation(&["-psn_0_123456".into()], false, false));
        assert!(is_gui_invocation(
            &["-NSDocumentRevisionsDebugMode".into()],
            false,
            false
        ));
    }

    #[test]
    fn a_real_subcommand_is_never_a_gui_launch() {
        // The LaunchAgent runs `signet host-signer`; an agent runs `signet enroll` —
        // both have a bare-word subcommand, so they parse via clap, never install.
        assert!(!is_gui_invocation(&["host-signer".into()], false, false));
        assert!(!is_gui_invocation(&["enroll".into()], false, false));
    }

    #[test]
    fn a_terminal_with_a_tty_is_never_a_gui_launch() {
        // `signet` (or `signet --quiet`) typed in a terminal → clap's help, not install.
        assert!(!is_gui_invocation(&[], true, true));
        assert!(!is_gui_invocation(&[], true, false));
        assert!(!is_gui_invocation(&[], false, true));
        assert!(!is_gui_invocation(&["--quiet".into()], true, true));
    }

    #[test]
    fn a_flag_without_a_tty_is_not_a_gui_launch() {
        // The bug this fixes (caught by the live S060 install verification): a flag
        // with no bare-word subcommand and no TTY — `signet --version` / `--help` from
        // a script or an agent version check — is a deliberate CLI call. It must reach
        // clap, NOT the installer.
        assert!(!is_gui_invocation(&["--version".into()], false, false));
        assert!(!is_gui_invocation(&["--help".into()], false, false));
        assert!(!is_gui_invocation(&["-V".into()], false, false));
        assert!(!is_gui_invocation(&["-h".into()], false, false));
        assert!(!is_gui_invocation(&["--quiet".into()], false, false));
        assert!(!is_gui_invocation(
            &["--server-url".into(), "https://x".into()],
            false,
            false
        ));
    }

    #[test]
    fn broker_launchagent_plist_is_always_on_from_install() {
        let cred = "/Users/x/.config/signet/broker/credential.json";
        let plist = broker_launchagent_plist(
            Path::new(
                "/Users/x/Library/Application Support/Signet/signet.app/Contents/MacOS/signet",
            ),
            Path::new(cred),
            "127.0.0.1:8765",
            Path::new("/Users/x/Library/Logs/Signet/broker.log"),
        );
        // Runs `signet broker serve --credential <cred> --bind <bind>`.
        assert!(plist.contains(&format!("<string>{BROKER_LAUNCHD_LABEL}</string>")));
        assert!(plist.contains("<string>broker</string>"));
        assert!(plist.contains("<string>serve</string>"));
        assert!(plist.contains("<string>--credential</string>"));
        assert!(plist.contains(&format!("<string>{cred}</string>")));
        assert!(plist.contains("<string>--bind</string>"));
        assert!(plist.contains("<string>127.0.0.1:8765</string>"));
        assert!(plist.contains("<key>RunAtLoad</key><true/>"));
        // Bug030(1)/S120: KeepAlive is a bare `true` — the daemon is ALWAYS-ON from install
        // so the menu-bar (liveness) shows before the first PRSN. The old PathState-on-
        // credential gate is gone; the crypto serve-loop is internally credential-gated instead.
        assert!(plist.contains("<key>KeepAlive</key><true/>"));
        assert!(!plist.contains("<key>PathState</key>"));
        assert!(plist.contains("broker.log"));
    }
}
