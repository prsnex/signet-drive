// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! `signet host-channel` — host-side provisioning + management of the bind-mounted
//! delegation channels a containerized PRSN uses to reach the host Secure Enclave
//! (Account-and-Kit spec §f.7).
//!
//! `provision` is a **container-creation-time** action, run on the host by the
//! operator BEFORE the container's agent runs `signet enroll`. It:
//!   1. generates the per-PRSN channel secret + a stable **channel id** (NOT the
//!      handle — the handle is chosen later, at enrollment, and TOFU-pinned by the
//!      host-signer, §f.3a);
//!   2. creates the host-side **channel folder** (bind-mounted read-write into the
//!      container) and a **separate secret folder** — never the channel folder
//!      (§f.4: a secret in the channel folder is readable by anything that can read
//!      the channel);
//!   3. registers the channel with the host-signer (`registry.toml`);
//!   4. emits the container-side material — the env + a bind-mount/run snippet for
//!      Docker and Apple `container`.
//!
//! The operator then creates the container with that material; inside it, `signet
//! enroll` delegates keygen to the host-signer (which pins the handle on the first
//! keygen). Host-side only — this never touches the SE (the host-signer owns SE
//! access). The registry + secrets live 0600 under `<config_dir>/host-signer`
//! (`config::host_signer_dir`).

use std::path::{Path, PathBuf};

use rand_core::{OsRng, RngCore};

use crate::error::{CliError, Result};
use crate::host_signer::{ChannelConfig, Registry};
use crate::output::OutputMode;

/// In-container mount targets (fixed, non-secret paths the snippet + the container
/// env agree on). The channel is read-write (request/response files); the secret dir
/// is read-only.
const IN_CONTAINER_CHANNEL_DIR: &str = "/run/signet/channel";
const IN_CONTAINER_SECRET_DIR: &str = "/run/signet/secret";
const IN_CONTAINER_SECRET_FILE: &str = "/run/signet/secret/secret.hex";
/// Where the host delivers the bundled Linux `signet` for the container to run.
const IN_CONTAINER_BIN_DIR: &str = "/run/signet/bin";

/// The host-signer LaunchAgent's launchd label — must match the plist `install.sh` lays
/// down. `provision` kickstarts this label so a newly-provisioned channel is served
/// without a manual restart.
pub const HOST_SIGNER_LAUNCHD_LABEL: &str = "ai.prsnex.signet.host-signer";

/// The Garnet SE-broker LaunchAgent's launchd label — must match the plist the graphical
/// install ([`crate::install`]) lays down. `signet broker provision` kickstarts this label
/// so a freshly-provisioned broker starts serving without a manual restart. The Garnet
/// successor to [`HOST_SIGNER_LAUNCHD_LABEL`] (co-located here as the daemon-launchd home;
/// under Garnet the broker is the installed daemon and the host-signer is the manual,
/// present-but-inactive fallback).
pub const BROKER_LAUNCHD_LABEL: &str = "ai.prsnex.signet.broker";

/// Everything a caller needs to present the container-side material after a
/// successful [`provision_core`]: the CLI prints it (stderr guidance + a stdout JSON
/// receipt); the menu-bar "Add a containerized PRSN…" action shows it in an alert.
pub struct ProvisionReceipt {
    /// The channel id (provided or freshly generated).
    pub channel_id: String,
    pub channel_dir: PathBuf,
    pub secret_file: PathBuf,
    pub registry_path: PathBuf,
    /// The in-container `signet` path: `/run/signet/bin/signet` when the bundled Linux
    /// helper was delivered host-side, else `signet` (the container must carry its own).
    pub signet_in_container: &'static str,
    /// Whether the bundled Linux `signet` was delivered for the container to bind-mount.
    pub bin_delivered: bool,
    /// Ready-to-run `docker` / Apple `container` snippets (with `SIGNET_HANDLE` filled
    /// in when a handle was supplied, else a `<your-PRSN-handle>` placeholder).
    pub docker_snippet: String,
    pub apple_snippet: String,
}

/// Provision a new host-delegation channel for a containerized PRSN and return the
/// container-side material as a [`ProvisionReceipt`] — the shared core behind both the
/// CLI `host-channel provision` and the menu-bar "Add a containerized PRSN…" action.
///
/// `channel_id` defaults to a fresh random id. `handle` (the PRSN handle, e.g.
/// `ada-ai`) is folded into the snippets' `SIGNET_HANDLE` when known (the menu action
/// prompts for it); the CLI passes `None` → a `<your-PRSN-handle>` placeholder. Setting
/// `SIGNET_HANDLE` is what arms the launch-binding cross-check (§11) by default, so the
/// snippet always carries the line.
///
/// Side effects only (folders, secret file, registry) — never touches the SE. The
/// caller is responsible for any host-signer reload (the daemon reads the registry at
/// startup): the CLI kickstarts the LaunchAgent after this returns.
pub fn provision_core(
    host_signer_dir: &Path,
    channel_id: Option<&str>,
    handle: Option<&str>,
) -> Result<ProvisionReceipt> {
    let id = match channel_id {
        Some(s) => {
            validate_channel_id(s)?;
            s.to_string()
        }
        None => random_channel_id(),
    };

    let registry_path = host_signer_dir.join("registry.toml");
    let state_dir = host_signer_dir.join("state");
    let channel_dir = host_signer_dir.join("channels").join(&id);
    let secret_dir = host_signer_dir.join("secrets").join(&id);

    // Load-or-init the registry; refuse a duplicate id (no silent clobber of a live
    // channel's secret).
    let mut registry = Registry::load_or_init(&registry_path, &state_dir)?;
    if registry.channels.iter().any(|c| c.id == id) {
        return Err(CliError::invalid_args(format!(
            "channel id '{id}' is already registered in {}",
            registry_path.display()
        )));
    }

    // Generate the per-PRSN secret (the AEAD key root for this channel, §f.4).
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let secret_hex = hex::encode(secret);

    // Host-side folders.
    create_dir_secure(&channel_dir)?;
    create_dir_secure(&secret_dir)?;
    create_dir_secure(&state_dir)?;

    // The secret file the container reads via the read-only bind-mount.
    let secret_file = secret_dir.join("secret.hex");
    write_secret_file(&secret_file, &secret_hex)?;

    // Register the channel (the host-signer reads this at startup, §f.7).
    registry.channels.push(ChannelConfig {
        id: id.clone(),
        dir: channel_dir.clone(),
        secret_hex,
    });
    write_registry(&registry_path, &registry)?;

    // Deliver the bundled Linux `signet` for the container to bind-mount — one install,
    // no separate download. `None` when run from the bare dev binary (not the `.app`);
    // then the container must already carry `signet`.
    let bin_dir = deliver_linux_binary(host_signer_dir);
    let signet_in_container = if bin_dir.is_some() {
        "/run/signet/bin/signet"
    } else {
        "signet"
    };

    let docker = run_snippet(
        "docker",
        &id,
        &channel_dir,
        &secret_dir,
        bin_dir.as_deref(),
        handle,
    );
    let apple = run_snippet(
        "container",
        &id,
        &channel_dir,
        &secret_dir,
        bin_dir.as_deref(),
        handle,
    );

    Ok(ProvisionReceipt {
        channel_id: id,
        channel_dir,
        secret_file,
        registry_path,
        signet_in_container,
        bin_delivered: bin_dir.is_some(),
        docker_snippet: docker,
        apple_snippet: apple,
    })
}

/// Provision a new host-delegation channel for a containerized PRSN (CLI path).
/// `channel_id` defaults to a fresh random id (the handle is unknown until
/// enrollment). Prints human guidance → stderr and a machine receipt → stdout.
pub fn provision(host_signer_dir: &Path, channel_id: Option<&str>, out: &OutputMode) -> Result<()> {
    let r = provision_core(host_signer_dir, channel_id, None)?;

    let bin_note = if r.bin_delivered {
        "   `signet` is delivered into the container at /run/signet/bin/signet."
    } else {
        "   (No bundled `signet` found. Run from the installed Signet app to deliver it,\n\
         \x20  or ensure your container image already has `signet`.)"
    };

    // Human guidance → stderr; a machine receipt → stdout (mirrors `signet enroll`).
    eprintln!(
        "✓ provisioned host-delegation channel '{id}'\n\
         \n\
         Next:\n\
         1. Create your container with one of the snippets below (bind-mounts the channel\n\
         \x20  read-write + the secret read-only + the `signet` binary, and sets the\n\
         \x20  SIGNET_HOST_CHANNEL_* env). Replace SIGNET_HANDLE=<your-PRSN-handle> with the\n\
         \x20  PRSN's handle (e.g. ada-ai); it arms the launch-binding cross-check.\n\
         2. Inside the container, run `{signet_cmd} enroll`; keygen delegates to the\n\
         \x20  host-signer, which pins this channel to the PRSN handle on its first keygen (§f.3a).\n\
         {bin_note}\n\
         \n\
         Docker:\n{docker}\n\nApple container:\n{apple}\n",
        id = r.channel_id,
        signet_cmd = r.signet_in_container,
        docker = r.docker_snippet,
        apple = r.apple_snippet,
    );

    out.print_json(&serde_json::json!({
        "channel_id": r.channel_id,
        "channel_dir": r.channel_dir.display().to_string(),
        "secret_file": r.secret_file.display().to_string(),
        "registry": r.registry_path.display().to_string(),
        "signet_in_container": r.signet_in_container,
        "container_env": {
            "SIGNET_HOST_CHANNEL_DIR": IN_CONTAINER_CHANNEL_DIR,
            "SIGNET_HOST_CHANNEL_ID": r.channel_id,
            "SIGNET_HOST_CHANNEL_SECRET_FILE": IN_CONTAINER_SECRET_FILE,
            "SIGNET_HANDLE": "<your-PRSN-handle>",
        },
        "run_snippets": { "docker": r.docker_snippet, "apple_container": r.apple_snippet },
    }))
}

/// List the provisioned channels + each one's pinned handle (if it has enrolled).
pub fn list(host_signer_dir: &Path, out: &OutputMode) -> Result<()> {
    let registry_path = host_signer_dir.join("registry.toml");
    if !registry_path.exists() {
        return out.print_json(&serde_json::json!({ "channels": [] }));
    }
    let registry = Registry::load(&registry_path)?;
    let channels: Vec<_> = registry
        .channels
        .iter()
        .map(|c| {
            let pin = registry.state_dir.join(format!("{}.handle", c.id));
            let pinned = std::fs::read_to_string(&pin)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            serde_json::json!({
                "channel_id": c.id,
                "channel_dir": c.dir.display().to_string(),
                "pinned_handle": pinned,
            })
        })
        .collect();
    out.print_json(&serde_json::json!({ "channels": channels }))
}

/// Remove a channel: drop its registry entry + delete its host-side folders + pinned
/// state. Does NOT delete the PRSN's SE keys or account (device-bound, separate).
/// `force` is required (destructive).
pub fn remove(
    host_signer_dir: &Path,
    channel_id: &str,
    force: bool,
    out: &OutputMode,
) -> Result<()> {
    let registry_path = host_signer_dir.join("registry.toml");
    if !registry_path.exists() {
        return Err(CliError::invalid_args(format!(
            "no host-signer registry at {}",
            registry_path.display()
        )));
    }
    let mut registry = Registry::load(&registry_path)?;
    let idx = registry
        .channels
        .iter()
        .position(|c| c.id == channel_id)
        .ok_or_else(|| {
            CliError::invalid_args(format!("no channel '{channel_id}' in the registry"))
        })?;
    if !force {
        return Err(CliError::invalid_args(format!(
            "removing channel '{channel_id}' deletes its host-side folders + registry entry \
             (NOT the PRSN's SE keys or account: those are device-bound and separate); \
             re-run with --force"
        )));
    }

    let removed = registry.channels.remove(idx);
    write_registry(&registry_path, &registry)?;
    // Best-effort cleanup; a leftover folder is harmless (the entry is already gone).
    let _ = std::fs::remove_dir_all(&removed.dir);
    let _ = std::fs::remove_dir_all(host_signer_dir.join("secrets").join(channel_id));
    let _ = std::fs::remove_file(registry.state_dir.join(format!("{channel_id}.handle")));

    out.print_json(&serde_json::json!({
        "removed": channel_id,
        "note": "the PRSN's SE keys + account are device-bound and were NOT deleted",
    }))
}

// ── helpers ─────────────────────────────────────────────────────────────────────

/// A bind-mount/run snippet for `runtime` (`docker` | `container`). The channel is
/// mounted read-write; the secret read-only. Verified against both runtimes in the
/// Step-4 container E2E.
fn run_snippet(
    runtime: &str,
    id: &str,
    channel_dir: &Path,
    secret_dir: &Path,
    bin_dir: Option<&Path>,
    handle: Option<&str>,
) -> String {
    // The bundled `signet` (read-only) — present only when it was delivered (§deliver).
    let bin_mount = match bin_dir {
        Some(b) => format!("-v {}:{IN_CONTAINER_BIN_DIR}:ro \\\n  ", b.display()),
        None => String::new(),
    };
    // SIGNET_HANDLE arms the launch-binding cross-check (§11): set, `signet` refuses if
    // the channel's pinned handle disagrees. Known → filled in (the menu action prompts
    // for it); unknown at CLI provision → a placeholder the human replaces (like
    // `<your-image>`).
    let handle = handle.unwrap_or("<your-PRSN-handle>");
    format!(
        "{runtime} run -d \\\n  \
         {bin_mount}\
         -v {chan}:{IN_CONTAINER_CHANNEL_DIR} \\\n  \
         -v {sec}:{IN_CONTAINER_SECRET_DIR}:ro \\\n  \
         -e SIGNET_HOST_CHANNEL_DIR={IN_CONTAINER_CHANNEL_DIR} \\\n  \
         -e SIGNET_HOST_CHANNEL_ID={id} \\\n  \
         -e SIGNET_HOST_CHANNEL_SECRET_FILE={IN_CONTAINER_SECRET_FILE} \\\n  \
         -e SIGNET_HANDLE={handle} \\\n  \
         <your-image>",
        chan = channel_dir.display(),
        sec = secret_dir.display(),
    )
}

/// Deliver the bundled Linux `signet` into a host-side `bin/` folder for the container
/// to bind-mount (read-only) — so a containerized PRSN needs no separate download; the
/// one installed app carries the helper. Located relative to the running binary: a
/// notarized install runs `<app>/Contents/MacOS/signet`, so the bundled helper sits at
/// `<app>/Contents/Resources/signet-linux-arm64`. Returns the host-side `bin/` dir on
/// success, or `None` when the helper isn't found (e.g. running the bare dev binary, not
/// the `.app`) — then the container must already carry `signet`. The dir + binary are
/// world-readable+executable (0755): the binary is the public CLI (no secret), and the
/// container process (whatever uid) must be able to exec it across the bind-mount.
fn deliver_linux_binary(host_signer_dir: &Path) -> Option<PathBuf> {
    // `signet` is normally invoked through a PATH symlink (install.sh links it into a bin
    // dir), and `current_exe()` returns that symlink path *unresolved* on macOS — so
    // canonicalize to the real `<app>/Contents/MacOS/signet` before locating the bundle.
    let exe = std::fs::canonicalize(std::env::current_exe().ok()?).ok()?;
    let bundled = exe
        .parent()? // <app>/Contents/MacOS
        .parent()? // <app>/Contents
        .join("Resources")
        .join("signet-linux-arm64");
    if !bundled.is_file() {
        return None;
    }
    let bin_dir = host_signer_dir.join("bin");
    std::fs::create_dir_all(&bin_dir).ok()?;
    let dest = bin_dir.join("signet");
    std::fs::copy(&bundled, &dest).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&bin_dir, std::fs::Permissions::from_mode(0o755));
        let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755));
    }
    Some(bin_dir)
}

/// Reload the host-signer LaunchAgent so it serves a just-provisioned channel (it reads
/// the registry at startup; `kickstart -k` restarts it — a sub-second blip, TOFU pins
/// persist). Best-effort: returns `false` if the agent isn't installed/loaded (or this
/// isn't macOS / `launchctl` is absent), and the caller prints a manual fallback. The
/// always-on install means the agent is normally already running.
pub fn kickstart_host_signer() -> bool {
    kickstart_launchagent(HOST_SIGNER_LAUNCHD_LABEL)
}

/// Reload the Garnet broker LaunchAgent so it picks up a just-written credential and
/// starts serving immediately (`signet broker provision` calls this after writing the
/// credential). Best-effort: returns `false` if the agent isn't installed/loaded (or this
/// isn't macOS / `launchctl` is absent), and the caller prints a manual fallback. The
/// always-on daemon (Bug030(1)/S120) is already running (showing the menu-bar); this
/// kickstart restarts it so it picks up the new credential and begins serving — mirrors
/// [`kickstart_host_signer`].
pub fn kickstart_broker() -> bool {
    kickstart_launchagent(BROKER_LAUNCHD_LABEL)
}

/// `launchctl kickstart -k gui/<uid>/<label>` — restart the named LaunchAgent in the
/// per-user gui domain. Best-effort (false if no uid / launchctl absent / not loaded).
fn kickstart_launchagent(label: &str) -> bool {
    let Some(uid) = current_uid() else {
        return false;
    };
    std::process::Command::new("launchctl")
        .args(["kickstart", "-k", &format!("gui/{uid}/{label}")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// `launchctl bootout gui/<uid>/<label>` — stop and de-register the named LaunchAgent
/// from the per-user gui domain, so its `KeepAlive` no longer applies and launchd won't
/// relaunch it. **Synchronous** (waits for completion) — `launchctl bootout` blocks
/// until the target process exits. Returns whether it succeeded; best-effort (false if
/// no uid / launchctl absent / the agent wasn't loaded).
///
/// **Never call this from inside the target agent's own process** — the self-bootout
/// would block on our own exit, a deadlock. `signet uninstall` (a *separate* process
/// tearing down the broker daemon) uses this; a daemon stopping *itself* (the menu-bar
/// "Quit") must use [`spawn_bootout_launchagent`].
pub fn bootout_launchagent(label: &str) -> bool {
    let Some(uid) = current_uid() else {
        return false;
    };
    std::process::Command::new("launchctl")
        .args(["bootout", &format!("gui/{uid}/{label}")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Spawn `launchctl bootout gui/<uid>/<label>` **detached** (do NOT wait). For a daemon
/// stopping *itself* — the menu-bar "Quit". `launchctl bootout` blocks until the target
/// process exits, and here the caller *is* that process, so waiting would deadlock.
/// Spawning-and-not-waiting lets launchd remove the service (dropping `KeepAlive`) and
/// then `SIGTERM` the caller — the correct teardown order, so it stops rather than
/// relaunches. The caller stays alive in its run loop until that `SIGTERM` lands, so the
/// spawned `launchctl` is never orphaned mid-request. Best-effort: a spawn failure is
/// swallowed (nothing the menu action can do about it).
pub fn spawn_bootout_launchagent(label: &str) {
    let Some(uid) = current_uid() else {
        return;
    };
    let _ = std::process::Command::new("launchctl")
        .args(["bootout", &format!("gui/{uid}/{label}")])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

/// The current user's numeric uid (for the `gui/<uid>` launchd domain), via `id -u`.
fn current_uid() -> Option<String> {
    let out = std::process::Command::new("id").arg("-u").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let uid = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!uid.is_empty()).then_some(uid)
}

/// A channel id is a stable, filesystem- + AAD-safe token: 1–64 chars of `[a-z0-9-]`,
/// not starting/ending with `-`. Distinct from the PRSN handle (unknown at this point).
fn validate_channel_id(s: &str) -> Result<()> {
    let ok = (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !s.starts_with('-')
        && !s.ends_with('-');
    if !ok {
        return Err(CliError::invalid_args(format!(
            "channel id '{s}' must be 1–64 chars of [a-z0-9-], not starting/ending with '-'"
        )));
    }
    Ok(())
}

/// A fresh random channel id (16 lowercase hex chars).
fn random_channel_id() -> String {
    let mut b = [0u8; 8];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

fn write_registry(path: &Path, registry: &Registry) -> Result<()> {
    if let Some(parent) = path.parent() {
        create_dir_secure(parent)?;
    }
    let toml = toml::to_string(registry)
        .map_err(|e| CliError::config(format!("serializing the registry: {e}")))?;
    std::fs::write(path, toml)
        .map_err(|e| CliError::filesystem(format!("writing {}: {e}", path.display())))?;
    set_mode_0600(path)?;
    Ok(())
}

fn write_secret_file(path: &Path, hex_str: &str) -> Result<()> {
    std::fs::write(path, hex_str)
        .map_err(|e| CliError::filesystem(format!("writing {}: {e}", path.display())))?;
    set_mode_0600(path)
}

/// Create a directory (and parents), 0700 on unix.
fn create_dir_secure(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)
        .map_err(|e| CliError::filesystem(format!("creating {}: {e}", dir.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| CliError::filesystem(format!("securing {}: {e}", dir.display())))?;
    }
    Ok(())
}

fn set_mode_0600(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| CliError::filesystem(format!("securing {}: {e}", path.display())))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out() -> OutputMode {
        OutputMode { pretty: false }
    }

    #[test]
    fn provision_creates_channel_secret_and_registry() {
        let hs = tempfile::tempdir().unwrap();
        provision(hs.path(), Some("testchan"), &out()).unwrap();

        assert!(hs.path().join("channels/testchan").is_dir());
        let secret_file = hs.path().join("secrets/testchan/secret.hex");
        assert!(secret_file.is_file());
        let hex_str = std::fs::read_to_string(&secret_file).unwrap();
        assert_eq!(hex_str.trim().len(), 64); // 32 bytes
        assert_eq!(hex::decode(hex_str.trim()).unwrap().len(), 32);

        // The registry provision writes must be exactly what the host-signer loads.
        let reg = Registry::load(&hs.path().join("registry.toml")).unwrap();
        assert_eq!(reg.channels.len(), 1);
        assert_eq!(reg.channels[0].id, "testchan");
        assert_eq!(reg.channels[0].secret_hex, hex_str.trim());
        assert_eq!(reg.channels[0].dir, hs.path().join("channels/testchan"));
    }

    #[test]
    fn provision_refuses_duplicate_channel_id() {
        let hs = tempfile::tempdir().unwrap();
        provision(hs.path(), Some("dup"), &out()).unwrap();
        assert!(provision(hs.path(), Some("dup"), &out()).is_err());
        let reg = Registry::load(&hs.path().join("registry.toml")).unwrap();
        assert_eq!(reg.channels.len(), 1);
    }

    #[test]
    fn provision_appends_to_existing_registry_with_distinct_secrets() {
        let hs = tempfile::tempdir().unwrap();
        provision(hs.path(), Some("c1"), &out()).unwrap();
        provision(hs.path(), Some("c2"), &out()).unwrap();
        let reg = Registry::load(&hs.path().join("registry.toml")).unwrap();
        assert_eq!(reg.channels.len(), 2);
        assert_ne!(reg.channels[0].secret_hex, reg.channels[1].secret_hex);
    }

    #[test]
    fn random_channel_id_is_valid_and_unique() {
        let a = random_channel_id();
        let b = random_channel_id();
        assert_eq!(a.len(), 16);
        assert!(validate_channel_id(&a).is_ok());
        assert_ne!(a, b);
    }

    #[test]
    fn validate_channel_id_rejects_bad() {
        assert!(validate_channel_id("").is_err());
        assert!(validate_channel_id("-x").is_err());
        assert!(validate_channel_id("x-").is_err());
        assert!(validate_channel_id("Has Caps").is_err());
        assert!(validate_channel_id("ok-id-1").is_ok());
    }

    #[test]
    fn remove_needs_force_then_drops_entry_and_folders() {
        let hs = tempfile::tempdir().unwrap();
        provision(hs.path(), Some("gone"), &out()).unwrap();
        assert!(remove(hs.path(), "gone", false, &out()).is_err()); // needs --force
        remove(hs.path(), "gone", true, &out()).unwrap();
        let reg = Registry::load(&hs.path().join("registry.toml")).unwrap();
        assert!(reg.channels.is_empty());
        assert!(!hs.path().join("channels/gone").exists());
        assert!(!hs.path().join("secrets/gone").exists());
    }

    #[test]
    fn remove_unknown_channel_errors() {
        let hs = tempfile::tempdir().unwrap();
        provision(hs.path(), Some("here"), &out()).unwrap();
        assert!(remove(hs.path(), "nope", true, &out()).is_err());
    }

    #[test]
    fn deliver_linux_binary_none_when_not_bundled() {
        // The test runner isn't inside a `.app`, so there's no bundled Linux helper to
        // deliver — deliver returns None (and the container must carry its own `signet`).
        let hs = tempfile::tempdir().unwrap();
        assert!(deliver_linux_binary(hs.path()).is_none());
        assert!(!hs.path().join("bin").exists()); // nothing written on the None path
    }

    #[test]
    fn run_snippet_includes_bin_mount_only_when_delivered() {
        let chan = Path::new("/h/chan");
        let sec = Path::new("/h/sec");
        let bin = Path::new("/h/bin");
        let with = run_snippet("docker", "c1", chan, sec, Some(bin), None);
        let without = run_snippet("docker", "c1", chan, sec, None, None);
        assert!(with.contains("/h/bin:/run/signet/bin:ro"));
        assert!(!without.contains("/run/signet/bin"));
        // the rest of the snippet is unchanged either way
        assert!(with.contains("SIGNET_HOST_CHANNEL_ID=c1"));
        assert!(without.contains("/h/chan:/run/signet/channel"));
    }

    #[test]
    fn run_snippet_carries_signet_handle_placeholder_or_value() {
        let chan = Path::new("/h/chan");
        let sec = Path::new("/h/sec");
        // Unknown handle → a placeholder line (the human fills it; it arms the cross-check).
        let placeholder = run_snippet("docker", "c1", chan, sec, None, None);
        assert!(placeholder.contains("-e SIGNET_HANDLE=<your-PRSN-handle>"));
        // Known handle (the menu-bar path) → filled in, no placeholder left behind.
        let filled = run_snippet("docker", "c1", chan, sec, None, Some("ada-ai"));
        assert!(filled.contains("-e SIGNET_HANDLE=ada-ai"));
        assert!(!filled.contains("<your-PRSN-handle>"));
    }

    #[test]
    fn provision_core_returns_a_usable_receipt() {
        let hs = tempfile::tempdir().unwrap();
        let r = provision_core(hs.path(), Some("chan-a"), Some("ada-ai")).unwrap();
        assert_eq!(r.channel_id, "chan-a");
        assert!(r.secret_file.ends_with("secret.hex"));
        assert!(r.secret_file.exists(), "the secret file is written");
        // The handle is folded into both snippets (arming the cross-check by default).
        assert!(r.docker_snippet.contains("-e SIGNET_HANDLE=ada-ai"));
        assert!(r.apple_snippet.contains("container run"));
        // A duplicate id is refused (no silent clobber of a live channel's secret).
        assert!(provision_core(hs.path(), Some("chan-a"), None).is_err());
    }
}
