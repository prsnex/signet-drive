// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! `signet status` — a local, network-free health check for the Signet daemon: is
//! the Garnet **broker** LaunchAgent running, is it provisioned, and what version is
//! installed. Under Garnet the broker is the installed daemon (S096); the host-signer
//! is reported only as a secondary line when it's present (the manual, present-but-
//! inactive fallback for comparison testing). This is the data source behind the
//! menu-bar status item (Launch-Punch-List §1-29) and a human-facing "is it working?"
//! command. No server calls and no side effects.

use crate::config;
use crate::error::Result;
use crate::host_channel::{BROKER_LAUNCHD_LABEL, HOST_SIGNER_LAUNCHD_LABEL};
use crate::host_signer::Registry;
use crate::output::OutputMode;

/// Pull the live PID out of a `launchctl list <label>` dump. launchctl prints a
/// plist-style dict; a *running* job carries a `"PID" = <n>;` line, a loaded-but-
/// stopped job does not. Returns `None` when there is no PID line.
fn parse_launchctl_pid(dump: &str) -> Option<u32> {
    dump.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("\"PID\"")?.trim_start();
        let rest = rest.strip_prefix('=')?.trim();
        rest.strip_suffix(';')
            .unwrap_or(rest)
            .trim()
            .parse::<u32>()
            .ok()
    })
}

/// Query launchd for the `label` LaunchAgent. Returns `(installed, pid)`: `installed`
/// is true when the agent is registered with launchd (whether or not it is currently
/// up); `pid` is `Some` only while it is running. Shells out to `launchctl list <label>`
/// (the user domain); any failure — not macOS, agent absent (`exit 113`) — reads as
/// not-installed.
fn launchd_state(label: &str) -> (bool, Option<u32>) {
    let output = std::process::Command::new("launchctl")
        .args(["list", label])
        .output();
    match output {
        Ok(out) if out.status.success() => (
            true,
            parse_launchctl_pid(&String::from_utf8_lossy(&out.stdout)),
        ),
        _ => (false, None),
    }
}

/// Count provisioned delegation channels. A missing registry is the normal idle
/// state (zero channels); a malformed one also reads as zero rather than erroring
/// — `status` reports health, it does not gate on it.
fn channel_count() -> usize {
    let path = config::host_signer_registry_path();
    if path.exists() {
        Registry::load(&path).map(|r| r.channels.len()).unwrap_or(0)
    } else {
        0
    }
}

/// `signet status`: the Garnet broker daemon's liveness + provisioning state +
/// installed version, and — only when present — the host-signer fallback. JSON
/// (`--json`-shaped via `OutputMode`) or a short human summary.
pub fn status(json: bool, out: &OutputMode) -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);

    // The Garnet broker — the installed daemon under Garnet, always-on from install
    // (Bug030(1)/S120). "provisioned" = its credential file exists (`signet broker provision`
    // has run, i.e. a PRSN was added); the daemon runs from install regardless, so it can be
    // running-but-not-yet-provisioned (ready, no PRSN).
    let (broker_installed, broker_pid) = launchd_state(BROKER_LAUNCHD_LABEL);
    let broker_provisioned = config::broker_credential_path().exists();

    // The host-signer — the manual, present-but-inactive fallback (S096). Reported only
    // when it's actually installed/running (e.g. someone ran it for comparison testing).
    let (hs_installed, hs_pid) = launchd_state(HOST_SIGNER_LAUNCHD_LABEL);
    let channels = channel_count();

    if json {
        return out.print_json(&serde_json::json!({
            "version": version,
            "platform": platform,
            "broker": {
                "installed": broker_installed,
                "running": broker_pid.is_some(),
                "pid": broker_pid,
                "provisioned": broker_provisioned,
            },
            "host_signer": {
                "installed": hs_installed,
                "running": hs_pid.is_some(),
                "pid": hs_pid,
                "channels": channels,
            },
        }));
    }

    let broker = match (broker_installed, broker_pid, broker_provisioned) {
        (_, Some(pid), true) => format!("running (pid {pid})"),
        (_, Some(pid), false) => format!("running (pid {pid}): ready, no PRSN yet"),
        (_, None, true) => "provisioned, not running".to_string(),
        (true, None, false) => "installed, not running".to_string(),
        (false, None, _) => "not installed".to_string(),
    };
    println!("signet {version} ({platform})");
    println!("broker:      {broker}");
    // Only surface the host-signer fallback when it's actually present.
    if hs_installed || hs_pid.is_some() {
        let hs = match hs_pid {
            Some(pid) => format!("running (pid {pid})"),
            None => "installed, not running".to_string(),
        };
        println!("host-signer: {hs} (manual fallback, {channels} channels)");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_launchctl_pid;

    /// Faithful to the real `launchctl list ai.prsnex.signet.host-signer` dump
    /// (tab-indented; `"PID" = <n>;` present while running).
    #[test]
    fn parses_pid_from_a_running_job_dump() {
        let dump = "{\n\
            \t\"StandardOutPath\" = \"/Users/x/Library/Logs/Signet/host-signer.log\";\n\
            \t\"Label\" = \"ai.prsnex.signet.host-signer\";\n\
            \t\"OnDemand\" = false;\n\
            \t\"LastExitStatus\" = 15;\n\
            \t\"PID\" = 38515;\n\
            \t\"Program\" = \"/Users/x/.../signet\";\n\
            };";
        assert_eq!(parse_launchctl_pid(dump), Some(38515));
    }

    /// A loaded-but-stopped job has no `PID` line.
    #[test]
    fn no_pid_when_loaded_but_stopped() {
        let dump = "{\n\
            \t\"Label\" = \"ai.prsnex.signet.host-signer\";\n\
            \t\"OnDemand\" = false;\n\
            \t\"LastExitStatus\" = 0;\n\
            };";
        assert_eq!(parse_launchctl_pid(dump), None);
    }

    /// Other numeric keys (`LastExitStatus`, etc.) must not be mistaken for the PID,
    /// and a `"PIDFile"`-style key must not partial-match `"PID"`.
    #[test]
    fn ignores_unrelated_and_lookalike_keys() {
        let dump = "\t\"LastExitStatus\" = 0;\n\t\"PIDFile\" = \"/var/run/x.pid\";";
        assert_eq!(parse_launchctl_pid(dump), None);
    }
}
