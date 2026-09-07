// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Configuration (CLI Spec v08 §"Configuration file").
//!
//! `~/.config/signet/config.toml` (XDG-style on every platform, per the spec —
//! *not* the macOS-native `~/Library/Application Support`). Created lazily; absent
//! → defaults. Env vars override file values; per-invocation flags override env.
//! Unknown fields are ignored on read (forward-compatible config evolution).

use std::path::PathBuf;

use serde::Deserialize;

use crate::error::{CliError, Result};

const DEFAULT_SERVER_URL: &str = "https://drive.mysignet.ca";

fn default_server_url() -> String {
    DEFAULT_SERVER_URL.to_string()
}
fn default_output_format() -> String {
    "machine".to_string()
}
fn default_errors_format() -> String {
    "human".to_string()
}
fn default_log_level() -> String {
    "warn".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_server_url")]
    pub server_base_url: String,
    #[serde(default)]
    pub default_signing_key: Option<String>,
    #[serde(default)]
    pub default_kem_key: Option<String>,
    #[serde(default = "default_output_format")]
    pub output_format: String,
    #[serde(default = "default_errors_format")]
    pub errors_format: String,
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_base_url: default_server_url(),
            default_signing_key: None,
            default_kem_key: None,
            output_format: default_output_format(),
            errors_format: default_errors_format(),
            log_level: default_log_level(),
        }
    }
}

impl Config {
    /// Load the config file if present (else defaults), then apply env overrides.
    pub fn load() -> Result<Self> {
        let path = config_file_path();
        let mut config = if path.exists() {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| CliError::config(format!("reading config {}: {e}", path.display())))?;
            toml::from_str(&text)
                .map_err(|e| CliError::config(format!("parsing config {}: {e}", path.display())))?
        } else {
            Config::default()
        };
        config.apply_env_overrides();
        Ok(config)
    }

    fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("SIGNET_SERVER_URL")
            && !v.is_empty()
        {
            self.server_base_url = v;
        }
        if let Ok(v) = std::env::var("SIGNET_DEFAULT_SIGNING_KEY")
            && !v.is_empty()
        {
            self.default_signing_key = Some(v);
        }
        if let Ok(v) = std::env::var("SIGNET_DEFAULT_KEM_KEY")
            && !v.is_empty()
        {
            self.default_kem_key = Some(v);
        }
    }
}

/// `$XDG_CONFIG_HOME/signet` if set, else `$HOME/.config/signet`.
pub fn config_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME")
        && !xdg.is_empty()
    {
        return PathBuf::from(xdg).join("signet");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".config").join("signet")
}

/// `$SIGNET_CONFIG` if set, else `<config_dir>/config.toml`.
pub fn config_file_path() -> PathBuf {
    if let Ok(path) = std::env::var("SIGNET_CONFIG")
        && !path.is_empty()
    {
        return PathBuf::from(path);
    }
    config_dir().join("config.toml")
}

/// Where the software-tier keystore lives. `$SIGNET_KEYS_DIR` if set, else
/// `<config_dir>/keys`. Containers point this at the persistent key volume so keys
/// survive restarts (S011 §5 — the load-bearing persistence requirement).
pub fn keys_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("SIGNET_KEYS_DIR")
        && !dir.is_empty()
    {
        return PathBuf::from(dir);
    }
    config_dir().join("keys")
}

/// The host-signer's home directory (**host side only** — the Mac running the
/// `signet-host-signer` LaunchAgent for containerized PRSNs). Holds the channel
/// registry (`registry.toml`), per-channel pinned-handle state (`state/`), and the
/// bind-mounted channel folders (`channels/<channel-id>/`). `$SIGNET_HOST_SIGNER_DIR`
/// overrides (tests), else `<config_dir>/host-signer`. `signet host-channel provision`
/// writes here; the `signet-host-signer` LaunchAgent reads `registry.toml` (Account-
/// and-Kit §f.7).
pub fn host_signer_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("SIGNET_HOST_SIGNER_DIR")
        && !dir.is_empty()
    {
        return PathBuf::from(dir);
    }
    config_dir().join("host-signer")
}

/// The canonical host-signer registry path (`<host_signer_dir>/registry.toml`).
pub fn host_signer_registry_path() -> PathBuf {
    host_signer_dir().join("registry.toml")
}

/// The Garnet SE-broker's home directory (**host side only** — the Mac running the
/// `signet broker serve` LaunchAgent). Holds the broker's provisioned identity
/// credential (K3 + K_bc; [`crate::broker_credential::BrokerCredential`]).
/// `$SIGNET_BROKER_DIR` overrides (tests), else `<config_dir>/broker`. `signet broker
/// provision` writes here; the broker LaunchAgent's `serve` reads it. The Garnet
/// successor to [`host_signer_dir`].
pub fn broker_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("SIGNET_BROKER_DIR")
        && !dir.is_empty()
    {
        return PathBuf::from(dir);
    }
    config_dir().join("broker")
}

/// The canonical broker credential path (`<broker_dir>/credential.json`) — the single
/// source of truth shared by `signet broker provision` (writes it), `signet broker
/// serve` (loads it), and the broker LaunchAgent (baked into its plist). The always-on
/// daemon (Bug030(1)/S120) starts its crypto serve-loop exactly when this file exists.
pub fn broker_credential_path() -> PathBuf {
    broker_dir().join("credential.json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn broker_credential_path_lives_under_broker_dir() {
        // No env mutation (env is process-global; mutating it races parallel tests):
        // assert the structural relationship the LaunchAgent + provision + serve rely on.
        let cred = broker_credential_path();
        assert_eq!(cred.file_name().unwrap(), "credential.json");
        assert_eq!(cred.parent().unwrap(), broker_dir());
        assert!(broker_dir().ends_with("broker"));
    }
}
