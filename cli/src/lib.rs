// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! `signet_cli` — the testable core behind the `signet` binary.
//!
//! The `signet` CLI is the v1 PRSN-side crypto tool (CLI Spec v08). It does no raw
//! cryptography itself: every primitive goes through `signet-crypto`, the single
//! validated chokepoint shared with the server. This crate owns the macOS keystore
//! (tier-detected: `secure_enclave` for PRSNs, `software` for dev/test/CI — S052),
//! argument handling, config, I/O, the HTTP verification paths, and the `signet
//! enroll` onboarding flow.

pub mod broker;
pub mod broker_client;
pub mod broker_credential;
pub mod broker_provision;
pub mod broker_tls;
pub mod broker_transport_key;
pub mod broker_wire;
pub mod bucket_transport;
pub mod commands;
pub mod config;
pub mod enroll;
pub mod error;
pub mod garnet;
pub mod garnet_credential;
pub mod garnet_grant_status_client;
pub mod garnet_pickup;
pub mod garnet_revocation;
pub mod host_channel;
pub mod host_signer;
pub mod http;
pub mod hybrid;
pub mod keystore;
pub mod names;
pub mod output;
pub mod power;
pub mod recipient_verify;
pub mod resolve;
pub mod status;
/// Shared test fixtures for the degrade tests (S163). Test builds only — never shipped.
#[cfg(test)]
mod test_support;
pub mod transfer_governor;
pub mod upload_state;

// The host-signer's menu-bar status item — AppKit, macOS-only (the bundled
// static-Linux helper never compiles it).
#[cfg(target_os = "macos")]
pub mod menubar;

// The graphical self-install (double-click `signet.app`) — macOS-only (the install
// target is a Mac `.app`; Launch-Punch-List §1-27).
#[cfg(target_os = "macos")]
pub mod install;

// Assisted in-app update (the menu-bar "Update Signet…" action) — download + verify +
// Gatekeeper-check + install the newest notarized release. macOS-only (bug039 Increment II).
#[cfg(target_os = "macos")]
pub mod update;

// `signet uninstall` — the reverse of `install` (stop + remove the broker LaunchAgent,
// the app, the PATH shim, the broker credential + logs; SE keys preserved). macOS-only.
#[cfg(target_os = "macos")]
pub mod uninstall;
