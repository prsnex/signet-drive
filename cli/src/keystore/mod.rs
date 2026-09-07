// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! The keystore — the PRSN's private-key custody, abstracted over the
//! `key_protection` tier (S011; SE-only for PRSNs, S052).
//!
//! One trait, tier-detected backend:
//! - **`secure_enclave`** (Apple Silicon Mac host) — keys never leave the SE
//!   (B6a PR4; macOS-only). **The only `key_protection` for a real PRSN** — the
//!   server enforces SE-only (S052). A native macOS PRSN uses the device SE
//!   directly; a containerized PRSN reaches the *host* SE via a host signer
//!   (host-delegation — a gated build, owned by the Account-and-Kit spec).
//! - **`software`** — keys sealed under a local KEK; at-rest protection bounded
//!   by host disk encryption. **dev/test/CI-only** — the production server
//!   rejects it on a PRSN attestation; it backs the CI-testable path and the
//!   non-macOS target build.
//!
//! The CLI does no raw crypto: backends call `signet-crypto` for every primitive.
//!
//! *(S052: the `software_se_sealed` sealed-keys-in-container tier is removed —
//! superseded by host-delegation, where a containerized PRSN's keys live in the
//! host SE and every crypto op is delegated, never sealed inside the container.)*

mod broker;
mod delegated;
#[cfg(target_os = "macos")]
mod se_shim;
#[cfg(target_os = "macos")]
mod secure_enclave;
mod software;

pub use broker::BrokerKeystore;
pub use delegated::DelegatedKeystore;
#[cfg(target_os = "macos")]
pub use secure_enclave::SecureEnclaveKeystore;
// The broker's K3 transport-key SE helpers (Garnet Phase-6) — a broker transport key, outside
// the PRSN `KeyLabel`/`Keystore` abstraction, reusing this module's SE FFI.
#[cfg(target_os = "macos")]
pub(crate) use secure_enclave::{
    broker_se_sign, generate_broker_se_key, sweep_stale_broker_se_keys,
};
pub use software::SoftwareKeystore;

use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;

use serde::Serialize;
use signet_channel::auth::ChannelSecret;

use crate::config::{self, Config};
use crate::error::{CliError, Result};

/// A key's purpose. The classical signing key is `ES256` (per-request auth); the
/// classical KEM key is `ECDH-ES+A256KW` (DEK/metadata-key unwrap) — one of each
/// per PRSN (S009-001). The v1 hybrid PQR (PQR Crypto Spec §6/§8; item 2) adds
/// the two PQ halves as their own purposes: `SigningPq` (ML-DSA-87, the identity
/// dual-sign half) and `KemPq` (ML-KEM-1024, the hybrid content-wrap half) —
/// **four keys per PRSN**, individually addressed; the attestation (§8.5) is what
/// binds them as one identity (Build-Plan §2a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Signing,
    Kem,
    SigningPq,
    KemPq,
}

impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Purpose::Signing => "signing",
            Purpose::Kem => "kem",
            Purpose::SigningPq => "signing-pq",
            Purpose::KemPq => "kem-pq",
        }
    }

    /// The label suffix that encodes this purpose (`<handle>-<purpose>`).
    pub fn suffix(self) -> &'static str {
        match self {
            Purpose::Signing => "-signing",
            Purpose::Kem => "-kem",
            Purpose::SigningPq => "-signing-pq",
            Purpose::KemPq => "-kem-pq",
        }
    }

    /// The v1 algorithm for this purpose (one alg per purpose; PQR Spec §2).
    pub fn default_alg(self) -> &'static str {
        match self {
            Purpose::Signing => "ES256",
            Purpose::Kem => "ECDH-ES+A256KW",
            Purpose::SigningPq => "ML-DSA-87",
            Purpose::KemPq => "ML-KEM-1024",
        }
    }
}

/// The `key_protection` tier of a backend / a stored key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    SecureEnclave,
    Software,
}

impl Tier {
    /// The hyphenated **display** string (the `keys list` STORAGE column + the
    /// `pubkey` / `keys` views).
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::SecureEnclave => "secure-enclave",
            Tier::Software => "software",
        }
    }

    /// The underscored **wire** string for the `key_protection` field the server
    /// stores + validates (Schema §1; the enrollment `submit-keys` body). Distinct
    /// from [`Tier::as_str`]'s hyphenated display form — the server accepts only
    /// `secure_enclave` for a PRSN attestation (S052).
    pub fn wire_str(self) -> &'static str {
        match self {
            Tier::SecureEnclave => "secure_enclave",
            Tier::Software => "software",
        }
    }
}

/// A validated key label: a PRSN handle + a purpose, serialized as
/// `<handle>-<purpose>` (e.g. `hlin-ai-signing`). The handle ends in `-ai` and
/// matches the SigDrive handle regex (S005-008 / S009-001).
#[derive(Debug, Clone)]
pub struct KeyLabel {
    handle: String,
    purpose: Purpose,
}

impl KeyLabel {
    /// Parse a full label `<handle>-<purpose>`. If `expected` is `Some`, the
    /// parsed purpose must match the flag the caller passed (`--signing`/`--kem`).
    pub fn parse(label: &str, expected: Option<Purpose>) -> Result<Self> {
        // The `-pq` suffixes are checked first (belt-and-braces: a `…-signing-pq`
        // label can never match `strip_suffix("-signing")` — it ends in `-pq` —
        // but the longest-suffix-first order makes that not depend on the check
        // sequence at all).
        let (handle, purpose) = if let Some(h) = label.strip_suffix(Purpose::SigningPq.suffix()) {
            (h, Purpose::SigningPq)
        } else if let Some(h) = label.strip_suffix(Purpose::KemPq.suffix()) {
            (h, Purpose::KemPq)
        } else if let Some(h) = label.strip_suffix(Purpose::Signing.suffix()) {
            (h, Purpose::Signing)
        } else if let Some(h) = label.strip_suffix(Purpose::Kem.suffix()) {
            (h, Purpose::Kem)
        } else {
            return Err(CliError::invalid_args(format!(
                "label '{label}' must end in '-signing', '-kem', '-signing-pq', or '-kem-pq' \
                 (format <prsn-handle>-<purpose>)"
            )));
        };
        if let Some(exp) = expected
            && exp != purpose
        {
            return Err(CliError::invalid_args(format!(
                "label '{label}' is a {} key, but --{} was specified",
                purpose.as_str(),
                exp.as_str()
            )));
        }
        validate_handle(handle)?;
        Ok(Self {
            handle: handle.to_string(),
            purpose,
        })
    }

    /// Build from a bare handle + purpose (the `keys delete --label <handle>` path).
    pub fn from_handle(handle: &str, purpose: Purpose) -> Result<Self> {
        validate_handle(handle)?;
        Ok(Self {
            handle: handle.to_string(),
            purpose,
        })
    }

    pub fn purpose(&self) -> Purpose {
        self.purpose
    }

    /// The PRSN handle component of the label (`<handle>` in `<handle>-<purpose>`).
    /// Used by the host-signer to scope a delegated op to the channel's PRSN.
    pub fn handle(&self) -> &str {
        &self.handle
    }

    /// The full label string `<handle>-<purpose>` (also the keystore filename stem).
    pub fn full(&self) -> String {
        format!("{}{}", self.handle, self.purpose.suffix())
    }
}

/// Validate a PRSN handle: lowercase ASCII, 2–64 chars matching
/// `^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$`, ending in `-ai` (S009-001).
fn validate_handle(handle: &str) -> Result<()> {
    let n = handle.len();
    if !(2..=64).contains(&n) {
        return Err(CliError::invalid_args(format!(
            "handle '{handle}' must be 2–64 characters"
        )));
    }
    let bytes = handle.as_bytes();
    let is_alnum = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !is_alnum(bytes[0]) || !is_alnum(bytes[n - 1]) {
        return Err(CliError::invalid_args(format!(
            "handle '{handle}' must start and end with a lowercase letter or digit"
        )));
    }
    if !bytes.iter().all(|&b| is_alnum(b) || b == b'-') {
        return Err(CliError::invalid_args(format!(
            "handle '{handle}' may contain only lowercase ASCII letters, digits, and hyphens"
        )));
    }
    if !handle.ends_with("-ai") {
        return Err(CliError::invalid_args(format!(
            "handle '{handle}' must end in '-ai' (PRSN handle convention)"
        )));
    }
    Ok(())
}

/// Metadata for a stored key (the `keys list` row + the `keygen` receipt). The
/// public key rides along for the `pubkey` command but is omitted from JSON.
#[derive(Debug, Clone, Serialize)]
pub struct KeyMeta {
    pub label: String,
    pub purpose: String,
    pub algorithm: String,
    pub storage: String,
    pub fingerprint: String,
    #[serde(skip)]
    pub public_key: Vec<u8>,
}

/// A private-key custody backend. Private-key bytes never cross this boundary —
/// `sign`/`ecdh` perform the operation in the backend (in-process for `software`,
/// in the Secure Enclave for `secure_enclave`).
pub trait Keystore {
    fn tier(&self) -> Tier;
    /// Generate a keypair for `label` (purpose from the label) under `algorithm`.
    fn generate(&self, label: &KeyLabel, algorithm: &str) -> Result<KeyMeta>;
    /// Metadata (incl. the X9.63 public key) for an existing key.
    fn meta(&self, label: &KeyLabel) -> Result<KeyMeta>;
    /// `ES256` signature (raw `r‖s`) over `msg`. Signing keys only.
    fn sign(&self, label: &KeyLabel, msg: &[u8]) -> Result<[u8; 64]>;
    /// ECDH P-256 agreement with `peer_pub_x963`. KEM keys only.
    fn ecdh(&self, label: &KeyLabel, peer_pub_x963: &[u8]) -> Result<[u8; 32]>;
    /// ML-KEM-1024 decapsulation of the 1568-byte ciphertext `ek` → `Z_mlkem`
    /// (PQR Spec §6; item 2). `kem-pq` keys only. **Deliberately no default
    /// impl** — every backend decides explicitly (Build-Plan §2a): the SE backend
    /// implements it via the CryptoKit shim (item 1); software refuses
    /// (`unsupported_algorithm`); broker/mount forward.
    fn ml_kem_decapsulate(&self, label: &KeyLabel, ek: &[u8]) -> Result<[u8; 32]>;
    /// ML-DSA-87 hedged signature over `msg` with the FIPS 204 context `ctx`
    /// (≤ 255 bytes, the FIPS 204 context *parameter* — never prepended to `msg`;
    /// PQR Spec §8.7). `signing-pq` keys only; 4627-byte signature. Same
    /// no-default-impl rule as [`Keystore::ml_kem_decapsulate`].
    fn ml_dsa_sign(&self, label: &KeyLabel, msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>>;
    /// All keys held by this keystore (for `keys list`).
    fn list(&self) -> Result<Vec<KeyMeta>>;
    fn delete(&self, label: &KeyLabel) -> Result<()>;
    fn exists(&self, label: &KeyLabel) -> Result<bool>;
}

/// The ML-DSA-87 signature length (FIPS 204) — forwarding backends validate the
/// wire result against it, mirroring the 64-byte `sign` check.
pub(crate) const ML_DSA_87_SIG_LEN: usize = 4627;

/// The FIPS 204 context-string ceiling. Validated wherever a `ctx` enters
/// (the wire dispatch + the forwarding backends), so an oversized context fails
/// fast with a nameable error instead of deep in the signer.
pub(crate) fn validate_mldsa_ctx(ctx: &[u8]) -> Result<()> {
    if ctx.len() > 255 {
        return Err(CliError::invalid_args(format!(
            "ML-DSA context must be at most 255 bytes (FIPS 204), got {}",
            ctx.len()
        )));
    }
    Ok(())
}

/// A keystore backend that marshals ops over the wire ([`DelegatedKeystore`] over the mount channel,
/// [`broker::BrokerKeystore`](broker) over the Garnet broker) returned a result that doesn't match
/// the request — a protocol violation, not a normal op failure. Shared so both transports report it
/// identically.
pub(crate) fn unexpected(ok: &signet_channel::wire::OpOk) -> CliError {
    CliError::generic(format!(
        "the keystore backend returned an unexpected response for the request: {ok:?}"
    ))
}

/// Reconstruct a [`CliError`] from a wire [`OpErr`](signet_channel::wire::OpErr) `{code, message}`,
/// routing through the matching constructor so the **exit code is preserved** — a delegated (mount) or
/// broker (Garnet) op failure exits exactly the same as the native path. Unknown codes fall back to
/// generic. Shared by both wire keystores so the two transports re-raise a host-side error identically.
pub(crate) fn cli_error_from_wire(code: &str, message: String) -> CliError {
    match code {
        "key_already_exists" => CliError::key_exists(message),
        "key_not_found" => CliError::key_not_found(message),
        "unsupported_algorithm" => CliError::unsupported_algorithm(message),
        "invalid_arguments" => CliError::invalid_args(message),
        "invalid_data" => CliError::invalid_data(message),
        "unsupported_platform" => CliError::unsupported_platform(message),
        "authorization_denied" => CliError::authorization_denied(message),
        "filesystem_error" => CliError::filesystem(message),
        "encryption_failed" => CliError::encryption_failed(message),
        "decrypt_failed" => CliError::decrypt_failed(message),
        // bug114 Part F (S156): the broker's grant refusal must survive the wire→CLI mapping
        // with its code intact — the BrokerKeystore re-auth recovery triggers on it, and the
        // old fall-through to `generic` erased exactly the fact the recovery keys on. Exit 77
        // = the Garnet access-refusal family (`token_denied`, the same semantic state seen
        // from the token surface).
        "access_paused" => CliError::new(77, "access_paused", message),
        _ => CliError::generic(message),
    }
}

/// Detect the strongest available `key_protection` tier. `SIGNET_KEY_TIER`
/// overrides (forces a tier — used by CI/tests to exercise the `software` path on
/// a Mac, and by containers where detection is ambiguous). PR1 ships only the
/// `software` backend; PR4 adds Apple-Silicon SE detection.
pub fn detect_tier() -> Tier {
    if let Ok(forced) = std::env::var("SIGNET_KEY_TIER") {
        match forced.as_str() {
            "software" => return Tier::Software,
            "secure_enclave" | "secure-enclave" => return Tier::SecureEnclave,
            _ => {}
        }
    }
    // A containerized PRSN delegates crypto to the *host* Mac's Secure Enclave over
    // the channel (host-delegation) — the custody grade is `secure_enclave`. `open()`
    // builds the delegation backend for this case (this guest is Linux, so the
    // native-SE arm below would not apply); reporting it here keeps the tier honest.
    // Presence of the channel dir (provisioned at container creation) is the signal.
    if std::env::var_os("SIGNET_HOST_CHANNEL_DIR").is_some() {
        return Tier::SecureEnclave;
    }
    // Auto-detect: an Apple Silicon Mac host gets `secure_enclave` (the only PRSN
    // tier). Off that host (target_os != macos — a Linux container or CI) →
    // `software`, which is dev/test only; a real containerized PRSN reaches the host
    // SE via host-delegation (gated; owned by the Account-and-Kit spec), not a local
    // software tier.
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        Tier::SecureEnclave
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        Tier::Software
    }
}

/// Open the keystore for the detected tier.
pub fn open(config: &Config) -> Result<Box<dyn Keystore>> {
    // The Garnet broker is the **live PRSN-access path** (S094): when a broker is configured
    // (`SIGNET_BROKER_ADDR`), every crypto op goes through the local SE-broker over mutual-TLS. It
    // takes precedence over the mount below, which stays **present-but-inactive** as the fallback
    // until Garnet is proven on Staging (then it retires).
    if let Some(bd) = broker_delegation()? {
        // AUTO-PICKUP (bug084 §5): a configured broker with NO credential yet is the
        // freshly-authorized state — claim the credential now by SIGNED pickup, so `signet
        // enroll` stays the only hand-run step. Signing runs over the enrollment-phase
        // channel (the broker path needs the very credential this creates). A failure is a
        // clear, actionable error — never a silent fallback to a non-broker path.
        if !bd.credential_path.exists() {
            crate::garnet::auto_pickup(config, &bd.credential_path)?;
        }
        let ks = broker::BrokerKeystore::open(bd.broker_addr, bd.credential_path)?;
        return Ok(Box::new(ks));
    }
    open_non_broker(config)
}

/// Open the keystore reachable during the ENROLLMENT PHASE — before any Garnet credential
/// exists (bug084). The broker arm requires the very credential the signed pickup creates,
/// so the pre-credential operations (`signet enroll`'s keygen/PoP, and the signed pickup
/// itself) reach the Secure Enclave over the credential-free channel: container
/// host-delegation, or the native tier. Deliberately NOT a fallback for a broken broker
/// path — [`open`] stays fail-closed on a configured-but-unopenable broker; this is only
/// for the two operations that by design run before the credential exists.
pub fn open_enrollment_channel(config: &Config) -> Result<Box<dyn Keystore>> {
    open_non_broker(config)
}

/// The non-broker arms shared by [`open`] (when no broker is configured) and
/// [`open_enrollment_channel`] (the pre-credential phase).
fn open_non_broker(_config: &Config) -> Result<Box<dyn Keystore>> {
    // Container host-delegation (the mount fallback): the keys are in the *host* SE,
    // reached over the channel — selected by the container-creation environment,
    // independent of this (Linux) guest's own platform.
    if let Some(hd) = host_delegation()? {
        let ks = DelegatedKeystore::open(hd.channel_dir, hd.channel_id, hd.secret);
        // Launch-binding verification (the §11 cross-check) — fail closed before the
        // delegated keystore is ever used, so a mis-mapped channel mount cannot act
        // as the wrong identity.
        verify_channel_identity(&ks)?;
        return Ok(Box::new(ks));
    }
    match detect_tier() {
        Tier::Software => Ok(Box::new(SoftwareKeystore::open(config::keys_dir())?)),
        Tier::SecureEnclave => {
            #[cfg(target_os = "macos")]
            {
                Ok(Box::new(secure_enclave::SecureEnclaveKeystore::open()?))
            }
            #[cfg(not(target_os = "macos"))]
            {
                Err(CliError::unsupported_platform(
                    "the secure_enclave keystore backend is macOS-only",
                ))
            }
        }
    }
}

/// Launch-binding verification — the §11 cross-check (`Signet-Drive-Container-PRSN-
/// Onboarding-Requirement` v05). Before a containerized PRSN acts, confirm the
/// host-signer's per-channel **pinned** handle matches the handle the *harness*
/// asserts at launch (`SIGNET_HANDLE`); **fail closed** on a mismatch. The pinned
/// handle is an *independent* source (the host-signer set it at enrollment, §f.3a),
/// so it can disagree with a wrong `SIGNET_HANDLE` — which is exactly the realistic
/// accident this catches: a per-PRSN channel mount mis-keyed in a hand-edited launch
/// config, turning silent cross-identity action into a refused error.
///
/// Cases:
/// - No `SIGNET_HANDLE` asserted → nothing to verify against here; skip. (Requiring
///   it for any multi-capable host is a separate resolver gate — Phase 1b.)
/// - Channel not yet enrolled (pin `None`) → nothing to verify yet; `enroll` will
///   establish the pin. Skip — do **not** block enrollment.
/// - Pin present and == the asserted handle → OK.
/// - Pin present and ≠ the asserted handle → **fail closed** (`identity_mismatch`).
///
/// Not caught: a *wholesale* wrong identity where the pin and `SIGNET_HANDLE` agree
/// on the same wrong PRSN — that is the harness's wake-signal integrity, upstream of
/// SigDrive (Threat-Model §3).
fn verify_channel_identity(ks: &DelegatedKeystore) -> Result<()> {
    let asserted = std::env::var("SIGNET_HANDLE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let pinned = ks.pinned_identity()?;
    check_identity_match(pinned.as_deref(), asserted.as_deref())
}

/// The pure launch-binding decision (no I/O) — split out so it is unit-testable
/// without a running host-signer or process env. See [`verify_channel_identity`].
/// Shared with the broker keystore, which cross-checks its credential's cryptographic handle against
/// the harness-asserted `SIGNET_HANDLE` the same way (`pinned` = the credential handle).
pub(crate) fn check_identity_match(pinned: Option<&str>, asserted: Option<&str>) -> Result<()> {
    match (pinned, asserted) {
        // Nothing asserted to verify against → skip here (requiring `SIGNET_HANDLE`
        // for a multi-capable host is a separate resolver gate, Phase 1b).
        (_, None) => Ok(()),
        // Channel not yet enrolled → nothing to verify; `enroll` will pin it.
        (None, Some(_)) => Ok(()),
        (Some(p), Some(a)) if p == a => Ok(()),
        (Some(p), Some(a)) => Err(CliError::identity_mismatch(format!(
            "launch-binding mismatch: this container is wired to PRSN '{p}' (the host-signer's \
             channel pin), but SIGNET_HANDLE asserts '{a}'. Refusing to act as the wrong identity \
             (the container's channel mount must point at '{a}'s channel)."
        ))),
    }
}

/// Garnet broker config, read from the environment (the live PRSN-access path, S094): the broker's
/// **loopback** socket (`SIGNET_BROKER_ADDR`, e.g. `127.0.0.1:8765`) + the agent's PoP credential
/// path (`SIGNET_BROKER_CREDENTIAL`, else the per-handle default for `SIGNET_HANDLE`). Present ⇒
/// this agent's ops go through the SE-broker over mutual-TLS.
struct BrokerDelegation {
    broker_addr: SocketAddr,
    credential_path: PathBuf,
}

/// Read the Garnet broker config from the environment, or `None` if a broker is not configured
/// (`SIGNET_BROKER_ADDR` unset/empty) — in which case [`open`] falls through to the mount / native
/// paths. A set-but-unparseable address is a loud config error (never silently ignored).
fn broker_delegation() -> Result<Option<BrokerDelegation>> {
    let Some(addr) = std::env::var("SIGNET_BROKER_ADDR")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    else {
        return Ok(None);
    };
    let broker_addr = resolve_broker_addr(&addr)?;
    Ok(Some(BrokerDelegation {
        broker_addr,
        credential_path: broker_credential_path()?,
    }))
}

/// Resolve `SIGNET_BROKER_ADDR` (`host:port`) to a [`SocketAddr`]. Accepts both an **IP literal**
/// (`127.0.0.1:8765`, the native case) and a **hostname** (`host.docker.internal:8765`, the Docker
/// container case — the Harness-Contract's documented value), resolving the latter via the runtime's
/// resolver ([`ToSocketAddrs`]). Prefers IPv4 (the loopback broker and Docker Desktop's host-loopback
/// proxy are reached over v4; a hostname that also has an AAAA record must not pick the v6 address).
/// Fails loud on an unresolvable/malformed value (never silently ignored).
///
/// This does not weaken the S1 loopback-only invariant: the broker still binds loopback, and the agent
/// still pins the broker's K3 SPKI from its credential — a hostname in this var cannot redirect the
/// agent to a rogue broker (the mutual-TLS handshake fails unless the endpoint presents the pinned K3).
fn resolve_broker_addr(addr: &str) -> Result<SocketAddr> {
    let mut resolved: Vec<SocketAddr> = addr
        .to_socket_addrs()
        .map_err(|e| {
            CliError::config(format!(
                "SIGNET_BROKER_ADDR='{addr}' is not a resolvable socket address (host:port): {e}"
            ))
        })?
        .collect();
    // Prefer IPv4 over IPv6 among the resolved addresses (stable ordering; `false` < `true`).
    resolved.sort_by_key(SocketAddr::is_ipv6);
    resolved.into_iter().next().ok_or_else(|| {
        CliError::config(format!(
            "SIGNET_BROKER_ADDR='{addr}' resolved to no socket addresses"
        ))
    })
}

/// Resolve the agent's PoP credential path for the broker path: `SIGNET_BROKER_CREDENTIAL` if set,
/// else the per-handle default (`<config-dir>/garnet/<handle>.json`) for `SIGNET_HANDLE`. With a
/// broker configured but neither present, fail loud rather than guess.
fn broker_credential_path() -> Result<PathBuf> {
    if let Some(p) = std::env::var("SIGNET_BROKER_CREDENTIAL")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        return Ok(PathBuf::from(p));
    }
    match std::env::var("SIGNET_HANDLE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        Some(handle) => Ok(crate::garnet::default_credential_path(&handle)),
        None => Err(CliError::config(
            "SIGNET_BROKER_ADDR is set but the broker credential is unresolved. Set \
             SIGNET_BROKER_CREDENTIAL or SIGNET_HANDLE",
        )),
    }
}

/// Container host-delegation config, read from the environment provisioned at
/// container creation (Account-and-Kit §f.7): the bind-mounted channel folder, a
/// stable channel id (NOT the handle — the handle is chosen later, at enrollment),
/// and the per-PRSN secret (a hex-encoded 32-byte file in the container's *private*
/// filesystem, never the channel folder). Present ⇒ this guest delegates to a
/// host-signer.
struct HostDelegation {
    channel_dir: PathBuf,
    channel_id: String,
    secret: ChannelSecret,
}

/// Read the host-delegation config from the environment, or `None` if this is not a
/// delegating container (`SIGNET_HOST_CHANNEL_DIR` unset).
fn host_delegation() -> Result<Option<HostDelegation>> {
    let Some(channel_dir) = std::env::var_os("SIGNET_HOST_CHANNEL_DIR") else {
        return Ok(None);
    };
    let channel_id = std::env::var("SIGNET_HOST_CHANNEL_ID").map_err(|_| {
        CliError::config("SIGNET_HOST_CHANNEL_DIR is set but SIGNET_HOST_CHANNEL_ID is not")
    })?;
    let secret_file = std::env::var("SIGNET_HOST_CHANNEL_SECRET_FILE").map_err(|_| {
        CliError::config(
            "SIGNET_HOST_CHANNEL_DIR is set but SIGNET_HOST_CHANNEL_SECRET_FILE is not",
        )
    })?;
    Ok(Some(HostDelegation {
        channel_dir: PathBuf::from(channel_dir),
        channel_id,
        secret: read_channel_secret(&secret_file)?,
    }))
}

/// Read a per-PRSN channel secret from a hex-encoded file (32 bytes / 64 hex chars).
/// The file lives in the container's private filesystem (never the channel folder,
/// which is host-readable).
fn read_channel_secret(path: &str) -> Result<ChannelSecret> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        CliError::config(format!("reading the host-delegation secret '{path}': {e}"))
    })?;
    let bytes = hex::decode(text.trim())
        .map_err(|_| CliError::config("the host-delegation secret file must be hex-encoded"))?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        CliError::config("the host-delegation secret must be 32 bytes (64 hex chars)")
    })?;
    Ok(ChannelSecret::from_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_parse_accepts_canonical() {
        let l = KeyLabel::parse("hlin-ai-signing", Some(Purpose::Signing)).unwrap();
        assert_eq!(l.full(), "hlin-ai-signing");
        assert_eq!(l.purpose(), Purpose::Signing);
        let k = KeyLabel::parse("mira-ai-kem", None).unwrap();
        assert_eq!(k.purpose(), Purpose::Kem);
    }

    #[test]
    fn label_parse_accepts_pq_purposes() {
        // The four-key hybrid identity (PQR item 2, Build-Plan §2a): the PQ
        // suffixes parse to their own purposes and yield the same handle.
        let s = KeyLabel::parse("hlin-ai-signing-pq", None).unwrap();
        assert_eq!(s.purpose(), Purpose::SigningPq);
        assert_eq!(s.handle(), "hlin-ai");
        assert_eq!(s.full(), "hlin-ai-signing-pq");
        let k = KeyLabel::parse("mira-ai-kem-pq", Some(Purpose::KemPq)).unwrap();
        assert_eq!(k.purpose(), Purpose::KemPq);
        // No cross-matching in either direction: a classical label is not a PQ
        // label, and a PQ label is not its classical prefix's purpose.
        assert!(KeyLabel::parse("hlin-ai-signing", Some(Purpose::SigningPq)).is_err());
        assert!(KeyLabel::parse("hlin-ai-signing-pq", Some(Purpose::Signing)).is_err());
        assert!(KeyLabel::parse("hlin-ai-kem-pq", Some(Purpose::Kem)).is_err());
        // Round-trip through the Purpose API.
        assert_eq!(Purpose::SigningPq.default_alg(), "ML-DSA-87");
        assert_eq!(Purpose::KemPq.default_alg(), "ML-KEM-1024");
    }

    #[test]
    fn label_parse_rejects_bad() {
        // Wrong / missing purpose suffix.
        assert!(KeyLabel::parse("hlin-ai", None).is_err());
        // Purpose/flag mismatch.
        assert!(KeyLabel::parse("hlin-ai-kem", Some(Purpose::Signing)).is_err());
        // Handle not ending in -ai.
        assert!(KeyLabel::parse("hlin-signing", Some(Purpose::Signing)).is_err());
        // Uppercase.
        assert!(KeyLabel::parse("Hlin-ai-signing", Some(Purpose::Signing)).is_err());
        // A bare `-pq` is not a purpose.
        assert!(KeyLabel::parse("hlin-ai-pq", None).is_err());
    }

    #[test]
    fn mldsa_ctx_ceiling_enforced() {
        assert!(validate_mldsa_ctx(b"signet:req:v1").is_ok());
        assert!(validate_mldsa_ctx(&[0u8; 255]).is_ok());
        assert!(validate_mldsa_ctx(&[0u8; 256]).is_err());
    }

    #[test]
    fn tier_wire_str_is_underscored_distinct_from_display() {
        // The server's `key_protection` accepts the underscored wire form only
        // (S052; `enroll` submits this). The hyphenated `as_str` is CLI display only.
        assert_eq!(Tier::SecureEnclave.wire_str(), "secure_enclave");
        assert_eq!(Tier::Software.wire_str(), "software");
        assert_eq!(Tier::SecureEnclave.as_str(), "secure-enclave");
    }

    #[test]
    fn resolve_broker_addr_accepts_ip_and_hostname() {
        // IP literal (the native case) — no DNS.
        let a = resolve_broker_addr("127.0.0.1:8765").unwrap();
        assert_eq!(a, "127.0.0.1:8765".parse::<SocketAddr>().unwrap());
        // A resolvable hostname (the Docker `host.docker.internal` case, exercised hermetically with
        // `localhost`) — IPv4 preferred over any AAAA record → loopback v4.
        let l = resolve_broker_addr("localhost:8765").unwrap();
        assert!(
            l.ip().is_loopback(),
            "localhost must resolve to loopback, got {l}"
        );
        assert_eq!(l.port(), 8765);
        assert!(
            l.is_ipv4(),
            "IPv4 is preferred over the AAAA record, got {l}"
        );
    }

    #[test]
    fn resolve_broker_addr_rejects_malformed() {
        assert!(resolve_broker_addr("127.0.0.1").is_err()); // no port
        assert!(resolve_broker_addr("").is_err()); // empty
        assert!(resolve_broker_addr("not-a-socket-addr").is_err()); // no port → no DNS attempt
    }

    #[test]
    fn read_channel_secret_parses_hex_32() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.hex");
        std::fs::write(&path, format!("{}\n", "ab".repeat(32))).unwrap();
        let secret = read_channel_secret(path.to_str().unwrap()).unwrap();
        assert_eq!(secret.as_bytes(), &[0xab; 32]);
    }

    #[test]
    fn read_channel_secret_rejects_wrong_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secret.hex");
        std::fs::write(&path, "abab").unwrap();
        assert!(read_channel_secret(path.to_str().unwrap()).is_err());
    }

    #[test]
    fn check_identity_match_fails_closed_on_mismatch() {
        // The realistic accident: the container is wired to a different PRSN's
        // channel than SIGNET_HANDLE asserts → refuse, fail closed.
        let err = check_identity_match(Some("zain-ai"), Some("mira-ai")).unwrap_err();
        assert_eq!(err.code, "identity_mismatch");
        assert_eq!(err.exit_code, 61);
        // The message names both the pinned and the asserted handle (actionable).
        assert!(err.message.contains("zain-ai") && err.message.contains("mira-ai"));
    }

    #[test]
    fn check_identity_match_ok_when_pin_equals_asserted() {
        assert!(check_identity_match(Some("mira-ai"), Some("mira-ai")).is_ok());
    }

    #[test]
    fn check_identity_match_skips_when_nothing_to_check() {
        // No asserted handle → nothing to verify against here (the resolver gate
        // handles "require SIGNET_HANDLE" separately).
        assert!(check_identity_match(Some("mira-ai"), None).is_ok());
        assert!(check_identity_match(None, None).is_ok());
        // Channel not yet enrolled (pin None) → do not block; `enroll` will pin it.
        assert!(check_identity_match(None, Some("mira-ai")).is_ok());
    }
}
