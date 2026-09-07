// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Subcommand implementations: key management (keygen, fingerprint, pubkey, keys
//! list/delete), crypto operations (sign, encrypt, decrypt, rewrap, encrypt-name,
//! decrypt-name), utilities (rand, base64url-no-pad, version), server-bound
//! verification + sync (attestation-verify, transparency-verify, audit, update),
//! account reads (whoami, quota), and the file transport (upload, download). Each
//! takes the opened keystore (where needed) + output mode and returns a
//! [`Result`]; `main` maps the error to an exit code. The CLI does no raw crypto —
//! every primitive goes through `signet-crypto`; secret material (DEKs, KEKs,
//! shared secrets) is held in `Zeroizing` and never crosses the command line.

use std::io::{BufRead, Read, Seek, SeekFrom, Write};
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use serde_json::Value;
use signet_crypto::encname::NameEnvelope;
use signet_crypto::hybrid_wrap::HybridWrapEnvelope;
use signet_crypto::wrap::WrapEnvelope;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::config::Config;
use crate::error::{CliError, Result};
use crate::http;
use crate::hybrid;
use crate::keystore::{KeyLabel, Keystore, Purpose};
use crate::output::OutputMode;
use crate::resolve::Resolver;
use crate::transfer_governor::{GovernorKnobs, TransferGovernor};

/// The wrap algorithm of a wrapped-key JSON value, read from `alg` ALONE —
/// never inferred from field presence (PQR Spec §5.2). Any other alg —
/// including the reserved pure `ML-KEM-1024+A256KW` — is rejected.
pub(crate) enum WrapAlg {
    Classical,
    Hybrid,
}

pub(crate) fn wrap_alg_of(value: &Value) -> Result<WrapAlg> {
    match value.get("alg").and_then(Value::as_str) {
        Some("ECDH-ES+A256KW") => Ok(WrapAlg::Classical),
        Some("ECDH-ES+ML-KEM-1024+A256KW") => Ok(WrapAlg::Hybrid),
        _ => Err(CliError::invalid_data("unknown wrap alg")),
    }
}

/// The kem-pq sibling of a kem label (same handle — the four-key identity).
fn kem_pq_sibling(kem_label: &KeyLabel) -> Result<KeyLabel> {
    KeyLabel::from_handle(kem_label.handle(), Purpose::KemPq)
}

/// Unwrap a wrapped-DEK JSON value addressed to me — classical or hybrid,
/// dispatched on `alg` alone (§5.2). The hybrid path's shared secrets come
/// from the keystore (`ecdh` + `ml_kem_decapsulate`); per §10 a tampered `ek`
/// surfaces as AES-KW integrity failure, never a decap error.
pub(crate) fn unwrap_dek_value(
    keystore: &dyn Keystore,
    value: &Value,
    kem_label: &KeyLabel,
) -> Result<Zeroizing<[u8; 32]>> {
    match wrap_alg_of(value)? {
        WrapAlg::Classical => {
            let envelope: WrapEnvelope = serde_json::from_value(value.clone())
                .map_err(|_| CliError::invalid_data("wrapped DEK envelope"))?;
            let epk = envelope
                .ephemeral_pubkey_x963()
                .map_err(|_| CliError::invalid_data("wrapped DEK epk"))?;
            let z = Zeroizing::new(keystore.ecdh(kem_label, &epk)?);
            Ok(Zeroizing::new(
                signet_crypto::wrap::unwrap_dek_with_shared_secret(&z, &envelope)?,
            ))
        }
        WrapAlg::Hybrid => {
            let envelope: HybridWrapEnvelope = serde_json::from_value(value.clone())
                .map_err(|_| CliError::invalid_data("hybrid wrapped DEK envelope"))?;
            hybrid::unwrap_key_hybrid(
                keystore,
                kem_label,
                &kem_pq_sibling(kem_label)?,
                &envelope,
                &[],
            )
        }
    }
}

/// Resolve exactly one of `--signing` / `--kem` / `--signing-pq` / `--kem-pq`
/// into a [`Purpose`].
pub fn purpose_from_flags(
    signing: bool,
    kem: bool,
    signing_pq: bool,
    kem_pq: bool,
) -> Result<Purpose> {
    match (signing, kem, signing_pq, kem_pq) {
        (true, false, false, false) => Ok(Purpose::Signing),
        (false, true, false, false) => Ok(Purpose::Kem),
        (false, false, true, false) => Ok(Purpose::SigningPq),
        (false, false, false, true) => Ok(Purpose::KemPq),
        (false, false, false, false) => Err(CliError::invalid_args(
            "specify one of --signing, --kem, --signing-pq, or --kem-pq",
        )),
        _ => Err(CliError::invalid_args(
            "--signing, --kem, --signing-pq, and --kem-pq are mutually exclusive",
        )),
    }
}

/// v1 accepts exactly one algorithm per purpose (v2 adds ML-DSA-87 / ML-KEM).
fn validate_alg(purpose: Purpose, alg: &str) -> Result<()> {
    if alg == purpose.default_alg() {
        Ok(())
    } else {
        Err(CliError::invalid_args(format!(
            "algorithm '{alg}' is not valid for a {} key in v1 (expected '{}')",
            purpose.as_str(),
            purpose.default_alg()
        )))
    }
}

/// The active PRSN handle the harness asserts for this session, from `SIGNET_HANDLE`
/// (trimmed; empty ⇒ unset). The launch-injected "which PRSN am I" — the safe-default
/// identity source on any host that could be multi-PRSN, and the value the resolver
/// cross-checks an explicit `--key` / config default against (Container-PRSN-Onboarding-
/// Requirement v05 §9/§11). `pub(crate)` so `enroll`'s idempotency check shares it.
pub(crate) fn asserted_handle() -> Option<String> {
    std::env::var("SIGNET_HANDLE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// The configured default key label for `purpose`, if any (the optional single-PRSN
/// native convenience — Account-and-Kit §c).
fn config_default(purpose: Purpose, config: &Config) -> Option<String> {
    match purpose {
        Purpose::Signing => config.default_signing_key.clone(),
        Purpose::Kem => config.default_kem_key.clone(),
        // No config-default convenience for the PQ halves: they are addressed by
        // explicit label (or derived from the resolved handle) — the resolver's
        // other sources cover them (PQR item 2; Build-Plan §2a).
        Purpose::SigningPq | Purpose::KemPq => None,
    }
}

/// The identity resolver (Container-PRSN-Onboarding-Requirement v05 §9/§11): resolve
/// *which key a command acts with*, then **verify** the binding, fail-closed.
///
/// **Resolve** in order: explicit `--key` → `SIGNET_HANDLE` (the harness-injected safe
/// default) → the optional config default → **error — never guess** (an actionable
/// refusal naming `SIGNET_HANDLE`, not a silent pick).
///
/// **Verify** (the native analog of the container launch-binding cross-check —
/// `keystore::open`'s `verify_channel_identity`): if the harness asserts a handle
/// (`SIGNET_HANDLE`), it must equal the resolved key's handle, else **fail closed**
/// (`identity_mismatch`). This catches a `--key` / config default that names a
/// *different* PRSN than the harness asserts at launch — a confident-but-wrong binding
/// that the never-guess rule alone would not (never-guess catches *ambiguity*, not a
/// consistent wrong choice).
///
/// Identity is **never resolved by enumerating the keystore.** An incomplete
/// enumeration (1-of-N) would silently select a wrong identity that never-guess cannot
/// catch — incompleteness hides the multiplicity (v05 §11). `keys list` enumerates for
/// display only; resolution requires an explicit source. (Enumeration-as-a-convenience
/// is gated on the §12 hardware validation and is not wired here.)
fn resolve_label(label_arg: Option<&str>, purpose: Purpose, config: &Config) -> Result<KeyLabel> {
    resolve_label_for(asserted_handle().as_deref(), label_arg, purpose, config)
}

/// The pure resolver decision (no environment read) — split out so the full
/// resolve-and-verify logic is unit-testable without mutating the process `SIGNET_HANDLE`
/// (mirroring `keystore::check_identity_match`). See [`resolve_label`] for the contract.
fn resolve_label_for(
    asserted: Option<&str>,
    label_arg: Option<&str>,
    purpose: Purpose,
    config: &Config,
) -> Result<KeyLabel> {
    let label = match label_arg {
        // An explicit --key names the exact label; verified against SIGNET_HANDLE below.
        Some(s) => KeyLabel::parse(s, Some(purpose))?,
        // SIGNET_HANDLE is authoritative when set (a divergent config default cannot
        // silently win — it is simply not consulted here).
        None if asserted.is_some() => {
            KeyLabel::from_handle(asserted.expect("asserted is_some"), purpose)?
        }
        // No --key, no SIGNET_HANDLE → the optional config default (single-PRSN native).
        None => match config_default(purpose, config) {
            Some(cfg_label) => KeyLabel::parse(&cfg_label, Some(purpose))?,
            None => {
                return Err(CliError::invalid_args(format!(
                    "no identity to act as: set SIGNET_HANDLE (the handle your harness injects), \
                     pass --key <handle>-{p}, or configure default_{p}_key; `signet` never \
                     guesses which PRSN you are.",
                    p = purpose.as_str()
                )));
            }
        },
    };
    if let Some(h) = asserted
        && label.handle() != h
    {
        return Err(CliError::identity_mismatch(format!(
            "launch-binding mismatch: the harness asserts SIGNET_HANDLE='{h}', but this key \
             resolves to PRSN '{}'. Refusing to act as a different identity than the one \
             asserted at launch; reconcile --key / default_{}_key with SIGNET_HANDLE.",
            label.handle(),
            purpose.as_str()
        )));
    }
    Ok(label)
}

pub fn keygen(
    keystore: &dyn Keystore,
    label: &str,
    purpose: Purpose,
    algorithm: Option<&str>,
    out: &OutputMode,
) -> Result<()> {
    let label = KeyLabel::parse(label, Some(purpose))?;
    let alg = algorithm.unwrap_or_else(|| purpose.default_alg());
    validate_alg(purpose, alg)?;
    let meta = keystore.generate(&label, alg)?;
    out.print_json(&meta)
}

pub fn fingerprint(
    keystore: &dyn Keystore,
    key: Option<&str>,
    purpose: Purpose,
    json: bool,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    let label = resolve_label(key, purpose, config)?;
    let meta = keystore.meta(&label)?;
    if json {
        out.print_json(&serde_json::json!({
            "label": meta.label,
            "purpose": meta.purpose,
            "algorithm": meta.algorithm,
            "fingerprint": meta.fingerprint,
        }))
    } else {
        out.write_str(&meta.fingerprint)
    }
}

pub fn pubkey(
    keystore: &dyn Keystore,
    key: Option<&str>,
    purpose: Purpose,
    format: &str,
    base64url: bool,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    let label = resolve_label(key, purpose, config)?;
    let pk = keystore.meta(&label)?.public_key;
    // PQ keys are raw FIPS bytes (an ML-DSA-87 vk / an ML-KEM-1024 ek) — no
    // SPKI/JWK form exists for them in v1; `raw` (or the default) emits the
    // bytes, optionally base64url.
    if matches!(purpose, Purpose::SigningPq | Purpose::KemPq) {
        return match format {
            "raw" | "x963" => emit_bytes(&pk, base64url, out),
            other => Err(CliError::invalid_args(format!(
                "--format '{other}' is not defined for a PQ key (use raw)"
            ))),
        };
    }
    match format {
        "x963" | "raw" => emit_bytes(&pk, base64url, out),
        "der" => emit_bytes(&signet_crypto::pubkey::spki_der(&pk)?, base64url, out),
        "pem" => out.write_str(&signet_crypto::pubkey::spki_pem(&pk)?),
        "jwk" => out.print_json(&signet_crypto::pubkey::jwk(&pk)?),
        other => Err(CliError::invalid_args(format!(
            "unknown --format '{other}' (expected x963|der|pem|jwk)"
        ))),
    }
}

fn emit_bytes(bytes: &[u8], base64url: bool, out: &OutputMode) -> Result<()> {
    if base64url {
        out.write_str(&URL_SAFE_NO_PAD.encode(bytes))
    } else {
        out.write_bytes(bytes)
    }
}

pub fn keys_list(keystore: &dyn Keystore, json: bool, out: &OutputMode) -> Result<()> {
    let keys = keystore.list()?;
    if json {
        return out.print_json(&keys);
    }
    // Tabular default.
    let mut stdout = std::io::stdout().lock();
    writeln!(
        stdout,
        "{:<22} {:<8} {:<16} {:<18} FINGERPRINT",
        "LABEL", "PURPOSE", "ALGORITHM", "STORAGE"
    )
    .map_err(write_err)?;
    for k in &keys {
        let fp = if k.fingerprint.len() > 16 {
            format!("{}…", &k.fingerprint[..16])
        } else {
            k.fingerprint.clone()
        };
        writeln!(
            stdout,
            "{:<22} {:<8} {:<16} {:<18} {}",
            k.label, k.purpose, k.algorithm, k.storage, fp
        )
        .map_err(write_err)?;
    }
    Ok(())
}

pub fn keys_delete(
    keystore: &dyn Keystore,
    handle: &str,
    purpose: Option<Purpose>,
    force: bool,
    confirm_delete_both: bool,
) -> Result<()> {
    let targets: Vec<KeyLabel> = match purpose {
        Some(p) => vec![KeyLabel::from_handle(handle, p)?],
        None => {
            let mut existing = Vec::new();
            // All four purposes (the hybrid identity is four keys — PQR item 2);
            // the sweep silently skips purposes with no key, as before.
            for p in [
                Purpose::Signing,
                Purpose::Kem,
                Purpose::SigningPq,
                Purpose::KemPq,
            ] {
                let label = KeyLabel::from_handle(handle, p)?;
                if keystore.exists(&label)? {
                    existing.push(label);
                }
            }
            if existing.is_empty() {
                return Err(CliError::key_not_found(format!(
                    "no keys for handle '{handle}'"
                )));
            }
            existing
        }
    };

    // More than one key in a purposeless sweep = deleting (part of) the PRSN's
    // whole identity — the same guard as the original both-keys case, extended
    // to the four-key hybrid identity.
    let deleting_both = purpose.is_none() && targets.len() > 1;
    if deleting_both && force && !confirm_delete_both {
        return Err(CliError::invalid_args(
            "deleting multiple keys for a handle requires --confirm-delete-both with --force",
        ));
    }

    for label in &targets {
        if !keystore.exists(label)? {
            // Explicit single-purpose target that's missing is an error; a
            // both-purposes sweep silently skips an absent purpose.
            if purpose.is_some() {
                return Err(CliError::key_not_found(format!(
                    "no key '{}'. 'signet keys list' shows what this keystore holds",
                    label.full()
                )));
            }
            continue;
        }
        if !force
            && !confirm_prompt(&format!(
                "Delete key {} ({})?",
                label.full(),
                label.purpose().as_str()
            ))?
        {
            return Err(CliError::new(1, "declined", "deletion declined"));
        }
        keystore.delete(label)?;
    }
    Ok(())
}

/// Prompt on stderr, read a line from stdin; true on y/yes.
fn confirm_prompt(question: &str) -> Result<bool> {
    eprint!("{question} [y/N] ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| CliError::input_read(format!("reading confirmation: {e}")))?;
    let answer = line.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}

fn write_err(e: std::io::Error) -> CliError {
    CliError::output_write(format!("writing stdout: {e}"))
}

/// bug058: render an epoch-seconds timestamp human-readably in TABLE output —
/// `2026-07-06 14:27 UTC` (minute precision, explicit UTC). The table is the
/// human-legible register; **JSON output keeps raw epoch seconds** (the agent's
/// native register — unambiguous, sortable) and must not change. Out-of-range
/// falls back to the raw number rather than erroring a listing over one bad row.
fn table_ts(epoch_secs: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(epoch_secs) {
        Ok(t) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02} UTC",
            t.year(),
            u8::from(t.month()),
            t.day(),
            t.hour(),
            t.minute()
        ),
        Err(_) => epoch_secs.to_string(),
    }
}

// ── Shared I/O + parsing helpers (crypto-op commands) ───────────────────────

/// Read input bytes from `--in <path>` or stdin (to EOF).
pub(crate) fn read_input(path: Option<&Path>) -> Result<Vec<u8>> {
    match path {
        Some(p) => std::fs::read(p)
            .map_err(|e| CliError::input_read(format!("reading {}: {e}", p.display()))),
        None => {
            let mut buf = Vec::new();
            std::io::stdin()
                .lock()
                .read_to_end(&mut buf)
                .map_err(|e| CliError::input_read(format!("reading stdin: {e}")))?;
            Ok(buf)
        }
    }
}

/// Write output bytes to `--out <path>` or stdout.
pub(crate) fn write_output(path: Option<&Path>, bytes: &[u8]) -> Result<()> {
    match path {
        Some(p) => std::fs::write(p, bytes)
            .map_err(|e| CliError::output_write(format!("writing {}: {e}", p.display()))),
        None => std::io::stdout().write_all(bytes).map_err(write_err),
    }
}

/// Read a JSON value from a file path, or stdin when the path is `-`.
fn read_json_arg<T: serde::de::DeserializeOwned>(path: &str, what: &str) -> Result<T> {
    let bytes = if path == "-" {
        read_input(None)?
    } else {
        read_input(Some(Path::new(path)))?
    };
    serde_json::from_slice(&bytes)
        .map_err(|e| CliError::invalid_data(format!("invalid {what}: {e}")))
}

/// Parse a UUID string into its 16 raw bytes.
fn parse_uuid16(s: &str) -> Result<[u8; 16]> {
    let uuid = uuid::Uuid::parse_str(s)
        .map_err(|_| CliError::invalid_args(format!("'{s}' is not a valid UUID")))?;
    Ok(*uuid.as_bytes())
}

/// Parse a `--to-pubkey` value into a 65-byte X9.63 P-256 point. Auto-detects
/// base64url(X9.63) | JWK JSON | PEM, or `@<file>` (reads + parses the file).
fn parse_pubkey_arg(value: &str) -> Result<Vec<u8>> {
    if let Some(path) = value.strip_prefix('@') {
        let bytes = std::fs::read(path)
            .map_err(|e| CliError::input_read(format!("reading pubkey file {path}: {e}")))?;
        return match std::str::from_utf8(&bytes) {
            Ok(text) => parse_pubkey_text(text.trim()),
            Err(_) => validate_x963(bytes),
        };
    }
    parse_pubkey_text(value.trim())
}

fn parse_pubkey_text(value: &str) -> Result<Vec<u8>> {
    if value.contains("BEGIN PUBLIC KEY") {
        return signet_crypto::pubkey::x963_from_pem(value)
            .map_err(|_| CliError::invalid_data("invalid PEM public key"));
    }
    if value.starts_with('{') {
        let jwk: serde_json::Value =
            serde_json::from_str(value).map_err(|_| CliError::invalid_data("invalid JWK JSON"))?;
        return signet_crypto::pubkey::x963_from_jwk(&jwk)
            .map_err(|_| CliError::invalid_data("invalid JWK public key"));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| CliError::invalid_data("--to-pubkey is not base64url / PEM / JWK"))?;
    validate_x963(bytes)
}

fn validate_x963(bytes: Vec<u8>) -> Result<Vec<u8>> {
    if bytes.len() != 65 || bytes[0] != 0x04 {
        return Err(CliError::invalid_data(
            "expected a 65-byte X9.63 uncompressed P-256 point",
        ));
    }
    // Confirm the point is on-curve (fingerprint parses via from_sec1_bytes).
    signet_crypto::pubkey::fingerprint(&bytes)
        .map_err(|_| CliError::invalid_data("public key is not a valid P-256 point"))?;
    Ok(bytes)
}

// ── Crypto operations ───────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
pub fn sign(
    keystore: &dyn Keystore,
    key: Option<&str>,
    input_format: &str,
    output_format: &str,
    in_path: Option<&Path>,
    out_path: Option<&Path>,
    dual: bool,
    config: &Config,
) -> Result<()> {
    let label = resolve_label(key, Purpose::Signing, config)?;
    let message = decode_sign_input(&read_input(in_path)?, input_format)?;
    if message.len() > SIGN_INPUT_MAX {
        return Err(CliError::invalid_args("input exceeds the 1 MB sign limit"));
    }
    if !dual {
        let sig = keystore.sign(&label, &message)?;
        return write_output(out_path, &encode_signature(&sig, output_format)?);
    }

    // `--dual`: the per-request hybrid signature, composed EXACTLY as the wire
    // path composes it (http.rs `request_signature` — spec §8 point 1 / §8.7):
    // both halves over the identical bytes, the ML-DSA half under the
    // `signet:req:v1` context as the FIPS 204 context *parameter*. Explicit
    // rather than auto-detected: a scripter asking for the dual should get the
    // dual or a clear error, never a silent classical signature.
    if matches!(output_format, "der" | "base64url-der") {
        return Err(CliError::invalid_args(
            "--dual emits the fixed-width raw dual; DER is a classical-signature wire form \
             (use raw or base64url-raw)",
        ));
    }
    let pq_label = KeyLabel::from_handle(label.handle(), Purpose::SigningPq)?;
    if !keystore.exists(&pq_label)? {
        return Err(CliError::key_not_found(format!(
            "no signing-pq key for handle '{}': --dual needs the four-key hybrid identity \
             (enroll through the four-key ceremony, or drop --dual to sign classically)",
            label.handle()
        )));
    }
    let sig_es = keystore.sign(&label, &message)?;
    let sig_pq = keystore.ml_dsa_sign(
        &pq_label,
        &message,
        signet_crypto::attest::REQUEST_MLDSA_CTX,
    )?;
    if sig_pq.len() != signet_crypto::attest::MLDSA87_SIG_LEN {
        return Err(CliError::generic(format!(
            "keystore returned a {}-byte ML-DSA-87 signature (expected 4627)",
            sig_pq.len()
        )));
    }
    let mut dual_sig = Vec::with_capacity(signet_crypto::attest::REQUEST_DUAL_SIG_LEN);
    dual_sig.extend_from_slice(&sig_es);
    dual_sig.extend_from_slice(&sig_pq);
    write_output(out_path, &encode_signature(&dual_sig, output_format)?)
}

/// The 1 MB cap on a sign input (applies to both the direct keystore sign and the broker-routed
/// `signet garnet sign`).
pub(crate) const SIGN_INPUT_MAX: usize = 1_048_576;

/// Decode a sign input per `--input-format` (`bytes`|`hex`|`base64url`). Shared by the direct sign
/// and the Garnet broker-routed sign so the two cannot diverge. Pure.
pub(crate) fn decode_sign_input(raw: &[u8], input_format: &str) -> Result<Vec<u8>> {
    match input_format {
        "bytes" => Ok(raw.to_vec()),
        "hex" => hex::decode(String::from_utf8_lossy(raw).trim())
            .map_err(|_| CliError::invalid_args("--input-format hex: invalid hex")),
        "base64url" => URL_SAFE_NO_PAD
            .decode(String::from_utf8_lossy(raw).trim())
            .map_err(|_| CliError::invalid_args("--input-format base64url: invalid base64url")),
        other => Err(CliError::invalid_args(format!(
            "unknown --input-format '{other}' (bytes|hex|base64url)"
        ))),
    }
}

/// Encode a raw `r‖s` ES256 signature per `--output-format` (`raw`|`der`|`base64url-raw`|
/// `base64url-der`). Shared by the direct sign (a `[u8; 64]`) and the Garnet broker-routed sign (a
/// `Vec<u8>`); a DER format requires exactly 64 bytes. Pure.
pub(crate) fn encode_signature(sig: &[u8], output_format: &str) -> Result<Vec<u8>> {
    let to_der = |sig: &[u8]| -> Result<Vec<u8>> {
        let raw: &[u8; 64] = sig
            .try_into()
            .map_err(|_| CliError::invalid_data("signature is not a 64-byte raw r‖s"))?;
        Ok(signet_crypto::ecdsa::sig_raw_to_der(raw)?)
    };
    match output_format {
        "raw" => Ok(sig.to_vec()),
        "der" => to_der(sig),
        "base64url-raw" => Ok(URL_SAFE_NO_PAD.encode(sig).into_bytes()),
        "base64url-der" => Ok(URL_SAFE_NO_PAD.encode(to_der(sig)?).into_bytes()),
        other => Err(CliError::invalid_args(format!(
            "unknown --output-format '{other}' (raw|der|base64url-raw|base64url-der)"
        ))),
    }
}

/// Assemble the offline recipient set for `encrypt`/`rewrap` from explicit
/// `--to-pubkey` / `--to-pq-pubkey` pairs (matched by position). Mandatory
/// hybrid write (F-DOWNGRADE(a)) applies to the OFFLINE writers too: every
/// recipient needs its ML-KEM half — the shipped binary emits no classical-
/// only wrap from any path. (The classical-only pairing survives behind the
/// hard-off `classical-write` feature, like every other write arm.)
fn offline_recipients(
    to_pubkey: &[String],
    to_pq_pubkey: &[String],
) -> Result<Vec<RecipientWrapKeys>> {
    if to_pubkey.is_empty() {
        return Err(CliError::invalid_args(
            "at least one --to-pubkey is required",
        ));
    }
    #[cfg(not(feature = "classical-write"))]
    if to_pq_pubkey.len() != to_pubkey.len() {
        return Err(CliError::invalid_args(format!(
            "every recipient needs its ML-KEM key: got {} --to-pubkey but {} \
             --to-pq-pubkey (mandatory hybrid write, PQR §9.2; pair them by \
             position)",
            to_pubkey.len(),
            to_pq_pubkey.len()
        )));
    }
    #[cfg(feature = "classical-write")]
    if !to_pq_pubkey.is_empty() && to_pq_pubkey.len() != to_pubkey.len() {
        return Err(CliError::invalid_args(
            "--to-pq-pubkey must be given for every recipient or none (paired by position)",
        ));
    }
    let mut recipients: Vec<RecipientWrapKeys> = Vec::with_capacity(to_pubkey.len());
    let mut seen: Vec<Vec<u8>> = Vec::with_capacity(to_pubkey.len());
    for (i, value) in to_pubkey.iter().enumerate() {
        let pk = parse_pubkey_arg(value)?;
        if seen.contains(&pk) {
            return Err(CliError::invalid_args("a --to-pubkey value was repeated"));
        }
        seen.push(pk.clone());
        let rk_pq = match to_pq_pubkey.get(i) {
            Some(b64) => {
                let ek = URL_SAFE_NO_PAD
                    .decode(b64)
                    .map_err(|_| CliError::invalid_args("--to-pq-pubkey is not base64url"))?;
                if ek.len() != signet_crypto::hybrid_wrap::MLKEM1024_EK_LEN {
                    return Err(CliError::invalid_args(
                        "--to-pq-pubkey must be a 1568-byte ML-KEM-1024 encapsulation key",
                    ));
                }
                Some(ek)
            }
            None => None,
        };
        recipients.push(RecipientWrapKeys { rk_ec: pk, rk_pq });
    }
    Ok(recipients)
}

pub fn encrypt(
    in_path: &Path,
    out_path: &Path,
    aad_file_id: &str,
    to_pubkey: &[String],
    to_pq_pubkey: &[String],
    wraps_out: &Path,
    out: &OutputMode,
) -> Result<()> {
    let recipients = offline_recipients(to_pubkey, to_pq_pubkey)?;
    let file_id = parse_uuid16(aad_file_id)?;
    let plaintext = read_input(Some(in_path))?;

    let mut dek = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *dek);
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);

    let ciphertext = signet_crypto::envelope::seal_file(&dek, &iv, &file_id, &plaintext)
        .map_err(|_| CliError::encryption_failed("file encryption failed"))?;
    write_output(Some(out_path), &ciphertext)?;

    // One dispatch for every wrap the CLI ever emits (wrap_dek_for) — the
    // offline path shares the mandatory-hybrid backstop with the drive flows.
    let mut wraps: Vec<Value> = Vec::with_capacity(recipients.len());
    for keys in &recipients {
        wraps.push(wrap_dek_for(keys, &dek)?);
    }
    let wraps_json = serde_json::to_vec_pretty(&wraps)
        .map_err(|e| CliError::generic(format!("serializing wraps: {e}")))?;
    std::fs::write(wraps_out, wraps_json)
        .map_err(|e| CliError::output_write(format!("writing {}: {e}", wraps_out.display())))?;

    out.print_json(&serde_json::json!({
        "file_id": aad_file_id,
        "size_bytes": plaintext.len(),
        "ciphertext_size_bytes": ciphertext.len(),
        "recipients_wrapped": recipients.len(),
        "wraps_file": wraps_out.display().to_string(),
    }))
}

pub fn decrypt(
    keystore: &dyn Keystore,
    in_path: &Path,
    out_path: &Path,
    aad_file_id: &str,
    wrap_envelope: &str,
    key: Option<&str>,
    config: &Config,
) -> Result<()> {
    let file_id = parse_uuid16(aad_file_id)?;
    let label = resolve_label(key, Purpose::Kem, config)?;
    let ciphertext = read_input(Some(in_path))?;
    let envelope: Value = read_json_arg(wrap_envelope, "wrap envelope")?;
    let dek = unwrap_dek_value(keystore, &envelope, &label)?;
    let plaintext = signet_crypto::envelope::open_file(&dek, &file_id, &ciphertext)?;
    write_output(Some(out_path), &plaintext)
}

/// Re-wrap a DEK from my wrap envelope (classical or hybrid — dispatched on
/// `alg`) to a new recipient — the DEK never leaves the process: unwrap with
/// my keystore keys (the private material never surfaces), then wrap to the
/// recipient's verified bundle (§9.2 dispatch). The shared step behind
/// `signet rewrap` (one envelope) and `share invite` (every file's DEK).
fn rewrap_dek_to(
    keystore: &dyn Keystore,
    kem_label: &KeyLabel,
    envelope: &Value,
    recipient: &RecipientWrapKeys,
) -> Result<Value> {
    let dek = unwrap_dek_value(keystore, envelope, kem_label)?;
    wrap_dek_for(recipient, &dek)
}

pub fn rewrap(
    keystore: &dyn Keystore,
    wrap_envelope_in: &str,
    to_pubkey: &str,
    to_pq_pubkey: Option<&str>,
    wrap_out: &Path,
    key: Option<&str>,
    config: &Config,
) -> Result<()> {
    let label = resolve_label(key, Purpose::Kem, config)?;
    let envelope: Value = read_json_arg(wrap_envelope_in, "wrap envelope")?;
    // The standalone command takes explicit --to-pubkey / --to-pq-pubkey
    // recipient keys (no directory bundle exists offline). Mandatory hybrid
    // write applies here too: `offline_recipients` requires the ML-KEM half
    // in the default build. Directory-driven rewraps (share invite) carry the
    // recipient's full verified bundle instead.
    let recipient = offline_recipients(
        std::slice::from_ref(&to_pubkey.to_string()),
        to_pq_pubkey
            .map(|s| vec![s.to_string()])
            .unwrap_or_default()
            .as_slice(),
    )?
    .pop()
    .expect("one recipient in, one out");
    let new_envelope = rewrap_dek_to(keystore, &label, &envelope, &recipient)?;
    let json = serde_json::to_vec_pretty(&new_envelope)
        .map_err(|e| CliError::generic(format!("serializing wrap: {e}")))?;
    std::fs::write(wrap_out, json)
        .map_err(|e| CliError::output_write(format!("writing {}: {e}", wrap_out.display())))
}

#[allow(clippy::too_many_arguments)]
pub fn encrypt_name(
    keystore: &dyn Keystore,
    metadata_key_wrap: &str,
    root_folder_id: &str,
    target_id: &str,
    name: &str,
    key: Option<&str>,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    if name.len() > 255 {
        return Err(CliError::name_too_long("name exceeds 255 bytes"));
    }
    let root = parse_uuid16(root_folder_id)?;
    let target = parse_uuid16(target_id)?;
    let metadata_key = unwrap_metadata_key(keystore, metadata_key_wrap, &root, key, config)?;
    let envelope = signet_crypto::encname::encrypt_name(&metadata_key, &root, &target, name)
        .map_err(|_| CliError::encryption_failed("name encryption failed"))?;
    out.print_json(&envelope)
}

#[allow(clippy::too_many_arguments)]
pub fn decrypt_name(
    keystore: &dyn Keystore,
    metadata_key_wrap: &str,
    root_folder_id: &str,
    target_id: &str,
    in_path: &str,
    key: Option<&str>,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    let root = parse_uuid16(root_folder_id)?;
    let target = parse_uuid16(target_id)?;
    let metadata_key = unwrap_metadata_key(keystore, metadata_key_wrap, &root, key, config)?;
    let envelope: NameEnvelope = read_json_arg(in_path, "name envelope")?;
    let name = signet_crypto::encname::decrypt_name(&metadata_key, &root, &target, &envelope)?;
    out.write_str(&name)
}

/// Unwrap a folder's metadata key from its wrap envelope (addressed to my KEM key,
/// bound to `root` via P-015). Shared by encrypt-name / decrypt-name (envelope read
/// from `--metadata-key-wrap`).
fn unwrap_metadata_key(
    keystore: &dyn Keystore,
    metadata_key_wrap: &str,
    root: &[u8; 16],
    key: Option<&str>,
    config: &Config,
) -> Result<Zeroizing<[u8; 32]>> {
    let label = resolve_label(key, Purpose::Kem, config)?;
    let value: Value = read_json_arg(metadata_key_wrap, "metadata-key wrap envelope")?;
    unwrap_metadata_key_envelope(keystore, &value, root, &label)
}

/// Unwrap a metadata key from a wrap-envelope JSON value addressed to
/// `kem_label` (P-015 binds it to `root`) — classical or hybrid, dispatched on
/// `alg` alone (§5.2). The core shared by the `--metadata-key-wrap` commands,
/// `upload` (which fetches the envelope over HTTP), and the path resolver.
pub(crate) fn unwrap_metadata_key_envelope(
    keystore: &dyn Keystore,
    value: &Value,
    root: &[u8; 16],
    kem_label: &KeyLabel,
) -> Result<Zeroizing<[u8; 32]>> {
    match wrap_alg_of(value)? {
        WrapAlg::Classical => {
            let envelope: WrapEnvelope = serde_json::from_value(value.clone())
                .map_err(|_| CliError::invalid_data("metadata-key wrap envelope"))?;
            let epk = envelope
                .ephemeral_pubkey_x963()
                .map_err(|_| CliError::invalid_data("metadata-key wrap epk"))?;
            let z = Zeroizing::new(keystore.ecdh(kem_label, &epk)?);
            Ok(Zeroizing::new(
                signet_crypto::wrap::unwrap_metadata_key_with_shared_secret(&z, &envelope, root)?,
            ))
        }
        WrapAlg::Hybrid => {
            let envelope: HybridWrapEnvelope = serde_json::from_value(value.clone())
                .map_err(|_| CliError::invalid_data("hybrid metadata-key wrap envelope"))?;
            hybrid::unwrap_key_hybrid(
                keystore,
                kem_label,
                &kem_pq_sibling(kem_label)?,
                &envelope,
                root,
            )
        }
    }
}

// ── Utilities ───────────────────────────────────────────────────────────────

pub fn rand(format: &str, n: usize, out: &OutputMode) -> Result<()> {
    if n > 1_048_576 {
        return Err(CliError::invalid_args("rand max is 1 MiB (1048576 bytes)"));
    }
    let mut bytes = vec![0u8; n];
    OsRng.fill_bytes(&mut bytes);
    match format {
        "hex" => out.write_str(&hex::encode(&bytes)),
        "base64url" => out.write_str(&URL_SAFE_NO_PAD.encode(&bytes)),
        "bytes" => out.write_bytes(&bytes),
        other => Err(CliError::invalid_args(format!(
            "unknown rand format '{other}'"
        ))),
    }
}

pub fn base64url_encode(in_path: Option<&Path>, out: &OutputMode) -> Result<()> {
    let bytes = read_input(in_path)?;
    out.write_str(&URL_SAFE_NO_PAD.encode(&bytes))
}

pub fn base64url_decode(in_path: Option<&Path>, out: &OutputMode) -> Result<()> {
    let raw = read_input(in_path)?;
    let decoded = URL_SAFE_NO_PAD
        .decode(String::from_utf8_lossy(&raw).trim())
        .map_err(|_| CliError::invalid_data("invalid base64url-no-pad input"))?;
    out.write_bytes(&decoded)
}

pub fn version(json: bool, out: &OutputMode) -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    if json {
        out.print_json(&serde_json::json!({ "version": version, "platform": platform }))
    } else {
        println!("signet {version} ({platform})");
        Ok(())
    }
}

// ── Server-bound commands (verification + sync) ─────────────────────────────

/// Decode a 32-byte value from a lowercase-hex JSON string field.
fn hex32(value: &Value, what: &str) -> Result<[u8; 32]> {
    let s = value
        .as_str()
        .ok_or_else(|| CliError::invalid_data(format!("missing/invalid {what}")))?;
    hex::decode(s)
        .map_err(|_| CliError::invalid_data(format!("{what} is not hex")))?
        .as_slice()
        .try_into()
        .map_err(|_| CliError::invalid_data(format!("{what} is not 32 bytes")))
}

/// Fetch the server's signing public key (X9.63) for `server_key_id` from
/// `/v1/server-info` (current or retired keys).
fn fetch_server_pubkey(server_url: &str, server_key_id: &str) -> Result<Vec<u8>> {
    let info = http::get_json(&format!("{server_url}/v1/server-info"), &[])?;
    for field in ["current_signing_keys", "retired_signing_keys"] {
        let Some(keys) = info.get(field).and_then(|v| v.as_array()) else {
            continue;
        };
        for key in keys {
            if key.get("key_id").and_then(|v| v.as_str()) == Some(server_key_id) {
                let pk_b64 = key
                    .get("public_key")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| CliError::invalid_data("server-info key missing public_key"))?;
                return URL_SAFE_NO_PAD
                    .decode(pk_b64)
                    .map_err(|_| CliError::invalid_data("server-info public_key base64url"));
            }
        }
    }
    Err(CliError::transparency_violation(format!(
        "server-info has no signing key with id {server_key_id}"
    )))
}

/// The server's ACTIVE ML-DSA-87 dual-sign key from `/v1/server-info`
/// (`purpose = attestation_verification_pq`), or `None` when the deployment has
/// not published one (pre-7c). The MF-2 trigger: once this key is published, an
/// ES256-only §9 response is rejected (N9).
fn fetch_server_pq_key(server_url: &str) -> Result<Option<Vec<u8>>> {
    let info = http::get_json(&format!("{server_url}/v1/server-info"), &[])?;
    let Some(keys) = info.get("current_signing_keys").and_then(|v| v.as_array()) else {
        return Ok(None);
    };
    for key in keys {
        if key.get("purpose").and_then(|v| v.as_str()) == Some("attestation_verification_pq") {
            let pk_b64 = key
                .get("public_key")
                .and_then(|v| v.as_str())
                .ok_or_else(|| CliError::invalid_data("server-info key missing public_key"))?;
            let vk = URL_SAFE_NO_PAD
                .decode(pk_b64)
                .map_err(|_| CliError::invalid_data("server-info public_key base64url"))?;
            return Ok(Some(vk));
        }
    }
    Ok(None)
}

/// Verify an ML-DSA-87 signature (raw FIPS 204 vk; the FIPS 204 ctx parameter —
/// PQR Spec §8.7). The RustCrypto lineage, same as the enrollment PoP verifier.
pub(crate) fn verify_mldsa87(vk_bytes: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> Result<()> {
    use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa87, Signature, VerifyingKey};
    let vk_arr = EncodedVerifyingKey::<MlDsa87>::try_from(vk_bytes)
        .map_err(|_| CliError::invalid_data("server ML-DSA-87 key size"))?;
    let vk = VerifyingKey::<MlDsa87>::decode(&vk_arr);
    let sig_arr = EncodedSignature::<MlDsa87>::try_from(sig)
        .map_err(|_| CliError::signature_invalid("ML-DSA-87 signature size"))?;
    let sig = Signature::<MlDsa87>::decode(&sig_arr)
        .ok_or_else(|| CliError::signature_invalid("malformed ML-DSA-87 signature"))?;
    if !vk.verify_with_context(msg, ctx, &sig) {
        return Err(CliError::signature_invalid(
            "ML-DSA-87 signature does not verify",
        ));
    }
    Ok(())
}

pub fn attestation_verify(
    attestation_id: Option<&str>,
    in_path: Option<&str>,
    server_url: &str,
    server_pubkey: Option<&str>,
    server_pq_pubkey: Option<&str>,
    out: &OutputMode,
) -> Result<()> {
    let response: Value = match (attestation_id, in_path) {
        (Some(id), None) => http::get_json(
            &format!("{server_url}/v1/attestations/{id}/verification"),
            &[],
        )?,
        (None, Some(path)) => read_json_arg(path, "verification response")?,
        _ => {
            return Err(CliError::invalid_args(
                "specify exactly one of --attestation-id or --in",
            ));
        }
    };

    let server_key_id = response
        .get("server_key_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CliError::invalid_data("response missing server_key_id"))?
        .to_string();
    let signed_at = response
        .get("signed_at")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| CliError::invalid_data("response missing signed_at"))?;
    let attestation = response
        .get("attestation")
        .ok_or_else(|| CliError::invalid_data("response missing attestation"))?;
    let signature = URL_SAFE_NO_PAD
        .decode(
            response
                .get("server_signature")
                .and_then(|v| v.as_str())
                .ok_or_else(|| CliError::invalid_data("response missing server_signature"))?,
        )
        .map_err(|_| CliError::invalid_data("server_signature base64url"))?;
    let signing_input =
        signet_crypto::attest::verification_signing_input(attestation, &server_key_id, signed_at)
            .map_err(|_| CliError::invalid_data("verification canonical bytes"))?;

    // Verify the server signature; on failure re-fetch the server key once (the
    // S005-001 rotation-race auto-recovery) when we resolved it ourselves.
    let mut server_pub = match server_pubkey {
        Some(pk) => parse_pubkey_arg(pk)?,
        None => fetch_server_pubkey(server_url, &server_key_id)?,
    };
    if signet_crypto::ecdsa::verify_es256(&server_pub, &signing_input, &signature).is_err() {
        if server_pubkey.is_none() {
            server_pub = fetch_server_pubkey(server_url, &server_key_id)?;
        }
        signet_crypto::ecdsa::verify_es256(&server_pub, &signing_input, &signature)
            .map_err(|_| CliError::signature_invalid("server signature does not verify"))?;
    }

    // MF-2 / N9 (item 7c, PQR Spec §8.6): resolve the server's ML-DSA-87 vk —
    // the operator's --server-pq-pubkey pin, or (when we resolve keys ourselves)
    // the response's server_pq_key_id / the active-by-purpose probe. Once a PQ
    // vk is known to exist, an ES256-only response is REJECTED — an attacker
    // who can forge ES256 must not win by omitting the PQ half.
    let server_pq_vk: Option<Vec<u8>> = match server_pq_pubkey {
        Some(pk) => Some(
            URL_SAFE_NO_PAD
                .decode(pk)
                .map_err(|_| CliError::invalid_args("--server-pq-pubkey base64url"))?,
        ),
        None if server_pubkey.is_none() => {
            match response.get("server_pq_key_id").and_then(|v| v.as_str()) {
                // The response names its PQ key: resolve THAT key (rotation-exact).
                Some(pq_kid) => Some(fetch_server_pubkey(server_url, pq_kid)?),
                // No PQ fields in the response: probe by purpose — if the server
                // HAS an active PQ key, this response is a downgrade (N9).
                None => fetch_server_pq_key(server_url)?,
            }
        }
        // Offline mode with only a classical pin: the operator's trust anchor
        // is explicit; PQ enforcement requires --server-pq-pubkey.
        None => None,
    };
    enforce_response_dual_signature(&response, &signing_input, server_pq_vk.as_deref())?;

    // §10a: verify the inline transparency-log receipts (defense-in-depth). Each
    // receipt is independently server-signed — the §9 signature does NOT cover them
    // (attestation.rs). The receipt omits the public_key + prev_entry_hash, so the
    // entry_hash isn't client-recomputable; the binding we verify is the receipt's
    // own server signature + its public_key_fingerprint matching the attested key +
    // the key_purpose. The MMD→inclusion-proof→published-root escalation is D1-gated
    // (transparency-verify covers log inclusion against a published root).
    let transparency =
        verify_inline_receipts(&response, attestation, &server_pub, server_pq_vk.as_deref())?;

    let status = attestation
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    out.print_json(&serde_json::json!({
        "valid": status == "active",
        "subject_account_id": attestation.get("subject_account_id"),
        "subject_handle": attestation.get("subject_handle"),
        "subject_signing_pubkey_fingerprint": attestation.get("subject_signing_pubkey_fingerprint"),
        "subject_kem_pubkey_fingerprint": attestation.get("subject_kem_pubkey_fingerprint"),
        "expires_at": attestation.get("expires_at"),
        "status": status,
        "prsn_sharing_capability": attestation.get("prsn_sharing_capability"),
        "transparency": transparency,
    }))?;

    // Signature + inline receipts verified; the status drives the exit code (CLI Spec v08).
    match status {
        "active" => Ok(()),
        "revoked" => Err(CliError::attestation_revoked("attestation is revoked")),
        "expired" => Err(CliError::attestation_expired("attestation is expired")),
        other => Err(CliError::invalid_data(format!("unknown status '{other}'"))),
    }
}

/// Verify the inline §10a transparency-log receipts (if present) and return a
/// status string for the output. Errors (exit 60) on a present-but-invalid
/// receipt. Receipts are defense-in-depth: each is independently server-signed,
/// and the §9 response signature does not cover them — so absence degrades
/// gracefully ("absent") while a present-but-bad receipt fails closed.
/// bug127 (audit F-009) — **PQR §9.4 N9: the response-path signature-downgrade defence.**
///
/// When the server has a published ML-DSA-87 key (so the caller holds one, via
/// `--server-pq-pubkey`), an ES256-only `§9` response MUST be refused: accepting it would let a
/// downgrading middlebox strip the PQ half and be believed.
///
/// ⚠ **Extracted from `attestation_verify` to make it TESTABLE, which is the finding.** The
/// defence is mandatory and was implemented correctly — but it lives behind an
/// `Option`-gated branch that every existing test left unset, so **no test ever executed it**
/// (§8 boundary type 2: a seam between *configuration modes* rather than between layers). A
/// mandatory defence that no test can reach is indistinguishable from an absent one, which is
/// this audit round's recurring shape.
///
/// `None` means the caller has no published PQ key to check against — enforcement is off **by
/// design**, not by accident, and is documented at the call site.
pub(crate) fn enforce_response_dual_signature(
    response: &Value,
    signing_input: &[u8],
    server_pq_vk: Option<&[u8]>,
) -> Result<()> {
    let Some(pq_vk) = server_pq_vk else {
        return Ok(());
    };
    let pq_sig_b64 = response
        .get("server_signature_mldsa87")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CliError::signature_invalid(
                "ES256-only response rejected: the server has a published ML-DSA-87 \
                 key, so the §9 response MUST be dual-signed (MF-2/N9)",
            )
        })?;
    let pq_sig = URL_SAFE_NO_PAD
        .decode(pq_sig_b64)
        .map_err(|_| CliError::invalid_data("server_signature_mldsa87 base64url"))?;
    verify_mldsa87(
        pq_vk,
        signing_input,
        signet_crypto::attest::SERVER_VERIFY_MLDSA_CTX,
        &pq_sig,
    )?;
    Ok(())
}

pub(crate) fn verify_inline_receipts(
    response: &Value,
    attestation: &Value,
    server_pub: &[u8],
    server_pq_vk: Option<&[u8]>,
) -> Result<&'static str> {
    let receipts = [
        (
            "subject_signing_pubkey_receipt",
            "subject_signing_pubkey_fingerprint",
            "signing",
        ),
        (
            "subject_kem_pubkey_receipt",
            "subject_kem_pubkey_fingerprint",
            "kem",
        ),
        // The hybrid four-key identity's PQ pair (items 7a/7c).
        (
            "subject_signing_pq_pubkey_receipt",
            "subject_signing_pq_pubkey_fingerprint",
            "signing_pq",
        ),
        (
            "subject_kem_pq_pubkey_receipt",
            "subject_kem_pq_pubkey_fingerprint",
            "kem_pq",
        ),
    ];
    // A hybrid attestation carries four logged keys; a classical one two.
    let expected = if attestation
        .get("subject_signing_pq_pubkey_fingerprint")
        .is_some()
    {
        4
    } else {
        2
    };
    let mut present = 0;
    for (receipt_field, fp_field, purpose) in receipts {
        let Some(receipt) = response.get(receipt_field) else {
            continue;
        };
        present += 1;
        let asserted_fp = attestation
            .get(fp_field)
            .and_then(|v| v.as_str())
            .ok_or_else(|| CliError::invalid_data(format!("attestation missing {fp_field}")))?;
        // No account binding here: the attestation itself (server-signed)
        // binds these keys to `subject_account_id`.
        verify_one_receipt(
            receipt,
            asserted_fp,
            None,
            purpose,
            server_pub,
            server_pq_vk,
        )?;
    }
    Ok(if present == 0 {
        "absent"
    } else if present == expected {
        "verified"
    } else {
        "partial"
    })
}

/// Verify one §10a receipt: its `public_key_fingerprint` + `key_purpose` bind it
/// to the asserted key, and its own `server_signature` verifies against the server
/// key. The receipt omits the public_key + prev_entry_hash, so the `entry_hash`
/// itself is server-vouched (by the signature), not client-recomputable. (The
/// receipt's `server_key_id` is assumed equal to the §9 response's; a mid-rotation
/// receipt signed by a different key fails the signature check here.)
///
/// `expected_account_id`: when the receipt is the SOLE record binding the key to
/// an identity (the F-DOWNGRADE(b) human-recipient path — no attestation), the
/// receipt's `account_id` MUST name that identity; a verifying receipt for a key
/// logged under a different account is a substitution, not this recipient's key.
/// `None` when an attestation already carries the account binding.
pub(crate) fn verify_one_receipt(
    receipt: &Value,
    asserted_fp: &str,
    expected_account_id: Option<&str>,
    expected_purpose: &str,
    server_pub: &[u8],
    server_pq_vk: Option<&[u8]>,
) -> Result<()> {
    let receipt_fp = receipt
        .get("public_key_fingerprint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            CliError::transparency_violation("receipt missing public_key_fingerprint")
        })?;
    if receipt_fp != asserted_fp {
        return Err(CliError::transparency_violation(format!(
            "{expected_purpose} receipt fingerprint does not match the asserted public key"
        )));
    }
    if let Some(expected_account) = expected_account_id {
        let receipt_account = receipt
            .get("account_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CliError::transparency_violation("receipt missing account_id"))?;
        if !receipt_account.eq_ignore_ascii_case(expected_account) {
            return Err(CliError::transparency_violation(format!(
                "{expected_purpose} receipt binds the key to a DIFFERENT account. A logged key that is not this recipient's is a substitution"
            )));
        }
    }
    if receipt.get("key_purpose").and_then(|v| v.as_str()) != Some(expected_purpose) {
        return Err(CliError::transparency_violation(format!(
            "{expected_purpose} receipt has an unexpected key_purpose"
        )));
    }
    let sig = URL_SAFE_NO_PAD
        .decode(
            receipt
                .get("server_signature")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    CliError::transparency_violation("receipt missing server_signature")
                })?,
        )
        .map_err(|_| CliError::transparency_violation("receipt server_signature base64url"))?;
    // The signing input = the receipt with EVERY server_signature* field
    // removed (§8.7 — both halves sign the identical bytes; on pre-7c receipts
    // the PQ removal is a no-op, reproducing their original signed shape).
    let mut unsigned = receipt.clone();
    let obj = unsigned
        .as_object_mut()
        .ok_or_else(|| CliError::invalid_data("receipt is not a JSON object"))?;
    obj.remove("server_signature");
    let pq_sig_b64 = obj
        .remove("server_signature_mldsa87")
        .and_then(|v| v.as_str().map(String::from));
    let signing_input = signet_crypto::translog::receipt_signing_input(&unsigned)
        .map_err(|_| CliError::invalid_data("receipt canonical bytes"))?;
    signet_crypto::ecdsa::verify_es256(server_pub, &signing_input, &sig).map_err(|_| {
        CliError::transparency_violation(format!(
            "{expected_purpose} receipt signature does not verify"
        ))
    })?;

    // A receipt whose SIGNED object names a PQ key MUST carry a verifying
    // ML-DSA co-signature — the key id sits inside the ES256-signed bytes, so
    // stripping it breaks the classical verify above; keeping it while
    // dropping the PQ signature fails here (the MF-2 receipt-layer rule).
    // Pre-7c receipts name no PQ key and verify classically — their ES256
    // signature proves they were issued in that shape.
    if unsigned.get("server_pq_key_id").is_some() {
        let pq_sig_b64 = pq_sig_b64.ok_or_else(|| {
            CliError::transparency_violation(format!(
                "{expected_purpose} receipt names a server PQ key but carries no \
                 ML-DSA-87 co-signature (MF-2)"
            ))
        })?;
        let pq_vk = server_pq_vk.ok_or_else(|| {
            CliError::transparency_violation(
                "a dual-signed receipt cannot be verified without the server's \
                 ML-DSA-87 key (use --server-pq-pubkey offline)",
            )
        })?;
        let pq_sig = URL_SAFE_NO_PAD.decode(&pq_sig_b64).map_err(|_| {
            CliError::transparency_violation("receipt server_signature_mldsa87 base64url")
        })?;
        verify_mldsa87(
            pq_vk,
            &signing_input,
            signet_crypto::translog::RECEIPT_MLDSA_CTX,
            &pq_sig,
        )
        .map_err(|_| {
            CliError::transparency_violation(format!(
                "{expected_purpose} receipt ML-DSA-87 co-signature does not verify"
            ))
        })?;
    }
    Ok(())
}

pub fn transparency_verify(
    inclusion_proof_file: Option<&str>,
    fingerprint: Option<&str>,
    purpose: Option<&str>,
    published_root: Option<&str>,
    published_size: Option<u64>,
    server_url: &str,
    out: &OutputMode,
) -> Result<()> {
    // clap pairs these (`requires`), but this fn is callable directly.
    if published_root.is_some() != published_size.is_some() {
        return Err(CliError::invalid_args(
            "--published-root and --published-size must be given together: the roots.jsonl line carries both",
        ));
    }
    let proof_doc: Value = match (inclusion_proof_file, fingerprint) {
        (Some(file), None) => read_json_arg(file, "inclusion proof")?,
        (None, Some(fp)) => {
            let purpose = purpose.ok_or_else(|| {
                CliError::invalid_args("--purpose is required with --fingerprint")
            })?;
            http::get_json(
                &format!(
                    "{server_url}/v1/transparency/log/inclusion-proof?fingerprint={fp}&purpose={purpose}"
                ),
                &[],
            )?
        }
        _ => {
            return Err(CliError::invalid_args(
                "specify --inclusion-proof <file> or --fingerprint --purpose",
            ));
        }
    };

    let entry_hash = hex32(&proof_doc["entry_hash"], "entry_hash")?;
    let entry_id = proof_doc["entry_id"]
        .as_u64()
        .ok_or_else(|| CliError::invalid_data("proof missing entry_id"))?;
    let tree_size = proof_doc["log_size_at_proof"]
        .as_u64()
        .ok_or_else(|| CliError::invalid_data("proof missing log_size_at_proof"))?;
    let proof_root = hex32(&proof_doc["merkle_root_at_proof"], "merkle_root_at_proof")?;
    let path: Vec<[u8; 32]> = proof_doc["inclusion_proof"]
        .as_array()
        .ok_or_else(|| CliError::invalid_data("proof missing inclusion_proof array"))?
        .iter()
        .map(|v| hex32(v, "inclusion_proof element"))
        .collect::<Result<_>>()?;

    let consistent = signet_crypto::merkle::verify_inclusion(
        &entry_hash,
        (entry_id - 1) as usize,
        tree_size as usize,
        &path,
        &proof_root,
    );

    // The published anchor to check against: --published-root/--published-size
    // (a roots.jsonl line), else the server's last publicly-committed root+size
    // (null until D1's GitHub commit).
    let committed: Option<([u8; 32], u64)> = match (published_root, published_size) {
        (Some(hex), Some(size)) => Some((
            hex::decode(hex.trim())
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                .ok_or_else(|| CliError::invalid_args("--published-root must be 32-byte hex"))?,
            size,
        )),
        _ => fetch_committed_root(server_url)?,
    };

    // bug149: the published root is a SNAPSHOT at its own log size. Raw equality
    // against the proof's (current-size) root is only meaningful at the same size;
    // between publishes the correct question is whether the current log EXTENDS the
    // published one (RFC 6962 consistency). Judged only if the inclusion proof
    // itself verified — a broken proof short-circuits below.
    let verdict = if consistent {
        Some(judge_published_root(
            &proof_root,
            tree_size,
            committed,
            |from, to| fetch_consistency_nodes(server_url, from, to),
        )?)
    } else {
        None
    };

    out.print_json(&serde_json::json!({
        "valid": consistent,
        "fingerprint": proof_doc.get("public_key_fingerprint"),
        "purpose": proof_doc.get("key_purpose"),
        "entry_id": entry_id,
        "log_size_at_proof": tree_size,
        "merkle_root_at_proof": hex::encode(proof_root),
        "merkle_root_publicly_committed": committed.map(|(root, _)| hex::encode(root)),
        "published_log_size": committed.map(|(_, size)| size),
        // Raw same-size equality, kept for compatibility; null when the sizes
        // differ (equality is not the question there — see published_root_status).
        "match": match verdict {
            Some(PublishedRootVerdict::MatchAtSameSize) => Some(true),
            Some(PublishedRootVerdict::RootMismatchAtSameSize) => Some(false),
            _ => None,
        },
        "published_root_status": verdict.as_ref().map(PublishedRootVerdict::as_str),
    }))?;

    if !consistent {
        return Err(CliError::signature_invalid(
            "inclusion proof does not verify against its root",
        ));
    }
    match verdict.expect("verdict is Some when consistent") {
        // No public root to compare (D1 not live): informational, exit 0.
        PublishedRootVerdict::NoPublishedRoot => Ok(()),
        PublishedRootVerdict::MatchAtSameSize => Ok(()),
        // The log grew since the last publish and provably extends it — the
        // ordinary between-publishes state, not an alarm (bug149).
        PublishedRootVerdict::ConsistentAdvance { .. } => Ok(()),
        PublishedRootVerdict::RootMismatchAtSameSize => Err(CliError::transparency_violation(
            "the log presents a DIFFERENT root for the publicly-committed size (fork or rewrite): TRANSPARENCY VIOLATION",
        )),
        PublishedRootVerdict::LogShrank { published, proof } => {
            Err(CliError::transparency_violation(format!(
                "the log ({proof} entries) is SMALLER than the publicly-committed \
                 size ({published}): entries have been removed. TRANSPARENCY VIOLATION",
            )))
        }
        PublishedRootVerdict::NotAnExtension { from, to } => {
            Err(CliError::transparency_violation(format!(
                "the log's advance {from} → {to} does NOT extend the publicly-committed \
                 root: history rewritten. TRANSPARENCY VIOLATION",
            )))
        }
    }
}

/// The verdict on the published anchor vs the inclusion proof's root (bug149).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublishedRootVerdict {
    NoPublishedRoot,
    MatchAtSameSize,
    ConsistentAdvance { from: u64, to: u64 },
    RootMismatchAtSameSize,
    LogShrank { published: u64, proof: u64 },
    NotAnExtension { from: u64, to: u64 },
}

impl PublishedRootVerdict {
    fn as_str(&self) -> &'static str {
        match self {
            Self::NoPublishedRoot => "no_published_root",
            Self::MatchAtSameSize => "match",
            Self::ConsistentAdvance { .. } => "consistent_advance",
            Self::RootMismatchAtSameSize => "root_mismatch_at_same_size",
            Self::LogShrank { .. } => "log_shrank",
            Self::NotAnExtension { .. } => "not_an_extension",
        }
    }
}

/// Judge the published anchor against the proof root. Pure except for the injected
/// consistency-proof fetch (only called on genuine advance), so the whole decision
/// table is unit-testable without HTTP — the bug127 lesson: a defence no test can
/// reach is indistinguishable from an absent one.
///
/// ⚠ The proof nodes are the ONLY thing taken from the fetch; both roots are bound
/// locally (`verify_consistency` compares against `first_hash`/`second_hash` and
/// requires the final subtree cursor to close), so a server echoing plausible roots
/// alongside a proof for some other pair gains nothing.
fn judge_published_root(
    proof_root: &[u8; 32],
    proof_size: u64,
    committed: Option<([u8; 32], u64)>,
    fetch_consistency_nodes: impl FnOnce(u64, u64) -> Result<Vec<[u8; 32]>>,
) -> Result<PublishedRootVerdict> {
    let Some((published_root, published_size)) = committed else {
        return Ok(PublishedRootVerdict::NoPublishedRoot);
    };
    use std::cmp::Ordering;
    match published_size.cmp(&proof_size) {
        Ordering::Equal => Ok(if published_root == *proof_root {
            PublishedRootVerdict::MatchAtSameSize
        } else {
            PublishedRootVerdict::RootMismatchAtSameSize
        }),
        Ordering::Greater => Ok(PublishedRootVerdict::LogShrank {
            published: published_size,
            proof: proof_size,
        }),
        Ordering::Less => {
            let nodes = fetch_consistency_nodes(published_size, proof_size)?;
            let extends = signet_crypto::merkle::verify_consistency(
                published_size as usize,
                proof_size as usize,
                &published_root,
                proof_root,
                &nodes,
            );
            Ok(if extends {
                PublishedRootVerdict::ConsistentAdvance {
                    from: published_size,
                    to: proof_size,
                }
            } else {
                PublishedRootVerdict::NotAnExtension {
                    from: published_size,
                    to: proof_size,
                }
            })
        }
    }
}

/// Fetch the server's RFC 6962 consistency-proof nodes for `from → to`.
/// ⚠ Query params are `from`/`to` (`ConsistencyQuery`, server transparency.rs) —
/// wrong names 400. Only the nodes are used; the response's echoed roots are not
/// trusted (see `judge_published_root`).
fn fetch_consistency_nodes(server_url: &str, from: u64, to: u64) -> Result<Vec<[u8; 32]>> {
    let doc = http::get_json(
        &format!("{server_url}/v1/transparency/log/consistency-proof?from={from}&to={to}"),
        &[],
    )?;
    doc["consistency_proof"]
        .as_array()
        .ok_or_else(|| CliError::invalid_data("consistency-proof response missing proof array"))?
        .iter()
        .map(|v| hex32(v, "consistency_proof element"))
        .collect()
}

/// The server's most-recent publicly-committed Merkle root AND its log size
/// (null until D1). The size is load-bearing (bug149): without it the root is a
/// snapshot with no way to ask the extension question.
fn fetch_committed_root(server_url: &str) -> Result<Option<([u8; 32], u64)>> {
    let root = http::get_json(&format!("{server_url}/v1/transparency/log/root"), &[])?;
    match root.get("last_publicly_committed") {
        None | Some(Value::Null) => Ok(None),
        Some(committed) => {
            let size = committed["log_size"]
                .as_u64()
                .ok_or_else(|| CliError::invalid_data("committed root missing log_size"))?;
            Ok(Some((
                hex32(&committed["merkle_root"], "committed merkle_root")?,
                size,
            )))
        }
    }
}

pub fn audit(
    keystore: &dyn Keystore,
    key: Option<&str>,
    since: Option<&str>,
    limit: u32,
    server_url: &str,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    let label = resolve_label(key, Purpose::Signing, config)?;
    let mut path = format!("/v1/me/audit?limit={limit}");
    if let Some(s) = since {
        path.push_str(&format!("&since={s}"));
    }
    let body = http::get_text_signed(keystore, &label, server_url, &path)?;
    out.write_str(&body)
}

pub fn update(server_url: &str, json: bool, out: &OutputMode) -> Result<()> {
    let latest = http::get_text(&format!("{server_url}/cli/latest-version"), &[])?
        .trim()
        .to_string();
    let current = env!("CARGO_PKG_VERSION").to_string();
    let newer = is_newer(&latest, &current);
    // signet is installed — and updated — by a human, never by the agent itself
    // (required human install; no `curl | sh` self-update path). The human's path
    // is the assisted update: the menu-bar item shows ◉ ↑ + an "Update Signet…"
    // action when a newer release is published (bug039); re-running the installer
    // by hand still works and replaces the install in place.
    let how_to_update = "Ask your guardian to update Signet from the menu-bar item \
                         (◉ ↑ → \"Update Signet…\"). Re-running the installer also works.";
    if json {
        out.print_json(&serde_json::json!({
            "current_version": current,
            "latest_version": latest,
            "newer_available": newer,
            "how_to_update": how_to_update,
        }))?;
    } else if newer {
        eprintln!(
            "A newer version of signet ({latest}) is available. Current: {current}.\n\
             {how_to_update}"
        );
    }
    // "newer available" is informational (exit 8), not a failure.
    if newer {
        Err(CliError::new(
            8,
            "update_available",
            "a newer version is available",
        ))
    } else {
        Ok(())
    }
}

/// True if dotted-numeric `latest` is greater than `current` (best-effort).
/// `pub(crate)` so the menu-bar version line shares one currency comparison.
pub(crate) fn is_newer(latest: &str, current: &str) -> bool {
    fn parts(v: &str) -> Vec<u64> {
        v.trim()
            .trim_start_matches('v')
            .split('.')
            .map(|p| p.trim().parse().unwrap_or(0))
            .collect()
    }
    parts(latest) > parts(current)
}

// ── Account reads (whoami, quota) ────────────────────────────────────────────

/// `signet whoami` — the authenticated account's identity. A signed `GET /v1/me`,
/// reduced to the identity-relevant fields (the full `/v1/me` also carries billing
/// and KEM-key material that other commands use). Identity is the shared
/// human↔PRSN vocabulary, so this is the PRSN's "who am I on this Drive" answer.
pub fn whoami(
    keystore: &dyn Keystore,
    key: Option<&str>,
    server_url: &str,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    let label = resolve_label(key, Purpose::Signing, config)?;
    let me = http::get_json_signed(keystore, &label, server_url, "/v1/me")?;
    out.print_json(&shape_whoami(&me))
}

/// Reduce a `/v1/me` response to the identity view `whoami` prints: account id +
/// type + handle always; `prsn_sharing_capability` and the Guardian's handle only
/// when present (a human has neither). Pure (no I/O) — unit-tested without a server.
fn shape_whoami(me: &Value) -> Value {
    let mut obj = serde_json::Map::new();
    for field in ["account_id", "account_type", "handle"] {
        if let Some(v) = me.get(field) {
            obj.insert(field.to_string(), v.clone());
        }
    }
    if let Some(cap) = me.get("prsn_sharing_capability").filter(|v| !v.is_null()) {
        obj.insert("prsn_sharing_capability".to_string(), cap.clone());
    }
    // The Guardian is flattened to just the handle — the part a PRSN reports back
    // ("my Guardian is chris"), not the key material.
    if let Some(handle) = me
        .get("guardian")
        .and_then(|g| g.get("handle"))
        .filter(|v| !v.is_null())
    {
        obj.insert("guardian".to_string(), handle.clone());
    }
    // §1-62 PR-D: the PRSN's own Signet Drive access state (status / overdue /
    // reconfirm cadence) — whoami is the packet's named "where am I" command,
    // so the answer must actually carry the Drive-access half. PRSN-only
    // (absent for humans, whose access is the web session).
    if let Some(da) = me.get("drive_access").filter(|v| !v.is_null()) {
        obj.insert("drive_access".to_string(), da.clone());
    }
    Value::Object(obj)
}

/// `signet quota` — storage usage + limit. A signed `GET /v1/me/quota` (the
/// Guardian-pooled, group-scoped figures), with a derived `bytes_available` for
/// convenience (the 1-Pager lists quota visibility as "current usage, available").
pub fn quota(
    keystore: &dyn Keystore,
    key: Option<&str>,
    server_url: &str,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    let label = resolve_label(key, Purpose::Signing, config)?;
    let q = http::get_json_signed(keystore, &label, server_url, "/v1/me/quota")?;
    out.print_json(&shape_quota(&q)?)
}

/// Add a derived `bytes_available` (quota − used, floored at 0 for the over-quota
/// case after a downgrade) to the `{bytes_used, bytes_quota}` the server returns.
/// Pure; unit-tested.
fn shape_quota(q: &Value) -> Result<Value> {
    let bytes_used = q
        .get("bytes_used")
        .and_then(Value::as_i64)
        .ok_or_else(|| CliError::invalid_data("quota response missing bytes_used"))?;
    let bytes_quota = q
        .get("bytes_quota")
        .and_then(Value::as_i64)
        .ok_or_else(|| CliError::invalid_data("quota response missing bytes_quota"))?;
    Ok(serde_json::json!({
        "bytes_used": bytes_used,
        "bytes_quota": bytes_quota,
        "bytes_available": (bytes_quota - bytes_used).max(0),
    }))
}

// ── Drive management: folder / file list (name-addressed) ────────────────────

/// Parse a `--…-id` argument into a [`Uuid`], with a flag-named error.
fn parse_uuid_arg(value: &str, flag: &str) -> Result<Uuid> {
    Uuid::parse_str(value)
        .map_err(|_| CliError::invalid_args(format!("{flag} is not a valid UUID")))
}

/// `signet folder list [<path>]` — list the folders under `<path>` (top-level when
/// omitted), decrypting each name. `--parent-id` is the id-based precision fallback
/// for `<path>`. Tabular by default; `--json` for machine output (mirrors `keys list`).
#[allow(clippy::too_many_arguments)]
pub fn folder_list(
    keystore: &dyn Keystore,
    path: Option<&str>,
    parent_id: Option<&str>,
    json: bool,
    signing_key: Option<&str>,
    kem_key: Option<&str>,
    server_url: &str,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    let signing = resolve_label(signing_key, Purpose::Signing, config)?;
    let kem = resolve_label(kem_key, Purpose::Kem, config)?;
    let mut resolver = Resolver::new(keystore, &signing, &kem, server_url);

    let parent = match (path, parent_id) {
        (Some(_), Some(_)) => {
            return Err(CliError::invalid_args(
                "give a <path> or --parent-id, not both",
            ));
        }
        (Some(p), None) => Some(resolver.resolve_folder(p)?.folder_id),
        (None, Some(id)) => Some(parse_uuid_arg(id, "--parent-id")?),
        (None, None) => None,
    };

    let entries = resolver.list_folders(parent)?;
    if json {
        return out.print_json(&entries);
    }
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{:<28} {:<36} MODIFIED_AT", "NAME", "FOLDER_ID").map_err(write_err)?;
    for e in &entries {
        writeln!(
            stdout,
            "{:<28} {:<36} {}",
            // bug132(ii): the same marker the web renders, so the two surfaces describe an
            // undecodable name identically.
            e.name.as_deref().unwrap_or("(unreadable)"),
            e.folder_id,
            table_ts(e.modified_at)
        )
        .map_err(write_err)?;
    }
    Ok(())
}

/// `signet file list [<folder-path>]` (or `--folder-id <ID> [--root-folder-id <ID>]`)
/// — list the files in a folder, decrypting each name. A `FileView` carries no
/// `root_folder_id`, so the id form takes `--root-folder-id` (defaulting to the
/// folder itself, the top-level case); a `<folder-path>` supplies the root for free.
#[allow(clippy::too_many_arguments)]
pub fn file_list(
    keystore: &dyn Keystore,
    path: Option<&str>,
    folder_id: Option<&str>,
    root_folder_id: Option<&str>,
    json: bool,
    signing_key: Option<&str>,
    kem_key: Option<&str>,
    server_url: &str,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    let signing = resolve_label(signing_key, Purpose::Signing, config)?;
    let kem = resolve_label(kem_key, Purpose::Kem, config)?;
    let mut resolver = Resolver::new(keystore, &signing, &kem, server_url);

    let (folder, root) = match (path, folder_id) {
        (Some(_), Some(_)) => {
            return Err(CliError::invalid_args(
                "give a <folder-path> or --folder-id, not both",
            ));
        }
        (Some(p), None) => {
            let r = resolver.resolve_folder(p)?;
            (r.folder_id, r.root_folder_id)
        }
        (None, Some(id)) => {
            let folder = parse_uuid_arg(id, "--folder-id")?;
            let root = match root_folder_id {
                Some(r) => parse_uuid_arg(r, "--root-folder-id")?,
                None => folder,
            };
            (folder, root)
        }
        (None, None) => {
            return Err(CliError::invalid_args(
                "give a <folder-path> or --folder-id",
            ));
        }
    };

    let entries = resolver.list_files(folder, root)?;
    if json {
        return out.print_json(&entries);
    }
    let mut stdout = std::io::stdout().lock();
    writeln!(
        stdout,
        "{:<28} {:<36} {:>14}  MODIFIED_AT",
        "NAME", "FILE_ID", "SIZE"
    )
    .map_err(write_err)?;
    for e in &entries {
        writeln!(
            stdout,
            "{:<28} {:<36} {:>14}  {}",
            e.name.as_deref().unwrap_or("(unreadable)"),
            e.file_id,
            // bug083: the user's number is the PLAINTEXT size; the ciphertext
            // length is storage accounting, not "the file's size". Fall back to
            // size_bytes only when the server could not derive plaintext.
            e.plaintext_bytes.unwrap_or(e.size_bytes),
            table_ts(e.modified_at)
        )
        .map_err(write_err)?;
    }
    Ok(())
}

// ── Drive management: folder / share create ──────────────────────────────────

#[derive(Serialize)]
struct CreateFolderBody<'a> {
    folder_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_folder_id: Option<String>,
    encrypted_name: &'a NameEnvelope,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_metadata_key_wrap: Option<&'a Value>,
}

#[derive(Serialize)]
struct CreateShareFolderBody<'a> {
    folder_id: String,
    encrypted_name: &'a NameEnvelope,
    owner_metadata_key_wrap: &'a Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    guardian_metadata_key_wrap: Option<&'a Value>,
}

/// Decode + verify a KEM public key from a `{kem_pubkey, kem_pubkey_fingerprint}`
/// block — a `/v1/me` Guardian block or a `/v1/recipients/{handle}` response (the
/// same shape). The P-011 check — the key must match its stated fingerprint — runs
/// before any secret is wrapped to it; a mismatch (possible key substitution) is
/// exit 60. `who` names the party in the error text (e.g. "Guardian", "recipient").
fn verify_recipient_kem_pub(value: &Value, who: &str) -> Result<Vec<u8>> {
    let kem_b64 = value
        .get("kem_pubkey")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::invalid_data(format!("{who} has no KEM public key")))?;
    let stated_fp = value
        .get("kem_pubkey_fingerprint")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::invalid_data(format!("{who} KEM key has no fingerprint")))?;
    let pubkey = URL_SAFE_NO_PAD
        .decode(kem_b64)
        .map_err(|_| CliError::invalid_data(format!("{who} KEM pubkey is not base64url")))?;
    let computed = signet_crypto::pubkey::fingerprint(&pubkey).map_err(|_| {
        CliError::invalid_data(format!("{who} KEM pubkey is not a valid P-256 point"))
    })?;
    if computed != stated_fp {
        return Err(CliError::transparency_violation(format!(
            "{who} KEM-key fingerprint mismatch"
        )));
    }
    Ok(pubkey)
}

/// A recipient's verified wrap target (PQR §9.2 presence-gating): the P-011
/// classical key always; the ML-KEM half exactly when the bundle carries the
/// full, fingerprint-verified PQ pair.
pub(crate) struct RecipientWrapKeys {
    pub(crate) rk_ec: Vec<u8>,
    pub(crate) rk_pq: Option<Vec<u8>>,
}

/// Decode + verify a recipient's HYBRID key bundle. Classical: P-011 as
/// [`verify_recipient_kem_pub`]. PQ (§9.2/N6): when `kem_pq_pubkey` is
/// present it must be a length-exact ek matching its `fingerprint_raw`
/// fingerprint — and a HALF-stripped pair (key without fingerprint, or
/// fingerprint without key) is a tampering signal: refuse to wrap at all,
/// never fall back classical.
///
/// F-DOWNGRADE(a) — mandatory hybrid write: a FULLY-stripped bundle (no PQ
/// pair at all) is ALSO refused. At v1 launch every content identity is
/// hybrid, so "this recipient has no ML-KEM key" is never legitimate — it is
/// the harvest-now downgrade §9.2 exists to prevent, presented by the one
/// party (the directory) an attacker may control. The classical-only-write
/// arm is retained ONLY behind the hard-off `classical-write` cargo feature
/// (never in a shipped binary; a deliberate v2 non-Mac custody decision would
/// re-open it — D2 F-DOWNGRADE terminology note: this gates the
/// classical-only-WRITE path, not the classical crypto code, which every
/// hybrid op and the read path still use).
pub(crate) fn verify_recipient_wrap_keys(value: &Value, who: &str) -> Result<RecipientWrapKeys> {
    let rk_ec = verify_recipient_kem_pub(value, who)?;
    let pq_key = value.get("kem_pq_pubkey").and_then(Value::as_str);
    let pq_fp = value
        .get("kem_pq_pubkey_fingerprint")
        .and_then(Value::as_str);
    let rk_pq = match (pq_key, pq_fp) {
        #[cfg(feature = "classical-write")]
        (None, None) => None,
        #[cfg(not(feature = "classical-write"))]
        (None, None) => {
            return Err(CliError::transparency_violation(format!(
                "{who} has no published ML-KEM key: refusing a classical-only wrap \
                 (mandatory hybrid write, PQR §9.2: every v1 identity is hybrid; \
                 a PQ-less bundle is a stripped directory response)"
            )));
        }
        (Some(k), Some(fp)) => {
            let ek = URL_SAFE_NO_PAD.decode(k).map_err(|_| {
                CliError::invalid_data(format!("{who} ML-KEM pubkey is not base64url"))
            })?;
            if ek.len() != signet_crypto::hybrid_wrap::MLKEM1024_EK_LEN {
                return Err(CliError::invalid_data(format!(
                    "{who} ML-KEM pubkey must be 1568 bytes"
                )));
            }
            if signet_crypto::pubkey::fingerprint_raw(&ek) != fp {
                return Err(CliError::transparency_violation(format!(
                    "{who} ML-KEM-key fingerprint mismatch"
                )));
            }
            Some(ek)
        }
        _ => {
            return Err(CliError::transparency_violation(format!(
                "{who} hybrid KEM bundle is half-stripped (ML-KEM key/fingerprint pair incomplete)"
            )));
        }
    };
    Ok(RecipientWrapKeys { rk_ec, rk_pq })
}

/// My own wrap target for self-wraps. Classical: the local keystore KEM key
/// (ground truth — it is what unwraps later). PQ: gated on my ATTESTED bundle
/// (`/v1/me`) carrying an ML-KEM ek, which must byte-match the local
/// keystore's kem-pq key — attested-but-missing-locally, or attested ≠ local,
/// is a broken identity state: fail loud rather than wrap to a key I could
/// not unwrap with (or one the server substituted).
fn self_wrap_keys(
    keystore: &dyn Keystore,
    me: &Value,
    kem_label: &KeyLabel,
) -> Result<RecipientWrapKeys> {
    let rk_ec = keystore.meta(kem_label)?.public_key;
    let rk_pq = match me.get("kem_pq_pubkey").and_then(Value::as_str) {
        // F-DOWNGRADE(a): a `/v1/me` with no PQ half is either a stripped
        // response or a pre-hybrid identity — both refuse (mandatory hybrid
        // write; the classical-only self-wrap survives only behind the
        // hard-off `classical-write` feature). A four-key identity re-enrolls
        // via Wave B; nothing legitimate is refused at launch.
        #[cfg(feature = "classical-write")]
        None => None,
        #[cfg(not(feature = "classical-write"))]
        None => {
            return Err(CliError::transparency_violation(
                "my attested bundle has no ML-KEM key: refusing a classical-only \
                 self-wrap (mandatory hybrid write, PQR §9.2: if this identity \
                 pre-dates the four-key ceremony, re-enroll it)",
            ));
        }
        Some(b64) => {
            let attested = URL_SAFE_NO_PAD
                .decode(b64)
                .map_err(|_| CliError::invalid_data("my ML-KEM pubkey is not base64url"))?;
            let local = keystore
                .meta(&kem_pq_sibling(kem_label)?)
                .map_err(|_| {
                    CliError::invalid_data(
                        "my attested bundle is hybrid but the local keystore has no ML-KEM key",
                    )
                })?
                .public_key;
            if attested != local {
                return Err(CliError::transparency_violation(
                    "my attested ML-KEM key does not match the local keystore key",
                ));
            }
            Some(local)
        }
    };
    Ok(RecipientWrapKeys { rk_ec, rk_pq })
}

/// Refuse a classical-only wrap at the DISPATCH point (F-DOWNGRADE(a)'s
/// invariant backstop): a writer must never emit a classical-only wrap, no
/// matter which path built the `RecipientWrapKeys`. The resolution-layer
/// refusals give the recipient-naming errors; this one catches any future
/// code path that reaches the dispatch with no PQ half. Compiled out only
/// under the hard-off `classical-write` feature.
#[cfg(not(feature = "classical-write"))]
fn refuse_classical_write(what: &str) -> CliError {
    CliError::transparency_violation(format!(
        "refusing a classical-only {what} (mandatory hybrid write, PQR §9.2)"
    ))
}

/// Wrap a DEK to a verified recipient bundle — hybrid always (mandatory
/// hybrid write, F-DOWNGRADE(a)); the classical-only arm exists only behind
/// the hard-off `classical-write` feature. Returns the envelope as a JSON
/// value (the server stores either shape opaquely).
fn wrap_dek_for(keys: &RecipientWrapKeys, dek: &[u8; 32]) -> Result<Value> {
    let value = match &keys.rk_pq {
        Some(rk_pq) => serde_json::to_value(hybrid::wrap_key_hybrid(&keys.rk_ec, rk_pq, dek, &[])?),
        #[cfg(feature = "classical-write")]
        None => serde_json::to_value(
            signet_crypto::wrap::wrap_dek(&keys.rk_ec, dek)
                .map_err(|_| CliError::encryption_failed("DEK wrap failed"))?,
        ),
        #[cfg(not(feature = "classical-write"))]
        None => return Err(refuse_classical_write("DEK wrap")),
    };
    value.map_err(|e| CliError::generic(format!("serializing wrap envelope: {e}")))
}

/// Wrap a metadata key to a verified recipient bundle (P-015 binds `root`) —
/// the same mandatory-hybrid dispatch as [`wrap_dek_for`].
fn wrap_metadata_key_for(
    keys: &RecipientWrapKeys,
    metadata_key: &[u8; 32],
    root: &[u8; 16],
) -> Result<Value> {
    let value = match &keys.rk_pq {
        Some(rk_pq) => serde_json::to_value(hybrid::wrap_key_hybrid(
            &keys.rk_ec,
            rk_pq,
            metadata_key,
            root,
        )?),
        #[cfg(feature = "classical-write")]
        None => serde_json::to_value(
            signet_crypto::wrap::wrap_metadata_key(&keys.rk_ec, metadata_key, root)
                .map_err(|_| CliError::encryption_failed("metadata-key wrap failed"))?,
        ),
        #[cfg(not(feature = "classical-write"))]
        None => return Err(refuse_classical_write("metadata-key wrap")),
    };
    value.map_err(|e| CliError::generic(format!("serializing wrap envelope: {e}")))
}

/// `signet share create --name <N>` — create a top-level share folder. Mints a
/// metadata key, wraps it to self and — for a PRSN owner — to the Guardian (the
/// mandatory recipient, resolved + fingerprint-verified from `/v1/me`), encrypts the
/// name, and POSTs. The folder is its own root (P-015 binds the wraps to it).
#[allow(clippy::too_many_arguments)]
pub fn share_create(
    keystore: &dyn Keystore,
    path: Option<&str>,
    name: Option<&str>,
    signing_key: Option<&str>,
    kem_key: Option<&str>,
    server_url: &str,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    // A top-level share folder's path IS its name (S040 path-first; Bug034):
    // accept the positional (with or without a leading `/`) or --name, not both.
    let name: String = match (path, name) {
        (Some(_), Some(_)) => {
            return Err(CliError::invalid_args("give a <name> or --name, not both"));
        }
        (Some(p), None) => {
            let trimmed = p.strip_prefix('/').unwrap_or(p);
            if trimmed.is_empty() {
                return Err(CliError::invalid_args("the share folder needs a name"));
            }
            if trimmed.contains('/') {
                return Err(CliError::invalid_args(
                    "a share folder is top-level: give a single name (e.g. Projects), not a nested path",
                ));
            }
            trimmed.to_string()
        }
        (None, Some(n)) => n.to_string(),
        (None, None) => return Err(CliError::invalid_args("give a <name> or --name")),
    };
    let name = name.as_str();
    if name.len() > 255 {
        return Err(CliError::name_too_long("name exceeds 255 bytes"));
    }
    let signing_label = resolve_label(signing_key, Purpose::Signing, config)?;
    let kem_label = resolve_label(kem_key, Purpose::Kem, config)?;

    // A top-level share folder is its own root.
    let folder_id = Uuid::new_v4();
    let root_bytes = *folder_id.as_bytes();

    // Mint a fresh metadata key; self-wrap (I must read my own folder's names).
    // Hybrid when my attested bundle is hybrid (§9.2 via self_wrap_keys).
    let mut metadata_key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *metadata_key);
    let me = http::get_json_signed(keystore, &signing_label, server_url, "/v1/me")?;
    let self_keys = self_wrap_keys(keystore, &me, &kem_label)?;
    let owner_wrap = wrap_metadata_key_for(&self_keys, &metadata_key, &root_bytes)?;

    // A PRSN must also wrap the key to its Guardian (the mandatory recipient).
    // Mandatory hybrid + verified-source (F-DOWNGRADE a+b): the Guardian's keys
    // verify against their §10a log receipts (guardians are humans) before
    // anything is wrapped to them — never the bare `/v1/me` bundle alone.
    let is_prsn = me.get("account_type").and_then(Value::as_str) == Some("prsn");
    let guardian_wrap = if is_prsn {
        let guardian = me.get("guardian").ok_or_else(|| {
            CliError::invalid_data("a PRSN must have a Guardian to create a share folder")
        })?;
        let trust = crate::recipient_verify::ServerTrust::fetch(server_url)?;
        let guardian_keys = crate::recipient_verify::verified_wrap_keys(
            &trust,
            server_url,
            guardian,
            crate::recipient_verify::HandleExpectation::ServerListed,
            "Guardian",
        )?;
        Some(wrap_metadata_key_for(
            &guardian_keys,
            &metadata_key,
            &root_bytes,
        )?)
    } else {
        None
    };

    // Encrypt the name (§7.3; a top-level folder's name binds to root‖itself).
    let encrypted_name =
        signet_crypto::encname::encrypt_name(&metadata_key, &root_bytes, &root_bytes, name)
            .map_err(|_| CliError::encryption_failed("name encryption failed"))?;

    let body = CreateShareFolderBody {
        folder_id: folder_id.to_string(),
        encrypted_name: &encrypted_name,
        owner_metadata_key_wrap: &owner_wrap,
        guardian_metadata_key_wrap: guardian_wrap.as_ref(),
    };
    let body_bytes = serde_json::to_vec(&body)
        .map_err(|e| CliError::generic(format!("serializing create request: {e}")))?;
    let view = http::post_json_signed(
        keystore,
        &signing_label,
        server_url,
        "/v1/share-folders",
        &body_bytes,
    )?;

    out.print_json(&serde_json::json!({
        "folder_id": view.get("folder_id"),
        "root_folder_id": view.get("root_folder_id"),
        "folder_type": view.get("folder_type"),
        "name": name,
        "recipients": view.get("recipients"),
    }))
}

/// `signet folder create <path>` (or `--name <N> [--parent-id <ID> [--root-folder-id <ID>]]`)
/// — create a private top-level folder or a nested subfolder. A `<path>`'s last
/// segment is the new folder's name and the rest is its parent. A top-level folder
/// mints its own metadata key (self-wrapped); a nested folder reuses its root's key.
/// PRSNs can only create *nested* folders (the server rejects a top-level private
/// folder for a PRSN — top-level PRSN folders are share folders, `signet share create`).
#[allow(clippy::too_many_arguments)]
pub fn folder_create(
    keystore: &dyn Keystore,
    path: Option<&str>,
    parent_id: Option<&str>,
    root_folder_id: Option<&str>,
    name: Option<&str>,
    signing_key: Option<&str>,
    kem_key: Option<&str>,
    server_url: &str,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    let signing_label = resolve_label(signing_key, Purpose::Signing, config)?;
    let kem_label = resolve_label(kem_key, Purpose::Kem, config)?;

    // Determine (parent, new_name): a <path>'s last segment is the new name and the
    // rest is the parent; otherwise --name (+ optional --parent-id/--root-folder-id).
    let (parent, new_name): (Option<(Uuid, Uuid)>, String) = match (path, name) {
        (Some(_), Some(_)) => {
            return Err(CliError::invalid_args("give a <path> or --name, not both"));
        }
        (Some(p), None) => {
            let mut resolver = Resolver::new(keystore, &signing_label, &kem_label, server_url);
            let (parent, new_name) = resolver.resolve_create_parent(p)?;
            (parent.map(|r| (r.folder_id, r.root_folder_id)), new_name)
        }
        (None, Some(n)) => {
            let parent = match parent_id {
                Some(id) => {
                    let pid = parse_uuid_arg(id, "--parent-id")?;
                    let root = match root_folder_id {
                        Some(r) => parse_uuid_arg(r, "--root-folder-id")?,
                        None => pid,
                    };
                    Some((pid, root))
                }
                None => None,
            };
            (parent, n.to_string())
        }
        (None, None) => return Err(CliError::invalid_args("give a <path> or --name")),
    };

    if new_name.len() > 255 {
        return Err(CliError::name_too_long("name exceeds 255 bytes"));
    }
    let folder_id = Uuid::new_v4();
    let new_bytes = *folder_id.as_bytes();

    // Top-level: mint a metadata key + self-wrap. Nested: reuse the root's key.
    //
    // The top-level self-wrap is MANDATORY HYBRID, by the same dispatch as its
    // two siblings: `self_wrap_keys` + `wrap_metadata_key_for`, so a bundle
    // with no PQ half hits `refuse_classical_write` instead of silently
    // emitting a classical envelope.
    //
    // bug138 residual (Gus, S161 review). This branch previously wrapped
    // classically and *unconditionally*. It is still not live-reachable — the
    // server refuses `PrsnCannotCreatePrivateFolder` before the F-005
    // chokepoint, so the no-population claim holds — but the old comment's
    // premise ("upgrading it later is a local change") stopped being true the
    // moment bug138 made a classical `rfp` a write-side *refusal*: the client
    // would have been building precisely the envelope the server now rejects.
    // Client and server must agree at the same seam, and this was the one arm
    // that disagreed. It also breaks the day v2 lifts the private-folder
    // restriction. (PQR item 4; §9.2 writer discipline.)
    let (encrypted_name, owner_wrap) = match parent {
        None => {
            let mut metadata_key = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(&mut *metadata_key);
            let me = http::get_json_signed(keystore, &signing_label, server_url, "/v1/me")?;
            let self_keys = self_wrap_keys(keystore, &me, &kem_label)?;
            let wrap = wrap_metadata_key_for(&self_keys, &metadata_key, &new_bytes)?;
            let name_env = signet_crypto::encname::encrypt_name(
                &metadata_key,
                &new_bytes,
                &new_bytes,
                &new_name,
            )
            .map_err(|_| CliError::encryption_failed("name encryption failed"))?;
            (name_env, Some(wrap))
        }
        Some((_, root)) => {
            let mut resolver = Resolver::new(keystore, &signing_label, &kem_label, server_url);
            let metadata_key = resolver.metadata_key(root)?;
            let root_bytes = *root.as_bytes();
            let name_env = signet_crypto::encname::encrypt_name(
                &metadata_key,
                &root_bytes,
                &new_bytes,
                &new_name,
            )
            .map_err(|_| CliError::encryption_failed("name encryption failed"))?;
            (name_env, None)
        }
    };

    let body = CreateFolderBody {
        folder_id: folder_id.to_string(),
        parent_folder_id: parent.map(|(pid, _)| pid.to_string()),
        encrypted_name: &encrypted_name,
        owner_metadata_key_wrap: owner_wrap.as_ref(),
    };
    let body_bytes = serde_json::to_vec(&body)
        .map_err(|e| CliError::generic(format!("serializing create request: {e}")))?;
    let view = http::post_json_signed(
        keystore,
        &signing_label,
        server_url,
        "/v1/folders",
        &body_bytes,
    )?;

    out.print_json(&serde_json::json!({
        "folder_id": view.get("folder_id"),
        "parent_folder_id": view.get("parent_folder_id"),
        "root_folder_id": view.get("root_folder_id"),
        "folder_type": view.get("folder_type"),
        "name": new_name,
    }))
}

// ── Drive management: rename / move / delete ─────────────────────────────────

/// Resolve a folder target (`<path>` or `--folder-id [--root-folder-id]`) to its
/// `(folder_id, root_folder_id)`; the id form defaults the root to the folder itself.
fn resolve_folder_target(
    resolver: &mut Resolver,
    path: Option<&str>,
    folder_id: Option<&str>,
    root_folder_id: Option<&str>,
) -> Result<(Uuid, Uuid)> {
    match (path, folder_id) {
        (Some(_), Some(_)) => Err(CliError::invalid_args(
            "give a <path> or --folder-id, not both",
        )),
        (Some(p), None) => {
            let r = resolver.resolve_folder(p)?;
            Ok((r.folder_id, r.root_folder_id))
        }
        (None, Some(id)) => {
            let fid = parse_uuid_arg(id, "--folder-id")?;
            let root = match root_folder_id {
                Some(r) => parse_uuid_arg(r, "--root-folder-id")?,
                None => fid,
            };
            Ok((fid, root))
        }
        (None, None) => Err(CliError::invalid_args("give a <path> or --folder-id")),
    }
}

/// Resolve a file target (`<path>` or `--file-id --root-folder-id`) to its
/// `(file_id, root_folder_id)`; a file has no implicit root, so the id form needs
/// `--root-folder-id` (used by `rename`, which re-encrypts the name under the root).
fn resolve_file_target(
    resolver: &mut Resolver,
    path: Option<&str>,
    file_id: Option<&str>,
    root_folder_id: Option<&str>,
) -> Result<(Uuid, Uuid)> {
    match (path, file_id) {
        (Some(_), Some(_)) => Err(CliError::invalid_args(
            "give a <path> or --file-id, not both",
        )),
        (Some(p), None) => {
            let r = resolver.resolve_file(p)?;
            Ok((r.file_id, r.root_folder_id))
        }
        (None, Some(id)) => {
            let fid = parse_uuid_arg(id, "--file-id")?;
            let root = root_folder_id
                .ok_or_else(|| CliError::invalid_args("give --root-folder-id with --file-id"))?;
            Ok((fid, parse_uuid_arg(root, "--root-folder-id")?))
        }
        (None, None) => Err(CliError::invalid_args("give a <path> or --file-id")),
    }
}

/// Resolve a file to just its id (`<path>` or `--file-id`) — for ops that don't need
/// the hierarchy root (move, delete).
fn resolve_file_id(
    resolver: &mut Resolver,
    path: Option<&str>,
    file_id: Option<&str>,
) -> Result<Uuid> {
    match (path, file_id) {
        (Some(_), Some(_)) => Err(CliError::invalid_args(
            "give a <path> or --file-id, not both",
        )),
        (Some(p), None) => Ok(resolver.resolve_file(p)?.file_id),
        (None, Some(id)) => parse_uuid_arg(id, "--file-id"),
        (None, None) => Err(CliError::invalid_args("give a <path> or --file-id")),
    }
}

/// Resolve a move destination folder (`--to <path>` or an id flag) to its id.
fn resolve_dest_folder(
    resolver: &mut Resolver,
    to: Option<&str>,
    to_id: Option<&str>,
    id_flag: &str,
) -> Result<Uuid> {
    match (to, to_id) {
        (Some(_), Some(_)) => Err(CliError::invalid_args(format!(
            "give --to <dest-path> or {id_flag}, not both"
        ))),
        (Some(p), None) => Ok(resolver.resolve_folder(p)?.folder_id),
        (None, Some(id)) => parse_uuid_arg(id, id_flag),
        (None, None) => Err(CliError::invalid_args(format!(
            "give --to <dest-path> or {id_flag}"
        ))),
    }
}

/// `signet folder rename (<path>|--folder-id [--root-folder-id]) --name <NEW>` —
/// re-encrypt the name under the folder's root metadata key (§7.3 AAD unchanged),
/// PATCH it.
#[allow(clippy::too_many_arguments)]
pub fn folder_rename(
    keystore: &dyn Keystore,
    path: Option<&str>,
    folder_id: Option<&str>,
    root_folder_id: Option<&str>,
    new_name: &str,
    signing_key: Option<&str>,
    kem_key: Option<&str>,
    server_url: &str,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    if new_name.len() > 255 {
        return Err(CliError::name_too_long("name exceeds 255 bytes"));
    }
    let signing = resolve_label(signing_key, Purpose::Signing, config)?;
    let kem = resolve_label(kem_key, Purpose::Kem, config)?;
    let mut resolver = Resolver::new(keystore, &signing, &kem, server_url);
    let (fid, root) = resolve_folder_target(&mut resolver, path, folder_id, root_folder_id)?;
    let metadata_key = resolver.metadata_key(root)?;
    let encrypted_name = signet_crypto::encname::encrypt_name(
        &metadata_key,
        root.as_bytes(),
        fid.as_bytes(),
        new_name,
    )
    .map_err(|_| CliError::encryption_failed("name encryption failed"))?;
    let body = serde_json::to_vec(&serde_json::json!({ "encrypted_name": encrypted_name }))
        .map_err(|e| CliError::generic(format!("serializing rename: {e}")))?;
    let view = http::patch_json_signed(
        keystore,
        &signing,
        server_url,
        &format!("/v1/folders/{fid}"),
        &body,
    )?;
    out.print_json(&serde_json::json!({ "folder_id": view.get("folder_id"), "name": new_name }))
}

/// `signet file rename (<path>|--file-id --root-folder-id) --name <NEW>`.
#[allow(clippy::too_many_arguments)]
pub fn file_rename(
    keystore: &dyn Keystore,
    path: Option<&str>,
    file_id: Option<&str>,
    root_folder_id: Option<&str>,
    new_name: &str,
    signing_key: Option<&str>,
    kem_key: Option<&str>,
    server_url: &str,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    if new_name.len() > 255 {
        return Err(CliError::name_too_long("name exceeds 255 bytes"));
    }
    let signing = resolve_label(signing_key, Purpose::Signing, config)?;
    let kem = resolve_label(kem_key, Purpose::Kem, config)?;
    let mut resolver = Resolver::new(keystore, &signing, &kem, server_url);
    let (fid, root) = resolve_file_target(&mut resolver, path, file_id, root_folder_id)?;
    let metadata_key = resolver.metadata_key(root)?;
    let encrypted_name = signet_crypto::encname::encrypt_name(
        &metadata_key,
        root.as_bytes(),
        fid.as_bytes(),
        new_name,
    )
    .map_err(|_| CliError::encryption_failed("name encryption failed"))?;
    let body = serde_json::to_vec(&serde_json::json!({ "encrypted_name": encrypted_name }))
        .map_err(|e| CliError::generic(format!("serializing rename: {e}")))?;
    let view = http::patch_json_signed(
        keystore,
        &signing,
        server_url,
        &format!("/v1/files/{fid}"),
        &body,
    )?;
    out.print_json(&serde_json::json!({ "file_id": view.get("file_id"), "name": new_name }))
}

/// `signet folder move (<path>|--folder-id) --to (<dest-path>|--to-parent-id)` —
/// same-root only (server-enforced); no crypto (the §7.3 AAD binds root + id, both
/// unchanged by a same-root move).
#[allow(clippy::too_many_arguments)]
pub fn folder_move(
    keystore: &dyn Keystore,
    path: Option<&str>,
    folder_id: Option<&str>,
    to: Option<&str>,
    to_parent_id: Option<&str>,
    signing_key: Option<&str>,
    kem_key: Option<&str>,
    server_url: &str,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    let signing = resolve_label(signing_key, Purpose::Signing, config)?;
    let kem = resolve_label(kem_key, Purpose::Kem, config)?;
    let mut resolver = Resolver::new(keystore, &signing, &kem, server_url);
    let (fid, _root) = resolve_folder_target(&mut resolver, path, folder_id, None)?;
    let dest = resolve_dest_folder(&mut resolver, to, to_parent_id, "--to-parent-id")?;
    let body = serde_json::to_vec(&serde_json::json!({ "parent_folder_id": dest.to_string() }))
        .map_err(|e| CliError::generic(format!("serializing move: {e}")))?;
    let view = http::patch_json_signed(
        keystore,
        &signing,
        server_url,
        &format!("/v1/folders/{fid}"),
        &body,
    )?;
    out.print_json(&serde_json::json!({
        "folder_id": view.get("folder_id"),
        "parent_folder_id": dest.to_string(),
    }))
}

/// `signet file move (<path>|--file-id) --to (<dest-folder-path>|--to-folder-id)`.
#[allow(clippy::too_many_arguments)]
pub fn file_move(
    keystore: &dyn Keystore,
    path: Option<&str>,
    file_id: Option<&str>,
    to: Option<&str>,
    to_folder_id: Option<&str>,
    signing_key: Option<&str>,
    kem_key: Option<&str>,
    server_url: &str,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    let signing = resolve_label(signing_key, Purpose::Signing, config)?;
    let kem = resolve_label(kem_key, Purpose::Kem, config)?;
    let mut resolver = Resolver::new(keystore, &signing, &kem, server_url);
    let fid = resolve_file_id(&mut resolver, path, file_id)?;
    let dest = resolve_dest_folder(&mut resolver, to, to_folder_id, "--to-folder-id")?;
    let body = serde_json::to_vec(&serde_json::json!({ "folder_id": dest.to_string() }))
        .map_err(|e| CliError::generic(format!("serializing move: {e}")))?;
    let view = http::patch_json_signed(
        keystore,
        &signing,
        server_url,
        &format!("/v1/files/{fid}"),
        &body,
    )?;
    out.print_json(&serde_json::json!({
        "file_id": view.get("file_id"),
        "folder_id": dest.to_string(),
    }))
}

/// Build a batch-delete body `{folder_ids|file_ids: [...]}` (the dynamic field name
/// is why this isn't a `json!` literal). Pure; unit-tested.
fn batch_delete_body(field: &str, ids: &[Uuid]) -> Result<Vec<u8>> {
    let id_strs: Vec<String> = ids.iter().map(Uuid::to_string).collect();
    let mut obj = serde_json::Map::new();
    obj.insert(field.to_string(), Value::from(id_strs));
    serde_json::to_vec(&Value::Object(obj))
        .map_err(|e| CliError::generic(format!("serializing delete: {e}")))
}

/// Delete the resolved ids: a single `DELETE /v1/{kind}/{id}` or a batch
/// `DELETE /v1/{kind} {…_ids}`. `kind` is "folders" or "files".
fn delete_targets(
    keystore: &dyn Keystore,
    signing: &KeyLabel,
    server_url: &str,
    kind: &str,
    ids: &[Uuid],
    out: &OutputMode,
) -> Result<()> {
    if ids.is_empty() {
        return Err(CliError::invalid_args("nothing to delete"));
    }
    if ids.len() == 1 {
        http::delete_signed(
            keystore,
            signing,
            server_url,
            &format!("/v1/{kind}/{}", ids[0]),
        )?;
        return out.print_json(&serde_json::json!({ "deleted": 1 }));
    }
    let field = if kind == "folders" {
        "folder_ids"
    } else {
        "file_ids"
    };
    let body = batch_delete_body(field, ids)?;
    let resp =
        http::delete_json_signed(keystore, signing, server_url, &format!("/v1/{kind}"), &body)?;
    out.print_json(&serde_json::json!({ "deleted": resp.get("deleted") }))
}

/// `signet folder delete (<path>...|--folder-id <ID>...)` — single or batch.
#[allow(clippy::too_many_arguments)]
pub fn folder_delete(
    keystore: &dyn Keystore,
    paths: &[String],
    folder_ids: &[String],
    signing_key: Option<&str>,
    kem_key: Option<&str>,
    server_url: &str,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    let signing = resolve_label(signing_key, Purpose::Signing, config)?;
    let kem = resolve_label(kem_key, Purpose::Kem, config)?;
    let mut resolver = Resolver::new(keystore, &signing, &kem, server_url);
    let mut ids: Vec<Uuid> = Vec::new();
    for p in paths {
        ids.push(resolver.resolve_folder(p)?.folder_id);
    }
    for id in folder_ids {
        ids.push(parse_uuid_arg(id, "--folder-id")?);
    }
    delete_targets(keystore, &signing, server_url, "folders", &ids, out)
}

/// `signet file delete (<path>...|--file-id <ID>...)` — single or batch.
#[allow(clippy::too_many_arguments)]
pub fn file_delete(
    keystore: &dyn Keystore,
    paths: &[String],
    file_ids: &[String],
    signing_key: Option<&str>,
    kem_key: Option<&str>,
    server_url: &str,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    let signing = resolve_label(signing_key, Purpose::Signing, config)?;
    let kem = resolve_label(kem_key, Purpose::Kem, config)?;
    let mut resolver = Resolver::new(keystore, &signing, &kem, server_url);
    let mut ids: Vec<Uuid> = Vec::new();
    for p in paths {
        ids.push(resolver.resolve_file(p)?.file_id);
    }
    for id in file_ids {
        ids.push(parse_uuid_arg(id, "--file-id")?);
    }
    delete_targets(keystore, &signing, server_url, "files", &ids, out)
}

// ── File transport: signet upload (§4.2 multipart, direct-to-storage) ────────

/// Default per-chunk plaintext size (16 MiB) — matches the web `Drive`. Every
/// upload goes through multipart; a file at or under one chunk is a 1-part upload.
const DEFAULT_CHUNK_SIZE: usize = 16 * 1024 * 1024;
/// S3's hard cap on the parts in one multipart upload (mirrors the server).
const MAX_PARTS: i64 = 10_000;

/// The object-storage floor for every multipart part except the last (S3 semantics,
/// which OVH follows). Below this, `CompleteMultipartUpload` rejects the whole upload
/// with `EntityTooSmall` *after* every part has been transferred — so we refuse the
/// plan up front instead (bug060/S1). Pairs with [`MAX_PARTS`]: floor and ceiling.
const MIN_MULTIPART_CHUNK_SIZE: usize = 5 * 1024 * 1024;
/// Fixed §4.2 on-disk overhead per chunk: magic(1) + alg(1) + index(4) + IV(12) +
/// GCM tag(16). Stored ciphertext = plaintext + this per chunk.
const MULTIPART_CHUNK_OVERHEAD: i64 = 34;

#[derive(Serialize)]
struct InitiateBody<'a> {
    folder_id: String,
    encrypted_name: &'a NameEnvelope,
    wrapped_deks: Vec<WrappedDekInput>,
    declared_size: i64,
    chunk_size: i32,
    chunk_count: i32,
    algorithm: &'a str,
}

#[derive(Serialize)]
struct WrappedDekInput {
    recipient_account_id: String,
    /// A classical or hybrid wrap envelope (the server stores either opaquely).
    wrapped_dek: Value,
}

#[derive(Serialize)]
struct CompleteBody {
    parts: Vec<PartInput>,
}

#[derive(Serialize)]
struct PartInput {
    part_number: i32,
    etag: String,
}

/// `signet upload` — encrypt a file and upload it via the §4.2 multipart transport
/// (direct-to-object-storage). Ports the web `Drive.uploadFile`: a fresh DEK seals
/// each chunk, the name is encrypted under the folder's metadata key, and the content
/// streams from disk straight to storage — the API never relays a content byte. The
/// DEK is wrapped to the uploader AND to every current recipient of the share folder
/// (S049), so recipients — notably a PRSN's mandatory Guardian — can read it.
#[allow(clippy::too_many_arguments)]
pub fn upload(
    keystore: &dyn Keystore,
    dest_path: Option<&str>,
    in_path: &Path,
    to: Option<&str>,
    folder_id: Option<&str>,
    root_folder_id: Option<&str>,
    name: Option<&str>,
    chunk_size: Option<usize>,
    signing_key: Option<&str>,
    kem_key: Option<&str>,
    server_url: &str,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    let chunk_size = chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
    if chunk_size == 0 || chunk_size > i32::MAX as usize {
        return Err(CliError::invalid_args(
            "--chunk-size must be between 1 and 2147483647 bytes",
        ));
    }
    let signing_label = resolve_label(signing_key, Purpose::Signing, config)?;
    let kem_label = resolve_label(kem_key, Purpose::Kem, config)?;

    // Destination: a positional <path> carries folder AND name (its last segment —
    // the same split as `folder create`; S040 path-first, Bug034). Otherwise
    // --to <folder-path> / --folder-id (+ --root-folder-id) with --name.
    let (folder_uuid, root_uuid, name): (Uuid, Uuid, String) = match dest_path {
        Some(dest) => {
            if to.is_some() || folder_id.is_some() || name.is_some() {
                return Err(CliError::invalid_args(
                    "give a destination <path> (its last segment is the file's name) or the --to/--folder-id + --name flags, not both",
                ));
            }
            let mut resolver = Resolver::new(keystore, &signing_label, &kem_label, server_url);
            let (parent, new_name) = resolver.resolve_create_parent(dest)?;
            match parent {
                Some(r) => (r.folder_id, r.root_folder_id, new_name),
                None => {
                    return Err(CliError::invalid_args(
                        "a file needs a destination folder: give /<folder>/<name> (files cannot live at the top level)",
                    ));
                }
            }
        }
        None => {
            let name = name
                .ok_or_else(|| {
                    CliError::invalid_args(
                        "give --name with --to/--folder-id, or a destination <path> whose last segment is the file's name",
                    )
                })?
                .to_string();
            let (folder, root) = match (to, folder_id) {
                (Some(_), Some(_)) => {
                    return Err(CliError::invalid_args(
                        "give --to <folder-path> or --folder-id, not both",
                    ));
                }
                (Some(p), None) => {
                    let mut resolver =
                        Resolver::new(keystore, &signing_label, &kem_label, server_url);
                    let r = resolver.resolve_folder(p)?;
                    (r.folder_id, r.root_folder_id)
                }
                (None, Some(id)) => {
                    let folder = parse_uuid_arg(id, "--folder-id")?;
                    let root = match root_folder_id {
                        Some(r) => parse_uuid_arg(r, "--root-folder-id")?,
                        None => folder,
                    };
                    (folder, root)
                }
                (None, None) => {
                    return Err(CliError::invalid_args(
                        "give a destination <path>, or --to <folder-path> / --folder-id",
                    ));
                }
            };
            (folder, root, name)
        }
    };
    // bug048: the folder may already hold this name (names are ciphertext to
    // the server — zero-access — so uniqueness is a CLIENT decision; the web
    // client applies the identical rule, names.rs ↔ names.ts). Deterministic
    // across re-runs: pending uploads are invisible to the listing, so an
    // interrupted upload's re-run derives the SAME deduped name and its
    // resume state still matches (find_match keys on the name).
    let name = {
        let mut resolver = Resolver::new(keystore, &signing_label, &kem_label, server_url);
        let taken: std::collections::HashSet<String> = resolver
            .list_files(folder_uuid, root_uuid)?
            .into_iter()
            // bug132(ii): only names we could actually read can be "taken". ⚠ Honest
            // limitation, stated rather than hidden: a file whose name cannot be decoded
            // cannot participate in dedup, so a new upload could collide with its real
            // name. That is unavoidable — we cannot deduplicate against a name we cannot
            // read — and it is strictly better than the previous behaviour, where one such
            // file made the whole upload fail.
            .filter_map(|f| f.name)
            .collect();
        let deduped = crate::names::dedupe_name(&name, &taken);
        if deduped != name {
            eprintln!("signet: '{name}' already exists in this folder. Uploading as '{deduped}'");
        }
        deduped
    };
    let name = name.as_str();
    if name.len() > 255 {
        return Err(CliError::name_too_long("name exceeds 255 bytes"));
    }
    let root_bytes = *root_uuid.as_bytes();

    // The chunk plan comes from the file size; file_id is client-supplied (the §4.2 AAD).
    let source_meta = std::fs::metadata(in_path)
        .map_err(|e| CliError::input_read(format!("reading {}: {e}", in_path.display())))?;
    let file_size = source_meta.len();
    // The resume signature (bug047): canonical path + size + mtime identify
    // "the same source, unchanged" across process runs.
    let source_mtime = source_meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let source_path = std::fs::canonicalize(in_path)
        .unwrap_or_else(|_| in_path.to_path_buf())
        .to_string_lossy()
        .into_owned();

    // bug047: an interrupted prior upload of this same unchanged source to this
    // same destination RESUMES instead of restarting — the parts storage
    // already holds are never re-sent. `Ok(None)` = not resumable (state
    // cleaned); fall through to a fresh upload. A `transfer_stalled` inside the
    // resumed transfer propagates with the state kept: re-run resumes again.
    // bug129 (F-003): compute the content anchor for the CURRENT source, so the resume decision
    // rests on the bytes rather than on a second-granular mtime.
    let source_anchor = crate::upload_state::content_anchor(in_path, file_size, chunk_size);
    if let Some(state) = crate::upload_state::find_match(&crate::upload_state::ResumeKey {
        server_url,
        folder_id: &folder_uuid.to_string(),
        name,
        source_path: &source_path,
        file_size,
        file_mtime_unix: source_mtime,
        content_anchor: source_anchor.as_deref(),
    }) && let Some(view) = try_resume(
        keystore,
        &signing_label,
        &kem_label,
        server_url,
        &state,
        in_path,
        file_size,
    )? {
        return out.print_json(&view);
    }

    let (chunk_count, declared_size) = chunk_plan(file_size, chunk_size)?;
    check_multipart_floor(chunk_count, chunk_size)?;
    let file_id = Uuid::new_v4();
    let file_id_bytes = *file_id.as_bytes();

    // My account_id + attested bundle (the uploader must appear in wrapped_deks;
    // the bundle gates the hybrid self-wrap, §9.2).
    let me = http::get_json_signed(keystore, &signing_label, server_url, "/v1/me")?;
    let account_id = me
        .get("account_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CliError::invalid_data("/v1/me response missing account_id"))?
        .to_string();

    // bug070: refuse an upload that cannot succeed BEFORE any byte moves — the PRSN
    // half of the fix. This surface had neither check: it fetched the very `/v1/me`
    // response that carries `max_upload_size_bytes` and ignored the field, so the
    // human got a (flawed) local guard and the PRSN got none. Under the load-bearing
    // principle, if one surface pre-flights, so does the other.
    //
    // Both comparisons are against `declared_size` — the STORED ciphertext size from
    // `chunk_plan` — because that is the figure the server bounds and reserves
    // against, not the file's size on disk.
    //
    // ⚠ POSITION IS LOAD-BEARING: this must stay AFTER the `try_resume` early return
    // above. A resumed upload's reservation is ALREADY counted in `bytes_used`, so
    // re-checking capacity would find `available` short by exactly this file's size
    // and refuse every resume — turning a recovery path into a guaranteed failure.
    // Do not hoist this next to `chunk_plan` or above the resume attempt.
    preflight_capacity(keystore, &signing_label, server_url, &me, declared_size)?;

    // A fresh DEK, self-wrapped to my KEM key (I must be able to read my own
    // file) — hybrid when my attested bundle is hybrid.
    let mut dek = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *dek);
    let self_keys = self_wrap_keys(keystore, &me, &kem_label)?;
    let wrapped_dek = wrap_dek_for(&self_keys, &dek)?;

    // The folder's metadata key → encrypt the name (§7.3, bound to root‖file_id).
    let mkw_path = format!("/v1/folders/{root_uuid}/metadata-key-wrap");
    let mkw = http::get_json_signed(keystore, &signing_label, server_url, &mkw_path)?;
    let wrapped_key = mkw
        .get("wrapped_key")
        .ok_or_else(|| CliError::invalid_data("metadata-key-wrap response missing wrapped_key"))?;
    let metadata_key =
        unwrap_metadata_key_envelope(keystore, wrapped_key, &root_bytes, &kem_label)?;
    let encrypted_name =
        signet_crypto::encname::encrypt_name(&metadata_key, &root_bytes, &file_id_bytes, name)
            .map_err(|_| CliError::encryption_failed("name encryption failed"))?;

    // Wrap the DEK to every current recipient of the share folder too (S049), so a
    // recipient — notably a PRSN's mandatory Guardian — can read a file added after
    // they joined. Self first; then each recipient's shareable KEM key, P-011-checked
    // against its fingerprint before any wrap. The server enforces that the set covers
    // exactly the folder's recipients + uploader. (PRSN folders are always share
    // folders, so `/share-folders/{root}/recipients` always resolves.)
    let mut wrapped_deks = vec![WrappedDekInput {
        recipient_account_id: account_id.clone(),
        wrapped_dek,
    }];
    let recipients = http::get_json_signed(
        keystore,
        &signing_label,
        server_url,
        &format!("/v1/share-folders/{root_uuid}/recipients"),
    )?;
    // Verified-source recipient keys (F-DOWNGRADE a+b): one server-trust fetch
    // for the whole recipient set (lazily, on the first non-self recipient),
    // then each recipient's keys verify against their identity record
    // (attestation / §10a receipts) before any wrap. The OWNER (Bug038) is
    // wrapped too, so a read_write recipient uploading to a folder it does not
    // own still covers the owner; when we ARE the owner it is skipped as self.
    let mut trust: Option<crate::recipient_verify::ServerTrust> = None;
    let mut seen: std::collections::HashSet<String> =
        std::collections::HashSet::from([account_id.clone()]);
    let owner = recipients.get("owner");
    let wrap_targets = owner.into_iter().chain(
        recipients
            .get("recipients")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default(),
    );
    for r in wrap_targets {
        let rid = r
            .get("recipient_account_id")
            .and_then(Value::as_str)
            .ok_or_else(|| CliError::invalid_data("recipient missing account_id"))?;
        if !seen.insert(rid.to_string()) {
            continue; // self, or already wrapped (owner also listed as a recipient)
        }
        if trust.is_none() {
            trust = Some(crate::recipient_verify::ServerTrust::fetch(server_url)?);
        }
        let trust = trust.as_ref().expect("just initialized");
        let recipient_keys = crate::recipient_verify::verified_wrap_keys(
            trust,
            server_url,
            r,
            crate::recipient_verify::HandleExpectation::ServerListed,
            "recipient",
        )?;
        wrapped_deks.push(WrappedDekInput {
            recipient_account_id: rid.to_string(),
            wrapped_dek: wrap_dek_for(&recipient_keys, &dek)?,
        });
    }

    // Initiate the multipart upload (reserves quota, returns one part URL per chunk).
    let initiate_body = InitiateBody {
        folder_id: folder_uuid.to_string(),
        encrypted_name: &encrypted_name,
        wrapped_deks,
        declared_size,
        chunk_size: chunk_size as i32,
        chunk_count,
        algorithm: "A256GCM",
    };
    let initiate_bytes = serde_json::to_vec(&initiate_body)
        .map_err(|e| CliError::generic(format!("serializing initiate request: {e}")))?;
    let initiate_path = format!("/v1/files/{file_id}/multipart");
    let initiate = http::post_json_signed(
        keystore,
        &signing_label,
        server_url,
        &initiate_path,
        &initiate_bytes,
    )?;
    let upload_id = initiate
        .get("upload_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CliError::invalid_data("initiate response missing upload_id"))?
        .to_string();
    let part_urls = initiate
        .get("part_urls")
        .and_then(|v| v.as_array())
        .ok_or_else(|| CliError::invalid_data("initiate response missing part_urls"))?;
    // The server-tuned transfer-resilience knobs (bug047) ride the initiate
    // response; defaults apply if an older server omits them.
    let knobs = http::TransferKnobs::from_response(&initiate);
    // bug060: the governor derives every duration-shaped bound from the rate this
    // upload measures on itself, so no value here encodes a minimum bandwidth.
    let mut governor = TransferGovernor::new(GovernorKnobs::from_response(&initiate));
    let prepare_ahead = upload_prepare_ahead(&initiate);
    #[allow(unused_assignments)]
    let mut busy_fraction = 0.0_f64;

    // Persist the resume state BEFORE any byte moves (bug047): even a hard
    // crash mid-transfer leaves a resumable trail. Removed on complete/abort.
    let resume_state = crate::upload_state::UploadState {
        file_id: file_id.to_string(),
        upload_id: upload_id.clone(),
        server_url: server_url.to_string(),
        folder_id: folder_uuid.to_string(),
        root_folder_id: root_uuid.to_string(),
        name: name.to_string(),
        source_path: source_path.clone(),
        file_size,
        file_mtime_unix: source_mtime,
        // bug129 (F-003): persist the anchor computed for this exact source, so a later resume
        // can prove the bytes are unchanged instead of inferring it from the clock.
        content_anchor: source_anchor.clone(),
        chunk_size,
        chunk_count,
        rate_estimate_bps: None,
        rate_measured_at_unix: None,
    };
    if let Err(error) = crate::upload_state::save(&resume_state) {
        // Best-effort: an unwritable state costs resumability, not the upload.
        eprintln!(
            "signet: note: could not write resume state ({error}); an interrupted upload will not be resumable"
        );
    }

    // Stream each chunk from disk → §4.2-seal → PUT straight to storage. A
    // `transfer_stalled` exhaustion (a bad network window) PRESERVES the upload
    // + state for resume; any other failure aborts to free the reservation.
    let parts = match upload_parts(
        in_path,
        &dek,
        &file_id_bytes,
        chunk_size,
        chunk_count as u32,
        part_urls,
        &knobs,
        &mut governor,
        prepare_ahead,
        upload_concurrency(&initiate),
    ) {
        Ok((parts, busy)) => {
            busy_fraction = busy;
            parts
        }
        Err(error) if error.code == "transfer_stalled" => {
            // Carry the measured rate into the resume so the next run starts warm
            // rather than re-deriving its bounds from nothing (bug060). Best-effort
            // by design: losing it costs a bootstrap, never the upload.
            persist_rate_estimate(&resume_state, &governor);
            eprintln!(
                "signet: upload paused mid-transfer; re-run the same command to resume from the parts already stored"
            );
            return Err(error);
        }
        Err(error) => {
            abort_then_forget(keystore, &signing_label, server_url, &file_id, &upload_id);
            return Err(error);
        }
    };

    let complete_bytes = serde_json::to_vec(&CompleteBody { parts })
        .map_err(|e| CliError::generic(format!("serializing complete request: {e}")))?;
    let complete_path = format!("/v1/files/{file_id}/multipart/{upload_id}/complete");
    let file_view = match http::post_json_signed(
        keystore,
        &signing_label,
        server_url,
        &complete_path,
        &complete_bytes,
    ) {
        Ok(view) => view,
        Err(error) if error.code == "not_found" => {
            // The server no longer knows the upload (swept, or finalized under
            // us) — the state is dead. Matches try_resume's complete site.
            crate::upload_state::remove(&resume_state.file_id);
            return Err(error);
        }
        Err(error) => {
            // bug050: every part is stored — the transfer is DONE; only the
            // signed finalize failed (network, a locked Secure Enclave [the
            // §Resolved-#8 custody model ends SE access at screen lock — the
            // most probable interruption of an hours-long upload], a 5xx, …).
            // NEVER abort here and NEVER drop the state: preserving a fully-
            // transferred upload is strictly better than re-sending it, and a
            // re-run re-resumes + re-completes in seconds. Only a server that
            // affirmatively no longer knows the upload (above) kills the state.
            // (The pre-bug050 branch aborted-and-forgot on any non-network
            // code — destroying resumability exactly when it was needed.)
            eprintln!(
                "signet: the upload is fully transferred but could not be finalized ({}); it is preserved. Re-run the same command to resume",
                error.code
            );
            return Err(error);
        }
    };
    crate::upload_state::remove(&resume_state.file_id);

    out.print_json(&serde_json::json!({
        "file_id": file_id.to_string(),
        "folder_id": folder_uuid.to_string(),
        // Bug008: the *plaintext* input size, named distinctly from the `size_bytes`
        // that `file list` / `download` report (the stored ciphertext size — server
        // is zero-access, so it only knows the on-disk/ciphertext size).
        "plaintext_bytes": file_size,
        "chunk_count": chunk_count,
        // ⭐ S174: the fraction of wall clock with bytes actually IN FLIGHT.
        // The relay emits `effective_streams`, but the relay carries WEB uploads
        // only - the CLI goes direct to storage and never traverses it, so a
        // single acceptance bar on that metric would report clean on a surface it
        // cannot see. This is this surface's own instrument. 1.0 = never idle;
        // the pre-S174 serial path sits well below it because sealing happened
        // with the network stopped.
        "busy_fraction": (busy_fraction * 1000.0).round() / 1000.0,
        "etag": file_view.get("etag"),
    }))
}

/// Attempt to resume a previously-interrupted upload (bug047). `Ok(Some(view))`
/// = resumed and completed — `view` is the command's output object. `Ok(None)`
/// = not resumable (the server no longer knows the upload, or the state
/// disagrees with the server's geometry); the state file has been cleaned and
/// the caller starts a fresh upload. A `transfer_stalled` inside the resumed
/// transfer propagates as `Err` with the state KEPT — the next re-run resumes
/// again. The DEK is re-obtained by unwrapping the caller's own wrap from the
/// resume response (never persisted locally); the uploaded-part set + ETags
/// come from the server's authoritative `ListParts` view.
fn try_resume(
    keystore: &dyn Keystore,
    signing_label: &KeyLabel,
    kem_label: &KeyLabel,
    server_url: &str,
    state: &crate::upload_state::UploadState,
    in_path: &Path,
    file_size: u64,
) -> Result<Option<Value>> {
    let resume_path = format!(
        "/v1/files/{}/multipart/{}/resume",
        state.file_id, state.upload_id
    );
    let resume = match http::post_signed(keystore, signing_label, server_url, &resume_path) {
        Ok(text) => serde_json::from_str::<Value>(&text)
            .map_err(|e| CliError::invalid_data(format!("resume response: {e}")))?,
        Err(error) if error.code == "not_found" => {
            // Finalized, expired + swept, or gone at storage (the server
            // cleaned it up) — nothing to resume.
            eprintln!(
                "signet: the previous upload of {} is no longer resumable; starting fresh",
                state.name
            );
            crate::upload_state::remove(&state.file_id);
            return Ok(None);
        }
        Err(error) => return Err(error),
    };

    // The server's geometry is authoritative; a state that disagrees with it
    // must never resume (the §4.2 seal derives from DEK + geometry + content).
    let chunk_size = resume
        .get("chunk_size")
        .and_then(Value::as_i64)
        .unwrap_or(0) as usize;
    let chunk_count = resume
        .get("chunk_count")
        .and_then(Value::as_i64)
        .unwrap_or(0) as i32;
    if chunk_size != state.chunk_size || chunk_count != state.chunk_count || chunk_count < 1 {
        eprintln!(
            "signet: the previous upload's stored state does not match the server; starting fresh"
        );
        if let Ok(file_uuid) = Uuid::parse_str(&state.file_id) {
            // This in-flight upload is unusable to us — free its reservation.
            // Deleting the state below is deliberate EVEN IF this abort fails
            // (unlike the bug050 sites): a state that disagrees with the
            // server must never drive a resume; if the abort didn't land, the
            // idle-deadline sweep reaps the server side.
            let _ = abort_upload(
                keystore,
                signing_label,
                server_url,
                &file_uuid,
                &state.upload_id,
            );
        }
        crate::upload_state::remove(&state.file_id);
        return Ok(None);
    }

    let wrapped = resume
        .get("wrapped_dek")
        .ok_or_else(|| CliError::invalid_data("resume response missing wrapped_dek"))?;
    let dek = unwrap_dek_value(keystore, wrapped, kem_label)?;
    let file_uuid = Uuid::parse_str(&state.file_id)
        .map_err(|_| CliError::invalid_data("upload state carries an invalid file id"))?;
    let file_id_bytes = *file_uuid.as_bytes();

    let uploaded = resume
        .get("uploaded_parts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let part_urls = resume
        .get("part_urls")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let knobs = http::TransferKnobs::from_response(&resume);
    // A resumed upload starts warm from the rate the interrupted run measured, if
    // it is recent enough to still describe this link (15-min horizon).
    let mut governor = match state.rate_estimate_bps {
        Some(rate) => TransferGovernor::with_warm_start(
            GovernorKnobs::from_response(&resume),
            rate,
            state.rate_measured_age(),
        ),
        None => TransferGovernor::new(GovernorKnobs::from_response(&resume)),
    };
    eprintln!(
        "signet: resuming upload of {}: {} of {chunk_count} parts already stored, {} to send",
        state.name,
        uploaded.len(),
        part_urls.len()
    );

    let new_parts = upload_parts(
        in_path,
        &dek,
        &file_id_bytes,
        chunk_size,
        chunk_count as u32,
        &part_urls,
        &knobs,
        &mut governor,
        upload_prepare_ahead(&resume),
        upload_concurrency(&resume),
    );
    if let Err(error) = &new_parts
        && error.code == "transfer_stalled"
    {
        // Same warm-start carry as the initiate path: a repeatedly-resumed
        // upload on a bad link accumulates a better estimate each time.
        persist_rate_estimate(state, &governor);
    }
    let (new_parts, busy_fraction) = new_parts?;

    // Complete with the server-reported ETags for stored parts + the fresh ones.
    let mut parts: Vec<PartInput> = Vec::with_capacity(uploaded.len() + new_parts.len());
    for part in &uploaded {
        parts.push(PartInput {
            part_number: part.get("part_number").and_then(Value::as_i64).unwrap_or(0) as i32,
            etag: part
                .get("etag")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        });
    }
    parts.extend(new_parts);

    let complete_bytes = serde_json::to_vec(&CompleteBody { parts })
        .map_err(|e| CliError::generic(format!("serializing complete request: {e}")))?;
    let complete_path = format!(
        "/v1/files/{}/multipart/{}/complete",
        state.file_id, state.upload_id
    );
    let file_view = match http::post_json_signed(
        keystore,
        signing_label,
        server_url,
        &complete_path,
        &complete_bytes,
    ) {
        Ok(view) => view,
        Err(error) if error.code == "not_found" => {
            // Finalized under us by a concurrent path — the state is dead.
            crate::upload_state::remove(&state.file_id);
            return Err(error);
        }
        // Anything else (notably a network failure) keeps the state: every
        // part is stored, so a re-run re-resumes and simply re-completes.
        Err(error) => return Err(error),
    };

    crate::upload_state::remove(&state.file_id);
    Ok(Some(serde_json::json!({
        "file_id": state.file_id,
        "folder_id": state.folder_id,
        "plaintext_bytes": file_size,
        "chunk_count": chunk_count,
        // ⭐ S174: the fraction of wall clock with bytes actually IN FLIGHT.
        // The relay emits `effective_streams`, but the relay carries WEB uploads
        // only - the CLI goes direct to storage and never traverses it, so a
        // single acceptance bar on that metric would report clean on a surface it
        // cannot see. This is this surface's own instrument. 1.0 = never idle;
        // the pre-S174 serial path sits well below it because sealing happened
        // with the network stopped.
        "busy_fraction": (busy_fraction * 1000.0).round() / 1000.0,
        "etag": file_view.get("etag"),
        "resumed": true,
    })))
}

/// The §4.2 chunk plan: chunk_count (≥1, ≤ `MAX_PARTS`) + declared ciphertext size
/// (plaintext + `MULTIPART_CHUNK_OVERHEAD` per chunk). Mirrors the web
/// `Drive.uploadFile` byte-for-byte so both surfaces declare the same size.
fn chunk_plan(file_size: u64, chunk_size: usize) -> Result<(i32, i64)> {
    let chunk_count: u64 = if file_size == 0 {
        1
    } else {
        file_size.div_ceil(chunk_size as u64)
    };
    if chunk_count > MAX_PARTS as u64 {
        return Err(CliError::invalid_args(format!(
            "file needs {chunk_count} chunks at chunk_size {chunk_size}; the max is {MAX_PARTS}. Use a larger --chunk-size"
        )));
    }
    let declared_size = file_size as i64 + chunk_count as i64 * MULTIPART_CHUNK_OVERHEAD;
    Ok((chunk_count as i32, declared_size))
}

/// bug070: refuse an upload that provably cannot succeed, before any byte moves.
///
/// The server already refuses both of these at `multipart::initiate`, correctly and
/// before object storage is touched. What was missing on THIS surface was refusing
/// first: the CLI fetched the `/v1/me` response carrying `max_upload_size_bytes` and
/// ignored the field, so a PRSN learned that a 50 GB upload into 500 MB of remaining
/// pool was impossible only from the server's rejection.
///
/// `declared_size` is the STORED ciphertext size from [`chunk_plan`] — the figure the
/// server bounds and reserves against. Comparing the file's on-disk size instead is
/// what made the web's old guard wrong at the boundary (bug070 face (c)).
///
/// **The quota read FAILS OPEN.** The server stays authoritative, so letting a
/// doubtful upload proceed costs nothing — it is refused correctly if it truly does
/// not fit — whereas failing closed would block a legitimate upload whenever the
/// quota endpoint hiccups. The ceiling check needs no such escape: its value already
/// arrived in the `/v1/me` response this upload could not have started without.
fn preflight_capacity(
    keystore: &dyn Keystore,
    signing: &KeyLabel,
    server_url: &str,
    me: &serde_json::Value,
    declared_size: i64,
) -> Result<()> {
    let ceiling = me.get("max_upload_size_bytes").and_then(|v| v.as_i64());
    // A failed read yields None, which `capacity_refusal` treats as fail-open by
    // contract — the escape hatch lives in the rule, not scattered through the I/O.
    let remaining = http::get_json_signed(keystore, signing, server_url, "/v1/me/quota")
        .ok()
        .and_then(|quota| {
            let used = quota.get("bytes_used").and_then(|v| v.as_i64())?;
            let limit = quota.get("bytes_quota").and_then(|v| v.as_i64())?;
            Some((limit - used).max(0))
        });
    match capacity_refusal(declared_size, ceiling, remaining) {
        // bug070 follow-up (S140): a capacity condition is NOT an invalid argument.
        // The command line was well-formed and the identical invocation succeeds once
        // space exists — reporting exit 2 told a harness to go fix its arguments, which
        // is the one action guaranteed not to help. See `CliError::insufficient_storage`.
        Some(message) => Err(CliError::insufficient_storage(message)),
        None => Ok(()),
    }
}

/// The bug070 pre-flight DECISION for one file, free of I/O — a refusal message, or
/// `None` to proceed. The web runs the same rule over a batch
/// (`drive.ts::capacityRefusal`); both are pinned by verbatim-identical vectors, the
/// way the bug048 name rule is pinned across `names.rs` / `names.ts`.
///
/// `ceiling: None` means the field was absent from `/v1/me`; `remaining: None` means
/// the quota read failed. **Both proceed** — the server is authoritative and refuses
/// an impossible upload before any byte reaches storage, so failing closed on missing
/// local information would only block legitimate work.
fn capacity_refusal(
    declared_size: i64,
    ceiling: Option<i64>,
    remaining: Option<i64>,
) -> Option<String> {
    if let Some(ceiling) = ceiling
        && declared_size > ceiling
    {
        return Some(format!(
            "file is too large: it stores as {declared_size} bytes, over the server's \
             {ceiling}-byte single-file limit"
        ));
    }
    let remaining = remaining?;
    if declared_size > remaining {
        return Some(format!(
            "not enough storage: this upload needs {declared_size} bytes but only \
             {remaining} of the account's pooled quota is available; free space, or \
             ask your Guardian to move to a larger plan"
        ));
    }
    None
}

/// bug060/S1: object storage requires every part EXCEPT THE LAST to be >= 5 MiB. A
/// sub-floor `chunk_size` is accepted by every individual PutPart and rejected only at
/// `CompleteMultipartUpload` — i.e. *after* the entire file has been uploaded (measured:
/// a 100 MB upload spent three minutes before failing). Refuse the plan up front.
///
/// The rule is **file-size-dependent, not a bare parse-time floor**: a single-part
/// upload IS the last part, so a 2 MiB file at a 2 MiB chunk size is legal and must stay
/// legal. Deliberately kept out of [`chunk_plan`], which is a pure arithmetic mirror of
/// the web's overhead model (and is unit-tested with byte-sized chunks for readability);
/// this is policy, not arithmetic.
fn check_multipart_floor(chunk_count: i32, chunk_size: usize) -> Result<()> {
    if chunk_count > 1 && chunk_size < MIN_MULTIPART_CHUNK_SIZE {
        return Err(CliError::invalid_args(format!(
            "--chunk-size {chunk_size} is below the {MIN_MULTIPART_CHUNK_SIZE}-byte (5 MiB) minimum \
             that object storage requires for multi-part uploads; this file needs {chunk_count} parts \
             (use a larger --chunk-size; only a single-part upload may go below the minimum)"
        )));
    }
    Ok(())
}

/// Record the governor's current rate estimate in the upload's resume state, so a
/// later `signet file upload` of the same file starts warm (bug060).
///
/// Best-effort throughout: a rate estimate is an optimization, never a
/// correctness input — the resume path treats a missing, stale, or implausible
/// value as "no estimate" and falls back to the bootstrap. So a write failure
/// here is deliberately silent rather than noisy or fatal.
fn persist_rate_estimate(state: &crate::upload_state::UploadState, governor: &TransferGovernor) {
    let Some(rate) = governor.rate_estimate() else {
        return;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let updated = crate::upload_state::UploadState {
        rate_estimate_bps: Some(rate),
        rate_measured_at_unix: Some(now),
        ..state.clone()
    };
    let _ = crate::upload_state::save(&updated);
}

/// Stream the file's chunks: for each pre-signed part URL, seek to that chunk's
/// offset, read up to `chunk_size` bytes, §4.2-seal them under the DEK (AAD =
/// file_id‖index), and PUT the envelope straight to storage. The 100 GB path:
/// in-flight memory is `(1 + prepare_ahead) x chunk_size`, never the file.
///
/// Returns the parts (number + ETag) for `complete`, plus the BUSY FRACTION —
/// the share of wall clock with bytes actually in flight (S174; under fan-out
/// this is the UNION of in-flight intervals, never a per-worker sum).
/// `concurrency == 1 && prepare_ahead == 0` is the retraction position and runs
/// the original serial loop verbatim.
///
/// 3b (S175): `concurrency` is how many parts are SENT at once. In-flight
/// memory is bounded by `(concurrency + prepare_ahead) × chunk` — the workers'
/// envelopes (N), the channel buffer (`prepare_ahead − 1`), and the one the
/// producer is sealing (+1). (Gus F1, S175: an earlier draft said `+ 1` on top
/// of that — an overcount in the safe direction, corrected to the exact bound.)
#[allow(clippy::too_many_arguments)]
fn upload_parts(
    in_path: &Path,
    dek: &[u8; 32],
    file_id: &[u8; 16],
    chunk_size: usize,
    chunk_count: u32,
    part_urls: &[Value],
    knobs: &http::TransferKnobs,
    governor: &mut TransferGovernor,
    prepare_ahead: usize,
    concurrency: usize,
) -> Result<(Vec<PartInput>, f64)> {
    // bug050 rider: keep the machine from idle-sleeping for as long as the
    // transfer runs (RAII — released when this function returns). Idle sleep
    // only; the screen lock stays the user's, and the transfer survives it.
    let _awake = crate::power::TransferAssertion::hold();

    // 3b (S175): "busy" under fan-out is the UNION of in-flight intervals — the
    // wall time with AT LEAST one part on the wire. Summing per-worker durations
    // would overcount overlap N-fold and report a busy_fraction above 1.
    struct BusyClock {
        in_flight: usize,
        since: Option<std::time::Instant>,
        total: std::time::Duration,
    }
    fn busy_begin(clock: &std::sync::Mutex<BusyClock>) {
        let mut c = clock.lock().expect("busy clock poisoned");
        if c.in_flight == 0 {
            c.since = Some(std::time::Instant::now());
        }
        c.in_flight += 1;
    }
    fn busy_end(clock: &std::sync::Mutex<BusyClock>) {
        let mut c = clock.lock().expect("busy clock poisoned");
        c.in_flight -= 1;
        if c.in_flight == 0
            && let Some(since) = c.since.take()
        {
            c.total += since.elapsed();
        }
    }

    // bug178 phase 2 (S174; kept under 3b): the SEND half. Whatever produced the
    // sealed envelope — the serial reader, the seal-ahead producer, a fan-out
    // worker — this fn is the ONLY place bytes go on the wire, so ceiling, epoch
    // stamp, penalty, observation and the busy clock have exactly one home.
    #[allow(clippy::too_many_arguments)]
    fn send_one(
        part_number: i32,
        url: &str,
        envelope: Vec<u8>,
        knobs: &http::TransferKnobs,
        governor: &std::sync::Mutex<&mut TransferGovernor>,
        clock: &std::sync::Mutex<BusyClock>,
        parts: &std::sync::Mutex<Vec<PartInput>>,
    ) -> Result<()> {
        // bug060: bound this attempt by what the MEASURED rate says the part
        // should take (k x bytes / rate), never by a fixed number of seconds.
        // `None` on the first part — with no estimate yet there is nothing to
        // derive a duration from, and the transport's rate-free no-progress gap
        // is already a complete dead-flow detector without one.
        //
        // 3a-i (S175): stamp the estimate's epoch at attempt start. Under
        // fan-out one link event trips N parts at once; the stamp is how the
        // governor answers the burst ONCE instead of N times. Serial behaviour
        // is unchanged (the epoch cannot advance between a serial stamp and its
        // penalty). Both reads under ONE lock acquisition.
        let (ceiling, stamp) = {
            let g = governor.lock().expect("governor poisoned");
            (g.ceiling(envelope.len()), g.generation())
        };
        busy_begin(clock);
        let started = std::time::Instant::now();
        let outcome = http::put_presigned(url, &envelope, knobs, ceiling);
        let elapsed = started.elapsed();
        busy_end(clock);
        match outcome {
            Ok(etag) => {
                governor
                    .lock()
                    .expect("governor poisoned")
                    .observe_part(envelope.len(), elapsed);
                parts
                    .lock()
                    .expect("parts poisoned")
                    .push(PartInput { part_number, etag });
                Ok(())
            }
            Err(e) => {
                // A stalled part means the estimate was too optimistic: retreat
                // fast (multiplicative decrease) so the retry — and every later
                // part — gets a proportionally wider allowance. The epoch stamp
                // makes a same-burst duplicate a no-op (3a-i, Rider 1: the
                // compare-and-halve is one critical section inside the
                // governor, never a caller-side check).
                governor
                    .lock()
                    .expect("governor poisoned")
                    .penalize_stall(stamp);
                Err(e)
            }
        }
    }

    let parts = std::sync::Mutex::new(Vec::with_capacity(part_urls.len()));
    let governor = std::sync::Mutex::new(governor);
    let clock = std::sync::Mutex::new(BusyClock {
        in_flight: 0,
        since: None,
        total: std::time::Duration::ZERO,
    });
    let wall_started = std::time::Instant::now();

    if concurrency <= 1 && prepare_ahead == 0 {
        // ⭐ THE RETRACTION POSITION IS THE ORIGINAL CODE PATH, not a
        // reimplementation that happens to behave the same. Setting the knob to 0
        // runs literally this loop — read, seal, send, repeat — so "retract"
        // cannot mean "a different serial implementation with its own bugs".
        let mut file = std::fs::File::open(in_path)
            .map_err(|e| CliError::input_read(format!("opening {}: {e}", in_path.display())))?;
        let mut buf = vec![0u8; chunk_size];
        for part in part_urls {
            let (part_number, url) = part_fields(part)?;
            let index = (part_number - 1) as u32;
            file.seek(SeekFrom::Start(index as u64 * chunk_size as u64))
                .map_err(|e| CliError::input_read(format!("seeking input: {e}")))?;
            let read = fill_chunk(&mut file, &mut buf)?;
            let envelope =
                signet_crypto::envelope::seal_chunk(dek, file_id, index, chunk_count, &buf[..read])
                    .map_err(|_| CliError::encryption_failed("chunk encryption failed"))?;
            send_one(part_number, url, envelope, knobs, &governor, &clock, &parts)?;
        }
    } else {
        // ⭐⭐ SEAL AHEAD + FAN OUT (S174 phase 2 + S175 3b). One producer thread
        // reads and seals; `concurrency` workers send. At concurrency == 1 this
        // is exactly the S174 pipeline (same channel capacity, same rendezvous
        // handoff, same serial sends); above 1 the workers overlap sends, and
        // the seal-ahead overlap comes free because the producer seals while
        // every worker is on the wire.
        //
        // ⚠ Bounded by construction: `sync_channel(prepare_ahead - 1)` blocks the
        // producer once it is that far ahead, so in-flight memory is
        // `(concurrency + prepare_ahead) × chunk` and cannot grow with file
        // size. The producer opens its OWN file handle rather than sharing a
        // seek cursor.
        //
        // ⚠ The S174 order cross-check is retired BY CONSTRUCTION, not dropped:
        // the (part_number, url, envelope) triple is now assembled at ONE site —
        // the producer, from one plan entry — so the mispairing the consumer
        // used to check for (plan position vs envelope order) has no assembly
        // point left to happen at. Workers legitimately complete out of order;
        // `parts` is sorted before finalize.
        let planned: Vec<(i32, String)> = part_urls
            .iter()
            .map(|p| part_fields(p).map(|(n, u)| (n, u.to_string())))
            .collect::<Result<_>>()?;
        let (tx, rx) = std::sync::mpsc::sync_channel::<Result<(i32, String, Vec<u8>)>>(
            prepare_ahead.saturating_sub(1),
        );
        // First error wins; every later worker becomes a DRAINER (see below).
        let first_error: std::sync::Mutex<Option<CliError>> = std::sync::Mutex::new(None);
        let abort = std::sync::atomic::AtomicBool::new(false);
        let record_error = |e: CliError| {
            let mut slot = first_error.lock().expect("error slot poisoned");
            if slot.is_none() {
                *slot = Some(e);
            }
            abort.store(true, std::sync::atomic::Ordering::Relaxed);
        };
        let plan_for_producer = planned.clone();
        // ⚠⚠ THE S174 DEADLOCK LESSON, generalised to N consumers (Gus F1, S174:
        // a producer parked in `send` with no receiver left is a silent hang on
        // exactly the bad-window path whose promise is an honest resumable
        // pause). Two guarantees close every path:
        //   1. The producer checks `abort` between parts and stops.
        //   2. A worker that errors NEVER just returns — it records the error,
        //      sets `abort`, and keeps DRAINING the channel until the producer
        //      closes it. A producer mid-`send` therefore always finds a
        //      receiver, finishes its current handoff, sees `abort`, and exits.
        //      `thread::scope` then joins everything.
        // (`rx` lives OUTSIDE the scope so worker borrows provably outlive it.)
        let rx = std::sync::Mutex::new(rx);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                let tx = tx; // owned: dropped on every exit path → channel closes
                let mut file = match std::fs::File::open(in_path) {
                    Ok(f) => f,
                    Err(e) => {
                        let _ = tx.send(Err(CliError::input_read(format!(
                            "opening {}: {e}",
                            in_path.display()
                        ))));
                        return;
                    }
                };
                let mut buf = vec![0u8; chunk_size];
                for (part_number, url) in &plan_for_producer {
                    if abort.load(std::sync::atomic::Ordering::Relaxed) {
                        return;
                    }
                    let index = (*part_number - 1) as u32;
                    let prepared = (|| -> Result<(i32, String, Vec<u8>)> {
                        file.seek(SeekFrom::Start(index as u64 * chunk_size as u64))
                            .map_err(|e| CliError::input_read(format!("seeking input: {e}")))?;
                        let read = fill_chunk(&mut file, &mut buf)?;
                        let envelope = signet_crypto::envelope::seal_chunk(
                            dek,
                            file_id,
                            index,
                            chunk_count,
                            &buf[..read],
                        )
                        .map_err(|_| CliError::encryption_failed("chunk encryption failed"))?;
                        Ok((*part_number, url.clone(), envelope))
                    })();
                    let failed = prepared.is_err();
                    // A closed channel means every worker exited; stop rather
                    // than seal the rest of the file for nobody.
                    if tx.send(prepared).is_err() || failed {
                        return;
                    }
                }
            });

            for _ in 0..concurrency.max(1) {
                scope.spawn(|| {
                    loop {
                        // Holding the lock across the blocking recv is the
                        // intended competing-consumer queue: the next worker
                        // takes the lock the moment this one has its item.
                        let item = rx.lock().expect("receiver poisoned").recv();
                        let Ok(item) = item else {
                            return; // producer done and channel drained
                        };
                        if abort.load(std::sync::atomic::Ordering::Relaxed) {
                            continue; // draining: keep the producer unblocked
                        }
                        match item {
                            Ok((part_number, url, envelope)) => {
                                if let Err(e) = send_one(
                                    part_number,
                                    &url,
                                    envelope,
                                    knobs,
                                    &governor,
                                    &clock,
                                    &parts,
                                ) {
                                    record_error(e);
                                }
                            }
                            Err(e) => record_error(e),
                        }
                    }
                });
            }
        });
        if let Some(e) = first_error.lock().expect("error slot poisoned").take() {
            return Err(e);
        }
        // The retired order-check's spirit, kept as a completeness assertion:
        // every exit path above either records an error or delivers every part,
        // so a shortfall here is a logic bug — checked rather than assumed,
        // because finalize would otherwise report it as a confusing server-side
        // missing-parts error long after the cause.
        let delivered = parts.lock().expect("parts poisoned").len();
        if delivered != part_urls.len() {
            return Err(CliError::invalid_data(format!(
                "upload fan-out delivered {delivered} of {} parts with no error recorded",
                part_urls.len()
            )));
        }
    }

    // ⭐⭐ THE CLI'S OWN IN-FLIGHT ACCOUNTING (S174). The relay emits
    // `effective_streams`, but the relay carries WEB uploads only — the CLI goes
    // direct to storage and never traverses it, so a single acceptance bar on
    // that metric would report clean on a surface it cannot see. This is the
    // CLI's equivalent: the fraction of wall clock with at least one part
    // actually in flight (an interval UNION, so fan-out cannot score above 1).
    let wall = wall_started.elapsed();
    let clock = clock.into_inner().expect("busy clock poisoned");
    let busy_fraction = if wall.as_secs_f64() > 0.0 {
        clock.total.as_secs_f64() / wall.as_secs_f64()
    } else {
        0.0
    };
    let mut parts = parts.into_inner().expect("parts poisoned");
    // Fan-out completes out of order; finalize gets a deterministic input.
    parts.sort_by_key(|p| p.part_number);
    Ok((parts, busy_fraction))
}

/// The CLI's compiled ceiling on upload seal-ahead (knob rule 1, S174).
///
/// ⚠ Higher than the web's 2: in-flight memory is `(1 + prepare_ahead) x
/// chunk_size` (64 MiB here at the ceiling), and a CLI carries that where a
/// browser tab already holds bug179's measured 489 MiB baseline.
const CLI_MAX_UPLOAD_PREPARE_AHEAD: i64 = 4;

/// How many upload parts to seal ahead, from the served knob.
///
/// ⭐ **Anything unusable ⇒ 0, i.e. exactly the pre-S174 serial seal-then-send** —
/// which on this surface is not merely equivalent behaviour but literally the
/// original loop (see `upload_parts`). An older server that omits the field, a
/// nonsense value, and a deliberate retraction all land there.
fn upload_prepare_ahead(response: &Value) -> usize {
    response
        .get("governor")
        .and_then(|g| g.get("upload_prepare_ahead"))
        .and_then(Value::as_i64)
        .unwrap_or(0)
        .clamp(0, CLI_MAX_UPLOAD_PREPARE_AHEAD) as usize
}

/// The CLI's compiled ceiling on upload part concurrency (knob rule 1, S175 —
/// 3b). Mirrors `CLI_MAX_DOWNLOAD_CONCURRENCY`: in-flight memory is
/// `(n + prepare_ahead) × chunk` (worst case 192 MiB at the ceilings), which a
/// CLI process carries comfortably; the web clamps lower (4) because a browser
/// tab already holds bug179's measured 489 MiB baseline.
const CLI_MAX_UPLOAD_CONCURRENCY: i64 = 8;

/// How many parts to SEND at once, from the served knob
/// (`governor.concurrency_upload`).
///
/// ⭐ **Anything unusable ⇒ 1, i.e. exactly the serial send path** — an older
/// server that omits the field, a nonsense value, and a deliberate retraction
/// all land on the same safe position (knob rule 4's off-position, exercised by
/// tests rather than declared). At 1, `upload_parts` runs LITERALLY the
/// pre-3b code paths, not a reimplementation that happens to behave the same.
fn upload_concurrency(response: &Value) -> usize {
    response
        .get("governor")
        .and_then(|g| g.get("concurrency_upload"))
        .and_then(Value::as_i64)
        .unwrap_or(1)
        .clamp(1, CLI_MAX_UPLOAD_CONCURRENCY) as usize
}

/// The `(part_number, url)` pair from a served part-url object. Extracted so the
/// serial and seal-ahead paths cannot disagree about how a plan is read.
fn part_fields(part: &serde_json::Value) -> Result<(i32, &str)> {
    let part_number =
        part.get("part_number")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| CliError::invalid_data("part url missing part_number"))? as i32;
    let url = part
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CliError::invalid_data("part url missing url"))?;
    Ok((part_number, url))
}

/// Read up to `buf.len()` bytes (a full chunk, or fewer at EOF for the last chunk);
/// returns the count read. A short `read` is not EOF, so this loops until the buffer
/// is full or the file ends.
fn fill_chunk(file: &mut std::fs::File, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = file
            .read(&mut buf[filled..])
            .map_err(|e| CliError::input_read(format!("reading input: {e}")))?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// Best-effort abort to free the quota reservation when an upload fails mid-flight.
/// Server-side abort of an in-flight multipart upload. Returns the call's
/// result so callers can make local-state deletion CONDITIONAL on a
/// DEMONSTRATED abort (bug050): the abort is itself a *signed* request, so it
/// shares failure modes with whatever the caller is recovering from (a locked
/// Secure Enclave, a dead network) — and an unconfirmed abort leaves the
/// server holding a resumable upload that the local state is the only record of.
fn abort_upload(
    keystore: &dyn Keystore,
    signing: &KeyLabel,
    server_url: &str,
    file_id: &Uuid,
    upload_id: &str,
) -> Result<()> {
    let path = format!("/v1/files/{file_id}/multipart/{upload_id}");
    http::delete_signed(keystore, signing, server_url, &path)
}

/// bug050: abort the upload and forget the local resume state — but the state
/// may only die on a demonstrated abort. If the abort did not confirmably
/// land, the server still holds the upload; the state file stays as the
/// truthful record (a later re-run resumes, or self-cleans via `/resume`
/// once the server has swept it; the idle-deadline sweep is the backstop).
fn abort_then_forget(
    keystore: &dyn Keystore,
    signing: &KeyLabel,
    server_url: &str,
    file_id: &Uuid,
    upload_id: &str,
) {
    match abort_upload(keystore, signing, server_url, file_id, upload_id) {
        Ok(()) => crate::upload_state::remove(&file_id.to_string()),
        Err(abort_error) => eprintln!(
            "signet: note: could not abort the upload ({abort_error}); it remains resumable. Re-run the same command to resume, or let it expire server-side"
        ),
    }
}

// ── File transport: signet download (§4.2 multipart, direct-from-storage) ────

/// `signet download` — fetch + decrypt a file to disk. The DEK is unwrapped with
/// the KEM key; the §4.2 multipart file is fetched chunk-by-chunk via Range reads of
/// its pre-signed GetObject URL (each chunk opened with AAD = file_id‖index) and
/// streamed straight to disk. Ports the web `Drive.downloadFile`. (The legacy
/// single-PUT §4.1 transport was retired in S042.)
#[allow(clippy::too_many_arguments)]
pub fn download(
    keystore: &dyn Keystore,
    path: Option<&str>,
    file_id: Option<&str>,
    out_path: &Path,
    signing_key: Option<&str>,
    kem_key: Option<&str>,
    server_url: &str,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    let signing_label = resolve_label(signing_key, Purpose::Signing, config)?;
    let kem_label = resolve_label(kem_key, Purpose::Kem, config)?;

    // bug050 rider: no idle sleep while a (possibly hours-long) download runs.
    let _awake = crate::power::TransferAssertion::hold();

    // Target file: a path resolves to a file id (walking its folder path); --file-id
    // is the precision fallback.
    let file_id = match (path, file_id) {
        (Some(_), Some(_)) => {
            return Err(CliError::invalid_args(
                "give a <path> or --file-id, not both",
            ));
        }
        (Some(p), None) => {
            let mut resolver = Resolver::new(keystore, &signing_label, &kem_label, server_url);
            resolver.resolve_file(p)?.file_id
        }
        (None, Some(id)) => parse_uuid_arg(id, "--file-id")?,
        (None, None) => return Err(CliError::invalid_args("give a <path> or --file-id")),
    };
    let file_id_bytes = *file_id.as_bytes();

    // Unwrap the file's DEK with my keystore keys (classical or hybrid,
    // dispatched on the envelope's alg — §5.2).
    let wd = http::get_json_signed(
        keystore,
        &signing_label,
        server_url,
        &format!("/v1/files/{file_id}/wrapped-dek"),
    )?;
    let wrapped_dek = wd
        .get("wrapped_dek")
        .ok_or_else(|| CliError::invalid_data("wrapped-dek response missing wrapped_dek"))?;
    let dek = unwrap_dek_value(keystore, wrapped_dek, &kem_label)?;

    // The pre-signed GetObject URL + the chunk metadata.
    let du = http::get_json_signed(
        keystore,
        &signing_label,
        server_url,
        &format!("/v1/files/{file_id}/download-url"),
    )?;
    let download_url = du
        .get("download_url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CliError::invalid_data("download-url response missing download_url"))?;
    let size_bytes = du
        .get("size_bytes")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| CliError::invalid_data("download-url response missing size_bytes"))?
        .max(0) as u64;
    let multipart_chunks = du.get("multipart_chunks").and_then(|v| v.as_i64());
    let chunk_size = du.get("chunk_size").and_then(|v| v.as_i64());

    // bug180: write to a TEMP path and rename on success, so a failed download
    // can never leave a truncated file under the name the caller asked for.
    //
    // ⚠ THE FAILURE THIS REMOVES: every `?` in the chunk loop below returns
    // immediately, and nothing used to remove the partial. The bytes on disk
    // were not corrupt — each chunk had passed its AEAD open — so what a PRSN
    // got was VALID, VERIFIED AND SHORT, which is exactly the failure a
    // checksum-free consumer cannot detect. The exit code was non-zero, but a
    // harness that pipes the file onward never sees it.
    //
    // ⭐ Sibling temp in the SAME directory so the rename stays on one
    // filesystem (a cross-device rename is a copy, and would reintroduce a
    // window where the real name exists and is short). `std::fs::rename` is
    // atomic on POSIX: the requested path either does not exist, or names a
    // complete file. There is no observable intermediate state.
    //
    // This is the CLI half of the same semantic bug179 gives the web (commit
    // only on success — there via the writable's close()/abort()).
    let tmp_path = download_temp_path(out_path);
    // bug180 (S172, Chris ruled option 3): a pre-existing temp means an EARLIER
    // download of this target was interrupted. `File::create` truncates, so the
    // stale bytes were already harmless — verified live at S172, where a 16 MiB
    // orphan left by a SIGTERM was consumed by the next run and the output was
    // byte-identical. ⭐ What was missing is not cleanup, it is SAYING SO: a
    // silent reuse leaves the operator with no signal that a prior attempt died.
    // Cheap, honest, and it costs nothing on the normal path (ROOTS §B-3.7 — a
    // control's own behaviour should report itself).
    if let Ok(meta) = std::fs::metadata(&tmp_path) {
        eprintln!(
            "note: discarding {} bytes from an earlier interrupted download ({})",
            meta.len(),
            tmp_path.display()
        );
    }
    let file = std::fs::File::create(&tmp_path)
        .map_err(|e| CliError::output_write(format!("creating {}: {e}", tmp_path.display())))?;
    // RAII, not hand-written cleanup at each `?`: the loop below has several
    // early returns and will grow more. A guard covers every one of them —
    // including the ones nobody has written yet — which is the difference
    // between making the wrong thing impossible and remembering to detect it.
    let mut tmp_guard = TempFileGuard(Some(tmp_path.clone()));
    // bug083: report the bytes actually WRITTEN (the plaintext), named to match
    // upload's `plaintext_bytes`. The old output surfaced the transport's
    // ciphertext `size_bytes` under a name a scripting PRSN reads as the file's
    // length — a false mismatch waiting to happen.
    let plaintext_written: u64;

    match (multipart_chunks, chunk_size) {
        // §4.2 multipart: Range-GET each on-disk chunk, open it, stream to disk.
        (Some(chunks), Some(csize)) => {
            let chunk_count = chunks.max(0) as u32;
            let ranges = chunk_ranges(chunk_count, csize.max(0) as u64, size_bytes);
            let n = download_concurrency(du.get("concurrency").and_then(|v| v.as_i64()));

            // bug193 (S176): fetch chunks through a SLIDING WINDOW of `n` workers,
            // write each at its own offset. Rewrites the S174 rounds loop.
            //
            // ⚠ THE ROUNDS DESIGN THIS REPLACES WAS JUSTIFIED BY A MEASUREMENT
            // ARTIFACT, recorded here so the reasoning isn't re-derived: the old
            // comment cited "saturates at ~2.09x regardless of n" — that ceiling
            // was short-transfer TCP ramp (killed by the S175 boto3-on-1GiB pair,
            // 633 Mbps on the same path), and the round barrier it justified was
            // measured at S176 costing ~26% of wall clock on the sibling web path
            // (effective parallelism 2.41x vs the sliding upload path's 3.86x).
            // Every round cost its slowest member; a fast chunk's freed slot sat
            // idle. Owner: bug193 + Download-Loop-Rewrite v03 §2.
            //
            // ⭐ POSITIONED WRITES SUPERSEDE THE OLD IN-ORDER-APPEND RATIONALE,
            // CONSCIOUSLY (v03; Gus's acceptance assertion). The old loop appended
            // in order so an interrupted temp stayed SHORT rather than full-size-
            // with-holes. Under positioned writes the holey shape can exist — but
            // only ever under the `.part` temp name: the rename gate below is the
            // single commit point (bug180), the RAII guard deletes the temp on
            // every error path, and a signal-path survivor is discarded with a
            // notice on the next run. The acceptance campaign OBSERVES the
            // interrupted temp staying un-renamed rather than assuming it.
            // (The discard notice reports the temp's apparent length, which for a
            // holey file overstates the bytes actually fetched — cosmetic, known.)
            //
            // ⭐ Memory stays bounded at `n × chunk`: at most `n` plaintexts exist
            // at once, one per in-flight worker; completion order is free because
            // each lands at `index × chunk_size` (PLAINTEXT space — `chunk_ranges`
            // owns the plaintext↔stored boundary via MULTIPART_CHUNK_OVERHEAD,
            // the one derivation site; Gus F1's class).
            //
            // ⭐ THE WORK QUEUE CANNOT DEADLOCK BY CONSTRUCTION (Gus, S176): the
            // whole plan is materialized up front and workers take items with an
            // atomic cursor — his pre-filled-channel shape realized with even less
            // machinery. There is no producer, no send, nothing to block on; the
            // S174 upload-deadlock class is unrepresentable here, not guarded
            // against. First error records itself and trips `abort`; the other
            // workers finish their current chunk and exit; a completeness
            // assertion refuses to fall through with silent gaps.
            let indexed: Vec<(usize, (u64, u64))> = ranges.into_iter().enumerate().collect();
            let plain_stride = csize.max(0) as u64;
            // 1c (S175): one download-scoped connection pool, shared by the
            // round workers. Healthy connections carry chunk after chunk
            // (dropping the per-chunk TCP+TLS+slow-start tax the reference
            // client never paid — measured 2.65× against boto3 on the same
            // 1 GiB objects); a connection that fails in ANY way is evicted and
            // the retry is a genuinely fresh flow. Dropping the pool at the end
            // of the download closes every idle socket.
            //
            // ⚠ The pool exists ONLY at n > 1, deliberately: 1c has no knob of
            // its own, so `transfer_concurrency_download = 1` must retract BOTH
            // behaviours — at n = 1 this is the pre-1c serial path exactly, one
            // fresh connection per chunk attempt (knob rule 4's off-position;
            // the deployment.md retraction row states this coupling).
            use std::sync::Mutex;
            use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
            let done = AtomicUsize::new(0);
            let written = AtomicU64::new(0);
            // v03 §6-1: per-chunk start/done instants, env-gated (SIGNET_TRANSFER_TRACE=1),
            // never default output — the acceptance campaign's scheduling check reads these
            // (pass = next start follows the FIRST completion). The monitoring spec owns
            // anything emitted permanently; this is a debug instrument, not telemetry.
            let trace = std::env::var_os("SIGNET_TRANSFER_TRACE").is_some();
            let t0 = std::time::Instant::now();
            // ⚠⚠ THE PRE-SIGNED URL EXPIRES MID-DOWNLOAD ON A LARGE FILE (S185;
            // bug211 §7-3's CLI twin — the web half shipped in v0.5.47). The URL
            // minted above carries `X-Amz-Expires=3600`, so holding it for the
            // whole transfer silently declares a MINIMUM BANDWIDTH of
            // size ÷ 3600 s (ROOTS §B-3.4: a wall-clock constant bounding a
            // bytes÷rate quantity; ~288 GB ceiling at the 80 MB/s we measured,
            // proportionally lower on the slow links that are our named user
            // class, bug047/bug060/bug211).
            //
            // Unlike the web (where S3's CORS-less 403 arrives as a bare
            // TypeError), THIS surface sees the real 403 — so the remedy is
            // REACTIVE, per Gus's S184 ruling: run the chunk loop in
            // GENERATIONS. A generation that aborts on `presigned_rejected`
            // re-requests a fresh URL from the server (on this thread — the
            // keystore is never touched from workers, same as today) and the
            // next generation resumes over ONLY the chunks not yet completed.
            //
            // ⛔ The give-up bound is PROGRESS-CONDITIONED, not a count or a
            // clock: refreshes are unlimited while chunks are completing (a
            // transfer needs ~1 refresh per hour of wall time, and how many
            // hours a download takes is exactly what we must not bound), and a
            // small budget only caps CONSECUTIVE no-progress refreshes — the
            // revoked-access case, where the server happily mints URLs that
            // storage then rejects. Rate-free by construction.
            let mut current_url: String = download_url.to_string();
            let completed_chunks: Vec<AtomicBool> =
                (0..indexed.len()).map(|_| AtomicBool::new(false)).collect();
            let mut stale_refreshes: u32 = 0;
            loop {
                let pending: Vec<(usize, (u64, u64))> = indexed
                    .iter()
                    .filter(|(i, _)| !completed_chunks[*i].load(Ordering::Acquire))
                    .copied()
                    .collect();
                if pending.is_empty() {
                    break;
                }
                let done_before = done.load(Ordering::Acquire);
                // 1c pool per GENERATION, rebuilt after every refresh: flows
                // opened after a rejected signature should be genuinely fresh
                // (bug047's per-flow re-roll — the same rule that already makes
                // retries bypass the pool).
                let pool = (n > 1).then(crate::bucket_transport::DownloadPool::new);
                let cursor = AtomicUsize::new(0);
                let abort = AtomicBool::new(false);
                let first_err: Mutex<Option<CliError>> = Mutex::new(None);
                let workers = n.min(pending.len()).max(1);
                let url: &str = current_url.as_str();
                std::thread::scope(|scope| {
                    for _ in 0..workers {
                        scope.spawn(|| {
                        loop {
                            if abort.load(Ordering::Acquire) {
                                break;
                            }
                            let slot = cursor.fetch_add(1, Ordering::Relaxed);
                            let Some(&(index, (start, end))) = pending.get(slot) else {
                                break;
                            };
                            if trace {
                                eprintln!(
                                    "transfer-trace: chunk {index} start +{}ms",
                                    t0.elapsed().as_millis()
                                );
                            }
                            // A panicking worker must surface as an error, not take
                            // the process down mid-download: the temp guard still
                            // needs to run (same contract as the rounds loop had).
                            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                                || -> Result<u64> {
                                    let envelope = match pool.as_ref() {
                                        Some(p) => http::get_presigned_range_pooled(
                                            p, url, start, end,
                                        )?,
                                        None => http::get_presigned_range(url, start, end)?,
                                    };
                                    // Verify BEFORE any byte reaches disk (bug061's
                                    // ordering): open_chunk authenticates; only its
                                    // plaintext is ever written.
                                    let plaintext = signet_crypto::envelope::open_chunk(
                                        &dek,
                                        &file_id_bytes,
                                        index as u32,
                                        chunk_count,
                                        &envelope,
                                    )?;
                                    write_plaintext_at(
                                        &file,
                                        &plaintext,
                                        index as u64 * plain_stride,
                                    )
                                    .map_err(|e| {
                                        CliError::output_write(format!("writing output: {e}"))
                                    })?;
                                    Ok(plaintext.len() as u64)
                                },
                            ));
                            match outcome {
                                Ok(Ok(len)) => {
                                    completed_chunks[index].store(true, Ordering::Release);
                                    written.fetch_add(len, Ordering::Relaxed);
                                    done.fetch_add(1, Ordering::Relaxed);
                                    if trace {
                                        eprintln!(
                                            "transfer-trace: chunk {index} done +{}ms",
                                            t0.elapsed().as_millis()
                                        );
                                    }
                                }
                                Ok(Err(e)) => {
                                    let mut slot = first_err.lock().unwrap();
                                    if slot.is_none() {
                                        *slot = Some(e);
                                    }
                                    abort.store(true, Ordering::Release);
                                    break;
                                }
                                Err(_panic) => {
                                    let mut slot = first_err.lock().unwrap();
                                    if slot.is_none() {
                                        *slot = Some(CliError::invalid_data(
                                            "a download worker thread panicked; output incomplete",
                                        ));
                                    }
                                    abort.store(true, Ordering::Release);
                                    break;
                                }
                            }
                        }
                    });
                    }
                });
                match first_err.into_inner().unwrap() {
                    // No error this generation: the next `pending` rebuild is
                    // empty and the loop exits through the break above.
                    None => {}
                    Some(e) if e.code == "presigned_rejected" => {
                        let progressed = done.load(Ordering::Acquire) > done_before;
                        if !presigned_refresh_decision(progressed, &mut stale_refreshes) {
                            // The server keeps minting URLs that storage keeps
                            // rejecting with zero chunks landing — that is not
                            // expiry, it is access genuinely gone (or storage
                            // auth broken). Fail honestly with the real cause.
                            return Err(CliError::new(
                                31,
                                "network_error",
                                format!(
                                    "storage rejected the pre-signed URL \
                                     {PRESIGNED_STALE_REFRESH_BUDGET} consecutive times with no \
                                     chunk completing, retries on freshly-requested URLs \
                                     included. This is not expiry; giving up (last: {})",
                                    e.message
                                ),
                            ));
                        }
                        // Mint a fresh URL on THIS thread (the keystore is never
                        // touched from workers). A server refusal here escapes
                        // as its own honest error (e.g. authorization_denied).
                        let du = http::get_json_signed(
                            keystore,
                            &signing_label,
                            server_url,
                            &format!("/v1/files/{file_id}/download-url"),
                        )?;
                        let fresh =
                            du.get("download_url")
                                .and_then(|v| v.as_str())
                                .ok_or_else(|| {
                                    CliError::invalid_data(
                                        "download-url refresh response missing download_url",
                                    )
                                })?;
                        current_url = fresh.to_string();
                        eprintln!(
                            "signet: storage rejected the download URL (HTTP 403, likely expired \
                             mid-transfer); fetched a fresh one, resuming {} remaining chunk(s)",
                            indexed.len() - done.load(Ordering::Acquire)
                        );
                    }
                    Some(e) => return Err(e),
                }
            }
            // Completeness assertion (v03 §2): no error was recorded, so every
            // chunk must be accounted for. Falling through with silent gaps is the
            // failure mode a green gate cannot see — refuse it loudly.
            let completed = done.load(Ordering::Acquire);
            if completed != indexed.len() {
                return Err(CliError::invalid_data(format!(
                    "download completeness assertion failed: {completed} of {} chunks written \
                     with no error recorded",
                    indexed.len()
                )));
            }
            plaintext_written = written.load(Ordering::Acquire);
        }
        // No §4.2 chunk metadata: not a multipart file. The legacy single-PUT (§4.1)
        // transport was retired (S042), so this should not occur for a live file.
        _ => {
            return Err(CliError::invalid_data(
                "download-url returned no multipart chunk metadata (the single-PUT transport is retired)",
            ));
        }
    }
    // bug180: close the handle BEFORE the rename (Windows refuses to rename an
    // open file; POSIX allows it, and relying on that would make this correct
    // on one platform by accident). Positioned writes go straight to the file —
    // there is no userspace buffer left to flush.
    drop(file);
    // The commit point. Only here does the requested name come into existence,
    // and only with a complete file behind it.
    std::fs::rename(&tmp_path, out_path).map_err(|e| {
        CliError::output_write(format!(
            "renaming {} to {}: {e}",
            tmp_path.display(),
            out_path.display()
        ))
    })?;
    // Disarm AFTER the rename succeeds: if the rename fails, the guard still
    // removes the temp rather than stranding it.
    tmp_guard.disarm();

    out.print_json(&serde_json::json!({
        "file_id": file_id.to_string(),
        "out": out_path.display().to_string(),
        "plaintext_bytes": plaintext_written,
    }))
}

/// How many CONSECUTIVE no-progress URL REJECTIONS the download loop tolerates
/// before giving up (S185, bug211 §7-3's CLI twin). The unit is rejections, not
/// refreshes: the counter increments per rejected generation, so a budget of 3
/// grants exactly 2 fresh URLs (the boundary test pins BUDGET−1) — the first
/// rejection arrives on the original URL. (Gus's review caught this line saying
/// "refreshes" while the code and its own test counted rejections — the A7
/// class again, a derivation comment disagreeing with the mechanism it
/// documents, this time inside the fix for that class's sibling.)
///
/// The bound is deliberately on consecutive-without-progress, never on total
/// refreshes: a legitimate transfer needs roughly one refresh per hour of wall
/// time, and how many hours a download takes is exactly the quantity ROOTS
/// §B-3.4 forbids bounding. What this cap catches is the OTHER cause of a 403 —
/// access genuinely revoked (or storage auth broken), where the server mints
/// URLs that storage rejects forever and no chunk ever lands. 3 covers a
/// refresh racing a revocation plus one repeat for an unlucky in-flight window,
/// without stretching an honest failure past ~three round-trips.
const PRESIGNED_STALE_REFRESH_BUDGET: u32 = 3;

/// Decide whether a chunk-loop generation that aborted on `presigned_rejected`
/// earns a fresh URL (`true`) or ends the download (`false`).
///
/// Exported as a real function so the test pins the SHIPPED decision, not a
/// replica of its shape (the bug190 rule: a replica test passes happily while
/// the wiring drifts). `progressed` = at least one chunk completed since the
/// last refresh; it RESETS the consecutive counter — that reset is the whole
/// §B-3.4 argument, so it is the thing the test must hold.
pub(crate) fn presigned_refresh_decision(progressed: bool, stale_refreshes: &mut u32) -> bool {
    if progressed {
        *stale_refreshes = 0;
        return true;
    }
    *stale_refreshes += 1;
    *stale_refreshes < PRESIGNED_STALE_REFRESH_BUDGET
}

/// The CLI's compiled ceiling on download concurrency (knob rule 1, S174).
///
/// ⚠ **An unclamped served value is a DoS switch pointed at our own users**, and
/// the ceiling is per-surface because the cost is: in-flight memory is
/// `N × chunk`, so 8 × 16 MiB = 128 MiB here. A CLI can carry that; the web
/// surface clamps lower because bug179 measured a 489 MiB renderer baseline
/// before any concurrency at all.
const CLI_MAX_DOWNLOAD_CONCURRENCY: i64 = 8;

/// Resolve how many chunks to fetch at once from the served knob.
///
/// ⭐ **Absent ⇒ 1, i.e. exactly today's serial behaviour.** An older server that
/// does not serve the field, a malformed value, or a deliberate retraction all
/// land on the same safe position rather than on a guess. That is knob rule 4's
/// off-position, and it is exercised by tests rather than declared.
fn download_concurrency(served: Option<i64>) -> usize {
    served
        .unwrap_or(1)
        .clamp(1, CLI_MAX_DOWNLOAD_CONCURRENCY)
        .max(1) as usize
}

/// bug180: the sibling temp path a download is written to before its
/// rename-on-success. Same directory as the target, so the rename stays on one
/// filesystem and remains atomic.
///
/// The `.part` suffix is APPENDED to the whole filename rather than replacing
/// the extension: `report.pdf` → `report.pdf.part`, never `report.part`. That
/// keeps the temp obviously associated with its target, and — more importantly
/// — cannot collide with a real sibling file the caller owns.
fn download_temp_path(out_path: &std::path::Path) -> std::path::PathBuf {
    let mut name = out_path.file_name().unwrap_or_default().to_os_string();
    name.push(".part");
    out_path.with_file_name(name)
}

/// bug180: removes the partial download on drop unless disarmed.
///
/// RAII rather than cleanup at each error site: the download loop has several
/// early returns today and will acquire more, and a hand-written `remove_file`
/// per `?` is a control that silently stops covering the paths added after it.
/// Drop covers every return, including a panic.
struct TempFileGuard(Option<std::path::PathBuf>);

impl TempFileGuard {
    /// Called only once the temp has been renamed into place.
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            // Best-effort: the download already failed, and a cleanup failure
            // must not mask the real error the caller is about to see.
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Positioned write of a whole buffer at `offset`, platform-portable (bug193's
/// sliding-window download lands each verified chunk at `index × chunk_size`).
/// Unix `write_all_at` loops internally; Windows `seek_write` does not, so the
/// loop is written out — a partial positioned write silently dropped would be a
/// torn chunk that reads as valid length.
#[cfg(unix)]
fn write_plaintext_at(file: &std::fs::File, buf: &[u8], offset: u64) -> std::io::Result<()> {
    std::os::unix::fs::FileExt::write_all_at(file, buf, offset)
}
#[cfg(windows)]
fn write_plaintext_at(
    file: &std::fs::File,
    mut buf: &[u8],
    mut offset: u64,
) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !buf.is_empty() {
        let n = file.seek_write(buf, offset)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "seek_write wrote 0 bytes",
            ));
        }
        buf = &buf[n..];
        offset += n as u64;
    }
    Ok(())
}

/// The download Range boundaries for a §4.2 file: each on-disk chunk is
/// `chunk_size + MULTIPART_CHUNK_OVERHEAD` bytes, the last running to
/// `size_bytes - 1`. Inclusive `[start, end]` per chunk. Mirrors the web
/// `Drive.downloadFile` so the two surfaces step over identical boundaries.
fn chunk_ranges(multipart_chunks: u32, chunk_size: u64, size_bytes: u64) -> Vec<(u64, u64)> {
    let on_disk = chunk_size + MULTIPART_CHUNK_OVERHEAD as u64;
    let last = size_bytes.saturating_sub(1);
    (0..multipart_chunks)
        .map(|i| {
            let start = i as u64 * on_disk;
            let end = if i < multipart_chunks - 1 {
                start + on_disk - 1
            } else {
                last
            };
            (start, end)
        })
        .collect()
}

// ── Share (Increment 3): the thin surface ────────────────────────────────────
//
// list / recipients / preview / accept / remove / leave + recipient-key
// resolution. Mostly signed calls; the only crypto is name-decryption on `share
// list` (reusing the resolver's metadata-key path). `share invite` (the heavy,
// recursive DEK re-wrap) is built on top of `resolve_recipient_pubkey` here.

/// Extract + parse a required UUID string field from a JSON object.
fn json_uuid(v: &Value, field: &str) -> Result<Uuid> {
    v.get(field)
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
        .ok_or_else(|| CliError::invalid_data(format!("response missing/invalid {field}")))
}

/// Extract + parse an optional UUID string field (absent or null → `None`).
fn json_opt_uuid(v: &Value, field: &str) -> Option<Uuid> {
    v.get(field)
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
}

/// Resolve a recipient handle to its **verified** KEM public-key bytes: a signed
/// `GET /v1/recipients/{handle}` → the full verified-source resolution
/// (F-DOWNGRADE a+b: P-011 + §8.5 fingerprints, mandatory hybrid, and the keys
/// verified against the recipient's identity record — attestation for a PRSN,
/// §10a log receipts for a human — before any secret is wrapped to them).
/// Shared by `recipient` (surfacing the key for out-of-band verification) and
/// `share invite` (wrapping the metadata key + DEKs to it). Returns the
/// verified key bytes + the raw response.
fn resolve_recipient_pubkey(
    keystore: &dyn Keystore,
    signing: &KeyLabel,
    server_url: &str,
    handle: &str,
) -> Result<(RecipientWrapKeys, Value)> {
    let resp = http::get_json_signed(
        keystore,
        signing,
        server_url,
        &format!("/v1/recipients/{handle}"),
    )?;
    let trust = crate::recipient_verify::ServerTrust::fetch(server_url)?;
    // F-PIN1: `handle` is the user-typed name — the bundle's echo must match it.
    let keys = crate::recipient_verify::verified_wrap_keys(
        &trust,
        server_url,
        &resp,
        crate::recipient_verify::HandleExpectation::UserNamed(handle),
        &format!("recipient '{handle}'"),
    )?;
    Ok((keys, resp))
}

/// `signet recipient <handle>` — resolve + verify a recipient's KEM public key
/// (P-011) and print `{handle, account_type, kem_pubkey, kem_pubkey_fingerprint}`.
/// For out-of-band key verification before sharing.
pub fn recipient(
    keystore: &dyn Keystore,
    handle: &str,
    signing_key: Option<&str>,
    server_url: &str,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    let signing = resolve_label(signing_key, Purpose::Signing, config)?;
    let (_pubkey, resp) = resolve_recipient_pubkey(keystore, &signing, server_url, handle)?;
    out.print_json(&resp)
}

/// A share folder shared with me, name-decrypted for display.
// `Debug` so a failing degrade test can print what it actually got — an assertion that
// cannot show the wrong value costs a round-trip to diagnose (S163).
#[derive(Serialize, Debug)]
struct ShareEntry {
    /// The decrypted folder name, or `null` if its metadata key couldn't be resolved.
    name: Option<String>,
    folder_id: Uuid,
    root_folder_id: Uuid,
    permission: String,
}

/// Build the `ShareEntry` rows from an already-fetched `/v1/shared-with-me` payload,
/// decrypting each name and **degrading the row, never the listing**, when one cannot be
/// read (bug139's property on the share surface — the third of three listing homes).
///
/// ⚠ **Extracted from [`share_list`] so the degrade is OBSERVABLE (Gus, S163).** The first
/// version of the test could only assert `share_list(...).is_ok()`, and Gus's review caught
/// that this cannot tell `[2 rows, names null]` from `[0 rows]` — so a degrade that silently
/// *dropped* undecryptable rows, or an empty-but-Ok listing, would both have passed while the
/// doc-comment claimed "one poisoned share never hides the others". An assertion that cannot
/// see the harm it documents is the bug140 shape. Returning the rows makes the claim checkable.
///
/// Pure over its inputs: no I/O of its own beyond the resolver's per-root key fetch, so a test
/// can pre-seed the resolver's cache and drive both a decryptable and an undecryptable row
/// through it in one pass.
fn share_entries(resolver: &mut Resolver<'_>, folders: &[Value]) -> Result<Vec<ShareEntry>> {
    let mut entries = Vec::with_capacity(folders.len());
    for f in folders {
        let folder_id = json_uuid(f, "folder_id")?;
        // A top-level share folder is its own root; the view's field is nullable.
        let root = json_opt_uuid(f, "root_folder_id").unwrap_or(folder_id);
        let permission = f
            .get("permission")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let name = match f.get("encrypted_name") {
            Some(enc) => match resolver.decrypt_name(root, folder_id, enc) {
                Ok(n) => Some(n),
                Err(e) => {
                    eprintln!(
                        "signet: could not decrypt name for share folder {folder_id}: {}",
                        e.message
                    );
                    None
                }
            },
            None => None,
        };
        entries.push(ShareEntry {
            name,
            folder_id,
            root_folder_id: root,
            permission,
        });
    }
    Ok(entries)
}

/// `signet share list` — the share folders I'm a recipient of ("shared with me"),
/// decrypting each name with my recipient metadata-key wrap (the route is
/// folder-type-agnostic + recipient-keyed, so it returns *my* wrap). Tabular by
/// default; `--json` for machine output. A name that can't be decrypted is surfaced
/// as `null` / `(name unavailable)` with a stderr note — one bad entry never hides
/// the rest.
#[allow(clippy::too_many_arguments)]
pub fn share_list(
    keystore: &dyn Keystore,
    json: bool,
    signing_key: Option<&str>,
    kem_key: Option<&str>,
    server_url: &str,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    let signing = resolve_label(signing_key, Purpose::Signing, config)?;
    let kem = resolve_label(kem_key, Purpose::Kem, config)?;
    // bug130 (F-12): `share list` shows folders shared WITH me, which now has its own path.
    let resp = http::get_json_signed(keystore, &signing, server_url, "/v1/shared-with-me")?;
    let folders = resp
        .get("folders")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut resolver = Resolver::new(keystore, &signing, &kem, server_url);
    let entries = share_entries(&mut resolver, &folders)?;

    if json {
        return out.print_json(&entries);
    }
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{:<28} {:<36} PERMISSION", "NAME", "FOLDER_ID").map_err(write_err)?;
    for e in &entries {
        let name = e.name.as_deref().unwrap_or("(name unavailable)");
        writeln!(stdout, "{:<28} {:<36} {}", name, e.folder_id, e.permission).map_err(write_err)?;
    }
    Ok(())
}

/// `signet share recipients (<path>|--folder-id <ID>)` — list a share folder's
/// recipients (handle, permission, mandatory-Guardian flag, account id). No crypto.
/// Tabular by default; `--json` for the raw response.
#[allow(clippy::too_many_arguments)]
pub fn share_recipients(
    keystore: &dyn Keystore,
    path: Option<&str>,
    folder_id: Option<&str>,
    json: bool,
    signing_key: Option<&str>,
    kem_key: Option<&str>,
    server_url: &str,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    let signing = resolve_label(signing_key, Purpose::Signing, config)?;
    let kem = resolve_label(kem_key, Purpose::Kem, config)?;
    let mut resolver = Resolver::new(keystore, &signing, &kem, server_url);
    let (folder, _root) = resolve_folder_target(&mut resolver, path, folder_id, None)?;

    let resp = http::get_json_signed(
        keystore,
        &signing,
        server_url,
        &format!("/v1/share-folders/{folder}/recipients"),
    )?;
    if json {
        return out.print_json(&resp);
    }
    let recipients = resp
        .get("recipients")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut stdout = std::io::stdout().lock();
    writeln!(
        stdout,
        "{:<24} {:<12} {:<9} ACCOUNT_ID",
        "HANDLE", "PERMISSION", "GUARDIAN"
    )
    .map_err(write_err)?;
    for r in &recipients {
        let handle = r
            .get("handle")
            .and_then(Value::as_str)
            .unwrap_or("(unknown)");
        let permission = r.get("permission").and_then(Value::as_str).unwrap_or("");
        let guardian = if r
            .get("is_mandatory_guardian")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            "yes"
        } else {
            "no"
        };
        let account_id = r
            .get("recipient_account_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        writeln!(
            stdout,
            "{handle:<24} {permission:<12} {guardian:<9} {account_id}"
        )
        .map_err(write_err)?;
    }
    Ok(())
}

/// `signet share preview --token <T>` — preview an invitation addressed to me
/// (inviter, permission, file count, timing). No crypto; never the folder/file names.
pub fn share_preview(
    keystore: &dyn Keystore,
    token: &str,
    signing_key: Option<&str>,
    server_url: &str,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    let signing = resolve_label(signing_key, Purpose::Signing, config)?;
    let resp = http::get_json_signed(
        keystore,
        &signing,
        server_url,
        &format!("/v1/invitations/{token}"),
    )?;
    out.print_json(&resp)
}

/// `signet share accept --token <T>` — accept an invitation; the server activates
/// the pre-staged metadata-key + per-file DEK wraps in one transaction. No client
/// crypto. Prints `{share_folder_id, permission, files_granted}`.
pub fn share_accept(
    keystore: &dyn Keystore,
    token: &str,
    signing_key: Option<&str>,
    server_url: &str,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    let signing = resolve_label(signing_key, Purpose::Signing, config)?;
    let text = http::post_signed(
        keystore,
        &signing,
        server_url,
        &format!("/v1/invitations/{token}/accept"),
    )?;
    let resp: Value = serde_json::from_str(&text)
        .map_err(|e| CliError::invalid_data(format!("server returned invalid JSON: {e}")))?;
    out.print_json(&resp)
}

/// `signet share invitations (<path>|--folder-id <ID>)` — the owner's view of a
/// share folder's PENDING invitations (S121, W6; parity with the web dialog's
/// pending list). The server never re-serves the invitation's bearer link —
/// it is shown exactly once, at `share invite`; a lost link is `share
/// cancel-invite` + a fresh `share invite`.
#[allow(clippy::too_many_arguments)]
pub fn share_invitations(
    keystore: &dyn Keystore,
    path: Option<&str>,
    folder_id: Option<&str>,
    json: bool,
    signing_key: Option<&str>,
    kem_key: Option<&str>,
    server_url: &str,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    let signing = resolve_label(signing_key, Purpose::Signing, config)?;
    let kem = resolve_label(kem_key, Purpose::Kem, config)?;
    let mut resolver = Resolver::new(keystore, &signing, &kem, server_url);
    let (folder, _root) = resolve_folder_target(&mut resolver, path, folder_id, None)?;

    let resp = http::get_json_signed(
        keystore,
        &signing,
        server_url,
        &format!("/v1/share-folders/{folder}/invitations"),
    )?;
    if json {
        return out.print_json(&resp);
    }
    let invitations = resp
        .get("invitations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut stdout = std::io::stdout().lock();
    writeln!(
        stdout,
        "{:<24} {:<12} {:<20} INVITATION_ID",
        "RECIPIENT", "PERMISSION", "EXPIRES_AT"
    )
    .map_err(write_err)?;
    for i in &invitations {
        let handle = i
            .get("recipient_handle")
            .and_then(Value::as_str)
            .unwrap_or("—");
        let permission = i.get("permission").and_then(Value::as_str).unwrap_or("—");
        let expires = i.get("expires_at").and_then(Value::as_i64).unwrap_or(0);
        let id = i
            .get("invitation_id")
            .and_then(Value::as_str)
            .unwrap_or("—");
        writeln!(
            stdout,
            "{handle:<24} {permission:<12} {:<20} {id}",
            table_ts(expires)
        )
        .map_err(write_err)?;
    }
    Ok(())
}

/// `signet share cancel-invite (<path>|--folder-id <ID>) --invitation-id <ID>` —
/// the owner cancels a PENDING invitation: the folder's writes resume and the
/// invitation's one-time link stops working. Ids come from `share invitations`.
#[allow(clippy::too_many_arguments)]
pub fn share_cancel_invite(
    keystore: &dyn Keystore,
    path: Option<&str>,
    folder_id: Option<&str>,
    invitation_id: &str,
    signing_key: Option<&str>,
    kem_key: Option<&str>,
    server_url: &str,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    let signing = resolve_label(signing_key, Purpose::Signing, config)?;
    let kem = resolve_label(kem_key, Purpose::Kem, config)?;
    let mut resolver = Resolver::new(keystore, &signing, &kem, server_url);
    let (folder, _root) = resolve_folder_target(&mut resolver, path, folder_id, None)?;
    let iid = parse_uuid_arg(invitation_id, "--invitation-id")?;
    http::delete_signed(
        keystore,
        &signing,
        server_url,
        &format!("/v1/share-folders/{folder}/invitations/{iid}"),
    )?;
    out.print_json(&serde_json::json!({
        "share_folder_id": folder,
        "canceled_invitation_id": iid,
    }))
}

/// `signet share remove (<path>|--folder-id <ID>) --recipient-id <ACCOUNT_ID>` — the
/// owner removes a recipient (their recipient row + metadata-key wrap + per-file DEK
/// wraps), revoking access. The mandatory Guardian cannot be removed (server-enforced).
/// `--recipient-id` is the recipient's account id, as shown by `share recipients`.
#[allow(clippy::too_many_arguments)]
pub fn share_remove(
    keystore: &dyn Keystore,
    path: Option<&str>,
    folder_id: Option<&str>,
    recipient_id: &str,
    signing_key: Option<&str>,
    kem_key: Option<&str>,
    server_url: &str,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    let signing = resolve_label(signing_key, Purpose::Signing, config)?;
    let kem = resolve_label(kem_key, Purpose::Kem, config)?;
    let mut resolver = Resolver::new(keystore, &signing, &kem, server_url);
    let (folder, _root) = resolve_folder_target(&mut resolver, path, folder_id, None)?;
    let rid = parse_uuid_arg(recipient_id, "--recipient-id")?;
    http::delete_signed(
        keystore,
        &signing,
        server_url,
        &format!("/v1/share-folders/{folder}/recipients/{rid}"),
    )?;
    out.print_json(&serde_json::json!({
        "share_folder_id": folder,
        "removed_recipient_id": rid,
    }))
}

/// `signet share leave (<path>|--folder-id <ID>)` — a recipient removes themselves
/// from a share folder. A recipient typically passes `--folder-id` (from `share
/// list`), since a folder shared *with* them isn't in their own top-level tree to
/// path-resolve. The mandatory Guardian cannot leave (server-enforced).
#[allow(clippy::too_many_arguments)]
pub fn share_leave(
    keystore: &dyn Keystore,
    path: Option<&str>,
    folder_id: Option<&str>,
    signing_key: Option<&str>,
    kem_key: Option<&str>,
    server_url: &str,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    let signing = resolve_label(signing_key, Purpose::Signing, config)?;
    let kem = resolve_label(kem_key, Purpose::Kem, config)?;
    let mut resolver = Resolver::new(keystore, &signing, &kem, server_url);
    let (folder, _root) = resolve_folder_target(&mut resolver, path, folder_id, None)?;
    http::post_signed(
        keystore,
        &signing,
        server_url,
        &format!("/v1/share-folders/{folder}/leave"),
    )?;
    out.print_json(&serde_json::json!({ "left_share_folder_id": folder }))
}

// ── Share invite (Increment 3, 3b — the heavy, recursive DEK re-wrap) ─────────

/// The `POST /v1/share-folders/{id}/invitations` body — matches the server's
/// `CreateInvitationRequest` + `PreComputedWraps` deserializers. The per-file field
/// is `wrap` (not `wrapped_dek`).
#[derive(Serialize)]
struct CreateInvitationBody<'a> {
    recipient_handle: &'a str,
    permission: &'a str,
    pre_computed_wraps: PreComputedWrapsBody<'a>,
}

#[derive(Serialize)]
struct PreComputedWrapsBody<'a> {
    metadata_key_wrap: &'a Value,
    file_dek_wraps: &'a [FileDekWrapBody],
}

#[derive(Serialize)]
struct FileDekWrapBody {
    file_id: Uuid,
    /// A classical or hybrid wrap envelope (opaque to the server).
    wrap: Value,
}

/// `signet share invite (<path>|--folder-id <ID> [--root-folder-id <ID>]) --to
/// <HANDLE> [--permission read_only|read_write]` — invite a recipient to a share
/// folder. Ports the web `inviteToShareFolder`: wrap the folder's metadata key, and
/// recursively re-wrap every file's DEK under the folder tree, to the recipient's
/// KEM key; then POST the pre-computed wraps as a single-use invitation. PRSN-
/// initiated sharing is capability-gated — the server enforces the owner's
/// `prsn_sharing_capability` and returns a clean error if this PRSN may not issue the
/// requested permission. The token it returns is delivered out-of-band.
#[allow(clippy::too_many_arguments)]
pub fn share_invite(
    keystore: &dyn Keystore,
    path: Option<&str>,
    folder_id: Option<&str>,
    root_folder_id: Option<&str>,
    to: &str,
    permission: &str,
    signing_key: Option<&str>,
    kem_key: Option<&str>,
    server_url: &str,
    config: &Config,
    out: &OutputMode,
) -> Result<()> {
    let signing = resolve_label(signing_key, Purpose::Signing, config)?;
    let kem = resolve_label(kem_key, Purpose::Kem, config)?;
    let mut resolver = Resolver::new(keystore, &signing, &kem, server_url);

    // The share folder (its own root) + the recipient's verified hybrid bundle
    // (P-011 classical + §9.2 presence-gated PQ pair).
    let (folder, root) = resolve_folder_target(&mut resolver, path, folder_id, root_folder_id)?;
    let (recipient_keys, _) = resolve_recipient_pubkey(keystore, &signing, server_url, to)?;

    // Wrap the metadata key to the recipient (bound to the root via P-015) so they can
    // decrypt the folder/file names — hybrid when the recipient is hybrid (§9.2/N6).
    let metadata_key = resolver.metadata_key(root)?;
    let metadata_key_wrap = wrap_metadata_key_for(&recipient_keys, &metadata_key, root.as_bytes())?;

    // Re-wrap every file's DEK under the folder tree to the recipient (the DEK never
    // leaves the process — unwrap-with-my-keystore then wrap-to-recipient, per file;
    // each side dispatches classical/hybrid on its own alg).
    let file_ids = resolver.files_under(folder)?;
    let mut file_dek_wraps = Vec::with_capacity(file_ids.len());
    for file_id in &file_ids {
        let resp = http::get_json_signed(
            keystore,
            &signing,
            server_url,
            &format!("/v1/files/{file_id}/wrapped-dek"),
        )?;
        let my_wrap = resp
            .get("wrapped_dek")
            .ok_or_else(|| CliError::invalid_data("wrapped-dek response missing wrapped_dek"))?;
        let wrap = rewrap_dek_to(keystore, &kem, my_wrap, &recipient_keys)?;
        file_dek_wraps.push(FileDekWrapBody {
            file_id: *file_id,
            wrap,
        });
    }

    let body = CreateInvitationBody {
        recipient_handle: to,
        permission,
        pre_computed_wraps: PreComputedWrapsBody {
            metadata_key_wrap: &metadata_key_wrap,
            file_dek_wraps: &file_dek_wraps,
        },
    };
    let body_bytes = serde_json::to_vec(&body)
        .map_err(|e| CliError::generic(format!("serializing invitation request: {e}")))?;
    let resp = http::post_json_signed(
        keystore,
        &signing,
        server_url,
        &format!("/v1/share-folders/{folder}/invitations"),
        &body_bytes,
    )?;
    out.print_json(&resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// S185 (bug211 §7-3's CLI twin) — the URL-refresh decision, pinned on the
    /// SHIPPED function. The property under test is §B-3.4's: the give-up bound
    /// must be on CONSECUTIVE no-progress rejections only, so a download of any
    /// duration survives any number of refreshes as long as chunks land.
    #[test]
    fn presigned_refresh_progress_resets_the_budget_so_duration_is_unbounded() {
        let mut stale = 0u32;
        // A day-long transfer: ~24 refreshes, every one preceded by progress.
        // Every single one must be granted, and the counter must stay reset —
        // THIS is the rate-free property; a total-count cap would fail here.
        for _ in 0..24 {
            assert!(presigned_refresh_decision(true, &mut stale));
            assert_eq!(stale, 0, "progress must reset the consecutive counter");
        }
        // Even after a long run, a lone no-progress rejection is retried…
        assert!(presigned_refresh_decision(false, &mut stale));
        // …and progress afterwards forgives it completely.
        assert!(presigned_refresh_decision(true, &mut stale));
        assert_eq!(stale, 0);
    }

    /// The other arm: with NO progress ever (access revoked; server mints, storage
    /// rejects), the budget must run out — and exactly at the documented bound,
    /// because an over-generous loop here is an unbounded retry against a
    /// permanent refusal.
    #[test]
    fn presigned_refresh_no_progress_exhausts_at_the_documented_budget() {
        let mut stale = 0u32;
        let mut granted = 0u32;
        while presigned_refresh_decision(false, &mut stale) {
            granted += 1;
            assert!(granted < 100, "must not loop unbounded");
        }
        // BUDGET counts consecutive rejections; the last one is refused, so the
        // loop grants exactly BUDGET−1 refreshes before giving up.
        assert_eq!(granted, PRESIGNED_STALE_REFRESH_BUDGET - 1);
        assert_eq!(stale, PRESIGNED_STALE_REFRESH_BUDGET);
    }

    /// bug058 — table timestamps render human-readably (UTC, minute precision);
    /// vectors computed independently (Python datetime, UTC). JSON output is
    /// untouched by construction (the json branches return before any table
    /// formatting), so these pin the one function the table branches share.
    #[test]
    fn table_ts_renders_utc_minutes() {
        assert_eq!(table_ts(1_783_360_037), "2026-07-06 17:47 UTC");
        assert_eq!(table_ts(1_784_408_660), "2026-07-18 21:04 UTC");
        assert_eq!(table_ts(0), "1970-01-01 00:00 UTC");
        // Out-of-range: fall back to the raw value, never error a listing.
        assert_eq!(table_ts(i64::MAX), i64::MAX.to_string());
    }

    // ── Shared sign input/output codecs (used by direct sign + `garnet sign`) ─────

    #[test]
    fn decode_sign_input_handles_each_format() {
        assert_eq!(
            decode_sign_input(b"\x01\x02\xff", "bytes").unwrap(),
            vec![1, 2, 255]
        );
        assert_eq!(
            decode_sign_input(b"0102ff", "hex").unwrap(),
            vec![1, 2, 255]
        );
        assert_eq!(
            decode_sign_input(b"AQL_", "base64url").unwrap(),
            vec![1, 2, 255]
        );
        assert!(decode_sign_input(b"zz", "hex").is_err());
        assert!(decode_sign_input(b"x", "unknown").is_err());
    }

    #[test]
    fn encode_signature_handles_each_format() {
        // A valid 64-byte raw r‖s (low values are well-formed for DER conversion).
        let sig = [1u8; 64];
        assert_eq!(encode_signature(&sig, "raw").unwrap(), sig);
        assert_eq!(
            encode_signature(&sig, "base64url-raw").unwrap(),
            URL_SAFE_NO_PAD.encode(sig).into_bytes()
        );
        // der + base64url-der produce the DER of the raw signature.
        let der = signet_crypto::ecdsa::sig_raw_to_der(&sig).unwrap();
        assert_eq!(encode_signature(&sig, "der").unwrap(), der);
        assert_eq!(
            encode_signature(&sig, "base64url-der").unwrap(),
            URL_SAFE_NO_PAD.encode(&der).into_bytes()
        );
        assert!(encode_signature(&sig, "unknown").is_err());
        // A non-64-byte input (the broker could in principle return an odd length) errors on a DER
        // format rather than panicking.
        assert!(encode_signature(&[1u8; 10], "der").is_err());
    }

    // ── `sign --dual` (the per-request hybrid dual, spec §8 point 1 / §8.7) ──────

    /// The full `--dual` path through `sign()`: a four-key software identity
    /// signs a message; the output is the fixed-width 4691-byte dual whose
    /// halves BOTH verify over the identical bytes — the ML-DSA half under the
    /// `signet:req:v1` context. Plus the two guard rails: no `signing-pq` key
    /// → a clear error (never a silent classical signature), and DER output
    /// formats refuse (DER is a classical-only wire form).
    #[test]
    fn sign_dual_emits_a_verifying_fixed_width_dual() {
        use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa87, Signature, VerifyingKey};

        let dir =
            std::env::temp_dir().join(format!("signet-sign-dual-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ks = crate::keystore::SoftwareKeystore::open(dir.clone()).expect("open keystore");
        let label = KeyLabel::parse("tester-ai-signing", Some(Purpose::Signing)).expect("label");
        let meta = ks.generate(&label, "ES256").expect("generate signing key");
        let pq_label =
            KeyLabel::parse("tester-ai-signing-pq", Some(Purpose::SigningPq)).expect("pq label");
        let pq_meta = ks
            .generate(&pq_label, "ML-DSA-87")
            .expect("generate signing-pq key");

        let config = Config::default();
        let message = b"SIGNET-V1\nGET\n/v1/quota\nstand-in-canonical-bytes";
        let in_path = dir.join("m.bin");
        let out_path = dir.join("sig.bin");
        std::fs::write(&in_path, message).expect("write message");

        sign(
            &ks,
            Some("tester-ai-signing"),
            "bytes",
            "raw",
            Some(&in_path),
            Some(&out_path),
            true,
            &config,
        )
        .expect("sign --dual");

        let dual = std::fs::read(&out_path).expect("read dual");
        assert_eq!(
            dual.len(),
            signet_crypto::attest::REQUEST_DUAL_SIG_LEN,
            "the fixed-width 4691-byte dual"
        );
        let (sig_es, sig_pq) = dual.split_at(64);

        // ES256 half verifies over the identical bytes.
        signet_crypto::ecdsa::verify_es256(&meta.public_key, message, sig_es)
            .expect("ES256 half verifies");
        // ML-DSA-87 half verifies over the SAME bytes under the request ctx.
        let vk_arr = EncodedVerifyingKey::<MlDsa87>::try_from(&pq_meta.public_key[..])
            .expect("2592-byte vk");
        let vk = VerifyingKey::<MlDsa87>::decode(&vk_arr);
        let sig_arr = EncodedSignature::<MlDsa87>::try_from(sig_pq).expect("4627-byte sig");
        let sig = Signature::<MlDsa87>::decode(&sig_arr).expect("signature decodes");
        assert!(
            vk.verify_with_context(message, signet_crypto::attest::REQUEST_MLDSA_CTX, &sig),
            "ML-DSA half verifies under signet:req:v1"
        );

        // Guard rails: DER refuses; a two-key identity errors instead of
        // silently signing classically.
        let der_err = sign(
            &ks,
            Some("tester-ai-signing"),
            "bytes",
            "der",
            Some(&in_path),
            Some(&out_path),
            true,
            &config,
        );
        assert!(der_err.is_err(), "--dual + DER must refuse");

        ks.delete(&pq_label).expect("delete pq key");
        let no_pq = sign(
            &ks,
            Some("tester-ai-signing"),
            "bytes",
            "raw",
            Some(&in_path),
            Some(&out_path),
            true,
            &config,
        );
        assert!(no_pq.is_err(), "--dual without a signing-pq key must error");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Identity resolver (Container-PRSN-Onboarding-Requirement v05 §9/§11) ──────
    // Exercised through the pure `resolve_label_for` (asserted handle passed in), so
    // no test mutates the process `SIGNET_HANDLE` — parallel-safe.

    fn cfg_defaults(signing: Option<&str>, kem: Option<&str>) -> Config {
        Config {
            default_signing_key: signing.map(String::from),
            default_kem_key: kem.map(String::from),
            ..Config::default()
        }
    }

    #[test]
    fn resolver_explicit_key_wins_without_a_handle() {
        let cfg = cfg_defaults(None, None);
        let l = resolve_label_for(None, Some("hlin-ai-signing"), Purpose::Signing, &cfg).unwrap();
        assert_eq!(l.full(), "hlin-ai-signing");
    }

    #[test]
    fn resolver_signet_handle_derives_both_labels() {
        let cfg = cfg_defaults(None, None);
        assert_eq!(
            resolve_label_for(Some("mira-ai"), None, Purpose::Signing, &cfg)
                .unwrap()
                .full(),
            "mira-ai-signing"
        );
        assert_eq!(
            resolve_label_for(Some("mira-ai"), None, Purpose::Kem, &cfg)
                .unwrap()
                .full(),
            "mira-ai-kem"
        );
    }

    #[test]
    fn resolver_signet_handle_outranks_a_divergent_config_default() {
        // A config default naming a *different* PRSN must not silently win over the
        // harness-asserted handle (SIGNET_HANDLE is authoritative).
        let cfg = cfg_defaults(Some("zain-ai-signing"), None);
        assert_eq!(
            resolve_label_for(Some("mira-ai"), None, Purpose::Signing, &cfg)
                .unwrap()
                .full(),
            "mira-ai-signing"
        );
    }

    #[test]
    fn resolver_uses_config_default_when_no_handle() {
        let cfg = cfg_defaults(Some("hlin-ai-signing"), Some("hlin-ai-kem"));
        assert_eq!(
            resolve_label_for(None, None, Purpose::Signing, &cfg)
                .unwrap()
                .full(),
            "hlin-ai-signing"
        );
        assert_eq!(
            resolve_label_for(None, None, Purpose::Kem, &cfg)
                .unwrap()
                .full(),
            "hlin-ai-kem"
        );
    }

    #[test]
    fn resolver_never_guesses_when_nothing_is_specified() {
        // No --key, no SIGNET_HANDLE, no config default → an actionable refusal naming
        // SIGNET_HANDLE, never a silent pick.
        let cfg = cfg_defaults(None, None);
        let err = resolve_label_for(None, None, Purpose::Signing, &cfg).unwrap_err();
        assert_eq!(err.exit_code, 2);
        assert_eq!(err.code, "invalid_arguments");
        assert!(err.message.contains("SIGNET_HANDLE"));
    }

    #[test]
    fn resolver_cross_check_fails_closed_when_key_handle_differs_from_signet_handle() {
        // --key names a different PRSN than SIGNET_HANDLE asserts → fail closed (61),
        // the native analog of the container launch-binding cross-check.
        let cfg = cfg_defaults(None, None);
        let err = resolve_label_for(
            Some("mira-ai"),
            Some("zain-ai-signing"),
            Purpose::Signing,
            &cfg,
        )
        .unwrap_err();
        assert_eq!(err.exit_code, 61);
        assert_eq!(err.code, "identity_mismatch");
        assert!(err.message.contains("mira-ai") && err.message.contains("zain-ai"));
    }

    #[test]
    fn resolver_cross_check_passes_when_key_handle_matches_signet_handle() {
        let cfg = cfg_defaults(None, None);
        let l =
            resolve_label_for(Some("mira-ai"), Some("mira-ai-kem"), Purpose::Kem, &cfg).unwrap();
        assert_eq!(l.full(), "mira-ai-kem");
    }

    #[test]
    fn resolver_rejects_a_malformed_signet_handle() {
        // A SIGNET_HANDLE that isn't a valid PRSN handle (no `-ai`) → an actionable arg
        // error, not a panic or a silent miss.
        let cfg = cfg_defaults(None, None);
        let err = resolve_label_for(Some("not-a-prsn"), None, Purpose::Signing, &cfg).unwrap_err();
        assert_eq!(err.exit_code, 2);
    }

    #[test]
    fn batch_delete_body_uses_the_right_field() {
        let ids = vec![
            Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap(),
            Uuid::parse_str("22222222-2222-4222-8222-222222222222").unwrap(),
        ];
        let folders: Value =
            serde_json::from_slice(&batch_delete_body("folder_ids", &ids).unwrap()).unwrap();
        assert_eq!(folders["folder_ids"].as_array().unwrap().len(), 2);
        assert!(folders.get("file_ids").is_none());
        // ids serialize as strings under the file-side field name.
        let files: Value =
            serde_json::from_slice(&batch_delete_body("file_ids", &ids).unwrap()).unwrap();
        assert_eq!(files["file_ids"][0], "11111111-1111-4111-8111-111111111111");
    }

    #[test]
    fn share_create_body_has_the_server_field_names() {
        // Build a realistic body with real envelopes (throwaway keys) and assert the
        // serialized JSON uses the exact field names the server's
        // CreateShareFolderRequest deserializes.
        let (_, recipient_pub) = signet_crypto::ecdh::generate_keypair();
        let mk = [5u8; 32];
        let root = [1u8; 16];
        let owner_wrap = serde_json::to_value(
            signet_crypto::wrap::wrap_metadata_key(&recipient_pub, &mk, &root).unwrap(),
        )
        .unwrap();
        let guardian_wrap = serde_json::to_value(
            signet_crypto::wrap::wrap_metadata_key(&recipient_pub, &mk, &root).unwrap(),
        )
        .unwrap();
        let name_env = signet_crypto::encname::encrypt_name(&mk, &root, &root, "Finance").unwrap();

        let body = CreateShareFolderBody {
            folder_id: "00000000-0000-4000-8000-000000000000".to_string(),
            encrypted_name: &name_env,
            owner_metadata_key_wrap: &owner_wrap,
            guardian_metadata_key_wrap: Some(&guardian_wrap),
        };
        let v = serde_json::to_value(&body).unwrap();
        for key in [
            "folder_id",
            "encrypted_name",
            "owner_metadata_key_wrap",
            "guardian_metadata_key_wrap",
        ] {
            assert!(v.get(key).is_some(), "share-create body missing `{key}`");
        }
        // A human owner sends no Guardian wrap → the field is omitted (not null).
        let human = CreateShareFolderBody {
            folder_id: "x".to_string(),
            encrypted_name: &name_env,
            owner_metadata_key_wrap: &owner_wrap,
            guardian_metadata_key_wrap: None,
        };
        assert!(
            serde_json::to_value(&human)
                .unwrap()
                .get("guardian_metadata_key_wrap")
                .is_none()
        );
    }

    #[test]
    fn folder_create_body_field_names_top_level_and_nested() {
        let (_, pubk) = signet_crypto::ecdh::generate_keypair();
        let mk = [7u8; 32];
        let root = [2u8; 16];
        let wrap = serde_json::to_value(
            signet_crypto::wrap::wrap_metadata_key(&pubk, &mk, &root).unwrap(),
        )
        .unwrap();
        let name_env = signet_crypto::encname::encrypt_name(&mk, &root, &root, "sub").unwrap();

        // Top-level: carries owner_metadata_key_wrap, no parent.
        let top = CreateFolderBody {
            folder_id: "f".to_string(),
            parent_folder_id: None,
            encrypted_name: &name_env,
            owner_metadata_key_wrap: Some(&wrap),
        };
        let tv = serde_json::to_value(&top).unwrap();
        assert!(tv.get("owner_metadata_key_wrap").is_some());
        assert!(tv.get("parent_folder_id").is_none());

        // Nested: carries parent, no owner wrap (it inherits the root's key).
        let nested = CreateFolderBody {
            folder_id: "f".to_string(),
            parent_folder_id: Some("p".to_string()),
            encrypted_name: &name_env,
            owner_metadata_key_wrap: None,
        };
        let nv = serde_json::to_value(&nested).unwrap();
        assert!(nv.get("parent_folder_id").is_some());
        assert!(nv.get("owner_metadata_key_wrap").is_none());
    }

    #[test]
    fn metadata_key_self_wrap_round_trips() {
        // Mint → wrap to my own key → unwrap → the same key (the create self-wrap).
        let (scalar, pubk) = signet_crypto::ecdh::generate_keypair();
        let mk = [9u8; 32];
        let root = [3u8; 16];
        let wrap = signet_crypto::wrap::wrap_metadata_key(&pubk, &mk, &root).unwrap();
        let back = signet_crypto::wrap::unwrap_metadata_key(&scalar, &wrap, &root).unwrap();
        assert_eq!(back, mk);
    }

    #[test]
    fn guardian_key_verified_or_rejected_by_fingerprint() {
        let (_, pubk) = signet_crypto::ecdh::generate_keypair();
        let fp = signet_crypto::pubkey::fingerprint(&pubk).unwrap();
        let good = serde_json::json!({
            "kem_pubkey": URL_SAFE_NO_PAD.encode(&pubk),
            "kem_pubkey_fingerprint": fp,
        });
        assert_eq!(verify_recipient_kem_pub(&good, "Guardian").unwrap(), pubk);
        // A fingerprint that doesn't match the key → exit 60 (possible substitution).
        let bad = serde_json::json!({
            "kem_pubkey": URL_SAFE_NO_PAD.encode(&pubk),
            "kem_pubkey_fingerprint": "00",
        });
        let err = verify_recipient_kem_pub(&bad, "recipient").unwrap_err();
        assert_eq!(err.exit_code, 60);
    }

    #[test]
    fn json_uuid_extracts_present_and_errors_on_missing_or_malformed() {
        let id = "11111111-1111-4111-8111-111111111111";
        let v = serde_json::json!({ "folder_id": id });
        assert_eq!(json_uuid(&v, "folder_id").unwrap().to_string(), id);
        // Missing field, and a present-but-malformed value, both error.
        assert!(json_uuid(&v, "root_folder_id").is_err());
        assert!(json_uuid(&serde_json::json!({ "folder_id": "nope" }), "folder_id").is_err());
        // The optional variant: present → Some, absent/null → None.
        assert!(json_opt_uuid(&v, "folder_id").is_some());
        assert!(json_opt_uuid(&v, "root_folder_id").is_none());
        assert!(
            json_opt_uuid(
                &serde_json::json!({ "root_folder_id": Value::Null }),
                "root_folder_id"
            )
            .is_none()
        );
    }

    #[test]
    fn share_entry_serializes_undecryptable_name_as_null() {
        let fid = Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap();
        // A folder whose name couldn't be decrypted still lists, with name = null.
        let unnamed = ShareEntry {
            name: None,
            folder_id: fid,
            root_folder_id: fid,
            permission: "read_only".to_string(),
        };
        let v = serde_json::to_value(&unnamed).unwrap();
        assert!(v.get("name").unwrap().is_null());
        assert_eq!(v["permission"], "read_only");
        // A decrypted name serializes as the plain string.
        let named = ShareEntry {
            name: Some("Finance".to_string()),
            folder_id: fid,
            root_folder_id: fid,
            permission: "read_write".to_string(),
        };
        assert_eq!(serde_json::to_value(&named).unwrap()["name"], "Finance");
    }

    #[test]
    fn create_invitation_body_has_the_server_field_names() {
        // The body must deserialize into the server's CreateInvitationRequest +
        // PreComputedWraps: recipient_handle / permission / pre_computed_wraps.{
        // metadata_key_wrap, file_dek_wraps:[{file_id, wrap}] }.
        let (_, kem_pub) = signet_crypto::ecdh::generate_keypair();
        let metadata_key_wrap = serde_json::to_value(
            signet_crypto::wrap::wrap_metadata_key(&kem_pub, &[4u8; 32], &[1u8; 16]).unwrap(),
        )
        .unwrap();
        let dek_wrap =
            serde_json::to_value(signet_crypto::wrap::wrap_dek(&kem_pub, &[5u8; 32]).unwrap())
                .unwrap();
        let file_id = Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap();
        let wraps = vec![FileDekWrapBody {
            file_id,
            wrap: dek_wrap,
        }];
        let body = CreateInvitationBody {
            recipient_handle: "maren-ai",
            permission: "read_only",
            pre_computed_wraps: PreComputedWrapsBody {
                metadata_key_wrap: &metadata_key_wrap,
                file_dek_wraps: &wraps,
            },
        };
        let v = serde_json::to_value(&body).unwrap();
        assert_eq!(v["recipient_handle"], "maren-ai");
        assert_eq!(v["permission"], "read_only");
        assert!(v["pre_computed_wraps"]["metadata_key_wrap"].is_object());
        let fdw = &v["pre_computed_wraps"]["file_dek_wraps"][0];
        assert_eq!(fdw["file_id"], "11111111-1111-4111-8111-111111111111");
        // The per-file field is `wrap`, not `wrapped_dek` (the server's FileDekWrap).
        assert!(fdw["wrap"].is_object());
        assert!(fdw.get("wrapped_dek").is_none());
    }

    #[test]
    fn rewrap_dek_to_re_wraps_to_a_new_recipient() {
        // Unwrap-with-my-KEM (via the keystore) then wrap-to-recipient → the recipient
        // recovers the same DEK. The per-file crypto behind `share invite`.
        let dir = std::env::temp_dir().join(format!("signet-rewrap-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ks = crate::keystore::SoftwareKeystore::open(dir.clone()).expect("open keystore");
        let my_kem = KeyLabel::parse("tester-ai-kem", Some(Purpose::Kem)).expect("label");
        let my_meta = ks
            .generate(&my_kem, "ECDH-ES+A256KW")
            .expect("generate kem key");

        // A DEK wrapped to me — the shape `GET /v1/files/{id}/wrapped-dek`
        // returns. The classical READ side stays: my own older wrap may be
        // classical (crypto-agility); only the WRITE side is mandatory-hybrid.
        let dek = [7u8; 32];
        let my_wrap =
            serde_json::to_value(signet_crypto::wrap::wrap_dek(&my_meta.public_key, &dek).unwrap())
                .unwrap();

        // A hybrid recipient (mandatory hybrid write: every v1 recipient is).
        use kem::Decapsulate;
        let (recipient_scalar, recipient_pub) = signet_crypto::ecdh::generate_keypair();
        let d = ml_kem::B32::try_from(&[0x41u8; 32][..]).unwrap();
        let z = ml_kem::B32::try_from(&[0x42u8; 32][..]).unwrap();
        let (recipient_dk, recipient_ek) =
            <ml_kem::MlKem1024 as ml_kem::KemCore>::generate_deterministic(&d, &z);
        let recipient_ek_bytes = ml_kem::EncodedSizeUser::as_bytes(&recipient_ek).to_vec();
        let recipient = RecipientWrapKeys {
            rk_ec: recipient_pub.clone(),
            rk_pq: Some(recipient_ek_bytes.clone()),
        };

        let rewrapped = rewrap_dek_to(&ks, &my_kem, &my_wrap, &recipient).unwrap();
        // The re-wrap is HYBRID, and the recipient (ECDH scalar + ML-KEM dk)
        // recovers the same DEK through the §5.3 two-shared-secret unwrap.
        let envelope: HybridWrapEnvelope = serde_json::from_value(rewrapped).unwrap();
        assert_eq!(envelope.alg, "ECDH-ES+ML-KEM-1024+A256KW");
        let epk = envelope.ephemeral_pubkey_x963().unwrap();
        let ek_ct = URL_SAFE_NO_PAD.decode(&envelope.ek).unwrap();
        let z_ecdh = signet_crypto::ecdh::ecdh_p256(&recipient_scalar, &epk).unwrap();
        let ct_arr = ml_kem::Ciphertext::<ml_kem::MlKem1024>::try_from(&ek_ct[..]).unwrap();
        let z_mlkem: [u8; 32] = recipient_dk.decapsulate(&ct_arr).unwrap().into();
        let recovered = signet_crypto::hybrid_wrap::unwrap_with_shared_secrets(
            &z_ecdh,
            &z_mlkem,
            &envelope,
            &recipient_pub,
            &recipient_ek_bytes,
            &[],
        )
        .unwrap();
        assert_eq!(recovered, dek);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_recipient_wrap_keys_enforces_the_9_2_gate() {
        // A real classical key + fingerprint (P-011 must pass first).
        let (_, rk_ec) = signet_crypto::ecdh::generate_keypair();
        let ec_b64 = URL_SAFE_NO_PAD.encode(&rk_ec);
        let ec_fp = signet_crypto::pubkey::fingerprint(&rk_ec).unwrap();
        let ek = vec![0xE4u8; 1568];
        let ek_b64 = URL_SAFE_NO_PAD.encode(&ek);
        let ek_fp = signet_crypto::pubkey::fingerprint_raw(&ek);

        // F-DOWNGRADE(a): a FULLY-stripped bundle (no PQ pair at all) → refuse.
        // Every v1 identity is hybrid; "no ML-KEM key" is the harvest-now
        // downgrade, not a legitimate classical recipient. (The classical-only
        // arm survives only behind the hard-off `classical-write` feature.)
        let classical = serde_json::json!({
            "kem_pubkey": ec_b64, "kem_pubkey_fingerprint": ec_fp,
        });
        #[cfg(not(feature = "classical-write"))]
        assert!(
            verify_recipient_wrap_keys(&classical, "recipient").is_err(),
            "a PQ-less bundle must be refused (mandatory hybrid write)"
        );
        #[cfg(feature = "classical-write")]
        assert!(
            verify_recipient_wrap_keys(&classical, "recipient")
                .unwrap()
                .rk_pq
                .is_none()
        );

        // Full hybrid bundle → PQ half present + verified.
        let hybrid = serde_json::json!({
            "kem_pubkey": ec_b64, "kem_pubkey_fingerprint": ec_fp,
            "kem_pq_pubkey": ek_b64, "kem_pq_pubkey_fingerprint": ek_fp,
        });
        let keys = verify_recipient_wrap_keys(&hybrid, "recipient").unwrap();
        assert_eq!(keys.rk_pq.as_deref(), Some(&ek[..]));

        // N6: a HALF-stripped bundle (fingerprint without key — the shape a
        // PQ-stripping attacker leaves) → refuse; NEVER classical fallback.
        let stripped = serde_json::json!({
            "kem_pubkey": ec_b64, "kem_pubkey_fingerprint": ec_fp,
            "kem_pq_pubkey_fingerprint": ek_fp,
        });
        assert!(verify_recipient_wrap_keys(&stripped, "recipient").is_err());
        let keyless = serde_json::json!({
            "kem_pubkey": ec_b64, "kem_pubkey_fingerprint": ec_fp,
            "kem_pq_pubkey": ek_b64,
        });
        assert!(verify_recipient_wrap_keys(&keyless, "recipient").is_err());

        // A tampered PQ key (fingerprint mismatch) → refuse (exit-60 class).
        let mut wrong = ek.clone();
        wrong[0] ^= 1;
        let mismatch = serde_json::json!({
            "kem_pubkey": ec_b64, "kem_pubkey_fingerprint": ec_fp,
            "kem_pq_pubkey": URL_SAFE_NO_PAD.encode(&wrong), "kem_pq_pubkey_fingerprint": ek_fp,
        });
        assert!(verify_recipient_wrap_keys(&mismatch, "recipient").is_err());
    }

    #[test]
    fn wrap_dek_for_dispatches_hybrid_for_a_hybrid_bundle() {
        // §9.2: presence of the PQ half MUST produce a hybrid envelope.
        let (_, rk_ec) = signet_crypto::ecdh::generate_keypair();
        let d = ml_kem::B32::try_from(&[0x31u8; 32][..]).unwrap();
        let z = ml_kem::B32::try_from(&[0x32u8; 32][..]).unwrap();
        let (_dk, ek_obj) = <ml_kem::MlKem1024 as ml_kem::KemCore>::generate_deterministic(&d, &z);
        let rk_pq = ml_kem::EncodedSizeUser::as_bytes(&ek_obj).to_vec();

        let dek = [9u8; 32];
        let hybrid_keys = RecipientWrapKeys {
            rk_ec: rk_ec.clone(),
            rk_pq: Some(rk_pq),
        };
        let v = wrap_dek_for(&hybrid_keys, &dek).unwrap();
        assert_eq!(v["alg"], "ECDH-ES+ML-KEM-1024+A256KW");
        assert!(v.get("ek").is_some() && v.get("wk").is_some());

        // F-DOWNGRADE(a)'s dispatch-point backstop: a wrap target with no PQ
        // half is REFUSED at the dispatch, no matter which path built it.
        let classical_keys = RecipientWrapKeys { rk_ec, rk_pq: None };
        #[cfg(not(feature = "classical-write"))]
        assert!(
            wrap_dek_for(&classical_keys, &dek).is_err(),
            "the writer must never emit a classical-only wrap"
        );
        #[cfg(feature = "classical-write")]
        {
            let v = wrap_dek_for(&classical_keys, &dek).unwrap();
            assert_eq!(v["alg"], "ECDH-ES+A256KW");
            assert!(v.get("ek").is_none());
        }
    }

    #[test]
    fn shape_whoami_human_has_no_guardian_or_capability() {
        // A human's /v1/me carries billing + key material and a null guardian.
        let me = serde_json::json!({
            "account_id": "11111111-1111-4111-8111-111111111111",
            "account_type": "human",
            "handle": "chris",
            "admin_role": true,
            "paid_until": 1_700_000_000i64,
            "kem_pubkey": "AAAA",
            "guardian": null,
        });
        let shaped = shape_whoami(&me);
        assert_eq!(shaped["account_id"], "11111111-1111-4111-8111-111111111111");
        assert_eq!(shaped["account_type"], "human");
        assert_eq!(shaped["handle"], "chris");
        // A human has neither a Guardian nor a sharing capability.
        assert!(shaped.get("guardian").is_none());
        assert!(shaped.get("prsn_sharing_capability").is_none());
        // Billing/key fields are not part of the identity view.
        assert!(shaped.get("paid_until").is_none());
        assert!(shaped.get("kem_pubkey").is_none());
    }

    #[test]
    fn shape_whoami_prsn_includes_guardian_handle_and_capability() {
        let me = serde_json::json!({
            "account_id": "22222222-2222-4222-8222-222222222222",
            "account_type": "prsn",
            "handle": "hlin-ai",
            "prsn_sharing_capability": "read_only",
            "guardian": {
                "handle": "chris",
                "kem_pubkey": "AAAA",
                "kem_pubkey_fingerprint": "ff",
            },
        });
        let shaped = shape_whoami(&me);
        assert_eq!(shaped["account_type"], "prsn");
        assert_eq!(shaped["handle"], "hlin-ai");
        assert_eq!(shaped["prsn_sharing_capability"], "read_only");
        // The Guardian is flattened to just the handle a PRSN reports back.
        assert_eq!(shaped["guardian"], "chris");
    }

    #[test]
    fn shape_quota_derives_available_and_floors_over_quota() {
        let shaped =
            shape_quota(&serde_json::json!({ "bytes_used": 30, "bytes_quota": 100 })).unwrap();
        assert_eq!(shaped["bytes_used"], 30);
        assert_eq!(shaped["bytes_quota"], 100);
        assert_eq!(shaped["bytes_available"], 70);

        // Over quota (e.g. after a downgrade): available floors at 0, never negative.
        let over =
            shape_quota(&serde_json::json!({ "bytes_used": 150, "bytes_quota": 100 })).unwrap();
        assert_eq!(over["bytes_available"], 0);

        // A malformed response (missing a field) is a clean invalid_data error.
        assert!(shape_quota(&serde_json::json!({ "bytes_used": 1 })).is_err());
    }

    #[test]
    fn chunk_plan_matches_the_web_overhead_model() {
        // Empty file → one chunk, 34 declared bytes (the lone chunk's overhead).
        assert_eq!(chunk_plan(0, 16).unwrap(), (1, 34));
        // Exactly one chunk.
        assert_eq!(chunk_plan(16, 16).unwrap(), (1, 16 + 34));
        // One byte over → two chunks.
        assert_eq!(chunk_plan(17, 16).unwrap(), (2, 17 + 2 * 34));
        // A multi-chunk file (100 / 16 = 6.25 → 7 chunks).
        assert_eq!(chunk_plan(100, 16).unwrap(), (7, 100 + 7 * 34));
    }

    // bug070 — the pre-upload capacity rule.
    //
    // ⚠ THE PARITY VECTORS. These seven cases are asserted VERBATIM-IDENTICALLY by
    // the web (`drive.test.ts`, the `PARITY` table in "bug070 pre-upload capacity"):
    // same numbers, same verdicts. Change one side and the other must change in the
    // same commit — the way the bug048 name rule is pinned across names.rs/names.ts.
    /// One parity case. A named struct rather than a tuple: it mirrors the web's
    /// object shape (`{declared, ceiling, remaining, allowed, why}`), which makes the
    /// correspondence between the two tables checkable by eye instead of positional.
    struct ParityVector {
        declared: i64,
        ceiling: Option<i64>,
        remaining: Option<i64>,
        allowed: bool,
        why: &'static str,
    }

    #[test]
    fn capacity_refusal_parity_vectors() {
        let vectors = [
            ParityVector {
                declared: 100,
                ceiling: Some(100),
                remaining: Some(1000),
                allowed: true,
                why: "exactly at the ceiling",
            },
            ParityVector {
                declared: 101,
                ceiling: Some(100),
                remaining: Some(1000),
                allowed: false,
                why: "one byte over the ceiling",
            },
            ParityVector {
                declared: 100,
                ceiling: Some(1000),
                remaining: Some(100),
                allowed: true,
                why: "exactly fills the pool",
            },
            ParityVector {
                declared: 101,
                ceiling: Some(1000),
                remaining: Some(100),
                allowed: false,
                why: "one byte over the pool",
            },
            ParityVector {
                declared: 101,
                ceiling: Some(100),
                remaining: Some(100),
                allowed: false,
                why: "ceiling is checked first",
            },
            ParityVector {
                declared: 5000,
                ceiling: None,
                remaining: Some(1000),
                allowed: false,
                why: "no ceiling known, pool still applies",
            },
            ParityVector {
                declared: 5000,
                ceiling: Some(10000),
                remaining: None,
                allowed: true,
                why: "quota read failed -> fail OPEN",
            },
        ];
        for v in &vectors {
            let refusal = capacity_refusal(v.declared, v.ceiling, v.remaining);
            assert_eq!(
                refusal.is_none(),
                v.allowed,
                "declared={} ceiling={:?} remaining={:?} ({}): {:?}",
                v.declared,
                v.ceiling,
                v.remaining,
                v.why,
                refusal
            );
        }
    }

    // The refusals must say WHICH limit was hit — a user who cannot tell "too big for
    // this server" from "too big for your plan" cannot act on either.
    #[test]
    fn capacity_refusals_name_the_limit_that_was_hit() {
        let ceiling_hit = capacity_refusal(101, Some(100), Some(1_000_000)).unwrap();
        assert!(
            ceiling_hit.contains("too large") && ceiling_hit.contains("single-file limit"),
            "ceiling refusal must name the single-file limit: {ceiling_hit}"
        );
        let pool_hit = capacity_refusal(101, Some(1_000_000), Some(100)).unwrap();
        assert!(
            pool_hit.contains("not enough storage") && pool_hit.contains("pooled quota"),
            "pool refusal must name the pooled quota: {pool_hit}"
        );
    }

    /// bug070 follow-up (S140): a capacity condition is a **refusal**, not user error.
    ///
    /// This pins the exit code because it is a machine contract: a harness branches on
    /// it, and the previous value (2 `invalid_arguments`) instructed that harness to go
    /// fix its command line — the one action that cannot help, since the identical
    /// invocation succeeds the moment space exists. The assertion is on the number and
    /// the machine code together, since `--json-errors` consumers key on the latter.
    #[test]
    fn a_capacity_refusal_is_insufficient_storage_not_invalid_arguments() {
        let err = CliError::insufficient_storage("not enough storage: …");
        assert_eq!(err.exit_code, 18);
        assert_eq!(err.code, "insufficient_storage");

        // The regression this exists to prevent, named explicitly.
        assert_ne!(
            err.exit_code,
            CliError::invalid_args("x").exit_code,
            "a well-formed command refused for capacity must not report as user error"
        );
        // ...and it is distinct from the server-side authorization refusal, because this
        // one is raised locally before any request is made (see the doc comment on 18).
        assert_ne!(err.exit_code, CliError::authorization_denied("x").exit_code);
    }

    // Face (c), as the defect: a file whose PLAINTEXT fits the ceiling but whose
    // STORED size does not. The old web guard compared the former and shipped a file
    // the server then rejected.
    #[test]
    fn the_ceiling_applies_to_stored_size_not_plaintext() {
        let plaintext = 100u64;
        let (_chunks, declared) = chunk_plan(plaintext, 16).unwrap();
        assert!(declared > plaintext as i64, "stored size exceeds plaintext");
        // Ceiling set exactly at the plaintext size: allowed on a plaintext
        // comparison, refused on the stored one the server actually applies.
        assert!(capacity_refusal(declared, Some(plaintext as i64), Some(i64::MAX)).is_some());
    }

    #[test]
    fn chunk_plan_bounds_the_part_count() {
        // Exactly MAX_PARTS is allowed; one chunk more is rejected.
        assert!(chunk_plan(MAX_PARTS as u64, 1).is_ok());
        assert!(chunk_plan(MAX_PARTS as u64 + 1, 1).is_err());
    }

    // bug060/S1 — the multipart floor. Object storage rejects non-final parts below
    // 5 MiB, but only at CompleteMultipartUpload, i.e. after the whole file has been
    // transferred. These pin the rule as file-size-dependent, NOT a bare floor.
    #[test]
    fn multipart_floor_rejects_sub_floor_multi_part_plans() {
        let under = MIN_MULTIPART_CHUNK_SIZE - 1;
        let err = check_multipart_floor(2, under).unwrap_err().to_string();
        assert!(
            err.contains("5 MiB") && err.contains("--chunk-size"),
            "the error must name the floor and the flag that sets it: {err}"
        );
        // The exact size that produced the real staging failure (4 MiB, 25 parts).
        assert!(check_multipart_floor(25, 4 * 1024 * 1024).is_err());
    }

    #[test]
    fn multipart_floor_exempts_single_part_uploads() {
        // A single part IS the last part, so the floor does not apply — a small file
        // at a small chunk size is legal and must stay legal.
        assert!(check_multipart_floor(1, 1).is_ok());
        assert!(check_multipart_floor(1, MIN_MULTIPART_CHUNK_SIZE - 1).is_ok());
    }

    #[test]
    fn multipart_floor_admits_plans_at_and_above_the_floor() {
        assert!(check_multipart_floor(2, MIN_MULTIPART_CHUNK_SIZE).is_ok());
        assert!(check_multipart_floor(64, DEFAULT_CHUNK_SIZE).is_ok());
        // 6 MiB is the size proven to work end-to-end on a ~6 Mbps link (bug060 §5.2).
        assert!(check_multipart_floor(17, 6 * 1024 * 1024).is_ok());
    }

    #[test]
    fn fill_chunk_reads_full_then_partial() {
        let dir = std::env::temp_dir().join(format!("signet-fill-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("data.bin");
        let data: Vec<u8> = (0..50u8).collect();
        std::fs::write(&path, &data).unwrap();

        let mut file = std::fs::File::open(&path).unwrap();
        let mut buf = vec![0u8; 16];
        // First chunk: a full 16 bytes.
        assert_eq!(fill_chunk(&mut file, &mut buf).unwrap(), 16);
        assert_eq!(&buf[..16], &data[..16]);
        // The last (partial) chunk: seek to offset 48 → only 2 bytes remain.
        file.seek(SeekFrom::Start(48)).unwrap();
        assert_eq!(fill_chunk(&mut file, &mut buf).unwrap(), 2);
        assert_eq!(&buf[..2], &data[48..50]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn initiate_body_has_the_server_field_names() {
        // Build a realistic body with real envelopes (throwaway keys) and assert the
        // serialized JSON uses the exact field names the server's InitiateRequest
        // deserializes — catching any drift between the surfaces.
        let (_, recipient_pub) = signet_crypto::ecdh::generate_keypair();
        let dek = Zeroizing::new([7u8; 32]);
        let wrapped_dek =
            serde_json::to_value(signet_crypto::wrap::wrap_dek(&recipient_pub, &dek).unwrap())
                .unwrap();
        let metadata_key = [9u8; 32];
        let root = [1u8; 16];
        let file_id = [2u8; 16];
        let encrypted_name =
            signet_crypto::encname::encrypt_name(&metadata_key, &root, &file_id, "f.txt").unwrap();

        let body = InitiateBody {
            folder_id: "00000000-0000-4000-8000-000000000000".to_string(),
            encrypted_name: &encrypted_name,
            wrapped_deks: vec![WrappedDekInput {
                recipient_account_id: "11111111-1111-4111-8111-111111111111".to_string(),
                wrapped_dek,
            }],
            declared_size: 34,
            chunk_size: 16,
            chunk_count: 1,
            algorithm: "A256GCM",
        };
        let value = serde_json::to_value(&body).unwrap();
        let obj = value.as_object().expect("object");
        for key in [
            "folder_id",
            "encrypted_name",
            "wrapped_deks",
            "declared_size",
            "chunk_size",
            "chunk_count",
            "algorithm",
        ] {
            assert!(obj.contains_key(key), "initiate body missing `{key}`");
        }
        let wrap = &value["wrapped_deks"][0];
        assert!(wrap.get("recipient_account_id").is_some());
        assert!(wrap.get("wrapped_dek").is_some());

        // CompleteBody mirrors the server's CompleteRequest shape too.
        let complete = serde_json::to_value(CompleteBody {
            parts: vec![PartInput {
                part_number: 1,
                etag: "\"abc\"".to_string(),
            }],
        })
        .unwrap();
        assert_eq!(
            complete,
            serde_json::json!({ "parts": [{ "part_number": 1, "etag": "\"abc\"" }] })
        );
    }

    /// ⚠⚠ **THE DEADLOCK GUARD (Gus F1, S174).** With seal-ahead active the
    /// producer thread parks in `tx.send`; if a consumer-side error did not drop
    /// the receiver, it would park FOREVER and the CLI would hang silently — on
    /// exactly the bug047 bad-window path whose promise is an honest resumable
    /// pause. That is the worst failure shape this transport has, and it would
    /// have been reintroduced by the fix for dead air.
    ///
    /// ⭐ **This test HANGS against the pre-fix code and passes after it** — the
    /// fail-before/pass-after shape. It is also the test whose absence let a
    /// 1217/1217 gate stay green over a deadlock: no other CLI test injects a
    /// transport error while the producer is mid-file.
    ///
    /// The URL is a closed port, so every attempt fails fast and the error
    /// arrives from the SEND half while the producer is still sealing.
    #[test]
    fn seal_ahead_does_not_deadlock_when_a_part_fails_mid_file() {
        let dir = std::env::temp_dir().join(format!("signet-seal-ahead-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let in_path = dir.join("payload.bin");
        // Four chunks of 8 bytes: enough that the failure lands while the
        // producer still has parts left to seal.
        std::fs::write(&in_path, vec![7u8; 32]).unwrap();

        let part_urls: Vec<Value> = (1..=4)
            .map(|n| serde_json::json!({ "part_number": n, "url": "http://127.0.0.1:1/part" }))
            .collect();
        let knobs = http::TransferKnobs {
            attempts: 1,
            ..Default::default()
        };
        let mut governor = TransferGovernor::new(GovernorKnobs::default());

        let result = upload_parts(
            &in_path,
            &[9u8; 32],
            &[3u8; 16],
            8,
            4,
            &part_urls,
            &knobs,
            &mut governor,
            1, // seal one part ahead — the path with the producer thread
            1, // serial sends: the S174 deadlock shape this test pins
        );

        std::fs::remove_dir_all(&dir).ok();
        assert!(
            result.is_err(),
            "a failing part must surface as an error, not hang the process"
        );
    }

    /// ⭐ **KNOB RULE 4, upload half.** The off-position here is **0**, not 1 —
    /// the knobs count different things (chunks-at-once vs parts-sealed-ahead),
    /// so a shared default would be wrong for one of them.
    /// ⚠ And on this surface 0 is not merely equivalent to the old behaviour: it
    /// runs the ORIGINAL serial loop verbatim, so retraction cannot mean "a
    /// different serial implementation with its own bugs".
    #[test]
    fn upload_prepare_ahead_falls_back_to_serial_rather_than_guessing() {
        let none = serde_json::json!({});
        assert_eq!(upload_prepare_ahead(&none), 0, "an older server ⇒ serial");
        let off = serde_json::json!({"governor": {"upload_prepare_ahead": 0}});
        assert_eq!(upload_prepare_ahead(&off), 0, "the retraction position");
        let junk = serde_json::json!({"governor": {"upload_prepare_ahead": "x"}});
        assert_eq!(upload_prepare_ahead(&junk), 0, "nonsense ⇒ serial");
        let neg = serde_json::json!({"governor": {"upload_prepare_ahead": -3}});
        assert_eq!(upload_prepare_ahead(&neg), 0, "negative ⇒ serial");
    }

    #[test]
    fn upload_concurrency_falls_back_to_serial_rather_than_guessing() {
        // 3b (S175): knob rule 4's off-position. An older server that omits the
        // field, a nonsense value, a zero and a deliberate retraction all land
        // on 1 — the serial send path, which at prepare_ahead == 0 is literally
        // the original loop.
        let none = serde_json::json!({});
        assert_eq!(upload_concurrency(&none), 1, "an older server ⇒ serial");
        let off = serde_json::json!({"governor": {"concurrency_upload": 1}});
        assert_eq!(upload_concurrency(&off), 1, "the retraction position");
        let zero = serde_json::json!({"governor": {"concurrency_upload": 0}});
        assert_eq!(upload_concurrency(&zero), 1, "zero ⇒ serial, never a stall");
        let junk = serde_json::json!({"governor": {"concurrency_upload": "x"}});
        assert_eq!(upload_concurrency(&junk), 1, "nonsense ⇒ serial");
        let neg = serde_json::json!({"governor": {"concurrency_upload": -3}});
        assert_eq!(upload_concurrency(&neg), 1, "negative ⇒ serial");
        let served = serde_json::json!({"governor": {"concurrency_upload": 4}});
        assert_eq!(upload_concurrency(&served), 4, "the served value passes");
        let huge = serde_json::json!({"governor": {"concurrency_upload": 9999}});
        assert_eq!(
            upload_concurrency(&huge),
            CLI_MAX_UPLOAD_CONCURRENCY as usize,
            "a hostile served value cannot exceed the compiled ceiling"
        );
    }

    /// 3b (S175): the S174 deadlock shape, re-pinned under FAN-OUT. Four workers
    /// all fail their part (nothing listens on 127.0.0.1:1); every worker
    /// becomes a drainer, the producer must never park forever in `send`, and
    /// the call returns an error rather than hanging. Verified empirically at
    /// S174 that WITHOUT the drain design this shape hangs silently — the gate
    /// was green over it because no test injected a transport error mid-file.
    #[test]
    fn upload_fanout_failure_surfaces_as_an_error_not_a_hang() {
        let dir = std::env::temp_dir().join(format!("signet-fanout-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let in_path = dir.join("in.bin");
        std::fs::write(&in_path, vec![7u8; 64]).unwrap();

        let part_urls: Vec<Value> = (1..=8)
            .map(|n| serde_json::json!({ "part_number": n, "url": "http://127.0.0.1:1/part" }))
            .collect();
        let knobs = http::TransferKnobs {
            attempts: 1,
            ..Default::default()
        };
        let mut governor = TransferGovernor::new(GovernorKnobs::default());

        let result = upload_parts(
            &in_path,
            &[9u8; 32],
            &[3u8; 16],
            8,
            8,
            &part_urls,
            &knobs,
            &mut governor,
            1, // producer seals ahead
            4, // four send workers — the burst + drain paths both exercise
        );

        std::fs::remove_dir_all(&dir).ok();
        assert!(
            result.is_err(),
            "a failing fan-out must surface as an error, not hang the process"
        );
    }

    /// ⚠ In-flight memory is `(1 + prepare_ahead) x chunk`, so the compiled
    /// ceiling is the real bound rather than whatever is served.
    #[test]
    fn upload_prepare_ahead_is_clamped_to_the_compiled_ceiling() {
        let seeded = serde_json::json!({"governor": {"upload_prepare_ahead": 1}});
        assert_eq!(
            upload_prepare_ahead(&seeded),
            1,
            "the seeded value passes through"
        );
        let huge = serde_json::json!({"governor": {"upload_prepare_ahead": 9999}});
        assert_eq!(
            upload_prepare_ahead(&huge),
            CLI_MAX_UPLOAD_PREPARE_AHEAD as usize,
            "a hostile or fat-fingered served value cannot exceed the ceiling"
        );
    }

    /// ⭐ **KNOB RULE 4 — the off-position is EXERCISED, not declared.** Every way
    /// of not getting a usable value must land on strictly-serial, which is
    /// exactly today's behaviour: an older server that omits the field, a
    /// deliberate retraction to 1, or a nonsense value.
    #[test]
    fn download_concurrency_falls_back_to_serial_rather_than_guessing() {
        assert_eq!(download_concurrency(None), 1, "an older server ⇒ serial");
        assert_eq!(download_concurrency(Some(1)), 1, "the retraction position");
        assert_eq!(
            download_concurrency(Some(0)),
            1,
            "nonsense ⇒ serial, never 0"
        );
        assert_eq!(download_concurrency(Some(-5)), 1, "negative ⇒ serial");
    }

    /// ⚠ An unclamped served value is a DoS switch pointed at our own users, and
    /// in-flight memory is `N × chunk` — so the compiled ceiling is the real
    /// bound, not the served number.
    #[test]
    fn download_concurrency_is_clamped_to_the_compiled_ceiling() {
        assert_eq!(
            download_concurrency(Some(4)),
            4,
            "the ruled default passes through"
        );
        assert_eq!(
            download_concurrency(Some(9_999)),
            CLI_MAX_DOWNLOAD_CONCURRENCY as usize,
            "a hostile or fat-fingered served value cannot exceed the compiled ceiling"
        );
    }

    #[test]
    fn positioned_writes_reassemble_out_of_order_completions() {
        // bug193's sliding window lands chunks in COMPLETION order, which is not
        // arrival order. The offset math (index × plaintext chunk_size) must make
        // that reordering free: writing 2, 0, 3, 1 yields the same bytes as 0..4.
        let dir = std::env::temp_dir().join(format!("sigdl-ooo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ooo.bin");
        let file = std::fs::File::create(&path).unwrap();
        let stride = 8u64;
        let chunks: Vec<Vec<u8>> = vec![
            (0x00..0x08).collect(),
            (0x10..0x18).collect(),
            (0x20..0x28).collect(),
            (0x30..0x33).collect(), // short final chunk
        ];
        for &i in &[2usize, 0, 3, 1] {
            write_plaintext_at(&file, &chunks[i], i as u64 * stride).unwrap();
        }
        drop(file);
        let got = std::fs::read(&path).unwrap();
        assert_eq!(
            got,
            chunks.concat(),
            "out-of-order positioned writes must reassemble exactly"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn chunk_ranges_match_the_web_boundary_math() {
        // 3 on-disk chunks of 50 (chunk_size 16 + 34 overhead), the last partial →
        // total 139 stored bytes.
        assert_eq!(
            chunk_ranges(3, 16, 139),
            vec![(0, 49), (50, 99), (100, 138)]
        );
        // A single chunk runs straight to size - 1.
        assert_eq!(chunk_ranges(1, 16, 34), vec![(0, 33)]);
    }

    #[test]
    fn seal_range_open_reconstructs_the_file() {
        // The whole transport crypto composes: seal each chunk (upload), concatenate
        // as stored, slice by the download Range math, open each (download) → the
        // original plaintext. This is the round-trip, proven locally.
        let dek = [3u8; 32];
        let file_id = [4u8; 16];
        let chunk_size = 8usize;
        let plaintext: Vec<u8> = (0..20u8).collect(); // 20 bytes → 3 chunks (8, 8, 4)

        let chunk_count = plaintext.len().div_ceil(chunk_size);
        let mut stored = Vec::new();
        for i in 0..chunk_count {
            let slice = &plaintext[i * chunk_size..((i + 1) * chunk_size).min(plaintext.len())];
            stored.extend_from_slice(
                &signet_crypto::envelope::seal_chunk(
                    &dek,
                    &file_id,
                    i as u32,
                    chunk_count as u32,
                    slice,
                )
                .unwrap(),
            );
        }

        let ranges = chunk_ranges(chunk_count as u32, chunk_size as u64, stored.len() as u64);
        let mut reconstructed = Vec::new();
        for (i, (start, end)) in ranges.into_iter().enumerate() {
            let envelope = &stored[start as usize..=end as usize];
            reconstructed.extend_from_slice(
                &signet_crypto::envelope::open_chunk(
                    &dek,
                    &file_id,
                    i as u32,
                    chunk_count as u32,
                    envelope,
                )
                .unwrap(),
            );
        }
        assert_eq!(reconstructed, plaintext);
    }
}

#[cfg(test)]
mod dual_sign_receipt_tests {
    use super::*;
    use serde_json::json;

    /// Build a dual-signed receipt the way the server does (item 7c): both
    /// halves over the receipt object with every server_signature* field
    /// absent; the PQ key id INSIDE the classically-signed object.
    fn dual_signed_receipt() -> (Value, Vec<u8>, Vec<u8>) {
        let (es_scalar, es_pub) = signet_crypto::ecdsa::generate_keypair();
        let seed = ml_dsa::Seed::try_from(&[0x77u8; 32][..]).unwrap();
        let sk = ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa87>::from_seed(&seed);
        let pq_vk = sk.verifying_key().encode().to_vec();

        let mut receipt = json!({
            "v": 1,
            "type": "signet-pubkey-log-receipt",
            "entry_id": 7,
            "entry_version": 2,
            "account_id": "00000000-0000-4000-8000-00000000cafe",
            "key_purpose": "signing",
            "algorithm": "ES256",
            "public_key_fingerprint": "fp-signing",
            "entry_hash": "aa",
            "log_size_at_insertion": 7,
            "issued_at": 1_700_000_000i64,
            "max_merge_delay_seconds": 86_400i64,
            "server_key_id": "00000000-0000-4000-8000-0000000000aa",
            "server_pq_key_id": "00000000-0000-4000-8000-0000000000bb",
        });
        let signing_input = signet_crypto::translog::receipt_signing_input(&receipt).unwrap();
        let es_sig = signet_crypto::ecdsa::sign_es256(&es_scalar, &signing_input).unwrap();
        let pq_sig = sk
            .sign_deterministic(&signing_input, signet_crypto::translog::RECEIPT_MLDSA_CTX)
            .unwrap();
        let obj = receipt.as_object_mut().unwrap();
        obj.insert(
            "server_signature".into(),
            json!(URL_SAFE_NO_PAD.encode(es_sig)),
        );
        obj.insert(
            "server_signature_mldsa87".into(),
            json!(URL_SAFE_NO_PAD.encode(pq_sig.encode().as_slice())),
        );
        (receipt, es_pub, pq_vk)
    }

    #[test]
    fn dual_signed_receipt_verifies_and_resists_stripping() {
        let (receipt, es_pub, pq_vk) = dual_signed_receipt();

        // The honest dual-signed receipt verifies.
        verify_one_receipt(
            &receipt,
            "fp-signing",
            None,
            "signing",
            &es_pub,
            Some(&pq_vk),
        )
        .expect("dual-signed receipt verifies");

        // MF-2 receipt rule: dropping the ML-DSA signature while the signed
        // object still names the PQ key → rejected.
        let mut stripped_sig = receipt.clone();
        stripped_sig
            .as_object_mut()
            .unwrap()
            .remove("server_signature_mldsa87");
        assert!(
            verify_one_receipt(
                &stripped_sig,
                "fp-signing",
                None,
                "signing",
                &es_pub,
                Some(&pq_vk),
            )
            .is_err(),
            "PQ-signature-stripped receipt must be rejected"
        );

        // The anti-strip binding: removing the PQ key id (to fake a classical
        // receipt) breaks the ES256 signature — the id is inside its bytes.
        let mut stripped_kid = receipt.clone();
        let obj = stripped_kid.as_object_mut().unwrap();
        obj.remove("server_pq_key_id");
        obj.remove("server_signature_mldsa87");
        assert!(
            verify_one_receipt(
                &stripped_kid,
                "fp-signing",
                None,
                "signing",
                &es_pub,
                Some(&pq_vk),
            )
            .is_err(),
            "a receipt downgraded to the classical shape must fail ES256"
        );

        // N9's receipt-layer cousin: a dual-signed receipt with NO pq vk in
        // hand fails closed (never silently skips the PQ half).
        assert!(
            verify_one_receipt(&receipt, "fp-signing", None, "signing", &es_pub, None,).is_err(),
            "cannot silently skip an unverifiable PQ co-signature"
        );
    }

    #[test]
    fn receipt_account_binding_rejects_a_foreign_account() {
        // F-DOWNGRADE(b), the human-recipient path: when the receipt is the
        // sole record binding a key to an identity, its account_id must name
        // the recipient — a verifying receipt for a key logged under a
        // different account is a substitution, not this recipient's key.
        let (receipt, es_pub, pq_vk) = dual_signed_receipt();

        verify_one_receipt(
            &receipt,
            "fp-signing",
            Some("00000000-0000-4000-8000-00000000cafe"),
            "signing",
            &es_pub,
            Some(&pq_vk),
        )
        .expect("the receipt binds to its own account");

        assert!(
            verify_one_receipt(
                &receipt,
                "fp-signing",
                Some("11111111-1111-4111-8111-111111111111"),
                "signing",
                &es_pub,
                Some(&pq_vk),
            )
            .is_err(),
            "a receipt bound to a different account must be rejected"
        );
    }
}

#[cfg(test)]
mod n9_response_path_tests {
    //! bug127 (audit F-009) — **PQR §9.4 N9, the RESPONSE-path signature-downgrade defence.**
    //!
    //! ⚠ Distinct from the receipt-layer rule already covered in `dual_sign_receipt_tests`.
    //! That module tests the §10a *receipts*; this one tests the §9 **response** signature —
    //! the branch entered only when the caller holds the server's ML-DSA-87 key
    //! (`--server-pq-pubkey`). Every existing test ran the other configuration mode, where the
    //! defence is off by design, so a **mandatory** defence had zero executing tests: §8
    //! boundary type 2, a seam between configuration modes rather than between layers.
    use super::*;
    use serde_json::json;

    /// A §9 response signed the way the server signs one, plus the keys to check it.
    fn dual_signed_response() -> (Value, Vec<u8>, Vec<u8>, Vec<u8>) {
        let seed = ml_dsa::Seed::try_from(&[0x5au8; 32][..]).unwrap();
        let sk = ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa87>::from_seed(&seed);
        let pq_vk = sk.verifying_key().encode().to_vec();

        let signing_input = b"signet:test:n9-response-signing-input".to_vec();
        let pq_sig = sk
            .sign_deterministic(
                &signing_input,
                signet_crypto::attest::SERVER_VERIFY_MLDSA_CTX,
            )
            .unwrap();
        let response = json!({
            "server_signature": "irrelevant-here",
            "server_signature_mldsa87": URL_SAFE_NO_PAD.encode(pq_sig.encode().as_slice()),
        });
        (response, pq_vk, signing_input, pq_sig.encode().to_vec())
    }

    #[test]
    fn n9_accepts_an_honest_dual_signed_response() {
        // POSITIVE CONTROL. Without it, a check that refused everything would look like a
        // passing fix while breaking every real client.
        let (response, pq_vk, signing_input, _) = dual_signed_response();
        enforce_response_dual_signature(&response, &signing_input, Some(&pq_vk))
            .expect("an honest dual-signed response must verify");
    }

    #[test]
    fn n9_refuses_an_es256_only_response_when_a_pq_key_is_held() {
        // THE defence. A downgrading middlebox strips the PQ half; holding the server's
        // published ML-DSA-87 key, we must refuse rather than accept the classical remainder.
        let (mut response, pq_vk, signing_input, _) = dual_signed_response();
        response
            .as_object_mut()
            .unwrap()
            .remove("server_signature_mldsa87");
        let err = enforce_response_dual_signature(&response, &signing_input, Some(&pq_vk))
            .expect_err("an ES256-only response must be REFUSED when a PQ key is held");
        assert!(
            err.message.contains("MUST be dual-signed"),
            "the refusal must name the N9 rule, got: {}",
            err.message
        );
    }

    #[test]
    fn n9_refuses_a_pq_signature_that_does_not_verify() {
        // Presence is not verification — the audit's own recurring shape. A response carrying
        // a well-formed but WRONG ML-DSA signature must fail, not pass because a field exists.
        let (mut response, pq_vk, signing_input, mut sig) = dual_signed_response();
        sig[0] ^= 0xFF;
        response.as_object_mut().unwrap().insert(
            "server_signature_mldsa87".into(),
            json!(URL_SAFE_NO_PAD.encode(&sig)),
        );
        assert!(
            enforce_response_dual_signature(&response, &signing_input, Some(&pq_vk)).is_err(),
            "a non-verifying PQ signature must be refused"
        );
    }

    #[test]
    fn n9_is_off_by_design_without_a_published_pq_key() {
        // The other configuration mode, pinned so its behaviour is a DECISION rather than an
        // accident: with no server PQ key in hand there is nothing to verify against, and the
        // ES256-only response is accepted. This is what every pre-existing test exercised —
        // which is precisely why the enforcing branch above had never run.
        let (mut response, _pq_vk, signing_input, _) = dual_signed_response();
        response
            .as_object_mut()
            .unwrap()
            .remove("server_signature_mldsa87");
        enforce_response_dual_signature(&response, &signing_input, None)
            .expect("without a published PQ key, N9 enforcement is off by design");
    }
}

#[cfg(test)]
mod share_list_degrade_tests {
    //! bug139's THIRD home — `share_list`'s degrade (Gus, S163 review).
    //!
    //! ⚠ **Why this is a separate test module from `resolve.rs`'s.** The degrade-on-a-bad-row
    //! decision is implemented at THREE places: `resolve_entry_name`, `list_files`'s inline
    //! pair, and `share_list`'s inline `match` below. ROOTS §3.5 — *a decision replicated
    //! across two surfaces will diverge; care is not the mitigation* — and bug139 is the
    //! proof-by-history: bug132(ii)'s fix reached one surface and missed its sibling.
    //!
    //! `share_list` is **correct by implementation but was covered by zero tests**. Gus's
    //! S163 sweep classified the callers: `folder_create` / `folder_rename` / `file_rename` /
    //! `share_invite` / `DecryptName` are **targeted ops where aborting is CORRECT** — you
    //! named the object, so failing loudly is right — and are properly out of set. The
    //! LISTING surfaces, where degrade-per-row is the property, are exactly three, and this
    //! is the third.
    //!
    //! This test exists so that deleting the last live malformed folder (`a2ddad8b`) does not
    //! leave this surface unwitnessed. Unifying the three homes is agreed but deliberately
    //! NOT blocking the deletion — it rides the next CLI-touching round.

    use super::*;
    use crate::test_support::{junk_wrap_body, spawn_json_server, test_handle, test_keystore};

    /// ⭐ **The two-sided fixture** — one share folder genuinely DECRYPTABLE, one poisoned.
    ///
    /// ⚠ This replaces a first version that asserted only `share_list(...).is_ok()`. Gus's
    /// S163 review caught that such an assertion **cannot see the harm it documents**: it
    /// cannot tell `[2 rows, names null]` from `[0 rows]`, so a degrade that silently DROPPED
    /// undecryptable rows, or an empty-but-Ok listing, would both have passed — and an
    /// empty-but-Ok listing is the original bug's exact user-visible harm minus the exit code.
    /// The doc-comment claimed "one poisoned share never hides the others" while the assertion
    /// could not check it. That is the bug140 shape, in the test that is about to become this
    /// surface's permanent witness.
    #[test]
    fn share_list_degrades_the_poisoned_row_and_keeps_the_healthy_one() {
        let healthy = Uuid::new_v4();
        let poisoned = Uuid::new_v4();
        let key: [u8; 32] = [31u8; 32];

        // A REAL name the resolver can decrypt, under a root whose key we pre-seed.
        let healthy_name = signet_crypto::encname::encrypt_name(
            &key,
            healthy.as_bytes(),
            healthy.as_bytes(),
            "Quarterly",
        )
        .expect("fixture: encrypt a valid share name");

        let folders = vec![
            serde_json::json!({
                "folder_id": poisoned, "root_folder_id": poisoned, "permission": "read",
                "encrypted_name": { "adversarial": "F005-junkwrap-name" }
            }),
            serde_json::json!({
                "folder_id": healthy, "root_folder_id": healthy, "permission": "write",
                "encrypted_name": healthy_name
            }),
        ];

        // The poisoned root's wrap is fetched and is junk; the healthy root never hits the
        // network because its key is pre-seeded.
        let port = spawn_json_server("{}".to_string(), junk_wrap_body());
        let (_dir, ks, signing, kem) = test_keystore();
        let url = format!("http://127.0.0.1:{port}");
        let mut resolver = Resolver::new(&ks, &signing, &kem, &url);
        resolver.preseed_metadata_key(healthy, key);

        let entries = share_entries(&mut resolver, &folders)
            .expect("an undecryptable share name must never abort the listing");

        assert_eq!(
            entries.len(),
            2,
            "BOTH rows must be present. A degrade that DROPS the unreadable row is not a \
             degrade — it is the same denial as an abort, just silent. Got: {entries:?}"
        );

        let h = entries
            .iter()
            .find(|e| e.folder_id == healthy)
            .expect("healthy row present");
        assert_eq!(
            h.name.as_deref(),
            Some("Quarterly"),
            "the healthy share must still decrypt to its REAL name beside the poisoned one — \
             this is the assertion that makes \"one poisoned share never hides the others\" \
             checkable rather than merely claimed"
        );

        let p = entries
            .iter()
            .find(|e| e.folder_id == poisoned)
            .expect("poisoned row present");
        assert!(
            p.name.is_none(),
            "the poisoned share must degrade to null, got {:?}",
            p.name
        );
    }

    /// A share folder whose name cannot be decrypted degrades to `None` and the listing
    /// still succeeds — one poisoned share never hides the others.
    #[test]
    fn share_list_degrades_a_poisoned_share_folder_instead_of_aborting() {
        let poisoned = Uuid::new_v4();
        let healthy = Uuid::new_v4();

        // Both rows carry a name; neither root's wrap can be unwrapped, so `decrypt_name`
        // returns Err per row and the inline match must degrade each to None. The property
        // under test is that `share_list` still returns Ok — pre-degrade, an Err here would
        // have denied the user their entire "shared with me" view.
        let listing = serde_json::json!({
            "folders": [
                { "folder_id": poisoned, "root_folder_id": poisoned,
                  "permission": "read",
                  "encrypted_name": { "adversarial": "F005-junkwrap-name" } },
                { "folder_id": healthy, "root_folder_id": healthy,
                  "permission": "write",
                  "encrypted_name": { "adversarial": "also-unreadable" } },
            ]
        })
        .to_string();

        let port = spawn_json_server(listing, junk_wrap_body());
        let (_dir, ks, signing, kem) = test_keystore();
        let handle = test_handle();
        let url = format!("http://127.0.0.1:{port}");
        let config = Config::default();
        let out = OutputMode { pretty: false };

        let signing_arg = signing.full();
        let kem_arg = kem.full();

        let result = share_list(
            &ks,
            true, // --json, so the assertion does not depend on table formatting
            Some(&signing_arg),
            Some(&kem_arg),
            &url,
            &config,
            &out,
        );

        assert!(
            result.is_ok(),
            "bug139's property on the THIRD surface: an undecryptable share-folder name must \
             degrade to null, never abort the listing. Acting as handle {handle:?}. Got: {:?}",
            result.err()
        );
    }
}

/// bug149 — the published-root judgment's full decision table, tested without HTTP
/// by injecting the consistency fetch. Logs are fabricated locally with the same
/// `signet_crypto::merkle` the server uses, so the positive control (an honest
/// advance verifies) and the negative control (a rewritten history is refused)
/// exercise the real primitive, not a mock of it.
///
/// ⚠ Negative control RUN (S165): with the extension check disabled (`extends`
/// forced true), exactly `a_rewritten_history_is_refused` and
/// `an_unrelated_proof_is_refused` go RED while the other six stay green — the
/// discriminating split. (Run on the uncommitted tree; re-run after commit.)
#[cfg(test)]
mod transparency_verify_tests {
    use super::{PublishedRootVerdict, judge_published_root};
    use signet_crypto::merkle;

    /// A deterministic fabricated log of `n` entry hashes.
    fn entries(n: usize) -> Vec<[u8; 32]> {
        (0..n).map(|i| [i as u8; 32]).collect()
    }

    fn no_fetch(_: u64, _: u64) -> crate::error::Result<Vec<[u8; 32]>> {
        panic!("this arm must not fetch a consistency proof");
    }

    #[test]
    fn no_published_root_is_informational() {
        let e = entries(9);
        let root = merkle::merkle_root(&e);
        let v = judge_published_root(&root, 9, None, no_fetch).unwrap();
        assert_eq!(v, PublishedRootVerdict::NoPublishedRoot);
    }

    #[test]
    fn same_size_equal_roots_match() {
        let e = entries(9);
        let root = merkle::merkle_root(&e);
        let v = judge_published_root(&root, 9, Some((root, 9)), no_fetch).unwrap();
        assert_eq!(v, PublishedRootVerdict::MatchAtSameSize);
    }

    #[test]
    fn same_size_different_root_is_a_violation() {
        let e = entries(9);
        let root = merkle::merkle_root(&e);
        let forged = merkle::merkle_root(&entries(8));
        let v = judge_published_root(&root, 9, Some((forged, 9)), no_fetch).unwrap();
        assert_eq!(v, PublishedRootVerdict::RootMismatchAtSameSize);
    }

    #[test]
    fn a_shrunken_log_is_a_violation() {
        let e = entries(6);
        let root = merkle::merkle_root(&e);
        let published = merkle::merkle_root(&entries(9));
        let v = judge_published_root(&root, 6, Some((published, 9)), no_fetch).unwrap();
        assert_eq!(
            v,
            PublishedRootVerdict::LogShrank {
                published: 9,
                proof: 6
            }
        );
    }

    /// ⭐ The positive control — the exact shape T1 leg 4 hit live (bug149): the log
    /// grew 65→69 past the published snapshot and the OLD code cried violation. An
    /// honest advance with a genuine consistency proof must be exit-0 territory.
    #[test]
    fn an_honest_advance_verifies() {
        let e = entries(9);
        let published_root = merkle::merkle_root(&e[..5]);
        let current_root = merkle::merkle_root(&e);
        let nodes = merkle::consistency_proof(&e, 5);
        let v = judge_published_root(&current_root, 9, Some((published_root, 5)), |from, to| {
            assert_eq!((from, to), (5, 9));
            Ok(nodes.clone())
        })
        .unwrap();
        assert_eq!(
            v,
            PublishedRootVerdict::ConsistentAdvance { from: 5, to: 9 }
        );
    }

    /// ⭐ The negative control — the attack the check exists for: history rewritten
    /// after the publish (entry 2 replaced), server presents its forged tree's own
    /// internally-valid consistency proof. Both roots are bound LOCALLY (the
    /// published anchor + the inclusion-verified proof root), so the forged nodes
    /// cannot verify and the verdict must be NotAnExtension. Without this test a
    /// judgment that answered ConsistentAdvance unconditionally would look fixed —
    /// the same defect wearing the other mask (bug149 §4).
    #[test]
    fn a_rewritten_history_is_refused() {
        let honest = entries(9);
        let published_root = merkle::merkle_root(&honest[..5]);
        let mut forged = honest.clone();
        forged[2] = [0xAA; 32];
        let forged_root = merkle::merkle_root(&forged);
        // The server's best lie: a proof that IS valid for its own forged tree.
        let forged_nodes = merkle::consistency_proof(&forged, 5);
        let v = judge_published_root(&forged_root, 9, Some((published_root, 5)), |_, _| {
            Ok(forged_nodes.clone())
        })
        .unwrap();
        assert_eq!(v, PublishedRootVerdict::NotAnExtension { from: 5, to: 9 });
    }

    /// Garbage proof nodes must also refuse — a truncated or unrelated proof is not
    /// a softer failure than a forged one.
    #[test]
    fn an_unrelated_proof_is_refused() {
        let e = entries(9);
        let published_root = merkle::merkle_root(&e[..5]);
        let current_root = merkle::merkle_root(&e);
        let v = judge_published_root(&current_root, 9, Some((published_root, 5)), |_, _| {
            Ok(vec![[0x11; 32], [0x22; 32]])
        })
        .unwrap();
        assert_eq!(v, PublishedRootVerdict::NotAnExtension { from: 5, to: 9 });
    }

    /// The sanity floor: the honest nodes for the honest pair, checked straight
    /// against the crypto primitive — if THIS fails the fabrication helpers are
    /// wrong and every other assertion here is noise.
    #[test]
    fn the_fabricated_log_is_self_consistent() {
        let e = entries(9);
        assert!(merkle::verify_consistency(
            5,
            9,
            &merkle::merkle_root(&e[..5]),
            &merkle::merkle_root(&e),
            &merkle::consistency_proof(&e, 5),
        ));
    }
}

#[cfg(test)]
mod bug180_partial_download_tests {
    use super::{TempFileGuard, download_temp_path};
    use std::path::Path;

    /// The temp APPENDS `.part` rather than replacing the extension. Replacing
    /// it (`report.pdf` -> `report.part`) could collide with a real sibling the
    /// caller owns, and this fix must never destroy a file it did not create.
    #[test]
    fn temp_path_appends_and_stays_in_the_same_directory() {
        let out = Path::new("/tmp/finance/report.pdf");
        let tmp = download_temp_path(out);
        assert_eq!(tmp, Path::new("/tmp/finance/report.pdf.part"));
        // Same directory: a cross-filesystem rename is a copy, which would
        // reintroduce a window where the real name exists and is short.
        assert_eq!(tmp.parent(), out.parent());
        // No extension, and a dotfile, both keep the whole name.
        assert_eq!(
            download_temp_path(Path::new("/tmp/archive")),
            Path::new("/tmp/archive.part")
        );
        assert_eq!(
            download_temp_path(Path::new("/tmp/.hidden")),
            Path::new("/tmp/.hidden.part")
        );
    }

    /// ⚠ THE NEGATIVE CONTROL. An armed guard must actually delete — this is the
    /// whole defect. If it ever stops, a failed download silently goes back to
    /// stranding a valid-but-short file.
    #[test]
    fn an_armed_guard_removes_the_partial() {
        let dir = std::env::temp_dir().join("bug180-armed");
        std::fs::create_dir_all(&dir).unwrap();
        let partial = dir.join("report.pdf.part");
        std::fs::write(&partial, b"first 7 of 12 chunks").unwrap();
        assert!(partial.exists(), "precondition: the partial is on disk");
        {
            let _guard = TempFileGuard(Some(partial.clone()));
        } // dropped here, as it would be on any `?` in the chunk loop
        assert!(!partial.exists(), "the partial must be gone");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The POSITIVE half: a disarmed guard must NOT delete. Without this, a
    /// guard that deleted unconditionally would pass the test above while
    /// destroying every successful download — the most damaging way this could
    /// be wrong, and invisible to a delete-only test.
    #[test]
    fn a_disarmed_guard_leaves_the_completed_file() {
        let dir = std::env::temp_dir().join("bug180-disarmed");
        std::fs::create_dir_all(&dir).unwrap();
        let final_path = dir.join("report.pdf");
        std::fs::write(&final_path, b"all 12 chunks").unwrap();
        {
            let mut guard = TempFileGuard(Some(final_path.clone()));
            guard.disarm();
        }
        assert!(
            final_path.exists(),
            "a disarmed guard must never delete — this is the success path"
        );
        assert_eq!(std::fs::read(&final_path).unwrap(), b"all 12 chunks");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A cleanup failure (already-gone temp) must not panic: the download has
    /// already failed and the caller is owed THAT error, not a cleanup one.
    #[test]
    fn cleanup_of_a_missing_temp_is_silent() {
        let missing = std::env::temp_dir().join("bug180-never-existed.part");
        std::fs::remove_file(&missing).ok();
        drop(TempFileGuard(Some(missing)));
    }
}
