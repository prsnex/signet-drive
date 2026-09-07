// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! CLI error model + exit codes (owner: `Signet-Drive-CLI-Spec` §"Exit codes").
//!
//! The reference is deliberately **version-agnostic** (the S038 rule: name the owner,
//! not its version — the structural fix for label-lag). This line read "CLI Spec v08"
//! until S140, ten versions stale, which is the drift the rule exists to prevent.
//!
//! Every failure carries the spec's numeric exit code, a stable machine code
//! (for `--json-errors`), and a one-line human message. `main` renders it to
//! stderr (human or JSON) and exits with the code. The ranges:
//! 0 success · 1 generic · 2 invalid args · 8 info · 10–19 key/auth ·
//! 20–29 I/O · 30–39 network · 40–49 crypto · 50–59 config · 60–69 transparency.

use std::fmt;

/// A CLI failure: exit code + machine code + human message.
#[derive(Debug)]
pub struct CliError {
    pub exit_code: i32,
    pub code: &'static str,
    pub message: String,
}

impl CliError {
    pub fn new(exit_code: i32, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            exit_code,
            code,
            message: message.into(),
        }
    }

    /// 1 — generic error (no specific category fits).
    pub fn generic(message: impl Into<String>) -> Self {
        Self::new(1, "error", message)
    }

    /// 2 — invalid arguments (bad flags, malformed label, mutually-exclusive misuse).
    pub fn invalid_args(message: impl Into<String>) -> Self {
        Self::new(2, "invalid_arguments", message)
    }

    /// 11 — a key with this label + purpose already exists.
    pub fn key_exists(message: impl Into<String>) -> Self {
        Self::new(11, "key_already_exists", message)
    }

    /// 12 — key not found by label.
    pub fn key_not_found(message: impl Into<String>) -> Self {
        Self::new(12, "key_not_found", message)
    }

    /// 21 — filesystem error (keystore dir/perms).
    pub fn filesystem(message: impl Into<String>) -> Self {
        Self::new(21, "filesystem_error", message)
    }

    /// 22 — input read error.
    pub fn input_read(message: impl Into<String>) -> Self {
        Self::new(22, "input_error", message)
    }

    /// 23 — output write error.
    pub fn output_write(message: impl Into<String>) -> Self {
        Self::new(23, "output_error", message)
    }

    /// 24 — malformed input data (bad envelope JSON, bad `--to-pubkey` value/format).
    pub fn invalid_data(message: impl Into<String>) -> Self {
        Self::new(24, "invalid_data", message)
    }

    /// 25 — name too long (encrypt-name; > 255 bytes).
    pub fn name_too_long(message: impl Into<String>) -> Self {
        Self::new(25, "name_too_long", message)
    }

    /// 40 — encryption failure.
    pub fn encryption_failed(message: impl Into<String>) -> Self {
        Self::new(40, "encryption_failed", message)
    }

    /// 41 — algorithm/key-purpose mismatch (e.g. `sign` given a KEM key).
    pub fn unsupported_algorithm(message: impl Into<String>) -> Self {
        Self::new(41, "unsupported_algorithm", message)
    }

    /// 42 — decrypt / unwrap failure (tag mismatch — wrong key or tampered blob).
    pub fn decrypt_failed(message: impl Into<String>) -> Self {
        Self::new(42, "decrypt_failed", message)
    }

    /// 50 — config error (missing/malformed config, bad value).
    pub fn config(message: impl Into<String>) -> Self {
        Self::new(50, "config_error", message)
    }

    /// 51 — platform-capability error (e.g. legacy Mac / no Secure Enclave).
    pub fn unsupported_platform(message: impl Into<String>) -> Self {
        Self::new(51, "unsupported_platform", message)
    }

    /// 52 — the Mac is locked: Secure-Enclave keys are lock-gated
    /// (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`) and unavailable until a
    /// human unlocks the session (bug057). Temporary and externally-clearable —
    /// a harness can branch "wait for unlock, then retry" off this code, the way
    /// 32 `transfer_stalled` keys retry-later on the network path.
    pub fn se_locked(message: impl Into<String>) -> Self {
        Self::new(52, "se_locked", message)
    }

    /// 13 — server/attestation signature did not verify.
    pub fn signature_invalid(message: impl Into<String>) -> Self {
        Self::new(13, "signature_invalid", message)
    }

    /// 14 — attestation expired.
    pub fn attestation_expired(message: impl Into<String>) -> Self {
        Self::new(14, "attestation_expired", message)
    }

    /// 15 — attestation revoked.
    pub fn attestation_revoked(message: impl Into<String>) -> Self {
        Self::new(15, "attestation_revoked", message)
    }

    /// 10 — the server did not accept the request's authentication (HTTP 401):
    /// a missing/invalid signature, a stale timestamp, a replayed nonce, or an
    /// attestation the server rejects (expired / revoked / unknown). Distinct from
    /// 13 `signature_invalid`, which is a *local* check of a server/attestation
    /// signature — this is the server refusing the CLI's own request auth.
    pub fn authentication_failed(message: impl Into<String>) -> Self {
        Self::new(10, "authentication_failed", message)
    }

    /// 17 — the server authenticated the request but refused it (HTTP 403):
    /// insufficient sharing capability, a read-only/over-quota account, or an
    /// admin-only route. An authorization refusal, not a network failure — the
    /// server reached us and answered.
    pub fn authorization_denied(message: impl Into<String>) -> Self {
        Self::new(17, "authorization_denied", message)
    }

    /// 18 — the upload cannot fit: it exceeds the server's single-file ceiling, or the
    /// Guardian group's pooled quota has less room than the upload needs (bug070).
    ///
    /// **Why this is not 2 `invalid_arguments`** (which it used to be, S140): nothing
    /// about the command was malformed. The arguments were valid, the file was real, and
    /// the same invocation would succeed unchanged the moment space exists. Reporting a
    /// capacity condition as user error tells a harness to stop and fix its command line,
    /// which is precisely the wrong action.
    ///
    /// **Why not 17 `authorization_denied`**, which does mention over-quota: 17's contract
    /// is that *the server reached us and answered*. This refusal is raised **client-side,
    /// before any byte is sent** — reusing 17 would make the exit code lie about where the
    /// refusal came from, and a harness distinguishing local pre-flight from server verdict
    /// would be misled.
    ///
    /// Semantically HTTP 507. Like 17 it is a *refusal*, not a fault: retrying unchanged
    /// will not help, so a harness should surface it to a human (free space, or move to a
    /// larger plan) rather than back off and retry the way it would for 31/32.
    pub fn insufficient_storage(message: impl Into<String>) -> Self {
        Self::new(18, "insufficient_storage", message)
    }

    /// 26 — the server reported the referenced resource does not exist (HTTP 404):
    /// e.g. no such recipient handle, or a share folder that isn't there. A server
    /// *semantic* response (the server reached us and answered), distinct from the
    /// client-side `name_not_found` (exit 2, a local resolver miss) and from a
    /// network failure.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(26, "not_found", message)
    }

    /// 27 — the request conflicts with current server state (HTTP 409): e.g. the
    /// handle is already a recipient of the share. A server semantic response, not a
    /// network failure or an optimistic-concurrency error.
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(27, "conflict", message)
    }

    /// 32 — a direct-to-storage transfer exhausted its per-part attempt budget:
    /// every attempt stalled or failed on a fresh connection — a bad network
    /// window between this host and object storage (bug047). The upload is left
    /// in place server-side and a resume state file is kept: **re-running the
    /// same upload command resumes from the parts already stored.** Distinct
    /// from 31 `network_error` (non-resumable) so a harness can key the
    /// retry-later behavior off the exit code.
    pub fn transfer_stalled(message: impl Into<String>) -> Self {
        Self::new(32, "transfer_stalled", message)
    }

    /// 60 — transparency/verification mismatch (proof valid but ≠ public root, etc.).
    pub fn transparency_violation(message: impl Into<String>) -> Self {
        Self::new(60, "transparency_violation", message)
    }

    /// 61 — launch-binding verification failed: the container's host-signer-pinned
    /// PRSN handle does not match the harness-asserted `SIGNET_HANDLE`. A *local*,
    /// fail-closed safety refusal — the in-container `signet` will not act as the
    /// wrong identity — distinct from a server authorization refusal (17) or a
    /// network failure. See `keystore::verify_channel_identity`.
    pub fn identity_mismatch(message: impl Into<String>) -> Self {
        Self::new(61, "identity_mismatch", message)
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for CliError {}

/// At-rest keystore decrypt/seal failures map to crypto/auth exit codes; a bad
/// public-key/point or unknown algorithm is invalid input at the CLI boundary.
impl From<signet_crypto::CryptoError> for CliError {
    fn from(e: signet_crypto::CryptoError) -> Self {
        use signet_crypto::CryptoError::*;
        match e {
            Authentication => CliError::decrypt_failed(e.to_string()),
            SignatureInvalid => CliError::new(13, "signature_invalid", e.to_string()),
            UnknownAlgorithm => CliError::unsupported_algorithm(e.to_string()),
            InvalidInput(_) => CliError::invalid_args(e.to_string()),
        }
    }
}

pub type Result<T> = std::result::Result<T, CliError>;
