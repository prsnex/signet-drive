// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! `signet enroll <code>` — the human-initiated PRSN onboarding flow (S052; S063
//! human-initiated only; canonical design: `Signet-Drive-PRSN-Account-and-Kit-Spec`
//! §a–c).
//!
//! The human Guardian starts the enrollment from the Signet Drive web app ("+ Add account")
//! and hands the agent the one-time `code`. This drives the agent's side of the
//! server-mediated rendezvous. **The Kit is retired** (S076 — Account-and-Kit §c):
//! identity is *discovered* (the channel pin / `SIGNET_HANDLE`), not carried in a
//! visible folder, so enrollment writes at most an optional hidden config default.
//!
//! 0. **Idempotency** (Zain F6): if the harness asserts our handle (`SIGNET_HANDLE`)
//!    and both classical keys already exist, succeed as a **no-op** — so `enroll` can
//!    sit in the every-wake routine. (Deliberately the CLASSICAL pair: a pre-7a
//!    two-key PRSN is enrolled — its every-wake no-op must keep working; going
//!    hybrid is a fresh, guardian-opened re-enrollment, not this fast-path's job.)
//!    Only when *not* already enrolled is a `code` required.
//! 1. `join` → claim the single-use `submit_token` (delivered to the agent over its
//!    direct connection, never via the browser — so a leaked code can't submit keys;
//!    review M4).
//! 2. Poll until the human **confirms** in their browser (naming the PRSN).
//! 3. On `confirmed`: **keygen-into-SE** — all FOUR keypairs (item 7a: ES256 + ECDH
//!    classical, ML-DSA-87 + ML-KEM-1024 via the CryptoKit shim), then `submit-keys`
//!    (the four PUBLIC keys + fingerprints + the token), which returns the PoP
//!    challenge + a nonce wrapped to our hybrid KEM pair.
//! 4. **The proof-of-possession** (Enrollment-Ceremony ops doc §3): dual-sign the
//!    challenge (`ES256` + `ML-DSA-87(ctx = signet:attest:v1)` over identical bytes,
//!    spec §8.7) and unwrap the nonce through our own keystore — the end-to-end
//!    self-test of the whole hybrid wrap path (SE · shim · combiner · both halves) —
//!    then `keys/pop` to reach `keys_submitted`.
//! 5. Poll until `completed` (the human's passkey approval issues the attestation).
//! 6. Write the optional hidden config default (no visible Kit), best-effort, and report.
//!    The step can never fail the enrollment (bug282): the server has attested the keys.
//!
//! The agent is **never authenticated** — it holds only the single-use `code` the
//! human handed it and the `submit_token` it claimed; ALL authorization is the
//! human's (their session created + confirms the enrollment, their passkey attests).
//! If anything fails after keygen, the just-generated keys + any partial Kit are
//! cleaned up (orphaned-Kit cleanup, §b).
//!
//! Native path only here (the only built backend): the keys are in the device Secure
//! Enclave. The containerized host-delegation path is a committed-v1 but gated build
//! (Account-and-Kit §Gates), so it isn't wired in this increment.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;
use serde_json::Value;

use crate::commands;
use crate::config::{self, Config};
use crate::error::{CliError, Result};
use crate::http;
use crate::keystore::{self, KeyLabel, KeyMeta, Keystore, Purpose, Tier};
use crate::output::OutputMode;

/// A hard ceiling on the agent's total wait per phase. The server's rendezvous TTL
/// is the real bound (a swept enrollment reports `expired`); this is a backstop so
/// the agent never hangs forever.
const MAX_POLL: Duration = Duration::from_secs(3600);

/// Poll cadence, overridable via `SIGNET_ENROLL_POLL_MS` (tests drive it fast).
fn poll_interval() -> Duration {
    std::env::var("SIGNET_ENROLL_POLL_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(Duration::from_secs(2))
}

/// The fields the agent acts on from a status poll (a subset of the server's
/// `PollResponse`).
struct PollState {
    handle: Option<String>,
    attestation_id: Option<String>,
}

/// The machine-readable result on stdout (progress goes to stderr).
#[derive(Serialize)]
struct EnrollResult {
    handle: String,
    key_protection: String,
    attestation_id: Option<String>,
    /// The hidden config default written (Account-and-Kit §c), or omitted when none was
    /// written (a multi-PRSN host where SIGNET_HANDLE selects, or the no-op path).
    #[serde(skip_serializing_if = "Option::is_none")]
    config_path: Option<String>,
    /// True on the idempotent already-enrolled no-op path (Zain F6).
    already_enrolled: bool,
}

/// `signet enroll [CODE]`.
///
/// S063: **human-initiated only.** The human Guardian opens the enrollment from the
/// web "+ Add account" page and hands the agent the one-time `CODE`; the agent joins it
/// (claiming its `submit_token`), waits for the human to confirm, then keygen →
/// submit → attestation. There is no agent-first path: only a logged-in human can open
/// an enrollment.
///
/// **Idempotent** (S076, Zain F6): `CODE` is optional. If the harness asserts our
/// handle (`SIGNET_HANDLE`) and we are already enrolled, this is a success **no-op** —
/// so it can live in the every-wake routine. Only a *not-yet-enrolled* agent needs a
/// `CODE`.
pub fn enroll(base_url: &str, code: Option<&str>, config: &Config, out: &OutputMode) -> Result<()> {
    let base = base_url.trim_end_matches('/');

    // Open the keystore up front: it drives both the idempotency fast-path and the
    // enrollment. For a containerized PRSN this runs the launch-binding cross-check
    // (`keystore::open`), so a wake with a wrong `SIGNET_HANDLE` fails closed here.
    let keystore = keystore::open(config)?;

    // (0) Idempotency: if the harness asserts our handle and both keys already exist,
    //     we are enrolled → succeed as a no-op. Any keystore error (e.g. a container
    //     channel not yet pinned) reads as "not enrolled" and falls through.
    if let Some(handle) = commands::asserted_handle() {
        let signing = KeyLabel::from_handle(&handle, Purpose::Signing)?;
        let kem = KeyLabel::from_handle(&handle, Purpose::Kem)?;
        if keystore.exists(&signing).unwrap_or(false) && keystore.exists(&kem).unwrap_or(false) {
            // §1-62 PR-D (design note §6.3): the no-code re-run is the agent's
            // universal "where am I" move — DERIVE the state and say what's next,
            // instead of a bare "nothing to do". Best-effort: a status-query
            // failure must never fail the no-op (it IS a no-op), so any error
            // falls back to the static line.
            let state_line =
                crate::http::get_json_signed(keystore.as_ref(), &signing, base, "/v1/me")
                    .ok()
                    .and_then(|me| {
                        let da = me.get("drive_access")?;
                        Some(drive_access_line(
                            da.get("status")?.as_str()?,
                            da.get("overdue").and_then(|v| v.as_bool()).unwrap_or(false),
                        ))
                    })
                    .unwrap_or_else(|| {
                        "If you're setting up Signet Drive access, your guardian continues \
                     from their account page; run `signet whoami` to check your own access."
                            .to_string()
                    });
            progress(&format!(
                "already enrolled as '{handle}'. Nothing to do. {state_line}"
            ));
            return out.print_json(&EnrollResult {
                handle,
                key_protection: keystore.tier().wire_str().to_string(),
                attestation_id: None,
                config_path: None,
                already_enrolled: true,
            });
        }
    }

    // Not enrolled → a one-time enrollment CODE is required (the guardian opens
    // "+ Add account" in Signet Drive and hands it to the agent — S063 human-initiated).
    let code = code.ok_or_else(|| {
        CliError::invalid_args(
            "not enrolled yet, and no enrollment CODE was given. Ask your guardian to open \
             \"+ Add account\" under PRSN Accounts in Signet Drive and hand you the one-time code, then run \
             `signet enroll <CODE>`. (If you ARE enrolled, set SIGNET_HANDLE so I can tell.)",
        )
    })?;

    // (1) Join to claim our submit_token — delivered over our direct connection, never
    //     through the browser, so a leaked code can't submit keys (review M4). Mint-once.
    progress("joining the enrollment your guardian opened…");
    let submit_token = join(base, code)?;

    // (2) Wait for the human to confirm (they name the PRSN in their browser). A
    //     terminal state here fails before any keys exist — nothing to clean up.
    progress("waiting for your human to confirm (they name you in their browser)…");
    let confirmed = poll_until(base, code, "confirmed", "confirmation")?;
    let handle = confirmed
        .handle
        .ok_or_else(|| CliError::invalid_data("server reported 'confirmed' without a handle"))?;
    progress(&format!(
        "confirmed as '{handle}'. Generating keys in the Secure Enclave…"
    ));

    // (3–5) keygen → submit + PoP → await attestation → write the optional hidden
    //       config. From the first keygen on, any failure cleans up all four
    //       just-generated keys.
    let labels = EnrollLabels {
        signing: KeyLabel::from_handle(&handle, Purpose::Signing)?,
        kem: KeyLabel::from_handle(&handle, Purpose::Kem)?,
        signing_pq: KeyLabel::from_handle(&handle, Purpose::SigningPq)?,
        kem_pq: KeyLabel::from_handle(&handle, Purpose::KemPq)?,
    };

    match complete(
        base,
        code,
        &submit_token,
        &handle,
        keystore.as_ref(),
        &labels,
    ) {
        Ok(result) => {
            progress(&format!(
                "done. Your Signet Drive account '{}' is ready. Tell your guardian; \
                 they authorize your Drive access next, from their account page. \
                 Once they have, run `signet connect`. Some setups connect on their \
                 own with the first Signet Drive command.",
                result.handle
            ));
            out.print_json(&result)
        }
        Err(e) => {
            cleanup_keys(keystore.as_ref(), &labels);
            Err(e)
        }
    }
}

/// The four key labels one enrollment generates (item 7a — the hybrid identity).
struct EnrollLabels {
    signing: KeyLabel,
    kem: KeyLabel,
    signing_pq: KeyLabel,
    kem_pq: KeyLabel,
}

/// `POST /v1/prsn-enrollments/join` — claim the single-use `submit_token` that gates
/// submit-keys (S063, review M4). The server delivers it to the agent here, over the
/// agent's direct connection — never via the human's browser — so a leaked enrollment
/// code cannot, on its own, register keys. Mint-once: if a second agent already
/// joined this code, the server refuses (404) and we abort.
fn join(base: &str, code: &str) -> Result<String> {
    let body = serde_json::json!({ "code": code });
    let bytes = serde_json::to_vec(&body)
        .map_err(|e| CliError::generic(format!("serializing join body: {e}")))?;
    let resp = http::post_json(&format!("{base}/v1/prsn-enrollments/join"), Some(&bytes))?;
    json_str(&resp, "submit_token")
}

/// keygen → submit-keys → the PoP → await the attestation → write the optional
/// config. Split out so the caller can clean up the generated keys on any failure
/// in this stretch.
fn complete(
    base: &str,
    code: &str,
    submit_token: &str,
    handle: &str,
    ks: &dyn Keystore,
    labels: &EnrollLabels,
) -> Result<EnrollResult> {
    let signing_meta = ks.generate(&labels.signing, Purpose::Signing.default_alg())?;
    let kem_meta = ks.generate(&labels.kem, Purpose::Kem.default_alg())?;
    let signing_pq_meta = ks.generate(&labels.signing_pq, Purpose::SigningPq.default_alg())?;
    let kem_pq_meta = ks.generate(&labels.kem_pq, Purpose::KemPq.default_alg())?;

    let pop = submit_keys(
        base,
        code,
        submit_token,
        &signing_meta,
        &kem_meta,
        &signing_pq_meta,
        &kem_pq_meta,
        ks.tier(),
    )?;

    // The proof-of-possession (step 4): dual-sign the challenge with both signing
    // keys over IDENTICAL bytes (spec §8.7 — the shared builder), and unwrap
    // the nonce through our own keystore — the end-to-end hybrid self-test.
    progress("proving possession (dual-sign + hybrid unwrap self-test)…");
    let msg = signet_crypto::attest::enroll_pop_signing_base(&pop.challenge);
    let sig_es256 = ks.sign(&labels.signing, &msg)?;
    let sig_mldsa87 = ks.ml_dsa_sign(
        &labels.signing_pq,
        &msg,
        signet_crypto::attest::ENROLL_POP_MLDSA_CTX,
    )?;
    let nonce =
        crate::hybrid::unwrap_key_hybrid(ks, &labels.kem, &labels.kem_pq, &pop.envelope, &[])?;
    submit_pop(
        base,
        code,
        submit_token,
        &sig_es256,
        &sig_mldsa87,
        &nonce[..],
    )?;
    progress("submitted. Waiting for your human to approve with their passkey (the attestation)…");

    let completed = poll_until(base, code, "completed", "the attestation")?;
    // The Kit is retired (Account-and-Kit §c): no visible folder, no `keys.pub`, no
    // `container/` record (the host-side registry is authoritative). Write at most the
    // optional hidden config default — the single-PRSN native convenience.
    // ⛔ bug282 (Gus): no `?` here. The server has attested these keys, and an error out
    // of `complete()` runs `cleanup_keys`, which would delete the Secure Enclave keys of a
    // completed enrollment — irreversibly — over an optional file.
    let config_path = write_default_config(
        base,
        ks,
        handle,
        &signing_meta,
        &kem_meta,
        &config::config_file_path(),
    );

    Ok(EnrollResult {
        handle: handle.to_string(),
        key_protection: ks.tier().wire_str().to_string(),
        attestation_id: completed.attestation_id,
        config_path: config_path.map(|p| p.display().to_string()),
        already_enrolled: false,
    })
}

/// The PoP artifacts `submit_keys` returns (item 7a): the raw 32-byte challenge
/// and the nonce envelope wrapped to our hybrid KEM pair.
struct PopChallenge {
    challenge: Vec<u8>,
    envelope: signet_crypto::hybrid_wrap::HybridWrapEnvelope,
}

/// `POST /v1/prsn-enrollments/keys` — submit the FOUR public keys + fingerprints +
/// the `key_protection` wire value (the server enforces `secure_enclave`), and
/// receive the PoP challenge + wrapped nonce (the PoP begin).
#[allow(clippy::too_many_arguments)]
fn submit_keys(
    base: &str,
    code: &str,
    submit_token: &str,
    signing_meta: &KeyMeta,
    kem_meta: &KeyMeta,
    signing_pq_meta: &KeyMeta,
    kem_pq_meta: &KeyMeta,
    tier: Tier,
) -> Result<PopChallenge> {
    // The claimed custody tier is the keystore's own. ONE test affordance,
    // structurally absent from any release binary (`debug_assertions`): a local
    // E2E harness driving a software-tier keystore may claim `secure_enclave`
    // so the full production ceremony (four keys + PoP) runs against the
    // SE-only server — the same synthetic claim the server's own integration
    // tests make when they hand-post the ceremony.
    let claimed_tier = tier.wire_str();
    #[cfg(debug_assertions)]
    let claimed_tier = std::env::var("SIGNET_TEST_CLAIM_KEY_PROTECTION")
        .unwrap_or_else(|_| claimed_tier.to_string());
    let body = serde_json::json!({
        "code": code,
        "submit_token": submit_token,
        "subject_signing_pubkey": URL_SAFE_NO_PAD.encode(&signing_meta.public_key),
        "subject_signing_pubkey_fingerprint": signing_meta.fingerprint,
        "subject_kem_pubkey": URL_SAFE_NO_PAD.encode(&kem_meta.public_key),
        "subject_kem_pubkey_fingerprint": kem_meta.fingerprint,
        "subject_signing_pq_pubkey": URL_SAFE_NO_PAD.encode(&signing_pq_meta.public_key),
        "subject_signing_pq_pubkey_fingerprint": signing_pq_meta.fingerprint,
        "subject_kem_pq_pubkey": URL_SAFE_NO_PAD.encode(&kem_pq_meta.public_key),
        "subject_kem_pq_pubkey_fingerprint": kem_pq_meta.fingerprint,
        "key_protection": claimed_tier,
    });
    let bytes = serde_json::to_vec(&body)
        .map_err(|e| CliError::generic(format!("serializing submit-keys body: {e}")))?;
    let resp = http::post_json(&format!("{base}/v1/prsn-enrollments/keys"), Some(&bytes))?;

    let challenge_b64 = json_str(&resp, "pop_challenge")?;
    let challenge = URL_SAFE_NO_PAD
        .decode(challenge_b64.as_bytes())
        .map_err(|_| CliError::invalid_data("pop_challenge is not base64url"))?;
    let envelope = resp
        .get("pop_nonce_envelope")
        .cloned()
        .ok_or_else(|| CliError::invalid_data("server response missing pop_nonce_envelope"))?;
    let envelope = serde_json::from_value(envelope).map_err(|_| {
        CliError::invalid_data("pop_nonce_envelope is not a hybrid recipient block")
    })?;
    Ok(PopChallenge {
        challenge,
        envelope,
    })
}

/// `POST /v1/prsn-enrollments/keys/pop` — the PoP complete: both signatures over
/// the identical signing base + the unwrapped nonce. Advances the enrollment to
/// `keys_submitted`.
fn submit_pop(
    base: &str,
    code: &str,
    submit_token: &str,
    sig_es256: &[u8; 64],
    sig_mldsa87: &[u8],
    nonce: &[u8],
) -> Result<()> {
    let body = serde_json::json!({
        "code": code,
        "submit_token": submit_token,
        "pop_signature_es256": URL_SAFE_NO_PAD.encode(sig_es256),
        "pop_signature_mldsa87": URL_SAFE_NO_PAD.encode(sig_mldsa87),
        "pop_nonce": URL_SAFE_NO_PAD.encode(nonce),
    });
    let bytes = serde_json::to_vec(&body)
        .map_err(|e| CliError::generic(format!("serializing keys/pop body: {e}")))?;
    http::post_text(
        &format!("{base}/v1/prsn-enrollments/keys/pop"),
        Some(&bytes),
    )?;
    Ok(())
}

/// Poll `GET /v1/prsn-enrollments/status` until `target`, failing on a terminal
/// non-target state (`expired`/`cancelled`/`failed`) or the wait ceiling.
fn poll_until(base: &str, code: &str, target: &str, waiting_for: &str) -> Result<PollState> {
    let url = format!("{base}/v1/prsn-enrollments/status?code={code}");
    let interval = poll_interval();
    let start = SystemTime::now();
    loop {
        let resp = http::get_json(&url, &[])?;
        let status = json_str(&resp, "status")?;
        if status == target {
            return Ok(PollState {
                handle: opt_str(&resp, "handle"),
                attestation_id: opt_str(&resp, "attestation_id"),
            });
        }
        match status.as_str() {
            "expired" => {
                // §1-62 PR-D: an expired CODE cannot be re-run — the actionable
                // instruction is a FRESH code (the prior wording said "run
                // `signet enroll` again", which re-submits the same dead code).
                return Err(CliError::generic(format!(
                    "the enrollment expired while waiting for {waiting_for}. Ask your \
                     guardian for a fresh code (they start over from \"+ Add account\"), \
                     then run `signet enroll <NEW-CODE>`"
                )));
            }
            "cancelled" => {
                return Err(CliError::generic(format!(
                    "the enrollment was cancelled while waiting for {waiting_for}. If \
                     this is unexpected, ask your guardian; they can start over from \
                     \"+ Add account\" with a fresh code"
                )));
            }
            "failed" => {
                return Err(CliError::generic(format!(
                    "the enrollment failed while waiting for {waiting_for}"
                )));
            }
            // pending / confirmed / keys_submitted (i.e. not yet at the target) — wait.
            _ => {}
        }
        if SystemTime::now().duration_since(start).unwrap_or_default() > MAX_POLL {
            return Err(CliError::generic(format!(
                "timed out after {}s waiting for {waiting_for}",
                MAX_POLL.as_secs()
            )));
        }
        std::thread::sleep(interval);
    }
}

// ── The optional hidden config (the Kit is retired — Account-and-Kit §c) ──────

/// What `enroll` does with the Mac's one shared config file (bug282). Pure; unit-tested.
#[derive(Debug, PartialEq, Eq)]
enum ConfigPlan {
    /// No other agent on this Mac and no config file yet: write one (the single-agent
    /// native convenience — the agent then resolves its identity with no `SIGNET_HANDLE`).
    Write,
    /// The keystore holds keys for other agents: leave the config alone, whatever it holds.
    /// A default naming one agent is exactly what bug280 refuses on a multi-identity host.
    OtherAgents(Vec<String>),
    /// A config file exists: never rewrite it. Its `server_base_url` and any default in it
    /// are the user's (bug282 condition 2).
    Existing,
}

/// Decide from the handles the keystore holds and whether the file exists. `held`
/// includes the NEW agent (its four keys exist by now), so it is excluded here — a
/// "held is not empty" test would stop writing on every fresh single-agent Mac (Gus).
fn plan_config(held: &BTreeSet<String>, new_handle: &str, file_exists: bool) -> ConfigPlan {
    let others: Vec<String> = held
        .iter()
        .filter(|h| h.as_str() != new_handle)
        .cloned()
        .collect();
    if !others.is_empty() {
        ConfigPlan::OtherAgents(others)
    } else if file_exists {
        ConfigPlan::Existing
    } else {
        ConfigPlan::Write
    }
}

/// Write the optional hidden config default at `path`, **best-effort**: any error (the
/// keystore listing, the existence read, the directory, the write) prints one line and
/// returns `None`. It never fails the enrollment (see the call site). Returns the path
/// written, or `None` when skipped. Private keys are never written here (they live in
/// the Secure Enclave).
fn write_default_config(
    base: &str,
    ks: &dyn Keystore,
    handle: &str,
    signing_meta: &KeyMeta,
    kem_meta: &KeyMeta,
    path: &Path,
) -> Option<PathBuf> {
    match try_write_default_config(base, ks, handle, signing_meta, kem_meta, path) {
        Ok(written) => written,
        Err(e) => {
            progress(&format!(
                "could not set up this Mac's optional config ({}). Your enrollment is \
                 complete. Set SIGNET_HANDLE={handle} to act as this agent.",
                e.message
            ));
            None
        }
    }
}

fn try_write_default_config(
    base: &str,
    ks: &dyn Keystore,
    handle: &str,
    signing_meta: &KeyMeta,
    kem_meta: &KeyMeta,
    path: &Path,
) -> Result<Option<PathBuf>> {
    let held = commands::held_handles(ks)?;
    // Existence from the path itself, never `Config::load().ok()`: that reads an
    // unparsable file as "no default" and would have rewritten it (Gus).
    let file_exists = match std::fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => {
            return Err(CliError::filesystem(format!(
                "reading {}: {e}",
                path.display()
            )));
        }
    };
    match plan_config(&held, handle, file_exists) {
        ConfigPlan::OtherAgents(others) => {
            let n = others.len();
            progress(&format!(
                "this Mac holds {n} other agent{}, so its shared config is left as it is. \
                 Set SIGNET_HANDLE={handle} to act as this agent.",
                if n == 1 { "" } else { "s" }
            ));
            Ok(None)
        }
        ConfigPlan::Existing => {
            progress(&existing_config_line(
                path,
                base,
                &signing_meta.label,
                handle,
            ));
            Ok(None)
        }
        ConfigPlan::Write => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    CliError::filesystem(format!("creating {}: {e}", parent.display()))
                })?;
            }
            // `create_new`: never replace a file that appeared after the existence read.
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(|e| CliError::filesystem(format!("writing {}: {e}", path.display())))?;
            std::io::Write::write_all(
                &mut file,
                default_config_toml(base, signing_meta, kem_meta).as_bytes(),
            )
            .map_err(|e| CliError::filesystem(format!("writing {}: {e}", path.display())))?;
            Ok(Some(path.to_path_buf()))
        }
    }
}

/// The one line `enroll` prints when the config file already exists. Read only to word
/// the line; an unreadable or unparsable file is left alone like any other.
fn existing_config_line(path: &Path, base: &str, new_signing_label: &str, handle: &str) -> String {
    let table: Option<toml::Table> = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.parse().ok());
    let field = |k: &str| {
        table
            .as_ref()
            .and_then(|t| t.get(k))
            .and_then(|v| v.as_str())
            .map(str::to_string)
    };
    let server = field("server_base_url");
    let default = field("default_signing_key");
    if default.as_deref() == Some(new_signing_label) && server.as_deref() == Some(base) {
        return "this Mac's config already names this agent.".to_string();
    }
    match server {
        Some(other) if other != base => format!(
            "left this Mac's config ({}) as it is. It names the server {other}, and this \
             account is on {base}: set SIGNET_HANDLE={handle} and pass --server-url {base} \
             to act as this agent.",
            path.display()
        ),
        _ => format!(
            "left this Mac's config ({}) as it is. Set SIGNET_HANDLE={handle} to act as \
             this agent.",
            path.display()
        ),
    }
}

/// The hidden config's TOML — server URL + the PRSN's default key labels. Preferences
/// only; private keys live in the Secure Enclave, never here.
fn default_config_toml(base: &str, signing_meta: &KeyMeta, kem_meta: &KeyMeta) -> String {
    format!(
        "# Signet Drive per-PRSN config (written by `signet enroll`). Optional + hidden,\n\
         # preferences only: identity is discovered (SIGNET_HANDLE / the channel pin), not\n\
         # carried here. Private keys live in this Mac's Secure Enclave, never in this file.\n\
         server_base_url = \"{base}\"\n\
         default_signing_key = \"{}\"\n\
         default_kem_key = \"{}\"\n",
        signing_meta.label, kem_meta.label
    )
}

// ── Small helpers ──────────────────────────────────────────────────────────────

fn progress(message: &str) {
    eprintln!("signet enroll: {message}");
}

/// The agent-facing "where am I / what's next" line for each Drive-access state
/// (§1-62 PR-D, design note §6.3) — the CLI half of the wizard, in the PRSN's
/// native idiom. Pure (no I/O); unit-tested. States mirror the server's
/// `DriveAccessSummary` (`me.rs`); an unknown status gets the safe generic line
/// rather than a wrong instruction.
fn drive_access_line(status: &str, overdue: bool) -> String {
    match (status, overdue) {
        ("none", _) => "Your guardian hasn't authorized Signet Drive access yet. They do \
                        that from their account page (Signet Drive access). Nothing for \
                        you to run."
            .to_string(),
        ("awaiting_pickup", _) => "Your guardian has authorized you. A connection code from \
                                   them completes the link (your harness's Signet setup \
                                   redeems it). Ask them for the code if you don't have it."
            .to_string(),
        ("awaiting_confirmation", _) => "Connected. Waiting for your guardian to verify your \
                                         connection fingerprint from their account page. \
                                         Nothing for you to run."
            .to_string(),
        ("authorized", true) => "Your Signet Drive access is paused pending your guardian's \
                                 re-confirmation: ask them to re-confirm from their account \
                                 page."
            .to_string(),
        ("authorized", false) => "You're fully set up for Signet Drive. Try `signet whoami` \
                                  or `signet file list`."
            .to_string(),
        _ => "Run `signet whoami` to check your Signet Drive access state.".to_string(),
    }
}

#[cfg(test)]
mod drive_access_line_tests {
    use super::drive_access_line;

    #[test]
    fn each_state_gets_a_distinct_actionable_line() {
        let none = drive_access_line("none", false);
        let pickup = drive_access_line("awaiting_pickup", false);
        let confirm = drive_access_line("awaiting_confirmation", false);
        let ok = drive_access_line("authorized", false);
        let paused = drive_access_line("authorized", true);
        // Distinct, and each names who acts (the load-bearing property: a weak
        // agent must learn what to DO, not just what happened).
        for s in [&none, &pickup, &confirm, &paused] {
            assert!(s.contains("guardian"), "who-acts missing: {s}");
        }
        assert!(ok.contains("fully set up"));
        let all = [&none, &pickup, &confirm, &ok, &paused];
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn an_unknown_status_gets_the_safe_generic_line_not_a_wrong_instruction() {
        let line = drive_access_line("something_new", false);
        assert!(line.contains("signet whoami"));
        assert!(
            !line.contains("guardian hasn't authorized"),
            "must not guess a state"
        );
    }
}

fn json_str(value: &Value, key: &str) -> Result<String> {
    opt_str(value, key).ok_or_else(|| {
        CliError::invalid_data(format!("server response missing string field '{key}'"))
    })
}

fn opt_str(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(String::from)
}

fn cleanup_keys(ks: &dyn Keystore, labels: &EnrollLabels) {
    progress("cleaning up the keys from this incomplete enrollment…");
    for label in [
        &labels.signing,
        &labels.kem,
        &labels.signing_pq,
        &labels.kem_pq,
    ] {
        if ks.exists(label).unwrap_or(false) {
            let _ = ks.delete(label);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(label: &str, alg: &str, fp: &str, pk: &[u8]) -> KeyMeta {
        KeyMeta {
            label: label.to_string(),
            purpose: "signing".to_string(),
            algorithm: alg.to_string(),
            storage: "software".to_string(),
            fingerprint: fp.to_string(),
            public_key: pk.to_vec(),
        }
    }

    #[test]
    fn default_config_carries_server_and_key_labels() {
        let s = meta("mira-ai-signing", "ES256", "aa", b"sig");
        let k = meta("mira-ai-kem", "ECDH-ES+A256KW", "bb", b"kem");
        let toml = default_config_toml("https://drive.mysignet.ca", &s, &k);
        assert!(toml.contains("server_base_url = \"https://drive.mysignet.ca\""));
        assert!(toml.contains("default_signing_key = \"mira-ai-signing\""));
        assert!(toml.contains("default_kem_key = \"mira-ai-kem\""));
        // It must parse as TOML and round-trip into a Config.
        let cfg: crate::config::Config =
            toml::from_str(&toml).expect("hidden config is valid TOML");
        assert_eq!(cfg.server_base_url, "https://drive.mysignet.ca");
        assert_eq!(cfg.default_signing_key.as_deref(), Some("mira-ai-signing"));
        assert_eq!(cfg.default_kem_key.as_deref(), Some("mira-ai-kem"));
    }

    fn handles(hs: &[&str]) -> BTreeSet<String> {
        hs.iter().map(|h| h.to_string()).collect()
    }

    #[test]
    fn plan_config_writes_only_for_the_first_agent_with_no_file() {
        // The keystore already holds the NEW agent's keys when the step runs: that alone
        // is the single-agent Mac, the main path, and must still write (Gus).
        assert_eq!(
            plan_config(&handles(&["tester-ai"]), "tester-ai", false),
            ConfigPlan::Write
        );
        assert_eq!(
            plan_config(&handles(&[]), "tester-ai", false),
            ConfigPlan::Write
        );
        // bug282 condition 1: any other agent on this Mac → no default, file or not.
        assert_eq!(
            plan_config(&handles(&["tester-ai", "zain-ai"]), "tester-ai", false),
            ConfigPlan::OtherAgents(vec!["zain-ai".to_string()])
        );
        assert_eq!(
            plan_config(&handles(&["tester-ai", "zain-ai"]), "tester-ai", true),
            ConfigPlan::OtherAgents(vec!["zain-ai".to_string()])
        );
        // bug282 condition 2: an existing file is never rewritten.
        assert_eq!(
            plan_config(&handles(&["tester-ai"]), "tester-ai", true),
            ConfigPlan::Existing
        );
    }

    /// A software keystore whose `list()` fails — the listing the config step now reads.
    struct ListFails(crate::keystore::SoftwareKeystore);
    impl Keystore for ListFails {
        fn tier(&self) -> Tier {
            self.0.tier()
        }
        fn generate(&self, label: &KeyLabel, algorithm: &str) -> Result<KeyMeta> {
            self.0.generate(label, algorithm)
        }
        fn meta(&self, label: &KeyLabel) -> Result<KeyMeta> {
            self.0.meta(label)
        }
        fn sign(&self, label: &KeyLabel, msg: &[u8]) -> Result<[u8; 64]> {
            self.0.sign(label, msg)
        }
        fn ecdh(&self, label: &KeyLabel, peer_pub_x963: &[u8]) -> Result<[u8; 32]> {
            self.0.ecdh(label, peer_pub_x963)
        }
        fn ml_kem_decapsulate(&self, label: &KeyLabel, ek: &[u8]) -> Result<[u8; 32]> {
            self.0.ml_kem_decapsulate(label, ek)
        }
        fn ml_dsa_sign(&self, label: &KeyLabel, msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>> {
            self.0.ml_dsa_sign(label, msg, ctx)
        }
        fn list(&self) -> Result<Vec<KeyMeta>> {
            Err(CliError::filesystem("the keystore listing failed (test)"))
        }
        fn delete(&self, label: &KeyLabel) -> Result<()> {
            self.0.delete(label)
        }
        fn exists(&self, label: &KeyLabel) -> Result<bool> {
            self.0.exists(label)
        }
    }

    /// bug282 (Gus's requirement): the config step never fails, so it can never route an
    /// attested enrollment into `cleanup_keys`. A failing listing and an unwritable path
    /// each give `None`, and the agent's keys are untouched.
    #[test]
    fn the_config_step_is_best_effort_and_never_touches_the_keys() {
        let dir = tempfile::TempDir::new().unwrap();
        let soft = crate::keystore::SoftwareKeystore::open(dir.path().join("keys")).unwrap();
        let signing = KeyLabel::from_handle("tester-ai", Purpose::Signing).unwrap();
        let kem = KeyLabel::from_handle("tester-ai", Purpose::Kem).unwrap();
        let s_meta = soft
            .generate(&signing, Purpose::Signing.default_alg())
            .unwrap();
        let k_meta = soft.generate(&kem, Purpose::Kem.default_alg()).unwrap();

        // (1) The keystore listing fails.
        let ks = ListFails(soft);
        let path = dir.path().join("cfg").join("config.toml");
        let out = write_default_config(
            "https://drive.mysignet.ca",
            &ks,
            "tester-ai",
            &s_meta,
            &k_meta,
            &path,
        );
        assert_eq!(out, None);
        assert!(!path.exists(), "no config written when the listing failed");
        assert!(
            ks.exists(&signing).unwrap() && ks.exists(&kem).unwrap(),
            "the keys are untouched"
        );

        // (2) An unwritable path: its parent is a regular file, so no directory can be made.
        let blocker = dir.path().join("blocker");
        std::fs::write(&blocker, b"not a directory").unwrap();
        let soft = crate::keystore::SoftwareKeystore::open(dir.path().join("keys")).unwrap();
        let path = blocker.join("config.toml");
        let out = write_default_config(
            "https://drive.mysignet.ca",
            &soft,
            "tester-ai",
            &s_meta,
            &k_meta,
            &path,
        );
        assert_eq!(out, None);
        assert!(
            soft.exists(&signing).unwrap() && soft.exists(&kem).unwrap(),
            "the keys are untouched"
        );
    }

    #[test]
    fn an_existing_config_naming_this_agent_reads_as_no_warning() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "server_base_url = \"https://drive.mysignet.ca\"\ndefault_signing_key = \"tester-ai-signing\"\n",
        )
        .unwrap();
        let line = existing_config_line(
            &path,
            "https://drive.mysignet.ca",
            "tester-ai-signing",
            "tester-ai",
        );
        assert_eq!(line, "this Mac's config already names this agent.");
        let line = existing_config_line(
            &path,
            "https://staging.drive.mysignet.ca",
            "tester-ai-signing",
            "tester-ai",
        );
        assert!(
            line.contains("names the server https://drive.mysignet.ca"),
            "{line}"
        );
        // An unparsable file is left alone, and the line still says what to set.
        std::fs::write(&path, "this is = = not toml").unwrap();
        let line = existing_config_line(
            &path,
            "https://drive.mysignet.ca",
            "tester-ai-signing",
            "tester-ai",
        );
        assert!(line.contains("SIGNET_HANDLE=tester-ai"), "{line}");
    }
}
