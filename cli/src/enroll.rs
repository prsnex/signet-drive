// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! `signet enroll <code>` — the human-initiated PRSN onboarding flow (S052; S063
//! human-initiated only; canonical design: `Signet-Drive-PRSN-Account-and-Kit-Spec`
//! §a–c).
//!
//! The human Guardian starts the enrollment from the Signet web app ("+ Add PRSN")
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
//! 5. Poll until `completed` (the human's Touch ID issues the attestation).
//! 6. Write the optional hidden config default (no visible Kit) and report.
//!
//! The agent is **never authenticated** — it holds only the single-use `code` the
//! human handed it and the `submit_token` it claimed; ALL authorization is the
//! human's (their session created + confirms the enrollment, their Touch ID attests).
//! If anything fails after keygen, the just-generated keys + any partial Kit are
//! cleaned up (orphaned-Kit cleanup, §b).
//!
//! Native path only here (the only built backend): the keys are in the device Secure
//! Enclave. The containerized host-delegation path is a committed-v1 but gated build
//! (Account-and-Kit §Gates), so it isn't wired in this increment.

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
/// web "Add PRSN" page and hands the agent the one-time `CODE`; the agent joins it
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
    // "+ Add PRSN" in Signet and hands it to the agent — S063 human-initiated).
    let code = code.ok_or_else(|| {
        CliError::invalid_args(
            "not enrolled yet, and no enrollment CODE was given. Ask your guardian to open \
             \"+ Add PRSN\" in Signet and hand you the one-time code, then run \
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
    progress("submitted. Waiting for your human's Touch ID (the attestation)…");

    let completed = poll_until(base, code, "completed", "the attestation")?;
    // The Kit is retired (Account-and-Kit §c): no visible folder, no `keys.pub`, no
    // `container/` record (the host-side registry is authoritative). Write at most the
    // optional hidden config default — the single-PRSN native convenience, clobber-safe.
    let config_path = write_default_config(base, &signing_meta, &kem_meta)?;

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
                     guardian for a fresh code (they start over from \"+ Add PRSN\"), \
                     then run `signet enroll <NEW-CODE>`"
                )));
            }
            "cancelled" => {
                return Err(CliError::generic(format!(
                    "the enrollment was cancelled while waiting for {waiting_for}. If \
                     this is unexpected, ask your guardian; they can start over from \
                     \"+ Add PRSN\" with a fresh code"
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

/// Write the optional, hidden per-PRSN config default (Account-and-Kit §c — the Kit is
/// retired). At `~/.config/signet/config.toml` (the default `Config::load` location), it
/// records the server URL + this PRSN's default key labels, so a single-PRSN native host
/// resolves identity ambiently (no `SIGNET_HANDLE` needed). **Clobber-safe:** if a config
/// already names a *different* PRSN's default, we don't overwrite it — that host is
/// multi-PRSN, where `SIGNET_HANDLE` (not a shared default) is the resolution mechanism
/// (v05 §11); we leave the existing default and return `None`. Returns the path written,
/// or `None` when skipped. Private keys are never written here (they live in the SE).
fn write_default_config(
    base: &str,
    signing_meta: &KeyMeta,
    kem_meta: &KeyMeta,
) -> Result<Option<PathBuf>> {
    let existing = Config::load().ok().and_then(|c| c.default_signing_key);
    if !should_write_default(existing.as_deref(), &signing_meta.label) {
        progress(&format!(
            "left this Mac's existing default ({}) in place. Set SIGNET_HANDLE to select \
             this PRSN.",
            existing.as_deref().unwrap_or("")
        ));
        return Ok(None);
    }

    let path = config::config_file_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| CliError::filesystem(format!("creating {}: {e}", parent.display())))?;
    }
    write_file(&path, &default_config_toml(base, signing_meta, kem_meta))?;
    Ok(Some(path))
}

/// Whether `enroll` may (over)write the shared default config: yes when there is no
/// existing default, or it already names *this* PRSN; no when a *different* PRSN owns the
/// default (a multi-PRSN host — don't clobber; `SIGNET_HANDLE` selects there). Pure;
/// unit-tested.
fn should_write_default(existing_default_signing: Option<&str>, new_signing_label: &str) -> bool {
    match existing_default_signing {
        None => true,
        Some(cur) => cur == new_signing_label,
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

fn write_file(path: &Path, content: &str) -> Result<()> {
    std::fs::write(path, content)
        .map_err(|e| CliError::filesystem(format!("writing {}: {e}", path.display())))
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

    #[test]
    fn should_write_default_only_when_absent_or_same_prsn() {
        // No existing default → write (first PRSN on this Mac).
        assert!(should_write_default(None, "hlin-ai-signing"));
        // The same PRSN is already the default → write (idempotent overwrite).
        assert!(should_write_default(
            Some("hlin-ai-signing"),
            "hlin-ai-signing"
        ));
        // A *different* PRSN owns the default → don't clobber (a multi-PRSN host, where
        // SIGNET_HANDLE selects).
        assert!(!should_write_default(
            Some("zain-ai-signing"),
            "hlin-ai-signing"
        ));
    }
}
