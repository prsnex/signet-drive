// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! F-DOWNGRADE(b) — verified-source recipient keys (PQR D2; Spec §9.2/§8.5/§9.3).
//!
//! A writer must wrap to the recipient's *attested / transparency-logged* keys,
//! never to a bare directory response an attacker-controlled server could
//! substitute. Every third-party recipient resolution routes through
//! [`verified_wrap_keys`], which:
//!
//! 1. runs the bundle-shape verification ([`commands::verify_recipient_wrap_keys`]:
//!    P-011 classical fingerprint + §8.5 raw-ek fingerprint + the half-strip and
//!    full-strip refusals — mandatory hybrid write, F-DOWNGRADE(a));
//! 2. classifies the recipient **from the handle** — the schema invariant
//!    (1-Pager Resolved #1) that PRSN handles end in `-ai` and human handles
//!    cannot, so the classification comes from what the *user* named, not from a
//!    server-supplied field an attacker could flip (the server's `account_type`
//!    is still cross-checked as a tamper signal);
//! 3. verifies the keys against the recipient's identity record:
//!    - **PRSN** → the §9 attestation-verification response (dual-signed
//!      ES256 + ML-DSA-87, inline §10a receipts, `status == active`, the §8.5
//!      `rfp` pair-commitment recomputed, `subject_account_id` bound), byte-
//!      compared to the bundle;
//!    - **human** → the §10a transparency-log receipts for BOTH halves of the
//!      hybrid KEM pair (humans have no attestation; the server-dual-signed,
//!      watcher-visible receipt is the affirmed analog — D2 affirmation §1),
//!      each receipt's `account_id` bound to the recipient.
//!
//! What this buys, in the D2 clock framing: **downgrade** (stripped bundle →
//! classical wrap → harvest-now) is refused outright by (a); **substitution**
//! (a coherent-but-attacker hybrid key) is forced through server-signed,
//! append-only, watcher-visible records — not prevented in real time (that is
//! the trust model's verifiability layer, forgery-clock), but made provable.
//!
//! Key-currency note (recorded for the record): a receipt proves a key was
//! *logged* for an account, not that it is *current*. For humans this is moot
//! in v1 — the KEM identity is set-once (`keys/initialize`, me.rs) and never
//! rotates; for PRSNs currency is exactly what the attestation path's
//! `status == "active"` check enforces, which is why the classification step
//! must not let a lying server route a PRSN through the receipt path.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;

use crate::anchors::{LogMode, receipt_rule};
use crate::commands::{
    AccountBinding, RecipientWrapKeys, verify_inline_receipts, verify_mldsa87, verify_one_receipt,
    verify_recipient_wrap_keys,
};
use crate::error::{CliError, Result};
use crate::http;

/// The server verification keys a writer checks recipient identity records
/// against — one `/v1/server-info` fetch per command invocation — and the
/// receipt rule that read's epoch selects, anchored against the public files
/// once (design v05 §10.6, §10.9). On the write path BOTH signing halves are
/// required: this server is post-7c by construction (launch premise), so a
/// missing ML-DSA-87 key is itself a downgrade signal (MF-2/N9), not a legacy
/// state.
pub struct ServerTrust<'a> {
    info: Value,
    mode: LogMode,
    /// The served epoch that read anchored: every epoch-bound read after it
    /// names it, and every part it binds must answer for it (design §10.4).
    epoch: u16,
    /// The attempt it was anchored in: it cannot be carried out of it.
    attempt: std::marker::PhantomData<&'a crate::anchors::EpochAttempt>,
}

impl<'a> ServerTrust<'a> {
    /// Fetch `/v1/server-info` once and anchor its epoch, inside `attempt`.
    /// Fails if the server publishes no active ML-DSA-87 verification key —
    /// the write path never verifies ES256-only — or if its epoch is not
    /// anchored.
    pub fn fetch(attempt: &'a crate::anchors::EpochAttempt, server_url: &str) -> Result<Self> {
        let info = http::get_json(&format!("{server_url}/v1/server-info"), &[])?;
        let mut trust = ServerTrust {
            info,
            mode: LogMode::Legacy,
            epoch: 1,
            attempt: std::marker::PhantomData,
        };
        trust.active_pq_key()?; // fail at the seam, not per-recipient
        // The write path may judge by the files as last read (#651 ruling 3).
        let anchoring =
            crate::anchors::anchor_served(attempt, server_url, &trust.info, None, true)?;
        trust.epoch = anchoring.served.epoch;
        trust.mode = receipt_rule(anchoring.verdict)?;
        Ok(trust)
    }

    /// What a receipt for `account_id` must name under this server's epoch
    /// ([`crate::anchors::index_under`]); `None` in epoch 1.
    fn index_for(
        &self,
        account_id: &str,
        proof: Option<&str>,
        who: &str,
    ) -> Result<Option<(u16, [u8; signet_crypto::vrf::INDEX_LEN])>> {
        crate::anchors::index_under(&self.mode, account_id, proof, who)
    }

    /// A signing key by id (current or retired — a §9 response or receipt may
    /// be signed by a since-rotated key). On a cache miss, re-fetches
    /// server-info once (the rotation race) before failing.
    fn key_by_id(&self, server_url: &str, key_id: &str) -> Result<Vec<u8>> {
        if let Some(vk) = Self::find_key_by_id(&self.info, key_id)? {
            return Ok(vk);
        }
        let fresh = http::get_json(&format!("{server_url}/v1/server-info"), &[])?;
        Self::find_key_by_id(&fresh, key_id)?.ok_or_else(|| {
            CliError::transparency_violation(format!(
                "server-info has no signing key with id {key_id}"
            ))
        })
    }

    fn find_key_by_id(info: &Value, key_id: &str) -> Result<Option<Vec<u8>>> {
        for field in ["current_signing_keys", "retired_signing_keys"] {
            let Some(keys) = info.get(field).and_then(Value::as_array) else {
                continue;
            };
            for key in keys {
                if key.get("key_id").and_then(Value::as_str) == Some(key_id) {
                    let pk_b64 =
                        key.get("public_key")
                            .and_then(Value::as_str)
                            .ok_or_else(|| {
                                CliError::invalid_data("server-info key missing public_key")
                            })?;
                    let vk = URL_SAFE_NO_PAD
                        .decode(pk_b64)
                        .map_err(|_| CliError::invalid_data("server-info public_key base64url"))?;
                    return Ok(Some(vk));
                }
            }
        }
        Ok(None)
    }

    /// The active ML-DSA-87 dual-sign key (`purpose =
    /// attestation_verification_pq`). REQUIRED on the write path.
    fn active_pq_key(&self) -> Result<Vec<u8>> {
        let keys = self
            .info
            .get("current_signing_keys")
            .and_then(Value::as_array)
            .ok_or_else(|| CliError::invalid_data("server-info missing current_signing_keys"))?;
        for key in keys {
            if key.get("purpose").and_then(Value::as_str) == Some("attestation_verification_pq") {
                let pk_b64 = key
                    .get("public_key")
                    .and_then(Value::as_str)
                    .ok_or_else(|| CliError::invalid_data("server-info key missing public_key"))?;
                return URL_SAFE_NO_PAD
                    .decode(pk_b64)
                    .map_err(|_| CliError::invalid_data("server-info public_key base64url"));
            }
        }
        Err(CliError::transparency_violation(
            "server publishes no active ML-DSA-87 verification key: refusing to \
             verify recipient identity records ES256-only (MF-2/N9)",
        ))
    }
}

/// The caller's trust regime for the bundle's `handle` field (F-PIN1): every
/// call site declares which regime it is in, so a user-typed name is always
/// pinned and a server-listed row is *visibly* unpinned.
///
/// - `UserNamed`: the caller holds the handle the USER typed (`share invite`,
///   `recipient`). The bundle's echoed handle MUST match it — otherwise a lying
///   directory can answer a request for `x-ai` with a coherent bundle for a
///   different (attacker) identity and route classification around the `-ai`
///   invariant one level up.
/// - `ServerListed`: the bundle came from server state with no user-typed name
///   to pin against (the `/v1/me` guardian block; a share-recipients row). The
///   identity record still binds keys→account; set membership is established
///   at invite time through the pinned path. (Whether enrollment should give
///   the client a pinnable guardian anchor is an open v2 design question.)
pub(crate) enum HandleExpectation<'a> {
    UserNamed(&'a str),
    ServerListed,
}

/// Resolve + fully verify a third-party recipient's wrap keys from any
/// recipient-key-bearing response object (`/v1/recipients/{handle}`, a
/// share-folder recipients row, or `/v1/me`'s guardian block). The single
/// entry point for every third-party wrap — see the module docs.
pub(crate) fn verified_wrap_keys(
    trust: &ServerTrust,
    server_url: &str,
    bundle: &Value,
    expectation: HandleExpectation<'_>,
    who: &str,
) -> Result<RecipientWrapKeys> {
    // Identity first, keys second: a bundle answering for the wrong handle is
    // refused before any of its key material is evaluated.
    //
    // No handle → cannot classify → fail closed.
    let handle = bundle
        .get("handle")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::transparency_violation(format!(
                "{who}: recipient bundle carries no handle: cannot classify for \
                 verified-source key resolution"
            ))
        })?;

    // F-PIN1: the echo is not the request. Classification below runs on the
    // BUNDLE's handle; when the caller holds a user-typed name, the two must
    // be the same string before that handle is trusted for anything.
    if let HandleExpectation::UserNamed(expected) = expectation
        && handle != expected
    {
        return Err(CliError::transparency_violation(format!(
            "{who}: asked the directory for '{expected}' but the bundle answers \
             for '{handle}'; refusing (substitution)"
        )));
    }
    // (a) bundle-shape verification: fingerprints + strip refusals + mandatory hybrid.
    let keys = verify_recipient_wrap_keys(bundle, who)?;

    let is_prsn = handle.ends_with("-ai");

    // The server's own account_type claim must agree — a mismatch means the
    // directory is lying about who this is (e.g. routing a PRSN around the
    // attestation-status check).
    if let Some(claimed) = bundle.get("account_type").and_then(Value::as_str)
        && (claimed == "prsn") != is_prsn
    {
        return Err(CliError::transparency_violation(format!(
            "{who}: the server calls '{handle}' a {claimed}, but the handle \
             says otherwise (PRSN handles end in -ai); refusing"
        )));
    }

    // The account id and, in epoch ≥ 2, its VRF proof, named in pairs:
    // `<prefix>account_id` beside `<prefix>account_vrf_proof` (§10.6).
    let (account_id, proof) = ["", "recipient_"]
        .iter()
        .find_map(|prefix| {
            let id = bundle
                .get(format!("{prefix}account_id"))
                .and_then(Value::as_str)?;
            let proof = bundle
                .get(format!("{prefix}account_vrf_proof"))
                .and_then(Value::as_str);
            Some((id, proof))
        })
        .ok_or_else(|| {
            CliError::transparency_violation(format!(
                "{who}: recipient bundle carries no account id: cannot bind the \
                 keys to an identity record"
            ))
        })?;

    // The bundle answers for the anchored epoch, or the epoch moved under the
    // command (it is read before the anchor at every write site).
    check_bundle_epoch(bundle, trust.epoch, who)?;
    if is_prsn {
        verify_against_attestation(trust, server_url, bundle, &keys, account_id, handle, who)?;
    } else {
        verify_against_receipts(trust, server_url, bundle, account_id, proof, who)?;
    }
    Ok(keys)
}

/// A bundle's `epoch` must be the anchored epoch: a proof made under another
/// epoch's key is not this epoch's binding. An ABSENT `epoch` is epoch 1, since
/// the server omits the field while epoch 1 is served (Bob, at unit 3), so a
/// bundle read before a serve shows as the move it is. Another epoch means the
/// server's epoch moved under the command, so the command re-anchors once
/// ([`crate::anchors::once_more_on_epoch_change`]); met again on the retry, it
/// is exit 60.
fn check_bundle_epoch(bundle: &Value, epoch: u16, who: &str) -> Result<()> {
    let named = bundle.get("epoch").map_or(Some(1), Value::as_u64);
    if named == Some(u64::from(epoch)) {
        return Ok(());
    }
    let shown = bundle
        .get("epoch")
        .map_or_else(|| "1 (absent)".to_string(), Value::to_string);
    Err(CliError::transparency_violation(format!(
        "{who}: the recipient bundle names epoch {shown}, but the anchored epoch is {epoch}"
    ))
    .as_epoch_move())
}

/// PRSN recipients: the verified source is the §9 attestation-verification
/// response — dual-signed, receipt-carrying, status-checked, rfp-committed —
/// byte-compared against the directory bundle.
fn verify_against_attestation(
    trust: &ServerTrust,
    server_url: &str,
    bundle: &Value,
    bundle_keys: &RecipientWrapKeys,
    account_id: &str,
    handle: &str,
    who: &str,
) -> Result<()> {
    let attestation_id = bundle
        .get("attestation_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::transparency_violation(format!(
                "{who}: '{handle}' is a PRSN but its bundle names no attestation: \
                 cannot verified-source the wrap keys"
            ))
        })?;
    let response = http::get_json(
        &format!("{server_url}/v1/attestations/{attestation_id}/verification"),
        &[],
    )?;
    let attestation = verify_verification_response(trust, server_url, &response, who)?;

    // Status: only an ACTIVE attestation's keys are wrap targets.
    match attestation.get("status").and_then(Value::as_str) {
        Some("active") => {}
        Some("revoked") => {
            return Err(CliError::attestation_revoked(format!(
                "{who}: '{handle}' attestation is revoked"
            )));
        }
        Some("expired") => {
            return Err(CliError::attestation_expired(format!(
                "{who}: '{handle}' attestation is expired"
            )));
        }
        other => {
            return Err(CliError::invalid_data(format!(
                "{who}: attestation has unknown status {other:?}"
            )));
        }
    }

    // Identity binding: the attestation must be about THIS account + handle.
    let subject_account = attestation
        .get("subject_account_id")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::invalid_data("attestation missing subject_account_id"))?;
    if !subject_account.eq_ignore_ascii_case(account_id) {
        return Err(CliError::transparency_violation(format!(
            "{who}: attestation subject is a DIFFERENT account than the directory \
             row: substitution"
        )));
    }
    // The §9 object always carries subject_handle (attestation.rs builds it
    // unconditionally) — absence is a malformed or doctored record, not an
    // older shape. Required, and it must name THIS handle.
    let subject_handle = attestation
        .get("subject_handle")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::transparency_violation(format!(
                "{who}: attestation carries no subject_handle: refusing \
                 (the §9 schema guarantees the field)"
            ))
        })?;
    if subject_handle != handle {
        return Err(CliError::transparency_violation(format!(
            "{who}: attestation subject handle '{subject_handle}' does not \
             match '{handle}'"
        )));
    }

    // The attested keys — the PQ pair is REQUIRED (mandatory hybrid write; a
    // classical-only attestation cannot be a v1 wrap target).
    let att_kem = decode_b64(attestation, "subject_kem_pubkey", who)?;
    let att_kem_pq = match attestation
        .get("subject_kem_pq_pubkey")
        .and_then(Value::as_str)
    {
        Some(b64) => URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|_| CliError::invalid_data(format!("{who} attested ML-KEM key base64url")))?,
        None => {
            return Err(CliError::transparency_violation(format!(
                "{who}: '{handle}' attestation carries no ML-KEM key: refusing a \
                 classical-only wrap (mandatory hybrid write, PQR §9.2)"
            )));
        }
    };

    // §8.5: recompute the rfp pair-commitment over the attested pair; it must
    // equal the attestation's own committed value.
    let rfp = signet_crypto::hybrid_wrap::hybrid_rfp(&att_kem, &att_kem_pq)
        .map_err(|_| CliError::invalid_data(format!("{who} attested KEM keys non-canonical")))?;
    match attestation.get("rfp").and_then(Value::as_str) {
        Some(committed) if committed == rfp => {}
        Some(_) => {
            return Err(CliError::transparency_violation(format!(
                "{who}: recomputed rfp does not match the attestation's pair-commitment"
            )));
        }
        None => {
            return Err(CliError::transparency_violation(format!(
                "{who}: hybrid attestation carries no rfp pair-commitment"
            )));
        }
    }

    // Byte-equality with the directory bundle: the keys we are about to wrap
    // to must BE the attested ones.
    if bundle_keys.rk_ec != att_kem || bundle_keys.rk_pq.as_deref() != Some(att_kem_pq.as_slice()) {
        return Err(CliError::transparency_violation(format!(
            "{who}: directory bundle keys differ from the attested keys: substitution"
        )));
    }
    // (bundle == attested also re-proves the bundle fingerprints, already
    // checked against these same bytes in verify_recipient_wrap_keys.)
    let _ = bundle;
    Ok(())
}

/// Human recipients: no attestation exists — the verified source is the §10a
/// transparency-log receipt for EACH half of the hybrid KEM pair
/// (server-dual-signed, append-only, watcher-visible), bound to the
/// recipient's account (D2 affirmation §1): by `account_id` in epoch 1, and by
/// the account's VRF index in epoch ≥ 2 (`proof` is the bundle's).
fn verify_against_receipts(
    trust: &ServerTrust,
    server_url: &str,
    bundle: &Value,
    account_id: &str,
    proof: Option<&str>,
    who: &str,
) -> Result<()> {
    let index = trust.index_for(account_id, proof, who)?;
    let binding = match &index {
        None => AccountBinding::AccountId(account_id),
        Some((epoch, index)) => AccountBinding::Index {
            epoch: *epoch,
            index,
        },
    };
    // The bundle fingerprints were verified against the key bytes in
    // verify_recipient_wrap_keys; under mandatory hybrid write both are present.
    let fp_ec = bundle
        .get("kem_pubkey_fingerprint")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::invalid_data(format!("{who} bundle missing KEM fingerprint")))?;
    let fp_pq = bundle
        .get("kem_pq_pubkey_fingerprint")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::invalid_data(format!("{who} bundle missing ML-KEM fingerprint"))
        })?;
    let pq_vk = trust.active_pq_key()?;
    for (fp, purpose) in [(fp_ec, "kem"), (fp_pq, "kem_pq")] {
        // At the anchored epoch: a server that has since served another
        // refuses it, and the command re-anchors (design §10.4).
        let receipt = http::get_json(
            &format!(
                "{server_url}/v1/transparency/log/receipt?fingerprint={fp}&purpose={purpose}&epoch={}",
                trust.epoch
            ),
            &[],
        )
        .map_err(|e| {
            if e.epoch_moved {
                return e;
            }
            CliError::transparency_violation(format!(
                "{who}: no verifiable {purpose} log receipt for the offered key \
                 ({e}); an unlogged key is not a wrap target"
            ))
        })?;
        // A receipt naming another epoch than the one asked for is the server
        // contradicting its own parameter, not a race: the shape rules below
        // refuse it at 60.
        // Resolve the receipt's own signer (rotation-correct), then verify:
        // fingerprint + purpose + account binding + ES256 + (MF-2) ML-DSA-87.
        let key_id = receipt
            .get("server_key_id")
            .and_then(Value::as_str)
            .ok_or_else(|| CliError::transparency_violation("receipt missing server_key_id"))?;
        let server_pub = trust.key_by_id(server_url, key_id)?;
        verify_one_receipt(&receipt, fp, binding, purpose, &server_pub, Some(&pq_vk))?;
    }
    Ok(())
}

/// Verify a §9 attestation-verification response on the WRITE path: ES256 +
/// ML-DSA-87 over the identical canonical bytes (both REQUIRED — MF-2/N9), and
/// the inline §10a receipts present and verified. Returns the signed
/// `attestation` object.
fn verify_verification_response<'a>(
    trust: &ServerTrust,
    server_url: &str,
    response: &'a Value,
    who: &str,
) -> Result<&'a Value> {
    let server_key_id = response
        .get("server_key_id")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::invalid_data("response missing server_key_id"))?;
    let signed_at = response
        .get("signed_at")
        .and_then(Value::as_i64)
        .ok_or_else(|| CliError::invalid_data("response missing signed_at"))?;
    let attestation = response
        .get("attestation")
        .ok_or_else(|| CliError::invalid_data("response missing attestation"))?;
    let signature = URL_SAFE_NO_PAD
        .decode(
            response
                .get("server_signature")
                .and_then(Value::as_str)
                .ok_or_else(|| CliError::invalid_data("response missing server_signature"))?,
        )
        .map_err(|_| CliError::invalid_data("server_signature base64url"))?;
    let signing_input =
        signet_crypto::attest::verification_signing_input(attestation, server_key_id, signed_at)
            .map_err(|_| CliError::invalid_data("verification canonical bytes"))?;

    let server_pub = trust.key_by_id(server_url, server_key_id)?;
    signet_crypto::ecdsa::verify_es256(&server_pub, &signing_input, &signature).map_err(|_| {
        CliError::signature_invalid(format!("{who}: server signature does not verify"))
    })?;

    // MF-2/N9: the write path never accepts an ES256-only response — the
    // server IS post-7c (ServerTrust::fetch required its PQ key).
    let pq_vk = match response.get("server_pq_key_id").and_then(Value::as_str) {
        Some(pq_kid) => trust.key_by_id(server_url, pq_kid)?,
        None => trust.active_pq_key()?,
    };
    let pq_sig_b64 = response
        .get("server_signature_mldsa87")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::signature_invalid(format!(
                "{who}: ES256-only verification response rejected: the server has a \
                 published ML-DSA-87 key, so the §9 response MUST be dual-signed \
                 (MF-2/N9)"
            ))
        })?;
    let pq_sig = URL_SAFE_NO_PAD
        .decode(pq_sig_b64)
        .map_err(|_| CliError::invalid_data("server_signature_mldsa87 base64url"))?;
    verify_mldsa87(
        &pq_vk,
        &signing_input,
        signet_crypto::attest::SERVER_VERIFY_MLDSA_CTX,
        &pq_sig,
    )?;

    // In epoch ≥ 2 the receipts must also sit under the subject's index. The
    // proof is read from INSIDE the signed object (§10.6), verified above.
    let subject_account = attestation
        .get("subject_account_id")
        .and_then(Value::as_str)
        .ok_or_else(|| CliError::invalid_data("attestation missing subject_account_id"))?;
    let index = trust.index_for(
        subject_account,
        attestation
            .get("subject_account_vrf_proof")
            .and_then(Value::as_str),
        who,
    )?;
    let binding = match &index {
        None => AccountBinding::Attested,
        Some((epoch, index)) => AccountBinding::Index {
            epoch: *epoch,
            index,
        },
    };

    // Inline §10a receipts: on the write path they must be present AND verify
    // ("verified" — not "absent", not "partial"): the receipts are what tie
    // the attested keys into the transparency log.
    let transparency = verify_inline_receipts(
        response,
        attestation,
        &server_pub,
        Some(&pq_vk),
        binding,
        Some(trust.epoch),
    )?;
    if transparency != "verified" {
        return Err(CliError::transparency_violation(format!(
            "{who}: attestation response's transparency receipts are {transparency}: \
             the write path requires the full receipt set"
        )));
    }
    Ok(attestation)
}

fn decode_b64(obj: &Value, field: &str, who: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(
            obj.get(field)
                .and_then(Value::as_str)
                .ok_or_else(|| CliError::invalid_data(format!("{who}: missing {field}")))?,
        )
        .map_err(|_| CliError::invalid_data(format!("{who}: {field} base64url")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // The pin runs before any key material or network is touched, so a
    // handle-only bundle exercises it in isolation: when the pin fires we see
    // the substitution error; when it passes, the NEXT gate (bundle shape,
    // which this fixture deliberately fails) reports instead.
    fn trust() -> ServerTrust<'static> {
        ServerTrust {
            info: json!({}),
            mode: LogMode::Legacy,
            epoch: 1,
            attempt: std::marker::PhantomData,
        }
    }

    #[test]
    fn user_named_mismatch_is_refused_as_substitution() {
        // F-PIN1: asked for `friend-ai`, served a coherent-looking row for
        // `mallory` — refused before classification or key checks.
        let bundle = json!({ "handle": "mallory" });
        let Err(err) = verified_wrap_keys(
            &trust(),
            "http://unused.invalid",
            &bundle,
            HandleExpectation::UserNamed("friend-ai"),
            "recipient 'friend-ai'",
        ) else {
            panic!("expected a refusal")
        };
        let msg = err.to_string();
        assert!(
            msg.contains("answers for 'mallory'") && msg.contains("substitution"),
            "expected the F-PIN1 substitution refusal, got: {msg}"
        );
    }

    #[test]
    fn user_named_match_passes_the_pin() {
        // Same fixture, matching expectation: the pin must NOT fire — the
        // error comes from the next gate (missing key material), proving the
        // request reached bundle-shape verification.
        let bundle = json!({ "handle": "mallory" });
        let Err(err) = verified_wrap_keys(
            &trust(),
            "http://unused.invalid",
            &bundle,
            HandleExpectation::UserNamed("mallory"),
            "recipient 'mallory'",
        ) else {
            panic!("expected a refusal")
        };
        let msg = err.to_string();
        assert!(
            !msg.contains("substitution"),
            "the pin fired on a matching handle: {msg}"
        );
    }

    #[test]
    fn server_listed_skips_the_pin() {
        // A server-listed row has no user-typed name to pin against — the
        // regime is declared, not defaulted, and verification proceeds to the
        // key gates.
        let bundle = json!({ "handle": "mallory" });
        let Err(err) = verified_wrap_keys(
            &trust(),
            "http://unused.invalid",
            &bundle,
            HandleExpectation::ServerListed,
            "recipient",
        ) else {
            panic!("expected a refusal")
        };
        assert!(!err.to_string().contains("substitution"));
    }

    #[test]
    fn missing_handle_fails_closed_before_anything_else() {
        let bundle = json!({ "kem_pubkey": "irrelevant" });
        let Err(err) = verified_wrap_keys(
            &trust(),
            "http://unused.invalid",
            &bundle,
            HandleExpectation::ServerListed,
            "recipient",
        ) else {
            panic!("expected a refusal")
        };
        assert!(err.to_string().contains("carries no handle"));
    }

    // ---- epoch 2: the receipt rule and the VRF binding (design v05 §10.6, §10.9) ----

    use crate::anchors::{ServedEpoch, judge_epoch};
    use base64::Engine;

    const ACCOUNT: &str = "00000000-0000-4000-8000-00000000cafe";
    const OTHER: &str = "11111111-1111-4111-8111-111111111111";
    const ES_KID: &str = "00000000-0000-4000-8000-0000000000aa";
    const PQ_KID: &str = "00000000-0000-4000-8000-0000000000bb";

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn uuid_bytes(id: &str) -> [u8; 16] {
        *uuid::Uuid::parse_str(id).unwrap().as_bytes()
    }

    /// A server in epoch 2: real ES256 and ML-DSA-87 keys in its server-info,
    /// and a real VRF key standing for the one pinned from `vrf-keys.jsonl`.
    struct Epoch2 {
        trust: ServerTrust<'static>,
        vrf: signet_crypto::vrf::VrfSecretKey,
        es_scalar: [u8; 32],
        pq_sk: ml_dsa::ExpandedSigningKey<ml_dsa::MlDsa87>,
    }

    impl Epoch2 {
        fn new() -> Self {
            let (es_scalar, es_pub) = signet_crypto::ecdsa::generate_keypair();
            let seed = ml_dsa::Seed::try_from(&[0x55u8; 32][..]).unwrap();
            let pq_sk = ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa87>::from_seed(&seed);
            let pq_vk = pq_sk.verifying_key().encode().to_vec();
            let vrf = signet_crypto::vrf::VrfSecretKey::generate();
            let trust = ServerTrust {
                info: json!({ "current_signing_keys": [
                    { "key_id": ES_KID, "purpose": "attestation_verification", "public_key": b64(&es_pub) },
                    { "key_id": PQ_KID, "purpose": "attestation_verification_pq", "public_key": b64(&pq_vk) },
                ]}),
                mode: LogMode::V3 {
                    epoch: 2,
                    vrf_public_key: vrf.public_key(),
                    genesis_entry_hash: [0u8; 32],
                },
                epoch: 2,
                attempt: std::marker::PhantomData,
            };
            Self {
                trust,
                vrf,
                es_scalar,
                pq_sk,
            }
        }

        fn legacy(mut self) -> Self {
            self.trust.mode = LogMode::Legacy;
            self.trust.epoch = 1;
            self
        }

        fn prove(&self, id: &str) -> ([u8; 64], [u8; 80]) {
            self.vrf.prove(&uuid_bytes(id)).unwrap()
        }

        /// Dual-sign `object` the way the server does: both halves over the
        /// same bytes, every server_signature* field absent from them.
        fn sign(&self, mut object: Value, input: &[u8], ctx: &[u8]) -> Value {
            let es = signet_crypto::ecdsa::sign_es256(&self.es_scalar, input).unwrap();
            let pq = self.pq_sk.sign_deterministic(input, ctx).unwrap();
            let obj = object.as_object_mut().unwrap();
            obj.insert("server_signature".into(), json!(b64(&es[..])));
            obj.insert(
                "server_signature_mldsa87".into(),
                json!(b64(pq.encode().as_slice())),
            );
            object
        }

        fn receipt(&self, unsigned: Value) -> Value {
            let input = signet_crypto::translog::receipt_signing_input(&unsigned).unwrap();
            self.sign(unsigned, &input, signet_crypto::translog::RECEIPT_MLDSA_CTX)
        }
    }

    /// The §10.5 receipt shape, under `index`.
    fn v2_receipt(purpose: &str, fp: &str, index: &[u8; 64]) -> Value {
        json!({
            "v": 2, "type": "signet-pubkey-log-receipt", "epoch": 2,
            "entry_id": 7, "entry_version": 3, "account_index": hex::encode(index),
            "key_purpose": purpose, "algorithm": "test", "public_key_fingerprint": fp,
            "entry_hash": "aa", "log_size_at_insertion": 7, "issued_at": 1_700_000_000i64,
            "max_merge_delay_seconds": 86_400i64,
            "server_key_id": ES_KID, "server_pq_key_id": PQ_KID,
        })
    }

    /// The epoch-1 receipt shape, bound by `account_id`.
    fn v1_receipt(purpose: &str, fp: &str, account: &str) -> Value {
        json!({
            "v": 1, "type": "signet-pubkey-log-receipt",
            "entry_id": 7, "entry_version": 2, "account_id": account,
            "key_purpose": purpose, "algorithm": "test", "public_key_fingerprint": fp,
            "entry_hash": "aa", "log_size_at_insertion": 7, "issued_at": 1_700_000_000i64,
            "max_merge_delay_seconds": 86_400i64,
            "server_key_id": ES_KID, "server_pq_key_id": PQ_KID,
        })
    }

    /// A loopback server answering the two receipt lookups by purpose.
    fn serve_receipts(kem: Value, kem_pq: Value) -> String {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let (kem, kem_pq) = (kem.to_string(), kem_pq.to_string());
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut sock) = conn else { break };
                let mut buf = [0u8; 4096];
                let n = sock.read(&mut buf).unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]);
                // `purpose=kem` is a prefix of `purpose=kem_pq`: test the longer first.
                let body = if head.contains("purpose=kem_pq") {
                    &kem_pq
                } else {
                    &kem
                };
                let _ = sock.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                         Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                    .as_bytes(),
                );
            }
        });
        format!("http://127.0.0.1:{port}")
    }

    fn human_bundle() -> Value {
        json!({
            "handle": "alice", "account_id": ACCOUNT, "epoch": 2,
            "kem_pubkey_fingerprint": "fp-kem", "kem_pq_pubkey_fingerprint": "fp-kem-pq",
        })
    }

    /// Gus's #650 ruling 3, first half: with the anchor files unreadable and
    /// the server in epoch 1, the write path keeps the epoch-1 receipt rule, so
    /// an unreachable GitHub does not stop shares before the cut. The second
    /// half, that `transparency verify` reports the same state `unanchored`
    /// with exit 62, is `an_unanchored_result_is_never_valid_and_exits_62` in
    /// `cli/tests/verify.rs`.
    #[test]
    fn files_unreadable_at_epoch_1_keep_the_legacy_receipt_rule() {
        let served = ServedEpoch {
            epoch: 1,
            vrf_public_key: None,
        };
        let mode = receipt_rule(judge_epoch(&served, None, 0, None)).expect("epoch 1 binds");
        assert_eq!(mode, LogMode::Legacy);
    }

    #[test]
    fn an_unanchorable_later_epoch_binds_nothing_and_exits_62() {
        let served = ServedEpoch {
            epoch: 2,
            vrf_public_key: Some([7u8; 32]),
        };
        let Err(err) = receipt_rule(judge_epoch(&served, None, 0, None)) else {
            panic!("an epoch whose key cannot be pinned must not bind")
        };
        assert_eq!(err.exit_code, 62);
    }

    #[test]
    fn a_rolled_back_epoch_is_a_violation_on_the_write_path() {
        let served = ServedEpoch {
            epoch: 1,
            vrf_public_key: None,
        };
        let Err(err) = receipt_rule(judge_epoch(&served, None, 2, None)) else {
            panic!("the ratchet must refuse a rollback")
        };
        assert_eq!(err.exit_code, 60);
    }

    #[test]
    fn epoch_2_binds_human_receipts_through_the_vrf_index() {
        let e = Epoch2::new();
        let (index, proof) = e.prove(ACCOUNT);
        let url = serve_receipts(
            e.receipt(v2_receipt("kem", "fp-kem", &index)),
            e.receipt(v2_receipt("kem_pq", "fp-kem-pq", &index)),
        );
        verify_against_receipts(
            &e.trust,
            &url,
            &human_bundle(),
            ACCOUNT,
            Some(&hex::encode(proof)),
            "recipient",
        )
        .expect("receipts under the account's own index bind");
    }

    #[test]
    fn epoch_2_refuses_a_receipt_under_another_accounts_index() {
        let e = Epoch2::new();
        let (index, proof) = e.prove(ACCOUNT);
        let (other_index, _) = e.prove(OTHER);
        // The KEM half is logged under another account: the substitution §10.6 refuses.
        let url = serve_receipts(
            e.receipt(v2_receipt("kem", "fp-kem", &other_index)),
            e.receipt(v2_receipt("kem_pq", "fp-kem-pq", &index)),
        );
        let err = verify_against_receipts(
            &e.trust,
            &url,
            &human_bundle(),
            ACCOUNT,
            Some(&hex::encode(proof)),
            "recipient",
        )
        .unwrap_err();
        assert_eq!(err.exit_code, 60);
        assert!(
            err.message.contains("DIFFERENT account index"),
            "{}",
            err.message
        );
    }

    #[test]
    fn epoch_2_refuses_a_proof_made_for_another_account() {
        let e = Epoch2::new();
        let (_, other_proof) = e.prove(OTHER);
        let err = verify_against_receipts(
            &e.trust,
            "http://unused.invalid",
            &human_bundle(),
            ACCOUNT,
            Some(&hex::encode(other_proof)),
            "recipient",
        )
        .unwrap_err();
        assert_eq!(err.exit_code, 60);
        assert!(err.message.contains("does not verify"), "{}", err.message);
    }

    #[test]
    fn epoch_2_refuses_a_bundle_with_no_proof() {
        let e = Epoch2::new();
        let err = verify_against_receipts(
            &e.trust,
            "http://unused.invalid",
            &human_bundle(),
            ACCOUNT,
            None,
            "recipient",
        )
        .unwrap_err();
        assert_eq!(err.exit_code, 60);
        assert!(err.message.contains("no VRF proof"), "{}", err.message);
    }

    #[test]
    fn epoch_2_refuses_the_epoch_1_receipt_shape() {
        let e = Epoch2::new();
        let (_, proof) = e.prove(ACCOUNT);
        let url = serve_receipts(
            e.receipt(v1_receipt("kem", "fp-kem", ACCOUNT)),
            e.receipt(v1_receipt("kem_pq", "fp-kem-pq", ACCOUNT)),
        );
        let err = verify_against_receipts(
            &e.trust,
            &url,
            &human_bundle(),
            ACCOUNT,
            Some(&hex::encode(proof)),
            "recipient",
        )
        .unwrap_err();
        assert_eq!(err.exit_code, 60);
        assert!(err.message.contains("receipt shape"), "{}", err.message);
    }

    #[test]
    fn epoch_1_keeps_the_account_id_rule_and_refuses_the_epoch_2_shape() {
        let e = Epoch2::new().legacy();
        let (index, _) = e.prove(ACCOUNT);
        let honest = serve_receipts(
            e.receipt(v1_receipt("kem", "fp-kem", ACCOUNT)),
            e.receipt(v1_receipt("kem_pq", "fp-kem-pq", ACCOUNT)),
        );
        verify_against_receipts(
            &e.trust,
            &honest,
            &human_bundle(),
            ACCOUNT,
            None,
            "recipient",
        )
        .expect("epoch 1 binds by account_id, as before the cut");
        let v2 = serve_receipts(
            e.receipt(v2_receipt("kem", "fp-kem", &index)),
            e.receipt(v2_receipt("kem_pq", "fp-kem-pq", &index)),
        );
        let err =
            verify_against_receipts(&e.trust, &v2, &human_bundle(), ACCOUNT, None, "recipient")
                .unwrap_err();
        assert!(
            err.message.contains("missing account_id"),
            "{}",
            err.message
        );
    }

    #[test]
    fn a_bundle_naming_another_epoch_is_refused() {
        assert!(check_bundle_epoch(&json!({}), 1, "r").is_ok());
        assert!(check_bundle_epoch(&json!({ "epoch": 2 }), 2, "r").is_ok());
        let err = check_bundle_epoch(&json!({ "epoch": 3 }), 2, "r").unwrap_err();
        assert_eq!(err.exit_code, 60);
        // Absent is epoch 1, as the server omits it there (Bob, at unit 3): a
        // bundle read before a serve, under an epoch-2 anchor, is an epoch move.
        let err = check_bundle_epoch(&json!({}), 2, "r").unwrap_err();
        assert!(err.epoch_moved, "{}", err.message);
    }

    /// The §9 response for a PRSN in epoch 2: the subject's proof inside the
    /// signed attestation (unless `proof_outside`), four inline receipts, the
    /// KEM one under `kem_index`.
    fn prsn_response(e: &Epoch2, kem_index: &[u8; 64], proof_outside: bool) -> Value {
        let (index, proof) = e.prove(ACCOUNT);
        let mut attestation = json!({
            "subject_account_id": ACCOUNT, "subject_handle": "pat-ai", "status": "active",
            "subject_signing_pubkey_fingerprint": "fp-s", "subject_kem_pubkey_fingerprint": "fp-k",
            "subject_signing_pq_pubkey_fingerprint": "fp-sq", "subject_kem_pq_pubkey_fingerprint": "fp-kq",
        });
        if !proof_outside {
            attestation["subject_account_vrf_proof"] = json!(hex::encode(proof));
        }
        let signed_at = 1_700_000_000i64;
        let input =
            signet_crypto::attest::verification_signing_input(&attestation, ES_KID, signed_at)
                .unwrap();
        let mut response = json!({
            "server_key_id": ES_KID, "server_pq_key_id": PQ_KID, "signed_at": signed_at,
            "attestation": attestation,
            "subject_signing_pubkey_receipt": e.receipt(v2_receipt("signing", "fp-s", &index)),
            "subject_kem_pubkey_receipt": e.receipt(v2_receipt("kem", "fp-k", kem_index)),
            "subject_signing_pq_pubkey_receipt": e.receipt(v2_receipt("signing_pq", "fp-sq", &index)),
            "subject_kem_pq_pubkey_receipt": e.receipt(v2_receipt("kem_pq", "fp-kq", &index)),
        });
        if proof_outside {
            response["subject_account_vrf_proof"] = json!(hex::encode(proof));
        }
        e.sign(
            response,
            &input,
            signet_crypto::attest::SERVER_VERIFY_MLDSA_CTX,
        )
    }

    #[test]
    fn epoch_2_binds_a_prsns_inline_receipts_to_its_index() {
        let e = Epoch2::new();
        let (index, _) = e.prove(ACCOUNT);
        let response = prsn_response(&e, &index, false);
        verify_verification_response(&e.trust, "http://unused.invalid", &response, "pat-ai")
            .expect("all four receipts sit under the subject's index");
    }

    #[test]
    fn epoch_2_refuses_a_prsn_receipt_under_another_index() {
        let e = Epoch2::new();
        let (other_index, _) = e.prove(OTHER);
        let response = prsn_response(&e, &other_index, false);
        let err =
            verify_verification_response(&e.trust, "http://unused.invalid", &response, "pat-ai")
                .unwrap_err();
        assert_eq!(err.exit_code, 60);
        assert!(
            err.message.contains("DIFFERENT account index"),
            "{}",
            err.message
        );
    }

    #[test]
    fn epoch_2_takes_a_prsns_proof_only_from_inside_the_signed_object() {
        let e = Epoch2::new();
        let (index, _) = e.prove(ACCOUNT);
        let response = prsn_response(&e, &index, true);
        let err =
            verify_verification_response(&e.trust, "http://unused.invalid", &response, "pat-ai")
                .unwrap_err();
        assert_eq!(err.exit_code, 60);
        assert!(err.message.contains("no VRF proof"), "{}", err.message);
    }

    // ---- the CLI half of 3c3: one epoch per command, or one retry (§10.4) ----

    use crate::test_support::{epoch_retired, serve_scripted};
    use std::cell::Cell;
    use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
    use std::sync::{Arc, Mutex};

    fn retired() -> (u16, String) {
        epoch_retired()
    }

    /// A human recipient with real key bytes (the bundle-shape gate runs
    /// before any binding).
    struct Alice {
        ec: Vec<u8>,
        pq: Vec<u8>,
        fp_ec: String,
        fp_pq: String,
    }

    impl Alice {
        fn new() -> Self {
            let (_, ec) = signet_crypto::ecdh::generate_keypair();
            let pq = vec![0xE4u8; 1568];
            let fp_ec = signet_crypto::pubkey::fingerprint(&ec).unwrap();
            let fp_pq = signet_crypto::pubkey::fingerprint_raw(&pq);
            Self {
                ec,
                pq,
                fp_ec,
                fp_pq,
            }
        }

        /// Her bundle as `/v1/recipients/alice` serves it in `epoch`.
        fn bundle(&self, epoch: u16, proof: Option<&[u8; 80]>) -> String {
            let mut bundle = json!({
                "handle": "alice", "account_type": "human", "account_id": ACCOUNT,
                "kem_pubkey": b64(&self.ec), "kem_pubkey_fingerprint": self.fp_ec,
                "kem_pq_pubkey": b64(&self.pq), "kem_pq_pubkey_fingerprint": self.fp_pq,
            });
            // The server's shape: `epoch` absent while epoch 1 is served.
            if epoch >= 2 {
                bundle["epoch"] = json!(epoch);
            }
            if let Some(proof) = proof {
                bundle["account_vrf_proof"] = json!(hex::encode(proof));
            }
            bundle.to_string()
        }
    }

    fn trust_at<'a>(e: &Epoch2, epoch: u16) -> ServerTrust<'a> {
        let mode = if epoch == 1 {
            LogMode::Legacy
        } else {
            e.trust.mode.clone()
        };
        ServerTrust {
            info: e.trust.info.clone(),
            mode,
            epoch,
            attempt: std::marker::PhantomData,
        }
    }

    /// Resolve `alice` against `url`, anchoring by `epochs` in turn; returns
    /// the ML-KEM key it bound, and how many times the command anchored.
    fn resolve_alice(e: &Epoch2, url: &str, epochs: &[u16]) -> (Result<Option<Vec<u8>>>, usize) {
        let (_dir, ks, signing, _) = crate::test_support::test_keystore();
        let anchors = Cell::new(0usize);
        let result = crate::commands::resolve_recipient_pubkey_with(
            &ks,
            &signing,
            url,
            "alice",
            &mut |_| {
                assert!(
                    crate::http::writes_refused(),
                    "every attempt runs under the arm"
                );
                let n = anchors.get();
                anchors.set(n + 1);
                Ok(trust_at(e, epochs[n.min(epochs.len() - 1)]))
            },
        )
        .map(|(keys, _)| keys.rk_pq);
        (result, anchors.get())
    }

    fn only_reads(log: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
        let log = log.lock().unwrap().clone();
        assert!(
            log.iter().all(|l| l.starts_with("GET ")),
            "an attempt that may run twice wrote: {log:?}"
        );
        log
    }

    #[test]
    fn a_serve_between_the_anchor_and_the_receipt_read_is_a_clean_retry() {
        // Bob's flip: anchored at epoch 1, the serve lands, and the epoch-1
        // receipt read is refused. One re-anchor, and the share's keys bind
        // under epoch 2; never exit 60, and nothing written in either attempt.
        let e = Epoch2::new();
        let alice = Alice::new();
        let (index, proof) = e.prove(ACCOUNT);
        let (b1, b2) = (alice.bundle(1, None), alice.bundle(2, Some(&proof)));
        let r_kem = e
            .receipt(v2_receipt("kem", &alice.fp_ec, &index))
            .to_string();
        let r_pq = e
            .receipt(v2_receipt("kem_pq", &alice.fp_pq, &index))
            .to_string();
        let served_2 = Arc::new(AtomicBool::new(false));
        let (url, log) = serve_scripted(move |_, target| {
            if target.starts_with("/v1/recipients/") {
                return (200, (if served_2.load(SeqCst) { &b2 } else { &b1 }).clone());
            }
            served_2.store(true, SeqCst); // the serve lands before the first receipt read
            if target.contains("&epoch=1") {
                return retired();
            }
            let body = if target.contains("purpose=kem_pq") {
                &r_pq
            } else {
                &r_kem
            };
            (200, body.clone())
        });

        let (result, anchors) = resolve_alice(&e, &url, &[1, 2]);
        let rk_pq = result.expect("a clean retry, never exit 60");
        assert_eq!(rk_pq.as_deref(), Some(&alice.pq[..]));
        assert_eq!(anchors, 2, "re-anchored once");
        let log = only_reads(&log);
        assert_eq!(log.len(), 5, "{log:?}");
        assert!(log[1].contains("&epoch=1"), "{log:?}");
        assert!(
            log[3].contains("&epoch=2") && log[4].contains("&epoch=2"),
            "{log:?}"
        );
    }

    #[test]
    fn a_bundle_read_before_the_serve_is_read_again_after_it() {
        // The other direction (Bob): the bundle is read before the anchor at
        // every write site, so it can name epoch 1 under an epoch-2 anchor.
        let e = Epoch2::new();
        let alice = Alice::new();
        let (index, proof) = e.prove(ACCOUNT);
        let (b1, b2) = (alice.bundle(1, None), alice.bundle(2, Some(&proof)));
        let r_kem = e
            .receipt(v2_receipt("kem", &alice.fp_ec, &index))
            .to_string();
        let r_pq = e
            .receipt(v2_receipt("kem_pq", &alice.fp_pq, &index))
            .to_string();
        let bundle_read = Arc::new(AtomicBool::new(false));
        let (url, log) = serve_scripted(move |_, target| {
            if target.starts_with("/v1/recipients/") {
                return (
                    200,
                    (if bundle_read.swap(true, SeqCst) {
                        &b2
                    } else {
                        &b1
                    })
                    .clone(),
                );
            }
            if target.contains("&epoch=1") {
                return retired();
            }
            let body = if target.contains("purpose=kem_pq") {
                &r_pq
            } else {
                &r_kem
            };
            (200, body.clone())
        });

        let (result, anchors) = resolve_alice(&e, &url, &[2]);
        result.expect("the bundle is read again under the fresh anchor");
        assert_eq!(anchors, 2);
        let log = only_reads(&log);
        assert_eq!(
            log.len(),
            4,
            "no receipt read under the mismatched bundle: {log:?}"
        );
    }

    #[test]
    fn a_bundle_that_names_another_epoch_on_both_attempts_is_a_violation() {
        // Bob's control: the catch must not turn a persistent contradiction
        // into "run it again". Retried once, then exit 60.
        let e = Epoch2::new();
        let alice = Alice::new();
        let b1 = alice.bundle(1, None);
        let (url, log) = serve_scripted(move |_, _| (200, b1.clone()));

        let (result, anchors) = resolve_alice(&e, &url, &[2]);
        let err = result.unwrap_err();
        assert_eq!((err.exit_code, err.code), (60, "transparency_violation"));
        assert_eq!(anchors, 2, "it did retry first");
        assert_eq!(only_reads(&log).len(), 2);
    }

    #[test]
    fn a_second_refusal_is_run_it_again_never_a_violation() {
        // Refused on both attempts: the server declined, nothing was bound.
        let e = Epoch2::new();
        let alice = Alice::new();
        let b1 = alice.bundle(1, None);
        let (url, log) = serve_scripted(move |_, target| {
            if target.starts_with("/v1/recipients/") {
                (200, b1.clone())
            } else {
                retired()
            }
        });

        let (result, anchors) = resolve_alice(&e, &url, &[1, 1]);
        let err = result.unwrap_err();
        assert_eq!((err.exit_code, err.code), (62, "epoch_changed"));
        assert_eq!(anchors, 2);
        assert_eq!(only_reads(&log).len(), 4);
    }

    #[test]
    fn a_section_9_receipt_from_another_epoch_is_an_epoch_move() {
        // The §9 response is read before the anchor and takes no epoch; its
        // receipts name theirs, so another than the anchored one re-anchors
        // (and is exit 60 if the retry meets it again).
        let e = Epoch2::new();
        let (index, _) = e.prove(ACCOUNT);
        let response = json!({ "subject_kem_pubkey_receipt": v2_receipt("kem", "fp", &index) });
        let attestation = json!({ "subject_kem_pubkey_fingerprint": "fp" });
        let err = crate::commands::verify_inline_receipts(
            &response,
            &attestation,
            b"unused",
            None,
            AccountBinding::Attested,
            Some(1),
        )
        .unwrap_err();
        assert_eq!(err.exit_code, 60);
        assert!(err.epoch_moved, "{}", err.message);
        // Offline (no anchored epoch) the check does not apply.
        let offline = crate::commands::verify_inline_receipts(
            &response,
            &attestation,
            b"unused",
            None,
            AccountBinding::Attested,
            None,
        )
        .unwrap_err();
        assert!(!offline.epoch_moved);
    }

    #[test]
    fn a_refusal_that_is_not_an_epoch_move_is_not_retried() {
        // Only an epoch move earns the retry: a substituted handle (F-PIN1)
        // fails on the first attempt, anchored once.
        let e = Epoch2::new();
        let alice = Alice::new();
        let mallory = alice.bundle(1, None).replace("\"alice\"", "\"mallory\"");
        let (url, log) = serve_scripted(move |_, _| (200, mallory.clone()));

        let (result, anchors) = resolve_alice(&e, &url, &[1]);
        assert!(result.unwrap_err().message.contains("substitution"));
        assert_eq!(anchors, 1);
        assert_eq!(only_reads(&log).len(), 1);
    }
}
