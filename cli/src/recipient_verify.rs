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

use crate::commands::{
    RecipientWrapKeys, verify_inline_receipts, verify_mldsa87, verify_one_receipt,
    verify_recipient_wrap_keys,
};
use crate::error::{CliError, Result};
use crate::http;

/// The server verification keys a writer checks recipient identity records
/// against — one `/v1/server-info` fetch per command invocation. On the write
/// path BOTH halves are required: this server is post-7c by construction
/// (launch premise), so a missing ML-DSA-87 key is itself a downgrade signal
/// (MF-2/N9), not a legacy state.
pub struct ServerTrust {
    info: Value,
}

impl ServerTrust {
    /// Fetch `/v1/server-info` once. Fails if the server publishes no active
    /// ML-DSA-87 verification key — the write path never verifies ES256-only.
    pub fn fetch(server_url: &str) -> Result<Self> {
        let info = http::get_json(&format!("{server_url}/v1/server-info"), &[])?;
        let trust = ServerTrust { info };
        trust.active_pq_key()?; // fail at the seam, not per-recipient
        Ok(trust)
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

    let account_id = bundle
        .get("account_id")
        .or_else(|| bundle.get("recipient_account_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            CliError::transparency_violation(format!(
                "{who}: recipient bundle carries no account id: cannot bind the \
                 keys to an identity record"
            ))
        })?;

    if is_prsn {
        verify_against_attestation(trust, server_url, bundle, &keys, account_id, handle, who)?;
    } else {
        verify_against_receipts(trust, server_url, bundle, account_id, who)?;
    }
    Ok(keys)
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
/// recipient's account (D2 affirmation §1).
fn verify_against_receipts(
    trust: &ServerTrust,
    server_url: &str,
    bundle: &Value,
    account_id: &str,
    who: &str,
) -> Result<()> {
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
        let receipt = http::get_json(
            &format!("{server_url}/v1/transparency/log/receipt?fingerprint={fp}&purpose={purpose}"),
            &[],
        )
        .map_err(|e| {
            CliError::transparency_violation(format!(
                "{who}: no verifiable {purpose} log receipt for the offered key \
                 ({e}); an unlogged key is not a wrap target"
            ))
        })?;
        // Resolve the receipt's own signer (rotation-correct), then verify:
        // fingerprint + purpose + account binding + ES256 + (MF-2) ML-DSA-87.
        let key_id = receipt
            .get("server_key_id")
            .and_then(Value::as_str)
            .ok_or_else(|| CliError::transparency_violation("receipt missing server_key_id"))?;
        let server_pub = trust.key_by_id(server_url, key_id)?;
        verify_one_receipt(
            &receipt,
            fp,
            Some(account_id),
            purpose,
            &server_pub,
            Some(&pq_vk),
        )?;
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

    // Inline §10a receipts: on the write path they must be present AND verify
    // ("verified" — not "absent", not "partial"): the receipts are what tie
    // the attested keys into the transparency log.
    let transparency = verify_inline_receipts(response, attestation, &server_pub, Some(&pq_vk))?;
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
    fn trust() -> ServerTrust {
        ServerTrust { info: json!({}) }
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
}
