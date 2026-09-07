// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! `signet garnet …` — the agent-side Garnet use surface (Auth-Core Spec v05 §5/§7, Design Spec
//! v05). Garnet is the broker-mediated PRSN-access path: the agent picks up a small **PoP
//! credential** by SIGNING its pickup with its attested, SE-bound key (bug084/S145: the pairing
//! code and the guardian hard-confirm are both GONE; the guardian's *authorize* action is the whole
//! gesture and the credential is confirmed automatically), then renews
//! a broker-audience token and performs Secure-Enclave ops through its local broker — no mounts.
//!
//! This module owns the *command* wiring; the protocol flows live in their own modules
//! ([`crate::garnet_pickup`] the pickup flow, [`crate::garnet_credential::PoPCredential`] the
//! credential, [`crate::broker_client`] the op client). The first command is **pickup**; token
//! acquisition/renewal and the op command (`signet garnet <op>`) follow in later increments.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde::Serialize;
use signet_channel::wire::{Op, OpErr, OpOk, Response};
use zeroize::Zeroizing;

use crate::broker_client::BrokerClient;
use crate::config;
use crate::error::{CliError, Result};
use crate::garnet_credential::PoPCredential;
use crate::garnet_pickup;
use crate::keystore::{KeyLabel, Purpose};
use crate::output::OutputMode;

/// A per-request connect/read timeout for the agent→server token call (one small mutual-TLS
/// round-trip); a stalled server surfaces promptly rather than hanging.
const RENEW_TIMEOUT: Duration = Duration::from_secs(10);

/// The default home for a PRSN's PoP credential: `<config_dir>/garnet/<handle>.json`. **Per-handle**
/// — a guardian's Mac hosts up to 8 PRSNs, so each needs its own credential file (a shared path
/// would collide). The handle is the server-issued one (the K4 leaf SAN), never a client-supplied
/// value. Renewal + the op command resolve the same path from their resolved handle.
pub fn default_credential_path(handle: &str) -> PathBuf {
    config::config_dir()
        .join("garnet")
        .join(format!("{handle}.json"))
}

/// The machine-readable pickup result (stdout). Progress narration goes to stderr.
#[derive(Serialize)]
struct PickupResult {
    /// The handle the server bound the credential to (the K4 leaf SAN — derived from the
    /// authenticated account, never a client-supplied value).
    handle: String,
    /// The K4 leaf's `x5t#S256` fingerprint (informational — nothing to relay: the signed
    /// pickup itself proved this credential belongs to your attested key, bug084).
    cert_fingerprint: String,
    /// Where the PoP credential was written.
    credential_path: String,
    /// `true`: the signed pickup auto-confirms the authorization (the signature IS the
    /// verification the old guardian match-gate approximated).
    enrollment_confirmed: bool,
    /// Whether the broker-audience token was acquired at pickup time (best-effort); when
    /// `false` it is acquired lazily on your first Secure-Enclave op.
    broker_token_acquired: bool,
}

/// The shared pickup engine (bug084 — signature-authenticated): sign the pickup with
/// `handle`'s attested key over the enrollment-phase keystore channel, best-effort complete
/// the credential with a broker-audience token (the grant is auto-confirmed at pickup, so it
/// is immediately mintable; on failure the `BrokerKeystore` lazy-renews on first use), and
/// persist to `path`. Returns the credential + whether the broker token landed.
fn pickup_and_save(
    config: &crate::config::Config,
    base_url: &str,
    handle: &str,
    path: &Path,
) -> Result<(PoPCredential, bool)> {
    let keystore = crate::keystore::open_enrollment_channel(config)?;
    let (mut cred, reissued) =
        garnet_pickup::pickup(base_url, keystore.as_ref(), handle).map_err(|e| {
            CliError::generic(format!(
                "signed pickup failed: {e}\n  If you have not enrolled yet, run `signet enroll` \
                 (your guardian opens it from their Signet Drive account page). If you are \
                 enrolled, your guardian may not have authorized Signet Drive access yet."
            ))
        })?;
    if reissued {
        // v09 (bug090/S147): the ONE client-visible signal separating a deliberate recovery
        // from a same-user process taking the credential — mandatory, never quiet. The full
        // old→new key record is in both the PRSN's and the guardian's audit logs.
        progress(&format!(
            "⚠ A NEW credential was issued for '{handle}' and the PREVIOUS one no longer \
             works (recorded in your and your guardian's audit logs). If you did not \
             deliberately re-run pickup or recover this agent just now, treat this as a \
             takeover signal and tell your guardian immediately."
        ));
    }

    let broker_token_acquired = match request_token(cred.grant_status_url(), &cred, "signet-broker")
    {
        Ok(token) => {
            cred.set_broker_token(token);
            true
        }
        Err(e) => {
            progress(&format!(
                "broker token not acquired yet ({e}); it will be acquired automatically on \
                     your first Secure-Enclave op"
            ));
            false
        }
    };
    cred.save(path)?;
    Ok((cred, broker_token_acquired))
}

/// Refresh an EXISTING credential by signed re-pickup — the bug090 pin-refresh entry
/// ([`crate::keystore::BrokerKeystore`], on a `broker_pin_mismatch`): re-fetches the broker's
/// current SPKI pin (and rotates K4 — the v09 re-issue, loud by construction: the server
/// audits both parties and [`pickup_and_save`] prints the takeover-signal line). The handle
/// comes from the credential's own cryptographically-bound identity, never the environment.
pub(crate) fn refresh_pickup(
    config: &crate::config::Config,
    handle: &str,
    credential_path: &Path,
) -> Result<()> {
    let (_cred, _token) =
        pickup_and_save(config, &config.server_base_url, handle, credential_path)?;
    Ok(())
}

/// Claim this PRSN's Garnet credential automatically — called by `keystore::open` when the
/// broker path is configured (`SIGNET_BROKER_ADDR`) but its credential file does not exist
/// yet (the freshly-authorized state). This is what makes `signet enroll` the only hand-run
/// step (bug084 §3/§5): once the guardian authorizes, the agent's next `signet` use
/// self-provisions by signed pickup.
pub fn auto_pickup(config: &crate::config::Config, credential_path: &Path) -> Result<()> {
    let handle = crate::commands::asserted_handle().ok_or_else(|| {
        CliError::config(
            "not connected yet, and SIGNET_HANDLE is not set. Set SIGNET_HANDLE so \
             signet can claim your credential by signed pickup",
        )
    })?;
    progress("not connected yet. Claiming your Signet Drive credential by signed pickup…");
    // The config here is the command's MERGED config (a `--server` override has already been
    // folded into `server_base_url` by main before any keystore::open).
    let (cred, _) = pickup_and_save(config, &config.server_base_url, &handle, credential_path)?;
    progress(&format!(
        "connected as '{}'. Signet Drive credential at {}",
        cred.handle,
        credential_path.display()
    ));
    Ok(())
}

/// `signet garnet pickup` — first contact, signature-authenticated (Auth-Core §5/§7, bug084).
///
/// Claim this PRSN's Garnet **PoP credential** by signing the pickup with your attested,
/// SE-bound key (no pairing code — your guardian's *authorize* action is the whole
/// hand-off): a fresh K4 keypair, its server-issued leaf, the pinned K2 anchor, and access
/// tokens. The authorization is **auto-confirmed** by the pickup itself. The credential is
/// persisted (default `<config_dir>/garnet/<handle>.json`, or `--credential <path>`).
///
/// Rarely needed by hand: any `signet` command that needs the broker claims the credential
/// automatically ([`auto_pickup`]). This command exists for explicit provisioning + scripts.
pub fn pickup_command(base_url: &str, credential: Option<&Path>, out: &OutputMode) -> Result<()> {
    let config = crate::config::Config::load()?;
    let handle = crate::commands::asserted_handle().ok_or_else(|| {
        CliError::config("set SIGNET_HANDLE so signet knows which PRSN is picking up")
    })?;
    let path = credential
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_credential_path(&handle));

    progress("claiming your Signet Drive credential by signed pickup (first contact)…");
    let (cred, broker_token_acquired) = pickup_and_save(&config, base_url, &handle, &path)?;

    progress(&format!(
        "connected as '{}' (credential at {}). Your Signet Drive access is confirmed. \
         Nothing to relay to your guardian: the signed pickup proved this credential is yours.",
        cred.handle,
        path.display(),
    ));

    out.print_json(&PickupResult {
        handle: cred.handle.clone(),
        cert_fingerprint: cred.fingerprint(),
        credential_path: path.display().to_string(),
        enrollment_confirmed: true,
        broker_token_acquired,
    })
}

/// The machine-readable renew result (stdout).
#[derive(Serialize)]
struct RenewResult {
    handle: String,
    /// The audience renewed: `server` (account access) or `broker` (SE ops).
    audience: String,
    credential_path: String,
}

/// `signet garnet renew --audience <server|broker>` — acquire or refresh an access token
/// (Auth-Core §3/§7).
///
/// Opens the agent→server **mutual-TLS** channel presenting this PRSN's K4 cert (the cert *is* the
/// refresh credential — no separate secret), asks the server for a fresh token for the requested
/// audience against the live grant, and stores it in the PoP credential. This is how you get your
/// first **broker** token (SE ops) once your guardian has confirmed you; the server refuses a broker
/// token until then (`awaiting guardian confirmation`).
///
/// The token endpoint is the Garnet mutual-TLS ingress the server **advertised at pickup** and the
/// credential carries (`<grant_status_url>/v1/garnet/token`; S094 — no longer a CLI flag). The
/// credential is resolved from `--credential`, else `<config-dir>/garnet/<handle>.json` for the active
/// `SIGNET_HANDLE`.
pub fn renew_command(audience: &str, credential: Option<&Path>, out: &OutputMode) -> Result<()> {
    let audience_wire = audience_to_wire(audience).ok_or_else(|| {
        CliError::invalid_args(format!(
            "--audience must be 'server' or 'broker' (got '{audience}')"
        ))
    })?;
    let path = resolve_credential_path(credential)?;
    let mut cred = PoPCredential::load(&path)?;
    let token_url = cred.grant_status_url().to_string();

    progress(&format!(
        "renewing a '{audience}' token for '{}' over mutual-TLS…",
        cred.handle
    ));
    let token = request_token(&token_url, &cred, audience_wire)?;
    match audience {
        "broker" => cred.set_broker_token(token),
        "server" => cred.set_server_token(token),
        _ => unreachable!("audience validated by audience_to_wire above"),
    }
    cred.save(&path)?;
    progress(&format!("done. Your '{audience}' token is refreshed."));

    out.print_json(&RenewResult {
        handle: cred.handle.clone(),
        audience: audience.to_string(),
        credential_path: path.display().to_string(),
    })
}

/// The machine-readable cert-renewal result (stdout).
#[derive(Serialize)]
struct RenewCertResult {
    handle: String,
    /// The new K4 leaf's `x5t#S256` fingerprint — the cert and every re-minted token are now bound to
    /// this. (A guardian re-confirm is **not** required: the grant is already confirmed; renewal only
    /// refreshes the cert, it does not re-enroll.)
    cert_fingerprint: String,
    credential_path: String,
    /// Which audiences were re-minted against the new cert (`server`, and `broker` if SE access was
    /// held).
    tokens_refreshed: Vec<String>,
}

/// `signet garnet renew-cert` — refresh this PRSN's K4 client certificate (Auth-Core §4).
///
/// Before the (7-day) cert expires, generate a fresh K4 keypair + CSR and submit it over the
/// agent→server **mutual-TLS** channel presenting the *current* cert (the cert is the credential — no
/// pairing code). The server checks the live grant + `enrollment_confirmed`, issues a fresh cert (same
/// handle, new serial), and **cuts the old one**. The new cert changes the `cnf` thumbprint, so the
/// agent re-mints its access tokens against it immediately. The new cert is persisted **before** the
/// token re-mint — it is the irreplaceable credential; the tokens are always re-mintable from it.
///
/// The cert-renewal + token routes share the Garnet mutual-TLS ingress the server **advertised at
/// pickup** and the credential carries (`<grant_status_url>/...`; S094 — no longer a CLI flag). The
/// credential is resolved from `--credential`, else `<config-dir>/garnet/<handle>.json` for the active
/// `SIGNET_HANDLE`.
pub fn renew_cert_command(credential: Option<&Path>, out: &OutputMode) -> Result<()> {
    let path = resolve_credential_path(credential)?;
    let (handle, fingerprint, refreshed, credential_path) = renew_cert_flow(&path)?;
    progress(&format!(
        "done. New certificate active (fingerprint {fingerprint}); {} token(s) refreshed.",
        refreshed.len()
    ));
    out.print_json(&RenewCertResult {
        handle,
        cert_fingerprint: fingerprint,
        credential_path,
        tokens_refreshed: refreshed,
    })
}

/// The §4 cert-renewal flow, shared by the manual `garnet renew-cert` verb and the
/// Bug037 (i) auto-renew-on-use path. Returns `(handle, new_fingerprint,
/// tokens_refreshed, credential_path)` on success; the caller owns presentation.
fn renew_cert_flow(path: &Path) -> Result<(String, String, Vec<String>, String)> {
    let mut cred = PoPCredential::load(path)?;
    let token_url = cred.grant_status_url().to_string();
    let had_broker = cred.broker_token().is_some();

    // A fresh K4 keypair — the scalar is consumed (into the CSR + the persisted PKCS#8) and zeroized.
    let (scalar, _public) = signet_crypto::ecdsa::generate_keypair();
    let scalar = Zeroizing::new(scalar);
    let csr_der = signet_crypto::x509::build_csr(&scalar, "agent")
        .map_err(|e| CliError::generic(format!("building the renewal CSR: {e}")))?;

    progress(&format!(
        "renewing the certificate for '{}' over mutual-TLS…",
        cred.handle
    ));
    let new_cert_der = request_cert_renewal(&token_url, &cred, &csr_der)?;

    // The server builds the SAN from the grant, so the handle MUST be unchanged — verify before
    // rotating (defense-in-depth against a server/protocol fault rotating us onto a wrong identity).
    let new_handle = signet_crypto::x509::cert_san_handle(&new_cert_der)
        .ok()
        .flatten()
        .ok_or_else(|| {
            CliError::invalid_data("renewal returned a cert without a PRSN-handle SAN")
        })?;
    if new_handle != cred.handle {
        return Err(CliError::invalid_data(format!(
            "renewal returned a cert for '{new_handle}', not '{}'. Refusing to rotate",
            cred.handle
        )));
    }

    let new_key = signet_crypto::ecdsa::p256_scalar_to_pkcs8_der(&scalar)
        .map_err(|e| CliError::generic(format!("encoding the renewed K4 key: {e}")))?;

    // Rotate + PERSIST the new cert FIRST — it is the irreplaceable credential. A crash here leaves a
    // usable new cert (the agent re-mints tokens on its next use), never a cut cert with nothing held.
    cred.rotate_cert(new_key, new_cert_der);
    cred.save(path)?;

    // Re-mint the tokens bound to the NEW cert (server always; broker only if SE access was held).
    let mut refreshed = Vec::new();
    let server_token = request_token(&token_url, &cred, "signet-server")?;
    cred.set_server_token(server_token);
    refreshed.push("server".to_string());
    if had_broker {
        let broker_token = request_token(&token_url, &cred, "signet-broker")?;
        cred.set_broker_token(broker_token);
        refreshed.push("broker".to_string());
    }
    cred.save(path)?;

    let fingerprint = cred.fingerprint();
    Ok((
        cred.handle.clone(),
        fingerprint,
        refreshed,
        path.display().to_string(),
    ))
}

/// Bug037 (i) — **auto-renew-on-use.** When the credential's K4 cert is past HALF its
/// validity window, silently run the §4 renewal before the op, so any living agent's
/// cert self-extends and expiry becomes a dormant-only event (the guardian re-issue
/// ceremony covers that case). **Best-effort by design:** any failure — offline
/// ingress, server blip, a lost renewal race with a sibling process (the server cuts
/// the old cert; the loser's attempt fails at mTLS) — falls through to the op on the
/// current credential, which the op's own error handling already owns. Auto-renew
/// must never block an op the current cert can still perform.
pub(crate) fn auto_renew_cert_if_due(path: &Path, cred: PoPCredential) -> PoPCredential {
    let chain = cred.client_cert_chain();
    let Some(leaf) = chain.first() else {
        return cred;
    };
    let Ok((not_before, not_after)) = signet_crypto::x509::cert_validity_window(leaf.as_ref())
    else {
        return cred;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if !past_half_validity(not_before, not_after, now) {
        return cred;
    }
    progress("agent certificate past half its validity. Auto-renewing…");
    match renew_cert_flow(path) {
        Ok(_) => PoPCredential::load(path).unwrap_or(cred),
        Err(err) => {
            progress(&format!(
                "auto-renew failed (continuing on the current certificate): {err}"
            ));
            cred
        }
    }
}

/// The auto-renew trigger: past the midpoint of the validity window. Pure — the
/// host clock only decides WHEN we renew early; actual validity is the server's.
pub(crate) fn past_half_validity(not_before: u64, not_after: u64, now: u64) -> bool {
    now >= not_before + not_after.saturating_sub(not_before) / 2
}

/// Map the friendly `--audience` value to its wire audience, or `None` for an invalid value. Pure.
fn audience_to_wire(audience: &str) -> Option<&'static str> {
    match audience {
        "server" => Some("signet-server"),
        "broker" => Some("signet-broker"),
        _ => None,
    }
}

/// Resolve which credential file to renew: `--credential` if given, else the per-handle default for
/// the active `SIGNET_HANDLE`. Errors clearly when neither is available (a multi-PRSN host with no
/// asserted handle).
fn resolve_credential_path(credential: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = credential {
        return Ok(p.to_path_buf());
    }
    match crate::commands::asserted_handle() {
        Some(handle) => Ok(default_credential_path(&handle)),
        None => Err(CliError::invalid_args(
            "no --credential path and SIGNET_HANDLE is unset. Pass --credential <path>, or set \
             SIGNET_HANDLE so I know which PRSN's credential to renew.",
        )),
    }
}

/// How a non-2xx token response is classified (bug118, S156). The distinction is
/// **behavioural, not cosmetic**: only [`Self::AuthorizationRefused`] maps to `token_denied`,
/// which is a recovery TRIGGER in
/// [`BrokerKeystore::perform_op`](crate::keystore::BrokerKeystore).
#[derive(Debug, PartialEq, Eq)]
enum TokenReject {
    /// **HTTP 403 carrying our own `{"error": …}` JSON shape** — our server, answering that
    /// *this credential's authorization* is refused. The one state where a fresh grant may
    /// await, so the one that may fire a signed re-pickup.
    AuthorizationRefused,
    /// Everything else — a 4xx that isn't 403, any 5xx, a future 429, or a 403 whose body is
    /// not our shape (a proxy / captive portal / load balancer). **Never a recovery trigger.**
    Other,
}

/// The token-refusal discriminator (bug118) — pure and test-pinned, one home, so the
/// classification and its consequence cannot drift apart.
///
/// **Both conditions are load-bearing, and neither is redundant:**
/// * the **status** check excludes the server's own internal-error arm, which answers `500`
///   *with* an `{"error":"internal"}` body (so a shape-only test would wrongly admit it);
/// * the **shape** check excludes a 403 that did not come from us (a proxy's HTML error page
///   parses to nothing).
///
/// Deliberately **NOT** keyed on the server's reason *string*: that would make a
/// security-recovery path hostage to a copy edit (the current reason even contains an
/// em-dash, and 34 of those were swept from user-facing copy two sessions ago), and it would
/// fail **silently**. The shape is machine-checkable; the prose is not (Gus's proposal,
/// withdrawn on exactly this argument — S156).
fn reject_kind(status: u16, body_is_our_error_shape: bool) -> TokenReject {
    if status == 403 && body_is_our_error_shape {
        TokenReject::AuthorizationRefused
    } else {
        TokenReject::Other
    }
}

/// POST `/v1/garnet/token` over the agent→server mutual-TLS channel (presenting K4, pinning the
/// server to the credential's K2 anchor — the shared [`crate::broker_tls::k2_pinned_client_config`],
/// the same mechanism as the grant-status client). Returns the minted token, or a clear error
/// carrying the server's stable reason on a refusal.
pub(crate) fn request_token(
    token_url: &str,
    cred: &PoPCredential,
    audience_wire: &str,
) -> Result<String> {
    let tls = crate::broker_tls::k2_pinned_client_config(
        cred.ca_anchor_der().to_vec(),
        cred.client_cert_chain(),
        cred.client_key(),
    )
    .map_err(|e| CliError::new(70, "internal", format!("renewal mTLS config: {e}")))?;
    let agent = ureq::builder()
        .timeout(RENEW_TIMEOUT)
        .tls_config(Arc::new(tls))
        .build();
    let url = format!("{}/v1/garnet/token", token_url.trim_end_matches('/'));

    // Send the JSON body as bytes (the cli's `ureq` has no `json` feature, mirroring the
    // grant-status client which uses query params, not `send_json`).
    let body = serde_json::to_vec(&serde_json::json!({ "audience": audience_wire }))
        .map_err(|e| CliError::generic(format!("serializing the token request: {e}")))?;
    match agent
        .post(&url)
        .set("Content-Type", "application/json")
        .send_bytes(&body)
    {
        Ok(resp) => {
            let body = resp.into_string().map_err(|e| {
                CliError::new(
                    69,
                    "token_endpoint_unreachable",
                    format!("reading the token response: {e}"),
                )
            })?;
            let v: serde_json::Value = serde_json::from_str(&body)
                .map_err(|e| CliError::invalid_data(format!("malformed token response: {e}")))?;
            v.get("access_token")
                .and_then(serde_json::Value::as_str)
                .map(String::from)
                .ok_or_else(|| CliError::invalid_data("token response missing 'access_token'"))
        }
        // The server answered a refusal. **bug118 (S156): the code this maps to is a TRIGGER, so
        // its breadth is a correctness question, not a cosmetic one.** `token_denied` fires the
        // BrokerKeystore's re-auth recovery (a signed re-pickup), so it must mean *an
        // AUTHORIZATION refusal from OUR server* — where a fresh grant may await — and never
        // "the request failed somehow". A transient 5xx (or a future 429) reaching the recovery
        // rotates a healthy credential and fires the v09 LOUD RE-ISSUE at the guardian: a false
        // takeover alarm from a server blip. See [`reject_kind`] for the discriminator.
        Err(ureq::Error::Status(code, resp)) => {
            let reason = resp
                .into_string()
                .ok()
                .and_then(|b| serde_json::from_str::<serde_json::Value>(&b).ok())
                .and_then(|v| {
                    v.get("error")
                        .and_then(serde_json::Value::as_str)
                        .map(String::from)
                });
            match reject_kind(code, reason.is_some()) {
                TokenReject::AuthorizationRefused => Err(CliError::new(
                    77,
                    "token_denied",
                    format!(
                        "the server refused the token ({code}): {}",
                        reason.unwrap_or_else(|| "authorization refused".to_string())
                    ),
                )),
                TokenReject::Other => Err(CliError::new(
                    77,
                    "token_request_failed",
                    format!(
                        "the token request failed ({code}): {}",
                        reason.unwrap_or_else(|| "token request rejected".to_string())
                    ),
                )),
            }
        }
        Err(ureq::Error::Transport(t)) => Err(CliError::new(
            69,
            "token_endpoint_unreachable",
            format!("could not reach the token endpoint at {url}: {t}"),
        )),
    }
}

/// POST `/v1/garnet/renew-cert` over the agent→server mutual-TLS channel (presenting the CURRENT K4
/// cert, pinning the server to the credential's K2 anchor — the same mechanism as [`request_token`]).
/// The body carries only the new CSR (base64-standard DER); the server builds the new cert's identity
/// from the grant (the keystone). Returns the new cert DER, or a clear error carrying the server's
/// stable reason on a refusal.
fn request_cert_renewal(token_url: &str, cred: &PoPCredential, csr_der: &[u8]) -> Result<Vec<u8>> {
    let tls = crate::broker_tls::k2_pinned_client_config(
        cred.ca_anchor_der().to_vec(),
        cred.client_cert_chain(),
        cred.client_key(),
    )
    .map_err(|e| CliError::new(70, "internal", format!("cert-renewal mTLS config: {e}")))?;
    let agent = ureq::builder()
        .timeout(RENEW_TIMEOUT)
        .tls_config(Arc::new(tls))
        .build();
    let url = format!("{}/v1/garnet/renew-cert", token_url.trim_end_matches('/'));

    // Send the JSON body as bytes (the cli's `ureq` has no `json` feature — mirrors `request_token`).
    let body = serde_json::to_vec(&serde_json::json!({ "csr": STANDARD.encode(csr_der) }))
        .map_err(|e| CliError::generic(format!("serializing the cert-renewal request: {e}")))?;
    match agent
        .post(&url)
        .set("Content-Type", "application/json")
        .send_bytes(&body)
    {
        Ok(resp) => {
            let body = resp.into_string().map_err(|e| {
                CliError::new(
                    69,
                    "token_endpoint_unreachable",
                    format!("reading the cert-renewal response: {e}"),
                )
            })?;
            let v: serde_json::Value = serde_json::from_str(&body).map_err(|e| {
                CliError::invalid_data(format!("malformed cert-renewal response: {e}"))
            })?;
            let pem = v
                .get("client_cert")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    CliError::invalid_data("cert-renewal response missing 'client_cert'")
                })?;
            signet_crypto::x509::pem_to_der(pem).map_err(|e| {
                CliError::invalid_data(format!("cert-renewal returned a malformed cert: {e}"))
            })
        }
        // A definitive refusal (e.g. 403 not-confirmed/revoked, 400 bad CSR) — surface its reason.
        Err(ureq::Error::Status(code, resp)) => {
            let reason = resp
                .into_string()
                .ok()
                .and_then(|b| serde_json::from_str::<serde_json::Value>(&b).ok())
                .and_then(|v| {
                    v.get("error")
                        .and_then(serde_json::Value::as_str)
                        .map(String::from)
                })
                .unwrap_or_else(|| "cert renewal rejected".to_string());
            Err(CliError::new(
                77,
                "cert_renewal_denied",
                format!("the server refused the cert renewal ({code}): {reason}"),
            ))
        }
        Err(ureq::Error::Transport(t)) => Err(CliError::new(
            69,
            "token_endpoint_unreachable",
            format!("could not reach the cert-renewal endpoint at {url}: {t}"),
        )),
    }
}

// ── The SE-op surface through the broker (`signet garnet keygen` / `sign`) ────────────────────────

/// `signet garnet keygen --purpose <signing|kem>` — create the PRSN's Secure-Enclave keypair via the
/// local broker (Auth-Core §7). The broker performs the keygen in the host SE for this PRSN's
/// authenticated handle; the agent never touches the SE. Prints the public key + fingerprint.
pub fn keygen_command(
    broker: SocketAddr,
    purpose: Purpose,
    algorithm: Option<&str>,
    credential: Option<&Path>,
    out: &OutputMode,
) -> Result<()> {
    let (cred, client, token) = open_broker(broker, credential)?;
    let label = KeyLabel::from_handle(&cred.handle, purpose)?.full();
    let alg = algorithm
        .unwrap_or_else(|| purpose.default_alg())
        .to_string();

    progress(&format!(
        "keygen '{label}' in the Secure Enclave via the broker…"
    ));
    match client.perform(
        &token,
        Op::Keygen {
            label: label.clone(),
            algorithm: alg,
        },
    )? {
        Response::Ok(OpOk::Keygen {
            public_key,
            fingerprint,
            algorithm,
        }) => out.print_json(&serde_json::json!({
            "label": label,
            "algorithm": algorithm,
            "fingerprint": fingerprint,
            "public_key": URL_SAFE_NO_PAD.encode(&public_key),
        })),
        Response::Ok(other) => Err(unexpected_response(&other)),
        Response::Err(e) => Err(broker_op_error(e)),
    }
}

/// `signet garnet sign` — sign a message with the PRSN's Secure-Enclave **signing** key via the local
/// broker (the SE op the partnered E2E exercises). Mirrors `signet sign`'s input/output formats; the
/// broker returns the raw `r‖s` ES256 signature.
pub fn sign_command(
    broker: SocketAddr,
    input_format: &str,
    output_format: &str,
    in_path: Option<&Path>,
    out_path: Option<&Path>,
    credential: Option<&Path>,
) -> Result<()> {
    let (cred, client, token) = open_broker(broker, credential)?;
    let label = KeyLabel::from_handle(&cred.handle, Purpose::Signing)?.full();

    let raw = crate::commands::read_input(in_path)?;
    let message = crate::commands::decode_sign_input(&raw, input_format)?;
    if message.len() > crate::commands::SIGN_INPUT_MAX {
        return Err(CliError::invalid_args("input exceeds the 1 MB sign limit"));
    }

    match client.perform(
        &token,
        Op::Sign {
            label,
            msg: message,
        },
    )? {
        Response::Ok(OpOk::Sign { signature }) => {
            let bytes = crate::commands::encode_signature(&signature, output_format)?;
            crate::commands::write_output(out_path, &bytes)
        }
        Response::Ok(other) => Err(unexpected_response(&other)),
        Response::Err(e) => Err(broker_op_error(e)),
    }
}

/// Load the PoP credential, build the broker client, and extract the **broker-audience**
/// token — **auto-acquiring one when absent** (bug084 §5: the authorization is auto-confirmed
/// at pickup, so the token is immediately mintable; no hand-run `renew` step). Returns
/// `(credential, client, broker_token)`.
fn open_broker(
    broker: SocketAddr,
    credential: Option<&Path>,
) -> Result<(PoPCredential, BrokerClient, String)> {
    let path = resolve_credential_path(credential)?;
    let cred = PoPCredential::load(&path)?;
    // Bug037 (i): self-extend the K4 cert when past half its life (best-effort).
    let mut cred = auto_renew_cert_if_due(&path, cred);
    let token = match cred.broker_token() {
        Some(t) => t.to_string(),
        None => {
            progress("no broker token yet. Acquiring one over mutual-TLS…");
            let token = request_token(cred.grant_status_url(), &cred, "signet-broker")?;
            cred.set_broker_token(token.clone());
            cred.save(&path)?;
            token
        }
    };
    let client = BrokerClient::new(broker, &cred)?;
    Ok((cred, client, token))
}

/// Re-raise the broker's own [`OpErr`] (e.g. `authorization_denied`, `key_not_found`) faithfully.
/// The broker's dynamic code rides in the message (the `CliError` code taxonomy is a fixed
/// `&'static str` set, so the broker's runtime code can't be it) — the agent still sees both.
fn broker_op_error(e: OpErr) -> CliError {
    CliError::new(
        77,
        "broker_op_failed",
        format!("the broker refused the op ({}): {}", e.code, e.message),
    )
}

/// A broker response whose variant does not match the request (a protocol fault) — never expected.
fn unexpected_response(got: &OpOk) -> CliError {
    CliError::invalid_data(format!(
        "the broker returned an unexpected response variant: {got:?}"
    ))
}

/// Progress narration to stderr (stdout is the machine-readable result).
fn progress(message: &str) {
    eprintln!("signet: {message}");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// bug118 (S156) — pin the token-refusal discriminator. This decides whether a failed
    /// token mint may fire a signed re-pickup, so an edit that widens it re-introduces the
    /// false-takeover-alarm defect (a transient 5xx rotating a healthy credential). The
    /// NEGATIVE cases carry the weight here: each one is a state that must NOT recover.
    #[test]
    fn reject_kind_triggers_only_on_a_403_carrying_our_error_shape() {
        // The ONE trigger: our server's authorization refusal (403 + our {"error": …} body).
        // This is the state where a fresh grant may await — GrantNotActive / NotConfirmed.
        assert_eq!(
            reject_kind(403, true),
            TokenReject::AuthorizationRefused,
            "our 403 refusal is the recovery trigger"
        );

        // NOT a trigger — a 403 that did not come from us (a proxy / captive portal / LB
        // returning an HTML error page, which parses to no `error` field).
        assert_eq!(reject_kind(403, false), TokenReject::Other);

        // NOT a trigger — transient/server-side failures. The 500 case is the sharp one:
        // the server's own internal-error arm answers 500 WITH an {"error":"internal"}
        // body, so the status check (not the shape check) is what excludes it. This is the
        // exact shape of the original bug118 defect.
        for status in [500u16, 502, 503] {
            assert_eq!(reject_kind(status, true), TokenReject::Other);
            assert_eq!(reject_kind(status, false), TokenReject::Other);
        }

        // NOT a trigger — a rate-limit refusal, so an automatic extra pickup can never be
        // spent against a budget (the token path is unlimited today; this pins the future).
        assert_eq!(reject_kind(429, true), TokenReject::Other);

        // NOT a trigger — other 4xx (e.g. 400 bad audience, 401): a malformed or
        // unauthenticated request is not "authorization refused, a fresh grant may await".
        assert_eq!(reject_kind(400, true), TokenReject::Other);
        assert_eq!(reject_kind(401, true), TokenReject::Other);
    }

    #[test]
    fn past_half_validity_triggers_at_the_midpoint_and_after() {
        // A 7-day window starting at t=1000: midpoint at 1000 + 302_400.
        let (nb, na) = (1_000u64, 1_000 + 604_800);
        let mid = nb + 302_400;
        assert!(!past_half_validity(nb, na, nb)); // freshly issued
        assert!(!past_half_validity(nb, na, mid - 1)); // just before the midpoint
        assert!(past_half_validity(nb, na, mid)); // at the midpoint
        assert!(past_half_validity(nb, na, na)); // at expiry (renewal will fail at mTLS — fine)
        assert!(past_half_validity(nb, na, na + 999)); // long expired
    }

    #[test]
    fn past_half_validity_handles_a_degenerate_window() {
        // not_after <= not_before (malformed) — always "due"; the renewal attempt
        // then fails or succeeds on the server's authority, never panics here.
        assert!(past_half_validity(500, 500, 500));
        assert!(past_half_validity(500, 400, 500));
    }

    #[test]
    fn default_credential_path_is_per_handle_under_garnet() {
        let path = default_credential_path("hlin-ai");
        // Per-handle file, namespaced under `garnet/` in the config dir (the parent is `<…>/garnet`).
        assert_eq!(path.file_name().unwrap(), "hlin-ai.json");
        assert_eq!(path.parent().unwrap().file_name().unwrap(), "garnet");
    }

    #[test]
    fn default_credential_path_distinguishes_co_resident_prsns() {
        // Two PRSNs on one guardian Mac must not share a credential file.
        assert_ne!(
            default_credential_path("hlin-ai"),
            default_credential_path("mira-ai")
        );
    }

    #[test]
    fn audience_to_wire_maps_only_the_two_friendly_values() {
        assert_eq!(audience_to_wire("server"), Some("signet-server"));
        assert_eq!(audience_to_wire("broker"), Some("signet-broker"));
        assert_eq!(audience_to_wire("signet-broker"), None); // the wire form is not a valid input
        assert_eq!(audience_to_wire(""), None);
    }

    #[test]
    fn resolve_credential_path_prefers_an_explicit_flag() {
        let explicit = Path::new("/tmp/somewhere/cred.json");
        assert_eq!(resolve_credential_path(Some(explicit)).unwrap(), explicit);
    }

    #[test]
    fn broker_op_error_surfaces_the_brokers_code_and_message() {
        let err = broker_op_error(OpErr {
            code: "authorization_denied".into(),
            message: "label 'x-ai-signing' is not this PRSN".into(),
        });
        assert_eq!(err.code, "broker_op_failed");
        // The broker's own (dynamic) code + message ride in the message so the agent sees both.
        assert!(err.message.contains("authorization_denied"));
        assert!(err.message.contains("not this PRSN"));
    }
}
