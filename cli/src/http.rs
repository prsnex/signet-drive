// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Minimal blocking HTTP for the server-bound commands. Three request families:
//!
//! - **Public GET** (`get_text` / `get_json`) — server-info, transparency, the
//!   version check; no credentials.
//! - **Authenticated** (`get_json_signed` / `get_text_signed` / `post_json_signed`
//!   / `delete_signed`) — per-request SIGNET-V1 ECDSA signing (Envelope §6.2): sign
//!   the canonical bytes with the keystore signing key and send the four `Signet-*`
//!   headers. A fresh timestamp + single-use nonce are minted **each attempt**, so a
//!   retry re-signs — a replayed nonce is rejected `replay_detected`.
//! - **Pre-signed bucket transfer** (`put_presigned` / `get_presigned_range`) —
//!   direct-to-object-storage PUT / Range-GET for the §4.2 large-file path. The
//!   pre-signed URL self-authenticates, so these carry **no** `Signet-*` (or
//!   `Signet-Cli-Version`) headers — they go to the bucket, not the API.
//!
//! Every API request sends `Signet-Cli-Version`; all families retry transient
//! failures (timeout / 5xx / connection) with exponential backoff; `400 cli_outdated`
//! → exit 16 and the soft `Signet-Cli-Update-Recommended` nudge is surfaced
//! (CLI Spec v08 §"CLI version drift").

use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::{OsRng, RngCore};

use crate::bucket_transport;
use crate::error::{CliError, Result};
use crate::keystore::{KeyLabel, Keystore, Purpose};

const CLI_VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_RETRIES: u32 = 3;

/// The rustls `ClientConfig` every request in this module uses — built on the
/// crate's **aws-lc-rs** provider so the default kx groups apply (with the
/// `prefer-post-quantum` feature, **X25519MLKEM768 first** — PQR item 10,
/// transport-PQ against harvest-now-decrypt-later on the CLI→server leg).
/// ureq's own internal default hard-codes the *ring* provider (no ML-KEM), so
/// routing through this config is what makes the CLI PQ-capable at all. Trust
/// anchors = the same Mozilla set ureq's default uses (`webpki-roots`); TLS
/// 1.2+1.3 like ureq's default (the bucket endpoints stay reachable) — the API
/// server itself is TLS 1.3.
pub(crate) fn pq_tls_config() -> Arc<rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let config = rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("aws-lc-rs supports the default protocol versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
            Arc::new(config)
        })
        .clone()
}

/// The shared HTTP agent — all module requests go through it so every TLS
/// connection uses [`pq_tls_config`] (ureq's free functions would silently use
/// its internal ring-provider default instead).
fn agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| ureq::builder().tls_config(pq_tls_config()).build())
}

fn network(message: impl Into<String>) -> CliError {
    CliError::new(31, "network_error", message)
}

/// Map a non-retryable **API** HTTP error status to a CliError. A 4xx the server
/// answered is a *semantic* refusal, not a network failure — each maps to a precise
/// category so a PRSN can key off the code/exit (the body carries the server's own
/// error code): 401 → `authentication_failed` (10), 403 → `authorization_denied`
/// (17), 404 → `not_found` (26), 409 → `conflict` (27). Everything else (an
/// unexpected 4xx, or an exhausted 5xx) stays `network_error` (31). API calls only.
/// (A pre-signed bucket 403 has its OWN classification, `presigned_rejected`, in
/// `get_presigned_range_impl` — S185. This sentence used to read "a pre-signed
/// bucket 4xx (e.g. an expired URL) is a transfer failure and stays `network`",
/// which documented the bug211-twin defect as policy: the download loop could not
/// tell an expired URL from a network fault, so it retried dead signatures and
/// then died. Kept corrected rather than deleted — prose that asserted a policy
/// nothing should have implemented.)
fn api_status_error(code: u16, body: String) -> CliError {
    match code {
        401 => CliError::authentication_failed(format!(
            "the server did not accept the request's authentication (HTTP 401): {body}"
        )),
        403 => CliError::authorization_denied(format!(
            "the server refused the request (HTTP 403): {body}"
        )),
        404 => CliError::not_found(format!(
            "the server reported the resource does not exist (HTTP 404): {body}"
        )),
        409 => CliError::conflict(format!(
            "the request conflicts with the current state (HTTP 409): {body}"
        )),
        _ => network(format!("server returned HTTP {code}: {body}")),
    }
}

fn backoff(attempt: u32) -> std::time::Duration {
    std::time::Duration::from_secs(1u64 << (attempt - 1)) // 1s, 2s, 4s
}

/// GET `url` (with extra headers) and return the body text. Retries transient
/// errors; surfaces the update-recommended nudge; maps cli_outdated.
pub fn get_text(url: &str, headers: &[(&str, &str)]) -> Result<String> {
    let mut attempt = 0;
    loop {
        let mut req = agent().get(url).set("Signet-Cli-Version", CLI_VERSION);
        for (name, value) in headers {
            req = req.set(name, value);
        }
        match req.call() {
            Ok(resp) => {
                if resp.header("Signet-Cli-Update-Recommended") == Some("true") {
                    eprintln!(
                        "signet: a newer version is available; run 'signet update' to upgrade."
                    );
                }
                return resp
                    .into_string()
                    .map_err(|e| network(format!("reading response body: {e}")));
            }
            Err(ureq::Error::Status(400, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                if body.contains("cli_outdated") {
                    return Err(CliError::new(
                        16,
                        "cli_outdated",
                        "this CLI version is no longer accepted; run 'signet update' to upgrade",
                    ));
                }
                return Err(CliError::invalid_data(format!(
                    "server rejected the request: {body}"
                )));
            }
            Err(ureq::Error::Status(code, resp)) => {
                if (500..600).contains(&code) && attempt < MAX_RETRIES {
                    attempt += 1;
                    std::thread::sleep(backoff(attempt));
                    continue;
                }
                let body = resp.into_string().unwrap_or_default();
                return Err(api_status_error(code, body));
            }
            Err(ureq::Error::Transport(transport)) => {
                if attempt < MAX_RETRIES {
                    attempt += 1;
                    std::thread::sleep(backoff(attempt));
                    continue;
                }
                return Err(network(format!("request to {url} failed: {transport}")));
            }
        }
    }
}

/// GET `url` and parse the body as JSON.
pub fn get_json(url: &str, headers: &[(&str, &str)]) -> Result<serde_json::Value> {
    let text = get_text(url, headers)?;
    serde_json::from_str(&text)
        .map_err(|e| CliError::invalid_data(format!("server returned invalid JSON: {e}")))
}

/// GET `url` and stream the response body to `dest` (a file), returning the byte count.
/// For the assisted-update download of the notarized zip (a large binary — streamed to disk,
/// not buffered). Single attempt with the module's PQ-TLS agent; the caller verifies the
/// download's sha256 against the served `.sha256` companion.
pub fn download_to_file(url: &str, dest: &std::path::Path) -> Result<u64> {
    let resp = agent()
        .get(url)
        .set("Signet-Cli-Version", CLI_VERSION)
        .call()
        .map_err(|e| network(format!("downloading {url}: {e}")))?;
    let mut reader = resp.into_reader();
    let mut file = std::fs::File::create(dest)
        .map_err(|e| CliError::filesystem(format!("creating {}: {e}", dest.display())))?;
    std::io::copy(&mut reader, &mut file)
        .map_err(|e| network(format!("writing download to {}: {e}", dest.display())))
}

/// GET `url` **once**, with a hard `timeout` — no retries, no backoff. For
/// best-effort callers that must never stall: the menu-bar version-currency
/// check at host-signer startup pays at most `timeout`, once, on an offline or
/// serverless Mac (`get_text`'s 1s/2s/4s backoff would block the status item).
/// Any failure is the caller's signal to skip, not to surface.
pub fn get_text_once(url: &str, timeout: std::time::Duration) -> Result<String> {
    let agent = ureq::builder()
        .timeout(timeout)
        .tls_config(pq_tls_config())
        .build();
    match agent.get(url).set("Signet-Cli-Version", CLI_VERSION).call() {
        Ok(resp) => resp
            .into_string()
            .map_err(|e| network(format!("reading response body: {e}"))),
        Err(ureq::Error::Status(code, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            Err(api_status_error(code, body))
        }
        Err(ureq::Error::Transport(transport)) => {
            Err(network(format!("request to {url} failed: {transport}")))
        }
    }
}

// ── Unsigned POST (the PRSN-enrollment rendezvous) ───────────────────────────

/// POST `url` (optionally with a JSON `body`) → response body text — **unsigned**
/// (no `Signet-*` headers). The PRSN-enrollment agent authenticates with the
/// single-use `code` it carries in the body/query, not a signing key (a brand-new
/// PRSN has none yet): `create-pending` (no body) and `submit-keys` (a JSON body).
/// Mirrors `get_text`'s transient retry + `cli_outdated` handling; a 2xx with an
/// empty body (a 204) returns `""`.
pub fn post_text(url: &str, body: Option<&[u8]>) -> Result<String> {
    let mut attempt = 0;
    loop {
        let req = agent().post(url).set("Signet-Cli-Version", CLI_VERSION);
        let outcome = match body {
            Some(bytes) => req
                .set("Content-Type", "application/json")
                .send_bytes(bytes),
            None => req.call(),
        };
        match outcome {
            Ok(resp) => {
                if resp.header("Signet-Cli-Update-Recommended") == Some("true") {
                    eprintln!(
                        "signet: a newer version is available; run 'signet update' to upgrade."
                    );
                }
                return resp
                    .into_string()
                    .map_err(|e| network(format!("reading response body: {e}")));
            }
            Err(ureq::Error::Status(400, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                if body.contains("cli_outdated") {
                    return Err(CliError::new(
                        16,
                        "cli_outdated",
                        "this CLI version is no longer accepted; run 'signet update' to upgrade",
                    ));
                }
                return Err(CliError::invalid_data(format!(
                    "server rejected the request: {body}"
                )));
            }
            Err(ureq::Error::Status(code, resp)) => {
                if (500..600).contains(&code) && attempt < MAX_RETRIES {
                    attempt += 1;
                    std::thread::sleep(backoff(attempt));
                    continue;
                }
                let body = resp.into_string().unwrap_or_default();
                return Err(api_status_error(code, body));
            }
            Err(ureq::Error::Transport(transport)) => {
                if attempt < MAX_RETRIES {
                    attempt += 1;
                    std::thread::sleep(backoff(attempt));
                    continue;
                }
                return Err(network(format!("request to {url} failed: {transport}")));
            }
        }
    }
}

/// Unsigned POST → parsed JSON (the enrollment `create-pending` response body).
pub fn post_json(url: &str, body: Option<&[u8]>) -> Result<serde_json::Value> {
    let text = post_text(url, body)?;
    serde_json::from_str(&text)
        .map_err(|e| CliError::invalid_data(format!("server returned invalid JSON: {e}")))
}

// ── Authenticated requests (per-request SIGNET-V1 signing, Envelope §6.2) ─────

/// Build the four `Signet-*` auth headers for one request: sign the SIGNET-V1
/// canonical bytes (method ‖ path ‖ body-hash ‖ timestamp ‖ nonce ‖ fingerprint)
/// with the keystore's signing key. The timestamp + single-use nonce are minted
/// fresh here, so **every call re-signs** — a caller retrying a request MUST rebuild
/// these (a reused nonce is rejected `replay_detected`). `path` is the exact
/// path-and-query the server reconstructs; `body` is the raw request body (an empty
/// slice for a bodyless request → the body hash is `SHA-256("")`). Headers come back
/// in the order `[timestamp, nonce, fingerprint, signature]`.
/// Sign the SIGNET-V1 canonical bytes for one request (PQR Spec §8 / item 7b).
///
/// When this identity holds a `signing-pq` key (every account enrolled through
/// the four-key ceremony), the signature is the fixed-width **dual**:
/// `sig_es256 (64 B, raw r‖s) ‖ sig_mldsa87 (4627 B)` — both halves over the
/// identical canonical bytes, the ML-DSA half under the `signet:req:v1` FIPS
/// 204 context (as the context *parameter*, never prepended). A two-key
/// pre-re-enrollment identity keeps signing classically. The existence probe is
/// deliberately stateless (one cheap keystore/broker round-trip per request —
/// sub-ms against the ~13–18 ms SE ML-DSA sign it gates; no cached identity
/// state to go stale across a re-enrollment).
fn request_signature(
    keystore: &dyn Keystore,
    signing: &KeyLabel,
    canonical: &[u8],
) -> Result<Vec<u8>> {
    let pq_label = KeyLabel::from_handle(signing.handle(), Purpose::SigningPq)?;
    if !keystore.exists(&pq_label)? {
        return Ok(keystore.sign(signing, canonical)?.to_vec());
    }
    let sig_es = keystore.sign(signing, canonical)?;
    let sig_pq = keystore.ml_dsa_sign(
        &pq_label,
        canonical,
        signet_crypto::attest::REQUEST_MLDSA_CTX,
    )?;
    if sig_pq.len() != signet_crypto::attest::MLDSA87_SIG_LEN {
        return Err(CliError::generic(format!(
            "keystore returned a {}-byte ML-DSA-87 signature (expected 4627)",
            sig_pq.len()
        )));
    }
    let mut dual = Vec::with_capacity(signet_crypto::attest::REQUEST_DUAL_SIG_LEN);
    dual.extend_from_slice(&sig_es);
    dual.extend_from_slice(&sig_pq);
    Ok(dual)
}

fn auth_headers(
    keystore: &dyn Keystore,
    signing: &KeyLabel,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<[(&'static str, String); 4]> {
    let fingerprint = keystore.meta(signing)?.fingerprint;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| network("system clock is before the unix epoch"))?
        .as_secs()
        .to_string();
    let mut nonce_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = hex::encode(nonce_bytes);
    let canonical = signet_crypto::signing::signet_v1_canonical_bytes(
        method,
        path,
        body,
        &timestamp,
        &nonce,
        &fingerprint,
    );
    let signature = URL_SAFE_NO_PAD.encode(request_signature(keystore, signing, &canonical)?);
    Ok([
        ("Signet-Timestamp", timestamp),
        ("Signet-Nonce", nonce),
        ("Signet-Fingerprint", fingerprint),
        ("Signet-Signature", signature),
    ])
}

/// An authenticated request → response body text. Dials `base_url + path` and signs
/// over `path` (the value the server reconstructs as its `path_and_query`). `body`,
/// when present, is sent **verbatim** with a JSON content type — the same bytes are
/// hashed into the signature, so a caller passes already-serialized bytes and must
/// never re-serialize between signing and sending. Re-signs on every attempt (fresh
/// nonce), so a retried request is never a replay; mirrors `get_text`'s transient
/// retry + `cli_outdated` handling.
fn signed_call(
    keystore: &dyn Keystore,
    signing: &KeyLabel,
    method: &str,
    base_url: &str,
    path: &str,
    body: Option<&[u8]>,
) -> Result<String> {
    let url = format!("{base_url}{path}");
    let mut attempt = 0;
    loop {
        let headers = auth_headers(keystore, signing, method, path, body.unwrap_or(&[]))?;
        let req = match method {
            "GET" => agent().get(&url),
            "POST" => agent().post(&url),
            "PATCH" => agent().request("PATCH", &url),
            "DELETE" => agent().delete(&url),
            other => {
                return Err(CliError::invalid_args(format!(
                    "unsupported signed HTTP method '{other}'"
                )));
            }
        };
        let mut req = req.set("Signet-Cli-Version", CLI_VERSION);
        for (name, value) in &headers {
            req = req.set(name, value);
        }
        let outcome = match body {
            Some(bytes) => req
                .set("Content-Type", "application/json")
                .send_bytes(bytes),
            None => req.call(),
        };
        match outcome {
            Ok(resp) => {
                if resp.header("Signet-Cli-Update-Recommended") == Some("true") {
                    eprintln!(
                        "signet: a newer version is available; run 'signet update' to upgrade."
                    );
                }
                return resp
                    .into_string()
                    .map_err(|e| network(format!("reading response body: {e}")));
            }
            Err(ureq::Error::Status(400, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                if body.contains("cli_outdated") {
                    return Err(CliError::new(
                        16,
                        "cli_outdated",
                        "this CLI version is no longer accepted; run 'signet update' to upgrade",
                    ));
                }
                return Err(CliError::invalid_data(format!(
                    "server rejected the request: {body}"
                )));
            }
            Err(ureq::Error::Status(code, resp)) => {
                if (500..600).contains(&code) && attempt < MAX_RETRIES {
                    attempt += 1;
                    std::thread::sleep(backoff(attempt));
                    continue;
                }
                let body = resp.into_string().unwrap_or_default();
                return Err(api_status_error(code, body));
            }
            Err(ureq::Error::Transport(transport)) => {
                if attempt < MAX_RETRIES {
                    attempt += 1;
                    std::thread::sleep(backoff(attempt));
                    continue;
                }
                return Err(network(format!("request to {url} failed: {transport}")));
            }
        }
    }
}

/// Authenticated GET → parsed JSON.
pub fn get_json_signed(
    keystore: &dyn Keystore,
    signing: &KeyLabel,
    base_url: &str,
    path: &str,
) -> Result<serde_json::Value> {
    let text = signed_call(keystore, signing, "GET", base_url, path, None)?;
    serde_json::from_str(&text)
        .map_err(|e| CliError::invalid_data(format!("server returned invalid JSON: {e}")))
}

/// Authenticated GET → raw response text (passthrough, e.g. `audit`).
pub fn get_text_signed(
    keystore: &dyn Keystore,
    signing: &KeyLabel,
    base_url: &str,
    path: &str,
) -> Result<String> {
    signed_call(keystore, signing, "GET", base_url, path, None)
}

/// Authenticated POST of a JSON `body` → parsed JSON. `body` is sent and signed
/// verbatim — pass already-serialized bytes.
pub fn post_json_signed(
    keystore: &dyn Keystore,
    signing: &KeyLabel,
    base_url: &str,
    path: &str,
    body: &[u8],
) -> Result<serde_json::Value> {
    let text = signed_call(keystore, signing, "POST", base_url, path, Some(body))?;
    serde_json::from_str(&text)
        .map_err(|e| CliError::invalid_data(format!("server returned invalid JSON: {e}")))
}

/// Authenticated POST with **no** request body → raw response text. For the
/// path-only endpoints (`invitations/{token}/accept`, `share-folders/{id}/leave`)
/// that take no JSON body — the signed body hash is `SHA-256("")`. The caller
/// parses the text (accept returns a small JSON ack; leave returns an empty 204).
pub fn post_signed(
    keystore: &dyn Keystore,
    signing: &KeyLabel,
    base_url: &str,
    path: &str,
) -> Result<String> {
    signed_call(keystore, signing, "POST", base_url, path, None)
}

/// Authenticated PATCH of a JSON `body` → parsed JSON (rename / same-root move).
/// `body` is sent and signed verbatim — pass already-serialized bytes.
pub fn patch_json_signed(
    keystore: &dyn Keystore,
    signing: &KeyLabel,
    base_url: &str,
    path: &str,
    body: &[u8],
) -> Result<serde_json::Value> {
    let text = signed_call(keystore, signing, "PATCH", base_url, path, Some(body))?;
    serde_json::from_str(&text)
        .map_err(|e| CliError::invalid_data(format!("server returned invalid JSON: {e}")))
}

/// Authenticated DELETE. Discards the response body (a 204 or a small JSON ack).
pub fn delete_signed(
    keystore: &dyn Keystore,
    signing: &KeyLabel,
    base_url: &str,
    path: &str,
) -> Result<()> {
    signed_call(keystore, signing, "DELETE", base_url, path, None).map(|_| ())
}

/// Authenticated DELETE of a JSON `body` → parsed JSON (the batch-delete endpoints,
/// which take `{folder_ids|file_ids}` and return `{deleted}`). Signed verbatim.
pub fn delete_json_signed(
    keystore: &dyn Keystore,
    signing: &KeyLabel,
    base_url: &str,
    path: &str,
    body: &[u8],
) -> Result<serde_json::Value> {
    let text = signed_call(keystore, signing, "DELETE", base_url, path, Some(body))?;
    serde_json::from_str(&text)
        .map_err(|e| CliError::invalid_data(format!("server returned invalid JSON: {e}")))
}

// ── Pre-signed bucket transfer (direct-to-object-storage, §4.2) ──────────────
//
// bug047: a fraction of byte-transfer connections to object storage can
// silently stall on a degraded network path (root-caused S123: per-connection-
// random, path-side; a stalled flow hangs to a ~13m42s TCP timeout). The cure —
// measured 65% per-connection stall → 95% effective success — is per-attempt
// stall-detection + abort + retry on a FRESH connection. Both bucket functions
// below therefore transfer over the purpose-built `bucket_transport` (NEVER the
// shared pooled API agent: a pooled, possibly-sick flow would silently defeat
// the fix — ⚠ 1c/S175 amends this ON THE DOWNLOAD HALF ONLY, deliberately: the
// UPLOAD half keeps fresh-per-attempt because that re-roll IS the measured
// 25.6× bug047 containment, while downloads — measured healthy in the same bad
// windows — may reuse via bucket_transport's own DownloadPool, which evicts on
// any failure so a retry is still a genuinely fresh flow. The split and its
// receipts live in bucket_transport's module doctrine; do not "fix" either half
// to match the other), whose every bound is rate-free or rate-derived: a no-write-progress
// gap that ANY forward byte resets on the write path, and a rate-derived
// response ceiling on the read path — so a slow-but-moving path is never killed
// by a wall-clock deadline (bug060; the module invariant lives in
// `bucket_transport`). (The pre-bug060 `ureq` path armed `timeout_read`/
// `timeout_write` as an inbound-silence timer that ran CONCURRENTLY with
// transmission and so killed healthy uploads — S127 P1; those functions no
// longer exist.)

/// Attempt budget for the defensive download path. Downloads measured 0%
/// stall in the same windows uploads stalled 65% (bug047 exp B) — this is
/// belt-and-braces symmetry, not the mitigation, so it is a small constant
/// rather than a served knob.
const DOWNLOAD_ATTEMPTS: u32 = 3;

/// Client-side transfer-resilience knobs for the pre-signed bucket paths
/// (bug047). Server-tunable: the multipart initiate/resume responses carry the
/// current `system_config` values (`multipart_part_retry_attempts`,
/// `multipart_stall_timeout_seconds`); these defaults apply when a response
/// omits them (an older server).
#[derive(Debug, Clone, Copy)]
pub struct TransferKnobs {
    /// Per-part attempt budget (attempts, not retries — 1 means no retry).
    pub attempts: u32,
    /// The per-socket-op no-progress threshold (any transferred byte resets it).
    pub stall_timeout: std::time::Duration,
    /// `SO_SNDBUF` cap for bucket transfers (`transfer_sndbuf_bytes`, migration
    /// 0037). Bounds how far socket write-progress may lead true delivery, which
    /// is what makes the gap detector honest — served so field evidence can retune
    /// it without a client release (bug060).
    pub sndbuf_bytes: usize,
}

impl Default for TransferKnobs {
    fn default() -> Self {
        Self {
            attempts: 10,
            stall_timeout: std::time::Duration::from_secs(15),
            sndbuf_bytes: bucket_transport::TransportBounds::default().sndbuf_bytes,
        }
    }
}

impl TransferKnobs {
    /// Read the knobs from a multipart initiate/resume response, defaulting
    /// when absent and clamping to the same bounds the server schema enforces
    /// (attempts 1..=100, stall 5..=300 s) so a corrupt value cannot disable
    /// stall-detection or spin unbounded retries.
    pub fn from_response(value: &serde_json::Value) -> Self {
        let default = Self::default();
        let attempts = value
            .get("part_retry_attempts")
            .and_then(serde_json::Value::as_i64)
            .map(|v| v.clamp(1, 100) as u32)
            .unwrap_or(default.attempts);
        let stall = value
            .get("stall_timeout_seconds")
            .and_then(serde_json::Value::as_i64)
            .map(|v| std::time::Duration::from_secs(v.clamp(5, 300) as u64))
            .unwrap_or(default.stall_timeout);
        // Clamped to the same bounds migration 0037's schema enforces, so a
        // corrupt value can neither unbound the send buffer nor shrink it to
        // uselessness.
        let sndbuf_bytes = value
            .get("governor")
            .and_then(|g| g.get("sndbuf_bytes"))
            .and_then(serde_json::Value::as_i64)
            .map(|v| v.clamp(256 * 1024, 8 * 1024 * 1024) as usize)
            .unwrap_or(default.sndbuf_bytes);
        Self {
            attempts,
            stall_timeout: stall,
            sndbuf_bytes,
        }
    }

    /// Project these knobs onto the bucket transport's bounds.
    ///
    /// `stall_timeout` becomes the **no-write-progress gap** — which is what the
    /// served knob always *claimed* to be ("any transferred byte resets it") and,
    /// as of bug060, finally is. Under `ureq` the value was armed as an
    /// inbound-silence read timeout that ran concurrently with transmission, so it
    /// killed healthy uploads; the same number is now applied to a genuinely
    /// rate-free quantity. No migration is needed for it: the semantics are
    /// corrected, not changed.
    pub fn transport_bounds(&self) -> bucket_transport::TransportBounds {
        bucket_transport::TransportBounds {
            write_gap: self.stall_timeout,
            sndbuf_bytes: self.sndbuf_bytes,
            // A rate-free safety constant, not a served knob — same class as
            // CONNECT_TIMEOUT. Carried on the struct so liveness tests can exercise
            // the bound without waiting out its production value.
            ..bucket_transport::TransportBounds::default()
        }
    }
}

/// Backoff before transfer attempt `attempt` (1-based): the first retry is
/// immediate (the failure is path-probabilistic, not server load — storage is
/// provably healthy), then full-jitter over ~1/2/4/8 s capped at 10 s to ride
/// out short bursts.
fn transfer_backoff(attempt: u32) -> std::time::Duration {
    if attempt <= 2 {
        return std::time::Duration::ZERO;
    }
    let cap_ms = 1000u64 * (1u64 << (attempt - 3).min(3)); // 1s, 2s, 4s, 8s…
    let cap_ms = cap_ms.min(10_000);
    std::time::Duration::from_millis(OsRng.next_u64() % cap_ms)
}

/// PUT `body` to a pre-signed bucket URL and return the storage `ETag` (needed
/// to complete a multipart upload). The pre-signed URL self-authenticates, so
/// this carries no `Signet-*` headers — it goes to the bucket, not the API.
///
/// bug047 resilience: up to `knobs.attempts` attempts, each on a fresh
/// connection with stall-detection; every retry is announced on stderr (the
/// PRSN-visible reliability signal — counts only, never phoned home). An
/// exhausted budget returns `transfer_stalled` (exit 32) — the caller keeps
/// the upload resumable rather than aborting it.
/// Widen a per-attempt transfer ceiling after a stall (G1's multiplicative increase).
///
/// Doubling, capped so a pathological retry chain cannot manufacture an effectively
/// unbounded attempt. The cap is a rate-free safety ceiling on a value that is itself
/// rate-derived, not a duration bound on a `bytes ÷ rate` quantity — the module
/// invariant is about where a *constant* originates, and this one only ever limits
/// how far an estimate may be relaxed.
fn relax_ceiling(c: std::time::Duration) -> std::time::Duration {
    const MAX_RELAXED_CEILING: std::time::Duration = std::time::Duration::from_secs(86_400);
    (c * 2).min(MAX_RELAXED_CEILING)
}

pub fn put_presigned(
    url: &str,
    body: &[u8],
    knobs: &TransferKnobs,
    ceiling: Option<std::time::Duration>,
) -> Result<String> {
    let bounds = knobs.transport_bounds();
    let mut last_error = String::new();
    // The per-attempt ceiling RELAXES as attempts are spent (Gus, S127 G1).
    //
    // The governor's ceiling is `k x bytes / measured_rate`. If the link has since
    // slowed by more than `k`, that estimate is too tight for the current reality —
    // and holding it fixed across every attempt means all of them die under the same
    // wrong bound, the part fails, and the upload aborts. `penalize_stall()` (the
    // AIMD decrease) only runs after that whole budget is spent, so within a single
    // run the estimate never got to correct itself: recovery required a manual
    // re-run, and the module doc's claim that an over-optimistic estimate
    // "self-corrects within a part or two rather than repeatedly condemning healthy
    // transfers" described behaviour the code did not have.
    //
    // Doubling per stalled attempt puts the decrease where the doc already said it
    // lived, inside the part's own budget: a 10x rate drop is absorbed in ~2 further
    // attempts instead of ~2 further invocations. It stays invariant-legal because
    // the value being widened is itself rate-derived — this scales an estimate, it
    // does not introduce a constant.
    //
    // Only `transfer_stalled` widens it. A 5xx is the store's problem, not evidence
    // that our rate estimate is wrong, so it must not buy extra time.
    let mut ceiling = ceiling;
    for attempt in 1..=knobs.attempts {
        if attempt > 1 {
            std::thread::sleep(transfer_backoff(attempt));
            // NOTE: `last_error` is built only from redacted forms — a pre-signed
            // URL's query string IS the authorization, and must never reach a
            // terminal, a scrollback buffer, or a log (bug060 §10.3).
            eprintln!(
                "signet: storage transfer attempt {attempt}/{} ({last_error}): retrying on a fresh connection",
                knobs.attempts
            );
        }
        match bucket_transport::put(url, body, &bounds, ceiling) {
            Ok(t) if t.status == 200 || t.status == 204 => {
                return t
                    .etag
                    .ok_or_else(|| network("pre-signed PUT response is missing an ETag header"));
            }
            Ok(t) if (500..600).contains(&t.status) => {
                last_error = format!("storage answered HTTP {}", t.status);
                continue;
            }
            Ok(t) => {
                // A definitive 4xx (e.g. an expired pre-signed URL) is not
                // retryable on the same URL — resume re-issues fresh ones.
                let detail = String::from_utf8_lossy(&t.body);
                let detail: String = detail.chars().take(400).collect();
                return Err(network(format!(
                    "pre-signed PUT to {} returned HTTP {}: {detail}",
                    bucket_transport::redact(url),
                    t.status
                )));
            }
            Err(e) => {
                // A stall is evidence the ceiling was too tight for the link as it
                // is NOW — relax it for the next attempt rather than re-condemning
                // a possibly-healthy transfer under the same wrong bound.
                if e.code == "transfer_stalled" {
                    ceiling = ceiling.map(relax_ceiling);
                }
                last_error = e.message.clone();
                continue;
            }
        }
    }
    Err(CliError::transfer_stalled(format!(
        "part transfer failed after {} attempts on fresh connections ({last_error}): \
         a bad network window between this host and object storage; \
         the upload is preserved: re-run the same command to resume",
        knobs.attempts
    )))
}

/// Range-GET bytes `[start, end]` (inclusive) from a pre-signed bucket URL —
/// one §4.2 chunk envelope, or a whole object. No `Signet-*` headers.
///
/// Defensive bug047 symmetry (downloads measured clean in the same bad windows
/// — exp B): fresh connection + stall-detection per attempt,
/// [`DOWNLOAD_ATTEMPTS`] budget.
pub fn get_presigned_range(url: &str, start: u64, end: u64) -> Result<Vec<u8>> {
    get_presigned_range_impl(url, start, end, None)
}

/// 1c (S175): [`get_presigned_range`] drawing from a download-scoped
/// [`bucket_transport::DownloadPool`]. ⚠ The pool is offered on the FIRST
/// attempt only — every retry in the budget opens a genuinely fresh flow
/// (stall-evicts-pool), which is what keeps bug047's per-flow re-roll intact on
/// the one path that now reuses connections.
pub fn get_presigned_range_pooled(
    pool: &bucket_transport::DownloadPool,
    url: &str,
    start: u64,
    end: u64,
) -> Result<Vec<u8>> {
    get_presigned_range_impl(url, start, end, Some(pool))
}

fn get_presigned_range_impl(
    url: &str,
    start: u64,
    end: u64,
    pool: Option<&bucket_transport::DownloadPool>,
) -> Result<Vec<u8>> {
    let bounds = TransferKnobs::default().transport_bounds();
    let mut last_error = String::new();
    for attempt in 1..=DOWNLOAD_ATTEMPTS {
        if attempt > 1 {
            std::thread::sleep(transfer_backoff(attempt));
            eprintln!(
                "signet: storage download attempt {attempt}/{DOWNLOAD_ATTEMPTS} ({last_error}): retrying on a fresh connection"
            );
        }
        // First attempt may reuse; retries bypass the pool by rule.
        let outcome = match pool.filter(|_| attempt == 1) {
            Some(p) => bucket_transport::get_range_pooled(p, url, start, end, &bounds, None),
            None => bucket_transport::get_range(url, start, end, &bounds, None),
        };
        match outcome {
            // 206 Partial Content is the expected answer to a Range GET; 200 is
            // accepted for a store that answers the whole object.
            Ok(t) if t.status == 200 || t.status == 206 => return Ok(t.body),
            Ok(t) if (500..600).contains(&t.status) => {
                last_error = format!("storage answered HTTP {}", t.status);
                continue;
            }
            // ⚠ 403 is DISTINGUISHABLE here and must stay so (S185, bug211 §7-3's
            // CLI twin). A pre-signed URL whose `X-Amz-Expires` window has lapsed
            // gets a real 403 from storage on this surface (no CORS masking — that
            // ambiguity is the WEB's problem, not ours), and the download loop in
            // `commands.rs` re-requests a fresh URL and resumes on exactly this
            // code. Classifying it as plain `network_error` is what shipped the
            // defect: a wall-clock TTL silently bounding a bytes÷rate transfer
            // (ROOTS §B-3.4; ceiling = rate × 3600 per link — ~288 GB at the
            // 80 MB/s we measured, proportionally less on the slow links that are
            // our named user class).
            //
            // No attempts are spent here on purpose: retrying a rejected
            // signature re-sends the identical dead bytes (measured on the web:
            // ten retries, one signature). The remedy is a FRESH URL, and that
            // lives one layer up where the API client is.
            Ok(t) if t.status == 403 => {
                let detail = String::from_utf8_lossy(&t.body);
                let detail: String = detail.chars().take(400).collect();
                return Err(CliError::new(
                    31,
                    "presigned_rejected",
                    format!(
                        "storage rejected the pre-signed URL (HTTP 403; likely expired): {detail}"
                    ),
                ));
            }
            Ok(t) => {
                let detail = String::from_utf8_lossy(&t.body);
                let detail: String = detail.chars().take(400).collect();
                return Err(network(format!(
                    "pre-signed GET from {} returned HTTP {}: {detail}",
                    bucket_transport::redact(url),
                    t.status
                )));
            }
            Err(e) => {
                last_error = e.message.clone();
                continue;
            }
        }
    }
    Err(network(format!(
        "pre-signed GET from storage failed after {DOWNLOAD_ATTEMPTS} attempts ({last_error})"
    )))
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;
    use crate::keystore::{Purpose, SoftwareKeystore};

    /// G1 — a stalled attempt must WIDEN the next attempt's ceiling.
    ///
    /// Holding the governor's ceiling fixed across all ten attempts meant a link that
    /// had slowed by more than `k` killed every attempt under the same too-tight
    /// bound, failed the part, and aborted the upload — the AIMD decrease only ran
    /// afterwards, so within a run the estimate never corrected itself. The
    /// governor's own module doc claimed the opposite.
    ///
    /// Ten attempts of doubling covers a 512x rate collapse, so the part's own budget
    /// absorbs any drop the link can plausibly produce.
    #[test]
    fn a_stalled_attempt_relaxes_the_next_attempts_ceiling() {
        let c = std::time::Duration::from_secs(40);

        assert_eq!(
            relax_ceiling(c),
            std::time::Duration::from_secs(80),
            "a stall must double the ceiling — the multiplicative decrease has to \
             happen INSIDE the attempt budget, which is where the governor's doc \
             says it does"
        );

        // Strictly increasing across a retry chain, and enough range to matter.
        let mut v = c;
        for _ in 0..9 {
            let next = relax_ceiling(v);
            assert!(next > v, "each stalled attempt must widen the bound");
            v = next;
        }
        assert!(
            v >= c * 512,
            "ten attempts must span a 512x rate collapse; got {v:?} from {c:?}"
        );

        // Capped, so a pathological chain cannot manufacture an unbounded attempt.
        let huge = std::time::Duration::from_secs(80_000);
        assert_eq!(relax_ceiling(huge), std::time::Duration::from_secs(86_400));
        assert_eq!(
            relax_ceiling(std::time::Duration::from_secs(86_400)),
            std::time::Duration::from_secs(86_400),
            "the cap must be a fixed point, not a value that keeps growing"
        );
    }

    /// PQR item 10 — the transport-PQ regression pin: X25519MLKEM768 MUST be the
    /// FIRST default kx group, which is exactly what the rustls
    /// `prefer-post-quantum` feature provides. If someone drops the feature from
    /// Cargo.toml, the group silently falls to last (the ClientHello key_share
    /// goes classical and X25519 wins every negotiation) with no other symptom —
    /// this test is the tripwire. Every rustls site in the CLI (the http agent,
    /// the broker mTLS ends, the Garnet agent client) uses this provider's
    /// default groups.
    #[test]
    fn default_kx_groups_are_post_quantum_first() {
        let first = rustls::crypto::aws_lc_rs::DEFAULT_KX_GROUPS
            .first()
            .expect("provider has kx groups")
            .name();
        assert_eq!(
            first,
            rustls::NamedGroup::X25519MLKEM768,
            "X25519MLKEM768 must be the first default kx group — \
             is the rustls `prefer-post-quantum` feature still enabled?"
        );
    }

    /// The CLI's signed bytes must verify under the server's Envelope §6.2 path:
    /// rebuild the canonical bytes from the emitted header values + body and verify
    /// with `verify_es256` (exactly the server's step 6), and confirm the fingerprint
    /// header equals the key's stored fingerprint (the server's attestation-lookup
    /// key). Also confirms the signature is a 64-byte raw r‖s (passes the server's
    /// length gate) and that each call re-signs with a fresh nonce (the retry-safety
    /// invariant that keeps a retried request from being a replay).
    #[test]
    fn auth_headers_verify_under_the_server_path() {
        let dir =
            std::env::temp_dir().join(format!("signet-http-auth-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ks = SoftwareKeystore::open(dir.clone()).expect("open keystore");
        let label = KeyLabel::parse("tester-ai-signing", Some(Purpose::Signing)).expect("label");
        let meta = ks.generate(&label, "ES256").expect("generate signing key");

        let method = "POST";
        let path = "/v1/files/00000000-0000-4000-8000-000000000000/multipart";
        let body = br#"{"declared_size":1048576,"chunk_count":1}"#;

        let headers = auth_headers(&ks, &label, method, path, body).expect("auth headers");
        let map: std::collections::HashMap<&str, String> =
            headers.iter().map(|(k, v)| (*k, v.clone())).collect();
        let timestamp = &map["Signet-Timestamp"];
        let nonce = &map["Signet-Nonce"];
        let fingerprint = &map["Signet-Fingerprint"];
        let signature = URL_SAFE_NO_PAD
            .decode(&map["Signet-Signature"])
            .expect("signature is base64url-no-pad");

        // The fingerprint header is the attestation-lookup key the server uses.
        assert_eq!(*fingerprint, meta.fingerprint);
        // A raw r‖s ES256 signature is 64 bytes — passes the server's length gate.
        assert_eq!(signature.len(), 64);
        // The nonce is a 32-hex (16-byte) single-use value.
        assert_eq!(nonce.len(), 32);

        // Rebuild the canonical bytes exactly as the server does, then verify.
        let canonical = signet_crypto::signing::signet_v1_canonical_bytes(
            method,
            path,
            body,
            timestamp,
            nonce,
            fingerprint,
        );
        signet_crypto::ecdsa::verify_es256(&meta.public_key, &canonical, &signature)
            .expect("CLI-signed bytes must verify under the server's verify_es256");

        // A second build re-signs with a fresh nonce.
        let again = auth_headers(&ks, &label, method, path, body).expect("auth headers 2");
        assert_ne!(&again[1].1, nonce, "each call must mint a fresh nonce");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Item 7b: when the identity holds a `signing-pq` key, `auth_headers`
    /// emits the fixed-width DUAL signature — raw ES256 r‖s (64) ‖ ML-DSA-87
    /// (4627) — both halves verifying over the identical canonical bytes, the
    /// ML-DSA half under the shared `signet:req:v1` context. (The classical
    /// test above doubles as the two-key regression: no `signing-pq` key ⇒ a
    /// 64-byte classical signature.)
    #[test]
    fn auth_headers_emit_the_dual_when_a_pq_key_exists() {
        use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa87, Signature, VerifyingKey};

        let dir =
            std::env::temp_dir().join(format!("signet-http-dual-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ks = SoftwareKeystore::open(dir.clone()).expect("open keystore");
        let label = KeyLabel::parse("tester-ai-signing", Some(Purpose::Signing)).expect("label");
        let meta = ks.generate(&label, "ES256").expect("generate signing key");
        let pq_label =
            KeyLabel::parse("tester-ai-signing-pq", Some(Purpose::SigningPq)).expect("pq label");
        let pq_meta = ks
            .generate(&pq_label, "ML-DSA-87")
            .expect("generate signing-pq key");

        let method = "GET";
        let path = "/v1/quota";
        let body = b"";

        let headers = auth_headers(&ks, &label, method, path, body).expect("auth headers");
        let map: std::collections::HashMap<&str, String> =
            headers.iter().map(|(k, v)| (*k, v.clone())).collect();
        let signature = URL_SAFE_NO_PAD
            .decode(&map["Signet-Signature"])
            .expect("signature is base64url-no-pad");

        // The dual's exact wire length (spec §8 point 1) — the server's dispatch key.
        assert_eq!(
            signature.len(),
            signet_crypto::attest::REQUEST_DUAL_SIG_LEN,
            "hybrid identity must emit the 4691-byte dual"
        );

        let canonical = signet_crypto::signing::signet_v1_canonical_bytes(
            method,
            path,
            body,
            &map["Signet-Timestamp"],
            &map["Signet-Nonce"],
            &map["Signet-Fingerprint"],
        );
        let (sig_es, sig_pq) = signature.split_at(64);

        // The ES256 half verifies over the canonical bytes (the server's leg 1).
        signet_crypto::ecdsa::verify_es256(&meta.public_key, &canonical, sig_es)
            .expect("the ES256 half must verify");

        // The ML-DSA-87 half verifies under the shared request context (leg 2)
        // — and NOT under the enrollment context (per-purpose domain separation).
        let vk_arr =
            EncodedVerifyingKey::<MlDsa87>::try_from(&pq_meta.public_key[..]).expect("vk length");
        let vk = VerifyingKey::<MlDsa87>::decode(&vk_arr);
        let sig_arr = EncodedSignature::<MlDsa87>::try_from(sig_pq).expect("sig length");
        let sig = Signature::<MlDsa87>::decode(&sig_arr).expect("sig decodes");
        assert!(
            vk.verify_with_context(&canonical, signet_crypto::attest::REQUEST_MLDSA_CTX, &sig),
            "the ML-DSA-87 half must verify under signet:req:v1"
        );
        assert!(
            !vk.verify_with_context(
                &canonical,
                signet_crypto::attest::ENROLL_POP_MLDSA_CTX,
                &sig
            ),
            "a request signature must NOT verify under the enrollment context"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// API HTTP refusals the server answered map to precise exit codes, not
    /// network_error: 401 → `authentication_failed` (10), 403 → `authorization_denied`
    /// (17), 404 → `not_found` (26), 409 → `conflict` (27). Only an unexpected 4xx or
    /// an exhausted 5xx stays `network_error` (31). The server's specific error code
    /// survives in the message.
    #[test]
    fn api_status_error_maps_server_statuses_precisely() {
        let unauth = api_status_error(401, "authentication_required".into());
        assert_eq!(unauth.exit_code, 10);
        assert_eq!(unauth.code, "authentication_failed");

        let forbidden = api_status_error(403, "sharing_capability_insufficient".into());
        assert_eq!(forbidden.exit_code, 17);
        assert_eq!(forbidden.code, "authorization_denied");
        assert!(
            forbidden
                .message
                .contains("sharing_capability_insufficient"),
            "the server's specific error code should survive in the message",
        );

        let missing = api_status_error(404, "recipient_not_found".into());
        assert_eq!(missing.exit_code, 26);
        assert_eq!(missing.code, "not_found");
        assert!(
            missing.message.contains("recipient_not_found"),
            "the server's specific error code should survive in the message",
        );

        let conflict = api_status_error(409, "version_conflict".into());
        assert_eq!(conflict.exit_code, 27);
        assert_eq!(conflict.code, "conflict");
        assert!(
            conflict.message.contains("version_conflict"),
            "the server's specific error code should survive in the message",
        );

        for code in [418u16, 500, 503] {
            let other = api_status_error(code, "boom".into());
            assert_eq!(other.exit_code, 31, "HTTP {code} should stay network_error");
            assert_eq!(other.code, "network_error");
        }
    }

    // ── bug047 transfer-resilience (fault-injection stall server) ────────────

    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A local HTTP "bucket" that STALLS the first `stall_first` connections —
    /// accepts, then never reads or answers, so the client's body write fills
    /// the socket buffers and blocks: exactly the bug047 stall signature — and
    /// answers every later connection like S3 (drain the body, 200 + ETag).
    /// Returns `(put_url, connection_counter)`; the counter proves each
    /// attempt really opened a FRESH connection (the fix's core premise).
    fn stall_server(stall_first: usize) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let seen = connections.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let n = seen.fetch_add(1, Ordering::SeqCst) + 1;
                std::thread::spawn(move || {
                    if n <= stall_first {
                        // Hold the socket open, reading nothing, long past any
                        // test timeout — the stalled-flow signature.
                        std::thread::sleep(std::time::Duration::from_secs(20));
                        drop(stream);
                        return;
                    }
                    // Healthy S3-ish handler: drain headers + body, answer.
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut content_length = 0usize;
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).unwrap_or(0) == 0 {
                            return;
                        }
                        let lower = line.trim().to_ascii_lowercase();
                        if let Some(v) = lower.strip_prefix("content-length:") {
                            content_length = v.trim().parse().unwrap_or(0);
                        }
                        if line.trim().is_empty() {
                            break;
                        }
                    }
                    let mut remaining = content_length;
                    let mut buf = [0u8; 65536];
                    while remaining > 0 {
                        let want = remaining.min(buf.len());
                        match reader.read(&mut buf[..want]) {
                            Ok(0) => break,
                            Ok(k) => remaining -= k,
                            Err(_) => return,
                        }
                    }
                    let mut stream = stream;
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nETag: \"stall-test-etag\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                });
            }
        });
        (
            format!("http://{addr}/bucket/object?part=1&sig=test"),
            connections,
        )
    }

    /// A 4 MiB body — large enough that a write to a never-draining socket
    /// fills the kernel buffers and blocks (the write-stall the timeout must
    /// catch), on any sane loopback buffer size.
    fn big_body() -> Vec<u8> {
        vec![0x5Au8; 4 * 1024 * 1024]
    }

    /// A **healthy but slow** peer: it drains the whole body (so write progress
    /// never stops), then stays silent for `quiet` before answering — exactly what
    /// a real object store does while it ingests a large part and only then
    /// responds. Counts connections so a test can prove no retry occurred.
    fn slow_server(quiet: std::time::Duration) -> (String, Arc<AtomicUsize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let seen = connections.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                seen.fetch_add(1, Ordering::SeqCst);
                std::thread::spawn(move || {
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut content_length = 0usize;
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).unwrap_or(0) == 0 {
                            return;
                        }
                        let lower = line.trim().to_ascii_lowercase();
                        if let Some(v) = lower.strip_prefix("content-length:") {
                            content_length = v.trim().parse().unwrap_or(0);
                        }
                        if line.trim().is_empty() {
                            break;
                        }
                    }
                    // Drain the body steadily — the peer is alive and accepting.
                    let mut remaining = content_length;
                    let mut buf = [0u8; 8192];
                    while remaining > 0 {
                        let want = remaining.min(buf.len());
                        match reader.read(&mut buf[..want]) {
                            Ok(0) => break,
                            Ok(k) => remaining -= k,
                            Err(_) => return,
                        }
                    }
                    // …then say nothing at all for a while. THIS is the silence
                    // that bug060's inbound-silence timer used to kill.
                    std::thread::sleep(quiet);
                    let mut stream = stream;
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nETag: \"slow-ok\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    );
                });
            }
        });
        (
            format!("http://{addr}/bucket/object?part=1&sig=test"),
            connections,
        )
    }

    /// **bug060 regression.** A healthy transfer whose peer is silent for longer
    /// than the no-progress gap must COMPLETE, on the first attempt, with no
    /// retry — because silence from a server that is busy ingesting is not a
    /// stall, and the read timer must not be armed against it.
    ///
    /// Under the pre-fix implementation this exact scenario failed: `SO_RCVTIMEO`
    /// was armed at connect and ran concurrently with the body write, so any
    /// transfer whose quiet period exceeded the timeout was aborted and retried
    /// until the budget was exhausted — regardless of part size or progress. That
    /// is what made every link below ~9 Mbps unable to upload at all.
    #[test]
    fn put_presigned_survives_a_server_silent_longer_than_the_gap() {
        // Quiet period 3x the gap: fatal before the fix, a non-event after it.
        let gap = std::time::Duration::from_secs(1);
        let (url, connections) = slow_server(std::time::Duration::from_secs(3));
        let knobs = TransferKnobs {
            attempts: 4,
            stall_timeout: gap,
            sndbuf_bytes: bucket_transport::TransportBounds::default().sndbuf_bytes,
        };

        let started = std::time::Instant::now();
        let etag = put_presigned(&url, &big_body(), &knobs, None)
            .expect("a slow-but-healthy transfer must not be treated as a stall");
        let elapsed = started.elapsed();

        assert_eq!(etag, "\"slow-ok\"");
        assert_eq!(
            connections.load(Ordering::SeqCst),
            1,
            "no retry may occur: the flow was alive the whole time"
        );
        assert!(
            elapsed >= std::time::Duration::from_secs(3),
            "the transfer must have actually waited through the silence (took {elapsed:?})"
        );
    }

    /// The core bug047 proof in miniature: two stalled connections are each
    /// aborted at ~the stall timeout (not the ~13m TCP timeout), and the third
    /// attempt — a fresh connection — succeeds. The connection counter proves
    /// per-attempt freshness.
    #[test]
    fn put_presigned_aborts_stalls_and_recovers_on_a_fresh_connection() {
        let (url, connections) = stall_server(2);
        let knobs = TransferKnobs {
            attempts: 4,
            stall_timeout: std::time::Duration::from_secs(1),
            sndbuf_bytes: bucket_transport::TransportBounds::default().sndbuf_bytes,
        };
        let started = std::time::Instant::now();
        let etag = put_presigned(&url, &big_body(), &knobs, None).expect("recovers on attempt 3");
        let elapsed = started.elapsed();

        assert_eq!(etag, "\"stall-test-etag\"");
        assert_eq!(
            connections.load(Ordering::SeqCst),
            3,
            "each attempt must open a FRESH connection (2 stalled + 1 healthy)"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(15),
            "two stalls must cost ~2x the stall timeout, not TCP-timeout minutes (took {elapsed:?})"
        );
    }

    /// A dead window (every connection stalls): the budget exhausts in bounded
    /// time and surfaces the RESUMABLE `transfer_stalled` (exit 32) — never
    /// `network_error` — so the caller preserves the upload for resume.
    #[test]
    fn put_presigned_exhaustion_is_transfer_stalled_and_bounded() {
        let (url, connections) = stall_server(usize::MAX);
        let knobs = TransferKnobs {
            attempts: 2,
            stall_timeout: std::time::Duration::from_secs(1),
            sndbuf_bytes: bucket_transport::TransportBounds::default().sndbuf_bytes,
        };
        let started = std::time::Instant::now();
        let error = put_presigned(&url, &big_body(), &knobs, None).expect_err("all attempts stall");
        let elapsed = started.elapsed();

        assert_eq!(error.code, "transfer_stalled");
        assert_eq!(error.exit_code, 32);
        assert!(
            error.message.contains("re-run the same command to resume"),
            "the error must tell the caller resume exists: {}",
            error.message
        );
        assert_eq!(
            connections.load(Ordering::SeqCst),
            2,
            "one fresh connection per attempt"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "exhaustion must be bounded by attempts x stall, not minutes (took {elapsed:?})"
        );
    }

    /// The knobs parse from an initiate/resume response, default when absent,
    /// and clamp corrupt values to the schema bounds (a poisoned response can
    /// neither disable stall-detection nor spin unbounded retries).
    #[test]
    fn transfer_knobs_parse_default_and_clamp() {
        let served = TransferKnobs::from_response(&serde_json::json!({
            "part_retry_attempts": 7, "stall_timeout_seconds": 30
        }));
        assert_eq!(served.attempts, 7);
        assert_eq!(served.stall_timeout, std::time::Duration::from_secs(30));

        let absent = TransferKnobs::from_response(&serde_json::json!({}));
        assert_eq!(absent.attempts, 10);
        assert_eq!(absent.stall_timeout, std::time::Duration::from_secs(15));

        let corrupt = TransferKnobs::from_response(&serde_json::json!({
            "part_retry_attempts": 0, "stall_timeout_seconds": 100000
        }));
        assert_eq!(corrupt.attempts, 1, "attempts clamp to >=1");
        assert_eq!(
            corrupt.stall_timeout,
            std::time::Duration::from_secs(300),
            "stall clamps to <=300s"
        );
    }
}
