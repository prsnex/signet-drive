// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! `signet broker provision` — the broker's client half of Garnet provisioning
//! (Step-1 Inc.2b; Design Spec v05 §4.4/§4.6, Auth-Core Spec v04 §1/§4). The mirror of
//! the agent's [`crate::garnet_pickup`], for the broker's **K3** (serverAuth) + **K_bc**
//! (clientAuth) certs rather than the agent's K4.
//!
//! The SE-broker ([`crate::broker`]) needs a stable, K2-signed identity before it can
//! serve. This command produces it, driving the merged 2a server endpoint
//! ([`signet_server::garnet::broker::provision`]):
//!
//! 1. Generate the broker's **K3** keypair (its agent-facing serverAuth identity) — the
//!    public half goes to the server as an X9.63 point; a server leaf is issued from it
//!    *without* a CSR PoP (a cert is useless without the key — consistent with
//!    `build_server_leaf` and the §4 server-cert path). The private half never leaves.
//! 2. Generate the broker's **K_bc** keypair (its grant-status clientAuth identity) and
//!    build a PKCS#10 **CSR** — CSR-based (proof-of-possession). The server uses the CSR
//!    as a public-key carrier + PoP only; the SAN (`urn:signet:broker:<id>`) is built
//!    server-side from the server-generated `broker_id` (the keystone discipline, §4).
//! 3. `POST /v1/garnet/broker/provision` with `{ provision_code, k3_pubkey, kbc_csr }`.
//!    The endpoint is **provision-code-gated, unauthenticated** — the guardian mints the
//!    code from their authenticated session (`POST .../provision-code`) and hands it to
//!    the install, exactly as the pairing code is handed to an enrolling agent.
//! 4. Receive `{ broker_id, k3_cert, kbc_cert, ca_cert, k1_verify }`, pair the issued
//!    certs with the locally-held keys, and write the [`BrokerCredential`] that
//!    [`signet broker serve`](crate::broker::serve_from_credential) loads.
//!
//! **`grant_status_url` is not in the bundle** — the server cannot authoritatively name
//! the grant-status listener's address until that listener is wired (a later Step-1
//! increment, Inc 3); until then 2b takes it as a required CLI flag and writes it into
//! the credential.
//!
//! Provision MUST be reached at the deployment origin under standard public-web-PKI
//! server-cert validation (the K2 anchor it delivers cannot validate its own delivery —
//! the same trust bootstrap as pickup, §5); that is [`crate::http`]'s standard TLS, with
//! no certificate-verification override here.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Serialize;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::broker_credential::BrokerCredential;
use crate::broker_transport_key::BrokerK3KeyHome;
#[cfg(target_os = "macos")]
use crate::broker_transport_key::broker_k3_generation_label;
use crate::error::{CliError, Result};
use crate::http;
use crate::keystore::Tier;
use crate::output::OutputMode;

/// The machine-readable result on stdout (progress goes to stderr) — the broker's
/// server-assigned id, where the credential was written, and the grant-status URL the server
/// advertised (baked into the credential). Private key material is never surfaced (it lives,
/// 0600 or SE-resident, inside the credential file).
#[derive(Serialize)]
struct ProvisionResult {
    broker_id: String,
    credential_path: String,
    grant_status_url: String,
}

/// `signet broker provision <CODE> --credential <path>`.
///
/// Runs the provisioning flow against `base_url` (the deployment origin — config
/// `server_base_url` / `SIGNET_SERVER_URL`) with the one-time `provision_code` the
/// guardian minted, writes the resulting [`BrokerCredential`] to `credential_path`, and
/// reports. The grant-status URL is the **authoritative one the server advertises** in the
/// provision bundle (`SIGNET_GARNET_GRANT_STATUS_URL`) — no longer a CLI flag (S094).
pub fn run(
    base_url: &str,
    provision_code: &str,
    credential_path: &std::path::Path,
    out: &OutputMode,
) -> Result<()> {
    let base = base_url.trim_end_matches('/');
    progress(&format!("provisioning the broker against {base}…"));

    let cred = provision(base, provision_code)?;
    cred.save(credential_path)?;

    progress(&format!(
        "broker provisioned (id {}). Wrote the credential to {}.",
        cred.broker_id,
        credential_path.display()
    ));

    // The provision SUCCEEDED and the credential names its own per-generation SE key — every
    // other broker-K3 key (the legacy fixed label, orphans from failed attempts, prior
    // generations) is now unambiguously stale. Sweep them, verified, and REPORT the outcome
    // either way (bug087 fix 0b — the silent `let _ =` delete is how the orphan survived).
    sweep_stale_keys(&cred);

    // Start (or restart) the broker LaunchAgent now that its credential exists, so serving
    // begins immediately rather than at next login — mirrors the host-signer's
    // provision→kickstart. Off-macOS / not-installed → a manual-start hint.
    if crate::host_channel::kickstart_broker() {
        progress("started the broker (kickstarted its LaunchAgent).");
        // bug087 fix 5: "provisioned" is not "serving" — the pre-fix command printed success
        // over a broker that could not complete a single handshake (sub-finding (b)). Prove
        // the daemon serves THIS credential (a pinned loopback handshake) before reporting
        // success; a persistent failure FAILS the command with the honest state.
        verify_broker_serving(&cred)?;
        progress(
            "verified: the broker is serving this credential (mutual-TLS handshake completed).",
        );
    } else {
        progress(
            "start the broker with `signet broker serve` (or it starts automatically at \
             next login if the Signet app is installed).",
        );
    }
    out.print_json(&ProvisionResult {
        broker_id: cred.broker_id.clone(),
        credential_path: credential_path.display().to_string(),
        grant_status_url: cred.grant_status_url().to_string(),
    })
}

/// The bounded serving probe behind the fix-5 self-test: the kickstarted daemon needs a
/// moment to come up (launchd spawn + credential load + the K3 binding self-check), so retry
/// the pinned handshake for up to ~6 s (12 × 500 ms — a bounded wait matched to a local
/// daemon start, per the bounded-waits rule). A persistent failure is an ERROR that names the
/// true state: the credential is written and the server has registered the broker, but the
/// local daemon is NOT serving it — with where to look next.
fn verify_broker_serving(cred: &BrokerCredential) -> Result<()> {
    let addr: std::net::SocketAddr = crate::broker::DEFAULT_BROKER_BIND
        .parse()
        .map_err(|e| CliError::generic(format!("default broker bind: {e}")))?;
    const ATTEMPTS: u32 = 12;
    const PAUSE: std::time::Duration = std::time::Duration::from_millis(500);
    let mut last_err = None;
    for _ in 0..ATTEMPTS {
        match cred.verify_serving(addr) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_err = Some(e);
                std::thread::sleep(PAUSE);
            }
        }
    }
    let detail = last_err.map(|e| e.to_string()).unwrap_or_default();
    Err(CliError::new(
        69,
        "broker_not_serving",
        format!(
            "the broker was provisioned (id {}) and the credential written, but the local \
             daemon did NOT serve it within ~6 s ({detail}). The server-side registration is \
             fine; the local broker needs attention: check the menu-bar status, \
             `signet status`, and ~/Library/Logs/Signet/broker.log, then re-run \
             `signet broker provision` with a fresh code if needed.",
            cred.broker_id
        ),
    ))
}

/// Sweep stale broker-K3 SE keys after a SUCCESSFUL provision (macOS SE home only; the
/// software tier holds its key in the credential file, nothing to sweep). Loud in both
/// directions: removed generations are named, and a failed removal is a printed warning —
/// harmless to serving (the new credential's key has its own label; stale keys are inert by
/// construction), but litter worth knowing about. Never fails the provision.
fn sweep_stale_keys(cred: &BrokerCredential) {
    #[cfg(target_os = "macos")]
    {
        let BrokerK3KeyHome::SecureEnclave { label } = cred.k3_key_home() else {
            return;
        };
        match crate::keystore::sweep_stale_broker_se_keys(label) {
            Ok(sweep) => {
                if !sweep.removed.is_empty() {
                    progress(&format!(
                        "removed {} stale broker key generation(s): {}",
                        sweep.removed.len(),
                        sweep.removed.join(", ")
                    ));
                }
                for (label, why) in &sweep.failed {
                    progress(&format!(
                        "⚠ stale broker key '{label}' could not be removed ({why}): harmless \
                         to serving (this credential names its own key), but worth reporting"
                    ));
                }
            }
            Err(e) => progress(&format!(
                "⚠ stale-broker-key sweep skipped ({e}): harmless to serving (this \
                 credential names its own key); re-run `signet broker provision` to retry"
            )),
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = cred;
}

/// Run the provisioning flow against `base_url` with the one-time `provision_code`,
/// returning the assembled [`BrokerCredential`] (the caller persists it). Generates the
/// K3 + K_bc keypairs locally (the private halves never leave), drives the provision
/// endpoint, and pairs the issued certs with those keys + the server-advertised grant-status URL.
pub fn provision(base_url: &str, provision_code: &str) -> Result<BrokerCredential> {
    let base = base_url.trim_end_matches('/');

    // (1) K3 (serverAuth): generate the key in its tier-appropriate home. The public half (X9.63)
    //     is sent for `build_server_leaf` — no CSR, the server issues from the bare pubkey (§4). On
    //     the production Apple-Silicon Mac the private key is generated **in the Secure Enclave** and
    //     never leaves it (the credential holds only the Keychain label); on the software tier it is
    //     a raw in-memory PKCS#8 key.
    let (k3_pubkey, k3_key) = generate_k3_key()?;

    // (2) K_bc (clientAuth): a CSR (public-key carrier + PoP; the subject is ignored
    //     server-side — the SAN is built from the server-generated broker_id, §4).
    let (kbc_scalar, _public) = signet_crypto::ecdsa::generate_keypair();
    let kbc_scalar = Zeroizing::new(kbc_scalar);
    let kbc_csr_der = signet_crypto::x509::build_csr(&kbc_scalar, "broker")
        .map_err(|e| CliError::generic(format!("building the K_bc CSR: {e}")))?;
    let kbc_key_pkcs8 = signet_crypto::ecdsa::p256_scalar_to_pkcs8_der(&kbc_scalar)
        .map_err(|e| CliError::generic(format!("encoding the K_bc key: {e}")))?;

    // (3) POST the code + the K3 public key + the K_bc CSR.
    let body = build_provision_body(provision_code, &k3_pubkey, &kbc_csr_der)?;
    let resp = http::post_json(&format!("{base}/v1/garnet/broker/provision"), Some(&body))?;

    // (4) Take the authoritative grant-status URL from the bundle (the server names its own
    //     listener — S094), then assemble the credential from the bundle + the locally-held keys.
    let grant_status_url = json_str(&resp, "grant_status_url")?;
    assemble_credential(&resp, k3_key, kbc_key_pkcs8, &grant_status_url)
}

/// Generate the broker's **K3** signing key in its tier-appropriate home, returning its X9.63
/// public key (sent to the server for `build_server_leaf` cert issuance) + the [`BrokerK3KeyHome`]
/// to persist. On the production Apple-Silicon Mac (`secure_enclave` tier) the key is generated
/// **in the Secure Enclave** — the scalar never leaves it and the credential holds only the
/// Keychain label; on the `software` tier (dev / CI / non-macOS) it is a raw in-memory PKCS#8 key.
fn generate_k3_key() -> Result<(Vec<u8>, BrokerK3KeyHome)> {
    match crate::keystore::detect_tier() {
        Tier::SecureEnclave => {
            #[cfg(target_os = "macos")]
            {
                // A fresh PER-GENERATION label (bug087 fix 0): the credential names this
                // exact key, so an orphan from a failed attempt (the server validates the
                // code only after this keygen) can never shadow a live key. Stale
                // generations are swept after a provision SUCCEEDS (`run` below).
                let label = broker_k3_generation_label();
                let pubkey = crate::keystore::generate_broker_se_key(&label)?;
                Ok((pubkey, BrokerK3KeyHome::SecureEnclave { label }))
            }
            #[cfg(not(target_os = "macos"))]
            {
                Err(CliError::unsupported_platform(
                    "the broker's Secure-Enclave K3 key is macOS-only; off a Mac set \
                     SIGNET_KEY_TIER=software",
                ))
            }
        }
        Tier::Software => {
            let (k3_scalar, k3_pubkey) = signet_crypto::ecdsa::generate_keypair();
            let k3_scalar = Zeroizing::new(k3_scalar);
            let k3_key_pkcs8 = signet_crypto::ecdsa::p256_scalar_to_pkcs8_der(&k3_scalar)
                .map_err(|e| CliError::generic(format!("encoding the K3 key: {e}")))?;
            Ok((k3_pubkey, BrokerK3KeyHome::RawPkcs8(k3_key_pkcs8)))
        }
    }
}

/// Build the provision request body `{ provision_code, k3_pubkey, kbc_csr }` — the K3
/// public key as base64-standard X9.63 and the K_bc CSR as base64-standard DER, the
/// shape [`signet_server::garnet::broker::ProvisionRequest`] decodes. Pure — unit-tested
/// for the wire shape.
fn build_provision_body(
    provision_code: &str,
    k3_pubkey: &[u8],
    kbc_csr_der: &[u8],
) -> Result<Vec<u8>> {
    let body = serde_json::json!({
        "provision_code": provision_code,
        "k3_pubkey": STANDARD.encode(k3_pubkey),
        "kbc_csr": STANDARD.encode(kbc_csr_der),
    });
    serde_json::to_vec(&body)
        .map_err(|e| CliError::generic(format!("serializing the provision body: {e}")))
}

/// Assemble a [`BrokerCredential`] from the provision response bundle `{ broker_id,
/// k3_cert, kbc_cert, ca_cert, k1_verify }` and the locally-generated K3 + K_bc keys.
/// Decodes the bundle's PEM certs to DER (we persist/use the DER) and the X9.63 K1
/// verify key from base64-standard; pairs each issued cert with its matching private
/// key. The `broker_id` is the server-authoritative value (it IS the certs' SAN).
///
/// This is the client-side assembly seam (the half of provisioning that does not touch
/// the network) — exposed so the runnable end-to-end proof can assemble a credential from
/// a server-issued bundle without a live HTTP round-trip.
pub fn assemble_credential(
    resp: &Value,
    k3_key: BrokerK3KeyHome,
    kbc_key_pkcs8: Vec<u8>,
    grant_status_url: &str,
) -> Result<BrokerCredential> {
    let broker_id = json_str(resp, "broker_id")?;
    let k3_cert_der = pem_field_to_der(resp, "k3_cert")?;
    let kbc_cert_der = pem_field_to_der(resp, "kbc_cert")?;
    let ca_anchor_der = pem_field_to_der(resp, "ca_cert")?;

    let k1_verify = STANDARD
        .decode(json_str(resp, "k1_verify")?.trim())
        .map_err(|_| {
            CliError::invalid_data("provision returned a malformed k1_verify (not base64)")
        })?;

    Ok(BrokerCredential::new(
        broker_id,
        k3_cert_der,
        k3_key,
        kbc_cert_der,
        kbc_key_pkcs8,
        ca_anchor_der,
        k1_verify,
        grant_status_url,
    ))
}

/// Extract a required PEM string field from the response and decode it to DER.
fn pem_field_to_der(resp: &Value, key: &str) -> Result<Vec<u8>> {
    let pem = json_str(resp, key)?;
    signet_crypto::x509::pem_to_der(&pem)
        .map_err(|e| CliError::invalid_data(format!("provision returned a malformed {key}: {e}")))
}

/// Extract a required string field from the provision response.
fn json_str(value: &Value, key: &str) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(String::from)
        .ok_or_else(|| {
            CliError::invalid_data(format!("provision response missing string field '{key}'"))
        })
}

fn progress(message: &str) {
    eprintln!("signet broker provision: {message}");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The request body carries the code and base64-standard-encodes the K3 public key
    /// (a 65-byte X9.63 point) + the K_bc CSR DER, exactly as the server decodes them.
    #[test]
    fn provision_body_carries_code_pubkey_and_csr() {
        let (_k3_scalar, k3_pubkey) = signet_crypto::ecdsa::generate_keypair();
        let (kbc_scalar, _) = signet_crypto::ecdsa::generate_keypair();
        let csr = signet_crypto::x509::build_csr(&kbc_scalar, "broker").unwrap();

        let bytes = build_provision_body("PROV-CODE-123", &k3_pubkey, &csr).unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(v["provision_code"], "PROV-CODE-123");
        // k3_pubkey decodes back to the original 65-byte uncompressed point.
        let decoded_pubkey = STANDARD.decode(v["k3_pubkey"].as_str().unwrap()).unwrap();
        assert_eq!(decoded_pubkey, k3_pubkey);
        assert_eq!(decoded_pubkey.len(), 65);
        // kbc_csr decodes back to the original CSR DER.
        assert_eq!(
            STANDARD.decode(v["kbc_csr"].as_str().unwrap()).unwrap(),
            csr
        );
    }

    /// `assemble_credential` parses a realistic provision response (real K2-signed certs,
    /// built by the SAME `signet_crypto::x509` functions the server's issuer uses) and
    /// pairs them with the locally-generated keys, producing a credential that round-trips
    /// through save/load AND builds both rustls configs — i.e. exactly what `signet broker
    /// serve` does. This proves the server-issuance ↔ cli-assembly seam against the real
    /// cert producer, with no live HTTP server (that two-process run is Inc 3+).
    #[test]
    fn assemble_credential_pairs_certs_and_builds_configs() {
        // A K2 deployment CA.
        let (ca_scalar, _) = signet_crypto::ecdsa::generate_keypair();
        let ca =
            signet_crypto::x509::build_ca_cert(&ca_scalar, "Test Garnet CA", &[1], 315_360_000)
                .unwrap();

        // K3 (serverAuth) issued from the broker's public key — `build_server_leaf`, the
        // exact call the provision endpoint makes; the scalar becomes the local PKCS#8.
        let (k3_scalar, k3_pub) = signet_crypto::ecdsa::generate_keypair();
        let k3 = signet_crypto::x509::build_server_leaf(
            &k3_pub,
            "test-broker-id",
            &ca_scalar,
            "Test Garnet CA",
            &[2],
            31_536_000,
        )
        .unwrap();
        let k3_key_pkcs8 = signet_crypto::ecdsa::p256_scalar_to_pkcs8_der(&k3_scalar).unwrap();

        // K_bc (clientAuth) issued from the broker's CSR — `issue_broker_client_cert`, the
        // exact call the endpoint makes.
        let (kbc_scalar, _) = signet_crypto::ecdsa::generate_keypair();
        let kbc_csr = signet_crypto::x509::build_csr(&kbc_scalar, "broker").unwrap();
        let kbc = signet_crypto::x509::issue_broker_client_cert(
            &kbc_csr,
            "test-broker-id",
            &ca_scalar,
            "Test Garnet CA",
            &[3],
            604_800,
        )
        .unwrap();
        let kbc_key_pkcs8 = signet_crypto::ecdsa::p256_scalar_to_pkcs8_der(&kbc_scalar).unwrap();

        // K1 verify key, base64-standard X9.63 — as the server encodes it.
        let (_k1_scalar, k1_pub) = signet_crypto::ecdsa::generate_keypair();

        // The bundle the server returns: PEM certs + the base64 K1 key.
        let resp = serde_json::json!({
            "broker_id": "test-broker-id",
            "k3_cert": k3.pem,
            "kbc_cert": kbc.pem,
            "ca_cert": ca.pem,
            "k1_verify": STANDARD.encode(&k1_pub),
        });

        let cred = assemble_credential(
            &resp,
            BrokerK3KeyHome::RawPkcs8(k3_key_pkcs8),
            kbc_key_pkcs8,
            "https://127.0.0.1:9443",
        )
        .unwrap();

        assert_eq!(cred.broker_id, "test-broker-id");
        assert_eq!(cred.k1_verify(), k1_pub.as_slice());

        // Round-trip through the on-disk form, then build both rustls configs from the
        // loaded credential — the precise thing `serve_from_credential` requires.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("garnet/broker.json");
        cred.save(&path).unwrap();
        let loaded = BrokerCredential::load(&path).unwrap();
        assert_eq!(loaded.broker_id, "test-broker-id");
        assert!(
            loaded.broker_server_config().is_ok(),
            "the K3 cert must pair with the local K3 key (server config)"
        );
        assert!(
            loaded.grant_status_client().is_ok(),
            "the K_bc cert must pair with the local K_bc key (grant-status client)"
        );
    }

    /// A response missing a required field is a clear, typed error (not a panic).
    #[test]
    fn assemble_rejects_a_missing_field() {
        let resp = serde_json::json!({ "broker_id": "x" }); // no certs / k1_verify
        let err = assemble_credential(
            &resp,
            BrokerK3KeyHome::RawPkcs8(vec![1, 2, 3]),
            vec![4, 5, 6],
            "https://x",
        )
        .unwrap_err();
        assert_eq!(err.code, "invalid_data");
    }

    /// A response whose cert field is not valid PEM is a clear, typed error.
    #[test]
    fn assemble_rejects_malformed_pem() {
        let resp = serde_json::json!({
            "broker_id": "x",
            "k3_cert": "not a pem",
            "kbc_cert": "not a pem",
            "ca_cert": "not a pem",
            "k1_verify": STANDARD.encode([0u8; 65]),
        });
        let err = assemble_credential(
            &resp,
            BrokerK3KeyHome::RawPkcs8(vec![1]),
            vec![2],
            "https://x",
        )
        .unwrap_err();
        assert_eq!(err.code, "invalid_data");
    }
}
