// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! The agent's persistent Garnet PoP credential (Auth-Core Spec v03 §1/§7, Design Spec v05 §5.2).
//!
//! After [`crate::garnet_pickup::pickup`], the agent holds its **K4** client keypair, the issued K4
//! leaf (its mutual-TLS identity), the pinned **K2** deployment-CA anchor, and its access token(s).
//! This is the small persistent credential the harness contract names — a per-agent **workspace
//! file**, not a host mount. The broker-op client ([`crate::broker_client`]) presents it as the mTLS
//! client identity; token renewal (Phase 3, not yet built) re-mints tokens against it.
//!
//! ## Two tokens, one credential (§3)
//!
//! Pickup yields a **server-audience** token only (broker-inert until the guardian hard-confirms,
//! §5/§7). The **broker-audience** token is minted later (the first renewal after confirm) and set
//! via [`PoPCredential::set_broker_token`]. A broker op is impossible until then — exactly the §7
//! broker-inert-at-enrollment property.
//!
//! ## At-rest framing (honest — named for the pre-launch crypto-code review)
//!
//! K4 is the agent's **transport** identity, **not** an SE crypto key: Auth-Core §1 places it in the
//! agent's own writable workspace, never exported, distinct from the SE-bound sign/KEM keys the
//! broker actually operates. It is persisted **PKCS#8 at 0600** in the agent's private workspace;
//! at-rest protection is bounded by host disk encryption + file permissions (the same honest bound as
//! the `software` keystore tier). It is time-boxed (the 7-day K4 cert) and revocable (the live
//! grant, §6). The access tokens are bearer secrets and are persisted/zeroized with the same care.

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{CliError, Result};

/// The in-memory Garnet PoP credential. Secret material (the K4 key + the bearer tokens) is zeroized
/// on drop. The public material (the handle, the K4 leaf, the K2 anchor) rides along — it is the
/// agent's identity, not a secret.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PoPCredential {
    /// The PRSN handle this credential is bound to (the K4 leaf's SAN handle; the token `sub`).
    pub handle: String,
    /// The K4 client private key, PKCS#8 DER — the transport identity (§1; not an SE key).
    k4_key_pkcs8: Vec<u8>,
    /// The issued K4 client certificate (the mutual-TLS identity), DER.
    client_cert_der: Vec<u8>,
    /// The pinned K2 deployment-CA anchor, DER — the single trust root for the local channels.
    ca_anchor_der: Vec<u8>,
    /// The pinned **broker SPKI** — `base64url(SHA-256(broker K3 SubjectPublicKeyInfo))`, delivered at
    /// pickup for *this guardian's* broker (§4 launch gate). Public material (a hash of a public key);
    /// the agent→broker channel pins it so a substituted-but-K2-chained broker is rejected.
    broker_spki_pin: String,
    /// The Garnet mutual-TLS **ingress** base URL the agent renews its tokens/cert against
    /// (`<url>/v1/garnet/token`, `<url>/v1/garnet/renew-cert`; Auth-Core §7). Advertised by the
    /// server at pickup (S094), retiring the interim `--token-url` flag. Public material (a deployment
    /// address), not a secret.
    grant_status_url: String,
    /// The server-audience access token (account access). Always present after pickup.
    server_token: String,
    /// The broker-audience access token (SE ops). `None` until the guardian hard-confirms (§7).
    broker_token: Option<String>,
}

/// The on-disk form: byte fields base64 (standard), so the credential file is readable text — the
/// same shape discipline as the `software` keystore's stored key. The K4 key rides as plaintext
/// PKCS#8 base64 at 0600 (the §1 at-rest framing above).
#[derive(Serialize, Deserialize)]
struct StoredCredential {
    handle: String,
    k4_key_pkcs8_b64: String,
    client_cert_der_b64: String,
    ca_anchor_der_b64: String,
    broker_spki_pin: String,
    grant_status_url: String,
    server_token: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    broker_token: Option<String>,
}

impl PoPCredential {
    /// Construct from the pieces pickup produced (the broker-audience token is set later, §7).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        handle: impl Into<String>,
        k4_key_pkcs8: Vec<u8>,
        client_cert_der: Vec<u8>,
        ca_anchor_der: Vec<u8>,
        broker_spki_pin: impl Into<String>,
        grant_status_url: impl Into<String>,
        server_token: impl Into<String>,
    ) -> Self {
        Self {
            handle: handle.into(),
            k4_key_pkcs8,
            client_cert_der,
            ca_anchor_der,
            broker_spki_pin: broker_spki_pin.into(),
            grant_status_url: grant_status_url.into(),
            server_token: server_token.into(),
            broker_token: None,
        }
    }

    /// The pinned K2 deployment-CA anchor (DER).
    pub fn ca_anchor_der(&self) -> &[u8] {
        &self.ca_anchor_der
    }

    /// The pinned broker SPKI (base64url SHA-256 of the broker K3 SPKI, §4) — what the agent→broker
    /// channel pins to reject a substituted-but-K2-chained broker.
    pub fn broker_spki_pin(&self) -> &str {
        &self.broker_spki_pin
    }

    /// The Garnet ingress base URL the agent renews its tokens/cert against (Auth-Core §7) — the
    /// authoritative value the server advertised at pickup (S094).
    pub fn grant_status_url(&self) -> &str {
        &self.grant_status_url
    }

    /// The server-audience access token (account access).
    pub fn server_token(&self) -> &str {
        &self.server_token
    }

    /// The broker-audience access token, or `None` until the guardian hard-confirms (§7).
    pub fn broker_token(&self) -> Option<&str> {
        self.broker_token.as_deref()
    }

    /// Set the broker-audience token (minted by the first renewal after the guardian confirms, §7).
    pub fn set_broker_token(&mut self, token: impl Into<String>) {
        self.broker_token = Some(token.into());
    }

    /// Replace the server-audience token (a renewal refreshes it before it expires, §7).
    pub fn set_server_token(&mut self, token: impl Into<String>) {
        self.server_token = token.into();
    }

    /// Rotate the agent's K4 identity after a **cert renewal** (Auth-Core §4): replace the client key
    /// and cert with the freshly-issued pair — **zeroizing the old key** — and drop the broker token.
    /// A renewal changes the cert DER ⇒ the `cnf` thumbprint changes ⇒ every cert-bound token is
    /// invalidated (§4). The caller MUST re-mint its tokens against the new cert immediately after:
    /// the `server_token` left here is stale (overwritten by that re-mint, and harmless meanwhile —
    /// the server rejects an old-`cnf` token, which just prompts a renewal); the broker token is
    /// cleared outright so no SE op runs on an invalidated `cnf` until it is re-minted.
    pub fn rotate_cert(&mut self, new_key_pkcs8: Vec<u8>, new_cert_der: Vec<u8>) {
        self.k4_key_pkcs8.zeroize();
        self.k4_key_pkcs8 = new_key_pkcs8;
        self.client_cert_der = new_cert_der;
        self.broker_token = None;
    }

    /// The K4 client cert chain (a single depth-1 leaf — Garnet's PKI has no intermediates, §4) for
    /// a rustls mutual-TLS client config.
    pub fn client_cert_chain(&self) -> Vec<CertificateDer<'static>> {
        vec![CertificateDer::from(self.client_cert_der.clone())]
    }

    /// The K4 leaf's `x5t#S256` fingerprint — `base64url(SHA-256(cert DER))`. This is the value the
    /// agent reports to its guardian for the hard-confirm (§7) and the token `cnf` binding (§3); it
    /// is computed by the **same shared** [`signet_crypto::x509::cert_thumbprint_b64url`] the server
    /// records into `garnet_agent_certs` and binds into the token, so the three cannot drift.
    pub fn fingerprint(&self) -> String {
        signet_crypto::x509::cert_thumbprint_b64url(&self.client_cert_der)
    }

    /// The K4 private key for a rustls mutual-TLS client config (PKCS#8).
    pub fn client_key(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(self.k4_key_pkcs8.clone().into())
    }

    /// Persist the credential to `path` as JSON, **0600** (the workspace PoP file). Creates parent
    /// directories. Overwrites any existing credential at `path` (re-enrollment replaces it).
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| CliError::filesystem(format!("creating {}: {e}", parent.display())))?;
        }
        let stored = StoredCredential {
            handle: self.handle.clone(),
            k4_key_pkcs8_b64: STANDARD.encode(&self.k4_key_pkcs8),
            client_cert_der_b64: STANDARD.encode(&self.client_cert_der),
            ca_anchor_der_b64: STANDARD.encode(&self.ca_anchor_der),
            broker_spki_pin: self.broker_spki_pin.clone(),
            grant_status_url: self.grant_status_url.clone(),
            server_token: self.server_token.clone(),
            broker_token: self.broker_token.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&stored)
            .map_err(|e| CliError::generic(format!("serializing PoP credential: {e}")))?;
        write_secret_file(path, &bytes)
    }

    /// Load a credential persisted by [`PoPCredential::save`].
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                CliError::key_not_found(format!("no Signet Drive credential at {}", path.display()))
            }
            _ => CliError::filesystem(format!("reading {}: {e}", path.display())),
        })?;
        let stored: StoredCredential = serde_json::from_str(&text)
            .map_err(|e| CliError::filesystem(format!("parsing {}: {e}", path.display())))?;
        Ok(Self {
            handle: stored.handle,
            k4_key_pkcs8: b64(&stored.k4_key_pkcs8_b64, "k4 key")?,
            client_cert_der: b64(&stored.client_cert_der_b64, "client cert")?,
            ca_anchor_der: b64(&stored.ca_anchor_der_b64, "ca anchor")?,
            broker_spki_pin: stored.broker_spki_pin,
            grant_status_url: stored.grant_status_url,
            server_token: stored.server_token,
            broker_token: stored.broker_token,
        })
    }
}

/// A redacting [`Debug`] — the K4 key + bearer tokens are secret and never printed; only the public
/// identity (handle) + which tokens are present are shown.
impl std::fmt::Debug for PoPCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PoPCredential")
            .field("handle", &self.handle)
            .field("k4_key_pkcs8", &"<redacted>")
            .field("client_cert_der_len", &self.client_cert_der.len())
            .field("ca_anchor_der_len", &self.ca_anchor_der.len())
            .field("broker_spki_pin", &self.broker_spki_pin)
            .field("grant_status_url", &self.grant_status_url)
            .field("server_token", &"<redacted>")
            .field(
                "broker_token",
                &self.broker_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Decode a base64 (standard) field, mapping a malformed value to a clear error.
fn b64(s: &str, field: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(s)
        .map_err(|_| CliError::filesystem(format!("malformed PoP credential field '{field}'")))
}

/// Write secret bytes to a 0600 file (mirrors the keystore's at-rest file discipline).
fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)
        .map_err(|e| CliError::output_write(format!("writing {}: {e}", path.display())))?;
    set_mode(path, 0o600)
        .map_err(|e| CliError::output_write(format!("securing {}: {e}", path.display())))?;
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PoPCredential {
        // Use a real P-256 PKCS#8 key + a real issued leaf so the rustls helpers are exercised on
        // well-formed material (not arbitrary bytes).
        let (ca_scalar, _) = signet_crypto::ecdsa::generate_keypair();
        let ca =
            signet_crypto::x509::build_ca_cert(&ca_scalar, "Signet Garnet CA", &[1], 315_360_000)
                .unwrap();
        let (k4_scalar, _) = signet_crypto::ecdsa::generate_keypair();
        let csr = signet_crypto::x509::build_csr(&k4_scalar, "agent").unwrap();
        let leaf = signet_crypto::x509::issue_agent_cert(
            &csr,
            "hlin-ai",
            &ca_scalar,
            "Signet Garnet CA",
            &[2],
            604_800,
        )
        .unwrap();
        let k4_key = signet_crypto::ecdsa::p256_scalar_to_pkcs8_der(&k4_scalar).unwrap();
        PoPCredential::new(
            "hlin-ai",
            k4_key,
            leaf.der,
            ca.der,
            "broker-spki-pin-b64url",
            "https://drive.mysignet.ca:8443",
            "server.token.jws",
        )
    }

    #[test]
    fn save_load_round_trips_every_field() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("garnet/credential.json");
        let mut cred = sample();
        cred.set_broker_token("broker.token.jws");
        cred.save(&path).unwrap();

        let loaded = PoPCredential::load(&path).unwrap();
        assert_eq!(loaded.handle, "hlin-ai");
        assert_eq!(loaded.server_token(), "server.token.jws");
        assert_eq!(loaded.broker_token(), Some("broker.token.jws"));
        assert_eq!(loaded.broker_spki_pin(), "broker-spki-pin-b64url");
        assert_eq!(loaded.grant_status_url(), "https://drive.mysignet.ca:8443");
        assert_eq!(loaded.ca_anchor_der(), cred.ca_anchor_der());
        // The rustls helpers produce the same DER cert + a usable key on the loaded credential.
        assert_eq!(loaded.client_cert_chain(), cred.client_cert_chain());
        let _key = loaded.client_key(); // does not panic — well-formed PKCS#8
    }

    #[test]
    fn broker_token_absent_until_set() {
        let cred = sample();
        assert_eq!(cred.broker_token(), None);
    }

    #[test]
    fn rotate_cert_replaces_identity_and_drops_the_broker_token() {
        let mut cred = sample();
        cred.set_broker_token("broker.token.jws");
        let old_chain = cred.client_cert_chain();
        let old_fingerprint = cred.fingerprint();

        // A second freshly-issued leaf + its key (the cert-renewal result).
        let (ca_scalar, _) = signet_crypto::ecdsa::generate_keypair();
        let (k4b_scalar, _) = signet_crypto::ecdsa::generate_keypair();
        let csr = signet_crypto::x509::build_csr(&k4b_scalar, "agent").unwrap();
        let leaf2 = signet_crypto::x509::issue_agent_cert(
            &csr,
            "hlin-ai",
            &ca_scalar,
            "Signet Garnet CA",
            &[9],
            604_800,
        )
        .unwrap();
        let key2 = signet_crypto::ecdsa::p256_scalar_to_pkcs8_der(&k4b_scalar).unwrap();

        cred.rotate_cert(key2, leaf2.der.clone());

        assert_ne!(cred.client_cert_chain(), old_chain, "the cert is replaced");
        assert_ne!(
            cred.fingerprint(),
            old_fingerprint,
            "the cnf thumbprint changes with the new cert"
        );
        assert_eq!(
            cred.fingerprint(),
            signet_crypto::x509::cert_thumbprint_b64url(&leaf2.der),
            "the fingerprint tracks the new cert"
        );
        assert_eq!(
            cred.broker_token(),
            None,
            "the broker token is dropped (its cnf is invalidated)"
        );
        assert_eq!(cred.handle, "hlin-ai", "the handle is unchanged");
        let _key = cred.client_key(); // the new key is well-formed PKCS#8 (does not panic)
    }

    #[test]
    fn fingerprint_is_the_shared_x5t_thumbprint() {
        let cred = sample();
        let der = cred.client_cert_chain()[0].as_ref().to_vec();
        // The agent's reported fingerprint MUST equal the shared issuer/verifier thumbprint, or the
        // hard-confirm comparison (§7) and the token `cnf` binding (§3) would silently disagree.
        assert_eq!(
            cred.fingerprint(),
            signet_crypto::x509::cert_thumbprint_b64url(&der)
        );
        // base64url-no-pad of a SHA-256 digest → 43 chars, no `=` padding.
        assert_eq!(cred.fingerprint().len(), 43);
        assert!(!cred.fingerprint().contains('='));
    }

    #[test]
    fn saved_file_is_0600() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("cred.json");
            sample().save(&path).unwrap();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn load_missing_is_a_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = PoPCredential::load(&dir.path().join("nope.json")).unwrap_err();
        assert_eq!(err.code, "key_not_found");
    }
}
