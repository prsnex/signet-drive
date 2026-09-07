// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! The broker's persistent Garnet identity (Auth-Core Spec v04 §1, Design Spec v05 §4.4/§5.2).
//!
//! The SE-broker ([`crate::broker`]) is a long-running local service; to serve it needs a stable,
//! K2-signed identity. This is the broker's side of the PKI, the mirror of the agent's
//! [`crate::garnet_credential::PoPCredential`]:
//!
//! * **K3** — the broker's mutual-TLS **server** cert (EKU=serverAuth) + key, presented to agents on
//!   the local channel ([`crate::broker_tls::broker_server_config`]).
//! * **K_bc** — the broker's mutual-TLS **client** cert (EKU=clientAuth) + key, presented to the
//!   server's grant-status endpoint ([`crate::garnet_grant_status_client::HttpGrantStatusClient`]).
//! * **K2 anchor** — the pinned deployment-CA anchor (verifies agents' K4 certs and pins the server).
//! * **K1 verify key** — the server's token-signing public half (the broker verifies tokens locally).
//! * **grant-status URL** — where the broker confirms the live grant per-op (§6).
//!
//! Provisioning (how this file is produced — the server issues the broker's K3/K_bc under K2) is a
//! separate step; this module is what the **`signet broker serve`** entry loads to run.
//!
//! ## At-rest framing (honest — named for the pre-launch crypto-code review)
//!
//! K3 and K_bc are the broker's **transport** identity, **not** SE crypto keys — the PRSN sign/KEM
//! keys the broker operates never leave the Secure Enclave (the broker holds none of them).
//!
//! **K3** (the broker's durable, agent-SPKI-pinned server identity) has two homes, by key tier
//! ([`BrokerK3KeyHome`]): on the production Apple-Silicon Mac its private key is generated **in the
//! Secure Enclave** and never leaves it (this file holds only the Keychain label); on the software
//! tier (dev / CI / non-macOS) it is **PKCS#8 at 0600**. The SE home is v1 defense-in-depth (S094):
//! it makes the #226 SPKI-pin hardware-rooted and keeps the broker's durable identity
//! non-extractable — the raw home's bound is disk-encryption + 0600.
//!
//! **K_bc** (the broker's grant-status *client* cert — generic, K2-chain-verified, not pinned) stays
//! **PKCS#8 at 0600**: it is lower-value and unpinned, so the SE home is not warranted (S094 Q2).
//! Both are time-boxed (the cert validity) and the channel is loopback-only — the same honest bound
//! as [`PoPCredential`](crate::garnet_credential::PoPCredential)'s K4 key.

use std::path::Path;
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::broker_transport_key::BrokerK3KeyHome;
use crate::error::{CliError, Result};
use crate::garnet_grant_status_client::HttpGrantStatusClient;

/// The in-memory broker identity. Secret material (the K3 + K_bc private keys) is zeroized on drop;
/// the public material (the certs, the K2 anchor, the K1 verify key, the URL) is the broker's
/// identity, not a secret.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct BrokerCredential {
    /// The per-install broker id (the K3/K_bc SAN — `urn:signet:broker:<id>` / `urn:signet:server:<id>`).
    pub broker_id: String,
    /// The K3 server certificate (the agent-facing mutual-TLS identity), DER.
    k3_cert_der: Vec<u8>,
    /// The K3 server private-key home — raw PKCS#8 (software tier) or an SE Keychain label
    /// (production Mac; the private scalar never leaves the enclave).
    k3_key: BrokerK3KeyHome,
    /// The K_bc client certificate (the grant-status mutual-TLS identity), DER.
    kbc_cert_der: Vec<u8>,
    /// The K_bc client private key, PKCS#8 DER (secret).
    kbc_key_pkcs8: Vec<u8>,
    /// The pinned K2 deployment-CA anchor, DER — verifies agent K4 certs and pins the server.
    ca_anchor_der: Vec<u8>,
    /// The server's K1 token-signing **public** half — the broker verifies access tokens locally.
    k1_verify: Vec<u8>,
    /// The server's grant-status endpoint base URL (where the broker confirms the live grant, §6).
    grant_status_url: String,
}

/// The on-disk form: byte fields base64 (standard), so the credential file is readable text — the
/// same shape discipline as [`PoPCredential`](crate::garnet_credential::PoPCredential).
#[derive(Serialize, Deserialize)]
struct StoredBrokerCredential {
    broker_id: String,
    k3_cert_der_b64: String,
    /// The K3 private-key home — a raw PKCS#8 blob (software tier) or an SE Keychain label
    /// (production Mac). Tagged so the on-disk form is self-describing.
    k3_key: StoredK3KeyHome,
    kbc_cert_der_b64: String,
    kbc_key_pkcs8_b64: String,
    ca_anchor_der_b64: String,
    k1_verify_b64: String,
    grant_status_url: String,
}

/// The on-disk K3 key home (tagged) — the raw path carries the PKCS#8 bytes; the SE path carries
/// only the Keychain label (the private scalar lives in the enclave, never in this file).
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum StoredK3KeyHome {
    RawPkcs8 { pkcs8_b64: String },
    SecureEnclave { label: String },
}

impl BrokerCredential {
    /// Construct from the pieces provisioning produced (K3 cert + its key home, K_bc, the K2
    /// anchor, the K1 verify key).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        broker_id: impl Into<String>,
        k3_cert_der: Vec<u8>,
        k3_key: BrokerK3KeyHome,
        kbc_cert_der: Vec<u8>,
        kbc_key_pkcs8: Vec<u8>,
        ca_anchor_der: Vec<u8>,
        k1_verify: Vec<u8>,
        grant_status_url: impl Into<String>,
    ) -> Self {
        Self {
            broker_id: broker_id.into(),
            k3_cert_der,
            k3_key,
            kbc_cert_der,
            kbc_key_pkcs8,
            ca_anchor_der,
            k1_verify,
            grant_status_url: grant_status_url.into(),
        }
    }

    /// The server's K1 token-verifying public key (the broker verifies access tokens with it).
    pub fn k1_verify(&self) -> &[u8] {
        &self.k1_verify
    }

    /// The K3 private-key home (raw PKCS#8 or an SE Keychain label). Read-only — used by the
    /// post-provision stale-key sweep (bug087 fix 0b), which is macOS-only (the software tier
    /// holds its key in the credential file, nothing to sweep), so this accessor is too.
    #[cfg(target_os = "macos")]
    pub(crate) fn k3_key_home(&self) -> &BrokerK3KeyHome {
        &self.k3_key
    }

    /// The grant-status listener URL this broker confirms the live grant against (Auth-Core §6) —
    /// the authoritative value the server advertised at provision.
    pub fn grant_status_url(&self) -> &str {
        &self.grant_status_url
    }

    /// **The serve-start K3 binding self-check (bug087 fix 3): prove the key this credential
    /// names is the key its certificate carries — BEFORE serving.** Finding a key is exactly
    /// what the bug087 broken state did successfully (with the *wrong* key, signing every TLS
    /// CertificateVerify into `bad signature`); the check must therefore prove *this key
    /// matches this cert*:
    ///
    /// * **SE home:** sign a probe with the labeled SE key ([`crate::keystore::broker_se_sign`]
    ///   — the same seam the TLS signer uses) and verify it against the certificate's public
    ///   key. Also catches a missing key (`key_not_found`) and a locked session (`se_locked`).
    /// * **Raw home:** derive the PKCS#8 key's public half and require byte-equality with the
    ///   certificate's (deterministic — no probe needed).
    ///
    /// A failure means serving is IMPOSSIBLE (every handshake would die), so callers refuse to
    /// serve and surface the state loudly (log + menu-bar) instead of silently accepting
    /// connections they will fail — re-provisioning is the recovery.
    pub fn verify_k3_binding(&self) -> Result<()> {
        let cert_pub = signet_crypto::x509::cert_pubkey_x963(&self.k3_cert_der)
            .map_err(|e| CliError::invalid_data(format!("broker K3 cert public key: {e}")))?;
        match &self.k3_key {
            BrokerK3KeyHome::RawPkcs8(pkcs8) => {
                let key_pub = signet_crypto::ecdsa::p256_pkcs8_public_x963(pkcs8)
                    .map_err(|e| CliError::invalid_data(format!("broker K3 key: {e}")))?;
                if key_pub == cert_pub {
                    Ok(())
                } else {
                    Err(k3_binding_mismatch(&self.broker_id))
                }
            }
            #[cfg(target_os = "macos")]
            BrokerK3KeyHome::SecureEnclave { label } => {
                const PROBE: &[u8] = b"signet-garnet-broker-k3-binding-self-check-v1";
                let raw = crate::keystore::broker_se_sign(label, PROBE)?;
                signet_crypto::ecdsa::verify_es256(&cert_pub, PROBE, &raw)
                    .map_err(|_| k3_binding_mismatch(&self.broker_id))
            }
            #[cfg(not(target_os = "macos"))]
            BrokerK3KeyHome::SecureEnclave { .. } => Err(CliError::unsupported_platform(
                "the broker's Secure-Enclave K3 key home is macOS-only (this is a non-macOS build)",
            )),
        }
    }

    /// Build the broker's mutual-TLS **server** config (K3) — the listener presents this to agents,
    /// and it requires an agent client cert chaining to the pinned K2 (EKU=clientAuth). The K3
    /// private key comes from its home: raw PKCS#8 → rustls's built-in signer; SE label → a custom
    /// signer that signs each handshake in the Secure Enclave (the scalar never leaves it).
    pub fn broker_server_config(&self) -> Result<Arc<ServerConfig>> {
        let chain = vec![CertificateDer::from(self.k3_cert_der.clone())];
        let cfg = match &self.k3_key {
            BrokerK3KeyHome::RawPkcs8(pkcs8) => crate::broker_tls::broker_server_config(
                self.ca_anchor_der.clone(),
                chain,
                PrivateKeyDer::Pkcs8(pkcs8.clone().into()),
            )
            .map_err(|e| {
                CliError::new(
                    70,
                    "internal",
                    format!("broker server config (K3, raw): {e}"),
                )
            })?,
            #[cfg(target_os = "macos")]
            BrokerK3KeyHome::SecureEnclave { label } => {
                let signing_key: Arc<dyn rustls::sign::SigningKey> = Arc::new(
                    crate::broker_transport_key::BrokerK3SigningKey::new(Arc::new(
                        crate::broker_transport_key::SeEs256Signer::new(label.clone()),
                    )),
                );
                crate::broker_tls::broker_server_config_with_signing_key(
                    self.ca_anchor_der.clone(),
                    chain,
                    signing_key,
                )
                .map_err(|e| {
                    CliError::new(
                        70,
                        "internal",
                        format!("broker server config (K3, SE): {e}"),
                    )
                })?
            }
            #[cfg(not(target_os = "macos"))]
            BrokerK3KeyHome::SecureEnclave { .. } => {
                return Err(CliError::unsupported_platform(
                    "the broker's Secure-Enclave K3 key home is macOS-only (this is a non-macOS build)",
                ));
            }
        };
        Ok(cfg)
    }

    /// **The provision loopback self-test (bug087 fix 5): complete one pinned mutual-TLS
    /// handshake against the local broker at `addr`, proving it is serving THIS credential.**
    /// The verifier pins the served leaf to this credential's K3 SPKI, and TLS 1.3 forces the
    /// server to produce a valid CertificateVerify — the bug087 orphan-key state fails exactly
    /// there (`bad signature`), which is what `signet broker provision`'s old "success" message
    /// never checked. The client identity is this credential's own **K_bc** (K2-chained
    /// clientAuth — the broker's verifier accepts the chain; no agent credential is needed, and
    /// the probe is dropped after the handshake without ever sending a frame). Handshake
    /// completion IS the proof.
    pub fn verify_serving(&self, addr: std::net::SocketAddr) -> Result<()> {
        use rustls::pki_types::ServerName;
        let pin = signet_crypto::x509::cert_spki_sha256_b64url(&self.k3_cert_der)
            .map_err(|e| CliError::invalid_data(format!("broker K3 cert: {e}")))?;
        let config = crate::broker_tls::broker_pinned_client_config(
            self.ca_anchor_der.clone(),
            vec![CertificateDer::from(self.kbc_cert_der.clone())],
            PrivateKeyDer::Pkcs8(self.kbc_key_pkcs8.clone().into()),
            pin,
        )
        .map_err(|e| CliError::new(70, "internal", format!("self-test mTLS config: {e}")))?;
        let mut sock =
            std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(2))
                .map_err(|e| {
                    CliError::new(
                        69,
                        "broker_unreachable",
                        format!("self-test: could not reach the broker at {addr}: {e}"),
                    )
                })?;
        sock.set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .ok();
        sock.set_write_timeout(Some(std::time::Duration::from_secs(3)))
            .ok();
        // The broker's K3 SAN is a URN, not a DNS name; the pin+K2 verifier ignores SNI.
        let server_name = ServerName::try_from("broker.local")
            .map_err(|_| CliError::new(70, "internal", "invalid broker server name"))?;
        let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)
            .map_err(|e| CliError::new(70, "internal", format!("self-test TLS init: {e}")))?;
        if conn.complete_io(&mut sock).is_err() || conn.is_handshaking() {
            return Err(CliError::new(
                69,
                "broker_unreachable",
                "self-test: the mutual-TLS handshake against the just-provisioned broker failed",
            ));
        }
        Ok(())
    }

    /// Build the broker's grant-status client (K_bc) — presents K_bc to the server's grant-status
    /// endpoint and pins the server to K2 (EKU=serverAuth).
    pub fn grant_status_client(&self) -> Result<HttpGrantStatusClient> {
        HttpGrantStatusClient::new(
            self.grant_status_url.clone(),
            self.ca_anchor_der.clone(),
            vec![CertificateDer::from(self.kbc_cert_der.clone())],
            PrivateKeyDer::Pkcs8(self.kbc_key_pkcs8.clone().into()),
        )
    }

    /// Persist the credential to `path` as JSON, **0600** (the broker's workspace identity file).
    /// Creates parent directories. Overwrites any existing credential at `path` (re-provisioning
    /// replaces it).
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| CliError::filesystem(format!("creating {}: {e}", parent.display())))?;
        }
        let k3_key = match &self.k3_key {
            BrokerK3KeyHome::RawPkcs8(pkcs8) => StoredK3KeyHome::RawPkcs8 {
                pkcs8_b64: STANDARD.encode(pkcs8),
            },
            BrokerK3KeyHome::SecureEnclave { label } => StoredK3KeyHome::SecureEnclave {
                label: label.clone(),
            },
        };
        let stored = StoredBrokerCredential {
            broker_id: self.broker_id.clone(),
            k3_cert_der_b64: STANDARD.encode(&self.k3_cert_der),
            k3_key,
            kbc_cert_der_b64: STANDARD.encode(&self.kbc_cert_der),
            kbc_key_pkcs8_b64: STANDARD.encode(&self.kbc_key_pkcs8),
            ca_anchor_der_b64: STANDARD.encode(&self.ca_anchor_der),
            k1_verify_b64: STANDARD.encode(&self.k1_verify),
            grant_status_url: self.grant_status_url.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&stored)
            .map_err(|e| CliError::generic(format!("serializing broker credential: {e}")))?;
        write_secret_file(path, &bytes)
    }

    /// Load a credential persisted by [`BrokerCredential::save`].
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                CliError::key_not_found(format!("no broker credential at {}", path.display()))
            }
            _ => CliError::filesystem(format!("reading {}: {e}", path.display())),
        })?;
        let stored: StoredBrokerCredential = serde_json::from_str(&text)
            .map_err(|e| CliError::filesystem(format!("parsing {}: {e}", path.display())))?;
        let k3_key = match stored.k3_key {
            StoredK3KeyHome::RawPkcs8 { pkcs8_b64 } => {
                BrokerK3KeyHome::RawPkcs8(b64(&pkcs8_b64, "k3 key")?)
            }
            StoredK3KeyHome::SecureEnclave { label } => BrokerK3KeyHome::SecureEnclave { label },
        };
        Ok(Self {
            broker_id: stored.broker_id,
            k3_cert_der: b64(&stored.k3_cert_der_b64, "k3 cert")?,
            k3_key,
            kbc_cert_der: b64(&stored.kbc_cert_der_b64, "kbc cert")?,
            kbc_key_pkcs8: b64(&stored.kbc_key_pkcs8_b64, "kbc key")?,
            ca_anchor_der: b64(&stored.ca_anchor_der_b64, "ca anchor")?,
            k1_verify: b64(&stored.k1_verify_b64, "k1 verify key")?,
            grant_status_url: stored.grant_status_url,
        })
    }
}

/// The K3 binding-mismatch error — the bug087 signature (a key that is not the cert's key
/// would sign every TLS CertificateVerify into `bad signature`). One home for the message so
/// both key-home paths say the same actionable thing.
fn k3_binding_mismatch(broker_id: &str) -> CliError {
    CliError::invalid_data(format!(
        "the broker's K3 key does not match its certificate (broker {broker_id}): serving is \
         impossible (every mutual-TLS handshake would fail with a bad signature). Re-provision \
         this broker: mint a setup code from the guardian's Signet Drive account page and run \
         `signet broker provision <CODE>`."
    ))
}

/// A redacting [`Debug`] — the K3 + K_bc private keys are secret and never printed; only the public
/// identity (broker id, the grant-status URL, field sizes) is shown.
impl std::fmt::Debug for BrokerCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokerCredential")
            .field("broker_id", &self.broker_id)
            .field("k3_cert_der_len", &self.k3_cert_der.len())
            .field("k3_key", &self.k3_key)
            .field("kbc_cert_der_len", &self.kbc_cert_der.len())
            .field("kbc_key_pkcs8", &"<redacted>")
            .field("ca_anchor_der_len", &self.ca_anchor_der.len())
            .field("k1_verify_len", &self.k1_verify.len())
            .field("grant_status_url", &self.grant_status_url)
            .finish()
    }
}

/// Decode a base64 (standard) field, mapping a malformed value to a clear error.
fn b64(s: &str, field: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(s)
        .map_err(|_| CliError::filesystem(format!("malformed broker credential field '{field}'")))
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

    /// A real K2 CA + a K3 server leaf + a K_bc client leaf under it, plus a K1 keypair's public
    /// half — well-formed material so the rustls helpers are exercised on real certs, not arbitrary
    /// bytes (mirrors `PoPCredential`'s `sample`).
    fn sample() -> BrokerCredential {
        let (ca_scalar, _) = signet_crypto::ecdsa::generate_keypair();
        let ca_anchor =
            signet_crypto::x509::build_ca_cert(&ca_scalar, "Signet Garnet CA", &[1], 315_360_000)
                .unwrap()
                .der;

        let (k3_scalar, k3_pub) = signet_crypto::ecdsa::generate_keypair();
        let k3 = signet_crypto::x509::build_server_leaf(
            &k3_pub,
            "mac-test",
            &ca_scalar,
            "Signet Garnet CA",
            &[2],
            31_536_000,
        )
        .unwrap()
        .der;
        let k3_key = signet_crypto::ecdsa::p256_scalar_to_pkcs8_der(&k3_scalar).unwrap();

        let (kbc_scalar, _) = signet_crypto::ecdsa::generate_keypair();
        let kbc_csr = signet_crypto::x509::build_csr(&kbc_scalar, "broker").unwrap();
        let kbc = signet_crypto::x509::issue_broker_client_cert(
            &kbc_csr,
            "mac-test",
            &ca_scalar,
            "Signet Garnet CA",
            &[3],
            604_800,
        )
        .unwrap()
        .der;
        let kbc_key = signet_crypto::ecdsa::p256_scalar_to_pkcs8_der(&kbc_scalar).unwrap();

        let (_k1_scalar, k1_pub) = signet_crypto::ecdsa::generate_keypair();

        BrokerCredential::new(
            "mac-test",
            k3,
            BrokerK3KeyHome::RawPkcs8(k3_key),
            kbc,
            kbc_key,
            ca_anchor,
            k1_pub.to_vec(),
            "https://127.0.0.1:9443",
        )
    }

    #[test]
    fn save_load_round_trips_every_field() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("garnet/broker.json");
        let cred = sample();
        cred.save(&path).unwrap();

        let loaded = BrokerCredential::load(&path).unwrap();
        assert_eq!(loaded.broker_id, "mac-test");
        assert_eq!(loaded.grant_status_url, "https://127.0.0.1:9443");
        assert_eq!(loaded.k1_verify(), cred.k1_verify());
        // The loaded credential builds both rustls configs on the round-tripped certs/keys.
        assert!(loaded.broker_server_config().is_ok());
        assert!(loaded.grant_status_client().is_ok());
    }

    #[test]
    fn builds_both_mtls_configs() {
        let cred = sample();
        // K3 (server) config: the listener's identity + the K2 client-cert verifier.
        assert!(cred.broker_server_config().is_ok());
        // K_bc (client) config: the grant-status client pinning the server to K2.
        assert!(cred.grant_status_client().is_ok());
    }

    #[test]
    fn saved_file_is_0600() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("broker.json");
            sample().save(&path).unwrap();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn load_missing_is_a_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = BrokerCredential::load(&dir.path().join("nope.json")).unwrap_err();
        assert_eq!(err.code, "key_not_found");
    }

    #[test]
    fn debug_redacts_private_keys() {
        let dbg = format!("{:?}", sample());
        assert!(dbg.contains("<redacted>"));
        assert!(dbg.contains("mac-test"));
        // The raw PKCS#8 key bytes must not leak into Debug (the key home redacts them).
        assert!(!dbg.contains("k3_key_pkcs8"));
    }

    /// The SE key home carries **only a Keychain label** on disk — no private key bytes — and the
    /// label survives the round-trip. (The SE-backed `broker_server_config` itself needs real
    /// hardware; here we prove the credential shape, which is CI-safe.)
    #[test]
    fn se_key_home_round_trips_label_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broker.json");
        let raw = sample();
        // Rebuild the sample with an SE K3 home (same public material, no K3 key bytes).
        let cred = BrokerCredential::new(
            raw.broker_id.clone(),
            raw.k3_cert_der.clone(),
            BrokerK3KeyHome::SecureEnclave {
                label: crate::broker_transport_key::BROKER_K3_SE_LABEL.to_string(),
            },
            raw.kbc_cert_der.clone(),
            raw.kbc_key_pkcs8.clone(),
            raw.ca_anchor_der.clone(),
            raw.k1_verify().to_vec(),
            "https://drive.mysignet.ca:8443",
        );
        cred.save(&path).unwrap();

        // The on-disk JSON carries the label, tagged `secure_enclave`, and no K3 key bytes.
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("secure_enclave"));
        assert!(text.contains(crate::broker_transport_key::BROKER_K3_SE_LABEL));
        assert!(!text.contains("k3_key_pkcs8"));

        let loaded = BrokerCredential::load(&path).unwrap();
        match &loaded.k3_key {
            BrokerK3KeyHome::SecureEnclave { label } => {
                assert_eq!(label, crate::broker_transport_key::BROKER_K3_SE_LABEL)
            }
            other => panic!("expected an SE key home, got {other:?}"),
        }
        // K_bc (the client grant-status identity) still round-trips.
        assert!(loaded.grant_status_client().is_ok());
    }
}
