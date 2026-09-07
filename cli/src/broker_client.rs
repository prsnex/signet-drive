// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! The agent's **broker-op client** — the client end of the Garnet SE-broker channel (Auth-Core Spec
//! v03 §7, Design Spec v05 §4.4/§5.2). The counterpart to [`crate::broker`] (the listener): an
//! enrolled agent reaches its local broker to have a Secure-Enclave op performed.
//!
//! Per op the agent: opens a **mutual-TLS** connection presenting its **K4** client cert (from the
//! [`PoPCredential`]); authenticates the broker's **K3** server cert by **chain-to-K2 / serverAuth
//! and the pinned broker SPKI** (the shared [`crate::broker_tls::broker_pinned_client_config`]); then
//! sends one [`BrokerRequest`] — its **broker-audience** token + the [`Op`] — and reads the
//! [`Response`] ([`crate::broker_wire`], one op per connection, #3).
//!
//! ## Server-cert trust — the broker SPKI pin (Auth-Core §4, the Phase-6 launch gate)
//!
//! The broker's K3 is authenticated here by **chain-to-K2 + serverAuth + a pin on the broker's
//! SPKI** — the §4 least-authority rule: the agent pins *its* broker's public key (delivered in the
//! pickup response and held in the [`PoPCredential`]), not merely "any cert K2 signed." A K3 *cert*
//! rotation on a stable key keeps the pin (no lock-out); a K3 *key* rotation is a guardian-visible
//! re-trust event, not a silent widening within the K2 namespace. This closes the gap that mattered
//! under a compromised server (K1+K2): such an attacker can mint a valid K2-chained serverAuth cert
//! for a substituted local broker, which chain-to-K2-alone would have accepted; the pin rejects it.

use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection};
use signet_channel::wire::{Op, Response};

use crate::broker_wire::{self, BrokerRequest};
use crate::error::{CliError, Result};
use crate::garnet_credential::PoPCredential;

/// Per-op connect/read/write timeout — a broker op is one small frame + one SE call; a stalled broker
/// must surface promptly rather than hang the agent.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// The agent's client for its local Garnet SE-broker. Holds the broker's loopback endpoint and a
/// reusable mutual-TLS [`ClientConfig`] presenting the agent's K4 identity + pinning the server to K2.
pub struct BrokerClient {
    endpoint: SocketAddr,
    config: Arc<ClientConfig>,
}

impl BrokerClient {
    /// Build the client from the agent's [`PoPCredential`] and its local broker `endpoint`
    /// (loopback). The mutual-TLS config presents K4 (the credential's cert + key) and pins the
    /// broker's server cert to the credential's K2 anchor (serverAuth) **and** to the broker's pinned
    /// SPKI (§4 — pin *this* broker, not any K2-chained serverAuth cert).
    pub fn new(endpoint: SocketAddr, credential: &PoPCredential) -> Result<Self> {
        let config = crate::broker_tls::broker_pinned_client_config(
            credential.ca_anchor_der().to_vec(),
            credential.client_cert_chain(),
            credential.client_key(),
            credential.broker_spki_pin().to_string(),
        )
        .map_err(|e| CliError::new(70, "internal", format!("broker-client mTLS config: {e}")))?;
        Ok(Self {
            endpoint,
            config: Arc::new(config),
        })
    }

    /// Perform one SE `op` against the broker, presenting `broker_token` (the agent's
    /// `signet-broker`-audience access token). Returns the broker's [`Response`] — `Ok(Response::Ok)`
    /// for a served op, `Ok(Response::Err)` for the broker's own refusal (e.g. `access_paused` when the
    /// grant is not live). An `Err` here is a **transport** failure: the broker is unreachable, the
    /// mutual-TLS handshake failed (a bad/expired K4, a non-K2 server), or the framed exchange broke.
    pub fn perform(&self, broker_token: &str, op: Op) -> Result<Response> {
        let mut sock = TcpStream::connect(self.endpoint).map_err(|e| {
            CliError::new(
                69,
                "broker_unreachable",
                format!(
                    "could not reach the Signet broker at {}: {e}",
                    self.endpoint
                ),
            )
        })?;
        sock.set_read_timeout(Some(IO_TIMEOUT)).ok();
        sock.set_write_timeout(Some(IO_TIMEOUT)).ok();

        // The broker's K3 SAN is a `urn:signet:*` URI, not a DNS name; the K2 server-cert verifier
        // ignores `server_name` (it authenticates by the K2 chain). A fixed placeholder satisfies
        // rustls; SNI is irrelevant (the broker presents a single cert).
        let server_name = ServerName::try_from("broker.local")
            .map_err(|_| CliError::new(70, "internal", "invalid broker server name"))?;
        let mut conn = ClientConnection::new(Arc::clone(&self.config), server_name)
            .map_err(|e| CliError::new(70, "internal", format!("broker-client TLS init: {e}")))?;

        match conn.complete_io(&mut sock) {
            // The PIN-MISMATCH case, surfaced distinctly (bug090): the broker completed a
            // K2-chained handshake but presented an SPKI other than the one this credential
            // pins — the signature of a RE-PROVISIONED broker (a rotated K3), which orphans
            // every existing agent pin. The keystore recovers it with ONE signed re-pickup
            // (v09 re-issue — loud, audited); every other failure stays the generic
            // `broker_unreachable` and is NEVER auto-recovered (a down broker, a rejected
            // agent cert, and the bug087 wrong-key state must not trigger credential churn).
            Err(e) if is_pin_mismatch(&e) => {
                return Err(CliError::new(
                    69,
                    "broker_pin_mismatch",
                    "the local broker presented an identity that does not match this \
                     credential's pinned broker key; the broker may have been re-provisioned \
                     (its identity rotates on re-provision)",
                ));
            }
            Err(_) => {
                return Err(broker_unreachable());
            }
            Ok(_) if conn.is_handshaking() => {
                return Err(broker_unreachable());
            }
            Ok(_) => {}
        }

        let mut tls = rustls::Stream::new(&mut conn, &mut sock);
        let request = BrokerRequest {
            token: broker_token.to_string(),
            op,
        };
        broker_wire::write_frame(&mut tls, &request).map_err(|e| {
            CliError::new(
                69,
                "broker_unreachable",
                format!("sending the broker request: {e}"),
            )
        })?;
        broker_wire::read_frame(&mut tls).map_err(|e| {
            CliError::new(
                69,
                "broker_unreachable",
                format!("reading the broker response: {e}"),
            )
        })
    }
}

/// The generic transport failure — a down broker, a rejected agent cert, a broken handshake
/// of any non-pin kind. Deliberately cause-agnostic (fail-closed, no probing detail).
fn broker_unreachable() -> CliError {
    CliError::new(
        69,
        "broker_unreachable",
        "the Signet broker mutual-TLS handshake failed (broker down, or a rejected/expired \
         credential)",
    )
}

/// Whether a handshake IO error is the verifier's **SPKI pin mismatch** — surfaced by
/// [`crate::broker_tls`]'s server-cert verifier as `ApplicationVerificationFailure`, which it
/// uses for NOTHING else (chain failures are `UnknownIssuer`, malformed leaves `BadEncoding`).
/// Detected by downcast, never by string-matching, so a rustls message change cannot silently
/// break the bug090 recovery trigger.
fn is_pin_mismatch(e: &std::io::Error) -> bool {
    e.get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        .is_some_and(|re| {
            matches!(
                re,
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure
                )
            )
        })
}

#[cfg(test)]
mod tests {
    //! A real agent↔broker round-trip over mutual-TLS: stand up the actual [`crate::broker`] listener
    //! (software keystore, a live grant stub) with a **K2-signed** K3 server cert, and drive it through
    //! the real [`BrokerClient`] using a real [`PoPCredential`]. Proves the client's transport +
    //! cert/token presentation against the production listener (the cross-crate full chain — pickup →
    //! confirm → revoke — is `server/tests/garnet_full_chain.rs`).

    use super::*;
    use crate::broker::{self, GrantStatusClient};
    use crate::garnet_revocation::{GrantStatusOutcome, LeaseConfig};
    use crate::keystore::{KeyLabel, Keystore, SoftwareKeystore};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use signet_channel::wire::{OpErr, OpOk};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, Ordering};
    use uuid::Uuid;

    /// A grant-status stub returning a fixed outcome (no network — the broker's §6 wiring is proven in
    /// the broker module; here we only need a *live* answer so the op serves).
    struct Stub(GrantStatusOutcome);
    impl GrantStatusClient for Stub {
        fn query(&self, _g: Uuid, _h: &str, _c: &str) -> GrantStatusOutcome {
            self.0
        }
    }

    fn unix_now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// Mint a `signet-broker`-audience token for `handle`/`cnf`, signed by `k1_scalar`.
    fn broker_token(
        k1_scalar: &[u8; 32],
        k1_kid: Uuid,
        handle: &str,
        cnf: &str,
        grant: Uuid,
    ) -> String {
        use base64::Engine;
        let si = signet_crypto::garnet_token::encode_signing_input(
            k1_kid,
            signet_crypto::garnet_token::Audience::Broker,
            handle,
            cnf,
            grant,
            900,
            unix_now(),
        )
        .unwrap();
        let sig = signet_crypto::ecdsa::sign_es256(k1_scalar, si.as_bytes()).unwrap();
        format!(
            "{si}.{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig)
        )
    }

    #[test]
    fn round_trips_a_live_se_op_against_the_real_broker() {
        let handle = "wire-ai";

        // K2 deployment CA.
        let (k2_scalar, _) = signet_crypto::ecdsa::generate_keypair();
        let k2 =
            signet_crypto::x509::build_ca_cert(&k2_scalar, "Signet Garnet CA", &[1], 315_360_000)
                .unwrap();

        // K1 token-signing key.
        let (k1_scalar, k1_pub) = signet_crypto::ecdsa::generate_keypair();
        let k1_kid = Uuid::new_v4();

        // The broker's K3 server cert — **K2-signed**, serverAuth (production shape; the agent verifies
        // chain-to-K2 + the broker SPKI pin, §4).
        let (k3_scalar, k3_pub) = signet_crypto::ecdsa::generate_keypair();
        let k3 = signet_crypto::x509::build_server_leaf(
            &k3_pub,
            "mac-broker-1",
            &k2_scalar,
            "Signet Garnet CA",
            &[7],
            31_536_000,
        )
        .unwrap();
        let k3_key = signet_crypto::ecdsa::p256_scalar_to_pkcs8_der(&k3_scalar).unwrap();
        let server_config = crate::broker_tls::broker_server_config(
            k2.der.clone(),
            vec![CertificateDer::from(k3.der.clone())],
            PrivateKeyDer::Pkcs8(k3_key.into()),
        )
        .unwrap();

        // The agent's K4 cert + key (K2-signed clientAuth) → its PoP credential.
        let (k4_scalar, _) = signet_crypto::ecdsa::generate_keypair();
        let csr = signet_crypto::x509::build_csr(&k4_scalar, "agent").unwrap();
        let k4 = signet_crypto::x509::issue_agent_cert(
            &csr,
            handle,
            &k2_scalar,
            "Signet Garnet CA",
            &[9],
            604_800,
        )
        .unwrap();
        let k4_key = signet_crypto::ecdsa::p256_scalar_to_pkcs8_der(&k4_scalar).unwrap();
        // The credential pins the broker's K3 SPKI (§4) — it must match the live broker's K3 cert or
        // the handshake fails. (The wrong-pin rejection is exercised in `wrong_broker_pin_is_rejected`.)
        let k3_pin = signet_crypto::x509::cert_spki_sha256_b64url(&k3.der).unwrap();
        let mut cred = PoPCredential::new(
            handle,
            k4_key,
            k4.der.clone(),
            k2.der.clone(),
            k3_pin,
            "https://localhost:8443",
            "server.tok",
        );
        let grant = Uuid::new_v4();
        cred.set_broker_token(broker_token(
            &k1_scalar,
            k1_kid,
            handle,
            &k4.thumbprint_b64url,
            grant,
        ));

        // The broker: software keystore, a *live* grant stub, lease=0 so every op re-confirms.
        let dir = tempfile::tempdir().unwrap();
        let ks = SoftwareKeystore::open(dir.path().to_path_buf()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = AtomicBool::new(false);
        let grant_status: Arc<dyn GrantStatusClient> =
            Arc::new(Stub(GrantStatusOutcome::live(unix_now())));
        let lease = LeaseConfig {
            lease: Duration::from_secs(0),
            outage_grace: Duration::from_secs(90),
            token_skew: Duration::from_secs(30),
        };

        std::thread::scope(|s| {
            s.spawn(|| {
                broker::serve_on(
                    listener,
                    server_config,
                    k1_pub.clone(),
                    grant_status,
                    lease,
                    &ks,
                    &shutdown,
                )
                .unwrap();
            });

            let client = BrokerClient::new(addr, &cred).unwrap();
            let token = cred.broker_token().unwrap().to_string();

            // A live grant → the keygen serves (the agent's own handle's key).
            let resp = client
                .perform(
                    &token,
                    Op::Keygen {
                        label: format!("{handle}-signing"),
                        algorithm: "ES256".into(),
                    },
                )
                .unwrap();
            match resp {
                Response::Ok(OpOk::Keygen { public_key, .. }) => assert_eq!(public_key.len(), 65),
                other => panic!("a live grant should serve the keygen, got {other:?}"),
            }

            // A cross-handle label on this connection MUST be refused (the §7 triple) — the broker
            // answers (Ok(Response::Err)), not a transport error.
            let resp2 = client
                .perform(
                    &token,
                    Op::Sign {
                        label: "someone-else-ai-signing".into(),
                        msg: b"x".to_vec(),
                    },
                )
                .unwrap();
            assert!(
                matches!(resp2, Response::Err(OpErr { ref code, .. }) if code == "authorization_denied"),
                "a cross-handle label must be refused, got {resp2:?}"
            );

            shutdown.store(true, Ordering::Relaxed);
            let _ = TcpStream::connect(addr); // nudge a worker to observe shutdown
        });

        // Sanity: the broker created exactly the agent's own key.
        let own = KeyLabel::parse(&format!("{handle}-signing"), None).unwrap();
        assert!(ks.exists(&own).unwrap());
    }

    #[test]
    fn wrong_broker_pin_is_rejected_at_the_handshake() {
        // THE GATE, end-to-end through BrokerClient (§4): a credential pinning the WRONG broker SPKI
        // cannot complete the mutual-TLS handshake against the real broker — even though the broker's
        // K3 cert is a perfectly valid K2-chained serverAuth cert. The pin, not the chain, rejects it.
        let handle = "wire-ai";
        let (k2_scalar, _) = signet_crypto::ecdsa::generate_keypair();
        let k2 =
            signet_crypto::x509::build_ca_cert(&k2_scalar, "Signet Garnet CA", &[1], 315_360_000)
                .unwrap();
        // The broker needs *a* K1 verify key to start; the handshake fails before any token is read,
        // so its value is irrelevant here.
        let (_, k1_pub) = signet_crypto::ecdsa::generate_keypair();

        // The broker's real K3 server cert (K2-signed, serverAuth).
        let (k3_scalar, k3_pub) = signet_crypto::ecdsa::generate_keypair();
        let k3 = signet_crypto::x509::build_server_leaf(
            &k3_pub,
            "mac-broker-1",
            &k2_scalar,
            "Signet Garnet CA",
            &[7],
            31_536_000,
        )
        .unwrap();
        let k3_key = signet_crypto::ecdsa::p256_scalar_to_pkcs8_der(&k3_scalar).unwrap();
        let server_config = crate::broker_tls::broker_server_config(
            k2.der.clone(),
            vec![CertificateDer::from(k3.der.clone())],
            PrivateKeyDer::Pkcs8(k3_key.into()),
        )
        .unwrap();

        // The agent's K4 cert/key, and a credential that pins a DIFFERENT (also K2-signed serverAuth)
        // cert's SPKI — i.e. the wrong broker.
        let (k4_scalar, _) = signet_crypto::ecdsa::generate_keypair();
        let csr = signet_crypto::x509::build_csr(&k4_scalar, "agent").unwrap();
        let k4 = signet_crypto::x509::issue_agent_cert(
            &csr,
            handle,
            &k2_scalar,
            "Signet Garnet CA",
            &[9],
            604_800,
        )
        .unwrap();
        let k4_key = signet_crypto::ecdsa::p256_scalar_to_pkcs8_der(&k4_scalar).unwrap();
        let (_, other_pub) = signet_crypto::ecdsa::generate_keypair();
        let other_k3 = signet_crypto::x509::build_server_leaf(
            &other_pub,
            "some-other-broker",
            &k2_scalar,
            "Signet Garnet CA",
            &[8],
            31_536_000,
        )
        .unwrap();
        let wrong_pin = signet_crypto::x509::cert_spki_sha256_b64url(&other_k3.der).unwrap();
        let cred = PoPCredential::new(
            handle,
            k4_key,
            k4.der,
            k2.der,
            wrong_pin,
            "https://localhost:8443",
            "server.tok",
        );

        let dir = tempfile::tempdir().unwrap();
        let ks = SoftwareKeystore::open(dir.path().to_path_buf()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = AtomicBool::new(false);
        let grant_status: Arc<dyn GrantStatusClient> =
            Arc::new(Stub(GrantStatusOutcome::live(unix_now())));
        let lease = LeaseConfig {
            lease: Duration::from_secs(0),
            outage_grace: Duration::from_secs(90),
            token_skew: Duration::from_secs(30),
        };

        std::thread::scope(|s| {
            s.spawn(|| {
                let _ = broker::serve_on(
                    listener,
                    server_config,
                    k1_pub.clone(),
                    grant_status,
                    lease,
                    &ks,
                    &shutdown,
                );
            });
            let client = BrokerClient::new(addr, &cred).unwrap();
            let err = client
                .perform(
                    "tok",
                    Op::Keygen {
                        label: format!("{handle}-signing"),
                        algorithm: "ES256".into(),
                    },
                )
                .unwrap_err();
            // Shut the serve thread down BEFORE asserting: `thread::scope` joins it, so a
            // failing assert that skipped this store would hang the whole suite instead of
            // failing (bug090's S147 gate caught exactly that — the assert below changed and
            // the suite wedged for an hour rather than going red).
            shutdown.store(true, Ordering::Relaxed);
            let _ = TcpStream::connect(addr); // nudge a worker to observe shutdown
            // v09 (bug090): the wrong-pin rejection surfaces as the DISTINCT
            // `broker_pin_mismatch` — still fail-closed at the handshake (the test's point:
            // the pin, not the chain, rejects it), now precisely classified so the keystore's
            // one-shot re-pickup recovery can key on it and nothing else.
            assert_eq!(
                err.code, "broker_pin_mismatch",
                "a wrong-SPKI pin must fail the handshake closed, classified as a pin \
                 mismatch (got {err:?})"
            );
        });
    }

    #[test]
    fn unreachable_broker_is_a_transport_error() {
        // A credential pointing at a closed loopback port → a broker_unreachable transport error.
        let (k2_scalar, _) = signet_crypto::ecdsa::generate_keypair();
        let k2 =
            signet_crypto::x509::build_ca_cert(&k2_scalar, "Signet Garnet CA", &[1], 315_360_000)
                .unwrap();
        let (k4_scalar, _) = signet_crypto::ecdsa::generate_keypair();
        let csr = signet_crypto::x509::build_csr(&k4_scalar, "agent").unwrap();
        let k4 = signet_crypto::x509::issue_agent_cert(
            &csr,
            "wire-ai",
            &k2_scalar,
            "Signet Garnet CA",
            &[9],
            604_800,
        )
        .unwrap();
        let k4_key = signet_crypto::ecdsa::p256_scalar_to_pkcs8_der(&k4_scalar).unwrap();
        // The broker is unreachable (port closed), so no handshake occurs and the pin is never
        // checked — a placeholder is fine here.
        let cred = PoPCredential::new(
            "wire-ai",
            k4_key,
            k4.der,
            k2.der,
            "unused-broker-pin",
            "https://localhost:8443",
            "server.tok",
        );

        // Bind then drop the listener so the port is (almost certainly) closed.
        let addr = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap()
        };
        let client = BrokerClient::new(addr, &cred).unwrap();
        let err = client
            .perform(
                "tok",
                Op::Keygen {
                    label: "wire-ai-signing".into(),
                    algorithm: "ES256".into(),
                },
            )
            .unwrap_err();
        assert_eq!(err.code, "broker_unreachable");
    }
}
