// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! The SE-broker's mutual-TLS configuration (Garnet Phase-2, Auth-Core Spec v03 §4/§5.2).
//!
//! The broker listens on the **local network** under mutual-TLS: an agent presents its K4 client
//! cert (issued by the deployment CA, K2, scoped to its handle) to open the channel, and only then
//! does the broker read a request. This module builds the rustls [`ServerConfig`] for that listener
//! (the listener loop itself is Phase-2 #3's second PR). Two pieces:
//!
//! * [`K2ClientCertVerifier`] — the rustls client-cert verifier. The **chain decision** (does the
//!   leaf chain to the pinned K2, is it valid, EKU=clientAuth) is delegated to the project's
//!   hand-rolled, ring-free [`signet_crypto::x509::verify_leaf_chains_to_ca`] — the same "pin
//!   everything, don't trust a permissive path-builder" lineage as the token verifier. The **TLS-1.3
//!   handshake proof-of-possession** (the `CertificateVerify` signature, proving the peer holds the
//!   cert's private key for *this* handshake) is delegated to the aws-lc-rs provider — standard TLS,
//!   not something to hand-roll.
//! * [`broker_server_config`] — wires the verifier into a TLS-1.3-only [`ServerConfig`] presenting
//!   the broker's own (K3) server cert.
//!
//! Garnet's PKI is **depth-1 by construction** (leaf → K2, `pathlen:0`, no intermediates), so the
//! verifier rejects any presented intermediate outright.
//!
//! Note: the broker's own K3 server identity is injected here as a parameter; its Keychain-backed
//! key home is Phase-2 #4 / enrollment work. The agent's `cnf` proof-of-possession (the token bound
//! to *this* leaf) is enforced by the per-op token check in the listener — this module only gates
//! the channel.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::WebPkiSupportedAlgorithms;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, Error, ServerConfig, SignatureScheme,
};

/// A rustls [`ClientCertVerifier`] that requires the agent's client cert to chain (depth-1) to the
/// pinned **K2** deployment CA and carry **EKU=clientAuth**. The chain decision is the project's
/// hand-rolled [`signet_crypto::x509::verify_leaf_chains_to_ca`]; the TLS-1.3 `CertificateVerify`
/// proof-of-possession is delegated to the provider's algorithms.
#[derive(Debug)]
struct K2ClientCertVerifier {
    /// The pinned K2 CA anchor (DER) — the single trust root for the local channel.
    ca_anchor_der: Vec<u8>,
    /// The provider's signature-verification algorithms, used for the handshake-sig delegation.
    supported_algs: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for K2ClientCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    /// Mutual-TLS is mandatory — the broker never serves an anonymous connection.
    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        // Depth-1 PKI (Auth-Core §4): the CA issues only leaves, so a presented intermediate is
        // never legitimate — reject before any chain work.
        if !intermediates.is_empty() {
            return Err(Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ));
        }
        // The pinned, hand-rolled chain decision: chains to K2, valid at `now`, CA:FALSE, clientAuth.
        signet_crypto::x509::verify_leaf_chains_to_ca(
            end_entity.as_ref(),
            &self.ca_anchor_der,
            signet_crypto::x509::ID_KP_CLIENT_AUTH,
            now.as_secs() as i64,
        )
        .map_err(|_| Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer))?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // TLS 1.2 is not enabled (the `ServerConfig` is TLS-1.3-only, and the `tls12` rustls feature
        // is off), so this is unreachable — fail closed if it is ever somehow invoked.
        Err(Error::General(
            "garnet broker: TLS 1.2 is not supported".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // Standard TLS-1.3 CertificateVerify proof-of-possession — delegate to the provider.
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Pin to ECDSA P-256 / SHA-256 — the only scheme Garnet's P-256 PKI uses.
        vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

/// The aws-lc-rs provider + the K2 client-cert verifier — the shared front half of both
/// broker `ServerConfig` builders (the workspace is ring-free, so the provider is explicit).
fn provider_and_verifier(
    ca_anchor_der: Vec<u8>,
) -> (
    Arc<rustls::crypto::CryptoProvider>,
    Arc<K2ClientCertVerifier>,
) {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let supported_algs = provider.signature_verification_algorithms;
    let verifier = Arc::new(K2ClientCertVerifier {
        ca_anchor_der,
        supported_algs,
    });
    (provider, verifier)
}

/// Build the broker's mutual-TLS [`ServerConfig`]: **TLS 1.3 only**, requiring an agent client cert
/// that chains (depth-1) to the pinned K2 anchor with EKU=clientAuth, and presenting the broker's
/// own (K3) server cert from an **in-memory** private key (the software tier — dev / CI / non-macOS).
///
/// `broker_cert_chain` + `broker_key` are the broker's K3 server identity; `with_single_cert` checks
/// the key matches the leaf. The production Apple-Silicon Mac home keeps K3 in the Secure Enclave —
/// see [`broker_server_config_with_signing_key`].
pub fn broker_server_config(
    ca_anchor_der: Vec<u8>,
    broker_cert_chain: Vec<CertificateDer<'static>>,
    broker_key: PrivateKeyDer<'static>,
) -> Result<Arc<ServerConfig>, Error> {
    let (provider, verifier) = provider_and_verifier(ca_anchor_der);
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_single_cert(broker_cert_chain, broker_key)?;
    Ok(Arc::new(config))
}

/// Build the broker's mutual-TLS [`ServerConfig`] presenting K3 from a **custom
/// [`SigningKey`](rustls::sign::SigningKey)** — the Secure-Enclave K3 home (Garnet Phase-6). Same
/// TLS-1.3-only, K2-pinned-client-cert channel as [`broker_server_config`], but the K3 private key
/// is never handed to rustls: the handshake signature is produced by `signing_key` (the SE in
/// production; a raw-scalar stand-in in the CI handshake test). Uses a fixed cert resolver
/// ([`SingleCertAndKey`](rustls::sign::SingleCertAndKey)) since the broker serves one identity.
pub fn broker_server_config_with_signing_key(
    ca_anchor_der: Vec<u8>,
    broker_cert_chain: Vec<CertificateDer<'static>>,
    signing_key: Arc<dyn rustls::sign::SigningKey>,
) -> Result<Arc<ServerConfig>, Error> {
    let (provider, verifier) = provider_and_verifier(ca_anchor_der);
    let certified = rustls::sign::CertifiedKey::new(broker_cert_chain, signing_key);
    let resolver = Arc::new(rustls::sign::SingleCertAndKey::from(certified));
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(resolver);
    Ok(Arc::new(config))
}

// ── The K2-pinned mutual-TLS *client* side (Auth-Core §6 / §4) ─────────────────────────────────
//
// The mirror of the server side above: a Garnet client (the broker querying grant-status, or an
// agent reaching the broker) presents its own K2-issued **client** cert and pins the *server* it
// talks to to the **same K2** with EKU=serverAuth. Shared here so the one security-critical chain
// decision lives in a single tested place — the grant-status client
// ([`crate::garnet_grant_status_client`]) and the agent's broker-op client
// ([`crate::broker_client`]) both build their `ClientConfig` from it.

/// A rustls [`ServerCertVerifier`] requiring the peer's server cert to chain (depth-1) to the pinned
/// **K2** deployment CA with EKU=**serverAuth**. The server SAN is a `urn:signet:*` URI (not a DNS
/// name), so the **`server_name` is ignored** — authentication is the K2 chain, not the hostname.
/// The chain decision is the project's hand-rolled, ring-free
/// [`signet_crypto::x509::verify_leaf_chains_to_ca_uri`]; the TLS-1.3 signature is delegated to the
/// aws-lc-rs provider.
///
/// **`pinned_broker_spki` (the §4 Phase-6 launch gate).** When `Some(pin)`, the verifier additionally
/// requires the presented leaf's **SPKI pin** ([`signet_crypto::x509::cert_spki_sha256_b64url`]) to
/// equal `pin` — pinning *this specific broker's public key*, not merely "any cert K2 signed." That
/// is the least-authority property: under a compromised server (K1+K2) an attacker can mint a valid
/// K2-chained serverAuth cert for a substituted local broker; the SPKI pin rejects it. `None` is for
/// the broker→server / agent→server channels, where the peer is the **one** deployment server and the
/// K2 chain (bootstrapped over public-web PKI at pickup) is the trust — there is no specific-peer pin.
#[derive(Debug)]
struct K2ServerCertVerifier {
    ca_anchor_der: Vec<u8>,
    /// The pinned broker SPKI (base64url of SHA-256 of the leaf's SubjectPublicKeyInfo), or `None`
    /// for a server channel (K2 chain only). Set only on the agent→broker channel.
    pinned_broker_spki: Option<String>,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for K2ServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // Depth-1 PKI (§4): the CA issues only leaves — a presented intermediate is never legitimate.
        if !intermediates.is_empty() {
            return Err(Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer,
            ));
        }
        // The pinned, hand-rolled chain decision: chains to K2, valid at `now`, CA:FALSE, serverAuth.
        signet_crypto::x509::verify_leaf_chains_to_ca_uri(
            end_entity.as_ref(),
            &self.ca_anchor_der,
            signet_crypto::x509::ID_KP_SERVER_AUTH,
            now.as_secs() as i64,
        )
        .map_err(|_| Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer))?;
        // The §4 SPKI pin (agent→broker only): a K2 chain proves "the server vouches for this cert";
        // the pin proves "this is the broker I enrolled against." Both must hold — fail closed on a
        // mismatch (a substituted-but-K2-chained broker) or a malformed leaf.
        if let Some(pin) = &self.pinned_broker_spki {
            let presented = signet_crypto::x509::cert_spki_sha256_b64url(end_entity.as_ref())
                .map_err(|_| Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
            if &presented != pin {
                return Err(Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ));
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        // TLS 1.2 is not enabled (TLS-1.3-only config); fail closed if ever invoked.
        Err(Error::General(
            "garnet client: TLS 1.2 is not supported".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ECDSA_NISTP256_SHA256]
    }
}

/// Build a Garnet mutual-TLS **client** [`ClientConfig`]: **TLS 1.3 only**, presenting the K2-issued
/// clientAuth leaf `client_cert_chain` / `client_key` (the broker's K_bc or an agent's K4) and pinning
/// the **server** to the K2 chain (serverAuth) via [`K2ServerCertVerifier`]. The aws-lc-rs provider (the
/// workspace is ring-free; the broker boundary uses aws-lc-rs, matching the listener).
///
/// This is the **server-channel** form (broker→server grant-status; agent→server token/cert renewal):
/// the peer is the one deployment server, whose K2 chain is bootstrapped over public-web PKI at pickup,
/// so there is no specific-peer SPKI pin. For the **agent→broker** channel use
/// [`broker_pinned_client_config`], which additionally pins the broker's SPKI (the §4 launch gate).
pub fn k2_pinned_client_config(
    ca_anchor_der: Vec<u8>,
    client_cert_chain: Vec<CertificateDer<'static>>,
    client_key: PrivateKeyDer<'static>,
) -> Result<ClientConfig, Error> {
    client_config(ca_anchor_der, client_cert_chain, client_key, None)
}

/// Build the **agent→broker** mutual-TLS [`ClientConfig`]: as [`k2_pinned_client_config`], but the
/// server-cert verifier *additionally* requires the broker leaf's SPKI to equal `broker_spki_pin`
/// (base64url SHA-256 of the SubjectPublicKeyInfo) — the §4 Phase-6 launch gate (pin *this* broker,
/// not any K2-chained serverAuth cert). The pin is a **required** parameter (not `Option`) so the
/// broker channel can never silently fall back to chain-to-K2-only.
pub fn broker_pinned_client_config(
    ca_anchor_der: Vec<u8>,
    client_cert_chain: Vec<CertificateDer<'static>>,
    client_key: PrivateKeyDer<'static>,
    broker_spki_pin: String,
) -> Result<ClientConfig, Error> {
    client_config(
        ca_anchor_der,
        client_cert_chain,
        client_key,
        Some(broker_spki_pin),
    )
}

/// The shared builder behind both client entry points (the one place the verifier is wired), so the
/// server-pinning and broker-SPKI-pinning forms cannot drift in their TLS-1.3 / provider / EKU setup.
fn client_config(
    ca_anchor_der: Vec<u8>,
    client_cert_chain: Vec<CertificateDer<'static>>,
    client_key: PrivateKeyDer<'static>,
    pinned_broker_spki: Option<String>,
) -> Result<ClientConfig, Error> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let supported_algs = provider.signature_verification_algorithms;
    let verifier = Arc::new(K2ServerCertVerifier {
        ca_anchor_der,
        pinned_broker_spki,
        supported_algs,
    });
    ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(client_cert_chain, client_key)
}

#[cfg(test)]
mod tests {
    //! The client-cert verifier's chain decision — the security core of the broker's mutual-TLS
    //! gate. (The full handshake + the listener live in #3's second PR; here we exercise the
    //! `verify_client_cert` path directly, which is where the pinned trust decision lives.)

    use super::*;
    use std::time::Duration;

    fn provider_algs() -> WebPkiSupportedAlgorithms {
        rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms
    }

    /// A fresh K2 CA + an agent leaf issued for `handle` under it.
    fn ca_and_leaf(handle: &str) -> (Vec<u8>, Vec<u8>) {
        let ca_scalar: [u8; 32] = {
            let (s, _) = signet_crypto::ecdsa::generate_keypair();
            s
        };
        let ca =
            signet_crypto::x509::build_ca_cert(&ca_scalar, "Signet Garnet CA", &[1], 315_360_000)
                .unwrap();
        let (agent_scalar, _) = signet_crypto::ecdsa::generate_keypair();
        let csr = signet_crypto::x509::build_csr(&agent_scalar, "agent").unwrap();
        let leaf = signet_crypto::x509::issue_agent_cert(
            &csr,
            handle,
            &ca_scalar,
            "Signet Garnet CA",
            &[2],
            604_800,
        )
        .unwrap();
        (ca.der, leaf.der)
    }

    fn verifier(ca_der: Vec<u8>) -> K2ClientCertVerifier {
        K2ClientCertVerifier {
            ca_anchor_der: ca_der,
            supported_algs: provider_algs(),
        }
    }

    fn now() -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        ))
    }

    #[test]
    fn accepts_a_valid_agent_leaf() {
        let (ca, leaf) = ca_and_leaf("hlin-ai");
        let v = verifier(ca);
        let leaf = CertificateDer::from(leaf);
        assert!(v.verify_client_cert(&leaf, &[], now()).is_ok());
    }

    #[test]
    fn rejects_a_leaf_from_a_different_ca() {
        let (_, leaf) = ca_and_leaf("hlin-ai");
        let (other_ca, _) = ca_and_leaf("someone-else-ai");
        let v = verifier(other_ca);
        let leaf = CertificateDer::from(leaf);
        assert!(v.verify_client_cert(&leaf, &[], now()).is_err());
    }

    #[test]
    fn rejects_a_presented_intermediate_chain() {
        // Depth-1 PKI: any intermediate is illegitimate, rejected before chain work.
        let (ca, leaf) = ca_and_leaf("hlin-ai");
        let v = verifier(ca);
        let leaf = CertificateDer::from(leaf);
        let bogus_intermediate = CertificateDer::from(vec![0x30, 0x00]);
        assert!(
            v.verify_client_cert(&leaf, std::slice::from_ref(&bogus_intermediate), now())
                .is_err()
        );
    }

    #[test]
    fn rejects_an_expired_leaf() {
        let (ca, leaf) = ca_and_leaf("hlin-ai");
        let v = verifier(ca);
        let leaf = CertificateDer::from(leaf);
        // Far past the 7-day validity.
        let far_future = UnixTime::since_unix_epoch(Duration::from_secs(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 30 * 24 * 3600,
        ));
        assert!(v.verify_client_cert(&leaf, &[], far_future).is_err());
    }

    // ── The K2-pinned client side: the server-cert verifier (the client end of the trust) ──────

    /// A fresh K2 CA, returning both the scalar (to issue server/client leaves) and the anchor DER.
    fn k2() -> ([u8; 32], Vec<u8>) {
        let (scalar, _) = signet_crypto::ecdsa::generate_keypair();
        let der =
            signet_crypto::x509::build_ca_cert(&scalar, "Signet Garnet CA", &[1], 315_360_000)
                .unwrap()
                .der;
        (scalar, der)
    }

    fn server_verifier(ca_der: Vec<u8>) -> K2ServerCertVerifier {
        K2ServerCertVerifier {
            ca_anchor_der: ca_der,
            pinned_broker_spki: None,
            supported_algs: provider_algs(),
        }
    }

    fn server_verifier_pinned(ca_der: Vec<u8>, pin: String) -> K2ServerCertVerifier {
        K2ServerCertVerifier {
            ca_anchor_der: ca_der,
            pinned_broker_spki: Some(pin),
            supported_algs: provider_algs(),
        }
    }

    fn server_leaf(ca_scalar: &[u8; 32]) -> Vec<u8> {
        let (_s, pubkey) = signet_crypto::ecdsa::generate_keypair();
        signet_crypto::x509::build_server_leaf(
            &pubkey,
            "drive-bhs-1",
            ca_scalar,
            "Signet Garnet CA",
            &[4],
            31_536_000,
        )
        .unwrap()
        .der
    }

    fn srv_name() -> ServerName<'static> {
        ServerName::try_from("drive.mysignet.ca").unwrap()
    }

    #[test]
    fn server_verifier_accepts_a_k2_signed_serverauth_cert() {
        let (ca_scalar, ca_der) = k2();
        let srv = server_leaf(&ca_scalar);
        let v = server_verifier(ca_der);
        assert!(
            v.verify_server_cert(&CertificateDer::from(srv), &[], &srv_name(), &[], now())
                .is_ok()
        );
    }

    #[test]
    fn server_verifier_rejects_a_cert_from_a_different_ca() {
        let (ca_scalar, _ca_der) = k2();
        let srv = server_leaf(&ca_scalar);
        let (_other, other_ca_der) = k2();
        let v = server_verifier(other_ca_der);
        assert!(
            v.verify_server_cert(&CertificateDer::from(srv), &[], &srv_name(), &[], now())
                .is_err()
        );
    }

    #[test]
    fn server_verifier_rejects_a_clientauth_cert_as_the_server() {
        // The EKU split: a broker K_bc (clientAuth) presented as the *server* must be rejected — the
        // client authenticates the server only by a serverAuth K2 leaf.
        let (ca_scalar, ca_der) = k2();
        let (s, _) = signet_crypto::ecdsa::generate_keypair();
        let csr = signet_crypto::x509::build_csr(&s, "broker").unwrap();
        let bc = signet_crypto::x509::issue_broker_client_cert(
            &csr,
            "mac-1",
            &ca_scalar,
            "Signet Garnet CA",
            &[3],
            604_800,
        )
        .unwrap()
        .der;
        let v = server_verifier(ca_der);
        assert!(
            v.verify_server_cert(&CertificateDer::from(bc), &[], &srv_name(), &[], now())
                .is_err(),
            "a clientAuth cert must not pass the serverAuth server verifier"
        );
    }

    #[test]
    fn pinned_verifier_accepts_the_pinned_broker_leaf() {
        // A K2-chained serverAuth broker leaf whose SPKI matches the pin is accepted.
        let (ca_scalar, ca_der) = k2();
        let srv = server_leaf(&ca_scalar);
        let pin = signet_crypto::x509::cert_spki_sha256_b64url(&srv).unwrap();
        let v = server_verifier_pinned(ca_der, pin);
        assert!(
            v.verify_server_cert(&CertificateDer::from(srv), &[], &srv_name(), &[], now())
                .is_ok()
        );
    }

    #[test]
    fn pinned_verifier_rejects_a_k2_chained_cert_with_a_different_spki() {
        // THE LAUNCH-GATE PROPERTY (§4): a *valid* K2-chained serverAuth cert — exactly what a
        // compromised server (K1+K2) could mint for a substituted local broker — is REJECTED when
        // its SPKI ≠ the pinned broker's. Chain-to-K2 alone would accept it; the pin is what closes
        // the least-authority gap.
        let (ca_scalar, ca_der) = k2();
        let pinned = server_leaf(&ca_scalar);
        let imposter = server_leaf(&ca_scalar); // same CA, valid serverAuth, different key → different SPKI
        let pin = signet_crypto::x509::cert_spki_sha256_b64url(&pinned).unwrap();
        let v = server_verifier_pinned(ca_der.clone(), pin);
        assert!(
            v.verify_server_cert(
                &CertificateDer::from(imposter.clone()),
                &[],
                &srv_name(),
                &[],
                now()
            )
            .is_err(),
            "a K2-chained serverAuth cert with the wrong SPKI must be rejected"
        );
        // Sanity: the SAME imposter cert passes the *unpinned* (chain-to-K2-only) verifier — proving
        // the rejection above is the pin's doing, not a chain failure.
        let unpinned = server_verifier(ca_der);
        assert!(
            unpinned
                .verify_server_cert(
                    &CertificateDer::from(imposter),
                    &[],
                    &srv_name(),
                    &[],
                    now()
                )
                .is_ok(),
            "the imposter is a valid K2-chained serverAuth cert — only the pin rejects it"
        );
    }

    #[test]
    fn k2_pinned_client_config_builds_with_a_client_leaf() {
        // Smoke: a K4-style clientAuth leaf + its key build a usable client config (the agent/broker
        // client end). The chain decisions are covered by the verifier tests above + the broker's
        // mTLS round-trip; here we prove the config assembles (key matches the leaf).
        let (ca_scalar, ca_der) = k2();
        let (scalar, _) = signet_crypto::ecdsa::generate_keypair();
        let csr = signet_crypto::x509::build_csr(&scalar, "agent").unwrap();
        let leaf = signet_crypto::x509::issue_agent_cert(
            &csr,
            "hlin-ai",
            &ca_scalar,
            "Signet Garnet CA",
            &[5],
            604_800,
        )
        .unwrap()
        .der;
        let key = signet_crypto::ecdsa::p256_scalar_to_pkcs8_der(&scalar).unwrap();
        let cfg = k2_pinned_client_config(
            ca_der,
            vec![CertificateDer::from(leaf)],
            PrivateKeyDer::Pkcs8(key.into()),
        );
        assert!(cfg.is_ok(), "the K2-pinned client config should build");
    }
}
