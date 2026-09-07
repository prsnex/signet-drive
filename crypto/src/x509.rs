// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Garnet server-as-CA X.509 primitives (Auth-Core Spec v02 §4).
//!
//! Pure X.509 over the existing RustCrypto P-256 lineage (`x509-cert` for the cert/CSR
//! DER structure; `signet_crypto::ecdsa` / `p256` for the signing primitive — no `ring`,
//! no OpenSSL in the shipped path, preserving the differential-oracle lineage). This
//! module is the cryptographic heart of the agent-credential issuance; the server-side
//! K2 key custody, the CA-cert materialization, and the pickup endpoint that drive it
//! live in the server crate (PR3b).
//!
//! ## THE ISSUANCE KEYSTONE (the single most important PKI rule, §4)
//!
//! A CSR is **attacker-controllable**. [`issue_agent_cert`] therefore treats the CSR as a
//! *public-key carrier + proof-of-possession ONLY*: it verifies the CSR self-signature
//! (the requester holds the private key) and that the key is **EC P-256**, then **discards
//! the CSR's subject and every requested extension** and constructs the entire certificate
//! server-side — the SAN is `urn:signet:prsn:<handle>` where `<handle>` is the caller's
//! argument (resolved from the *grant*, never the CSR). A CSR requesting a different
//! identity is not an error; it is ignored. Trusting the CSR's SAN would let anyone holding
//! any pairing code mint a cert for any handle (identity takeover). The build-gate test
//! `keystone_uses_grant_handle_not_csr` is the proof.

use std::str::FromStr;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::{DerSignature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
use sha2::{Digest, Sha256};
use x509_cert::builder::{Builder, CertificateBuilder, Profile, RequestBuilder};
use x509_cert::der::asn1::Ia5String;
use x509_cert::der::oid::ObjectIdentifier;
use x509_cert::der::{Decode, DecodePem, Encode, EncodePem};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::{
    BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName,
};
use x509_cert::name::Name;
use x509_cert::request::CertReq;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;

use crate::error::{CryptoError, Result};

/// `ecdsa-with-SHA256` (RFC 5758) — the only CSR/cert signature algorithm Garnet accepts.
const ECDSA_WITH_SHA256: &str = "1.2.840.10045.4.3.2";
/// `id-kp-clientAuth` (RFC 5280) — the EKU on every Garnet **client** certificate, and the EKU a
/// verifier requires on a presented client cert: the agent's K4 leaf (verified by the broker, §4 /
/// Channel 1) and the broker's grant-status **client** cert (verified by the server, #4 / Channel 2).
/// Public so callers pass it to [`verify_leaf_chains_to_ca`] / [`verify_leaf_chains_to_ca_uri`].
pub const ID_KP_CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
/// `id-kp-serverAuth` (RFC 5280) — the EKU on every Garnet **server** certificate, and the EKU a
/// verifier requires on a presented server cert: the broker's K3 server cert (verified by the agent,
/// Channel 1) and the server's grant-status **server** cert (verified by the **broker**, #4 /
/// Channel 2). The clientAuth/serverAuth split prevents client↔server (K3↔K4) role confusion (§4).
pub const ID_KP_SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";
/// The SAN URN scheme that names a PRSN by handle (the §3/§7 consistency-triple identity).
const SAN_URN_PREFIX: &str = "urn:signet:prsn:";
/// The SAN URN scheme that names a **broker** install (its K3 server cert + its K_bc grant-status
/// client cert, #4) — a namespace distinct from the PRSN space (§4: a broker is not a PRSN, so a
/// broker/server cert must never carry a `urn:signet:prsn:` SAN that the §7 triple would read as one).
const SAN_URN_BROKER_PREFIX: &str = "urn:signet:broker:";
/// The SAN URN scheme that names the **deployment server's** grant-status TLS identity (K_srv, #4).
const SAN_URN_SERVER_PREFIX: &str = "urn:signet:server:";

/// A CSR whose proof-of-possession and P-256 key type have been verified. Carries only the
/// validated public key — never the CSR's subject or requested extensions (the keystone).
#[derive(Debug)]
pub struct VerifiedCsr {
    /// The validated `SubjectPublicKeyInfo`, ready to embed in the server-constructed leaf.
    spki: SubjectPublicKeyInfoOwned,
    /// The 65-byte X9.63 uncompressed public key (for fingerprinting / diagnostics).
    pub pubkey_x963: Vec<u8>,
}

/// An issued certificate (a CA cert or an agent leaf), in the forms callers need.
pub struct IssuedCert {
    /// DER encoding — the canonical bytes (the `cnf` thumbprint preimage, the mTLS leaf).
    pub der: Vec<u8>,
    /// PEM encoding — what the pickup endpoint hands back to the agent.
    pub pem: String,
    /// The certificate serial number as lowercase hex (the revocation-list / DB key).
    pub serial_hex: String,
    /// `x5t#S256` — the base64url SHA-256 of the DER, the token `cnf` value (§3).
    pub thumbprint_b64url: String,
}

/// Verify a PKCS#10 CSR: it must be well-formed, declare `ecdsa-with-SHA256`, carry an **EC
/// P-256** public key, and bear a valid **self-signature** (proof the requester holds the
/// private key). Returns the validated public key. The CSR's subject and requested
/// extensions are deliberately NOT consulted — see the keystone.
pub fn verify_csr(csr_der: &[u8]) -> Result<VerifiedCsr> {
    let csr =
        CertReq::from_der(csr_der).map_err(|_| CryptoError::InvalidInput("garnet csr der"))?;

    // The signature algorithm is pinned from policy (like the token verifier pins `alg`):
    // only ecdsa-with-SHA256 is accepted, never selected from attacker-controlled fields.
    let want_sig_alg = ObjectIdentifier::new_unwrap(ECDSA_WITH_SHA256);
    if csr.algorithm.oid != want_sig_alg {
        return Err(CryptoError::InvalidInput("garnet csr signature algorithm"));
    }

    // Require an EC P-256 public key. `p256::PublicKey::from_public_key_der` succeeds ONLY
    // for a well-formed P-256 SPKI (right algorithm OID + curve OID + on-curve point), so it
    // is the P-256 enforcement and the point extraction in one step.
    let spki = csr.info.public_key.clone();
    let spki_der = spki
        .to_der()
        .map_err(|_| CryptoError::InvalidInput("garnet csr spki"))?;
    let public_key = p256::PublicKey::from_public_key_der(&spki_der)
        .map_err(|_| CryptoError::InvalidInput("garnet csr key not P-256"))?;
    let pubkey_x963 = public_key.to_encoded_point(false).as_bytes().to_vec();

    // Proof-of-possession: the self-signature is over DER(CertReqInfo), under the CSR's own
    // public key. ecdsa::verify_es256 hashes with SHA-256 (matching ecdsa-with-SHA256) and
    // accepts the DER signature form.
    let signed = csr
        .info
        .to_der()
        .map_err(|_| CryptoError::InvalidInput("garnet csr info"))?;
    let sig = csr
        .signature
        .as_bytes()
        .ok_or(CryptoError::InvalidInput("garnet csr signature bits"))?;
    crate::ecdsa::verify_es256(&pubkey_x963, &signed, sig)?;

    Ok(VerifiedCsr { spki, pubkey_x963 })
}

/// Build a PKCS#10 CSR (DER) for an agent — the agent side of [`issue_agent_cert`]. A
/// self-signed certification request over the agent's P-256 key; the subject CN is cosmetic
/// (the server keystone ignores it and names the cert from the grant) but a CSR requires one.
/// Used by the `signet` CLI at enrollment (Phase 3) + the pickup tests.
pub fn build_csr(scalar: &[u8; 32], subject_cn: &str) -> Result<Vec<u8>> {
    let key =
        SigningKey::from_slice(scalar).map_err(|_| CryptoError::InvalidInput("garnet csr key"))?;
    let subject = name(&format!("CN={subject_cn}"))?;
    let csr = RequestBuilder::new(subject, &key)
        .map_err(|_| CryptoError::InvalidInput("garnet csr builder"))?
        .build::<DerSignature>()
        .map_err(|_| CryptoError::InvalidInput("garnet csr sign"))?;
    csr.to_der()
        .map_err(|_| CryptoError::InvalidInput("garnet csr der"))
}

/// The shared leaf-construction core for every Garnet end-entity cert (agent K4, broker K_bc,
/// server K_srv): a `Profile::Leaf` cert (BasicConstraints CA:FALSE, KeyUsage=digitalSignature,
/// SKI/AKI) carrying a **single** URI SAN and a **single** EKU, signed by the CA key (K2). The
/// caller supplies the already-validated subject public key (a verified CSR's, or the server's
/// own), the full SAN URI, and the EKU OID — so the SAN namespace and the clientAuth/serverAuth
/// role are decided **server-side by the caller**, never selected from an attacker-controlled CSR
/// field. The keystone discipline (identity is built here, not taken from the request) holds for
/// all three leaf kinds.
fn build_leaf(
    subject_spki: SubjectPublicKeyInfoOwned,
    san_uri: &str,
    eku_oid: &str,
    ca_scalar: &[u8; 32],
    issuer_cn: &str,
    serial: &[u8],
    validity_secs: u64,
) -> Result<IssuedCert> {
    let ca_key = SigningKey::from_slice(ca_scalar)
        .map_err(|_| CryptoError::InvalidInput("garnet ca key"))?;
    let issuer = name(&format!("CN={issuer_cn}"))?;
    // The Subject CN is cosmetic (verifiers read the SAN, not the Subject) — set it to the SAN's bare
    // id (the segment after the last ':'), preserving the agent leaf's historical `CN=<handle>`.
    let subject_cn = san_uri.rsplit(':').next().unwrap_or(san_uri);
    let subject = name(&format!("CN={subject_cn}"))?;
    let serial_number =
        SerialNumber::new(serial).map_err(|_| CryptoError::InvalidInput("garnet cert serial"))?;
    let validity = Validity::from_now(Duration::from_secs(validity_secs))
        .map_err(|_| CryptoError::InvalidInput("garnet cert validity"))?;

    // Profile::Leaf adds BasicConstraints CA:FALSE + KeyUsage=digitalSignature + SKI/AKI;
    // we add the caller's URI SAN (the server-decided identity) and the caller's EKU.
    let mut builder = CertificateBuilder::new(
        Profile::Leaf {
            issuer,
            enable_key_agreement: false,
            enable_key_encipherment: false,
            include_subject_key_identifier: true,
        },
        serial_number,
        validity,
        subject,
        subject_spki,
        &ca_key,
    )
    .map_err(|_| CryptoError::InvalidInput("garnet cert builder"))?;

    builder
        .add_extension(&SubjectAltName(vec![
            GeneralName::UniformResourceIdentifier(
                Ia5String::new(san_uri).map_err(|_| CryptoError::InvalidInput("garnet san"))?,
            ),
        ]))
        .map_err(|_| CryptoError::InvalidInput("garnet san ext"))?;
    builder
        .add_extension(&ExtendedKeyUsage(vec![
            ObjectIdentifier::from_str(eku_oid)
                .map_err(|_| CryptoError::InvalidInput("garnet eku oid"))?,
        ]))
        .map_err(|_| CryptoError::InvalidInput("garnet eku ext"))?;

    let cert = builder
        .build::<DerSignature>()
        .map_err(|_| CryptoError::InvalidInput("garnet cert sign"))?;
    finish(cert)
}

/// **THE KEYSTONE.** Issue an agent leaf certificate (K4) whose identity comes ENTIRELY from
/// `handle` (the grant), taking ONLY the public key from the CSR. Verifies the CSR
/// ([`verify_csr`]: PoP + P-256) first — issuance without a verified CSR is impossible by
/// construction — then constructs the leaf server-side ([`build_leaf`]):
///   * SAN = `urn:signet:prsn:<handle>` (the grant identity; the CSR's subject is ignored),
///   * EKU = clientAuth, BasicConstraints CA:FALSE, KeyUsage = digitalSignature (Leaf profile),
///   * issuer = `issuer_cn` (the CA cert subject), signed by the CA key `ca_scalar` (K2).
///
/// `serial` is the server-chosen serial number (big-endian bytes; the server generates a
/// random one and tracks it for revocation). `validity_secs` is the leaf lifetime.
pub fn issue_agent_cert(
    csr_der: &[u8],
    handle: &str,
    ca_scalar: &[u8; 32],
    issuer_cn: &str,
    serial: &[u8],
    validity_secs: u64,
) -> Result<IssuedCert> {
    let verified = verify_csr(csr_der)?;
    build_leaf(
        verified.spki,
        &format!("{SAN_URN_PREFIX}{handle}"),
        ID_KP_CLIENT_AUTH,
        ca_scalar,
        issuer_cn,
        serial,
        validity_secs,
    )
}

/// Issue the broker's grant-status **client** certificate (K_bc, #4 / T3 option (a)). Same keystone
/// discipline as [`issue_agent_cert`]: the CSR is a verified public-key carrier + PoP only; the
/// identity is built server-side as `urn:signet:broker:<broker_id>` (a broker is **not** a PRSN, so
/// never a `urn:signet:prsn:` SAN) with EKU=**clientAuth**. K3 (the broker's server cert) is
/// serverAuth-only, so the broker needs this separate clientAuth identity to authenticate to the
/// server's grant-status mTLS (§6). The server verifies it chains to K2 with clientAuth (§4).
pub fn issue_broker_client_cert(
    csr_der: &[u8],
    broker_id: &str,
    ca_scalar: &[u8; 32],
    issuer_cn: &str,
    serial: &[u8],
    validity_secs: u64,
) -> Result<IssuedCert> {
    let verified = verify_csr(csr_der)?;
    build_leaf(
        verified.spki,
        &format!("{SAN_URN_BROKER_PREFIX}{broker_id}"),
        ID_KP_CLIENT_AUTH,
        ca_scalar,
        issuer_cn,
        serial,
        validity_secs,
    )
}

/// Build the deployment server's grant-status **server** certificate (K_srv, #4): a K2-signed leaf
/// over the server's own P-256 public key, SAN `urn:signet:server:<server_id>`, EKU=**serverAuth**.
/// The broker pins K2 and verifies the presented server cert chains to it with serverAuth (§6: "the
/// server cert chains to K2", so a same-host attacker cannot impersonate the server). The server
/// holds the matching private key for the TLS listener; only its public half is certified here, so
/// this function never sees the server's private key (only K2's, to sign). `server_pubkey_x963` is
/// the 65-byte uncompressed P-256 public key of the listener's K_srv key.
pub fn build_server_leaf(
    server_pubkey_x963: &[u8],
    server_id: &str,
    ca_scalar: &[u8; 32],
    issuer_cn: &str,
    serial: &[u8],
    validity_secs: u64,
) -> Result<IssuedCert> {
    let public_key = p256::PublicKey::from_sec1_bytes(server_pubkey_x963)
        .map_err(|_| CryptoError::InvalidInput("garnet server pubkey not P-256"))?;
    let spki_der = public_key
        .to_public_key_der()
        .map_err(|_| CryptoError::InvalidInput("garnet server spki"))?;
    let spki = SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes())
        .map_err(|_| CryptoError::InvalidInput("garnet server spki der"))?;
    build_leaf(
        spki,
        &format!("{SAN_URN_SERVER_PREFIX}{server_id}"),
        ID_KP_SERVER_AUTH,
        ca_scalar,
        issuer_cn,
        serial,
        validity_secs,
    )
}

/// Build the deployment CA certificate (K2): a **self-signed** root, `CA:TRUE` with
/// `pathLenConstraint:0` (it issues only end-entity leaves, never sub-CAs — §4) and
/// `KeyUsage = keyCertSign + cRLSign`. This is the trust anchor agents pin and the pickup
/// endpoint distributes; built once at CA init and stored (a rebuild would differ — ECDSA is
/// randomized — so it is materialized once, not regenerated per request).
///
/// `subject_cn` is the CA Common Name; it is also the issuer of every leaf, so it MUST equal
/// the `issuer_cn` passed to [`issue_agent_cert`]. `serial` / `validity_secs` are server-chosen.
///
/// **Name Constraints (spec §4) are intentionally omitted.** RFC 5280 URI name-constraints
/// apply to a URI's *host* component, but Garnet SANs are URNs (`urn:signet:prsn:<handle>`,
/// no host) — a URI constraint is not well-defined for them (ineffective, and a validator
/// hazard). The issuance keystone ([`issue_agent_cert`] builds the SAN server-side from the
/// grant) is the real, sufficient enforcement; `pathlen:0` still caps the CA to leaves.
pub fn build_ca_cert(
    ca_scalar: &[u8; 32],
    subject_cn: &str,
    serial: &[u8],
    validity_secs: u64,
) -> Result<IssuedCert> {
    let ca_key = SigningKey::from_slice(ca_scalar)
        .map_err(|_| CryptoError::InvalidInput("garnet ca key"))?;
    // Self-signed: the certificate's subject public key IS the CA signing key's public half.
    let spki_der = ca_key
        .verifying_key()
        .to_public_key_der()
        .map_err(|_| CryptoError::InvalidInput("garnet ca spki"))?;
    let spki = SubjectPublicKeyInfoOwned::from_der(spki_der.as_bytes())
        .map_err(|_| CryptoError::InvalidInput("garnet ca spki der"))?;

    let subject = name(&format!("CN={subject_cn}"))?;
    let serial_number =
        SerialNumber::new(serial).map_err(|_| CryptoError::InvalidInput("garnet ca serial"))?;
    let validity = Validity::from_now(Duration::from_secs(validity_secs))
        .map_err(|_| CryptoError::InvalidInput("garnet ca validity"))?;

    // Manual profile: self-signed (issuer == subject) with explicit BasicConstraints so we can
    // pin pathlen:0 (Profile::Root leaves the path length unconstrained).
    let mut builder = CertificateBuilder::new(
        Profile::Manual {
            issuer: Some(subject.clone()),
        },
        serial_number,
        validity,
        subject,
        spki,
        &ca_key,
    )
    .map_err(|_| CryptoError::InvalidInput("garnet ca builder"))?;

    builder
        .add_extension(&BasicConstraints {
            ca: true,
            path_len_constraint: Some(0),
        })
        .map_err(|_| CryptoError::InvalidInput("garnet ca basic constraints"))?;
    builder
        .add_extension(&KeyUsage(KeyUsages::KeyCertSign | KeyUsages::CRLSign))
        .map_err(|_| CryptoError::InvalidInput("garnet ca key usage"))?;

    let cert = builder
        .build::<DerSignature>()
        .map_err(|_| CryptoError::InvalidInput("garnet ca sign"))?;
    finish(cert)
}

/// Extract the first URI SAN from a certificate (the full URI, any namespace), or `None` if the
/// cert carries no URI SAN. Every Garnet leaf carries exactly one URI SAN ([`build_leaf`]); the
/// namespace-specific readers build on this. The broker/server grant-status cert verifiers read
/// the raw URI (their authorization is chain + EKU, not the SAN content), while [`cert_san_handle`]
/// reads the PRSN-namespace handle.
pub fn cert_san_uri(der: &[u8]) -> Result<Option<String>> {
    let cert = x509_cert::Certificate::from_der(der)
        .map_err(|_| CryptoError::InvalidInput("garnet cert der"))?;
    let Some(exts) = cert.tbs_certificate.extensions else {
        return Ok(None);
    };
    let san_oid = ObjectIdentifier::new_unwrap("2.5.29.17");
    let Some(ext) = exts.iter().find(|e| e.extn_id == san_oid) else {
        return Ok(None);
    };
    let san = SubjectAltName::from_der(ext.extn_value.as_bytes())
        .map_err(|_| CryptoError::InvalidInput("garnet san"))?;
    for gn in &san.0 {
        if let GeneralName::UniformResourceIdentifier(uri) = gn {
            return Ok(Some(uri.as_str().to_string()));
        }
    }
    Ok(None)
}

/// Extract the PRSN handle from a leaf's SAN (`urn:signet:prsn:<handle>`), or `None` if the cert
/// carries no such PRSN-namespace SAN URI. This is the §7 consistency-triple read — the broker/
/// server asserts `cert SAN handle == token.sub` (Phase 2) — and it confirms the keystone issued
/// the grant's identity, not the CSR's. A broker/server cert (another URN namespace) returns `None`.
pub fn cert_san_handle(der: &[u8]) -> Result<Option<String>> {
    Ok(cert_san_uri(der)?.and_then(|uri| uri.strip_prefix(SAN_URN_PREFIX).map(str::to_string)))
}

/// A certificate's validity window as unix seconds `(not_before, not_after)`. Read-only metadata
/// access (no verification — that stays with [`verify_garnet_leaf`]); the Bug037 auto-renew-on-use
/// heuristic reads it to decide whether the agent's K4 cert is past half its life.
pub fn cert_validity_window(der: &[u8]) -> Result<(u64, u64)> {
    let cert = x509_cert::Certificate::from_der(der)
        .map_err(|_| CryptoError::InvalidInput("certificate DER"))?;
    let v = &cert.tbs_certificate.validity;
    Ok((
        v.not_before.to_unix_duration().as_secs(),
        v.not_after.to_unix_duration().as_secs(),
    ))
}

/// Extract the broker id from a leaf's SAN (`urn:signet:broker:<broker_id>`), or `None` if the cert
/// carries no broker-namespace SAN URI (e.g. an agent's PRSN-handle cert, or a server `urn:signet:
/// server:` cert). Symmetric with [`cert_san_handle`]; used to authenticate a broker to the server
/// by its presented K_bc client leaf (the broker-self deregister route).
pub fn cert_san_broker_id(der: &[u8]) -> Result<Option<String>> {
    Ok(cert_san_uri(der)?
        .and_then(|uri| uri.strip_prefix(SAN_URN_BROKER_PREFIX).map(str::to_string)))
}

/// Verify that `leaf_der` is a valid end-entity certificate **issued by** the pinned CA `ca_der`
/// (K2) — Garnet's depth-1 PKI (leaf → K2, no intermediates), hand-verified to keep the trust
/// decision in owned, ring-free code (the same lineage as the token verifier; the project pins
/// rather than delegates to a permissive path-builder). All checks are fail-closed:
///   * the leaf's `signatureAlgorithm` is `ecdsa-with-SHA256` (pinned from policy, never selected);
///   * `leaf.issuer == ca.subject` (name chaining);
///   * the leaf signature verifies under the CA's public key (signature chaining);
///   * `now_unix` is within the leaf's validity window (certs are coarse — no skew here; the broker
///     separately checks the token `exp` against trusted time with skew, §6);
///   * the leaf is **not** a CA (`BasicConstraints CA:FALSE`, or absent for an end-entity cert);
///   * the leaf's EKU contains `required_eku` (an OID string) — pinned per channel direction:
///     [`ID_KP_CLIENT_AUTH`] when verifying a **client** cert (the broker verifying an agent, §4;
///     the server verifying the broker's grant-status client cert, #4), [`ID_KP_SERVER_AUTH`] when
///     verifying a **server** cert (an agent verifying the broker's K3; the broker verifying the
///     server's grant-status cert, #4) — which prevents client↔server (K3↔K4) role confusion.
///
/// On success returns the leaf's full SAN URI (any namespace — `urn:signet:prsn:` for an agent,
/// `urn:signet:broker:` / `urn:signet:server:` for the grant-status channel). The pinned `ca_der`
/// is trusted as the anchor and is **not** itself re-validated here (pinning the CA is the trust
/// decision). For the PRSN-handle convenience (the §7 triple identity) see [`verify_leaf_chains_to_ca`].
pub fn verify_leaf_chains_to_ca_uri(
    leaf_der: &[u8],
    ca_der: &[u8],
    required_eku: &str,
    now_unix: i64,
) -> Result<String> {
    let leaf = x509_cert::Certificate::from_der(leaf_der)
        .map_err(|_| CryptoError::InvalidInput("garnet leaf der"))?;
    let ca = x509_cert::Certificate::from_der(ca_der)
        .map_err(|_| CryptoError::InvalidInput("garnet ca der"))?;

    // Pin the signature algorithm from policy — never select it from the (attacker-presentable) cert.
    let want_sig_alg = ObjectIdentifier::new_unwrap(ECDSA_WITH_SHA256);
    if leaf.signature_algorithm.oid != want_sig_alg {
        return Err(CryptoError::InvalidInput("garnet leaf signature algorithm"));
    }

    // Name chaining: the leaf's issuer must be the pinned CA's subject.
    if leaf.tbs_certificate.issuer != ca.tbs_certificate.subject {
        return Err(CryptoError::InvalidInput("garnet leaf issuer mismatch"));
    }

    // Signature chaining: the leaf signature is over DER(TBSCertificate), under the CA's key.
    let ca_spki_der = ca
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| CryptoError::InvalidInput("garnet ca spki"))?;
    let ca_pubkey = p256::PublicKey::from_public_key_der(&ca_spki_der)
        .map_err(|_| CryptoError::InvalidInput("garnet ca key not P-256"))?
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let tbs = leaf
        .tbs_certificate
        .to_der()
        .map_err(|_| CryptoError::InvalidInput("garnet leaf tbs"))?;
    let sig = leaf
        .signature
        .as_bytes()
        .ok_or(CryptoError::InvalidInput("garnet leaf signature bits"))?;
    crate::ecdsa::verify_es256(&ca_pubkey, &tbs, sig)?; // CryptoError::SignatureInvalid on mismatch

    // Validity window. Certs carry no clock skew (the token's exp check owns the skew tolerance).
    let not_before = leaf
        .tbs_certificate
        .validity
        .not_before
        .to_unix_duration()
        .as_secs();
    let not_after = leaf
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs();
    let now = now_unix.max(0) as u64;
    if now < not_before {
        return Err(CryptoError::InvalidInput("garnet leaf not yet valid"));
    }
    if now > not_after {
        return Err(CryptoError::InvalidInput("garnet leaf expired"));
    }

    // Extensions must be present (a leaf without them carries no EKU/SAN).
    let exts = leaf
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or(CryptoError::InvalidInput("garnet leaf extensions"))?;

    // The leaf must NOT be a CA (CA:FALSE, or BasicConstraints absent for an end-entity cert).
    if let Some(bc_ext) = exts
        .iter()
        .find(|e| e.extn_id == ObjectIdentifier::new_unwrap("2.5.29.19"))
    {
        let bc = BasicConstraints::from_der(bc_ext.extn_value.as_bytes())
            .map_err(|_| CryptoError::InvalidInput("garnet leaf basic constraints"))?;
        if bc.ca {
            return Err(CryptoError::InvalidInput("garnet leaf is a CA"));
        }
    }

    // EKU must contain the required usage (pinned both directions — K3↔K4 confusion defense).
    let want_eku = ObjectIdentifier::from_str(required_eku)
        .map_err(|_| CryptoError::InvalidInput("garnet required eku oid"))?;
    let eku_ext = exts
        .iter()
        .find(|e| e.extn_id == ObjectIdentifier::new_unwrap("2.5.29.37"))
        .ok_or(CryptoError::InvalidInput("garnet leaf eku missing"))?;
    let eku = ExtendedKeyUsage::from_der(eku_ext.extn_value.as_bytes())
        .map_err(|_| CryptoError::InvalidInput("garnet leaf eku"))?;
    if !eku.0.contains(&want_eku) {
        return Err(CryptoError::InvalidInput("garnet leaf eku mismatch"));
    }

    // The identity: the full SAN URI the keystone wrote (namespace-agnostic; the PRSN wrapper strips it).
    cert_san_uri(leaf_der)?.ok_or(CryptoError::InvalidInput("garnet leaf san missing"))
}

/// The PRSN-handle convenience over [`verify_leaf_chains_to_ca_uri`]: verifies the leaf chains to
/// `ca_der` with `required_eku` (all the same fail-closed checks) **and** that it carries a
/// `urn:signet:prsn:` SAN, returning the bare handle (the §7 consistency-triple identity the broker
/// asserts `== token.sub`). A leaf in another URN namespace (a broker/server cert) is rejected here
/// — an agent verifier must never accept a broker cert as a PRSN. Used by the broker's agent
/// client-cert verifier (#3, [`crate::x509::ID_KP_CLIENT_AUTH`]).
pub fn verify_leaf_chains_to_ca(
    leaf_der: &[u8],
    ca_der: &[u8],
    required_eku: &str,
    now_unix: i64,
) -> Result<String> {
    let uri = verify_leaf_chains_to_ca_uri(leaf_der, ca_der, required_eku, now_unix)?;
    uri.strip_prefix(SAN_URN_PREFIX)
        .map(str::to_string)
        .ok_or(CryptoError::InvalidInput("garnet leaf san handle missing"))
}

/// Re-encode a stored DER certificate as PEM (for serving the CA anchor at pickup, where the
/// DB holds the canonical DER but the wire form is PEM).
pub fn cert_der_to_pem(der: &[u8]) -> Result<String> {
    let cert = x509_cert::Certificate::from_der(der)
        .map_err(|_| CryptoError::InvalidInput("garnet cert der"))?;
    cert.to_pem(x509_cert::der::pem::LineEnding::LF)
        .map_err(|_| CryptoError::InvalidInput("garnet cert pem"))
}

/// Decode a PEM certificate back to canonical DER (the inverse of [`cert_der_to_pem`]) — for the
/// agent's pickup client, which receives its issued K4 leaf + the K2 anchor as PEM on the wire but
/// pins/persists the DER. Rejects anything that is not a single well-formed certificate.
pub fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    let cert = x509_cert::Certificate::from_pem(pem.as_bytes())
        .map_err(|_| CryptoError::InvalidInput("garnet cert pem"))?;
    cert.to_der()
        .map_err(|_| CryptoError::InvalidInput("garnet cert der"))
}

/// The `x5t#S256` of a certificate: `base64url(SHA-256(DER))` — the token `cnf` value (§3) and
/// the issuer's [`IssuedCert::thumbprint_b64url`]. **Shared** so a presented leaf's PoP thumbprint
/// — which the broker computes from the live mutual-TLS connection's leaf — cannot drift from the
/// value the issuer bound into the token (a drift there would be a silent proof-of-possession bypass).
pub fn cert_thumbprint_b64url(der: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(der))
}

/// The **SPKI pin** of a certificate: `base64url(SHA-256(SubjectPublicKeyInfo DER))` — the Garnet
/// broker pin (§4, the Phase-6 launch gate). It hashes the certificate's **public key**, *not* the
/// whole DER (the distinction from [`cert_thumbprint_b64url`]): a broker K3 **cert** rotation that
/// keeps the *same* key preserves the pin (the agent is not locked out — the reliability requirement),
/// while a K3 **key** rotation changes it — a guardian-visible re-trust event, never a silent widening
/// within the K2 namespace. **Shared** so the value the server derives from the registered broker cert
/// (delivered to the agent at pickup) cannot drift from the value the agent's broker-channel verifier
/// computes from the live presented leaf — a drift there would silently defeat the pin.
pub fn cert_spki_sha256_b64url(der: &[u8]) -> Result<String> {
    let cert = x509_cert::Certificate::from_der(der)
        .map_err(|_| CryptoError::InvalidInput("garnet cert der"))?;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| CryptoError::InvalidInput("garnet cert spki der"))?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(&spki_der)))
}

/// The certificate's P-256 public key as an uncompressed **X9.63 point** (`0x04 ‖ X ‖ Y`) —
/// the form [`crate::ecdsa::verify_es256`] takes. Used by the broker's serve-start
/// **K3 binding self-check** (bug087 fix 3): prove the key the keystore will sign with is
/// the key this certificate names, *before* accepting connections. Enforces P-256 the same
/// way [`verify_csr`] does (`from_public_key_der` validates OID + curve + on-curve point).
pub fn cert_pubkey_x963(der: &[u8]) -> Result<Vec<u8>> {
    let cert = x509_cert::Certificate::from_der(der)
        .map_err(|_| CryptoError::InvalidInput("garnet cert der"))?;
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|_| CryptoError::InvalidInput("garnet cert spki der"))?;
    let public_key = p256::PublicKey::from_public_key_der(&spki_der)
        .map_err(|_| CryptoError::InvalidInput("garnet cert key not P-256"))?;
    Ok(public_key.to_encoded_point(false).as_bytes().to_vec())
}

/// `base64url(SHA-256(SPKI DER))` of a **verified** CSR's public key — the F2 pickup
/// binding value (bug084): the first signed pickup for a grant records it; a later,
/// differing CSR for the same grant is refused and raises the re-pointed `contested`
/// alarm. Runs the full [`verify_csr`] validation (well-formed, P-256,
/// proof-of-possession), so a bindable value is only ever produced for a CSR whose
/// requester holds the key. Same encoding as [`cert_spki_sha256_b64url`], so the bound
/// value is directly comparable to the SPKI pin of any cert later issued for that key.
pub fn csr_spki_sha256_b64url(csr_der: &[u8]) -> Result<String> {
    let verified = verify_csr(csr_der)?;
    let spki_der = verified
        .spki
        .to_der()
        .map_err(|_| CryptoError::InvalidInput("garnet csr spki der"))?;
    Ok(URL_SAFE_NO_PAD.encode(Sha256::digest(&spki_der)))
}

/// Build a `Name` from an RFC 4514 string, mapping a parse failure to `InvalidInput`.
fn name(s: &str) -> Result<Name> {
    Name::from_str(s).map_err(|_| CryptoError::InvalidInput("garnet x509 name"))
}

/// Encode a built certificate into the [`IssuedCert`] forms (DER, PEM, hex serial, x5t#S256).
fn finish(cert: x509_cert::Certificate) -> Result<IssuedCert> {
    let der = cert
        .to_der()
        .map_err(|_| CryptoError::InvalidInput("garnet cert der"))?;
    let pem = cert
        .to_pem(x509_cert::der::pem::LineEnding::LF)
        .map_err(|_| CryptoError::InvalidInput("garnet cert pem"))?;
    let serial_hex = hex::encode(cert.tbs_certificate.serial_number.as_bytes());
    let thumbprint_b64url = cert_thumbprint_b64url(&der);
    Ok(IssuedCert {
        der,
        pem,
        serial_hex,
        thumbprint_b64url,
    })
}

#[cfg(test)]
mod tests {
    //! The §4 keystone build-gate + the CSR-verification negative tests. A CSR is crafted by
    //! a throwaway agent key; issuance is driven by a separate CA key. The load-bearing test
    //! is `keystone_uses_grant_handle_not_csr`.

    use super::*;
    use p256::ecdsa::SigningKey;
    use rand_core::OsRng;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now_unix() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// A fresh CA + an agent leaf issued for `handle` under it (same issuer CN, so the names chain).
    fn ca_and_leaf(handle: &str) -> ([u8; 32], IssuedCert, IssuedCert) {
        let ca = ca_key();
        let ca_cert = build_ca_cert(&ca, "Signet Garnet CA", &[1], 315_360_000).unwrap();
        let (csr, _) = make_csr("agent");
        let leaf = issue_agent_cert(&csr, handle, &ca, "Signet Garnet CA", &[2], 604_800).unwrap();
        (ca, ca_cert, leaf)
    }

    #[test]
    fn cert_validity_window_reads_the_leaf_window() {
        // Issued with a 7-day validity: the window must span exactly that, anchored ~now
        // (Validity::from_now — allow a small build-time skew for the not_before read).
        let (_, _, leaf) = ca_and_leaf("hlin-ai");
        let (not_before, not_after) = cert_validity_window(&leaf.der).unwrap();
        assert_eq!(not_after - not_before, 604_800);
        let now = now_unix() as u64;
        assert!(not_before <= now + 5 && not_before + 60 > now);
    }

    #[test]
    fn cert_validity_window_rejects_garbage() {
        assert!(cert_validity_window(b"not a certificate").is_err());
    }

    /// Build a self-signed PKCS#10 CSR requesting `requested_cn`, returning (csr_der, the
    /// agent's X9.63 public key). Exercises the real [`build_csr`] primitive.
    fn make_csr(requested_cn: &str) -> (Vec<u8>, Vec<u8>) {
        let key = SigningKey::random(&mut OsRng);
        let scalar: [u8; 32] = key.to_bytes().into();
        let der = build_csr(&scalar, requested_cn).unwrap();
        let pubkey = key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        (der, pubkey)
    }

    #[test]
    fn pem_to_der_inverts_cert_der_to_pem() {
        // The agent's pickup client receives its leaf + the K2 anchor as PEM and pins the DER:
        // pem_to_der must recover exactly the canonical DER cert_der_to_pem emitted.
        let (_ca, ca_cert, leaf) = ca_and_leaf("hlin-ai");
        for original in [&ca_cert.der, &leaf.der] {
            let pem = cert_der_to_pem(original).unwrap();
            let back = pem_to_der(&pem).unwrap();
            assert_eq!(
                &back, original,
                "PEM→DER must round-trip to the canonical DER"
            );
        }
        // The IssuedCert's own PEM (the wire form pickup serves) parses to the same DER.
        assert_eq!(pem_to_der(&leaf.pem).unwrap(), leaf.der);
    }

    #[test]
    fn pem_to_der_rejects_non_pem() {
        assert!(pem_to_der("not a pem").is_err());
        assert!(pem_to_der("").is_err());
    }

    fn ca_key() -> [u8; 32] {
        SigningKey::random(&mut OsRng).to_bytes().into()
    }

    /// Parse a leaf's SAN URIs.
    fn san_uris(der: &[u8]) -> Vec<String> {
        let cert = x509_cert::Certificate::from_der(der).unwrap();
        let exts = cert.tbs_certificate.extensions.unwrap();
        let san_oid = ObjectIdentifier::new_unwrap("2.5.29.17");
        let ext = exts.iter().find(|e| e.extn_id == san_oid).unwrap();
        let san = SubjectAltName::from_der(ext.extn_value.as_bytes()).unwrap();
        san.0
            .iter()
            .filter_map(|gn| match gn {
                GeneralName::UniformResourceIdentifier(uri) => Some(uri.as_str().to_string()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn keystone_uses_grant_handle_not_csr() {
        // The CSR requests the attacker's handle; issuance is driven by the GRANT's handle.
        let (csr, _) = make_csr("attacker-x-ai");
        let cert = issue_agent_cert(
            &csr,
            "real-y-ai",
            &ca_key(),
            "Signet Garnet CA",
            &[1, 2, 3, 4],
            604_800,
        )
        .expect("issue");

        let uris = san_uris(&cert.der);
        assert!(
            uris.contains(&"urn:signet:prsn:real-y-ai".to_string()),
            "the SAN must be the grant handle; got {uris:?}"
        );
        assert!(
            !uris.iter().any(|u| u.contains("attacker")),
            "the CSR's requested identity must NOT appear in the issued cert"
        );
    }

    #[test]
    fn issued_leaf_has_the_garnet_profile() {
        let (csr, _) = make_csr("agent");
        let cert = issue_agent_cert(
            &csr,
            "hlin-ai",
            &ca_key(),
            "Signet Garnet CA",
            &[9, 9, 9],
            604_800,
        )
        .unwrap();
        let parsed = x509_cert::Certificate::from_der(&cert.der).unwrap();
        let exts = parsed.tbs_certificate.extensions.unwrap();

        // BasicConstraints CA:FALSE.
        let bc = x509_cert::ext::pkix::BasicConstraints::from_der(
            exts.iter()
                .find(|e| e.extn_id == ObjectIdentifier::new_unwrap("2.5.29.19"))
                .expect("basic constraints")
                .extn_value
                .as_bytes(),
        )
        .unwrap();
        assert!(!bc.ca, "leaf must be CA:FALSE");

        // EKU clientAuth.
        let eku = ExtendedKeyUsage::from_der(
            exts.iter()
                .find(|e| e.extn_id == ObjectIdentifier::new_unwrap("2.5.29.37"))
                .expect("eku")
                .extn_value
                .as_bytes(),
        )
        .unwrap();
        assert!(
            eku.0
                .contains(&ObjectIdentifier::new_unwrap(ID_KP_CLIENT_AUTH)),
            "leaf EKU must include clientAuth"
        );

        // Serial + thumbprint are populated.
        assert!(!cert.serial_hex.is_empty());
        assert!(!cert.thumbprint_b64url.is_empty());
    }

    #[test]
    fn issued_leaf_is_signed_by_the_ca_key() {
        let ca = ca_key();
        let ca_pubkey = SigningKey::from_slice(&ca)
            .unwrap()
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let (csr, _) = make_csr("agent");
        let cert =
            issue_agent_cert(&csr, "hlin-ai", &ca, "Signet Garnet CA", &[7], 604_800).unwrap();

        // The leaf signature is over DER(TBSCertificate), under the CA key.
        let parsed = x509_cert::Certificate::from_der(&cert.der).unwrap();
        let tbs = parsed.tbs_certificate.to_der().unwrap();
        let sig = parsed.signature.as_bytes().unwrap();
        crate::ecdsa::verify_es256(&ca_pubkey, &tbs, sig).expect("leaf is signed by the CA key");
    }

    #[test]
    fn verify_csr_accepts_a_valid_csr() {
        let (csr, pubkey) = make_csr("agent");
        let v = verify_csr(&csr).expect("valid CSR verifies");
        assert_eq!(v.pubkey_x963, pubkey, "extracts the CSR's public key");
    }

    #[test]
    fn verify_csr_rejects_a_tampered_csr() {
        // Flip a byte in the middle of the DER — the self-signature no longer matches.
        let (mut csr, _) = make_csr("agent");
        let mid = csr.len() / 2;
        csr[mid] ^= 0x01;
        assert!(verify_csr(&csr).is_err(), "a tampered CSR must be rejected");
    }

    #[test]
    fn verify_csr_rejects_garbage() {
        assert_eq!(
            verify_csr(b"not a csr at all").unwrap_err(),
            CryptoError::InvalidInput("garnet csr der")
        );
    }

    #[test]
    fn issue_rejects_a_tampered_csr() {
        // The keystone verifies PoP first — a tampered CSR can never be issued against.
        let (mut csr, _) = make_csr("agent");
        let mid = csr.len() / 2;
        csr[mid] ^= 0x01;
        assert!(
            issue_agent_cert(
                &csr,
                "hlin-ai",
                &ca_key(),
                "Signet Garnet CA",
                &[1],
                604_800
            )
            .is_err(),
            "issuance must fail on an unverifiable CSR"
        );
    }

    #[test]
    fn ca_cert_has_the_ca_profile() {
        let cert = build_ca_cert(&ca_key(), "Signet Garnet CA", &[1, 2, 3], 315_360_000).unwrap();
        let parsed = x509_cert::Certificate::from_der(&cert.der).unwrap();

        // Self-signed: issuer == subject.
        assert_eq!(
            parsed.tbs_certificate.issuer, parsed.tbs_certificate.subject,
            "the CA cert is self-signed"
        );

        let exts = parsed.tbs_certificate.extensions.unwrap();
        // BasicConstraints CA:TRUE, pathlen:0.
        let bc = BasicConstraints::from_der(
            exts.iter()
                .find(|e| e.extn_id == ObjectIdentifier::new_unwrap("2.5.29.19"))
                .expect("basic constraints")
                .extn_value
                .as_bytes(),
        )
        .unwrap();
        assert!(bc.ca, "CA cert must be CA:TRUE");
        assert_eq!(bc.path_len_constraint, Some(0), "CA cert must be pathlen:0");

        // KeyUsage keyCertSign + cRLSign.
        let ku = KeyUsage::from_der(
            exts.iter()
                .find(|e| e.extn_id == ObjectIdentifier::new_unwrap("2.5.29.15"))
                .expect("key usage")
                .extn_value
                .as_bytes(),
        )
        .unwrap();
        assert!(ku.0.contains(KeyUsages::KeyCertSign), "CA must keyCertSign");
        assert!(ku.0.contains(KeyUsages::CRLSign), "CA must cRLSign");
    }

    #[test]
    fn leaf_chains_to_the_ca_cert() {
        let ca = ca_key();
        let ca_pubkey = SigningKey::from_slice(&ca)
            .unwrap()
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let ca_cert = build_ca_cert(&ca, "Signet Garnet CA", &[1], 315_360_000).unwrap();
        let (csr, _) = make_csr("agent");
        let leaf =
            issue_agent_cert(&csr, "hlin-ai", &ca, "Signet Garnet CA", &[2], 604_800).unwrap();

        let ca_parsed = x509_cert::Certificate::from_der(&ca_cert.der).unwrap();
        let leaf_parsed = x509_cert::Certificate::from_der(&leaf.der).unwrap();

        // Name chaining: leaf.issuer == CA.subject.
        assert_eq!(
            leaf_parsed.tbs_certificate.issuer, ca_parsed.tbs_certificate.subject,
            "the leaf's issuer must be the CA's subject"
        );
        // Signature chaining: the leaf is signed by the CA key.
        let tbs = leaf_parsed.tbs_certificate.to_der().unwrap();
        crate::ecdsa::verify_es256(&ca_pubkey, &tbs, leaf_parsed.signature.as_bytes().unwrap())
            .expect("the leaf chains to (is signed by) the CA key");
    }

    #[test]
    fn build_csr_round_trips_through_verify() {
        let (scalar, pubkey) = crate::ecdsa::generate_keypair();
        let csr = build_csr(&scalar, "agent").unwrap();
        let v = verify_csr(&csr).expect("a built CSR verifies");
        assert_eq!(v.pubkey_x963, pubkey, "the CSR carries the agent's key");
    }

    #[test]
    fn cert_san_handle_reads_the_issued_grant_handle() {
        // The CSR requests the wrong handle; the issued cert's SAN handle is the grant's.
        let (csr, _) = make_csr("attacker-x-ai");
        let cert = issue_agent_cert(
            &csr,
            "real-y-ai",
            &ca_key(),
            "Signet Garnet CA",
            &[5],
            604_800,
        )
        .unwrap();
        assert_eq!(
            cert_san_handle(&cert.der).unwrap().as_deref(),
            Some("real-y-ai")
        );
    }

    #[test]
    fn cert_san_broker_id_reads_only_a_broker_cert() {
        // The deregister route's identity discrimination: a broker's K_bc cert carries
        // urn:signet:broker:<id> → Some(id); an agent's K4 cert carries urn:signet:prsn:<handle>,
        // which is NOT a broker → None (so a K4 holder cannot deregister a broker). The two SAN
        // readers are mirror-exclusive (a broker cert has no handle; an agent cert has no broker id).
        let ca = ca_key();
        let (kbc_csr, _) = make_csr("broker");
        let kbc =
            issue_broker_client_cert(&kbc_csr, "mac-42", &ca, "Signet Garnet CA", &[7], 604_800)
                .unwrap();
        assert_eq!(
            cert_san_broker_id(&kbc.der).unwrap().as_deref(),
            Some("mac-42")
        );
        assert_eq!(
            cert_san_handle(&kbc.der).unwrap(),
            None,
            "a broker is not a handle"
        );

        let (agent_csr, _) = make_csr("agent-x-ai");
        let agent = issue_agent_cert(
            &agent_csr,
            "agent-x-ai",
            &ca,
            "Signet Garnet CA",
            &[8],
            604_800,
        )
        .unwrap();
        assert_eq!(
            cert_san_broker_id(&agent.der).unwrap(),
            None,
            "an agent's PRSN cert is not a broker"
        );
    }

    #[test]
    fn cert_thumbprint_matches_the_issued_thumbprint() {
        // The broker computes the cnf from the presented leaf; it MUST equal what the issuer bound.
        let (_, _, leaf) = ca_and_leaf("hlin-ai");
        assert_eq!(cert_thumbprint_b64url(&leaf.der), leaf.thumbprint_b64url);
    }

    #[test]
    fn spki_pin_survives_a_cert_rotation_on_a_stable_key_but_not_a_key_rotation() {
        // The §4 launch-gate property: the broker SPKI pin hashes the public KEY, not the cert.
        let ca = ca_key();
        let (_k, pubkey) = crate::ecdsa::generate_keypair();
        // Two distinct certs for the SAME key (different serials + validity) — a cert rotation.
        let leaf_v1 =
            build_server_leaf(&pubkey, "mac-1", &ca, "Signet Garnet CA", &[10], 604_800).unwrap();
        let leaf_v2 =
            build_server_leaf(&pubkey, "mac-1", &ca, "Signet Garnet CA", &[11], 1_209_600).unwrap();
        assert_ne!(leaf_v1.der, leaf_v2.der, "the two certs must differ in DER");
        assert_ne!(
            cert_thumbprint_b64url(&leaf_v1.der),
            cert_thumbprint_b64url(&leaf_v2.der),
            "the whole-cert thumbprint DOES change across the rotation (the contrast)"
        );
        assert_eq!(
            cert_spki_sha256_b64url(&leaf_v1.der).unwrap(),
            cert_spki_sha256_b64url(&leaf_v2.der).unwrap(),
            "the SPKI pin MUST survive a cert rotation on a stable key (no agent lock-out)"
        );

        // A different key → a different pin (a K3 key rotation is a guardian-visible re-trust).
        let (_k2, other_pubkey) = crate::ecdsa::generate_keypair();
        let leaf_other = build_server_leaf(
            &other_pubkey,
            "mac-1",
            &ca,
            "Signet Garnet CA",
            &[12],
            604_800,
        )
        .unwrap();
        assert_ne!(
            cert_spki_sha256_b64url(&leaf_v1.der).unwrap(),
            cert_spki_sha256_b64url(&leaf_other.der).unwrap(),
            "a different public key MUST change the pin"
        );
    }

    #[test]
    fn verify_leaf_accepts_a_valid_leaf_and_returns_the_handle() {
        let (_, ca_cert, leaf) = ca_and_leaf("hlin-ai");
        let handle =
            verify_leaf_chains_to_ca(&leaf.der, &ca_cert.der, ID_KP_CLIENT_AUTH, now_unix())
                .expect("a valid leaf chained to its CA verifies");
        assert_eq!(handle, "hlin-ai");
    }

    #[test]
    fn verify_leaf_rejects_a_leaf_from_a_different_ca() {
        // A forger uses the same issuer CN ("Signet Garnet CA") but a different key — names chain,
        // the signature does not. This is the load-bearing rejection.
        let (_, _, leaf) = ca_and_leaf("hlin-ai");
        let other_ca = ca_key();
        let other_ca_cert =
            build_ca_cert(&other_ca, "Signet Garnet CA", &[9], 315_360_000).unwrap();
        assert_eq!(
            verify_leaf_chains_to_ca(&leaf.der, &other_ca_cert.der, ID_KP_CLIENT_AUTH, now_unix())
                .unwrap_err(),
            CryptoError::SignatureInvalid
        );
    }

    #[test]
    fn verify_leaf_rejects_a_tampered_leaf() {
        let (_, ca_cert, leaf) = ca_and_leaf("hlin-ai");
        let mut der = leaf.der.clone();
        let mid = der.len() / 2;
        der[mid] ^= 0x01;
        assert!(
            verify_leaf_chains_to_ca(&der, &ca_cert.der, ID_KP_CLIENT_AUTH, now_unix()).is_err()
        );
    }

    #[test]
    fn verify_leaf_rejects_an_expired_leaf() {
        let (_, ca_cert, leaf) = ca_and_leaf("hlin-ai");
        // now well past the 7-day validity.
        let far_future = now_unix() + 30 * 24 * 3600;
        assert_eq!(
            verify_leaf_chains_to_ca(&leaf.der, &ca_cert.der, ID_KP_CLIENT_AUTH, far_future)
                .unwrap_err(),
            CryptoError::InvalidInput("garnet leaf expired")
        );
    }

    #[test]
    fn verify_leaf_rejects_a_not_yet_valid_leaf() {
        let (_, ca_cert, leaf) = ca_and_leaf("hlin-ai");
        // now at the epoch — well before the leaf's notBefore (~2026).
        assert_eq!(
            verify_leaf_chains_to_ca(&leaf.der, &ca_cert.der, ID_KP_CLIENT_AUTH, 0).unwrap_err(),
            CryptoError::InvalidInput("garnet leaf not yet valid")
        );
    }

    #[test]
    fn verify_leaf_rejects_a_wrong_eku() {
        // The agent leaf is clientAuth; requiring serverAuth must reject (the K3↔K4 confusion defense).
        let (_, ca_cert, leaf) = ca_and_leaf("hlin-ai");
        assert_eq!(
            verify_leaf_chains_to_ca(&leaf.der, &ca_cert.der, ID_KP_SERVER_AUTH, now_unix())
                .unwrap_err(),
            CryptoError::InvalidInput("garnet leaf eku mismatch")
        );
    }

    #[test]
    fn verify_leaf_rejects_a_ca_cert_presented_as_a_leaf() {
        // The CA cert is self-signed (name + signature chain trivially), so the catch is the
        // BasicConstraints CA:TRUE check — a CA cert must never pass as an end-entity leaf.
        let (_, ca_cert, _) = ca_and_leaf("hlin-ai");
        assert_eq!(
            verify_leaf_chains_to_ca(&ca_cert.der, &ca_cert.der, ID_KP_CLIENT_AUTH, now_unix())
                .unwrap_err(),
            CryptoError::InvalidInput("garnet leaf is a CA")
        );
    }

    // ── #4: the grant-status channel certs (broker client K_bc + server K_srv) ──

    #[test]
    fn broker_client_cert_is_clientauth_in_the_broker_namespace() {
        // The broker's grant-status client cert (K_bc, T3 opt-a): clientAuth EKU + a urn:signet:broker
        // SAN (NOT a PRSN URN). It chains to K2 and verifies under clientAuth (the keystone discipline
        // holds — the broker_id is server-supplied, the CSR is PoP-only).
        let ca = ca_key();
        let ca_cert = build_ca_cert(&ca, "Signet Garnet CA", &[1], 315_360_000).unwrap();
        let (csr, _) = make_csr("broker");
        let leaf =
            issue_broker_client_cert(&csr, "mac-7f3a", &ca, "Signet Garnet CA", &[3], 604_800)
                .unwrap();
        assert_eq!(
            cert_san_uri(&leaf.der).unwrap().as_deref(),
            Some("urn:signet:broker:mac-7f3a")
        );
        assert_eq!(
            cert_san_handle(&leaf.der).unwrap(),
            None,
            "a broker cert is not a PRSN"
        );
        // Verifies under clientAuth (what the server's grant-status verifier requires); the EKU split
        // rejects it under serverAuth.
        let uri =
            verify_leaf_chains_to_ca_uri(&leaf.der, &ca_cert.der, ID_KP_CLIENT_AUTH, now_unix())
                .expect("broker client cert verifies under clientAuth");
        assert_eq!(uri, "urn:signet:broker:mac-7f3a");
        assert_eq!(
            verify_leaf_chains_to_ca_uri(&leaf.der, &ca_cert.der, ID_KP_SERVER_AUTH, now_unix())
                .unwrap_err(),
            CryptoError::InvalidInput("garnet leaf eku mismatch")
        );
        // The PRSN wrapper rejects it (no PRSN SAN) — an agent verifier must not accept a broker cert.
        assert_eq!(
            verify_leaf_chains_to_ca(&leaf.der, &ca_cert.der, ID_KP_CLIENT_AUTH, now_unix())
                .unwrap_err(),
            CryptoError::InvalidInput("garnet leaf san handle missing")
        );
    }

    #[test]
    fn server_leaf_is_serverauth_in_the_server_namespace_and_certifies_its_key() {
        // The deployment server's grant-status cert (K_srv): serverAuth EKU + a urn:signet:server SAN,
        // K2-signed over the server's OWN P-256 key (the listener holds the private half).
        let ca = ca_key();
        let ca_cert = build_ca_cert(&ca, "Signet Garnet CA", &[1], 315_360_000).unwrap();
        let (_srv_scalar, srv_pub) = crate::ecdsa::generate_keypair();
        let leaf = build_server_leaf(
            &srv_pub,
            "drive-bhs-1",
            &ca,
            "Signet Garnet CA",
            &[4],
            31_536_000,
        )
        .unwrap();
        assert_eq!(
            cert_san_uri(&leaf.der).unwrap().as_deref(),
            Some("urn:signet:server:drive-bhs-1")
        );
        // The cert certifies the server's own public key.
        let parsed = x509_cert::Certificate::from_der(&leaf.der).unwrap();
        let spki_der = parsed
            .tbs_certificate
            .subject_public_key_info
            .to_der()
            .unwrap();
        let cert_pub = p256::PublicKey::from_public_key_der(&spki_der)
            .unwrap()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        assert_eq!(cert_pub, srv_pub, "the cert certifies the server's own key");
        // Verifies under serverAuth (what the broker requires); rejected under clientAuth.
        let uri =
            verify_leaf_chains_to_ca_uri(&leaf.der, &ca_cert.der, ID_KP_SERVER_AUTH, now_unix())
                .expect("server cert verifies under serverAuth");
        assert_eq!(uri, "urn:signet:server:drive-bhs-1");
        assert_eq!(
            verify_leaf_chains_to_ca_uri(&leaf.der, &ca_cert.der, ID_KP_CLIENT_AUTH, now_unix())
                .unwrap_err(),
            CryptoError::InvalidInput("garnet leaf eku mismatch")
        );
    }

    #[test]
    fn grant_status_certs_cross_verify_their_channel_roles() {
        // The channel directions (#4): the SERVER requires clientAuth on the broker's cert; the BROKER
        // requires serverAuth on the server's cert. Each cert passes its own role and fails the other —
        // the K3↔K4 / client↔server confusion defense, end to end.
        let ca = ca_key();
        let ca_cert = build_ca_cert(&ca, "Signet Garnet CA", &[1], 315_360_000).unwrap();
        let (bcsr, _) = make_csr("broker");
        let bc = issue_broker_client_cert(&bcsr, "mac-1", &ca, "Signet Garnet CA", &[6], 604_800)
            .unwrap();
        let (_s, spub) = crate::ecdsa::generate_keypair();
        let srv =
            build_server_leaf(&spub, "drive-1", &ca, "Signet Garnet CA", &[7], 31_536_000).unwrap();

        // Server-side verifier (clientAuth) accepts K_bc, rejects K_srv.
        assert!(
            verify_leaf_chains_to_ca_uri(&bc.der, &ca_cert.der, ID_KP_CLIENT_AUTH, now_unix())
                .is_ok()
        );
        assert!(
            verify_leaf_chains_to_ca_uri(&srv.der, &ca_cert.der, ID_KP_CLIENT_AUTH, now_unix())
                .is_err()
        );
        // Broker-side verifier (serverAuth) accepts K_srv, rejects K_bc.
        assert!(
            verify_leaf_chains_to_ca_uri(&srv.der, &ca_cert.der, ID_KP_SERVER_AUTH, now_unix())
                .is_ok()
        );
        assert!(
            verify_leaf_chains_to_ca_uri(&bc.der, &ca_cert.der, ID_KP_SERVER_AUTH, now_unix())
                .is_err()
        );
    }
}
