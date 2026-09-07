// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! The agent's Garnet **pickup** client — first contact (Auth-Core Spec §5/§7, bug084:
//! signature-authenticated).
//!
//! Pickup is a normal SIGNET-V1 **signed request**: the agent proves possession of its
//! attested, SE-bound signing key (the same authentication every Drive API call uses), and
//! the server binds the issued credential to the **authenticated account** — no pairing
//! code, nothing for the guardian to relay. The signing runs over the **enrollment-phase
//! keystore channel** ([`crate::keystore::open_enrollment_channel`]) — the same channel
//! `signet enroll` used for keygen — because the broker path requires the very credential
//! pickup is creating.
//!
//! 1. Generate a fresh **K4** client keypair (P-256) — the agent's transport identity; the
//!    private half lives only in the [`PoPCredential`], never exported (§1).
//! 2. Build a PKCS#10 **CSR** carrying that public key. The server uses the CSR as a
//!    public-key carrier + proof-of-possession **only** — the keystone builds the leaf's SAN
//!    from the authenticated account's current handle and ignores the CSR subject. The
//!    server **binds this CSR's key at first contact** (F2): the same key re-picks-up
//!    idempotently; a different key is refused (`contested` — recovery is guardian
//!    revoke-and-re-authorize).
//! 3. POST the signed `{ csr }`; receive the issued **K4 leaf** (PEM), the pinned **K2**
//!    anchor (PEM), and a **server-audience** access token. The grant is **auto-confirmed**
//!    by the pickup itself — the signature is the verification the old §6 match-gate
//!    approximated — so SE ops are available as soon as a broker-audience token is
//!    (lazily) acquired.
//! 4. Assemble the [`PoPCredential`] — bound to the handle the *server* put in the leaf SAN
//!    (not a client-supplied value). The caller persists it ([`PoPCredential::save`]).
//!
//! Pickup MUST be reached at the deployment origin under full public-web-PKI server-cert
//! validation (§5 — the K2 anchor it delivers cannot validate its own delivery). That is the
//! [`crate::http`] client's standard TLS; this module adds no certificate-verification
//! override.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;
use zeroize::Zeroizing;

use crate::error::{CliError, Result};
use crate::garnet_credential::PoPCredential;
use crate::http;
use crate::keystore::{KeyLabel, Keystore, Purpose};

/// Run the signature-authenticated Garnet pickup against `base_url`, signing with `handle`'s
/// attested signing key via `keystore` (the enrollment-phase channel), and return the
/// assembled [`PoPCredential`] (server-audience token; the broker-audience token is acquired
/// lazily or by the caller) plus the server's **`reissued`** flag (v09: `true` means this
/// pickup re-bound an already-claimed grant and the server CUT the previous credential — the
/// caller MUST surface that loudly). The caller persists the credential.
pub fn pickup(
    base_url: &str,
    keystore: &dyn Keystore,
    handle: &str,
) -> Result<(PoPCredential, bool)> {
    let base = base_url.trim_end_matches('/');
    let signing = KeyLabel::from_handle(handle, Purpose::Signing)?;

    // (1) Fresh K4 keypair — the scalar is consumed here (into the CSR + the persisted PKCS#8)
    //     and zeroized on drop; only the public half leaves in the CSR.
    let (scalar, _public) = signet_crypto::ecdsa::generate_keypair();
    let scalar = Zeroizing::new(scalar);

    // (2) The CSR (public-key carrier + PoP; the subject is ignored server-side — the keystone).
    let csr_der = signet_crypto::x509::build_csr(&scalar, "agent")
        .map_err(|e| CliError::generic(format!("building the pickup CSR: {e}")))?;

    // (3) The SIGNED pickup: body `{ csr }`, authenticated by the attested SE-bound signing
    //     key. Serialized once and sent verbatim (the same bytes are hashed into the
    //     signature — post_json_signed's contract).
    let body = build_pickup_body(&csr_der)?;
    let resp = http::post_json_signed(keystore, &signing, base, "/v1/garnet/pickup", &body)?;

    // (4) Parse + assemble. PEM→DER for the leaf + anchor (we pin/persist the DER).
    let client_cert_pem = json_str(&resp, "client_cert")?;
    let ca_cert_pem = json_str(&resp, "ca_cert")?;
    // The broker SPKI pin for this guardian's broker (§4 launch gate) — the agent→broker channel
    // pins it so a substituted-but-K2-chained broker is rejected. Required from pickup onward.
    let broker_spki_pin = json_str(&resp, "broker_spki_pin")?;
    let access_token = json_str(&resp, "access_token")?;
    // The Garnet ingress base URL the agent renews its tokens/cert against (§7) — the server
    // names its own ingress (S094).
    let grant_status_url = json_str(&resp, "grant_status_url")?;

    let client_cert_der = signet_crypto::x509::pem_to_der(&client_cert_pem).map_err(|e| {
        CliError::invalid_data(format!("pickup returned a malformed client cert: {e}"))
    })?;
    let ca_anchor_der = signet_crypto::x509::pem_to_der(&ca_cert_pem).map_err(|e| {
        CliError::invalid_data(format!("pickup returned a malformed CA anchor: {e}"))
    })?;

    // The handle is the one the SERVER put in the leaf SAN (derived from the authenticated
    // account) — never a client-supplied value. A leaf without a PRSN-handle SAN is a
    // server/protocol fault.
    let san_handle = signet_crypto::x509::cert_san_handle(&client_cert_der)
        .ok()
        .flatten()
        .ok_or_else(|| {
            CliError::invalid_data("pickup returned a cert without a PRSN-handle SAN")
        })?;

    let k4_key_pkcs8 = signet_crypto::ecdsa::p256_scalar_to_pkcs8_der(&scalar)
        .map_err(|e| CliError::generic(format!("encoding the K4 key: {e}")))?;

    // v09: whether this pickup RE-ISSUED an already-claimed grant's credential (the server
    // cut the previous one). Optional-with-default so a pre-v09 server (field absent) reads
    // as an ordinary pickup — additive compatibility.
    let reissued = resp
        .get("reissued")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    Ok((
        PoPCredential::new(
            san_handle,
            k4_key_pkcs8,
            client_cert_der,
            ca_anchor_der,
            broker_spki_pin,
            grant_status_url,
            access_token,
        ),
        reissued,
    ))
}

/// Build the signed-pickup request body `{ csr }` (the CSR as base64-standard DER, the shape
/// [`signet_server::garnet::pickup`] decodes). Pure — unit-tested for the wire shape.
fn build_pickup_body(csr_der: &[u8]) -> Result<Vec<u8>> {
    let body = serde_json::json!({ "csr": STANDARD.encode(csr_der) });
    serde_json::to_vec(&body)
        .map_err(|e| CliError::generic(format!("serializing pickup body: {e}")))
}

/// Extract a required string field from the pickup response.
fn json_str(value: &Value, key: &str) -> Result<String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(String::from)
        .ok_or_else(|| {
            CliError::invalid_data(format!("pickup response missing string field '{key}'"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pickup_body_carries_the_base64_csr_and_no_bearer_secret() {
        // A real CSR so the base64 is well-formed DER the server would accept.
        let (scalar, _) = signet_crypto::ecdsa::generate_keypair();
        let csr = signet_crypto::x509::build_csr(&scalar, "agent").unwrap();
        let bytes = build_pickup_body(&csr).unwrap();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        let csr_b64 = v["csr"].as_str().unwrap();
        assert_eq!(STANDARD.decode(csr_b64).unwrap(), csr);
        // The flag-day pin: the body carries NO pairing code field at all.
        assert!(v.get("pairing_code").is_none());
        assert_eq!(v.as_object().unwrap().len(), 1, "csr is the whole body");
    }

    #[test]
    fn json_str_requires_the_field() {
        let v = serde_json::json!({ "access_token": "tok" });
        assert_eq!(json_str(&v, "access_token").unwrap(), "tok");
        assert!(json_str(&v, "client_cert").is_err());
    }
}
