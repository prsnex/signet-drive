// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! The broker's **K3 transport-key home** and its rustls signer (Garnet Phase-6, S094).
//!
//! K3 is the broker's agent-facing mutual-TLS **server** identity — the cert the agent
//! SPKI-pins (#226, Auth-Core §4). Its private key lives in one of two homes, selected by
//! the `key_protection` tier at provision time:
//!
//! * **Secure Enclave** ([`BrokerK3KeyHome::SecureEnclave`]) — the production
//!   Apple-Silicon-Mac home. The key is generated *in* the SE at provision, never leaves
//!   it, and every TLS `CertificateVerify` signature is produced by the SE in place. The
//!   broker credential file holds only the key's Keychain **label**, never key bytes.
//! * **Raw PKCS#8** ([`BrokerK3KeyHome::RawPkcs8`]) — the software-tier home (dev / CI /
//!   the non-macOS build). An in-memory key handed to rustls's own signer; zeroized on drop.
//!
//! **Why the SE home is v1 (defense-in-depth, not "required" — S094 verification).** Moving
//! K3 into the SE closes no *in-scope* v1 threat (the only reader of the raw 0600 key is a
//! same-user local process, an accepted v1 residual; K3 is a transport cert, not a content
//! key; and the agent's symmetric K4 identity ships raw in v1). It is worth shipping in v1
//! because it makes the #226 SPKI-pin a **hardware-rooted** claim and keeps the broker's
//! *durable* identity non-extractable — the raw home's at-rest bound is only disk encryption plus
//! 0600 file permissions. (§1 of the Auth-Core spec calls this "REQUIRED"; that overstates it —
//! corrected to "defense-in-depth, v1 target".)
//!
//! **The signer.** rustls has no notion of a non-extractable key, so the SE home needs a
//! custom [`rustls::sign::SigningKey`] (`BrokerK3SigningKey`) that delegates the handshake
//! signature to an `Es256Signer`. In production that backend is the Secure Enclave
//! (`SeEs256Signer`); the CI handshake test drives the *same* rustls-integration path with a
//! raw-scalar backend (`RawEs256Signer`), so the novel signer code is proven end-to-end without
//! hardware and only the SE `sign` leg itself needs the on-device follow (#208-style). The raw
//! home does **not** use this signer — it stays on rustls's built-in `with_single_cert` path (no
//! regression to the software tier). The signer machinery is therefore compiled only where it is
//! used: on macOS (the production SE home) or in tests (the CI proof).

use zeroize::Zeroize;

/// Where the broker's K3 server private key lives (selected at provision by the key tier).
#[derive(Clone)]
pub enum BrokerK3KeyHome {
    /// Raw PKCS#8 held in memory (software tier — dev / CI / non-macOS). Zeroized on drop.
    RawPkcs8(Vec<u8>),
    /// An SE-resident key referenced by its Keychain `label` — the private scalar never
    /// leaves the enclave (production Apple-Silicon Mac; macOS-only at use time). The label is
    /// not secret.
    SecureEnclave { label: String },
}

impl Zeroize for BrokerK3KeyHome {
    fn zeroize(&mut self) {
        match self {
            BrokerK3KeyHome::RawPkcs8(k) => k.zeroize(),
            // The label is a non-secret Keychain handle; the private key lives in the SE and
            // is not held here. Zeroize it anyway for uniformity.
            BrokerK3KeyHome::SecureEnclave { label } => label.zeroize(),
        }
    }
}

/// A redacting [`std::fmt::Debug`]: raw key bytes are secret and never printed; the SE label
/// is a non-secret Keychain handle.
impl std::fmt::Debug for BrokerK3KeyHome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BrokerK3KeyHome::RawPkcs8(k) => f
                .debug_struct("RawPkcs8")
                .field("pkcs8_len", &k.len())
                .field("key", &"<redacted>")
                .finish(),
            BrokerK3KeyHome::SecureEnclave { label } => f
                .debug_struct("SecureEnclave")
                .field("label", label)
                .finish(),
        }
    }
}

// ── The K3 signer (the Secure-Enclave home) — compiled only on macOS or under test ────────────
//
// On a non-macOS non-test build the SE home is unreachable (`broker_server_config` returns an
// "SE key home is macOS-only" error for it), so none of this is referenced — gate it out rather
// than leave it as dead code.

/// The **legacy** fixed Keychain label for the broker's SE-resident K3 key — retained so
/// pre-bug087 credentials (which carry this label) keep serving, and as the prefix of the
/// per-generation labels below. Deliberately **not** a PRSN `<handle>-<purpose>` label — it is
/// a broker transport key, outside the PRSN `KeyLabel`/`Keystore` abstraction, and `keys list`
/// skips it (it does not parse as a PRSN label), so it never pollutes the PRSN key list.
///
/// ⚠ **New keys are NEVER created under this label (bug087).** A fixed label meant "which key
/// is mine" was answered by whatever the keychain returned first — a lookup that cannot
/// distinguish generations. An orphan key left by a failed provision (`generate_k3_key` runs
/// before the code is validated server-side) could therefore shadow the live key the moment a
/// new process resolved the label, signing every TLS CertificateVerify with the wrong key
/// (wire signature: `tls_process_cert_verify: bad signature`) — the S141→S146 broker brick.
/// Provisioning now mints a unique [`broker_k3_generation_label`] per attempt, and the
/// credential names its own key, so an orphan is **inert by construction**.
#[cfg(any(target_os = "macos", test))]
pub(crate) const BROKER_K3_SE_LABEL: &str = "signet-garnet-broker-k3";

/// A fresh per-generation Keychain label for a broker K3 key:
/// `signet-garnet-broker-k3-<16 lowercase hex>` (8 CSPRNG bytes). The label is stored in the
/// broker credential ([`BrokerK3KeyHome::SecureEnclave`]), so `signet broker serve` looks up
/// exactly *this credential's* key — a key from any other provision attempt (including an
/// orphan from a rejected code) has a different label and is never returned.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn broker_k3_generation_label() -> String {
    use rand_core::{OsRng, RngCore};
    let mut nonce = [0u8; 8];
    OsRng.fill_bytes(&mut nonce);
    format!("{BROKER_K3_SE_LABEL}-{}", hex::encode(nonce))
}

/// Whether `label` is a **stale** broker-K3 label safe to sweep once `keep_label` is the live
/// one (bug087 fix 0b): the legacy fixed label, or a per-generation label
/// (`signet-garnet-broker-k3-` + exactly 16 lowercase hex) other than `keep_label`.
///
/// The generation-suffix parse is deliberately **strict** (exactly 16 lowercase hex): a PRSN
/// `<handle>-<purpose>` label can share the textual prefix (a handle may legally begin with
/// `signet-garnet-broker-k3`), and a sweeping deleter must be structurally unable to match a
/// PRSN key. Pure — unit-tested below, including the adversarial-handle shape.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn is_stale_broker_k3_label(label: &str, keep_label: &str) -> bool {
    if label == keep_label {
        return false;
    }
    if label == BROKER_K3_SE_LABEL {
        return true;
    }
    match label.strip_prefix(concat!("signet-garnet-broker-k3", "-")) {
        Some(suffix) => {
            suffix.len() == 16
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        None => false,
    }
}

#[cfg(any(target_os = "macos", test))]
mod signer {
    use std::sync::Arc;

    use rustls::sign::{Signer, SigningKey};
    use rustls::{SignatureAlgorithm, SignatureScheme};

    use crate::error::Result;

    /// Produces an `ES256` signature (raw `r‖s`) over a message — the seam [`BrokerK3SigningKey`]
    /// delegates the TLS handshake signature to. Two homes implement it: the Secure Enclave
    /// ([`SeEs256Signer`], production) and a raw scalar ([`RawEs256Signer`], the CI handshake
    /// test). `Debug` must not reveal key material.
    pub(crate) trait Es256Signer: std::fmt::Debug + Send + Sync {
        /// Sign `msg` with `ES256`, returning the raw 64-byte `r‖s`. The scheme's SHA-256 hash is
        /// applied by the backend (the SE hashes in-enclave; the raw scalar hashes in
        /// `signet-crypto`).
        fn sign_es256(&self, msg: &[u8]) -> Result<[u8; 64]>;
    }

    /// The Secure-Enclave `ES256` signer: signs `msg` with the SE-resident K3 key at `label`, in
    /// the enclave, never touching the private scalar. macOS-only.
    #[cfg(target_os = "macos")]
    pub(crate) struct SeEs256Signer {
        label: String,
    }

    #[cfg(target_os = "macos")]
    impl SeEs256Signer {
        pub(crate) fn new(label: String) -> Self {
            Self { label }
        }
    }

    #[cfg(target_os = "macos")]
    impl std::fmt::Debug for SeEs256Signer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SeEs256Signer")
                .field("label", &self.label)
                .finish()
        }
    }

    #[cfg(target_os = "macos")]
    impl Es256Signer for SeEs256Signer {
        fn sign_es256(&self, msg: &[u8]) -> Result<[u8; 64]> {
            crate::keystore::broker_se_sign(&self.label, msg)
        }
    }

    /// A rustls [`SigningKey`] backed by an [`Es256Signer`] — the K3 server-cert signer for the SE
    /// key home. It offers exactly `ECDSA_NISTP256_SHA256` (Garnet's only PKI scheme) and delegates
    /// the `CertificateVerify` signature to the backend, returning it DER-encoded (the format rustls
    /// requires for an ECDSA scheme).
    #[derive(Debug)]
    pub(crate) struct BrokerK3SigningKey {
        signer: Arc<dyn Es256Signer>,
    }

    impl BrokerK3SigningKey {
        pub(crate) fn new(signer: Arc<dyn Es256Signer>) -> Self {
            Self { signer }
        }
    }

    impl SigningKey for BrokerK3SigningKey {
        fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
            offered
                .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
                .then(|| {
                    Box::new(BrokerK3Signer {
                        signer: Arc::clone(&self.signer),
                    }) as Box<dyn Signer>
                })
        }

        fn algorithm(&self) -> SignatureAlgorithm {
            SignatureAlgorithm::ECDSA
        }
    }

    /// The scheme-bound signer [`BrokerK3SigningKey::choose_scheme`] hands back.
    #[derive(Debug)]
    struct BrokerK3Signer {
        signer: Arc<dyn Es256Signer>,
    }

    impl Signer for BrokerK3Signer {
        fn sign(&self, message: &[u8]) -> std::result::Result<Vec<u8>, rustls::Error> {
            // rustls passes the un-hashed message; the backend applies SHA-256 (implicit in the
            // scheme). The wire format for ECDSA_NISTP256_SHA256 is ASN.1 DER, so r‖s → DER.
            let raw = self
                .signer
                .sign_es256(message)
                .map_err(|e| rustls::Error::General(format!("garnet K3 signer: {e}")))?;
            signet_crypto::ecdsa::sig_raw_to_der(&raw)
                .map_err(|e| rustls::Error::General(format!("garnet K3 signature encode: {e}")))
        }

        fn scheme(&self) -> SignatureScheme {
            SignatureScheme::ECDSA_NISTP256_SHA256
        }
    }

    /// A raw-scalar [`Es256Signer`] — the CI handshake test's stand-in for the Secure Enclave. It
    /// exercises the *exact* [`BrokerK3SigningKey`] → rustls path production uses, decorrelated from
    /// the SE hardware (the SE `sign` leg itself is proven by the on-device follow, #208-style). Not
    /// a production key home (the software tier uses rustls's built-in `with_single_cert`).
    #[cfg(test)]
    pub(crate) struct RawEs256Signer {
        scalar: [u8; 32],
    }

    #[cfg(test)]
    impl RawEs256Signer {
        pub(crate) fn new(scalar: [u8; 32]) -> Self {
            Self { scalar }
        }
    }

    #[cfg(test)]
    impl std::fmt::Debug for RawEs256Signer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("RawEs256Signer")
                .field("scalar", &"<redacted>")
                .finish()
        }
    }

    #[cfg(test)]
    impl Es256Signer for RawEs256Signer {
        fn sign_es256(&self, msg: &[u8]) -> Result<[u8; 64]> {
            Ok(signet_crypto::ecdsa::sign_es256(&self.scalar, msg)?)
        }
    }
}

#[cfg(any(target_os = "macos", test))]
pub(crate) use signer::BrokerK3SigningKey;
#[cfg(test)]
pub(crate) use signer::RawEs256Signer;
#[cfg(target_os = "macos")]
pub(crate) use signer::SeEs256Signer;

#[cfg(test)]
mod tests {
    // `BrokerK3SigningKey` + `RawEs256Signer` come in via the re-exports (`use super::*`).
    use super::*;
    use rustls::sign::SigningKey;
    use rustls::{SignatureAlgorithm, SignatureScheme};
    use std::sync::Arc;

    /// The custom signer produces a valid `ES256` signature that verifies under the raw
    /// scalar's public key — the crypto contract the rustls handshake relies on. (The full
    /// mutual-TLS handshake through this signer is proven in `broker.rs`'s
    /// `mtls_round_trip_se_signer`.)
    #[test]
    fn signer_produces_verifiable_es256() {
        let (scalar, pubkey) = signet_crypto::ecdsa::generate_keypair();
        let sk = BrokerK3SigningKey::new(Arc::new(RawEs256Signer::new(scalar)));
        let signer = sk
            .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
            .expect("the ECDSA P-256 scheme is offered");
        assert_eq!(signer.scheme(), SignatureScheme::ECDSA_NISTP256_SHA256);
        let msg = b"garnet K3 CertificateVerify transcript stand-in";
        let der = signer.sign(msg).expect("sign");
        // rustls wants DER for this scheme; it must verify under the key's public half.
        signet_crypto::ecdsa::verify_es256(&pubkey, msg, &der).expect("the DER signature verifies");
    }

    #[test]
    fn declines_an_unoffered_scheme() {
        let (scalar, _) = signet_crypto::ecdsa::generate_keypair();
        let sk = BrokerK3SigningKey::new(Arc::new(RawEs256Signer::new(scalar)));
        // Only ECDSA P-256 / SHA-256 is Garnet's PKI scheme — anything else is declined.
        assert!(sk.choose_scheme(&[SignatureScheme::ED25519]).is_none());
        assert!(sk.choose_scheme(&[]).is_none());
    }

    #[test]
    fn algorithm_is_ecdsa() {
        let (scalar, _) = signet_crypto::ecdsa::generate_keypair();
        let sk = BrokerK3SigningKey::new(Arc::new(RawEs256Signer::new(scalar)));
        assert_eq!(sk.algorithm(), SignatureAlgorithm::ECDSA);
    }

    /// Generation labels: correct shape (prefix + exactly 16 lowercase hex), unique per call.
    #[test]
    fn generation_labels_are_well_formed_and_unique() {
        let a = broker_k3_generation_label();
        let b = broker_k3_generation_label();
        for l in [&a, &b] {
            let suffix = l
                .strip_prefix("signet-garnet-broker-k3-")
                .expect("generation label carries the prefix");
            assert_eq!(suffix.len(), 16, "8 CSPRNG bytes hex-encode to 16 chars");
            assert!(
                suffix
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
                "lowercase hex only: {l}"
            );
        }
        assert_ne!(a, b, "two provisions never share a label");
    }

    /// The stale-label classifier: sweeps the legacy fixed label and other generations, never
    /// the live label, and is structurally unable to match a PRSN `<handle>-<purpose>` label —
    /// including the adversarial handle that shares the textual prefix.
    #[test]
    fn stale_label_classifier_is_strict() {
        let live = "signet-garnet-broker-k3-0123456789abcdef";
        // Sweepable: the legacy fixed label + a different generation.
        assert!(is_stale_broker_k3_label(BROKER_K3_SE_LABEL, live));
        assert!(is_stale_broker_k3_label(
            "signet-garnet-broker-k3-fedcba9876543210",
            live
        ));
        // Never the live label itself.
        assert!(!is_stale_broker_k3_label(live, live));
        // Never a PRSN label — even one whose handle shares the prefix. A PRSN handle ends in
        // `-ai`, so its labels' suffixes are never exactly-16-hex.
        assert!(!is_stale_broker_k3_label(
            "signet-garnet-broker-k3-ai-signing",
            live
        ));
        assert!(!is_stale_broker_k3_label("hlin-260730a-ai-signing", live));
        assert!(!is_stale_broker_k3_label("hlin-260730a-ai-kem-pq", live));
        // Malformed suffixes: wrong length, uppercase hex, non-hex.
        assert!(!is_stale_broker_k3_label(
            "signet-garnet-broker-k3-abc",
            live
        ));
        assert!(!is_stale_broker_k3_label(
            "signet-garnet-broker-k3-0123456789ABCDEF",
            live
        ));
        assert!(!is_stale_broker_k3_label(
            "signet-garnet-broker-k3-0123456789abcdeg",
            live
        ));
        // Unrelated labels untouched.
        assert!(!is_stale_broker_k3_label("some-other-key", live));
    }

    #[test]
    fn key_home_debug_redacts_raw_key() {
        let home = BrokerK3KeyHome::RawPkcs8(vec![1, 2, 3, 4]);
        let dbg = format!("{home:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(dbg.contains("pkcs8_len"));
        assert!(!dbg.contains("1, 2, 3, 4"));
        // The SE label is a non-secret Keychain handle.
        let se = BrokerK3KeyHome::SecureEnclave {
            label: BROKER_K3_SE_LABEL.to_string(),
        };
        assert!(format!("{se:?}").contains(BROKER_K3_SE_LABEL));
    }
}
