// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Algorithm-identifier registry (Envelope Format v09 §3).
//!
//! Every signed or encrypted object carries a JOSE algorithm identifier so the
//! server can dispatch on it. v1 → v2 (ML-KEM-1024 / ML-DSA-87) is purely
//! additive: new variants, same dispatch shape.

use crate::error::CryptoError;

/// A v1 algorithm identifier (RFC 7518 names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlgId {
    /// `A256GCM` — AES-256-GCM authenticated encryption (RFC 7518 §5.3).
    A256Gcm,
    /// `ECDH-ES+A256KW` — ephemeral-static ECDH P-256 → Concat-KDF-SHA-256 →
    /// AES-256 Key Wrap (RFC 7518 §4.6 + NIST SP 800-56A §5.8.1 + RFC 3394).
    EcdhEsA256Kw,
    /// `ECDH-ES+ML-KEM-1024+A256KW` — the **hybrid** content-wrap: P-256 ECDH ⊕
    /// ML-KEM-1024 combined via the NIST SP 800-227 §4.6 two-step HKDF KDM →
    /// AES-256 Key Wrap (PQR Crypto Spec §3–§5). Secure if *either* KEM half
    /// holds (monotonicity). Additive to the classical `ECDH-ES+A256KW`, which
    /// stays readable.
    EcdhEsMlKem1024A256Kw,
    /// `ES256` — ECDSA P-256 with SHA-256 (RFC 7518 §3.4).
    Es256,
}

impl AlgId {
    /// The canonical JOSE identifier string.
    pub const fn as_jose(self) -> &'static str {
        match self {
            AlgId::A256Gcm => "A256GCM",
            AlgId::EcdhEsA256Kw => "ECDH-ES+A256KW",
            AlgId::EcdhEsMlKem1024A256Kw => "ECDH-ES+ML-KEM-1024+A256KW",
            AlgId::Es256 => "ES256",
        }
    }

    /// Parse a JOSE identifier. Anything outside the active v1 registry is
    /// [`CryptoError::UnknownAlgorithm`] — the dispatch point a v2 client hitting
    /// a v1 server (or vice versa) lands on.
    ///
    /// The pure post-quantum `ML-KEM-1024+A256KW` endpoint (PQR Spec §3, the v3
    /// horizon) is deliberately **absent** from this active registry: seen in a
    /// v1 envelope it lands here as `UnknownAlgorithm` and is rejected — the
    /// "reserved / not-enabled → reject" rule. It is not enabled until a
    /// classical-hedge-retirement decision that does not exist in v1.
    pub fn from_jose(s: &str) -> Result<Self, CryptoError> {
        match s {
            "A256GCM" => Ok(AlgId::A256Gcm),
            "ECDH-ES+A256KW" => Ok(AlgId::EcdhEsA256Kw),
            "ECDH-ES+ML-KEM-1024+A256KW" => Ok(AlgId::EcdhEsMlKem1024A256Kw),
            "ES256" => Ok(AlgId::Es256),
            _ => Err(CryptoError::UnknownAlgorithm),
        }
    }
}
