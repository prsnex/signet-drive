// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Signet Drive shared cryptography crate.
//!
//! # Off-the-shelf only
//!
//! Per the v1 assurance model, this crate uses **off-the-shelf primitives only**
//! (the RustCrypto family) — chosen because they are pure-Rust with their own
//! audit history *and* of a different lineage from the OpenSSL-family oracle the
//! harness differential-tests against (unlike `ring`, which is BoringSSL-derived
//! and shares OpenSSL's lineage). The only genuinely novel surface is the
//! **glue**: how primitives are composed (the `ECDH-ES+A256KW` wrap chain) and
//! the SigDrive-specific canonical byte layouts (SIGNET-V1 signing bytes, the
//! Concat-KDF `OtherInfo`, the transparency-log `entry_hash`).
//!
//! # Validation is the assurance backbone
//!
//! v1 ships with no external cryptographic audit, so byte-level validation
//! *is* the review mechanism. Every operation is checked at one of four tiers,
//! by an oracle **independent of this crate** (differential-testing RustCrypto
//! against RustCrypto proves nothing):
//!
//! 1. **Primitives** (`AES-256-GCM`, `AES-256-KW`, `ECDH P-256`, `ECDSA P-256`,
//!    `HKDF-SHA-256`, `HMAC-SHA-256`, `SHA-256`) → published **NIST/RFC
//!    known-answer tests** +
//!    byte-for-byte **differential vs OpenSSL** (a separate C codebase). High
//!    assurance.
//! 2. **JOSE-standardized composition** (the `ECDH-ES+A256KW` wrap envelope) →
//!    differential vs an **independent JOSE library** — validates RFC-7518
//!    conformance, not mere self-consistency.
//! 3. **WebAuthn JSON shapes** → differential vs **SimpleWebAuthn**.
//! 4. **Our genuinely-novel composition** (SIGNET-V1 bytes, the Concat-KDF
//!    `OtherInfo` incl. the `root_folder_id` binding) → the golden
//!    `docs/design/test-vectors/` values, which prove *impl-matches-spec* but
//!    **cannot** prove *spec-is-sound*. That gap is the **named residual risk**,
//!    carried by the open/reproducible posture + the webauthn-rs upstream +
//!    decorrelation-if-needed — not by the harness.
//!
//! # What lives here now (Phase 2 / B0 + B1)
//!
//! B0 provided the **tier-1 validated primitives** (`aead`, `keywrap`, `kdf`,
//! `ecdh`, `ecdsa`, `hash`) and the harness framework. B1 adds the **wrap-chain
//! composition**: `concatkdf` (Concat-KDF-SHA-256 + the JOSE `OtherInfo`),
//! `wrap` (the `ECDH-ES+A256KW` DEK + metadata-key envelopes, with the P-015
//! folder binding), `envelope` (the single-PUT file ciphertext frame), and
//! `pubkey` (SPKI fingerprints). These are validated by tier-3 (panva/jose
//! golden vectors) and tier-4 (golden file-envelope bytes) in
//! `crypto/tests/golden_vectors.rs`. B2 adds `signing` (the SIGNET-V1
//! per-request canonical bytes, the shared source of truth for the `signet` CLI
//! signer and the server verifier). B3 adds `kem_wrap` (the human-side
//! PRF→wrap-key→AES-256-GCM chain that protects the human ECDH KEM private key;
//! Envelope §8) — the reference impl + golden vectors pinning the browser's
//! WebCrypto chain. B4 adds the canonical bytes the server ES256-signs (and
//! verifiers reconstruct): `jcs` (RFC 8785 JSON canonicalization), `attest` (the
//! §9 server-signed verification-response signing input), and `translog` (the
//! `pubkey_log` `entry_hash` composition + the §10a log-receipt signing input).
//! Still ahead: the aggregate transparency-log Merkle tree + inclusion/consistency
//! proofs (B5). See `Signet-Drive-Build-Plan`.
//!
//! The **PQR arc** (the `Signet-Drive-PQR-Build-Plan`) extends the crate for the
//! v1 hybrid post-quantum re-fit: `hybrid_wrap` (item 3) is the SP 800-227 §4.6
//! hybrid content-wrap combiner + envelope (`ECDH-ES+ML-KEM-1024+A256KW`, PQR
//! Crypto Spec §3–§5), byte-pinned by the A3 co-signed KeyCombine KAT.

pub mod aead;
pub mod alg;
pub mod attest;
pub mod concatkdf;
pub mod ecdh;
pub mod ecdsa;
pub mod encname;
pub mod envelope;
pub mod error;
pub mod garnet_token;
pub mod hash;
pub mod hybrid_wrap;
pub mod jcs;
pub mod kdf;
pub mod kem_wrap;
pub mod keywrap;
pub mod mac;
pub mod merkle;
pub mod pubkey;
pub mod signing;
pub mod translog;
pub mod wrap;
pub mod x509;

pub use alg::AlgId;
pub use error::{CryptoError, Result};
