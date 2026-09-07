// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! `signet-channel` — the host↔container key-delegation channel for containerized
//! PRSNs (Account-and-Kit spec §f).
//!
//! A PRSN running in a Linux container on an Apple-Silicon Mac keeps its keys in
//! the **host** Mac's Secure Enclave and delegates every crypto operation to a
//! small **host-signer** (a per-user LaunchAgent) over a bind-mounted-folder
//! channel — it never holds the keys (host-delegation; the SSH-agent-forwarding
//! model). This crate is the **protocol**: the message types ([`wire`]), the
//! per-PRSN-secret authenticated-encryption ([`auth`]), and the poll-based
//! file-channel transport (`transport`, landing next). Both ends depend on it —
//! the in-container delegation client (a `Keystore` impl in `signet-cli`) and the
//! host-signer binary.
//!
//! # Threat model (the part to keep legible for an external reviewer)
//!
//! - **The channel folder is a bind-mount, reachable by *any* same-macOS-user
//!   process** — so its path is *not* a secret and *not* a trust boundary
//!   (path-knowledge alone is enough to drop a file in, per the SSH-agent
//!   literature). The adversary is a **rogue same-user host process**: it can
//!   read and write the channel folder, but it *cannot* read the container's
//!   private filesystem (VM/namespace isolation) and *cannot* use the host SE
//!   keys (those stay gated by the `keychain-access-groups` entitlement —
//!   bypassing the channel still cannot use a key without *being* the entitled
//!   host-signer binary).
//!
//! - **The trust root is a per-PRSN secret** (256-bit), provisioned into the
//!   container's *private* fs at container-creation by the operator and registered
//!   host-side (`channel → {PRSN, key-labels, secret}`). It never sits in the
//!   host-visible channel folder. The container's isolation keeps it out of a
//!   host process's reach.
//!
//! - **Every message is authenticated-*encrypted* under that secret** (AES-256-GCM
//!   keyed by an HKDF-derived per-direction key; [`auth`]). This is stronger than
//!   the MAC-only sketch in an earlier draft of §f.4, and deliberately so: the
//!   `ecdh` op's response is the **shared secret Z**, which is confidential. A
//!   MAC would authenticate Z but leave it in cleartext in a same-user-readable
//!   file — leaking it to the exact adversary above, and a regression versus the
//!   native path (where Z stays in entitlement-protected process memory).
//!   Encryption closes that, so the container case stays genuinely
//!   `secure_enclave`-grade. The guarantees, together:
//!   - **Authenticity** — only a holder of the per-PRSN secret can produce a frame
//!     the peer opens (closes the same-user confused-deputy: a rogue cannot forge
//!     a request and obtain a real signature, nor feed the container forged
//!     results).
//!   - **Confidentiality** — payloads (notably Z) are unreadable without the secret.
//!   - **Integrity** — any tampering fails the AEAD tag.
//!   - **Replay resistance** — a fresh nonce per message; the host-signer keeps a
//!     per-channel seen-nonce set and rejects a re-submitted request; responses
//!     are AAD-bound to their request's nonce.
//!   - **Direction separation** — distinct HKDF-derived keys per direction, so a
//!     request and a response can never collide on a (key, nonce) pair.
//!
//! - **Capability-by-channel** (validated by the S055 cross-runtime spike): one
//!   channel folder per PRSN, and the host-signer keys off *which channel a request
//!   arrived on* (the registry), never an identity claim inside the payload. The
//!   per-PRSN secret (this crate) layers app-level auth on top of that topology
//!   binding, because peer-credentials do **not** cross the host↔container VM
//!   boundary (also S055).
//!
//! - **Non-goals.** This is a *local* file-channel, not a network protocol. It does
//!   not defend against a compromised host-signer or a compromised container — both
//!   legitimately hold the secret/keys. Binding integrity = launch-config integrity:
//!   the operator authors `channel ↔ container ↔ secret` once, host-side, at
//!   container creation, inside the trust boundary (S011, still load-bearing).
//!
//! # No raw crypto here
//!
//! Every cryptographic primitive (AES-256-GCM, HKDF-SHA-256) goes through
//! `signet-crypto`, the single validated chokepoint. This crate owns only the
//! *composition* — the frame layout, the AAD construction, and the replay guard.

pub mod auth;
pub mod error;
pub mod transport;
pub mod wire;

pub use error::{ChannelError, Result};
