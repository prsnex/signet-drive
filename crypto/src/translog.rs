// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Public-key transparency-log canonical bytes (Envelope §10 / Transparency Log
//! Spec v06 §3.3 / Schema v10 §21).
//!
//! Two B4 pieces live here: the per-entry [`entry_hash`] (the SHA-256 that forms
//! the log's tamper-evident hash chain — every `pubkey_log` row is born with one),
//! and the [`receipt_signing_input`] for the §10a log receipt (the CT/SCT-style
//! immediate-trust signal the server ES256-signs at INSERT time). The *aggregate*
//! Merkle tree (leaf/internal/root hashes, inclusion/consistency proofs, the
//! periodic root publication) is B5 and lands here later.

use serde_json::Value;

use crate::error::Result;
use crate::hash;
use crate::jcs;

/// The `pubkey_log.key_purpose` enum, with its fixed `entry_hash` byte mapping
/// (P-015 / P-016): `signing = 0x01`, `kem = 0x02` — matching the Schema §21
/// `CHECK IN ('signing', 'kem')` order. The byte is part of the signed `entry_hash`
/// preimage, so the mapping is load-bearing for cross-implementation portability.
///
/// The v2 entry format (PQR Transparency-Log ops doc §2, item 7a) adds the hybrid
/// PQ purposes — `signing_pq = 0x03` (ML-DSA-87) and `kem_pq = 0x04`
/// (ML-KEM-1024) — and `epoch = 0x00`, the v1→v2 cutover checkpoint entry (the
/// rule boundary recorded IN the chain; ops doc §2/§3a). `0x00` marks it as
/// not-a-key; the key purposes stay 1–4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPurpose {
    Epoch,
    Signing,
    Kem,
    SigningPq,
    KemPq,
}

impl KeyPurpose {
    /// The 1-byte enum value used in the `entry_hash` canonical bytes.
    pub fn as_byte(self) -> u8 {
        match self {
            KeyPurpose::Epoch => 0x00,
            KeyPurpose::Signing => 0x01,
            KeyPurpose::Kem => 0x02,
            KeyPurpose::SigningPq => 0x03,
            KeyPurpose::KemPq => 0x04,
        }
    }
}

/// The per-entry `pubkey_log.entry_hash` = `SHA-256(canonical_bytes)`, where the
/// canonical bytes are the byte-by-byte concatenation (Envelope §10 / Transparency
/// Log Spec §3.3 — all multi-byte integers **big-endian**):
///
/// ```text
/// uint64_be(entry_id)                       // 8
///   || account_id (16 raw UUID bytes)       // 16
///   || uint8(key_purpose)                   // 1   (signing=0x01, kem=0x02)
///   || uint32_be(algorithm utf8 len)        // 4
///   || algorithm utf8 bytes                 // L
///   || public_key (X9.63, 65 bytes for P-256)
///   || uint64_be(created_at unix seconds)   // 8
///   || prev_entry_hash (32 bytes; all-zero for the genesis entry)
/// ```
///
/// `account_id` is the raw 16-byte UUID (NOT the 36-char hyphenated form);
/// `prev_entry_hash` is `[0u8; 32]` for `entry_id == 1`. `created_at` is unix
/// **seconds**. The chain (each entry commits to the previous `entry_hash`) makes
/// any retroactive edit detectable.
pub fn entry_hash(
    entry_id: u64,
    account_id: &[u8; 16],
    key_purpose: KeyPurpose,
    algorithm: &str,
    public_key: &[u8],
    created_at: u64,
    prev_entry_hash: &[u8; 32],
) -> [u8; 32] {
    let alg = algorithm.as_bytes();
    let mut buf = Vec::with_capacity(134 + alg.len());
    buf.extend_from_slice(&entry_id.to_be_bytes());
    buf.extend_from_slice(account_id);
    buf.push(key_purpose.as_byte());
    buf.extend_from_slice(&(alg.len() as u32).to_be_bytes());
    buf.extend_from_slice(alg);
    buf.extend_from_slice(public_key);
    buf.extend_from_slice(&created_at.to_be_bytes());
    buf.extend_from_slice(prev_entry_hash);
    hash::sha256(&buf)
}

/// The 1-byte entry-format version hashed FIRST in a v2 preimage. An unhashed
/// field that selects the hashing rule would be a canonicalization ambiguity in
/// an append-only Merkle structure (ops doc §2, Gus C2 A1 — MUST), so the
/// version lives inside the hashed bytes.
pub const ENTRY_VERSION_V2: u8 = 0x02;

/// The per-entry `entry_hash` under the **v2** canonical bytes (PQR
/// Transparency-Log ops doc §2 — the hybrid-identity entry format, item 7a):
///
/// ```text
/// uint8(entry_version = 0x02)               // 1   (INSIDE the hashed bytes)
///   || uint64_be(entry_id)                  // 8
///   || account_id (16 raw UUID bytes)       // 16  (all-zero when NULL — see below)
///   || uint8(key_purpose)                   // 1   (epoch=0x00, signing=0x01, kem=0x02,
///                                           //      signing_pq=0x03, kem_pq=0x04)
///   || uint32_be(algorithm utf8 len)        // 4
///   || algorithm utf8 bytes                 // L
///   || uint32_be(public_key len)            // 4   (NEW vs v1: length-prefixed —
///   || public_key bytes                     // K    fits ML-KEM ek 1568 B / ML-DSA vk 2592 B)
///   || uint64_be(created_at unix seconds)   // 8
///   || prev_entry_hash (32 bytes)           // 32
/// ```
///
/// `account_id = None` (an account-less entry — the epoch checkpoint; later the
/// server's own keys) hashes as 16 zero bytes, mirroring the v1 genesis
/// `prev_entry_hash` convention. v1 entries already in the chain keep the v1
/// rule ([`entry_hash`]) forever — a verifier selects the rule per entry from
/// the version byte its recomputation must match, with the epoch checkpoint
/// marking the boundary in-chain (ops doc §2/§6.3).
pub fn entry_hash_v2(
    entry_id: u64,
    account_id: Option<&[u8; 16]>,
    key_purpose: KeyPurpose,
    algorithm: &str,
    public_key: &[u8],
    created_at: u64,
    prev_entry_hash: &[u8; 32],
) -> [u8; 32] {
    let alg = algorithm.as_bytes();
    let mut buf = Vec::with_capacity(139 + alg.len() + public_key.len());
    buf.push(ENTRY_VERSION_V2);
    buf.extend_from_slice(&entry_id.to_be_bytes());
    buf.extend_from_slice(account_id.unwrap_or(&[0u8; 16]));
    buf.push(key_purpose.as_byte());
    buf.extend_from_slice(&(alg.len() as u32).to_be_bytes());
    buf.extend_from_slice(alg);
    buf.extend_from_slice(&(public_key.len() as u32).to_be_bytes());
    buf.extend_from_slice(public_key);
    buf.extend_from_slice(&created_at.to_be_bytes());
    buf.extend_from_slice(prev_entry_hash);
    hash::sha256(&buf)
}

/// The v1→v2 cutover checkpoint's fixed field values (ops doc §2 — "the cutover
/// is itself recorded as a log entry"; §3a — it doubles as the epoch marker the
/// completeness rule keys off). One per log, account-less, written by the server
/// immediately before the first v2 entry. The `public_key` payload is this
/// descriptive tag (the v2 length prefix makes any payload well-defined); its
/// fingerprint is the standard raw-bytes fingerprint of the tag.
pub const EPOCH_ALGORITHM: &str = "signet-translog-v2";
/// The epoch checkpoint's `public_key` payload bytes.
pub const EPOCH_PAYLOAD: &[u8] = b"signet-pubkey-log-v2-epoch";

/// The 1-byte entry-format version hashed FIRST in a v3 preimage: the epoch-2
/// format (Transparency-Log Epoch-2 design v03 §2–§3), where an entry names its
/// account by the VRF index ([`crate::vrf`]) instead of the account id, so a
/// deletion leaves nothing in the log to forget.
pub const ENTRY_VERSION_V3: u8 = 0x03;

/// The per-entry `entry_hash` under the **v3** canonical bytes: v2's layout with
/// the 16-byte account id replaced by the 64-byte VRF account index.
///
/// ```text
/// uint8(entry_version = 0x03)               // 1   (INSIDE the hashed bytes)
///   || uint64_be(entry_id)                  // 8   (1-based within the epoch)
///   || account_index (64 bytes)             // 64  (VRF output β; all-zero when None)
///   || uint8(key_purpose)                   // 1
///   || uint32_be(algorithm utf8 len)        // 4
///   || algorithm utf8 bytes                 // L
///   || uint32_be(public_key len)            // 4
///   || public_key bytes                     // K
///   || uint64_be(created_at unix seconds)   // 8
///   || prev_entry_hash (32 bytes)           // 32  (all-zero for the epoch's genesis)
/// ```
///
/// `account_index = None` is an account-less entry (the epoch's genesis entry)
/// and hashes as 64 zero bytes, as v2 hashed a NULL account as 16.
pub fn entry_hash_v3(
    entry_id: u64,
    account_index: Option<&[u8; crate::vrf::INDEX_LEN]>,
    key_purpose: KeyPurpose,
    algorithm: &str,
    public_key: &[u8],
    created_at: u64,
    prev_entry_hash: &[u8; 32],
) -> [u8; 32] {
    let alg = algorithm.as_bytes();
    let mut buf = Vec::with_capacity(122 + alg.len() + public_key.len());
    buf.push(ENTRY_VERSION_V3);
    buf.extend_from_slice(&entry_id.to_be_bytes());
    buf.extend_from_slice(account_index.unwrap_or(&[0u8; crate::vrf::INDEX_LEN]));
    buf.push(key_purpose.as_byte());
    buf.extend_from_slice(&(alg.len() as u32).to_be_bytes());
    buf.extend_from_slice(alg);
    buf.extend_from_slice(&(public_key.len() as u32).to_be_bytes());
    buf.extend_from_slice(public_key);
    buf.extend_from_slice(&created_at.to_be_bytes());
    buf.extend_from_slice(prev_entry_hash);
    hash::sha256(&buf)
}

/// The algorithm field of an epoch-2-or-later genesis entry.
pub const EPOCH_ALGORITHM_V3: &str = "signet-translog-v3";
/// The tag that opens a v3 genesis entry's payload.
pub const EPOCH_PAYLOAD_V3_TAG: &[u8] = b"signet-pubkey-log-v3-epoch";

/// The `public_key` payload of a v3 genesis entry, which binds the new epoch to
/// the one it succeeds and to the epoch's VRF key, inside the chain (design v03
/// §3.2 and §2a):
///
/// ```text
/// EPOCH_PAYLOAD_V3_TAG || 0x00
///   || uint16_be(epoch)                     // 2
///   || uint64_be(previous epoch's final log_size)
///   || previous epoch's final Merkle root   // 32
///   || SHA-256(this epoch's VRF public key) // 32
/// ```
///
/// A client accepts a new epoch only if the published roots file carries the
/// previous epoch's end line with this `(size, root)`, and the VRF key file a
/// line for this epoch whose key hashes to this value.
pub fn epoch_payload_v3(
    epoch: u16,
    prev_epoch_size: u64,
    prev_epoch_root: &[u8; 32],
    vrf_public_key: &[u8; crate::vrf::PUBLIC_KEY_LEN],
) -> Vec<u8> {
    let mut p = Vec::with_capacity(EPOCH_PAYLOAD_V3_TAG.len() + 1 + 2 + 8 + 32 + 32);
    p.extend_from_slice(EPOCH_PAYLOAD_V3_TAG);
    p.push(0x00);
    p.extend_from_slice(&epoch.to_be_bytes());
    p.extend_from_slice(&prev_epoch_size.to_be_bytes());
    p.extend_from_slice(prev_epoch_root);
    p.extend_from_slice(&hash::sha256(vrf_public_key));
    p
}

/// The domain-separation prefix for log-receipt signatures (Envelope §10a).
const RECEIPT_PREFIX: &[u8] = b"signet-pubkey-log-receipt-v1\n";

/// The FIPS 204 context for the ML-DSA-87 half of the server's §10a receipt
/// dual-signature (PQR Spec §8 point 4, item 7c). The purpose LABEL — the
/// prefix name WITHOUT the trailing `\n` (the newline is the signing input's
/// framing byte, not part of the label). Both halves sign the identical bytes
/// ([`receipt_signing_input`] over the receipt object with EVERY
/// `server_signature*` field removed); the ML-DSA half takes this as the
/// FIPS 204 context *parameter*. Pinned by the §11.5b KAT.
pub const RECEIPT_MLDSA_CTX: &[u8] = b"signet-pubkey-log-receipt-v1";

/// The bytes the server ES256-signs to produce a log receipt's `server_signature`
/// (Envelope §10a): `"signet-pubkey-log-receipt-v1\n" || JCS(receipt_without_signature)`.
///
/// `receipt` is the receipt JSON object **excluding** the `server_signature` field
/// (which is the output of signing these bytes). The same builder reconstructs the
/// bytes on the verifier side, so server and CLI/watcher agree byte-for-byte.
pub fn receipt_signing_input(receipt: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(RECEIPT_PREFIX.len() + 256);
    out.extend_from_slice(RECEIPT_PREFIX);
    out.extend_from_slice(&jcs::to_canonical_bytes(receipt)?);
    Ok(out)
}
