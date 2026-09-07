// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! File ciphertext envelope — single-PUT (Envelope §4.1).
//!
//! On-disk layout in Object Storage:
//!
//! ```text
//! [1 byte magic 0x01] [1 byte alg 0x01 = A256GCM] [12-byte IV] [N-byte ciphertext] [16-byte GCM tag]
//! ```
//!
//! The AAD is the file's `file_id` (16 raw UUID bytes), **not stored** — both
//! sides reconstruct it. It binds the ciphertext to its file so the storage
//! layer cannot substitute one blob for another (the tag fails on a mismatch).
//! The 32-byte DEK is fresh per file and wrapped to each recipient via the
//! [`crate::wrap`] envelope; the 12-byte IV is fresh random per file (the
//! caller supplies it — GCM nonce reuse under one key is catastrophic).
//!
//! ## Multipart (§4.2, `0x02` magic)
//!
//! Large files (> the single-PUT cap) are split into chunks, each sealed
//! independently with [`seal_chunk`]. The per-chunk IV is **HKDF-derived** from
//! the DEK + chunk index (not random) so every chunk under one DEK gets a unique
//! nonce without a per-chunk random draw, and the AAD is
//! `file_id || chunk_index || is_last` so a chunk cannot be moved between files,
//! reordered within a file, or **silently truncated**. `is_last` (whether this is
//! the file's terminal chunk, derived from the caller's `chunk_count`) is
//! authenticated, so dropping the real last chunk and lowering the reported count
//! makes the new boundary chunk fail to open — it was sealed `is_last = false`. The
//! external `chunk_count` is thus self-authenticating against truncation rather than
//! trusted. The transport (direct-to-object-storage pre-signed multipart) lives
//! above this module (the Large-File Direct-to-Storage Design doc); this module owns
//! only the chunk byte format.

use crate::error::{CryptoError, Result};
use crate::{aead, kdf};

/// Single-PUT envelope-format-version byte (§4.1).
pub const FILE_MAGIC_SINGLE_PUT: u8 = 0x01;
/// Algorithm byte for `A256GCM` (§4.1).
pub const FILE_ALG_A256GCM: u8 = 0x01;

/// Header (magic + alg) + IV length: the fixed prefix before the ciphertext.
const HEADER_LEN: usize = 2 + 12;
/// Smallest valid envelope: header + a 16-byte tag (an empty-plaintext file).
const MIN_ENVELOPE_LEN: usize = HEADER_LEN + 16;

/// Seal a plaintext file into the single-PUT envelope (§4.1). `iv` MUST be
/// unique per `dek`; AAD is the 16-byte `file_id`.
pub fn seal_file(
    dek: &[u8; 32],
    iv: &[u8; 12],
    file_id: &[u8; 16],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let sealed = aead::seal(dek, iv, plaintext, file_id)?; // ciphertext || tag
    let mut out = Vec::with_capacity(HEADER_LEN + sealed.len());
    out.push(FILE_MAGIC_SINGLE_PUT);
    out.push(FILE_ALG_A256GCM);
    out.extend_from_slice(iv);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Open a single-PUT envelope: validate the magic + alg bytes, split the IV,
/// and AEAD-open with AAD = `file_id`. Returns the plaintext, or
/// [`CryptoError::Authentication`] on a wrong DEK / wrong `file_id` / tamper,
/// or [`CryptoError::InvalidInput`] on a structurally malformed envelope.
pub fn open_file(dek: &[u8; 32], file_id: &[u8; 16], envelope: &[u8]) -> Result<Vec<u8>> {
    if envelope.len() < MIN_ENVELOPE_LEN {
        return Err(CryptoError::InvalidInput("file envelope too short"));
    }
    if envelope[0] != FILE_MAGIC_SINGLE_PUT {
        return Err(CryptoError::InvalidInput("file envelope magic"));
    }
    if envelope[1] != FILE_ALG_A256GCM {
        return Err(CryptoError::InvalidInput("file envelope alg"));
    }
    let iv: [u8; 12] = envelope[2..HEADER_LEN]
        .try_into()
        .expect("HEADER_LEN - 2 == 12");
    aead::open(dek, &iv, &envelope[HEADER_LEN..], file_id)
}

// --- §4.2 Multipart (large files) -------------------------------------------

/// Multipart-chunk envelope-format-version byte (§4.2).
pub const FILE_MAGIC_MULTIPART: u8 = 0x02;

/// HKDF `info`-label prefix for per-chunk IV derivation (§4.2). The full `info`
/// is this label followed by the 4-byte big-endian chunk index.
const MULTIPART_IV_LABEL: &[u8] = b"signet-drive-multipart-iv-v1";

/// Multipart header: magic + alg + 4-byte chunk_index + 12-byte IV (= 18 bytes).
const MULTIPART_HEADER_LEN: usize = 2 + 4 + 12;
/// Smallest valid chunk: header + a 16-byte tag (an empty final chunk).
const MULTIPART_MIN_ENVELOPE_LEN: usize = MULTIPART_HEADER_LEN + 16;

/// The fixed per-chunk envelope overhead (§4.2): header (18) + GCM tag (16) = **34 bytes**.
/// Public because it is the ONE home for this wire fact — the server derives a file's
/// plaintext size from its stored ciphertext size with it (bug083); restating "34"
/// anywhere else is the two-homes drift class.
pub const MULTIPART_CHUNK_OVERHEAD: u64 = MULTIPART_MIN_ENVELOPE_LEN as u64;

/// Invert the §4.2 framing: the exact plaintext length of a chunked file, from its
/// total on-disk ciphertext length and the per-chunk plaintext `chunk_size` (bug083).
///
/// Every chunk carries exactly [`MULTIPART_CHUNK_OVERHEAD`] bytes of framing, and a
/// file of plaintext `p` has `max(1, ceil(p / chunk_size))` chunks (an empty file is
/// one empty final chunk). So `ciphertext = p + 34·n`, which inverts exactly as
/// `n = ceil(ciphertext / (chunk_size + 34))`, then `p = ciphertext − 34·n`.
///
/// Returns `None` for inputs that cannot be a valid §4.2 framing (zero/negative
/// `chunk_size`, or a ciphertext smaller than one empty chunk) rather than a wrong
/// number — a display layer falls back to showing nothing, never a fabrication.
pub fn multipart_plaintext_len(ciphertext_len: u64, chunk_size: u64) -> Option<u64> {
    if chunk_size == 0 || ciphertext_len < MULTIPART_CHUNK_OVERHEAD {
        return None;
    }
    let per = chunk_size + MULTIPART_CHUNK_OVERHEAD;
    let chunks = ciphertext_len.div_ceil(per).max(1);
    ciphertext_len.checked_sub(chunks * MULTIPART_CHUNK_OVERHEAD)
}

/// Derive the deterministic per-chunk IV (§4.2): HKDF-SHA-256 over the DEK, empty
/// salt, `info = MULTIPART_IV_LABEL || chunk_index_be`. Deterministic per
/// (DEK, chunk_index) — guarantees nonce uniqueness across a file's chunks without
/// a per-chunk random draw (a repeated GCM nonce under one key is catastrophic).
fn multipart_iv(dek: &[u8; 32], chunk_index: u32) -> Result<[u8; 12]> {
    let mut info = Vec::with_capacity(MULTIPART_IV_LABEL.len() + 4);
    info.extend_from_slice(MULTIPART_IV_LABEL);
    info.extend_from_slice(&chunk_index.to_be_bytes());
    let iv = kdf::hkdf_sha256(dek, &[], &info, 12)?;
    iv.try_into()
        .map_err(|_| CryptoError::InvalidInput("multipart iv length"))
}

/// The §4.2 chunk AAD: `file_id` (16) || `chunk_index_be` (4) || `is_last` (1) =
/// 21 bytes. Binds the chunk to its file, its position, AND whether it is the
/// file's terminal chunk — defending against chunk substitution (wrong file),
/// reordering (wrong position), and whole-chunk truncation (dropping the trailing
/// chunk and lowering the count makes the new boundary chunk's `is_last` mismatch).
fn multipart_aad(file_id: &[u8; 16], chunk_index: u32, is_last: bool) -> [u8; 21] {
    let mut aad = [0u8; 21];
    aad[..16].copy_from_slice(file_id);
    aad[16..20].copy_from_slice(&chunk_index.to_be_bytes());
    aad[20] = is_last as u8;
    aad
}

/// Whether `chunk_index` is the terminal chunk of a `chunk_count`-chunk file, with
/// validation: `chunk_count` must be ≥ 1 and `chunk_index` in `0..chunk_count`. The
/// resulting `is_last` bit is bound into the chunk AAD ([`multipart_aad`]) so the
/// (untrusted) external `chunk_count` becomes self-authenticating against truncation.
fn is_last_chunk(chunk_index: u32, chunk_count: u32) -> Result<bool> {
    if chunk_count == 0 || chunk_index >= chunk_count {
        return Err(CryptoError::InvalidInput(
            "multipart chunk_index out of range for chunk_count",
        ));
    }
    Ok(chunk_index == chunk_count - 1)
}

/// Seal one multipart chunk (§4.2). On-disk layout:
///
/// ```text
/// [1 byte 0x02][1 byte 0x01 = A256GCM][4 bytes chunk_index BE][12 bytes IV][ciphertext][16 bytes tag]
/// ```
///
/// The IV is HKDF-derived from `dek` + `chunk_index` (deterministic; the caller
/// does not supply it), and the AAD is `file_id || chunk_index || is_last`, where
/// `is_last = (chunk_index == chunk_count - 1)`. `chunk_index` is 0-based and must
/// be in `0..chunk_count` (else [`CryptoError::InvalidInput`]).
pub fn seal_chunk(
    dek: &[u8; 32],
    file_id: &[u8; 16],
    chunk_index: u32,
    chunk_count: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let is_last = is_last_chunk(chunk_index, chunk_count)?;
    let iv = multipart_iv(dek, chunk_index)?;
    let aad = multipart_aad(file_id, chunk_index, is_last);
    let sealed = aead::seal(dek, &iv, plaintext, &aad)?; // ciphertext || tag
    let mut out = Vec::with_capacity(MULTIPART_HEADER_LEN + sealed.len());
    out.push(FILE_MAGIC_MULTIPART);
    out.push(FILE_ALG_A256GCM);
    out.extend_from_slice(&chunk_index.to_be_bytes());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Open one multipart chunk (§4.2). `chunk_index` is the position the caller
/// expects this chunk to occupy and `chunk_count` is the file's total chunk count;
/// together they drive the AAD (`file_id || chunk_index || is_last`) and the
/// stored-index check, so a chunk moved to (or duplicated at) the wrong position —
/// or a file truncated by dropping its trailing chunk and lowering the reported
/// count — is rejected. Returns the plaintext, or [`CryptoError::Authentication`]
/// on a wrong DEK / wrong `file_id` / wrong `is_last` (truncation) / tamper, or
/// [`CryptoError::InvalidInput`] on a structurally malformed envelope, a
/// stored-index mismatch, or `chunk_index` out of range for `chunk_count`.
///
/// Truncation detection: the genuine terminal chunk is the only one sealed
/// `is_last = true`. If a file's last chunk is dropped and the count lowered to
/// `M`, the reader opens the new chunk `M-1` expecting `is_last = true`, but it was
/// sealed `is_last = false` (it was not originally terminal) → the GCM tag fails.
pub fn open_chunk(
    dek: &[u8; 32],
    file_id: &[u8; 16],
    chunk_index: u32,
    chunk_count: u32,
    envelope: &[u8],
) -> Result<Vec<u8>> {
    let is_last = is_last_chunk(chunk_index, chunk_count)?;
    if envelope.len() < MULTIPART_MIN_ENVELOPE_LEN {
        return Err(CryptoError::InvalidInput("multipart chunk too short"));
    }
    if envelope[0] != FILE_MAGIC_MULTIPART {
        return Err(CryptoError::InvalidInput("multipart chunk magic"));
    }
    if envelope[1] != FILE_ALG_A256GCM {
        return Err(CryptoError::InvalidInput("multipart chunk alg"));
    }
    let stored_index = u32::from_be_bytes(envelope[2..6].try_into().expect("4 bytes"));
    if stored_index != chunk_index {
        return Err(CryptoError::InvalidInput("multipart chunk index mismatch"));
    }
    let iv: [u8; 12] = envelope[6..MULTIPART_HEADER_LEN]
        .try_into()
        .expect("MULTIPART_HEADER_LEN - 6 == 12");
    let aad = multipart_aad(file_id, chunk_index, is_last);
    aead::open(dek, &iv, &envelope[MULTIPART_HEADER_LEN..], &aad)
}

#[cfg(test)]
mod plaintext_len_tests {
    use super::multipart_plaintext_len;
    const MIB16: u64 = 16 * 1024 * 1024;

    /// The three vectors measured live on staging v0.5.18 (bug083 §2) — each a
    /// 1-chunk file whose stored size exceeded its plaintext by exactly 34.
    #[test]
    fn staging_measured_vectors() {
        assert_eq!(multipart_plaintext_len(116, MIB16), Some(82));
        assert_eq!(multipart_plaintext_len(8_388_642, MIB16), Some(8_388_608));
        assert_eq!(multipart_plaintext_len(2_097_186, MIB16), Some(2_097_152));
    }

    #[test]
    fn empty_file_is_one_empty_final_chunk() {
        assert_eq!(multipart_plaintext_len(34, MIB16), Some(0));
    }

    #[test]
    fn exact_multiple_and_boundary_chunk_counts() {
        // plaintext == 2·chunk_size exactly → 2 chunks → ct = 2cs + 68.
        assert_eq!(
            multipart_plaintext_len(2 * MIB16 + 68, MIB16),
            Some(2 * MIB16)
        );
        // plaintext == chunk_size + 1 → 2 chunks → ct = cs + 1 + 68.
        assert_eq!(
            multipart_plaintext_len(MIB16 + 1 + 68, MIB16),
            Some(MIB16 + 1)
        );
        // plaintext == chunk_size → 1 chunk → ct = cs + 34.
        assert_eq!(multipart_plaintext_len(MIB16 + 34, MIB16), Some(MIB16));
    }

    /// A control that can fail: invalid framings return None, never a number.
    #[test]
    fn invalid_inputs_refuse() {
        assert_eq!(multipart_plaintext_len(33, MIB16), None); // below one empty chunk
        assert_eq!(multipart_plaintext_len(0, MIB16), None);
        assert_eq!(multipart_plaintext_len(116, 0), None); // zero chunk_size
    }
}
