// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// File ciphertext envelope (Envelope §4). Mirrors signet-crypto's envelope.rs.
//
// Single-PUT (§4.1):
//   [0x01 magic][0x01 alg = A256GCM][12-byte IV][N-byte ciphertext][16-byte tag]
// The AAD is the file's file_id (16 raw UUID bytes), NOT stored — both sides
// reconstruct it, binding the ciphertext to its file so the storage layer cannot
// substitute one blob for another.
//
// Multipart (§4.2, 0x02 magic): large files split into chunks, each sealed with
// sealChunk. The per-chunk IV is HKDF-derived from the DEK + chunk index (not
// random) so every chunk under one DEK gets a unique nonce without a per-chunk
// random draw, and the AAD is file_id || chunk_index || is_last so a chunk cannot
// be moved between files, reordered within a file, or silently truncated — is_last
// (the terminal chunk, from the caller's chunk_count) is authenticated, so dropping
// the last chunk and lowering the count makes the new boundary chunk fail to open.
// The transport (direct-to-storage multipart) lives above this module.

import { aesGcmOpen, aesGcmSeal } from './aead';
import { concatBytes, u32be, utf8Encode, type Bytes } from './bytes';
import { hkdfSha256 } from './kdf';
import { InvalidInputError } from './errors';

export const FILE_MAGIC_SINGLE_PUT = 0x01;
export const FILE_MAGIC_MULTIPART = 0x02;
export const FILE_ALG_A256GCM = 0x01;
const HEADER_LEN = 2 + 12; // magic + alg + IV
const MIN_ENVELOPE_LEN = HEADER_LEN + 16; // + the GCM tag (an empty-plaintext file)

// §4.2 multipart header: magic + alg + 4-byte chunk_index + 12-byte IV.
const MULTIPART_HEADER_LEN = 2 + 4 + 12;
const MULTIPART_MIN_ENVELOPE_LEN = MULTIPART_HEADER_LEN + 16;
const MULTIPART_IV_LABEL = utf8Encode('signet-drive-multipart-iv-v1');
const MAX_U32 = 0xffffffff;

/** Seal a plaintext file into the single-PUT envelope (§4.1). `iv` MUST be unique
 *  per `dek`; AAD is the 16-byte `fileId`. */
export async function sealFile(
  dek: Bytes,
  iv: Bytes,
  fileId: Bytes,
  plaintext: Bytes,
): Promise<Bytes> {
  if (iv.length !== 12) throw new InvalidInputError('iv must be 12 bytes');
  if (fileId.length !== 16) throw new InvalidInputError('file_id must be 16 bytes');
  const sealed = await aesGcmSeal(dek, iv, plaintext, fileId); // ciphertext || tag
  return concatBytes(new Uint8Array([FILE_MAGIC_SINGLE_PUT, FILE_ALG_A256GCM]), iv, sealed);
}

/** Open a single-PUT envelope: validate magic + alg, split the IV, AEAD-open with
 *  AAD = `fileId`. Throws {@link InvalidInputError} on a structurally malformed
 *  envelope, or an IntegrityError on a wrong DEK / wrong fileId / tamper. */
export async function openFile(dek: Bytes, fileId: Bytes, envelope: Bytes): Promise<Bytes> {
  if (envelope.length < MIN_ENVELOPE_LEN) throw new InvalidInputError('file envelope too short');
  if (envelope[0] !== FILE_MAGIC_SINGLE_PUT) throw new InvalidInputError('file envelope magic');
  if (envelope[1] !== FILE_ALG_A256GCM) throw new InvalidInputError('file envelope alg');
  if (fileId.length !== 16) throw new InvalidInputError('file_id must be 16 bytes');
  const iv = envelope.slice(2, HEADER_LEN);
  const ciphertextAndTag = envelope.slice(HEADER_LEN);
  return aesGcmOpen(dek, iv, ciphertextAndTag, fileId);
}

// --- §4.2 Multipart (large files) -------------------------------------------

/** Derive the deterministic per-chunk IV (§4.2): HKDF-SHA-256 over the DEK, empty
 *  salt, info = "signet-drive-multipart-iv-v1" || chunk_index_be → 12 bytes.
 *  Deterministic per (dek, chunkIndex) — guarantees nonce uniqueness across a
 *  file's chunks without a per-chunk random draw. */
function multipartIv(dek: Bytes, chunkIndex: number): Promise<Bytes> {
  const info = concatBytes(MULTIPART_IV_LABEL, u32be(chunkIndex));
  return hkdfSha256(dek, new Uint8Array(0), info, 12);
}

/** The §4.2 chunk AAD: fileId (16) || chunk_index_be (4) || is_last (1) = 21 bytes.
 *  Binds the chunk to its file, its position, AND whether it is the file's terminal
 *  chunk (truncation defence). */
function multipartAad(fileId: Bytes, chunkIndex: number, isLast: boolean): Bytes {
  return concatBytes(fileId, u32be(chunkIndex), new Uint8Array([isLast ? 1 : 0]));
}

function assertChunkIndex(chunkIndex: number): void {
  if (!Number.isInteger(chunkIndex) || chunkIndex < 0 || chunkIndex > MAX_U32) {
    throw new InvalidInputError('chunk_index must be a uint32');
  }
}

/** Whether `chunkIndex` is the terminal chunk of a `chunkCount`-chunk file, with
 *  validation (chunkCount in 1..=uint32_max, chunkIndex in 0..chunkCount). The
 *  is_last bit is bound into the AAD so the external chunk_count is
 *  self-authenticating against truncation. */
function isLastChunk(chunkIndex: number, chunkCount: number): boolean {
  assertChunkIndex(chunkIndex);
  if (!Number.isInteger(chunkCount) || chunkCount < 1 || chunkCount > MAX_U32) {
    throw new InvalidInputError('chunk_count must be in 1..=uint32_max');
  }
  if (chunkIndex >= chunkCount) {
    throw new InvalidInputError('chunk_index out of range for chunk_count');
  }
  return chunkIndex === chunkCount - 1;
}

/** Seal one multipart chunk (§4.2):
 *    [0x02][0x01 = A256GCM][chunk_index BE(4)][IV(12)][ciphertext][tag(16)]
 *  The IV is HKDF-derived from `dek` + `chunkIndex` (deterministic; not supplied);
 *  AAD = `fileId` || `chunkIndex` || `is_last`, where `is_last = (chunkIndex ===
 *  chunkCount - 1)`. `chunkIndex` is 0-based and must be in `0..chunkCount`. */
export async function sealChunk(
  dek: Bytes,
  fileId: Bytes,
  chunkIndex: number,
  chunkCount: number,
  plaintext: Bytes,
): Promise<Bytes> {
  if (fileId.length !== 16) throw new InvalidInputError('file_id must be 16 bytes');
  const isLast = isLastChunk(chunkIndex, chunkCount);
  const iv = await multipartIv(dek, chunkIndex);
  const aad = multipartAad(fileId, chunkIndex, isLast);
  const sealed = await aesGcmSeal(dek, iv, plaintext, aad); // ciphertext || tag
  return concatBytes(
    new Uint8Array([FILE_MAGIC_MULTIPART, FILE_ALG_A256GCM]),
    u32be(chunkIndex),
    iv,
    sealed,
  );
}

/** Open one multipart chunk (§4.2). `chunkIndex` is the position the caller expects
 *  this chunk to occupy and `chunkCount` is the file's total chunk count; together
 *  they drive the AAD (`fileId || chunkIndex || is_last`) and the stored-index check,
 *  so a chunk moved or duplicated to the wrong position — or a file truncated by
 *  dropping its trailing chunk and lowering the reported count — is rejected. Throws
 *  {@link InvalidInputError} on a malformed envelope, a stored-index mismatch, or
 *  chunkIndex out of range for chunkCount; an IntegrityError on a wrong DEK / wrong
 *  fileId / wrong is_last (truncation) / tamper.
 *
 *  Truncation detection: only the genuine terminal chunk is sealed `is_last = true`,
 *  so dropping the last chunk and lowering the count to M makes the new chunk M-1
 *  open under `is_last = true` though it was sealed `false` → the GCM tag fails. */
export async function openChunk(
  dek: Bytes,
  fileId: Bytes,
  chunkIndex: number,
  chunkCount: number,
  envelope: Bytes,
): Promise<Bytes> {
  if (envelope.length < MULTIPART_MIN_ENVELOPE_LEN) {
    throw new InvalidInputError('multipart chunk too short');
  }
  if (envelope[0] !== FILE_MAGIC_MULTIPART) throw new InvalidInputError('multipart chunk magic');
  if (envelope[1] !== FILE_ALG_A256GCM) throw new InvalidInputError('multipart chunk alg');
  if (fileId.length !== 16) throw new InvalidInputError('file_id must be 16 bytes');
  const isLast = isLastChunk(chunkIndex, chunkCount);
  const storedIndex = new DataView(envelope.slice(2, 6).buffer).getUint32(0, false);
  if (storedIndex !== chunkIndex) throw new InvalidInputError('multipart chunk index mismatch');
  const iv = envelope.slice(6, MULTIPART_HEADER_LEN);
  const aad = multipartAad(fileId, chunkIndex, isLast);
  return aesGcmOpen(dek, iv, envelope.slice(MULTIPART_HEADER_LEN), aad);
}
