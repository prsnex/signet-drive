// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// AES-256-GCM (A256GCM, RFC 7518 §5.3). Returns/consumes ciphertext ‖ tag (the
// trailing 16 bytes are the GCM tag), matching the on-disk envelope layout and
// WebCrypto's own ct‖tag convention. AAD binds a ciphertext to its semantic
// context (file_id, folder scope); threading it through is the caller's job.

import type { Bytes } from './bytes';
import { IntegrityError, InvalidInputError } from './errors';

function importGcmKey(key: Bytes, usage: KeyUsage): Promise<CryptoKey> {
  if (key.length !== 32) throw new InvalidInputError('aes-256-gcm key must be 32 bytes');
  return crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, [usage]);
}

/** Seal plaintext under key (256-bit) + nonce (96-bit) with AAD; returns ct ‖ tag.
 *  The caller MUST use a unique nonce per (key, message). */
export async function aesGcmSeal(
  key: Bytes,
  nonce: Bytes,
  plaintext: Bytes,
  aad: Bytes,
): Promise<Bytes> {
  const k = await importGcmKey(key, 'encrypt');
  const ct = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
    k,
    plaintext,
  );
  return new Uint8Array(ct);
}

/** Open ciphertextAndTag (ct ‖ tag) under key + nonce + AAD. Throws
 *  {@link IntegrityError} on tag mismatch, wrong key, wrong AAD, or tampering —
 *  the caller MUST NOT distinguish these. */
export async function aesGcmOpen(
  key: Bytes,
  nonce: Bytes,
  ciphertextAndTag: Bytes,
  aad: Bytes,
): Promise<Bytes> {
  const k = await importGcmKey(key, 'decrypt');
  try {
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
      k,
      ciphertextAndTag,
    );
    return new Uint8Array(pt);
  } catch {
    throw new IntegrityError('aes-256-gcm authentication failed');
  }
}
