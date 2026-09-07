// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// AES-256 Key Wrap (RFC 3394) over native WebCrypto wrapKey/unwrapKey — the
// final step of ECDH-ES+A256KW. The Concat-KDF KEK wraps a 32-byte key to 40
// bytes; RFC 3394's built-in integrity check is what makes a wrong-KEK unwrap
// (e.g. a P-015 folder mismatch, or tampering) fail cleanly.
//
// WebCrypto exposes AES-KW only as a CryptoKey wrap/unwrap, never on raw bytes.
// To stay byte-oriented (mirroring signet-crypto's keywrap), the payload is
// carried as an HMAC key, whose 'raw' import/export is the literal key bytes for
// any length. The carrier is byte-faithful — proven against the RFC 3394 §4.6 KAT
// in keywrap.test.ts (same vector RustCrypto pins) — and reviewed SOUND (S045 #6).
// AES-KW wrapKey/unwrapKey is supported on all current engines (Chromium; Firefox
// 108+; Safari/WebKit). Our e2e exercises only Chrome, so this exact path is
// smoke-tested on Safari + Firefox pre-launch (D5) — a verification step, not
// missing browser support.

import type { Bytes } from './bytes';
import { IntegrityError, InvalidInputError } from './errors';

const AES_KW = { name: 'AES-KW' } as const;
const HMAC_CARRIER: HmacImportParams = { name: 'HMAC', hash: 'SHA-256' };

function importKek(kek: Bytes, usage: KeyUsage): Promise<CryptoKey> {
  if (kek.length !== 32) throw new InvalidInputError('aes-kw kek must be 32 bytes');
  return crypto.subtle.importKey('raw', kek, AES_KW, false, [usage]);
}

/** Wrap key_data under the 256-bit KEK (RFC 3394). Output is key_data.length + 8
 *  bytes (a 32-byte key wraps to 40). key_data must be a multiple of 8 and ≥ 16. */
export async function aesKwWrap(kek: Bytes, keyData: Bytes): Promise<Bytes> {
  if (keyData.length < 16 || keyData.length % 8 !== 0) {
    throw new InvalidInputError('aes-kw key_data length');
  }
  const kekKey = await importKek(kek, 'wrapKey');
  const payload = await crypto.subtle.importKey('raw', keyData, HMAC_CARRIER, true, ['sign']);
  const wrapped = await crypto.subtle.wrapKey('raw', payload, kekKey, AES_KW);
  return new Uint8Array(wrapped);
}

/** Unwrap under the KEK. Returns the key material, or throws {@link IntegrityError}
 *  if the RFC 3394 integrity check fails (wrong KEK or tampered wrap). A malformed
 *  length is {@link InvalidInputError} — never conflated with an integrity failure. */
export async function aesKwUnwrap(kek: Bytes, wrapped: Bytes): Promise<Bytes> {
  if (wrapped.length < 24 || wrapped.length % 8 !== 0) {
    throw new InvalidInputError('aes-kw wrapped length');
  }
  const kekKey = await importKek(kek, 'unwrapKey');
  let unwrapped: CryptoKey;
  try {
    unwrapped = await crypto.subtle.unwrapKey('raw', wrapped, kekKey, AES_KW, HMAC_CARRIER, true, [
      'sign',
    ]);
  } catch {
    throw new IntegrityError('aes-kw integrity check failed');
  }
  return new Uint8Array(await crypto.subtle.exportKey('raw', unwrapped));
}
