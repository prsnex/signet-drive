// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// HKDF-SHA-256 (RFC 5869), composed from native WebCrypto HMAC. Used for the
// human-side wrap-key derivation (Envelope §8.2: info = "signet-drive-kem-wrap-v1",
// empty salt) and the hybrid content-wrap KDM (PQR §4.2: info = FixedInfo,
// 3324/3340 bytes). The ECDH-ES+A256KW KEK uses Concat-KDF (concatkdf.ts), NOT HKDF.
//
// Why HMAC-composed and not SubtleCrypto's own 'HKDF' deriveBits: Node's
// WebCrypto (which the vitest suite runs on) rejects `info` longer than 1024
// bytes (ERR_OUT_OF_RANGE) — the hybrid FixedInfo is 3× that, and RFC 5869
// places no limit. Extract-then-Expand over native HMAC-SHA-256 is RFC 5869's
// own definition (§2.2/§2.3 — the same composition RustCrypto's hkdf crate
// runs over its hmac crate), has no length ceiling on any engine, and is
// byte-identical: pinned here by the RFC 5869 Appendix A vectors (kdf.test.ts),
// the committed kem-wrap goldens, and the A3 KeyCombine KAT (the long-info
// case, three derivation lineages).
//
// An empty salt is normalized to HashLen (32) zero bytes before the HMAC
// import — RFC 5869 §2.2 defines them as the same PRK (HMAC zero-pads short
// keys to the block size), and WebCrypto's HMAC importKey rejects an empty
// key outright.

import type { Bytes } from './bytes';
import { InvalidInputError } from './errors';

const HMAC_SHA256: HmacImportParams = { name: 'HMAC', hash: 'SHA-256' };
const HASH_LEN = 32;

async function hmacSha256(key: Bytes, data: Bytes): Promise<Bytes> {
  const k = await crypto.subtle.importKey('raw', key, HMAC_SHA256, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, data));
}

/** HKDF-SHA-256 extract-then-expand. `salt` may be empty (== 32 zero bytes,
 *  RFC 5869 §2.2); `info` is the context label, any length; `outLen` is in
 *  bytes (≤ 255 × 32 = 8160). */
export async function hkdfSha256(
  ikm: Bytes,
  salt: Bytes,
  info: Bytes,
  outLen: number,
): Promise<Bytes> {
  if (outLen <= 0 || outLen > 255 * HASH_LEN) {
    throw new InvalidInputError('hkdf output length');
  }
  // Extract (RFC 5869 §2.2): PRK = HMAC-Hash(salt, IKM).
  const prk = await hmacSha256(salt.length === 0 ? (new Uint8Array(HASH_LEN) as Bytes) : salt, ikm);
  // Expand (RFC 5869 §2.3): T(i) = HMAC-Hash(PRK, T(i-1) ‖ info ‖ i).
  const out = new Uint8Array(outLen);
  let t: Bytes = new Uint8Array(0);
  let written = 0;
  for (let i = 1; written < outLen; i++) {
    const block = new Uint8Array(t.length + info.length + 1);
    block.set(t, 0);
    block.set(info, t.length);
    block[t.length + info.length] = i;
    t = await hmacSha256(prk, block as Bytes);
    out.set(t.subarray(0, Math.min(HASH_LEN, outLen - written)), written);
    written += HASH_LEN;
  }
  prk.fill(0);
  t.fill(0);
  return out;
}
