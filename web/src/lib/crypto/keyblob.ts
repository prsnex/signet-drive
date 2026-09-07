// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// The PRF-blob v2 plaintext layout (PQR Spec §7 — the stored human secret).
//
//   0x02 (1B) ‖ u32be(len) ‖ p256_pkcs8 ‖ u32be(len) ‖ mlkem_seed(64)
//
// This is what goes INSIDE the single AES-GCM/PRF wrap (kem_wrap.ts — the
// INV-12 single-blob/single-wrap pattern is unchanged; only the plaintext
// grew). The stored PQ secret is the 64-byte (d,z) seed, never the ~3 KB
// decapsulation key: dk regenerates from the seed at sign-in (FIPS 203 KeyGen
// determinism, mlkem.ts).
//
// The version byte is pinned to 0x02 (SF-2): pre-launch re-enrollment means
// no legacy (bare-PKCS#8, 0x30-first) blobs exist in production, so v1 (the
// unversioned layout) is not parsed — anything but 0x02 is malformed. Length
// prefixes are the suite's u32 big-endian convention (§4.3 / bytes.u32be).
// Rotation (rotate.ts) is layout-agnostic — it re-wraps this plaintext
// opaquely under the new PRF without parsing it.

import { concatBytes, u32be, type Bytes } from './bytes';
import { InvalidInputError } from './errors';
import { MLKEM_SEED_LEN } from './mlkem';

export const KEY_BLOB_V2 = 0x02;

/** Encode the v2 blob plaintext from the two client-side secrets. */
export function encodeKeyBlobV2(p256Pkcs8: Bytes, mlkemSeed: Bytes): Bytes {
  if (p256Pkcs8.length === 0) throw new InvalidInputError('p256 pkcs8 must be non-empty');
  if (mlkemSeed.length !== MLKEM_SEED_LEN) {
    throw new InvalidInputError('ml-kem seed must be 64 bytes');
  }
  return concatBytes(
    new Uint8Array([KEY_BLOB_V2]) as Bytes,
    u32be(p256Pkcs8.length),
    p256Pkcs8,
    u32be(mlkemSeed.length),
    mlkemSeed,
  );
}

/** Strictly decode a v2 blob plaintext: exact version byte, exact field
 *  framing, no trailing bytes. Anything else — including a legacy bare-PKCS#8
 *  blob — is malformed (SF-2: no legacy path exists pre-launch). */
export function decodeKeyBlobV2(plain: Bytes): { p256Pkcs8: Bytes; mlkemSeed: Bytes } {
  if (plain.length < 1 || plain[0] !== KEY_BLOB_V2) {
    throw new InvalidInputError('key blob version must be 0x02');
  }
  let offset = 1;
  const readField = (): Bytes => {
    if (offset + 4 > plain.length) throw new InvalidInputError('key blob truncated');
    const len = new DataView(plain.buffer, plain.byteOffset + offset, 4).getUint32(0, false);
    offset += 4;
    if (offset + len > plain.length) throw new InvalidInputError('key blob truncated');
    const field = plain.slice(offset, offset + len);
    offset += len;
    return field;
  };
  const p256Pkcs8 = readField();
  const mlkemSeed = readField();
  if (offset !== plain.length) throw new InvalidInputError('key blob has trailing bytes');
  if (p256Pkcs8.length === 0) throw new InvalidInputError('p256 pkcs8 must be non-empty');
  if (mlkemSeed.length !== MLKEM_SEED_LEN) {
    throw new InvalidInputError('ml-kem seed must be 64 bytes');
  }
  return { p256Pkcs8, mlkemSeed };
}
