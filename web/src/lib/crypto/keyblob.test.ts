// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { describe, expect, it } from 'vitest';
import { hexEncode, type Bytes } from './bytes';
import { InvalidInputError } from './errors';
import { decodeKeyBlobV2, encodeKeyBlobV2 } from './keyblob';

const pkcs8 = new Uint8Array([0x30, 0x81, 0x87, 0x02, 0x01, 0x00]) as Bytes; // DER-ish stub
const seed = new Uint8Array(64).fill(0x5a) as Bytes;

describe('PRF-blob v2 layout (PQR §7)', () => {
  it('round-trips and pins the exact framing', () => {
    const blob = encodeKeyBlobV2(pkcs8, seed);
    // 1 (version) + 4 + pkcs8 + 4 + 64
    expect(blob.length).toBe(1 + 4 + pkcs8.length + 4 + 64);
    expect(blob[0]).toBe(0x02);
    const { p256Pkcs8, mlkemSeed } = decodeKeyBlobV2(blob);
    expect(hexEncode(p256Pkcs8)).toBe(hexEncode(pkcs8));
    expect(hexEncode(mlkemSeed)).toBe(hexEncode(seed));
  });

  it('rejects a legacy bare-PKCS#8 blob (SF-2: version byte is pinned 0x02)', () => {
    // A DER SEQUENCE starts 0x30 — the legacy unversioned layout. No legacy
    // path exists pre-launch; it must be malformed, not silently mis-parsed.
    expect(() => decodeKeyBlobV2(pkcs8)).toThrow(InvalidInputError);
  });

  it('rejects truncation, trailing bytes, and a wrong-length seed', () => {
    const blob = encodeKeyBlobV2(pkcs8, seed);
    expect(() => decodeKeyBlobV2(blob.slice(0, blob.length - 1) as Bytes)).toThrow(
      InvalidInputError,
    );
    const trailing = new Uint8Array(blob.length + 1);
    trailing.set(blob);
    expect(() => decodeKeyBlobV2(trailing as Bytes)).toThrow(InvalidInputError);
    expect(() => encodeKeyBlobV2(pkcs8, new Uint8Array(63) as Bytes)).toThrow(InvalidInputError);
    expect(() => encodeKeyBlobV2(new Uint8Array(0) as Bytes, seed)).toThrow(InvalidInputError);
  });
});
