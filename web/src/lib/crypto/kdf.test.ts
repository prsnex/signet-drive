// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { describe, expect, it } from 'vitest';
import { hexDecode, hexEncode, type Bytes } from './bytes';
import { hkdfSha256 } from './kdf';

// RFC 5869 Appendix A test vectors (SHA-256) — pin the HMAC-composed
// extract-then-expand byte-for-byte against the published spec vectors. The
// long-info case (3324 B, beyond Node WebCrypto's native-HKDF 1024-byte cap —
// the reason kdf.ts composes over HMAC) is pinned separately by the A3
// KeyCombine KAT in hybrid_wrap.test.ts.

describe('hkdfSha256 (RFC 5869 Appendix A)', () => {
  it('A.1 — basic test case', async () => {
    const okm = await hkdfSha256(
      hexDecode('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
      hexDecode('000102030405060708090a0b0c'),
      hexDecode('f0f1f2f3f4f5f6f7f8f9'),
      42,
    );
    expect(hexEncode(okm)).toBe(
      '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865',
    );
  });

  it('A.2 — longer inputs/outputs', async () => {
    const ikm = hexDecode(
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' +
        '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f' +
        '404142434445464748494a4b4c4d4e4f',
    );
    const salt = hexDecode(
      '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f' +
        '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f' +
        'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
    );
    const info = hexDecode(
      'b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf' +
        'd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef' +
        'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
    );
    const okm = await hkdfSha256(ikm, salt, info, 82);
    expect(hexEncode(okm)).toBe(
      'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c' +
        '59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71' +
        'cc30c58179ec3e87c14c01d5c1f3434f1d87',
    );
  });

  it('A.3 — zero-length salt and info (the empty-salt normalization path)', async () => {
    const okm = await hkdfSha256(
      hexDecode('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
      new Uint8Array(0) as Bytes,
      new Uint8Array(0) as Bytes,
      42,
    );
    expect(hexEncode(okm)).toBe(
      '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8',
    );
  });

  it('rejects invalid output lengths', async () => {
    const ikm = hexDecode('0b0b0b0b');
    await expect(hkdfSha256(ikm, ikm, ikm, 0)).rejects.toThrow();
    await expect(hkdfSha256(ikm, ikm, ikm, 255 * 32 + 1)).rejects.toThrow();
  });
});
