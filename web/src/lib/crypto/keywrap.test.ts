// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { describe, expect, it } from 'vitest';
import { hexDecode, hexEncode } from './bytes';
import { IntegrityError, InvalidInputError } from './errors';
import { aesKwUnwrap, aesKwWrap } from './keywrap';

// RFC 3394 §4.6 — Wrap 256 bits of Key Data with a 256-bit KEK. A published KAT,
// independent of the wrap-chain golden: it pins the AES-KW primitive on its own.
const KEK = hexDecode('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
const KEY_DATA = hexDecode('00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f');
const WRAPPED = '28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21';

describe('AES-KW (RFC 3394)', () => {
  it('wraps to the RFC 3394 §4.6 vector byte-for-byte', async () => {
    expect(hexEncode(await aesKwWrap(KEK, KEY_DATA))).toBe(WRAPPED);
  });

  it('unwraps the RFC 3394 §4.6 vector', async () => {
    expect(hexEncode(await aesKwUnwrap(KEK, hexDecode(WRAPPED)))).toBe(hexEncode(KEY_DATA));
  });

  it('round-trips', async () => {
    const wrapped = await aesKwWrap(KEK, KEY_DATA);
    expect(hexEncode(await aesKwUnwrap(KEK, wrapped))).toBe(hexEncode(KEY_DATA));
  });

  it('rejects a tampered wrap with IntegrityError', async () => {
    const wrapped = await aesKwWrap(KEK, KEY_DATA);
    wrapped[0] ^= 0x01;
    await expect(aesKwUnwrap(KEK, wrapped)).rejects.toBeInstanceOf(IntegrityError);
  });

  it('rejects a wrong KEK with IntegrityError', async () => {
    const wrapped = await aesKwWrap(KEK, KEY_DATA);
    const wrongKek = hexDecode('ff' + '00'.repeat(31));
    await expect(aesKwUnwrap(wrongKek, wrapped)).rejects.toBeInstanceOf(IntegrityError);
  });

  it('rejects malformed lengths with InvalidInputError (not conflated with integrity)', async () => {
    await expect(aesKwWrap(KEK, new Uint8Array(20))).rejects.toBeInstanceOf(InvalidInputError);
    await expect(aesKwWrap(KEK, new Uint8Array(8))).rejects.toBeInstanceOf(InvalidInputError);
    await expect(aesKwUnwrap(KEK, new Uint8Array(20))).rejects.toBeInstanceOf(InvalidInputError);
  });

  it('rejects a non-32-byte KEK with InvalidInputError', async () => {
    await expect(aesKwWrap(new Uint8Array(16), KEY_DATA)).rejects.toBeInstanceOf(InvalidInputError);
  });
});
