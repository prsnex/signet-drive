// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { describe, expect, it } from 'vitest';
import { b64uEncode, type Bytes } from './crypto/bytes';
import { fingerprint } from './crypto/pubkey';
import { normalizeFingerprint, verifyFingerprint } from './guardianship';

/** A fresh P-256 public key (base64url X9.63) + its correct SPKI fingerprint. */
async function freshPubkey(): Promise<{ b64url: string; fp: string }> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
    'deriveBits',
  ]);
  const raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)) as Bytes;
  return { b64url: b64uEncode(raw), fp: await fingerprint(raw) };
}

describe('normalizeFingerprint', () => {
  it('lowercases and strips spaces and colons', () => {
    expect(normalizeFingerprint('A1B2 C3D4')).toBe('a1b2c3d4');
    expect(normalizeFingerprint('a1:b2:c3:d4')).toBe('a1b2c3d4');
    expect(normalizeFingerprint('  A1b2\tC3D4 ')).toBe('a1b2c3d4');
  });
});

describe('verifyFingerprint (P-011)', () => {
  it('passes when the fingerprint matches the public key', async () => {
    const { b64url, fp } = await freshPubkey();
    await expect(verifyFingerprint(b64url, fp, 'signing key')).resolves.toBeUndefined();
  });

  it('accepts a spaced, uppercased fingerprint (normalized before compare)', async () => {
    const { b64url, fp } = await freshPubkey();
    const grouped = (fp.toUpperCase().match(/.{1,4}/g) ?? []).join(' ');
    await expect(verifyFingerprint(b64url, grouped, 'signing key')).resolves.toBeUndefined();
  });

  it('rejects a fingerprint that belongs to a different key', async () => {
    const a = await freshPubkey();
    const b = await freshPubkey();
    await expect(verifyFingerprint(a.b64url, b.fp, 'encryption (KEM) key')).rejects.toThrow(
      /don't match/,
    );
  });

  it('rejects an unreadable public key', async () => {
    await expect(verifyFingerprint('not-a-real-key', 'deadbeef', 'signing key')).rejects.toThrow(
      /couldn't be read/,
    );
  });
});
