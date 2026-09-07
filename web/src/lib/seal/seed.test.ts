// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Unit tests for the identity → impression seed helpers (the integration
// layer, Hlin). Pins the per-type regime Gus's carve review F2 fixed — a PRSN's
// own mark presses from its SIGNING fingerprint, a human's from its KEM
// fingerprint — and F4's single last-resort constant. Decorative surface, but
// "a PRSN presses from its signing identity" is the mechanic's whole premise.
import { describe, expect, it } from 'vitest';

import type { MeResponse } from '$lib/api';
import { fpSeed, identitySeed, meSeed } from './seed';

// Valid 6-byte hex fingerprints (≥12 hex chars) and their expected byte slices.
const SIGN_FP = 'aabbccddeeff0011';
const SIGN_BYTES = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
const KEM_FP = '112233445566ffff';
const KEM_BYTES = new Uint8Array([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

/** A minimal MeResponse carrying only the fields meSeed reads. */
function me(input: {
  account_type: MeResponse['account_type'];
  handle?: string | null;
  kem?: string | null;
  signing?: string | null;
}): MeResponse {
  return {
    account_type: input.account_type,
    handle: input.handle ?? null,
    kem_pubkey_fingerprint: input.kem ?? null,
    attestation: input.signing ? { signing_pubkey_fingerprint: input.signing } : null,
  } as MeResponse;
}

describe('fpSeed', () => {
  it('takes the first 6 bytes of a hex fingerprint', () => {
    expect(fpSeed(SIGN_FP)).toEqual(SIGN_BYTES);
  });
  it('returns null for a too-short, absent, or unparseable fingerprint', () => {
    expect(fpSeed('aabb')).toBeNull();
    expect(fpSeed(null)).toBeNull();
    expect(fpSeed(undefined)).toBeNull();
    expect(fpSeed('zzzzzzzzzzzz')).toBeNull();
  });
});

describe('identitySeed', () => {
  it('presses from the fingerprint when present', () => {
    expect(identitySeed(SIGN_FP, 'ignored-handle')).toEqual(SIGN_BYTES);
  });
  it('falls back to the stable string, then the single last-resort constant', () => {
    expect(identitySeed(null, 'octavia-ai')).toBe('octavia-ai');
    // F4: one last-resort everywhere — never the old inline 'prsn'.
    expect(identitySeed(null, null)).toBe('signet');
  });
});

describe('meSeed — the per-type own-mark regime (F2)', () => {
  it('a PRSN presses from its SIGNING fingerprint, not its KEM fingerprint', () => {
    const seed = meSeed(
      me({ account_type: 'prsn', handle: 'octavia-ai', kem: KEM_FP, signing: SIGN_FP }),
    );
    expect(seed).toEqual(SIGN_BYTES);
    expect(seed).not.toEqual(KEM_BYTES);
  });

  it('a human presses from its KEM fingerprint', () => {
    const seed = meSeed(me({ account_type: 'human', handle: 'alice', kem: KEM_FP }));
    expect(seed).toEqual(KEM_BYTES);
  });

  it('a PRSN without a signing fingerprint falls back to its handle', () => {
    expect(meSeed(me({ account_type: 'prsn', handle: 'octavia-ai' }))).toBe('octavia-ai');
  });

  it('a null/absent identity presses the last-resort constant', () => {
    expect(meSeed(null)).toBe('signet');
    expect(meSeed(undefined)).toBe('signet');
  });
});
