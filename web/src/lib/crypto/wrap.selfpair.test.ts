// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { describe, expect, it } from 'vitest';
import { generateKemKeypair, importKemPrivateNonExtractable } from '../kem';
import { kemKeypairMatches } from './wrap';

// Pre-launch crypto review #5: at sign-in the self KEM public key is
// server-supplied and used to self-wrap new secrets, while the private key is
// recovered NON-extractable (so its public key can't be re-derived for a direct
// comparison). `kemKeypairMatches` is the wrap→unwrap round-trip that verifies the
// server-supplied public key is genuinely the counterpart of the recovered key.
describe('kemKeypairMatches (self-pubkey verification, review #5)', () => {
  it('returns true for a matching non-extractable private key + its public key', async () => {
    const kp = await generateKemKeypair();
    const priv = await importKemPrivateNonExtractable(kp.privatePkcs8);
    expect(await kemKeypairMatches(priv, kp.publicX963)).toBe(true);
  });

  it('returns false when the public key is a different keypair (substitution)', async () => {
    const a = await generateKemKeypair();
    const b = await generateKemKeypair();
    const privA = await importKemPrivateNonExtractable(a.privatePkcs8);
    // The substituted public key derives a different KEK → AES-KW unwrap fails.
    expect(await kemKeypairMatches(privA, b.publicX963)).toBe(false);
  });

  it('returns false (fails closed) for a malformed public key', async () => {
    const a = await generateKemKeypair();
    const privA = await importKemPrivateNonExtractable(a.privatePkcs8);
    expect(await kemKeypairMatches(privA, new Uint8Array(10))).toBe(false);
  });
});
