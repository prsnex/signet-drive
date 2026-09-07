// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { describe, expect, it } from 'vitest';
import { hexEncode } from './bytes';
import { generateEphemeralKeypair } from './ecdh';
import { unwrapDek, unwrapMetadataKey, wrapDek, wrapMetadataKey } from './wrap';

// Exercises the wrap (upload) direction the golden cannot pin deterministically
// (a fresh random ephemeral key per wrap): a wrap → unwrap round-trip through a
// fresh recipient keypair, plus the P-015 folder-binding property end-to-end.

async function recipient() {
  const kp = await generateEphemeralKeypair();
  const pubX963 = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
  return { privateKey: kp.privateKey, pubX963 };
}

describe('ECDH-ES+A256KW wrap/unwrap round-trip', () => {
  it('a DEK wrapped to a fresh recipient round-trips', async () => {
    const r = await recipient();
    const dek = crypto.getRandomValues(new Uint8Array(32));
    const env = await wrapDek(r.pubX963, dek);
    expect(env.alg).toBe('ECDH-ES+A256KW');
    expect(env.epk.crv).toBe('P-256');
    const recovered = await unwrapDek(r.privateKey, env);
    expect(hexEncode(recovered)).toBe(hexEncode(dek));
  });

  it('a metadata key round-trips and is folder-bound (P-015)', async () => {
    const r = await recipient();
    const mk = crypto.getRandomValues(new Uint8Array(32));
    const rootFolderId = crypto.getRandomValues(new Uint8Array(16));
    const env = await wrapMetadataKey(r.pubX963, mk, rootFolderId);
    const recovered = await unwrapMetadataKey(r.privateKey, env, rootFolderId);
    expect(hexEncode(recovered)).toBe(hexEncode(mk));

    const wrongFolder = crypto.getRandomValues(new Uint8Array(16));
    await expect(unwrapMetadataKey(r.privateKey, env, wrongFolder)).rejects.toThrow();
  });

  it('rfp is a 64-char lowercase-hex SHA-256 (SPKI) fingerprint', async () => {
    const r = await recipient();
    const env = await wrapDek(r.pubX963, crypto.getRandomValues(new Uint8Array(32)));
    expect(env.rfp).toMatch(/^[0-9a-f]{64}$/);
  });
});
