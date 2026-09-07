// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { describe, expect, it } from 'vitest';
import { decryptName, encryptName } from './encname';

// No committed golden exists for §7.3 (the underlying AES-256-GCM is already
// golden-pinned via the file envelope + KEM-wrap). encname is validated by
// round-trip + the AAD-binding negatives that are the whole point of §7.3.

const key = () => crypto.getRandomValues(new Uint8Array(32));
const id = () => crypto.getRandomValues(new Uint8Array(16));

describe('encrypted names (§7.3)', () => {
  it('round-trips a name', async () => {
    const k = key();
    const root = id();
    const target = id();
    const env = await encryptName(k, root, target, 'schema.md');
    expect(env.alg).toBe('A256GCM');
    expect(await decryptName(k, root, target, env)).toBe('schema.md');
  });

  it('binds to target_id (AAD): a different target rejects', async () => {
    const k = key();
    const root = id();
    const env = await encryptName(k, root, id(), 'secret.md');
    await expect(decryptName(k, root, id(), env)).rejects.toThrow();
  });

  it('binds to root_folder_id (AAD): a different root rejects', async () => {
    const k = key();
    const target = id();
    const env = await encryptName(k, id(), target, 'secret.md');
    await expect(decryptName(k, id(), target, env)).rejects.toThrow();
  });

  it('a wrong metadata key rejects', async () => {
    const root = id();
    const target = id();
    const env = await encryptName(key(), root, target, 'secret.md');
    await expect(decryptName(key(), root, target, env)).rejects.toThrow();
  });

  it('handles unicode names', async () => {
    const k = key();
    const root = id();
    const target = id();
    const name = 'café-数据-🔐.txt';
    const env = await encryptName(k, root, target, name);
    expect(await decryptName(k, root, target, env)).toBe(name);
  });
});
