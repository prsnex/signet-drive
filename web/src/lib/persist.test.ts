// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Unlock-persistence gate logic (S116). These tests inject an in-memory store —
// Node's structuredClone cannot carry a CryptoKey (verified S116), so the REAL
// IndexedDB round-trip (structured-cloning non-extractable keys) is proven by the
// e2e spec in real Chrome. Everything else — the four restore gates, the F-UP1
// continuity anchor, the F-UP2 purge-vs-network split, the seal's AAD binding,
// the lifetime clamp + no-extend semantics — is exercised here with REAL crypto
// (node webcrypto P-256 + the real ML-KEM wasm).

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import { SignetApiError, type MeResponse, type PublicConfig } from './api';
import type { Session } from './auth';
import { b64uEncode } from './crypto/bytes';
import { initMlkem, mlkemKeygen } from './crypto/mlkem';
import { generateKemKeypair, importKemPrivateNonExtractable } from './kem';
import {
  persistSession,
  purgePersisted,
  restoreSession,
  type PersistDeps,
  type UnlockRecord,
  type UnlockStore,
} from './persist';

// The committed wasm pkg, loaded the node way (the mlkem.test.ts pattern).
const wasmBytes = readFileSync(
  fileURLToPath(new URL('./crypto/mlkem-wasm/signet_crypto_wasm_bg.wasm', import.meta.url)),
);

beforeAll(async () => {
  await initMlkem(wasmBytes);
});

// ---- fixtures ----

function memoryStore(): UnlockStore & { record: UnlockRecord | undefined } {
  const s = {
    record: undefined as UnlockRecord | undefined,
    async get() {
      return s.record;
    },
    async put(value: UnlockRecord) {
      s.record = value;
    },
    async delete() {
      s.record = undefined;
    },
  };
  return s;
}

/** A real session: node-webcrypto P-256 (non-extractable import, as sign-in does)
 *  + a real ML-KEM identity from the wasm. */
async function realSession(accountId = 'acct-1'): Promise<Session> {
  const kem = await generateKemKeypair();
  const mlkem = await mlkemKeygen();
  return {
    accountId,
    kemPrivateKey: await importKemPrivateNonExtractable(kem.privatePkcs8),
    kemPubkeyX963: b64uEncode(kem.publicX963),
    mlkemSeed: mlkem.seed,
    kemPqPubkeyEk: b64uEncode(mlkem.ek),
    // Opaque baggage to persist — carried for rotation, never parsed by persist.
    wrappedKemPrivkeyBlob: { v: 2, alg: 'A256GCM', iv: 'AA', ct: 'AA', tag: 'AA' },
  };
}

function meFor(session: Session): MeResponse {
  return {
    account_id: session.accountId,
    kem_pubkey: session.kemPubkeyX963,
    kem_pq_pubkey: session.kemPqPubkeyEk,
  } as unknown as MeResponse;
}

const config = (hours?: number): PublicConfig => ({
  turnstile_sitekey: null,
  unlock_persist_hours: hours,
});

function depsFor(
  session: Session,
  store: UnlockStore,
  overrides: Partial<{
    me: () => Promise<MeResponse>;
    cfg: () => Promise<PublicConfig>;
    now: () => number;
  }> = {},
): PersistDeps {
  return {
    api: {
      getMe: overrides.me ?? (async () => meFor(session)),
      getPublicConfig: overrides.cfg ?? (async () => config(24)),
    },
    now: overrides.now ?? (() => 1_000_000),
    store,
  };
}

// ---- the happy path ----

describe('unlock persistence (S116)', () => {
  it('persist → restore round-trips a real session through all four gates', async () => {
    const session = await realSession();
    const store = memoryStore();
    const deps = depsFor(session, store);

    await persistSession(session, deps);
    expect(store.record).toBeDefined();
    expect(store.record?.expiresAt).toBe(1_000_000 + 24 * 3_600_000);

    const restored = await restoreSession(deps);
    expect(restored).not.toBeNull();
    expect(restored?.accountId).toBe(session.accountId);
    expect(restored?.kemPubkeyX963).toBe(session.kemPubkeyX963);
    expect(restored?.kemPqPubkeyEk).toBe(session.kemPqPubkeyEk);
    // The seed round-tripped through the seal byte-exactly.
    expect(Array.from(restored!.mlkemSeed)).toEqual(Array.from(session.mlkemSeed));
    // The private key object is the persisted (non-extractable) one.
    expect(restored?.kemPrivateKey.extractable).toBe(false);
  });

  it('a restore does NOT extend the window (no-extend-on-restore)', async () => {
    const session = await realSession();
    const store = memoryStore();
    await persistSession(session, depsFor(session, store));
    const stamped = store.record?.expiresAt;

    const restored = await restoreSession(
      depsFor(session, store, { now: () => 1_000_000 + 3_600_000 }),
    );
    expect(restored).not.toBeNull();
    expect(store.record?.expiresAt).toBe(stamped); // untouched by the restore
  });

  // ---- gate 2: lifetime ----

  it('an expired record purges and falls back', async () => {
    const session = await realSession();
    const store = memoryStore();
    await persistSession(session, depsFor(session, store));

    const late = 1_000_000 + 24 * 3_600_000; // exactly at expiry ⇒ expired
    const restored = await restoreSession(depsFor(session, store, { now: () => late }));
    expect(restored).toBeNull();
    expect(store.record).toBeUndefined(); // purged
  });

  // ---- gate 3: server session + continuity (F-UP1) with the F-UP2 split ----

  it('a 401 purges (definitive verdict)', async () => {
    const session = await realSession();
    const store = memoryStore();
    await persistSession(session, depsFor(session, store));

    const restored = await restoreSession(
      depsFor(session, store, {
        me: async () => {
          throw new SignetApiError(401, 'authentication_required', 'no session');
        },
      }),
    );
    expect(restored).toBeNull();
    expect(store.record).toBeUndefined();
  });

  it('a network failure falls back WITHOUT purging (F-UP2 — offline reload keeps the capability)', async () => {
    const session = await realSession();
    const store = memoryStore();
    await persistSession(session, depsFor(session, store));

    const restored = await restoreSession(
      depsFor(session, store, {
        me: async () => {
          throw new TypeError('fetch failed'); // what fetch throws offline
        },
      }),
    );
    expect(restored).toBeNull();
    expect(store.record).toBeDefined(); // NOT purged — restores next online load
  });

  it('a registered-key mismatch purges (F-UP1 — continuity, not just self-consistency)', async () => {
    const session = await realSession();
    const other = await realSession(session.accountId); // same account, different keys
    const store = memoryStore();
    await persistSession(session, depsFor(session, store));

    const restored = await restoreSession(
      depsFor(session, store, { me: async () => meFor(other) }),
    );
    expect(restored).toBeNull();
    expect(store.record).toBeUndefined();
  });

  it('an account-id mismatch purges', async () => {
    const session = await realSession('acct-1');
    const store = memoryStore();
    await persistSession(session, depsFor(session, store));

    const restored = await restoreSession(
      depsFor(session, store, {
        me: async () => ({ ...meFor(session), account_id: 'acct-2' }) as MeResponse,
      }),
    );
    expect(restored).toBeNull();
    expect(store.record).toBeUndefined();
  });

  // ---- gate 4: the seal's AAD binding + integrity ----

  it('a record transplanted onto another account fails the seal AAD and purges', async () => {
    const session = await realSession('acct-1');
    const store = memoryStore();
    await persistSession(session, depsFor(session, store));

    // Tamper: rewrite the record's accountId (as a cross-account transplant
    // would) and make /v1/me agree with the transplant — gates 1–3 pass; the
    // GCM open must fail on the AAD (sealed under acct-1, opened as acct-2).
    store.record = { ...store.record!, accountId: 'acct-2' };
    const restored = await restoreSession(
      depsFor(session, store, {
        me: async () => ({ ...meFor(session), account_id: 'acct-2' }) as MeResponse,
      }),
    );
    expect(restored).toBeNull();
    expect(store.record).toBeUndefined();
  });

  it('a garbage record purges at the shape gate', async () => {
    const session = await realSession();
    const store = memoryStore();
    store.record = { v: 99, junk: true } as unknown as UnlockRecord;
    const restored = await restoreSession(depsFor(session, store));
    expect(restored).toBeNull();
    expect(store.record).toBeUndefined();
  });

  it('an empty store restores nothing and purges nothing', async () => {
    const session = await realSession();
    const store = memoryStore();
    const restored = await restoreSession(depsFor(session, store));
    expect(restored).toBeNull();
  });

  // ---- persist-time knob handling ----

  it('the lifetime knob is clamped to the 0032 bounds', async () => {
    const session = await realSession();
    const store = memoryStore();
    await persistSession(session, depsFor(session, store, { cfg: async () => config(10_000) }));
    expect(store.record?.expiresAt).toBe(1_000_000 + 168 * 3_600_000);
  });

  it('a config fetch failure falls back to the seeded default (24 h)', async () => {
    const session = await realSession();
    const store = memoryStore();
    await persistSession(
      session,
      depsFor(session, store, {
        cfg: async () => {
          throw new TypeError('fetch failed');
        },
      }),
    );
    expect(store.record).toBeDefined();
    expect(store.record?.expiresAt).toBe(1_000_000 + 24 * 3_600_000);
  });

  it('purgePersisted removes the record', async () => {
    const session = await realSession();
    const store = memoryStore();
    await persistSession(session, depsFor(session, store));
    await purgePersisted(store);
    expect(store.record).toBeUndefined();
  });
});
