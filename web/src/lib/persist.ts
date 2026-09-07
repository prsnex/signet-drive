// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Unlock persistence (S116; design: docs/security/Signet-Drive-Unlock-Persistence-
// Design-Note, reviewed SOUND — Gus 2026-07-14; product decisions Chris S116:
// device-scoped, 24 h default as the `web_unlock_persist_hours` server knob).
//
// Persists the session's decryption capability in origin-scoped IndexedDB for a
// bounded lifetime, so a reload restores the unlocked session with zero gestures:
// the P-256 KEM private key as a structured-cloned NON-extractable CryptoKey, and
// the ML-KEM (d,z) seed sealed AES-256-GCM under a second non-extractable key
// (WebCrypto has no ML-KEM, so the seed cannot be non-extractable itself — the
// design note prices that asymmetry honestly; §2/§4 T3).
//
// Restore runs behind four gates and FAILS OPEN to the gesture path (ReunlockCard /
// sign-in) on ANY failure — restore is an optimization, never a new failure mode:
//   1. record present + well-formed;
//   2. lifetime: `now < expiresAt` — stamped at PERSIST time from the server knob,
//      and never extended by a restore (the window measures time-since-last-
//      VERIFICATION; every fresh gesture re-persists and so resets it);
//   3. the live-server-session gate (`GET /v1/me` on the httpOnly cookie), which
//      also anchors CONTINUITY (review F-UP1): the persisted publics must
//      byte-match the account's REGISTERED keys from the same authoritative
//      source the CLI gates on — a rotation/key-change ends silent restores at
//      the next reload, not at expiry. Per F-UP2: a definitive auth verdict
//      (401/403, account/key mismatch) PURGES; a network failure does NOT (an
//      offline reload must not destroy a valid capability);
//   4. both sign-in integrity gates re-run (`kemKeypairMatches` + the FIPS-203
//      ekFromSeed byte-compare) — they cross-check the unsealed public halves
//      against the private material, catching what GCM cannot see.

import { createApiClient, SignetApiError, type DriveApi, type SignetApi } from './api';
import type { Session } from './auth';
import { b64uDecode, utf8Encode, type Bytes } from './crypto/bytes';
import type { KemPrivkeyWrap } from './crypto/kem_wrap';
import { mlkemEkFromSeed } from './crypto/mlkem';
import { hexEncode } from './crypto/bytes';
import { kemKeypairMatches } from './crypto/wrap';

const DB_NAME = 'signet-unlock';
const STORE = 'unlock';
const RECORD_KEY = 'current';
const RECORD_VERSION = 1;
/** The client-side fallback when the `web_unlock_persist_hours` knob is
 *  unreadable at persist time — matches the migration-0032 seeded default. */
const DEFAULT_PERSIST_HOURS = 24;
/** Defensive client-side clamp mirroring the knob's 0032 bounds. */
const MIN_PERSIST_HOURS = 1;
const MAX_PERSIST_HOURS = 168;

/** The seal's AAD binds the ciphertext to the account AND this record format —
 *  a record transplanted across accounts (or replayed into a future layout)
 *  fails the GCM open, not just a field compare. */
const SEAL_PURPOSE = 'signet-unlock-v1';

export interface UnlockRecord {
  v: number;
  accountId: string;
  /** Structured-cloned NON-extractable P-256 private key (use-only for script). */
  kemPrivateKey: CryptoKey;
  /** Non-extractable AES-256-GCM key sealing the ML-KEM seed; fresh per persist. */
  sealKey: CryptoKey;
  mlkemSeedSealed: ArrayBuffer;
  sealIv: Bytes;
  kemPubkeyX963: string;
  kemPqPubkeyEk: string;
  wrappedKemPrivkeyBlob: KemPrivkeyWrap;
  createdAt: number;
  expiresAt: number;
}

/** The storage seam. The default is the real IndexedDB store below; unit tests
 *  inject an in-memory one — Node's structuredClone cannot carry a CryptoKey
 *  (verified empirically S116), so the REAL round-trip (structured-cloning
 *  non-extractable keys through IDB) is proven in e2e in real Chrome — the
 *  design note's spike-test-first rule. */
export interface UnlockStore {
  get(): Promise<unknown>;
  put(value: UnlockRecord): Promise<void>;
  delete(): Promise<void>;
}

/** Injectable seams so the gate logic unit-tests without a browser. */
export interface PersistDeps {
  api: Pick<DriveApi, 'getMe'> & Pick<SignetApi, 'getPublicConfig'>;
  now: () => number;
  store: UnlockStore;
}

function defaultDeps(): PersistDeps {
  return {
    api: createApiClient(),
    now: () => Date.now(),
    store: { get: idbGet, put: idbPut, delete: idbDelete },
  };
}

// ---- minimal promisified IndexedDB (one DB, one store, one record) ----

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(STORE)) {
        req.result.createObjectStore(STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('indexeddb open failed'));
  });
}

async function idbGet(): Promise<unknown> {
  const db = await openDb();
  try {
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, 'readonly');
      const req = tx.objectStore(STORE).get(RECORD_KEY);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error ?? new Error('indexeddb read failed'));
    });
  } finally {
    db.close();
  }
}

async function idbPut(value: UnlockRecord): Promise<void> {
  const db = await openDb();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      tx.objectStore(STORE).put(value, RECORD_KEY);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error('indexeddb write failed'));
    });
  } finally {
    db.close();
  }
}

async function idbDelete(): Promise<void> {
  const db = await openDb();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      tx.objectStore(STORE).delete(RECORD_KEY);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error('indexeddb delete failed'));
    });
  } finally {
    db.close();
  }
}

// ---- the seal (AES-256-GCM over the ML-KEM seed) ----

function sealAad(accountId: string): Bytes {
  return utf8Encode(`${accountId}${SEAL_PURPOSE}`);
}

async function sealSeed(
  accountId: string,
  seed: Bytes,
): Promise<{ sealKey: CryptoKey; sealIv: Bytes; sealed: ArrayBuffer }> {
  // Non-extractable + fresh per persist: no nonce-reuse exposure, and the key
  // itself is never script-readable — at rest no field is plaintext key material
  // readable by a naive storage dump (design §3.1; what this does NOT claim is
  // at-rest encryption against a disk-level attacker — §4 T3).
  const sealKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
  const sealIv = crypto.getRandomValues(new Uint8Array(12));
  const sealed = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: sealIv, additionalData: sealAad(accountId) },
    sealKey,
    seed as BufferSource,
  );
  return { sealKey, sealIv, sealed };
}

// ---- public surface ----

/** Persist the unlocked session. Called after every FRESH GESTURE (signup
 *  complete, sign-in, re-unlock, passkey rotation — each involves a real UV
 *  gesture, so each legitimately resets the lifetime window). Failures are
 *  swallowed to a console warning: persistence is an optimization, and a
 *  persist failure must never break the sign-in that just succeeded. */
export async function persistSession(
  session: Session,
  deps: PersistDeps = defaultDeps(),
): Promise<void> {
  try {
    let hours = DEFAULT_PERSIST_HOURS;
    try {
      const cfg = await deps.api.getPublicConfig();
      if (typeof cfg.unlock_persist_hours === 'number') {
        hours = Math.min(MAX_PERSIST_HOURS, Math.max(MIN_PERSIST_HOURS, cfg.unlock_persist_hours));
      }
    } catch {
      // knob unreadable → the seeded default; never block a persist on config
    }
    const { sealKey, sealIv, sealed } = await sealSeed(session.accountId, session.mlkemSeed);
    const now = deps.now();
    await deps.store.put({
      v: RECORD_VERSION,
      accountId: session.accountId,
      kemPrivateKey: session.kemPrivateKey,
      sealKey,
      sealIv,
      mlkemSeedSealed: sealed,
      kemPubkeyX963: session.kemPubkeyX963,
      kemPqPubkeyEk: session.kemPqPubkeyEk,
      wrappedKemPrivkeyBlob: session.wrappedKemPrivkeyBlob,
      createdAt: now,
      expiresAt: now + hours * 3_600_000,
    });
  } catch (err) {
    console.warn('unlock persistence: persist failed (continuing without)', err);
  }
}

/** Remove the persisted capability. Called from Lock, sign-out (BEFORE the
 *  logout POST — the local purge must not depend on the network call landing),
 *  switch-account, and every restore-gate failure that is a definitive verdict. */
export async function purgePersisted(store: UnlockStore = defaultDeps().store): Promise<void> {
  try {
    await store.delete();
  } catch (err) {
    console.warn('unlock persistence: purge failed', err);
  }
}

function isRecordShaped(value: unknown): value is UnlockRecord {
  if (typeof value !== 'object' || value === null) return false;
  const r = value as Record<string, unknown>;
  return (
    r.v === RECORD_VERSION &&
    typeof r.accountId === 'string' &&
    typeof r.kemPubkeyX963 === 'string' &&
    typeof r.kemPqPubkeyEk === 'string' &&
    typeof r.expiresAt === 'number' &&
    r.kemPrivateKey instanceof CryptoKey &&
    r.sealKey instanceof CryptoKey
  );
}

/** Attempt the zero-gesture restore. Returns the restored Session, or null —
 *  in which case the caller proceeds exactly as today (cookie probe →
 *  ReunlockCard / sign-in). See the module doc for the four gates. */
export async function restoreSession(deps: PersistDeps = defaultDeps()): Promise<Session | null> {
  // Gate 1 — record present + well-formed. A malformed record is a definitive
  // local verdict (purge); an IDB read error is environmental (no purge).
  let raw: unknown;
  try {
    raw = await deps.store.get();
  } catch {
    return null;
  }
  if (raw === undefined || raw === null) return null;
  if (!isRecordShaped(raw)) {
    await purgePersisted(deps.store);
    return null;
  }
  const record = raw;

  try {
    // Gate 2 — lifetime (client-enforced; stamped at persist).
    if (deps.now() >= record.expiresAt) {
      await purgePersisted(deps.store);
      return null;
    }

    // Gate 3 — live server session + continuity (F-UP1) with the F-UP2 split:
    // definitive auth verdicts purge; network failures fall back WITHOUT purging.
    let me;
    try {
      me = await deps.api.getMe();
    } catch (err) {
      if (err instanceof SignetApiError && (err.status === 401 || err.status === 403)) {
        await purgePersisted(deps.store);
      }
      return null;
    }
    if (
      me.account_id !== record.accountId ||
      !me.kem_pubkey ||
      me.kem_pubkey !== record.kemPubkeyX963 ||
      !me.kem_pq_pubkey ||
      me.kem_pq_pubkey !== record.kemPqPubkeyEk
    ) {
      await purgePersisted(deps.store);
      return null;
    }

    // Gate 4a — unseal the seed (GCM authenticates; AAD binds account+purpose).
    const seed = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: record.sealIv, additionalData: sealAad(record.accountId) },
        record.sealKey,
        record.mlkemSeedSealed,
      ),
    );

    // Gate 4b — both sign-in integrity gates, re-run against the persisted
    // material (crypto-review #5 + PQR §7 applied to restore).
    if (!(await kemKeypairMatches(record.kemPrivateKey, b64uDecode(record.kemPubkeyX963)))) {
      await purgePersisted(deps.store);
      return null;
    }
    const ekFromSeed = await mlkemEkFromSeed(seed);
    if (hexEncode(ekFromSeed) !== hexEncode(b64uDecode(record.kemPqPubkeyEk))) {
      await purgePersisted(deps.store);
      return null;
    }

    return {
      accountId: record.accountId,
      kemPrivateKey: record.kemPrivateKey,
      kemPubkeyX963: record.kemPubkeyX963,
      mlkemSeed: seed,
      kemPqPubkeyEk: record.kemPqPubkeyEk,
      wrappedKemPrivkeyBlob: record.wrappedKemPrivkeyBlob,
    };
  } catch (err) {
    // Any unexpected failure inside the gates is a definitive local verdict for
    // THIS record (it cannot restore) — purge and fall back to the gesture path.
    console.warn('unlock persistence: restore failed — falling back to re-unlock', err);
    await purgePersisted(deps.store);
    return null;
  }
}
