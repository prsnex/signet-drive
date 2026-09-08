// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';
import type { BeginResponse, SigninResponse, SignetApi, VerifyEmailResponse } from './api';
import {
  completeSignup,
  registerSignupCredential,
  registerSignupPasskey,
  signIn,
  type AuthDeps,
  unlockSignupKeys,
} from './auth';
import { b64uDecode, b64uEncode, hexDecode, hexEncode } from './crypto/bytes';
import { deriveZ, generateEphemeralKeypair, importEcdhPublicX963 } from './crypto/ecdh';
import { initMlkem, mlkemEncapsulate, mlkemDecapsulate } from './crypto/mlkem';
import type {
  AssertionCredentialLike,
  RegistrationCredentialLike,
  WebAuthnGateway,
} from './webauthn';

beforeAll(async () => {
  await initMlkem(
    readFileSync(
      fileURLToPath(new URL('./crypto/mlkem-wasm/signet_crypto_wasm_bg.wasm', import.meta.url)),
    ),
  );
});

// A fixed 32-byte "PRF output" the mock authenticator returns for its single
// credential — identical on every assertion (signup harvest + sign-in), exactly
// as a real PRF is deterministic per credential+salt (INV-4). That determinism is
// precisely what lets the key wrapped at signup be recovered at sign-in.
const PRF_OUTPUT = hexDecode('1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100');
const CREDENTIAL_ID = hexDecode('c0ffee00');

const ab = (b: Uint8Array): ArrayBuffer =>
  b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;

function mockGateway(): WebAuthnGateway {
  return {
    create: async (): Promise<RegistrationCredentialLike> => ({
      id: b64uEncode(CREDENTIAL_ID),
      rawId: ab(CREDENTIAL_ID),
      type: 'public-key',
      response: {
        clientDataJSON: ab(hexDecode('01')),
        attestationObject: ab(hexDecode('02')),
        getTransports: () => ['internal'],
      },
      getClientExtensionResults: () => ({ prf: { enabled: true } }),
    }),
    get: async (): Promise<AssertionCredentialLike> => ({
      id: b64uEncode(CREDENTIAL_ID),
      rawId: ab(CREDENTIAL_ID),
      type: 'public-key',
      response: {
        clientDataJSON: ab(hexDecode('01')),
        authenticatorData: ab(hexDecode('02')),
        signature: ab(hexDecode('03')),
        userHandle: null,
      },
      getClientExtensionResults: () => ({ prf: { results: { first: ab(PRF_OUTPUT) } } }),
    }),
  };
}

/** A fake server: in-memory key-material store (set by keys/initialize, returned
 *  by sign-in), plus capture of the credential sent to complete-signin. */
function fakeServer(): {
  api: SignetApi;
  captured: { signinCredential?: unknown };
  store: { blob?: unknown; pubkey?: string; pqPubkey?: string; credentialId?: string };
} {
  const store: { blob?: unknown; pubkey?: string; pqPubkey?: string; credentialId?: string } = {};
  const captured: { signinCredential?: unknown } = {};
  const regOptions: BeginResponse = {
    ceremony_id: 'reg-1',
    options: {
      publicKey: {
        rp: { id: 'localhost', name: 'Signet Drive' },
        user: { id: b64uEncode(hexDecode('aabbccdd')), name: 'a', displayName: 'a' },
        challenge: b64uEncode(hexDecode('00112233445566778899aabbccddeeff')),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        extensions: { prf: {} },
      },
    },
  };
  const signinOptions: BeginResponse = {
    ceremony_id: 'auth-1',
    options: {
      publicKey: {
        challenge: b64uEncode(hexDecode('44556677889900aabbccddeeff00112233445566')),
        rpId: 'localhost',
        allowCredentials: [{ id: b64uEncode(CREDENTIAL_ID), type: 'public-key' }],
        userVerification: 'required',
        extensions: { prf: { eval: { first: b64uEncode(hexDecode('00'.repeat(32))) } } },
      },
    },
  };
  const api: SignetApi = {
    beginSignup: async () => {},
    // S206: the signup gate. Open here so these auth tests exercise the normal
    // path — the gate has its own tests and is not what this file is about.
    getSignupStatus: async () => ({ open: true }),
    // The admin half of the gate. Present only to satisfy the interface — these
    // auth tests never call them, and the gate has its own coverage.
    getSignupGate: async () => ({ mode: 'open' as const, cohort: null }),
    setSignupGateMode: async () => ({ mode: 'open' as const, cohort: null }),
    openSignupCohort: async () => ({
      cohort_id: 'c-1',
      label: 'test',
      cohort_ref: '260831-001',
      max_accounts: 1,
      used: 0,
      remaining: 1,
    }),
    closeSignupCohort: async () => {},
    createSignupInvite: async () => {},
    verifyEmail: async (): Promise<VerifyEmailResponse> => ({
      account_id: 'acct-1',
      handle: 'alice',
    }),
    beginRegistration: async () => regOptions,
    completeRegistration: async () => {},
    beginSignin: async () => signinOptions,
    completeSignin: async (body): Promise<SigninResponse> => {
      captured.signinCredential = body.credential;
      return {
        account_id: 'acct-1',
        wrapped_kem_privkey_blob: store.blob,
        kem_pubkey: store.pubkey,
        kem_pq_pubkey: store.pqPubkey,
      };
    },
    logout: async () => {},
    keysInitialize: async (body) => {
      store.blob = body.wrapped_kem_privkey_blob;
      store.pubkey = body.kem_pubkey;
      store.pqPubkey = body.kem_pq_pubkey;
      store.credentialId = body.credential_id;
    },
    getPublicConfig: async () => ({ turnstile_sitekey: null }),
  };
  return { api, captured, store };
}

describe('auth flows — keystone round-trip (mock authenticator + fake server)', () => {
  it('signup wraps the KEM key; sign-in recovers the SAME key', async () => {
    const { api } = fakeServer();
    const deps: AuthDeps = { api, gateway: mockGateway() };

    const signup = await completeSignup(deps, 'verify-token');
    expect(signup.accountId).toBe('acct-1');
    expect(signup.kemPubkeyX963.length).toBeGreaterThan(0);

    const session = await signIn(deps, 'alice@test.example');
    expect(session.accountId).toBe('acct-1');

    // The keystone: sign-in's recovered (non-extractable) private key pairs with
    // the public key registered at signup — proven via ECDH symmetry
    // (kem_priv·peer_pub == peer_priv·kem_pub).
    const kemPub = await importEcdhPublicX963(b64uDecode(signup.kemPubkeyX963));
    const peer = await generateEphemeralKeypair();
    const zRecovered = await deriveZ(session.kemPrivateKey, peer.publicKey);
    const zOriginal = await deriveZ(peer.privateKey, kemPub);
    expect(hexEncode(zRecovered)).toBe(hexEncode(zOriginal));

    // The PQ keystone (PRF-blob v2): the seed recovered at sign-in is the SAME
    // ML-KEM identity published at signup — a writer encapsulating to the
    // published ek produces a secret the session seed decapsulates.
    expect(session.kemPqPubkeyEk).toBe(signup.kemPqPubkeyEk);
    const { ct, ss } = await mlkemEncapsulate(b64uDecode(signup.kemPqPubkeyEk));
    expect(hexEncode(await mlkemDecapsulate(session.mlkemSeed, ct))).toBe(hexEncode(ss));
  });

  // bug062: the passkey half must be retryable on its own. A cancelled credential
  // ceremony leaves the single-use verification token already consumed, so the
  // page's "Try again" re-runs ONLY this half — it must never need the token.
  it('registerSignupPasskey completes from an accountId alone (no verification token)', async () => {
    const { api } = fakeServer();
    let verifyEmailCalls = 0;
    const deps: AuthDeps = {
      api: {
        ...api,
        verifyEmail: async () => {
          verifyEmailCalls += 1;
          return { account_id: 'acct-1', handle: 'alice' };
        },
      },
      gateway: mockGateway(),
    };

    const session = await registerSignupPasskey(deps, 'acct-1');
    expect(session.accountId).toBe('acct-1');
    expect(session.kemPubkeyX963.length).toBeGreaterThan(0);
    expect(verifyEmailCalls).toBe(0);
  });

  it('sign-in rejects a missing or substituted ML-KEM directory key (§9.2 on self)', async () => {
    const { api, store } = fakeServer();
    const deps: AuthDeps = { api, gateway: mockGateway() };
    await completeSignup(deps, 'verify-token');

    // Missing PQ key for a v2-blob account → infrastructure lying → reject.
    const pq = store.pqPubkey;
    store.pqPubkey = undefined;
    await expect(signIn(deps, 'alice@test.example')).rejects.toThrow(/no ML-KEM public key/);

    // A substituted (valid-shape, wrong-identity) ek → byte-compare rejects.
    store.pqPubkey = b64uEncode(new Uint8Array(1568).fill(0x77));
    await expect(signIn(deps, 'alice@test.example')).rejects.toThrow(/does not match/);

    store.pqPubkey = pq;
    await expect(signIn(deps, 'alice@test.example')).resolves.toBeTruthy();
  });

  it('INV-13: the assertion sent to the server carries no PRF output', async () => {
    const { api, captured } = fakeServer();
    const deps: AuthDeps = { api, gateway: mockGateway() };
    await completeSignup(deps, 'verify-token');
    await signIn(deps, 'alice@test.example');
    const cred = captured.signinCredential as { clientExtensionResults?: Record<string, unknown> };
    expect(cred.clientExtensionResults?.prf).toBeUndefined();
  });

  it('bug244: sign-in FINISHES an unfinished signup — no key material → initialise it, and a second sign-in recovers the same key', async () => {
    const { api, store } = fakeServer(); // store empty — the unlock never ran
    const deps: AuthDeps = { api, gateway: mockGateway() };
    expect(store.blob).toBeUndefined();

    const first = await signIn(deps, 'alice@test.example');
    expect(first.accountId).toBe('acct-1');
    expect(store.blob).toBeDefined();
    // bug245: the initialise names the passkey the assertion was made with.
    expect(store.credentialId).toBe(b64uEncode(CREDENTIAL_ID));
    expect(store.pubkey).toBe(first.kemPubkeyX963);
    expect(store.pqPubkey).toBe(first.kemPqPubkeyEk);

    const second = await signIn(deps, 'alice@test.example');
    expect(second.kemPubkeyX963).toBe(first.kemPubkeyX963);
    expect(second.kemPqPubkeyEk).toBe(first.kemPqPubkeyEk);
    expect(hexEncode(second.mlkemSeed)).toBe(hexEncode(first.mlkemSeed));
  });

  it('bug244: a cancelled unlock retries the unlock ALONE — zero further registration requests', async () => {
    const { api, store } = fakeServer();
    let beginRegistrationCalls = 0;
    let completeRegistrationCalls = 0;
    const countingApi: SignetApi = {
      ...api,
      beginRegistration: async (id) => {
        beginRegistrationCalls += 1;
        return api.beginRegistration(id);
      },
      completeRegistration: async (id, body) => {
        completeRegistrationCalls += 1;
        return api.completeRegistration(id, body);
      },
    };
    // The authenticator cancels the FIRST assertion (the user dismissed the second
    // prompt), then answers the retry.
    const real = mockGateway();
    let gets = 0;
    const gateway: WebAuthnGateway = {
      create: real.create,
      get: async (options) => {
        gets += 1;
        if (gets === 1) return null;
        return real.get(options);
      },
    };
    const deps: AuthDeps = { api: countingApi, gateway };

    const credential = await registerSignupCredential(deps, 'acct-1');
    expect(hexEncode(credential.credentialId)).toBe(hexEncode(CREDENTIAL_ID));
    expect(beginRegistrationCalls).toBe(1);
    expect(completeRegistrationCalls).toBe(1);
    expect(store.blob).toBeUndefined();

    await expect(unlockSignupKeys(deps, 'acct-1', credential)).rejects.toThrow(/cancelled/);
    expect(store.blob).toBeUndefined();

    const session = await unlockSignupKeys(deps, 'acct-1', credential);
    expect(session.accountId).toBe('acct-1');
    expect(store.blob).toBeDefined();
    expect(store.credentialId).toBe(b64uEncode(CREDENTIAL_ID));
    expect(gets).toBe(2);
    expect(beginRegistrationCalls).toBe(1);
    expect(completeRegistrationCalls).toBe(1);

    // And the key the unlock wrapped is the one sign-in recovers.
    const signedIn = await signIn({ api: countingApi, gateway: real }, 'alice@test.example');
    expect(signedIn.kemPubkeyX963).toBe(session.kemPubkeyX963);
  });
});
