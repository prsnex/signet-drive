// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { describe, expect, it } from 'vitest';
import type {
  AccountApi,
  RotatePasskeyBeginResponse,
  RotatePasskeyCompleteBody,
  RotatePasskeyResult,
} from './api';
import { b64uEncode, hexDecode, hexEncode, type Bytes } from './crypto/bytes';
import {
  deriveWrapKey,
  unwrapKemPrivkey,
  wrapKemPrivkey,
  type KemPrivkeyWrap,
} from './crypto/kem_wrap';
import { rotatePasskey } from './rotate';
import type {
  AssertionCredentialLike,
  RegistrationCredentialLike,
  WebAuthnGateway,
} from './webauthn';

const OLD_CREDENTIAL_ID = hexDecode('c0ffee01');
const NEW_CREDENTIAL_ID = hexDecode('c0ffee02');
// Two DISTINCT deterministic PRF outputs — a real authenticator emits a different
// one per credential (the whole reason rotation must re-wrap).
const OLD_PRF = hexDecode('1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100');
const NEW_PRF = hexDecode('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff');

const ab = (b: Uint8Array): ArrayBuffer =>
  b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;

interface Counts {
  creates: number;
  gets: number;
  complete?: RotatePasskeyCompleteBody;
}

// The rotation flow calls get() twice (assert old, assert new) and create() once.
// The 1st get() asserts the OLD credential (→ OLD_PRF); the 2nd, after
// registration, asserts the NEW credential (→ NEW_PRF).
function rotatingGateway(counts: Counts): WebAuthnGateway {
  return {
    create: async (): Promise<RegistrationCredentialLike> => {
      counts.creates += 1;
      return {
        id: b64uEncode(NEW_CREDENTIAL_ID),
        rawId: ab(NEW_CREDENTIAL_ID),
        type: 'public-key',
        response: {
          clientDataJSON: ab(hexDecode('01')),
          attestationObject: ab(hexDecode('02')),
          getTransports: () => ['internal'],
        },
        getClientExtensionResults: () => ({ prf: { enabled: true } }),
      };
    },
    get: async (): Promise<AssertionCredentialLike> => {
      counts.gets += 1;
      const first = counts.gets === 1;
      return {
        id: b64uEncode(first ? OLD_CREDENTIAL_ID : NEW_CREDENTIAL_ID),
        rawId: ab(first ? OLD_CREDENTIAL_ID : NEW_CREDENTIAL_ID),
        type: 'public-key',
        response: {
          clientDataJSON: ab(hexDecode('01')),
          authenticatorData: ab(hexDecode('02')),
          signature: ab(hexDecode('03')),
          userHandle: null,
        },
        getClientExtensionResults: () => ({
          prf: { results: { first: ab(first ? OLD_PRF : NEW_PRF) } },
        }),
      };
    },
  };
}

function fakeRotateApi(counts: Counts): AccountApi {
  return {
    listAudit: async () => ({ events: [], next_cursor: null }),
    listPrsns: async () => ({ prsns: [] }),
    discardInProgressPrsn: async () => ({ discarded: true }),
    ceremonyBegin: async () => ({ ceremony_id: 'x', options: {} }),
    ceremonyComplete: async <T>() => ({}) as T,
    rotatePasskeyBegin: async (): Promise<RotatePasskeyBeginResponse> => ({
      ceremony_id: 'rot-1',
      options: {
        publicKey: {
          challenge: b64uEncode(hexDecode('00112233445566778899aabbccddeeff')),
          rpId: 'localhost',
          allowCredentials: [{ id: b64uEncode(OLD_CREDENTIAL_ID), type: 'public-key' }],
          userVerification: 'required',
        },
      },
      registration_ceremony_id: 'reg-2',
      registration_options: {
        publicKey: {
          rp: { id: 'localhost', name: 'Signet Drive' },
          user: { id: b64uEncode(hexDecode('aabbccdd')), name: 'a', displayName: 'a' },
          challenge: b64uEncode(hexDecode('aabbccddeeff00112233445566778899')),
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          extensions: { prf: {} },
        },
      },
    }),
    rotatePasskeyComplete: async (body): Promise<RotatePasskeyResult> => {
      counts.complete = body;
      return { rotated: true };
    },
  };
}

describe('rotatePasskey — the browser-side KEM re-wrap', () => {
  it('preserves the KEM private key: old blob → new blob recovers the SAME pkcs8', async () => {
    // A real KEM keypair; its PKCS#8 is what must survive the rotation.
    const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
      'deriveBits',
    ]);
    const originalPkcs8 = new Uint8Array(
      await crypto.subtle.exportKey('pkcs8', pair.privateKey),
    ) as Bytes;

    // The session's current blob: the key wrapped under the OLD passkey's PRF.
    const oldWrapKey = await deriveWrapKey(OLD_PRF);
    const ivOld = crypto.getRandomValues(new Uint8Array(12));
    const currentBlob: KemPrivkeyWrap = await wrapKemPrivkey(oldWrapKey, originalPkcs8, ivOld);

    const counts: Counts = { creates: 0, gets: 0 };
    const newBlob = await rotatePasskey(
      { api: fakeRotateApi(counts), gateway: rotatingGateway(counts) },
      currentBlob,
    );

    // Exactly the 3 gestures: assert old, register new, assert new.
    expect(counts.gets).toBe(2);
    expect(counts.creates).toBe(1);

    // THE invariant: the new blob, unwrapped under the NEW PRF, is the SAME key.
    const newWrapKey = await deriveWrapKey(NEW_PRF);
    const recovered = await unwrapKemPrivkey(newWrapKey, newBlob);
    expect(hexEncode(recovered)).toBe(hexEncode(originalPkcs8));

    // The wrap envelope actually rotated: the OLD PRF no longer opens it.
    await expect(unwrapKemPrivkey(oldWrapKey, newBlob)).rejects.toThrow();
  });

  it('posts the new blob + both ceremony ids, and strips the PRF from the old assertion (INV-13)', async () => {
    const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
      'deriveBits',
    ]);
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', pair.privateKey)) as Bytes;
    const oldWrapKey = await deriveWrapKey(OLD_PRF);
    const currentBlob = await wrapKemPrivkey(
      oldWrapKey,
      pkcs8,
      crypto.getRandomValues(new Uint8Array(12)),
    );

    const counts: Counts = { creates: 0, gets: 0 };
    const newBlob = await rotatePasskey(
      { api: fakeRotateApi(counts), gateway: rotatingGateway(counts) },
      currentBlob,
    );

    expect(counts.complete?.ceremony_id).toBe('rot-1');
    expect(counts.complete?.registration_ceremony_id).toBe('reg-2');
    expect(counts.complete?.new_wrapped_kem_privkey_blob).toEqual(newBlob);
    const oldAssertion = counts.complete?.old_credential_assertion as {
      clientExtensionResults?: Record<string, unknown>;
    };
    expect(oldAssertion.clientExtensionResults?.prf).toBeUndefined();
  });
});
