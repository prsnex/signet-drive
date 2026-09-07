// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { describe, expect, it } from 'vitest';
import type { AccountApi, BeginResponse, CeremonyCompleteBody } from './api';
import { runCeremony, type CeremonyDeps } from './ceremony';
import { b64uEncode, hexDecode } from './crypto/bytes';
import type { AssertionCredentialLike, WebAuthnGateway } from './webauthn';

const CREDENTIAL_ID = hexDecode('c0ffee01');
const ab = (b: Uint8Array): ArrayBuffer =>
  b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer;

// A mock authenticator returning a fixed assertion. Its clientExtensionResults
// carry a prf result on purpose — so the test also proves the runner strips it
// (INV-13): an op-bound assertion must never forward a PRF output, even if the
// authenticator emits one.
function mockGateway(onGet?: (options: CredentialRequestOptions) => void): WebAuthnGateway {
  return {
    create: async () => null,
    get: async (options): Promise<AssertionCredentialLike> => {
      onGet?.(options);
      return {
        id: b64uEncode(CREDENTIAL_ID),
        rawId: ab(CREDENTIAL_ID),
        type: 'public-key',
        response: {
          clientDataJSON: ab(hexDecode('01')),
          authenticatorData: ab(hexDecode('02')),
          signature: ab(hexDecode('03')),
          userHandle: null,
        },
        getClientExtensionResults: () => ({ prf: { results: { first: ab(hexDecode('aa')) } } }),
      };
    },
  };
}

// The user dismissed the passkey prompt.
const cancelGateway: WebAuthnGateway = {
  create: async () => null,
  get: async () => null,
};

interface Captured {
  beginOp?: string;
  beginBody?: unknown;
  completeOp?: string;
  completeBody?: CeremonyCompleteBody;
}

function fakeAccountApi(captured: Captured, result: unknown): AccountApi {
  return {
    listAudit: async () => ({ events: [], next_cursor: null }),
    listPrsns: async () => ({ prsns: [] }),
    discardInProgressPrsn: async () => ({ discarded: true }),
    ceremonyBegin: async (operation, body): Promise<BeginResponse> => {
      captured.beginOp = operation;
      captured.beginBody = body;
      return {
        ceremony_id: 'cer-1',
        options: {
          publicKey: {
            challenge: b64uEncode(hexDecode('00112233445566778899aabbccddeeff')),
            rpId: 'localhost',
            allowCredentials: [{ id: b64uEncode(CREDENTIAL_ID), type: 'public-key' }],
            userVerification: 'required',
          },
        },
      };
    },
    ceremonyComplete: async <T>(operation: string, body: CeremonyCompleteBody): Promise<T> => {
      captured.completeOp = operation;
      captured.completeBody = body;
      return result as T;
    },
    rotatePasskeyBegin: async () => ({
      ceremony_id: 'r',
      options: {},
      registration_ceremony_id: 'rr',
      registration_options: {},
    }),
    rotatePasskeyComplete: async () => ({ rotated: true }),
  };
}

describe('op-bound ceremony runner', () => {
  it('runs begin → assert → complete and returns the typed result', async () => {
    const captured: Captured = {};
    const result = { subject_account_id: 's1', prsn_sharing_capability: 'read_write' };
    const deps: CeremonyDeps = { api: fakeAccountApi(captured, result), gateway: mockGateway() };

    const out = await runCeremony(deps, 'change-sharing-capability', {
      subject_account_id: 's1',
      prsn_sharing_capability: 'read_write',
    });

    expect(out).toEqual(result);
    expect(captured.beginOp).toBe('change-sharing-capability');
    expect(captured.beginBody).toEqual({
      subject_account_id: 's1',
      prsn_sharing_capability: 'read_write',
    });
    expect(captured.completeOp).toBe('change-sharing-capability');
    expect(captured.completeBody?.ceremony_id).toBe('cer-1');
  });

  it('decodes the server challenge into the assertion options it asserts over', async () => {
    let seen: CredentialRequestOptions | undefined;
    const deps: CeremonyDeps = {
      api: fakeAccountApi({}, {}),
      gateway: mockGateway((o) => (seen = o)),
    };
    await runCeremony(deps, 'revoke-attestation', { attestation_id: 'a1' });
    const challenge = seen?.publicKey?.challenge as ArrayBuffer;
    expect(new Uint8Array(challenge).length).toBe(16);
  });

  it('strips the PRF output from the assertion posted to complete (INV-13)', async () => {
    const captured: Captured = {};
    const deps: CeremonyDeps = { api: fakeAccountApi(captured, {}), gateway: mockGateway() };
    await runCeremony(deps, 'delete-account', { confirmation_handle: 'chris' });
    const cred = captured.completeBody?.credential as {
      clientExtensionResults?: Record<string, unknown>;
    };
    expect(cred.clientExtensionResults?.prf).toBeUndefined();
  });

  it('throws when the passkey prompt is dismissed (no assertion)', async () => {
    const deps: CeremonyDeps = { api: fakeAccountApi({}, {}), gateway: cancelGateway };
    await expect(
      runCeremony(deps, 'revoke-attestation', { attestation_id: 'a1' }),
    ).rejects.toThrow();
  });
});
