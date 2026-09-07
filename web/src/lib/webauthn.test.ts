// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { describe, expect, it } from 'vitest';
import { b64uEncode, hexDecode, hexEncode, type Bytes } from './crypto/bytes';
import { InvalidInputError } from './crypto/errors';
import {
  assertionOptionsFromServer,
  extractPrfFirst,
  registrationOptionsFromServer,
  registrationReportsPrfEnabled,
  serializeAssertionResponse,
  serializeRegistrationResponse,
  type AssertionCredentialLike,
  type RegistrationCredentialLike,
} from './webauthn';

const ab = (hex: string): ArrayBuffer => hexDecode(hex).buffer;

describe('server options JSON -> navigator.credentials options', () => {
  it('registration: decodes challenge + user.id, passes prf:{} through', () => {
    const challenge = hexDecode('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff');
    const userId = hexDecode('aaaaaaaa00004000800000000000000a');
    const options = registrationOptionsFromServer({
      publicKey: {
        rp: { id: 'mysignet.ca', name: 'Signet Drive' },
        user: { id: b64uEncode(userId), name: 'a@test.example', displayName: 'a@test.example' },
        challenge: b64uEncode(challenge),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        extensions: { prf: {} },
      },
    });
    const pk = options.publicKey;
    if (!pk) throw new Error('publicKey missing');
    expect(hexEncode(pk.challenge as Bytes)).toBe(hexEncode(challenge));
    expect(hexEncode(pk.user.id as Bytes)).toBe(hexEncode(userId));
    expect(pk.extensions?.prf).toEqual({});
  });

  it('assertion: decodes challenge, allowCredentials ids, and the prf eval salt', () => {
    const challenge = hexDecode('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20');
    const credId = hexDecode('cafebabe');
    const salt = hexDecode('1111111122222222333333334444444455555555666666667777777788888888');
    const options = assertionOptionsFromServer({
      publicKey: {
        challenge: b64uEncode(challenge),
        rpId: 'mysignet.ca',
        allowCredentials: [{ id: b64uEncode(credId), type: 'public-key' }],
        userVerification: 'required',
        extensions: { prf: { eval: { first: b64uEncode(salt) } } },
      },
    });
    const pk = options.publicKey;
    if (!pk) throw new Error('publicKey missing');
    expect(hexEncode(pk.challenge as Bytes)).toBe(hexEncode(challenge));
    expect(hexEncode(pk.allowCredentials![0].id as Bytes)).toBe(hexEncode(credId));
    const prf = pk.extensions?.prf as { eval: { first: BufferSource } };
    expect(hexEncode(prf.eval.first as Bytes)).toBe(hexEncode(salt));
  });
});

function regCredential(prfEnabled: boolean): RegistrationCredentialLike {
  return {
    id: 'credential-id',
    rawId: ab('aabbccdd'),
    type: 'public-key',
    response: {
      clientDataJSON: ab('01020304'),
      attestationObject: ab('05060708'),
      getTransports: () => ['internal'],
    },
    getClientExtensionResults: () => ({ prf: { enabled: prfEnabled } }),
  };
}

function assertionCredential(): AssertionCredentialLike {
  return {
    id: 'credential-id',
    rawId: ab('aabbccdd'),
    type: 'public-key',
    response: {
      clientDataJSON: ab('01020304'),
      authenticatorData: ab('05060708'),
      signature: ab('090a0b0c'),
      userHandle: null,
    },
    getClientExtensionResults: () => ({
      prf: {
        results: { first: ab('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff') },
      },
      uvm: [[1, 2, 3]],
    }),
  };
}

describe('response serialization', () => {
  it('registration keeps prf.enabled (server reads it for INV-6)', () => {
    const out = serializeRegistrationResponse(regCredential(true)) as Record<string, unknown>;
    expect(out.rawId).toBe(b64uEncode(hexDecode('aabbccdd')));
    const response = out.response as Record<string, unknown>;
    expect(response.attestationObject).toBe(b64uEncode(hexDecode('05060708')));
    expect(response.transports).toEqual(['internal']);
    expect(out.clientExtensionResults).toEqual({ prf: { enabled: true } });
  });

  it('registration STRIPS a prf.results output, keeps only prf.enabled (INV-13)', () => {
    // Registration requests no eval, so a real authenticator never returns prf.results
    // here — but the PRF output must never reach the server even if one appeared.
    const cred = regCredential(true);
    cred.getClientExtensionResults = () => ({
      prf: {
        enabled: true,
        results: { first: ab('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff') },
      },
      uvm: [[1, 2, 3]],
    });
    const out = serializeRegistrationResponse(cred) as Record<string, unknown>;
    expect(out.clientExtensionResults).toEqual({ prf: { enabled: true }, uvm: [[1, 2, 3]] });
  });

  it('assertion STRIPS the prf output (INV-13) but keeps other extensions', () => {
    const out = serializeAssertionResponse(assertionCredential()) as Record<string, unknown>;
    const cer = out.clientExtensionResults as Record<string, unknown>;
    expect(cer.prf).toBeUndefined();
    expect(cer.uvm).toEqual([[1, 2, 3]]);
    const response = out.response as Record<string, unknown>;
    expect(response.signature).toBe(b64uEncode(hexDecode('090a0b0c')));
    expect(response.userHandle).toBeNull();
  });

  it('assertion encodes a present userHandle', () => {
    const cred = assertionCredential();
    cred.response.userHandle = ab('deadbeef');
    const out = serializeAssertionResponse(cred) as Record<string, unknown>;
    const response = out.response as Record<string, unknown>;
    expect(response.userHandle).toBe(b64uEncode(hexDecode('deadbeef')));
  });
});

describe('PRF capability + output', () => {
  it('registrationReportsPrfEnabled reflects the authenticator', () => {
    expect(registrationReportsPrfEnabled(regCredential(true))).toBe(true);
    expect(registrationReportsPrfEnabled(regCredential(false))).toBe(false);
  });

  it('extractPrfFirst returns the 32-byte output', () => {
    const out = extractPrfFirst(assertionCredential());
    expect(out.length).toBe(32);
    expect(hexEncode(out)).toBe('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff');
  });

  it('extractPrfFirst throws when the PRF result is absent', () => {
    const cred = assertionCredential();
    cred.getClientExtensionResults = () => ({});
    expect(() => extractPrfFirst(cred)).toThrow(InvalidInputError);
  });

  it('extractPrfFirst throws on a non-32-byte output (truncation guard)', () => {
    const cred = assertionCredential();
    cred.getClientExtensionResults = () => ({ prf: { results: { first: ab('0011223344') } } });
    expect(() => extractPrfFirst(cred)).toThrow(InvalidInputError);
  });
});
