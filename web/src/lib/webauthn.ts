// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// WebAuthn ceremony plumbing for the browser (B3 / WebAuthn-PRF v07). The server
// sends standard WebAuthn options as JSON (base64url-encoded buffers, with `prf`
// injected); this module converts them to the ArrayBuffer-shaped options
// `navigator.credentials` wants, serializes the responses back to the JSON the
// server expects, and enforces INV-13 (the PRF *output* never goes to the server).
//
// The actual ceremony runs through an injectable WebAuthnGateway so unit tests
// drive a mock authenticator (canned PRF outputs) and the same code runs
// unchanged against a real browser. The crypto (PRF→W→wrap) is signet-crypto's
// kem_wrap, validated against the golden in C0.

import { b64uDecode, b64uEncode, type Bytes } from './crypto/bytes';
import { InvalidInputError } from './crypto/errors';

// --- the injectable seam ---------------------------------------------------

/** Minimal structural view of a registration credential — satisfied by the real
 *  PublicKeyCredential and by a unit-test mock. */
export interface RegistrationCredentialLike {
  id: string;
  rawId: ArrayBuffer;
  type: string;
  response: {
    clientDataJSON: ArrayBuffer;
    attestationObject: ArrayBuffer;
    getTransports?: () => string[];
  };
  getClientExtensionResults(): PrfClientExtensionResults;
}

/** Minimal structural view of an assertion credential. */
export interface AssertionCredentialLike {
  id: string;
  rawId: ArrayBuffer;
  type: string;
  response: {
    clientDataJSON: ArrayBuffer;
    authenticatorData: ArrayBuffer;
    signature: ArrayBuffer;
    userHandle: ArrayBuffer | null;
  };
  getClientExtensionResults(): PrfClientExtensionResults;
}

export interface PrfClientExtensionResults {
  prf?: {
    enabled?: boolean;
    results?: { first?: ArrayBuffer; second?: ArrayBuffer };
  };
  [key: string]: unknown;
}

/** The two WebAuthn ceremonies, abstracted so tests inject a mock authenticator. */
export interface WebAuthnGateway {
  create(options: CredentialCreationOptions): Promise<RegistrationCredentialLike | null>;
  get(options: CredentialRequestOptions): Promise<AssertionCredentialLike | null>;
}

/** The production gateway: the platform `navigator.credentials`. */
export const browserGateway: WebAuthnGateway = {
  create: (options) =>
    navigator.credentials.create(options) as unknown as Promise<RegistrationCredentialLike | null>,
  get: (options) =>
    navigator.credentials.get(options) as unknown as Promise<AssertionCredentialLike | null>,
};

// --- server-options JSON → navigator.credentials options -------------------

interface CredentialDescriptorJSON {
  id: string;
  type: string;
  transports?: string[];
}

interface RegistrationOptionsJSON {
  publicKey: {
    rp: PublicKeyCredentialRpEntity;
    user: { id: string; name: string; displayName: string };
    challenge: string;
    pubKeyCredParams: PublicKeyCredentialParameters[];
    timeout?: number;
    attestation?: string;
    authenticatorSelection?: AuthenticatorSelectionCriteria;
    excludeCredentials?: CredentialDescriptorJSON[];
    extensions?: Record<string, unknown>;
  };
}

interface AssertionOptionsJSON {
  publicKey: {
    challenge: string;
    timeout?: number;
    rpId?: string;
    allowCredentials?: CredentialDescriptorJSON[];
    userVerification?: string;
    extensions?: {
      prf?: { eval?: { first?: string; second?: string } };
      [key: string]: unknown;
    };
  };
}

function toDescriptor(d: CredentialDescriptorJSON): PublicKeyCredentialDescriptor {
  return {
    id: b64uDecode(d.id),
    type: d.type as PublicKeyCredentialType,
    ...(d.transports ? { transports: d.transports as AuthenticatorTransport[] } : {}),
  };
}

/** Convert the server's registration options (JSON, base64url buffers) into the
 *  `CredentialCreationOptions` for `navigator.credentials.create`. The `prf: {}`
 *  capability request carries no buffers, so it passes through unchanged. */
export function registrationOptionsFromServer(serverOptions: unknown): CredentialCreationOptions {
  const pk = (serverOptions as RegistrationOptionsJSON).publicKey;
  return {
    publicKey: {
      rp: pk.rp,
      user: { id: b64uDecode(pk.user.id), name: pk.user.name, displayName: pk.user.displayName },
      challenge: b64uDecode(pk.challenge),
      pubKeyCredParams: pk.pubKeyCredParams,
      ...(pk.timeout !== undefined ? { timeout: pk.timeout } : {}),
      ...(pk.attestation ? { attestation: pk.attestation as AttestationConveyancePreference } : {}),
      ...(pk.authenticatorSelection ? { authenticatorSelection: pk.authenticatorSelection } : {}),
      ...(pk.excludeCredentials
        ? { excludeCredentials: pk.excludeCredentials.map(toDescriptor) }
        : {}),
      ...(pk.extensions
        ? { extensions: pk.extensions as AuthenticationExtensionsClientInputs }
        : {}),
    },
  };
}

/** Convert the server's assertion options into `CredentialRequestOptions`. The
 *  `prf.eval.first` (and optional `second`) salt is base64url in the JSON and MUST
 *  be decoded to a BufferSource for `navigator.credentials.get`. */
export function assertionOptionsFromServer(serverOptions: unknown): CredentialRequestOptions {
  const pk = (serverOptions as AssertionOptionsJSON).publicKey;
  return {
    publicKey: {
      challenge: b64uDecode(pk.challenge),
      ...(pk.timeout !== undefined ? { timeout: pk.timeout } : {}),
      ...(pk.rpId ? { rpId: pk.rpId } : {}),
      ...(pk.allowCredentials ? { allowCredentials: pk.allowCredentials.map(toDescriptor) } : {}),
      ...(pk.userVerification
        ? { userVerification: pk.userVerification as UserVerificationRequirement }
        : {}),
      ...convertAssertionExtensions(pk.extensions),
    },
  };
}

function convertAssertionExtensions(ext: AssertionOptionsJSON['publicKey']['extensions']): {
  extensions?: AuthenticationExtensionsClientInputs;
} {
  if (!ext) return {};
  const out: Record<string, unknown> = { ...ext };
  if (ext.prf?.eval) {
    const evalInputs: Record<string, BufferSource> = {};
    if (ext.prf.eval.first !== undefined) evalInputs.first = b64uDecode(ext.prf.eval.first);
    if (ext.prf.eval.second !== undefined) evalInputs.second = b64uDecode(ext.prf.eval.second);
    out.prf = { eval: evalInputs };
  }
  return { extensions: out as AuthenticationExtensionsClientInputs };
}

/** Build assertion options for the signup-time PRF harvest of a just-registered
 *  credential (WebAuthn-PRF v07 §"Sign-up flow" step 4). The browser constructs
 *  these locally — the assertion is NOT posted to the server (it only harvests the
 *  PRF output), so the challenge is fresh-random and the fixed salt (`prfSalt()`)
 *  is supplied by the caller. */
export function buildPrfAssertionOptions(params: {
  credentialId: Bytes;
  prfSaltValue: Bytes;
  rpId?: string;
}): CredentialRequestOptions {
  return {
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      ...(params.rpId ? { rpId: params.rpId } : {}),
      allowCredentials: [{ id: params.credentialId, type: 'public-key' }],
      userVerification: 'required',
      extensions: {
        prf: { eval: { first: params.prfSaltValue } },
      } as AuthenticationExtensionsClientInputs,
    },
  };
}

// --- response → server JSON ------------------------------------------------

const toBytes = (a: ArrayBuffer): Bytes => new Uint8Array(a);

/** Serialize a registration response for the server. The server reads only
 *  `prf.enabled` (the INV-6 capability gate), so registration keeps that and
 *  STRIPS everything else under `prf` — notably any `prf.results` (INV-13: the PRF
 *  *output* must never reach the server). Registration requests no eval, so results
 *  should never appear, but the output is stripped even if a future
 *  eval-at-registration change or a hostile authenticator produced one. */
export function serializeRegistrationResponse(cred: RegistrationCredentialLike): unknown {
  const transports = cred.response.getTransports?.();
  const extensionsForServer: Record<string, unknown> = { ...cred.getClientExtensionResults() };
  if (extensionsForServer.prf !== undefined) {
    const enabled = (extensionsForServer.prf as { enabled?: boolean }).enabled === true;
    extensionsForServer.prf = { enabled }; // INV-13: keep only the capability flag
  }
  return {
    id: cred.id,
    rawId: b64uEncode(toBytes(cred.rawId)),
    type: cred.type,
    response: {
      clientDataJSON: b64uEncode(toBytes(cred.response.clientDataJSON)),
      attestationObject: b64uEncode(toBytes(cred.response.attestationObject)),
      ...(transports ? { transports } : {}),
    },
    clientExtensionResults: extensionsForServer,
  };
}

/** Serialize an assertion response for the server, STRIPPING the PRF output
 *  (INV-13): the wrap key W stays browser-side even against a passively-logging
 *  server. The PRF output is read separately via {@link extractPrfFirst} before
 *  this is called. */
export function serializeAssertionResponse(cred: AssertionCredentialLike): unknown {
  const extensionsForServer: Record<string, unknown> = { ...cred.getClientExtensionResults() };
  delete extensionsForServer.prf; // INV-13
  const userHandle = cred.response.userHandle;
  return {
    id: cred.id,
    rawId: b64uEncode(toBytes(cred.rawId)),
    type: cred.type,
    response: {
      clientDataJSON: b64uEncode(toBytes(cred.response.clientDataJSON)),
      authenticatorData: b64uEncode(toBytes(cred.response.authenticatorData)),
      signature: b64uEncode(toBytes(cred.response.signature)),
      userHandle: userHandle ? b64uEncode(toBytes(userHandle)) : null,
    },
    clientExtensionResults: extensionsForServer,
  };
}

/** INV-6 capability check: did the authenticator report PRF support at registration? */
export function registrationReportsPrfEnabled(cred: RegistrationCredentialLike): boolean {
  return cred.getClientExtensionResults().prf?.enabled === true;
}

/** The 32-byte PRF output from an assertion (`clientExtensionResults.prf.results.first`).
 *  Throws if absent or not exactly 32 bytes (a truncated output silently weakens W). */
export function extractPrfFirst(cred: AssertionCredentialLike): Bytes {
  const first = cred.getClientExtensionResults().prf?.results?.first;
  if (!first) throw new InvalidInputError('assertion did not return a PRF result');
  const bytes = new Uint8Array(first);
  if (bytes.length !== 32) throw new InvalidInputError('PRF output must be 32 bytes');
  return bytes;
}
