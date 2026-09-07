// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// The op-bound-challenge ceremony runner (C4): the shared client half of every
// account-management action a Guardian authorizes with a single passkey gesture
// (issue / revoke / change-capability / delete attestation). Each is a server
// two-phase ceremony — `begin` returns WebAuthn assertion options with an
// operation-bound challenge injected (so the assertion cryptographically commits
// to the exact operation + parameters, not just a random nonce), `complete` posts
// the assertion. This runner orchestrates the navigator.credentials.get
// round-trip between them, reusing the C1a WebAuthnGateway seam so it unit-tests
// against a mock authenticator and runs unchanged in a real browser.
//
// Passkey rotation is deliberately NOT here: its 3-gesture flow (assert old +
// register new + assert new, with a browser-side KEM re-wrap) is distinct enough
// to warrant its own module + isolated review (C4-S4 / PR B).

import type { AccountApi } from './api';
import { InvalidInputError } from './crypto/errors';
import {
  assertionOptionsFromServer,
  serializeAssertionResponse,
  type WebAuthnGateway,
} from './webauthn';

export interface CeremonyDeps {
  api: AccountApi;
  gateway: WebAuthnGateway;
}

/** Run an operation-bound ceremony end-to-end. POST `{operation}/ceremony/begin`
 *  with `beginBody`; assert the Guardian's passkey over the server-injected
 *  operation-bound challenge (one Touch ID gesture); POST
 *  `{operation}/ceremony/complete` with the assertion. Returns the typed
 *  complete-phase result. These operations carry no PRF (the server injects no
 *  `prf.eval`), but the serializer strips any PRF output regardless (INV-13). A
 *  dismissed passkey prompt surfaces as InvalidInputError. */
export async function runCeremony<T>(
  deps: CeremonyDeps,
  operation: string,
  beginBody: unknown,
): Promise<T> {
  const { api, gateway } = deps;
  const begin = await api.ceremonyBegin(operation, beginBody);
  const assertion = await gateway.get(assertionOptionsFromServer(begin.options));
  if (!assertion) throw new InvalidInputError('the authorization was cancelled');
  return api.ceremonyComplete<T>(operation, {
    ceremony_id: begin.ceremony_id,
    credential: serializeAssertionResponse(assertion),
  });
}
