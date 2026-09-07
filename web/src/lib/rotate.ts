// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Passkey rotation (C4-S4 client) — the one piece of genuinely novel browser
// crypto in the C4 human surface. A human swaps their passkey without losing
// access to their data: assert the CURRENT passkey (authorize the rotation AND
// harvest its PRF), register a NEW passkey, assert it (harvest its PRF), then
// re-wrap the KEM private key from the old PRF to the new one and post the new
// wrap. The KEM keypair is unchanged — only its wrap envelope rotates — so every
// wrapped DEK in the user's storage stays openable; the server stores the blob
// opaquely and never sees the KEM key or any PRF output (INV-13).
//
// The session holds the KEM key NON-extractable (it can derive, never re-export),
// so the PKCS#8 needed for the re-wrap is recovered by unwrapping the current
// blob under the old PRF — not by exporting the session key. The crypto-correctness
// invariant (new blob, under new PRF, recovers the SAME PKCS#8) is pinned by the
// unit test; the E2E proves it end-to-end (the new passkey signs in + decrypts).

import type { AccountApi } from './api';
import { b64uEncode } from './crypto/bytes';
import { InvalidInputError } from './crypto/errors';
import {
  deriveWrapKey,
  prfSalt,
  unwrapKemPrivkey,
  wrapKemPrivkey,
  type KemPrivkeyWrap,
} from './crypto/kem_wrap';
import {
  assertionOptionsFromServer,
  buildPrfAssertionOptions,
  extractPrfFirst,
  registrationOptionsFromServer,
  registrationReportsPrfEnabled,
  serializeAssertionResponse,
  serializeRegistrationResponse,
  type WebAuthnGateway,
} from './webauthn';

export interface RotateDeps {
  api: AccountApi;
  gateway: WebAuthnGateway;
}

/** Run the 3-gesture passkey rotation end-to-end. Returns the new PRF-wrapped KEM
 *  blob, which the caller stores in the session (the KEM keypair + its public key
 *  are unchanged). Throws InvalidInputError if any gesture is dismissed or the new
 *  authenticator lacks PRF. */
export async function rotatePasskey(
  deps: RotateDeps,
  currentBlob: KemPrivkeyWrap,
): Promise<KemPrivkeyWrap> {
  const { api, gateway } = deps;
  const begin = await api.rotatePasskeyBegin();

  // Gesture 1 — assert the CURRENT passkey over the server's operation-bound
  // challenge, and harvest its PRF. The server's options carry no prf.eval
  // (begin_ceremony injects only the challenge), so we add the fixed salt
  // locally; sign-in proves a single assertion can be both PRF-bearing and
  // server-verified (the PRF output is stripped before posting, INV-13).
  const oldAssertion = await gateway.get(await assertionOptionsWithLocalPrf(begin.options));
  if (!oldAssertion) throw new InvalidInputError('the rotation was cancelled');
  const oldPrf = extractPrfFirst(oldAssertion);

  // Recover the current PKCS#8 by unwrapping under the old PRF (the session key
  // is non-extractable; this is the only way to the bytes the re-wrap needs).
  const oldWrapKey = await deriveWrapKey(oldPrf);
  const pkcs8 = await unwrapKemPrivkey(oldWrapKey, currentBlob);

  // Gesture 2 — register the NEW passkey (its own registration ceremony, issued
  // at begin; prf capability already requested in the options).
  const newCredential = await gateway.create(
    registrationOptionsFromServer(begin.registration_options),
  );
  if (!newCredential) throw new InvalidInputError('the rotation was cancelled');
  if (!registrationReportsPrfEnabled(newCredential)) {
    throw new InvalidInputError('this authenticator does not support the required PRF extension');
  }

  // Gesture 3 — assert the NEW passkey locally (not posted; just to harvest its
  // PRF, exactly as signup harvests a freshly-registered credential's PRF).
  const newPrfAssertion = await gateway.get(
    buildPrfAssertionOptions({
      credentialId: new Uint8Array(newCredential.rawId),
      prfSaltValue: await prfSalt(),
      rpId: readRpId(begin.registration_options),
    }),
  );
  if (!newPrfAssertion) throw new InvalidInputError('the rotation was cancelled');
  const newPrf = extractPrfFirst(newPrfAssertion);

  // Re-wrap the SAME PKCS#8 under the new PRF (fresh IV per wrap event).
  const newWrapKey = await deriveWrapKey(newPrf);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const newBlob = await wrapKemPrivkey(newWrapKey, pkcs8, iv);

  await api.rotatePasskeyComplete({
    ceremony_id: begin.ceremony_id,
    registration_ceremony_id: begin.registration_ceremony_id,
    old_credential_assertion: serializeAssertionResponse(oldAssertion),
    new_credential: serializeRegistrationResponse(newCredential),
    new_wrapped_kem_privkey_blob: newBlob,
  });

  return newBlob;
}

/** Decode the server's assertion options into the BufferSource form, injecting a
 *  local prf.eval salt so the assertion also harvests the credential's PRF —
 *  the same single-assertion shape sign-in uses. */
async function assertionOptionsWithLocalPrf(
  serverOptions: unknown,
): Promise<CredentialRequestOptions> {
  const copy = JSON.parse(JSON.stringify(serverOptions)) as {
    publicKey: { extensions?: { prf?: { eval?: { first?: string } } } };
  };
  const extensions = (copy.publicKey.extensions ??= {});
  extensions.prf = { eval: { first: b64uEncode(await prfSalt()) } };
  return assertionOptionsFromServer(copy);
}

/** The rp.id from the new passkey's registration options — the relying party the
 *  local gesture-3 PRF assertion must target. */
function readRpId(options: unknown): string | undefined {
  const id = (options as { publicKey?: { rp?: { id?: string } } }).publicKey?.rp?.id;
  return typeof id === 'string' ? id : undefined;
}
