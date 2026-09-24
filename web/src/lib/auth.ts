// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Human auth flows (B3): signup (the email-link continue half) and identified
// sign-in. Each ends with the KEM private key imported NON-extractable in memory
// — the session's decryption capability that C2-C4 depend on. Both take an
// injected api + WebAuthn gateway, so they unit-test against a fake server + a
// mock authenticator (no real navigator.credentials). The crypto is
// signet-crypto's kem_wrap, golden-validated in C0.

import type { SignetApi } from './api';
import { b64uDecode, b64uEncode, hexEncode, type Bytes } from './crypto/bytes';
import { IntegrityError, InvalidInputError } from './crypto/errors';
import {
  deriveWrapKey,
  prfSalt,
  unwrapKemPrivkey,
  wrapKemPrivkey,
  type KemPrivkeyWrap,
} from './crypto/kem_wrap';
import { decodeKeyBlobV2, encodeKeyBlobV2 } from './crypto/keyblob';
import { mlkemEkFromSeed, mlkemKeygen } from './crypto/mlkem';
import { kemKeypairMatches } from './crypto/wrap';
import { generateKemKeypair, importKemPrivateNonExtractable } from './kem';
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

export interface AuthDeps {
  api: SignetApi;
  gateway: WebAuthnGateway;
}

/** An authenticated session: the account id plus the in-memory non-extractable
 *  KEM private key — the decryption capability C2-C4 use for every DEK unwrap.
 *  Also carries the current PRF-wrapped KEM blob: the session key is
 *  non-extractable (cannot be re-exported to PKCS#8), so passkey rotation (C4-S4)
 *  re-derives the PKCS#8 by unwrapping this blob under the old passkey's PRF
 *  before re-wrapping it under the new one. */
export interface Session {
  accountId: string;
  kemPrivateKey: CryptoKey;
  kemPubkeyX963: string;
  /** The session's ML-KEM-1024 (d,z) seed (PQR §7 — the PQ decryption
   *  capability; the dk regenerates from it inside the wasm per op). Held
   *  in-memory only, alongside the non-extractable classical key. */
  mlkemSeed: Bytes;
  /** The session's ML-KEM-1024 encapsulation key (base64url, 1568 B) — the
   *  self-wrap target's PQ half, verified against the seed at sign-in. */
  kemPqPubkeyEk: string;
  wrappedKemPrivkeyBlob: KemPrivkeyWrap;
}

/** Signup phase 1: record the pending email verification. The user then clicks
 *  the emailed link, landing where {@link completeSignup} runs. (Email delivery is
 *  stubbed server-side until Phase 4.) */
export function beginSignup(
  api: SignetApi,
  input: { handle: string; email: string; turnstileToken?: string; acceptedTerms: boolean },
): Promise<void> {
  return api.beginSignup(input);
}

/** Signup phase 2a (the email-link continue page): verify the token, which mints
 *  the session and creates — or adopts (Bug023 B) — the account.
 *
 *  Split from the passkey half so the page can explain the OS credential dialog
 *  BEFORE it fires, and can retry just the passkey step afterwards without
 *  re-consuming the single-use verification token (bug062). Sequencing only —
 *  the ceremony, its operations, and their order are unchanged. */
export async function verifySignupEmail(
  deps: AuthDeps,
  token: string,
  acceptTerms = false,
): Promise<{ accountId: string; handle: string }> {
  const verified = await deps.api.verifyEmail(token, acceptTerms);
  return { accountId: verified.account_id, handle: verified.handle };
}

/** The passkey created in signup phase 2b-i, carried to phase 2b-ii (the unlock).
 *  Only what the local PRF assertion needs: the credential id to allow, and the
 *  rp id the registration was made against. Nothing secret. */
export interface SignupCredential {
  credentialId: Bytes;
  rpId?: string;
}

/** Signup phase 2b-i: register a passkey. One authenticator prompt
 *  (`credentials.create()`), then `complete-registration`. Returns the created
 *  credential's descriptor for phase 2b-ii.
 *
 *  bug244: split from the unlock so the page can put ITS OWN screen — and the
 *  user's own click — between the two prompts, and so a failure after this point
 *  retries the unlock alone. Retrying registration after a stored credential is
 *  refused by the server (v1 is single-passkey), which was the lock-out. */
export async function registerSignupCredential(
  deps: AuthDeps,
  accountId: string,
): Promise<SignupCredential> {
  const { api, gateway } = deps;

  const reg = await api.beginRegistration(accountId);
  const created = await gateway.create(registrationOptionsFromServer(reg.options));
  if (!created) throw new InvalidInputError('passkey registration was cancelled');
  if (!registrationReportsPrfEnabled(created)) {
    throw new InvalidInputError('this authenticator does not support the required PRF extension');
  }
  await api.completeRegistration(accountId, {
    ceremony_id: reg.ceremony_id,
    credential: serializeRegistrationResponse(created),
  });
  return { credentialId: new Uint8Array(created.rawId), rpId: readRpId(reg.options) };
}

/** Signup phase 2b-ii: unlock. One authenticator prompt (`credentials.get()` on
 *  the passkey just created — a LOCAL assertion, never posted; see
 *  buildPrfAssertionOptions) harvests its PRF output; then the hybrid KEM key
 *  material is generated, wrapped under it, and initialised on the server.
 *  Retry-safe: needs only the accountId and the credential descriptor; makes no
 *  registration request. */
export async function unlockSignupKeys(
  deps: AuthDeps,
  accountId: string,
  credential: SignupCredential,
): Promise<Session> {
  const { api, gateway } = deps;
  const assertion = await gateway.get(
    buildPrfAssertionOptions({
      credentialId: credential.credentialId,
      prfSaltValue: await prfSalt(),
      rpId: credential.rpId,
    }),
  );
  if (!assertion) throw new InvalidInputError('PRF assertion was cancelled');
  return initializeKeysFromPrf(api, accountId, extractPrfFirst(assertion), credential.credentialId);
}

/** Signup phase 2b, both halves back to back: register a passkey, harvest its
 *  PRF output, generate + wrap the KEM keypair, initialize the account's key
 *  material, and return the session. The `/verify` page drives the halves
 *  separately (bug244); this composition serves callers that do not need the
 *  interstitial. Retry-safe after a cancelled or failed credential ceremony: it
 *  needs only the accountId, never the (already-consumed) verification token. */
export async function registerSignupPasskey(deps: AuthDeps, accountId: string): Promise<Session> {
  const credential = await registerSignupCredential(deps, accountId);
  return unlockSignupKeys(deps, accountId, credential);
}

/** Generate the hybrid KEM key material, wrap it under the PRF-derived wrap key,
 *  and initialise it on the server (set-once). Shared by the signup unlock and by
 *  sign-in's finish-an-unfinished-signup path (bug244): the two arrive with the
 *  same thing in hand — a PRF output from an assertion on the account's active
 *  passkey — and must produce the same key material. */
async function initializeKeysFromPrf(
  api: SignetApi,
  accountId: string,
  prfOutput: Bytes,
  credentialId: Bytes,
): Promise<Session> {
  const wrapKey = await deriveWrapKey(prfOutput);
  const kem = await generateKemKeypair();
  // The hybrid PQ half (PQR §7): a fresh ML-KEM-1024 identity. The 64-byte
  // (d,z) seed rides the SAME single PRF-wrapped blob (layout v2, INV-12
  // unchanged); the ek publishes to the directory beside the classical key.
  const mlkem = await mlkemKeygen();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const blob = await wrapKemPrivkey(wrapKey, encodeKeyBlobV2(kem.privatePkcs8, mlkem.seed), iv);
  const kemPubkeyX963 = b64uEncode(kem.publicX963);
  const kemPqPubkeyEk = b64uEncode(mlkem.ek);
  await api.keysInitialize({
    kem_pubkey: kemPubkeyX963,
    kem_pq_pubkey: kemPqPubkeyEk,
    // bug245: bind the key material to the passkey that produced its wrap key.
    credential_id: b64uEncode(credentialId),
    wrapped_kem_privkey_blob: blob,
  });

  const kemPrivateKey = await importKemPrivateNonExtractable(kem.privatePkcs8);
  return {
    accountId,
    kemPrivateKey,
    kemPubkeyX963,
    mlkemSeed: mlkem.seed,
    kemPqPubkeyEk,
    wrappedKemPrivkeyBlob: blob,
  };
}

/** Signup phase 2, end to end (verify the emailed token, then register the
 *  passkey). The `/verify` page drives the two halves separately so it can
 *  prepare the user for the credential dialog and retry it; this composition is
 *  the whole-flow entry point. */
export async function completeSignup(deps: AuthDeps, token: string): Promise<Session> {
  const { accountId } = await verifySignupEmail(deps, token);
  return registerSignupPasskey(deps, accountId);
}

/** Identified sign-in: assert the passkey (with PRF), recover + import the KEM
 *  private key NON-extractable, and return the session. */
export async function signIn(deps: AuthDeps, email: string): Promise<Session> {
  const { api, gateway } = deps;
  const begin = await api.beginSignin(email);
  const assertion = await gateway.get(assertionOptionsFromServer(begin.options));
  if (!assertion) throw new InvalidInputError('sign-in was cancelled');
  const prfOutput = extractPrfFirst(assertion);

  const result = await api.completeSignin({
    ceremony_id: begin.ceremony_id,
    credential: serializeAssertionResponse(assertion),
  });
  if (!result.wrapped_kem_privkey_blob || !result.kem_pubkey) {
    // bug244: an UNFINISHED signup — the passkey exists (the server just verified
    // an assertion on it) but the key material was never initialised, because
    // the second signup prompt was dismissed. Sign-in holds exactly what the
    // signup unlock holds — this passkey's PRF output — so finish here rather
    // than refuse: the server's set-once initialise is the guard against a race
    // with a concurrent unlock. This is the safety net under the /verify
    // interstitial; there is no state a user can reach that leaves them locked out.
    return initializeKeysFromPrf(
      api,
      result.account_id,
      prfOutput,
      new Uint8Array(assertion.rawId),
    );
  }

  const wrappedKemPrivkeyBlob = result.wrapped_kem_privkey_blob as KemPrivkeyWrap;
  const wrapKey = await deriveWrapKey(prfOutput);
  const { p256Pkcs8, mlkemSeed } = decodeKeyBlobV2(
    await unwrapKemPrivkey(wrapKey, wrappedKemPrivkeyBlob),
  );
  const kemPrivateKey = await importKemPrivateNonExtractable(p256Pkcs8);

  // Pre-launch crypto review #5: the self KEM public key is server-supplied here
  // (the recovered private key is non-extractable, so we can't re-derive it to
  // compare) and is used to self-wrap every new DEK + metadata key. Verify it is
  // the counterpart of the recovered (genuine) private key before trusting it — a
  // malicious server could otherwise substitute the self-wrap target and capture
  // the user's own new uploads. The wrap→unwrap round-trip is the only local check.
  if (!(await kemKeypairMatches(kemPrivateKey, b64uDecode(result.kem_pubkey)))) {
    throw new IntegrityError(
      'the server returned a KEM public key that does not match your account key',
    );
  }

  // The PQ half of the same check (PQR §7/§9.2 applied to self): every v1
  // account is hybrid from enrollment, so a missing/mismatched directory ek
  // for an account whose blob carries a seed is infrastructure lying — and
  // unlike the classical probe, FIPS 203 KeyGen determinism makes this a
  // direct byte-compare.
  if (!result.kem_pq_pubkey) {
    throw new IntegrityError('the server returned no ML-KEM public key for this account');
  }
  const ekFromSeed = await mlkemEkFromSeed(mlkemSeed);
  if (hexEncode(ekFromSeed) !== hexEncode(b64uDecode(result.kem_pq_pubkey))) {
    throw new IntegrityError(
      'the server returned an ML-KEM public key that does not match your account key',
    );
  }

  return {
    accountId: result.account_id,
    kemPrivateKey,
    kemPubkeyX963: result.kem_pubkey,
    mlkemSeed,
    kemPqPubkeyEk: result.kem_pq_pubkey,
    wrappedKemPrivkeyBlob,
  };
}

/** The rp.id from server registration options — used as the rpId for the local
 *  signup PRF assertion so it matches the registration's relying party. */
function readRpId(options: unknown): string | undefined {
  const id = (options as { publicKey?: { rp?: { id?: string } } }).publicKey?.rp?.id;
  return typeof id === 'string' ? id : undefined;
}
