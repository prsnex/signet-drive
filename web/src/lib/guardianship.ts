// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// P-011 fingerprint verification for the "Add PRSN to Guardianship" wizard. The
// Guardian pastes a public key (base64url X9.63) plus a fingerprint they verified
// out-of-band against the PRSN. The short fingerprint is what a human can compare
// by eye; the long key blob is not. Recomputing SHA-256(SubjectPublicKeyInfo) and
// checking it equals the pasted fingerprint binds the key the wizard will attest
// to the fingerprint the human actually checked — that is the whole security value
// of the paste-two-things flow (the server re-verifies, but only the human can
// vouch the fingerprint out-of-band). A mismatch or an unreadable key throws a
// clear message, surfaced before any passkey gesture is spent.
//
// Pure (no reactive state) so it unit-tests in the node test config; the account
// store calls it.

import { b64uDecode } from './crypto/bytes';
import { InvalidInputError } from './crypto/errors';
import { fingerprint } from './crypto/pubkey';

/** Fingerprints are lowercase hex; accept the spaced / colon-grouped forms a human
 *  may paste (the wireframe shows `a1b2 c3d4 …`) by stripping separators. */
export function normalizeFingerprint(fp: string): string {
  return fp.trim().toLowerCase().replace(/[\s:]/g, '');
}

/** Throw unless `claimedFp` equals SHA-256(SPKI) of the base64url X9.63 `pubkey`.
 *  `label` names the key in the error (e.g. "signing key"). */
export async function verifyFingerprint(
  pubkeyB64url: string,
  claimedFp: string,
  label: string,
): Promise<void> {
  let actual: string;
  try {
    actual = await fingerprint(b64uDecode(pubkeyB64url.trim()));
  } catch {
    throw new InvalidInputError(`The ${label} couldn't be read — check the public key you pasted.`);
  }
  if (actual !== normalizeFingerprint(claimedFp)) {
    throw new InvalidInputError(
      `The ${label} and its fingerprint don't match — re-check what you pasted.`,
    );
  }
}
