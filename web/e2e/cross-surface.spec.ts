// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { test, expect } from '@playwright/test';
import {
  attestPrsnViaEnrollment,
  prsnIdentity,
  prsnSignedFetch,
  seedBroker,
  signUp,
} from './helpers';

// C7 foundation: the cross-surface PRSN-authentication proof. A PRSN whose keys
// come from the REAL `signet` CLI (software-tier keystore) is attested by a human
// Guardian through the web wizard, then authenticates to the server with a
// CLI-signed request — proving the PRSN tooling works end-to-end against the
// human-attested identity, both surfaces meeting at one account. The data-plane
// golden path (share → download → `signet decrypt` → revoke) builds on this next.
// Run against the E2E stack (docs/operations/web-e2e.md): the API server on :8080,
// the `signet` binary built at target/debug/signet.
test('a CLI-keyed PRSN, attested via the web, authenticates with a signed request', async ({
  page,
}) => {
  const { handle: guardianHandle } = await signUp(page);
  seedBroker(guardianHandle); // bug154 §2c: BEFORE /account mounts

  // The PRSN's keys come from the real CLI (no browser-generated stand-ins).
  const prsn = prsnIdentity();

  // The Guardian attests it via the S052 enrollment flow (no hand-transcription):
  // confirm + name, then the agent's submit-keys (the CLI keys posted directly here),
  // then one passkey gesture. The server verifies fingerprint == SHA-256(SPKI) at submit.
  await page.getByRole('link', { name: guardianHandle }).click();
  await expect(page.getByRole('heading', { name: 'Account Settings', exact: true })).toBeVisible({
    timeout: 15_000,
  });
  await attestPrsnViaEnrollment(page, prsn, guardianHandle);

  // The PRSN authenticates with a CLI-signed request — the cross-surface proof:
  // its CLI keystore signed canonical bytes the server's ECDSA verifier accepts,
  // resolving the attestation the Guardian just minted in the browser.
  const res = await prsnSignedFetch(prsn, 'GET', '/v1/me');
  expect(res.status).toBe(200);
  const me = (await res.json()) as { account_type: string; handle: string };
  expect(me.account_type).toBe('prsn');
  expect(me.handle).toBe(prsn.handle);

  // A tampered signature is rejected — the request is genuinely signature-gated,
  // not merely fingerprint-gated.
  const bad = await prsnSignedFetch(prsn, 'GET', '/v1/me', { tamper: true });
  expect(bad.status).toBe(401);
});
