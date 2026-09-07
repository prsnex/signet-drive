// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { test, expect } from '@playwright/test';
import {
  attestPrsnViaEnrollment,
  grantLive,
  prsnIdentity,
  prsnSignedFetch,
  signUp,
  seedBroker,
} from './helpers';
import { execFileSync } from 'node:child_process';

// S051 edge-case sweep: a PRSN's writability is group-scoped to its Guardian's
// subscription (auth.rs: a PRSN's read_only = guardian_lapsed). When the Guardian
// (pool master) lapses, the whole group goes read-only — the PRSN can still read
// but cannot write, until the Guardian recovers. Builds on the cross-surface PRSN
// attestation + CLI-signed-request harness; manipulates the Guardian's paid_until
// directly (the same psql affordance the helpers use). Needs the `signet` binary
// built (like cross-surface.spec) + the :8080 server.

function psql(sql: string): string {
  return execFileSync(
    'docker',
    ['exec', 'signet-postgres-dev', 'psql', '-U', 'signet', '-d', 'signet_drive_e2e', '-tAc', sql],
    { encoding: 'utf8' },
  ).trim();
}

test('guardian lapse → the pooled PRSN goes read-only (writes blocked, reads pass)', async ({
  page,
}) => {
  test.setTimeout(60_000);

  // Guardian (pool master), activated by signUp.
  const { handle: guardianHandle, email: guardianEmail } = await signUp(page);
  seedBroker(guardianHandle); // bug154 §2c: BEFORE /account mounts

  // A real-CLI-keyed PRSN, attested by the Guardian via the S052 enrollment flow.
  const prsn = prsnIdentity();
  await page.getByRole('link', { name: guardianHandle }).click();
  await expect(page.getByRole('heading', { name: 'Account Settings', exact: true })).toBeVisible({
    timeout: 15_000,
  });
  await attestPrsnViaEnrollment(page, prsn, guardianHandle);
  // bug117/S158: the PRSN's signed Drive requests below need a live Garnet grant
  // (the v0.5.26 backstop refuses grant-less PRSNs on every non-exempt route).
  // The lapse read-only semantics under test are BILLING state, orthogonal to the
  // grant's liveness — a live grant is the precondition, not the subject.
  grantLive(guardianHandle, prsn.handle);

  const writeBody = JSON.stringify({ probe: 'guardian-lapse' });

  // (1) Guardian ACTIVE — the PRSN authenticates and a write reaches the handler.
  const meActive = await prsnSignedFetch(prsn, 'GET', '/v1/me');
  expect(meActive.status).toBe(200);
  const writeActive = await prsnSignedFetch(prsn, 'POST', '/v1/folders', { body: writeBody });
  console.log(`[gl] GUARDIAN-ACTIVE  POST /v1/folders -> ${writeActive.status}`);
  expect(writeActive.status).not.toBe(403);

  // (2) Lapse the GUARDIAN (the pool master) — the PRSN's writes are now blocked.
  psql(`UPDATE accounts SET paid_until = now() - interval '1 day' WHERE email='${guardianEmail}'`);
  const writeLapsed = await prsnSignedFetch(prsn, 'POST', '/v1/folders', { body: writeBody });
  const lapsedText = await writeLapsed.text();
  console.log(
    `[gl] GUARDIAN-LAPSED  POST /v1/folders -> ${writeLapsed.status} ${lapsedText.slice(0, 110)}`,
  );
  expect(writeLapsed.status).toBe(403);
  expect(lapsedText).toContain('account_read_only');

  // (3) The PRSN can still READ while the Guardian is lapsed (data preserved).
  const meLapsed = await prsnSignedFetch(prsn, 'GET', '/v1/me');
  console.log(`[gl] GUARDIAN-LAPSED  GET  /v1/me      -> ${meLapsed.status}`);
  expect(meLapsed.status).toBe(200);
});
