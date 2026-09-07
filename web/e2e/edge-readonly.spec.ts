// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { test, expect } from '@playwright/test';
import { addPrfAuthenticator } from './helpers';
import { execFileSync } from 'node:child_process';

// S051 edge-case sweep: the lapse → read-only write-gate (auth.rs), end to end
// through the running server with a real authenticated session. Uncovered by the
// standard e2e (which uses activate()). Proves: a lapsed-but-in-grace human is
// blocked on mutating writes (403 account_read_only) but can still read, and can
// reach billing to re-subscribe (the recovery allowlist). Needs the live Stripe
// setup (the recovery assertion hits /v1/billing/checkout). Run with
// SIGNET_BILLING_LIVE_TEST=1 against the signet_drive_e2e server wired to rk_test.

const DB = 'signet_drive_e2e';
function psql(sql: string): string {
  return execFileSync(
    'docker',
    ['exec', 'signet-postgres-dev', 'psql', '-U', 'signet', '-d', DB, '-tAc', sql],
    { encoding: 'utf8' },
  ).trim();
}

test('lapse → read-only gate: writes blocked, reads + billing recovery allowed', async ({
  page,
}) => {
  // The read-only gate itself (steps 1-3) needs no Stripe → permanent coverage. The
  // billing-recovery assertion (step 4) hits /v1/billing/checkout, so it runs only
  // when the live Stripe setup is present (SIGNET_BILLING_LIVE_TEST=1).
  test.setTimeout(60_000);

  await addPrfAuthenticator(page);
  const id = `${Date.now()}`;
  const email = `ro-${id}@example.com`;
  await page.goto('/signup');
  await page.getByLabel('Username').fill(`ro-${id}`);
  await page.getByLabel('Email').fill(email);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByText('Check your email')).toBeVisible();
  const token = psql(
    `SELECT token FROM pending_email_verifications WHERE email='${email}' ORDER BY created_at DESC LIMIT 1`,
  );
  await page.goto(`/verify?token=${token}`);
  await page.getByRole('button', { name: 'Create my passkey' }).click(); // bug062
  await expect(page.getByRole('heading', { name: 'Share folders' })).toBeVisible({
    timeout: 15_000,
  });

  // page.context().request shares the browser's session cookie → authenticated.
  const req = page.context().request;
  // The read-only gate is middleware (method + path), so it fires before the
  // handler validates the body — a minimal POST is enough to exercise it.
  const writeBody = { data: { probe: 'read-only-gate' } };

  // (1) ACTIVE — a mutating write is NOT read-only-blocked (reaches the handler).
  psql(
    `UPDATE accounts SET paid_until = now() + interval '30 days', bytes_quota = 10737418240, activated_at = now() WHERE email='${email}'`,
  );
  const activeWrite = await req.post('/v1/folders', writeBody);
  console.log(`[ro] ACTIVE  POST /v1/folders          -> ${activeWrite.status()}`);
  expect(activeWrite.status()).not.toBe(403);

  // (2) LAPSED (within grace) — the same write is refused 403 account_read_only.
  psql(`UPDATE accounts SET paid_until = now() - interval '1 day' WHERE email='${email}'`);
  const lapsedWrite = await req.post('/v1/folders', writeBody);
  const lapsedBody = await lapsedWrite.text();
  console.log(
    `[ro] LAPSED  POST /v1/folders          -> ${lapsedWrite.status()} ${lapsedBody.slice(0, 120)}`,
  );
  expect(lapsedWrite.status()).toBe(403);
  expect(lapsedBody).toContain('account_read_only');

  // (3) LAPSED — a read still passes (the grace window preserves access).
  const lapsedRead = await req.get('/v1/me');
  console.log(`[ro] LAPSED  GET  /v1/me               -> ${lapsedRead.status()}`);
  expect(lapsedRead.status()).toBe(200);

  // (4) LAPSED — billing is allowlisted so the account can re-subscribe + recover.
  //     Needs the live Stripe key (the checkout call hits Stripe), so gate on the flag.
  if (process.env.SIGNET_BILLING_LIVE_TEST) {
    const recover = await req.post('/v1/billing/checkout', { data: { tier: '10gb' } });
    const recoverBody = await recover.text();
    console.log(
      `[ro] LAPSED  POST /v1/billing/checkout -> ${recover.status()} ${recoverBody.slice(0, 90)}`,
    );
    expect(recover.status()).toBe(200);
    expect(recoverBody).toContain('checkout.stripe.com');
  }
});
