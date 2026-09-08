// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { test, expect } from '@playwright/test';
import { addPrfAuthenticator } from './helpers';
import { execFileSync } from 'node:child_process';

// S051 edge-case sweep: the over-quota gate (multipart::initiate, Schema §26),
// end to end through the running server + a real UI upload. Uncovered by the
// standard e2e. Over-quota is NOT the global read-only gate — it is the per-upload
// declare-check (group_used + declared > pool_quota → 413 quota_exceeded). Proves:
// an upload that would exceed the pooled quota is refused 413; and after the quota
// is raised, the SAME upload succeeds (preserved-not-destroyed — never auto-delete).
// Run with SIGNET_BILLING_LIVE_TEST=1 (consistent with the sweep specs).

const DB = 'signet_drive_e2e';
function psql(sql: string): string {
  return execFileSync(
    'docker',
    ['exec', 'signet-postgres-dev', 'psql', '-U', 'signet', '-d', DB, '-tAc', sql],
    { encoding: 'utf8' },
  ).trim();
}

test('over-quota: upload refused 413, succeeds after quota raised', async ({ page }) => {
  // No Stripe needed — pure quota gate + a real upload against the e2e infra, so
  // this runs as permanent coverage in the normal suite.
  test.setTimeout(60_000);

  await addPrfAuthenticator(page);
  const id = `${Date.now()}`;
  const email = `oq-${id}@example.com`;
  await page.goto('/signup');
  await page.getByLabel('Username').fill(`oq-${id}`);
  await page.getByLabel('Email').fill(email);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByText('Check your email')).toBeVisible();
  const token = psql(
    `SELECT token FROM pending_email_verifications WHERE email='${email}' ORDER BY created_at DESC LIMIT 1`,
  );
  await page.goto(`/verify?token=${token}`);
  await page.getByRole('button', { name: 'Create my passkey' }).click(); // bug062
  // bug244: the second prompt sits behind its own screen; the user's click fires it.
  await page.getByRole('button', { name: 'Continue to unlock' }).click();
  await expect(page.getByRole('heading', { name: 'Share folders' })).toBeVisible({
    timeout: 15_000,
  });

  // Activate with a deliberately tiny pooled quota (1 KB) so a real file overruns it.
  psql(
    `UPDATE accounts SET paid_until = now() + interval '30 days', bytes_quota = 1024, activated_at = now() WHERE email='${email}'`,
  );

  // A private folder to upload into (recipients = just the uploader, so the
  // initiate's recipient-coverage check passes and we reach the quota check).
  const sidebar = page.locator('aside');
  await sidebar.getByRole('button', { name: 'New private folder' }).click();
  await page.getByLabel('Folder name').fill('Quota Test');
  await page.getByRole('dialog').getByRole('button', { name: 'Create' }).click();
  await expect(sidebar.getByRole('button', { name: 'Quota Test', exact: true })).toBeVisible();
  await sidebar.getByRole('button', { name: 'Quota Test', exact: true }).click();
  await expect(page.getByText('Nothing sealed here yet.')).toBeVisible();

  const bigFile = {
    name: 'over.bin',
    mimeType: 'application/octet-stream',
    buffer: Buffer.alloc(64 * 1024, 7),
  }; // 64 KB » 1 KB quota

  // (1) OVER QUOTA — bug070 (S137) CHANGED THE MECHANISM HERE, deliberately.
  //
  // This used to wait for the server's `413 quota_exceeded` on POST .../multipart.
  // The client now runs a pre-flight capacity check — it reads the live quota and
  // compares the STORED (ciphertext) size — so the upload is refused BEFORE any
  // request is made, and no initiate ever happens. Waiting for that response now
  // times out, which is how this test caught the change.
  //
  // The intent is unchanged and the assertion is strictly stronger: instead of
  // "the server rejected it", we pin "no request was even attempted, and the user
  // was told why". The server's own declare-check remains covered by
  // server/tests/multipart.rs (`initiate_over_quota_rejected`), which asserts the
  // 413, the `quota_exceeded` code, AND that nothing was reserved.
  const initiateAttempts: string[] = [];
  const countInitiates = (r: { url: () => string; method: () => string }) => {
    if (/\/v1\/files\/.+\/multipart$/.test(r.url()) && r.method() === 'POST') {
      initiateAttempts.push(r.url());
    }
  };
  page.on('request', countInitiates);
  await page.locator('input[type="file"]').setInputFiles(bigFile);
  // The user-visible refusal (FileList renders browser.error when no dialog is open).
  await expect(page.getByText(/Not enough storage/)).toBeVisible({ timeout: 20_000 });
  page.off('request', countInitiates);
  expect(
    initiateAttempts,
    'the pre-flight must refuse before any multipart initiate is attempted',
  ).toEqual([]);
  console.log(`[oq] OVER  refused client-side, 0 initiate attempts`);
  // The file must not have landed.
  await expect(page.getByRole('button', { name: 'over.bin' })).toHaveCount(0);

  // (2) RAISE the quota — the SAME upload now succeeds (data was never destroyed;
  //     the account simply could not write until it had room).
  psql(`UPDATE accounts SET bytes_quota = 10737418240 WHERE email='${email}'`);
  await page.locator('input[type="file"]').setInputFiles(bigFile);
  await expect(page.getByRole('button', { name: 'over.bin' })).toBeVisible({ timeout: 20_000 });
  console.log(`[oq] RAISED upload succeeded — over.bin visible`);
});
