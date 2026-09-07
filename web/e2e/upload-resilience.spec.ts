// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { test, expect } from '@playwright/test';
import { signUp } from './helpers';

// bug047/bug046: upload resilience on the human surface, fault-injected at the
// exact seam the real fault lives on — the direct-to-storage part PUTs (the
// API is never in the byte path, so Playwright's route interception on the
// MinIO origin is a faithful stand-in for a stalling OVH connection). Proves:
// a failed part PUT retries on a FRESH connection and completes byte-correct;
// an exhausted attempt budget PAUSES the upload resumably (never a silent
// 13-minute hang, never a dead upload); Resume re-syncs through the server's
// /resume endpoint and finishes; the paused UI is honest. globalSetup lowers
// `multipart_part_retry_attempts` to 2 in the E2E DB so exhaustion is fast.

/** True for a direct-to-storage part PUT (the injected-fault seam). */
function isPartPut(method: string, rawUrl: string): boolean {
  if (method !== 'PUT') return false;
  const url = new URL(rawUrl);
  return url.port === '9000' && url.searchParams.has('partNumber');
}

async function createAndEnterFolder(page: import('@playwright/test').Page, name: string) {
  const sidebar = page.locator('aside');
  await sidebar.getByRole('button', { name: 'New private folder' }).click();
  await page.getByLabel('Folder name').fill(name);
  await page.getByRole('dialog').getByRole('button', { name: 'Create' }).click();
  await sidebar.getByRole('button', { name, exact: true }).click();
  await expect(page.getByText('Nothing sealed here yet.')).toBeVisible();
}

test('a failed part PUT retries on a fresh connection and the upload completes byte-correct', async ({
  page,
}) => {
  await signUp(page);
  await createAndEnterFolder(page, 'Resilience');

  // Fail the FIRST part-PUT attempt at the network layer; the retry is a NEW
  // request (= a fresh connection — the bug047 premise) and passes through.
  // (One failure, not two: the E2E knob caps the budget at 2 attempts, so a
  // second injected failure would be exhaustion — the pause spec's job.)
  let failures = 0;
  await page.route('**/*', (route) => {
    if (isPartPut(route.request().method(), route.request().url()) && failures < 1) {
      failures += 1;
      return route.abort('connectionreset');
    }
    return route.fallback();
  });

  await page.locator('input[type="file"]').setInputFiles({
    name: 'retry.bin',
    mimeType: 'application/octet-stream',
    buffer: Buffer.from('stall-resilience proof content\n'.repeat(64)),
  });

  // The upload survives the injected failure and lands.
  await expect(page.getByRole('button', { name: 'retry.bin' })).toBeVisible();
  expect(failures).toBe(1);
});

test('an exhausted attempt budget PAUSES resumably; Resume re-syncs and completes', async ({
  page,
}) => {
  await signUp(page);
  await createAndEnterFolder(page, 'BadWindow');

  // A dead window: EVERY part PUT fails until the flag flips. With the E2E
  // knob at 2 attempts, the part exhausts fast and the upload must pause.
  let blocking = true;
  await page.route('**/*', (route) => {
    if (blocking && isPartPut(route.request().method(), route.request().url())) {
      return route.abort('connectionreset');
    }
    return route.fallback();
  });

  await page.locator('input[type="file"]').setInputFiles({
    name: 'pause.bin',
    mimeType: 'application/octet-stream',
    buffer: Buffer.from('paused-upload proof content\n'.repeat(64)),
  });

  // The honest paused affordance — copy + both actions (never a frozen bar,
  // never a silent failure).
  await expect(page.getByText(/Upload paused\. The network path to storage/)).toBeVisible();
  const resume = page.getByRole('button', { name: 'Resume upload' });
  await expect(resume).toBeVisible();
  await expect(page.getByRole('button', { name: 'Cancel upload' })).toBeVisible();
  await page.screenshot({ path: '/tmp/bug047-paused-ui.png' });

  // The window clears; the user resumes. The client re-syncs through the
  // server's /resume endpoint (fresh URLs) and the upload completes.
  blocking = false;
  await resume.click();
  await expect(page.getByRole('button', { name: 'pause.bin' })).toBeVisible();
});

test('bug050: a transient finalize failure pauses resumably — a fully-transferred upload is never lost', async ({
  page,
}) => {
  await signUp(page);
  await createAndEnterFolder(page, 'Finalize');

  // Every part lands untouched; the FINALIZE (an API call, not a byte-path
  // PUT) fails once with a 500. The pre-bug050 client fell to the abort path
  // here and destroyed a fully-transferred upload; it must now pause
  // resumably, and Resume re-drives /resume → re-complete.
  let failures = 0;
  await page.route('**/v1/files/*/multipart/*/complete', (route) => {
    if (failures < 1) {
      failures += 1;
      return route.fulfill({
        status: 500,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'internal', message: 'injected finalize failure' }),
      });
    }
    return route.fallback();
  });

  await page.locator('input[type="file"]').setInputFiles({
    name: 'finalize.bin',
    mimeType: 'application/octet-stream',
    buffer: Buffer.from('finalize-pause proof content\n'.repeat(64)),
  });

  await expect(page.getByText(/Upload paused/)).toBeVisible();
  await page.getByRole('button', { name: 'Resume upload' }).click();
  await expect(page.getByRole('button', { name: 'finalize.bin' })).toBeVisible();
  expect(failures).toBe(1);
});

test('bug048: uploading a duplicate name auto-suffixes Finder-style (both files kept)', async ({
  page,
}) => {
  await signUp(page);
  await createAndEnterFolder(page, 'DupNames');

  const payload = {
    name: 'dup.bin',
    mimeType: 'application/octet-stream',
    buffer: Buffer.from('duplicate-name content\n'.repeat(8)),
  };
  await page.locator('input[type="file"]').setInputFiles(payload);
  await expect(page.getByRole('button', { name: 'dup.bin', exact: true })).toBeVisible();

  // The same name again: the client (names are ciphertext to the server, so
  // this is a CLIENT decision) suffixes before the extension.
  await page.locator('input[type="file"]').setInputFiles(payload);
  await expect(page.getByRole('button', { name: 'dup (1).bin', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'dup.bin', exact: true })).toBeVisible();
});

test('cancelling a paused upload rolls it back cleanly (no stranded file row)', async ({
  page,
}) => {
  await signUp(page);
  await createAndEnterFolder(page, 'CancelWin');

  await page.route('**/*', (route) => {
    if (isPartPut(route.request().method(), route.request().url())) {
      return route.abort('connectionreset');
    }
    return route.fallback();
  });

  await page.locator('input[type="file"]').setInputFiles({
    name: 'doomed.bin',
    mimeType: 'application/octet-stream',
    buffer: Buffer.from('cancelled-upload content\n'.repeat(64)),
  });

  await expect(page.getByText(/Upload paused\. The network path to storage/)).toBeVisible();
  await page.getByRole('button', { name: 'Cancel upload' }).click();

  // The banner clears, no error is toasted (the user's own action), and the
  // pending file never appears — the abort rolled the reservation back.
  await expect(page.getByText(/Upload paused/)).not.toBeVisible();
  await expect(page.getByRole('button', { name: 'doomed.bin' })).not.toBeVisible();
  await expect(page.locator('.error')).not.toBeVisible();
});
