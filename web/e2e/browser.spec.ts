// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { signUp } from './helpers';

// The data-plane keystone: a human signs up, then creates / uploads / downloads /
// renames / deletes through the real file browser, real server, and real crypto.
// The decisive check is that after sign-out + sign-in the folder + file names
// still decrypt — proving the recovered KEM key unwraps the §7.2 metadata key and
// opens the §7.3 names, end-to-end in a real browser.
test('file browser: create, upload, download, rename, delete — names decrypt across re-auth', async ({
  page,
}) => {
  const { email } = await signUp(page);
  const sidebar = page.locator('aside');
  const content = 'the quick brown fox\n';

  // Create a top-level private folder; its decrypted name appears in the sidebar.
  await sidebar.getByRole('button', { name: 'New private folder' }).click();
  await page.getByLabel('Folder name').fill('Project Aurora');
  await page.getByRole('dialog').getByRole('button', { name: 'Create' }).click();
  await expect(sidebar.getByRole('button', { name: 'Project Aurora', exact: true })).toBeVisible();

  // Open it — empty to start.
  await sidebar.getByRole('button', { name: 'Project Aurora', exact: true }).click();
  await expect(page.getByText('Nothing sealed here yet.')).toBeVisible();

  // Upload a file with known content; its decrypted name appears in the list.
  await page.locator('input[type="file"]').setInputFiles({
    name: 'notes.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from(content),
  });
  await expect(page.getByRole('button', { name: 'notes.txt' })).toBeVisible();

  // Proof of the populated browser (visual check / artifact).
  await page.screenshot({ path: '/tmp/c2-2-browser.png', fullPage: true });

  // Mobile responsive proof (Block G): the overlay drawer + two-line file rows.
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole('button', { name: 'Open navigation' }).click();
  // Wait for the drawer to slide fully in (the sidebar heading enters the viewport).
  await expect(page.getByRole('heading', { name: 'Private folders' })).toBeInViewport();
  await page.screenshot({ path: '/tmp/fg-mobile.png' });
  await page.getByLabel('Close navigation').click({ position: { x: 360, y: 400 } });
  await page.setViewportSize({ width: 1280, height: 720 });

  // Download it; the client-side-decrypted bytes match what was uploaded.
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('checkbox', { name: 'Select file notes.txt' }).check();
  await page.getByRole('button', { name: 'Download' }).click();
  const download = await downloadPromise;
  const downloadedPath = await download.path();
  expect(readFileSync(downloadedPath, 'utf8')).toBe(content);

  // Rename it (re-encrypts the name under the same metadata key).
  await page.getByRole('checkbox', { name: 'Select file notes.txt' }).check();
  await page.getByRole('button', { name: 'Rename' }).click();
  await page.getByLabel('New name').fill('renamed.txt');
  await page.getByRole('dialog').getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('button', { name: 'renamed.txt' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'notes.txt' })).toHaveCount(0);

  // The keystone via crypto: sign out, sign back in, reopen the folder — the
  // folder + file names still decrypt with the recovered KEM key.
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
  await page.goto('/signin');
  await page.getByLabel('Email').fill(email);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByRole('heading', { name: 'Share folders' })).toBeVisible({
    timeout: 15_000,
  });
  await sidebar.getByRole('button', { name: 'Project Aurora', exact: true }).click();
  await expect(page.getByRole('button', { name: 'renamed.txt' })).toBeVisible();

  // Delete it (two-step confirm); the folder is empty again.
  await page.getByRole('checkbox', { name: 'Select file renamed.txt' }).check();
  await page.getByRole('button', { name: 'Delete' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Delete' }).click();
  await expect(page.getByText('Nothing sealed here yet.')).toBeVisible();
});
