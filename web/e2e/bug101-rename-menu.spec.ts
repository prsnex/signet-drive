// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { test, expect } from '@playwright/test';
import { signUp } from './helpers';

// bug101: the discoverable ⋯ / right-click rename affordance. This proves the two
// things the checkbox → toolbar path couldn't do:
//   (1) rename a TOP-LEVEL folder — which has no selectable row in the main panel —
//       from the left-nav tree's ⋯ menu (the core discoverability + reach gap);
//   (2) rename a file from the panel row's ⋯ menu.
// Owner context throughout (a private folder the signer owns), so the actions are
// enabled; the non-owner disabled-with-tooltip path is gated on ownsCurrentRoot /
// the tree `owned` prop (unit-covered) and verified visually paired.
// The ⋯ button carries a generic "More actions" label (row context supplies the
// item), so it's addressed by scoping to the item's row.
test('bug101: rename a top-level folder from the tree ⋯ menu, and a file from the panel ⋯ menu', async ({
  page,
}) => {
  await signUp(page);
  const sidebar = page.locator('aside');

  // A top-level private folder — the case the main panel cannot select for rename.
  await sidebar.getByRole('button', { name: 'New private folder' }).click();
  await page.getByLabel('Folder name').fill('Draft Folder');
  await page.getByRole('dialog').getByRole('button', { name: 'Create' }).click();
  await expect(sidebar.getByRole('button', { name: 'Draft Folder', exact: true })).toBeVisible();

  // Rename it from the TREE ⋯ menu — bug101's core: reachable only here.
  await sidebar
    .locator('.row', { hasText: 'Draft Folder' })
    .getByRole('button', { name: 'More actions' })
    .click();
  await page.getByRole('menuitem', { name: 'Rename' }).click();
  await page.getByLabel('New name').fill('Renamed Folder');
  await page.getByRole('dialog').getByRole('button', { name: 'Save' }).click();
  await expect(sidebar.getByRole('button', { name: 'Renamed Folder', exact: true })).toBeVisible();
  await expect(sidebar.getByRole('button', { name: 'Draft Folder', exact: true })).toHaveCount(0);

  // Open it, upload a file, then rename the file from the PANEL row's ⋯ menu.
  await sidebar.getByRole('button', { name: 'Renamed Folder', exact: true }).click();
  await page.locator('input[type="file"]').setInputFiles({
    name: 'notes.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('hello\n'),
  });
  await expect(page.getByRole('button', { name: 'notes.txt' })).toBeVisible();

  await page
    .locator('tr', { hasText: 'notes.txt' })
    .getByRole('button', { name: 'More actions' })
    .click();
  await page.getByRole('menuitem', { name: 'Rename' }).click();
  await page.getByLabel('New name').fill('renamed.txt');
  await page.getByRole('dialog').getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('button', { name: 'renamed.txt' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'notes.txt' })).toHaveCount(0);

  // And delete the file from the panel ⋯ menu (the other confirmed action).
  await page
    .locator('tr', { hasText: 'renamed.txt' })
    .getByRole('button', { name: 'More actions' })
    .click();
  await page.getByRole('menuitem', { name: 'Delete' }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Delete' }).click();
  await expect(page.getByText('Nothing sealed here yet.')).toBeVisible();
});
