// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { test, expect } from '@playwright/test';
import { signUp } from './helpers';

// bug055 — select-all: the tri-state header checkbox (unchecked / checked /
// indeterminate), the ⌘A/Ctrl+A keyboard path, and the decided mixed-selection
// rule — Download DISABLES when the selection includes folders, rather than
// silently downloading only the file subset (S125: silent partial action is
// exactly what a storage product must not do).
test('select all: tri-state header checkbox, keyboard path, and the mixed-selection Download rule', async ({
  page,
}) => {
  await signUp(page);
  const sidebar = page.locator('aside');

  await sidebar.getByRole('button', { name: 'New private folder' }).click();
  await page.getByLabel('Folder name').fill('Bulk');
  await page.getByRole('dialog').getByRole('button', { name: 'Create' }).click();
  await sidebar.getByRole('button', { name: 'Bulk', exact: true }).click();

  // Two files + one subfolder → a genuinely mixed listing.
  await page.locator('input[type="file"]').setInputFiles([
    { name: 'a.txt', mimeType: 'text/plain', buffer: Buffer.from('aaa\n') },
    { name: 'b.txt', mimeType: 'text/plain', buffer: Buffer.from('bbb\n') },
  ]);
  await expect(page.getByRole('button', { name: 'a.txt' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'b.txt' })).toBeVisible();
  await page.getByRole('button', { name: 'New folder', exact: true }).click();
  await page.getByLabel('Folder name').fill('sub');
  await page.getByRole('dialog').getByRole('button', { name: 'Create' }).click();
  await expect(page.getByRole('checkbox', { name: 'Select folder sub' })).toBeVisible();

  const selectAll = page.getByRole('checkbox', { name: 'Select all items in this folder' });

  // Select all → 3 selected; the mixed selection DISABLES Download.
  await selectAll.check();
  await expect(page.getByText('3 selected')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Download' })).toBeDisabled();
  await expect(selectAll).toBeChecked();

  // Partial: drop the subfolder → indeterminate header; Download enables
  // (files-only selection is exactly what Download applies to).
  await page.getByRole('checkbox', { name: 'Select folder sub' }).uncheck();
  await expect(page.getByText('2 selected')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Download' })).toBeEnabled();
  await expect(selectAll).not.toBeChecked();
  expect(await selectAll.evaluate((el) => (el as HTMLInputElement).indeterminate)).toBe(true);

  // An indeterminate header click selects everything again…
  await selectAll.click();
  await expect(page.getByText('3 selected')).toBeVisible();
  // …and a fully-checked header click clears the selection (deselect-all free).
  await selectAll.click();
  await expect(page.getByText(/\d+ selected/)).toHaveCount(0);

  // The keyboard path re-selects the listing.
  await page.keyboard.press('ControlOrMeta+a');
  await expect(page.getByText('3 selected')).toBeVisible();

  // ⌘A must NOT hijack a text field: open Rename (single file), select-all in
  // its input, and confirm the listing selection did not change shape.
  await selectAll.click(); // clear
  await page.getByRole('checkbox', { name: 'Select file a.txt' }).check();
  await page.getByRole('button', { name: 'Rename' }).click();
  await page.getByLabel('New name').fill('a2.txt');
  await page.getByLabel('New name').press('ControlOrMeta+a');
  await expect(page.getByText('1 selected')).toBeVisible(); // still just the one
  await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();
});
