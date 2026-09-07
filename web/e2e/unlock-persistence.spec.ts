// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// S116 unlock persistence — the real-Chrome proof (design:
// docs/security/Signet-Drive-Unlock-Persistence-Design-Note; Gus review SOUND).
//
// This spec IS the design note's spike test, promoted: it proves the load-bearing
// browser primitive (a structured-cloned NON-extractable CryptoKey surviving an
// IndexedDB round-trip across a real reload) and the product behavior on top:
//   • reload → the drive comes back with ZERO gestures (silent restore), and the
//     restored session drives real crypto (a folder create wraps a metadata key);
//   • Lock → the persisted capability is gone; reloads stay locked; one tap
//     re-unlocks and re-arms persistence;
//   • sign-out → everything is gone (record purged BEFORE the logout POST).
// If the primitive fails in a major browser, this fails — the review's named
// falsifier for the "standard, correct primitive" conclusion.

import { test, expect, type Page } from '@playwright/test';
import { signUp } from './helpers';

const driveVisible = (page: Page) =>
  expect(page.getByRole('heading', { name: 'Share folders' })).toBeVisible({ timeout: 15_000 });

test('a reload silently restores the unlocked session; Lock and sign-out end it', async ({
  page,
}) => {
  await signUp(page);

  // ── The spike: reload → silent restore (no Unlock tap, no sign-in) ──
  await page.reload();
  await driveVisible(page);
  await expect(page.getByRole('button', { name: 'Unlock' })).not.toBeVisible();

  // The restored session is cryptographically live: a folder create mints +
  // wraps a metadata key under the restored (non-extractable) KEM key.
  const sidebar = page.locator('aside');
  await sidebar.getByRole('button', { name: 'New private folder' }).click();
  await page.getByLabel('Folder name').fill('restored-proof');
  await page.getByRole('dialog').getByRole('button', { name: 'Create' }).click();
  await expect(sidebar.getByRole('button', { name: 'restored-proof', exact: true })).toBeVisible();

  // A second reload keeps working (restore does not consume the record) and the
  // folder's ENCRYPTED name still decrypts under the restored session.
  await page.reload();
  await driveVisible(page);
  await expect(
    page.locator('aside').getByRole('button', { name: 'restored-proof', exact: true }),
  ).toBeVisible({ timeout: 15_000 });

  // ── Lock: the explicit walk-away — locked NOW, and still locked after reload ──
  await page.getByRole('button', { name: 'Lock' }).click();
  await expect(page.getByRole('button', { name: 'Unlock' })).toBeVisible({ timeout: 15_000 });
  await page.reload();
  await expect(page.getByRole('button', { name: 'Unlock' })).toBeVisible({ timeout: 15_000 });

  // One tap re-unlocks (the Bug014 card; the virtual authenticator satisfies the
  // gesture) — and the fresh gesture re-arms persistence…
  await page.getByRole('button', { name: 'Unlock' }).click();
  await driveVisible(page);
  // …so the next reload is silent again.
  await page.reload();
  await driveVisible(page);
  await expect(page.getByRole('button', { name: 'Unlock' })).not.toBeVisible();

  // ── Sign out: record purged (before the logout POST) + cookie gone ──
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible({ timeout: 15_000 });
  await page.reload();
  // Landing again: no drive, no re-unlock offer for a signed-out account.
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible({ timeout: 15_000 });
  await expect(page.getByRole('button', { name: 'Unlock' })).not.toBeVisible();
});
