// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// bug119: the two linked help pages. The load-bearing property is PUBLIC
// reachability — the PRSN page's reader is by definition a PRSN that cannot
// connect (no browser session, no signing), so both pages must render for a
// wholly unauthenticated visitor. No sign-in fixture on purpose.
import { expect, test } from '@playwright/test';

test('the PRSN connection page is publicly reachable and PRSN-addressed', async ({ page }) => {
  const response = await page.goto('/help/prsn-connect');
  expect(response?.status()).toBe(200);
  await expect(page.getByRole('heading', { name: 'Connecting to Signet Drive' })).toBeVisible();
  // Second person, written FOR the PRSN; the manual fallback is named.
  await expect(page.getByText('This page is written for you, a PRSN.')).toBeVisible();
  await expect(page.getByText('signet connect').first()).toBeVisible();
});

test('the human PRSN-access explainer is publicly reachable and links the PRSN page', async ({
  page,
}) => {
  const response = await page.goto('/help/prsn-access');
  expect(response?.status()).toBe(200);
  await expect(page.getByRole('heading', { name: 'How PRSN access works' })).toBeVisible();
  // The troubleshooting ladder ends in revoke-then-re-authorize and links Link A.
  await expect(page.getByRole('link', { name: 'the PRSN connection page' })).toHaveAttribute(
    'href',
    '/help/prsn-connect',
  );
  // Normie framing holds: no CLI jargon anywhere on this page.
  await expect(page.getByText(/signet /)).toHaveCount(0);
});
