// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { test, expect } from '@playwright/test';
import { signUp } from './helpers';

test('signup then sign-in recovers the same account through real WebAuthn-PRF ceremonies', async ({
  page,
}) => {
  const { handle, email } = await signUp(page);
  // The file browser header shows the account's handle once signed in.
  await expect(page.getByText(handle)).toBeVisible();

  // Sign out clears the in-memory KEM key.
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();

  // Sign in: the same credential's PRF unwraps the stored KEM key.
  await page.goto('/signin');
  await page.getByLabel('Email').fill(email);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByRole('heading', { name: 'Share folders' })).toBeVisible({
    timeout: 15_000,
  });

  // The keystone: the same account is recovered end-to-end — its handle returns,
  // through a real browser, real ceremonies, and the real API.
  await expect(page.getByText(handle)).toBeVisible();
});
