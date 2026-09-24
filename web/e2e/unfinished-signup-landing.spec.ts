// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { expect, test } from '@playwright/test';
import { verificationToken } from './helpers';

// bug065: an abandoned signup (email verified, passkey never created — exactly the
// state a cancelled bug062 prompt leaves) that returns to the site root was shown
// "Welcome back … Unlock", which can never succeed (there is no passkey to sign in
// with) and whose error misdirects. Two properties are pinned:
//   (a) the landing offers FINISHING setup, not the dead-end "Unlock";
//   (b) that path RESUMES registration (the bug062 prep screen) with no second
//       verification email.
// No virtual authenticator is needed: we deliberately stop *before* the passkey
// ceremony, which is the whole point — the account is incomplete.
test('an unfinished signup is offered finish-setup on the landing, not a dead-end unlock', async ({
  page,
}) => {
  const runId = `${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
  const handle = `e2e-unfinished-${runId}`;
  const email = `${handle}@example.com`;

  // Sign up + verify the email — but do NOT register a passkey.
  await page.goto('/signup');
  await page.getByLabel('Username').fill(handle);
  await page.getByLabel('Email').fill(email);
  await page.getByRole('checkbox', { name: /Terms of Service/ }).check();
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByText('Check your email')).toBeVisible();

  // Verifying the token mints the session and creates the account; the prep screen
  // then appears — the account now has a valid session but no passkey and no KEM key.
  await page.goto(`/verify?token=${verificationToken(email)}`);
  await expect(
    page.getByRole('heading', { name: 'Next, create your passkey for Signet Drive' }),
  ).toBeVisible();

  // (a) Returning to the site root must NOT offer the dead-end "Unlock" (bug065).
  await page.goto('/');
  await expect(page.getByRole('button', { name: 'Finish setting up' })).toBeVisible();
  await expect(page.getByText(/account isn't finished yet/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Unlock', exact: true })).toHaveCount(0);

  // (b) Finishing setup resumes registration — the bug062 prep screen — with no
  // second verification email (the token was already consumed).
  await page.getByRole('button', { name: 'Finish setting up' }).click();
  await expect(
    page.getByRole('heading', { name: 'Next, create your passkey for Signet Drive' }),
  ).toBeVisible();
});
