// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { expect, test } from '@playwright/test';
import { verificationToken } from './helpers';

// bug062: an unexplained OS credential dialog reads as a scam, so users cancel it
// — a real, security-aware one did, on the primary signup path. Two properties are
// pinned here:
//   (a) the ceremony does NOT fire on page load; the user is told what the dialog
//       is, and their own click triggers it;
//   (b) a cancelled/unavailable ceremony lands on a recoverable screen that says
//       progress is saved and offers a retry — not a raw W3C-link error whose only
//       affordance ("Back to sign up") reads as start-over.
//
// The authenticator here is deliberately one that CANNOT satisfy user
// verification (`isUserVerified: false` against a UV-required ceremony), so
// `credentials.create()` rejects with NotAllowedError — the same error a user
// cancelling the OS dialog produces, which is the whole point of (b). (Registering
// no authenticator at all does not work: the ceremony then simply hangs.)
test('signup explains the passkey prompt first, and a cancelled ceremony offers a retry', async ({
  page,
}) => {
  const runId = `${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
  const handle = `e2e-cancel-${runId}`;
  const email = `${handle}@example.com`;

  const client = await page.context().newCDPSession(page);
  await client.send('WebAuthn.enable');
  await client.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      automaticPresenceSimulation: true,
      isUserVerified: false,
      hasPrf: true,
    },
  });

  await page.goto('/signup');
  await page.getByLabel('Username').fill(handle);
  await page.getByLabel('Email').fill(email);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByText('Check your email')).toBeVisible();

  await page.goto(`/verify?token=${verificationToken(email)}`);

  // (a) Prepared BEFORE the prompt — the ceremony has not fired on load.
  await expect(
    page.getByRole('heading', { name: 'Next, create your passkey for Signet Drive' }),
  ).toBeVisible();
  // The load-bearing promise of the new copy: the user is told TWO checks are
  // coming, so the second prompt is not a fresh surprise (the flow runs
  // create() + a PRF assertion — two gestures on macOS/Chrome, S132).
  await expect(page.getByText(/two passkey checks during account registration/)).toBeVisible();
  // bug066's 15-minute completion window must stay on this screen. It was nearly
  // deleted by a copy branch four sessions stale that predated the line (S137);
  // pinning it means the next such reconciliation fails loudly, not silently.
  await expect(page.getByText(/within 15 minutes to complete signup/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Create my passkey' })).toBeVisible();

  // (b) Cancellation is a recoverable state, and the page says so.
  await page.getByRole('button', { name: 'Create my passkey' }).click();
  await expect(page.getByRole('heading', { name: 'Passkey setup was cancelled' })).toBeVisible({
    timeout: 30_000,
  });
  await expect(page.getByText(/Your progress is saved/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Try again' })).toBeVisible();
});
