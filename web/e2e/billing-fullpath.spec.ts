// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { test, expect } from '@playwright/test';
import { addPrfAuthenticator } from './helpers';
import { execFileSync } from 'node:child_process';

// S051 Stripe-test pass, Phase 2(b): the FULL human subscribe path, driven entirely
// by Playwright (virtual authenticator — no real Touch ID) + Stripe's hosted test
// checkout (card 4242). Proves create_checkout_session (outbound) + the hosted-page
// UX + the active-status webhook grant end to end. Runs against a dedicated
// signet_drive_billing DB + a server wired to the real rk_test key + stripe listen.
// NOT part of `npm run e2e` (the automated suite stubs Stripe via activate()).

const DB = 'signet_drive_billing';

function verificationToken(email: string): string {
  const sql = `SELECT token FROM pending_email_verifications WHERE email = '${email}' ORDER BY created_at DESC LIMIT 1`;
  return execFileSync(
    'docker',
    ['exec', 'signet-postgres-dev', 'psql', '-U', 'signet', '-d', DB, '-tAc', sql],
    { encoding: 'utf8' },
  ).trim();
}

test('subscribe → hosted checkout (4242) → active webhook grant', async ({ page }) => {
  // Requires the live Stripe-test setup (server wired to the rk_test key + a
  // running `stripe listen` + the signet_drive_billing DB). Skipped in the normal
  // `npm run e2e` gate; run with SIGNET_BILLING_LIVE_TEST=1 after that setup.
  test.skip(!process.env.SIGNET_BILLING_LIVE_TEST, 'needs the live Stripe-test setup');
  test.setTimeout(120_000);
  const runId = `${Date.now()}`;
  const handle = `billing-${runId}`;
  const email = `billing-${runId}@example.com`;

  await addPrfAuthenticator(page);

  // --- real signup (NO activate() — that's the point; we activate via real checkout) ---
  await page.goto('/signup');
  await page.getByLabel('Username').fill(handle);
  await page.getByLabel('Email').fill(email);
  await page.getByRole('checkbox', { name: /Terms of Service/ }).check();
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByText('Check your email')).toBeVisible();
  const token = verificationToken(email);
  expect(token).toMatch(/^[0-9a-f]{32}$/);
  await page.goto(`/verify?token=${token}`);
  await page.getByRole('button', { name: 'Create my passkey' }).click(); // bug062
  // bug244: the second prompt sits behind its own screen; the user's click fires it.
  await page.getByRole('button', { name: 'Continue to unlock' }).click();
  await expect(page.getByRole('heading', { name: 'Share folders' })).toBeVisible({
    timeout: 15_000,
  });
  console.log(`[billing] signed up + verified: ${email}`);

  // --- in-app nav to the billing section (client-side, preserves the KEM session) ---
  // Under the two-window trial (S134) a fresh signup is a USABLE trial, so the banner
  // offers "Manage your trial" and the paid-tier button is "Upgrade" (not the old
  // card-up-front "Choose a plan" / "Subscribe to activate").
  await page.getByRole('link', { name: /Manage your trial/i }).click();
  await expect(page.getByRole('heading', { name: 'Subscription' })).toBeVisible();
  const subscribe = page.getByRole('button', { name: 'Upgrade' });
  await expect(subscribe.first()).toBeVisible();
  console.log(`[billing] tiers shown: ${await subscribe.count()} upgrade buttons`);

  // first button = smallest tier (sortTiers orders small→large) = 10 GB
  await subscribe.first().click();

  // --- Stripe-hosted checkout ---
  await page.waitForURL(/checkout\.stripe\.com/, { timeout: 30_000 });
  console.log(`[billing] at Stripe checkout: ${page.url()}`);
  // Wait for the hosted page to finish rendering before the proof screenshot.
  await expect(page.locator('#cardNumber')).toBeVisible({ timeout: 20_000 });
  await page.screenshot({ path: '/tmp/s051-stripe-checkout.png', fullPage: true });

  // The hosted page (checkout.stripe.com) exposes top-level inputs (not iframed —
  // the whole page is Stripe's origin). Fill the test card.
  await page.locator('#cardNumber').fill('4242424242424242');
  await page.locator('#cardExpiry').fill('1234');
  await page.locator('#cardCvc').fill('123');
  const name = page.locator('#billingName');
  if (await name.count()) await name.fill('Hlin Test');
  const postal = page.locator('#billingPostalCode');
  if (await postal.count()) await postal.fill('42424');
  await page.screenshot({ path: '/tmp/s051-stripe-filled.png', fullPage: true });

  // Submit. Stripe's hosted submit button carries this test id.
  const submit = page.locator(
    '[data-testid="hosted-payment-submit-button"], .SubmitButton, button[type="submit"]',
  );
  await submit.first().click();

  // --- back on the merchant success page ---
  await page.waitForURL(/\/billing\/success/, { timeout: 90_000 });
  await expect(page.getByText('Subscription confirmed')).toBeVisible({ timeout: 15_000 });
  console.log(`[billing] success page: ${page.url()}`);
  await page.screenshot({ path: '/tmp/s051-billing-success.png', fullPage: true });

  // Record the email for the DB grant check (run separately).
  console.log(`[billing] DONE — verify grant for email=${email}`);
});
