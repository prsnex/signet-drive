// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { test, expect } from '@playwright/test';
import { attestPrsnViaEnrollment, prsnIdentity, seedBroker, signUp } from './helpers';

// Account Settings (Views 5/5b, C4 client). Drives the account ceremonies end-to-end
// through real WebAuthn assertions (the CDP virtual authenticator auto-satisfies the
// gesture): issuing an attestation via the S052 enrollment flow (confirm → agent
// submit-keys → approve, no hand-transcription), then change-capability / delete —
// against the real server.
test('a Guardian manages a PRSN through the op-bound ceremonies', async ({ page }) => {
  const { handle, email } = await signUp(page);
  seedBroker(handle); // bug154 §2c: BEFORE /account mounts, so the gate's store read sees it

  // Into Account Settings (the header handle links to /account).
  await page.getByRole('link', { name: handle }).click();
  await expect(page.getByRole('heading', { name: 'Account Settings', exact: true })).toBeVisible({
    timeout: 15_000,
  });
  await expect(page.getByText('Paid until')).toBeVisible();
  // The C4-fields follow-up: the identity header surfaces the login email + the join date.
  await expect(page.getByText(email)).toBeVisible();
  await expect(page.getByText(/Joined/)).toBeVisible();

  // Add a PRSN via the S052 enrollment flow (no hand-transcription, Punch-List 1-23).
  // The Guardian confirms + names it on the confirm-and-approve page; we simulate the
  // agent's keygen + code-authed submit-keys; then one passkey gesture attests exactly
  // those keys (the enrollment-bound issue-attestation ceremony).
  const prsn = prsnIdentity();
  await attestPrsnViaEnrollment(page, prsn, handle);
  // The new PRSN is attested, at the default read-only capability.
  await expect(page.getByText('Verified')).toBeVisible();
  await expect(page.getByText('Can share, read-only')).toBeVisible();

  // Proof of the guardianship dashboard (visual check / artifact).
  await page.screenshot({ path: '/tmp/e-account.png', fullPage: true });

  // Change its sharing capability — the change-sharing-capability ceremony.
  await page.getByRole('button', { name: 'Change capability' }).click();
  const capDialog = page.getByRole('dialog');
  await capDialog.getByRole('combobox').selectOption('read_write');
  await capDialog.getByRole('button', { name: 'Change' }).click();
  await expect(page.getByText('Can share, read-write')).toBeVisible({ timeout: 15_000 });

  // Delete the PRSN — the delete-account ceremony (soft delete → pending deletion).
  // (bug107 removed the standalone attestation-Revoke button + dialog; Delete cascades
  // the attestation away, so revoke-only is no longer a separate guardian UI action.)
  await page.getByRole('button', { name: 'Delete', exact: true }).click();
  const delDialog = page.getByRole('dialog');
  await delDialog.getByPlaceholder(prsn.handle).fill(prsn.handle);
  await delDialog.getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(page.getByText('pending deletion')).toBeVisible({ timeout: 15_000 });
});

test('a Guardian deletes their own account, ending the session', async ({ page }) => {
  const { handle } = await signUp(page);

  await page.getByRole('link', { name: handle }).click();
  await expect(page.getByRole('heading', { name: 'Account Settings', exact: true })).toBeVisible({
    timeout: 15_000,
  });

  await page.getByRole('button', { name: 'Delete account' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByPlaceholder(handle).fill(handle);
  await dialog.getByRole('button', { name: 'Delete my account' }).click();

  // The session is cleared (the account is now pending_deletion, which the auth
  // gate rejects) → back to the landing page.
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible({ timeout: 15_000 });
});

// The C4-S4 keystone: rotating the passkey re-wraps the KEM key under the new
// passkey's PRF (browser-side), and a fresh sign-in with the NEW passkey recovers
// that same key — proven by the file browser rendering after rotation + re-auth.
test('passkey rotation: the new passkey still recovers the KEM key on next sign-in', async ({
  page,
}) => {
  const { handle, email } = await signUp(page);

  await page.getByRole('link', { name: handle }).click();
  await expect(page.getByRole('heading', { name: 'Account Settings', exact: true })).toBeVisible({
    timeout: 15_000,
  });

  // Rotate — three gestures (assert old, register new, assert new), each
  // auto-satisfied by the CDP virtual authenticator; the re-wrap is browser-side.
  await page.getByRole('button', { name: 'Rotate passkey' }).click();
  const dialog = page.getByRole('dialog');
  await dialog.getByRole('button', { name: 'Rotate now' }).click();
  await expect(page.getByText('Your new passkey is active')).toBeVisible({ timeout: 15_000 });
  await page.getByRole('button', { name: 'Done' }).click();

  // Sign out, then sign in: the NEW credential's PRF must unwrap the re-wrapped
  // KEM key. The file browser sidebar rendering proves the key was recovered —
  // the rotation preserved decryptability end-to-end.
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible();
  await page.goto('/signin');
  await page.getByLabel('Email').fill(email);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByRole('heading', { name: 'Share folders' })).toBeVisible({
    timeout: 15_000,
  });
  await expect(page.getByText(handle)).toBeVisible();
});
