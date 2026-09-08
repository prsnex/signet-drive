// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { test, expect } from '@playwright/test';
import { makeAdmin, signUp } from './helpers';

// The View 6 admin dashboard (C5-UI). Auth is the human session (no passkey
// ceremony for the admin reads/mutations). The session is in-memory, so navigate
// via in-app link clicks (a full page load would drop it); reaching the dashboard
// is gated on the admin role. Run against the E2E stack (docs/operations/web-e2e.md).

test('a non-admin never sees the Admin entry point', async ({ page }) => {
  await signUp(page);
  // The file browser header gates the Admin link on admin_role — absent for a
  // normal account (the role gate users actually experience).
  await expect(page.getByRole('link', { name: 'Admin' })).toHaveCount(0);
});

test('an admin opens the dashboard and grants a comp', async ({ page }) => {
  const { handle, email } = await signUp(page);
  makeAdmin(email);

  // Visiting Account re-reads /v1/me (client-side nav keeps the session); with the
  // role now granted, the Admin link appears and leads to the dashboard.
  await page.getByRole('link', { name: handle }).click();
  await expect(page.getByRole('heading', { name: 'Account Settings', exact: true })).toBeVisible({
    timeout: 15_000,
  });
  await page.getByRole('link', { name: 'Admin' }).click();

  // All three §8 panes render for an admin.
  await expect(page.getByRole('heading', { name: 'Admin Dashboard' })).toBeVisible({
    timeout: 15_000,
  });
  await expect(page.getByRole('heading', { name: 'System Config' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Transparency Log Status' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Accounts' })).toBeVisible();
  await expect(page.locator('.config-row').first()).toBeVisible();

  // Grant a comp to the admin's own account (the newest → on the first page).
  const row = page.locator('.acct-row', { hasText: handle });
  await expect(row).toBeVisible();

  // The admin's own row carries the read-only admin badge (admin status is
  // visible in the dashboard; promote/revoke live in the server CLI).
  await expect(row.locator('.admin-badge')).toBeVisible();
  await row.getByRole('button', { name: 'Grant comp' }).click();
  await page.getByRole('button', { name: 'Grant', exact: true }).click();

  // The grant lands: the row shows the comp (paid_until coupled to the grant).
  await expect(page.locator('.acct-row', { hasText: handle }).getByText('Comped')).toBeVisible({
    timeout: 10_000,
  });
});

// v1.0.3: an operator deletes a human account from the dashboard. Two accounts:
// the target signs up first and signs out; the admin signs up second. The typed
// confirmation gates the button client-side and the server re-checks it; the row
// then reads `pending_deletion` and loses its Delete action.
test('an admin deletes a human account after typing its name', async ({ page }) => {
  const target = await signUp(page);
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeVisible({ timeout: 15_000 });

  const { handle: adminHandle, email: adminEmail } = await signUp(page);
  makeAdmin(adminEmail);
  await page.getByRole('link', { name: adminHandle }).click();
  await expect(page.getByRole('heading', { name: 'Account Settings', exact: true })).toBeVisible({
    timeout: 15_000,
  });
  await page.getByRole('link', { name: 'Admin' }).click();
  await expect(page.getByRole('heading', { name: 'Admin Dashboard' })).toBeVisible({
    timeout: 15_000,
  });

  const row = page.locator('.acct-row', { hasText: target.handle });
  await expect(row).toBeVisible();
  await row.getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Delete this account' })).toBeVisible();

  // The confirm stays disabled until the exact handle is typed.
  const confirm = page.getByRole('button', { name: 'Delete account' });
  await expect(confirm).toBeDisabled();
  await page.getByLabel('Type the account name to confirm').fill('wrong-name');
  await expect(confirm).toBeDisabled();
  await page.getByLabel('Type the account name to confirm').fill(target.handle);
  await expect(confirm).toBeEnabled();
  await confirm.click();

  // The row reflects the pipeline state and no longer offers Delete; the admin's
  // own row never offered it (admins are refused).
  const after = page.locator('.acct-row', { hasText: target.handle });
  await expect(after.getByText('pending_deletion')).toBeVisible({ timeout: 10_000 });
  await expect(after.getByRole('button', { name: 'Delete', exact: true })).toHaveCount(0);
  await expect(
    page
      .locator('.acct-row', { hasText: adminHandle })
      .getByRole('button', { name: 'Delete', exact: true }),
  ).toHaveCount(0);
});
