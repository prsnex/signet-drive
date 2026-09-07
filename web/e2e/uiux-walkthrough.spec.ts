// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
//
// S121 UI/UX details-review instrument — NOT a regression test. Kept in-repo
// but excluded from the e2e suite + CI via `testIgnore` in playwright.config.ts
// (it's a manual review tool, not a gate). Drives every human-web screen and
// state and captures full-page screenshots for a careful visual + copy review;
// assertions exist only to sequence the walk — the review happens on the
// captured images (web/test-results/uiux-shots/, gitignored) afterwards.
//
// To run it for a review: temporarily remove it from testIgnore, start the
// stack (docs/operations/web-e2e.md), then `npx playwright test uiux-walkthrough`.

import { expect, test } from '@playwright/test';
import { spawn } from 'node:child_process';
import {
  activate,
  addPrfAuthenticator,
  makeAdmin,
  SIGNET_BIN,
  prsnIdentity,
  psql,
  signetEnv,
  verificationToken,
} from './helpers';

const SHOTS = 'test-results/uiux-shots';

let shotIndex = 0;
async function shot(page: import('@playwright/test').Page, name: string) {
  shotIndex += 1;
  const n = String(shotIndex).padStart(2, '0');
  await page.screenshot({ path: `${SHOTS}/${n}-${name}.png`, fullPage: true });
}

/** Run an optional walk segment; a selector miss logs and moves on instead of
 *  killing the remaining walk (this is a review instrument, not a gate). */
const missed: string[] = [];
async function tryStep(name: string, fn: () => Promise<void>) {
  try {
    await fn();
  } catch (e) {
    missed.push(`${name}: ${String(e).split('\n')[0]}`);
  }
}

test.setTimeout(420_000);

test('walk every human-web screen and state', async ({ page, browser }) => {
  const runId = `${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
  const handle = `uiux-${runId}`;
  const email = `uiux-${runId}@example.com`;

  await addPrfAuthenticator(page);

  // --- 1. Unauthenticated auth surfaces -----------------------------------
  await page.goto('/signin');
  await expect(
    page.getByLabel('Email').or(page.getByRole('button', { name: 'Unlock' })),
  ).toBeVisible({
    timeout: 15_000,
  });
  await shot(page, 'signin-fresh');

  // Unknown-account error copy.
  await page.getByLabel('Email').fill('nobody@example.com');
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.waitForTimeout(1500);
  await shot(page, 'signin-unknown-account-error');

  await page.goto('/signup');
  await shot(page, 'signup-empty');

  // Client-side validation state.
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.waitForTimeout(700);
  await shot(page, 'signup-validation-empty-submit');

  await page.getByLabel('Username').fill(handle);
  await page.getByLabel('Email').fill(email);
  await shot(page, 'signup-filled');
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByText('Check your email')).toBeVisible();
  await shot(page, 'signup-check-your-email');

  const token = verificationToken(email);
  await page.goto(`/verify?token=${token}`);
  await page.getByRole('button', { name: 'Create my passkey' }).click(); // bug062
  await expect(page.getByRole('heading', { name: 'Share folders' })).toBeVisible({
    timeout: 15_000,
  });

  // --- 2. The un-activated (read-only) state, then activation -------------
  await shot(page, 'drive-unactivated-readonly');
  activate(email);
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Share folders' })).toBeVisible({
    timeout: 15_000,
  });
  await shot(page, 'drive-empty-hero');

  // --- 3. Drive: folders, files, selection, rename, sort ------------------
  // (The two "+ New" buttons share one accessible name — disambiguated by
  // section text, which is itself a catalog finding: W-a11y-1.)
  const sidebar = page.locator('aside');
  await sidebar.getByRole('button', { name: 'New share folder' }).click();
  await shot(page, 'new-folder-dialog');
  await page.getByLabel('Folder name').fill('Project Aurora');
  await page.getByRole('dialog').getByRole('button', { name: 'Create' }).click();
  await sidebar.getByRole('button', { name: 'Project Aurora', exact: true }).click();
  await expect(page.getByText('Nothing sealed here yet.')).toBeVisible();
  await shot(page, 'folder-empty-state');

  await page.locator('input[type="file"]').setInputFiles([
    { name: 'notes.txt', mimeType: 'text/plain', buffer: Buffer.from('uiux review notes\n') },
    {
      name: 'quarterly-report-with-a-fairly-long-filename.pdf',
      mimeType: 'application/pdf',
      buffer: Buffer.from('%PDF-1.4 uiux'),
    },
    { name: 'photo.jpg', mimeType: 'image/jpeg', buffer: Buffer.from([0xff, 0xd8, 0xff, 0xe0]) },
  ]);
  await expect(page.getByRole('button', { name: 'notes.txt' })).toBeVisible({ timeout: 30_000 });
  await expect(page.getByRole('button', { name: 'photo.jpg' })).toBeVisible({ timeout: 30_000 });
  await shot(page, 'folder-populated');

  await page.getByRole('checkbox', { name: 'Select file notes.txt' }).check();
  await shot(page, 'selection-single');
  await page.getByRole('checkbox', { name: 'Select file photo.jpg' }).check();
  await shot(page, 'selection-multi');

  await page.getByRole('checkbox', { name: 'Select file photo.jpg' }).uncheck();
  await tryStep('rename-dialog', async () => {
    await page.getByRole('button', { name: 'Rename' }).click();
    await shot(page, 'rename-dialog');
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();
  });
  await page.getByRole('checkbox', { name: 'Select file notes.txt' }).uncheck();

  // Column sorting states.
  await tryStep('sort-name-active', async () => {
    await page.getByRole('button', { name: 'Name', exact: true }).click({ timeout: 5000 });
    await shot(page, 'sort-name-active');
  });

  // Delete confirmation dialog (canceled — the state is what we review).
  await tryStep('delete-confirm-dialog', async () => {
    await page.getByRole('checkbox', { name: 'Select file photo.jpg' }).check();
    await page.getByRole('button', { name: 'Delete' }).click();
    await shot(page, 'delete-confirm-dialog');
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();
    await page.getByRole('checkbox', { name: 'Select file photo.jpg' }).uncheck();
  });

  // --- 4. Sharing: dialog, invite link, second-account accept -------------
  // The recipient signs up first (in a second context) so the invite can name them.
  const recipientCtx = await browser.newContext();
  const rPage = await recipientCtx.newPage();
  await addPrfAuthenticator(rPage);
  const rHandle = `uiux-r-${runId}`;
  const rEmail = `uiux-r-${runId}@example.com`;
  await rPage.goto('/signup');
  await rPage.getByLabel('Username').fill(rHandle);
  await rPage.getByLabel('Email').fill(rEmail);
  await rPage.getByRole('button', { name: 'Continue' }).click();
  await expect(rPage.getByText('Check your email')).toBeVisible();
  await rPage.goto(`/verify?token=${verificationToken(rEmail)}`);
  await rPage.getByRole('button', { name: 'Create my passkey' }).click(); // bug062
  await expect(rPage.getByRole('heading', { name: 'Share folders' })).toBeVisible({
    timeout: 15_000,
  });
  activate(rEmail);

  await page.getByRole('button', { name: 'Share', exact: true }).click();
  await shot(page, 'share-dialog-empty');
  await page.getByLabel('Their username').fill(rHandle);
  await page.getByRole('dialog').getByRole('button', { name: 'Generate invitation link' }).click();
  await expect(page.getByRole('dialog').locator('code')).toBeVisible({ timeout: 15_000 });
  await shot(page, 'share-dialog-link-generated');
  const invite = (await page.getByRole('dialog').locator('code').innerText()).trim();
  await page.keyboard.press('Escape');

  await rPage.goto(invite);
  await expect(rPage.getByRole('button', { name: 'Accept' })).toBeVisible({ timeout: 15_000 });
  await shot(rPage, 'invite-accept-page');
  await rPage.getByRole('button', { name: 'Accept' }).click();
  await expect(rPage.getByText('You now have access')).toBeVisible({ timeout: 15_000 });
  await shot(rPage, 'invite-accepted');
  await rPage.goto('/');
  await expect(rPage.getByRole('heading', { name: 'Share folders' })).toBeVisible({
    timeout: 15_000,
  });
  await shot(rPage, 'recipient-shared-with-you-nav');
  await rPage.locator('aside').getByRole('button', { name: 'Project Aurora', exact: true }).click();
  await page.waitForTimeout(800);
  await shot(rPage, 'recipient-shared-folder-view');

  // The owner's recipient list after the accept.
  await page.getByRole('button', { name: 'Share', exact: true }).click();
  await page.waitForTimeout(800);
  await shot(page, 'share-dialog-recipient-list');
  await page.keyboard.press('Escape');

  // --- 5. PRSN enrollment (wizard states) ----------------------------------
  await page.getByRole('link', { name: handle }).click();
  await expect(page.getByRole('heading', { name: 'Account Settings', exact: true })).toBeVisible({
    timeout: 15_000,
  });
  await shot(page, 'account-dashboard-full');

  await page.getByRole('button', { name: '+ Add PRSN' }).click();
  await expect(page.getByRole('heading', { name: 'Add a PRSN' })).toBeVisible({
    timeout: 15_000,
  });
  // §1-62: step 1 is the naming form; the mint happens on Continue.
  await shot(page, 'enrollment-wizard-name-step');

  const prsn = prsnIdentity();
  await page.getByLabel('PRSN name').fill(prsn.handle);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/account\/add-prsn\/confirm\?code=/, { timeout: 15_000 });
  await shot(page, 'enrollment-approve-page-waiting');
  const code = new URL(page.url()).searchParams.get('code');
  const env = {
    ...signetEnv(prsn.keysDir),
    SIGNET_HANDLE: prsn.handle,
    SIGNET_ENROLL_POLL_MS: '250',
    SIGNET_TEST_CLAIM_KEY_PROTECTION: 'secure_enclave',
  };
  const agent = spawn(SIGNET_BIN, ['enroll', code as string], { env });
  let agentOut = '';
  agent.stdout.on('data', (d: Buffer) => (agentOut += d.toString()));
  agent.stderr.on('data', (d: Buffer) => (agentOut += d.toString()));
  const agentDone = new Promise<void>((resolvePromise, reject) => {
    agent.on('close', (exitCode: number | null) =>
      exitCode === 0
        ? resolvePromise()
        : reject(new Error(`signet enroll exited ${exitCode}: ${agentOut}`)),
    );
  });

  // Naming already happened at step 1 — the keys-arrived approve state unlocks.
  await expect(page.getByRole('button', { name: 'Approve with passkey' })).toBeVisible({
    timeout: 30_000,
  });
  await shot(page, 'enrollment-hard-confirm-keys-arrived');
  await page.getByRole('button', { name: 'Approve with passkey' }).click();
  await expect(page.getByText(/is set up/)).toBeVisible({ timeout: 15_000 });
  // §1-62 PR-C: the wizard continues into the Drive-access phase — first render is
  // the broker-setup gate (no broker in this stack yet).
  await shot(page, 'enrollment-complete-drive-broker-setup');
  await agentDone;

  // --- 5b. The Drive-access phase (bug084: ONE gesture, no code, auto-confirm) ---
  // Seed the guardian's broker row (no real broker binary in the e2e stack), then
  // walk authorize → wait → (simulated signed pickup) → done, and the bug085
  // cadence states on the account panel.
  await tryStep('drive-access walk', async () => {
    const guardianAccountId = psql(`SELECT account_id FROM handles WHERE handle='${handle}'`);
    psql(
      `INSERT INTO garnet_brokers (broker_id, guardian_account_id, k3_cert_der, provisioned_at) ` +
        `VALUES (gen_random_uuid(), '${guardianAccountId}', decode('00','hex'), now())`,
    );
    // Enter via /account + the continue-setup link (the real user path): a full
    // load on the WIZARD route drops the in-memory session (the reality
    // enrollment-signin-return pins), while the account surface restores silently
    // (S116 — garnet.spec's reloadIntoAccount proves it).
    await page.goto('/account');
    const accountHeading = page.getByRole('heading', { name: 'Account Settings', exact: true });
    const handleLink = page.getByRole('link', { name: handle });
    await expect(accountHeading.or(handleLink).first()).toBeVisible({ timeout: 15_000 });
    if (!(await accountHeading.isVisible())) {
      await handleLink.click();
      await expect(accountHeading).toBeVisible({ timeout: 15_000 });
    }
    await page.getByRole('link', { name: `${prsn.handle} · continue setup →` }).click();
    await expect(page.getByText(`Authorize ${prsn.handle} to use Signet Drive`)).toBeVisible({
      timeout: 15_000,
    });
    await shot(page, 'wizard-drive-authorize-step');
    await page.getByRole('button', { name: 'Authorize' }).click();
    await expect(page.getByText(`Waiting for ${prsn.handle} to connect`)).toBeVisible({
      timeout: 15_000,
    });
    await shot(page, 'wizard-drive-waiting-step');

    // The signed pickup's server effect (bug084), simulated at the DB.
    const grantId = psql(
      `SELECT grant_id FROM garnet_standing_grants WHERE prsn_handle='${prsn.handle}' AND status='active'`,
    );
    const serial = `uiux-${Date.now()}`;
    psql(
      `INSERT INTO garnet_agent_certs (serial, grant_id, prsn_handle, cert_thumbprint, expires_at, revoked) ` +
        `VALUES ('${serial}', '${grantId}', '${prsn.handle}', 'dWl1eC13YWxrdGhyb3VnaC1mcA', now() + interval '7 days', false)`,
    );
    psql(
      `UPDATE garnet_standing_grants SET enrollment_confirmed = true, enrolled_cert_serial = '${serial}', ` +
        `bound_csr_spki_sha256 = 'dWl1eC13YWxrdGhyb3VnaC1mcA', last_confirmed_at = now() WHERE grant_id='${grantId}'`,
    );
    await expect(page.getByText(/is added and authorized/)).toBeVisible({ timeout: 30_000 });
    await shot(page, 'wizard-drive-authorized-done');
    await page.getByRole('button', { name: 'Go to account' }).click();
    await expect(page.getByRole('heading', { name: 'Account Settings', exact: true })).toBeVisible({
      timeout: 15_000,
    });
    await shot(page, 'account-with-prsn-card');

    // The bug085 cadence states on the panel: read-only grace → the hard stop →
    // the one-tap re-confirm dialog → Active again.
    const panel = page.locator('#garnet');
    psql(
      `UPDATE garnet_standing_grants SET last_confirmed_at = now() - interval '33 days' WHERE grant_id='${grantId}'`,
    );
    await page.reload();
    await expect(panel.getByText('Read-only', { exact: true })).toBeVisible({ timeout: 15_000 });
    await shot(page, 'account-garnet-grace-readonly');
    psql(
      `UPDATE garnet_standing_grants SET last_confirmed_at = now() - interval '40 days' WHERE grant_id='${grantId}'`,
    );
    await page.reload();
    await expect(panel.getByText('Needs re-confirmation', { exact: true })).toBeVisible({
      timeout: 15_000,
    });
    await shot(page, 'account-garnet-hard-stop');
    await panel.getByRole('button', { name: 'Re-confirm', exact: true }).click();
    await expect(page.getByRole('dialog')).toBeVisible();
    await shot(page, 'garnet-reconfirm-dialog');
    await page.getByRole('dialog').getByRole('button', { name: 'Re-confirm', exact: true }).click();
    await expect(panel.getByText('Active', { exact: true })).toBeVisible({ timeout: 15_000 });
    await shot(page, 'account-garnet-active-after-reconfirm');
  });

  // --- 6. Admin surfaces ----------------------------------------------------
  makeAdmin(email);
  await page.goto('/admin');
  await page.waitForTimeout(1500);
  await shot(page, 'admin-dashboard');
  const configTab = page
    .getByRole('button', { name: /config/i })
    .or(page.getByRole('link', { name: /config/i }));
  if (
    await configTab
      .first()
      .isVisible()
      .catch(() => false)
  ) {
    await configTab.first().click();
    await page.waitForTimeout(800);
    await shot(page, 'admin-system-config');
  }

  // --- 7. Error page + lock + welcome-back ---------------------------------
  await page.goto('/nonexistent-route-for-404');
  await page.waitForTimeout(800);
  await shot(page, 'error-404-page');

  await tryStep('lock-unlock', async () => {
    await page.goto('/account');
    await expect(page.getByRole('heading', { name: 'Account Settings', exact: true })).toBeVisible({
      timeout: 15_000,
    });
    const lock = page.getByRole('button', { name: 'Lock', exact: true });
    await lock.click({ timeout: 5000 });
    await page.waitForTimeout(1200);
    await shot(page, 'locked-one-tap-unlock');
    const unlock = page.getByRole('button', { name: 'Unlock' });
    if (await unlock.isVisible().catch(() => false)) {
      await unlock.click();
      await page.waitForTimeout(1500);
    }
  });

  // --- 8. Responsive: mobile + tablet --------------------------------------
  await page.setViewportSize({ width: 375, height: 812 });
  await page.goto('/');
  await page.waitForTimeout(1200);
  await shot(page, 'mobile-drive');
  await tryStep('mobile-drawer', async () => {
    await page.getByRole('button', { name: 'Open navigation' }).click({ timeout: 5000 });
    await page.waitForTimeout(600);
    await shot(page, 'mobile-drawer-open');
    await page.getByLabel('Close navigation').click({ position: { x: 360, y: 400 } });
  });
  await page.goto('/account');
  await page.waitForTimeout(1200);
  await shot(page, 'mobile-account');

  await page.setViewportSize({ width: 768, height: 1024 });
  await page.goto('/');
  await page.waitForTimeout(1200);
  await shot(page, 'tablet-drive');

  // --- 9. Sign out + the welcome-back one-tap variant ----------------------
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/');
  await page.waitForTimeout(800);
  await tryStep('sign-out-and-welcome-back', async () => {
    await page.getByRole('button', { name: 'Sign out' }).click({ timeout: 8000 });
    await page.waitForTimeout(1000);
    await shot(page, 'signed-out');
    await page.goto('/signin');
    await page.waitForTimeout(1000);
    await shot(page, 'signin-welcome-back-one-tap');
  });

  await recipientCtx.close();
  if (missed.length) console.log(`[walkthrough] skipped segments:\n  ${missed.join('\n  ')}`);
});
