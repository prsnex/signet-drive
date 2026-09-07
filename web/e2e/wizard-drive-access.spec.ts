// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { test, expect } from '@playwright/test';
import { attestPrsnViaEnrollment, prsnIdentity, seedBroker, signUp, psql } from './helpers';

// §1-62 PR-C, narrowed by bug084 — the add-PRSN wizard's Signet Drive-access phase,
// end-to-end against the real server: the unfinished-setup entry link → authorize
// (ONE real passkey ceremony, carrying the bug086 allocation + revocability copy) →
// the state-derived wait ("waiting for {handle} to connect" — no pairing code, no
// match-gate) → the agent's signed pickup (simulated at the DB, auto-confirming the
// grant — no real broker binary in e2e) → authorized, with the platform-cadence
// deadline stated.
//
// Also asserts the RESUME property the whole wizard is built on (design note §3.2):
// a mid-flow reload re-derives the step from server state — under bug084 the resumed
// wait step simply continues waiting (there is no shown-once code to lose and no
// re-issue affordance to offer).

test('the wizard walks Signet Drive access end-to-end: authorize → wait → signed pickup auto-confirms → authorized', async ({
  page,
}) => {
  const { handle, email } = await signUp(page);
  seedBroker(handle); // bug154 §2c: BEFORE /account mounts, so the gate's store read sees it

  // Steps 1–3 (covered in depth by the enrollment specs): enroll a PRSN, taking
  // the helper's skip exit back to the account page.
  const prsn = prsnIdentity();
  await page.getByRole('link', { name: handle }).click();
  await expect(page.getByRole('heading', { name: 'Account Settings', exact: true })).toBeVisible({
    timeout: 15_000,
  });
  // bug108 §1 retired the "continue setup" resume link — the wizard continues STRAIGHT
  // into the Drive-access phase, so stay in it rather than exiting + re-entering.
  await attestPrsnViaEnrollment(page, prsn, handle, { stayInWizard: true });

  // The wizard shell names the FLOW, not a step (bug079), and the stepper renders
  // current-step-only — truncation structurally unrepresentable (bug080).
  await expect(page.getByRole('heading', { name: 'Add a PRSN' })).toBeVisible({ timeout: 15_000 });
  await expect(page.getByText('Step 4 of 6 · Authorize')).toBeVisible();

  // bug154 §2c REORDERED this flow: the entry gate means a broker always exists by
  // here, so the wizard lands on AUTHORIZE directly. The Mac-setup step is still a
  // real state (agent-first confirm-page entry has no gate — deliberately), so its
  // coverage moves below: broker deleted mid-flow + a reload re-derives the step.
  // ONE gesture; no interval field (bug085: the cadence is platform-fixed); the two
  // decision inputs on screen (bug086): the allocation statement + revocability.
  // (§4a deleted the old 'Authorize {handle} to use…' intro — the per-step subtitle
  // carries the instruction now.)
  await expect(
    page.getByText('Next, you must authorize this PRSN to use its Signet Drive account.'),
  ).toBeVisible({ timeout: 30_000 });
  await expect(
    page.getByText(`This gives ${prsn.handle} its own working access to Signet Drive`),
  ).toBeVisible();
  await expect(page.getByText('You can revoke it at any time.')).toBeVisible();
  // bug154 §4b: this screen speaks its own verb + primes the macOS "Sign In" quirk.
  await expect(page.getByText(/Authorizing asks for your passkey\. macOS will say/)).toBeVisible();
  await expect(page.getByRole('spinbutton')).toHaveCount(0);

  // The Mac-setup leg (bug154 §2c relocation): delete the broker, reload (the
  // resume path re-derives the step from server state) → the setup card, with NO
  // "check" button (Chris, S145) — the broker-less state is a hot-poll condition,
  // so re-seeding the broker must clear it BY ITSELF, within one poll interval,
  // back to authorize. No further reload.
  const guardianAccountId = psql(`SELECT account_id FROM handles WHERE handle='${handle}'`);
  expect(guardianAccountId.length).toBeGreaterThan(0);
  psql(`DELETE FROM garnet_brokers WHERE guardian_account_id='${guardianAccountId}'`);
  await page.reload();
  await expect(page.getByText('Sign in to approve this PRSN')).toBeVisible({ timeout: 15_000 });
  await page.getByRole('button', { name: 'Sign in' }).click();
  {
    const unlock = page.getByRole('button', { name: 'Unlock' });
    const emailField = page.getByLabel('Email');
    await expect(unlock.or(emailField)).toBeVisible({ timeout: 15_000 });
    if (await unlock.isVisible()) {
      await unlock.click();
    } else {
      await emailField.fill(email);
      await page.getByRole('button', { name: 'Continue' }).click();
    }
  }
  await expect(page.getByText('Connect the Signet app on your Mac')).toBeVisible({
    timeout: 15_000,
  });
  await expect(page.getByRole('button', { name: /Check the connection/ })).toHaveCount(0);
  // The installer download lives HERE now (bug154 §2b moved it off the hand-off step).
  const setupDownload = page.getByRole('link', { name: /Download the Signet app/ });
  await expect(setupDownload).toBeVisible();
  await expect(setupDownload).toHaveAttribute('href', '/cli/signet-macos.zip');
  psql(
    `INSERT INTO garnet_brokers (broker_id, guardian_account_id, k3_cert_der, provisioned_at) ` +
      `VALUES (gen_random_uuid(), '${guardianAccountId}', decode('00','hex'), now())`,
  );
  await expect(
    page.getByText('Next, you must authorize this PRSN to use its Signet Drive account.'),
  ).toBeVisible({ timeout: 30_000 });
  await page.getByRole('button', { name: 'Authorize' }).click();

  // The wait step — state-derived; nothing to hand over (bug084: no pairing code
  // on screen, anywhere). bug154 §5: the guidance is three bullets now, the false
  // self-advance promise is DELETED (not softened), and the fallback command is
  // named so the copy is true for host-native PRSNs too (bug151 §2b).
  await expect(page.getByText(`Waiting for ${prsn.handle} to connect`)).toBeVisible({
    timeout: 15_000,
  });
  await expect(page.getByText('Step 5 of 6 · Connect')).toBeVisible();
  await expect(page.getByText(/There's no code to hand over/)).toBeVisible();
  await expect(page.getByText(/signet connect/)).toBeVisible();
  await expect(page.getByText('This page updates by itself')).toHaveCount(0);
  await expect(page.locator('code')).toHaveCount(0);

  // THE RESUME PROPERTY: reload mid-flow. A full load on this route drops the
  // in-memory session (the same reality enrollment-signin-return pins), so the
  // resumed path runs sign-in → returnTo (now carrying ?handle=) → the Bug014
  // one-tap → back HERE — where the step re-derives from server state (still
  // awaiting pickup) and simply keeps waiting.
  await page.reload();
  await expect(page.getByText('Sign in to approve this PRSN')).toBeVisible({ timeout: 15_000 });
  await page.getByRole('button', { name: 'Sign in' }).click();
  const unlock = page.getByRole('button', { name: 'Unlock' });
  const emailField = page.getByLabel('Email');
  await expect(unlock.or(emailField)).toBeVisible({ timeout: 15_000 });
  if (await unlock.isVisible()) {
    await unlock.click();
  } else {
    await emailField.fill(email);
    await page.getByRole('button', { name: 'Continue' }).click();
  }
  await expect(page).toHaveURL(/handle=/, { timeout: 15_000 });
  await expect(page.getByText(`Waiting for ${prsn.handle} to connect`)).toBeVisible({
    timeout: 15_000,
  });

  // "The agent connected": simulate the SIGNED pickup's server effect (bug084 —
  // integration-tested in garnet_pickup.rs): record the issued cert AND
  // auto-confirm the grant in the same stroke. The wizard's hot-poll must then
  // advance to Done by itself (Bug033: no reload).
  const fp = 'ZTJlLXdpemFyZC10aHVtYnByaW50LWI2NHVybC0zMg';
  const grantId = psql(
    `SELECT grant_id FROM garnet_standing_grants WHERE prsn_handle='${prsn.handle}' AND status='active'`,
  );
  expect(grantId.length).toBeGreaterThan(0);
  const serial = `e2e-wizard-${Date.now()}`;
  psql(
    `INSERT INTO garnet_agent_certs (serial, grant_id, prsn_handle, cert_thumbprint, expires_at, revoked) ` +
      `VALUES ('${serial}', '${grantId}', '${prsn.handle}', '${fp}', now() + interval '7 days', false)`,
  );
  psql(
    `UPDATE garnet_standing_grants SET enrollment_confirmed = true, enrolled_cert_serial = '${serial}', ` +
      `bound_csr_spki_sha256 = '${fp}', last_confirmed_at = COALESCE(last_confirmed_at, now()) ` +
      `WHERE grant_id='${grantId}'`,
  );

  // Done — authorized (no confirm ceremony: the signature WAS the verification),
  // with the platform-cadence deadline stated concretely.
  await expect(
    page.getByText(`✓ ${prsn.handle} is added and authorized for Signet Drive.`),
  ).toBeVisible({
    timeout: 30_000,
  });
  await expect(page.getByText('Step 6 of 6 · Done')).toBeVisible();
  // bug154 §6a: the consequence stated TRUE — a read-only grace, not a cut-off.
  await expect(page.getByText(/You'll need to re-confirm this authorization by/)).toBeVisible();
  await expect(page.getByText(/can still read and download/)).toBeVisible();
  await page.getByRole('button', { name: 'Go to account' }).click();
  await expect(page.getByRole('heading', { name: 'Account Settings', exact: true })).toBeVisible({
    timeout: 15_000,
  });
});

// bug108 §2/§3 — Cancel out of setup. PRE-account (the hand-off step): a confirm modal,
// then the pending-enrollment record is removed and we land back on Settings. No agent.
test('Cancel at the hand-off step removes the pre-account enrollment and returns to Settings', async ({
  page,
}) => {
  const { handle } = await signUp(page);
  // bug154 §2c: seed BEFORE /account mounts — the gate reads the store's
  // mount-time broker fetch, so a later seed is invisible until the next poll.
  seedBroker(handle);
  await page.getByRole('link', { name: handle }).click();
  await expect(page.getByRole('heading', { name: 'Account Settings', exact: true })).toBeVisible({
    timeout: 15_000,
  });

  // Name → Continue mints the enrollment (Step 2, hand-off).
  await page.getByRole('button', { name: '+ Add PRSN' }).click();
  await expect(page.getByRole('heading', { name: 'Add a PRSN' })).toBeVisible({ timeout: 15_000 });
  await page.getByLabel('PRSN name').fill('cancelme');
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/account\/add-prsn\/confirm\?code=/, { timeout: 15_000 });

  // Cancel — the confirm modal names the wipe, then the enrollment record is removed.
  const cancel = page.getByRole('button', { name: 'Cancel', exact: true });
  await expect(cancel).toBeVisible({ timeout: 15_000 });
  await cancel.click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByText(/permanently deletes/)).toBeVisible();
  await dialog.getByRole('button', { name: 'Cancel and delete' }).click();

  await expect(page.getByRole('heading', { name: 'Account Settings', exact: true })).toBeVisible({
    timeout: 15_000,
  });
  expect(psql(`SELECT count(*) FROM pending_prsn_enrollments WHERE handle='cancelme-ai'`)).toBe(
    '0',
  );
});

// bug108 §2/§3 — Cancel POST-attest (the Mac-setup step): an attested, never-authorized
// account exists; the confirm modal wipes it (marked pending_deletion) and returns to Settings.
test('Cancel at the Mac-setup step wipes the attested PRSN account and returns to Settings', async ({
  page,
}) => {
  const { handle } = await signUp(page);
  seedBroker(handle); // bug154 §2c: BEFORE /account mounts
  const prsn = prsnIdentity();
  await page.getByRole('link', { name: handle }).click();
  await expect(page.getByRole('heading', { name: 'Account Settings', exact: true })).toBeVisible({
    timeout: 15_000,
  });
  await attestPrsnViaEnrollment(page, prsn, handle, { stayInWizard: true });

  // bug154 §2c: post-attest now lands on AUTHORIZE (a broker always exists past
  // the entry gate). The bug108 property under test is unchanged — Cancel at any
  // post-attest, pre-connect step wipes the account; the authorize step carries
  // the same Cancel affordance the Mac-setup step did.
  await expect(
    page.getByText('Next, you must authorize this PRSN to use its Signet Drive account.'),
  ).toBeVisible({ timeout: 15_000 });
  const acctId = psql(`SELECT account_id FROM handles WHERE handle='${prsn.handle}'`);
  expect(acctId.length).toBeGreaterThan(0);

  const cancel = page.getByRole('button', { name: 'Cancel', exact: true });
  await expect(cancel).toBeVisible({ timeout: 15_000 });
  await cancel.click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByText(/permanently deletes/)).toBeVisible();
  await dialog.getByRole('button', { name: 'Cancel and delete' }).click();

  await expect(page.getByRole('heading', { name: 'Account Settings', exact: true })).toBeVisible({
    timeout: 15_000,
  });
  expect(psql(`SELECT status FROM accounts WHERE account_id='${acctId}'`)).toBe('pending_deletion');
});
