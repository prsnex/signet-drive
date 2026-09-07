// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { test, expect, type Page } from '@playwright/test';
import { attestPrsnViaEnrollment, prsnIdentity, seedBroker, signUp, psql } from './helpers';

/** Reload, then return to Account. S116 unlock persistence: a reload SILENTLY
 *  restores the session (zero gestures — the no-reload standard applied to the
 *  crypto session itself), so this asserts the account surface comes back
 *  WITHOUT the Bug014 Unlock tap that reloads used to cost. */
async function reloadIntoAccount(page: Page, handle: string): Promise<void> {
  await page.reload();
  const accountHeading = page.getByRole('heading', { name: 'Account Settings', exact: true });
  const handleLink = page.getByRole('link', { name: handle });
  await expect(accountHeading.or(handleLink).first()).toBeVisible({ timeout: 15_000 });
  // The silent restore is the assertion: no Unlock gesture may be required.
  await expect(page.getByRole('button', { name: 'Unlock' })).not.toBeVisible();
  if (!(await accountHeading.isVisible())) {
    await handleLink.click();
    await expect(accountHeading).toBeVisible({ timeout: 15_000 });
  }
}

// The Garnet guardian dashboard (Phase 4 §6, narrowed by bug084) — the human surface
// for the PRSN Signet Drive-access standing-grant lifecycle. Drives authorize →
// revoke end-to-end through real WebAuthn assertions (the CDP virtual authenticator
// auto-satisfies the gesture), against the real server (Inc.1 routes, #210). This is
// the runes-store ceremony flow the vitest unit can't reach; garnet.test.ts covers the
// pure authorize-picker filter. No pairing code and no hand-off dialog: the agent
// claims the grant by signing its pickup — after authorize the row simply waits.
test('a Guardian authorizes a PRSN for Signet Drive access, then revokes', async ({ page }) => {
  const { handle } = await signUp(page);
  seedBroker(handle); // bug154 §2c: BEFORE /account mounts, so the gate's store read sees it

  // Into Account Settings, then add a guarded PRSN (the attest flow leaves us on /account).
  await page.getByRole('link', { name: handle }).click();
  await expect(page.getByRole('heading', { name: 'Account Settings', exact: true })).toBeVisible({
    timeout: 15_000,
  });

  // bug157, the WITH-BROKER arm (observed live on Chris's account at S168; pinned
  // here so both arms of the conditional live in CI): a broker is registered, the
  // setup card doesn't render, and the nav must not assert the section it targets.
  await expect(
    page
      .getByRole('navigation', { name: 'Account sections' })
      .getByRole('link', { name: 'Signet Drive access' }),
  ).toHaveCount(0);

  const prsn = prsnIdentity();
  await attestPrsnViaEnrollment(page, prsn, handle);

  // §1-64 (S166): ONE card. The PRSN row renders in the consolidated PRSN Accounts
  // card with the NOT AUTHORIZED tag + inline Authorize — the never-authorized
  // state is finally VISIBLE (bug148's actual defect was state-by-omission).
  const card = page.locator('#prsns');
  await expect(card.getByText(prsn.handle, { exact: true })).toBeVisible({ timeout: 15_000 });
  await expect(card.getByText('Not authorized', { exact: true })).toBeVisible();
  await expect(card.getByText('Not authorized', { exact: true })).toHaveAttribute(
    'title',
    /haven't authorized it for Signet Drive yet/,
  );

  // Authorize it inline — ONE passkey gesture mints the standing grant (the whole
  // guardian act, bug084). The dialog opens PRESELECTED to this row's PRSN and
  // carries the bug086 decision inputs: the allocation statement and the shared
  // revocability sentence.
  await card.getByRole('button', { name: 'Authorize', exact: true }).click();
  const authDialog = page.getByRole('dialog');
  await expect(
    authDialog.getByText(`This gives ${prsn.handle} its own working access to Signet Drive`),
  ).toBeVisible();
  await expect(authDialog.getByText('You can revoke it at any time.')).toBeVisible();
  // bug085: the per-grant interval field is gone — the cadence is platform-fixed.
  await expect(authDialog.getByRole('spinbutton')).toHaveCount(0);
  await authDialog.getByRole('button', { name: 'Authorize', exact: true }).click();

  // No code dialog (bug084): the dialog closes and the row flips to the WAITING TO
  // CONNECT tag (its signed pickup auto-confirms; nothing for the guardian to do).
  await expect(card.getByText('Waiting to connect', { exact: true })).toBeVisible({
    timeout: 15_000,
  });

  // bug114 Part D: the tag explains itself on hover (the plain-language tooltip that
  // points at the instructions button — the human half of the surface split).
  await expect(card.getByText('Waiting to connect', { exact: true })).toHaveAttribute(
    'title',
    /Waiting for the PRSN to reconnect/,
  );
  // bug119 (supersedes the bug114 Part-E content): the per-card help button opens the
  // four-line normie modal — reassurance first, the app check, then the two help-page
  // links (rendered as absolute URLs a guardian can paste to their PRSN). The old
  // PRSN-facing jargon (signet commands, "Give these steps to…") is gone from the modal.
  await card.getByRole('button', { name: 'PRSN connection help' }).click();
  const instructions = page.getByRole('dialog');
  await expect(
    instructions.getByText(/Some PRSNs connect automatically when they use Signet Drive/),
  ).toBeVisible();
  await expect(instructions.getByRole('link', { name: /\/help\/prsn-connect$/ })).toHaveAttribute(
    'href',
    '/help/prsn-connect',
  );
  await expect(instructions.getByRole('link', { name: /\/help\/prsn-access$/ })).toHaveAttribute(
    'href',
    '/help/prsn-access',
  );
  await expect(instructions.getByText(/signet garnet pickup/)).not.toBeVisible();
  await instructions.getByRole('button', { name: 'Done', exact: true }).click();
  await expect(instructions).not.toBeVisible();

  // Revoke it — one passkey gesture. §1-64: the row does not leave the card (one
  // row per PRSN, always); its tag flips to REVOKED and the inline action becomes
  // Re-authorize — re-authorization discoverable on the SAME row (the bug108 §6
  // muted-section shape is retired with the second card).
  await card.getByRole('button', { name: 'Revoke', exact: true }).click();
  const revokeDialog = page.getByRole('dialog');
  await expect(revokeDialog.getByText(/Cut Signet Drive access for/)).toBeVisible();
  await revokeDialog.getByRole('button', { name: 'Revoke access' }).click();
  await expect(card.getByText('Revoked', { exact: true })).toBeVisible({ timeout: 15_000 });
  await expect(card.getByText(prsn.handle, { exact: true })).toBeVisible();
  await expect(card.getByRole('button', { name: 'Re-authorize', exact: true })).toBeVisible();

  // Re-authorize creates a FRESH grant (a new authorize gesture, direct — no
  // dialog: the PRSN is named by its own row) — back to WAITING TO CONNECT.
  await card.getByRole('button', { name: 'Re-authorize', exact: true }).click();
  await expect(card.getByText('Waiting to connect', { exact: true })).toBeVisible({
    timeout: 15_000,
  });
  await expect(card.getByText('Revoked', { exact: true })).not.toBeVisible();
});

// bug114 Part B: the 5-minute setup-deadline warning, end-to-end against the REAL clock —
// an attested-but-never-authorized PRSN is in setup (the server emits `setup_deadline` =
// created_at + 30 min on /v1/me/prsns); aging the account into the warning window (26 min:
// past warnAt = deadline − 5 min, still inside the deadline, and safely inside the server
// sweep's own 30-min predicate) must fire the single-OK modal, and OK — with time
// remaining — returns the guardian to the setup flow.
test('the 5-minute setup-deadline warning fires for an in-setup PRSN and OK returns to setup', async ({
  page,
}) => {
  const { handle } = await signUp(page);
  seedBroker(handle); // bug154 §2c: BEFORE /account mounts, so the gate's store read sees it
  await page.getByRole('link', { name: handle }).click();
  await expect(page.getByRole('heading', { name: 'Account Settings', exact: true })).toBeVisible({
    timeout: 15_000,
  });
  const prsn = prsnIdentity();
  await attestPrsnViaEnrollment(page, prsn, handle);

  // Age the in-setup account into the warning window (server-side truth — the client
  // clock never decides; the store's next read carries the aged deadline).
  psql(
    `UPDATE accounts SET created_at = now() - interval '26 minutes' ` +
      `FROM handles WHERE handles.account_id = accounts.account_id ` +
      `AND handles.handle = '${prsn.handle}'`,
  );

  // A reload re-mounts the GarnetStore → fresh /v1/me/prsns read → the warning arms and,
  // being already past warnAt, fires immediately.
  await reloadIntoAccount(page, handle);
  const warning = page.getByRole('dialog');
  await expect(warning.getByText('Setup time is almost up')).toBeVisible({ timeout: 15_000 });
  await expect(
    warning.getByText(`The setup for ${prsn.handle} will be removed in about 5 minutes`),
  ).toBeVisible();

  // OK with time remaining (deadline ~4 min out) → back to the setup flow for this PRSN.
  await warning.getByRole('button', { name: 'OK', exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`/account/add-prsn/confirm\\?handle=${prsn.handle}`), {
    timeout: 15_000,
  });
});

// The broker-setup step (Phase 6): a guardian who has not set up signet on their Mac yet sees the
// one-time setup card and can mint a setup code (session-authed, not a passkey gesture — a
// provisioned-but-unconfirmed broker is inert). Drives the card → Get setup code → code hand-off +
// copy against the real server (GET /v1/garnet/brokers + POST /v1/garnet/broker/provision-code).
test('a Guardian without a broker sees the Mac-setup step and mints a setup code', async ({
  page,
}) => {
  // ⚠ Deliberately NO seedBroker here — the broker-less state IS this test.
  const { handle } = await signUp(page);
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);

  await page.getByRole('link', { name: handle }).click();
  await expect(page.getByRole('heading', { name: 'Account Settings', exact: true })).toBeVisible({
    timeout: 15_000,
  });

  // §1-64: the old section heading is gone with the second card — what remains at
  // #garnet is exactly the one-time Mac-setup card (no broker provisioned yet),
  // which is also the bug154 §2c gate's routing target.
  const panel = page.locator('#garnet');
  await expect(panel.getByText('Set up Signet Drive access on your Mac')).toBeVisible({
    timeout: 15_000,
  });

  // bug157, the NO-BROKER arm — the one never observed live (staging had no
  // broker-less guardian). The nav renders under the SAME predicate as this card,
  // so in this state the entry must exist and must land on the card. The fix is a
  // conditional render, and a conditional proven only where its predicate is false
  // is the bug147/bug150 shape — this assertion is the missing arm, pinned in CI.
  const navLink = page
    .getByRole('navigation', { name: 'Account sections' })
    .getByRole('link', { name: 'Signet Drive access' });
  await expect(navLink).toBeVisible();
  await navLink.click();
  await expect(panel).toBeInViewport();

  // Mint a setup code — session-authed, no passkey gesture — and the code hand-off appears.
  await panel.getByRole('button', { name: 'Get setup code' }).click();
  const setupDialog = page.getByRole('dialog');
  await expect(
    setupDialog.getByRole('heading', { name: 'Set up the Signet app on your Mac' }),
  ).toBeVisible({
    timeout: 15_000,
  });
  await expect(setupDialog.getByText('One-time setup code')).toBeVisible();

  // The code is shown once — copy must work (clipboard actually holds it).
  const code = (await setupDialog.locator('code').innerText()).trim();
  expect(code.length).toBeGreaterThan(0);
  await setupDialog.getByRole('button', { name: 'Copy', exact: true }).click();
  await expect(setupDialog.getByRole('button', { name: 'Copied' })).toBeVisible();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(code);

  await setupDialog.getByRole('button', { name: 'Done' }).click();
  // No broker registered yet (the human hasn't run the install), so the card remains.
  await expect(panel.getByText('Set up Signet Drive access on your Mac')).toBeVisible();
});

// bug085 — the platform-fixed re-confirm cadence, end-to-end on the human surface:
// authorize (no interval field) → the agent's SIGNED pickup auto-confirms (simulated
// at the DB — no real agent in the web e2e stack; the panel must flip to Active on
// its own, Bug033) → the anchor is backdated through the three liveness states
// (in-window eligibility → read-only grace → the hard stop; nothing in coverage
// sleeps) → the ONE-TAP re-confirm (no fingerprint entry — bug084 retired the
// match-gate) re-stamps the anchor → Active again.
test('the fixed cadence degrades through grace to the stop, and one tap re-confirms it back', async ({
  page,
}) => {
  const { handle } = await signUp(page);
  seedBroker(handle); // bug154 §2c: BEFORE /account mounts, so the gate's store read sees it

  await page.getByRole('link', { name: handle }).click();
  await expect(page.getByRole('heading', { name: 'Account Settings', exact: true })).toBeVisible({
    timeout: 15_000,
  });
  const prsn = prsnIdentity();
  await attestPrsnViaEnrollment(page, prsn, handle);

  // Authorize inline from the consolidated card (§1-64) — one gesture; the
  // cadence is the platform's (no dial to set). The dialog preselects the row.
  const panel = page.locator('#prsns');
  await panel.getByRole('button', { name: 'Authorize', exact: true }).click();
  const authDialog = page.getByRole('dialog');
  await authDialog.getByRole('button', { name: 'Authorize', exact: true }).click();
  await expect(panel.getByText('Waiting to connect', { exact: true })).toBeVisible({
    timeout: 15_000,
  });

  // "The agent connected": simulate the SIGNED pickup's server effect (bug084 —
  // integration-tested in garnet_pickup.rs): cert recorded + grant auto-confirmed
  // in one stroke. NO RELOAD (Bug033): the waiting grant is "hot", so the panel's
  // ~10 s poll must flip it to Active by itself — this wait IS the live-update
  // assertion, and the deadline meta line appears with it.
  const fp = 'ZTJlLXJlY29uZmlybS10aHVtYnByaW50LWI2NHVybA';
  const grantId = psql(
    `SELECT grant_id FROM garnet_standing_grants WHERE prsn_handle='${prsn.handle}' AND status='active'`,
  );
  expect(grantId.length).toBeGreaterThan(0);
  const serial = `e2e-cadence-${Date.now()}`;
  psql(
    `INSERT INTO garnet_agent_certs (serial, grant_id, prsn_handle, cert_thumbprint, expires_at, revoked) ` +
      `VALUES ('${serial}', '${grantId}', '${prsn.handle}', '${fp}', now() + interval '7 days', false)`,
  );
  psql(
    `UPDATE garnet_standing_grants SET enrollment_confirmed = true, enrolled_cert_serial = '${serial}', ` +
      `bound_csr_spki_sha256 = '${fp}', last_confirmed_at = now() WHERE grant_id='${grantId}'`,
  );
  await expect(panel.getByText('Active', { exact: true })).toBeVisible({ timeout: 30_000 });
  await expect(panel.getByText(/Re-confirm by/)).toBeVisible();
  // In the healthy middle of the window there is nothing to tap yet — the
  // eligibility window opens with the first warning, not before.
  await expect(panel.getByRole('button', { name: 'Re-confirm', exact: true })).not.toBeVisible();

  // 25 "days pass" (interval 30, lead 7): inside the warning window — the grant is
  // still Active, and the one-tap Re-confirm is now offered (reconfirm_available
  // mirrors the server's eligibility gate exactly).
  psql(
    `UPDATE garnet_standing_grants SET last_confirmed_at = now() - interval '25 days' WHERE grant_id='${grantId}'`,
  );
  await reloadIntoAccount(page, handle);
  await expect(panel.getByText('Active', { exact: true })).toBeVisible({ timeout: 15_000 });
  await expect(panel.getByRole('button', { name: 'Re-confirm', exact: true })).toBeVisible();

  // 33 "days pass": past the deadline, inside the 7-day grace. §1-64 Option B +
  // the WRITES PAUSED ruling: the tag names the consequence, never a permission
  // level — the old 'Read-only' badge collided with the read_only sharing
  // capability rendered on the SAME row.
  psql(
    `UPDATE garnet_standing_grants SET last_confirmed_at = now() - interval '33 days' WHERE grant_id='${grantId}'`,
  );
  await reloadIntoAccount(page, handle);
  await expect(panel.getByText('Writes paused', { exact: true })).toBeVisible({ timeout: 15_000 });
  await expect(panel.getByText(/can read its files but not save changes/)).toBeVisible();

  // 40 "days pass": past deadline + grace — the hard stop (loud, and instantly
  // recoverable by exactly the tap below). Tag: STOPPED.
  psql(
    `UPDATE garnet_standing_grants SET last_confirmed_at = now() - interval '40 days' WHERE grant_id='${grantId}'`,
  );
  await reloadIntoAccount(page, handle);
  await expect(panel.getByText('Stopped', { exact: true })).toBeVisible({
    timeout: 15_000,
  });
  await expect(panel.getByText(/access is paused/)).toBeVisible();

  // The ONE-TAP re-confirm: no fingerprint entry, one passkey gesture — Active again.
  await panel.getByRole('button', { name: 'Re-confirm', exact: true }).click();
  const reconfirmDialog = page.getByRole('dialog');
  await expect(
    reconfirmDialog.getByRole('heading', { name: `Re-confirm ${prsn.handle}` }),
  ).toBeVisible();
  await expect(reconfirmDialog.getByRole('textbox')).toHaveCount(0);
  await reconfirmDialog.getByRole('button', { name: 'Re-confirm', exact: true }).click();
  await expect(panel.getByText('Active', { exact: true })).toBeVisible({ timeout: 15_000 });
  await expect(panel.getByText('Stopped', { exact: true })).not.toBeVisible();
});
