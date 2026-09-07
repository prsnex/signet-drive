// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { test } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { psql, signUp } from './helpers';

// §1-64 VISUAL CAPTURE — a review instrument in the uiux-walkthrough mold, NOT a
// regression test (no assertions beyond render): it seeds one PRSN per ruled
// state directly in the e2e DB, renders the REAL consolidated card from the REAL
// server `grant_state` projection, and captures desktop + phone screenshots for
// the layout review (Chris's S166 mobile question). Excluded from the suite via
// playwright.config.ts testIgnore; run explicitly:
//   npx playwright test consolidation-visual --config playwright.config.ts
// ⚠ The default is RELATIVE and must stay that way. It was previously an absolute
// path captured from one authoring session, which leaked four things at once: a
// substrate marker, the operator's OS username (in flattened form), the estate's
// directory layout, and a session UUID. `test-results/` is already gitignored, and
// VISUAL_OUT still overrides for a run that wants the artifacts elsewhere.
const OUT = process.env.VISUAL_OUT ?? 'test-results/consolidation-visual';

/** One synthetic PRSN account + handle under the guardian, no attestation (the
 *  tag column is what's under review; attestation chips render "No attestation"). */
function seedPrsn(guardianHandle: string, handle: string, status = 'active'): void {
  psql(
    `INSERT INTO accounts (account_id, account_type, guardian_account_id, status, ` +
      `prsn_sharing_capability, paid_until, bytes_quota` +
      `${status === 'pending_deletion' ? ', pending_deletion_at' : ''}) ` +
      `SELECT gen_random_uuid(), 'prsn', h.account_id, '${status}', 'read_only', ` +
      `now() + interval '30 days', 1073741824` +
      `${status === 'pending_deletion' ? ", now() + interval '20 hours'" : ''} ` +
      `FROM handles h WHERE h.handle = '${guardianHandle}'`,
  );
  psql(
    `INSERT INTO handles (handle_id, account_id, handle, assigned_at) ` +
      `SELECT gen_random_uuid(), a.account_id, '${handle}', now() FROM accounts a ` +
      `JOIN handles gh ON gh.account_id = a.guardian_account_id AND gh.handle = '${guardianHandle}' ` +
      `WHERE a.account_type = 'prsn' AND NOT EXISTS ` +
      `(SELECT 1 FROM handles h2 WHERE h2.account_id = a.account_id)`,
  );
}

/** A grant in a precise cadence state for the PRSN (30-day interval, 7-day grace
 *  are the seeded knobs; confirmedAgoDays picks the liveness band). */
function seedGrant(
  guardianHandle: string,
  prsnHandle: string,
  opts: { status?: string; confirmed?: boolean; confirmedAgoDays?: number },
): void {
  const status = opts.status ?? 'active';
  const confirmed = opts.confirmed ?? true;
  const ago = opts.confirmedAgoDays ?? 1;
  psql(
    `INSERT INTO garnet_standing_grants ` +
      `(grant_id, prsn_handle, guardian_account_id, status, enrollment_confirmed, ` +
      `enrolled_cert_serial, created_at, last_confirmed_at, prsn_account_id` +
      `${status === 'revoked' ? ', revoked_at' : ''}) ` +
      `SELECT gen_random_uuid(), '${prsnHandle}', gh.account_id, '${status}', ${confirmed}, ` +
      `${confirmed ? `'visual-fixture'` : 'NULL'}, now() - interval '60 days', ` +
      `${confirmed ? `now() - interval '${ago} days'` : 'NULL'}, ph.account_id` +
      `${status === 'revoked' ? ', now()' : ''} ` +
      `FROM handles gh, handles ph ` +
      `WHERE gh.handle = '${guardianHandle}' AND ph.handle = '${prsnHandle}'`,
  );
}

test('capture the consolidated card in every ruled state, desktop + phone', async ({ page }) => {
  test.setTimeout(180_000);
  mkdirSync(OUT, { recursive: true });
  const { handle: guardian } = await signUp(page);

  // A broker, so the machine setup card hides and the §2c gate passes.
  psql(
    `INSERT INTO garnet_brokers (broker_id, guardian_account_id, k3_cert_der) ` +
      `SELECT gen_random_uuid(), h.account_id, '\\x00' FROM handles h WHERE h.handle = '${guardian}'`,
  );

  // One PRSN per ruled state (handles chosen so the card sorts them readably).
  seedPrsn(guardian, 'a-active-ai');
  seedGrant(guardian, 'a-active-ai', { confirmedAgoDays: 1 });
  seedPrsn(guardian, 'b-waiting-ai');
  seedGrant(guardian, 'b-waiting-ai', { confirmed: false });
  seedPrsn(guardian, 'c-not-authorized-ai'); // no grant at all
  seedPrsn(guardian, 'd-writes-paused-ai');
  seedGrant(guardian, 'd-writes-paused-ai', { confirmedAgoDays: 33 }); // 30 < 33 < 37
  seedPrsn(guardian, 'e-stopped-ai');
  seedGrant(guardian, 'e-stopped-ai', { confirmedAgoDays: 45 }); // past 30 + 7
  seedPrsn(guardian, 'f-revoked-ai');
  seedGrant(guardian, 'f-revoked-ai', { status: 'revoked', confirmedAgoDays: 10 });
  seedPrsn(guardian, 'g-deleting-ai', 'pending_deletion');
  seedGrant(guardian, 'g-deleting-ai', { confirmedAgoDays: 2 });

  // Desktop.
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto('/account');
  const card = page.locator('#prsns');
  await card.waitFor({ state: 'visible', timeout: 20_000 });
  // Let the two stores land (tags render once /v1/me/prsns + grants return).
  await page.waitForTimeout(1_500);
  await card.screenshot({ path: `${OUT}/card-desktop.png` });
  await page.screenshot({ path: `${OUT}/account-desktop-full.png`, fullPage: true });

  // Phone (iPhone-ish logical size).
  await page.setViewportSize({ width: 375, height: 812 });
  await page.waitForTimeout(500);
  await card.screenshot({ path: `${OUT}/card-mobile.png` });
  await page.screenshot({ path: `${OUT}/account-mobile-full.png`, fullPage: true });

  // The drive sidebar with the bug150 markers (pending-deletion + not-authorized).
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto('/');
  await page.waitForTimeout(2_000);
  await page.screenshot({ path: `${OUT}/drive-sidebar-desktop.png` });
});
