// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { test, expect } from '@playwright/test';
import { spawn } from 'node:child_process';
import { SIGNET_BIN, prsnIdentity, seedBroker, signUp, signetEnv } from './helpers';

// Regression — S054 partnered-test finding #1.
//
// The agent-first confirm page is opened by `signet enroll` in a fresh tab with no
// in-memory session, so it shows "sign in to approve". Before the fix, that button
// went to `/signin`, which on success redirected to the drive (`/`) — the human
// never returned to the confirm page, orphaning the agent's enrollment with no path
// back to approve it. The fix carries the enrollment code through sign-in
// (`/signin?returnTo=…/confirm?code=…`, honored same-origin) so the human lands back
// on the confirm page. This test fails pre-fix (it would end on the drive).
test('confirm: signing in from the no-session confirm page returns to confirm, not the drive', async ({
  page,
}) => {
  const { handle, email } = await signUp(page);
  // bug154 §2c: the broker gate stands between + PRSN and the wizard.
  seedBroker(handle);

  // Into /account via the header handle link (a client-side nav keeps the session;
  // a full `goto('/account')` would drop the in-memory session and bounce to /signin).
  await page.getByRole('link', { name: handle }).click();
  await expect(page.getByRole('heading', { name: 'Account Settings', exact: true })).toBeVisible({
    timeout: 15_000,
  });

  // §1-62: name first, mint on Continue — the code appears in the confirm URL
  // only after the step-1 submit.
  await page.getByRole('button', { name: '+ Add PRSN' }).click();
  await expect(page.getByRole('heading', { name: 'Add a PRSN' })).toBeVisible({
    timeout: 15_000,
  });
  await page.getByLabel('PRSN name').fill(prsnIdentity().handle);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/account\/add-prsn\/confirm\?code=/, { timeout: 15_000 });
  const code = new URL(page.url()).searchParams.get('code');
  expect(code).toBeTruthy();

  // The agent-first reality: a full page load (a fresh tab) drops the in-memory
  // session, so the confirm page shows "sign in to approve" — not the flow.
  await page.goto(`/account/add-prsn/confirm?code=${code}`);
  await expect(page.getByText('Sign in to approve this PRSN')).toBeVisible({ timeout: 15_000 });

  // The confirm page's "Sign in" must carry the code via returnTo.
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page).toHaveURL(/\/signin\?returnTo=/);

  // Sign in (identified; the virtual authenticator keeps the passkey). A
  // remembered account in this context shows the Bug014 one-tap Unlock
  // variant instead of the Email form — both must return to the confirm page.
  const unlock = page.getByRole('button', { name: 'Unlock' });
  const emailField = page.getByLabel('Email');
  await expect(unlock.or(emailField)).toBeVisible({ timeout: 15_000 });
  if (await unlock.isVisible()) {
    await unlock.click();
  } else {
    await emailField.fill(email);
    await page.getByRole('button', { name: 'Continue' }).click();
  }

  // The fix: land back on the confirm page with the flow live, NOT the drive.
  // (Pre-fix this URL would be `/`.) The row was named+confirmed at step 1, so the
  // resumed page shows the HAND-OFF step (the enroll command), not the naming form.
  await expect(page).toHaveURL(/\/account\/add-prsn\/confirm\?code=/, { timeout: 15_000 });
  await expect(page.getByText(/signet enroll/)).toBeVisible();
});

// Regression — Bug028 (S110 Wave A-PQR finding, med severity, fix-before-launch).
//
// The wizard's phase used to live only in client memory (`phase = $state('confirm')`,
// never re-derived from the server), so losing the page between the agent's key
// submission and the Touch-ID approve — a closed tab, a navigation, or (observed
// live) a sign-in bounce — restarted the wizard at NAMING. Re-clicking Confirm then
// failed (`UPDATE … WHERE status='pending'`; the row is `keys_submitted`) and no
// surface anywhere listed the in-flight enrollment: unrecoverable by the guardian,
// dead at TTL. The fix (`EnrollmentStore.resume()`) polls the rendezvous on mount and
// derives the phase from the row's actual status. This test fails pre-fix (after the
// bounce it would show the naming form; approve would be unreachable).
test('confirm: a reopened confirm page resumes at the approve step, not naming (Bug028)', async ({
  page,
}) => {
  const { handle, email } = await signUp(page);
  // bug154 §2c: the broker gate stands between + PRSN and the wizard.
  seedBroker(handle);
  await page.getByRole('link', { name: /e2e-/ }).click();
  await expect(page.getByRole('heading', { name: 'Account Settings', exact: true })).toBeVisible({
    timeout: 15_000,
  });

  // §1-62: name first (step 1), mint on Continue — then the code exists.
  const prsn = prsnIdentity();
  await page.getByRole('button', { name: '+ Add PRSN' }).click();
  await expect(page.getByRole('heading', { name: 'Add a PRSN' })).toBeVisible({
    timeout: 15_000,
  });
  await page.getByLabel('PRSN name').fill(prsn.handle);
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page).toHaveURL(/\/account\/add-prsn\/confirm\?code=/, { timeout: 15_000 });
  const code = new URL(page.url()).searchParams.get('code');
  expect(code).toBeTruthy();

  // The agent runs the production enrollment alongside (it blocks awaiting the
  // guardian's approve) — same wiring as attestPrsnViaEnrollment.
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

  // Naming already happened at step 1; wait until the agent's keys arrive (the
  // approve step is live).
  await expect(page.getByRole('button', { name: 'Approve with passkey' })).toBeVisible({
    timeout: 30_000,
  });

  // THE BUG028 MOMENT: lose the page mid-flow (a full load drops the in-memory
  // session → the sign-in prompt → sign back in via returnTo).
  await page.goto(`/account/add-prsn/confirm?code=${code}`);
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
  await expect(page).toHaveURL(/\/account\/add-prsn\/confirm\?code=/, { timeout: 15_000 });

  // THE FIX: the wizard resumes at APPROVE (the row is keys_submitted) — the naming
  // form must NOT reappear. Pre-fix: 'PRSN name' rendered and approve was unreachable.
  await expect(page.getByRole('button', { name: 'Approve with passkey' })).toBeVisible({
    timeout: 15_000,
  });
  await expect(page.getByLabel('PRSN name')).not.toBeVisible();

  // And the resumed flow completes end-to-end: approve → done → the agent exits 0.
  await page.getByRole('button', { name: 'Approve with passkey' }).click();
  await expect(page.getByText(/is set up/)).toBeVisible({ timeout: 15_000 });
  await agentDone;
});
