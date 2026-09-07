// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { signInAgain, signUp } from './helpers';

// The load-bearing principle, end to end across two accounts: an owner creates a
// share folder, uploads a file, and invites a second account; the recipient
// accepts via the invitation link, then sees the folder and reads the file —
// proving a folder encrypted by one person is decrypted by another. Two distinct
// accounts (distinct passkeys), so there's no credential-sharing limitation.
test('two accounts: owner shares a folder, recipient accepts and reads the file', async ({
  browser,
}) => {
  // Recipient signs up first, so the owner can invite their handle.
  const ctxB = await browser.newContext();
  const recipient = await ctxB.newPage();
  const { handle: recipientHandle, email: recipientEmail } = await signUp(recipient);

  // Owner signs up, creates a share folder, and uploads a file. (Clipboard
  // permissions for the Bug005(a) copy-link assertion below.)
  const ctxA = await browser.newContext();
  await ctxA.grantPermissions(['clipboard-read', 'clipboard-write']);
  const owner = await ctxA.newPage();
  await signUp(owner);

  await owner.getByRole('button', { name: 'New share folder' }).click();
  await owner.getByLabel('Folder name').fill('Shared');
  await owner.getByRole('dialog').getByRole('button', { name: 'Create' }).click();
  await owner.locator('aside').getByRole('button', { name: 'Shared', exact: true }).click();
  await expect(owner.getByText('Nothing sealed here yet.')).toBeVisible();

  const content = 'shared content';
  await owner.locator('input[type="file"]').setInputFiles({
    name: 'doc.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from(content),
  });
  await expect(owner.getByRole('button', { name: 'doc.txt' })).toBeVisible();

  // Owner invites the recipient and copies the invitation link.
  await owner.getByRole('button', { name: 'Share', exact: true }).click();
  await owner.getByLabel('Their username').fill(recipientHandle);
  await owner.getByRole('dialog').getByRole('button', { name: 'Generate invitation link' }).click();
  const link = (await owner.getByRole('dialog').locator('code').innerText()).trim();
  expect(link).toContain('/accept-share/');

  // Bug005(a): the link is one-tap copyable — the button flips to "Copied" only
  // after a successful clipboard write, and the clipboard holds the link.
  await owner.getByRole('dialog').getByRole('button', { name: 'Copy link' }).click();
  await expect(owner.getByRole('dialog').getByRole('button', { name: 'Copied' })).toBeVisible();
  const clipboard = await owner.evaluate(() => navigator.clipboard.readText());
  expect(clipboard).toBe(link);

  // Bug005(b): re-inviting while the invitation is still pending answers with the
  // honest share-context message — NOT the misleading name-collision copy the
  // generic 409 mapping produced (the S068 finding).
  await owner.getByLabel('Their username').fill(recipientHandle);
  await owner.getByRole('dialog').getByRole('button', { name: 'Generate invitation link' }).click();
  await expect(owner.getByText(/already has a pending invitation for this folder/)).toBeVisible();
  await expect(owner.getByText('That name is already in use here')).not.toBeVisible();

  // Recipient opens the link and accepts (cookie-authed; no key needed yet).
  await recipient.goto(link);
  await recipient.getByRole('button', { name: 'Accept' }).click();
  await expect(recipient.getByText('You now have access')).toBeVisible({ timeout: 15_000 });

  // The link was opened fresh, so the in-memory key is gone — sign in again to
  // browse (this recovers the same KEM key the owner wrapped the share to).
  await signInAgain(recipient, recipientEmail);
  await expect(recipient.getByRole('heading', { name: 'Share folders' })).toBeVisible({
    timeout: 15_000,
  });

  // The shared folder appears with its decrypted name (the metadata-key wrap),
  // and its file's name decrypts too.
  await recipient.locator('aside').getByRole('button', { name: 'Shared', exact: true }).click();
  await expect(recipient.getByRole('button', { name: 'doc.txt' })).toBeVisible({ timeout: 10_000 });

  // The recipient downloads it — the DEK wrap lets them decrypt the content.
  const downloadPromise = recipient.waitForEvent('download');
  await recipient.getByRole('checkbox', { name: 'Select file doc.txt' }).check();
  await recipient.getByRole('button', { name: 'Download' }).click();
  const download = await downloadPromise;
  expect(readFileSync(await download.path(), 'utf8')).toBe(content);

  await ctxA.close();
  await ctxB.close();
});

// S049 regression: a file added to a share folder AFTER a recipient has joined must
// be readable by them. Pre-fix, upload wrapped the DEK only to the owner, so anything
// added post-invite (and every file a PRSN's mandatory Guardian should see) was
// unreadable to the recipient. The fix wraps each upload to all current recipients.
test('a file added to a share folder after a recipient joined is readable by them', async ({
  browser,
}) => {
  const ctxB = await browser.newContext();
  const recipient = await ctxB.newPage();
  const { handle: recipientHandle, email: recipientEmail } = await signUp(recipient);

  const ctxA = await browser.newContext();
  const owner = await ctxA.newPage();
  await signUp(owner);

  // Owner creates a share folder and invites the recipient to the still-empty folder.
  await owner.getByRole('button', { name: 'New share folder' }).click();
  await owner.getByLabel('Folder name').fill('Shared');
  await owner.getByRole('dialog').getByRole('button', { name: 'Create' }).click();
  await owner.locator('aside').getByRole('button', { name: 'Shared', exact: true }).click();
  await owner.getByRole('button', { name: 'Share', exact: true }).click();
  await owner.getByLabel('Their username').fill(recipientHandle);
  await owner.getByRole('dialog').getByRole('button', { name: 'Generate invitation link' }).click();
  const link = (await owner.getByRole('dialog').locator('code').innerText()).trim();
  // Close the share dialog so its overlay doesn't block the upload input.
  await owner.keyboard.press('Escape');
  await expect(owner.getByRole('dialog')).toBeHidden();

  // Recipient accepts — this releases the owner's write-lock on the folder.
  await recipient.goto(link);
  await recipient.getByRole('button', { name: 'Accept' }).click();
  await expect(recipient.getByText('You now have access')).toBeVisible({ timeout: 15_000 });

  // NOW the owner uploads a file — after the recipient joined. The upload must wrap
  // the DEK to the recipient (not just self) for them to read it.
  const content = 'added after the recipient joined';
  await owner.locator('input[type="file"]').setInputFiles({
    name: 'after.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from(content),
  });
  await expect(owner.getByRole('button', { name: 'after.txt' })).toBeVisible();

  // Recipient signs in (recovering their KEM key) and reads the newly-added file.
  await signInAgain(recipient, recipientEmail);
  await expect(recipient.getByRole('heading', { name: 'Share folders' })).toBeVisible({
    timeout: 15_000,
  });
  await recipient.locator('aside').getByRole('button', { name: 'Shared', exact: true }).click();
  await expect(recipient.getByRole('button', { name: 'after.txt' })).toBeVisible({
    timeout: 10_000,
  });

  const downloadPromise = recipient.waitForEvent('download');
  await recipient.getByRole('checkbox', { name: 'Select file after.txt' }).check();
  await recipient.getByRole('button', { name: 'Download' }).click();
  const download = await downloadPromise;
  expect(readFileSync(await download.path(), 'utf8')).toBe(content);

  await ctxA.close();
  await ctxB.close();
});

// S121 (W6/W7): a pending invitation is visible to the owner — with a cancel that
// releases the write-lock — and the generated link names its recipient. Pre-fix,
// a pending invite was invisible ("No one yet.") while it silently write-locked
// the folder for up to its full TTL, and the stale link block never named who a
// link was for.
test('the owner sees a pending invitation, and canceling it unlocks the folder', async ({
  browser,
}) => {
  const ctxB = await browser.newContext();
  const recipient = await ctxB.newPage();
  const { handle: recipientHandle } = await signUp(recipient);

  const ctxA = await browser.newContext();
  const owner = await ctxA.newPage();
  await signUp(owner);

  await owner.getByRole('button', { name: 'New share folder' }).click();
  await owner.getByLabel('Folder name').fill('Shared');
  await owner.getByRole('dialog').getByRole('button', { name: 'Create' }).click();
  await owner.locator('aside').getByRole('button', { name: 'Shared', exact: true }).click();
  await expect(owner.getByText('Nothing sealed here yet.')).toBeVisible();

  // Invite → the link block names its recipient (W7) and the pending list shows
  // them with an expiry + a Cancel (W6).
  await owner.getByRole('button', { name: 'Share', exact: true }).click();
  await owner.getByLabel('Their username').fill(recipientHandle);
  await owner.getByRole('dialog').getByRole('button', { name: 'Generate invitation link' }).click();
  const link = (await owner.getByRole('dialog').locator('code').innerText()).trim();
  await expect(owner.getByText(`For ${recipientHandle}`)).toBeVisible();
  await expect(owner.getByRole('heading', { name: 'Pending invitations' })).toBeVisible();
  await expect(owner.getByRole('dialog').getByText(/expires/)).toBeVisible();
  await owner.keyboard.press('Escape');
  await expect(owner.getByRole('dialog')).toBeHidden();

  // The pending invitation write-locks the folder — and the error copy now says
  // so honestly, naming the resolution paths (was: "finishing a share …
  // try again in a moment", while the lock could hold for the invite's full TTL).
  await owner.locator('input[type="file"]').setInputFiles({
    name: 'blocked.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('blocked while pending'),
  });
  await expect(owner.getByText(/pending share invitation/)).toBeVisible({ timeout: 15_000 });

  // Cancel the invitation: the pending section empties…
  await owner.getByRole('button', { name: 'Share', exact: true }).click();
  await owner.getByRole('dialog').getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(owner.getByRole('heading', { name: 'Pending invitations' })).toBeHidden();
  await owner.keyboard.press('Escape');
  await expect(owner.getByRole('dialog')).toBeHidden();

  // …the folder's writes resume (the lock released by construction)…
  await owner.locator('input[type="file"]').setInputFiles({
    name: 'unblocked.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('after cancel'),
  });
  await expect(owner.getByRole('button', { name: 'unblocked.txt' })).toBeVisible({
    timeout: 30_000,
  });

  // …and the canceled link is dead for the recipient, with invitation-specific
  // copy (not the generic drive mapping's "refreshing your view").
  await recipient.goto(link);
  await expect(recipient.getByText(/This invitation is no longer available/)).toBeVisible({
    timeout: 15_000,
  });

  await ctxA.close();
  await ctxB.close();
});
