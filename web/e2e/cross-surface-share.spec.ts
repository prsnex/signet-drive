// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { test, expect } from '@playwright/test';
import {
  attestPrsnViaEnrollment,
  grantLive,
  prsnDownload,
  prsnIdentity,
  prsnSignedFetch,
  signUp,
  seedBroker,
} from './helpers';

// C7 data-plane golden path — the capstone. A human encrypts a file in the
// browser and shares it to a PRSN; the PRSN, entirely on the CLI + signed HTTP,
// downloads the ciphertext + its wrapped DEK and DECRYPTS it; then the Guardian
// revokes, and the PRSN's next request is rejected. This is the load-bearing
// principle fully realized across two surfaces — a human encrypting in a browser
// and a PRSN decrypting on a command line hold the same encrypted data as
// functional equals. It builds on the cross-surface foundation (real CLI keys,
// web attestation, signed HTTP) and the C3b wrap-to-recipient chain; no new crypto.
// Run against the E2E stack (docs/operations/web-e2e.md): the API server on :8080,
// the `signet` binary at target/debug/signet.
test('a human shares an encrypted file to a PRSN that decrypts it on the CLI; revoke then cuts it off', async ({
  page,
}) => {
  test.setTimeout(60_000); // signup + attest + share + a CLI decrypt + revoke
  const content =
    'the capstone: a human encrypts in the browser, a PRSN decrypts on the CLI — S031';

  // The human Guardian signs up — signUp activates the account (a fresh
  // subscribe-to-activate signup is otherwise read-only, and the issue-attestation
  // write below would be blocked).
  const { handle: guardianHandle } = await signUp(page);
  seedBroker(guardianHandle); // bug154 §2c: BEFORE /account mounts

  // The PRSN's keys come from the real `signet` CLI (software-tier keystore) —
  // the same keys it will later sign requests and decrypt with.
  const prsn = prsnIdentity();

  // The Guardian attests the PRSN via the S052 enrollment flow. Its attested KEM
  // key is the one `signet keygen` produced, so the inviter can wrap to it and the
  // CLI can unwrap (the server verifies fingerprint == SHA-256(SPKI) at submit-keys).
  await page.getByRole('link', { name: guardianHandle }).click();
  await expect(page.getByRole('heading', { name: 'Account Settings', exact: true })).toBeVisible({
    timeout: 15_000,
  });
  await attestPrsnViaEnrollment(page, prsn, guardianHandle);
  // bug117/S158: the PRSN's signed Drive requests below need a live Garnet grant
  // (the v0.5.26 backstop refuses grant-less PRSNs on every non-exempt route).
  grantLive(guardianHandle, prsn.handle);

  // Back to the file browser via client-side nav — this keeps the in-memory KEM
  // key alive, which the share-wrap needs (it unwraps the metadata key + DEK to
  // re-wrap them to the recipient). A full page load would drop it.
  await page.getByRole('link', { name: /Back to Signet Drive/ }).click();
  await expect(page.getByRole('heading', { name: 'Share folders' })).toBeVisible({
    timeout: 15_000,
  });

  // Create a share folder and upload a file (encrypted client-side; the file_id
  // is the client-supplied PUT path, so it is also the §4.1 envelope's AAD).
  await page.getByRole('button', { name: 'New share folder' }).click();
  await page.getByLabel('Folder name').fill('Shared');
  await page.getByRole('dialog').getByRole('button', { name: 'Create' }).click();
  await page.locator('aside').getByRole('button', { name: 'Shared', exact: true }).click();
  await expect(page.getByText('Nothing sealed here yet.')).toBeVisible();
  await page.locator('input[type="file"]').setInputFiles({
    name: 'doc.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from(content),
  });
  await expect(page.getByRole('button', { name: 'doc.txt' })).toBeVisible();

  // Invite the PRSN by handle — the browser fetches its attested KEM key and
  // wraps the metadata key + file DEK to it (C3b), then stages them on the
  // invitation. Capture the token from the link.
  await page.getByRole('button', { name: 'Share', exact: true }).click();
  await page.getByLabel('Their username').fill(prsn.handle);
  await page.getByRole('dialog').getByRole('button', { name: 'Generate invitation link' }).click();
  const link = (await page.getByRole('dialog').locator('code').innerText()).trim();
  expect(link).toContain('/accept-share/');
  const token = link.split('/accept-share/').pop()!.trim();

  // Close the share dialog so its overlay doesn't intercept later navigation.
  await page.keyboard.press('Escape');
  await expect(page.getByRole('dialog')).toBeHidden();

  // --- The PRSN takes over: CLI keys + signed HTTP, no browser ---

  // Accept the invitation (signed). The accept is recipient-bound, so the signed
  // caller must resolve to the invited PRSN — proving the same identity the
  // Guardian attested in the browser.
  const acceptRes = await prsnSignedFetch(prsn, 'POST', `/v1/invitations/${token}/accept`);
  expect(acceptRes.status).toBe(200);
  const accept = (await acceptRes.json()) as {
    share_folder_id: string;
    permission: string;
    files_granted: number;
  };
  expect(accept.files_granted).toBe(1);

  // List the shared folder's files (signed) — exercises list_files recipient-access.
  const listRes = await prsnSignedFetch(prsn, 'GET', `/v1/folders/${accept.share_folder_id}/files`);
  expect(listRes.status).toBe(200);
  const list = (await listRes.json()) as { files: { file_id: string }[] };
  expect(list.files).toHaveLength(1);
  const fileId = list.files[0].file_id;

  // Download + decrypt on the CLI — THE CAPSTONE, post-§4.2. `signet file download`
  // does the whole recipient read path itself: fetch the wrapped DEK (the §5
  // envelope addressed to the PRSN's KEM key), unwrap it with that key, request the
  // pre-signed GetObject URL, Range-GET + open each §4.2 chunk (AAD = file_id‖index),
  // and stream the plaintext to disk. The recovered plaintext must equal exactly
  // what the human encrypted in the browser. (The §4.1 raw-bytes GET + `signet
  // decrypt` path was retired with the single-PUT transport in S042.)
  const recovered = prsnDownload(prsn, fileId);
  expect(recovered).toBe(content);

  // The Guardian removes the PRSN via Delete (web), which cascades its attestation
  // away — bug107 retired the standalone attestation-Revoke button, and Delete is now
  // the guardian web action that invalidates a PRSN's identity.
  await page.getByRole('link', { name: guardianHandle }).click();
  await expect(page.getByRole('heading', { name: 'Account Settings', exact: true })).toBeVisible({
    timeout: 15_000,
  });
  await page.getByRole('button', { name: 'Delete', exact: true }).click();
  const delDialog = page.getByRole('dialog');
  await delDialog.getByPlaceholder(prsn.handle).fill(prsn.handle);
  await delDialog.getByRole('button', { name: 'Delete', exact: true }).click();
  await expect(page.getByText('pending deletion')).toBeVisible({ timeout: 15_000 });

  // The PRSN's next signed request fails: the deleted (pending_deletion) account no
  // longer resolves an active identity, so the auth path returns 401. Removal cuts off
  // future access — it does not recall the plaintext already recovered above.
  const afterRevoke = await prsnSignedFetch(prsn, 'GET', '/v1/me');
  expect(afterRevoke.status).toBe(401);
});
