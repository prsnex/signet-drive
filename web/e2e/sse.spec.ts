// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { test, expect } from '@playwright/test';
import { signUp } from './helpers';

// SSE live update: a change the UI did not make appears via the change stream.
// We sign in, create + open a folder, and upload a file — then DELETE that file
// directly through the API (a crypto-free request that bypasses the UI store),
// standing in for a change from another session/device. The view must drop the
// file from the change-stream refresh alone, with no action in the UI.
test('an out-of-band change refreshes the view via the SSE stream', async ({ page }) => {
  await signUp(page);

  await page.getByRole('button', { name: 'New private folder' }).click();
  await page.getByLabel('Folder name').fill('Live');
  await page.getByRole('dialog').getByRole('button', { name: 'Create' }).click();
  await page.locator('aside').getByRole('button', { name: 'Live', exact: true }).click();
  await expect(page.getByText('Nothing sealed here yet.')).toBeVisible();

  await page.locator('input[type="file"]').setInputFiles({
    name: 'live.txt',
    mimeType: 'text/plain',
    buffer: Buffer.from('live update'),
  });
  await expect(page.getByRole('button', { name: 'live.txt' })).toBeVisible();

  // Delete the file out-of-band: list (auth-only) for its id, then DELETE
  // (auth-only, no crypto) — bypassing the UI store. The server then publishes a
  // change event that the page's own EventSource receives.
  const status = await page.evaluate(async () => {
    const foldersRes = (await (await fetch('/v1/folders', { credentials: 'include' })).json()) as {
      folders: { folder_id: string }[];
    };
    const folderId = foldersRes.folders[0].folder_id;
    const filesRes = (await (
      await fetch(`/v1/folders/${folderId}/files`, { credentials: 'include' })
    ).json()) as { files: { file_id: string }[] };
    const fileId = filesRes.files[0].file_id;
    const res = await fetch(`/v1/files/${fileId}`, { method: 'DELETE', credentials: 'include' });
    return res.status;
  });
  expect(status).toBe(204);

  // The UI never initiated the delete — only the change stream did. The file
  // disappears once the SSE-triggered refresh lands.
  await expect(page.getByRole('button', { name: 'live.txt' })).toHaveCount(0, { timeout: 10_000 });
  await expect(page.getByText('Nothing sealed here yet.')).toBeVisible();
});
