// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { test, expect, type Page } from '@playwright/test';
import { signUp, psql } from './helpers';

// bug241 — the web Drive shows at most 50 files and 50 subfolders per folder.
//
// `api.ts` accepts a cursor on `listFiles`/`listFolders`; NO call site in
// `browser.svelte.ts` passes one, and the store has no cursor handling at all.
// The server pages at 50 (`files.rs`/`folders.rs` DEFAULT_PAGE), returns
// `next_cursor`, and the client drops it on the floor. The 51st item is invisible
// — no message, no truncation notice, no load-more.
//
// ⛔ THIS SPEC IS THE NEGATIVE CONTROL FOR THE FIX. It must FAIL before the fix
// and PASS after. Run it against unfixed code first and bank the number; an arm
// that has never been shown able to fail proves nothing (ROOTS §B-5.22).
//
// ⚠ THE INSTRUMENT, banked so the after-run is like-for-like and not merely
// similar (Gus's §0 condition 1):
//   • Two SEPARATE fixture folders, one per arm. Folder rows and file rows are
//     both bare <tr> in the same <tbody> with no distinguishing class, so a mixed
//     folder would make `tbody tr` ambiguous. Isolating each arm makes the count
//     unambiguous by construction.
//   • Count selector: `table tbody tr` inside the main pane.
//   • Files arm: 51 REAL uploads through the client's own crypto, in one
//     `setInputFiles` call.
//   • Folders arm: 51 rows cloned in SQL from a UI-created folder, reusing its
//     `encrypted_name`. Cloning is a speed choice, not a shortcut around the
//     defect: the client's listing path is identical either way, and the defect
//     is in pagination, not in how a row was born.
//     ⛔ CORRECTED 2026-09-03 (S208). This used to claim the clones "decrypt
//     normally under the same account key and render as ordinary rows". THAT IS
//     FALSE, and was false the day it was written. `encname.ts:41` seals a name
//     with `nameAad(rootFolderId, targetId)` as AES-GCM ADDITIONAL AUTHENTICATED
//     DATA, and the INSERT below necessarily assigns a fresh `gen_random_uuid()`
//     folder_id — so `targetId` no longer matches the AAD, GCM authentication
//     fails, and every clone renders `(unreadable)` (`browser.svelte.ts:1651`).
//     Confirmed live on staging at v0.5.60.
//     ⭐ THE ARM IS UNAFFECTED, which is why this is worth stating rather than
//     just deleting: the test counts `table tbody tr`, never names. A reader who
//     trusts the old sentence and then meets `(unreadable)` will suspect the
//     FIXTURE or the DEFECT — both wrong, and the wrong suspicion costs a
//     session. The ROWS are the subject.

const FILE_COUNT = 51;
const FOLDER_COUNT = 51;
const PAGE_SIZE = 50; // files.rs / folders.rs DEFAULT_PAGE — the truncation point

async function newFolder(page: Page, name: string): Promise<void> {
  const sidebar = page.locator('aside');
  await sidebar.getByRole('button', { name: 'New private folder' }).click();
  await page.getByLabel('Folder name').fill(name);
  await page.getByRole('dialog').getByRole('button', { name: 'Create' }).click();
  await expect(sidebar.getByRole('button', { name, exact: true })).toBeVisible();
}

async function openFolder(page: Page, name: string): Promise<void> {
  await page.locator('aside').getByRole('button', { name, exact: true }).click();
}

// ⚠ EVERY query below is scoped to THIS run's account. `signet_drive_e2e` is
// shared across specs and across repeated local runs, so a bare
// `ORDER BY created_at DESC LIMIT 1` would happily return another test's folder
// — the arm would then measure the wrong subject and still look green.
function accountId(email: string): string {
  return psql(`SELECT account_id FROM accounts WHERE email = '${email}'`);
}

/** The account's non-root folder with the most children/files — its fixture. */
function folderNamed(account: string, hasParent: boolean): string {
  return psql(
    `SELECT folder_id FROM folders
     WHERE account_id = '${account}' AND parent_folder_id IS ${hasParent ? 'NOT NULL' : 'NULL'}
     ORDER BY created_at DESC LIMIT 1`,
  );
}

test('bug241 — a folder with more than one page of files shows every file', async ({ page }) => {
  const { email } = await signUp(page);
  const account = accountId(email);
  expect(account).not.toBe('');
  await newFolder(page, 'Fixture Files');
  await openFolder(page, 'Fixture Files');

  // 51 real uploads in one call — same client, same crypto a user gets.
  await page.locator('input[type="file"]').setInputFiles(
    Array.from({ length: FILE_COUNT }, (_, i) => ({
      name: `file-${String(i).padStart(3, '0')}.txt`,
      mimeType: 'text/plain',
      buffer: Buffer.from(`fixture ${i}\n`),
    })),
  );

  // Every upload landed server-side — so a short render is the CLIENT's doing and
  // not a fixture that failed to build. This assertion is what stops the test
  // from "passing" on a folder that only ever had 50 files in it.
  await expect
    .poll(
      () =>
        Number(
          psql(
            `SELECT COUNT(*) FROM files
             WHERE folder_id = '${folderNamed(account, false)}'`,
          ),
        ),
      { timeout: 120_000, message: 'all 51 files should reach the server' },
    )
    .toBe(FILE_COUNT);

  await page.reload();
  await openFolder(page, 'Fixture Files');

  const rows = page.locator('table tbody tr');
  await expect.poll(() => rows.count(), { timeout: 30_000 }).toBeGreaterThan(0);

  // ⛔ THE CLAIM. Before the fix this reads 50 and the 51st file is unreachable.
  await expect(rows).toHaveCount(FILE_COUNT);
});

test('bug241 — a folder with more than one page of subfolders shows every subfolder', async ({
  page,
}) => {
  const { email } = await signUp(page);
  const account = accountId(email);
  expect(account).not.toBe('');
  await newFolder(page, 'Fixture Folders');
  await openFolder(page, 'Fixture Folders');

  // One real child through the UI, then clone its row. The clones share the
  // parent's account + root and reuse the child's `encrypted_name`.
  // ⚠ They render `(unreadable)`, NOT as ordinary folder rows — the fresh
  // `gen_random_uuid()` below breaks the name's AAD binding to `targetId`
  // (corrected note in the header). Expected; this assertion counts ROWS.
  await page.getByRole('button', { name: 'New folder', exact: true }).click();
  await page.getByLabel('Folder name').fill('child-000');
  await page.getByRole('dialog').getByRole('button', { name: 'Create' }).click();
  await expect(page.locator('table tbody tr')).toHaveCount(1);

  const child = folderNamed(account, true);
  expect(child).not.toBe('');

  psql(
    `INSERT INTO folders (folder_id, account_id, parent_folder_id, root_folder_id,
                          folder_type, encrypted_name)
     SELECT gen_random_uuid(), account_id, parent_folder_id, root_folder_id,
            folder_type, encrypted_name
     FROM folders, generate_series(1, ${FOLDER_COUNT - 1})
     WHERE folder_id = '${child}'`,
  );

  const siblings = Number(
    psql(
      `SELECT COUNT(*) FROM folders WHERE parent_folder_id =
         (SELECT parent_folder_id FROM folders WHERE folder_id = '${child}')`,
    ),
  );
  expect(siblings).toBe(FOLDER_COUNT); // the fixture is real before we judge the client

  await page.reload();
  await openFolder(page, 'Fixture Folders');

  const rows = page.locator('table tbody tr');
  await expect.poll(() => rows.count(), { timeout: 30_000 }).toBeGreaterThan(0);

  // ⛔ THE CLAIM. Before the fix this reads 50.
  await expect(rows).toHaveCount(FOLDER_COUNT);
});

// A guard on the guard: if the server's page size ever changes, these specs stop
// testing what they claim to test — 51 items would fit in one page and both would
// pass without the fix. Fail loudly instead of silently going vacuous.
test('bug241 — the fixture still straddles a page boundary', async () => {
  expect(FILE_COUNT).toBeGreaterThan(PAGE_SIZE);
  expect(FOLDER_COUNT).toBeGreaterThan(PAGE_SIZE);
});
