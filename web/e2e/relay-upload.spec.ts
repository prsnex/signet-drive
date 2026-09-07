// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { readFileSync } from 'node:fs';

import { test, expect } from '@playwright/test';
import { signUp } from './helpers';

// The web-upload relay (Fix-Proposal v04 §4.2, M1): with the server started in
// relay mode (`SIGNET_UPLOAD_PATH=relay`), a multi-part browser upload
// completes with ZERO requests reaching the storage origin — asserted at the
// TRAFFIC level, not by inspecting the URLs the server issued ("the relay ran"
// and "nothing bypassed the relay" are different claims; only the second
// catches a partial fallback).
//
// Run via `npm run e2e:relay` (its own Playwright config): the operator starts
// the API server with SIGNET_UPLOAD_PATH=relay first — see
// docs/operations/web-e2e.md §relay.
//
// ⚠ What a green run here CANNOT prove (the bug173 e2e-trap lesson): MinIO is
// local, so no address family exists to get wrong. This proves the relay
// carries the bytes and nothing leaks around it — the Calgary dual-stack ≥1 GB
// partnered proof validates the property the relay exists FOR.

/** The storage origin the direct path would hit (matches the suite's CSP env). */
const STORAGE_ORIGIN_PORT = '9000';

test('a multi-part upload completes through the relay with ZERO storage-origin requests', async ({
  page,
}) => {
  // ── Trap-proofing FIRST (the spec's own negative control): if the server is
  // in direct mode, initiate hands out absolute presigned URLs and this spec
  // would "pass" while testing nothing. Refuse to run instead. ──
  let sawRelayPartUrl = false;
  let sawPresignedPartUrl = false;
  // S171: the PLANNED part count, read from issuance rather than assumed. See
  // the fixture note below — the previous hardcoded expectation was
  // unsatisfiable.
  let plannedParts = 0;
  page.on('response', async (response) => {
    if (!response.url().includes('/multipart')) return;
    try {
      const body = await response.json();
      const urls: { url: string }[] = body?.part_urls ?? [];
      plannedParts += urls.length;
      for (const u of urls) {
        if (u.url.startsWith('/v1/uploads/')) sawRelayPartUrl = true;
        else if (u.url.includes('://')) sawPresignedPartUrl = true;
      }
    } catch {
      /* non-JSON multipart responses are not issuance */
    }
  });

  // ── The M1 assertion source: every request the BROWSER makes, by origin. ──
  const storageOriginRequests: string[] = [];
  let relayPartPuts = 0;
  page.on('request', (request) => {
    const url = new URL(request.url());
    if (url.port === STORAGE_ORIGIN_PORT) storageOriginRequests.push(request.url());
    if (request.method() === 'PUT' && /\/v1\/uploads\/.+\/parts\/\d+$/.test(url.pathname)) {
      relayPartPuts += 1;
    }
  });

  await signUp(page);

  const sidebar = page.locator('aside');
  await sidebar.getByRole('button', { name: 'New private folder' }).click();
  await page.getByLabel('Folder name').fill('RelayProof');
  await page.getByRole('dialog').getByRole('button', { name: 'Create' }).click();
  await sidebar.getByRole('button', { name: 'RelayProof', exact: true }).click();
  await expect(page.getByText('Nothing sealed here yet.')).toBeVisible();

  // ⚠ S171 — THE FIXTURE MUST EXCEED THE **DEFAULT** PART SIZE, NOT THE FLOOR.
  // This was 12 MiB with the comment "multiple parts at the web's 5 MiB plan
  // floor". That is wrong and the spec could never pass, on ANY link:
  //   DEFAULT_CHUNK_SIZE = 16 MiB (drive.ts:73); at plan time rateEst === null,
  //   so partSize() takes base = defaultSize = 16 MiB, clamps to
  //   [partMinBytes 5 MiB, partMaxBytes 64 MiB] => 16 MiB, and
  //   chunkCount = ceil(12 MiB / 16 MiB) = 1.
  // 5 MiB is the FLOOR (a dire-link minimum), never the default. Found on this
  // spec's first-ever execution — it shipped written-but-unrun at S170.
  // 36 MiB => ceil(36/16) = 3 parts, and uploadPlan() is computed ONCE up front
  // (drive.ts:459) so the count does not drift as the rate estimate lands.
  const thirtySixMiB = Buffer.alloc(36 * 1024 * 1024, 0x5a);
  await page.locator('input[type="file"]').setInputFiles({
    name: 'relay-proof.bin',
    mimeType: 'application/octet-stream',
    buffer: thirtySixMiB,
  });

  // The upload lands (generous timeout: 12 MiB through dev-mode vite + relay).
  await expect(page.getByRole('button', { name: 'relay-proof.bin' })).toBeVisible({
    timeout: 120_000,
  });

  // ── The spec's own validity gate ──
  expect(
    sawRelayPartUrl,
    'initiate never issued a relay URL — the server is NOT in relay mode; start it with SIGNET_UPLOAD_PATH=relay',
  ).toBe(true);
  expect(
    sawPresignedPartUrl,
    'initiate issued PRESIGNED part URLs in relay mode — the issuance switch is broken',
  ).toBe(false);

  // ── M1, the property this spec exists for ──
  expect(
    storageOriginRequests,
    `the browser reached the storage origin directly in relay mode: ${storageOriginRequests
      .slice(0, 3)
      .join(', ')}`,
  ).toEqual([]);
  // ⚠ S171 — assert what the message SAYS: one relay part-PUT per **planned**
  // part, with the plan READ FROM ISSUANCE rather than hardcoded. The previous
  // `toBeGreaterThanOrEqual(3)` encoded a part-size policy the client does not
  // have, so it could only ever fail (the mirror of bug145/S164's gate that
  // could only pass). Derived, this stays correct under any future part-size
  // policy — and it is a STRICTER check than the old one, being an equality.
  expect(
    plannedParts,
    'issuance planned no parts — the multipart hook saw nothing',
  ).toBeGreaterThan(0);
  expect(
    plannedParts,
    `the fixture produced ${plannedParts} part(s) — it must exceed DEFAULT_CHUNK_SIZE (16 MiB) or this spec is not exercising MULTI-part relay carriage`,
  ).toBeGreaterThan(1);
  expect(relayPartPuts, 'expected one relay part-PUT per planned part').toBe(plannedParts);

  // Round-trip honesty: the sealed bytes come back byte-identical THROUGH the
  // download path (which stays direct even in relay mode — v04 §2). The
  // download hitting the storage origin is EXPECTED and correct; M1 above was
  // asserted before any download traffic existed.
  const downloadPromise = page.waitForEvent('download');
  await page.getByRole('checkbox', { name: 'Select file relay-proof.bin' }).check();
  await page.getByRole('button', { name: 'Download' }).click();
  const download = await downloadPromise;
  const downloadedPath = await download.path();
  const bytes = readFileSync(downloadedPath);
  expect(bytes.length).toBe(thirtySixMiB.length);
  expect(bytes.equals(thirtySixMiB), 'downloaded bytes differ from the uploaded ones').toBe(true);
});
