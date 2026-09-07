// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { test, expect, type Page } from '@playwright/test';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { psql, signUp } from './helpers';

// ⚠⚠ THE DOWNLOAD CONTROL — Gus's S177 Q5(1), built at S178.
//
// Run ONLY via `npm run e2e:swdl` (playwright.swdl.config.ts): the BUILT app under
// `vite preview`, three engines, production CSP. Under `vite dev` no service worker
// registers at all, and these tests would silently exercise the capped fallback —
// which is precisely the inversion that let bug195 and bug197 each reach a deploy.
//
// THE STANDARD EVERY ASSERTION HERE MEETS: **sha256 of the artifact against a source
// we generated.** Not "a download event fired", not "the file exists", not "the size
// looks right". At S178, four downloads produced 2401 bytes of our own SPA shell
// under the users' filenames; the size check passed, the download event fired, and
// only opening a PDF revealed it. An assertion weaker than the bytes cannot see this
// bug class, and this file exists because we shipped three fixes verified that way.

/** sha256 of what actually landed on disk. The only end-to-end check that exists. */
function sha256File(path: string): string {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

/**
 * ⛔ THE VALIDITY GATE — the most important function in this file.
 *
 * A download test that runs without the worker controlling the page is not a weaker
 * test; it is a test OF A DIFFERENT CODE PATH that reports green under this file's
 * name. That is the whole bug195/bug197 failure mode, one level up. So we refuse to
 * proceed rather than measure the wrong thing quietly — the same doctrine as the
 * relay suite's refusal to run against a direct-mode server.
 */
async function requireServiceWorkerControl(page: Page): Promise<void> {
  const state = await page.evaluate(async () => {
    if (!('serviceWorker' in navigator)) return { supported: false, controller: false, state: '' };
    const reg = await navigator.serviceWorker.ready.catch(() => null);
    // ⚠ WAIT for control rather than sampling it. `ready` resolves when a worker is
    // ACTIVATED, which is not the same as this page being CONTROLLED — a page loaded
    // before the worker took over stays uncontrolled until `controllerchange` or a
    // reload. Chromium and WebKit happened to be controlled by the time we looked;
    // FIREFOX was not, and on the first real run (S178) the gate correctly REFUSED
    // there. That refusal was right and the sampling was wrong: the engine was
    // slower, not broken. Bounded so a genuine never-controlled state still fails
    // loudly instead of hanging — the failure must stay visible.
    if (!navigator.serviceWorker.controller) {
      await Promise.race([
        new Promise<void>((r) =>
          navigator.serviceWorker.addEventListener('controllerchange', () => r(), { once: true }),
        ),
        new Promise<void>((r) => setTimeout(r, 10_000)),
      ]);
    }
    return {
      supported: true,
      controller: !!navigator.serviceWorker.controller,
      state: reg?.active?.state ?? '',
    };
  });
  expect(
    state.supported,
    'no serviceWorker in navigator — this suite must run against the BUILT app (vite preview), never vite dev',
  ).toBe(true);
  expect(state.state, 'the service worker must be activated before any download assertion').toBe(
    'activated',
  );
  expect(
    state.controller,
    'the page must be CONTROLLED by the worker; an uncontrolled page silently takes the fallback path and would report green about the wrong code',
  ).toBe(true);
}

/** Flip a served knob in the e2e DB. Reads LIVE per request — no server restart. */
function setKnob(key: string, value: string): void {
  psql(`UPDATE system_config SET value = '${value}' WHERE key = '${key}'`);
}

test.beforeEach(async ({ page }) => {
  await page.goto('/');
  // ⚠ Await `ready` as a VOID — returning the registration object from `evaluate`
  // is not serializable, so the original form resolved to nothing useful and the
  // wait was silently a no-op.
  await page.evaluate(async () => {
    await navigator.serviceWorker.ready;
  });
  // A page loaded BEFORE the worker activated is not controlled, and a reload is
  // the documented remedy. Our worker does `skipWaiting()` + `clients.claim()`, so
  // one pass is usually enough — Chromium and WebKit were claimed immediately. On
  // the first real run (S178) FIREFOX was not, and the validity gate correctly
  // refused rather than testing the fallback under this file's name.
  // ⚠ BOUNDED, and deliberately not a sleep: three reload attempts, then let the
  // gate fail loudly. A never-controlled engine must stay a visible failure, not
  // something a longer wait papers over.
  for (let i = 0; i < 3; i++) {
    if (await page.evaluate(() => !!navigator.serviceWorker.controller)) break;
    await page.reload();
    await page.evaluate(async () => {
      await navigator.serviceWorker.ready;
    });
  }
});

/**
 * ⭐ THE PER-ENGINE CONTRACT — runs on chromium, firefox AND webkit.
 *
 * The reserved namespace belongs to the WORKER. If the host ever answers it, an
 * interception failure becomes a silently corrupt file instead of a failed download.
 * At S178 the host answered `200` + `index.html` and that is what landed on disk.
 *
 * Two halves, and both matter:
 *   - the WORKER answers (its own 404 body) ⇒ interception is live on this engine;
 *   - the HOST, if ever reached, answers 404 + text/plain, NEVER html/200.
 */
test('the reserved download namespace is served by the worker, never the SPA shell', async ({
  page,
}) => {
  await requireServiceWorkerControl(page);

  const viaFetch = await page.evaluate(async () => {
    const r = await fetch('/__signet_dl/e2e-unregistered-probe');
    const body = await r.text();
    return { status: r.status, body, ct: r.headers.get('content-type') ?? '' };
  });

  expect(viaFetch.status, 'an unregistered id must 404, never 200').toBe(404);
  expect(
    viaFetch.ct,
    'the reserved namespace must never answer HTML — that is how the SPA shell landed on disk as a .dmg (bug197)',
  ).not.toContain('text/html');
  expect(
    viaFetch.body,
    'the WORKER should answer here; its body is the proof it was the worker and not the host',
  ).toBe('unknown download id');

  // A top-level navigation is the primary interception case and the shape the fixed
  // trigger uses — so it gets its own assertion rather than being inferred.
  const nav = await page.goto('/__signet_dl/e2e-unregistered-nav');
  expect(nav?.status(), 'navigation to the reserved namespace must 404').toBe(404);
  expect(
    await page.content(),
    'a navigation must not render the SPA shell for the reserved namespace',
  ).toContain('unknown download id');
});

/**
 * ⭐⭐ THE BYTE-VERIFIED HALF — chromium-only, and it MUTATES THE SERVED KNOB, so it
 * owns the restore that used to be a file-wide afterEach.
 *
 * ⚠ Scoped deliberately (Gus, S179). The namespace contract above needs NO backend —
 * no auth, no storage, no server — which is what lets it run in CI on three engines.
 * A file-wide `afterEach` calling `setKnob` (a `docker exec` against the dev DB)
 * chained the contract test to the local stack for no reason of its own.
 *
 * ⭐ The restore inside stays UNCONDITIONAL — no CI-awareness, no try/catch, no env
 * flag. It exists because a knob left flipped confounded bug197's live investigation,
 * and conditioning it would recreate exactly that hazard. Scoping moves it; it does
 * not weaken it. Restore now lives beside the mutation, which is better locality than
 * a global hook anyway.
 */
test.describe('byte-verified downloads (chromium-only, mutates the served knob)', () => {
  test.afterEach(() => {
    // Leave the knob in its shipped position whatever a test did (bug197's live
    // investigation was confounded by exactly this being left flipped).
    setKnob('web_sw_download_enabled', '1');
  });

  /**
   * ⭐⭐ THE REGRESSION TEST FOR bug197 — the real product path, end to end.
   *
   * ⚠ chromium-only, and the reason is a hard platform constraint, not laziness: sign-up
   * needs a WebAuthn PRF authenticator, which Playwright can only virtualize through
   * CDP. Firefox and WebKit get the per-engine contract above; the full pipeline runs
   * here. **This bound is stated rather than hidden** — an undocumented single-engine
   * test reads as three-engine coverage, which is the class of mistake this file exists
   * to end.
   *
   * ⛔ THIS TEST MUST FAIL AGAINST THE `a[download]` TRIGGER. Verified at S178 before
   * the fix was written: if it passes against the broken trigger, the test is wrong and
   * gets thrown away, not the bug.
   */
  test('a real download through the shipped path lands bytes identical to source @chromium-only', async ({
    page,
    browserName,
  }) => {
    test.skip(browserName !== 'chromium', 'WebAuthn PRF virtual authenticator is CDP-only');

    await signUp(page);
    await requireServiceWorkerControl(page);

    // A multi-chunk-shaped payload with a hash we know before the round trip. Bytes
    // chosen so a truncation, a substitution, or an HTML page are all distinguishable.
    const source = Buffer.alloc(3 * 1024 * 1024);
    for (let i = 0; i < source.length; i++) source[i] = (i * 31 + 7) & 0xff;
    const sourceSha = createHash('sha256').update(source).digest('hex');

    const sidebar = page.locator('aside');
    await sidebar.getByRole('button', { name: 'New private folder' }).click();
    await page.getByLabel('Folder name').fill('swdl');
    await page.getByRole('dialog').getByRole('button', { name: 'Create' }).click();
    await sidebar.getByRole('button', { name: 'swdl', exact: true }).click();

    await page.locator('input[type="file"]').setInputFiles({
      name: 'swdl-probe.bin',
      mimeType: 'application/octet-stream',
      buffer: source,
    });
    await expect(page.getByRole('button', { name: 'swdl-probe.bin' })).toBeVisible();

    // ⛔ THE ZERO-RETRIES INSTRUMENT (bug198, Gus S178) — armed AFTER the upload so
    // only the download's storage traffic is counted.
    //
    // ⚠⚠ WHY IT EXISTS, and it indicts the test above it: this suite was GREEN over
    // bug198 for an entire release. Playwright's `retries: 0` is SUITE-level;
    // `transferWithRetry`'s own budget silently absorbed a failed fetch at the head
    // of EVERY download, inside a passing test. The control built to catch
    // composition defects was blind to a deterministic tax beside the defect it did
    // catch. A correct N-chunk download issues EXACTLY N storage requests; any extra
    // is a retry, and a retry on a SUCCEEDING download means a failure was papered
    // over — the only signature this class produces, since the bytes come out right.
    //
    // ⚠⚠⚠ WHAT THIS ASSERTION DOES **NOT** PROVE, STATED SO NOBODY INFERS IT LATER:
    // it is **NOT must-fail-proven against bug198**. Measured at S178: with the
    // navigation fence REMOVED, this suite still passes 5/5 and observes ZERO
    // storage failures. **The race does not reproduce on localhost** — the worker
    // answers `/__signet_dl/<id>` with no network in the path, so the navigation
    // resolves before the chunk loop issues its first fetch and the cancellation
    // window never opens. On staging (real latency) it opens every time.
    //
    // ⇒ This guards the CLASS (any future silent retry-absorption on a happy path)
    // and it is cheap, so it stays. But **bug198's fix is verified on STAGING, not
    // here**, and treating a green run of this file as evidence about bug198 would
    // be the exact false comfort the file's own header warns about.
    //
    // ⭐ The structural lesson, which is bigger than this bug: a control that needs
    // production-like LATENCY to reproduce its defect cannot be built on localhost.
    // That is an argument for the §4.1 real-browser smoke arm owed to the v06 batch,
    // not for a cleverer assertion here.
    const storageRequests: string[] = [];
    const storageFailures: string[] = [];
    page.on('request', (r) => {
      if (/s3\.|bhs|storage|minio|:9000/.test(r.url())) storageRequests.push(r.url());
    });
    page.on('requestfailed', (r) => {
      if (/s3\.|bhs|storage|minio|:9000/.test(r.url()))
        storageFailures.push(`${r.failure()?.errorText ?? 'unknown'} ${r.url().slice(0, 60)}`);
    });

    const downloadPromise = page.waitForEvent('download', { timeout: 120_000 });
    await page.getByRole('checkbox', { name: 'Select file swdl-probe.bin' }).check();
    await page.getByRole('button', { name: 'Download' }).click();
    const download = await downloadPromise;
    const landed = await download.path();

    expect(landed, 'the download must produce a file on disk').toBeTruthy();
    expect(
      sha256File(landed!),
      'the downloaded bytes must equal the source EXACTLY. A mismatch here is bug197: the SPA shell, a truncation, or a wrong-path download — all of which pass a size check',
    ).toBe(sourceSha);

    // ⛔ bug198: the happy path must cost EXACTLY ONE storage request per chunk.
    // 3 MiB under a 16 MiB chunk size ⇒ one chunk ⇒ one request. A second request
    // for the same bytes is a retry, and on a download that SUCCEEDED a retry means
    // a failure was absorbed rather than surfaced.
    expect(
      storageFailures,
      'no storage fetch may FAIL on the happy path. A failure here that the test otherwise survives is bug198: the trigger navigation cancelling in-flight chunk fetches, paid for out of the retry budget',
    ).toEqual([]);
    expect(
      storageRequests.length,
      `a 1-chunk download must issue exactly ONE storage request; ${storageRequests.length} means ${storageRequests.length - 1} retry attempt(s) were absorbed silently`,
    ).toBe(1);
  });

  /**
   * Gus's fallback arm (S178): the capped path is the product's RETRACTION path, so it
   * needs the same standard as the primary. Until S178 it had never once been executed
   * — and our own rule is that a kill-switch nobody has pulled is not a kill-switch.
   * Flipping it in production must never again enter territory no test has seen.
   */
  test('the capped fallback also lands bytes identical to source @chromium-only', async ({
    page,
    browserName,
  }) => {
    test.skip(browserName !== 'chromium', 'WebAuthn PRF virtual authenticator is CDP-only');

    setKnob('web_sw_download_enabled', '0');
    await signUp(page);

    const source = Buffer.alloc(512 * 1024);
    for (let i = 0; i < source.length; i++) source[i] = (i * 17 + 3) & 0xff;
    const sourceSha = createHash('sha256').update(source).digest('hex');

    const sidebar = page.locator('aside');
    await sidebar.getByRole('button', { name: 'New private folder' }).click();
    await page.getByLabel('Folder name').fill('swdl-fallback');
    await page.getByRole('dialog').getByRole('button', { name: 'Create' }).click();
    await sidebar.getByRole('button', { name: 'swdl-fallback', exact: true }).click();

    await page.locator('input[type="file"]').setInputFiles({
      name: 'fallback-probe.bin',
      mimeType: 'application/octet-stream',
      buffer: source,
    });
    await expect(page.getByRole('button', { name: 'fallback-probe.bin' })).toBeVisible();

    const downloadPromise = page.waitForEvent('download', { timeout: 120_000 });
    await page.getByRole('checkbox', { name: 'Select file fallback-probe.bin' }).check();
    await page.getByRole('button', { name: 'Download' }).click();
    const download = await downloadPromise;
    const landed = await download.path();

    expect(landed).toBeTruthy();
    expect(
      sha256File(landed!),
      'the capped fallback must deliver the source bytes; it is the path a production kill-switch retracts to',
    ).toBe(sourceSha);
  });
});
