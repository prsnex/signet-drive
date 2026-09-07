// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { defineConfig, devices } from '@playwright/test';

// ⚠⚠ THE SERVICE-WORKER DOWNLOAD E2E — Gus's S177 Q5 item (1), built at S178 after
// the control it describes was identified, not built, and then needed.
//
// WHY THIS IS A SEPARATE CONFIG, and why it is the only honest way to test this:
//
//   **No service worker registers under `vite dev`.** The default suite's webServer
//   is `npm run dev`, so every download e2e this repo owned was exercising the
//   CAPPED FALLBACK while the SHIPPED path — the SW-streamed download — had zero
//   automated coverage. The suite was green about the path we had REPLACED. That
//   inversion is invisible by construction: nothing in a passing run says which of
//   two code paths produced it.
//
//   It cost two launch blockers on two consecutive deploys:
//     - bug195 (S177): our own `frame-src` refused the SW download iframe.
//     - bug197 (S178): the `a[download]` trigger is never intercepted by the worker,
//       so the request reached the host, the SPA fallback answered 200 + index.html,
//       and FOUR downloads landed as 2401 bytes of our own web page carrying the
//       user's filenames (.dmg, .tif, .pdf — all byte-identical). On a custody
//       product. Every size check passed. Only opening a PDF revealed it.
//
// So this config changes the three things that made the old suite blind:
//   1. **The BUILT app** (`build && preview`) — the worker registers and the
//      production CSP from svelte.config.js applies.
//   2. **Engines — PER TEST, and the bound belongs HERE, not only in skip-lines
//      below (S179).** This header previously read "Three engines", which is true
//      of ONE of the three tests. A reader trusts the header first; mine did, for a
//      full session, before checking the tests. §B-5.8 — every control declares what
//      it cannot see — applies to the claim's most-read location.
//
//        · the reserved-namespace contract → **chromium + firefox + webkit**. No
//          auth, no storage, no server: it loads the built app and asserts the
//          worker owns `/__signet_dl/*`. This is the arm that runs in CI, as
//          `swdl-namespace-contract`.
//        · both sha-of-artifact tests → **CHROMIUM ONLY**, and it is a platform
//          bound rather than laziness: sign-up needs a WebAuthn PRF authenticator,
//          which Playwright can only virtualize over CDP. These need the full local
//          stack and run BY HAND per release. **They are not in CI.**
//
//      ⇒ dispatch behaviour is per-engine and bug197 was found on Safari, so the
//      contract covers all three; the byte path is verified on one engine plus the
//      §4.1 manual smoke.
//   3. **sha-of-artifact assertions** — never "the download completed", which is
//      precisely the assertion that would have passed while all four files were the
//      wrong bytes.
//
// ⚠ Prerequisites are the same stack as the default suite (docs/operations/web-e2e.md):
// `docker compose up -d`, a Mailpit sink, and the API server on :8080 built with
// `--features signet-server/dev-auth`. `vite preview` proxies /v1 there (the
// `preview.proxy` block added to vite.config.ts at S178 — `server.proxy` alone does
// not apply to preview, which is a further reason nothing ever ran here).
//
// Run: `npm run e2e:swdl`
export default defineConfig({
  testDir: 'e2e',
  testMatch: ['**/sw-download.spec.ts'],
  globalSetup: './e2e/global-setup.ts',
  fullyParallel: false,
  // ⚠⚠ ONE WORKER, and this is a correctness requirement rather than a tuning choice.
  //
  // `fullyParallel: false` only serializes WITHIN a project; Playwright still runs the
  // three projects concurrently. These tests mutate a SERVED KNOB in the shared e2e
  // database (`web_sw_download_enabled`) and restore it in afterEach — so with
  // concurrent workers, one project's afterEach writes `1` while another project's
  // fallback test is mid-download expecting `0`. Caught on the first real run at S178:
  // the capped-fallback test took the SW path and failed, and the knob was innocent.
  //
  // ⭐ The general shape is the one that has bitten this arc repeatedly: shared global
  // state read live per request, mutated by a test, with no isolation — the test-suite
  // twin of the confound that made tonight's live investigation uninterpretable
  // (the same knob, flipped mid-sequence, by me).
  workers: 1,
  forbidOnly: !!process.env.CI,
  // ⚠ Retries stay at 0 DELIBERATELY. A flaky-tolerant download test is worse than
  // none: the failure mode this guards against (wrong bytes, silently) is exactly
  // what a retry would paper over on the second attempt.
  retries: 0,
  reporter: 'list',
  use: {
    // ⚠ 5173, NOT vite preview's default 4173. WebAuthn binds to the ORIGIN, and
    // `SIGNET_RP_ORIGIN` is `http://localhost:5173` (web-e2e.md) — a preview server
    // on 4173 could never complete signup, so the full-pipeline test would be
    // unrunnable and the suite would quietly shrink to its no-auth half.
    baseURL: 'http://localhost:5173',
    trace: 'on-first-retry',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'], channel: 'chrome' } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
  webServer: {
    // ⚠ BOTH steps, every run. Previewing a stale `build/` would reproduce the exact
    // class this config exists to end — a green run about code that is not the code
    // on disk (the same trap as the wasm 3-way check's `rm -rf web/build`).
    command: 'npm run build && npm run preview -- --port 5173 --strictPort',
    url: 'http://localhost:5173',
    // ⚠⚠ NOT reused, and `--strictPort` is deliberate. A vite DEV server already on
    // :5173 is the single most dangerous thing that can happen to this suite: it
    // would serve, no worker would register, and every test here would exercise the
    // capped fallback while reporting under this file's name — the exact inversion
    // this config exists to end. strictPort turns that into a loud port collision
    // instead of a quiet green run about the wrong code. Kill a stale vite first.
    reuseExistingServer: false,
    timeout: 180_000,
    env: {
      ...process.env,
      SIGNET_WEB_S3_ORIGIN: process.env.SIGNET_WEB_S3_ORIGIN ?? 'http://localhost:9000',
    },
  },
});
