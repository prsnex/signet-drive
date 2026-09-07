// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { defineConfig, devices } from '@playwright/test';

// Local-only E2E (deliberately NOT in web-ci — the unit mocks gate the logic in
// CI; a browser-in-CI adds ~150MB Chromium for one test). It drives the real
// signup -> sign-in WebAuthn-PRF keystone through system Chrome + a CDP virtual
// authenticator against a running stack.
//
// Prerequisites (started manually per docs/operations/web-e2e.md):
//   - docker compose up -d   (Postgres + MinIO)
//   - a Mailpit SMTP sink (begin-signup always sends a verification email)
//   - cargo run -p signet-server   with SIGNET_RP_ORIGIN=http://localhost:5173
// Playwright starts the vite dev server itself, and this config makes the run
// SELF-CONTAINED: globalSetup lifts the per-IP rate-limit caps (S046) and
// webServer.env points the CSP connect-src at the local MinIO origin (S048) so
// the browser's direct-to-storage uploads aren't blocked. (Both only apply when
// Playwright starts vite — if a stale vite is already on :5173, restart it.)
export default defineConfig({
  testDir: 'e2e',
  // uiux-walkthrough.spec.ts is a manual UI/UX review instrument (drives every
  // human-web screen and captures full-page screenshots for a visual + copy
  // review) — NOT a regression test, so it is kept out of the suite and CI.
  // To run it for a review, temporarily remove it from this list.
  // consolidation-visual is a §1-64 review instrument (screenshots, not a
  // regression test) — VISUAL=1 admits it for an explicit capture run.
  testIgnore: process.env.VISUAL
    ? ['**/uiux-walkthrough.spec.ts']
    : ['**/uiux-walkthrough.spec.ts', '**/consolidation-visual.spec.ts'],
  globalSetup: './e2e/global-setup.ts',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:5173',
    trace: 'on-first-retry',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'], channel: 'chrome' } }],
  webServer: {
    command: 'npm run dev',
    url: 'http://localhost:5173',
    reuseExistingServer: true,
    timeout: 60_000,
    // The SvelteKit CSP connect-src must include the object-storage origin for the
    // direct-to-storage data plane (svelte.config.js; S048 #127). Default it to the
    // dev MinIO host so a local `npm run e2e` works out of the box; an explicit
    // override (e.g. a remote bucket) still wins.
    env: {
      ...process.env,
      SIGNET_WEB_S3_ORIGIN: process.env.SIGNET_WEB_S3_ORIGIN ?? 'http://localhost:9000',
    },
  },
});
