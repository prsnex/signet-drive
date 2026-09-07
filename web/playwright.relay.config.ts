// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { defineConfig, devices } from '@playwright/test';

// The RELAY-mode E2E project (Fix-Proposal v04 §4.2 M1) — deliberately a
// separate config: the default suite's upload-resilience specs fault-inject at
// the STORAGE origin (`isPartPut`, port 9000), which relay mode makes
// unreachable by design, so one server cannot honestly serve both suites.
//
// Run: start the stack per docs/operations/web-e2e.md, but launch the API
// server with SIGNET_UPLOAD_PATH=relay — then `npm run e2e:relay`.
// The spec refuses to run against a direct-mode server (its own validity gate),
// so pointing this config at the wrong server fails loudly, never silently.
export default defineConfig({
  testDir: 'e2e',
  testMatch: ['**/relay-upload.spec.ts'],
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
    env: {
      ...process.env,
      SIGNET_WEB_S3_ORIGIN: process.env.SIGNET_WEB_S3_ORIGIN ?? 'http://localhost:9000',
    },
  },
});
