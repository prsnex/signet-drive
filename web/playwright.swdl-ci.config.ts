// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { defineConfig, devices } from '@playwright/test';
import base from './playwright.swdl.config';

// ⚠⚠ THE CI HALF OF THE SW-DOWNLOAD SUITE — and it is a HALF. Read this before
// treating a green run here as download coverage.
//
// WHAT THIS COVERS: the reserved-namespace contract, on chromium + firefox + webkit.
// The worker must answer `/__signet_dl/<unregistered>` with its own 404 body, and
// must NEVER answer HTML. That is precisely the bug197 shape — the host answered
// `200 + index.html` and four downloads landed as 2401 bytes of our own SPA shell
// under the users' filenames, on a custody product.
//
// ⛔ WHAT THIS DOES **NOT** COVER — byte verification. The two sha-of-artifact tests
// are chromium-only (WebAuthn PRF needs a virtual authenticator, which Playwright can
// only drive over CDP) and they need the full local stack: Postgres, MinIO, Mailpit
// and an API server built with `--features signet-server/dev-auth`. **They run
// locally, by hand, per release — never here.** A green run of this config says the
// namespace contract holds on three engines. It says NOTHING about whether a download
// produces the right bytes.
//
// WHY THE SPLIT EXISTS (S179): "wire the swdl suite into CI" turned out to mean
// standing up the FIRST browser-based CI in the repo — no workflow ran Playwright at
// all. That is a session of infrastructure and ~20-25 min per run, parked as a named
// option for Chris's resourcing call. Meanwhile the namespace contract needs only
// `build && preview`, so it ships now rather than waiting for the foundation.
// ⭐ Gus's ruling: half an arm honestly labeled beats two more sessions of nothing —
// and the honesty lives in the JOB NAME (`swdl-namespace-contract`), because check
// names survive into memory where comments do not.
//
// ⚠ NO `globalSetup` HERE, deliberately. The base config's global setup raises
// rate-limit caps via `docker exec` against the dev database — needed by the
// signup-driven byte tests, and the single thing that would chain this backend-free
// arm to a local stack it otherwise has no use for.
//
// Selection is by EXPLICIT `--grep` in the workflow, never by relying on the
// chromium-only skips inside the spec (Gus, S179): what CI runs must be visible in
// the workflow file, not derivable from skip conditions scattered through specs.
export default defineConfig({
  ...base,
  // The base's globalSetup is a docker-exec into the dev DB; this arm has no DB.
  globalSetup: undefined,
  // ⚠⚠ CI RUNS BUNDLED CHROMIUM, NOT BRANDED CHROME — a deliberate, ruled
  // narrowing (S183), not an oversight. READ THIS BEFORE "fixing" it back.
  //
  // The base config pins `channel: 'chrome'` because the engine under test should
  // be the one users actually run. That pin is RIGHT, and it is retained
  // everywhere it can be honoured: the per-release local run — `npm run e2e:swdl`,
  // the BASE config, which keeps `channel: 'chrome'` — uses branded Chrome, and it
  // is the arm that also carries the byte-verification tests. It cannot be honoured
  // HERE, and the reason is structural:
  //
  //   - This job runs in `mcr.microsoft.com/playwright:v1.60.0-noble`, which is
  //     the only way webkit runs in CI at all. The bare GitHub runner is short
  //     THIRTY-FIVE libraries for webkit (libgtk-4, the whole gstreamer stack,
  //     all fourteen libflite*, libavif, libharfbuzz-icu, libwoff2dec, libx264 …)
  //     — measured, not assumed: PR #436 proved it in 1m6s with webkit failing
  //     `browserType.launch: Host system is missing dependencies`.
  //   - The image ships bundled chromium and NO branded Chrome. Installing Chrome
  //     into it means apt — the exact category whose removal is the entire point
  //     of the S183 change (three remedies died tuning it; see web-ci.yml).
  //
  // ⭐ WHY THE NARROWING IS SOUND FOR *THIS* ASSERTION SPECIFICALLY. This suite
  // asserts one thing: the service worker answers `/__signet_dl/<unregistered>`
  // with its own 404 body and NEVER HTML (the bug197 shape). Service-worker
  // interception is core Chromium and is identical in both builds. What branded
  // Chrome adds over Chromium — proprietary codecs, Widevine DRM, Google service
  // integration — touches none of it. So the fidelity given up here is nil for
  // what this file actually checks.
  //
  // ⛔ THE LIMIT OF THAT ARGUMENT, stated so it is not over-read: it licenses
  // bundled chromium for THIS namespace-contract assertion ONLY. A test that
  // depends on codecs, DRM, or branded-Chrome behaviour may NOT ride this
  // override — it belongs in the local branded-Chrome run (`npm run e2e:swdl`).
  //
  // ⭐ Side benefit, worth keeping: `npm run e2e:swdl:contract` now runs the SAME
  // engine set locally as in CI, so a local green is stronger evidence about CI
  // than it was when the two differed by a browser build.
  //
  // Ruled by Hlin, endorsed by Gus (S183); Chris delegated the call.
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
  // ⚠ Retries stay 0, as in the base. A flaky-tolerant interception test is worse
  // than none: the failure it guards is "wrong bytes, silently", and a retry papers
  // exactly that over on the second attempt.
  retries: 0,
});
