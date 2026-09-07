// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Node 22 exposes WebCrypto as the global `crypto` — the same SubtleCrypto
    // surface the browser client uses, so the differential harness runs without
    // a DOM environment.
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
});
