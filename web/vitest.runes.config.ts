// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { defineConfig } from 'vitest/config';

// bug151 defect A: the reactive seam between GarnetStore and the wizard's driveStep
// chain can only be exercised with the runes compiler in the loop — the plain unit
// config (vitest.config.ts) deliberately runs without the Svelte plugin and cannot
// compile `$state`/`$derived`. This config exists for `*.test.svelte.ts` files ONLY;
// keep the two includes disjoint so no test runs twice.
//
// ⚠ TWO SILENT-FAILURE TRAPS, both proven by this suite's own control test:
// under `environment: 'node'` vitest runs vite's SSR pipeline, which (a) compiles
// runes for the SERVER — where $effect.root is a deliberate no-op that never runs
// its body — and (b) resolves the `svelte` package to index-server.js (measured
// via import.meta.resolve). Neither failure throws; every reactive assertion just
// tests nothing. The two overrides below force client codegen and client runtime.
export default defineConfig({
  plugins: [svelte()],
  ssr: { resolve: { conditions: ['browser'] } },
  resolve: { conditions: ['browser'] },
  test: {
    // happy-dom (a WEB environment) is what makes vitest request web-mode
    // transforms, so vite-plugin-svelte emits the CLIENT compilation — the
    // 'node' environment's SSR pipeline compiles $effect.root to the server
    // no-op, and no config knob overrides that per-plugin (generate is ignored
    // with a warning; testTransformMode is dead in vitest 4 — both measured).
    environment: 'happy-dom',
    include: ['src/**/*.test.svelte.ts'],
    // svelte must be INLINED: vitest externalizes node_modules to native Node
    // imports, whose own conditions pick the server runtime again regardless of
    // the vite-side conditions above.
    server: { deps: { inline: [/^svelte/] } },
  },
});
