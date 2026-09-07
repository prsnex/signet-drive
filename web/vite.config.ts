// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { paraglideVitePlugin } from '@inlang/paraglide-js';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

// The unit tests (crypto + auth, node env) keep their own vitest.config.ts so the
// SvelteKit plugin never runs during them — they import no $app/$lib aliases and
// need no SSR transform. This config drives `vite dev` / `vite build` only.
export default defineConfig({
  plugins: [
    // Compile-time i18n (inlang Paraglide). Messages in messages/{locale}.json
    // compile to tree-shakable ESM functions in src/lib/paraglide/. Locale is
    // resolved CLIENT-SIDE (no SSR — this is a static SPA): localStorage, then the
    // browser's preferred language, then the base locale. See svelte.config.js.
    paraglideVitePlugin({
      project: './project.inlang',
      outdir: './src/lib/paraglide',
      strategy: ['localStorage', 'preferredLanguage', 'baseLocale'],
      // Emit .d.ts so the generated message module is typed (svelte-check needs
      // it — no implicit-any on `$lib/paraglide/messages.js`). Matches the
      // compile:i18n CLI flag, so dev/build/prepare all produce identical output
      // regardless of which path regenerates src/lib/paraglide/.
      emitTsDeclarations: true,
    }),
    sveltekit(),
  ],
  server: {
    // Dev only: proxy the API to the local Rust server (SIGNET_BIND_ADDR default)
    // so the SPA on :5173 and the API share an origin — same-origin fetch carries
    // the session cookie, and WebAuthn runs against one origin. Production serving
    // (Caddy → static bundle + /v1 proxy) is wired at deployment (Phase 4).
    proxy: {
      '/v1': { target: 'http://localhost:8080', changeOrigin: true },
    },
  },
  // ⚠⚠ bug197 (S178): `vite preview` needs the SAME proxy, and until now it had
  // none — which is a large part of why nothing ever ran against the BUILT app.
  //
  // The distinction is not cosmetic: **no service worker registers under `vite
  // dev`**, so every download e2e we owned was exercising the capped-fallback
  // path while the SHIPPED path (service-worker-streamed) had ZERO automated
  // coverage. That inversion is invisible — the suite is green, and green about
  // the wrong path. It let a launch blocker reach a deploy twice (bug195, bug197).
  //
  // With this, `npm run build && npm run preview` serves the real bundle, the
  // worker registers, and the production CSP from svelte.config.js applies — the
  // three conditions a download test needs in order to be about the product.
  // Owner: playwright.swdl.config.ts (Gus's S177 Q5 item 1).
  preview: {
    proxy: {
      '/v1': { target: 'http://localhost:8080', changeOrigin: true },
    },
  },
});
