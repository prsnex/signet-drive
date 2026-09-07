// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Signet Drive is a zero-knowledge client: the wrap chain and the session KEM
// private key exist only in the browser. SSR is therefore disabled app-wide — no
// route may execute key logic server-side — and nothing is prerendered. The
// static adapter (svelte.config.js) emits an index.html fallback so client-side
// routing works as a single-page app.
export const ssr = false;
export const prerender = false;
