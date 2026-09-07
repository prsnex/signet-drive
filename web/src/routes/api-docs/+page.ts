// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// The PRSN-facing API & CLI reference (Strawman §8). Unlike the rest of the app
// — a zero-knowledge SPA with SSR off (see ../+layout.ts) — this route carries no
// key logic, so it is prerendered to static HTML: an LLM or crawler reads it
// without executing any JS. These options override the layout defaults for this
// route only; the static adapter emits it as api-docs.html alongside the SPA shell.
export const ssr = true;
export const prerender = true;
