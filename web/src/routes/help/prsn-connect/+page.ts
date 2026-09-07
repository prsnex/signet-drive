// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// bug119: the PRSN-facing connection help page. Public + prerendered (the api-docs
// pattern, overriding the app-wide prerender=false): its reader is BY DEFINITION a
// PRSN that cannot connect, and PRSN auth is request-signing on API routes, not a
// browser session — a sign-in wall would make this page unreachable by exactly its
// audience. It contains no secrets and executes no key logic; it renders to static
// HTML an agent can fetch and read as plain text.
//
// ⚠ BOTH lines are load-bearing (bug120 defect A): under the app-wide ssr=false
// (../+layout.ts), `prerender` alone emits the SPA SHELL — a 200 with no content,
// which a browser e2e cannot see by construction. `ssr = true` is what makes the
// prerender pass render the page's actual HTML (the api-docs precedent).
export const ssr = true;
export const prerender = true;
