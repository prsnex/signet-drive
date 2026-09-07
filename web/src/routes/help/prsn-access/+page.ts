// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// bug119: the human-facing PRSN-access explainer. Public + prerendered (the api-docs
// pattern): a generic plain-language explainer with no secrets and no key logic, kept
// on the product origin so it ships and versions WITH the product whose states it
// describes. Public rather than session-gated so a prospective guardian (or support)
// can read it too.
//
// ⚠ BOTH lines are load-bearing (bug120 defect A): under the app-wide ssr=false
// (../+layout.ts), `prerender` alone emits the SPA SHELL — a 200 with no content,
// which a browser e2e cannot see by construction. `ssr = true` is what makes the
// prerender pass render the page's actual HTML (the api-docs precedent).
export const ssr = true;
export const prerender = true;
