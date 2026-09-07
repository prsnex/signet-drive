// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Client-side mirror of the server's human-handle rule (validate_human_handle in
// server/src/signup.rs). Kept as a pure, unit-tested helper so it can't silently
// drift from the server rule — the server stays authoritative; this only spares the
// user from burning a single-use Turnstile token on an obviously-invalid handle and
// lets us show the *specific* reason inline (the server flattens it to a generic
// "invalid_request" by the time friendlyAuthError sees it). Bug015.

/** Normalize what a user TYPED into the handle a handle actually is: trimmed and
 *  lower-cased. S203 — the server does exactly this at `begin_signup`, and before
 *  this existed the client gate below rejected `Hlin` and RETURNED, so the server's
 *  normalization never saw it: the fix was true at the API and false in the browser.
 *
 *  ⚠ Deliberately SEPARATE from {@link validateHandle} rather than folded into it.
 *  A validator that silently repairs its input stops being able to answer "is this a
 *  valid handle?" honestly, and every caller then inherits a guess about which it did.
 *  Normalize at the input boundary; validate the normalized value. */
export function normalizeHandle(raw: string): string {
  return raw.trim().toLowerCase();
}

/** Why a handle is rejected: a bad shape, or the PRSN-reserved "-ai" suffix. */
export type HandleProblem = 'invalid' | 'reserved_ai';

// 2–64 chars, a–z / 0–9 / hyphen, starting and ending alphanumeric (hyphens only in
// the interior; consecutive hyphens are allowed, matching the server's charset check).
const HANDLE_RE = /^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$/;

/** Validate a human handle against the server rule. Returns the problem, or null
 *  when the handle is acceptable. Trim before calling — the server trims too. */
export function validateHandle(handle: string): HandleProblem | null {
  if (!HANDLE_RE.test(handle)) return 'invalid';
  if (handle.endsWith('-ai')) return 'reserved_ai';
  return null;
}

// --- PRSN naming (the add-PRSN wizard; §1-62 / design note §4) -----------------
//
// PRSN handles MUST end in `-ai` (Resolved-Q #1; the server's /confirm gates it).
// The rule is invariant, so the user never types it: the wizard's name field takes
// the BASE and the suffix is appended here — idempotently, so a habit-typed
// "hlin-ai" still yields "hlin-ai", never "hlin-ai-ai".

/** Append the reserved `-ai` suffix to a PRSN base name, idempotently. Trims. */
export function appendAiSuffix(base: string): string {
  const b = base.trim();
  return b.endsWith('-ai') ? b : `${b}-ai`;
}

/** Validate a PRSN name AFTER suffixing (i.e. validate `appendAiSuffix(base)`
 *  against the server's charset rule). Returns null when acceptable. The server
 *  stays authoritative — this only gives the inline reason (mirrors
 *  {@link validateHandle}, whose `reserved_ai` arm is inverted here: for PRSNs
 *  the suffix is required, and the append guarantees it). */
export function validatePrsnHandle(suffixed: string): 'invalid' | null {
  return HANDLE_RE.test(suffixed) && suffixed.endsWith('-ai') ? null : 'invalid';
}
