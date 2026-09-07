// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Post-sign-in redirect helper. A `returnTo` query value (set, e.g., by the PRSN
// confirm-and-approve page reached via `signet enroll`) lets sign-in send the user
// back where they came from instead of always to the drive. Validated against
// open-redirect: same-origin absolute paths only — never an off-origin URL or a
// protocol-relative `//host`.

export function safeReturnPath(returnTo: string | null | undefined): string {
  if (!returnTo) return '/';
  // Reject protocol-relative (`//host`) and its backslash variant (`/\host`, which
  // some browsers normalize to `//host`) — both would navigate off-origin.
  if (returnTo.startsWith('//') || returnTo.startsWith('/\\')) return '/';
  // Otherwise require a same-origin absolute path (so `https://…`, `javascript:…`,
  // and bare hosts all fall back to the drive).
  if (!returnTo.startsWith('/')) return '/';
  return returnTo;
}
