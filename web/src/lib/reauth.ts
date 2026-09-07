// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Post-refresh re-unlock detection (Bug014). A page refresh clears the in-memory
// KEM private key — it is non-extractable and never persisted, which is the
// zero-access guarantee, so the decryption capability is gone. But the httpOnly
// session cookie persists, so the server still knows *who* you are. If that cookie
// is still valid we can offer a one-Touch-ID re-unlock (recover the KEM key via the
// existing sign-in path) instead of a full email + passkey sign-in.
//
// This probes GET /v1/me with the cookie: it resolves for a returning human and
// rejects (401) when there's no usable session. The key is NEVER persisted — only
// the cookie is, and that already existed.

import { createApiClient, type DriveApi, type MeResponse } from './api';

/** The returning human if the session cookie is still valid and identifies a human
 *  with an email — the value the re-unlock pre-fills into the existing identified
 *  sign-in. Returns null when there is no usable session (401 / any error), so the
 *  caller falls back to the full sign-in. The web cookie is human-only, so a valid
 *  /v1/me is always a human; the email guard is defensive (a human always has one).
 *  `api` is injectable for tests; in the browser it defaults to the real client. */
export async function detectReturningUser(
  api: Pick<DriveApi, 'getMe'> = createApiClient(),
): Promise<MeResponse | null> {
  try {
    const me = await api.getMe();
    return me.email ? me : null;
  } catch {
    return null;
  }
}
