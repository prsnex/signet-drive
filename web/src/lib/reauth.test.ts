// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { describe, expect, it } from 'vitest';
import { SignetApiError, type MeResponse } from './api';
import { detectReturningUser } from './reauth';

// Only `getMe` matters to the detection; cast a minimal fixture to MeResponse.
const me = (email: string | null): MeResponse => ({ email }) as unknown as MeResponse;

describe('detectReturningUser (Bug014 re-unlock detection)', () => {
  it('returns the user when the session cookie is valid and identifies a human with an email', async () => {
    const result = await detectReturningUser({ getMe: async () => me('alice@test.example') });
    expect(result?.email).toBe('alice@test.example');
  });

  it('returns null when /v1/me rejects — no / expired / invalid cookie → full sign-in', async () => {
    const result = await detectReturningUser({
      getMe: async () => {
        throw new SignetApiError(401, 'authentication_required', 'no session');
      },
    });
    expect(result).toBeNull();
  });

  it('returns null when the session carries no email (defensive — re-unlock needs it to pre-fill sign-in)', async () => {
    const result = await detectReturningUser({ getMe: async () => me(null) });
    expect(result).toBeNull();
  });
});
