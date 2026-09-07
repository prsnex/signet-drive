// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { describe, expect, it } from 'vitest';
import { safeReturnPath } from './nav';

describe('safeReturnPath', () => {
  it('accepts same-origin absolute paths, including a query string', () => {
    expect(safeReturnPath('/account')).toBe('/account');
    expect(safeReturnPath('/account/add-prsn/confirm?code=abc-123_XYZ')).toBe(
      '/account/add-prsn/confirm?code=abc-123_XYZ',
    );
  });

  it('falls back to / when no returnTo is given', () => {
    expect(safeReturnPath(null)).toBe('/');
    expect(safeReturnPath(undefined)).toBe('/');
    expect(safeReturnPath('')).toBe('/');
  });

  it('rejects off-origin and open-redirect vectors', () => {
    expect(safeReturnPath('//evil.example')).toBe('/');
    expect(safeReturnPath('/\\evil.example')).toBe('/');
    expect(safeReturnPath('https://evil.example')).toBe('/');
    expect(safeReturnPath('http://evil.example')).toBe('/');
    expect(safeReturnPath('javascript:alert(1)')).toBe('/');
    expect(safeReturnPath('mailto:x@y.z')).toBe('/');
    expect(safeReturnPath('evil.example/path')).toBe('/');
  });
});
