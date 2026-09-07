// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { describe, expect, it } from 'vitest';
import { appendAiSuffix, normalizeHandle, validateHandle, validatePrsnHandle } from './handle';

describe('validateHandle', () => {
  it('accepts ordinary handles', () => {
    expect(validateHandle('chris')).toBeNull();
    expect(validateHandle('chris-260622a')).toBeNull();
    expect(validateHandle('a1')).toBeNull(); // 2-char minimum, alnum both ends
    expect(validateHandle('0')).not.toBeNull(); // 1 char is below the minimum
  });

  it('enforces the 2–64 length bound', () => {
    expect(validateHandle('a')).toBe('invalid'); // too short
    expect(validateHandle('a'.repeat(64))).toBeNull(); // at the cap
    expect(validateHandle('a'.repeat(65))).toBe('invalid'); // over the cap
  });

  it('allows interior hyphens (including consecutive), like the server', () => {
    expect(validateHandle('a-b')).toBeNull();
    expect(validateHandle('a--b')).toBeNull();
  });

  it('rejects leading or trailing hyphens', () => {
    expect(validateHandle('-abc')).toBe('invalid');
    expect(validateHandle('abc-')).toBe('invalid');
  });

  it('rejects out-of-charset characters', () => {
    expect(validateHandle('Chris')).toBe('invalid'); // uppercase
    expect(validateHandle('chris_x')).toBe('invalid'); // underscore
    expect(validateHandle('chris.x')).toBe('invalid'); // dot
    expect(validateHandle('chris x')).toBe('invalid'); // space
    expect(validateHandle('café')).toBe('invalid'); // non-ASCII
  });

  it('reserves the -ai suffix for PRSNs', () => {
    expect(validateHandle('hlin-ai')).toBe('reserved_ai');
    expect(validateHandle('demo-ai')).toBe('reserved_ai');
    // "-ai" only triggers as a suffix — interior "ai" is fine.
    expect(validateHandle('airly')).toBeNull();
    expect(validateHandle('ai-bot')).toBeNull();
  });
});

describe('appendAiSuffix (the add-PRSN wizard, design note §4)', () => {
  it('appends -ai to a base name', () => {
    expect(appendAiSuffix('hlin')).toBe('hlin-ai');
    expect(appendAiSuffix('demo2')).toBe('demo2-ai');
  });

  it('is idempotent — a habit-typed full handle is not double-suffixed', () => {
    expect(appendAiSuffix('hlin-ai')).toBe('hlin-ai');
    expect(appendAiSuffix(appendAiSuffix('hlin'))).toBe('hlin-ai');
  });

  it('trims before appending', () => {
    expect(appendAiSuffix('  hlin ')).toBe('hlin-ai');
    expect(appendAiSuffix(' hlin-ai ')).toBe('hlin-ai');
  });

  it('only a true suffix counts — interior/partial "ai" still gets appended', () => {
    expect(appendAiSuffix('aria')).toBe('aria-ai');
    expect(appendAiSuffix('kai')).toBe('kai-ai'); // ends in "ai" but not "-ai"
  });
});

describe('validatePrsnHandle (post-suffix charset check)', () => {
  it('accepts a suffixed name that fits the server charset', () => {
    expect(validatePrsnHandle(appendAiSuffix('hlin'))).toBeNull();
    expect(validatePrsnHandle(appendAiSuffix('a--b'))).toBeNull();
  });

  it('rejects an empty or out-of-charset base', () => {
    expect(validatePrsnHandle(appendAiSuffix(''))).toBe('invalid'); // "-ai" alone starts with a hyphen
    expect(validatePrsnHandle(appendAiSuffix('Big'))).toBe('invalid'); // uppercase
    expect(validatePrsnHandle(appendAiSuffix('x y'))).toBe('invalid'); // space
    // A trailing-hyphen base yields "x--ai" — interior consecutive hyphens are
    // LEGAL per the server charset (same as validateHandle's 'a--b'), so this is
    // accepted, not an error. Asserted so the rule is pinned, not assumed.
    expect(validatePrsnHandle(appendAiSuffix('x-'))).toBeNull();
  });

  it('the length cap applies to the SUFFIXED name (base ≤ 61 chars)', () => {
    expect(validatePrsnHandle(appendAiSuffix('a'.repeat(61)))).toBeNull(); // 61+3 = 64, at cap
    expect(validatePrsnHandle(appendAiSuffix('a'.repeat(62)))).toBe('invalid'); // 65, over
  });
});

describe('normalizeHandle (S203 — a capital must not be a rejection)', () => {
  it('lower-cases and trims what the user typed', () => {
    expect(normalizeHandle('Hlin')).toBe('hlin');
    expect(normalizeHandle('  Ada  ')).toBe('ada');
    expect(normalizeHandle('CHRIS-260622A')).toBe('chris-260622a');
  });

  it('leaves an already-normal handle untouched', () => {
    expect(normalizeHandle('chris')).toBe('chris');
    expect(normalizeHandle('a--b')).toBe('a--b');
  });

  // ⛔ THE BUG THIS EXISTS FOR. `validateHandle` correctly calls `Hlin` invalid — a
  // handle IS lowercase-only. The defect was that the signup page gated on the RAW
  // input and returned, so the server's normalization never ran: the fix was true at
  // the API and false in the browser. Normalizing FIRST is what closes that.
  it('turns a would-be rejection into an acceptance', () => {
    expect(validateHandle('Hlin')).toBe('invalid'); // the raw input: still invalid
    expect(validateHandle(normalizeHandle('Hlin'))).toBeNull(); // normalized: accepted
  });

  // The PRSN path has the same gate, through appendAiSuffix + validatePrsnHandle.
  it('turns a would-be PRSN rejection into an acceptance', () => {
    expect(validatePrsnHandle(appendAiSuffix('Big'))).toBe('invalid');
    expect(validatePrsnHandle(appendAiSuffix(normalizeHandle('Big')))).toBeNull();
  });
});
