// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { describe, expect, it } from 'vitest';

import { formatBytes, formatDate, formatDeadline } from './format';

// 2026-07-31T00:12:00Z — the exact instant from bug072. Derived and round-trip
// verified, not recalled (a hand-written epoch constant in the server half of this
// fix was three days out and only an assertion caught it).
const BUG072_INSTANT = 1_785_456_720;

describe('formatDeadline (bug072)', () => {
  // This is the test that proves the DEFECT was real, and it is deliberately
  // timezone-independent: it names both zones explicitly rather than depending on
  // the ambient TZ of whatever machine runs it. That matters — the bug is only
  // visible from a western timezone, so a test that relied on the runner's zone
  // would pass vacuously in CI (which runs UTC) and prove nothing at all.
  it('the bare-date rendering really is ambiguous for this instant', () => {
    const localDay = new Intl.DateTimeFormat('en-CA', {
      timeZone: 'America/Denver',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
    }).format(new Date(BUG072_INSTANT * 1000));

    const utcDay = new Intl.DateTimeFormat('en-CA', {
      timeZone: 'UTC',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
    }).format(new Date(BUG072_INSTANT * 1000));

    // The app showed the left, the email showed the right, for ONE instant.
    expect(localDay).toBe('2026-07-30');
    expect(utcDay).toBe('2026-07-31');
    expect(localDay).not.toBe(utcDay);
  });

  it('states a time, so the day is no longer the whole message', () => {
    const rendered = formatDeadline(BUG072_INSTANT);
    expect(rendered).toMatch(/\d{1,2}:\d{2}/);
  });

  it('states a zone, which is what makes the two surfaces reconcilable', () => {
    const rendered = formatDeadline(BUG072_INSTANT);
    // A zone renders either as an abbreviation (MDT, UTC) or a GMT offset,
    // depending on locale data — accept both, require one.
    expect(rendered).toMatch(/[A-Z]{2,5}|GMT[+-]\d{1,2}/);
  });

  it('carries strictly more than the bare date it replaces', () => {
    const bare = formatDate(BUG072_INSTANT);
    const deadline = formatDeadline(BUG072_INSTANT);
    expect(deadline).not.toBe(bare);
    expect(deadline.length).toBeGreaterThan(bare.length);
  });

  it('applies the rule unconditionally, not only near a day boundary', () => {
    // 2026-07-15T13:45:00Z — mid-afternoon UTC, no boundary anywhere near it.
    const rendered = formatDeadline(1_784_123_100);
    expect(rendered).toMatch(/\d{1,2}:\d{2}/);
    expect(rendered).toMatch(/[A-Z]{2,5}|GMT[+-]\d{1,2}/);
  });
});

describe('formatDate is deliberately left alone', () => {
  // Guard against a well-meaning "consistency" refactor: formatDate still serves
  // non-deadline display (audit history, a paid account's through-date, the lapsed-on
  // date). Those are informational; only a destructive deadline needs the full instant.
  it('still renders a bare date', () => {
    expect(formatDate(BUG072_INSTANT)).not.toMatch(/\d{1,2}:\d{2}/);
  });
});

describe('formatBytes', () => {
  it('renders below 1 KiB in bytes', () => {
    expect(formatBytes(512)).toBe('512 B');
  });

  it('keeps one decimal under 10 and rounds above it', () => {
    expect(formatBytes(1536)).toBe('1.5 KB');
    expect(formatBytes(20 * 1024)).toBe('20 KB');
  });
});
