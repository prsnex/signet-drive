// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { describe, it, expect } from 'vitest';
import {
  formatTierAmounts,
  tierDisplayName,
  tierSizeBytes,
  sortTiers,
  billingBannerState,
  type BannerState,
} from './billing';
import type { MeResponse, QuotaResponse } from './api';

describe('tier display + ordering', () => {
  it('formats labels into display names', () => {
    expect(tierDisplayName('10gb')).toBe('10 GB');
    expect(tierDisplayName('100gb')).toBe('100 GB');
    expect(tierDisplayName('1tb')).toBe('1 TB');
  });

  it('falls back to an uppercased label when unrecognized', () => {
    expect(tierDisplayName('custom')).toBe('CUSTOM');
  });

  it('orders the lexically-sorted server list by real size', () => {
    // The server returns labels lexically: "100gb" < "10gb" < "1tb" as strings.
    expect(sortTiers(['100gb', '10gb', '1tb'])).toEqual(['10gb', '100gb', '1tb']);
  });

  it('sizes tb above gb above mb', () => {
    expect(tierSizeBytes('1tb')).toBeGreaterThan(tierSizeBytes('100gb'));
    expect(tierSizeBytes('1gb')).toBeGreaterThan(tierSizeBytes('1mb'));
  });

  it('sorts an unrecognized label last', () => {
    expect(sortTiers(['1tb', 'mystery', '10gb'])).toEqual(['10gb', '1tb', 'mystery']);
  });
});

// Minimal MeResponse / QuotaResponse builders — only the fields the banner reads.
function me(over: Partial<MeResponse>): MeResponse {
  return {
    account_id: 'a',
    account_type: 'human',
    handle: 'user',
    created_at: 0,
    paid_until: 0,
    read_only: false,
    needs_activation: false,
    trial_card_added: false,
    max_upload_size_bytes: 2_147_483_648,
    ...over,
  };
}

function quota(used: number, total: number): QuotaResponse {
  return { bytes_used: used, bytes_quota: total };
}

describe('billingBannerState — human', () => {
  const cases: [string, MeResponse, QuotaResponse | null, BannerState][] = [
    ['active and under quota → none', me({}), quota(1, 100), 'none'],
    [
      'never activated but usable (a two-window trial in its window) → trial',
      me({ needs_activation: true, read_only: false }),
      quota(1, 2_147_483_648),
      'trial',
    ],
    [
      'never activated AND read-only (defensive; unreachable under the S134 trial) → needs_activation',
      me({ needs_activation: true, read_only: true }),
      quota(0, 0),
      'needs_activation',
    ],
    ['lapsed in grace → lapsed', me({ read_only: true }), quota(5, 100), 'lapsed'],
    ['active but at quota → over_quota', me({}), quota(100, 100), 'over_quota'],
    ['active but over quota → over_quota', me({}), quota(150, 100), 'over_quota'],
  ];
  for (const [name, m, q, expected] of cases) {
    it(name, () => expect(billingBannerState(m, q)).toBe(expected));
  }

  it('prefers needs_activation over a coincidental zero-quota over-quota', () => {
    // A never-activated account has bytes_quota 0; the bytes_quota>0 guard plus
    // needs_activation precedence both keep it off the over_quota branch.
    expect(billingBannerState(me({ needs_activation: true, read_only: true }), quota(0, 0))).toBe(
      'needs_activation',
    );
  });

  it('prefers lapsed (read_only) over over_quota when both could apply', () => {
    expect(billingBannerState(me({ read_only: true }), quota(150, 100))).toBe('lapsed');
  });

  it('returns none when quota is unknown and the account is healthy', () => {
    expect(billingBannerState(me({}), null)).toBe('none');
  });
});

describe('billingBannerState — prsn', () => {
  it('shows prsn_lapsed when the Guardian lapsed (read_only)', () => {
    expect(billingBannerState(me({ account_type: 'prsn', read_only: true }), quota(5, 100))).toBe(
      'prsn_lapsed',
    );
  });

  it('shows prsn_over_quota when the pool is full', () => {
    expect(billingBannerState(me({ account_type: 'prsn' }), quota(100, 100))).toBe(
      'prsn_over_quota',
    );
  });

  it('never shows needs_activation for a PRSN', () => {
    // needs_activation is always false for PRSNs; even if set, the prsn branch
    // never reaches the human activation state.
    expect(billingBannerState(me({ account_type: 'prsn', read_only: true }), null)).toBe(
      'prsn_lapsed',
    );
  });

  it('is none for a healthy PRSN', () => {
    expect(billingBannerState(me({ account_type: 'prsn' }), quota(1, 100))).toBe('none');
  });
});

describe('billingBannerState — guards', () => {
  it('is none when me is null', () => {
    expect(billingBannerState(null, quota(1, 100))).toBe('none');
  });
});

// --- bug171: the both-currencies amount format (ruled Option 3, Chris S171) ---
describe('formatTierAmounts', () => {
  it('renders the ruled mock-up shape: CA$ then US$, whole amounts without cents', () => {
    expect(
      formatTierAmounts([
        { currency: 'cad', amount_minor: 800 },
        { currency: 'usd', amount_minor: 700 },
      ]),
    ).toBe('CA$8 / US$7');
  });

  it('keeps two places for non-whole amounts', () => {
    expect(formatTierAmounts([{ currency: 'usd', amount_minor: 1550 }])).toBe('US$15.50');
  });

  it('renders an unknown currency visibly rather than skipping it', () => {
    // A future EUR price must not silently vanish from the screen — an honest
    // ugly render beats a silent omission (the bug176/177 class, in copy).
    expect(formatTierAmounts([{ currency: 'eur', amount_minor: 600 }])).toBe('EUR 6');
  });

  it('single currency renders with no separator', () => {
    expect(formatTierAmounts([{ currency: 'cad', amount_minor: 600 }])).toBe('CA$6');
  });
});
