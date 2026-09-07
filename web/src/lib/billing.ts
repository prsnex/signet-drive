// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Billing display + state logic for the D2 web cluster (the subscribe-to-activate
// screen, the read-only/over-quota banner). Pure functions, no DOM — the screen
// and the banner are thin renderers over `billingBannerState` + the tier helpers.
//
// Commercial model (1-Pager v0.13 §Commercial model): SigDrive owns capacity,
// Stripe owns commerce. A tier is just a storage size; its price lives in the
// Stripe Price object and is shown on Stripe Checkout, never hardcoded here.

import type { MeResponse, QuotaResponse, TierAmount } from './api';

/** bug171 (ruled Option 3, Chris S171): render a tier's list amounts in EVERY
 *  configured currency — `CA$6 / US$5` — so no guess is made about the viewer
 *  and whatever Checkout later picks has already been seen. Amounts arrive
 *  from the Stripe price objects via the server; ⚠ nothing here is a price,
 *  only presentation (the S169 lookup-key rule: prices are fetched, never
 *  typed into copy).
 *
 *  Whole amounts drop the cents (`CA$6`, not `CA$6.00` — the ruled mock-up);
 *  non-whole amounts keep two places. An unknown currency code renders as
 *  `CODE 6` — visible and honest rather than silently skipped. */
const CURRENCY_PREFIX: Record<string, string> = {
  cad: 'CA$',
  usd: 'US$',
};

export function formatTierAmounts(amounts: TierAmount[]): string {
  return amounts
    .map((a) => {
      const whole = a.amount_minor % 100 === 0;
      const value = whole ? String(a.amount_minor / 100) : (a.amount_minor / 100).toFixed(2);
      const prefix = CURRENCY_PREFIX[a.currency];
      return prefix ? `${prefix}${value}` : `${a.currency.toUpperCase()} ${value}`;
    })
    .join(' / ');
}

const UNIT_BYTES: Record<string, number> = {
  mb: 1024 ** 2,
  gb: 1024 ** 3,
  tb: 1024 ** 4,
};

/** Parse a tier label like `"10gb"` / `"1tb"` into its value + lowercased unit,
 *  or null when it doesn't match the expected shape. */
function parseTier(label: string): { value: number; unit: string } | null {
  const match = /^(\d+(?:\.\d+)?)\s*(mb|gb|tb)$/i.exec(label.trim());
  if (!match) return null;
  return { value: Number(match[1]), unit: match[2].toLowerCase() };
}

/** A tier label → a display name (`"10gb"` → `"10 GB"`, `"1tb"` → `"1 TB"`). An
 *  unrecognized label renders uppercased as a safe fallback. */
export function tierDisplayName(label: string): string {
  const parsed = parseTier(label);
  return parsed ? `${parsed.value} ${parsed.unit.toUpperCase()}` : label.toUpperCase();
}

/** Approximate byte size of a tier label, for size-ordering the tiles. An
 *  unrecognized label sorts last. */
export function tierSizeBytes(label: string): number {
  const parsed = parseTier(label);
  if (!parsed) return Number.MAX_SAFE_INTEGER;
  return parsed.value * (UNIT_BYTES[parsed.unit] ?? 0);
}

/** Order tier labels small → large by parsed size. The server returns them
 *  lexically (e.g. `["100gb","10gb","1tb"]`); the screen shows them by size. */
export function sortTiers(labels: string[]): string[] {
  return [...labels].sort((a, b) => tierSizeBytes(a) - tierSizeBytes(b));
}

/** The banner the file browser shows for an account that cannot currently write.
 *  Human and PRSN are distinct surfaces: a human can subscribe/recover directly;
 *  a PRSN never bills (it draws from its Guardian's pooled quota), so its banner
 *  informs and points at the Guardian rather than offering a billing CTA. */
export type BannerState =
  | 'none'
  /** Human on a usable two-window free trial (never-activated, paid_until in the
   *  future) — a countdown + upgrade/add-card CTA (S134). */
  | 'trial'
  /** Human, never billing-activated AND read-only — the legacy subscribe-to-activate
   *  state (unreachable under the S134 trial, which is usable in-window; kept defensive). */
  | 'needs_activation'
  /** Human, subscription lapsed and in the read-only grace window. */
  | 'lapsed'
  /** Human, active but at/over the storage quota (a separate state from read-only). */
  | 'over_quota'
  /** PRSN whose Guardian's subscription lapsed (group-scoped read-only). */
  | 'prsn_lapsed'
  /** PRSN whose Guardian's pooled storage is full. */
  | 'prsn_over_quota';

/** Decide which (if any) billing banner to show, from `/v1/me` + the quota readout.
 *
 *  Precedence — most-fundamental cause first:
 *    human: needs_activation › lapsed (read_only) › over_quota › none
 *    prsn:  prsn_lapsed (read_only) › prsn_over_quota › none
 *
 *  Over-quota is derived from the quota readout, NOT the server `read_only` flag
 *  (the two are independent states), and is guarded by `bytes_quota > 0` so a
 *  zero-quota un-activated account never reads as "over quota". */
export function billingBannerState(
  me: MeResponse | null,
  quota: QuotaResponse | null,
): BannerState {
  if (!me) return 'none';
  const overQuota = !!quota && quota.bytes_quota > 0 && quota.bytes_used >= quota.bytes_quota;

  if (me.account_type === 'prsn') {
    if (me.read_only) return 'prsn_lapsed';
    if (overQuota) return 'prsn_over_quota';
    return 'none';
  }
  if (me.account_type === 'human') {
    // Never-activated (activated_at NULL) = a two-window free trial (S134). In its
    // window it is usable (not read_only) → the trial countdown; if somehow read_only
    // (a trial is locked out past paid_until, so this is defensive) → the legacy
    // subscribe-to-activate banner.
    if (me.needs_activation) return me.read_only ? 'needs_activation' : 'trial';
    if (me.read_only) return 'lapsed';
    if (overQuota) return 'over_quota';
    return 'none';
  }
  return 'none';
}
