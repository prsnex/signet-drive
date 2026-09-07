// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Display formatters for the file browser. Sizes are humanized (the file list +
// quota readout); dates render from unix seconds (the "Modified" column).

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`;
}

export function formatDate(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

/**
 * A **deadline** — date + time + zone. The rendering for any instant after which the
 * user loses something (today: the free-trial wipe date).
 *
 * bug072 (S140): `formatDate` above renders a bare local date, while the server rendered
 * the same instant as a bare UTC date. For any deadline landing in the UTC evening —
 * which is *every* evening signup in a western timezone — the two named **different
 * days**: this app said `Jul 30`, the email said `2026-07-31`, and neither was wrong.
 * A bare date cannot state which day it means.
 *
 * The rule (Chris's ruling, option (b)), stated once and applied on both surfaces:
 * a deadline is **never** rendered as a bare date — always *date + time + zone*. Each
 * surface renders in the zone it can legitimately compute (this one knows the browser's;
 * the server has no per-account timezone and states UTC), because once the instant is
 * complete the two are reconcilable by reading rather than by knowing.
 *
 * ⚠ Do **not** "simplify" this back to `formatDate` — the time and `timeZoneName` are
 * the fix, not decoration. The server half is `lifecycle::format_deadline`, named to
 * match so a search for one finds the other.
 */
export function formatDeadline(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    timeZoneName: 'short',
  });
}

/**
 * bug156: the pending-deletion soonest-bound — floored to the HOUR, viewer's local
 * zone. Flooring is deliberate (Chris, S167): the purge runs at the first lifecycle
 * tick after the deadline and the storage drain completes asynchronously, so an
 * exact-minute rendering claims precision the machinery does not have. Flooring is
 * presentation only — the instant itself is server-computed (`deletes_at`), so the
 * client carries no knob assumption. Zone included per the bug072 rule above
 * (a deadline is never a bare date).
 */
export function formatDeletionHour(unixSeconds: number): string {
  const floored = Math.floor(unixSeconds / 3600) * 3600;
  return new Date(floored * 1000).toLocaleString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    timeZoneName: 'short',
  });
}

/** Date + time, for the account-history feed (audit events). */
export function formatDateTime(unixSeconds: number): string {
  return new Date(unixSeconds * 1000).toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
}

// The audit-log event types (account/security events — Schema §"audit log"; the
// minimal-by-design set, NOT file-access patterns) → calm human labels for the
// account-history feed. Unknown types fall back to a title-cased form so a new
// server event still renders legibly.
const EVENT_LABELS: Record<string, string> = {
  account_created: 'Account created',
  attestation_issued: 'PRSN attested',
  attestation_revoked: 'Attestation revoked',
  attestation_revoked_self: 'Your attestation was revoked',
  guardian_changed_prsn_sharing_capability: 'Sharing capability changed',
  account_pending_deletion: 'Account scheduled for deletion',
  passkey_rotated: 'Passkey rotated',
};

export function formatEventType(type: string): string {
  return EVENT_LABELS[type] ?? type.replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase());
}

/** A sharing-capability enum → a human label (the per-PRSN row + the select). */
export function formatCapability(capability: string | null | undefined): string {
  // bug154 §1a/§1c: ONE vocabulary on both surfaces (the wizard's Step-1 options
  // and the account card's per-row line). The old bare "Read-only" under a
  // PRSN heading read as "this PRSN can only read" — false, and it changed a
  // real decision. The grammar now answers what the setting governs: what the
  // PRSN may GRANT TO OTHERS, never its own access.
  switch (capability) {
    case 'read_write':
      return 'Can share, read-write';
    case 'read_only':
      return 'Can share, read-only';
    case 'none':
      return "Can't share with anyone else";
    default:
      return '—';
  }
}

/** Elapsed wall-clock, for the honest "nothing has acknowledged yet" readout
 *  during an upload's silent stretch (bug075 item 1).
 *
 *  ⚠ This is a CLOCK, never a progress signal. It is shown alongside a phase
 *  label precisely BECAUSE no progress figure would be truthful yet: elapsed
 *  time is a fact, a percentage derived from it would be a fabrication, and
 *  fabricated in-flight progress on this exact surface is bug060.
 */
export function formatElapsed(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000));
  const minutes = Math.floor(total / 60);
  const seconds = total % 60;
  return minutes > 0 ? `${minutes}m ${String(seconds).padStart(2, '0')}s` : `${seconds}s`;
}
