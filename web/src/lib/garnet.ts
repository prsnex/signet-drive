// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Pure (rune-free) helpers for the Garnet guardian dashboard — kept here, apart from
// the `$state` store (garnet.svelte.ts), so the decision logic is unit-testable under
// the node vitest config (which doesn't compile Svelte runes). Canonical: Garnet
// Design-Spec v05 §6.

import type { GarnetGrant, GuardedPrsn } from './api';

/** The PRSNs a guardian can authorize for the FIRST time: a guarded PRSN in good standing
 *  (`status === 'active'`, with a handle) that holds NO Garnet grant at all — neither active
 *  nor revoked. These drive the "Authorize a PRSN" picker. A deliberately-REVOKED PRSN is NOT
 *  here (bug108 §6): it re-authorizes through its own muted "Re-authorize" row (`revokedPrsns`),
 *  so the two states are never conflated — the exact bug the old "pending final set-up" list
 *  had. The server independently re-checks guardianship + the at-most-one-active-grant
 *  invariant — this is the friendly client-side filter, not a security boundary. A grant keys
 *  to the PRSN by `prsn_handle`. */
/** The consolidated card's one state tag per PRSN row (§1-64, S166 Option B —
 *  seven values, ruled at the mock-up review). `pending_deletion` is an ACCOUNT
 *  fact and overrides everything; the rest map the server's `grant_state`
 *  projection one-to-one. ⚠ N-1 rule: an absent field (older server) or an
 *  unrecognized value returns null — RENDER NO TAG, never guess. */
export type PrsnStateTag =
  | 'active'
  | 'not_authorized'
  | 'waiting_to_connect'
  | 'writes_paused'
  | 'stopped'
  | 'pending_deletion'
  | 'revoked'
  | 'contested';

export function prsnStateTag(p: GuardedPrsn): PrsnStateTag | null {
  if (p.status === 'pending_deletion') return 'pending_deletion';
  switch (p.grant_state) {
    case 'never_authorized':
      return 'not_authorized';
    case 'waiting_to_connect':
      return 'waiting_to_connect';
    case 'active':
      return 'active';
    case 'writes_paused':
      return 'writes_paused';
    case 'stopped':
      return 'stopped';
    case 'revoked':
      return 'revoked';
    case 'contested':
      return 'contested';
    default:
      return null;
  }
}

/** The same seven-tag vocabulary, derived from the LIVE grants list instead of the
 *  `grant_state` snapshot. ⚠ Why two derivations exist (each surface has exactly
 *  one): the consolidated card's roster (AccountStore) is fetched at page mount,
 *  but its grant actions run on GarnetStore — deriving the tag from the roster's
 *  `grant_state` left every ceremony's result invisible until a reload (found by
 *  the garnet e2e at S166: authorize completed and the row still said "Not
 *  authorized"). Surfaces that HOLD the grants list derive from it — fresh at
 *  every ceremony and every hot-poll tick; surfaces that don't (the drive
 *  sidebar) read the server projection via `prsnStateTag`. Both are server-truth:
 *  the liveness inputs here (`grace_read_only` / `overdue` / `contested`) are
 *  server-computed booleans on the grant row, never client clock math. */
export function prsnStateTagFromGrants(p: GuardedPrsn, grants: GarnetGrant[]): PrsnStateTag | null {
  if (p.status === 'pending_deletion') return 'pending_deletion';
  if (p.handle == null) return null;
  const active = grants.find((g) => g.prsn_handle === p.handle && g.status === 'active');
  if (active) {
    if (active.contested) return 'contested';
    if (!active.enrollment_confirmed) return 'waiting_to_connect';
    if (active.grace_read_only) return 'writes_paused';
    if (active.overdue) return 'stopped';
    return 'active';
  }
  if (grants.some((g) => g.prsn_handle === p.handle)) return 'revoked';
  return 'not_authorized';
}

export function neverAuthorizedPrsns(grants: GarnetGrant[], prsns: GuardedPrsn[]): GuardedPrsn[] {
  const hasAnyGrant = new Set(grants.map((g) => g.prsn_handle));
  return prsns.filter(
    (p) => p.status === 'active' && p.handle != null && !hasAnyGrant.has(p.handle),
  );
}

/** The PRSNs that completed setup and were then DELIBERATELY REVOKED: a guarded PRSN in good
 *  standing (`status === 'active'`, with a handle) that has at least one grant but NONE
 *  currently active. bug108 §6: each gets a muted "Revoked · Re-authorize" row in the Signet
 *  Drive access card; Re-authorize creates a FRESH grant (new 30-day window). Kept distinct
 *  from `neverAuthorizedPrsns` so a never-completed account (which auto-wipes) is never shown
 *  the same affordance as one the guardian intentionally kept-but-revoked. */
export function revokedPrsns(grants: GarnetGrant[], prsns: GuardedPrsn[]): GuardedPrsn[] {
  const activeHandles = new Set(
    grants.filter((g) => g.status === 'active').map((g) => g.prsn_handle),
  );
  const anyGrantHandles = new Set(grants.map((g) => g.prsn_handle));
  return prsns.filter(
    (p) =>
      p.status === 'active' &&
      p.handle != null &&
      anyGrantHandles.has(p.handle) &&
      !activeHandles.has(p.handle),
  );
}

/** Whether any grant is in a "hot" state — one whose server-side state can change out-of-band
 *  while the guardian watches (Bug033, the no-reload standard): an active grant that is
 *  awaiting confirmation (the agent's pickup arrives from outside the browser), contested, or
 *  overdue for re-confirmation. Hot ⇒ the dashboard polls; quiet ⇒ it doesn't (bounded by
 *  construction — the poll only runs while the panel is mounted, visible, and hot). */
export function hasHotGrant(grants: GarnetGrant[]): boolean {
  return grants.some(
    (g) => g.status === 'active' && (!g.enrollment_confirmed || g.contested || g.overdue),
  );
}

// (The §6 hard-confirm match-gate helper `fingerprintsMatch` and the authorize-dialog
// interval parser `parseReconfirmDays` are GONE — bug084 retired the match-gate (the
// agent's signed pickup IS the verification, auto-confirming the grant) and bug085
// replaced the per-grant interval with the platform-fixed cadence.)

// --- bug114 Part B: the 5-minute setup-deadline warning ------------------------

/** The client warning fires this many seconds before the server's setup deadline. */
export const SETUP_WARNING_LEAD_SECONDS = 5 * 60;

export interface SetupWarningTarget {
  handle: string;
  /** The server-authoritative wipe moment (unix seconds — `GuardedPrsn.setup_deadline`). */
  deadline: number;
  /** When the warning should fire: `deadline - SETUP_WARNING_LEAD_SECONDS`. */
  warnAt: number;
}

/** The account the 5-minute warning should track: the SOONEST-expiring in-setup PRSN, or
 *  null. Presence of `setup_deadline` IS the in-setup signal (the server emits it only
 *  while the shared in-setup predicate matches); a pre-bug114 server never emits it, so
 *  the warning simply never arms — absence-tolerant by construction. Pure + unit-tested
 *  (the rune-free home); the timer/modal live in `SetupDeadlineWarning.svelte`. */
export function setupWarningTarget(prsns: GuardedPrsn[]): SetupWarningTarget | null {
  let best: SetupWarningTarget | null = null;
  for (const p of prsns) {
    if (p.status !== 'active' || p.handle == null || p.setup_deadline == null) continue;
    if (best === null || p.setup_deadline < best.deadline) {
      best = {
        handle: p.handle,
        deadline: p.setup_deadline,
        warnAt: p.setup_deadline - SETUP_WARNING_LEAD_SECONDS,
      };
    }
  }
  return best;
}

// --- The add-PRSN wizard's Drive-access phase (§1-62 PR-C; design note §3.2) ----
//
// The wizard's back half derives from the guardian's Garnet state for ONE handle.
// Pure + unit-tested here (the rune-free home), same reason as the helpers above:
// the wizard renders server truth and stores no step of its own (Bug028 pattern).

export type DriveSetupStep =
  | { kind: 'not_found' }
  | { kind: 'broker_setup' }
  | { kind: 'authorize' }
  | { kind: 'pickup_wait'; grant: GarnetGrant }
  | { kind: 'authorized'; grant: GarnetGrant };

/** Derive the wizard's Drive-access step for `handle` from server state.
 *  Order matters and is deliberate:
 *  1. an unknown/inactive PRSN → not_found (the wizard was opened for a handle
 *     the guardian doesn't guard);
 *  2. an ALREADY-authorized PRSN is done regardless of broker state (the broker
 *     could have been deregistered later — that is the management surface's
 *     concern, not this wizard's);
 *  3. no broker → broker_setup first (pickup needs the guardian's broker: the §4
 *     SPKI pin is delivered from the registered broker — the guided order, even
 *     though the server permits authorize without one);
 *  4. then authorize → pickup_wait. There is no confirm step (bug084): the agent's
 *     signature-authenticated pickup auto-confirms the grant, so an unconfirmed
 *     active grant is always "waiting for the agent to connect" — including one
 *     picked up under the retired pre-flag-day flow, which self-heals the same way
 *     (its next signed pickup confirms it). Contested rides the grant and renders
 *     as the alarm inside the wait step. */
export function driveSetupStep(
  handle: string,
  hasBroker: boolean,
  grants: GarnetGrant[],
  prsns: GuardedPrsn[],
): DriveSetupStep {
  const prsn = prsns.find((p) => p.handle === handle && p.status === 'active');
  if (!prsn) return { kind: 'not_found' };
  const active = grants.find((g) => g.prsn_handle === handle && g.status === 'active');
  if (active?.enrollment_confirmed) return { kind: 'authorized', grant: active };
  if (!hasBroker) return { kind: 'broker_setup' };
  if (!active) return { kind: 'authorize' };
  return { kind: 'pickup_wait', grant: active };
}
