// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { describe, expect, it } from 'vitest';
import {
  SETUP_WARNING_LEAD_SECONDS,
  driveSetupStep,
  hasHotGrant,
  neverAuthorizedPrsns,
  prsnStateTag,
  prsnStateTagFromGrants,
  revokedPrsns,
  setupWarningTarget,
} from './garnet';
import type { GarnetGrant, GuardedPrsn } from './api';

// The Garnet authorize picker's filter — the one piece of branching decision logic on
// the guardian dashboard, so it gets a focused unit test (the stateful store + the
// authorize/revoke ceremony flow are covered by the Playwright e2e, the codebase's
// mechanism for runes-store UI). Canonical: Garnet Design-Spec v05 §6 + Auth-Core v08.

function grant(over: Partial<GarnetGrant> = {}): GarnetGrant {
  return {
    grant_id: 'g',
    prsn_handle: 'aria-ai',
    status: 'active',
    enrollment_confirmed: false,
    contested: false,
    overdue: false,
    grace_read_only: false,
    reconfirm_deadline_at: null,
    reconfirm_available: false,
    enrolling_fingerprint: null,
    created_at: 0,
    last_confirmed_at: null,
    revoked_at: null,
    ...over,
  };
}

function prsn(over: Partial<GuardedPrsn> = {}): GuardedPrsn {
  return { account_id: 'a', handle: 'aria-ai', status: 'active', ...over };
}

// bug108 §6 split the old `authorizablePrsns` (which lumped never-authorized + revoked)
// into two: `neverAuthorizedPrsns` (the "Authorize a PRSN" picker — no grant at all) and
// `revokedPrsns` (the muted "Re-authorize" rows — a grant exists but none active). The
// partition is exhaustive over the three PRSN states: active-granted / never-granted /
// revoked-only.
describe('neverAuthorizedPrsns', () => {
  it('offers an active PRSN that holds no grant at all', () => {
    expect(neverAuthorizedPrsns([], [prsn({ handle: 'aria-ai' })])).toHaveLength(1);
  });

  it('excludes a PRSN that holds an active grant', () => {
    const out = neverAuthorizedPrsns(
      [grant({ prsn_handle: 'aria-ai', status: 'active' })],
      [prsn({ handle: 'aria-ai' })],
    );
    expect(out).toHaveLength(0);
  });

  it('excludes a PRSN whose only grant is revoked (bug108: it is a revokedPrsn, NOT never-authorized)', () => {
    const out = neverAuthorizedPrsns(
      [grant({ prsn_handle: 'aria-ai', status: 'revoked' })],
      [prsn({ handle: 'aria-ai' })],
    );
    expect(out).toHaveLength(0);
  });

  it('excludes a PRSN that is not in good standing (pending_deletion / suspended)', () => {
    expect(neverAuthorizedPrsns([], [prsn({ status: 'pending_deletion' })])).toHaveLength(0);
    expect(neverAuthorizedPrsns([], [prsn({ status: 'suspended' })])).toHaveLength(0);
  });

  it('excludes a PRSN with no handle (the grant keys on handle)', () => {
    expect(neverAuthorizedPrsns([], [prsn({ handle: null })])).toHaveLength(0);
  });

  it('filters a mixed roster, keying grant↔PRSN by handle', () => {
    const grants = [
      grant({ prsn_handle: 'has-grant-ai', status: 'active' }),
      grant({ prsn_handle: 'revoked-ai', status: 'revoked' }),
    ];
    const prsns = [
      prsn({ account_id: '1', handle: 'has-grant-ai' }), // excluded: active grant
      prsn({ account_id: '2', handle: 'free-ai' }), // included: no grant at all
      prsn({ account_id: '3', handle: 'revoked-ai' }), // excluded: has a (revoked) grant → revokedPrsns
      prsn({ account_id: '4', handle: 'gone-ai', status: 'suspended' }), // excluded: not active
    ];
    expect(neverAuthorizedPrsns(grants, prsns).map((p) => p.account_id)).toEqual(['2']);
  });
});

describe('revokedPrsns', () => {
  it('includes a PRSN whose only grant is revoked', () => {
    const out = revokedPrsns(
      [grant({ prsn_handle: 'aria-ai', status: 'revoked' })],
      [prsn({ handle: 'aria-ai' })],
    );
    expect(out.map((p) => p.handle)).toEqual(['aria-ai']);
  });

  it('excludes a PRSN with an active grant (it currently has access)', () => {
    const out = revokedPrsns(
      [grant({ prsn_handle: 'aria-ai', status: 'active' })],
      [prsn({ handle: 'aria-ai' })],
    );
    expect(out).toHaveLength(0);
  });

  it('excludes a PRSN with BOTH an active and a revoked grant (active wins → not revoked-only)', () => {
    const out = revokedPrsns(
      [
        grant({ prsn_handle: 'aria-ai', status: 'revoked' }),
        grant({ prsn_handle: 'aria-ai', status: 'active' }),
      ],
      [prsn({ handle: 'aria-ai' })],
    );
    expect(out).toHaveLength(0);
  });

  it('excludes a never-authorized PRSN (no grant at all)', () => {
    expect(revokedPrsns([], [prsn({ handle: 'aria-ai' })])).toHaveLength(0);
  });

  it('excludes a PRSN not in good standing even with a revoked grant', () => {
    const out = revokedPrsns(
      [grant({ prsn_handle: 'aria-ai', status: 'revoked' })],
      [prsn({ handle: 'aria-ai', status: 'pending_deletion' })],
    );
    expect(out).toHaveLength(0);
  });
});

// (`fingerprintsMatch` + `parseReconfirmDays` tests are GONE with their functions —
// bug084 retired the match-gate, bug085 the per-grant interval.)

describe('hasHotGrant', () => {
  // The Bug033 poll predicate: hot = an active grant whose state can move out-of-band
  // (awaiting pickup/confirm, contested, or overdue). Quiet panels must not poll.
  it('is hot while an active grant awaits confirmation', () => {
    expect(hasHotGrant([grant({ enrollment_confirmed: false })])).toBe(true);
  });

  it('is hot for a contested or overdue grant', () => {
    expect(hasHotGrant([grant({ enrollment_confirmed: true, contested: true })])).toBe(true);
    expect(hasHotGrant([grant({ enrollment_confirmed: true, overdue: true })])).toBe(true);
  });

  it('is quiet for a healthy confirmed grant, a revoked grant, or no grants', () => {
    expect(hasHotGrant([grant({ enrollment_confirmed: true })])).toBe(false);
    expect(
      hasHotGrant([grant({ status: 'revoked', enrollment_confirmed: false, contested: true })]),
    ).toBe(false);
    expect(hasHotGrant([])).toBe(false);
  });
});

// The add-PRSN wizard's Drive-access step derivation (§1-62 PR-C, design note
// §3.2; narrowed by bug084): every branch, plus the two ordering rules that would
// silently misroute the wizard if lost — authorized-wins-over-missing-broker, and
// the strict broker→authorize→pickup_wait guided order (there is no confirm step:
// the agent's signed pickup auto-confirms).
describe('driveSetupStep', () => {
  const h = 'aria-ai';

  it('unknown or inactive PRSN → not_found', () => {
    expect(driveSetupStep(h, true, [], []).kind).toBe('not_found');
    expect(driveSetupStep(h, true, [], [prsn({ status: 'suspended' })]).kind).toBe('not_found');
    expect(driveSetupStep('other-ai', true, [], [prsn()]).kind).toBe('not_found');
  });

  it('a confirmed active grant → authorized, regardless of broker state', () => {
    const g = grant({ enrollment_confirmed: true });
    expect(driveSetupStep(h, false, [g], [prsn()])).toEqual({ kind: 'authorized', grant: g });
    expect(driveSetupStep(h, true, [g], [prsn()]).kind).toBe('authorized');
  });

  it('no broker (and not yet authorized) → broker_setup first', () => {
    expect(driveSetupStep(h, false, [], [prsn()]).kind).toBe('broker_setup');
    // Even with an unconfirmed grant in flight, the guided order still surfaces
    // the broker prerequisite — pickup cannot complete without it.
    expect(driveSetupStep(h, false, [grant()], [prsn()]).kind).toBe('broker_setup');
  });

  it('broker present, no active grant → authorize (a revoked grant does not count)', () => {
    expect(driveSetupStep(h, true, [], [prsn()]).kind).toBe('authorize');
    expect(driveSetupStep(h, true, [grant({ status: 'revoked' })], [prsn()]).kind).toBe(
      'authorize',
    );
  });

  it('any unconfirmed active grant → pickup_wait (the agent connects + auto-confirms)', () => {
    const g = grant();
    expect(driveSetupStep(h, true, [g], [prsn()])).toEqual({ kind: 'pickup_wait', grant: g });
    // A grant picked up under the RETIRED pre-flag-day flow (cert present, never
    // confirmed) waits the same way — its next signed pickup self-heals it. There is
    // no hard_confirm step to route to (bug084).
    const legacy = grant({ enrolling_fingerprint: 'fp' });
    expect(driveSetupStep(h, true, [legacy], [prsn()])).toEqual({
      kind: 'pickup_wait',
      grant: legacy,
    });
    // Contested rides the grant — the wait step renders the alarm from it.
    const c = grant({ contested: true });
    expect(driveSetupStep(h, true, [c], [prsn()])).toEqual({ kind: 'pickup_wait', grant: c });
  });

  it("another PRSN's grant never leaks into this handle's derivation", () => {
    const other = grant({ prsn_handle: 'other-ai', enrollment_confirmed: true });
    expect(driveSetupStep(h, true, [other], [prsn()]).kind).toBe('authorize');
  });
});

// bug114 Part B: the 5-min warning's target derivation — which account the timer tracks.
// Presence of `setup_deadline` IS the in-setup signal (the server emits it only while the
// shared in-setup predicate matches); absence (incl. a pre-bug114 server) must never arm.
describe('setupWarningTarget', () => {
  it('returns null when no PRSN carries a setup_deadline (incl. a pre-bug114 server)', () => {
    expect(setupWarningTarget([])).toBeNull();
    expect(setupWarningTarget([prsn()])).toBeNull();
    expect(setupWarningTarget([prsn({ setup_deadline: null })])).toBeNull();
  });

  it('targets the in-setup PRSN with warnAt exactly 5 minutes before its deadline', () => {
    const t = setupWarningTarget([prsn({ handle: 'aria-ai', setup_deadline: 10_000 })]);
    expect(t).toEqual({
      handle: 'aria-ai',
      deadline: 10_000,
      warnAt: 10_000 - SETUP_WARNING_LEAD_SECONDS,
    });
  });

  it('picks the SOONEST deadline when several accounts are in setup', () => {
    const t = setupWarningTarget([
      prsn({ account_id: 'a1', handle: 'later-ai', setup_deadline: 20_000 }),
      prsn({ account_id: 'a2', handle: 'sooner-ai', setup_deadline: 10_000 }),
    ]);
    expect(t?.handle).toBe('sooner-ai');
  });

  it('ignores a non-active account even if a deadline lingers on the row', () => {
    // Defense-in-depth: the server drops the field once status leaves `active`, but the
    // client must not warn about an already-wiped account regardless.
    expect(
      setupWarningTarget([prsn({ status: 'pending_deletion', setup_deadline: 10_000 })]),
    ).toBeNull();
  });
});

describe('prsnStateTag (§1-64, the S166 Option B vocabulary)', () => {
  const p = (over: Partial<GuardedPrsn> = {}): GuardedPrsn => ({
    account_id: 'a',
    handle: 'aria-ai',
    status: 'active',
    grant_state: 'active',
    ...over,
  });

  it('maps every server grant_state to its ruled tag', () => {
    expect(prsnStateTag(p({ grant_state: 'never_authorized' }))).toBe('not_authorized');
    expect(prsnStateTag(p({ grant_state: 'waiting_to_connect' }))).toBe('waiting_to_connect');
    expect(prsnStateTag(p({ grant_state: 'active' }))).toBe('active');
    expect(prsnStateTag(p({ grant_state: 'writes_paused' }))).toBe('writes_paused');
    expect(prsnStateTag(p({ grant_state: 'stopped' }))).toBe('stopped');
    expect(prsnStateTag(p({ grant_state: 'revoked' }))).toBe('revoked');
    expect(prsnStateTag(p({ grant_state: 'contested' }))).toBe('contested');
  });

  it('pending_deletion is an ACCOUNT fact and overrides any grant state', () => {
    expect(prsnStateTag(p({ status: 'pending_deletion', grant_state: 'active' }))).toBe(
      'pending_deletion',
    );
  });

  it('N-1 rule: an absent or unrecognized grant_state renders NO tag, never a guess', () => {
    expect(prsnStateTag(p({ grant_state: undefined }))).toBeNull();
    expect(prsnStateTag(p({ grant_state: 'some_future_state' }))).toBeNull();
  });
});

describe('prsnStateTagFromGrants (the consolidated card derivation — live grants, not the snapshot)', () => {
  const p = (over: Partial<GuardedPrsn> = {}): GuardedPrsn => ({
    account_id: 'a',
    handle: 'aria-ai',
    status: 'active',
    ...over,
  });

  it('derives every ruled tag from the grant row the ceremonies actually refresh', () => {
    expect(prsnStateTagFromGrants(p(), [])).toBe('not_authorized');
    expect(prsnStateTagFromGrants(p(), [grant({ enrollment_confirmed: false })])).toBe(
      'waiting_to_connect',
    );
    expect(prsnStateTagFromGrants(p(), [grant({ enrollment_confirmed: true })])).toBe('active');
    expect(
      prsnStateTagFromGrants(p(), [
        grant({ enrollment_confirmed: true, overdue: true, grace_read_only: true }),
      ]),
    ).toBe('writes_paused');
    expect(
      prsnStateTagFromGrants(p(), [grant({ enrollment_confirmed: true, overdue: true })]),
    ).toBe('stopped');
    expect(prsnStateTagFromGrants(p(), [grant({ status: 'revoked' })])).toBe('revoked');
    expect(
      prsnStateTagFromGrants(p(), [grant({ enrollment_confirmed: true, contested: true })]),
    ).toBe('contested');
  });

  it('pending_deletion overrides, and other PRSNs’ grants are invisible', () => {
    expect(
      prsnStateTagFromGrants(p({ status: 'pending_deletion' }), [
        grant({ enrollment_confirmed: true }),
      ]),
    ).toBe('pending_deletion');
    expect(prsnStateTagFromGrants(p(), [grant({ prsn_handle: 'other-ai' })])).toBe(
      'not_authorized',
    );
  });

  it('an active grant wins over revoked history', () => {
    expect(
      prsnStateTagFromGrants(p(), [
        grant({ status: 'revoked' }),
        grant({ enrollment_confirmed: true }),
      ]),
    ).toBe('active');
  });
});
