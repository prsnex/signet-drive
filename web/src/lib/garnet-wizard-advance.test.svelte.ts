// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// bug151 defect A — the wizard's step-5 "Waiting for {handle} to connect…" did not
// advance when the agent's pickup confirmed the grant (S165, watched live under
// instruments).
//
// ⭐ HISTORY, because this file's result REVERSED a filed diagnosis: S165 recorded
// defect A as "a reactivity break across the GarnetStore boundary" at the page's
// driveStep $derived. This test was then written FAILING-FIRST (S166) to pin that
// mechanism — and it PASSED: the store→$derived→$effect seam, replicated from
// routes/account/add-prsn/confirm/+page.svelte lines 75–88 composition-exact,
// advances pickup_wait → authorized correctly when a hot-poll flips
// enrollment_confirmed. The filed mechanism is refuted; the live defect lives in
// some difference between this reproduction and the real page (see bug151 §2c for
// the remaining hypotheses). The test stays as REGRESSION coverage for the seam,
// with its control guarding the harness itself.
import { expect, test, vi } from 'vitest';
import { flushSync } from 'svelte';
import { GarnetStore } from './garnet.svelte';
import { driveSetupStep, type DriveSetupStep } from './garnet';
import type { AccountDeps } from './account.svelte';
import type { GarnetBroker, GarnetGrant, GuardedPrsn } from './api';

const HANDLE = 'wiz-test-ai';

/** Drain the microtask queue (init()'s Promise.all resolves on it; fake timers
 *  don't fake promises, so plain awaits do the draining). 8 turns is comfortably
 *  past the ~4 the store's await chain needs. */
async function flushMicrotasks(): Promise<void> {
  for (let i = 0; i < 8; i++) await Promise.resolve();
}

function grant(confirmed: boolean): GarnetGrant {
  return {
    grant_id: 'g-1',
    prsn_handle: HANDLE,
    status: 'active',
    enrollment_confirmed: confirmed,
    contested: false,
    overdue: false,
    grace_read_only: false,
    reconfirm_deadline_at: confirmed ? 1_760_000_000 : null,
  } as GarnetGrant;
}

function prsn(): GuardedPrsn {
  return {
    account_id: 'a-1',
    handle: HANDLE,
    status: 'active',
    prsn_sharing_capability: 'read_write',
  } as GuardedPrsn;
}

function broker(): GarnetBroker {
  return { broker_id: 'b-1', provisioned_at: 1_750_000_000 };
}

// CONTROL: the harness itself. This config exists because the plain node setup
// silently runs Svelte's SERVER build, where $effect.root never executes its body
// and every reactive assertion vacuously "passes" its setup — proven when this
// exact control FAILED under environment:'node' (see vitest.runes.config.ts). If
// this control ever reddens, fix the harness before reading the test below.
test('control: $effect.root runs its body synchronously and $derived tracks $state', () => {
  let ran = false;
  let seen = -1;
  const cleanup = $effect.root(() => {
    ran = true;
    let n = $state(1);
    const twice = $derived(n * 2);
    $effect(() => {
      seen = twice;
    });
    n = 21;
  });
  flushSync();
  expect(ran).toBe(true);
  expect(seen).toBe(42);
  cleanup();
});

test('the wizard driveStep seam advances to authorized when a hot-poll flips enrollment_confirmed', async () => {
  vi.useFakeTimers();
  try {
    // The "server": one mutable flag stands in for the agent's signed pickup.
    let confirmedOnServer = false;
    const api = {
      listGarnetGrants: async () => ({ grants: [grant(confirmedOnServer)] }),
      listPrsns: async () => ({ prsns: [prsn()] }),
      listGarnetBrokers: async () => ({ brokers: [broker()] }),
    };
    const store = new GarnetStore({ api, gateway: {} } as unknown as AccountDeps);

    // Replicate confirm/+page.svelte:75–88 exactly — including the store living
    // inside `$state`, which is part of the composition under test. (A ref object
    // rather than a bare local: TS's control-flow analysis cannot see the effect
    // callback run, so a plain `let` narrows to null at the assertions.)
    const seen: { step: DriveSetupStep | null } = { step: null };
    const cleanup = $effect.root(() => {
      let gs = $state<GarnetStore | null>(null);
      gs = store;
      void gs.init();
      const driveStep = $derived(
        gs && !gs.loading ? driveSetupStep(HANDLE, gs.hasBroker, gs.grants, gs.prsns) : null,
      );
      $effect(() => {
        seen.step = driveStep;
      });
    });
    flushSync();

    // init()'s Promise.all resolves on microtasks; drain them, then run effects.
    await flushMicrotasks();
    flushSync();
    expect(seen.step?.kind).toBe('pickup_wait'); // the wait step, correctly

    // The agent connects: the next hot-poll tick (HOT_POLL_MS = 10s) reads the
    // confirmed grant. This is the moment S165 watched fail on the real page —
    // and the seam, tested in isolation, handles it correctly.
    confirmedOnServer = true;
    await vi.advanceTimersByTimeAsync(10_000);
    await flushMicrotasks();
    flushSync();
    expect(seen.step?.kind).toBe('authorized');

    cleanup();
  } finally {
    vi.useRealTimers();
  }
});
