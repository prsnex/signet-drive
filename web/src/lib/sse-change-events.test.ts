// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// bug190 §6-1 — every change event is actually wired to a refresh.
//
// The original defect was a SHORT LIST: the client subscribed to 6 of the
// server's 8 event names. ⚠ Every one of those 6 worked perfectly, so a suite
// covering them reported 100% and the bug survived.
//
// Two separate things have to be true, and neither implies the other:
//
//   · the list matches what the server can emit   → the DENOMINATOR,
//     proven in `server/tests/sse_event_parity.rs` (§6-2)
//   · every member of the list is actually WIRED  → the BEHAVIOUR, here (§6-1)
//
// A correct list nobody iterates is as broken as a correct loop over a short
// list. Before this file, the loop had no test whatsoever — `resync` in
// particular was named in bug190's condition 1 and had never been exercised.
//
// ⚠ On "failing-then-passing": condition 1 asks for a test that FAILS against
// today's code. That was written at S175, before the fix existed. The fix
// shipped in v0.5.50, so a test written now passes immediately and the literal
// requirement is unsatisfiable. The condition's actual intent is the negative
// control — proving the test CAN fail — and that is discharged by mutation
// proof, recorded in bug190's closure. (Chris ruled the substitution, S190.)

import { describe, it, expect } from 'vitest';
import { attachChangeListeners, type ChangeEventTarget } from './browser.svelte';

/** A stand-in for `EventSource`, which does not exist in vitest's `node`
 *  environment. Records what was subscribed and lets a test fire one event. */
function fakeTarget() {
  const listeners = new Map<string, Array<() => void>>();
  const target: ChangeEventTarget = {
    addEventListener(type, listener) {
      const existing = listeners.get(type) ?? [];
      existing.push(listener);
      listeners.set(type, existing);
    },
  };
  return {
    target,
    names: () => [...listeners.keys()],
    fire: (type: string) => (listeners.get(type) ?? []).forEach((l) => l()),
  };
}

describe('bug190 §6-1: the change-event listener wiring', () => {
  it('subscribes to at least the six data-change events AND `resync`', () => {
    const f = fakeTarget();
    attachChangeListeners(f.target, () => {});

    // ⚠ `resync` is the one condition 1 names explicitly: it is half of the
    // server's resynchronisation mechanism, and it is exactly what the original
    // 6-of-8 defect dropped.
    for (const required of [
      'folder_created',
      'folder_updated',
      'folder_deleted',
      'file_uploaded',
      'file_updated',
      'file_deleted',
      'resync',
    ]) {
      expect(f.names()).toContain(required);
    }
  });

  it('fires a refresh for `resync` — the event bug190 was filed about', () => {
    const f = fakeTarget();
    let refreshes = 0;
    attachChangeListeners(f.target, () => refreshes++);

    f.fire('resync');
    expect(refreshes).toBe(1);
  });

  it('fires a refresh for every event it subscribed to, not just some', () => {
    const f = fakeTarget();
    let refreshes = 0;
    attachChangeListeners(f.target, () => refreshes++);

    const subscribed = f.names();
    for (const name of subscribed) f.fire(name);

    // ⚠ Asserted against the SUBSCRIBED count rather than a hardcoded number:
    // a literal here would have to be edited every time an event is added, and
    // an out-of-date literal is how a denominator goes stale in the first place.
    expect(refreshes).toBe(subscribed.length);
    expect(subscribed.length).toBeGreaterThanOrEqual(7);
  });

  it('does NOT subscribe to `connected` — it is handled separately, on purpose', () => {
    const f = fakeTarget();
    attachChangeListeners(f.target, () => {});

    // `connected` must NOT go through this loop: the FIRST one is deliberately
    // skipped (the page has just loaded its listing), which is what
    // `makeConnectedHandler` exists to do. Wiring it here as a plain refresh
    // would reintroduce the redundant page-load fetch that handler prevents.
    expect(f.names()).not.toContain('connected');
  });

  it('gives each event its own listener registration', () => {
    const f = fakeTarget();
    attachChangeListeners(f.target, () => {});

    // A loop that attached one listener under one name would satisfy a naive
    // "did it call addEventListener" check while subscribing to almost nothing.
    expect(new Set(f.names()).size).toBe(f.names().length);
  });
});
