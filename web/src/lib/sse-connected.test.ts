// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// bug190 — `connected` closes the gap our liveness poll cannot see.
//
// The poll (bug202) only acts on readyState CLOSED, and `scheduleReconnect`
// refreshes on that path. A TRANSIENT drop recovered by the browser's OWN retry
// never reaches CLOSED — so before this fix nothing refreshed and the view kept
// a silent gap. `connected` is the only signal that recovery happened.
//
// ⚠ These tests pin BOTH directions, because the first-connect skip is the part
// a future edit is most likely to "simplify" away in either direction: dropping
// the skip (redundant refresh on every page load) or dropping the listener
// (the gap returns, invisibly).
import { describe, it, expect } from 'vitest';
import { makeConnectedHandler } from './browser.svelte';

describe('bug190: the `connected` listener', () => {
  it('does NOT refresh on the FIRST connect — the page just loaded its listing', () => {
    let refreshes = 0;
    const onConnected = makeConnectedHandler(() => refreshes++);
    onConnected();
    expect(refreshes).toBe(0);
  });

  it('DOES refresh on a re-connect — the native-retry path that the poll cannot see', () => {
    let refreshes = 0;
    const onConnected = makeConnectedHandler(() => refreshes++);
    onConnected(); // initial
    onConnected(); // browser's own retry re-fires on the SAME EventSource
    expect(refreshes).toBe(1);
  });

  it('refreshes once per subsequent reconnect, not cumulatively', () => {
    let refreshes = 0;
    const onConnected = makeConnectedHandler(() => refreshes++);
    onConnected();
    onConnected();
    onConnected();
    expect(refreshes).toBe(2);
  });

  it('a NEW EventSource starts fresh, so our own reconnect does not double-refresh', () => {
    // `scheduleReconnect` already calls scheduleRefresh() and then builds a new
    // EventSource; that instance's first `connected` must be skipped or the
    // reconnect path refreshes twice.
    let refreshes = 0;
    const first = makeConnectedHandler(() => refreshes++);
    first();
    first(); // a retry on the old instance
    const second = makeConnectedHandler(() => refreshes++); // our reconnect
    second();
    expect(refreshes).toBe(1);
  });
});
