// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

import { describe, expect, it } from 'vitest';
import { shouldReconnectStream } from './browser.svelte';

// bug202 — the liveness poll's decision, pinned.
//
// ⛔ READ THIS BEFORE TRUSTING A GREEN RUN. These tests CANNOT catch the defect
// they were written alongside. The v0.5.43 fix was inert because a real Firefox
// never fires `onerror` on the download-abort path — and a stub fires whatever it
// is told to, so a unit test would have sailed past it. What is pinned here is the
// RULE (which readyState reconnects); the WIRING closes only on observation
// against deployed staging, on Firefox (bug202 §5). ROOTS §B-5.8: a control
// catches only the defects whose preconditions it reproduces, and this one
// reproduces none of them.
//
// What it does earn: the `!== OPEN` substitution is the plausible future edit, and
// it would leave the page holding two streams — the browser's native retry plus
// ours. That failure is silent and this is the cheapest place to make it loud.
describe('shouldReconnectStream (bug202)', () => {
  // Named locally rather than read off EventSource: the vitest environment is
  // `node`, where EventSource does not exist. Values are the WHATWG constants.
  const CONNECTING = 0;
  const OPEN = 1;
  const CLOSED = 2;

  it('reconnects on CLOSED — the state a download-aborted stream lands in silently', () => {
    expect(shouldReconnectStream(CLOSED)).toBe(true);
  });

  it('leaves CONNECTING alone — the browser is already retrying and we must not race it', () => {
    expect(shouldReconnectStream(CONNECTING)).toBe(false);
  });

  it('leaves OPEN alone', () => {
    expect(shouldReconnectStream(OPEN)).toBe(false);
  });

  // The mutation this file exists for, written as its own case so the intent
  // survives: `readyState !== OPEN` passes the CLOSED test and fails this one.
  it('is CLOSED-specific, not merely not-OPEN', () => {
    expect(shouldReconnectStream(CONNECTING)).toBe(false);
    expect(shouldReconnectStream(CLOSED)).toBe(true);
  });
});
