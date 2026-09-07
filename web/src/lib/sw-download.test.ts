// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
/* bug193 / Download-Loop-Rewrite v03 §6-4: the PULL-DRIVEN INVARIANT's mutation
 * test. The invariant: supply crosses the page→SW boundary only on the SW's own
 * pull — a push anywhere recreates bug179 inside the SW (measured: the S176
 * spike's first pump queued 2 GiB in Safari's SW and the worker was killed).
 *
 * The crisp, timing-free form of the invariant: **chunks received may never
 * exceed pulls issued.** The correct supply (PumpSupply) must satisfy it; the
 * push-mode fixture below — the exact defect shape the spike measured — must
 * VIOLATE it. An arm that cannot fail is theatre, so both directions run. */
import { describe, expect, it, vi } from 'vitest';

import {
  DownloadCancelledError,
  PendingRegistry,
  PumpSupply,
  TEST_ONLY_disableKeepalive,
  createPumpReceiverStream,
  openSwStreamedSink,
} from './sw-download';

/** Deliver pending MessagePort messages (ports deliver on macrotasks).
 *
 *  ⚠ `rounds` counts MACROTASK TURNS, not wall-clock — do NOT "fix" this into a
 *  sleep. That distinction is what makes the bug198 negative-control arm an
 *  EXHAUSTED-QUEUE absence proof rather than a timing bet: the only timer in that
 *  fixture is the stub's single `setTimeout(0)` delivering `dl-ready`, which fires
 *  in round 1. After it there is no event source left, so "still pending after N
 *  turns" means the promise cannot settle, not that we did not wait long enough
 *  (Gus, S178). */
async function settle(rounds = 20): Promise<void> {
  for (let i = 0; i < rounds; i++) await new Promise((r) => setTimeout(r, 0));
}

/** The SW side's contract, reduced to the invariant counter: it issues pulls
 *  one at a time and records every chunk arrival against the credit it issued. */
class FakeSwConsumer {
  pullsIssued = 0;
  chunksReceived = 0;
  /** Arrivals that exceeded issued credit — the invariant's violation counter. */
  overdeliveries = 0;
  ended = false;

  constructor(private readonly port: MessagePort) {
    port.onmessage = (m: MessageEvent) => {
      const d = m.data as { type?: string };
      if (d?.type === 'chunk') {
        this.chunksReceived += 1;
        if (this.chunksReceived > this.pullsIssued) this.overdeliveries += 1;
      } else if (d?.type === 'end' || d?.type === 'abort') {
        this.ended = true;
      }
    };
  }

  pull(): void {
    this.pullsIssued += 1;
    this.port.postMessage({ type: 'pull' });
  }
}

describe('the pull-driven supply invariant (v03 §6-4)', () => {
  it('PumpSupply crosses exactly one chunk per pull — never ahead of credit', async () => {
    const channel = new MessageChannel();
    const consumer = new FakeSwConsumer(channel.port2);
    const supply = new PumpSupply(channel.port1);

    // Five writes queue page-side; nothing may cross before a pull.
    const writes = [1, 2, 3, 4, 5].map((b) => supply.write(new Uint8Array([b])));
    await settle();
    expect(consumer.chunksReceived).toBe(0);

    for (let i = 1; i <= 5; i++) {
      consumer.pull();
      await settle();
      expect(consumer.chunksReceived).toBe(i);
      expect(consumer.overdeliveries).toBe(0);
    }
    await Promise.all(writes); // every write resolved by its own crossing
    await supply.end();
    await settle();
    expect(consumer.ended).toBe(true);
    expect(consumer.overdeliveries).toBe(0);
  });

  // F-A (Gus, complete-branch review — SERIOUS): a terminal arriving while no
  // pull is outstanding is the ORDINARY end-of-transfer state (SW queue full,
  // download manager draining). The first version silently discarded it — the
  // stream never closed and the download hung at 100% on Safari. The inbox fix
  // must honor a stashed terminal on the NEXT pull, without posting a 'pull'
  // that a departed page will never answer.
  it('F-A: an END sent with no pull outstanding still closes the stream', async () => {
    const channel = new MessageChannel();
    const stream = createPumpReceiverStream(channel.port1);
    const supply = channel.port2;

    // The page's exact end-of-transfer shape: last chunk answered, then 'end'
    // posted UNSOLICITED, then the page handler goes away entirely.
    const reader = stream.getReader();
    const first = reader.read(); // issues pull #1
    await settle();
    const chunk = new Uint8Array([7]).buffer;
    supply.postMessage({ type: 'chunk', buf: chunk }, [chunk]);
    await settle();
    supply.postMessage({ type: 'end' }); // no pull outstanding for this one
    supply.onmessage = null; // the page is gone; nothing will answer a 'pull'
    await settle();

    expect((await first).value).toEqual(new Uint8Array([7]));
    const done = await reader.read();
    expect(done.done).toBe(true); // hung forever before the inbox fix
  });

  it('F-A: an ABORT sent with no pull outstanding still errors the stream promptly', async () => {
    const channel = new MessageChannel();
    const stream = createPumpReceiverStream(channel.port1);
    channel.port2.postMessage({ type: 'abort' }); // before ANY pull exists
    await settle();
    const reader = stream.getReader();
    await expect(reader.read()).rejects.toThrow('aborted');
  });

  // F-B (Gus — MODERATE): downstream cancel must STOP the producer. A cancelled
  // user's remaining chunks must not be fetched and decrypted into a void.
  it('F-B: after downstream cancel, write() rejects with the typed cancelled error', async () => {
    const channel = new MessageChannel();
    const supply = new PumpSupply(channel.port1);
    const parked = supply.write(new Uint8Array([1])); // no credit: parks
    // Attach the handler BEFORE the rejection can fire — the assertion itself
    // is the catch, so the rejection is never unhandled.
    const parkedRejects = expect(parked).rejects.toBeInstanceOf(DownloadCancelledError);
    await settle();
    channel.port2.postMessage({ type: 'cancel' });
    await settle();
    await parkedRejects;
    await expect(supply.write(new Uint8Array([2]))).rejects.toBeInstanceOf(DownloadCancelledError);
  });

  it('MUTATION: a push-mode supply (the spike-measured defect) violates the invariant', async () => {
    const channel = new MessageChannel();
    const consumer = new FakeSwConsumer(channel.port2);

    // The reverted shape: fire-and-forget, no credit gate — what the S176
    // spike's first pump did, and what killed Safari's SW under 2 GiB.
    for (const b of [1, 2, 3, 4, 5]) {
      const buf = new Uint8Array([b]).buffer;
      channel.port1.postMessage({ type: 'chunk', buf }, [buf]);
    }
    await settle();

    expect(consumer.chunksReceived).toBe(5);
    // The assertion the correct supply passes MUST fail here — the arm can fail.
    expect(consumer.overdeliveries).toBeGreaterThan(0);
  });
});

/* bug195 (j): the SW's pending-download registry reaps on SILENCE, never on AGE.
 *
 * The rule this replaced swept on registration time, and it regressed a case the
 * S176 spike had MEASURED: Safari gates the first download per site behind an
 * Allow prompt a user can leave buried for minutes, and such a download resumes
 * cleanly when approved. An age sweep evicts the entry at the TTL, so the approval
 * 404s — an honest download turned into a silent failure by our own housekeeping.
 *
 * Both directions run, because an arm that cannot fail is theatre: the live case
 * must SURVIVE, the abandoned case must be REAPED, and the third arm replays the
 * old age-based predicate over the identical timeline and must FAIL the live case
 * — proving the fix is tested, not asserted. */
describe('PendingRegistry: reap on silence, not age (bug195 (j))', () => {
  const TTL = 120_000;
  const KA = 4000;
  const PARKED_MS = 300_000; // five minutes behind a buried Allow prompt

  function fakeStream() {
    let cancelled = false;
    return {
      handle: {
        cancel: async () => {
          cancelled = true;
        },
      },
      cancelled: () => cancelled,
    };
  }

  function entryFor(stream: { cancel(): Promise<void> }) {
    return { stream, filename: 'parked.bin', plaintextBytes: 1024 };
  }

  it('KEEPS a parked-but-live entry indefinitely — the spike-measured case', () => {
    const reg = new PendingRegistry<{ cancel(): Promise<void> }>(TTL);
    const s = fakeStream();
    reg.register('parked', entryFor(s.handle), 0);

    // The page is alive the whole time and pings every KEEPALIVE_MS.
    for (let t = KA; t <= PARKED_MS; t += KA) {
      reg.touch('parked', t);
      reg.sweep(t);
    }

    expect(reg.size).toBe(1);
    expect(s.cancelled()).toBe(false);
    // And the approval, five minutes later, still finds its stream.
    expect(reg.take('parked')).toBeDefined();
  });

  it('REAPS an entry whose page has gone silent — the leak the TTL exists for', () => {
    const reg = new PendingRegistry<{ cancel(): Promise<void> }>(TTL);
    const s = fakeStream();
    reg.register('abandoned', entryFor(s.handle), 0);

    reg.sweep(TTL); // exactly at the boundary: not yet
    expect(reg.size).toBe(1);

    reg.sweep(TTL + 1);
    expect(reg.size).toBe(0);
    expect(s.cancelled()).toBe(true);
    expect(reg.take('abandoned')).toBeUndefined();
  });

  it('NEGATIVE CONTROL: the old age-based rule fails the parked case', () => {
    // The predicate as it was written, replayed over the identical timeline. If
    // this ever stops evicting, the control has gone vacuous and the test above
    // is no longer evidence of anything.
    const registeredAt = 0;
    let evictedByAge = false;
    for (let t = KA; t <= PARKED_MS; t += KA) {
      if (t - registeredAt > TTL) evictedByAge = true;
    }
    expect(evictedByAge).toBe(true);
  });

  it('touch() on an unknown id is a no-op, not a resurrection', () => {
    const reg = new PendingRegistry<{ cancel(): Promise<void> }>(TTL);
    reg.touch('never-registered', 1000);
    expect(reg.size).toBe(0);
  });

  it('take() removes the entry — one registration, one response', () => {
    const reg = new PendingRegistry<{ cancel(): Promise<void> }>(TTL);
    reg.register('once', entryFor(fakeStream().handle), 0);
    expect(reg.take('once')).toBeDefined();
    expect(reg.take('once')).toBeUndefined();
    expect(reg.size).toBe(0);
  });
});

/* ⛔ bug198 (S178): THE NAVIGATION FENCE — asserted against the REAL function.
 *
 * The defect: `trigger()` starts a real top-level navigation, and a browser
 * beginning one CANCELS the page's in-flight fetches before dispatch. The caller's
 * chunk loop starts the instant `openSwStreamedSink` resolves, so resolving early
 * fires the first fetches into that window, where they die. Measured on staging:
 * failures == min(chunks, n); one 496 MB download died of it.
 *
 * ⚠⚠ THIS CANNOT LIVE IN THE E2E. With the fence removed the e2e still passes 5/5
 * with zero storage failures — the race does not reproduce on localhost, because
 * the worker answers the trigger with no network in the path. A control that
 * cannot fail against its own defect is theatre.
 *
 * ⚠ AND IT MUST DRIVE THE REAL `openSwStreamedSink`, not a model of it. A fixture
 * that re-implements the ordering asserts the author's belief about the code, not
 * the code — the proxy-vs-property failure (Gus, S177). Everything below stubs the
 * platform and calls the shipped function.
 *
 * THE INVARIANT, timing-free and therefore durable: **the sink is not handed to the
 * caller until `dl-consumed` has arrived.** The latency-dependent symptom is
 * downstream of it; this holds even where the race never fires.
 */
describe('the navigation fence (bug198) — against the real openSwStreamedSink', () => {
  /** Stub exactly the platform surface the function touches, and record the trigger. */
  function installFakePlatform() {
    const listeners = new Set<(e: MessageEvent) => void>();
    const sent: Record<string, unknown>[] = [];
    const state = { navigatedTo: null as string | null };

    const controller = {
      postMessage: (data: Record<string, unknown>) => {
        sent.push(data);
        // The worker answers `dl-pump` with `dl-ready` on a later task, as a real one does.
        if (data.type === 'dl-pump') {
          setTimeout(
            () =>
              listeners.forEach((l) =>
                l({ data: { type: 'dl-ready', id: data.id, mode: 'pump' } } as MessageEvent),
              ),
            0,
          );
        }
      },
    };
    // ⚠ `navigator` is a getter-only global in Node — plain assignment throws.
    // vi.stubGlobal is the supported route and unstubs cleanly.
    vi.stubGlobal('navigator', {
      serviceWorker: {
        // ⚠ bug203: the page resolves its worker via `getRegistration()`, NOT
        // `controller` — an uncontrolled page (Chrome after a hard reload) still
        // has a live registration, and nothing the download path does needs the
        // page to be controlled.
        //
        // ⭐ `controller` is DELIBERATELY ABSENT from this fake, and its absence is
        // the control: a regression that goes back to reading
        // `navigator.serviceWorker.controller` gets `undefined` here, falls to the
        // capped fallback, and the fence tests below FAIL. Leaving it on the fake
        // would let exactly that regression pass silently — the fake would stop
        // discriminating between the two contracts.
        getRegistration: () => Promise.resolve({ active: controller }),
        addEventListener: (_t: string, l: (e: MessageEvent) => void) => listeners.add(l),
        removeEventListener: (_t: string, l: (e: MessageEvent) => void) => listeners.delete(l),
      },
    });
    // `location.assign` IS the trigger under test — record it instead of navigating.
    vi.stubGlobal('location', {
      assign: (u: string) => {
        state.navigatedTo = u;
      },
    });
    return {
      state,
      sent,
      /** the worker's fetch handler CLAIMING the entry — i.e. navigation resolved */
      sendConsumed: () => {
        const id = (sent.find((m) => m.type === 'dl-pump')?.id ?? '') as string;
        listeners.forEach((l) => l({ data: { type: 'dl-consumed', id } } as MessageEvent));
      },
      restore: () => vi.unstubAllGlobals(),
    };
  }

  it('the sink is NOT produced until dl-consumed arrives — the fence itself', async () => {
    TEST_ONLY_disableKeepalive.value = true;
    const env = installFakePlatform();
    try {
      let settled = false;
      const opening = openSwStreamedSink('probe.bin', 1024).then((s) => {
        settled = true;
        return s;
      });

      await settle();

      // The navigation has started: we are inside the cancellation window.
      expect(env.state.navigatedTo, 'trigger() must have navigated by now').toMatch(
        /^\/__signet_dl\//,
      );
      expect(
        settled,
        'the sink must NOT be available while the navigation is unresolved — a caller given ' +
          'it here starts fetching into the cancellation window, which is bug198',
      ).toBe(false);

      env.sendConsumed();
      const sink = await opening;
      expect(settled).toBe(true);
      expect(sink, 'a sink is still produced once the worker claims the entry').toBeTruthy();
    } finally {
      env.restore();
      TEST_ONLY_disableKeepalive.value = false;
    }
  });

  it('NEGATIVE CONTROL: the fence is what holds it — without dl-consumed it never settles', async () => {
    TEST_ONLY_disableKeepalive.value = true;
    const env = installFakePlatform();
    try {
      let settled = false;
      void openSwStreamedSink('probe2.bin', 1024).then(() => {
        settled = true;
      });

      // Ready arrives and the trigger fires, but the entry is never claimed.
      await settle(40);
      expect(env.state.navigatedTo).toMatch(/^\/__signet_dl\//);
      expect(
        settled,
        'if this reads TRUE the fence is gone and the caller is free to fetch inside the ' +
          'cancellation window — the exact pre-fix behaviour this arm exists to catch',
      ).toBe(false);
    } finally {
      env.restore();
      TEST_ONLY_disableKeepalive.value = false;
    }
  });
});
