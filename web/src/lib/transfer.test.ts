// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// bug047: the transfer-resilience engine — pure policy tests (no XHR, no DOM).

import { describe, expect, it } from 'vitest';

import {
  RelayBusyError,
  DEFAULT_GOVERNOR_KNOBS,
  DEFAULT_KNOBS,
  MULTIPART_CHUNK_OVERHEAD,
  StallError,
  TransferGovernor,
  TransferCancelledError,
  TransferExhaustedError,
  backoffMs,
  indicatesRateOverestimate,
  isRetryable,
  governorKnobsFromResponse,
  knobsFromResponse,
  maxPlaintextPerPart,
  transferWithRetry,
} from './transfer';

const noSleep = () => Promise.resolve();

describe('knobsFromResponse', () => {
  it('reads served values', () => {
    expect(knobsFromResponse({ part_retry_attempts: 7 })).toEqual({ attempts: 7 });
  });

  it('ignores stall_timeout_seconds — this surface does not use it (W2)', () => {
    // The field is still served (the CLI uses it as its rate-free gap). Until
    // S127 the web parsed and stored it and then never read it, so an operator
    // tuning it for web uploads got no effect and no error. Pinned so it cannot
    // silently reappear as a decoy.
    const knobs = knobsFromResponse({
      part_retry_attempts: 7,
      stall_timeout_seconds: 30,
    } as Parameters<typeof knobsFromResponse>[0] & { stall_timeout_seconds: number });
    expect(knobs).toEqual({ attempts: 7 });
    expect('stallTimeoutMs' in knobs).toBe(false);
  });

  it('defaults when absent (an older server)', () => {
    expect(knobsFromResponse({})).toEqual(DEFAULT_KNOBS);
  });

  it('clamps corrupt values to the schema bounds', () => {
    // A poisoned response can neither disable stall-detection nor spin forever.
    const corrupt = knobsFromResponse({ part_retry_attempts: 0 });
    expect(corrupt.attempts).toBe(1);
  });
});

describe('indicatesRateOverestimate (W1 — cross-surface parity with the CLI)', () => {
  // The CLI relaxes its per-attempt ceiling ONLY on `transfer_stalled`, with the
  // reasoning that a 5xx is the store's problem and says nothing about our
  // bandwidth. The web penalised its rate estimate on EVERY retry, 5xx included —
  // the same decision reasoned two ways on two surfaces, kept in sync by nothing.
  // Direction was safe (over-conservative, never a cliff), but it drew a conclusion
  // the evidence did not support.

  it('a stall DOES indict the estimate', () => {
    expect(indicatesRateOverestimate(new StallError('no progress'))).toBe(true);
  });

  it('a 5xx does NOT — storage hiccuped; that is not evidence about our rate', () => {
    for (const status of [500, 502, 503, 504]) {
      expect(indicatesRateOverestimate({ status })).toBe(false);
    }
  });

  it('a network-level failure with no HTTP response DOES', () => {
    // status 0 = the transport failed outright; indistinguishable from a dead flow.
    expect(indicatesRateOverestimate({ status: 0 })).toBe(true);
  });

  it('is strictly narrower than isRetryable — retrying and re-estimating differ', () => {
    // A 5xx is retryable but must not move the estimate. If these two ever agree
    // on 5xx again, the W1 divergence has returned.
    expect(isRetryable({ status: 503 })).toBe(true);
    expect(indicatesRateOverestimate({ status: 503 })).toBe(false);
  });

  // ── bug220: a relay-detected stall is 408, and BOTH predicates must accept it ──

  it('bug220: a 408 relay stall is retryable — the server asked for a retry', () => {
    // The relay returns 408 `part_transfer_stalled` when a part made no progress.
    // Before bug220 this was 400, which this predicate treats as definitive: the
    // response instructed a retry in a status class that forbade one, so two
    // stalled parts abandoned an entire upload plus every part already sent.
    expect(isRetryable({ status: 408 })).toBe(true);
  });

  it('bug220: a 408 relay stall DOES indict the estimate — same event as StallError', () => {
    // It is the same physical condition as a locally-detected StallError, just
    // noticed at the far end. The CLI relaxes on `transfer_stalled`; if this
    // returns false while isRetryable returns true, the W1 web/CLI drift is back.
    expect(indicatesRateOverestimate({ status: 408 })).toBe(true);
    expect(indicatesRateOverestimate(new StallError('no progress'))).toBe(true);
  });

  it('bug220 NEGATIVE CONTROL: other 4xx stay definitive — 408 only, never "any 4xx"', () => {
    // This is the arm that proves the fix did not simply make 4xx retryable.
    // A definitive 4xx from storage (an expired presigned URL) needs FRESH URLs,
    // which is resume's job — retrying it burns the budget on a request that can
    // never succeed.
    for (const status of [400, 401, 403, 404, 409, 413]) {
      expect(isRetryable({ status })).toBe(false);
      expect(indicatesRateOverestimate({ status })).toBe(false);
    }
  });

  it('bug220 NEGATIVE CONTROL: 503 keeps its own disposition, unchanged', () => {
    // A stall must never be routed to 503: RelayBusyError deliberately does NOT
    // spend the part-retry budget (relay review S2), and a stall must. If a
    // future change maps stalls to 503, this pairing is what catches it.
    expect(isRetryable({ status: 503 })).toBe(true);
    expect(indicatesRateOverestimate({ status: 503 })).toBe(false);
  });
});

describe('backoffMs', () => {
  it('is immediate for the first retry (path-probabilistic, not server load)', () => {
    expect(backoffMs(1)).toBe(0);
    expect(backoffMs(2)).toBe(0);
  });

  it('full-jitters over a growing cap, never past 10s', () => {
    // random=1.0 gives the cap itself (exclusive bound irrelevant for the test).
    expect(backoffMs(3, () => 0.999_999)).toBeLessThanOrEqual(1000);
    expect(backoffMs(4, () => 0.999_999)).toBeLessThanOrEqual(2000);
    expect(backoffMs(5, () => 0.999_999)).toBeLessThanOrEqual(4000);
    expect(backoffMs(6, () => 0.999_999)).toBeLessThanOrEqual(8000);
    expect(backoffMs(12, () => 0.999_999)).toBeLessThanOrEqual(10_000);
    // Full jitter reaches all the way down to 0.
    expect(backoffMs(6, () => 0)).toBe(0);
  });
});

describe('isRetryable', () => {
  it('retries stalls and network-level failures', () => {
    expect(isRetryable(new StallError('no progress'))).toBe(true);
    expect(isRetryable({ status: 0 })).toBe(true);
    expect(isRetryable({ status: 503 })).toBe(true);
    expect(isRetryable(new TypeError('failed to fetch'))).toBe(true);
  });

  it('does not retry a definitive storage 4xx (expired URL → resume, not retry)', () => {
    expect(isRetryable({ status: 403 })).toBe(false);
    expect(isRetryable({ status: 404 })).toBe(false);
  });
});

describe('transferWithRetry', () => {
  it('recovers when a later attempt succeeds, surfacing each retry', async () => {
    const retries: number[] = [];
    let calls = 0;
    const result = await transferWithRetry(
      async () => {
        calls += 1;
        if (calls < 3) throw new StallError('stalled');
        return 'etag-3';
      },
      { attempts: 4 },
      'upload',
      { sleep: noSleep, onRetry: (attempt) => retries.push(attempt) },
    );
    expect(result).toBe('etag-3');
    expect(calls).toBe(3);
    expect(retries).toEqual([2, 3]);
  });

  it('exhausts a dead window into TransferExhaustedError (the resumable pause signal)', async () => {
    let calls = 0;
    await expect(
      transferWithRetry(
        async () => {
          calls += 1;
          throw new StallError('stalled');
        },
        { attempts: 3 },
        'upload',
        { sleep: noSleep },
      ),
    ).rejects.toBeInstanceOf(TransferExhaustedError);
    expect(calls).toBe(3);
  });

  it('propagates a non-retryable failure immediately (no attempt burn)', async () => {
    let calls = 0;
    await expect(
      transferWithRetry(
        async () => {
          calls += 1;
          throw { status: 403 };
        },
        { attempts: 5 },
        'upload',
        { sleep: noSleep },
      ),
    ).rejects.toEqual({ status: 403 });
    expect(calls).toBe(1);
  });

  it('a relay 503 waits Retry-After and does NOT spend the budget (v04 S2)', async () => {
    const sleeps: number[] = [];
    const busySeen: number[] = [];
    let calls = 0;
    const result = await transferWithRetry(
      async () => {
        calls += 1;
        if (calls <= 2) throw new RelayBusyError(3);
        return 'etag-after-busy';
      },
      // attempts=1: ANY budget spend on the busy responses would exhaust —
      // success proves busy is budget-exempt.
      { attempts: 1 },
      'upload',
      {
        sleep: async (ms) => {
          sleeps.push(ms);
        },
        onBusy: (s) => busySeen.push(s),
        onRetry: () => {
          throw new Error('busy waits must not surface as retries');
        },
      },
    );
    expect(result).toBe('etag-after-busy');
    expect(calls).toBe(3);
    // Each busy wait slept the SERVER's Retry-After (already jittered there),
    // not the client backoff curve.
    expect(sleeps).toEqual([3000, 3000]);
    expect(busySeen).toEqual([3, 3]);
  });

  it('permanent saturation converges to the honest pause: past the busy cap, 503s spend budget', async () => {
    let calls = 0;
    await expect(
      transferWithRetry(
        async () => {
          calls += 1;
          // 60 s (the per-wait clamp) per busy; the 10-minute cumulative cap
          // admits 10 free waits, after which each 503 costs an attempt.
          throw new RelayBusyError(60);
        },
        { attempts: 2 },
        'upload',
        { sleep: noSleep },
      ),
    ).rejects.toBeInstanceOf(TransferExhaustedError);
    // 10 budget-exempt busy waits + attempts(2) counted ones.
    expect(calls).toBe(12);
  });

  it('a busy relay does not indict the rate estimate', () => {
    expect(indicatesRateOverestimate(new RelayBusyError(4))).toBe(false);
  });

  it('honors attempts=1 (no retry at all)', async () => {
    let calls = 0;
    await expect(
      transferWithRetry(
        async () => {
          calls += 1;
          throw new StallError('stalled');
        },
        { attempts: 1 },
        'upload',
        { sleep: noSleep },
      ),
    ).rejects.toBeInstanceOf(TransferExhaustedError);
    expect(calls).toBe(1);
  });
});

// bug060: the rate governor. Every duration-shaped bound must be DERIVED from a
// measured rate — a fixed number of seconds encodes a minimum bandwidth, which
// is what made every sub-9 Mbps link unable to upload at all.
describe('TransferGovernor (bug060)', () => {
  const MB = 1024 * 1024;

  it('scales the ceiling with bytes rather than using a constant', () => {
    const g = new TransferGovernor();
    g.observePart(4 * MB, 4000); // 1 MB/s
    const small = g.ceilingMs(4 * MB)!;
    const large = g.ceilingMs(32 * MB)!;
    // 8x the bytes => ~8x the ceiling. A fixed constant would make these equal,
    // which is precisely the defect.
    expect(large / small).toBeCloseTo(8, 1);
  });

  it('allows a slower link MORE time for the same part', () => {
    const fast = new TransferGovernor();
    fast.observePart(16 * MB, 2000);
    const slow = new TransferGovernor();
    slow.observePart(16 * MB, 20_000);
    expect(slow.ceilingMs(16 * MB)!).toBeGreaterThan(fast.ceilingMs(16 * MB)!);
  });

  it('widens the allowance after a stall instead of tightening it', () => {
    const g = new TransferGovernor();
    g.observePart(8 * MB, 8000);
    const before = g.ceilingMs(8 * MB)!;
    g.penalizeStall(g.generation);
    // Retreating on the estimate must RELAX the bound — otherwise a stall would
    // make the retry likelier to fail too, and the upload would spiral.
    expect(g.ceilingMs(8 * MB)! / before).toBeCloseTo(2, 1);
  });

  it('drops the estimate entirely once repeated stalls make it incredible', () => {
    const g = new TransferGovernor();
    g.observePart(8 * MB, 8000);
    // Sequential, re-stamped stalls: each is fresh evidence and legitimately
    // halves — the 3a-i de-dup must not dampen a genuinely repeating one.
    for (let i = 0; i < 40; i++) g.penalizeStall(g.generation);
    expect(g.rateEstimate).toBeNull();
    // No estimate means no ceiling — the caller falls back to the absolute
    // backstop rather than inventing a duration.
    expect(g.ceilingMs(8 * MB)).toBeNull();
  });

  it('3a-i: a burst of simultaneous stalls halves exactly once', () => {
    // One link event trips N concurrent parts at once. All N attempts were
    // stamped under the SAME generation; only the first reporter may halve, or
    // a single event costs a 2^-N collapse of the estimate.
    const g = new TransferGovernor();
    g.observePart(8 * MB, 8000); // 1 MB/s
    const before = g.rateEstimate!;
    const stamp = g.generation;
    for (let i = 0; i < 4; i++) g.penalizeStall(stamp); // four parts, one burst
    expect(before / g.rateEstimate!).toBeCloseTo(2, 9);
  });

  it('3a-i: sequential degradations still halve twice', () => {
    // The de-dup removes same-cause duplicates ONLY: an attempt that began
    // AFTER the first halving carries the new stamp, and its stall is fresh
    // evidence.
    const g = new TransferGovernor();
    g.observePart(8 * MB, 8000);
    const before = g.rateEstimate!;
    const first = g.generation;
    g.penalizeStall(first);
    expect(g.generation).not.toBe(first);
    g.penalizeStall(g.generation);
    expect(before / g.rateEstimate!).toBeCloseTo(4, 9);
  });

  it('3a-i: a stale straggler neither penalises nor advances the epoch', () => {
    const g = new TransferGovernor();
    g.observePart(8 * MB, 8000);
    const ancient = g.generation;
    g.penalizeStall(ancient);
    g.penalizeStall(g.generation);
    const settled = g.rateEstimate!;
    const epoch = g.generation;
    g.penalizeStall(ancient); // reports a link state answered two epochs ago
    expect(g.rateEstimate).toBe(settled);
    expect(g.generation).toBe(epoch);
  });

  it('tracks a changing link without chasing a single sample', () => {
    const g = new TransferGovernor();
    g.observePart(10 * MB, 10_000); // 1 MB/s
    const first = g.rateEstimate!;
    g.observePart(10 * MB, 5000); // 2 MB/s
    const second = g.rateEstimate!;
    expect(second).toBeGreaterThan(first);
    expect(second).toBeLessThan(2 * MB);
  });

  it('sizes parts to the target duration and never below the storage floor', () => {
    const g = new TransferGovernor();
    g.observePart(6 * MB, 8000); // ~0.75 MB/s, the measured Starlink path
    const size = g.partSize(500 * MB, 10_000);
    expect(size).toBeGreaterThanOrEqual(5 * MB);
    expect(size).toBeLessThanOrEqual(64 * MB);
    // Even a dire link must not produce a sub-floor part: object storage rejects
    // those only at completion, after the whole file has been uploaded.
    const dire = new TransferGovernor();
    dire.observePart(1 * MB, 60_000);
    expect(dire.partSize(100 * MB, 10_000)).toBe(5 * MB);
  });

  it('F3-b: the first credible observation REPLACES the bootstrap seed; the second blends', () => {
    // Filed at the v1.0.4 staging test (2026-09-21): a 9 Mbps link's first part
    // blended 0.4 × measured with 0.6 × the 125,000 B/s seed and the panel read
    // ~3.8 Mbps for the first several parts. The seed is a stall-ceiling
    // constant, not a prior about the link (Gus: replace, don't blend).
    const g = new TransferGovernor();
    g.seedBootstrap(125_000);
    expect(g.measured).toBe(false);
    g.observePart(5 * MB, 5000); // 1 MB/s measured
    expect(g.measured).toBe(true);
    expect(g.rateEstimate).toBe(MB); // exactly the observation — no trace of the seed
    // From the second part on, the EWMA tracks without chasing a single sample.
    g.observePart(5 * MB, 2500); // 2 MB/s
    expect(g.rateEstimate!).toBeGreaterThan(MB);
    expect(g.rateEstimate!).toBeLessThan(2 * MB);
    // A seed halved by a stall before any measurement is replaced all the same.
    const stalled = new TransferGovernor();
    stalled.seedBootstrap(125_000);
    stalled.penalizeStall(stalled.generation);
    stalled.observePart(5 * MB, 5000);
    expect(stalled.rateEstimate).toBe(MB);
  });

  it("F1: with nothing measured yet, plans at the FLOOR — a fresh page's first 20 MB file is 4 parts, not 2", () => {
    // The Drive's first file is planned BEFORE the bootstrap seed and before any
    // part has completed, so `rateEst` is null here. It used to fall back to the
    // caller's 16 MiB default: one 16 MiB stream carrying 82% of a 20 MB file,
    // measured 2:10 on the travel link against ~50 s once the rate was known.
    const fresh = new TransferGovernor();
    expect(fresh.rateEstimate).toBeNull();
    const twentyMB = 20_000_000;
    const size = fresh.partSize(twentyMB, 10_000);
    expect(size).toBe(5 * MB);
    expect(Math.ceil(twentyMB / size)).toBe(4);
    // The bound, named: a fresh page's first file of ANY size plans at the floor
    // (a 10 GB first file is ~2,000 parts, under the 10,000 cap).
    expect(fresh.partSize(10 * 1024 * MB, 10_000)).toBe(5 * MB);
    expect(Math.ceil((10 * 1024 * MB) / (5 * MB))).toBeLessThanOrEqual(10_000);
    // And the floor is the served knob, not a literal: a served part_min_bytes
    // of 8 MiB plans 8 MiB parts with nothing measured.
    const served = new TransferGovernor({ ...DEFAULT_GOVERNOR_KNOBS, partMinBytes: 8 * MB });
    expect(served.partSize(twentyMB, 10_000)).toBe(8 * MB);
  });

  it('F1: once a part is measured, sizing follows rate × target seconds again (unchanged behaviour)', () => {
    const g = new TransferGovernor();
    g.observePart(5 * MB, 2000); // 2.5 MiB/s × 10 s = 25 MiB, inside the clamp
    expect(g.partSize(500 * MB, 10_000)).toBe(Math.floor(((5 * MB) / 2000) * 1000 * 10));
  });

  it('F1: with nothing measured, a file too big for the floor still enlarges to fit the part-count ceiling', () => {
    // 100 GB at 5 MiB would be ~20,480 parts; the planner must enlarge from the
    // floor exactly as it enlarges from a measured size.
    const fresh = new TransferGovernor();
    const fileSize = 100 * 1024 * MB;
    const size = fresh.partSize(fileSize, 10_000);
    expect(size).toBeGreaterThan(5 * MB);
    expect(Math.ceil(fileSize / size)).toBeLessThanOrEqual(10_000);
    expect(size + MULTIPART_CHUNK_OVERHEAD).toBeLessThanOrEqual(64 * MB);
  });

  it('F3: `measured` is false until a part completes — the bootstrap seed never counts as a measurement', () => {
    const g = new TransferGovernor();
    expect(g.measured).toBe(false);
    g.seedBootstrap(125_000);
    // The seed is a stall-ceiling constant: the estimate exists, the measurement does not.
    expect(g.rateEstimate).toBe(125_000);
    expect(g.measured).toBe(false);
    // A non-credible observation (below MIN_CREDIBLE_RATE) does not count either.
    g.observePart(10, 60_000);
    expect(g.measured).toBe(false);
    g.observePart(5 * MB, 2000);
    expect(g.measured).toBe(true);
  });

  it('enlarges parts so a huge file still fits the part-count ceiling', () => {
    const g = new TransferGovernor();
    g.observePart(1 * MB, 10_000);
    const fileSize = 100 * 1024 * MB; // 100 GB
    const size = g.partSize(fileSize, 10_000);
    expect(Math.ceil(fileSize / size)).toBeLessThanOrEqual(10_000);
  });

  it('bug192: the clamp lands BELOW the wire limit, never on it', () => {
    // The relay rejects declared wire bytes STRICTLY GREATER than
    // `transfer_part_max_bytes`, and the wire carries plaintext + 34 (envelope
    // overhead). A plaintext clamp AT partMaxBytes therefore produces a part
    // that cannot be sent: 67,108,864 + 34 > 67,108,864 -> 413 at part 1.
    // Observed live at S175 on the second large upload of a page session,
    // once the governor's learned rate pushed `base` past the clamp.
    const g = new TransferGovernor();
    g.observePart(64 * MB, 1000); // 64 MB/s — any fast link; clamp must bind
    const size = g.partSize(10 * 1024 * MB, 10_000);
    expect(size + MULTIPART_CHUNK_OVERHEAD).toBeLessThanOrEqual(64 * MB);
    // And the `needed`-to-fit-maxParts branch must obey the same bound.
    const enlarged = g.partSize(100 * 1024 * MB, 1_700);
    expect(enlarged + MULTIPART_CHUNK_OVERHEAD).toBeLessThanOrEqual(64 * MB);
  });

  it('bug192: maxPlaintextPerPart pins the conversion for every served value', () => {
    // The invariant that keeps the two numbers from drifting apart again:
    // whatever the server serves, plaintext max + overhead <= served wire max.
    for (const served of [5 * MB + 34, 8 * MB, 16 * MB, 64 * MB, 1024 * MB]) {
      expect(maxPlaintextPerPart(served) + MULTIPART_CHUNK_OVERHEAD).toBeLessThanOrEqual(served);
    }
  });

  it('clamps hostile served knobs to the server schema bounds', () => {
    const k = governorKnobsFromResponse({
      governor: {
        ceiling_k_web: 9999,
        target_part_seconds: 0,
        part_min_bytes: 1,
        part_max_bytes: 1,
      },
    });
    expect(k.ceilingK).toBeLessThanOrEqual(20);
    expect(k.targetPartSeconds).toBeGreaterThanOrEqual(2);
    // A corrupt value must never take the part size below the storage floor.
    expect(k.partMinBytes).toBeGreaterThanOrEqual(5 * MB);
    // An absent governor block yields the defaults.
    expect(governorKnobsFromResponse({}).ceilingK).toBe(DEFAULT_GOVERNOR_KNOBS.ceilingK);
  });
});

describe('bug076 — a user cancel is definitive, never retried', () => {
  it('isRetryable REFUSES TransferCancelledError', () => {
    // The whole point: a cancel retried on a fresh connection would resurrect
    // the transfer the user just killed.
    expect(isRetryable(new TransferCancelledError())).toBe(false);
  });

  it('still retries the network-shaped failures it always did (the control)', () => {
    // Without this leg the test above passes for a trivially-broken isRetryable.
    expect(isRetryable(new StallError('stalled'))).toBe(true);
    expect(isRetryable({ status: 0 })).toBe(true);
    expect(isRetryable({ status: 503 })).toBe(true);
  });

  it('transferWithRetry propagates a cancel immediately — one attempt, no backoff', async () => {
    let attempts = 0;
    await expect(
      transferWithRetry(
        () => {
          attempts += 1;
          return Promise.reject(new TransferCancelledError());
        },
        { attempts: 5 },
        'upload',
        { sleep: noSleep },
      ),
    ).rejects.toBeInstanceOf(TransferCancelledError);
    expect(attempts).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// bug209 (S181) — the download attempt budget, against the OBSERVED signature.
//
// ⚠ The mock reproduces what was actually measured on deployed v0.5.44 (Safari,
// transfer trace on), not an invented failure: a bare `TypeError` whose message is
// exactly "Load failed", rejecting effectively instantly.
//
// ⚠⚠ It deliberately does NOT set an error `.cause`. The traces show
// `range-failed {cause: null, ...}`, but that `cause` is OUR `abortCause`
// (`api.ts` — backstop | first-byte | gap | null), not a property of the error.
// `cause: null` means none of our timers fired, i.e. the fetch itself rejected.
// Modelling it on the error object would test a thing that does not exist.
// ---------------------------------------------------------------------------

/** The verbatim S181 failure shape. */
const deadSocketFailure = () => new TypeError('Load failed');

describe('bug209 — the download attempt budget against the S181 signature', () => {
  it('classifies the observed failure as retryable (the budget is really spent)', () => {
    // If this were false the budget would never be consumed and the whole fix
    // would be aimed at the wrong thing. The trace recorded `retryable: true`.
    expect(isRetryable(deadSocketFailure())).toBe(true);
  });

  it('⛔ MUST-FAIL ARM: the OLD compiled budget of 3 EXHAUSTS on the observed pattern', async () => {
    // S181 Run B: the first window's chunks lost attempts 1 and 2 ~1 ms apart and
    // only recovered on attempt 3. This encodes the case one notch worse — the
    // regime the ~42% failure rate came from. ⚠ If someone reverts `attempts` to 3,
    // the recovery test below goes red and this one documents why.
    let calls = 0;
    await expect(
      transferWithRetry(
        async () => {
          calls += 1;
          if (calls <= 3) throw deadSocketFailure();
          return 'chunk';
        },
        { attempts: 3 },
        'download',
        { sleep: noSleep },
      ),
    ).rejects.toBeInstanceOf(TransferExhaustedError);
    expect(calls).toBe(3);
  });

  it('the served budget of 10 RECOVERS on the identical pattern', async () => {
    let calls = 0;
    const result = await transferWithRetry(
      async () => {
        calls += 1;
        if (calls <= 3) throw deadSocketFailure();
        return 'chunk';
      },
      { attempts: 10 },
      'download',
      { sleep: noSleep },
    );
    expect(result).toBe('chunk');
    expect(calls).toBe(4);
  });

  it('survives a fully stale connection pool — the ~6-deep worst case', async () => {
    // One argument for 10: it must exceed a browser's per-host pool depth (~6 in
    // Safari), so a pool where EVERY member is dead cannot exhaust the budget.
    // ⚠ Loose by construction — Run B produced 8 failures across 4 concurrent
    // chunks, which does not map cleanly onto a 6-deep pool. The test pins the
    // property the number was chosen for, not a claim that 6 is the true depth.
    let calls = 0;
    const result = await transferWithRetry(
      async () => {
        calls += 1;
        if (calls <= 6) throw deadSocketFailure();
        return 'chunk';
      },
      { attempts: 10 },
      'download',
      { sleep: noSleep },
    );
    expect(result).toBe('chunk');
    expect(calls).toBe(7);
  });

  it('⚠ the first TWO attempts carry ZERO backoff — why 3 was effectively 2', () => {
    // The reason the old budget bought one instant double-tap plus a single real
    // retry. Against a failure that clears with ELAPSED time, attempts 1 and 2 are
    // one moment. Measured: Run A 58039ms -> 58040ms; Run B 368285ms -> 368287ms.
    expect(backoffMs(1, () => 0.999)).toBe(0);
    expect(backoffMs(2, () => 0.999)).toBe(0);
    // Attempt 3 is the first with a real delay — Run A landed at +308 ms, Run B at
    // +432 ms, both inside this jittered 0-1000 ms window.
    expect(backoffMs(3, () => 0.999)).toBeGreaterThan(0);
    expect(backoffMs(3, () => 0.999)).toBeLessThanOrEqual(1000);
  });
});
