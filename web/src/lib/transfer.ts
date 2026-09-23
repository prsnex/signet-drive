// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { trace, errorIdentity } from './trace';
// bug047: the transfer-resilience engine for the direct-to-storage byte path.
//
// A fraction of byte-transfer connections to object storage can silently stall
// on a degraded network path (root-caused S123: per-connection-random,
// path-side; a stalled browser PUT otherwise hangs to a ~13m42s TCP timeout).
// The cure — measured 65% per-connection stall → 95% effective success — is
// per-attempt stall-detection + abort + retry on a FRESH connection. This
// module is the pure engine: knobs, backoff, and the retry loop — no XHR, no
// DOM — so the policy is unit-testable; the XHR mechanics live in api.putPart.

/** Server-tunable transfer knobs (`system_config`), served in the multipart
 *  initiate/resume responses; defaults apply when a response omits them. */
export interface TransferKnobs {
  /** Per-part attempt budget (attempts, not retries — 1 means no retry). */
  attempts: number;
}

export const DEFAULT_KNOBS: TransferKnobs = { attempts: 10 };

// NOTE — `stall_timeout_seconds` is deliberately NOT read here.
//
// It was, until S127: parsed, clamped, stored on `TransferKnobs`, and then never
// consulted by anything. bug060 moved this surface onto `ceilingMs` (rate-derived)
// plus `backstopMs`, which left the field write-only — so an operator tuning
// `stall_timeout_seconds` to change web upload behaviour would have got no effect
// and no error, and reasonably concluded the setting did not help. A silent no-op
// on a tunable is worse than an absent one, because it costs someone a debugging
// session to disprove.
//
// The knob remains live and meaningful for the CLI (`TransferKnobs.write_gap`,
// the rate-free no-progress gap). Removed from the web's shape rather than left
// as a decoy. Gus, S127 W2.

/** Read the knobs from an initiate/resume response, defaulting when absent and
 *  clamping to the server's own schema bounds (attempts 1..=100) so a corrupt
 *  value cannot spin unbounded retries. */
export function knobsFromResponse(response: { part_retry_attempts?: number }): TransferKnobs {
  const attempts =
    typeof response.part_retry_attempts === 'number'
      ? Math.min(100, Math.max(1, Math.floor(response.part_retry_attempts)))
      : DEFAULT_KNOBS.attempts;
  return { attempts };
}

/** A transfer attempt aborted by the stall watchdog (no forward progress). */
export class StallError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'StallError';
  }
}

// ---------------------------------------------------------------------------
// bug060: the rate governor
// ---------------------------------------------------------------------------
//
// Two failure modes pull in opposite directions:
//
//   FM1 slow-but-steady — parts legitimately take tens of seconds; needs a LONG
//        tolerance or healthy uploads die (this was bug060).
//   FM2 fast-but-stalling — a connection silently dies; needs a SHORT tolerance
//        or a dead flow wastes minutes (this was bug047).
//
// One fixed number of seconds cannot serve both. Hence the governing invariant:
//
//   No absolute wall-time constant may bound a quantity proportional to
//   bytes / rate.
//
// WHY THE WEB NEEDED THIS MOST. The previous watchdog looked correct — it reset
// on `xhr.upload.onprogress` and only fired after a quiet period. But its INPUT
// is fiction: measured in S126, `upload.onprogress` fires ONCE, at ~0.4–1.5 s,
// reporting 100% "loaded" — the browser counts bytes handed to its network
// stack, not bytes delivered — and then goes silent for the entire real
// transmission. `lastProgressAt` froze, and the watchdog killed a healthy
// upload mid-flight (verified: aborted at 16.3 s a transfer that needed 25 s).
//
// XHR exposes no wire-level upload progress, by design. So part COMPLETION is
// the only honest clock this surface has, and the per-part ceiling IS the web's
// dead-flow detector — which is why `k` is tighter here than on the CLI (whose
// rate-free gap detector bounds FM2 independently), and why adaptive part
// SIZING is load-bearing here: driving expected part duration down is what
// keeps absolute detection latency acceptable at any k.

/** EWMA weight for a newly completed part. Chosen from the S126 measurement:
 *  the achievable rate varied 3.5x within a single 10-minute window, so the
 *  estimate must track briskly. Dimensionless, hence rate-free. */
const ALPHA = 0.4;

/** Below this, a "rate" is noise rather than a measurement (bytes/sec). */
const MIN_CREDIBLE_RATE = 1024;

/** Server-served governor parameters (migration 0037). */
export interface GovernorKnobs {
  /** Multiplier over a part's expected duration before the attempt is abandoned. */
  ceilingK: number;
  /** Target wall-clock seconds for one part, used to size parts. */
  targetPartSeconds: number;
  /** Adaptive part-size bounds. The floor is object storage's 5 MiB minimum for
   *  any non-final part — below it, completion fails after the whole file has
   *  already been uploaded (bug060/S1). */
  partMinBytes: number;
  partMaxBytes: number;
}

export const DEFAULT_GOVERNOR_KNOBS: GovernorKnobs = {
  ceilingK: 3,
  targetPartSeconds: 10,
  partMinBytes: 5 * 1024 * 1024,
  partMaxBytes: 64 * 1024 * 1024,
};

/** Read governor knobs from an initiate/resume response, clamping to the same
 *  bounds the server schema enforces so a corrupt value can neither disable the
 *  ceiling nor produce an illegal part size. */
export function governorKnobsFromResponse(response: {
  governor?: Record<string, unknown>;
}): GovernorKnobs {
  const g = response.governor;
  const int = (name: string, lo: number, hi: number, fallback: number): number => {
    const raw = g?.[name];
    return typeof raw === 'number' && Number.isFinite(raw)
      ? Math.min(hi, Math.max(lo, Math.floor(raw)))
      : fallback;
  };
  return {
    ceilingK: int('ceiling_k_web', 2, 20, DEFAULT_GOVERNOR_KNOBS.ceilingK),
    targetPartSeconds: int('target_part_seconds', 2, 120, DEFAULT_GOVERNOR_KNOBS.targetPartSeconds),
    partMinBytes: int(
      'part_min_bytes',
      5 * 1024 * 1024,
      64 * 1024 * 1024,
      DEFAULT_GOVERNOR_KNOBS.partMinBytes,
    ),
    partMaxBytes: int(
      'part_max_bytes',
      5 * 1024 * 1024,
      1024 * 1024 * 1024,
      DEFAULT_GOVERNOR_KNOBS.partMaxBytes,
    ),
  };
}

/** Tracks the observed transfer rate and derives bounds from it (AIMD: fold each
 *  completed part into an EWMA, halve on every stall). */
export class TransferGovernor {
  private rateEst: number | null = null;
  /** F3 (2026-09-21): parts that have COMPLETED on this governor and been folded
   *  into the estimate. Until it is > 0, `rateEst` is null or the bootstrap
   *  SEED — a stall-ceiling constant (125,000 B/s), not a measurement of the
   *  link — and the panel must not show it as a rate. Gus's catch at design
   *  review: a panel reading the governor "state only" would have printed
   *  "~1.0 Mbps measured" on a 9 Mbps link. */
  private observedParts = 0;
  /** 3a-i (S175): the estimate's epoch, advanced on every halving. Each attempt
   *  stamps the epoch it started under (`generation`); a stall penalises only if
   *  the epoch is unchanged since — so one link event tripping N concurrent
   *  parts costs ONE halving, not a 2⁻ᴺ collapse, while two genuinely
   *  sequential degradations still cost two. Derived from this control's own
   *  actions, never from link measurement: a suppressor on the existing AIMD
   *  reflex, not a new feedback path (Gus §7 check; S172 stays closed). This
   *  surface is single-threaded, so the compare-and-halve below is atomic for
   *  free; the CLI mirrors it under a lock. */
  private epoch = 0;

  constructor(private knobs: GovernorKnobs = DEFAULT_GOVERNOR_KNOBS) {}

  /** The current estimate epoch — read at ATTEMPT start, hand back to
   *  `penalizeStall` if that attempt stalls. */
  get generation(): number {
    return this.epoch;
  }

  /** Adopt the server-served knobs (they arrive with each initiate/resume). */
  applyKnobs(knobs: GovernorKnobs): void {
    this.knobs = knobs;
  }

  get rateEstimate(): number | null {
    return this.rateEst;
  }

  /** F3: true once at least one part has completed and been measured on THIS
   *  governor. `rateEstimate` is a measurement of the link only when this is
   *  true; before that it is null or the bootstrap seed. */
  get measured(): boolean {
    return this.observedParts > 0;
  }

  /** Seed from a conservative bootstrap. Unlike the CLI — whose rate-free gap
   *  detector is complete without any estimate — the web has no other detector,
   *  so its first part MUST have some ceiling. A deliberately pessimistic seed
   *  makes that first ceiling generous; the accepted cost is that one dead first
   *  flow takes a couple of minutes to notice, paid once per upload. */
  seedBootstrap(bytesPerSecond: number): void {
    if (this.rateEst === null && bytesPerSecond >= MIN_CREDIBLE_RATE) {
      this.rateEst = bytesPerSecond;
    }
  }

  /** Fold a completed part's observed rate into the estimate. */
  observePart(bytes: number, elapsedMs: number): void {
    if (bytes <= 0 || elapsedMs <= 0) return;
    const observed = (bytes / elapsedMs) * 1000;
    if (observed < MIN_CREDIBLE_RATE) return;
    this.observedParts += 1;
    this.rateEst = this.rateEst === null ? observed : ALPHA * observed + (1 - ALPHA) * this.rateEst;
  }

  /** Halve the estimate after a stalled attempt, so the retry gets a
   *  proportionally wider allowance. Retreat fast, rebuild slowly: an
   *  over-optimistic estimate is the only way this can harm a healthy transfer.
   *
   *  3a-i: `startGeneration` is the epoch the stalled attempt began under
   *  (`generation`). If the epoch advanced since — another part of the same
   *  burst already answered this link event — the call is a no-op, so N
   *  simultaneous trips cost ONE halving. ⚠ Rider 1 (Gus, S175): the compare
   *  and the halve-and-advance stay INSIDE this one method; never split the
   *  check to the caller side. */
  penalizeStall(startGeneration: number): void {
    if (startGeneration !== this.epoch) return; // this event was already answered
    if (this.rateEst === null) return;
    const halved = this.rateEst / 2;
    this.rateEst = halved >= MIN_CREDIBLE_RATE ? halved : null;
    this.epoch += 1;
  }

  /** The per-attempt ceiling in ms for a part of `bytes`, or `null` if there is
   *  no credible estimate (callers then fall back to the absolute backstop). */
  ceilingMs(bytes: number): number | null {
    if (this.rateEst === null) return null;
    const expectedMs = (bytes / this.rateEst) * 1000;
    return Math.max(1000, Math.min(expectedMs * this.knobs.ceilingK, 86_400_000));
  }

  /** The part size to plan an upload with: whatever transfers in roughly
   *  `targetPartSeconds` at the measured rate, clamped to the configured bounds
   *  and enlarged if necessary so the file fits `maxParts`.
   *
   *  Load-bearing on this surface: part duration sets dead-flow detection
   *  latency, because the ceiling is the only detector XHR permits.
   *
   *  ⭐ F1 (2026-09-21, from Chris's travel uploads): with NO measurement yet
   *  (`rateEst === null`, i.e. before this Drive's first observed part) the plan
   *  is the FLOOR, `partMinBytes`, by rule. It used to be the caller's 16 MiB
   *  default, so a fresh page's first 20 MB file went as one 16 MiB part on ONE
   *  stream — 2:10 measured against ~50 s for the same file once the rate was
   *  known, and the two-minute silence that produced a cancel. Four 5 MiB parts
   *  engage the fan-out from the first byte. The bound, named: a fresh page's
   *  first file of ANY size plans at 5 MiB parts (a 10 GB first file is ~2,000
   *  parts, each paying the relay's per-part reads, milliseconds against minutes
   *  of transfer); the second file re-plans from the measured rate as before.
   *  ⚠ NOT "seed before planning": the bootstrap seed is a stall-ceiling
   *  constant (125,000 B/s) that would reach the floor only by the coincidence
   *  of two constants tuned for other jobs (125,000 × 10 s = 1.25 MB, clamped).
   *  A rule that does not depend on that coincidence is the fix. */
  partSize(fileSize: number, maxParts: number): number {
    // bug192: `partMaxBytes` is a WIRE limit; this method sizes PLAINTEXT. The
    // clamp must land at the converted maximum, never at the served value —
    // a part sized AT `partMaxBytes` seals to `partMaxBytes + 34` and the relay
    // refuses it (413 at part 1). `maxPlaintextPerPart` is the one conversion.
    const maxPlain = maxPlaintextPerPart(this.knobs.partMaxBytes);
    const base =
      this.rateEst === null
        ? this.knobs.partMinBytes
        : Math.floor(this.rateEst * this.knobs.targetPartSeconds);
    let size = Math.min(maxPlain, Math.max(this.knobs.partMinBytes, base));
    if (maxParts > 0) {
      const needed = Math.ceil(fileSize / maxParts);
      if (needed > size) size = Math.min(maxPlain, needed);
    }
    return size;
  }
}

/** Fixed §4.2 on-disk overhead per chunk: magic(1) + alg(1) + index(4) + IV(12) +
 *  GCM tag(16). Stored ciphertext = plaintext + this per chunk — the figure
 *  `declared_size` reserves and the download Range math steps over.
 *  (Moved here from drive.ts for bug192: the part-sizing clamp needs it.) */
export const MULTIPART_CHUNK_OVERHEAD = 34;

/** bug192 — THE ONE CONVERSION SITE between the plaintext a part is sized in and
 *  the wire bytes the server bounds it in.
 *
 *  `transfer_part_max_bytes` is a WIRE limit: the relay refuses a declared
 *  Content-Length strictly greater than it, and the wire carries
 *  plaintext + MULTIPART_CHUNK_OVERHEAD. A plaintext clamp AT the served value
 *  therefore produced a part that could never be sent (413 at part 1, observed
 *  live at S175). The client owns this conversion because the client owns the
 *  envelope format — baking `+34` into the server would freeze one client's
 *  framing into a shared limit (Gus's ruling, S175). Every plaintext sizing
 *  path routes through here; a sizing decision that bypasses it is the bug
 *  reappearing. */
export function maxPlaintextPerPart(partMaxBytes: number): number {
  return partMaxBytes - MULTIPART_CHUNK_OVERHEAD;
}

/** Which way the bytes were going when a transfer exhausted its budget.
 *
 *  ⚠⚠ bug199: this exists because the shared retry path could not tell, and the
 *  UI therefore told a user whose DOWNLOAD failed to *"start the same upload
 *  again"* — an instruction for an operation they never began, which will not
 *  recover their file. Direction has to reach the error; there is nowhere else
 *  it can be recovered from by the time the copy is chosen. */
export type TransferDirection = 'upload' | 'download';

/** Every attempt in a part's budget stalled/failed — the bad-window signal.
 *  The transfer should PAUSE resumably, never silently die (bug047/bug046). */
export class TransferExhaustedError extends Error {
  constructor(
    message: string,
    public readonly attempts: number,
    public readonly lastError: unknown,
    public readonly direction: TransferDirection,
  ) {
    super(message);
    this.name = 'TransferExhaustedError';
  }
}

/** Backoff before attempt `attempt` (1-based), ms. The first retry is
 *  immediate — the failure is path-probabilistic, not server load (storage is
 *  provably healthy) — then full-jitter over ~1/2/4/8 s capped at 10 s to
 *  ride out short bursts. `random` is injectable for tests. */
export function backoffMs(attempt: number, random: () => number = Math.random): number {
  if (attempt <= 2) return 0;
  const capMs = Math.min(10_000, 1000 * 2 ** Math.min(3, attempt - 3));
  return Math.floor(random() * capMs);
}

export interface RetryHooks {
  /** Called before each retry (attempt ≥ 2) with the failure being retried. */
  onRetry?: (attempt: number, attempts: number, error: unknown) => void;
  /** Called when the relay reports at-capacity and the transfer is waiting the
   *  server's Retry-After (which does not spend the attempt budget). The UI
   *  can say "server busy — waiting" instead of looking frozen (bug075's
   *  honesty family). */
  onBusy?: (retryAfterSeconds: number) => void;
  /** Injectable sleep (tests use a no-op). */
  sleep?: (ms: number) => Promise<void>;
  /** Injectable randomness for the jitter. */
  random?: () => number;
}

const realSleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** bug211: the finalize retry path needs the same wait the part path uses. */
export const sleep = realSleep;

/** The relay answered 503 relay_at_capacity with a Retry-After (v04 §4.1 S2):
 *  the server is busy, the network is fine. A DISTINCT disposition from every
 *  transport failure — it waits the server's jittered Retry-After and does NOT
 *  spend the part-retry budget, which is sized for network faults (a busy
 *  Saturday must not fail an upload). */
export class RelayBusyError extends Error {
  constructor(public readonly retryAfterSeconds: number) {
    super(`relay at capacity — retry in ${retryAfterSeconds}s`);
    this.name = 'RelayBusyError';
  }
}

/** Cumulative busy-wait bound per part. Wall-clock DELIBERATELY (not a bug060
 *  violation: it bounds queue WAITING, not a bytes-over-rate transfer). Past
 *  it, busy responses start counting as ordinary attempts, so a permanently
 *  saturated relay converges to the honest resumable pause instead of waiting
 *  forever. */
const MAX_BUSY_WAIT_MS = 10 * 60_000;

/** Whether a failed attempt is worth a fresh-connection retry: stalls and
 *  network-level failures are; a definitive HTTP 4xx from storage is not (an
 *  expired pre-signed URL needs fresh URLs — resume's job, not retry's). A
 *  5xx is retryable (storage answered but hiccuped). */
export function isRetryable(error: unknown): boolean {
  // bug076: a user cancel is definitive — never retried, never "network-shaped".
  if (error instanceof TransferCancelledError) return false;
  // Server-busy is retryable by definition; transferWithRetry normally handles
  // it before this predicate is consulted (the no-budget path).
  if (error instanceof RelayBusyError) return true;
  if (error instanceof StallError) return true;
  if (error && typeof error === 'object' && 'status' in error) {
    const status = (error as { status: number }).status;
    // status 0 = the network layer itself failed (no HTTP response).
    //
    // 408 = the relay abandoned a part that made no progress (bug220,
    // `part_transfer_stalled`). It is the ONE 4xx that is transient by
    // construction, and it is the same physical event as the StallError branch
    // above — detected at the far end instead of here. Before bug220 the relay
    // returned 400 for this, so the response instructed a retry in a status
    // class this predicate treats as definitive, and two stalled parts
    // abandoned an entire upload along with every part already transferred.
    //
    // ⚠ Deliberately 408 and not "any 4xx": a definitive 4xx from storage
    // (an expired presigned URL) must stay non-retryable — that needs fresh
    // URLs, which is resume's job, not retry's.
    //
    // This predicate is origin-blind, so a 408 arriving from STORAGE on the
    // direct presigned path would also be retried. Considered and accepted
    // (Gus, bug220 review): S3-class endpoints signal a timeout as 400
    // `RequestTimeout`, not 408, so it is unlikely to fire — and if it ever
    // did, retry-on-transient is the correct disposition there too. Recorded
    // so the next reader does not re-derive it.
    return status === 0 || status === 408 || (status >= 500 && status < 600);
  }
  // Unknown error shapes (a thrown TypeError from a dead connection, etc.)
  // count as network-level: retrying on a fresh connection is safe — the
  // per-part PUT is idempotent (same part number overwrites).
  return true;
}

/** Does this failure say our RATE ESTIMATE was wrong?
 *
 *  Only a stall does. A stall means the part exceeded the time our measured rate
 *  predicted, so the estimate was too optimistic and must retreat (the AIMD
 *  multiplicative decrease). A **5xx does not**: storage answered and hiccuped,
 *  which is the store's problem and says nothing about our bandwidth — halving the
 *  estimate on it draws a conclusion the evidence does not support.
 *
 *  Status 0 counts, because the network layer failed with no HTTP response at all —
 *  indistinguishable from a dead flow at this layer.
 *
 *  This exists as a named predicate rather than an inline check because the CLI
 *  makes the identical decision (`http.rs`: relax only on `transfer_stalled`) and
 *  the two surfaces had drifted apart — the CLI reasoned it explicitly at S127/G1
 *  while the web penalised on *every* retry. Same decision, reasoned twice, kept in
 *  sync by nothing. Gus, S127 W1. */
export function indicatesRateOverestimate(error: unknown): boolean {
  // A busy relay says nothing about OUR bandwidth (the 5xx argument, exactly).
  if (error instanceof RelayBusyError) return false;
  if (error instanceof StallError) return true;
  if (error && typeof error === 'object' && 'status' in error) {
    const status = (error as { status: number }).status;
    // 408 `part_transfer_stalled` (bug220) is a stall the RELAY detected rather
    // than one we detected locally — the same physical event as the StallError
    // branch above, and therefore the same evidence: the part exceeded the time
    // our measured rate predicted, so the estimate was too optimistic.
    //
    // ⚠ This branch is load-bearing for surface parity, which is the whole
    // reason this predicate exists (Gus, S127 W1). The CLI relaxes on
    // `transfer_stalled` — the CLI's name for exactly this condition — so
    // widening `isRetryable` for 408 WITHOUT widening here would re-open the
    // web/CLI drift S127 closed, silently and in the same direction as before.
    return status === 0 || status === 408;
  }
  // Unknown shapes (a TypeError from a dead connection) count as evidence.
  //
  // The reason is **monotonicity**, not a guess about provenance (Gus, S127). An
  // earlier version of this comment argued unknown errors are "more likely
  // dead-flow than server-hiccup" — an empirical claim that is hard to defend at
  // the margin and would need revisiting whenever the error surface changed.
  //
  // The durable argument: `penalizeStall` only ever *lowers* the estimate, and a
  // lower estimate only ever *loosens* a ceiling (or nulls it, falling back to the
  // backstop). It structurally cannot tighten a bound, so an over-eager penalty
  // here can never manufacture a bandwidth cliff — the unsafe direction is
  // unreachable from this function. The real cost of penalizing when we shouldn't
  // have is slightly slower dead-flow detection, itself bounded by the attempt
  // budget. Erring toward `true` is therefore safe by construction.
  return true;
}

/** Run one part transfer under the bug047 policy: up to `knobs.attempts`
 *  attempts (the op must open a FRESH connection per call — XHR does), backoff
 *  between them, `onRetry` surfacing each one. Exhaustion throws
 *  [`TransferExhaustedError`] — the caller pauses resumably. */
/** bug076: the in-flight XHR was aborted by an explicit user cancel. Distinct
 *  from every network-shaped failure so the retry layer refuses it (a cancel
 *  retried on a fresh connection would resurrect the transfer the user killed). */
export class TransferCancelledError extends Error {
  constructor() {
    super('transfer cancelled by the user');
  }
}

/** ⚠ bug199: `direction` is a REQUIRED positional, deliberately ahead of the
 *  optional `hooks`, so a new call site cannot omit it and inherit whichever
 *  noun the copy happened to be written with. It is not a knob (nothing about
 *  it is served or tunable) and it is not a hook (a hook is optional, and this
 *  must not be). */
export async function transferWithRetry<T>(
  op: (attempt: number) => Promise<T>,
  knobs: TransferKnobs,
  direction: TransferDirection,
  hooks: RetryHooks = {},
): Promise<T> {
  const sleep = hooks.sleep ?? realSleep;
  const random = hooks.random ?? Math.random;
  let lastError: unknown;
  let busyWaitedMs = 0;
  let attempt = 0;
  while (attempt < knobs.attempts) {
    attempt += 1;
    if (attempt > 1) {
      await sleep(backoffMs(attempt, random));
      hooks.onRetry?.(attempt, knobs.attempts, lastError);
    }
    trace('attempt-start', { direction, attempt, of: knobs.attempts });
    try {
      const result = await op(attempt);
      trace('attempt-ok', { direction, attempt });
      return result;
    } catch (error) {
      // ⚠⚠ THE LINE S180 NEEDED AND DID NOT HAVE. Failing downloads showed exactly
      // ONE console error — the same count as PASSING ones — so from outside the
      // bundle "the retry never ran" and "the retry ran and died silently" were
      // indistinguishable. `retryable` is recorded BESIDE the identity because it
      // is the branch that decides, and a wrong classification here would spend a
      // 3-attempt budget on the first failure without a single visible sign.
      trace('attempt-failed', {
        direction,
        attempt,
        of: knobs.attempts,
        retryable: isRetryable(error),
        ...errorIdentity(error),
      });
      if (error instanceof RelayBusyError) {
        // v04 S2: server-busy is not a network fault. Wait the server's
        // (already jittered) Retry-After WITHOUT spending the budget — up to
        // the cumulative cap, after which busy degrades to an ordinary counted
        // failure so permanent saturation converges to the honest pause.
        const waitMs = Math.max(1, Math.min(error.retryAfterSeconds, 60)) * 1000;
        if (busyWaitedMs + waitMs <= MAX_BUSY_WAIT_MS) {
          busyWaitedMs += waitMs;
          hooks.onBusy?.(error.retryAfterSeconds);
          await sleep(waitMs);
          attempt -= 1;
          continue;
        }
      }
      if (!isRetryable(error)) throw error;
      lastError = error;
    }
  }
  trace('budget-exhausted', { direction, attempts: knobs.attempts, ...errorIdentity(lastError) });
  // ⚠ DEVELOPER/LOG-facing only: `friendlyDriveError` maps this error to a catalog
  // string by direction and never reads `.message`, so this wording carries no
  // user-visible copy and is outside the copy gate.
  //
  // ⛔ It previously asserted 'a bad network window between this device and
  // storage'. That named ONE cause as though it were the diagnosis — and it was
  // MEASURED WRONG (S185): a 100 GB download exhausted this budget because the
  // presigned URL had EXPIRED, and because S3 omits CORS headers on its 403 every
  // attempt surfaced as a bare `TypeError: Failed to fetch` — byte-identical to a
  // network fault. The old sentence sent its reader hunting the link.
  //
  // ⇒ This layer can see THAT n attempts failed, never WHY. Report the observable
  // and hand the reader `cause`; do not out-claim the evidence.
  throw new TransferExhaustedError(
    `${direction} failed after ${knobs.attempts} attempts on fresh connections — ` +
      'cause NOT determined at this layer; inspect `cause` (a bare TypeError here ' +
      'cannot distinguish a network fault from an expired or rejected URL)',
    knobs.attempts,
    lastError,
    direction,
  );
}

/** bug211: how many times to attempt the multipart FINALIZE before parking and
 *  asking the user.
 *
 *  ⭐ Chris's bar (S182): *"we don't want a user to have to [click Resume]. The
 *  upload should just complete."* The finalize had NO budget — one failure and
 *  the client parked on a human click, while part uploads got 10 attempts. By the
 *  time a user reaches the finalize they have spent hours uploading; that is the
 *  moment to be most patient automatically, not least.
 *
 *  ⚠ Anything unusable ⇒ 1, which is exactly the pre-S182 behaviour (ask on the
 *  first failure). Knob rule 4's off-position, reachable by retraction. */
export const MAX_FINALIZE_ATTEMPTS = 10;
export function finalizeAttempts(served: number | undefined): number {
  if (typeof served !== 'number' || !Number.isFinite(served)) return 1;
  return Math.min(Math.max(Math.floor(served), 1), MAX_FINALIZE_ATTEMPTS);
}
