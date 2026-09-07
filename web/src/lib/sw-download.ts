// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
/* bug193 (Download-Loop-Rewrite v03 §3c): the page half of the SW-streamed
 * download — the supply abstraction the sink factory hands to `downloadFileVia`.
 *
 * ONE abstraction, ONE mode, every browser (bug195, S177):
 *   pump — a MessagePort credit protocol: the SW asks, the page answers with
 *          EXACTLY one chunk. `write()` resolves only when its chunk has been
 *          handed over, so the caller's own awaited writes are the bound.
 *
 * ⚠⚠ The `transfer` mode is DELETED, not parked. It handed a ReadableStream
 * across realms and trusted the platform's backpressure — and Chrome fetched an
 * entire 512 MiB file with NOTHING consuming it while this module's own design
 * predicted a park at ~2 chunks: our writer was awaiting a queue that was not the
 * queue filling. A bound we do not own cannot be stated. The credit counter below
 * is ours, is mutation-tested, and holds everywhere.
 *
 * ⚠ THE PULL-DRIVEN INVARIANT IS LOAD-BEARING (v03; measured): a push-mode
 * supply queued 2 GiB inside Safari's SW and the worker was killed. The
 * mutation test (sw-download.test.ts) reverts to push mode against a fake
 * SW-side consumer and MUST fail its queue-growth assertion.
 *
 * ⚠ KEEPALIVE, UNCONDITIONAL (v03; measured): Firefox reaps the SW ~30 s in,
 * even mid-response — the ping is what saves the transfer there (ka-off died at
 * 755 MB of 2 GiB; ka-on completed). Chrome/Safari: harmless redundancy. */

import type { Bytes } from './crypto/bytes';
import type { DownloadSink } from './drive';
import { trace } from './trace';

const KEEPALIVE_MS = 4000;
const READY_TIMEOUT_MS = 3000;

/** The SW-intercepted download namespace — ONE home (Gus, complete-branch
 *  review): both the page trigger and the worker's fetch match derive from this
 *  constant, so the two sides cannot drift. Underscore-prefixed and 404-on-
 *  unknown; nothing else may route under it. */
export const RESERVED_DOWNLOAD_PREFIX = '/__signet_dl/';

/** The user cancelled the download from the BROWSER's own UI (its download
 *  manager). A decision, not an error — the drive loop aborts the transfer and
 *  the catch treats this type as quiet-cancel, never an error toast (Gus F-B;
 *  the download-side sibling of UploadCancelledError). */
export class DownloadCancelledError extends Error {
  constructor() {
    super('download cancelled from the browser');
  }
}

/** The SW side of pump mode, extracted here so F-A is UNIT-TESTED rather than
 *  reasoned about: the worker imports this to build the response stream.
 *
 *  ⚠ F-A (Gus, SERIOUS): a terminal message (`end`/`abort`) arrives WHENEVER the
 *  page sends it — including while no pull is outstanding, which is the ORDINARY
 *  state near completion (the SW queue full, the download manager draining).
 *  The first version delivered messages only into a pending pull and silently
 *  discarded the rest: the stream never closed and the download hung at 100%,
 *  on Safari, the platform pump mode exists for. The fix is an INBOX — anything
 *  arriving with no pull pending is stashed, and pull() consumes the stash
 *  before asking for more. `chunk`, `end` and `abort` are all safe in the
 *  window, and the page may drop its own port handler freely after `end`. */
export function createPumpReceiverStream(port: MessagePort): ReadableStream<Uint8Array> {
  type PumpMsg = { type: string; buf?: ArrayBuffer };
  const inbox: PumpMsg[] = [];
  let deliver: ((msg: PumpMsg) => void) | null = null;
  let terminal = false;

  port.onmessage = (m: MessageEvent) => {
    const p = m.data as PumpMsg;
    if (deliver) {
      const fn = deliver;
      deliver = null;
      fn(p);
    } else {
      inbox.push(p);
    }
  };

  return new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        if (terminal) return;
        const process = (p: PumpMsg): void => {
          if (p.type === 'chunk' && p.buf) {
            controller.enqueue(new Uint8Array(p.buf));
          } else if (p.type === 'end') {
            terminal = true;
            controller.close();
            port.onmessage = null;
          } else if (p.type === 'abort') {
            terminal = true;
            controller.error(new Error('download aborted by the page'));
            port.onmessage = null;
          }
        };
        // F-A: the stash first — a terminal that arrived between pulls must be
        // honored without posting a 'pull' no one will answer.
        const stashed = inbox.shift();
        if (stashed) {
          process(stashed);
          return;
        }
        return new Promise<void>((resolve) => {
          deliver = (p) => {
            process(p);
            resolve();
          };
          port.postMessage({ type: 'pull' });
        });
      },
      cancel() {
        // Downstream cancelled (the browser's own cancel button): tell the page
        // so its producer STOPS (F-B) rather than decrypting the rest unheard.
        try {
          port.postMessage({ type: 'cancel' });
        } catch {
          /* the page may already be gone */
        }
      },
    },
    // highWaterMark 2: at most two chunks queued SW-side — the mutation test
    // asserts supply can never outrun this (v03 §6-4).
    { highWaterMark: 2, size: () => 1 },
  );
}

/** The service worker we can reach, or null (no registration at all: private
 *  contexts that refuse registration, dev servers without the SW, first visit
 *  before activation). Callers fall back to the CAPPED buffering path — never an
 *  uncapped one (v03 §6-6).
 *
 *  ⚠⚠ bug203 (S179): this resolved `navigator.serviceWorker.controller` and that
 *  was TOO STRICT — it generalized from **subresource** behaviour to a
 *  **navigation**, and those differ.
 *
 *  A hard reload (Chrome ⌘⇧R) deliberately bypasses the worker, so the resulting
 *  page is UNCONTROLLED while the registration stays active on the correct build.
 *  Under the old check every download from that page silently took the capped
 *  fallback — identical success copy, whole-file buffering, and any file over the
 *  1 GiB cap refusing with a "too large" error that reads as a product defect.
 *
 *  ⭐ MEASURED (Gus + Chris, S179), and nothing the download path needs requires a
 *  controlled page:
 *    - the chunk fetches go DIRECT TO STORAGE — they never wanted the worker;
 *    - the trigger is a NAVIGATION, matched against the REGISTRATION regardless of
 *      the client's controller state — navigation to the reserved path
 *      post-hard-reload returned the WORKER's own 404 on all three engines;
 *    - the handshake works through the registration's `active` handle — a version
 *      round-trip completed while uncontrolled.
 *
 *  ⚠ Scope, measured on all three engines (bug203 §6a, S179 — `controller` sampled
 *  ten times over 5 s after the hard reload, per engine):
 *    - **Chrome** (⌘⇧R) — 10/10 UNCONTROLLED;
 *    - **Firefox** (⌘⇧R) — 10/10 UNCONTROLLED;
 *    - **Safari** (⌘⌥R) — 10/10 controlled: it does NOT uncontrol.
 *  ⇒ the blast radius is TWO engines, and Safari is the exception. ⚠ An earlier
 *  version of this comment had it backwards — it called Firefox disproven and left
 *  Safari unclassified, from a first-half measurement whose hard reload almost
 *  certainly never happened. Where pages stay controlled this change provably
 *  no-ops — `registration.active` is the same worker `controller` was. */
export async function swDownloadWorker(): Promise<ServiceWorker | null> {
  if (typeof navigator === 'undefined' || !('serviceWorker' in navigator)) return null;
  const registration = await navigator.serviceWorker.getRegistration();
  return registration?.active ?? null;
}

/** §3f: ask the reachable SW its baked release version (step 0's third end on the
 *  web surface). Resolves null when no worker is reachable, or none answers.
 *  ⚠ bug203: "reachable", not "controlling" — an uncontrolled page can still ask,
 *  and step 0 must not report a stale-client failure for a page that is fine. */
export async function swVersion(timeoutMs = READY_TIMEOUT_MS): Promise<string | null> {
  const worker = await swDownloadWorker();
  if (!worker) return null;
  return await new Promise((resolve) => {
    const timer = setTimeout(() => resolve(null), timeoutMs);
    const onMessage = (event: MessageEvent) => {
      const d = event.data as { type?: string; version?: string };
      if (d?.type === 'version') {
        clearTimeout(timer);
        navigator.serviceWorker.removeEventListener('message', onMessage);
        resolve(d.version ?? null);
      }
    };
    navigator.serviceWorker.addEventListener('message', onMessage);
    worker.postMessage({ type: 'version' });
  });
}

/** Test-only switch for the keepalive-off regression arm (v03 §6-5). Named so it
 *  can never be mistaken for a product knob: nothing served, nothing persisted —
 *  a test sets it and the pair (off dies / on completes) stays reproducible. */
export const TEST_ONLY_disableKeepalive = { value: false };

/** Open a SW-streamed sink: registers the supply with the controlling SW, then
 *  NAVIGATES to `/__signet_dl/<id>` so the browser's download manager takes the
 *  response. Returns null when the SW path is unavailable — the caller falls back
 *  (capped).
 *
 *  ⚠ A bare navigation — NOT an iframe (bug195: refused by our own `frame-src`)
 *  and NOT `<a download>` (bug197: never intercepted by the worker, so the host
 *  answered with the SPA shell and it was saved as the user's file). The trigger
 *  carries the full history and the measurements; read it before changing this.
 *
 *  ⚠ Call inside the user's click turn where possible: Safari gates the first
 *  download per site behind an Allow prompt, and pull-driven supply parks at no
 *  memory cost while it sits there. ⚠ Chrome's sticky block on gesture-less
 *  downloads was tested against this trigger at S178 — two consecutive downloads,
 *  no prompt, both byte-identical — but the origin's automatic-downloads
 *  permission may already have been granted there, so that cell is recorded
 *  UNRESOLVED rather than counted (bug197 §6-b). */
export async function openSwStreamedSink(
  filename: string,
  plaintextBytes: number,
): Promise<DownloadSink | null> {
  const worker = await swDownloadWorker();
  if (!worker) return null;

  const id =
    typeof crypto !== 'undefined' && 'randomUUID' in crypto
      ? crypto.randomUUID()
      : `dl${Date.now().toString(36)}${Math.random().toString(36).slice(2)}`;

  let keepaliveTimer: ReturnType<typeof setInterval> | null = null;
  const startKeepalive = () => {
    if (TEST_ONLY_disableKeepalive.value) return;
    // ⚠ The `id` is not decoration (bug195 (j)): it marks THIS entry's page alive
    // so the SW's sweep reaps on silence rather than on age, and a download parked
    // behind Safari's Allow prompt is not evicted out from under the user.
    keepaliveTimer = setInterval(() => worker.postMessage({ type: 'ka', id }), KEEPALIVE_MS);
  };
  const stopKeepalive = () => {
    if (keepaliveTimer !== null) clearInterval(keepaliveTimer);
    keepaliveTimer = null;
  };

  const trigger = () => {
    // ⚠⚠⚠ A BARE TOP-LEVEL NAVIGATION. No frame, no anchor, no `download`
    // attribute. Every one of those was tried and each broke a different way; the
    // history is here because the next person to "tidy" this will otherwise
    // re-derive one of them.
    //
    // • **iframe (S176 spike → v0.5.39): BROKEN by our own CSP (bug195).** An
    //   explicitly-present `frame-src` does NOT fall back to `default-src 'self'`,
    //   so the browser refused our own hidden frame and every web download hung.
    //
    // • **`<a download>` (v0.5.40): BROKEN — the service worker never sees it
    //   (bug197).** The request went to the NETWORK, the static host answered the
    //   unmatched route with `200` + `index.html`, and the download manager saved
    //   THAT under the user's filename. Four downloads landed as 2401 bytes of our
    //   own web page — `.dmg`, `.tif`, `.pdf`, byte-identical — on a custody
    //   product. Every size check passed; only opening a PDF revealed it.
    //   ⭐ MEASURED on all three engines: the worker intercepts an ordinary
    //   `fetch` and a top-level navigation, and does NOT intercept the
    //   download-attribute request. Three dispatch types, three engines.
    //
    // ⚠⚠ THE INVERSION WORTH REMEMBERING: the `download` attribute was added at
    // S177 **by me, for containment** — so a failed trigger could not replace the
    // SPA. That safety addition is what broke dispatch and produced the silent
    // corruption it was meant to prevent. Containment now lives at the SERVER,
    // where `/__signet_dl/*` returns an honest 404 (server/src/lib.rs, beside the
    // identical `/cli` and `/v1/{*rest}` rules) — so a miss is a FAILED download,
    // loudly, instead of a web page written to disk with the wrong extension.
    //
    // ⚠ Why the navigation does not replace the app: the worker answers with a
    // `Content-Disposition: attachment` response, and a navigation that resolves
    // to an attachment leaves the current document in place. **Verified, not
    // assumed** — five source-verified artifacts across Safari, Chrome and
    // Firefox at S178, page intact every time, and consecutive runs on the two
    // engines whose automatic-download policies could have bitten.
    //
    // Owner: bug197 + the Download-Loop-Rewrite Proposal. The regression test is
    // web/e2e/sw-download.spec.ts, which runs against the BUILT app on three
    // engines and asserts sha256 of the artifact against source — and which was
    // proven to FAIL against the `<a download>` trigger before this line changed.
    globalThis.location.assign(`/__signet_dl/${id}`);
  };
  const cleanup = () => {
    stopKeepalive();
  };

  const awaitReady = (): Promise<'pump' | null> =>
    new Promise((resolve) => {
      const timer = setTimeout(() => {
        navigator.serviceWorker.removeEventListener('message', onMessage);
        resolve(null);
      }, READY_TIMEOUT_MS);
      const onMessage = (event: MessageEvent) => {
        const d = event.data as { type?: string; id?: string; mode?: 'pump' };
        if (d?.type === 'dl-ready' && d.id === id) {
          clearTimeout(timer);
          navigator.serviceWorker.removeEventListener('message', onMessage);
          resolve(d.mode ?? null);
        }
      };
      navigator.serviceWorker.addEventListener('message', onMessage);
    });

  // ⚠⚠ ONE supply path: the credit-based pump, on EVERY browser (bug195, S177).
  //
  // The transferable-stream mode that used to sit here is DELETED, not parked —
  // the same rule as the uncapped buffer (Gus's ruling). It was the faster shape
  // on paper (zero-copy), but ITS BACKPRESSURE WAS NOT OURS: with the readable
  // transferred cross-realm, our writer awaited a queue that was not the queue
  // filling. Measured at S177: Chrome fetched an entire 512 MiB file with NOTHING
  // consuming it, while this code's own design predicted it would park at ~2
  // chunks. That is bug179's shape relocated into the plumbing, and no
  // highWaterMark of ours can reach a platform buffer we do not own.
  //
  // ⭐ The decisive asymmetry: THE PUMP'S BOUND IS OURS TO PROVE; a transferred
  // stream's bound is the platform's to change. "Benign in Chrome N" is an
  // unversioned trust that has already falsified one of our predictions once. The
  // credit counter in PumpSupply is mutation-tested — chunks received may never
  // exceed pulls issued — and it holds on every browser, permanently.
  //
  // ⚠ The cost is ARITHMETIC, not a measurement gap, and deliberately not tested
  // comparatively (the stop-chasing-variation rule): PumpSupply posts each chunk
  // with a transfer list, so the buffer MOVES rather than clones. The marginal
  // cost is one slice() per chunk — a ~16 MiB memcpy, single-digit milliseconds —
  // against 100 ms–2 s of network per chunk.
  //
  // ⚠ Deviation from a reference product, recorded WITH its reason (§B-3.8):
  // StreamSaver prefers transfer-where-available. Adoption defers to incumbents on
  // parameters we cannot cheaply distinguish; it does NOT survive a measured
  // falsification touching a safety property. Same rule that kept bug047's
  // no-reuse against boto3's pooling.
  //
  // Retraction for this whole path stays the served kill-switch to the capped
  // fallback. There is deliberately NO mode knob: one path, one bound, one matrix.
  const channel = new MessageChannel();
  const supply = new PumpSupply(channel.port1);
  const readyPromise = awaitReady();
  worker.postMessage({ type: 'dl-pump', id, filename, plaintextBytes }, [channel.port2]);
  if ((await readyPromise) !== 'pump') return null;

  // bug195 (k): the CAUSAL handoff signal. Resolves only when the SW's fetch
  // handler has actually claimed this entry — i.e. the browser has taken the
  // download. The caller gates its success notice on this, so a trigger that
  // never arrives can never be reported as a save.
  //
  // ⚠ Deliberately UNBOUNDED. A timeout here would be wrong: Safari gates the
  // first download per site behind an Allow prompt a user may leave buried for
  // MINUTES (spike-measured, and the case bug195 (j) protects), and no timeout can
  // distinguish "still waiting for the human" from "never going to arrive". The
  // listener is released in cleanup().
  let releaseConsumed: (() => void) | null = null;
  const consumed = new Promise<void>((resolve) => {
    const onConsumed = (event: MessageEvent) => {
      const d = event.data as { type?: string; id?: string };
      if (d?.type === 'dl-consumed' && d.id === id) {
        navigator.serviceWorker.removeEventListener('message', onConsumed);
        releaseConsumed = null;
        resolve();
      }
    };
    navigator.serviceWorker.addEventListener('message', onConsumed);
    releaseConsumed = () => navigator.serviceWorker.removeEventListener('message', onConsumed);
  });

  trace('sink-ready', { id });
  trace('keepalive-start', { id, everyMs: KEEPALIVE_MS });
  startKeepalive();
  // The trigger's own mark: bug198's fence exists because a navigation cancels
  // in-flight fetches AT BIRTH, so every chunk attempt's timing is only meaningful
  // relative to THIS instant.
  trace('trigger-nav', { id });
  trigger();

  // ⚠⚠⚠ THE NAVIGATION FENCE (bug198, S178) — do not remove, and do not "optimise"
  // it away by returning the sink early. This await is the whole fix.
  //
  // `trigger()` above starts a REAL top-level navigation. A browser beginning one
  // CANCELS the page's in-flight fetches — at birth, before dispatch — and only
  // afterwards discovers the response is an attachment and keeps the page. Without
  // this fence the caller's chunk loop starts immediately and its first requests
  // are issued straight into that window, where they die.
  //
  // MEASURED, not reasoned (staging v0.5.41, A/B on the kill-switch — the capped
  // fallback runs the IDENTICAL chunk loop but performs no navigation):
  //   fallback (no navigation): 2 runs, 0 head failures
  //   SW path  (navigation)   : 1 run,  1 head failure — `—` transferred, 2.63 ms
  // and the failed request carried ONLY page-set headers: no `Connection`, no
  // `Priority`, no `Accept-Language`, no address, no response. Those are added by
  // the network stack at dispatch, so their absence proves nothing was ever sent.
  // The count matched `min(chunks, n)` — exactly what was in flight — every time.
  //
  // ⚠ It corrupted nothing: the retry budget absorbed it and every completed
  // download was byte-exact. That is precisely what made it invisible for a whole
  // release — a DETERMINISTIC tax hiding inside a control provisioned for RANDOM
  // bad windows (bug060's lineage), silently spending margin that exists for
  // something else. A 496 MB download did die of it when four losses landed on one
  // chunk's budget.
  //
  // ⭐ Why `consumed` is the right fence and not a timer: it resolves when the
  // worker's fetch handler has CLAIMED this entry (bug195 (k)) — which can only
  // happen once the navigation has resolved into an attachment. The causal signal
  // built to make the success notice honest turns out to be exactly the event that
  // ends the cancellation window. No new machinery, no guessed delay.
  //
  // ⚠ Gus ruled this does NOT lengthen the parked-Allow wait (bug195 §4's
  // deliberately-unbounded residual): the browser must read the response headers to
  // know it has an attachment BEFORE it can raise Safari's Allow prompt, so
  // `consumed` fires ahead of that gate and the supply then parks on backpressure
  // exactly as the S176 spike measured. What moves earlier is only the
  // never-arriving case — and there we now fetch and decrypt NOTHING before
  // stalling, instead of doing the work and discarding it.
  //
  // ⚠ WHAT A DEAD TRIGGER NOW HOLDS, named because the fence changes it (Gus,
  // S178; walked with Chris and accepted). Waiting here instead of after the loop
  // means a download whose trigger never resolves keeps the keepalive pinging and
  // the worker holding its entry for the page's lifetime — where previously the
  // pointless transfer ran to completion and then cleaned up. The healing chain is
  // intact and cheap: a reload stops the pings, the silence-reap (bug195 (j))
  // collects the entry, and NOTHING lands on disk. Strictly better than the old
  // behaviour, which fetched and decrypted an entire file before discarding it —
  // but it is a different resting state, so it is written down rather than
  // discovered by whoever next debugs a stuck download.
  await consumed;
  // ⭐ The fence released. Everything after this is the chunk loop; anything dying
  // BEFORE it is the handshake or the navigation — and at S180 those two were
  // indistinguishable from outside the bundle.
  trace('fence-released', { id });

  return {
    consumed,
    write: (chunk: Bytes) => supply.write(chunk as Uint8Array),
    close: async () => {
      await supply.end();
      releaseConsumed?.();
      cleanup();
    },
    abort: async () => {
      supply.abort();
      releaseConsumed?.();
      cleanup();
    },
  };
}

/** The pump mode's page side, exported for the mutation test (v03 §6-4): the
 *  test drives a fake SW-side consumer against this (correct, credit-based)
 *  supply and against a push-mode fixture, and the queue-growth assertion must
 *  pass here and FAIL there — proving the invariant is tested, not asserted. */
export class PumpSupply {
  private credits = 0;
  private waiting: { buf: ArrayBuffer; resolve: () => void; reject: (e: Error) => void }[] = [];
  private ended = false;
  private cancelled = false;

  constructor(private readonly port: MessagePort) {
    port.onmessage = (m: MessageEvent) => {
      const d = m.data as { type?: string };
      if (d?.type === 'pull') {
        this.credits += 1;
        this.flush();
      } else if (d?.type === 'cancel') {
        // F-B (Gus): downstream cancelled — the producer must STOP, not keep
        // fetching and decrypting a file no one will receive. Parked and future
        // writes REJECT with the typed cancelled error; the drive loop's error
        // path aborts the sink and the catch treats the type as quiet-cancel.
        this.cancelled = true;
        this.ended = true;
        for (const w of this.waiting.splice(0)) w.reject(new DownloadCancelledError());
      }
    };
  }

  private flush(): void {
    while (this.waiting.length > 0 && this.credits > 0 && !this.ended) {
      const next = this.waiting.shift()!;
      this.credits -= 1;
      this.port.postMessage({ type: 'chunk', buf: next.buf }, [next.buf]);
      next.resolve();
    }
  }

  /** Resolves when the chunk has crossed — never earlier, which is what makes
   *  the caller's awaited write the memory bound. Rejects with
   *  {@link DownloadCancelledError} once downstream has cancelled (F-B). */
  write(chunk: Uint8Array): Promise<void> {
    if (this.cancelled) return Promise.reject(new DownloadCancelledError());
    if (this.ended) return Promise.resolve();
    // Slice: the caller may reuse its buffer; the transfer detaches ours.
    const buf = chunk.slice().buffer;
    return new Promise((resolve, reject) => {
      this.waiting.push({ buf, resolve, reject });
      this.flush();
    });
  }

  async end(): Promise<void> {
    // All prior writes have resolved (the loop awaits each), so nothing queues.
    this.ended = true;
    this.port.postMessage({ type: 'end' });
    this.port.onmessage = null;
  }

  abort(): void {
    this.ended = true;
    this.port.postMessage({ type: 'abort' });
    this.port.onmessage = null;
    for (const w of this.waiting.splice(0)) w.resolve();
  }
}

/** The SW's map of registered-but-not-yet-fetched downloads, extracted to `$lib`
 *  so its reaping rule is UNIT-TESTED rather than reasoned about inside a worker
 *  no test can load — the same move F-A's receiver made (Gus: the program's
 *  signature move, and this is the second finding to earn it).
 *
 *  ⚠⚠ bug195 (j): the rule is REAP ON SILENCE, NEVER ON AGE. The first version
 *  swept on registration time, which regressed a SPIKE-MEASURED case: Safari gates
 *  the first download per site behind an Allow prompt a user may leave buried for
 *  minutes, and such a download resumes cleanly when approved. An age sweep evicts
 *  it at the TTL and the approval then 404s — an honest download turned into a
 *  silent failure by our own housekeeping. Age is not evidence of abandonment;
 *  silence is. */
export interface PendingEntry<S> {
  lastSeenAt: number;
  stream: S;
  filename: string;
  plaintextBytes: number;
}

export class PendingRegistry<S extends { cancel(): Promise<void> }> {
  private readonly map = new Map<string, PendingEntry<S>>();

  constructor(private readonly ttlMs: number) {}

  get size(): number {
    return this.map.size;
  }

  register(id: string, entry: Omit<PendingEntry<S>, 'lastSeenAt'>, now: number): void {
    this.map.set(id, { ...entry, lastSeenAt: now });
  }

  /** A keepalive ping naming this id — the page is still alive and waiting. */
  touch(id: string, now: number): void {
    const entry = this.map.get(id);
    if (entry) entry.lastSeenAt = now;
  }

  /** Claim the entry for serving. Removes it: one registration, one response. */
  take(id: string): PendingEntry<S> | undefined {
    const entry = this.map.get(id);
    if (entry) this.map.delete(id);
    return entry;
  }

  /** Reap only entries whose page has gone SILENT for the whole TTL. */
  sweep(now: number): void {
    for (const [id, entry] of this.map) {
      if (now - entry.lastSeenAt > this.ttlMs) {
        this.map.delete(id);
        void entry.stream.cancel().catch(() => undefined);
      }
    }
  }
}
