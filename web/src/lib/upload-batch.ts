// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

/**
 * F2 (2026-09-23) — a BATCH of uploads: which files are open, and what the panel
 * may say about the batch as a whole.
 *
 * Design note v02 (Gus PASS 2026-09-21). Before F2 the store uploaded a batch
 * strictly one file after another, each file owning the served N send slots.
 * Here the batch owns ONE slot pool (`UploadSlots`) and keeps up to K = N files
 * open at once; each open file's part workers draw from the shared pool, so the
 * batch never has more than N parts in flight (the same bound one file had) and
 * a single-part file is one slot for its life — four photos move at once.
 *
 * ⛔ WHY THIS IS A MODULE AND NOT INLINE IN THE STORE: the scheduler and the
 * aggregation are decisions (when the next file opens; what "paused" means for
 * a batch; how the batch's bytes, parts and ETA are summed) and a decision that
 * lives inside a Svelte store cannot be tested without the runes compiler in the
 * loop. Here it runs against a stub `upload` in `upload-batch.test.ts`, and the
 * store's job shrinks to wiring: `document` events in, the record out.
 *
 * ⭐ THE OPEN STEP IS SEQUENTIAL; ONLY THE TRANSFER IS CONCURRENT (§2.1). Names
 * are chosen in file order, synchronously, before any await, exactly as before —
 * `dedupe` mutates the batch's taken-name set per call, and two files dropped
 * as "a.txt" still become "a.txt" + "a (1).txt".
 */
import { UploadCancelledError, UploadController, type UploadProgress } from './drive';
import { UploadSlots } from './upload-slots';

/** What the scheduler needs to know about a file before it opens it — a `File`
 *  satisfies this. */
export interface BatchFile {
  name: string;
  size: number;
}

/** The batch record the panel renders. A superset of the pre-F2 per-file record
 *  (the phase and in-flight decisions in `upload-phase.ts` read it structurally),
 *  with the batch facts added. Every number is a FACT about transfer state, never
 *  a clock or a guess (bug060, bug075): bytes and parts are sums of what the
 *  transfer layer reported per file, plus the planner's part-count forecast for
 *  files not yet opened. */
export interface UploadBatchState {
  fileCount: number;
  /** Files whose finalize returned — their rows land in the listing at batch end. */
  filesDone: number;
  /** Files rolled back on a non-retryable verdict; reported at batch end, never silently. */
  filesFailed: number;
  /** Files open right now (1..N once the pool's size is known). */
  filesOpen: number;
  /** 0-based indexes of the earliest and latest OPEN files, for "files 3–6 of 31";
   *  `-1` when nothing is open. */
  firstOpenIndex: number;
  lastOpenIndex: number;
  /** The earliest open file's upload name (the whole story for a one-file batch). */
  fileName: string;
  /** Wall-clock start of the BATCH — the honest elapsed readout for the silent
   *  stretch before any part acknowledges (bug075 item 1). Held here, not in
   *  `UploadProgress`, for the same reason the store used to hold it: a wall clock
   *  is not a transfer fact. */
  startedAt: number;
  /** True until ANY file's transfer layer makes its first report: everything
   *  before that is on-device work, the only interval honestly called "Encrypting". */
  sealing: boolean;
  /** The pool's size once the first initiate has taught it (the served N); 0 before. */
  slots: number;
  slotsBusy: number;
  completedParts: number;
  totalParts: number;
  sentBytes: number;
  totalBytes: number;
  retries: number;
  /** True when EVERY open file is paused on a bad window — the batch is waiting
   *  on the user and nothing is moving. One paused file among moving ones is
   *  listed in `pausedFiles` while the batch keeps going (§2.7). */
  paused: boolean;
  pausedFiles: Array<{ fileIndex: number; fileName: string }>;
  waitingForCapacitySeconds: number | null;
  inFlightParts: number;
  measuredRateBytesPerSec: number | null;
  etaSeconds: number | null;
  /** Page suspensions with parts in flight, counted ONCE per wake for the batch
   *  (each open file counts the same wake for itself; summing those would say
   *  four for one). */
  suspensions: number;
}

export interface UploadBatchDeps<F extends BatchFile> {
  files: F[];
  /** bug048: the folder's taken-name rule, mutating its set as the batch chooses. */
  dedupe: (desired: string) => string;
  /** The planner's part count for a file not yet opened (`Drive.uploadPlan`). */
  forecastParts: (size: number) => number;
  /** Open one file: the store binds this to `Drive.uploadFile` with the folder. */
  upload: (
    file: F,
    name: string,
    onProgress: (progress: UploadProgress) => void,
    controller: UploadController,
    slots: UploadSlots,
  ) => Promise<unknown>;
  onState: (state: UploadBatchState) => void;
  /** The document's CURRENT visibility at batch start (Gus, F4 fold 2). */
  initiallyVisible: boolean;
  now?: () => number;
}

export interface UploadBatchOutcome {
  done: number;
  cancelled: number;
  failures: Array<{ fileIndex: number; fileName: string; error: unknown }>;
}

interface OpenFile {
  name: string;
  size: number;
  forecastParts: number;
  controller: UploadController;
  progress: UploadProgress | null;
  settled: Promise<void>;
}

export class UploadBatch<F extends BatchFile> {
  /** The batch's one pool; its size is learned from the first file's initiate. */
  readonly slots = new UploadSlots();
  private readonly open = new Map<number, OpenFile>();
  private readonly failures: UploadBatchOutcome['failures'] = [];
  private done = 0;
  private cancelledFiles = 0;
  private doneBytes = 0;
  private doneParts = 0;
  private doneRetries = 0;
  /** Bytes and forecast parts of files that failed — taken OUT of the totals so
   *  the bar measures what is still being attempted. */
  private failedBytes = 0;
  private failedParts = 0;
  private cancelRequested = false;
  private visible: boolean;
  private suspensions = 0;
  private reported = false;
  private readonly startedAt: number;
  private readonly now: () => number;
  private readonly totalBytesAll: number;
  private readonly forecast: number[];

  constructor(private readonly deps: UploadBatchDeps<F>) {
    this.now = deps.now ?? (() => Date.now());
    this.startedAt = this.now();
    this.visible = deps.initiallyVisible;
    this.totalBytesAll = deps.files.reduce((n, f) => n + f.size, 0);
    this.forecast = deps.files.map((f) => deps.forecastParts(f.size));
  }

  /** Run the batch to its end: every file done, failed or cancelled. Never
   *  throws for a file's own failure — those are in the outcome (§2.7). */
  async run(): Promise<UploadBatchOutcome> {
    const { files } = this.deps;
    let next = 0;
    this.publish();
    for (;;) {
      // K = N: open files up to the pool's size — 1 until the first initiate has
      // taught the pool its N (a file with no slot to draw from would be idle).
      const want = this.cancelRequested ? 0 : Math.max(1, this.slots.size);
      while (!this.cancelRequested && next < files.length && this.open.size < want) {
        this.openFile(next);
        next += 1;
      }
      if (this.open.size === 0) break;
      const races: Promise<unknown>[] = [...this.open.values()].map((o) => o.settled);
      // Learning N is itself a reason to open more.
      if (!this.slots.known) races.push(this.slots.whenKnown());
      await Promise.race(races);
    }
    const cancelled = this.cancelledFiles + (files.length - next);
    return { done: this.done, cancelled, failures: [...this.failures] };
  }

  /** The whole batch, as today's one button: abort every in-flight attempt, roll
   *  back every unfinished file, keep every completed one, open nothing more. */
  cancel(): void {
    this.cancelRequested = true;
    for (const entry of this.open.values()) entry.controller.cancel();
    this.publish();
  }

  /** §2.7: cancel ONE file (typically a paused one); the batch continues. */
  cancelFile(fileIndex: number): void {
    this.open.get(fileIndex)?.controller.cancel();
  }

  resumeFile(fileIndex: number): void {
    this.open.get(fileIndex)?.controller.resume();
  }

  resumeAll(): void {
    for (const entry of this.open.values()) entry.controller.resume();
  }

  /** The store forwards every `visibilitychange`; one wake with parts in flight
   *  is one suspension for the batch. */
  setVisibility(visible: boolean): void {
    if (visible === this.visible) return;
    this.visible = visible;
    if (visible && this.inFlightParts() > 0) this.suspensions += 1;
    for (const entry of this.open.values()) entry.controller.setVisibility(visible);
    this.publish();
  }

  /** Every open file's server-side ids, for the pagehide keepalive abort. */
  activeUploads(): Array<{ fileId: string; uploadId: string }> {
    const active: Array<{ fileId: string; uploadId: string }> = [];
    for (const entry of this.open.values())
      if (entry.controller.active) active.push(entry.controller.active);
    return active;
  }

  private openFile(fileIndex: number): void {
    const file = this.deps.files[fileIndex];
    // Sequential and synchronous: the name is chosen in order, before any await.
    const name = this.deps.dedupe(file.name);
    const controller = new UploadController();
    controller.initVisibility(this.visible);
    const entry: OpenFile = {
      name,
      size: file.size,
      forecastParts: this.forecast[fileIndex],
      controller,
      progress: null,
      settled: Promise.resolve(),
    };
    entry.settled = this.deps
      .upload(
        file,
        name,
        (progress) => {
          entry.progress = progress;
          this.reported = true;
          this.publish();
        },
        controller,
        this.slots,
      )
      .then(
        () => {
          this.done += 1;
          this.doneBytes += file.size;
          this.doneParts += entry.progress?.totalParts ?? entry.forecastParts;
          this.doneRetries += entry.progress?.retries ?? 0;
        },
        (error: unknown) => {
          if (error instanceof UploadCancelledError || controller.cancelled) {
            this.cancelledFiles += 1;
          } else {
            this.failures.push({ fileIndex, fileName: name, error });
          }
          this.failedBytes += file.size;
          this.failedParts += entry.progress?.totalParts ?? entry.forecastParts;
          this.doneRetries += entry.progress?.retries ?? 0;
        },
      )
      .finally(() => {
        this.open.delete(fileIndex);
        this.publish();
      });
    this.open.set(fileIndex, entry);
    this.publish();
  }

  private inFlightParts(): number {
    let n = 0;
    for (const entry of this.open.values()) n += entry.progress?.inFlightParts ?? 0;
    return n;
  }

  private publish(): void {
    this.deps.onState(this.state());
  }

  /** The batch record, summed from the per-file reports. Exposed for tests. */
  state(): UploadBatchState {
    const { files } = this.deps;
    const indexes = [...this.open.keys()].sort((a, b) => a - b);
    const first = indexes.length > 0 ? indexes[0] : -1;
    const last = indexes.length > 0 ? indexes[indexes.length - 1] : -1;
    let openSent = 0;
    let openCompleted = 0;
    let openTotalParts = 0;
    let openRetries = 0;
    let inFlight = 0;
    let waiting: number | null = null;
    let rate: number | null = null;
    let pausedCount = 0;
    const pausedFiles: UploadBatchState['pausedFiles'] = [];
    for (const i of indexes) {
      const entry = this.open.get(i)!;
      const p = entry.progress;
      openTotalParts += p?.totalParts ?? entry.forecastParts;
      if (!p) continue;
      openSent += p.sentBytes;
      openCompleted += p.completedParts;
      openRetries += p.retries;
      inFlight += p.inFlightParts;
      if (p.waitingForCapacitySeconds !== null)
        waiting = Math.max(waiting ?? 0, p.waitingForCapacitySeconds);
      if (rate === null && p.measuredRateBytesPerSec !== null) rate = p.measuredRateBytesPerSec;
      if (p.paused) {
        pausedCount += 1;
        pausedFiles.push({ fileIndex: i, fileName: entry.name });
      }
    }
    // Files not yet opened: the planner's forecast, replaced by the initiate's
    // count once each opens.
    let pendingParts = 0;
    const opened = this.done + this.cancelledFiles + this.failures.length + indexes.length;
    for (let i = opened; i < files.length; i += 1) pendingParts += this.forecast[i];
    const totalBytes = this.totalBytesAll - this.failedBytes;
    const sentBytes = Math.min(totalBytes, this.doneBytes + openSent);
    const totalParts = this.doneParts + openTotalParts + pendingParts;
    const completedParts = this.doneParts + openCompleted;
    // F3-a: the rate is one stream's; the batch's remaining bytes ride on
    // `inFlight` streams right now.
    const etaSeconds =
      rate !== null && rate > 0
        ? Math.ceil((totalBytes - sentBytes) / (rate * Math.max(1, inFlight)))
        : null;
    const fileName =
      first >= 0
        ? this.open.get(first)!.name
        : files.length > 0
          ? (files[Math.min(files.length, opened) - 1]?.name ?? '')
          : '';
    return {
      fileCount: files.length,
      filesDone: this.done,
      filesFailed: this.failures.length,
      filesOpen: indexes.length,
      firstOpenIndex: first,
      lastOpenIndex: last,
      fileName,
      startedAt: this.startedAt,
      sealing: !this.reported && this.done === 0 && this.failures.length === 0,
      slots: this.slots.size,
      slotsBusy: this.slots.busy,
      completedParts,
      totalParts: Math.max(1, totalParts),
      sentBytes,
      totalBytes,
      retries: this.doneRetries + openRetries,
      paused: indexes.length > 0 && pausedCount === indexes.length,
      pausedFiles,
      waitingForCapacitySeconds: waiting,
      inFlightParts: inFlight,
      measuredRateBytesPerSec: rate,
      etaSeconds,
      suspensions: this.suspensions,
    };
  }
}
