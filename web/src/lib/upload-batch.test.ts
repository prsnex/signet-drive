// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { describe, expect, it } from 'vitest';
import { UploadCancelledError, UploadController, type UploadProgress } from './drive';
import { UploadBatch, type UploadBatchState } from './upload-batch';
import type { UploadSlots } from './upload-slots';

/**
 * F2 (2026-09-23) — the batch scheduler and its record, against a STUB upload.
 * The slot mechanics inside `uploadFile` are pinned in drive.test.ts; here the
 * subject is what the scheduler does around them: how many files it opens, what
 * cancel and a per-file pause do, and what the panel is told.
 */

function progress(over: Partial<UploadProgress> = {}): UploadProgress {
  return {
    completedParts: 0,
    totalParts: 1,
    sentBytes: 0,
    totalBytes: 10,
    retries: 0,
    paused: false,
    waitingForCapacitySeconds: null,
    inFlightParts: 0,
    measuredRateBytesPerSec: null,
    etaSeconds: null,
    suspensions: 0,
    ...over,
  };
}

/** A stub transfer: each file "learns" N at its initiate, holds a slot for its
 *  one part for `holdMs`, then lands. The test drives pauses and failures by
 *  name. */
function stubUpload(opts: {
  served: number;
  holdMs: number;
  paused?: Set<string>;
  failing?: Map<string, unknown>;
  initiated?: string[];
}) {
  return async (
    file: { name: string; size: number },
    name: string,
    onProgress: (p: UploadProgress) => void,
    controller: UploadController,
    slots: UploadSlots,
  ): Promise<unknown> => {
    await Promise.resolve(); // the initiate round trip
    opts.initiated?.push(name);
    slots.learn(opts.served);
    controller.active = { fileId: `file-${name}`, uploadId: `up-${name}` };
    const release = await slots.acquire();
    try {
      if (controller.cancelled) throw new UploadCancelledError();
      onProgress(progress({ inFlightParts: 1, totalBytes: file.size }));
      await new Promise((r) => setTimeout(r, opts.holdMs));
      if (opts.paused?.has(name)) {
        onProgress(progress({ inFlightParts: 0, totalBytes: file.size, paused: true }));
        const action = await controller.waitForResume();
        if (action === 'cancel') throw new UploadCancelledError();
        onProgress(progress({ inFlightParts: 1, totalBytes: file.size }));
        await new Promise((r) => setTimeout(r, opts.holdMs));
      }
      if (controller.cancelled) throw new UploadCancelledError();
      const failure = opts.failing?.get(name);
      if (failure !== undefined) throw failure;
      onProgress(
        progress({
          completedParts: 1,
          sentBytes: file.size,
          totalBytes: file.size,
          measuredRateBytesPerSec: 1000,
          etaSeconds: 0,
        }),
      );
      return { file_id: `file-${name}` };
    } finally {
      release();
      controller.active = null;
    }
  };
}

const files = (n: number, size = 10) =>
  Array.from({ length: n }, (_, i) => ({ name: `f${i}.jpg`, size }));

function harness(
  n: number,
  upload: ReturnType<typeof stubUpload>,
  over: Partial<ConstructorParameters<typeof UploadBatch>[0]> = {},
) {
  const states: UploadBatchState[] = [];
  const batch = new UploadBatch({
    files: files(n),
    dedupe: (d) => d,
    forecastParts: () => 1,
    upload,
    onState: (s) => states.push(s),
    initiallyVisible: true,
    now: () => 1_000,
    ...over,
  });
  return { batch, states };
}

describe('F2 — the batch scheduler (2026-09-23)', () => {
  it('opens ONE file until the pool learns N, then keeps N open — never more', async () => {
    const initiated: string[] = [];
    const { batch, states } = harness(8, stubUpload({ served: 4, holdMs: 10, initiated }));
    const outcome = await batch.run();
    expect(outcome).toEqual({ done: 8, cancelled: 0, failures: [] });
    expect(Math.max(...states.map((s) => s.filesOpen))).toBe(4);
    expect(Math.max(...states.map((s) => s.inFlightParts))).toBe(4);
    // Before the first initiate exactly one file is open; after it, four.
    const firstOpen = states.find((s) => s.filesOpen > 0)!;
    expect(firstOpen.filesOpen).toBe(1);
    expect(firstOpen.slots).toBe(0);
    expect(states.filter((s) => s.slots === 0).every((s) => s.filesOpen <= 1)).toBe(true);
    expect(states.some((s) => s.slots === 4 && s.filesOpen === 4)).toBe(true);
    // Files opened in order, named in order.
    expect(initiated).toEqual(files(8).map((f) => f.name));
    const last = states[states.length - 1];
    expect(last).toMatchObject({
      filesDone: 8,
      filesOpen: 0,
      completedParts: 8,
      totalParts: 8,
      sentBytes: 80,
      totalBytes: 80,
    });
  });

  it('the record sums what is open and forecasts what is pending; "files a–b of n" names the open range', async () => {
    const { batch, states } = harness(6, stubUpload({ served: 2, holdMs: 10 }));
    await batch.run();
    // A moment with two open: their indexes are consecutive and the range says so.
    const two = states.find((s) => s.filesOpen === 2 && s.inFlightParts === 2)!;
    expect(two).toBeDefined();
    expect(two.lastOpenIndex - two.firstOpenIndex).toBe(1);
    expect(two.fileName).toBe(`f${two.firstOpenIndex}.jpg`);
    expect(two.totalParts).toBe(6); // 2 open (reported) + 4 forecast, or later mixes — always the batch
    expect(two.totalBytes).toBe(60);
    // Sealing is true only before ANY file has reported.
    expect(states[0].sealing).toBe(true);
    expect(states.filter((s) => s.sealing).every((s) => s.completedParts === 0)).toBe(true);
    expect(states[states.length - 1].sealing).toBe(false);
    // The wall clock is the batch's, held in the record and never in the transfer facts.
    expect(states.every((s) => s.startedAt === 1_000)).toBe(true);
  });

  it('a paused file lists itself and does NOT stop the others; cancelling it rolls back only it (§2.7)', async () => {
    const paused = new Set(['f1.jpg']);
    const { batch, states } = harness(4, stubUpload({ served: 2, holdMs: 10, paused }));
    const run = batch.run();
    // Wait for the pause to be reported, with the batch still moving around it.
    const pausedState = await new Promise<UploadBatchState>((resolve) => {
      const tick = () => {
        const s = states.find((x) => x.pausedFiles.length > 0);
        if (s) resolve(s);
        else setTimeout(tick, 2);
      };
      tick();
    });
    expect(pausedState.pausedFiles).toEqual([{ fileIndex: 1, fileName: 'f1.jpg' }]);
    expect(pausedState.paused).toBe(false); // one of two open is paused: the batch is not
    // Let the rest finish around it.
    await new Promise((r) => setTimeout(r, 60));
    const around = states[states.length - 1];
    expect(around.filesDone).toBe(3);
    expect(around.paused).toBe(true); // now the ONLY open file is paused: the batch waits
    batch.cancelFile(1);
    const outcome = await run;
    expect(outcome).toEqual({ done: 3, cancelled: 1, failures: [] });
  });

  it('resuming the paused file completes it', async () => {
    const paused = new Set(['f0.jpg']);
    const { batch, states } = harness(1, stubUpload({ served: 2, holdMs: 5, paused }));
    const run = batch.run();
    await new Promise((r) => setTimeout(r, 30));
    expect(states[states.length - 1].paused).toBe(true);
    batch.resumeFile(0);
    expect(await run).toEqual({ done: 1, cancelled: 0, failures: [] });
  });

  it('batch cancel aborts every open file, opens nothing more, and keeps what landed (§2.6)', async () => {
    const { batch, states } = harness(8, stubUpload({ served: 4, holdMs: 20 }));
    const run = batch.run();
    await new Promise((r) => setTimeout(r, 30)); // the first four have landed, the next four are open
    expect(states[states.length - 1].filesDone).toBeGreaterThanOrEqual(1);
    batch.cancel();
    const outcome = await run;
    expect(outcome.failures).toEqual([]);
    expect(outcome.done + outcome.cancelled).toBe(8);
    expect(outcome.cancelled).toBeGreaterThanOrEqual(1);
    expect(batch.activeUploads()).toEqual([]);
  });

  it('a file failing on a definitive verdict is reported at batch end with the others landed — never silently', async () => {
    const boom = new Error('injected 4xx');
    const failing = new Map<string, unknown>([['f2.jpg', boom]]);
    const { batch, states } = harness(5, stubUpload({ served: 2, holdMs: 5, failing }));
    const outcome = await batch.run();
    expect(outcome.done).toBe(4);
    expect(outcome.failures).toEqual([{ fileIndex: 2, fileName: 'f2.jpg', error: boom }]);
    const last = states[states.length - 1];
    expect(last.filesFailed).toBe(1);
    // The failed file's bytes leave the totals, so the bar measures what was attempted.
    expect(last.totalBytes).toBe(40);
    expect(last.sentBytes).toBe(40);
  });

  it('F3-a: the batch ETA divides the remaining bytes by rate × parts in flight', async () => {
    // A stub that reports a measured rate WHILE its part is in flight, so a state
    // with four streams and a rate exists to check.
    const upload: ReturnType<typeof stubUpload> = async (
      file,
      name,
      onProgress,
      controller,
      slots,
    ) => {
      await Promise.resolve();
      slots.learn(4);
      const release = await slots.acquire();
      try {
        onProgress(
          progress({ inFlightParts: 1, totalBytes: file.size, measuredRateBytesPerSec: 2 }),
        );
        await new Promise((r) => setTimeout(r, 15));
        onProgress(
          progress({
            completedParts: 1,
            sentBytes: file.size,
            totalBytes: file.size,
            measuredRateBytesPerSec: 2,
            etaSeconds: 0,
          }),
        );
        return { file_id: name };
      } finally {
        release();
        controller.active = null;
      }
    };
    const { batch, states } = harness(8, upload);
    await batch.run();
    const four = states.find((s) => s.inFlightParts === 4 && s.measuredRateBytesPerSec !== null)!;
    expect(four).toBeDefined();
    // 80 bytes total, nothing sent yet, 2 B/s per stream × 4 streams = 10 s — not 40.
    expect(four.etaSeconds).toBe(Math.ceil((four.totalBytes - four.sentBytes) / (2 * 4)));
    expect(four.etaSeconds).toBe(10);
  });

  it('one wake with parts in flight is ONE suspension for the batch, forwarded to every open file', async () => {
    const { batch, states } = harness(4, stubUpload({ served: 4, holdMs: 30 }));
    const run = batch.run();
    await new Promise((r) => setTimeout(r, 10)); // four in flight
    batch.setVisibility(false);
    batch.setVisibility(true);
    await run;
    expect(Math.max(...states.map((s) => s.suspensions))).toBe(1);
  });

  it('activeUploads lists the open files’ server ids for the pagehide abort', async () => {
    const { batch } = harness(3, stubUpload({ served: 4, holdMs: 30 }));
    const run = batch.run();
    await new Promise((r) => setTimeout(r, 10));
    expect(
      batch
        .activeUploads()
        .map((a) => a.uploadId)
        .sort(),
    ).toEqual(['up-f0.jpg', 'up-f1.jpg', 'up-f2.jpg']);
    await run;
    expect(batch.activeUploads()).toEqual([]);
  });
});
