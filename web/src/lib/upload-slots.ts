// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

/**
 * F2 (2026-09-23) — the send-slot pool a batch of uploads SHARES.
 *
 * Before F2 every file owned the served N send slots and the next file opened
 * only when the previous one's last part had landed. Two measured costs
 * (Gus's assessment v02 §5, 09-17/18): a batch of files at or under the part
 * floor is one part per file, so it ran on ONE stream while the link carried
 * four; and on multi-part files each file's tail drained the slots — the last
 * part alone — for roughly a tenth of the batch's wall clock.
 *
 * ⭐ The unit of concurrency is the PART, as it already was inside one file.
 * This pool only widens the scope of "at most N parts in flight" from a file to
 * a batch: every part PUT, from any open file, holds one slot for the duration
 * of ONE attempt. A file with no batch passes no pool and gets a private one of
 * its own served N — today's behaviour, byte for byte, which is what keeps the
 * CLI-parity path and every existing upload test unchanged.
 *
 * ⚠ Capacity is LEARNED, not configured: N is the served `concurrency_upload`,
 * which a file reads from its initiate response, so the first file of a batch to
 * initiate teaches the pool its size. Until then the pool has none, and
 * `acquire()` waits — no part of a batch can move before its N is known, which is
 * the same instant it could move before F2 (its own initiate).
 */
export class UploadSlots {
  private capacity: number;
  private inUse = 0;
  private readonly waiters: Array<() => void> = [];
  private readonly knownWaiters: Array<() => void> = [];

  /** `0` (the default) means "not yet known — the first initiate will say". */
  constructor(capacity = 0) {
    this.capacity = Math.max(0, Math.floor(capacity));
  }

  /** The served N once a file has initiated; `0` before. */
  get size(): number {
    return this.capacity;
  }

  /** Slots held right now — the panel's "M of N slots busy". */
  get busy(): number {
    return this.inUse;
  }

  get known(): boolean {
    return this.capacity > 0;
  }

  /** Adopt the served N. The FIRST call sets the pool's size for the batch;
   *  later calls (each file initiates, and each carries the same served block)
   *  are ignored rather than resized mid-flight: a per-file retraction still
   *  bounds THAT file's workers through its own `uploadConcurrency`, and the
   *  batch keeps the size it was planned at. */
  learn(capacity: number): void {
    if (this.known) return;
    const n = Math.floor(capacity);
    if (!(n > 0)) return;
    this.capacity = n;
    for (const wake of this.knownWaiters.splice(0)) wake();
    this.wake();
  }

  /** Resolves once `learn` has been called (immediately if it has). */
  whenKnown(): Promise<void> {
    if (this.known) return Promise.resolve();
    return new Promise((resolve) => this.knownWaiters.push(resolve));
  }

  /** Take one slot, waiting in arrival order for a free one. Resolves to the
   *  one-shot release; calling it twice is harmless. */
  acquire(): Promise<() => void> {
    return new Promise((resolve) => {
      const attempt = () => {
        if (this.known && this.inUse < this.capacity) {
          this.inUse += 1;
          let released = false;
          resolve(() => {
            if (released) return;
            released = true;
            this.inUse -= 1;
            this.wake();
          });
          return true;
        }
        return false;
      };
      if (!attempt()) this.waiters.push(() => attempt());
    });
  }

  /** Hand free slots to waiters in arrival order (first come, no priority —
   *  the drain of one file fills naturally from the next file's queue). */
  private wake(): void {
    while (this.waiters.length > 0 && this.known && this.inUse < this.capacity) {
      const next = this.waiters.shift()!;
      next();
    }
  }
}
