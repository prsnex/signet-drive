// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
/**
 * F4 (2026-09-21) — hold the screen awake while a LONG upload runs.
 *
 * Measured on 09-17/18: three page suspensions in one evening batch (display
 * sleep once, a hidden tab twice), each pausing the upload silently until the
 * page was visible again. A Screen Wake Lock (Safari 16.4+, Chrome) keeps the
 * display from sleeping while it is held; the browser RELEASES it whenever the
 * page hides, so it is re-requested on the visible transition. It does nothing
 * for a background tab — that case is the resume-refresh barrier's, and the
 * desktop client's (Launch-Punch-List §4-13).
 *
 * ⭐ The gate is the governor's own forecast, not a fixed file size: the lock is
 * requested the first time the remaining-time estimate exceeds
 * `WAKE_LOCK_MIN_REMAINING_SECONDS`, and held until the batch ends. A three-second
 * upload never touches it; a long one gets it within its first measured part.
 * Absent API (older Safari, an insecure context): a no-op, and the panel is
 * unchanged.
 */

export const WAKE_LOCK_MIN_REMAINING_SECONDS = 60;

/** The subset of `WakeLockSentinel` this module reads. */
export interface WakeLockSentinelLike {
  readonly released?: boolean;
  release(): Promise<void>;
}
/** The subset of `navigator.wakeLock` this module calls. */
export interface WakeLockApiLike {
  request(type: 'screen'): Promise<WakeLockSentinelLike>;
}

export class UploadWakeLock {
  private sentinel: WakeLockSentinelLike | null = null;
  private wanted = false;
  private requesting: Promise<void> | null = null;
  /** Requests made against the API — a count the tests read; never phoned home. */
  requests = 0;

  constructor(private readonly api: WakeLockApiLike | undefined) {}

  /** Called on every progress report with the transfer layer's ETA (null until a
   *  rate has been measured). Once the forecast crosses the gate the lock stays
   *  wanted until `release()`, so a shrinking ETA near the end does not drop it. */
  consider(etaSeconds: number | null): void {
    if (etaSeconds !== null && etaSeconds > WAKE_LOCK_MIN_REMAINING_SECONDS) this.wanted = true;
    if (this.wanted) void this.acquire();
  }

  /** On `visibilitychange` → visible: the browser released the lock when the page
   *  hid; take it again if the upload still wants it. */
  onVisible(): void {
    if (this.wanted) void this.acquire();
  }

  /** At batch end or cancel. Idempotent. */
  async release(): Promise<void> {
    this.wanted = false;
    const held = this.sentinel;
    this.sentinel = null;
    if (held && !held.released) await held.release().catch(() => undefined);
  }

  get held(): boolean {
    return this.sentinel !== null && !this.sentinel.released;
  }

  private async acquire(): Promise<void> {
    if (!this.api || this.held || this.requesting) return;
    this.requests += 1;
    this.requesting = this.api
      .request('screen')
      .then(
        (sentinel) => {
          // The upload may have ended while the request was in flight.
          if (this.wanted) this.sentinel = sentinel;
          else void sentinel.release().catch(() => undefined);
        },
        // A refused request (policy, low battery, not visible) is not an error
        // for the upload: nothing changes, the next report may try again.
        () => undefined,
      )
      .finally(() => {
        this.requesting = null;
      });
    await this.requesting;
  }
}
