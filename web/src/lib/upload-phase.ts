// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

/**
 * bug075 item 1 — the upload readout's phase decision, in ONE home.
 *
 * ⛔ WHY THIS IS A MODULE AND NOT INLINE IN `FileList.svelte`: the decision "may a
 * progress bar be shown yet" is the whole content of this fix, and a decision that
 * lives inside a template cannot be tested without mounting the component. Extracted
 * here it is testable against records the REAL transfer path emits (see
 * `upload-phase.test.ts`), rather than against fixtures a test author imagined —
 * which is the trap that let bug228's suite pass over a check with no live call site.
 *
 * ⭐ THE PROPERTY THIS FILE EXISTS TO PRESERVE: every element the readout shows is a
 * FACT. Elapsed time is a fact. A completed-part count is a fact. A PERCENTAGE is a
 * fact only once parts have actually acknowledged — before that there is nothing
 * truthful to draw, so nothing is drawn. Not a bar at 0%, which is still a bar and
 * still unreadable as either healthy or broken.
 *
 * ⚠ THE TRAP, NAMED: the obvious remedy for 30 s of dead UI is a bar that moves on a
 * timer. That is bug060 reborn on the exact surface a person watches — fabricated
 * in-flight progress. Both functions below are pure functions of TRANSFER STATE and
 * take no clock, so a timer-driven variant cannot be written without changing their
 * signatures, which is the point.
 */

/** The transfer facts the readout decides on. A structural subset of the store's
 *  upload record, so this module never depends on the store's shape beyond what it
 *  genuinely reads. */
export interface UploadPhaseInput {
  /** Parts the storage layer has ACKNOWLEDGED. bug060: this counts completed parts
   *  only, never the in-flight part's buffered bytes — which is precisely why it is
   *  a trustworthy basis for "has anything actually happened yet". */
  completedParts: number;
  totalParts: number;
  /** True until the transfer layer makes its first report: genuinely on-device work
   *  (chunking, sealing) and the only interval we may honestly call "Encrypting". */
  sealing: boolean;
}

export type UploadPhase = 'encrypting' | 'starting' | 'uploading' | 'completing';

/** Which phase the upload is in, derived only from transfer state. */
export function uploadPhase(p: UploadPhaseInput): UploadPhase {
  if (p.sealing) return 'encrypting';
  if (p.completedParts === 0) return 'starting';
  if (p.completedParts >= p.totalParts) return 'completing';
  return 'uploading';
}

/**
 * Whether a determinate progress bar (and the percentage beside it) may be rendered.
 *
 * ⛔ Keyed to the FACT the bar depicts — that a part has acknowledged — and not to a
 * phase name. Keying it to phases would let a future phase be added that renders a
 * bar with nothing behind it; keying it here makes that impossible without editing
 * this line, which is where the argument lives.
 */
export function showUploadBar(p: UploadPhaseInput): boolean {
  return p.completedParts > 0;
}
