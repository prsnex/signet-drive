// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

// bug075 item 1 — THE ONE ARM (Hlin's condition, Chris agreed: one test, not a campaign).
//
// ⛔ WHAT MAKES THIS A TEST RATHER THAN THEATRE: a timer-driven progress bar would
// satisfy "a signal exists" and be bug060 REBORN — fabricated in-flight progress on
// the surface a user stares at for 30 s. The discriminator is that the readout must
// derive from REAL TRANSFER STATE and never from a clock.
//
// ⚠ AND THE LIMIT OF A UNIT TEST, STATED RATHER THAN GLOSSED: `showUploadBar` is a
// pure function of the progress record, so it CANNOT be timer-driven by construction
// — which makes asserting that fact partly tautological. The render-level promise
// ("no bar and no percent may ever appear") lives in the template, not here. So this
// file has TWO halves and needs both:
//
//   (a) the decision, driven by records the REAL transfer path emits, and
//   (b) a STATIC assertion over the component that the bar has exactly one element
//       and exactly one guard, and that the guard is this decision.
//
// Without (b) the component could grow a second, unguarded bar and every assertion
// in (a) would still pass. That is the "proven correct and never invoked" class
// (ROOTS §B-5.14c) aimed at a template instead of a function.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { showUploadBar, uploadPhase, type UploadPhaseInput } from './upload-phase';

describe('bug075 item 1 — the readout derives from transfer state, never a clock', () => {
  // ── (a) the decision, against the shape the real path emits ────────────────
  //
  // ⭐ GROUNDING, not invention: `drive.test.ts`'s live progress test pins the real
  // transfer path's FIRST report as `[completedParts, totalParts, sentBytes,
  // totalBytes] = [0, 6, 0, 43]`. So `completedParts === 0` as the opening state is
  // a measured property of the emitter, not an assumption of this test.
  const firstRealReport: UploadPhaseInput = { completedParts: 0, totalParts: 6, sealing: false };

  it('shows NO bar during the silent stretch, when nothing has acknowledged', () => {
    expect(uploadPhase(firstRealReport)).toBe('starting');
    expect(showUploadBar(firstRealReport)).toBe(false);
  });

  it('shows the bar the moment the FIRST part acknowledges, and not before', () => {
    // Walk the whole part sequence the real path steps through (6 chunks, per the
    // drive.test.ts pin) and find where the bar turns on.
    const sequence: UploadPhaseInput[] = Array.from({ length: 7 }, (_, completedParts) => ({
      completedParts,
      totalParts: 6,
      sealing: false,
    }));
    const flips = sequence.findIndex(showUploadBar);

    expect(flips).toBe(1); // exactly at the first acknowledged part, never earlier
    // ⛔ The load-bearing assertion: NO record with zero acknowledged parts may ever
    // yield a bar. A timer-driven implementation fails here for every elapsed value.
    for (const p of sequence.filter((r) => r.completedParts === 0)) {
      expect(showUploadBar(p)).toBe(false);
    }
  });

  it('labels on-device work separately from the silent stretch', () => {
    // `sealing` is the store's "the transfer layer has not reported at all yet" flag,
    // so it is the only interval that may honestly be called encrypting.
    expect(uploadPhase({ completedParts: 0, totalParts: 1, sealing: true })).toBe('encrypting');
    expect(uploadPhase({ completedParts: 6, totalParts: 6, sealing: false })).toBe('completing');
    expect(uploadPhase({ completedParts: 3, totalParts: 6, sealing: false })).toBe('uploading');
  });

  // ── (b) the render-level guarantee, asserted statically ────────────────────
  it('the component renders exactly ONE bar and guards it with exactly this decision', () => {
    const source = readFileSync(
      fileURLToPath(new URL('./components/FileList.svelte', import.meta.url)),
      'utf8',
    );

    // Scope to the UPLOAD readout: the download block below it has its own bar, and
    // a count over the whole file would silently include it — a true number about a
    // different subject, which is exactly how this kind of assertion goes wrong.
    const uploadBlock = source.slice(
      source.indexOf('{#if browser.uploadProgress}'),
      source.indexOf('{#if browser.downloadProgress}'),
    );
    expect(uploadBlock.length).toBeGreaterThan(0); // the slice actually found the block

    const bars = uploadBlock.match(/<div class="bar"/g) ?? [];
    expect(bars).toHaveLength(1);

    // The one bar is guarded, and the guard is the shared decision — not a re-derived
    // inline expression that could drift away from the tested one.
    expect(uploadBlock).toContain('{@const showBar = showUploadBar(p)}');
    expect(uploadBlock).toMatch(/\{#if showBar\}\s*<div class="bar"/);

    // ⛔ And no percentage may be rendered outside the guarded region either: the
    // phase strings for `encrypting` and `starting` must carry no `pct`.
    expect(uploadBlock).not.toMatch(/filelist_upload_encrypting\([^)]*pct/);
    expect(uploadBlock).not.toMatch(/filelist_upload_starting\([^)]*pct/);
  });
});
