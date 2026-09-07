// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// The seal impression derivation — Brand Foundations §1.2, v03 geometry
// (S003 UI carve; authored by Gus, integrated by Hlin; KAT'd in
// impression.test.ts against the mockup v03 reference impress()).
//
// Two seed regimes, per the S112 owner adjustments:
//
// - IDENTITY surfaces pass fingerprint bytes directly (`sealImpression(fp)`).
//   Which fingerprint is pinned at spec level: PRSN → the SIGNING-key
//   fingerprint (the identity anchor); human → the CLASSICAL KEM fingerprint
//   (humans hold no client-side signing key). The caller passes the right
//   bytes; this module never sees account objects.
//   Stability semantic, deliberate: "NEW KEYS, NEW PRESS" — re-enrollment
//   mints new keys and therefore a new impression. State it wherever the
//   impression is explained; a changed seal is provenance, not a bug.
// - ANONYMOUS app surfaces (sign-in, empty states) pass a page-path string —
//   hashed here via FNV-1a (`stringSeedBytes`), NEVER random-per-load: e2e
//   and visual assertions stay deterministic and the app keeps its
//   no-Math.random hygiene.
//
// Marks under 20 px render canonical (impressions collapse at that scale) —
// enforced by the component, with CANONICAL exported for it. Never animated,
// decorative only.

export const BAND = [0.06, 0.075, 0.09] as const; // outer band widths, fraction of diameter
export const CHANNEL = [0.05, 0.0667, 0.0833, 0.1] as const; // channel widths; L4 = max = canonical

/** The six impression variables — fractions/degrees, size-independent. */
export interface SealImpressionVars {
  /** outer band width, fraction of diameter */
  band: number;
  /** paper channel width, fraction of diameter */
  channel: number;
  /** center-disc diameter, fraction of the mark */
  core: number;
  /** offset angle, degrees */
  theta: number;
  /** offset magnitude, fraction of diameter (already scaled by channel) */
  mag: number;
  /** pressure-gradient direction, degrees */
  phi: number;
  /** ink-density delta, opacity */
  depth: number;
}

/** The canonical concentric mark: regular band, widest channel, zero drift,
 *  even ink. Used verbatim below 20 px and wherever a surface opts out. */
export const CANONICAL: SealImpressionVars = {
  band: BAND[1],
  channel: CHANNEL[3],
  core: 1 - 2 * BAND[1] - 2 * CHANNEL[3],
  theta: 0,
  mag: 0,
  phi: 0,
  depth: 0,
};

/** §1.2 reference derivation, exactly: six fingerprint bytes → six variables
 *  (one modulo each). 0% offset is a legal impression in any and all
 *  situations (Chris, S003) — never floored, jittered, or special-cased. */
export function sealImpression(fp: Uint8Array): SealImpressionVars {
  const band = BAND[fp[0] % 3];
  const channel = CHANNEL[fp[1] % 4];
  const theta = (fp[2] % 16) * 22.5;
  const mag = (fp[3] % 8) * 0.05 * channel;
  const phi = (fp[4] % 16) * 22.5;
  const depth = (fp[5] % 8) * (0.08 / 7);
  return { band, channel, core: 1 - 2 * band - 2 * channel, theta, mag, phi, depth };
}

/** FNV-1a 32-bit — the string-seed hash (same function, constant for
 *  constant, as the mockup v03 reference and the marketing site). */
export function fnv1a(str: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i += 1) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
}

/** Page-path (or any string) seed → six bytes in `sealImpression`'s slot
 *  order. The mockup/site convention maps the mixed hash bytes b[0..5] to
 *  variables as: b[5]→band, b[4]→channel, b[0]→theta, b[1]→mag, b[2]→phi,
 *  b[3]→depth — so this function REORDERS them into the fp[] slots
 *  (band, channel, theta, mag, phi, depth) and the derivation stays single.
 *  KAT-pinned against the mockup's string-seeded impress(). */
export function stringSeedBytes(seed: string): Uint8Array {
  const h = fnv1a(seed);
  const b = [
    h & 255,
    (h >> 8) & 255,
    (h >> 16) & 255,
    (h >> 24) & 255,
    ((h >>> 5) ^ (h >>> 19)) & 255,
    ((h >>> 11) ^ (h >>> 23)) & 255,
  ];
  return new Uint8Array([b[5], b[4], b[0], b[1], b[2], b[3]]);
}

/** The six CSS custom properties the mark's layers consume, formatted exactly
 *  as the mockup v03 reference emits them (same toFixed precisions). */
export function toCssVars(v: SealImpressionVars, size: number): Record<string, string> {
  const rad = (v.theta * Math.PI) / 180;
  return {
    '--band': (v.band * 100).toFixed(2) + '%',
    '--core': (v.core * size).toFixed(2) + 'px',
    '--dx': (Math.cos(rad) * v.mag * size).toFixed(2) + 'px',
    '--dy': (Math.sin(rad) * v.mag * size).toFixed(2) + 'px',
    '--ph': v.phi + 'deg',
    '--dp': v.depth.toFixed(3),
  };
}
