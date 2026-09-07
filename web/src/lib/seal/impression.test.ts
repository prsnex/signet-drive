// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// KAT for the seal impression derivation (S003 UI carve; authored by Gus).
// The vectors in impression-vectors.json were generated from the REFERENCE
// lineages only — the mockup v03 impress() (string seeds) and the Brand
// Foundations §1.2 snippet (fingerprint seeds) — never from this module. Two
// independent implementations of the same spec converging byte-exactly is
// the acceptance bar (the KeyCombine-KAT pattern applied to design code).
import { describe, expect, it } from 'vitest';

import {
  BAND,
  CANONICAL,
  CHANNEL,
  fnv1a,
  sealImpression,
  stringSeedBytes,
  toCssVars,
} from './impression';
import vectors from './impression-vectors.json';

const SIZES = ['20', '48', '64'] as const;

describe('sealImpression — fingerprint path (§1.2 reference lineage)', () => {
  for (const vec of vectors.fingerprints) {
    it(`fp [${vec.fp.join(',')}] reproduces the reference byte-exactly`, () => {
      const v = sealImpression(new Uint8Array(vec.fp));
      expect(v.band).toBe(vec.vars.band);
      expect(v.channel).toBe(vec.vars.channel);
      expect(v.theta).toBe(vec.vars.theta);
      expect(v.mag).toBe(vec.vars.mag);
      expect(v.phi).toBe(vec.vars.phi);
      expect(v.depth).toBe(vec.vars.depth);
      expect(v.core).toBe(1 - 2 * vec.vars.band - 2 * vec.vars.channel);
      for (const size of SIZES) {
        expect(toCssVars(v, Number(size))).toEqual(vec.css[size]);
      }
    });
  }

  it('0% offset is a legal impression — zero drift, never special-cased', () => {
    const v = sealImpression(new Uint8Array([0, 0, 0, 0, 0, 0]));
    expect(v.mag).toBe(0);
    const css = toCssVars(v, 48);
    expect(css['--dx']).toBe('0.00px');
    expect(css['--dy']).toBe('0.00px');
  });
});

describe('sealImpression — string-seed path (mockup v03 reference lineage)', () => {
  for (const vec of vectors.string_seeds) {
    it(`seed '${vec.seed}' reproduces the reference byte-exactly`, () => {
      expect(Array.from(stringSeedBytes(vec.seed))).toEqual(vec.seedBytes);
      const v = sealImpression(stringSeedBytes(vec.seed));
      expect(v.band).toBe(vec.vars.band);
      expect(v.channel).toBe(vec.vars.channel);
      expect(v.theta).toBe(vec.vars.theta);
      expect(v.mag).toBe(vec.vars.mag);
      expect(v.phi).toBe(vec.vars.phi);
      expect(v.depth).toBe(vec.vars.depth);
      for (const size of SIZES) {
        expect(toCssVars(v, Number(size))).toEqual(vec.css[size]);
      }
    });
  }

  it('fnv1a matches the shared constant-for-constant reference', () => {
    // Spot values recomputable by hand from the FNV-1a 32-bit definition.
    expect(fnv1a('')).toBe(0x811c9dc5);
    expect(fnv1a('a')).toBe(0xe40c292c);
  });
});

describe('canonical mark', () => {
  it('is the regular band + widest channel, concentric, even ink', () => {
    expect(CANONICAL.band).toBe(BAND[1]);
    expect(CANONICAL.channel).toBe(CHANNEL[3]);
    expect(CANONICAL.core).toBe(1 - 2 * BAND[1] - 2 * CHANNEL[3]);
    expect(CANONICAL.mag).toBe(0);
    expect(CANONICAL.depth).toBe(0);
    const css = toCssVars(CANONICAL, 48);
    expect(css['--band']).toBe('7.50%');
    expect(css['--core']).toBe('31.20px'); // 0.65 × 48
    expect(css['--dx']).toBe('0.00px');
    expect(css['--dp']).toBe('0.000');
  });
});
