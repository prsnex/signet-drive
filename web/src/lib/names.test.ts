// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

import { describe, expect, it } from 'vitest';

import { dedupeName } from './names';

describe('dedupeName (bug048)', () => {
  /** These vectors are duplicated VERBATIM in the CLI's `names.rs` — the two
   *  surfaces must resolve collisions identically (functional parity).
   *  Change both or neither. */
  it('shared parity vectors', () => {
    const cases: Array<[string, string[], string]> = [
      ['report.pdf', [], 'report.pdf'],
      ['report.pdf', ['report.pdf'], 'report (1).pdf'],
      ['report.pdf', ['report.pdf', 'report (1).pdf'], 'report (2).pdf'],
      ['archive.tar.gz', ['archive.tar.gz'], 'archive.tar (1).gz'],
      ['README', ['README'], 'README (1)'],
      ['.env', ['.env'], '.env (1)'],
      ['trailing.', ['trailing.'], 'trailing. (1)'],
      ['wave-a-renamed.bin', ['wave-a-renamed.bin'], 'wave-a-renamed (1).bin'],
      ['a (1).txt', ['a (1).txt'], 'a (1) (1).txt'],
    ];
    for (const [desired, existing, expected] of cases) {
      expect(dedupeName(desired, new Set(existing)), `dedupe(${desired})`).toBe(expected);
    }
  });
});
