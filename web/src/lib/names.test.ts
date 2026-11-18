// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

import { describe, expect, it } from 'vitest';

import {
  UNREADABLE_NAME,
  collides,
  dedupeName,
  firstCollision,
  moveClash,
  readableNames,
} from './names';

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

describe('collides (bug283)', () => {
  /** Duplicated VERBATIM in the CLI's `names.rs` (`shared_collision_vectors`). Change
   *  both or neither. */
  it('shared collision vectors', () => {
    const cases: Array<[string, string[], boolean]> = [
      ['notes.txt', [], false],
      ['notes.txt', ['notes.txt'], true],
      // exact equality, as upload's: a name differing only in case is free
      ['Notes.txt', ['notes.txt'], false],
      // and no Unicode normalization: NFC "café" is not NFD "café"
      ['caf\u00e9', ['cafe\u0301'], false],
      ['a (1).txt', ['a.txt', 'a (1).txt'], true],
      [' notes.txt', ['notes.txt'], false],
    ];
    for (const [name, others, expected] of cases) {
      expect(collides(name, new Set(others)), `collides(${name})`).toBe(expected);
    }
  });

  it('a move refuses a name already in the target, or shared within the selection', () => {
    expect(firstCollision(['a.txt', 'b.txt'], new Set(['c.txt']))).toBeNull();
    expect(firstCollision(['a.txt', 'b.txt'], new Set(['b.txt']))).toBe('b.txt');
    // two selected files with one name collide with each other, the target empty
    expect(firstCollision(['x.txt', 'x.txt'], new Set())).toBe('x.txt');
    expect(firstCollision([], new Set(['x.txt']))).toBeNull();
  });

  it("the store's move rule catches two moving files of one name, the target empty", () => {
    // moveClash is exactly what the store's moveCollision returns once the target is
    // listed (Gus: the selection check must fire from its caller, not only directly).
    expect(moveClash(['x.txt', 'x.txt'], [])).toBe('x.txt');
    expect(moveClash(['a.txt', 'b.txt'], ['b.txt'])).toBe('b.txt');
    expect(moveClash(['a.txt'], ['c.txt'])).toBeNull();
    // unreadable names on either side are no names
    expect(moveClash([UNREADABLE_NAME, UNREADABLE_NAME], [])).toBeNull();
    expect(moveClash(['a.txt'], [UNREADABLE_NAME])).toBeNull();
  });

  it('an unreadable name is no name: it cannot collide, as on upload and in the CLI', () => {
    const names = readableNames(['a.txt', UNREADABLE_NAME, UNREADABLE_NAME]);
    expect([...names]).toEqual(['a.txt']);
    expect(collides(UNREADABLE_NAME, names)).toBe(false);
  });
});
