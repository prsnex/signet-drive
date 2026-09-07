// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

import { describe, expect, it } from 'vitest';
import { compareDisplayNames, sortByName } from './folder-order';

/**
 * S209. The fixtures are the REAL folder names from the staging account this was
 * built against, not invented ones — the ordering rules were chosen because of what
 * those names did, so a synthetic set would be testing the rule against itself.
 */
describe('compareDisplayNames', () => {
  it('sorts numbers as numbers, not as text', () => {
    // A string sort puts "51-…" after "9-…" only by luck of first character; the real
    // failure is "51" before "9" because '5' < '9'. This is the case Chris named.
    expect(sortByName([{ name: '51-files-test-260903' }, { name: '9-files-test' }])).toEqual([
      { name: '9-files-test' },
      { name: '51-files-test-260903' },
    ]);
  });

  it('beats the raw string sort on case — the actual alternative', () => {
    // ⛔ THIS TEST WAS VACUOUS UNTIL S209 MUTATION TESTING. It used to assert only
    // that the output was correctly ordered, which passed with OR without the
    // collator option it was supposedly guarding. What it must discriminate against
    // is `Array.sort()` — the thing someone would actually reach for instead.
    const names = ['t2-invite-260807', 'RelayWalk', 'bug223-readonly-test', 'chris-share-260722a'];
    const ours = sortByName(names.map((name) => ({ name }))).map((f) => f.name);
    const raw = [...names].sort();

    expect(ours).toEqual([
      'bug223-readonly-test',
      'chris-share-260722a',
      'RelayWalk',
      't2-invite-260807',
    ]);
    // The positive control: the naive sort really does put RelayWalk first, so the
    // assertion above is testing a difference that exists.
    expect(raw[0]).toBe('RelayWalk');
    expect(ours).not.toEqual(raw);
  });

  it('orders the workspace subfolders that prompted the request', () => {
    // Creation order in the live account was: h1-live-E, bug202-gap-D, bug202-gap-C,
    // bug202-live-B, bug202-live-A, s184-transfer, data, notes.
    const names = [
      'h1-live-E',
      'bug202-gap-D',
      'bug202-gap-C',
      'bug202-live-B',
      'bug202-live-A',
      's184-transfer',
      'data',
      'notes',
    ];
    expect(sortByName(names.map((name) => ({ name }))).map((f) => f.name)).toEqual([
      'bug202-gap-C',
      'bug202-gap-D',
      'bug202-live-A',
      'bug202-live-B',
      'data',
      'h1-live-E',
      'notes',
      's184-transfer',
    ]);
  });

  it('is deterministic on case variants, without a hand-written tiebreak', () => {
    // The collator's DEFAULT sensitivity returns a non-zero for 'data' vs 'Data', so
    // the order does not depend on the input sequence (which is the server's creation
    // order). An earlier version passed sensitivity:'base', which made these compare
    // EQUAL and then needed a tiebreak to stay stable — an option that changed no
    // ordering, plus code to undo its side effect. Both removed.
    expect(compareDisplayNames('data', 'Data')).not.toBe(0);
    const a = sortByName([{ name: 'data' }, { name: 'Data' }]).map((f) => f.name);
    const b = sortByName([{ name: 'Data' }, { name: 'data' }]).map((f) => f.name);
    expect(a).toEqual(b);
  });

  it('does not mutate the caller array', () => {
    // The inputs are store-owned (browser.privateFolders, treeChildren.get(id)); an
    // in-place sort in a presentation component would reorder shared state.
    const input = [{ name: 'b' }, { name: 'a' }];
    const snapshot = [...input];
    sortByName(input);
    expect(input).toEqual(snapshot);
  });

  it('is a total order — sorting an already-sorted list is a no-op', () => {
    const names = ['51-files', 'bug223', 'chris-share', 'RelayWalk', 't2-invite'].map((name) => ({
      name,
    }));
    const once = sortByName(names);
    expect(sortByName(once)).toEqual(once);
  });
});
