// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// bug226 §5 — which expanded tree nodes are visible and never fetched.
//
// The defect: `treeExpanded` is persisted across a reload (bug184) and
// `treeChildren` is not, so a restored node rendered expanded with nothing fetched
// — and the template's `?? []` turned that into the sentence "No subfolders.",
// while the main panel listed the same folder's eight children.
//
// ⇒ The rule below exists to keep THREE states apart:
//     · `undefined` — never fetched            (unknown)
//     · `[]`        — fetched, genuinely empty (known, and empty)
//     · non-empty   — fetched, has children    (known)
// Collapsing the first two is the whole bug, so the `[]` arm is the load-bearing
// one here, not the obvious "an expanded node is returned" arm.

import { describe, it, expect } from 'vitest';
import { visibleUnfetchedExpanded } from './browser.svelte';

/** Children maps are keyed by id and hold view-shaped nodes; only the id is read. */
const kids = (...ids: string[]) => ids.map((id) => ({ view: { folder_id: id } }));

describe('bug226: visibleUnfetchedExpanded', () => {
  it('returns nothing when nothing is expanded', () => {
    expect(visibleUnfetchedExpanded(['a', 'b'], new Set(), new Map())).toEqual([]);
  });

  it('returns an expanded root whose children were never fetched', () => {
    expect(visibleUnfetchedExpanded(['a'], new Set(['a']), new Map())).toEqual(['a']);
  });

  // ⭐⭐ THE ARM THE BUG IS ABOUT. `[]` means "we asked, and it is empty" — a node in
  // that state must NOT be re-fetched and must NOT be treated as unknown.
  it('does NOT return a node fetched as genuinely EMPTY (`[]` is not `undefined`)', () => {
    const children = new Map([['a', kids()]]);
    expect(visibleUnfetchedExpanded(['a'], new Set(['a']), children)).toEqual([]);
  });

  it('descends through a fetched node to an expanded, unfetched child', () => {
    const children = new Map([['a', kids('a1', 'a2')]]);
    const expanded = new Set(['a', 'a2']);
    expect(visibleUnfetchedExpanded(['a'], expanded, children)).toEqual(['a2']);
  });

  // ⭐ THE BOUND. A node under a COLLAPSED parent never renders, so fetching it buys
  // nothing and costs one of h1's ~6 connections per host (bug219).
  it('ignores an expanded node hidden under a COLLAPSED parent', () => {
    const children = new Map([['a', kids('a1')]]);
    // 'a1' is expanded but 'a' is not, so 'a1' is never rendered.
    expect(visibleUnfetchedExpanded(['a'], new Set(['a1']), children)).toEqual([]);
  });

  // ⭐ ONE LEVEL PER ROUND: the walk stops AT an unfetched node, because its children
  // are exactly what is unknown. The grandchild cannot surface until its parent is.
  it('stops at an unfetched node rather than guessing past it', () => {
    const expanded = new Set(['a', 'a1', 'deep']);
    // 'a' is unfetched, so 'a1'/'deep' are unreachable this round.
    expect(visibleUnfetchedExpanded(['a'], expanded, new Map())).toEqual(['a']);

    // Once 'a' is known, the next round reaches 'a1'.
    const round2 = new Map([['a', kids('a1')]]);
    expect(visibleUnfetchedExpanded(['a'], expanded, round2)).toEqual(['a1']);
  });

  it('returns each visible unfetched sibling once, in tree order', () => {
    const children = new Map([['r', kids('x', 'y')]]);
    const expanded = new Set(['r', 'x', 'y']);
    expect(visibleUnfetchedExpanded(['r'], expanded, children)).toEqual(['x', 'y']);
  });

  // ⚠ Termination. A folder tree should not contain a cycle; a corrupted parent chain
  // could, and an unguarded walk would hang the page load rather than fail it.
  it('terminates on a cyclic parent chain', () => {
    const children = new Map([
      ['a', kids('b')],
      ['b', kids('a')],
    ]);
    const expanded = new Set(['a', 'b']);
    expect(visibleUnfetchedExpanded(['a'], expanded, children)).toEqual([]);
  });
});
