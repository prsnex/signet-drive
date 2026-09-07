// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { describe, expect, it } from 'vitest';
import {
  clearNavState,
  loadNavState,
  parseNavState,
  saveNavState,
  type NavState,
} from './nav-persist';

/** An in-memory Storage that we can also make hostile (throwing), because Safari private
 *  mode and a full quota BOTH throw on real storage and the restore path must survive it. */
function memStore(opts: { throwOnGet?: boolean; throwOnSet?: boolean } = {}): Storage {
  const m = new Map<string, string>();
  return {
    get length() {
      return m.size;
    },
    clear: () => m.clear(),
    key: (i: number) => [...m.keys()][i] ?? null,
    getItem: (k: string) => {
      if (opts.throwOnGet) throw new Error('storage unavailable');
      return m.get(k) ?? null;
    },
    setItem: (k: string, v: string) => {
      if (opts.throwOnSet) throw new Error('quota exceeded');
      m.set(k, v);
    },
    removeItem: (k: string) => void m.delete(k),
  } as Storage;
}

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';

describe('bug184 nav persistence', () => {
  it('round-trips a path, tree expansion and PRSN expansion', () => {
    const s = memStore();
    const state: NavState = {
      path: [{ folderId: A, rootFolderId: A }],
      treeExpanded: [A, B],
      expandedPrsns: [B],
    };
    saveNavState(state, s);
    expect(loadNavState(s)).toEqual(state);
  });

  it('⚠ NEVER persists a decrypted folder name — ids only', () => {
    const s = memStore();
    saveNavState(
      { path: [{ folderId: A, rootFolderId: A }], treeExpanded: [], expandedPrsns: [] },
      s,
    );
    // The whole serialized blob must not contain anything name-shaped. This is the arm
    // that fails if someone later "simplifies" by persisting Crumb[] wholesale.
    const raw = s.getItem('signet-nav-v1') ?? '';
    expect(raw).not.toMatch(/name/i);
    expect(raw).toContain(A);
  });

  it('a name smuggled into a record is DROPPED on parse, not trusted', () => {
    const parsed = parseNavState({
      path: [{ folderId: A, rootFolderId: A, name: 'Tax Returns 2026' }],
      treeExpanded: [],
      expandedPrsns: [],
    });
    expect(parsed.path).toEqual([{ folderId: A, rootFolderId: A }]);
    expect(JSON.stringify(parsed)).not.toContain('Tax');
  });

  // ── fail-soft arms. bug184 §4: a bad record lands on Home and NEVER errors. ──
  it('absent record → empty state', () => {
    expect(loadNavState(memStore())).toEqual({ path: [], treeExpanded: [], expandedPrsns: [] });
  });

  it('malformed JSON → empty state, no throw', () => {
    const s = memStore();
    s.setItem('signet-nav-v1', '{not json');
    expect(() => loadNavState(s)).not.toThrow();
    expect(loadNavState(s).path).toEqual([]);
  });

  it('wrong-shaped record → empty state', () => {
    expect(parseNavState({ path: 'nope', treeExpanded: 42 })).toEqual({
      path: [],
      treeExpanded: [],
      expandedPrsns: [],
    });
    expect(parseNavState(null)).toEqual({ path: [], treeExpanded: [], expandedPrsns: [] });
    expect(parseNavState('a string')).toEqual({ path: [], treeExpanded: [], expandedPrsns: [] });
  });

  it('partially-corrupt path keeps only the well-formed steps', () => {
    const parsed = parseNavState({
      path: [{ folderId: A, rootFolderId: A }, { folderId: 'not an id' }, null, 7],
      treeExpanded: [A, '', null, 'also not an id'],
      expandedPrsns: [],
    });
    expect(parsed.path).toEqual([{ folderId: A, rootFolderId: A }]);
    expect(parsed.treeExpanded).toEqual([A]);
  });

  it('storage that THROWS on read → empty state, no throw (Safari private mode)', () => {
    expect(() => loadNavState(memStore({ throwOnGet: true }))).not.toThrow();
    expect(loadNavState(memStore({ throwOnGet: true })).path).toEqual([]);
  });

  it('storage that THROWS on write → silent, navigation unaffected (quota full)', () => {
    expect(() =>
      saveNavState(
        { path: [], treeExpanded: [], expandedPrsns: [] },
        memStore({ throwOnSet: true }),
      ),
    ).not.toThrow();
  });

  it('clear removes the record', () => {
    const s = memStore();
    saveNavState(
      { path: [{ folderId: A, rootFolderId: A }], treeExpanded: [], expandedPrsns: [] },
      s,
    );
    clearNavState(s);
    expect(loadNavState(s).path).toEqual([]);
  });

  // Negative control: the parser must not be vacuously permissive — a valid record has
  // to survive it, or every arm above passes by rejecting everything.
  it('negative control: a fully valid record is NOT stripped', () => {
    const valid: NavState = {
      path: [
        { folderId: A, rootFolderId: A },
        { folderId: B, rootFolderId: A },
      ],
      treeExpanded: [A, B],
      expandedPrsns: [A],
    };
    expect(parseNavState(JSON.parse(JSON.stringify(valid)))).toEqual(valid);
  });
});
