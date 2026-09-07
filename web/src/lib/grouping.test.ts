// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { describe, expect, it } from 'vitest';
import { groupSharedByOwner } from './grouping';
import type { NamedFolder } from './browser.svelte';
import type { GuardedPrsn } from './api';

function folder(name: string, ownerAccountId?: string): NamedFolder {
  return {
    name,
    ownerAccountId,
    view: {
      folder_id: `fid-${name}`,
      parent_folder_id: null,
      root_folder_id: `fid-${name}`,
      folder_type: 'share',
      encrypted_name: {},
      created_at: 0,
      modified_at: 0,
    },
  };
}

function prsn(account_id: string, handle: string): GuardedPrsn {
  return { account_id, handle, status: 'active' };
}

describe('groupSharedByOwner', () => {
  it('groups PRSN-owned folders under each PRSN and routes the rest to humanShared', () => {
    const prsns = [prsn('p1', 'ada-ai'), prsn('p2', 'bo-ai')];
    const shared = [
      folder('A', 'p1'),
      folder('B', 'p2'),
      folder('C', 'p1'),
      folder('D', 'human-x'), // another human's share
      folder('E'), // no owner → human bucket
    ];

    const { prsnGroups, humanShared } = groupSharedByOwner(shared, prsns);

    expect(prsnGroups).toHaveLength(2);
    expect(prsnGroups[0].prsn.handle).toBe('ada-ai');
    expect(prsnGroups[0].folders.map((f) => f.name)).toEqual(['A', 'C']);
    expect(prsnGroups[1].prsn.handle).toBe('bo-ai');
    expect(prsnGroups[1].folders.map((f) => f.name)).toEqual(['B']);
    expect(humanShared.map((f) => f.name)).toEqual(['D', 'E']);
  });

  it('keeps a PRSN with no folders in the roster (empty list)', () => {
    const { prsnGroups } = groupSharedByOwner(
      [folder('A', 'p1')],
      [prsn('p1', 'ada-ai'), prsn('p2', 'bo-ai')],
    );
    expect(prsnGroups[1].prsn.handle).toBe('bo-ai');
    expect(prsnGroups[1].folders).toEqual([]);
  });

  it('preserves roster order in prsnGroups', () => {
    const prsns = [prsn('p2', 'bo-ai'), prsn('p1', 'ada-ai')];
    const { prsnGroups } = groupSharedByOwner([folder('A', 'p1')], prsns);
    expect(prsnGroups.map((g) => g.prsn.handle)).toEqual(['bo-ai', 'ada-ai']);
  });

  it('with no PRSNs, every share is humanShared', () => {
    const { prsnGroups, humanShared } = groupSharedByOwner([folder('A', 'someone')], []);
    expect(prsnGroups).toEqual([]);
    expect(humanShared.map((f) => f.name)).toEqual(['A']);
  });
});
