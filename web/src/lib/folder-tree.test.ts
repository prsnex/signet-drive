// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
import { describe, expect, it } from 'vitest';
import type { Crumb, NamedFolder } from './browser.svelte';
import { childCrumb, nodePath } from './folder-tree';

function folder(id: string, name: string): NamedFolder {
  return {
    view: {
      folder_id: id,
      parent_folder_id: null,
      root_folder_id: id,
      folder_type: 'share',
      encrypted_name: '',
      created_at: 0,
      modified_at: 0,
    },
    name,
  };
}

describe('childCrumb', () => {
  it('treats a top-level folder as its own root', () => {
    expect(childCrumb(folder('a', 'Alpha'), [])).toEqual({
      folderId: 'a',
      rootFolderId: 'a',
      name: 'Alpha',
    });
  });

  it('inherits the root id from the first ancestor at depth 1', () => {
    const ancestors: Crumb[] = [{ folderId: 'a', rootFolderId: 'a', name: 'Alpha' }];
    expect(childCrumb(folder('b', 'Beta'), ancestors)).toEqual({
      folderId: 'b',
      rootFolderId: 'a',
      name: 'Beta',
    });
  });

  it('keeps the top-level root id at any depth', () => {
    const ancestors: Crumb[] = [
      { folderId: 'a', rootFolderId: 'a', name: 'Alpha' },
      { folderId: 'b', rootFolderId: 'a', name: 'Beta' },
    ];
    // Even three levels down, rootFolderId is the hierarchy root, not the parent.
    expect(childCrumb(folder('c', 'Gamma'), ancestors)).toEqual({
      folderId: 'c',
      rootFolderId: 'a',
      name: 'Gamma',
    });
  });
});

describe('nodePath', () => {
  it('is just the folder itself at the top level', () => {
    expect(nodePath(folder('a', 'Alpha'), [])).toEqual([
      { folderId: 'a', rootFolderId: 'a', name: 'Alpha' },
    ]);
  });

  it('appends the folder to its ancestors, preserving order', () => {
    const ancestors: Crumb[] = [
      { folderId: 'a', rootFolderId: 'a', name: 'Alpha' },
      { folderId: 'b', rootFolderId: 'a', name: 'Beta' },
    ];
    expect(nodePath(folder('c', 'Gamma'), ancestors)).toEqual([
      { folderId: 'a', rootFolderId: 'a', name: 'Alpha' },
      { folderId: 'b', rootFolderId: 'a', name: 'Beta' },
      { folderId: 'c', rootFolderId: 'a', name: 'Gamma' },
    ]);
  });

  it('does not mutate the input ancestors', () => {
    const ancestors: Crumb[] = [{ folderId: 'a', rootFolderId: 'a', name: 'Alpha' }];
    nodePath(folder('b', 'Beta'), ancestors);
    expect(ancestors).toHaveLength(1);
  });
});
