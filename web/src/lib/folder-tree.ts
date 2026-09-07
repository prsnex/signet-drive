// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Pure helpers for the left-nav folder tree (§1-35). Kept separate from the
// recursive component + the Browser's tree state so the breadcrumb / root-crypto
// math is unit-testable on its own — and reusable by a future main-pane
// tree-table (v0.3.x) without a redo.

import type { Crumb, NamedFolder } from './browser.svelte';

/** The breadcrumb for `folder` sitting under `ancestors` — the path from the
 *  hierarchy root down to the folder's parent (empty for a top-level folder).
 *  `rootFolderId` is constant within a path: it's the top-level folder's id (the
 *  folder's own id when it has no ancestors) and binds the §7.2/§7.3 crypto for
 *  the whole hierarchy — the same rule openTopLevel/openChild encode. */
export function childCrumb(folder: NamedFolder, ancestors: Crumb[]): Crumb {
  return {
    folderId: folder.view.folder_id,
    rootFolderId: ancestors[0]?.folderId ?? folder.view.folder_id,
    name: folder.name,
  };
}

/** The full navigation path to `folder`: its ancestors plus its own crumb. A
 *  tree-node name-click opens this — the main pane needs the whole path (not just
 *  the leaf) so the breadcrumb and the root crypto are correct at any depth. It
 *  doubles as the `ancestors` to hand the node's own children. */
export function nodePath(folder: NamedFolder, ancestors: Crumb[]): Crumb[] {
  return [...ancestors, childCrumb(folder, ancestors)];
}
