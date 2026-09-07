// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// Group a Guardian's "shared with me" folders by owner (Bug009 — the per-PRSN nav).
//
// A folder appears in "shared with me" because the caller is a recipient of it. For
// a Guardian, that set mixes folders owned by their dependent PRSNs (the Guardian is
// the mandatory recipient on every PRSN folder) with folders other *humans* shared
// in. We split them by owner: PRSN-owned folders group under each PRSN; everything
// else is "shared with you".
//
// This is the forward-safe construction for v2 PRSN autonomy: the input is the set of
// folders the Guardian is a *recipient* of, so a future independent-PRSN's private
// folders (no Guardian recipient) are never in the input and can never surface here.

import type { GuardedPrsn } from './api';
import type { NamedFolder } from './browser.svelte';

export interface PrsnFolderGroup {
  prsn: GuardedPrsn;
  folders: NamedFolder[];
}

export interface GroupedShares {
  /** One entry per PRSN in the roster (in roster order), each with the folders that
   *  PRSN owns and shared to the Guardian. A PRSN with no folders yet gets an empty
   *  list (so it still shows in the nav). */
  prsnGroups: PrsnFolderGroup[];
  /** Shared-with-me folders whose owner is not one of the caller's PRSNs — i.e.
   *  folders other humans shared in. */
  humanShared: NamedFolder[];
}

export function groupSharedByOwner(shared: NamedFolder[], prsns: GuardedPrsn[]): GroupedShares {
  const prsnIds = new Set(prsns.map((p) => p.account_id));
  const byOwner = new Map<string, NamedFolder[]>();
  const humanShared: NamedFolder[] = [];

  for (const folder of shared) {
    const owner = folder.ownerAccountId;
    if (owner && prsnIds.has(owner)) {
      const list = byOwner.get(owner);
      if (list) list.push(folder);
      else byOwner.set(owner, [folder]);
    } else {
      humanShared.push(folder);
    }
  }

  const prsnGroups = prsns.map((prsn) => ({
    prsn,
    folders: byOwner.get(prsn.account_id) ?? [],
  }));

  return { prsnGroups, humanShared };
}
