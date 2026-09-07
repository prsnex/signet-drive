// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// bug223 §6 — the share-folder authority rules.
//
// The defect these pin: the SERVER's authority model is ternary
// (`None | Read | Write`, `sharing::folder_authority`) and the CLIENT's was binary
// (owner / not-owner, `ownsCurrentRoot`). A `read_write` recipient was therefore
// rendered read-only for DELETE — which the server allows them (bug208 §3b) — and
// full-owner for NEW FOLDER, which the server refuses with a 404 whose message
// claims the folder no longer exists. Both cells were wrong, in opposite
// directions, which is why "just hide the button" would have fixed half of it.
//
// ⚠ Every Guardian holds `read_write` on a PRSN's share folder BY CONSTRUCTION:
// `sharing.rs` inserts that row itself with `is_mandatory_guardian = TRUE` when a
// PRSN creates the folder. So the `read_write` recipient arms below are the
// Guardian's real, everyday state, not an exotic case (Chris, S191: "Guardians are
// always read-write on all PRSN account folders — that is what we planned").

import { describe, it, expect } from 'vitest';
import { mayAddContent, mayDelete } from './browser.svelte';

describe('bug223 §1: mayAddContent — upload / add / delete-own authority', () => {
  it('an owner may add (owned share root reports `owner`)', () => {
    expect(mayAddContent('owner', undefined)).toBe(true);
  });

  it('a private folder may add (reports `null`, not a share at all)', () => {
    expect(mayAddContent(null, undefined)).toBe(true);
  });

  // ⚠⚠ bug223 F2 (Gus) — THE SAME VALUE UNDER ITS SECOND MEANING, pinned on purpose.
  // `currentShareRole` returns `null` for two distinct states: a private folder
  // (owned) and a root not yet RESOLVED — a deep link, or a bug184 nav restore,
  // before `loadSharedWithMe` has landed. This rule treats both as owned, so in that
  // window a recipient briefly sees write controls enabled.
  //
  // ⇒ The fail-closed claim covers the PERMISSION axis only. On the ROLE axis this
  // fails OPEN, it predates this change (`ownsCurrentRoot` has always done it), and
  // it is display-only because the server answers at use. It is pinned here so that
  // it is a recorded decision rather than an accident a future reader "fixes" in
  // either direction without knowing which meaning they are changing.
  it('an UNRESOLVED root is treated as owned — fails OPEN on the role axis, by decision', () => {
    expect(mayAddContent(null, undefined)).toBe(true);
    // and it is the role, not the permission, doing that: a KNOWN recipient with an
    // unknown permission still fails closed.
    expect(mayAddContent('recipient', undefined)).toBe(false);
  });

  it('a `read_write` recipient MAY add — the Guardian-in-a-PRSN-folder case', () => {
    expect(mayAddContent('recipient', 'read_write')).toBe(true);
  });

  it('a `read_only` recipient may NOT add', () => {
    expect(mayAddContent('recipient', 'read_only')).toBe(false);
  });

  // ⚠ The fail-closed arms. A permissions default must never be the permissive
  // one, and "the client could not read the row" must not read as authority.
  it('fails CLOSED on a missing permission', () => {
    expect(mayAddContent('recipient', undefined)).toBe(false);
  });

  it('fails CLOSED on a permission value this client does not know', () => {
    expect(mayAddContent('recipient', 'read_write_someday')).toBe(false);
    expect(mayAddContent('recipient', '')).toBe(false);
    expect(mayAddContent('recipient', 'READ_WRITE')).toBe(false);
  });
});

describe('bug223 §2: mayDelete — delete is TWO rules, not one', () => {
  // A file: folder_authority ⇒ a read_write recipient may delete it (bug208 §3b).
  it('a `read_write` recipient MAY delete a file-only selection', () => {
    expect(mayDelete(/* ownsRoot */ false, /* canAdd */ true, /* hasFolder */ false)).toBe(true);
  });

  // A folder: folders.rs is owner-only, and answers not_found otherwise.
  it('a `read_write` recipient may NOT delete when a FOLDER is selected', () => {
    expect(mayDelete(false, true, true)).toBe(false);
  });

  it('an owner may delete either', () => {
    expect(mayDelete(true, true, false)).toBe(true);
    expect(mayDelete(true, true, true)).toBe(true);
  });

  it('a `read_only` recipient may delete neither', () => {
    expect(mayDelete(false, false, false)).toBe(false);
    expect(mayDelete(false, false, true)).toBe(false);
  });

  // ⭐ The arm that makes this a rule rather than a restatement of canAddContent:
  // a mixed selection must take the STRICTER bar. If mayDelete ignored the folder
  // flag, this would pass wrongly and the server would refuse part of the batch.
  it('a MIXED selection takes the stricter bar for a recipient', () => {
    const filesOnly = mayDelete(false, true, false);
    const withAFolder = mayDelete(false, true, true);
    expect(filesOnly).toBe(true);
    expect(withAFolder).toBe(false);
    expect(withAFolder).not.toBe(filesOnly);
  });
});
