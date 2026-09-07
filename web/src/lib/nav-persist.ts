// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.
// bug184: remember where you were in the Drive across a page load.
//
// A reload used to drop you at Home with the sidebar collapsed, because the Drive has no
// representation of location that outlives the page: it is served from `/`, there is no
// folder route, and there are no history calls anywhere in the drive page. Navigation
// position and tree expansion were ordinary in-memory Svelte state.
//
// ⚠ WHY sessionStorage AND NOT THE URL. The web-native fix is a folder route, which would
// also buy Back/Forward and bookmarking. It was considered and NOT chosen (bug184 §4,
// Chris S173): URLs enter browser history, which syncs to Google on a signed-in Chrome
// profile. Folder *names* are encrypted, so what would leak is "this user opened folder
// <uuid>" — low, but not zero, and the kind of default a privacy product should adopt on
// purpose. This module therefore does NOT deliver bookmarking or the back button; wanting
// those means re-opening the URL decision on its own terms.
//
// ⚠ WHY sessionStorage AND NOT localStorage. Sibling UI state here is persisted in
// localStorage (nav width in FileBrowser, sort order in FileList) because a column width
// is a lasting preference. "Where I was just now" is not, and should not outlive the tab.
// The difference is deliberate — do not "fix" the inconsistency.
//
// ⚠⚠ IDS ONLY — NEVER NAMES. A Crumb carries the DECRYPTED folder name, and sessionStorage
// is plainly readable by any script on the origin. `persist.ts` goes to real trouble to keep
// the KEM key a NON-EXTRACTABLE CryptoKey precisely so script cannot read it out; writing
// plaintext folder names beside it would expose more than the key store does. So we persist
// opaque UUIDs and re-derive names at restore, from data the session has already decrypted.

const KEY = 'signet-nav-v1';

/** One step of the persisted path — the two ids `openTreePath` needs, and no name. */
export interface NavStep {
  folderId: string;
  rootFolderId: string;
}

export interface NavState {
  /** Root → current. Empty means Home. */
  path: NavStep[];
  /** Folder ids expanded in the sidebar tree. */
  treeExpanded: string[];
  /** PRSN account ids whose group is expanded. */
  expandedPrsns: string[];
}

const EMPTY: NavState = { path: [], treeExpanded: [], expandedPrsns: [] };

/** A uuid-shaped string. Deliberately loose — this rejects obvious junk (and anything
 *  that could be a name that leaked in), not every malformed uuid. */
function looksLikeId(v: unknown): v is string {
  return typeof v === 'string' && /^[0-9a-fA-F-]{8,64}$/.test(v);
}

/** Narrow unknown parsed JSON to NavState, dropping anything that does not fit.
 *
 *  ⚠ Total by construction: every failure path returns a VALID NavState rather than
 *  throwing, because the caller's contract (bug184 §4) is that a bad record lands you on
 *  Home exactly as today and never errors. A restore is an optimisation; it must not be
 *  able to become a new failure mode. Same doctrine as persist.ts's fail-open-to-gesture.
 */
export function parseNavState(raw: unknown): NavState {
  if (typeof raw !== 'object' || raw === null) return EMPTY;
  const o = raw as Record<string, unknown>;

  const path: NavStep[] = Array.isArray(o.path)
    ? o.path
        .filter(
          (s): s is { folderId: string; rootFolderId: string } =>
            typeof s === 'object' &&
            s !== null &&
            looksLikeId((s as Record<string, unknown>).folderId) &&
            looksLikeId((s as Record<string, unknown>).rootFolderId),
        )
        .map((s) => ({ folderId: s.folderId, rootFolderId: s.rootFolderId }))
    : [];

  const ids = (v: unknown): string[] => (Array.isArray(v) ? v.filter(looksLikeId) : []);

  return { path, treeExpanded: ids(o.treeExpanded), expandedPrsns: ids(o.expandedPrsns) };
}

/** Read the saved state. Returns EMPTY on absent / unparseable / wrong-shaped records,
 *  and on any storage error (Safari private mode throws on access). */
export function loadNavState(store?: Storage): NavState {
  try {
    const s = store ?? (typeof sessionStorage === 'undefined' ? undefined : sessionStorage);
    if (!s) return EMPTY;
    const raw = s.getItem(KEY);
    if (!raw) return EMPTY;
    return parseNavState(JSON.parse(raw));
  } catch {
    return EMPTY;
  }
}

/** Persist. Silent on failure — a full or unavailable quota must never break navigation,
 *  which is the actual job. */
export function saveNavState(state: NavState, store?: Storage): void {
  try {
    const s = store ?? (typeof sessionStorage === 'undefined' ? undefined : sessionStorage);
    if (!s) return;
    s.setItem(KEY, JSON.stringify(state));
  } catch {
    /* quota, private mode, disabled storage — navigation still works without us */
  }
}

/** Drop the record (sign-out / lock: the next session should not inherit a position). */
export function clearNavState(store?: Storage): void {
  try {
    const s = store ?? (typeof sessionStorage === 'undefined' ? undefined : sessionStorage);
    s?.removeItem(KEY);
  } catch {
    /* nothing to do */
  }
}
