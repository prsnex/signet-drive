// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

/**
 * S209 (Chris): the left panel's standard ordering — alphabetical, with embedded
 * numbers compared as numbers.
 *
 * ── WHY THIS IS A CLIENT CONCERN, PERMANENTLY ─────────────────────────────────
 *
 * The server cannot do it. `folders.encrypted_name` is JSONB ciphertext and there
 * is no plaintext name column, so `folders.rs` orders by `created_at DESC,
 * folder_id DESC` — the only ordering it *can* express. Sorting by name
 * server-side would require the server to read names, which is the product's
 * central guarantee inverted. So ordering by name happens after decryption, here,
 * and that will not change.
 *
 * ⭐ AND IT IS ONLY CORRECT BECAUSE OF bug241. That server ordering is also the
 * keyset pagination cursor (`(created_at, folder_id) < ($3, $4)`, page 50). A
 * client that held one page would be sorting page 1 of a newest-first set — the
 * list would LOOK alphabetical while silently omitting older folders, and would
 * look right in every small account. `drive.ts` now follows the cursor to
 * exhaustion (bug241, S208), so the client holds the complete set and a local sort
 * is total rather than per-page. If that ever regresses to a single page, this
 * sort becomes a lie rather than a nuisance.
 *
 * ── THE COLLATOR ──────────────────────────────────────────────────────────────
 *
 * `numeric: true` so `9-x` precedes `51-x` rather than following it, which a text
 * comparison gets wrong because '5' < '9'.
 *
 * ⛔ THAT IS THE ONLY OPTION SET, AND AN EARLIER VERSION OF THIS FILE WAS WRONG
 * ABOUT WHY. It also passed `sensitivity: 'base'`, justified in a comment as
 * stopping capitals floating above lowercase — `RelayWalk` above `bug223-…`,
 * `S200-PrsnShare` away from `s117`. MEASURED, that justification belongs to a raw
 * `Array.sort()`, NOT to Intl.Collator:
 *
 *     String.sort()       RelayWalk  bug223-…  chris-share-…  t2-invite-…
 *     Collator (default)  bug223-…  chris-share-…  RelayWalk  t2-invite-…
 *     Collator + 'base'   bug223-…  chris-share-…  RelayWalk  t2-invite-…   (identical)
 *
 * ⭐ So the option changed no ordering at all. What it DID do is make `data` and
 * `Data` compare EQUAL (0), which then required a tiebreak to keep the sort stable —
 * an option doing no work, plus code to undo its side effect. Both are gone. The
 * default collator is already case-aware AND returns a deterministic non-zero for
 * case variants, so it is total on distinct names without help.
 *
 * ⚠ Found by mutation: removing `sensitivity: 'base'` left every test passing, which
 * meant the tests asserting "ignores case" were passing for a different reason than
 * they claimed. The real alternative to guard against is the raw string sort, and
 * that is what the tests compare against now.
 */
const collator = new Intl.Collator(undefined, { numeric: true });

/** Compare two display names in the panel's standard order. */
export function compareDisplayNames(a: string, b: string): number {
  return collator.compare(a, b);
}

export function sortByName<T extends { name: string }>(items: readonly T[]): T[] {
  return [...items].sort((x, y) => compareDisplayNames(x.name, y.name));
}
