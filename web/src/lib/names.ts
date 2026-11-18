// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

// bug048: client-side name-collision resolution (Finder-style " (N)" suffix).
//
// File names are ciphertext to the server (zero-access), so name uniqueness
// cannot be enforced at the DB or API layer — the client, which decrypts the
// folder listing, is the only place a collision can be SEEN. Both surfaces
// implement this same rule — this module and the CLI's `names.rs` — and pin
// it with MATCHING test vectors (the load-bearing principle's parity
// discipline): the suffix goes before the extension, the LAST dot splits,
// and a leading dot is not an extension boundary.

/** Resolve `desired` against the folder's `taken` names: unchanged when free,
 *  else the first free `"stem (N)ext"` (N = 1, 2, …). */
export function dedupeName(desired: string, taken: ReadonlySet<string>): string {
  if (!taken.has(desired)) return desired;
  const [stem, ext] = splitExtension(desired);
  for (let n = 1; ; n++) {
    const candidate = `${stem} (${n})${ext}`;
    if (!taken.has(candidate)) return candidate;
  }
}

/** The placeholder a file or folder whose name could not be decrypted lists under. */
export const UNREADABLE_NAME = '(unreadable)';

/** bug283: the names a rename or move compares against. An unreadable name cannot be
 *  compared, as on upload and in the CLI, so it is left out rather than matched as the
 *  placeholder text. */
export function readableNames(names: Iterable<string>): Set<string> {
  return new Set([...names].filter((n) => n !== UNREADABLE_NAME));
}

/** bug283: does `name` collide with a name another file in the folder already has?
 *  `others` excludes the file being renamed or moved (by id, so a file renamed to its
 *  own name, or moved into its own folder, is no collision). Equality is EXACTLY
 *  upload's ({@link dedupeName}'s `taken.has`): no case folding and no Unicode
 *  normalization, so the two rules can never disagree. A rename or move states a name
 *  the user chose, so the caller refuses rather than renaming. The CLI's
 *  `names::collides` is the same rule, pinned by matching vectors. */
export function collides(name: string, others: ReadonlySet<string>): boolean {
  return others.has(name);
}

/** bug283: the first name in `moving` that a move would give two files in the target:
 *  one already there (`others`), or an earlier file in the same move (two selected
 *  files sharing a name collide with each other, not with the target: Gus). `null`
 *  when every name is free. */
export function firstCollision(
  moving: readonly string[],
  others: ReadonlySet<string>,
): string | null {
  const seen = new Set(others);
  for (const name of moving) {
    if (collides(name, seen)) return name;
    seen.add(name);
  }
  return null;
}

/** bug283: what a move must refuse, as its caller sees it: the first name among the
 *  moving files that the target already holds, or that two moving files share. The
 *  moving names are a LIST, never a set: making them a set first would dedupe exactly
 *  the duplicate this exists to catch (Gus, v1.2.1 review). Unreadable names on either
 *  side cannot be compared, so they are left out. */
export function moveClash(moving: readonly string[], target: Iterable<string>): string | null {
  return firstCollision(
    moving.filter((n) => n !== UNREADABLE_NAME),
    readableNames(target),
  );
}

/** `"report.pdf"` → `["report", ".pdf"]` · `"archive.tar.gz"` →
 *  `["archive.tar", ".gz"]` (the LAST dot splits) · `".env"` → `[".env", ""]`
 *  (a leading dot is not an extension boundary) · `"README"` / `"trailing."`
 *  → no extension. */
function splitExtension(name: string): [string, string] {
  const i = name.lastIndexOf('.');
  if (i > 0 && i < name.length - 1) return [name.slice(0, i), name.slice(i)];
  return [name, ''];
}
