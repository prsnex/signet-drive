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

/** `"report.pdf"` → `["report", ".pdf"]` · `"archive.tar.gz"` →
 *  `["archive.tar", ".gz"]` (the LAST dot splits) · `".env"` → `[".env", ""]`
 *  (a leading dot is not an extension boundary) · `"README"` / `"trailing."`
 *  → no extension. */
function splitExtension(name: string): [string, string] {
  const i = name.lastIndexOf('.');
  if (i > 0 && i < name.length - 1) return [name.slice(0, i), name.slice(i)];
  return [name, ''];
}
