// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! bug048: client-side name-collision resolution (Finder-style `" (N)"` suffix).
//!
//! File names are ciphertext to the server (zero-access), so name uniqueness
//! cannot be enforced at the DB or API layer — the client, which decrypts the
//! folder listing, is the only place a collision can be SEEN. Both surfaces
//! implement this same rule — this module and the web client's `names.ts` —
//! and pin it with MATCHING test vectors (the load-bearing principle's parity
//! discipline): the suffix goes before the extension, the LAST dot splits,
//! and a leading dot is not an extension boundary.

use std::collections::HashSet;

/// Resolve `desired` against the folder's `taken` names: unchanged when free,
/// else the first free `"stem (N)ext"` (N = 1, 2, …).
pub fn dedupe_name(desired: &str, taken: &HashSet<String>) -> String {
    if !taken.contains(desired) {
        return desired.to_string();
    }
    let (stem, ext) = split_extension(desired);
    for n in 1u32.. {
        let candidate = format!("{stem} ({n}){ext}");
        if !taken.contains(&candidate) {
            return candidate;
        }
    }
    unreachable!("the u32 candidate space cannot be exhausted");
}

/// `"report.pdf"` → `("report", ".pdf")` · `"archive.tar.gz"` →
/// `("archive.tar", ".gz")` (the LAST dot splits) · `".env"` → `(".env", "")`
/// (a leading dot is not an extension boundary) · `"README"` / `"trailing."`
/// → no extension.
fn split_extension(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(i) if i > 0 && i < name.len() - 1 => (&name[..i], &name[i..]),
        _ => (name, ""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn taken(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    /// These vectors are duplicated VERBATIM in the web client's
    /// `names.test.ts` — the two surfaces must resolve collisions identically
    /// (functional parity). Change both or neither.
    #[test]
    fn shared_parity_vectors() {
        let cases: &[(&str, &[&str], &str)] = &[
            ("report.pdf", &[], "report.pdf"),
            ("report.pdf", &["report.pdf"], "report (1).pdf"),
            (
                "report.pdf",
                &["report.pdf", "report (1).pdf"],
                "report (2).pdf",
            ),
            ("archive.tar.gz", &["archive.tar.gz"], "archive.tar (1).gz"),
            ("README", &["README"], "README (1)"),
            (".env", &[".env"], ".env (1)"),
            ("trailing.", &["trailing."], "trailing. (1)"),
            (
                "wave-a-renamed.bin",
                &["wave-a-renamed.bin"],
                "wave-a-renamed (1).bin",
            ),
            ("a (1).txt", &["a (1).txt"], "a (1) (1).txt"),
        ];
        for (desired, existing, expected) in cases {
            assert_eq!(
                dedupe_name(desired, &taken(existing)),
                *expected,
                "dedupe({desired:?}, {existing:?})"
            );
        }
    }
}
