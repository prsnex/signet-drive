// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! RFC 6962 / RFC 9162 Merkle hash tree over transparency-log entries.
//!
//! The *aggregate* layer on top of the per-entry `entry_hash` chain (`translog`):
//! the log's leaves are the `pubkey_log.entry_hash` values (one per published key),
//! and this module computes the Merkle Tree Hash (root), inclusion proofs, and
//! consistency proofs over them.
//!
//! **Domain separation (RFC 6962 §2.1):** leaf hashes are prefixed `0x00`, internal
//! nodes `0x01`, which defends against leaf-vs-internal second-preimage collisions:
//!
//! ```text
//! leaf_hash(entry_hash)      = SHA-256(0x00 || entry_hash)
//! internal_hash(left, right) = SHA-256(0x01 || left || right)
//! ```
//!
//! **The leaf input is the entry's 32-byte `entry_hash`** (the SHA-256 of the §3.3
//! canonical bytes), not the canonical bytes themselves. So the tree is computed
//! directly from the stored `pubkey_log.entry_hash` column with no canonical-byte
//! reconstruction, and a v2 entry-format change leaves this layer untouched (the
//! leaf is always 32 bytes). (Transparency Log Spec §3.4; test-vectors Cat 08/09/10.)
//!
//! **Tree shape (RFC 6962 §2.1):** the Merkle Tree Hash of `n > 1` leaves splits at
//! `k` = the largest power of two *strictly* less than `n` — NOT `n/2`, NOT padded
//! to a power of two, NOT a duplicated rightmost leaf. This yields left-balanced
//! trees. The empty tree's root is `SHA-256("")`.
//!
//! Proof *construction* follows RFC 6962 §2.1.1 (audit/inclusion path) and §2.1.2
//! (consistency `SUBPROOF`). Proof *verification* follows the explicit algorithms in
//! RFC 9162 §2.1.3.2 / §2.1.4.2 (RFC 6962 leaves verification implicit, defining it
//! only as "reverse the construction").
//!
//! Cost: `merkle_root` / `inclusion_proof` / `consistency_proof` recompute subtree
//! hashes from the leaves, O(n) per call. That is fine at identity-event frequency
//! (the log grows one entry per signup/attestation; roots are computed every 24h).
//! Caching intermediate nodes is the known optimization if the log ever grows large.

use crate::hash::sha256;

const LEAF_PREFIX: u8 = 0x00;
const INTERNAL_PREFIX: u8 = 0x01;

/// `SHA-256(0x00 || entry_hash)` — the Merkle leaf hash for a log entry (RFC 6962
/// §2.1 leaf domain separation).
pub fn leaf_hash(entry_hash: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 33];
    input[0] = LEAF_PREFIX;
    input[1..].copy_from_slice(entry_hash);
    sha256(&input)
}

/// `SHA-256(0x01 || left || right)` — an internal Merkle node (RFC 6962 §2.1
/// internal-node domain separation). Order matters: `left` then `right`.
pub fn internal_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 65];
    input[0] = INTERNAL_PREFIX;
    input[1..33].copy_from_slice(left);
    input[33..].copy_from_slice(right);
    sha256(&input)
}

/// The largest power of two *strictly* less than `n` — the RFC 6962 split point.
/// Requires `n >= 2`.
fn split_point(n: usize) -> usize {
    debug_assert!(n >= 2);
    let mut k = 1;
    while k << 1 < n {
        k <<= 1;
    }
    k
}

/// The Merkle Tree Hash (root) over `entries` — their `entry_hash` values, in log
/// order (RFC 6962 §2.1). The empty log hashes to `SHA-256("")`.
pub fn merkle_root(entries: &[[u8; 32]]) -> [u8; 32] {
    if entries.is_empty() {
        return sha256(&[]);
    }
    mth(entries)
}

/// The Merkle Tree Hash of a non-empty leaf slice (RFC 6962 §2.1 `MTH`).
fn mth(entries: &[[u8; 32]]) -> [u8; 32] {
    match entries {
        [single] => leaf_hash(single),
        _ => {
            let k = split_point(entries.len());
            internal_hash(&mth(&entries[..k]), &mth(&entries[k..]))
        }
    }
}

/// The RFC 6962 §2.1.1 inclusion (audit) path for the entry at 0-based `index` in a
/// log of `entries`: the sibling hashes from the leaf up to the root, deepest first.
/// Panics if `index >= entries.len()`.
pub fn inclusion_proof(entries: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    assert!(index < entries.len(), "inclusion_proof: index out of range");
    let mut path = Vec::new();
    audit_path(entries, index, &mut path);
    path
}

/// RFC 6962 §2.1.1 `PATH(m, D[n])`: recurse toward the leaf, appending the sibling
/// subtree's `MTH` on the way back up (so the path lists the deepest sibling first).
fn audit_path(entries: &[[u8; 32]], index: usize, path: &mut Vec<[u8; 32]>) {
    let n = entries.len();
    if n == 1 {
        return; // PATH(0, D[1]) = {}
    }
    let k = split_point(n);
    if index < k {
        audit_path(&entries[..k], index, path);
        path.push(mth(&entries[k..]));
    } else {
        audit_path(&entries[k..], index - k, path);
        path.push(mth(&entries[..k]));
    }
}

/// Verify an RFC 6962 inclusion proof per **RFC 9162 §2.1.3.2**: reconstruct the
/// root from the entry's `entry_hash`, its 0-based `index`, the `tree_size`, and the
/// `proof` (sibling hashes, deepest first), and compare to `root`.
pub fn verify_inclusion(
    entry_hash: &[u8; 32],
    index: usize,
    tree_size: usize,
    proof: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    if index >= tree_size {
        return false;
    }
    let mut fnode = index;
    let mut snode = tree_size - 1;
    let mut r = leaf_hash(entry_hash);
    for p in proof {
        if snode == 0 {
            return false; // path longer than the tree is tall
        }
        if fnode & 1 == 1 || fnode == snode {
            r = internal_hash(p, &r);
            if fnode & 1 == 0 {
                // fnode == snode and even: descend to the next odd (or zero) level.
                loop {
                    fnode >>= 1;
                    snode >>= 1;
                    if fnode & 1 == 1 || fnode == 0 {
                        break;
                    }
                }
            }
        } else {
            r = internal_hash(&r, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    snode == 0 && &r == root
}

/// The RFC 6962 §2.1.2 consistency proof that the size-`m` prefix of `entries` is a
/// consistent prefix of the full size-`n` log (`n == entries.len()`). Requires
/// `0 < m < n`.
pub fn consistency_proof(entries: &[[u8; 32]], m: usize) -> Vec<[u8; 32]> {
    let n = entries.len();
    assert!(0 < m && m < n, "consistency_proof requires 0 < m < n");
    let mut proof = Vec::new();
    subproof(m, entries, true, &mut proof);
    proof
}

/// RFC 6962 §2.1.2 `SUBPROOF(m, D[n], b)`. `b` marks whether the size-`m` subtree is
/// a complete subtree the verifier already knows the root of (`true` → its root is
/// omitted, supplied by the verifier as `first_hash`).
fn subproof(m: usize, entries: &[[u8; 32]], b: bool, proof: &mut Vec<[u8; 32]>) {
    let n = entries.len();
    if m == n {
        if !b {
            proof.push(mth(entries));
        }
        return;
    }
    let k = split_point(n);
    if m <= k {
        subproof(m, &entries[..k], b, proof);
        proof.push(mth(&entries[k..]));
    } else {
        subproof(m - k, &entries[k..], false, proof);
        proof.push(mth(&entries[..k]));
    }
}

/// Verify an RFC 6962 consistency proof per **RFC 9162 §2.1.4.2**: that the size-`m`
/// tree with root `first_hash` is a prefix of the size-`n` tree with root
/// `second_hash`. Requires `0 < m < n` and a non-empty `proof`.
pub fn verify_consistency(
    m: usize,
    n: usize,
    first_hash: &[u8; 32],
    second_hash: &[u8; 32],
    proof: &[[u8; 32]],
) -> bool {
    if m == 0 || m >= n || proof.is_empty() {
        return false;
    }
    // §2.1.4.2 step 2: when m is an exact power of two, the size-m subtree is a
    // complete subtree whose root SUBPROOF omitted — the verifier supplies it.
    let mut path: Vec<[u8; 32]> = Vec::with_capacity(proof.len() + 1);
    if m.is_power_of_two() {
        path.push(*first_hash);
    }
    path.extend_from_slice(proof);

    let mut fnode = m - 1;
    let mut snode = n - 1;
    // step 4: align fnode to a left-subtree boundary.
    while fnode & 1 == 1 {
        fnode >>= 1;
        snode >>= 1;
    }
    // step 5.
    let mut fr = path[0];
    let mut sr = path[0];
    // step 6.
    for c in &path[1..] {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            fr = internal_hash(c, &fr);
            sr = internal_hash(c, &sr);
            if fnode & 1 == 0 {
                loop {
                    fnode >>= 1;
                    snode >>= 1;
                    if fnode & 1 == 1 || fnode == 0 {
                        break;
                    }
                }
            }
        } else {
            sr = internal_hash(&sr, c);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    &fr == first_hash && &sr == second_hash && snode == 0
}
