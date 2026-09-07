# Test Vector Category 09: Transparency log internal hash (RFC 6962)

**Layer:** 2 (concrete inputs + filled byte values)
**Spec source:** [Transparency Log Spec](../Signet-Drive-Transparency-Log-Spec.md) section 3.4 (internal hash construction) + RFC 6962 section 2.1 (Merkle Hash Trees)
**External standard:** RFC 6962 (Certificate Transparency)
**Reference implementation:** `signet_crypto::merkle::internal_hash` / `merkle_root`, KAT-pinned in `crypto/tests/merkle.rs`.

---

## Why this vector exists

RFC 6962 internal node hashes use the `0x01` domain-separation prefix:

```
internal_hash(left, right) = SHA-256(0x01 || left || right)
```

This is paired with [Category 08](08-transparency-log-leaf-hash.md)'s `0x00` prefix for leaves to prevent leaf-versus-internal-node hash collisions. Pinning the `0x01` prefix and hash construction covers the second-most-common transparency-log implementation bug (after Category 08's leaf prefix). The internal-node construction is identical regardless of the leaf-input choice; it operates on 32-byte child hashes.

## Construction (per RFC 6962 section 2.1 + Transparency Log Spec section 3.4)

```
internal_hash(left, right) = SHA-256(0x01 || left || right)
```

Where `left` and `right` are each 32 bytes (SHA-256 outputs of either leaf hashes or other internal hashes). Total input to SHA-256: 1 + 32 + 32 = 65 bytes.

## Reference leaves

The same synthetic reference `entry_hash` values as [Category 08](08-transparency-log-leaf-hash.md): `e_i` = byte `i` repeated 32 times. Their leaf hashes (Category 08):

- `leaf(e0) = 7f9c9e31ac8256ca2f258583df262dbc7d6f68f2a03043d5c99a4ae5a7396ce9`
- `leaf(e1) = dcffe786ded16d283c663846ad0c4ff26558fccde36ca9d30b2ea19eade9fc0e`
- `leaf(e2) = cba8c596120bdb69debbd923d92cba948bde7c7d06a465a1bb7d98d3116038fa`

## Test cases

### TC09-01: Empty-children baseline (RFC 6962 prefix sanity)

`SHA-256(0x01 || b"" || b"") = SHA-256(0x01)` (a single byte). Degenerate (real children are always 32 bytes); included only to pin the prefix.

**Expected output (32 bytes, lowercase hex; fully filled):**

```
4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a
```

**Cross-check:** `printf '\x01' | shasum -a 256`.

### TC09-02: Two-leaf tree (depth-1 internal node)

The internal node over `leaf(e0)` and `leaf(e1)`; this is also the Merkle root for a 2-entry log ([Category 10](10-transparency-log-merkle-root.md) TC10-03).

**Inputs:** `left = leaf(e0)`, `right = leaf(e1)` (32 bytes each).
**Computation:** `SHA-256(0x01 || leaf(e0) || leaf(e1))`; 65 bytes of input.
**Expected output:**

```
28fb81e496897e0ce886f08602392e9239b65c659041e5202163e58ad898f444
```

**Reproduce:**
```
python3 -c "import hashlib
L=lambda e:hashlib.sha256(bytes([0])+e).digest()
e0=bytes([0])*32; e1=bytes([1])*32
print(hashlib.sha256(bytes([1])+L(e0)+L(e1)).hexdigest())"
```

### TC09-03: Three-leaf tree (depth-2; non-power-of-2 handling)

A three-leaf tree (`e0`, `e1`, `e2`). RFC 6962 splits at the largest power of two below 3, so `k = 2`: the left subtree has leaves 0 and 1, and the lonely third leaf is **promoted as-is** to the parent level (not duplicated, not padded).

**Tree shape:**

```
            Root
           /    \
     internal   leaf(e2)        (lonely right leaf promoted)
      /     \
  leaf(e0) leaf(e1)
```

**Computations:**
- Step 1: `internal = internal_hash(leaf(e0), leaf(e1))` = TC09-02 = `28fb81e4…`
- Step 2: `Root = internal_hash(internal, leaf(e2))`

**Expected output (Root):**

```
ba8d94b7fbcecae7b81c4c80574fe24734a6917bf9c1ecd66ff3e0c34ead4620
```

This is the canonical non-power-of-2 RFC 6962 tree. It catches implementations that pad with a zero leaf or duplicate the rightmost leaf (both common, both WRONG per RFC 6962).

### TC09-04: Negative tests; common implementer mistakes

For TC09-01 (correct answer `4bf5122f…`):

- `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`: SHA-256 of empty (forgot the `0x01` prefix).
- `6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d`: SHA-256 of `0x00` (used the leaf prefix instead).
- For TC09-03: padding or duplicating to make the tree power-of-2; RFC 6962 promotes the lonely subtree.

## Implementer notes

- **The prefix is one byte: `0x01`.** Distinct from the leaf prefix `0x00`. A single byte.
- **`left` and `right` are each 32 bytes.** Total internal-hash input: 65 bytes (`1 + 32 + 32`).
- **Order matters cryptographically:** `internal_hash(a, b) != internal_hash(b, a)`. Inclusion and consistency proofs depend on knowing whether a sibling is on the left or right, derived from the leaf index and tree size (RFC 9162 sections 2.1.3.2 and 2.1.4.2).
- **RFC 6962 non-power-of-2 trees promote singleton subtrees** rather than padding or duplicating. The split is at the largest power of two strictly less than `n`.
- **In RustCrypto:** `let mut h = Sha256::new(); h.update(&[1u8]); h.update(&left); h.update(&right); h.finalize();`; see `signet_crypto::merkle::internal_hash`.

## Reviewer's verification path

TC09-01: `printf '\x01' | shasum -a 256` gives `4bf5122f…`. TC09-02/03: the Python snippets above (chaining Category 08's leaf hashes). All match `signet_crypto::merkle` byte-for-byte.
