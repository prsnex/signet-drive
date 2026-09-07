# Test Vector Category 08: Transparency log leaf hash (RFC 6962)

**Layer:** 2 (concrete inputs + filled byte values; the reference entry_hash values are synthetic; see "Reference leaves" below)
**Spec source:** [Transparency Log Spec](../Signet-Drive-Transparency-Log-Spec.md) section 3.4 (leaf hash construction) + RFC 6962 section 2.1 (Merkle Hash Trees)
**External standard:** RFC 6962 (Certificate Transparency)
**Reference implementation:** `signet_crypto::merkle::leaf_hash`, KAT-pinned in `crypto/tests/merkle.rs`.

---

## Why this vector exists

RFC 6962 specifies domain-separated Merkle tree hashing: **leaves are hashed with a `0x00` prefix; internal nodes with a `0x01` prefix.** Without domain separation, an attacker could construct a leaf whose hash equals an internal node's hash, breaking inclusion proofs. The `0x00`/`0x01` prefix is the load-bearing security property of CT-style transparency logs.

The most common transparency-log implementation bug is "forgot the `0x00` prefix on leaves" (or "used `0x01` instead"). This vector pins the prefix and the leaf-hash construction with concrete inputs so any implementation can verify byte-for-byte.

## The leaf input is the `entry_hash`

The Merkle leaf is computed over each entry's **`entry_hash`**, the 32-byte SHA-256 of the section 3.3 canonical bytes ([Category 07](07-pubkey-log-entry-hash.md)), NOT over the canonical bytes directly:

```
leaf_hash(entry_hash) = SHA-256(0x00 || entry_hash)        where entry_hash is 32 bytes
```

This matches the Transparency Log Spec sections 3.4 ("Leaves are `entry_hash` values") and 3.5 (the inclusion-proof worked example). Rationale:

- The `entry_hash` is materialized per entry, so the tree is computed directly from it; no canonical-byte reconstruction at root or proof time.
- The leaf input is always 32 bytes, decoupling the Merkle layer from the entry format: an entry-format change (for example, larger post-quantum public keys in v2 entries) leaves the leaf, internal, root, and proof code untouched.
- Cryptographically sound: `SHA-256(0x00 || SHA-256(canonical_bytes))` is a sound leaf hash; the extra hash weakens nothing.

Implementations MUST hash the `entry_hash`, not the canonical bytes. Skipping the transformation (treating `entry_hash` directly as the leaf value) is the most common implementer error; it produces a false mismatch at proof verification.

## Construction (per RFC 6962 section 2.1 + Transparency Log Spec section 3.4)

```
leaf_hash(d) = SHA-256(0x00 || d)
```

Where `d` is the 32-byte `entry_hash` of a log entry (Category 07). The `entry_hash` is `SHA-256(canonical_bytes)`, the per-entry chain pointer; the `leaf_hash` (this category) hashes that 32-byte value with the `0x00` leaf prefix to form the Merkle leaf.

## Reference leaves

To keep the Merkle vectors (Categories 08, 09, 10) reproducible and independent of the Category 07 key fixtures, the reference `entry_hash` values are the synthetic 32-byte values **`e_i` = byte `i` repeated 32 times** (`e0 = 0x00…00`, `e1 = 0x01…01`, `e2 = 0x02…02`, `e3 = 0x03…03`). The Merkle construction is independent of how an `entry_hash` was derived, so these stand in for real per-entry hashes.

## Test cases

### TC08-01: Empty-input baseline (RFC 6962 prefix sanity)

A pure RFC 6962 sanity check (not a real leaf; real leaves are 32-byte `entry_hash` values): `leaf_hash(b"") = SHA-256(0x00)`.

**Expected output (32 bytes, lowercase hex; fully filled):**

```
6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d
```

**Cross-check:** `printf '\x00' | shasum -a 256`. If an implementation produces `e3b0c44…` (SHA-256 of empty) it forgot the `0x00` prefix; `4bf5122f…` means it used the `0x01` internal prefix instead.

### TC08-02: Leaf hash of `e0` (entry_hash = 0x00…00)

**Input:** `d = e0 = 0x00` repeated 32 times.
**Computation:** `SHA-256(0x00 || e0)`, the SHA-256 of 33 zero bytes.
**Expected output:**

```
7f9c9e31ac8256ca2f258583df262dbc7d6f68f2a03043d5c99a4ae5a7396ce9
```

**Reproduce:** `python3 -c "import hashlib;print(hashlib.sha256(bytes([0])+bytes([0])*32).hexdigest())"`

### TC08-03: Leaf hash of `e1` (entry_hash = 0x01…01)

**Input:** `d = e1 = 0x01` repeated 32 times.
**Computation:** `SHA-256(0x00 || e1)`.
**Expected output:**

```
dcffe786ded16d283c663846ad0c4ff26558fccde36ca9d30b2ea19eade9fc0e
```

**Reproduce:** `python3 -c "import hashlib;print(hashlib.sha256(bytes([0])+bytes([1])*32).hexdigest())"`

### TC08-04: Leaf hash of `e2` (entry_hash = 0x02…02)

**Input:** `d = e2 = 0x02` repeated 32 times.
**Expected output:**

```
cba8c596120bdb69debbd923d92cba948bde7c7d06a465a1bb7d98d3116038fa
```

### TC08-05: Negative tests; common implementer mistakes

For TC08-02 (`leaf_hash(e0)`, correct answer `7f9c9e31…`):

- `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`: SHA-256 of empty (no prefix, no input).
- Hashing the canonical bytes instead of the `entry_hash`: the leaf input is the 32-byte `entry_hash`.
- Using a `0x01` prefix: that is the internal-node prefix (Category 09).

## Implementer notes

- **The prefix is one byte: `0x00`.** Not `0x0000`, not the ASCII char `'0'` (`0x30`). It prepends (`SHA-256(0x00 || d)`); it does not append.
- **`d` is the 32-byte `entry_hash`** (the SHA-256 of the Category 07 canonical bytes), not the canonical bytes and not a re-hash of the `entry_hash`. The total SHA-256 input is exactly 33 bytes (`1 + 32`).
- **In RustCrypto:** `let mut h = Sha256::new(); h.update(&[0u8]); h.update(&entry_hash); h.finalize();`; see `signet_crypto::merkle::leaf_hash`.
- **In WebCrypto:** concatenate `Uint8Array([0x00])` with the 32-byte `entry_hash`, then `crypto.subtle.digest("SHA-256", …)`.

## Reviewer's verification path

For TC08-01: `printf '\x00' | shasum -a 256` gives `6e340b9c…`. For TC08-02/03/04: the `python3` one-liners above. All four are reproducible without any Signet Drive code; they then match `signet_crypto::merkle::leaf_hash` byte-for-byte (the `crypto/tests/merkle.rs` KAT).
