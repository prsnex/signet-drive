# Test Vector Category 10: Transparency log Merkle root for a known entry sequence

**Layer:** 2 (concrete inputs + filled root values)
**Spec source:** [Transparency Log Spec](../Signet-Drive-Transparency-Log-Spec.md) section 3.4 (Merkle root construction) + RFC 6962 section 2.1
**External standard:** RFC 6962 (Certificate Transparency)
**Reference implementation:** `signet_crypto::merkle::merkle_root`, KAT-pinned in `crypto/tests/merkle.rs`.

---

## Why this vector exists

The Merkle root is the single 32-byte hash that summarizes the entire transparency log up to a given log size. On the publication cadence ([Transparency Log Spec](../Signet-Drive-Transparency-Log-Spec.md) section 5), the server computes the current Merkle root and commits it to the public commitment repository. Watchers verify consistency between consecutive committed roots; verifiers fetch the most recent root and use it as the trust anchor for inclusion proofs.

If implementations disagree on Merkle root computation, the public commits do not match what verifiers compute from the log, and the whole transparency mechanism's verifiability breaks. This vector pins the Merkle root construction with a known entry sequence. It is the **integration test** for Categories 07 (entry hash), 08 (leaf hash), and 09 (internal hash).

## Construction (per RFC 6962 section 2.1 + Transparency Log Spec section 3.4)

```
MerkleRoot(entries) = MTH(entries)

MTH({})            = SHA-256("")                       (only at log_size = 0)
MTH({d})           = leaf_hash(d) = SHA-256(0x00 || d)  (single leaf)
MTH({d_1,…,d_n}), n > 1:
    let k = largest power of 2 strictly less than n
    return internal_hash(MTH({d_1,…,d_k}), MTH({d_{k+1},…,d_n}))
```

Where each `d_i` is the **`entry_hash`** of log entry `i` ([Category 07](07-pubkey-log-entry-hash.md)), the 32-byte leaf input (see [Category 08](08-transparency-log-leaf-hash.md)).

**Key non-obvious property:** RFC 6962 splits at the largest power of 2 less than n, NOT at n/2. For n=3: k=2 (left 2, right 1). n=5: k=4. n=7: k=4. This produces left-balanced trees.

## Reference leaves

The synthetic reference `entry_hash` values from [Category 08](08-transparency-log-leaf-hash.md): `e_i` = byte `i` repeated 32 times. The Merkle construction is independent of how an `entry_hash` was derived, so these stand in for real per-entry hashes and keep the vectors reproducible without the Category 07 key fixtures.

## Test cases

### TC10-01: Empty log (log_size = 0)

`MTH({}) = SHA-256(b"")`. **Fully filled:**

```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

(RFC 6962 section 2.1 specifies this case. Implementations handle both `log_size = 0` and `log_size >= 1`.)

### TC10-02: Single-entry log (log_size = 1)

`MTH({e0}) = leaf_hash(e0)` (= Category 08 TC08-02).

```
7f9c9e31ac8256ca2f258583df262dbc7d6f68f2a03043d5c99a4ae5a7396ce9
```

### TC10-03: Two-entry log (log_size = 2)

`internal_hash(leaf(e0), leaf(e1))` (= Category 09 TC09-02).

```
28fb81e496897e0ce886f08602392e9239b65c659041e5202163e58ad898f444
```

### TC10-04: Three-entry log (log_size = 3); non-power-of-2

Split at `k = 2`: `internal_hash(MTH({e0,e1}), leaf(e2))` (= Category 09 TC09-03).

```
ba8d94b7fbcecae7b81c4c80574fe24734a6917bf9c1ecd66ff3e0c34ead4620
```

### TC10-05: Four-entry log (log_size = 4); power-of-2

Split at `k = 2`: `internal_hash(MTH({e0,e1}), MTH({e2,e3}))`.

```
fdea52008cdae79fa8bf806261959e23f5e11681646a2fa2bc9b5e56b32030a2
```

### TC10-06: Five-entry log (log_size = 5); non-power-of-2 with deeper imbalance

Split at `k = 4`: `internal_hash(MTH({e0..e3}), leaf(e4))`, that is, `internal_hash(TC10-05, leaf(e4))`.

```
85e20cac1f02fda7bcdb2fc3f908568c57018c77815f1fa361acad13994f08bf
```

### TC10-07: Negative tests; common implementer mistakes

For TC10-04 (the three-entry log):

- Splitting at n/2 instead of the largest power of 2 below n: wrong.
- Padding the third entry with a zero leaf, or duplicating it, to make the tree power-of-2: wrong; RFC 6962 promotes the lonely subtree.
- Using the `log_size = 4` shape for `log_size = 3` data: wrong; the tree shape depends on the exact `log_size`.
- Hashing the canonical bytes as leaves instead of the `entry_hash`: wrong; the leaf input is the 32-byte `entry_hash`.

## Reproduction

```
python3 -c "import hashlib
sha=lambda b:hashlib.sha256(b).digest()
L=lambda e:sha(bytes([0])+e); I=lambda l,r:sha(bytes([1])+l+r)
e=[bytes([i])*32 for i in range(5)]; l=[L(x) for x in e]
r2=I(l[0],l[1]); r4=I(r2,I(l[2],l[3]))
print('n=1',l[0].hex()); print('n=2',r2.hex())
print('n=3',I(r2,l[2]).hex()); print('n=4',r4.hex()); print('n=5',I(r4,l[4]).hex())"
```

These match `signet_crypto::merkle::merkle_root` byte-for-byte (`crypto/tests/merkle.rs`), which additionally round-trips inclusion and consistency proofs for log sizes up to 33 (generation per RFC 6962 sections 2.1.1 and 2.1.2, verification per RFC 9162 sections 2.1.3.2 and 2.1.4.2).

## Implementer notes

- **RFC 6962 section 2.1 has the canonical Merkle Tree Hash (MTH) definition.** The split-at-largest-power-of-2 rule is a frequent source of bugs.
- **The root for `log_size = N` is well-defined** given entries `1..N` appended in order.
- **Roots are computed on the publication cadence** (default 24 hours) and committed publicly; see [Transparency Log Spec](../Signet-Drive-Transparency-Log-Spec.md) section 5.
- **Consistency proofs** (RFC 6962 section 2.1.2; RFC 9162 section 2.1.4.2) verify that root `R_M` (size M) and `R_N` (size N > M) are consistent; covered by the `crypto/tests/merkle.rs` round-trip tests.
