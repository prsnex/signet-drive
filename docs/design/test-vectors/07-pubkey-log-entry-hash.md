# Test Vector Category 07: Log entry hash composition

**Layer:** 1 (spec + concrete inputs; v1 Layer 2 byte values pending; the v2 cases are KAT-pinned in the crypto test suite)
**Spec source:** [Transparency Log Spec](../Signet-Drive-Transparency-Log-Spec.md) sections 3.2 and 3.3 + [Envelope Format](../Signet-Drive-Envelope-Format.md) section 10

---

## Why this vector exists

`entry_hash` is the per-entry hash that forms the chain of the public key transparency log. It is composed from 8 fields with mixed encodings (uint64_be, raw bytes, length-prefixed strings), exactly the kind of construction that produces three different byte sequences when three implementers read the spec.

This is **the highest-leverage Signet-Drive-specific test vector**: the transparency log's per-entry tamper evidence depends on every implementation producing the exact same `entry_hash` bytes given the same inputs. A bug here breaks the whole transparency mechanism.

## Composition (v1 entries; per Transparency Log Spec section 3.3)

The `entry_hash` is `SHA-256(canonical_bytes)`, where the canonical bytes are the byte-by-byte concatenation:

```
canonical_bytes = uint64_be(entry_id)                              // 8 bytes
               || account_id_raw                                   // 16 bytes (UUID raw)
               || uint8(key_purpose_enum)                          // 1 byte
               || uint32_be(algorithm_byte_length)                 // 4 bytes
               || algorithm_utf8_bytes                             // variable: byte_length bytes
               || public_key                                       // 65 bytes for X9.63 P-256
               || uint64_be(created_at_unix_seconds)               // 8 bytes
               || prev_entry_hash                                  // 32 bytes (zero for entry 1)
```

Total: `8 + 16 + 1 + 4 + L + 65 + 8 + 32 = 134 + L` bytes, where L is the algorithm string's UTF-8 byte length.

## Per-field encoding rules

| Field | Encoding | Example |
|---|---|---|
| `entry_id` | uint64_be; 8 bytes; big-endian | `entry_id = 1` becomes `00 00 00 00 00 00 00 01` |
| `account_id_raw` | UUID raw bytes; 16 bytes; the UUID's binary encoding (RFC 4122) | `"00000000-0000-4000-8000-000000000001"` becomes `00 00 00 00 00 00 40 00 80 00 00 00 00 00 00 01` |
| `key_purpose_enum` | uint8; 1 byte | `signing` = `0x01`; `kem` = `0x02` (fixed by Transparency Log Spec section 3.3) |
| `algorithm_byte_length` | uint32_be; 4 bytes; the byte count of the next field | `"ES256"` is 5 bytes UTF-8; encode as `00 00 00 05` |
| `algorithm_utf8_bytes` | UTF-8 bytes of the algorithm string; no null terminator | `"ES256"` becomes `45 53 32 35 36` (5 bytes) |
| `public_key` | Raw X9.63 uncompressed P-256 pubkey; 65 bytes; `0x04` then 32-byte X then 32-byte Y | (per key) |
| `created_at_unix_seconds` | uint64_be; 8 bytes; unix seconds (NOT milliseconds) | `1700000000` (`TS_T0`) becomes `00 00 00 00 65 53 45 80` |
| `prev_entry_hash` | 32 raw bytes; SHA-256 of the previous entry's canonical bytes; **all zeros for entry 1** (genesis) | Entry 1: 32 zero bytes; entry 2 onward: the previous entry's hash |

## Test cases

### TC07-01: Genesis entry; first KEM key (human signup)

**Setup:** the first-ever entry in the transparency log: human `alice`'s KEM pubkey, added at sign-up.

**Inputs:**

| Field | Value |
|---|---|
| `entry_id` | `1` |
| `account_id` | `00000000-0000-4000-8000-000000000001` (HUMAN_1 = alice) |
| `key_purpose` | `kem` |
| `algorithm` | `"ECDH-ES+A256KW"` (14 ASCII bytes) |
| `public_key` | (alice's KEM X9.63 P-256 pubkey, 65 bytes; a designated deterministic test key; Layer 2) |
| `created_at` | `1700000000` (`TS_T0`) |
| `prev_entry_hash` | 32 zero bytes (genesis) |

**Expected canonical bytes, byte by byte:**

```
[8 bytes]   00 00 00 00 00 00 00 01                              // entry_id = 1
[16 bytes]  00 00 00 00 00 00 40 00 80 00 00 00 00 00 00 01      // account_id raw
[1 byte]    02                                                    // key_purpose = kem
[4 bytes]   00 00 00 0e                                          // algorithm_byte_length = 14
[14 bytes]  45 43 44 48 2d 45 53 2b 41 32 35 36 4b 57            // "ECDH-ES+A256KW" UTF-8
[65 bytes]  04 <32 bytes X> <32 bytes Y>                         // public_key (Layer 2)
[8 bytes]   00 00 00 00 65 53 45 80                              // created_at (TS_T0 = 1700000000)
[32 bytes]  00 00 00 ... 00                                       // prev_entry_hash = zeros (genesis)
```

Total: `8 + 16 + 1 + 4 + 14 + 65 + 8 + 32 = 148 bytes`.

**Expected entry_hash (Layer 2):** SHA-256 of the 148-byte canonical bytes.

### TC07-02: Second entry; PRSN signing key (attestation, atomicity-paired)

**Setup:** the attestation ceremony inserts TWO log entries atomically: one signing, one KEM. TC07-02 is the signing entry. Ordering is fixed: the signing entry precedes the KEM entry, matching the event definition in Transparency Log Spec section 4.1.

**Inputs:**

| Field | Value |
|---|---|
| `entry_id` | `2` |
| `account_id` | `00000000-0000-4000-8000-00000000000a` (PRSN_1) |
| `key_purpose` | `signing` |
| `algorithm` | `"ES256"` (5 ASCII bytes) |
| `public_key` | (PRSN_1's signing X9.63 P-256 pubkey; Layer 2) |
| `created_at` | `1700000060` (`TS_T1`) |
| `prev_entry_hash` | SHA-256 of TC07-01's canonical bytes (Layer 2) |

**Expected canonical bytes, byte by byte:**

```
[8 bytes]   00 00 00 00 00 00 00 02                              // entry_id = 2
[16 bytes]  00 00 00 00 00 00 40 00 80 00 00 00 00 00 00 0a      // account_id raw (PRSN_1)
[1 byte]    01                                                    // key_purpose = signing
[4 bytes]   00 00 00 05                                          // algorithm_byte_length = 5
[5 bytes]   45 53 32 35 36                                        // "ES256" UTF-8
[65 bytes]  04 <X> <Y>                                            // public_key (Layer 2)
[8 bytes]   00 00 00 00 65 53 45 bc                              // created_at (TS_T1 = 1700000060)
[32 bytes]  <TC07-01 entry_hash>                                  // prev_entry_hash chain
```

Total: `8 + 16 + 1 + 4 + 5 + 65 + 8 + 32 = 139 bytes`.

### TC07-03: Third entry; the PRSN's KEM key (same atomic transaction as TC07-02)

**Inputs:**

| Field | Value |
|---|---|
| `entry_id` | `3` |
| `account_id` | `00000000-0000-4000-8000-00000000000a` (PRSN_1) |
| `key_purpose` | `kem` |
| `algorithm` | `"ECDH-ES+A256KW"` (14 ASCII bytes) |
| `public_key` | (PRSN_1's KEM X9.63 P-256 pubkey; Layer 2) |
| `created_at` | `1700000060` (`TS_T1`; same transaction as TC07-02) |
| `prev_entry_hash` | TC07-02's entry_hash |

Both entries share `created_at` because both inserts happen in one transaction; the fixed signing-then-KEM ordering determines which receives the lower `entry_id`.

### TC07-04: Negative tests; implementer mistakes

For TC07-01's canonical bytes:

- Using little-endian for `entry_id`: must be big-endian.
- Using `uint32_be` instead of `uint64_be` for `entry_id`: the field is 8 bytes.
- Using the UUID hyphenated string instead of raw bytes for `account_id`: the field is 16 raw bytes.
- Using milliseconds for `created_at`: the field is unix seconds.
- Adding a length prefix to `public_key` in a v1 entry: the 65-byte X9.63 form is its own canonical length; no prefix.
- Using the SHA-256 fingerprint instead of the raw 65-byte pubkey: the field is the pubkey bytes themselves.
- Omitting `algorithm` or `created_at`: both are in the hashed bytes.
- Using a different `key_purpose_enum` mapping (`signing=0`, `kem=1`): the mapping is fixed as `signing=0x01`, `kem=0x02`.

## Implementer notes

- **Watch the endianness.** All multi-byte integers are big-endian, matching RFC 6962.
- **UUID raw bytes are 16 bytes, NOT 36 ASCII chars.** Implementations sometimes accidentally encode the hex-with-hyphens form; use the binary representation.
- **The algorithm length prefix is `uint32_be` (4 bytes), not `uint16_be`.** Generous for current strings, but consistent with the format's length-prefix convention.
- **The genesis `prev_entry_hash` is 32 zero bytes.** Not omitted; not one `0x00`; exactly 32 zero bytes.
- **The entry-hash chain provides tamper evidence.** Modifying any earlier entry changes its hash, breaking every subsequent entry's `prev_entry_hash`. Verifiers walk the chain to detect tampering.
- **Server-key publication entries** use the reserved server account id (`ACCOUNT_SERVER_RESERVED`; Transparency Log Spec section 4.1, event 5).

## Reviewer's verification path

1. Reconstruct the canonical bytes per the encoding rules above.
2. Compare the byte sequence to the published Layer 2 fixture.
3. Compute the SHA-256; compare to the published `entry_hash` fixture.

A mismatch at step 2 indicates a spec-interpretation difference (most likely endianness, UUID encoding, the enum mapping, or the length-prefix width). A mismatch at step 3 with a matching step 2 indicates a SHA-256 implementation bug.

## Layer 2 status (v1 cases)

**Pending for TC07-01 through TC07-03** (the reference implementation generates the canonical bytes and hashes; TC07-02 and TC07-03 chain from TC07-01). The v2 cases below are already KAT-pinned.

---

## v2 entry composition (the hybrid four-key identity)

The hybrid identity introduces a **v2 entry format**. The v2 canonical bytes are:

```
canonical_bytes_v2 = uint8(entry_version = 0x02)                   // 1 byte; FIRST, inside the hashed bytes
                  || uint64_be(entry_id)                           // 8 bytes
                  || account_id_raw                                // 16 bytes (ZERO UUID when the entry has no account)
                  || uint8(key_purpose_enum)                       // 1 byte
                  || uint32_be(algorithm_byte_length)              // 4 bytes
                  || algorithm_utf8_bytes                          // L bytes
                  || uint32_be(public_key_byte_length)             // 4 bytes; NEW vs v1 (length-prefixed key)
                  || public_key                                    // K bytes (65 / 1568 / 2592 / the epoch tag)
                  || uint64_be(created_at_unix_seconds)            // 8 bytes
                  || prev_entry_hash                               // 32 bytes
```

Deltas from v1, each load-bearing:

- **The version byte is INSIDE the hashed bytes (MUST):** an unhashed field that selects the hashing rule would be a canonicalization ambiguity in an append-only Merkle structure.
- **`public_key` is length-prefixed** (uint32_be), so the ML-KEM-1024 encapsulation key (1568 bytes) and the ML-DSA-87 verification key (2592 bytes) fit alongside the 65-byte classical keys.
- **`key_purpose_enum` gains** `signing_pq = 0x03`, `kem_pq = 0x04`, and `epoch = 0x00` (the v1-to-v2 cutover checkpoint: an account-less entry whose `algorithm` is `"signet-translog-v2"` and whose `public_key` payload is the UTF-8 tag `"signet-pubkey-log-v2-epoch"`).
- **A NULL account hashes as 16 zero bytes** (the epoch checkpoint; the server's own keys), mirroring the v1 genesis `prev_entry_hash` convention.

v1 entries already in a chain keep the v1 rule forever; a verifier selects the rule per entry (the entry-version field in range responses is the hint; the hashed version byte is authoritative, since recomputation under the claimed rule must reproduce the stored `entry_hash`). The epoch checkpoint marks the boundary in-chain.

### TC07-05 (v2): kem_pq entry, mid-chain

Pinned by the crypto test suite (`entry_hash_v2_matches_hand_built_canonical_bytes`): `entry_id = 7`, `account_id = HUMAN_1`, `key_purpose = kem_pq (0x04)`, `algorithm = "ML-KEM-1024"` (11 bytes), a 1568-byte encapsulation key whose byte `i` is `i % 251`, `created_at = 1700000120`, `prev_entry_hash = 0xAB` repeated 32 times. Preimage length: `1 + 8 + 16 + 1 + 4 + 11 + 4 + 1568 + 8 + 32 = 1653` bytes.

### TC07-06 (v2): the epoch checkpoint, NULL account

Pinned by the crypto test suite (`entry_hash_v2_epoch_checkpoint_hashes_null_account_as_zero_uuid`): `entry_id = 42`, `account_id = NULL` (16 zero bytes), `key_purpose = epoch (0x00)`, `algorithm = "signet-translog-v2"`, `public_key = b"signet-pubkey-log-v2-epoch"`, `created_at = 1700000300`, `prev_entry_hash = 0x11` repeated 32 times.

### TC07-07 (v2): v1/v2 domain separation

Pinned by the crypto test suite (`entry_hash_v1_and_v2_never_collide_on_identical_fields`): identical field values hashed under the v1 and v2 rules MUST produce different hashes (the version byte plus the length prefix separate the domains).
