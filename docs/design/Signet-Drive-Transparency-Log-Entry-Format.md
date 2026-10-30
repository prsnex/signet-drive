# Signet Drive Transparency Log Entry Format

## Status

This document specifies the hybrid post-quantum entry formats of the public key transparency log. It extends the [Transparency Log Specification](Signet-Drive-Transparency-Log-Spec.md) and the [Envelope Format](Signet-Drive-Envelope-Format.md), section 10, to the hybrid identity, and it satisfies the requirement in the [PQR Crypto Specification](Signet-Drive-PQR-Crypto-Spec.md), section 9.3, that a recipient's hybrid public keys be visible to watchers so that post-quantum stripping is detectable.

This is the public edition of the specification of record. It is regenerated when the mechanism changes, and substantive changes are noted in release notes. This edition describes the v2 entry and the v3 entry of the log's second epoch.

Byte-level known-answer vectors for every rule in this document live in the repository's crypto test suite, and the test-vector set in [test-vectors/](test-vectors/) covers the canonical bytes of the v1 and v2 entries.

## 1. Requirement

Under the hybrid identity an account holds four public keys. The classical pair is an ES256 signing key and an ECDH KEM key. The post-quantum pair is an ML-DSA-87 signing key and an ML-KEM-1024 KEM key. The original log recorded one 65-byte P-256 key per entry, with a key purpose of `signing` or `kem`. It MUST record the post-quantum keys too. Otherwise a compromised directory serving a classical-only bundle for a post-quantum-enrolled recipient would be undetectable at the log. The server's own ML-DSA-87 verification key MUST likewise appear, so that a substituted server post-quantum verification key is detectable by watchers.

## 2. The v2 entry

The fixed 65-byte `public_key` field cannot hold an ML-KEM-1024 encapsulation key (1568 bytes) or an ML-DSA-87 verification key (2592 bytes). So a v2 entry changes four things.

- `public_key` becomes length-prefixed, a 32-bit big-endian length followed by the bytes. It fits any key size, and the values of classical entries are unchanged.
- The `key_purpose` set gains `signing_pq` (3) and `kem_pq` (4).
- `algorithm`, the existing string field, carries the key's FIPS name, `ML-DSA-87` or `ML-KEM-1024`. The field describes the key, not a wrap construction.
- The append-only per-key model is unchanged. A hybrid identity produces four entries, one per key.

**Canonical bytes of a v2 entry, version-marked.**

```
canonical_bytes_v2 = uint8(entry_version = 0x02)
                  || uint64_be(entry_id)
                  || account_id                  (16 bytes; 16 zero bytes when the entry has no account)
                  || uint8(key_purpose_enum)
                  || uint32_be(len(algorithm)) || algorithm_utf8_bytes
                  || uint32_be(len(public_key)) || public_key
                  || uint64_be(created_at_unix_seconds)
                  || prev_entry_hash             (32 bytes)

entry_hash = SHA-256(canonical_bytes_v2)
```

The version byte is inside the hashed bytes. An unhashed field that selects the hashing rule would be a canonicalization ambiguity, never acceptable in an append-only Merkle structure.

**The hybrid checkpoint.** The cutover from v1 to v2 is itself recorded as a log entry, so the rule boundary lives in the chain. The checkpoint entry has `key_purpose = epoch` (byte `0x00`, which is not a key, so the key purposes stay 1 to 4), no account (`account_id` null, hashed as 16 zero bytes, mirroring the v1 genesis convention for `prev_entry_hash`), `algorithm = "signet-translog-v2"`, and a `public_key` equal to the UTF-8 tag `"signet-pubkey-log-v2-epoch"`. The server inserts it exactly once, under the same append lock as the first v2 entry and immediately before it, with a unique index as the backstop. No deployment sequence or code path can place a v2 entry before the checkpoint.

Each row carries a denormalized `entry_version`, also surfaced in receipts and in the range and inclusion-proof responses, as the verifier's rule-selection hint. The hashed version byte remains authoritative.

## 2b. The v3 entry (the second epoch)

From epoch 2 every entry is v3. It is the v2 layout with the 16-byte `account_id` replaced by the 64-byte **VRF account index**. The suite is ECVRF-RISTRETTO255-SHA512, specified at c2sp.org/vrf-r255, which is RFC 9381's ECVRF construction over the RFC 9496 ristretto255 group. The VRF input is a fixed framing of the account identifier, not the bare identifier.

```
alpha = "signet-pubkey-log-v3-account-index" || 0x00 || account_id (16 raw bytes)
index = VRF_hash(epoch secret key, alpha)      // the output beta, 64 bytes, whole, never truncated
```

The epoch's VRF public key is 32 bytes, a proof is 80 bytes, and the index is the full 64-byte output. A deletion then leaves nothing in the log that names the account. Only a holder of a proof from the server can link an index to an account. `entry_id` is 1-based within its epoch, and each epoch is its own chain and its own Merkle tree.

**Canonical bytes of a v3 entry, version-marked as v2 is.**

```
canonical_bytes_v3 = uint8(entry_version = 0x03)
                  || uint64_be(entry_id)
                  || account_index               (64 bytes; 64 zero bytes when the entry has no account)
                  || uint8(key_purpose_enum)
                  || uint32_be(len(algorithm)) || algorithm_utf8_bytes
                  || uint32_be(len(public_key)) || public_key
                  || uint64_be(created_at_unix_seconds)
                  || prev_entry_hash             (32 bytes)

entry_hash = SHA-256(canonical_bytes_v3)
```

An account-less entry, which is the genesis, hashes its index as 64 zero bytes, as a v2 entry hashed a null account as 16.

**The genesis entry** is each epoch's entry 1. It has `key_purpose = epoch` (`0x00`), no account, `algorithm = "signet-translog-v3"`, a `prev_entry_hash` of 32 zero bytes, and a `public_key` equal to the payload that binds the epoch to the one it succeeds and to its VRF key.

```
payload = "signet-pubkey-log-v3-epoch" || 0x00
       || uint16_be(epoch)
       || uint64_be(previous epoch's final log_size)
       || previous epoch's final merkle_root (32 bytes)
       || SHA-256(this epoch's VRF public key)
```

A client accepts an epoch only when the public roots file carries that end line and the VRF key file carries a line whose key hashes to the payload's value. The Transparency Log Specification, section 5.2, specifies both files.

**The receipt** of a v3 entry has the v2 receipt shape, with `"v": 2`, with `epoch` and `account_index` present, and with no `account_id`. It is built and dual-signed once at insert and stored whole. It is served as stored and never rebuilt from mutable columns. The signing input is unchanged. `"v"` names the receipt's object shape and `entry_version` the entry's canonical-bytes rule, two numbers for two things.

**Binding.** A client that binds a key to an account computes `index = VRF-verify(epoch public key, alpha(account_id), proof)` from the account's proof, with `alpha` as above, which is served beside every account identifier a client binds, and requires every receipt it binds to carry that `account_index` and that `epoch`. In epoch 1 it binds by `account_id`, as before.

## 3. The pair commitment

The PQR Crypto Specification's `rfp = SHA-256(len(rk_ec) || len(rk_pq))` binds both KEM keys. The log carries the two KEM entries for an account, `kem` (2) and `kem_pq` (4). A watcher reconstructs the pair commitment from them and cross-checks it against the attestation's `rfp`. The attestation, the envelope, and the log all carry the same commitment. A post-quantum-stripped bundle changes the reconstructed commitment and is therefore detectable.

## 3a. The completeness rule

The pair commitment of section 3 catches substitution, where the wrong keys give the wrong commitment. It does not catch omission at enrollment. An identity enrolled by a compromised server with classical keys only produces a lone `kem` entry, with nothing to reconstruct and no mismatch, and would be invisible. The rule closes it. Every identity enrolled after the hybrid checkpoint of section 2 MUST appear as a complete key set. That is four entries for a PRSN, two for a human, and two for the server. Watchers flag any incomplete set as an anomaly. With the version marking and the completeness rule together, the log detects post-quantum stripping both ways, by substitution and by absence.

A human's complete set is the hybrid KEM pair, `kem` and `kem_pq`. The human's passkey is deliberately not logged, because the log defends key substitution at directory lookup and the passkey is a server-internal sign-in verifier, not recipient material, and because passkey rotation produces no entries. The human's post-quantum stripping detection surface is exactly the KEM pair.

**From epoch 2.** A v3 entry carries no `account_id`, so a key set is grouped by its `account_index`, which is deterministic for an account under one epoch's VRF key. The rule holds per index. Every account's set is complete at the epoch's genesis, because the cut re-logs each live account's whole set, and a set that is incomplete under an index is the same anomaly.

## 4. Server keys in the log

The server's ES256 and ML-DSA-87 verification keys, published at `/v1/server-info` per the Envelope Format section 9, MUST appear as log entries like any other published key. Distribution and pinning follow one rule, both keys over the same channel together, and the log makes a substituted server post-quantum verification key detectable.

## 5. Watchers

A watcher checks all four identity keys, the server keys, and the reconstructed pair commitment, from the first version of any watcher software. The published `verify/verify-translog.sh` recomputes every entry of a served epoch under the rule its `entry_version` names and checks the epoch's genesis against the public anchor files. A continuously running reference watcher is deferred, as the Transparency Log Specification, section 7.4, describes.
