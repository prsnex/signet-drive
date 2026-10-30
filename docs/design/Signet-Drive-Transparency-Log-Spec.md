# Signet Drive Public Key Transparency Log Specification

## Status

This document specifies the public key transparency log that supports Signet Drive's verifiable trust posture. It is a load-bearing component of the trust model. Passive zero-access comes from cryptography. Verifiable trust comes from open source, reproducible builds, this transparency log, and community watchers.

This is the public edition of the specification of record. It is regenerated when the mechanism changes, and substantive changes are noted in release notes. This edition describes the log through its second epoch.

**Reference points.**

- [Signet Drive Overview](Signet-Drive-Overview.md), the Trust model section.
- [Signet Drive Envelope Format](Signet-Drive-Envelope-Format.md), section 10.
- [Signet Drive Transparency Log Entry Format](Signet-Drive-Transparency-Log-Entry-Format.md), which owns the v2 and v3 entry rules.
- Database tables. These are server-side and their definitions are not published at this time. The wire-visible entry format is fully specified in section 3.
- Test vectors. [test-vectors/](test-vectors/) in this directory covers `entry_hash` canonical bytes, RFC 6962 leaf and internal hashes, and the Merkle root.
- Release and bundle verification procedures. The `verify/` directory at the repository root, including `verify-translog.sh`, which verifies a served epoch end to end.
- Background reading. RFC 6962 (Certificate Transparency), Sigstore Rekor, and Keybase Sigchain are similar designs at varying scales.

Server signing-key rotation procedures live in an internal operations document. The parts that affect verifiers are specified here and in the Envelope Format.

## 1. Goals

The transparency log makes active key substitution publicly detectable. It defends against this threat.

> A compromised Signet Drive operator, or an external attacker with full server compromise, silently substitutes a malicious KEM public key when a recipient queries for a target user's keys, allowing the attacker to read content shared to the substituted key.

Without a transparency mechanism this attack is undetectable, because recipients see whatever key the server returns. With the transparency log, four things hold.

1. Every published KEM and signing public key is recorded in an append-only Merkle log.
2. The log's Merkle root is committed periodically to a public location outside Signet Drive's control.
3. Independent watchers can fetch the log and the published roots and verify that the server reports a consistent log to all queriers.
4. Active substitution requires either (a) the substituted key to also be in the log, in which case the substitution is visible to anyone auditing, or (b) the server to maintain different log states for different queriers, which watchers can detect by comparing roots and entries across requests.

This is the same architectural pattern as Certificate Transparency for TLS certificates.

The mechanism does not cryptographically prevent the attack. It makes the attack detectable. The deterrent is that any attempt would leave evidence. This is the meaningful security property for v1, consistent with the broader verifiable-trust posture.

## 2. Non-goals (v1)

- **Browser-side automatic enforcement.** Certificate Transparency in TLS uses browser-side enforcement, where browsers refuse certificates not present in CT logs. Signet Drive v1 does not do client-side automatic enforcement in the browser. The verifier is the watcher, community or self-run, and the command-line client, which does enforce the anchors described in section 7. A later release may add browser enforcement.
- **Federation and multi-operator logs.** v1 has one log, run by Signet Drive. Multi-operator federation is out of scope.
- **Sigstore-style signed entries.** Each log entry is hashed but not signed individually. The audit guarantee comes from the Merkle structure plus public root commits, not from per-entry signatures.

## 3. Log structure

### 3.1 Storage

The log is stored in two PostgreSQL tables.

- The entries table is append-only, with one row per published public key.
- The roots table holds periodic snapshots of the Merkle root, with a reference to where each root was publicly committed.

From the second epoch the entries table lives in its own schema, owned by an administrative role that the application never connects as. The application holds the right to read and to insert, and nothing else. Database triggers are a second layer. They refuse any update or delete of an entry in the second epoch or later, any update that would move an entry into one, and any truncation. These are defense-in-depth measures. The cryptographic guarantee comes from the Merkle hash chain and the public root commits.

### 3.2 Entry format

| Field | Type | Description |
|---|---|---|
| `epoch` | integer | The epoch the entry belongs to (section 3.8). Entries before the first cut are epoch 1. |
| `entry_id` | integer | 1-based position within its epoch. |
| `entry_version` | integer | The canonical-bytes rule for this entry. 1, 2 or 3. |
| `account_id` | UUID | Whose key. Present for epoch 1 entries. Null from epoch 2. |
| `account_index` | 64 bytes | The account's VRF index (section 3.8). Present from epoch 2. Null for a genesis entry. |
| `key_purpose` | string | `signing`, `kem`, `signing_pq`, `kem_pq`, or `epoch`. |
| `algorithm` | string | `ES256`, `ECDH-ES+A256KW`, `ML-DSA-87`, `ML-KEM-1024`, and similar identifiers. |
| `public_key` | bytes | The key. X9.63 uncompressed for P-256 (65 bytes). |
| `public_key_fingerprint` | hex string | Lowercase hex SHA-256 of the DER SubjectPublicKeyInfo. |
| `created_at` | timestamp | When the entry was added. |
| `prev_entry_hash` | bytes | SHA-256 of entry `entry_id - 1` in the same epoch. Zero bytes for entry 1. |
| `entry_hash` | bytes | SHA-256 of the canonical bytes of this entry, under the rule `entry_version` names. |

Section 3.3 gives the v1 rule, for classical 65-byte keys. Entries after the hybrid checkpoint use the v2 rule of section 3.7, which length-prefixes the key and adds the post-quantum purposes. Entries from the second epoch use the v3 rule of section 3.8, which names the account by its VRF index. The v2 and v3 rules are owned by the [Transparency Log Entry Format](Signet-Drive-Transparency-Log-Entry-Format.md), sections 2 and 2b. The `entry_version` field selects the rule, and the version byte inside a v2 or v3 preimage is authoritative.

### 3.3 Canonical bytes for hashing a v1 entry

Big-endian, length-prefixed where variable.

```
canonical_bytes = (
  uint64_be(entry_id)
  || account_id (16 raw bytes)
  || uint8(key_purpose_enum)             // 1 = signing, 2 = kem
  || uint32_be(algorithm_byte_length) || algorithm_utf8_bytes
  || public_key (65 bytes for P-256)
  || uint64_be(created_at_unix_seconds)
  || prev_entry_hash (32 bytes; all zeros for entry 1)
)

entry_hash = SHA-256(canonical_bytes)
```

Implementations MUST produce these bytes deterministically, with no spurious whitespace and no implementation-dependent encoding. Canonical test vectors for this construction are published under [test-vectors/](test-vectors/) so independent implementations can verify that their canonical-byte construction matches.

### 3.4 Merkle tree construction

Roots are computed via a standard Merkle hash tree (RFC 6962, section 2.1).

- Leaves are `entry_hash` values for `entry_id = 1 ... log_size` within one epoch.
- Internal nodes are `SHA-256(left_child || right_child)` with domain separation as below.
- The root is the top-level hash.

**Rooting policy.** The root for a given `log_size` is computed as the Merkle hash of leaves 1 through `log_size`, using the RFC 6962 construction. Leaf hashes are `0x00 || leaf_data` and internal hashes are `0x01 || left || right`. The prefixes provide domain separation between leaf and internal node hashes, defending against second-preimage attacks.

```
leaf_hash(entry_hash) = SHA-256(0x00 || entry_hash)
internal_hash(left, right) = SHA-256(0x01 || left || right)
```

### 3.5 Inclusion proofs

Standard RFC 6962 section 2.1.1 inclusion proofs. Given `entry_id` and `log_size`, the proof is a list of sibling hashes from the leaf to the root. The verifier reconstructs the root and compares it to the published root for that `log_size`.

**Explicit verification chain.** Independent verifier implementations MUST apply the leaf-hash transformation when reconstructing the root from `entry_hash`. The full chain is as follows.

```
canonical_bytes  --(SHA-256, per section 3.3)-->  entry_hash
entry_hash       --(prepend 0x00, SHA-256)-->  leaf_value = SHA-256(0x00 || entry_hash)
leaf_value + sibling hashes (per inclusion proof)
                 --(SHA-256(0x01 || left || right), per the RFC 6962 internal-node rule)-->  candidate_root
candidate_root == published root for log_size?
```

The `0x00` prefix on leaf hashing and the `0x01` prefix on internal-node hashing provide RFC 6962 domain separation against second-preimage attacks. A common implementer mistake is treating `entry_hash` directly as the leaf value and skipping the `0x00`-prefix transformation. The candidate root will not match, and the verifier would incorrectly conclude the log is inconsistent. The test-vector set includes known-answer vectors for this transformation specifically.

**Worked example.** The example is illustrative, and numeric vectors live in the test-vector set. A log of 4 entries with `entry_hash` values `e1, e2, e3, e4` produces leaves `l1=SHA-256(0x00||e1), l2=SHA-256(0x00||e2), l3=SHA-256(0x00||e3), l4=SHA-256(0x00||e4)`, intermediate nodes `n12=SHA-256(0x01||l1||l2), n34=SHA-256(0x01||l3||l4)`, and root `r=SHA-256(0x01||n12||n34)`. An inclusion proof for entry 2 supplies `l1` and `n34`. The verifier computes `l2` from `e2`, then `n12=SHA-256(0x01||l1||l2)`, then `candidate_root = SHA-256(0x01||n12||n34)`, and compares to the published `r`.

### 3.6 Consistency proofs

Standard RFC 6962 section 2.1.2 consistency proofs. Given two log sizes `m < n` of the same epoch and their respective roots `R_m`, `R_n`, the proof shows that the size-`n` log is an extension of the size-`m` log, with no entries inserted before position `m+1` and no entries modified at positions `1..m`.

### 3.7 The v2 entry format (hybrid post-quantum keys)

Under the hybrid identity, every account holds post-quantum public keys alongside the classical ones ([PQR Crypto Specification](Signet-Drive-PQR-Crypto-Spec.md), section 8), and the log records them. It must. A compromised directory serving a classical-only key bundle for a hybrid-enrolled recipient would otherwise be undetectable at the log, and the same holds for a substituted server PQ verification key.

The v1 format's fixed 65-byte `public_key` field cannot hold an ML-KEM-1024 encapsulation key (1568 bytes) or an ML-DSA-87 verification key (2592 bytes), so entries after the cutover use a **v2 format**.

```
canonical_bytes_v2 = uint8(entry_version = 0x02)                   // FIRST, inside the hashed bytes
                  || uint64_be(entry_id)
                  || account_id_raw              (16 bytes; 16 zero bytes when the entry has no account)
                  || uint8(key_purpose_enum)
                  || uint32_be(algorithm_byte_length) || algorithm_utf8_bytes
                  || uint32_be(public_key_byte_length) || public_key
                  || uint64_be(created_at_unix_seconds)
                  || prev_entry_hash             (32 bytes)

entry_hash = SHA-256(canonical_bytes_v2)
```

Deltas from v1, each load-bearing.

- **The version byte is inside the hashed bytes (MUST).** An unhashed field that selects the hashing rule would be a canonicalization ambiguity in an append-only Merkle structure.
- **`public_key` is length-prefixed** (uint32_be), fitting any key size. Classical key values are unchanged.
- **`key_purpose` gains `signing_pq` (3), `kem_pq` (4), and `epoch` (0).**
- **`algorithm` carries the key's FIPS name** (`ML-DSA-87`, `ML-KEM-1024`) for the PQ entries. The field describes the key, not a wrap construction.
- **The append-only per-key model is unchanged.** A hybrid identity produces one entry per key.

**The hybrid checkpoint.** The v1-to-v2 cutover is itself recorded in the chain, as an account-less entry with `key_purpose = epoch` (byte `0x00`, not a key), `account_id` null (hashed as 16 zero bytes, mirroring the v1 genesis `prev_entry_hash` convention), `algorithm = "signet-translog-v2"`, and `public_key` equal to the UTF-8 tag `"signet-pubkey-log-v2-epoch"`. It is inserted structurally, exactly once, immediately before the first v2 entry, so the rule boundary lives in the chain itself.

**Rule selection.** v1 entries already in the chain keep the v1 rule forever. A verifier selects the hashing rule per entry. The `entry_version` field surfaced in receipts and in range and inclusion-proof responses is the hint, and the hashed version byte is authoritative, since recomputation under the claimed rule must reproduce the stored `entry_hash`. Identical field values hashed under the v1 and v2 rules can never collide, because the version byte and the length prefix separate the domains.

**The Merkle layer is unchanged.** Leaves remain `SHA-256(0x00 || entry_hash)` over the 32-byte `entry_hash` whatever the entry version. The leaf, internal, root, and proof code never touch entry internals. Known-answer vectors are in [test-vectors](test-vectors/), Category 07 (the v2 cases).

### 3.8 Epochs and the v3 entry format

The log is a sequence of **epochs**. Each epoch is its own chain and its own Merkle tree, with entries `1..=size` within the epoch, its own roots, and its own proofs. Epoch 1 is the log as it stood before the first cut. From epoch 2 every entry is **v3**.

**Why epochs exist.** In epoch 1 an entry names its account by the account identifier. When an account is deleted, an entry that names it cannot be deleted without breaking the hash chain, and cannot be kept without keeping the identifier. The second epoch resolves this. From epoch 2 an entry names its account by a **VRF account index**, the 64-byte output of ECVRF-RISTRETTO255-SHA512 over the account identifier under the epoch's VRF key. A deletion then leaves nothing in the log that names the account. Only a holder of a proof from the server can link an index to an account.

**The v3 rule.** v2's layout with the 16-byte `account_id` replaced by the 64-byte `account_index`.

```
canonical_bytes_v3 = uint8(entry_version = 0x03)
                  || uint64_be(entry_id)
                  || account_index               (64 bytes; 64 zero bytes when the entry has no account)
                  || uint8(key_purpose_enum)
                  || uint32_be(algorithm_byte_length) || algorithm_utf8_bytes
                  || uint32_be(public_key_byte_length) || public_key
                  || uint64_be(created_at_unix_seconds)
                  || prev_entry_hash             (32 bytes)

entry_hash = SHA-256(canonical_bytes_v3)
```

The [Transparency Log Entry Format](Signet-Drive-Transparency-Log-Entry-Format.md), section 2b, owns this rule and the genesis payload below.

**The genesis entry.** Each epoch from the second begins with a genesis entry, which is entry 1 of the epoch. It has `key_purpose = epoch` (byte `0x00`), no account, `algorithm = "signet-translog-v3"`, and a `prev_entry_hash` of 32 zero bytes. Its `public_key` is the payload that binds the epoch to the one it succeeds and to its VRF key.

```
payload = "signet-pubkey-log-v3-epoch" || 0x00
       || uint16_be(epoch)
       || uint64_be(previous epoch's final log_size)
       || previous epoch's final merkle_root (32 bytes)
       || SHA-256(this epoch's VRF public key)
```

So the boundary lives in the chain. A client accepts an epoch only when the public roots file carries the end line the payload names and the VRF key file carries a line whose key hashes to the payload's value (section 5.2).

**The served epoch and the newest epoch.** Every endpoint in section 6 answers for the served epoch only. New entries go to the newest epoch. Once epoch N is built, epoch N minus 1 is closed and its end line cannot move.

**The cut.** An epoch cut is an operator procedure with four steps in a fixed order. First, epoch N is built, with its genesis and every live key re-logged, and not yet served. Second, the end line of epoch N minus 1 and the VRF key of epoch N are published (section 5.2). Third, the operator waits out the anchor files' cache window, and the server begins to serve epoch N. Fourth, the rows of epoch N minus 1 are deleted. A retired epoch stays on the public record through its end line, its root tags, and its successor's genesis.

**Receipts for v3 entries.** The receipt of a v3 entry has the v2 receipt shape, with `epoch` and `account_index` present and no `account_id`. It is built and signed once at insert and stored whole, and it is served as stored. `"v"` names the receipt's object shape and `entry_version` the entry's canonical-bytes rule.

**Binding a key to an account from epoch 2.** A client that binds a key to an account computes the index from the account's proof, `index = VRF-verify(epoch key, account_id, proof)`, and requires every receipt it binds to carry that `account_index` and that `epoch`. The proof is served beside every account identifier a client binds. In epoch 1 a client binds by `account_id`, as before.

## 4. What gets logged

### 4.1 Event triggers

A new entry is added for each of the following events.

1. **Human signup.** Two entries, the human's classical KEM public key (`kem`) and the ML-KEM-1024 encapsulation key (`kem_pq`), which are the hybrid directory pair recipients wrap to. The human's signing key is the WebAuthn passkey, which is per-credential rather than per-account, and is not logged, since it is not used for cryptographic recipient lookup.

   **Why the passkey's public key is not in the log.** The passkey's public key is used by Signet Drive to verify the user's sign-in WebAuthn assertions, a server-internal verification path. It is not used by other parties to look up the user's identity for content delivery. Only the KEM public key is used that way. The transparency log specifically defends against active key substitution at directory lookup, where Alice queries for a user's public key and the server might lie about it. That attack vector applies to KEM keys, which other users wrap content to, but not to passkey signing keys, which only the server's own authentication verification consumes. Logging passkey public keys would add noise without adding protection.

2. **Passkey rotation (humans).** The user's underlying ECDH KEM public key does not change during passkey rotation. Only the wrap of the private key changes. Therefore there is no new entry on passkey rotation.

3. **PRSN attestation issuance.** Four new entries, one per attested key. The classical signing and KEM keys (`signing`, `kem`) and the post-quantum pair (`signing_pq`, `kem_pq`).

4. **PRSN attestation revocation.** No new entry. Revocation is recorded in attestation state and reflected in the verification response, with status "revoked". The transparency log records what was published. Revocation is a separate state on top.

5. **Server signing key rotation.** Entries for the server's signing public keys, both halves (`signing` for ES256, `signing_pq` for ML-DSA-87), under a reserved account created at deploy time and labeled as such. A substituted server PQ verification key is therefore watcher-detectable like any other published key.

6. **PRSN attestation re-issuance after revocation.** If a Guardian revokes a PRSN's attestation and issues a new one with new keys, the new keys get new entries. If the same keys are re-attested, there are no new entries.

7. **An epoch cut.** The genesis entry, then one entry for every key that was live at the cut, re-logged under the new epoch.

8. **Account deletion.** No new entry, and no entry removed. From the second epoch the entries of a deleted account remain in the log under an index that names no one.

### 4.2 What is not logged

- **Per-file DEKs and DEK wraps.** They are per-message, and there is no value in logging billions of them.
- **Per-folder metadata keys and metadata-key wraps.**
- **Guardianship relationships.** They are internal data by design.
- **Sharing topology.**
- **The server's verification-response signatures.** They are not logged individually. The server's signing key being in the log is what allows verifiers to authenticate those responses.

The transparency log is specifically about published public keys, the things a server might lie about when serving a key lookup.

## 4a. Signed log receipts

### 4a.1 Why receipts

The log mechanism alone, a Merkle tree plus periodic public root commits, leaves a gap. When a new key is added to the log, what is the verifier's behavior in the window between the insert and the next publicly committed Merkle root, which can be up to the publication interval away?

The log adopts the Certificate Transparency SCT pattern. At the moment of the insert, the server immediately issues a signed log receipt, the equivalent of a Signed Certificate Timestamp. The receipt is the immediate trust signal for verifiers. Inclusion in a publicly committed root within the Maximum Merge Delay (MMD) is the retrospective audit anchor.

This eliminates the "key in log but not yet committed" gap entirely. Verifiers do not wait for the next publication cycle. They accept the receipt as evidence of inclusion, with the implicit promise that the entry will appear in some publicly committed root within MMD.

### 4a.2 Receipt format

JSON shape. The bytes-on-the-wire specification is in [Signet Drive Envelope Format](Signet-Drive-Envelope-Format.md), section 10a.

```json
{
  "v": 1,
  "type": "signet-pubkey-log-receipt",
  "entry_id": 9876,
  "account_id": "<UUID>",
  "key_purpose": "kem",
  "algorithm": "ECDH-ES+A256KW",
  "public_key_fingerprint": "<lowercase hex>",
  "entry_hash": "<lowercase hex>",
  "log_size_at_insertion": 9876,
  "issued_at": <unix seconds>,
  "max_merge_delay_seconds": 86400,
  "server_key_id": "<UUID>",
  "server_signature": "<base64url>"
}
```

Server signature. ECDSA P-256 over `"signet-pubkey-log-receipt-v1\n" || canonicalize_RFC_8785(receipt_without_signature)`, signed with the server's attestation-verification-purpose signing key. A v2 receipt is dual-signed, with the classical signature and an ML-DSA-87 signature, and carries `"v": 2`. From epoch 2 a receipt carries `epoch` and `account_index` and no `account_id`, and it is stored whole at insert and served as stored.

### 4a.3 Maximum Merge Delay (MMD)

MMD is 24 hours. It is a server configuration value with a default of 86400 seconds. This matches Certificate Transparency precedent, since the major CT logs use a 24-hour MMD.

The publication cadence is also a server configuration value, with a default of 24 hours, and matches MMD. Operators can shorten it if a real reason emerges.

### 4a.4 Verifier behavior with receipts

When a verifier receives a public key, via an attestation verification response per the Envelope Format section 9 or another path, the response includes or links to the corresponding log receipt. The verifier does four things.

1. Verifies the receipt's `server_signature` against the server's signing key, fetched from `/v1/server-info`.
2. Verifies that the receipt's `entry_hash` matches the canonical bytes for the asserted public key, under the rule `entry_version` names.
3. If `(now - receipt.issued_at)` is at most `receipt.max_merge_delay_seconds`, the receipt is valid as immediate evidence. The entry is in the log and will be in some publicly committed Merkle root within MMD.
4. If `(now - receipt.issued_at)` exceeds `receipt.max_merge_delay_seconds`, the entry MUST be in some publicly committed Merkle root. The verifier can fetch an inclusion proof and confirm.

Verifiers wanting stronger assurance can additionally verify the inclusion proof against the latest publicly committed root even before MMD has elapsed, at the cost of additional round trips.

### 4a.5 Watcher behavior with receipts

For each publicly committed Merkle root, the watcher verifies that every entry whose receipt was issued more than MMD ago is included in that root or a later one. A miss means the log is provably misbehaving, and the watcher alerts.

This catches the case where the server issues receipts but does not include the entries in published roots. That is provable misbehavior, not just inconsistent reporting.

## 5. Public root publication

### 5.1 Cadence

On the publication cadence (default 24 hours), a scheduler job runs five steps.

1. Read the current size of the served epoch.
2. If the size has grown since the last published root, compute the Merkle root over entries 1 through the current size.
3. Record the new root with its size and computation time, not yet committed.
4. Trigger the public commit (section 5.2). On success, record the commit time and the commit URL.
5. On commit failure, leave the root uncommitted, retry on the next cadence, and alert on persistent failure.

### 5.2 Public commit destination

The Merkle root is committed to a public GitHub repository under Signet Drive's control but not on Signet Drive's infrastructure. For production it is [signet-drive-transparency-log](https://github.com/prsnex/signet-drive-transparency-log). The repository is read-public, and only authorized Signet Drive servers can push.

**Implementation note.** The push uses a fine-grained GitHub token over HTTPS (the Contents API), not an SSH deploy key. It matches the server's outbound-HTTP style, needs no SSH key or `git` binary in the container, and the token is scoped to write the contents of this one repository. The security property is the same. Only a server holding the secret can push. The repository and token are deploy-time infrastructure.

**The roots file.** Each root commit adds one line to `roots.jsonl`, one JSON object per line, append-only.

```json
{"epoch": 2, "log_size": 12345, "merkle_root": "<hex>", "computed_at": "<ISO 8601>", "committed_at": "<ISO 8601>"}
```

A line with no `epoch` field is epoch 1. Every later root line carries `"epoch": N`. Each root commit also carries a tag named after the size. Epoch 1 keeps `root-<size>`, and later epochs use `e<N>-root-<size>`. Watchers can fetch all roots via the file or query the tag list. The commit message is `Publish Merkle root for log_size 12345`.

**The end line.** When an epoch is cut, the ending epoch's last root is republished as its end line, with `"epoch_end": true` and a reason.

```json
{"epoch": 1, "epoch_end": true, "log_size": 101, "merkle_root": "<hex>", "reason": "<text>", "committed_at": "<ISO 8601>"}
```

**The VRF key file.** `vrf-keys.jsonl` carries one line per epoch from the second.

```json
{"epoch": 2, "vrf_suite": "ECVRF-RISTRETTO255-SHA512", "vrf_public_key": "<hex 32>", "genesis_entry_hash": "<hex 32>", "committed_at": "<ISO 8601>"}
```

Each end line and each key line is appended once. The same line again is a no-op, and a different line for the same epoch is refused. An epoch's root lines are held until both of its anchoring lines are committed, so no reader sees an epoch's roots before the lines that anchor them. Clients read both files from `raw.githubusercontent.com`, unauthenticated, and never from a location the server names.

Each commit is a separate, append-only addition. The git history of the two files is the publication record.

### 5.3 Why GitHub specifically

- **External infrastructure.** GitHub is operated by Microsoft, not Signet Drive. A commit cannot be quietly retracted, and the history is preserved.
- **Easy verification.** Anyone with `git` can clone the repository and inspect the history.
- **Standard tooling.** Watchers can use any GitHub-aware tooling.
- **Long-term durability.** GitHub's data durability is widely trusted.

Alternatives considered were IPFS, which is decentralized but harder to verify, dedicated transparency log services, which are operationally heavier, and other version-control hosting, which has similar properties. If GitHub's role becomes a concern, a secondary commit destination can be added. Watchers verifying multiple sources of the same root values is the right design pattern.

### 5.4 Commit failure recovery

If the public commit fails for a sustained period, six things follow.

- The internal log keeps growing, and new entries continue to be inserted.
- New roots accumulate uncommitted.
- Receipts (section 4a) continue to be issued at insert time. The receipt mechanism is independent of commit health, and verifiers continue to receive valid receipts as immediate evidence of inclusion during the gap.
- Alerting fires.
- The operator investigates whether GitHub is down, the token is invalid, or the network is broken.
- When the issue is resolved, the scheduler catches up, committing all pending roots in order. Receipts issued during the gap come under the next published root and the audit chain is restored.

The receipt mechanism continues to operate during commit gaps. What degrades is the retrospective audit anchor, that is, verifying entries against a publicly committed root after MMD has elapsed. Once commits resume and catch-up completes, the audit chain is fully restored. Public commitment failure is a high-priority operational alert for two reasons. External watchers cannot verify root consistency during the gap. And if MMD elapses for entries issued before the gap and commits do not resume, those entries miss their audit-anchor deadline and the log becomes provably misbehaving. The gap is bounded by MMD, and sustained gaps approaching MMD warrant escalation.

## 6. Endpoints

Every endpoint answers for the served epoch only. Where an endpoint takes an optional `epoch` parameter, a value other than the served epoch is refused. An earlier epoch answers `410` with the code `epoch_retired` and details naming the epoch, its final log size and its final Merkle root. A later epoch, or one the server has never had, answers `404` with the code `epoch_unknown` and the epoch in its details. Both use the server's standard error envelope.

```json
{"error": {"code": "epoch_retired", "message": "<text>", "details": {"epoch": 1, "final_log_size": 101, "final_merkle_root": "<hex>"}}}
```

A client whose command spans a cut re-anchors and retries once, and never binds a receipt from one epoch under an anchor from the other.

### 6.1 `GET /v1/transparency/log/root`

Returns the current root state of the served epoch.

Response, in JSON.

```json
{
  "epoch": 2,
  "current_log_size": 12345,
  "current_merkle_root": "<hex>",
  "computed_at": <unix seconds>,
  "last_publicly_committed": {
    "log_size": 12340,
    "merkle_root": "<hex>",
    "committed_at": <unix seconds>,
    "commit_url": "https://github.com/prsnex/signet-drive-transparency-log/commit/<sha>"
  },
  "previous_epoch": {
    "epoch": 1,
    "log_size": 101,
    "merkle_root": "<hex>"
  }
}
```

The response includes both the current internal state and the most recently publicly committed state. They may differ briefly during the gap between log growth and the next publication cadence, and watchers reconcile by waiting for the next public commit. From epoch 2 the response carries `previous_epoch`, the end line the served epoch's genesis binds. `current_*` and `last_publicly_committed` describe the served epoch only.

### 6.1a `GET /v1/transparency/log/receipt?fingerprint=<hex>&purpose=<purpose>&epoch=<N>`

Returns the most recent signed log receipt for the (fingerprint, purpose) pair in the served epoch. Verifiers use this to fetch receipts on demand when a verification response does not include them inline. The `epoch` parameter is optional and must name the served epoch.

Response, in JSON. The receipt format per section 4a.2.

The `Cache-Control` header is `public, max-age=300`. Receipts are stable. An entry can change only if a new entry exists for the same account, key purpose and public key, which happens only on initial publication, on re-publication after revocation, or at an epoch cut.

### 6.2 `GET /v1/transparency/log/inclusion-proof?fingerprint=<hex>&purpose=<purpose>&epoch=<N>`

Returns an inclusion proof for the most recent entry matching the given fingerprint and purpose in the served epoch. The `epoch` parameter is optional and must name the served epoch.

Response, in JSON.

```json
{
  "epoch": 2,
  "entry_id": 35,
  "entry_version": 3,
  "account_index": "<hex 64>",
  "key_purpose": "kem",
  "algorithm": "ECDH-ES+A256KW",
  "public_key": "<base64url>",
  "public_key_fingerprint": "<hex>",
  "created_at": <unix seconds>,
  "prev_entry_hash": "<hex>",
  "entry_hash": "<hex>",
  "log_size_at_proof": 12345,
  "merkle_root_at_proof": "<hex>",
  "inclusion_proof": [
    "<sibling hash 1, hex>",
    "<sibling hash 2, hex>",
    ...
  ]
}
```

An epoch 1 response carries `account_id` in place of `account_index`.

The verifier recomputes `entry_hash` from the served fields, under the rule `entry_version` names, and requires `fingerprint(public_key)` to equal the fingerprint it asked about and `key_purpose` the purpose it asked about. It then derives the leaf from the recomputed hash (leaf = `SHA-256(0x00 || entry_hash)`, section 3.5), reconstructs the root from the leaf hash plus sibling hashes, compares it to `merkle_root_at_proof`, and cross-references `merkle_root_at_proof` against the publicly committed root for that log size. The response carries every field the recomputation needs, so the proof is verifiable from this response alone, and the verifier never trusts a server-vouched hash. A server that answers with a genuine proof for a different entry is caught at the fingerprint check.

### 6.3 `GET /v1/transparency/log/range?start=<entry_id>&end=<entry_id>&epoch=<N>`

Returns log entries in a range of the served epoch, for watchers downloading the full log incrementally. The `epoch` parameter is optional and must name the served epoch.

Response, in JSON, paginated.

```json
{
  "entries": [
    {
      "epoch": 2,
      "entry_id": 100,
      "entry_version": 3,
      "account_index": "<hex 64>",
      "key_purpose": "kem",
      "algorithm": "ECDH-ES+A256KW",
      "public_key": "<base64url>",
      "public_key_fingerprint": "<hex>",
      "created_at": <unix seconds>,
      "prev_entry_hash": "<hex>",
      "entry_hash": "<hex>"
    },
    ...
  ],
  "next_cursor": "<entry_id or null>"
}
```

Each entry carries `epoch` and `entry_version`. A v3 entry carries `account_index` (hex, 64 bytes, null for the genesis) in place of `account_id`. Watchers MUST verify each entry's `entry_hash` against the canonical-byte computation locally. They do not trust the server's reported hash.

### 6.4 `GET /v1/transparency/log/consistency-proof?from=<log_size>&to=<log_size>&epoch=<N>`

Returns a consistency proof between two sizes of the served epoch (RFC 6962, section 2.1.2). Watchers use this to verify that a larger root is an append-only extension of a smaller root. The sizes are the served epoch's. The `epoch` parameter is optional and must name the served epoch, so a client whose reads straddle a cut re-anchors, and never proves one epoch's sizes over another epoch's tree.

Response, in JSON.

```json
{
  "from_log_size": 1000,
  "to_log_size": 2000,
  "from_merkle_root": "<hex>",
  "to_merkle_root": "<hex>",
  "consistency_proof": ["<hash 1>", "<hash 2>", ...]
}
```

The verifier checks the proof per RFC 6962.

### 6.5 `GET /v1/server-info`

Returns the server's currently active signing public keys, for verifying server-signed verification responses per the Envelope Format section 9, and the transparency log's served epoch.

Response, in JSON.

```json
{
  "current_signing_keys": [
    {
      "key_id": "<UUID>",
      "purpose": "attestation_verification",
      "algorithm": "ES256",
      "public_key": "<base64url X9.63 65 bytes>",
      "public_key_fingerprint": "<hex>",
      "created_at": <unix seconds>,
      "transparency_log_entry_id": <entry_id>
    }
  ],
  "retired_signing_keys": [...],
  "translog": {
    "epoch": 2,
    "vrf_suite": "ECVRF-RISTRETTO255-SHA512",
    "vrf_public_key": "<hex 32>"
  }
}
```

Returns both the current keys, for verifying recent responses, and retired keys, for verifying historical responses. Each key's `transparency_log_entry_id` references its entry in the log so verifiers can confirm the published key is logged. The `translog` object names the served epoch and its VRF key, and reads `{"epoch": 1}` before the first cut. A client never trusts the key alone. It must equal the epoch's line in `vrf-keys.jsonl` (section 5.2).

## 7. Watcher protocol

A watcher is any party that periodically fetches the log and the public roots and verifies consistency.

### 7.1 Initial state

The watcher remembers the most recent `(epoch, log_size, merkle_root)` triple it has verified. On first run, this is epoch 1 at size 0 with the empty-tree hash.

### 7.2 Periodic check

On each run, hourly for example, the watcher does the following.

1. Fetch the latest publicly committed root. Read the latest line of `roots.jsonl` in the anchor repository, giving `(epoch, new_log_size, new_merkle_root, committed_at)`.
2. If the epoch is the watcher's known epoch and `new_log_size` exceeds the watcher's known size, do four things.
   a. Fetch a consistency proof from the server, `GET /v1/transparency/log/consistency-proof?from=<known size>&to=<new_log_size>&epoch=<epoch>`.
   b. Verify the proof against `(known root, new_merkle_root)` per RFC 6962. Fail loudly if inconsistent.
   c. Optionally, fetch all log entries in the new range via the range endpoint and verify each entry's hash against canonical bytes, verify the chain of `prev_entry_hash` values, and verify that the Merkle root over all entries matches `new_merkle_root`.
   d. Update the watcher state to `(epoch, new_log_size, new_merkle_root)`.
3. If the epoch is newer than the watcher's known epoch, verify the boundary before anything else. The roots file must carry exactly one end line for the known epoch, its root equal to the watcher's last verified root, and the VRF key file exactly one line for the new epoch. The new epoch's genesis entry, read from the range endpoint, must bind both, per section 3.8. Then download the new epoch in full and verify it as in step 2c, from entry 1.
4. Sleep, and repeat.

The published `verify/verify-translog.sh` performs steps 2c and 3 for the served epoch in one run. It recomputes every entry hash and the root locally, checks the end line and the VRF key line against the genesis, and checks that the last committed root is present in the public history.

**The transition bound.** The anchor files and the server may disagree about the epoch for a short while during a cut, since the files are published before the server serves the new epoch and a cache sits in front of the files. A client treats that disagreement as a wait, not a violation, for fifteen minutes from its first sighting, and as a violation after that. The first sighting is kept in local state per origin and epoch, because the server's clock cannot bound the server.

### 7.3 What watchers detect

- **The server tampers with old log entries.** The consistency proof fails, because the older root no longer reconstructs from the newer log.
- **The server reports different roots to different parties.** Watchers comparing notes see the inconsistency.
- **The server publishes a root to GitHub but serves a different root via the API.** The watcher's API-fetched data does not match the public commit.
- **The server stops publishing roots.** The watcher sees the publication gap and alerts.
- **The server cuts an epoch dishonestly.** A genesis that does not bind the published end line of the previous epoch, or a VRF key line that does not match the genesis, fails the boundary check. An end line that disagrees with the previous epoch's last verified root fails it too.
- **The server strips or substitutes post-quantum keys.** Two checks together close both directions. For substitution, a watcher reconstructs the hybrid pair commitment (`rfp`, [PQR Crypto Specification](Signet-Drive-PQR-Crypto-Spec.md) section 8.5) from an account's `kem` and `kem_pq` entries and cross-checks it against the attestation's `rfp`, and a substituted bundle changes the reconstruction. For absence, the **completeness rule** states that every identity enrolled after the hybrid checkpoint (section 3.7) MUST appear as a complete key set, with four entries for a PRSN, two for a human, and two for the server, and watchers flag any incomplete set as an anomaly. From epoch 2 a key set is grouped by its `account_index`, which is deterministic for an account under one epoch's VRF key, and every account's set is complete at the epoch's genesis because the cut re-logs each live account's whole set. An enrollment the server quietly recorded classical-only is visible by its missing entries.

Two residual vectors are closed by mechanism rather than watching.

- **The server selectively returns a wrong inclusion proof for one specific user while the log itself is consistent.** Closed by an atomicity invariant. Every log insert happens in the same database transaction as the corresponding user-facing audit event for the affected account. Inserting a fraudulent entry without notifying the affected user is structurally impossible from a clean code path. The affected user receives their existing notifications when keys are added under their account, and a notification for an action they did not initiate tells them something is wrong. From epoch 2 the proof itself binds the leaf to the key asked about (section 6.2).
- **The server silently delays publishing a new key** so that the window between publication and use can be exploited. Closed by the receipt mechanism. Receipts are issued at insert time and are immediately verifiable. The receipt is the trust signal, not the publication delay.

### 7.4 Reference watcher software

The watcher protocol above is part of v1, and anyone can verify by following this specification. The published `verify/verify-translog.sh` verifies one served epoch end to end against the anchor files. A continuously running reference watcher is deferred to a later release.

The rationale is that the protocol is the load-bearing part. The reference implementation is consumer software, and its protective value scales with the watcher community, which at launch is small. The trust posture, stated plainly, is this. The transparency log mechanism is real, with its table, receipts, commits, endpoints and atomicity invariant. Anyone can verify by following the spec and running the published verifier. Continuous watcher tooling will be published as the verifying community grows.

The trigger to publish the reference watcher is demand, whether from a compliance customer, a researcher who wants to deploy one, or feedback that the specification is hard to consume from scratch.

## 8. Security analysis

### 8.1 What the log defends against

Active server-mediated key substitution, where the server lies about a user's published key. With the log, three things hold.

- The legitimate key is in the log, under a published Merkle root.
- A substituted malicious key would need to also be in the log, visible to anyone auditing.
- Otherwise the server would need to maintain different log states for different queriers, which watchers detect by comparing roots and entries.

This is the load-bearing property of the verifiable-trust posture against active-platform-compromise key substitution.

### 8.2 What the log does not defend against

- **A backdoored web client or `signet` CLI.** The transparency log does not help if the client captures keys before encryption. Reproducible builds, open source, and bundle hash commits address that vector separately.
- **Server compromise that simultaneously compromises GitHub.** Unlikely, since the operators and the authentication chains differ, but theoretically possible. A later release may add a second public commit destination.
- **Compromise of past entries via cryptographic break.** A SHA-256 break would invalidate the chain. SHA-256 is widely trusted, and a future post-quantum migration may add a successor log under a different hash.
- **The time-of-check versus time-of-use gap.** A client that looked up a key at time T cannot retroactively detect that the key was substituted after T without re-checking. The mitigation is that clients can fetch an inclusion proof at lookup time, and the proof references the current `merkle_root_at_proof`, not just any prior root.
- **A compromise of an epoch's VRF secret.** Together with any list of account identifiers, such a compromise links that epoch's indexes to accounts, including deleted ones. Rotating the key is an epoch. Separately, the recipient lookup endpoint serves an account's identifier and its VRF proof to a signed-in caller who looks the handle up, so a party that looked a handle up while the account lived can keep that link after deletion. Handles are meant to be shared, so unlinkability from the log holds for strangers who never looked the handle up, the same limit the design accepts for public keys. The lookup is rate-limited per signed-in account.

### 8.3 Items for independent cryptographic review

- Canonical-bytes encoding for entry hashing, deterministic across implementations, under all three rules.
- Merkle tree construction and RFC 6962 conformance, with leaf hash and internal node domain separation.
- Inclusion-proof and consistency-proof construction.
- The genesis payload and the epoch boundary check.
- The VRF account index, its suite, and the proof a client verifies to bind an index to an account.
- Watcher implementation correctness.

## 9. Open questions

1. **Secondary public commit destination.** v1 ships GitHub-only. A later release may add a second destination, whether another git host, IPFS, or a dedicated transparency service, decided on whether GitHub-only proves insufficient after launch.
2. **Watcher community engagement.** The transparency property depends on watchers actually running. v1 launches with the protocol specification and the published verifier, and continuous reference watcher software follows demand. At launch the protective value is deterrent plus retrospective audit, scaling to real-time detection as the community grows.
3. **Browser-side automatic verification.** The command-line client enforces the anchors on every epoch-bound read. The web client binds keys through the same proofs but takes the epoch's VRF key from the server rather than from the public file, an accepted limit, since the web client never checks inclusion against a published root. A later release may bring the browser to the command-line client's rule.
