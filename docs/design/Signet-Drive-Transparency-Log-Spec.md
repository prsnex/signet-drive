# Signet Drive Public Key Transparency Log Specification

## Status

This document specifies the public key transparency log that supports Signet Drive's verifiable trust posture. It is a load-bearing component of the v1 trust model: passive zero-access via cryptography, plus verifiable trust via open source, reproducible builds, this transparency log, and community watchers.

This is the public edition of the specification of record. It is regenerated when the mechanism changes; substantive changes are noted in release notes.

**Reference points:**

- [Signet Drive Overview](Signet-Drive-Overview.md), Trust model section
- [Signet Drive Envelope Format](Signet-Drive-Envelope-Format.md), section 10
- Database tables: `pubkey_log`, `pubkey_log_roots`. These are server-side; their definitions are not published at this time. The wire-visible entry format is fully specified in section 3.
- Test vectors: [test-vectors/](test-vectors/) in this directory covers `entry_hash` canonical bytes, RFC 6962 leaf and internal hashes, and the Merkle root.
- Release and bundle verification procedures: the `verify/` directory at the repository root.
- Background reading: RFC 6962 (Certificate Transparency), Sigstore Rekor, Keybase Sigchain. These are similar designs at varying scales.

Server signing-key rotation procedures live in an internal operations document; the parts that affect verifiers are specified here and in the Envelope Format.

## 1. Goals

The transparency log makes active key substitution publicly detectable. It defends against this threat:

> A compromised Signet Drive operator, or an external attacker with full server compromise, silently substitutes a malicious KEM public key when a recipient queries for a target user's keys, allowing the attacker to read content shared to the substituted key.

Without a transparency mechanism this attack is undetectable: recipients see whatever key the server returns. With the transparency log:

1. Every published KEM and signing public key is recorded in an append-only Merkle log.
2. The log's Merkle root is committed periodically to a public location outside Signet Drive's control.
3. Independent watchers can fetch the log and the published roots and verify the server is reporting a consistent log to all queriers.
4. Active substitution requires either (a) the substituted key to also be in the log, in which case the substitution is visible to anyone auditing, or (b) the server to maintain different log states for different queriers, which watchers can detect by comparing roots and entries across requests.

This is the same architectural pattern as Certificate Transparency for TLS certificates.

The mechanism does not cryptographically prevent the attack; it makes the attack detectable. The deterrent is that any attempt would leave evidence. This is the meaningful security property for v1, consistent with the broader verifiable-trust posture.

## 2. Non-goals (v1)

- **Browser-side automatic enforcement.** Certificate Transparency in TLS uses browser-side enforcement: browsers refuse certificates not present in CT logs. Signet Drive v1 does not do client-side automatic enforcement. The verifier is the watcher (community or self-run), not every user's browser. A later release may add automatic enforcement.
- **Federation and multi-operator logs.** v1 has one log, run by Signet Drive. Multi-operator federation is out of scope.
- **Sigstore-style signed entries.** Each log entry is hashed but not signed individually. The audit guarantee comes from the Merkle structure plus public root commits, not from per-entry signatures.

## 3. Log structure

### 3.1 Storage

The log is stored in two PostgreSQL tables:

- **`pubkey_log`**: append-only entries; one row per published public key.
- **`pubkey_log_roots`**: periodic snapshots of the Merkle root, with a reference to where each root was publicly committed.

Application-level grants restrict the server's database user to INSERT-only on `pubkey_log` (no UPDATE, no DELETE). This is a defense-in-depth measure; the cryptographic guarantee comes from the Merkle hash chain and the public root commits.

### 3.2 Entry format

| Field | Type | Description |
|---|---|---|
| `entry_id` | `BIGSERIAL` | 1-based monotonically increasing position |
| `account_id` | `UUID` | Whose key |
| `key_purpose` | `VARCHAR(16)` | `signing` or `kem` |
| `algorithm` | `VARCHAR(32)` | `ES256`, `ECDH-ES+A256KW`, and similar identifiers |
| `public_key` | `BYTEA` | X9.63 uncompressed (65 bytes for P-256) |
| `public_key_fingerprint` | `VARCHAR(64)` | Lowercase hex SHA-256 of the DER SubjectPublicKeyInfo |
| `created_at` | `TIMESTAMPTZ` | When the entry was added |
| `prev_entry_hash` | `BYTEA` | SHA-256 of entry `entry_id - 1` (zero bytes for entry 1) |
| `entry_hash` | `BYTEA` | SHA-256 of the canonical bytes of this entry (section 3.3 for v1 entries; section 3.7 for v2) |

This table and section 3.3 describe **v1 entries** (classical 65-byte keys). Entries after the epoch checkpoint use the **v2 format** of section 3.7, which length-prefixes the key and adds the post-quantum purposes.

### 3.3 Canonical bytes for hashing each entry

Big-endian, length-prefixed where variable:

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

Implementations MUST produce these bytes deterministically: no spurious whitespace, no implementation-dependent encoding. Canonical test vectors for this construction are published under [test-vectors/](test-vectors/) so independent implementations can verify their canonical-byte construction matches.

### 3.4 Merkle tree construction

Roots are computed via a standard Merkle hash tree (RFC 6962, section 2.1):

- Leaves are `entry_hash` values for `entry_id = 1 ... log_size`.
- Internal nodes are `SHA-256(left_child || right_child)` with domain separation as below.
- The root is the top-level hash.

**Rooting policy:** the root for a given `log_size` is computed as the Merkle hash of leaves 1 through `log_size`, using the RFC 6962 construction: `0x00 || leaf_data` for leaf hashes and `0x01 || left || right` for internal hashes. The prefixes provide domain separation between leaf and internal node hashes, defending against second-preimage attacks.

```
leaf_hash(entry_hash) = SHA-256(0x00 || entry_hash)
internal_hash(left, right) = SHA-256(0x01 || left || right)
```

### 3.5 Inclusion proofs

Standard RFC 6962 section 2.1.1 inclusion proofs: given `entry_id` and `log_size`, a list of sibling hashes from the leaf to the root. The verifier reconstructs the root and compares it to the published root for that `log_size`.

**Explicit verification chain:** independent verifier implementations MUST apply the leaf-hash transformation when reconstructing the root from `entry_hash`. The full chain is:

```
canonical_bytes  --(SHA-256, per section 3.3)-->  entry_hash
entry_hash       --(prepend 0x00, SHA-256)-->  leaf_value = SHA-256(0x00 || entry_hash)
leaf_value + sibling hashes (per inclusion proof)
                 --(SHA-256(0x01 || left || right), per the RFC 6962 internal-node rule)-->  candidate_root
candidate_root == published root for log_size?
```

The `0x00` prefix on leaf hashing and the `0x01` prefix on internal-node hashing provide RFC 6962 domain separation against second-preimage attacks. A common implementer mistake is treating `entry_hash` directly as the leaf value, skipping the `0x00`-prefix transformation. The candidate root will not match, and the verifier would incorrectly conclude the log is inconsistent. The test-vector set includes known-answer vectors for this transformation specifically.

**Worked example** (illustrative; numeric vectors live in the test-vector set): a log of 4 entries with `entry_hash` values `e1, e2, e3, e4` produces leaves `l1=SHA-256(0x00||e1), l2=SHA-256(0x00||e2), l3=SHA-256(0x00||e3), l4=SHA-256(0x00||e4)`; intermediate nodes `n12=SHA-256(0x01||l1||l2), n34=SHA-256(0x01||l3||l4)`; root `r=SHA-256(0x01||n12||n34)`. An inclusion proof for entry 2 supplies `l1` and `n34`. The verifier computes `l2` from `e2`, then `n12=SHA-256(0x01||l1||l2)`, then `candidate_root = SHA-256(0x01||n12||n34)`, and compares to the published `r`.

### 3.6 Consistency proofs

Standard RFC 6962 section 2.1.2 consistency proofs: given two log sizes `m < n` and their respective roots `R_m`, `R_n`, a proof that the size-`n` log is an extension of the size-`m` log (no entries inserted before position `m+1`; no entries modified at positions `1..m`).

### 3.7 The v2 entry format (hybrid post-quantum keys)

Under the hybrid identity, every account holds post-quantum public keys alongside the classical ones ([PQR Crypto Specification](Signet-Drive-PQR-Crypto-Spec.md), section 8), and the log records them. It must: a compromised directory serving a classical-only key bundle for a hybrid-enrolled recipient would otherwise be undetectable at the log, and the same holds for a substituted server PQ verification key.

The v1 format's fixed 65-byte `public_key` field cannot hold an ML-KEM-1024 encapsulation key (1568 bytes) or an ML-DSA-87 verification key (2592 bytes), so entries after the cutover use a **v2 format**:

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

Deltas from v1, each load-bearing:

- **The version byte is inside the hashed bytes (MUST).** An unhashed field that selects the hashing rule would be a canonicalization ambiguity in an append-only Merkle structure.
- **`public_key` is length-prefixed** (uint32_be), fitting any key size; classical key values are unchanged.
- **`key_purpose` gains `signing_pq` (3), `kem_pq` (4), and `epoch` (0).**
- **`algorithm` carries the key's FIPS name** (`ML-DSA-87`, `ML-KEM-1024`) for the PQ entries: the field describes the key, not a wrap construction.
- **The append-only per-key model is unchanged:** a hybrid identity produces one entry per key.

**The epoch checkpoint.** The v1-to-v2 cutover is itself recorded in the chain: an account-less entry with `key_purpose = epoch` (byte `0x00`; not a key), `account_id` NULL (hashed as 16 zero bytes, mirroring the v1 genesis `prev_entry_hash` convention), `algorithm = "signet-translog-v2"`, and `public_key` = the UTF-8 tag `"signet-pubkey-log-v2-epoch"`. It is inserted structurally, exactly once, immediately before the first v2 entry, so the rule boundary lives in the chain itself.

**Rule selection.** v1 entries already in the chain keep the v1 rule forever. A verifier selects the hashing rule per entry: the `entry_version` field surfaced in receipts and range and inclusion-proof responses is the hint, and the hashed version byte is authoritative, since recomputation under the claimed rule must reproduce the stored `entry_hash`. Identical field values hashed under the v1 and v2 rules can never collide (the version byte and the length prefix separate the domains).

**The Merkle layer is unchanged.** Leaves remain `SHA-256(0x00 || entry_hash)` over the 32-byte `entry_hash` whatever the entry version; the leaf, internal, root, and proof code never touch entry internals. Known-answer vectors: [test-vectors](test-vectors/), Category 07 (the v2 cases).

## 4. What gets logged

### 4.1 Event triggers

A new entry is added to `pubkey_log` for each of the following events:

1. **Human signup.** Two entries: the human's classical KEM public key (`kem`) and the ML-KEM-1024 encapsulation key (`kem_pq`), the hybrid directory pair recipients wrap to. The human's signing key is the WebAuthn passkey, which is per-credential rather than per-account, and is not logged since it is not used for cryptographic recipient lookup. `account_id` is the new human's account id.

   **Why the passkey's public key is not in the log:** the passkey's public key is used by Signet Drive to verify the user's sign-in WebAuthn assertions, a server-internal verification path. It is not used by other parties to look up the user's identity for content delivery; only the KEM public key is used that way. The transparency log specifically defends against active key substitution at directory lookup (Alice queries for a user's public key; the server might lie about it). That attack vector applies to KEM keys, which other users wrap content to, but not to passkey signing keys, which only the server's own authentication verification consumes. Logging passkey public keys would add noise without adding protection.

2. **Passkey rotation (humans).** The user's underlying ECDH KEM public key does not change during passkey rotation; only the wrap of the private key changes. Therefore: no new entry on passkey rotation.

3. **PRSN attestation issuance.** Four new entries, one per attested key: the classical signing and KEM keys (`signing`, `kem`) and the post-quantum pair (`signing_pq`, `kem_pq`). `account_id` is the PRSN's account id.

4. **PRSN attestation revocation.** No new entry. Revocation is recorded in attestation state and reflected in the verification response (status "revoked"). The transparency log records what was published; revocation is a separate state on top.

5. **Server signing key rotation.** Entries for the server's signing public keys, both halves (`signing` for ES256, `signing_pq` for ML-DSA-87), under a reserved account id created at deploy time and labeled as such. A substituted server PQ verification key is therefore watcher-detectable like any other published key.

6. **PRSN attestation re-issuance after revocation.** If a Guardian revokes a PRSN's attestation and issues a new one with new keys, the new keys get new entries. If the same keys are re-attested, no new entries.

### 4.2 What is not logged

- **Per-file DEKs and DEK wraps.** They are per-message; there is no value in logging billions of them.
- **Per-folder metadata keys and metadata-key wraps.**
- **Guardianship relationships.** They are internal data by design.
- **Sharing topology.**
- **The server's verification-response signatures.** They are not logged individually. The server's signing key being in the log is what allows verifiers to authenticate those responses.

The transparency log is specifically about published public keys: the things a server might lie about when serving a key lookup.

## 4a. Signed log receipts

### 4a.1 Why receipts

The log mechanism alone (Merkle tree plus periodic public root commits) leaves a gap: when a new key is added to `pubkey_log`, what is the verifier's behavior in the window between the INSERT and the next publicly committed Merkle root, which can be up to the publication interval away?

The log adopts the Certificate Transparency SCT pattern: at the moment of the `pubkey_log` INSERT, the server immediately issues a signed log receipt, the equivalent of a Signed Certificate Timestamp. The receipt is the immediate trust signal for verifiers. Inclusion in a publicly committed root within the Maximum Merge Delay (MMD) is the retrospective audit anchor.

This eliminates the "key in log but not yet committed" gap entirely. Verifiers do not wait for the next publication cycle; they accept the receipt as evidence of inclusion, with the implicit promise that the entry will appear in some publicly committed root within MMD.

### 4a.2 Receipt format

JSON shape (the bytes-on-the-wire specification is in [Signet Drive Envelope Format](Signet-Drive-Envelope-Format.md), section 10a):

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

Server signature: ECDSA P-256 over `"signet-pubkey-log-receipt-v1\n" || canonicalize_RFC_8785(receipt_without_signature)`, signed with the server's attestation-verification-purpose signing key.

Stored on-server: the receipt is reconstructible from the `pubkey_log` row columns plus the `receipt_signature`, `receipt_issued_at`, and `receipt_server_key_id` columns.

### 4a.3 Maximum Merge Delay (MMD)

MMD is 24 hours, set via `system_config.pubkey_log_receipt_max_merge_delay_seconds` (default 86400). This matches Certificate Transparency precedent: the major CT logs use a 24-hour MMD.

The publication cadence (`system_config.pubkey_log_root_publication_interval_hours`, default 24 hours) matches MMD. Operators can shorten it via system configuration if a real reason emerges.

### 4a.4 Verifier behavior with receipts

When a verifier receives a public key (via an attestation verification response per the Envelope Format, section 9, or another path), the response includes or links to the corresponding log receipt. The verifier:

1. Verifies the receipt's `server_signature` against the server's signing key, fetched from `/v1/server-info`.
2. Verifies the receipt's `entry_hash` matches the canonical bytes for the asserted public key, per the section 3.3 computation.
3. If `(now - receipt.issued_at)` is at most `receipt.max_merge_delay_seconds`: the receipt is valid as immediate evidence; the entry is in the log and will be in some publicly committed Merkle root within MMD.
4. If `(now - receipt.issued_at)` exceeds `receipt.max_merge_delay_seconds`: the entry MUST be in some publicly committed Merkle root; the verifier can fetch an inclusion proof and confirm.

Verifiers wanting stronger assurance can additionally verify the inclusion proof against the latest publicly committed root even before MMD has elapsed, at the cost of additional round-trips.

### 4a.5 Watcher behavior with receipts

For each publicly committed Merkle root, the watcher verifies that every entry whose receipt was issued more than MMD ago is included in that root or a later one. A miss means the log is provably misbehaving, and the watcher alerts.

This catches the case where the server issues receipts but does not include the entries in published roots: provable misbehavior, not just inconsistent reporting.

## 5. Public root publication

### 5.1 Cadence

Every `system_config.pubkey_log_root_publication_interval_hours` (default 24), a scheduler job runs:

1. Fetch the current `MAX(entry_id)` from `pubkey_log`, giving `current_log_size`.
2. If `current_log_size > last_published_size`: compute the Merkle root over entries 1 through `current_log_size`.
3. INSERT into `pubkey_log_roots`: `(log_size = current_log_size, merkle_root = computed_root, computed_at = NOW(), committed_at = NULL, commit_url = NULL)`.
4. Trigger the public commit (section 5.2). On success, UPDATE the row: `committed_at = NOW(), commit_url = <URL>`.
5. On commit failure: leave `committed_at` NULL; retry on the next cadence; alert on persistent failure.

### 5.2 Public commit destination

The Merkle root is committed to a public GitHub repository under Signet Drive's control but not on Signet Drive's infrastructure: [signet-drive-transparency-log](https://github.com/prsnex/signet-drive-transparency-log). The repository is read-public; only authorized Signet Drive servers can push.

**Implementation note.** The push uses a fine-grained GitHub token over HTTPS (the Contents API), not an SSH deploy key. It matches the server's outbound-HTTP style, needs no SSH key or `git` binary in the container, and the token is scoped to `contents: write` on this one repository. The security property is the same: only a server holding the secret can push. The publisher is server-side code, disabled until configured via `SIGNET_TRANSPARENCY_GITHUB_REPO` and `SIGNET_TRANSPARENCY_GITHUB_TOKEN` (plus optional `SIGNET_TRANSPARENCY_GITHUB_BRANCH`, default `main`). The public repository and token are deploy-time infrastructure.

**Commit format:** each commit adds one line to `roots.jsonl` (one JSON object per line, append-only):

```json
{"log_size": 12345, "merkle_root": "<hex>", "computed_at": "<ISO 8601>", "committed_at": "<ISO 8601>"}
```

Plus a tag, `root-12345`, pointing to that commit, named after the `log_size`. Watchers can fetch all roots via the file or query the tag list.

**Commit message:**

```
Publish Merkle root for log_size 12345
```

Each commit is a separate, append-only addition. The git history of `roots.jsonl` is the publication record.

### 5.3 Why GitHub specifically

- **External infrastructure.** GitHub is operated by Microsoft, not Signet Drive. A commit cannot be quietly retracted; the history is preserved.
- **Easy verification.** Anyone with `git` can clone the repository and inspect the history.
- **Standard tooling.** Watchers can use any GitHub-aware tooling.
- **Long-term durability.** GitHub's data durability is widely trusted.

Alternatives considered: IPFS (decentralized but harder to verify), dedicated transparency log services (operationally heavier), other version-control hosting (similar properties). If GitHub's role becomes a concern, a secondary commit destination can be added; watchers verifying multiple sources of the same root values is the right design pattern.

### 5.4 Commit failure recovery

If the public commit fails for a sustained period:

- The internal `pubkey_log` keeps growing; new entries continue to be inserted.
- New `pubkey_log_roots` rows accumulate with `committed_at = NULL`.
- Receipts (section 4a) continue to be issued at INSERT time. The receipt mechanism is independent of commit health; verifiers continue to receive valid receipts as immediate evidence of inclusion during the gap.
- Alerting fires.
- The operator investigates: is GitHub down, is the token invalid, is the network broken?
- When the issue is resolved, the scheduler catches up, committing all pending roots in order. Receipts issued during the gap come under the next published root and the audit chain is restored.

The receipt mechanism continues to operate during commit gaps; what degrades is the retrospective audit anchor, that is, verifying entries against a publicly committed root after MMD has elapsed. Once commits resume and catch-up completes, the audit chain is fully restored. Public commitment failure is a high-priority operational alert because (a) external watchers cannot verify root consistency during the gap, and (b) if MMD elapses for entries issued before the gap and commits do not resume, those entries miss their audit-anchor deadline and the log becomes provably misbehaving. The gap is bounded by MMD; sustained gaps approaching MMD warrant escalation.

## 6. Endpoints

### 6.1 `GET /v1/transparency/log/root`

Returns the current root state.

**Response (JSON):**

```json
{
  "current_log_size": 12345,
  "current_merkle_root": "<hex>",
  "computed_at": <unix seconds>,
  "last_publicly_committed": {
    "log_size": 12340,
    "merkle_root": "<hex>",
    "committed_at": <unix seconds>,
    "commit_url": "https://github.com/prsnex/signet-drive-transparency-log/commit/<sha>"
  }
}
```

The response includes both the current internal state and the most recently publicly committed state. They may differ briefly during the gap between log growth and the next publication cadence; watchers reconcile by waiting for the next public commit.

### 6.1a `GET /v1/transparency/log/receipt?fingerprint=<hex>&purpose=<signing|kem>`

Returns the most recent signed log receipt for the (fingerprint, purpose) pair. Verifiers use this to fetch receipts on demand when a verification response does not include them inline.

**Response (JSON):** the receipt format per section 4a.2.

**Cache-Control:** `public, max-age=300`. Receipts are stable; an entry can change only if a new `pubkey_log` entry exists for the same (account, key purpose, public key), which happens only on initial publication or on re-publication after revocation.

### 6.2 `GET /v1/transparency/log/inclusion-proof?fingerprint=<hex>&purpose=<signing|kem>`

Returns an inclusion proof for the most recent entry matching the given fingerprint and purpose.

**Response (JSON):**

```json
{
  "entry_id": 9876,
  "account_id": "<UUID>",
  "key_purpose": "kem",
  "algorithm": "ECDH-ES+A256KW",
  "public_key_fingerprint": "<hex>",
  "created_at": <unix seconds>,
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

The verifier derives the leaf hash from the returned `entry_hash` (leaf = `SHA-256(0x00 || entry_hash)`, section 3.5), reconstructs the root from the leaf hash plus sibling hashes, compares it to `merkle_root_at_proof`, and cross-references `merkle_root_at_proof` against the publicly committed root for that log size. The inclusion-proof response carries `entry_hash` so the proof is verifiable from this response alone; the verifier trusts the server-vouched `entry_hash` rather than recomputing it. Independent recomputation of `entry_hash` from canonical bytes is the watcher's job over the range endpoint (section 6.3).

### 6.3 `GET /v1/transparency/log/range?start=<entry_id>&end=<entry_id>`

Returns log entries in a range, for watchers downloading the full log incrementally.

**Response (JSON, paginated):**

```json
{
  "entries": [
    {
      "entry_id": 100,
      "account_id": "<UUID>",
      "key_purpose": "kem",
      "algorithm": "ECDH-ES+A256KW",
      "public_key": "<base64url X9.63 65 bytes>",
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

Watchers MUST verify each entry's `entry_hash` against the canonical-byte computation locally; they do not trust the server's reported hash.

### 6.4 `GET /v1/transparency/log/consistency-proof?from=<log_size>&to=<log_size>`

Returns a consistency proof between two log sizes (RFC 6962, section 2.1.2). Watchers use this to verify that a larger root is an append-only extension of a smaller root.

**Response (JSON):**

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

Returns the server's currently active signing public keys, for verifying server-signed verification responses per the Envelope Format, section 9.

**Response (JSON):**

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
  "retired_signing_keys": [...]
}
```

Returns both the current keys (verifying recent responses) and retired keys (verifying historical responses). Each key's `transparency_log_entry_id` references its entry in `pubkey_log` so verifiers can confirm the published key is logged.

## 7. Watcher protocol

A watcher is any party that periodically fetches the log and the public roots and verifies consistency.

### 7.1 Initial state

The watcher remembers the most recent `(log_size, merkle_root)` pair it has verified. On first run, this is `(0, <empty-tree-hash>)`.

### 7.2 Periodic check

On each run (hourly, for example):

1. Fetch the latest publicly committed root from GitHub: pull [signet-drive-transparency-log](https://github.com/prsnex/signet-drive-transparency-log) and read the latest line of `roots.jsonl`, giving `(new_log_size, new_merkle_root, committed_at)`.
2. If `new_log_size > watcher_known_log_size`:
   a. Fetch a consistency proof from the server: `GET /v1/transparency/log/consistency-proof?from=<watcher_known_log_size>&to=<new_log_size>`.
   b. Verify the proof against `(watcher_known_merkle_root, new_merkle_root)` per RFC 6962. Fail loudly if inconsistent.
   c. Optionally, fetch all log entries in `(watcher_known_log_size, new_log_size]` via the range endpoint and verify each entry's hash against canonical bytes, verify the chain of `prev_entry_hash` values, and verify the Merkle root over all entries matches `new_merkle_root`.
   d. Update watcher state to `(new_log_size, new_merkle_root)`.
3. Sleep, repeat.

### 7.3 What watchers detect

- **The server tampers with old log entries.** The consistency proof fails: the older root no longer reconstructs from the newer log.
- **The server reports different roots to different parties.** Watchers comparing notes see the inconsistency.
- **The server publishes a root to GitHub but serves a different root via the API.** The watcher's API-fetched data does not match the public commit.
- **The server stops publishing roots.** The watcher sees the publication gap and alerts.
- **The server strips or substitutes post-quantum keys.** Two checks together close both directions. Substitution: a watcher reconstructs the hybrid pair-commitment (`rfp`, [PQR Crypto Specification](Signet-Drive-PQR-Crypto-Spec.md) section 8.5) from an account's `kem` and `kem_pq` entries and cross-checks it against the attestation's `rfp`; a substituted bundle changes the reconstruction. Absence: the **completeness rule** states that every identity enrolled after the epoch checkpoint (section 3.7) MUST appear as a complete key set (four entries for a PRSN, two for a human, two for the server), and watchers flag any incomplete post-epoch set as an anomaly. An enrollment the server quietly recorded classical-only is visible by its missing entries.

Two residual vectors are closed by mechanism rather than watching:

- **The server selectively returns a wrong inclusion proof for one specific user while the log itself is consistent.** Closed by an atomicity invariant: every `pubkey_log` INSERT happens in the same database transaction as the corresponding user-facing audit event for the affected account (`account_created`, `attestation_issued`, `server_key_rotated`). Inserting a fraudulent entry without notifying the affected user is structurally impossible from a clean code path. The affected user receives their existing notifications when keys are added under their account; a notification for an action they did not initiate tells them something is wrong.
- **The server silently delays publishing a new key** so the window between publication and use can be exploited. Closed by the receipt mechanism: receipts are issued at INSERT time and are immediately verifiable. The receipt is the trust signal, not the publication delay.

### 7.4 Reference watcher software

The watcher protocol above is part of v1: anyone can verify by following this specification. A published reference watcher implementation is deferred to a post-launch release.

Rationale: the protocol is the load-bearing part. The reference implementation is consumer software, and its protective value scales with the watcher community, which at launch is small. The v1 trust posture, stated plainly: the transparency log mechanism is real (table, receipts, commits, endpoints, atomicity invariant); anyone can verify by following the spec; reference verifier tooling will be published as the verifying community grows.

The trigger to publish the reference watcher: demand emerges, whether from a compliance customer, a researcher who wants to deploy one, or feedback that the specification is hard to consume from scratch.

## 8. Security analysis

### 8.1 What the log defends against

Active server-mediated key substitution: the server lying about a user's published key. With the log:

- The legitimate key is in the log, under a published Merkle root.
- A substituted malicious key would need to also be in the log, visible to anyone auditing.
- Otherwise the server would need to maintain different log states for different queriers, which watchers detect by comparing roots and entries.

This is the load-bearing property of the verifiable-trust posture against active-platform-compromise key substitution.

### 8.2 What the log does not defend against

- **A backdoored web client or `signet` CLI.** The transparency log does not help if the client captures keys before encryption. Reproducible builds, open source, and bundle hash commits address that vector separately.
- **Server compromise that simultaneously compromises GitHub.** Unlikely (different operators, different auth chains) but theoretically possible. A later release may add a second public commit destination.
- **Compromise of past entries via cryptographic break.** A SHA-256 break would invalidate the chain. SHA-256 is widely trusted; a future post-quantum migration may add a successor log under a different hash.
- **The time-of-check versus time-of-use gap.** A client that looked up a key at time T cannot retroactively detect that the key was substituted after T without re-checking. Mitigation: clients can fetch an inclusion proof at lookup time; the proof references the current `merkle_root_at_proof`, not just any prior root.

### 8.3 Items for independent cryptographic review

- Canonical-bytes encoding for entry hashing (deterministic across implementations).
- Merkle tree construction (RFC 6962 conformance: leaf hash domain separation, internal node domain separation).
- Inclusion-proof and consistency-proof construction.
- Watcher implementation correctness.

## 9. Open questions

1. **Secondary public commit destination.** v1 ships GitHub-only. A later release may add a second destination (another git host, IPFS, or a dedicated transparency service), decided on whether GitHub-only proves insufficient after launch.
2. **Watcher community engagement.** The transparency property depends on watchers actually running. v1 launches with the protocol specification; reference watcher software follows demand. At launch the protective value is deterrent plus retrospective audit, scaling to real-time detection as the community grows.
3. **Client-side automatic verification.** v1 does not enforce receipt and inclusion-proof checks on every key lookup; the verification capability exists via the receipt mechanism, and a later release may make it automatic. The trade-off is more network round-trips per operation and more complex error handling, against stronger real-time enforcement.
