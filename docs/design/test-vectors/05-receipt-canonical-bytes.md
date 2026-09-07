# Test Vector Category 05: Receipt canonical bytes (JCS-canonicalized and signed)

**Layer:** 1 (spec + concrete inputs; Layer 2 byte values pending; this is a Signet-Drive-specific construction)
**Spec source:** [Envelope Format](../Signet-Drive-Envelope-Format.md) section 10a (the receipt format and its signing input) + RFC 8785 (JSON Canonicalization Scheme)
**External standards:** RFC 8785 (JCS), RFC 7518 section 3.4 (ES256), NIST FIPS 180-4 (SHA-256)

---

## Why this vector exists

When a transparency-log entry is inserted, the server signs an immediate-trust signal called a receipt (the SCT equivalent; Certificate Transparency precedent). The receipt is a JSON object that gets JCS-canonicalized (RFC 8785), prefixed with a domain separator, and signed with the server's signing key. Verifiers of a published key can fetch the receipt and verify the server's signature on the canonical bytes, giving immediate trust before the entry's Merkle root is publicly committed.

If implementations disagree on JCS canonicalization (key ordering, escaping rules, number formatting) or on the receipt schema (which fields are present, with what types), receipts fail to verify cross-implementation. This vector pins the receipt schema plus the JCS canonicalization.

## Receipt JSON schema (per Envelope Format section 10a)

The signed receipt object has these fields (exact key names; types as specified):

| Key | Type | Notes |
|---|---|---|
| `v` | number (integer) | Envelope version, `1` |
| `type` | string | `"signet-pubkey-log-receipt"` |
| `entry_id` | number (integer) | The log entry position; NOT a string |
| `account_id` | string | UUID (canonical hyphenated lowercase form, RFC 4122) |
| `key_purpose` | string | `"signing"` or `"kem"` |
| `algorithm` | string | An RFC 7518-style identifier, for example `"ES256"` or `"ECDH-ES+A256KW"` |
| `public_key_fingerprint` | string | Lowercase hex SHA-256 of the DER `SubjectPublicKeyInfo`, 64 chars |
| `entry_hash` | string | Lowercase hex of the entry hash (SHA-256, 64 chars; [Category 07](07-pubkey-log-entry-hash.md)) |
| `log_size_at_insertion` | number (integer) | Equals `entry_id` for an append |
| `issued_at` | number (integer) | Unix seconds |
| `max_merge_delay_seconds` | number (integer) | Default `86400` |
| `server_key_id` | string | UUID of the server key that signs this receipt |

Twelve signed fields; no nested objects; no arrays. The `server_signature` (and, for a dual-signed receipt, `server_signature_mldsa87`) are siblings attached AFTER signing and are never part of the canonical bytes; a hybrid-era receipt also carries `server_pq_key_id` INSIDE the signed object (Envelope Format section 10a, the anti-strip binding).

**Signing input:** the canonical bytes are the domain prefix plus the JCS form:

```
"signet-pubkey-log-receipt-v1\n" || canonicalize_RFC_8785(receipt_without_signature_fields)
```

**Future compatibility:** if a later version adds fields, implementations must ignore unknown fields when verifying older receipts; JCS canonicalization handles new fields naturally (sorted key ordering).

## JCS canonicalization (RFC 8785) summary

Key rules from RFC 8785 that apply to receipt canonicalization:

- **Object keys sorted lexicographically** by their UTF-16 code-unit sequence (for ASCII keys, alphabetical).
- **No insignificant whitespace**: no spaces, tabs, or newlines between tokens.
- **String escaping**: minimal; `\u00XX` form only where the JSON spec requires it.
- **Number formatting**: no leading zeros; integers carry no decimal point; `42`, never `42.0` or `42e0`.

For the receipt's flat shape (no nesting, no arrays, five integer fields), JCS reduces to: sort keys; concatenate as `{"key1":value1,"key2":value2,...}` with no whitespace; serialize string values per RFC 8259 section 7.

## Test cases

### TC05-01: Sign-up KEM key receipt (human signup)

**Setup:** human `alice` (account id `ACCOUNT_HUMAN_1`) completes sign-up; her KEM public key is added to the log as entry 1 (see [Category 07](07-pubkey-log-entry-hash.md) TC07-01). The insert is atomic with the account's own audit event ([Transparency Log Spec](../Signet-Drive-Transparency-Log-Spec.md) section 7.3), and the server signs a receipt.

**Inputs (signed receipt fields):**

| Field | Value |
|---|---|
| `v` | `1` |
| `type` | `"signet-pubkey-log-receipt"` |
| `entry_id` | `1` (integer) |
| `account_id` | `"00000000-0000-4000-8000-000000000001"` |
| `key_purpose` | `"kem"` |
| `algorithm` | `"ECDH-ES+A256KW"` |
| `public_key_fingerprint` | (the reference key's fingerprint; Layer 2) |
| `entry_hash` | (Category 07 output for entry 1; Layer 2) |
| `log_size_at_insertion` | `1` |
| `issued_at` | `1700000000` (= `TS_T0`, integer) |
| `max_merge_delay_seconds` | `86400` |
| `server_key_id` | `"00000000-0000-4000-8000-0000000000aa"` (the designated test server key) |

**Expected JCS-canonicalized receipt JSON (structural; Layer 2 fills the placeholders):**

```json
{"account_id":"00000000-0000-4000-8000-000000000001","algorithm":"ECDH-ES+A256KW","entry_hash":"<cat07-output>","entry_id":1,"issued_at":1700000000,"key_purpose":"kem","log_size_at_insertion":1,"max_merge_delay_seconds":86400,"public_key_fingerprint":"<reference-fingerprint>","server_key_id":"00000000-0000-4000-8000-0000000000aa","type":"signet-pubkey-log-receipt","v":1}
```

(Keys sorted; no whitespace; integers unquoted; all other values quoted strings.)

**Expected canonical bytes:** the UTF-8 bytes of `"signet-pubkey-log-receipt-v1\n"` followed by the UTF-8 encoding of the JCS JSON above; no BOM; no trailing newline.

**Expected SHA-256 of the canonical bytes:** Layer 2.

**Expected ECDSA P-256 signature** (raw r||s, 64 bytes): Layer 2, with the test server key. (Signatures are non-deterministic; the fixture pins the signing input, plus a fixed-key verify vector.)

### TC05-02: PRSN attestation receipt (signing key)

**Setup:** Guardian `alice` issues an attestation for PRSN `jane-ai`; the PRSN's signing key enters the log as entry 2, atomically with the attestation's audit event.

**Inputs (differences from TC05-01):**

| Field | Value |
|---|---|
| `entry_id` / `log_size_at_insertion` | `2` |
| `account_id` | `"00000000-0000-4000-8000-00000000000a"` (PRSN_1) |
| `key_purpose` | `"signing"` |
| `algorithm` | `"ES256"` |
| `issued_at` | `1700000060` (`TS_T1`) |

### TC05-03: PRSN attestation receipt (KEM key; same attestation, second log entry)

**Setup:** the same attestation event as TC05-02; this is the second of TWO atomic log inserts (the PRSN's signing and KEM keys go in together). Two receipts are issued, one per key.

**Inputs (differences from TC05-02):**

| Field | Value |
|---|---|
| `entry_id` / `log_size_at_insertion` | `3` |
| `key_purpose` | `"kem"` |
| `algorithm` | `"ECDH-ES+A256KW"` |
| `issued_at` | `1700000060` (same `TS_T1` as TC05-02; both inserts share the atomic transaction's timestamp) |

**Note:** TC05-02 and TC05-03 share `issued_at` because both log inserts happen in the same transaction; both receipts are issued back-to-back. They differ in `entry_id`, `key_purpose`, `algorithm`, `public_key_fingerprint`, and `entry_hash`. Verifiers checking attestation validity look up both receipts.

### TC05-04: Negative test; modifications that MUST fail signature verification

For TC05-01's signed receipt:

- Adding insignificant whitespace inside the JSON (`{"account_id" :"..."}`): JCS forbids whitespace.
- Reordering keys (`entry_id` first instead of sorted): JCS sorts keys.
- Quoting an integer value (`"1"` instead of `1`): JCS preserves the integer-versus-string distinction.
- Omitting the domain prefix, or including a trailing newline: the canonical bytes are exactly the prefix plus the JCS form.
- Including a `server_signature*` field in the canonicalized input: the signing input strips every signature field first.
- Truncating a fingerprint: fingerprints are exactly 64 hex chars.

Each case is a real implementer mistake worth catching.

## Implementer notes

- **JCS orders keys by UTF-16 code units, not Unicode code points.** For the ASCII keys receipts use, this is plain alphabetical. Internationalized keys (not used here) differ subtly.
- **Numbers in JCS are normalized.** Integer `1` is `1`, never `1.0`. The receipt has five integer fields; ensure none is accidentally serialized as a string or float.
- **`issued_at` is unix seconds, an integer.** Not an ISO-8601 string. JCS normalizes JSON numbers; emit integers.
- **The receipt JSON does not include its signature.** The server signs the canonical bytes; the signature is delivered as a sibling field. Verifiers reconstruct the canonical bytes from the receipt fields and verify the signature externally.
- **Server signing-key rotation:** the receipt's `server_key_id` lets verifiers fetch the right server public key from `/v1/server-info` (which returns both current and retired keys). Receipts signed by retired keys remain verifiable.
- **Dual-signed receipts:** in the hybrid era, receipts carry an ML-DSA-87 co-signature; both halves sign the identical canonical bytes, and the verification rules are in [Envelope Format](../Signet-Drive-Envelope-Format.md) section 10a.

## Reviewer's verification path

A reviewer can verify TC05-01 (when the Layer 2 fixtures land) by:

1. Reading the receipt schema from Envelope Format section 10a.
2. Constructing the receipt JSON from the listed inputs.
3. Applying RFC 8785 JCS canonicalization and prepending the domain prefix.
4. Computing the SHA-256 of the canonical bytes; comparing against the published fixture.
5. Verifying the published signature against the hash plus the test server public key.

A mismatch at steps 3 or 4 indicates a JCS application bug (key ordering, whitespace, number formatting) or a prefix omission. A mismatch at step 5 indicates a signing or public-key-encoding bug.

## Layer 2 status

**Pending.** The test cases above specify inputs precisely; the reference implementation generates the canonical bytes, the SHA-256, and a fixed-key verify vector using the designated reference server key. The signing input is pinned by a known-answer test in the crypto test suite.
