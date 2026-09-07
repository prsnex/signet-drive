# Test Vector Category 06: Verification response canonical bytes (JCS-canonicalized and signed)

**Layer:** 1 (spec + concrete inputs; Layer 2 byte values pending; this is a Signet-Drive-specific construction)
**Spec source:** [Envelope Format](../Signet-Drive-Envelope-Format.md) section 9 (verification response canonical bytes) + RFC 8785 (JCS)
**External standards:** RFC 8785 (JCS), RFC 7518 section 3.4 (ES256)

---

## Why this vector exists

When a verifier (PRSN, human, or external watcher) calls `GET /v1/attestations/{id}/verification`, the server returns a server-signed JSON statement containing the attestation's state (subject public keys, validity status, sharing capability, key-protection tier). The response's `attestation` object is JCS-canonicalized and signed with the server's signing key; verifiers reconstruct the canonical bytes and verify the server's signature.

If implementations disagree on the verification-response schema or the JCS canonicalization, server-issued statements fail verification cross-implementation. This vector pins the schema, the canonicalization, and the signing flow.

## Verification response schema (per Envelope Format section 9)

The response is a JSON object: a signed `attestation` object plus a top-level server-signature wrapper. **No Guardian fields**: the response does NOT include `guardian_account_id` or `guardian_handle`; the server records the Guardian internally and does not expose it.

**Top-level:**

| Key | Type | Notes |
|---|---|---|
| `v` | integer | Envelope version (`1`) |
| `attestation` | object | The signed attestation state (fields below); JCS-canonicalized for signing |
| `server_key_id` | string | UUID of the server key that signed this response |
| `server_signature` | string | base64url ECDSA signature (raw r\|\|s) over the canonical bytes; NOT itself part of the canonical bytes |
| `signed_at` | integer | Unix seconds when the response was signed |

**`attestation` object:**

| Key | Type | Notes |
|---|---|---|
| `attestation_id` | string | UUID |
| `subject_account_id` | string | UUID; the PRSN |
| `subject_handle` | string | The PRSN's current handle |
| `subject_signing_pubkey` | string | base64url-no-pad of the 65-byte X9.63 uncompressed key |
| `subject_signing_pubkey_fingerprint` | string | lowercase hex SHA-256, 64 chars |
| `subject_signing_alg` | string | `"ES256"` |
| `subject_kem_pubkey` | string | base64url-no-pad of the 65-byte X9.63 uncompressed key |
| `subject_kem_pubkey_fingerprint` | string | lowercase hex SHA-256, 64 chars |
| `subject_kem_alg` | string | `"ECDH-ES+A256KW"` |
| `created_at` | integer | Unix seconds (UTC) |
| `expires_at` | integer \| null | Unix seconds, or `null` if no expiry set |
| `status` | string | `"active"`, `"revoked"`, or `"expired"` (computed by the server at response time) |
| `revoked_at` | integer \| null | Unix seconds, or `null` if not revoked |
| `prsn_sharing_capability` | string | `"none"` / `"read_only"` / `"read_write"`; a per-PRSN account property |
| `key_protection` | string | always `"secure_enclave"`, the only valid value for PRSNs, server-enforced |

For a hybrid attestation the signed `attestation` object also carries the subject's PQ public keys with fingerprints and algorithms plus the pair-commitment `rfp`, and the response is dual-signed; the rules are in [Envelope Format](../Signet-Drive-Envelope-Format.md) section 9. This vector's classical fields and construction are unchanged by that extension.

**Receipt delivery (as built):** the verification endpoint delivers the two log receipts inline in the response (`subject_signing_pubkey_receipt`, `subject_kem_pubkey_receipt`), but as **independently signed siblings**: each carries its own section 10a `server_signature`, and neither is inside the `server_signature`-covered `attestation` bytes. The section 9 canonical bytes are reconstructed from `attestation` plus `server_key_id` plus `signed_at` only. Receipt canonical bytes are pinned in [Category 05](05-receipt-canonical-bytes.md).

**Signature placement:** the server-signature wrapper is NOT part of the canonical bytes. The server canonicalizes the `attestation` object (RFC 8785), builds the canonical-byte string per section 9, signs the SHA-256, then attaches `server_key_id`, `server_signature`, and `signed_at` at top level. Verifiers reconstruct the canonical bytes from the `attestation` object, compute the SHA-256, and verify the signature.

**Canonical bytes (per Envelope Format section 9):**

```
"signet-server-attestation-verify-v1\n" || canonicalize_RFC_8785(attestation) || "\n" || server_key_id || "\n" || str(signed_at)
```

## Test cases

### TC06-01: Verify a PRSN attestation (current state, active, no expiry)

**Setup:** a verifier calls `GET /v1/attestations/<id>/verification` for PRSN `jane-ai`'s active attestation. The server returns the canonical state.

**Inputs (`attestation` object fields):**

| Field | Value |
|---|---|
| `attestation_id` | `"00000000-0000-4000-8000-000000000abc"` |
| `subject_account_id` | `"00000000-0000-4000-8000-00000000000a"` (PRSN_1) |
| `subject_handle` | `"jane-ai"` |
| `subject_signing_pubkey` | (base64url-no-pad of PRSN_1's signing pubkey; Layer 2) |
| `subject_signing_pubkey_fingerprint` | (lowercase hex SHA-256; Layer 2) |
| `subject_signing_alg` | `"ES256"` |
| `subject_kem_pubkey` | (base64url-no-pad of PRSN_1's KEM pubkey; Layer 2) |
| `subject_kem_pubkey_fingerprint` | (lowercase hex SHA-256; Layer 2) |
| `subject_kem_alg` | `"ECDH-ES+A256KW"` |
| `created_at` | `1700000060` (`TS_T1`, Unix seconds) |
| `expires_at` | `null` |
| `status` | `"active"` |
| `revoked_at` | `null` |
| `prsn_sharing_capability` | `"read_only"` |
| `key_protection` | `"secure_enclave"` |

Top-level wrapper: `v = 1`, `server_key_id` = the test server reference key id, `signed_at` = a designated signing timestamp, `server_signature` = Layer 2.

**Expected JCS-canonicalized JSON (structural; Layer 2 byte fixture pending):** the keys of the `attestation` object sorted; `null` values preserved as JSON `null`.

**Expected SHA-256 of the canonical bytes:** Layer 2.
**Expected ECDSA signature:** Layer 2; signed with the test server reference key.

### TC06-02: Verify a revoked attestation

**Setup:** PRSN_1's attestation was revoked; the server returns the historical state with `status: "revoked"` and `revoked_at` set.

**Inputs (delta from TC06-01):**

| Field | Value |
|---|---|
| `revoked_at` | `1700001000` (`TS_T2`) |
| `status` | `"revoked"` |

(All other `attestation` fields as TC06-01.)

### TC06-03: Verify an attestation with an explicit `expires_at` (Guardian-set time-bounded delegation)

**Setup:** the Guardian set a 30-day expiry at issuance. The verifier asks within the window.

**Inputs (delta from TC06-01):**

| Field | Value |
|---|---|
| `expires_at` | `1702592060` (`TS_T1 + 2592000`) |
| `status` | `"active"` (still within the window) |

### TC06-04: Negative test; modifications that MUST fail signature verification

For TC06-01's signed verification response:

- Reordering `attestation` keys (`subject_account_id` before `attestation_id`): JCS sorts keys.
- Whitespace inside the canonicalized JSON (pretty-printed): forbidden by JCS.
- Including the `server_signature` / `server_key_id` / `signed_at` wrapper inside the canonicalized `attestation`: wrong; signing an object that includes its own signature is a chicken-and-egg failure.
- Substituting current state for historical state (claiming a revoked attestation is `"active"`): the signature is over the actual state at response time.
- Altering any signed `attestation` field, for example flipping `prsn_sharing_capability` from `read_only` to `read_write`, or tampering `key_protection`: every field in the `attestation` object is covered by the server signature.

## Implementer notes

- **Timestamps are Unix seconds (integers), per Envelope Format section 9.** Not ISO-8601 strings. JCS normalizes JSON numbers; emit integers.
- **`expires_at` and `revoked_at` are nullable.** JCS canonicalizes JSON `null` as the literal `null`; do not omit the field (omitting changes the canonical bytes). Both fields are always present, with an integer or `null`.
- **`status` is computed at response time.** Server rule: if `revoked_at` is set, `"revoked"`; else if `expires_at` is set and past, `"expired"`; else `"active"`. Verifiers should also compute their own status from the timestamp fields rather than blindly trusting the server's computed value.
- **`key_protection` is always `"secure_enclave"`**, the only valid value for PRSNs, server-enforced. It remains an attested *claim* surfaced for relying parties: the keys live in an Apple Secure Enclave (the device Enclave natively; the host Mac's Enclave via host delegation for a containerized PRSN); the server enforces the value but cannot independently verify Enclave residency.
- **Server signing-key rotation:** the response carries `server_key_id` (top level, NOT in the canonical bytes); verifiers fetch the right server public key via `/v1/server-info`, which returns both current and retired keys. Old responses signed by retired server keys remain verifiable after rotation.

## Reviewer's verification path

With Layer 2 fixtures present, a reviewer:

1. Reconstructs the JCS-canonical `attestation` object from the listed inputs.
2. Builds the canonical-byte string per Envelope Format section 9 (`"signet-server-attestation-verify-v1\n" || JCS(attestation) || "\n" || server_key_id || "\n" || str(signed_at)`).
3. Computes the SHA-256 of the canonical bytes.
4. Verifies the ECDSA signature in `server_signature` against the SHA-256 plus the test server public key.

## Layer 2 status

**Pending.** The three test cases specify inputs precisely; the reference implementation generates the canonical bytes and a fixed-key verify vector for each. Per-vector fingerprints depend on the reference key fixtures.
