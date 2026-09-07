# Signet Drive Cryptographic Envelope Format

## Status

This document specifies the bytes on the wire for every cryptographic artifact in Signet Drive: file ciphertext, wrapped DEKs, encrypted metadata, attestation records, server-signed verification responses, the human-side wrap chain, transparency log entries, and the algorithm-identifier registry that ties them together.

This format is fully self-contained; it does not defer to prior versions for any layout or convention. It is the public edition of the specification of record, regenerated when the format changes.

This is the canonical reference for how cryptographic data is laid out and serialized. When this document and other design documents disagree on bytes-level details, this document wins, with one exception: the hybrid post-quantum constructions are owned by the [Signet Drive PQR Crypto Specification](Signet-Drive-PQR-Crypto-Spec.md), which extends this document (sections 3 and 5) and wins on the constructions it owns.

**Reference points:**

- [Signet Drive Overview](Signet-Drive-Overview.md): canonical product scope
- [Signet Drive PQR Crypto Specification](Signet-Drive-PQR-Crypto-Spec.md): the v1 hybrid post-quantum constructions (the hybrid content-wrap recipient block, the SP 800-227 section 4.6 KDM, the identity dual-signature)
- [Signet Drive Transparency Log Specification](Signet-Drive-Transparency-Log-Spec.md): the transparency log mechanism
- Database tables referenced throughout are server-side; their definitions are not published at this time. Every wire-visible shape is specified in this document.
- The WebAuthn PRF wrap implementation and the server signing-key lifecycle are covered by internal operations documents; every wire-visible consequence is specified here.

## 1. Design principles

1. **Off-the-shelf cryptographic primitives only.** No novel constructions. AES-256-GCM, ECDH P-256, ECDSA P-256, HKDF-SHA-256, AES Key Wrap (RFC 3394), Concat KDF (NIST SP 800-56A), ML-KEM-1024 (FIPS 203), ML-DSA-87 (FIPS 204).
2. **JOSE conformance.** Algorithm identifiers per RFC 7518 (`A256GCM`, `ECDH-ES+A256KW`, `ES256`); the PQ identifiers (`ECDH-ES+ML-KEM-1024+A256KW`, `ML-DSA-87`, the reserved `ML-KEM-1024+A256KW`) are consistent in shape.
3. **Crypto-agility from day one.** Every signed or encrypted object carries an algorithm identifier. Server-side dispatch keys on the identifier. Format evolution is additive.
4. **AAD binds purpose.** Authenticated Additional Data binds ciphertexts to their semantic context (`file_id` for content, fixed strings for wrap purposes). This defends against ciphertext substitution at the storage layer.
5. **Base64url-no-pad encoding** (RFC 4648, section 5) for all binary fields embedded in JSON envelopes. Standard JOSE convention.
6. **Single source of bytes-on-the-wire truth.** This document. Other documents reference it; they do not redefine it.
7. **Honest about what is encrypted.** File content and names are encrypted. Sharing topology, folder hierarchy, ownership, sizes, and timestamps are server-visible. The envelope format addresses the encrypted parts.

## 2. Top-level format conventions

**JSON envelopes** are used for stored cryptographic objects (wrapped DEKs, wrapped metadata keys, the human-side wrap blob, server-signed verification responses). Each envelope has an `alg` field identifying the algorithm.

**Binary on-disk format** is used for raw file ciphertext blobs in object storage (single-PUT and multipart chunks): a fixed-length header followed by the ciphertext.

**Byte order:** big-endian for any multi-byte length or counter fields. Lengths are uint32 unless otherwise noted.

**Base64url encoding:** RFC 4648, section 5, no padding. All base64url fields strip trailing `=` characters.

**JSON serialization:** UTF-8, no BOM. Fields are in canonical order where signature stability matters (server-signed verification responses use RFC 8785).

**Envelope versioning:** every envelope JSON has a `v` field (integer). v1 is the current version. New versions add fields without removing existing ones unless a major revision forces breakage, which would be flagged as such.

## 3. Algorithm identifier registry

| Identifier | Use | Spec | Status |
|---|---|---|---|
| `A256GCM` | Symmetric authenticated encryption (file ciphertext, key wrapping inside envelopes) | RFC 7518 section 5.3 | v1 |
| `ECDH-ES+A256KW` | Static-ephemeral DH, Concat KDF SHA-256, AES-256 Key Wrap (the classical DEK and metadata-key wrap; stays readable forever, by crypto-agility) | RFC 7518 section 4.6 + NIST SP 800-56A section 5.8.1 + RFC 3394 | v1 |
| `ECDH-ES+ML-KEM-1024+A256KW` | The hybrid content wrap (P-256 plus ML-KEM-1024 via the SP 800-227 section 4.6 two-step-HKDF KDM, then AES-256 Key Wrap): the section 5a recipient block; construction owned by the PQR Crypto Specification, sections 4 and 5 | NIST SP 800-227 section 4.6 + FIPS 203 + RFC 3394 | v1 |
| `ES256` | ECDSA P-256 with SHA-256 (per-request signing, server-signed responses; the classical half of the identity dual-signature) | RFC 7518 section 3.4 | v1 |
| `ML-DSA-87` | Post-quantum signature, hedged mode with FIPS 204 context strings; the PQ half of the identity dual-signature (PQR Crypto Specification, section 8) | FIPS 204 | v1 |
| `ML-KEM-1024+A256KW` | Pure-PQ KEM wrap. RESERVED. Known-but-disabled: v1 implementations MUST reject it (pin-tested); activating it would drop the classical hedge (PQR Crypto Specification, section 12) | FIPS 203 + RFC 3394 | reserved |

**The server's signing algorithm.** v1 servers dual-sign verification responses and log receipts: `ES256` plus `ML-DSA-87`, with AND-semantics verification (PQR Crypto Specification, section 8).

**Determinism note.** ECDSA P-256 signatures are non-deterministic in v1 (Apple Silicon Secure Enclave and most software signers produce them with hardware or CSPRNG-supplied randomness). RFC 6979 deterministic mode is not specified or required. ML-DSA-87 uses hedged signing (always randomized).

## 4. File ciphertext envelope

### 4.1 Single-PUT (at most 16 MB plaintext)

Used for files that fit in one upload request. Layout on disk in object storage:

```
[1 byte magic: 0x01] [1 byte alg: 0x01 = A256GCM] [12 bytes IV] [N bytes ciphertext] [16 bytes GCM tag]
```

Total size: 30 + N bytes for N-byte plaintext.

- **Magic byte (0x01):** identifies this as a Signet Drive single-PUT envelope. Catches accidental wrong-format reads.
- **Alg byte (0x01):** maps to `A256GCM`. Future variants use different alg byte values.
- **IV:** 12 bytes, generated fresh per file from `crypto.getRandomValues` (browser) or `OsRng` (CLI). Content encryption runs on the client only. Required to be unique per (key, file).
- **Ciphertext:** N bytes; raw GCM encryption output of the plaintext.
- **Tag:** 16 bytes; the standard GCM authentication tag.
- **AAD (NOT stored):** the file's `file_id` UUID encoded as 16 raw bytes. The sender and decryptor MUST include this as AAD on encrypt and decrypt operations. This defends against ciphertext substitution at the storage layer: if an attacker swaps blobs between two file ids, tag verification fails because the AAD does not match.

**DEK:** a 32-byte AES-256 key, generated fresh per file, wrapped to each recipient via section 5 envelopes.

### 4.2 Multipart (over 16 MB plaintext)

Used for large files via S3-style multipart upload. Each chunk is encrypted independently with a per-chunk derived nonce.

**Chunk layout on disk** (one object per chunk):

```
[1 byte magic: 0x02] [1 byte alg: 0x01 = A256GCM] [4 bytes chunk_index uint32_be] [12 bytes IV] [chunk_size bytes ciphertext] [16 bytes GCM tag]
```

Total per chunk: 34 + chunk_size bytes.

- **Magic byte (0x02):** identifies a multipart-chunk envelope.
- **Chunk index:** 0-based; monotonically increasing within an upload.
- **IV:** 12 bytes; derived from the DEK and chunk index via HKDF-SHA-256 with `info = "signet-drive-multipart-iv-v1" || chunk_index_uint32_be`. Deterministic per (DEK, chunk_index); this ensures uniqueness.
- **AAD (NOT stored):** `file_id || chunk_index_uint32_be || is_last` (21 bytes). `is_last` is one byte: `0x01` when this chunk is the file's terminal chunk (`chunk_index == chunk_count - 1`), `0x00` otherwise. This binds the chunk to its file, its position, and whether it terminates the file, so chunk substitution, reordering, and whole-chunk truncation all fail tag verification. The decryptor derives `is_last` from the externally supplied chunk count, and the AAD authenticates it, which makes the external count self-authenticating: dropping the real last chunk and lowering the count leaves a boundary chunk that was sealed with `is_last = 0x00` and refuses to open.

**Default chunk size:** 16 MB, configurable per upload-initiate request.
**Maximum chunks:** 10,000 (the S3 standard limit).

**S3 part-number mapping:** S3 part numbers are 1-based (1 to 10,000); `chunk_index` is 0-based for nonce derivation. Mapping: `chunk_index = part_number - 1`. The client converts to S3's 1-based numbering when calling the multipart-part-upload endpoint.

**Transport:** each encrypted chunk is one S3 multipart part. The transport protocol (initiate, upload, complete, abort) and the quota declare-verify model are owned by the large-file transport design; this section owns only the chunk byte format.

**Truncation detection (as built):** the truncation defense is in-envelope via the `is_last` AAD byte above. No header flag exists and none is needed; the frame layout carries no extra byte.

## 5. Wrapped DEK envelope

Used to wrap a DEK (or any 32-byte symmetric key) to a recipient's KEM public key.

**Classical algorithm:** `ECDH-ES+A256KW` per RFC 7518, section 4.6.

**Construction:**

1. The sender generates an ephemeral P-256 keypair (`epk_priv`, `epk_pub`).
2. ECDH agreement: `Z = ECDH(epk_priv, recipient_kem_pubkey)`; Z is a 32-byte shared secret.
3. Concat KDF (NIST SP 800-56A, section 5.8.1) with SHA-256: `KEK = ConcatKDF(Z, AlgorithmID="ECDH-ES+A256KW", PartyUInfo="", PartyVInfo="", SuppPubInfo=keydatalen=256 bits, SuppPrivInfo="")`. Output: a 32-byte KEK.
4. AES-256 Key Wrap (RFC 3394): `wrappedDEK = AES-KW(KEK, DEK)`. Output: 40 bytes (a 32-byte DEK plus 8 bytes of AES-KW overhead).

**Envelope (JSON):**

```json
{
  "v": 1,
  "alg": "ECDH-ES+A256KW",
  "epk": {
    "kty": "EC",
    "crv": "P-256",
    "x": "<base64url of 32-byte X coordinate>",
    "y": "<base64url of 32-byte Y coordinate>"
  },
  "ct": "<base64url of 40-byte wrappedDEK>",
  "rfp": "<recipient KEM pubkey fingerprint, lowercase hex>"
}
```

**Field semantics:**

- `v`: envelope version (1).
- `alg`: the algorithm identifier; the dispatch key.
- `epk`: the sender's ephemeral public key in JWK form (RFC 7517, section 3). `x` and `y` are 32 bytes each, base64url-encoded.
- `ct`: the wrapped DEK ciphertext (40 bytes).
- `rfp`: the recipient's KEM public-key fingerprint (lowercase hex SHA-256 of the recipient's DER-encoded SubjectPublicKeyInfo). Used for routing during DEK unwrap; the recipient verifies their own key matches before unwrapping.

**Unwrap (recipient):**

1. Parse the envelope; verify `alg`; retrieve `epk`.
2. `ECDH(recipient_kem_priv, epk_pub)` gives Z.
3. `ConcatKDF(Z, ...)` gives the KEK (same parameters as the wrap).
4. AES-KW unwrap of `ct` under the KEK gives the DEK. Failure indicates a wrong key or corrupted ciphertext.

### 5a. Hybrid recipient block (`ECDH-ES+ML-KEM-1024+A256KW`, v1)

The construction (the SP 800-227 section 4.6 two-step-HKDF KDM, the FixedInfo, the IND-CCA ciphertext binding, zeroization) is owned by the [PQR Crypto Specification](Signet-Drive-PQR-Crypto-Spec.md), sections 4 and 5, co-signed and KAT-pinned; this section records the on-the-wire shape and the validation rules every implementation enforces. As built: `crypto/src/hybrid_wrap.rs` (CLI and server side) and `web/src/lib/crypto/hybrid_wrap.ts`, proven byte-identical cross-surface by the committed `hybrid-crossover.json` goldens.

```json
{
  "v": 1,
  "alg": "ECDH-ES+ML-KEM-1024+A256KW",
  "epk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." },
  "ek":  "<base64url of the 1568-byte ML-KEM-1024 ciphertext>",
  "wk":  "<base64url of the 40-byte AES-KW output>",
  "rfp": "<recipient hybrid KEM pair-fingerprint, lowercase hex>"
}
```

**Field semantics:**

- `epk`: the sender's ephemeral P-256 public key (the classical half), JWK form as in section 5.
- `ek`: the ML-KEM-1024 ciphertext (`draft-ietf-jose-pqc-kem` naming), the PQ half. Length-exact 1568 bytes.
- `wk`: the AES-KW-wrapped key. Deliberately not a bare `ct`, which would collide with a KEM ciphertext in the same object.
- `rfp`: the pair-commitment of PQR Crypto Specification section 8.5: one SHA-256 over both length-prefixed recipient KEM public keys (`SHA-256(lp(rk_ec) || lp(rk_pq))`), NOT the classical single-key SPKI fingerprint. A PQ-stripped directory bundle changes it.

**Validation (MUST, symmetric; PQR Crypto Specification, section 5.2):** the hybrid block requires `epk` AND `ek`, each length-exact; missing or malformed either way means reject. A classical section 5 envelope with an `ek` smuggled in means reject: no field-smuggling across algorithms. Implementations select the unwrap code path from `alg` alone, never from field presence, and parse with exact-field strictness (`deny_unknown_fields` and strict parsers on both surfaces).

**Unwrap:** `Z_ecdh = ECDH(recipient_kem_priv, epk)` plus `Z_mlkem = ML-KEM.Decaps(sk_pq, ek)`, then the PQR section 4.2 KDM (with the recipient's own static public keys reconstructing FixedInfo, the recipient binding), then AES-KW unwrap. AES-KW integrity failure is the sole tamper signal: a tampered `ek` decapsulates to a pseudorandom secret per FIPS 203 implicit rejection and fails only here (PQR Crypto Specification, section 10). No decapsulation-versus-key-wrap oracle is exposed.

**The pure form** (`ML-KEM-1024+A256KW`: the same shape with `epk` replaced by `ek`) is reserved and rejected by v1 implementations (pin-tested); see section 3.

## 6. Attestation record format

Attestations are server-recorded database rows, not JWS-signed artifacts. When recipients need to verify an attestation, they query a server endpoint and receive a server-signed verification response (section 9).

This reflects the trust model: trust Signet Drive's record-keeping, backed by open source, reproducible builds, the transparency log, and community watchers, rather than a cryptographic chain back to the Guardian's passkey signatures.

### 6.1 Data fields recorded server-side

An attestation row contains:

| Field | Type | Notes |
|---|---|---|
| `attestation_id` | UUID | The unique identifier; recipients query by this |
| `subject_account_id` | UUID | The PRSN this attestation is for |
| `guardian_account_id` | UUID | The Guardian |
| `subject_signing_pubkey` | BYTEA | ECDSA P-256, X9.63 uncompressed (65 bytes) |
| `subject_signing_pubkey_fingerprint` | VARCHAR | Lowercase hex SHA-256 of the DER SubjectPublicKeyInfo |
| `subject_signing_alg` | VARCHAR | `ES256` |
| `subject_kem_pubkey` | BYTEA | ECDH P-256, X9.63 uncompressed (65 bytes) |
| `subject_kem_pubkey_fingerprint` | VARCHAR | Lowercase hex SHA-256 of the DER SubjectPublicKeyInfo |
| `subject_kem_alg` | VARCHAR | `ECDH-ES+A256KW` |
| `created_at` | TIMESTAMPTZ | When the attestation was issued |
| `expires_at` | TIMESTAMPTZ | NULL means no expiry; a Guardian-set value if time-bounded |
| `revoked_at` | TIMESTAMPTZ | NULL means active; set on revocation |
| `revoked_by_account_id` | UUID | Who revoked (Guardian or admin) |
| `webauthn_authorization_evidence` | JSONB | The Guardian's WebAuthn assertion proving authorization |

A hybrid attestation additionally binds the PQ keys (ML-DSA-87 signing and ML-KEM-1024 KEM public keys, each with a fingerprint), per PQR Crypto Specification section 8, point 5.

The PRSN's sharing capability is a per-PRSN account property, looked up from the accounts table when building the verification response; the attestation row does not carry it. There is no per-surface dimension: one keypair set per PRSN, on a single host.

The `webauthn_authorization_evidence` field stores the WebAuthn assertion produced by the Guardian's passkey gesture at attestation issuance. All sensitive operations use the same generic two-phase ceremony state machine (attestation issuance, attestation revocation, passkey rotation, account deletion, per-PRSN sharing-capability change). Shape:

```json
{
  "credential_id": "<base64url>",
  "client_data_json": "<base64url of clientDataJSON>",
  "authenticator_data": "<base64url>",
  "signature": "<base64url>",
  "challenge": "<base64url of the challenge the server issued>",
  "challenge_context": {
    "operation": "issue_attestation",
    "ceremony_id": "<UUID v4, server-generated at ceremony begin>",
    "operation_parameters": {
      "subject_account_id": "<UUID>",
      "subject_signing_pubkey_fingerprint": "<hex>",
      "subject_kem_pubkey_fingerprint": "<hex>",
      "expires_at": "<unix seconds or null>"
    },
    "issued_at": <unix seconds>
  }
}
```

The challenge included in the WebAuthn assertion's `clientDataJSON.challenge` is computed by the server as `SHA-256(canonical_json_per_RFC_8785(challenge_context))`. The Guardian's passkey signs the assertion; this is cryptographic evidence that the Guardian authorized this specific operation with these specific parameters. An operation-bound challenge is forensically stronger than a random nonce.

**On `ceremony_id` versus `attestation_id`:** the challenge context includes `ceremony_id`, which the server controls and pre-allocates at ceremony begin, NOT `attestation_id`. The attestation id (the primary key of the eventual attestation row) is generated at INSERT after verification; `ceremony_id` provides the uniqueness needed during the ceremony.

**The two-phase ceremony state machine, used for all sensitive operations:**

1. `POST /v1/{operation}/ceremony/begin` with operation parameters.
   - The server validates the parameters.
   - The server generates `ceremony_id` (UUID v4).
   - The server computes `challenge = SHA-256(canonical_json_per_RFC_8785({operation, ceremony_id, operation_parameters}))`.
   - The server inserts a pending-ceremony row with a TTL (`system_config.ceremony_ttl_seconds`, default 300).
   - The server returns `{ ceremony_id, challenge, webauthn_assertion_options }`.

2. `POST /v1/{operation}/ceremony/complete` with the assertion and `ceremony_id`.
   - The server selects the pending row by `ceremony_id`; it rejects if not found or expired.
   - The server verifies the WebAuthn assertion against the saved challenge.
   - The server reconstructs the challenge context from the saved operation parameters and verifies `clientDataJSON.challenge` matches `SHA-256(canonical_json_per_RFC_8785(reconstructed_context))`. This defends against client-side context tampering between begin and complete.
   - The server performs the operation atomically (insert the attestation row, or delete the attestation, or rotate the passkey blob, or mark the account pending deletion, and so on); fires the required audit events; inserts transparency-log entries with receipts (section 10a) where applicable.
   - The server deletes the pending-ceremony row and returns the operation result.

**Operation parameters per operation:**

- `issue_attestation`: `{ subject_account_id, subject_signing_pubkey_fingerprint, subject_kem_pubkey_fingerprint, key_protection, expires_at }`. `key_protection` is always `secure_enclave` for PRSNs, the only valid value; the server rejects any other. The keys live in an Apple Secure Enclave: the device Enclave for a native PRSN, the host Mac's Enclave via host delegation for a containerized one (the container holds no keys). It remains an attested claim: the server enforces the value but cannot independently verify Enclave residency. The new PRSN's account id and handle are allocated at ceremony complete, not at begin.
- `revoke_attestation`: `{ attestation_id }`.
- `rotate_passkey`: `{ new_credential_registration_response, new_wrapped_kem_privkey_blob }`, using the generic two-phase ceremony with an operation-bound challenge; the complete step carries these parameters plus the current credential's assertion.
- `delete_account`: `{ confirmation_handle }` (the user types their handle as a fat-finger guard).
- `change_sharing_capability`: `{ subject_account_id, new_sharing_capability }`. The server validates that the subject is a PRSN in the guardianship of the calling account (or admin).

**Cleanup:** a background job removes pending-ceremony rows past their expiry.

The evidence is retained for audit purposes. If a Guardian later disputes having issued an attestation, the server can produce the WebAuthn assertion, which only the Guardian's passkey could have produced under user verification, as proof: "your passkey signed THIS exact operation with THESE parameters," not just a random nonce. The evidence is not in the critical path for everyday verification; it becomes load-bearing in audit and dispute scenarios or in adversarial review of the server's record-keeping.

### 6.2 Per-request signing (PRSN side)

When a PRSN makes an API request, the request includes signed canonical bytes proving the request was authorized by the holder of the attested signing key.

**Canonical bytes to sign:**

```
SIGNET-V1
<HTTP method, uppercase>
<request path including query string>
<lowercase hex SHA-256 of request body bytes (empty body hashes to e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)>
<value of Signet-Timestamp header>
<value of Signet-Nonce header>
<value of Signet-Fingerprint header>
```

There is no special case for an empty body: always the SHA-256 of the body bytes, and an empty body produces the SHA-256 of zero-length input, `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

Elements are joined with a single LF (`0x0A`); no trailing newline. Seven elements: the `SIGNET-V1` version marker plus six request-specific values.

**Headers on the request:**

- `Signet-Fingerprint`: 64-character lowercase hex (the PRSN's signing-key fingerprint)
- `Signet-Timestamp`: unix seconds, integer
- `Signet-Nonce`: 32-character lowercase hex, random
- `Signet-Signature`: base64url of the signature; the accepted forms are below

**The hybrid dual-signature.** For a hybrid-attested account (the four-key attestation set), `Signet-Signature` carries the fixed-width dual signature `sig_es256 (64 B, raw r||s) || sig_mldsa87 (4627 B)`: 4691 bytes total, base64url as before; no new header, no framing. Both halves sign the identical canonical bytes above (PQR Crypto Specification, section 8.7); the ML-DSA-87 half uses the FIPS 204 context `signet:req:v1` supplied as the context parameter, never prepended (a shared, KAT-pinned constant).

**Length dispatch (as built):** the server distinguishes the forms by length alone. Exactly 64 bytes selects classical raw `r||s`; at most 72 bytes selects classical DER; exactly 4691 bytes selects dual (the ES256 half inside a dual is always raw; DER is a classical-wire form only, which keeps the split framing-free and the total unambiguous); anything else gets `401 signature_format_unknown`. In-between lengths are negative-tested.

**Server enforcement (the request-path downgrade defense):** a hybrid-attested account presenting a classical-form signature, even a valid one, is rejected with `401 dual_signature_required` (PQR Crypto Specification, section 8.6). Every account is hybrid-attested and enrollment issues the four-key hybrid set only, so there is no classical-signature path to fall back to. Verification is AND-semantics with per-half precise errors via a shared server verifier.

**Server verification:**

1. Look up the active attestation by `Signet-Fingerprint` (it matches `subject_signing_pubkey_fingerprint`); reject `401 attestation_not_found` if there is none.
2. Verify the attestation is not expired or revoked; reject `401 attestation_invalid` otherwise.
3. Verify `|now - Signet-Timestamp|` is within `system_config.replay_window_seconds`; reject `401 timestamp_skew`.
4. INSERT `(fingerprint, nonce, timestamp)` into the replay table with `ON CONFLICT DO NOTHING`; if not inserted, reject `409 replay_detected`. This is an atomic check-and-insert; no TOCTOU.
5. **Defensive signature-length check:** before verification, check the signature length is exactly 64 bytes (raw), at most 72 bytes (DER), or exactly 4691 bytes (dual). Otherwise reject `401 signature_format_unknown`; this saves cycles and produces a clearer error than running verification against malformed input. A valid DER signature whose `r` or `s` component has a short or leading-zero high byte is shorter than 70 bytes, which is why the DER bound is "at most 72", not a rigid range.
6. Verify the signature against the canonical bytes per the length dispatch above. Reject `401 signature_invalid` if the length was valid but the signature did not verify.
7. Execute the operation.

## 7. Encrypted metadata (folder and file names)

Folder names and file names are encrypted with the per-root-folder metadata key.

### 7.1 Metadata key model

One metadata key per share-folder hierarchy (and per private-folder hierarchy, though private folders are visible only to the owner anyway). The metadata key is a 32-byte AES-256 key.

- For private folders: the metadata key is wrapped to the owner's KEM public key only.
- For share folders: the metadata key is wrapped to each recipient's KEM public key (one row per folder-recipient pair).
- Subfolders inside a share folder use the same metadata key as the root folder; there is no separate wrap per subfolder.

When a new recipient is added to a share folder, the owner's client wraps the existing metadata key to the new recipient's KEM public key and POSTs the wrap envelope to the server.

### 7.2 Metadata-key envelope

The same shape as the section 5 wrapped-DEK envelope: the same algorithm (`ECDH-ES+A256KW`), wrap construction, and JSON shape. Hybrid recipients get the section 5a block instead, with the folder binding riding the PQR section 4.3 `party_v` field (the 16-byte `root_folder_id`, KAT-pinned, negative-tested as N7).

```json
{
  "v": 1,
  "alg": "ECDH-ES+A256KW",
  "epk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." },
  "ct": "<base64url of 40-byte wrapped metadata key>",
  "rfp": "<recipient KEM pubkey fingerprint>"
}
```

**Wrap binding.** This envelope uses `ECDH-ES+A256KW` (AES Key Wrap, RFC 3394), which has no AAD parameter, so there is no GCM-style AAD here (unlike the encrypted-name envelope in section 7.3). To bind the wrapped metadata key to its folder, as defense in depth against a malicious server swapping wrapped-metadata-key blobs between folders for the same recipient, the classical construction folds `root_folder_id` into the Concat-KDF `OtherInfo` so the derived KEK is folder-specific: a blob moved to another folder is unwrapped under that folder's KEK, and AES-KW's built-in integrity check rejects it cleanly. This keeps `alg = ECDH-ES+A256KW` (off-the-shelf, JOSE-conformant, crypto-agility by algorithm identifier, no envelope-shape change), preferred over an A256GCM-with-AAD composition, which would be a non-standard JOSE shape and would diverge this envelope from section 5. `root_folder_id` enters the Concat-KDF `OtherInfo` as its canonical 16-byte UUID in the `PartyVInfo` slot (the JOSE `apv` parameter); a DEK wrap uses an empty `PartyVInfo`. The placement is pinned by the committed cross-implementation golden ([test-vectors](test-vectors/), `golden/wrap-chain.json`). The section 5 DEK wrap already binds `file_id` via content-layer AAD, so it needs no change. The hybrid continuation of this binding is the `party_v` field, defined and KAT-pinned in the PQR Crypto Specification, section 4.3.

### 7.3 Encrypted-name envelope

Folder and file names are encrypted with AES-256-GCM using the parent root folder's metadata key.

```json
{
  "v": 1,
  "alg": "A256GCM",
  "iv": "<base64url of 12-byte AES-GCM nonce>",
  "ct": "<base64url of UTF-8-encoded name ciphertext>",
  "tag": "<base64url of 16-byte GCM tag>"
}
```

**AAD:** `root_folder_id (16 bytes) || target_id (16 bytes)`, where `target_id` is the file or folder id this name belongs to. This binds the name to its specific resource within the folder hierarchy and defends against name-substitution attacks.

**Plaintext:** the name as a UTF-8 byte string, limited to 255 UTF-8 bytes (server-enforced).

## 8. Human-side wrap chain (single-credential hybrid-KEM wrap)

Single passkey per human account; no multi-credential master-key indirection. The human's hybrid KEM private material, the ECDH P-256 private key AND the ML-KEM-1024 seed, is wrapped as ONE blob (the v2 plaintext layout, section 8.3) with a key derived from the user's WebAuthn PRF output. One blob, one wrap, one PRF gesture.

### 8.1 What is stored

On the account row:

- `kem_pubkey`: the ECDH P-256 public key (X9.63 uncompressed, 65 bytes; published)
- `kem_pubkey_fingerprint`: lowercase hex SHA-256 of the DER SubjectPublicKeyInfo (published)
- `kem_pq_pubkey`: the ML-KEM-1024 encapsulation key (1568 bytes; published; the PQ half of the hybrid directory pair)
- `kem_pq_pubkey_fingerprint`: lowercase hex SHA-256 over the raw FIPS 203 encapsulation-key bytes. This is a deliberate, named split from the classical SPKI convention above; ML-KEM keys have no SPKI form in this stack.
- `wrapped_kem_privkey_blob`: the encrypted hybrid private material (the server holds it; only the user can decrypt it with their passkey). Set atomically with both public keys at key initialization: a classical-only directory row is not a reachable state for a new account.

### 8.2 Wrap-key derivation

1. **WebAuthn PRF assertion.** The user performs a WebAuthn assertion with the PRF extension; the salt is fixed: `SHA-256("signet-drive-kem-wrap-v1")` (32 bytes).
2. **PRF output.** The authenticator returns 32 bytes of pseudo-random material in `clientExtensionResults.prf.results.first`.
3. **HKDF-SHA-256.** Derive the wrap key W:

   ```
   W = HKDF-SHA-256(
     ikm = prf_output,                    // 32 bytes
     salt = empty,                        // the PRF output is already a strong key; HKDF provides domain separation + version-suffix capability
     info = ASCII bytes of "signet-drive-kem-wrap-v1",  // 24 bytes
     length = 32                          // for AES-256
   )
   ```

   Implementation note, applying to every web-side HKDF use (this one and the hybrid KDM): the web client's `hkdfSha256` composes RFC 5869 Extract-then-Expand over native WebCrypto HMAC rather than calling SubtleCrypto's own HKDF deriveBits. Node's WebCrypto caps the native path's `info` at 1024 bytes while the hybrid FixedInfo is 3324 or 3340 bytes, and RFC 5869 imposes no limit. The composition is byte-identical by construction (HKDF is defined over HMAC; it is the same composition the Rust `hkdf` crate runs), pinned by the RFC 5869 Appendix A vectors, the committed kem-wrap goldens, and the KeyCombine KAT. As built: `web/src/lib/crypto/kdf.ts`.

### 8.3 Wrap envelope

```json
{
  "v": 1,
  "alg": "A256GCM",
  "iv": "<base64url of 12-byte AES-GCM nonce>",
  "ct": "<base64url of the blob-v2 plaintext ciphertext>",
  "tag": "<base64url of 16-byte GCM tag>"
}
```

**Plaintext: the blob v2 layout:**

```text
0x02 || u32be(len) || p256_pkcs8 || u32be(len) || mlkem_seed(64)
```

- `0x02`: the version byte, pinned. Pre-launch re-enrollment means no legacy (bare-PKCS#8, `0x30`-first) blobs ever exist in production, so anything but `0x02` is malformed; there is no legacy parse path. Length prefixes follow the suite's u32 big-endian convention.
- `p256_pkcs8`: the ECDH P-256 private key in PKCS#8 form (roughly 138 bytes; what `WebCrypto.subtle.exportKey("pkcs8", privateKey)` produces).
- `mlkem_seed`: the 64-byte ML-KEM-1024 (d,z) seed, never the roughly 3 KB decapsulation key. The decapsulation key regenerates from the seed at sign-in (FIPS 203 KeyGen determinism) and lives in WASM memory for the session.

As built: `web/src/lib/crypto/keyblob.ts` (strict decode: exact version byte, exact framing, no trailing bytes).

**AAD:** the fixed string `"signet-drive-kem-wrap-v1"` (ASCII bytes; 24 bytes). Binds the wrap to its purpose: domain separation between the KEM-key wrap and any future similar wraps.

**Encryption:** AES-256-GCM with key W (section 8.2), a fresh random 12-byte IV per wrap, regenerated on signup, on passkey rotation, or on any other re-wrap event.

### 8.4 Sign-up flow (first time)

1. The browser generates the ECDH P-256 keypair via `WebCrypto.subtle.generateKey`, and the ML-KEM-1024 identity via the WASM module (keygen produces the 64-byte (d,z) seed plus the 1568-byte encapsulation key, CSPRNG-seeded).
2. The browser performs WebAuthn registration with a new passkey.
3. The browser performs an immediate WebAuthn assertion with the PRF extension; salt `SHA-256("signet-drive-kem-wrap-v1")`.
4. The browser derives W per section 8.2.
5. The browser exports the ECDH private key to PKCS#8 and assembles the blob-v2 plaintext (section 8.3).
6. The browser encrypts the blob-v2 plaintext with W using AES-256-GCM (fresh 12-byte IV; AAD per section 8.3).
7. The browser uploads to the server: `kem_pubkey` (X9.63) plus `kem_pq_pubkey` (the ML-KEM encapsulation key) plus the wrap envelope.
8. The server validates (a valid P-256 point; the encapsulation key length-exact at 1568 bytes) and stores the hybrid pair plus blob atomically, set-once, per section 8.1.
9. The server adds entries to the transparency log for the published keys, carrying the hybrid pair-commitment (PQR Crypto Specification, section 8.5), with a dual-signed receipt per entry.
10. The browser zeroizes W, the PRF output, the seed copy, and the private-key bytes (best-effort given the JavaScript memory model).

### 8.5 Sign-in flow

1. The browser performs a WebAuthn assertion with the PRF extension; salt `SHA-256("signet-drive-kem-wrap-v1")`.
2. The server verifies the assertion; if valid, it returns the account's `wrapped_kem_privkey_blob`, `kem_pubkey`, and `kem_pq_pubkey`.
3. The browser derives W per section 8.2.
4. The browser decrypts the wrap envelope with W and strict-parses the blob-v2 plaintext (section 8.3) into the PKCS#8 key and the ML-KEM seed.
5. The browser imports the PKCS#8 as a non-extractable `CryptoKey`; the ML-KEM seed is held in memory, and the session decapsulation key regenerates from it inside the WASM per operation. It never crosses the JavaScript boundary.
6. **Self-key checks, both halves:** the classical `kem_pubkey` is verified by a wrap-then-unwrap probe round-trip; the PQ half is verified by direct byte-compare: the encapsulation key regenerated from the seed must equal the returned `kem_pq_pubkey` (FIPS 203 KeyGen determinism makes the direct compare possible). A missing or mismatched directory key for a v2-blob account is infrastructure lying, and it is a hard failure (the refuse-to-downgrade rule applied to self).
7. The browser zeroizes W, the PRF output, and the transient plaintext buffers.

### 8.6 Passkey rotation flow

The user is authenticated with passkey A. The rotation flow re-derives the blob plaintext fresh from the server-stored wrap blob, NOT from the in-memory non-extractable `CryptoKey`.

1. **Re-derive fresh:** the browser re-prompts a WebAuthn assertion on passkey A with the PRF extension to re-derive W_A, fetches the wrap envelope from the server, and decrypts to recover the blob plaintext in a transient buffer, for the duration of the rotation operation only. The in-memory non-extractable `CryptoKey` from prior session activity is not used as the source: it cannot be re-exported, and it does not need to be; the wrap blob is the source of truth.
2. The browser registers new passkey B via WebAuthn registration.
3. The browser performs an assertion on B with the PRF extension and derives the new wrap key W_B.
4. The browser encrypts the blob plaintext with W_B per section 8.3 (fresh IV; same AAD).
5. The browser uploads the new wrap envelope; the server replaces `wrapped_kem_privkey_blob`.
6. The server retires passkey A's credential row and inserts the new row for B.
7. The server adds a transparency-log entry only if the underlying `kem_pubkey` changed, which it does not on passkey rotation; only the wrap changes.
8. The browser zeroizes the transient plaintext buffer, W_A, and W_B.

**Rotation is blob-layout-agnostic:** under the v2 plaintext, the rotation flow re-wraps the whole blob plaintext opaquely (unwrap under W_A, re-wrap the identical plaintext under W_B, no parse). Both KEM halves therefore survive rotation unchanged. As built: `web/src/lib/rotate.ts`.

After rotation: only B can sign in. A's wrap key no longer decrypts the new blob. The ECDH `kem_pubkey` is unchanged, so existing wraps to the user remain valid.

### 8.7 Loss recovery

Lose the passkey, lose access to W, lose access to the private keys, lose access to the data. Mitigation: synced platform passkeys (iCloud Keychain, Google Password Manager, Windows Hello) recover via the ecosystem account.

## 9. Server-signed verification response format

When a recipient (or any verifier) needs to verify an attestation's contents, they query the server's verification endpoint:

```
GET /v1/attestations/<attestation_id>/verification
```

**Authentication:** none required. Attestation verification is a public lookup; the response itself is verifiable via the server signature.

**Response (JSON):**

```json
{
  "v": 1,
  "attestation": {
    "attestation_id": "<UUID>",
    "subject_account_id": "<UUID>",
    "subject_handle": "<handle string, e.g., 'ada-ai'>",
    "subject_signing_pubkey": "<base64url of X9.63 uncompressed>",
    "subject_signing_pubkey_fingerprint": "<lowercase hex>",
    "subject_signing_alg": "ES256",
    "subject_kem_pubkey": "<base64url of X9.63 uncompressed>",
    "subject_kem_pubkey_fingerprint": "<lowercase hex>",
    "subject_kem_alg": "ECDH-ES+A256KW",
    "created_at": <unix seconds>,
    "expires_at": <unix seconds or null>,
    "status": "active" | "revoked" | "expired",
    "revoked_at": <unix seconds, present if revoked>,
    "prsn_sharing_capability": "<none|read_only|read_write>",
    "key_protection": "secure_enclave"
  },
  "server_key_id": "<UUID, the server key that signed this response>",
  "server_signature": "<base64url of ECDSA signature over canonical bytes; raw r||s>",
  "signed_at": <unix seconds, when this response was signed; recent>
}
```

**No Guardian information.** The verification response does NOT include `guardian_account_id`, `guardian_handle`, or any Guardian-related fields. The server records the Guardian internally but does not expose it externally.

**`key_protection`** exposes the PRSN's attested key-custody tier so verifiers see the protection level they are trusting. It is always `secure_enclave`, the only valid value for PRSNs, server-enforced; host delegation puts containerized-PRSN keys in the host Mac's Enclave, so all PRSNs are Enclave-grade. It is part of the signed attestation object, inside the canonical bytes.

**Canonical bytes for the server signature:** the response's `attestation` field, serialized as canonical JSON per RFC 8785 (JCS), concatenated with `server_key_id` and `signed_at`:

```
"signet-server-attestation-verify-v1\n" || canonicalize_RFC_8785(attestation) || "\n" || server_key_id || "\n" || str(signed_at)
```

Joined with single LF separators. The domain-separation prefix prevents this signature being misinterpreted as another kind of signature. RFC 8785 defines deterministic key ordering, number normalization, and Unicode escape rules; Rust (`serde_jcs`) and TypeScript libraries are available.

**Exclusion of `server_signature` from canonicalization.** The signed canonical bytes are constructed from the `attestation` object plus `server_key_id` plus `signed_at` only. The top-level `server_signature` field is a sibling that is NOT part of the canonicalized input; it is the output of signing, so it is necessarily excluded. The inline receipt fields are likewise not covered by `server_signature`; each receipt carries its own server signature (section 10a) and is verified independently. A verifier reconstructs the canonical bytes by taking `attestation`, `server_key_id`, and `signed_at` from the response and applying the construction above; it does NOT canonicalize the whole response object.

**The response is dual-signed (`ES256` plus `ML-DSA-87`).** Two top-level siblings appear beside `server_signature`: `server_pq_key_id` (the server key of the `attestation_verification_pq` purpose) and `server_signature_mldsa87` (base64url of the ML-DSA-87 signature). Both halves sign the identical canonical bytes above (PQR Crypto Specification, section 8.7); the construction is unchanged, with no vector break. The ML-DSA half takes `ctx = "signet-server-attestation-verify-v1"` as the FIPS 204 context parameter (the domain-prefix label, the prefix string minus its framing `\n`; a shared, KAT-pinned constant). Both new fields are top-level siblings, NOT part of the canonicalized input, by the same exclusion rule. **Downgrade defense:** once the server's ML-DSA-87 verification key is published (`/v1/server-info`, purpose `attestation_verification_pq`), a verifier MUST reject an `ES256`-only response; the classical canonical bytes carry no PQ field, so the response-layer rule lives in the client, not the bytes. When the attestation itself is hybrid, the response also carries the subject's PQ public keys with fingerprints and algorithms, the section 8.5 pair-commitment `rfp`, and the two PQ inline receipts, all inside the same signed attestation object.

**Verification responses include log receipts.** Each public key referenced in the response has a corresponding signed log receipt, the SCT equivalent (Certificate Transparency precedent), included inline:

```json
{
  "v": 1,
  "attestation": { ... },
  "subject_signing_pubkey_receipt": { ... per section 10a ... },
  "subject_kem_pubkey_receipt": { ... per section 10a ... },
  "server_key_id": "<UUID>",
  "server_signature": "<base64url>",
  "signed_at": <unix seconds>
}
```

**Recipient verification:**

1. Fetch the response.
2. Fetch the server's public key for `server_key_id` from `/v1/server-info` (or trust a previously cached value).
3. Reconstruct the canonical bytes; verify `server_signature` against the server's public key (and `server_signature_mldsa87` against the server's PQ key, per the dual-signing rule above).
4. Verify each receipt per section 10a: the receipt's signature against the server's signing key; the receipt's `entry_hash` against the canonical bytes for the asserted public key; and if `(now - receipt.issued_at)` exceeds `receipt.max_merge_delay_seconds`, the entry MUST be in a publicly committed Merkle root, which the verifier can confirm from the public commit log.
5. Check `status = "active"` and, if `expires_at` is set, that it has not passed.
6. Use `subject_kem_pubkey` (and the PQ half, for a hybrid attestation) for wrapping operations; use the signing keys for signature verification on PRSN-side requests.

**Cache-Control on the verification endpoint:** responses are cacheable for a short period (default 60 seconds) via `Cache-Control: public, max-age=60`. Long enough to amortize server load; short enough that revocation propagates quickly. Recipients re-fetch beyond the cache window.

**Cache-Control on `/v1/server-info`:** also `public, max-age=60`, so server signing-key rotation propagates within about a minute.

**CLI auto-recovery on signature failure:** when `signet attestation-verify` encounters a server-signature verification failure, it re-fetches `/v1/server-info` once before exiting with the error. This handles the rotation race window where the verifier's cached server info still has the old key but the response was signed with a new one.

**Cross-checking against the transparency log:** the receipts are the immediate cross-check, signed by the server's known key and binding the public key bytes to a specific log entry. The publicly committed Merkle root is the retrospective audit anchor. Advanced verifiers can fetch inclusion proofs and verify against committed roots even before the MMD elapses, per the Transparency Log Specification, section 6.

## 10. Transparency log entry format

Each entry in the transparency log has the following shape:

| Field | Type | Notes |
|---|---|---|
| `entry_id` | uint64 | Position in the log (1-indexed) |
| `account_id` | UUID (16 bytes) | Whose key |
| `key_purpose` | enum | `signing` (1) or `kem` (2) |
| `algorithm` | string | `ES256`, `ECDH-ES+A256KW`, and similar identifiers |
| `public_key` | bytes | X9.63 uncompressed (65 bytes for P-256) |
| `public_key_fingerprint` | bytes (32) | SHA-256 of the DER SubjectPublicKeyInfo |
| `created_at` | uint64 | Unix seconds |
| `prev_entry_hash` | bytes (32) | SHA-256 of the previous entry; zero for entry 1 |
| `entry_hash` | bytes (32) | SHA-256 of the canonical bytes below |

**Canonical bytes for hashing each entry:** big-endian uint64 `entry_id`, then the 16-byte `account_id`, then the 1-byte `key_purpose` enum, then the length-prefixed UTF-8 `algorithm` string (uint32 big-endian length, then bytes), then the 65-byte `public_key`, then big-endian uint64 `created_at`, then the 32-byte `prev_entry_hash` (zero bytes for entry 1).

**Merkle root computation:** per the [Transparency Log Specification](Signet-Drive-Transparency-Log-Spec.md). Roots are computed periodically over all entries up to a given log size; root values are stored and committed to a public location.

The `entry_hash` composition above, which includes `algorithm` and `created_at`, is normative for bytes on the wire for **v1 entries**. Entries after the epoch checkpoint use the **v2 format**: a version byte inside the hashed bytes, a length-prefixed `public_key` (fitting the post-quantum key sizes), and the added `signing_pq`, `kem_pq`, and `epoch` purposes; the [Transparency Log Specification](Signet-Drive-Transparency-Log-Spec.md) section 3.7 is the authority. Cross-implementation portability for receipt verification depends on consistent canonical-bytes computation across all client implementations and any third-party verifiers.

## 10a. Log receipt format

Receipts are issued by the server immediately at log-insert time and serve as the SCT equivalent (Certificate Transparency precedent). The receipt is the immediate trust signal for verifiers; inclusion in a publicly committed Merkle root within the MMD is the retrospective audit anchor.

**JSON shape:**

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

**Server-signature canonical bytes:** the receipt JSON object EXCLUDING every `server_signature*` field, serialized per RFC 8785 (JCS), prefixed with the domain separator:

```
"signet-pubkey-log-receipt-v1\n" || canonicalize_RFC_8785(receipt_without_signatures)
```

Signed with the server's attestation-verification-purpose signing key. Recipients fetch the corresponding public key from `/v1/server-info`.

**Receipts are dual-signed at insert.** A hybrid-era receipt carries two additional fields: `server_pq_key_id` inside the classically signed object, and `server_signature_mldsa87` as a sibling of `server_signature`. The signing input strips every `server_signature*` field before canonicalizing, so both halves sign identical bytes (PQR Crypto Specification, section 8.7); the ML-DSA half takes `ctx = "signet-pubkey-log-receipt-v1"` (the label, a KAT-pinned constant). **The anti-strip binding:** `server_pq_key_id` lives INSIDE the ES256-signed bytes, so downgrading a dual receipt to the classical shape by dropping the PQ fields breaks the classical signature, and keeping the key id while dropping `server_signature_mldsa87` fails the client-side dual-verification rule. Receipts are dual-signed at insert, not re-signed at serving time: production ML-DSA signing is hedged (randomized), so the issued receipt is the only one. Receipts issued before the server's PQ key existed name no PQ key and verify classically as issued; honest legacy, watcher-visible via the log timeline. The server's own ES256 and ML-DSA-87 keys are themselves logged (a `signing` and a `signing_pq` entry under the reserved server account), so a substituted server PQ verification key is watcher-detectable.

**Verifier behavior:**

1. Verify `server_signature` against the server's public key for `server_key_id`. If the receipt names a `server_pq_key_id`, ALSO verify `server_signature_mldsa87` against the server's PQ verification key over the same signing input; a receipt naming a PQ key without a verifying co-signature is rejected.
2. Verify `entry_hash` matches the canonical bytes for the asserted public key (per the section 10 computation).
3. If `(now - issued_at)` is within `max_merge_delay_seconds`: the receipt is valid as immediate evidence; the entry is in the log and will be in some publicly committed Merkle root within the MMD.
4. If `(now - issued_at)` exceeds `max_merge_delay_seconds`: the entry MUST be in some publicly committed Merkle root or the log is provably misbehaving; the verifier can fetch the inclusion proof and confirm.

**Endpoint:** `GET /v1/transparency/log/receipt?fingerprint=<hex>&purpose=<signing|kem>` returns the most recent receipt for the key (Transparency Log Specification, section 6).

## 11. Worked example: round-trip a small file

A complete end-to-end example for a small file upload by a PRSN, sharing to one recipient.

### Setup

- File: `notes.md` (5 KB plaintext)
- File id: `7c8f...3b1a` (UUID)
- Owner: `ada-ai` (a PRSN)
- Recipient: `sam`, the Guardian (a mandatory recipient on the PRSN's share folder)
- Folder: `My Notes` (a share folder the PRSN owns; the Guardian is a recipient)

### Encrypt the file (single CLI call)

```bash
signet encrypt \
  --in notes.md \
  --out notes.enc \
  --aad-file-id 7c8f...3b1a \
  --to-pubkey "<sam's KEM pubkey, X9.63 uncompressed, base64url>" \
  --to-pubkey "<ada-ai's own KEM pubkey>" \
  --wraps-out wraps.json
```

Internally:

1. Generates a random 32-byte DEK.
2. Generates a random 12-byte IV.
3. AES-256-GCM-encrypts `notes.md` with the DEK, IV, and AAD = `7c8f...3b1a` (16 raw bytes).
4. Writes `notes.enc` in the format `[0x01][0x01][12-byte IV][N-byte ct][16-byte tag]`.
5. For each `--to-pubkey`: wraps the DEK to that recipient (hybrid recipients get the section 5a block); produces a wrap envelope.
6. Writes `wraps.json` containing the array of wrap envelopes.
7. Zeroizes the DEK in process memory.

The DEK never appears as a command-line argument, an environment variable, or a file; it lives only in the CLI's process memory for the duration of the operation.

### Encrypt the file name

```bash
signet encrypt-name \
  --metadata-key-wrap <folder-metadata-key-wrap-envelope> \
  --root-folder-id <folder-id> \
  --target-id 7c8f...3b1a \
  --name "notes.md" \
  > encrypted_name.json
```

Output:

```json
{
  "v": 1,
  "alg": "A256GCM",
  "iv": "<base64url of 12-byte AES-GCM nonce>",
  "ct": "<base64url of 'notes.md' ciphertext>",
  "tag": "<base64url of 16-byte GCM tag>"
}
```

AAD: `<folder-id> (16 bytes) || 7c8f...3b1a (16 bytes)`.

### Construct the request body and POST

```bash
sign_request PUT "/v1/files/7c8f...3b1a" "$(jq -n \
  --arg folder_id "<folder-id>" \
  --argjson encrypted_name "$(cat encrypted_name.json)" \
  --argjson wrapped_deks "$(cat wraps.json)" \
  --arg ct_b64 "$(signet base64url-no-pad < notes.enc)" \
  '{folder_id: $folder_id, encrypted_name: $encrypted_name, wrapped_deks: $wrapped_deks, ciphertext_b64: $ct_b64}')"
```

The `sign_request` helper produces canonical bytes per section 6.2, signs them via `signet sign`, and POSTs to the server with the appropriate headers.

Server actions:

1. Verifies the per-request signature per section 6.2.
2. Inserts the file row (file id, folder id, encrypted name, etag, and so on).
3. Inserts recipient rows for each entry in `wrapped_deks`.
4. Stores the ciphertext blob in object storage at the determined storage key.

### The recipient downloads and decrypts

1. The recipient's web client fetches the file: ciphertext bytes.
2. The web client fetches the recipient's wrapped DEK.
3. The web client unwraps the DEK using the recipient's private keys, recovered via WebAuthn PRF and the wrap blob per section 8.
4. The web client decrypts the file using the DEK, with AAD = `7c8f...3b1a`.
5. The web client decrypts the file name using the folder's metadata key, similarly unwrapped per section 7.
6. The plaintext file and name are presented in the UI.

The server's role throughout: store ciphertext and envelopes; enforce authorization; never see plaintext.

## 12. Version evolution rules

- **The `v` field on every envelope.** Increment for incompatible changes; add fields for compatible additions.
- **Algorithm-identifier dispatch is the version boundary.** The dispatch table is the crypto-agility seam; blobs indicate their construction via `alg`, and implementations select code paths from `alg` alone (section 5a validation).
- **Magic bytes on file ciphertext.** New magic bytes for new envelope shapes; old magic bytes remain valid for reading existing files.
- **AAD strings include a version suffix.** `"signet-drive-kem-wrap-v1"` and similar; future chains bump the suffix to allow simultaneous support.
- **The PRF-blob plaintext version byte** (section 8.3) is the human-custody evolution seam: `0x02` is the launch layout, pinned; a future layout bumps the byte and adds a decode arm, never reinterpreting `0x02`.
- **The hybrid launched with the product.** v1 ships the hybrid content wrap and dual signatures before any users exist, so no classical-only migration population ever exists. The pure `ML-KEM-1024+A256KW` endpoint stays reserved: activating it would drop the classical hedge (PQR Crypto Specification, section 12).

## 13. Open questions

- **Compression before encryption.** Currently none (CRIME-class avoidance). Could be revisited for storage savings if the attack model permits.
- **Multipart chunk-size default.** Currently 16 MB; could be adjusted per object-storage multipart performance characteristics.
- **AAD inclusion expansion.** Currently `file_id` for single-PUT and `file_id || chunk_index || is_last` for multipart. Revisit if owner transfer becomes a feature; it would need to bind owner identity too.

## 14. Security review notes

This envelope format relies on standard cryptographic primitives used in standard ways. No novel constructions. Specific reviewable claims:

- **AES-256-GCM** with random per-file nonces (single-PUT) and HKDF-derived per-chunk nonces (multipart). NIST SP 800-38D conformant.
- **ECDH-ES plus Concat KDF plus AES-KW** for classical DEK and metadata-key wrapping per RFC 7518 section 4.6 and RFC 3394.
- **The hybrid content wrap** (`ECDH-ES+ML-KEM-1024+A256KW`) per the co-signed PQR Crypto Specification: the SP 800-227 section 4.6 KDM, KAT-pinned by independently generated, byte-compared vectors.
- **ECDSA P-256 with SHA-256** (`ES256`) for per-request signatures, RFC 7518 section 3.4 conformant; the hybrid dual-signature adds ML-DSA-87 with AND-semantics and length-based wire dispatch.
- **Server-signed verification responses** (section 9): dual signatures over RFC 8785 canonical JSON. Recipients verify against the published server public keys in `/v1/server-info`.
- **The single-credential wrap chain** (section 8): AES-256-GCM under an HKDF-derived wrap key, with the WebAuthn PRF extension providing the input key material. The PRF plumbing is the elevated-risk surface and received focused review.
- **Transparency log entries** (section 10): an append-only, hash-chained Merkle log, a standard Certificate-Transparency-style construction, with dual-signed receipts.

Independent cryptographic review of this format before launch covered, by name: the WebAuthn PRF custom layer, the server-signed verification response signing path, the transparency-log entry format and inclusion-proof generation (including the leaf-hash transformation worked example in the Transparency Log Specification), and the multipart truncation-detection decision (adopted as the `is_last` AAD byte, section 4.2).
