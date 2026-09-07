# Test Vector Category 03: SIGNET-V1 per-request signing canonical bytes

**Layer:** 1 + 2 (spec + concrete inputs + computed golden values; see "Layer 2 results" below; this is a Signet-Drive-specific construction)
**Spec source:** [Envelope Format](../Signet-Drive-Envelope-Format.md) section 6.2 ("Canonical bytes to sign")

---

## Why this vector exists

Every PRSN request to the Signet Drive API is independently signed over a deterministic, line-based canonical-bytes string built from the request's HTTP method, path, body hash, timestamp, nonce, and fingerprint. If implementations disagree on the canonical-bytes construction by even one byte (line ending, ordering, casing, padding), signatures do not verify and PRSN requests fail at the server.

This vector pins the canonical-bytes construction with concrete known inputs so all implementations (the `signet` CLI, PRSN-side libraries in any language, the server's verifier) produce identical bytes.

## Canonical-bytes format (per Envelope Format section 6.2)

Seven elements joined by single LF (`0x0a`) between elements. **No trailing newline.**

```
SIGNET-V1
<HTTP method, uppercase>
<request path including query string>
<lowercase hex SHA-256 of request body bytes>
<value of Signet-Timestamp header>
<value of Signet-Nonce header>
<value of Signet-Fingerprint header>
```

Total: 6 LF separators between 7 elements. The string `"SIGNET-V1"` is the literal version marker (9 ASCII bytes).

## Specification of each element

| # | Element | Encoding rule |
|---|---|---|
| 1 | Version marker | Literal ASCII `"SIGNET-V1"` (9 bytes: `53 49 47 4e 45 54 2d 56 31`) |
| 2 | HTTP method | Uppercase ASCII (`"GET"`, `"POST"`, `"PUT"`, `"PATCH"`, `"DELETE"`). Lowercase or mixed case is non-canonical and MUST NOT be used. |
| 3 | Request path including query string | Exact path as sent in the request line. Includes the leading `/`. Includes `?query=string` if any. URL-encoding (percent-encoding) is preserved as sent. |
| 4 | Body hash | Lowercase hex SHA-256 of request body bytes; 64 hex chars; empty body = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (per [Category 04](04-empty-body-hash.md)). |
| 5 | Timestamp | Decimal ASCII representation of the unix-seconds integer in the `Signet-Timestamp` header. No leading zeros, no thousands separators. |
| 6 | Nonce | 32-char lowercase hex (16 random bytes) from the `Signet-Nonce` header, exactly as sent. |
| 7 | Fingerprint | 64-char lowercase hex SHA-256 of the DER `SubjectPublicKeyInfo` of the requesting PRSN's signing pubkey, exactly as sent in the `Signet-Fingerprint` header. |

## Test cases

### TC03-01: GET /v1/me (no body)

**Setup:** PRSN `jane-ai` (account id `ACCOUNT_PRSN_1`) signs a `GET /v1/me` request at `TS_T0` with a known nonce.

**Inputs:**

| Element | Value |
|---|---|
| HTTP method | `GET` |
| Path | `/v1/me` |
| Body bytes | (zero bytes) |
| Body hash | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| Timestamp | `1700000000` |
| Nonce | `0102030405060708090a0b0c0d0e0f10` |
| Fingerprint | The reference key's fingerprint, `f1d59449b727165de732bf283338122b99628a615918fedc67d878fffcf47da7` (see "Layer 2 results" for the key) |

**Expected canonical-bytes string (UTF-8, no trailing newline):**

```
SIGNET-V1
GET
/v1/me
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
1700000000
0102030405060708090a0b0c0d0e0f10
f1d59449b727165de732bf283338122b99628a615918fedc67d878fffcf47da7
```

Predictable byte length for this test case: `9 + 1 + 3 + 1 + 6 + 1 + 64 + 1 + 10 + 1 + 32 + 1 + 64 = 194 bytes`.

**Expected SHA-256 of the canonical bytes (the input to ECDSA signing):** see "Layer 2 results" below.

**On the signature itself:** ECDSA P-256 signatures are non-deterministic (hardware-supplied randomness), so the *signature* is not a canonical-bytes test fixture; only the canonical-bytes-to-sign input and its SHA-256 are. Implementations verify their canonical bytes by computing the SHA-256 and comparing; signature verification is a separate operation testing ECDSA correctness.

### TC03-02: PUT /v1/files/{id} (with body)

**Setup:** PRSN `jane-ai` uploads a file with a single-PUT request body containing a wrap envelope JSON.

**Inputs:**

| Element | Value |
|---|---|
| HTTP method | `PUT` |
| Path | `/v1/files/00000000-0000-4000-8000-000000000111` |
| Body bytes | UTF-8 JSON: `{"folder_id":"00000000-0000-4000-8000-000000000222","encrypted_name":{"alg":"A256GCM","iv":"AAAAAAAAAAAAAAAA","ct":"AAA","tag":"AAAAAAAAAAAAAAAAAAAAAA"},"wrapped_deks":[],"ciphertext_b64":""}` |
| Body hash | `6a46adce15c6d3cdf17434e82c3feb8f28ab51bffc85636636c195133c157f01` (SHA-256 of the body bytes) |
| Timestamp | `1700000060` |
| Nonce | `1112131415161718191a1b1c1d1e1f20` |
| Fingerprint | The reference key's fingerprint, as TC03-01 |

**Expected canonical-bytes string structure:**

```
SIGNET-V1
PUT
/v1/files/00000000-0000-4000-8000-000000000111
6a46adce15c6d3cdf17434e82c3feb8f28ab51bffc85636636c195133c157f01
1700000060
1112131415161718191a1b1c1d1e1f20
f1d59449b727165de732bf283338122b99628a615918fedc67d878fffcf47da7
```

**Expected SHA-256 of the canonical bytes:** see "Layer 2 results" below.

### TC03-03: GET with query-string preservation

**Setup:** a PRSN polls the audit log with an explicit cursor.

**Inputs:**

| Element | Value |
|---|---|
| HTTP method | `GET` |
| Path | `/v1/me/audit?since=00000000-0000-7000-8000-000000000001&limit=50` |
| Body bytes | (zero bytes) |
| Body hash | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| Timestamp | `1700001000` |
| Nonce | `2122232425262728292a2b2c2d2e2f30` |
| Fingerprint | The reference key's fingerprint |

**Specification clarification:** the spec says "request path including query string." Implementations MUST preserve the path AS SENT in the HTTP request line. The query-string ordering is NOT canonicalized: the client signs whatever it puts in the URL, and the server verifies against the same string. If a client builds the URL with `?since=X&limit=50`, the canonical bytes contain `?since=X&limit=50`. If the client builds it with `?limit=50&since=X`, the canonical bytes contain `?limit=50&since=X`. Different bytes, different signature, but both verifiable, as long as the URL the client signed is the URL the server receives.

This is intentional: it relies on the HTTP transport preserving the URL as sent, which is universal browser and CLI behavior. Implementations MUST NOT reorder, normalize, or canonicalize query parameters before signing.

**Expected canonical-bytes string:**

```
SIGNET-V1
GET
/v1/me/audit?since=00000000-0000-7000-8000-000000000001&limit=50
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
1700001000
2122232425262728292a2b2c2d2e2f30
f1d59449b727165de732bf283338122b99628a615918fedc67d878fffcf47da7
```

**Expected SHA-256:** see "Layer 2 results" below.

### TC03-04: Negative test; wrong canonical bytes that must NOT verify

**Purpose:** make explicit the canonical answers to common "would this work?" implementer questions.

The following canonical-bytes constructions are WRONG and MUST NOT verify against TC03-01's signature:

- **Lowercase HTTP method** (`get` instead of `GET`): the method MUST be uppercase.
- **Path WITHOUT the query string** (`/v1/me/audit` instead of `/v1/me/audit?since=...&limit=50` for TC03-03): the path MUST include the full query string as sent.
- **Uppercase hex body hash** (`E3B0C442...`): the body hash MUST be lowercase.
- **Trailing newline after the fingerprint**: the canonical bytes do NOT include a trailing LF after the 7th element.
- **CRLF (`\r\n`) instead of LF (`\n`)** as the separator: the separator is a single LF (`0x0a`).
- **JSON-canonicalized body for the body hash** (applying RFC 8785 to the JSON before SHA-256): the body hash is over the bytes AS SENT in the HTTP request body, whether or not those bytes are JSON-canonical.
- **Missing version marker** (skipping element 1): element 1 is the literal `SIGNET-V1` ASCII.
- **Reordered elements** (timestamp before path, say): the order is fixed.

Each of the above represents a real implementer mistake worth catching in a unit test. Deviations fail signature verification.

## Implementer notes

- The canonical-bytes string is built **before** signing and **also before** sending the request. Both client and server reconstruct it identically: the server reconstructs from the headers plus the body it received; the client built it from the values it is about to send.
- Server-side verification: the server computes `body_hash` from the actual bytes it received, NOT from a value the client claims (there is no `Signet-Body-Hash` header). If the client's and server's body hashes differ (corruption in transit, tampering), signature verification fails.
- The `Signet-Fingerprint` header value (element 7) appears in the canonical bytes verbatim. The server uses this fingerprint to look up the PRSN's attestation; the same fingerprint goes into the canonical bytes that get hashed and signed. This binds the signature to the asserted PRSN identity.
- ECDSA P-256 signatures are non-deterministic. Two signatures over the same canonical bytes will differ; both verify against the same canonical-bytes hash. Tests should verify "the signature verifies," never "the signature equals X."
- For hybrid-attested accounts, both halves of the dual signature sign these identical canonical bytes; see [Envelope Format](../Signet-Drive-Envelope-Format.md) section 6.2 and the [PQR Crypto Specification](../Signet-Drive-PQR-Crypto-Spec.md) section 8.7.

## Reviewer's verification path

For each test case, a reviewer:

1. Constructs the canonical-bytes string per Envelope Format section 6.2 from the listed inputs.
2. Computes the SHA-256 of the canonical-bytes string (this is what ECDSA signs).
3. Compares the SHA-256 to the published expected hash below.

If the reviewer's SHA-256 matches: the spec is unambiguous and implementations agree.

If it differs: report it. Likely causes: separator confusion (CRLF vs LF), trailing-newline disagreement, hex-case disagreement, query-string handling disagreement.

## Layer 2 results

**Filled by the reference implementation.** Pinned as golden assertions in the crypto test suite; this section is the published companion so a third-party verifier can reproduce the values without running our code.

**Reference signing key** (a deterministic test scalar, NOT a real key; chosen so the fingerprint in element 7 and the round trip are reproducible):

| Field | Value |
|---|---|
| Scalar (32 bytes) | `0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20` (bytes 1..=32) |
| Public key (X9.63 uncompressed, 65 bytes) | `04515c3d6eb9e396b904d3feca7f54fdcd0cc1e997bf375dca515ad0a6c3b4035f4536be3a50f318fbf9a5475902a221502bef0d57e08c53b2cc0a56f17d9f9354` |
| Fingerprint (SHA-256 of the DER `SubjectPublicKeyInfo`) | `f1d59449b727165de732bf283338122b99628a615918fedc67d878fffcf47da7` |

This fingerprint is the value of element 7 in each test case.

**Computed results.** The canonical-bytes raw bytes and their SHA-256 are deterministic from the inputs. The SHA-256 of the canonical bytes is the message ECDSA signs (`ES256` applies SHA-256 internally), so a verifier confirms agreement by matching this hash, independent of the non-deterministic signature.

| Test case | Body SHA-256 | Canonical-bytes SHA-256 |
|---|---|---|
| TC03-01 (`GET /v1/me`) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (empty body) | `e071f84adc329a236eb377807ac060a13ad6dd0dd6c97170239773c620b968c1` |
| TC03-02 (`PUT /v1/files/…`) | `6a46adce15c6d3cdf17434e82c3feb8f28ab51bffc85636636c195133c157f01` | `8f35b76a0673dc1a07af95b6a055143e67fb10efe640975f2a4f7fe364c14767` |
| TC03-03 (`GET …?since=…&limit=50`) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (empty body) | `6c5f18e7e786ea8bcc298d322b7d40de02c876d1022fac9770fb76c1467cf94f` |

The example ECDSA signature is non-deterministic and therefore not a fixture; the test suite signs TC03-01's canonical bytes with the reference key and asserts the matching public key verifies it (and that a tampered request does not).
