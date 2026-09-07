# Test Vector Category 04: Empty-body hash

**Layer:** 1 (fully filled; deterministic external standard)
**Spec source:** [Envelope Format](../Signet-Drive-Envelope-Format.md) section 6.2 (canonical-bytes-to-sign, element 3)
**External standard:** NIST FIPS 180-4 (SHA-256)

---

## Why this vector exists

Per the SIGNET-V1 canonical-bytes-to-sign format, the third element is "lowercase hex SHA-256 of request body bytes." There is no empty-body special case: every implementation uniformly hashes the body bytes regardless of length, and an empty body hashes to a specific universally known constant.

This vector is the smallest possible smoke test for the SHA-256 and canonical-bytes pipeline. If an implementation ever returns anything else for an empty body, it has a bug somewhere. The most common causes: a hash-of-empty-string special case still in the code path, or treating an empty body as null or missing instead of zero-length bytes.

## Input

Empty byte sequence:

```
input = b""    (zero bytes; the SHA-256 of an empty input message)
```

## Expected output

SHA-256 hash of the empty input, lowercase hex (64 chars, 32 bytes raw):

```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

Raw bytes (32 bytes):

```
e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24
27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55
```

## Cross-check sources

This is the well-known SHA-256-of-empty-string value. Any of:

- NIST CAVP SHA-256 test vectors (`Msg = ""`, `MD = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`)
- `printf '' | sha256sum` on any standard Linux/Unix system
- `printf '' | shasum -a 256 | awk '{print $1}'` on macOS
- Python: `hashlib.sha256(b"").hexdigest()`
- OpenSSL: `echo -n "" | openssl dgst -sha256`
- Rust: `sha2::Sha256::digest(b"")` produces these 32 bytes
- WebCrypto: `crypto.subtle.digest("SHA-256", new Uint8Array(0))` produces the same 32 bytes

## Test cases

### TC04-01: SIGNET-V1 canonical bytes for a GET request (no body)

**Setup:** a PRSN sends a GET request with no body. The canonical-bytes-to-sign include the body hash as element 3. The body is empty bytes; per this vector, body_hash = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

This single value appears in every signed GET request and every signed DELETE request without a body. The full canonical-bytes-to-sign computation is covered in [Test Vector Category 03](03-signet-v1-canonical-bytes.md); this category isolates the empty-body sub-step for unambiguous reference.

### TC04-02: SHA-256 of empty bytes is NOT empty, NOT null, NOT zero, NOT missing

**Negative-case clarifier:** the hash of empty input is the specific 32-byte value above. Implementations that:

- return `null` / `None` / `undefined` for hash-of-empty
- return zero bytes (`0000...0000`)
- return an empty string (`""`)
- return the hash of the string `"null"` or `"undefined"`
- skip the body-hash step entirely when the body is empty

are all wrong. Each of these has been a real bug class in practice; the explicit canonical answer above eliminates them.

## Implementer notes

- The hex output must be **lowercase**. The SIGNET-V1 canonical-bytes-to-sign format requires lowercase hex ([Envelope Format](../Signet-Drive-Envelope-Format.md) section 6.2). Uppercase hex (`E3B0C442...`) is a different byte sequence and will fail signature verification.
- The body hash is computed over **request body bytes**: not the URL, not the headers, not the canonical-bytes string itself. For an empty body, that is zero bytes of input to SHA-256.
- The HTTP body of a `GET` has zero bytes regardless of `Content-Length` header presence. Treat as empty.
- The HTTP body of a `DELETE` is typically zero bytes (the batch file-delete endpoint is the exception; it carries a JSON body listing ids). For the typical `DELETE` without a body: empty.

## Reviewer's verification path

Any SHA-256 implementation given empty input must return the listed 32 bytes. If a reviewer's implementation returns anything else, the implementation is wrong, not the vector.

This is the simplest of the vector categories and serves as a confidence check on the reviewer's tooling. A reviewer who cannot reproduce this output should debug their toolchain before attempting Categories 03, 05, 06, or 07.

## Layer 2 status

**Fully populated.** No Layer 2 work required: the algorithm (SHA-256) and input (empty bytes) are both fixed by external standard.
