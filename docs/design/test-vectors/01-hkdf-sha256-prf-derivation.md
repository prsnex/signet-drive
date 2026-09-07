# Test Vector Category 01: HKDF-SHA-256 PRF derivation chain

**Layer:** 1 + 2 (spec + concrete inputs; the PRF salt and the HKDF wrap-key W both filled, deterministic, from a designated reference PRF output)
**Spec source:** [Envelope Format](../Signet-Drive-Envelope-Format.md) section 8 (the human-side wrap chain; section 8.2 is the derivation)
**External standards:** RFC 5869 (HKDF), NIST FIPS 180-4 (SHA-256), W3C WebAuthn L3 (PRF extension)

---

## Why this vector exists

The human-side wrap key W (which encrypts the user's KEM private material for server-side storage as `wrapped_kem_privkey_blob`) is deterministically derived from a WebAuthn PRF assertion via HKDF-SHA-256. The PRF salt is fixed to a specific constant value, and the HKDF parameters are fixed by the spec. If any implementation uses a different salt, different HKDF parameters, or a different `info` string, sign-in fails to produce a wrap key that decrypts the existing `wrapped_kem_privkey_blob`.

This vector pins the deterministic portion of the chain (the PRF salt plus the HKDF info string) so any implementation can verify it produces the right inputs to PRF and HKDF before attempting end-to-end derivation.

## Chain (per Envelope Format section 8.2)

```
PRF salt        = SHA-256("signet-drive-kem-wrap-v1")           (FIXED)
PRF output      = WebAuthn assertion with `prf.eval.first = base64url(PRF salt)`
                  (32 bytes; credential-specific; deterministic per credential per salt)
W (wrap key)    = HKDF-SHA-256(
                    IKM     = PRF output,
                    salt    = empty (zero-length bytes),
                    info    = ASCII bytes of "signet-drive-kem-wrap-v1" (24 bytes),
                    length  = 32 bytes (AES-256-GCM key length)
                  )
```

The wrap key W is then used as the AES-256-GCM key in the wrap envelope per Envelope Format section 8.3 (see [Test Vector Category 02](02-aes-256-gcm-roundtrips.md) for the AES-GCM step and [Test Vector Category 04](04-empty-body-hash.md) for the SHA-256 baseline).

## Test cases

### TC01-01: PRF salt computation (Layer 1, fully filled)

**Input:** ASCII string `"signet-drive-kem-wrap-v1"` (24 bytes; UTF-8 = ASCII for this string).

**Raw bytes:**

```
73 69 67 6e 65 74 2d 64 72 69 76 65 2d 6b 65 6d 2d 77 72 61 70 2d 76 31
```

**Operation:** SHA-256 (NIST FIPS 180-4) over those 24 bytes.

**Expected output (32 bytes, lowercase hex):**

```
e93d48bd9013c08e0bac7555f09312a3dd27c8e8a6d557fb325929d9a5cdf637
```

**This value is what gets passed as `prf.eval.first` in the WebAuthn assertion request** (after base64url-no-pad encoding of the 32 bytes):

```
prf.eval.first (base64url-no-pad encoded) = 6T1IvZATwI4LrHVV8JMSo90nyOim1Vf7Mlkp2aXN9jc
```

(Verifiable: `base64url-no-pad(decode_hex("e93d48bd9013c08e0bac7555f09312a3dd27c8e8a6d557fb325929d9a5cdf637"))` = `6T1IvZATwI4LrHVV8JMSo90nyOim1Vf7Mlkp2aXN9jc`.)

**Cross-check:** any of `printf '%s' 'signet-drive-kem-wrap-v1' | openssl dgst -sha256` / `printf '%s' 'signet-drive-kem-wrap-v1' | shasum -a 256` / Python `hashlib.sha256(b'signet-drive-kem-wrap-v1').hexdigest()` / Rust `sha2::Sha256::digest(b"signet-drive-kem-wrap-v1")` / WebCrypto `crypto.subtle.digest("SHA-256", new TextEncoder().encode("signet-drive-kem-wrap-v1"))` all produce the listed 32 bytes.

### TC01-02: HKDF-SHA-256 wrap key derivation (Layer 1 spec; Layer 2 filled)

**Setup:** a registered credential (for example, the user's iCloud Keychain passkey) has been used in a sign-in WebAuthn assertion with `prf.eval.first` set to the PRF salt from TC01-01. The assertion's `clientExtensionResults.prf.results.first` returned a 32-byte PRF output.

**Inputs to HKDF-SHA-256:**

| Parameter | Value |
|---|---|
| `IKM` (input keying material) | The 32-byte PRF output from the WebAuthn assertion. **Layer 2 (filled):** pinned with a *designated synthetic* reference PRF output `0x00..0x1f`. The chain being validated is PRF output to HKDF to W to wrap, and the PRF output is its opaque input, so a fixed synthetic value suffices and is fully reproducible. A real authenticator's per-credential output is exercised only in manual real-authenticator testing. |
| `salt` | Empty bytes (zero-length byte string). |
| `info` | ASCII bytes of `"signet-drive-kem-wrap-v1"`, 24 bytes; same encoding as the TC01-01 input above. |
| `length` (output) | 32 bytes (AES-256-GCM key length). |

**Why empty salt plus this specific info:** the PRF output is already a strong, high-entropy key, so an empty HKDF salt is appropriate (RFC 5869 section 3.1). The HKDF pass exists for **domain separation** (this is the wrap key for THIS specific use, not some other key derived from the same PRF output) and for **forward-compatible versioning** (the `-v1` suffix in the info string allows a future migration to `-v2` without breaking v1 clients).

**Expected output structure:** 32 raw bytes (the wrap key W). Used directly as the AES-256-GCM key (per Test Vector Category 02 and Envelope Format section 8.3).

**Expected output bytes (Layer 2, filled; designated reference PRF output `0x00..0x1f`):**

```
IKM (PRF output) = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
W (wrap key)     = fac1e06abf3cb605d2d95cd59b52ecfcf6858da0240490b1b46c0a4b47106e74
```

Generated by Node WebCrypto (`gen/kem_wrap_gen.mjs`, output `golden/kem-wrap.json`), the exact `crypto.subtle` HKDF the browser runs, and verified byte-for-byte against the RustCrypto implementation by the crypto test suite (so RustCrypto HKDF equals WebCrypto HKDF for these section 8.2 parameters). The same golden also pins the section 8.3 AES-256-GCM wrap of a PKCS#8 ECDH P-256 key (`ct`/`tag`), exercised by the sibling tests.

### TC01-03: Same PRF input gives the same wrap key (deterministic property)

**Specification:** per the WebAuthn L3 PRF spec, for a fixed credential and a fixed salt, the PRF output is deterministic. Therefore, for a fixed credential, the wrap key W is also deterministic (same PRF output, same HKDF input, same W).

**Why this matters:** sign-in MUST produce the same W as sign-up; otherwise the existing `wrapped_kem_privkey_blob` does not decrypt. Passkey rotation (credential A to credential B) MUST produce a DIFFERENT W (different credential, different PRF output, different W); the rotation flow re-encrypts the private material under the new W.

**Test cases (structural; Layer 2 fixtures):**

- Sign-in #1 with credential A gives W_A1
- Sign-in #2 with credential A gives W_A2
- Assert: `W_A1 == W_A2`
- Sign-in #1 with credential B gives W_B1
- Assert: `W_A1 != W_B1`

The deterministic property is enforced by WebAuthn PRF (a credential is intended to be a deterministic PRF). TC01-03 is a spec clarifier rather than a byte fixture.

## Implementer notes

- **The PRF salt is itself a hash, not a string.** Do NOT pass `"signet-drive-kem-wrap-v1"` directly as the PRF salt; pass `SHA-256("signet-drive-kem-wrap-v1")` (the byte sequence in TC01-01). Skipping the SHA-256 step is a common bug in early WebAuthn-PRF implementations; the spec forbids it.
- **`prf.eval.first` is base64url-no-pad encoded** when sent in the WebAuthn extension input (per the WebAuthn L3 spec). The 32 raw salt bytes become 43 base64url-no-pad characters.
- **The HKDF salt is empty, NOT the PRF salt.** The PRF salt is the input to PRF (a WebAuthn-layer parameter); the HKDF salt is the input to HKDF (an HKDF-layer parameter, RFC 5869). They are conceptually different. Pass empty bytes (zero-length) as the HKDF `salt` parameter.
- **HKDF `info` is the UTF-8 bytes of the ASCII string `"signet-drive-kem-wrap-v1"`**, NOT the SHA-256 hash of that string. This differs from the PRF salt computation: both inputs use the same source string but at different layers (PRF salt = SHA-256 of the string; HKDF info = UTF-8 bytes of the string). This is intentional; see Envelope Format section 8.2.
- **Output length is exactly 32 bytes.** Do not request more; HKDF can produce up to 8160 bytes (255 times the hash length) but exactly 32 are wanted for AES-256-GCM. Anything longer or shorter is wrong.

## Reviewer's verification path

For TC01-01: the SHA-256 of the ASCII string `"signet-drive-kem-wrap-v1"` is fixed by NIST FIPS 180-4. Any implementation must produce `e93d48bd9013c08e0bac7555f09312a3dd27c8e8a6d557fb325929d9a5cdf637`.

For TC01-02: run the PRF output `0x00..0x1f` through any HKDF-SHA-256 with empty salt, info = ASCII `"signet-drive-kem-wrap-v1"`, length 32, and confirm `fac1e06abf3cb605d2d95cd59b52ecfcf6858da0240490b1b46c0a4b47106e74`; or re-run `gen/kem_wrap_gen.mjs`. The structural chain (PRF salt, PRF output, HKDF, W) is Envelope Format sections 8.2 and 8.4 through 8.5.

For TC01-03: the deterministic property is a guarantee from the WebAuthn L3 spec, not a Signet Drive construction; any compliant authenticator delivers it.

## Layer 2 status

**TC01-01 fully filled** (deterministic SHA-256). **TC01-02 filled:** the HKDF wrap-key W is pinned from a designated synthetic reference PRF output (`0x00..0x1f`) via Node WebCrypto, verified against the RustCrypto implementation; the section 8.3 AES-256-GCM wrap envelope is pinned in the same golden (`golden/kem-wrap.json`). TC01-03 is a structural property check (the deterministic-PRF guarantee is from the WebAuthn L3 spec), no byte fixture needed; real-credential PRF capture happens in manual real-authenticator testing.
