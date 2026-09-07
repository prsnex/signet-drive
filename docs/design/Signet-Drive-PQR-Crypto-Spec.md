# Signet Drive v1 Post-Quantum (Hybrid) Cryptographic Specification

## Status

This is the public edition of the specification of record for Signet Drive's v1 hybrid post-quantum cryptography. The specification was drafted twice, independently, by two authors, then merged and co-signed; the KeyCombine known-answer vectors were generated independently by both authors from the merged text and byte-compared (match confirmed: PRK, KEK, and wrapped key identical on both vectors). It extends the [Signet Drive Envelope Format](Signet-Drive-Envelope-Format.md), which remains the bytes-on-the-wire authority.

Grounded in: NIST SP 800-227 (final), section 4.6 (the KDM combiner, normative); SP 800-56C Rev 2; FIPS 203 and FIPS 204; RFC 7518, RFC 3394, RFC 5869; SP 800-56A; empirical Secure Enclave and WASM probes; and in-process benchmarks (section 12).

## 1. Scope and constraints

Signet Drive v1 ships hybrid post-quantum resistance: every long-lived confidentiality artifact and every identity or signature artifact is protected by a classical-plus-post-quantum construction that is secure if either component holds. This specification defines the constructions, the envelope bytes, the custody model, the downgrade defenses, and the validation requirements.

**Constraints (load-bearing):**

- **C1: off-the-shelf primitives and constructions.** No novel cryptography. Every construction here is a NIST-approved primitive combined via a NIST-approved key-derivation method (SP 800-227, section 4.6). No hand-rolled combiners.
- **C2: both surfaces or neither.** Identical capability for humans (WebCrypto plus WASM) and PRSNs (Secure Enclave via a CryptoKit shim). Parity is the product.
- **C3: additive, no envelope-format break.** New composite algorithm identifiers; classical envelopes stay readable via the existing algorithm dispatch (crypto-agility, Envelope Format sections 3 and 12).
- **C4: Secure Enclave custody preserved.** PRSN keys, both hybrid halves, are Secure-Enclave-bound, non-extractable, the only tier. They are reached via a CryptoKit C-ABI shim; no `SecKey` PQC path exists.
- **C5: monotonicity is the design goal.** The hybrid MUST guarantee security at least that of the stronger component, in every era. This covers not only a classical break or an ML-KEM cryptanalytic break but the implementation immaturity of young ML-KEM and ML-DSA code (KAT-tested, not yet audited): a flaw degrades to exactly today's P-256 posture, never below. This is why the design self-assembles a hybrid rather than adopting a pure-PQ endpoint now (section 12).

**Parameter choice.** The content-wrap hybrid instantiates P-256 plus ML-KEM-1024 (Category 5), not the IETF-named MLKEM768-P256 (Category 3), preserving the Category 5 margin and coherence with the reserved pure `ML-KEM-1024+A256KW` endpoint, at the cost of self-assembling a NIST-sanctioned form rather than citing an IETF codepoint. Signet Drive owns both ends of the wire, so there is no interop-by-codepoint need. MLKEM1024-P384 is disqualified: the Secure Enclave has no P-384. The construction is FIPS-approved primitives end to end (P-256 per SP 800-56A; ML-KEM as an approved KEM; HKDF and AES-KW approved). That is a statement about approved primitives and construction, not a FIPS 140 validation certificate.

**Platform floor (a C2 condition):** PRSN hosts require macOS 26 at v1 launch, the Secure Enclave PQC availability floor. Humans are unaffected.

**v1 is 100 percent PQR-complete.** There is no PQR capability deferred for convenience. Every confidentiality surface (content wrap, human and PRSN key custody, transport) and every identity or signature surface (attestation, per-request, server response) is hybrid-PQ in v1. The only items outside v1 are those it would be wrong to include now, or that the external ecosystem has not enabled, enumerated with reasons in section 12.

## 2. Components and parameters

| Component | Parameter | Standard | Role |
|---|---|---|---|
| ECDH, ephemeral-static | P-256 | SP 800-56A | classical KEM half (56A-approved, anchoring the combiner's approval per SP 800-227 section 4.6.2) |
| ML-KEM | ML-KEM-1024 | FIPS 203 | PQ KEM half (Category 5; ek 1568 B, ct 1568 B, ss 32 B, seed (d,z) 64 B) |
| KDM | two-step HKDF-SHA-256 | SP 800-56C Rev 2 / RFC 5869 | key combiner (section 4.2) |
| Key wrap | AES-256-KW | RFC 3394 | DEK and metadata-key wrap under the combined KEK |
| Signature (classical) | ECDSA P-256 / SHA-256 (`ES256`) | RFC 7518 section 3.4 | identity dual-sign half |
| Signature (PQ) | ML-DSA-87, hedged | FIPS 204 | identity dual-sign half (vk 2592 B, sig 4627 B) |

Composition rationale: Category 5 coherence with the reserved pure endpoint; both halves Secure-Enclave-residable; the whole construction within NIST-approved-primitive territory. X25519 and X-Wing structurally cannot give the last two properties.

## 3. Algorithm-identifier registry (additions to Envelope Format section 3)

| Identifier | Use | Spec | Phase |
|---|---|---|---|
| `ECDH-ES+ML-KEM-1024+A256KW` | Hybrid content wrap: P-256 ECDH plus ML-KEM-1024, SP 800-227 KDM, AES-256 Key Wrap | SP 800-56A + FIPS 203 + SP 800-227 section 4.6 + RFC 3394 | v1 (new) |
| `ML-DSA-87` | PQ signature (hedged), paired with `ES256` as a hybrid dual-signature | FIPS 204 | v1 (new, identity) |
| `ML-KEM-1024+A256KW` | Pure-PQ content wrap (no classical half) | FIPS 203 + RFC 3394 | Reserved (post-hybrid endpoint; matches `draft-ietf-jose-pqc-kem` naming) |

**Domain separation by construction.** The composite algorithm identifier `ECDH-ES+ML-KEM-1024+A256KW` MUST uniquely fix, as one unit: the two components and parameters (section 2), the composition order (`Z_ecdh` first), the KDM (two-step HKDF-SHA-256), the FixedInfo layout (section 4.3), and the KEK length. The identifier string itself is therefore the `domain_sep` bound into the KDM (SP 800-227, section 4.6.3), satisfied by construction.

**Dispatch rule (registry):** unknown `alg` means reject the envelope. Known-but-disabled `alg` means reject: the reserved pure endpoint MUST NOT be accepted in a v1 envelope until explicitly activated. Per-algorithm required-field validation per section 5.2.

**Naming versus IETF registries:** the identifier is Signet Drive's own; since Signet Drive owns both ends of the wire there is no interop-by-codepoint need. Alignment with the IETF drafts is revisited when they settle. Naming only; the construction is unaffected.

## 4. The hybrid content-wrap construction (the core)

Wraps a 32-byte key, either a file DEK (Envelope Format, section 5) or a per-folder metadata key (Envelope Format, section 7.2), to a recipient's hybrid KEM public keys: `rk_ec` (P-256, X9.63, 65 B) plus `rk_pq` (ML-KEM-1024 encapsulation key, 1568 B).

### 4.1 The two KEM operations

1. **Classical:** fresh ephemeral P-256 `(epk_priv, epk_pub)`; `Z_ecdh = ECDH(epk_priv, rk_ec)`, the 32-byte x-coordinate.
2. **Post-quantum:** `(ek, Z_mlkem) = ML-KEM-1024.Encaps(rk_pq)`; `Z_mlkem` is 32 bytes, `ek` (the ciphertext) is 1568 bytes.

### 4.2 KeyCombine: the SP 800-227 section 4.6.2 KDM (normative)

Two-step (Extract-then-Expand) HKDF-SHA-256, per SP 800-56C Rev 2:

```
Z_ecdh   = 32-byte ECDH x-coordinate          // S1: the SP 800-56A secret, FIRST (normative order)
Z_mlkem  = 32-byte ML-KEM-1024 shared secret  // S2
IKM      = Z_ecdh || Z_mlkem                   // both fixed 32 B, no length ambiguity
PRK      = HKDF-Extract(salt = zero-length, IKM)   // per RFC 5869 section 2.2 this equals HashLen (32) zero bytes
KEK (32) = HKDF-Expand(PRK, info = FixedInfo, L = 32)
```

- **MUST:** `Z_ecdh` is the first IKM component (S1 is the 56A-generated secret, per 56C Rev 2's `Z=(S1,S2)` form and section 4.6.2's approval condition). Byte order is KAT-pinned (section 11).
- **MUST:** both shared secrets enter HKDF-Extract as IKM. Neither appears in `salt` or `FixedInfo` (SP 800-227, section 4.6.2: extraction is performed over all shared secrets).
- **Salt wording (canonical):** `salt = zero-length`; per RFC 5869 section 2.2 this equals 32 zero bytes.

**Why two-step rather than one-step Concat-KDF.** One-step is equally sanctioned by section 4.6.2, so two-step is an operational choice, and the right one: HKDF is native in WebCrypto (`SubtleCrypto.deriveBits`) whereas Concat-KDF is library JavaScript on the human surface. Two-step gives native cryptography on both surfaces plus the extraction-hygiene property (all secrets pass through Extract). Both independent drafts chose it.

**Implementation note (construction unchanged).** Node's WebCrypto caps the native HKDF path's `info` at 1024 bytes (RFC 5869 imposes no limit) while this FixedInfo is 3324 or 3340 bytes, so the web `hkdfSha256` composes RFC 5869 Extract-then-Expand over native WebCrypto HMAC instead. This is byte-identical by definition (HKDF is specified over HMAC; it is the same composition the Rust `hkdf` crate runs), has no length ceiling on any engine, and is pinned by the RFC 5869 Appendix A vectors plus the section 11.5 KeyCombine KAT. The two-step choice itself is unaffected: HMAC-composed HKDF still runs entirely on native primitives, which one-step Concat-KDF would not.

### 4.3 FixedInfo (normative encoding)

`FixedInfo` (the `info` input to Expand) is the concatenation, in this exact order, of length-prefixed fields (`u32` big-endian length, then the bytes). Length-prefixing follows SP 800-227 section 4.6.2's pair-encoding caution (the `x||y = x'||y'` ambiguity):

1. `alg`: ASCII `ECDH-ES+ML-KEM-1024+A256KW` (the section 3 `domain_sep`)
2. `epk`: the sender's ephemeral P-256 public key, X9.63 uncompressed (65 B)
3. `ek`: the ML-KEM-1024 ciphertext (1568 B)
4. `rk_ec`: the recipient's static P-256 KEM public key, X9.63 (65 B)
5. `rk_pq`: the recipient's ML-KEM-1024 encapsulation key (1568 B)
6. `L`: the KEK bit length (256) as `u32` big-endian (keydatalen)
7. `party_v`: the folder-binding context. Empty (0-length) for a file-DEK wrap; the 16-byte `root_folder_id` for a metadata-key wrap (mirroring the classical construction's folder binding, Envelope Format section 7.2). Defined here as an explicit KAT-pinned field.

**No `enc` field.** The content-encryption identifier (`A256GCM`) is deliberately not bound in the KDF: the classical `ECDH-ES+A256KW` Concat-KDF binds wrap-alg and keydatalen only, the content cipher is already bound at the content layer (the `file_id` AAD), there is a single content cipher in v1, and JOSE key-wrap mode binds the wrap algorithm (already in `alg`), not `enc`. Binding `enc` would defend a cross-cipher-confusion scenario that cannot occur in v1 and would diverge from the proven construction.

**Recipient-key binding (a named property).** Items 4 and 5 bind the wrap to the intended recipient's public keys, both of them. This is what defeats cross-recipient block-swapping (negative test N4, section 9).

### 4.4 Why the ciphertext MUST be bound: IND-CCA necessity (SP 800-227, section 4.6.3)

Binding `ek` (and `epk`, the classical "ciphertext") into `FixedInfo` is not downgrade hygiene alone. It is the property that makes the composite generically IND-CCA when at least one component is IND-CCA. SP 800-227 section 4.6.3 (normative): a secrets-only combiner `KDF(K1,K2)` "does not preserve IND-CCA security, regardless of the properties of the KDF." Therefore `ek` in `FixedInfo` is a MUST, with this citation. This also closes the envelope-layer downgrade vector (section 9.1).

### 4.5 Wrap and unwrap flows

- **Wrap (any writer):** ephemeral P-256 gives `Z_ecdh` against `rk_ec`; `(ek, Z_mlkem)` from `ML-KEM.Encaps(rk_pq)`; KeyCombine gives the KEK; `wk = AES-KW(KEK, key)` (40 B for a 32-byte key, RFC 3394); emit the recipient block (section 5.2).
- **Unwrap (recipient):** `Z_ecdh` from `ECDH(sk_ec, epk)`; `Z_mlkem` from `ML-KEM.Decaps(sk_pq, ek)`; KeyCombine gives the KEK; `key = AES-KW-inverse(KEK, wk)`. AES-KW integrity failure is the sole tamper signal (section 10).

### 4.6 Zeroization

`Z_ecdh`, `Z_mlkem`, `PRK`, and `KEK` MUST all be zeroized promptly after the wrap or unwrap. The suite zeroization clause extends to all combiner intermediates: Rust `Zeroizing` on each; web best-effort per the existing posture.

## 5. Envelope integration (extends Envelope Format section 5)

### 5.1 Compatibility invariants

Additive only: classical `ECDH-ES+A256KW` envelopes remain readable forever; the server continues to store `wrapped_dek` and `wrapped_metadata_keys` as opaque JSONB (zero server parse, zero envelope-layer schema change); the same algorithm-dispatch table serves both.

### 5.2 The hybrid recipient block

```json
{
  "v": 1,
  "alg": "ECDH-ES+ML-KEM-1024+A256KW",
  "epk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." },
  "ek":  "<base64url of the 1568-byte ML-KEM ciphertext>",
  "wk":  "<base64url of the 40-byte AES-KW output>",
  "rfp": "<recipient hybrid KEM pair-fingerprint, lowercase hex>"
}
```

Field naming is disambiguated: `epk` (classical ephemeral public key); `ek` (ML-KEM ciphertext, the `draft-ietf-jose-pqc-kem` convention); `wk` (the wrapped key, not a bare `ct`, which would collide with a KEM ciphertext); `rfp` (the section 8.5 pair-commitment). The hybrid carries both `epk` and `ek`, unlike the reserved pure `ML-KEM-1024+A256KW`, which replaces `epk` with `ek`.

**Per-algorithm required-field validation (MUST, symmetric):**

- `alg = ECDH-ES+ML-KEM-1024+A256KW` requires `epk` present and `ek` present, each length-exact; missing or malformed either way means reject.
- `alg = ECDH-ES+A256KW` (classical) requires `ek` absent; present means reject. Strictness runs in both directions: no field-smuggling across algorithms.
- Unwrap implementations MUST select the code path from `alg` alone and MUST NOT infer from field presence. This is the code-level defense that makes section 9.1 real.

### 5.3 The two-shared-secret unwrap

The classical unwrap takes one shared secret. The hybrid adds a variant taking both `Z_ecdh` and `Z_mlkem`, each produced by a distinct keystore operation (section 6); it runs the section 4.2 KDM in the agent and AES-KW-unwraps. Classical and hybrid unwrap paths coexist behind the algorithm dispatch.

## 6. Key custody: PRSN surface

- Both private halves are Secure-Enclave-resident, non-extractable, mandatory (the custody invariant, C4): the existing `SecureEnclave.P256.KeyAgreement` key plus a new `SecureEnclave.MLKEM1024` key (macOS 26; CryptoKit-only, no `SecKey` path; reached via the Swift/CryptoKit C-ABI shim). The ML-DSA-87 identity key is likewise `SecureEnclave.MLDSA87`. Persistence uses Secure Enclave `dataRepresentation` sealed blobs, the same pattern as the existing Secure Enclave P-256 keys; blob round-trip and decapsulation were verified empirically.
- **Keystore contract: two new generic operations** slot behind the existing keystore dispatch (verified additive): `ml_kem_decapsulate(key_ref, ek)` returning `Z_mlkem`, and `ml_dsa_sign(key_ref, msg, ctx)` returning a signature. The wire protocol and host dispatch extend by variant; broker and mount backends inherit them; non-Secure-Enclave backends return `unsupported_algorithm`.
- **The combiner runs in the agent, not the Secure Enclave, and this preserves zero-access under server compromise:** the classical path already exports `Z_ecdh` from the Enclave into agent memory and runs the KDF and unwrap in software (the Enclave does raw ECDH only). The hybrid transits two per-operation secrets across the same boundary instead of one: no new exposure class, only count. Long-term private keys never leave the Enclave; a server compromise sees nothing it did not see before. There is also no alternative: no Secure Enclave hybrid-KEM type exists. Zeroization per section 4.6.

## 7. Key custody: human surface

- **Classical half:** the existing P-256 WebCrypto path, unchanged (extractable-once, PRF-wrap, discard; session re-import non-extractable). The classical web modules are `ecdh.ts` and `kem_wrap.ts`; the hybrid additions are `mlkem.ts`, `hybrid_wrap.ts`, and `keyblob.ts`.
- **PQ half:** ML-KEM-1024 in WASM compiled from Rust, using the same `ml-kem` crate as the CLI. One implementation, two compile targets, so cross-surface goldens come free; roughly 20 KB gzipped.
- **Seed storage (PRF-blob layout v2):** the stored secret is the 64-byte (d,z) seed, not the roughly 3 KB decapsulation key. Layout: `version = 0x02 (1B)`, then length-prefixed `p256_pkcs8`, then length-prefixed `mlkem_seed` (64 B), a single AES-GCM plaintext under the PRF-derived wrap key (the single-blob, single-wrap pattern preserved, roughly 70 B larger). The version byte is pinned to `0x02`; no legacy blobs exist in production because launch-day PQR means every account enrolls hybrid. The decapsulation key regenerates from the seed at sign-in (FIPS 203 KeyGen determinism); the session decapsulation key lives in WASM memory. Honest note: WebCrypto non-extractability does not extend to WASM-held keys, but the DEK already transits JavaScript memory, so this is not a new exposure class.
- **Keygen:** the seed comes from a CSPRNG; the encapsulation key (1568 B) is published to the directory at enrollment alongside the P-256 public key.
- **CSP:** `script-src` gains `'wasm-unsafe-eval'`, a named, narrow relaxation (WASM-compile only, narrower than `unsafe-eval`); the WASM asset hash is committed into the bundle manifest, so the asset is deterministic and verifiable via the reproducible-build path.

## 8. Identity dual-signature (`ES256` plus `ML-DSA-87`)

All PRSN and Guardian identity signatures become a hybrid dual-signature, both keys Secure-Enclave-resident (Apple's own documented hybrid pattern). All three signature surfaces are hybrid in v1.

1. **Format:** `sig = sig_es256(64 B, raw r||s) || sig_mldsa87(4627 B)`, a fixed-width split needing no framing. As built, the request-path wire dispatch is by length: 64 or up-to-72 bytes selects the classical forms, exactly 4691 selects dual. Inside a dual signature the ES256 half is always raw `r||s` (DER stays a classical-only wire form), which is what keeps the fixed-width split framing-free and the total length unambiguous. In-between lengths are negative-tested.
2. **Verification, AND-semantics (MUST):** both halves verify or the signature is invalid. This is monotone against either scheme breaking.
3. **ML-DSA mode:** hedged (randomized) signing only, the Secure Enclave default per FIPS 204. Deterministic mode MUST NOT be used.
4. **Domain separation, FIPS 204 context strings (MUST), per purpose:**
   - `signet:attest:v1`: PRSN identity and enrollment proof of possession (the PRSN signs the enrollment challenge with both signing keys, proving possession before the Guardian attests the four keys).
   - `signet:req:v1`: per-request PRSN dual-sign, active in v1. Extends the Envelope Format per-request signature (section 6.2) to carry the ML-DSA-87 half alongside `ES256`.
   - `signet:file:v1`: RESERVED. v1 has no file-level signature surface (file integrity is AES-GCM AEAD); reserved so a later file-signature purpose is additive, never reused.
   - Server-response dual-sign, active in v1: the server co-signs verification responses and log receipts with an `ML-DSA-87` key alongside `ES256`. The FIPS 204 context is the existing Envelope Format domain-separation prefix for each surface (`signet-server-attestation-verify-v1` for responses, `signet-pubkey-log-receipt-v1` for receipts): reuse, not new invention.
   - Contexts are per-purpose and MUST NOT be reused across purposes.
5. **Attestation binds all four public keys** (classical signing and KEM, plus ML-DSA-87 and ML-KEM-1024), each with a fingerprint. Every v1 account is hybrid-attested from enrollment; no classical-only attested population exists.

### 8.5 Hybrid fingerprint (`rfp`): a composite pair-commitment

`rfp = SHA-256( len_prefix(rk_ec) || len_prefix(rk_pq) )`: one fingerprint committing to both recipient KEM public keys. The payoff: a PQ-stripped directory response does not merely violate client policy (section 9.2), it changes the fingerprint, strengthening transparency-layer detectability (section 9.3) for free. Attestation, the envelope `rfp`, and the transparency-log entry all carry the same pair-commitment. Component fingerprints are SHA-256 over the exact section 4.3 field encodings: X9.63 for EC; FIPS 203 encapsulation-key bytes; FIPS 204 verification-key bytes.

### 8.6 Signature-path downgrade rules (the mirror of sections 5.2 and 9.2; MUST)

The wrap path refuses downgrades (section 5.2 symmetric field validation; section 9.2 client refuse-to-downgrade). With all three signature surfaces hybrid in v1, the signature path needs the same rules; otherwise a future ES256-forger omits the ML-DSA half and the PQ signature is decorative (SP 800-227 section 4.6.3's protocol-downgrade warning, applied to the signature path).

- **Request layer, server MUST:** for an account whose attestation includes ML-DSA-87 keys, the server MUST require the dual signature on every signed request; an ES256-only request from such an account MUST be rejected. Launch-day premise: every v1 account is hybrid-attested, so the rule reduces to "dual signature always required", with no mixed-population conditional. Negative test N8.
- **Response layer, client MUST:** once the server's ML-DSA-87 verification key is pinned, a client MUST reject an ES256-only server verification response or log receipt. Negative test N9.
- **Server PQ verification-key distribution (the prerequisite for the response rule):** the server's ML-DSA-87 verification key is published and pinned by the same channel as the ES256 server key (`/v1/server-info`), both keys pinned together; the server key pair appears in the transparency log like any other published key, so a substituted server PQ verification key is watcher-detectable.

### 8.7 The exact signing base per half (MUST)

To prevent implementer divergence on which bytes each half signs: both halves sign the identical message bytes `M`, the canonical bytes defined by the relevant Envelope Format surface (section 6.2 for requests; sections 9 and 10a for responses and receipts), including that surface's existing domain-separation prefix. The `ES256` half is `ECDSA(sk_es, M)`, unchanged and additive. The `ML-DSA-87` half is `ML-DSA.Sign(sk_mldsa, M, ctx)`, where `ctx` is the FIPS 204 context string for the purpose (section 8, point 4), supplied as the FIPS 204 context parameter, NOT prepended to `M`. Pinned by the dual-signature signing-base KAT (section 11.5b).

### 8.8 Server dual-sign key custody

The server's ML-DSA-87 signing key follows the same at-rest pattern as its classical key (AES-256-GCM at rest under the deployment key; no HSM, per the standing decision). The 32-byte FIPS 204 seed is stored at rest, not the roughly 4.9 KB expanded key; the key regenerates on load. Named residual (correlated at-rest custody): both server signature halves rest under the same deployment key. Accepted: the hybrid hedges algorithm breaks, not host compromise; host compromise was already full compromise in the classical posture. Recorded, not silently closed.

## 9. Downgrade resistance (three layers, all negative-tested)

### 9.1 Envelope layer: the algorithm identifier is bound in the KDM

The algorithm identifier is in `FixedInfo` (section 4.3) and per-algorithm required-field validation is enforced (section 5.2), so an attacker cannot strip `ek` and rewrite `alg` to classical: the KEK would differ (algorithm-identifier mismatch) and AES-KW rejects.

### 9.2 Key-directory and attestation layer: client refuse-to-downgrade (MUST)

The envelope KDM cannot see a downgrade one level up: a compromised server serving a classical-only key bundle for a recipient who actually holds hybrid keys would lead an honest writer to wrap classically, enabling harvest. Client MUST: if the recipient's attested key bundle includes an ML-KEM encapsulation key, the writer MUST wrap with the hybrid algorithm and MUST NOT emit a classical wrap for that recipient. It errors; it does not fall back. Structural note: launch-day PQR means no legacy classical population ever exists; every v1 account is hybrid from enrollment. This rule defends against malicious infrastructure, not legacy peers.

### 9.3 Transparency layer: hybrid public-key visibility

The recipient's hybrid public keys (the section 8.5 pair-commitment) MUST appear in their transparency-log entry, so a substituted classical-only bundle is watcher-detectable. Attestation and log entries MUST cover the same key set. The transparency-log entry format and the watcher protocol are PQ-aware from the start.

### 9.4 Negative-test inventory (N1 through N9; mandatory, CI-gating)

- **N1:** a hybrid envelope with `ek` stripped and `alg` rewritten classical: unwrap MUST fail.
- **N2:** `alg` rewritten with fields intact: fail.
- **N3:** `ek` swapped in from another envelope: fail.
- **N4:** a recipient block transplanted to another recipient: fail (recipient-key binding, section 4.3).
- **N5:** a classical envelope with `ek` injected: reject at validation (section 5.2, the symmetric direction).
- **N6:** a directory response lacking the PQ key for an attested-hybrid recipient: the writer refuses to wrap classically (section 9.2).
- **N7:** a metadata-key wrap (`party_v` = `root_folder_id`) replayed as a DEK wrap (`party_v` empty), or across folders: fail (the `party_v` binding).
- **N8:** an ES256-only signed request from a hybrid-attested account: the server MUST reject (section 8.6, the request-path signature downgrade).
- **N9:** an ES256-only server verification response or receipt, once the server PQ verification key is pinned: the client MUST reject (section 8.6, the response-path signature downgrade).

## 10. ML-KEM implicit rejection (implementation MUST)

ML-KEM decapsulation of a tampered `ek` does not error: it returns a pseudorandom shared secret (FIPS 203 implicit rejection). The failure therefore surfaces downstream at AES-KW integrity failure, not at decapsulation. Tests MUST assert on the unwrap outcome, never on a decapsulation error that never comes. The error taxonomy reports a single `unwrap_failed`; no decapsulation-versus-key-wrap oracle distinction may be exposed to any peer or log.

## 11. Validation requirements

Extends the three-tier harness (KAT against published vectors; differential against an independent lineage; committed cross-implementation goldens) to the PQ path:

1. **ACVP, full sets** for ML-KEM-1024 (keygen, encaps, decaps, including implicit-rejection vectors) and ML-DSA-87 (keygen, sign, verify), in CI, against the shipped Rust crates, on both compile targets.
2. **Differential, two lineages at launch:** RustCrypto (CLI and WASM) against CryptoKit/Secure Enclave (encapsulate-by-one, decapsulate-by-the-other, both directions; dual-signature cross-verification). Two genuinely independent lineages.
3. **Cross-target:** native-Rust against WASM-Rust byte-equality on identical inputs, catching miscompiles.
4. **Envelope round-trip goldens:** hybrid wrap and unwrap vectors plus the human-to-PRSN byte-identical crossover, re-run over the hybrid algorithm identifier; committed to the golden set.
5. **KeyCombine KATs (authored here):** fixed `Z_ecdh`, `Z_mlkem`, `FixedInfo` giving a fixed KEK, pinning the IKM byte order, the section 4.3 FixedInfo encoding, and the KEK output. The section 4 construction is the one component with no external vector source, so the specification's two authors each generated these vectors independently from the merged text and byte-compared them: match confirmed on both vectors (PRK, KEK, and wrapped key identical; FixedInfo 3324 and 3340 bytes). These vectors are committed as the CI KAT.

   5b. **Dual-signature signing-base KAT (section 8.7):** a fixed example request and response pinning the exact `M` bytes each half signs plus the `ctx` per surface, byte-compared independently, so implementers cannot diverge on which bytes each half signs. Signatures are non-deterministic; the KAT pins the signing base, plus a fixed-key verify vector.
6. **Negative tests N1 through N9** (section 9.4): mandatory, CI-gating.
7. **libcrux** (formally verified): an optional, allowed-to-fail third-lineage leg behind a harness feature flag, promoted when it stabilizes or an audit of the primary crates lands.
8. **Named residuals (the assurance model):** (a) the PQ differential runs two lineages at launch, versus three for classical; accepted on the monotonicity backstop (a PQ implementation bug degrades to P-256, never below) plus full ACVP coverage. (b) Correlated at-rest custody of the server's two signature keys under one deployment key (section 8.8); accepted because the hybrid hedges algorithm breaks, not host compromise. Recorded, not silently closed.

## 12. v1 scope boundary

**In v1 (the complete PQR surface):**

- The hybrid content wrap (sections 4 through 7): file DEKs and folder metadata keys.
- Human and PRSN key custody, Secure Enclave and WASM (sections 6 and 7).
- Identity dual-sign across all three surfaces (section 8): attestation and enrollment proof of possession (`signet:attest:v1`), per-request (`signet:req:v1`), and server response and receipt.
- Transport PQ: PQ key exchange (X25519MLKEM768) enabled on all TLS endpoints, with coverage verified empirically across the real ingress chain, not assumed. This protects metadata against network-level harvest-now-decrypt-later.
- The transparency-log PQ entry format and the PQ enrollment ceremony; section 9.3 states the cryptographic requirement they satisfy.

**Outside v1, for principled reasons, not deferred conveniences:**

- **The pure `ML-KEM-1024+A256KW` endpoint:** activating it would reduce security today. It drops the classical hedge that protects against ML-KEM implementation immaturity (C5 monotonicity). Reserved because it is not wanted yet, not because it is a nicety.
- **PQ-WebAuthn:** externally vendor-gated; authenticators and browsers do not do PQ passkeys yet. No harvest-now-decrypt-later hole results: the human's confidentiality (the key-seed wrap) is already PQ-safe (AES-256-GCM under a PRF-derived key); only the login signature is classical, which is a forgery clock rather than a harvest exposure.
- **Native WebCrypto PQC:** not a capability gap. The human already gets full ML-KEM via WASM; this is only a future implementation swap.

**Performance** (N=1000, Apple M4 Pro Secure Enclave, in-process):

- ML-KEM-1024 Secure Enclave decapsulation: 2.2 ms, faster than Secure Enclave ECDH at 4.5 ms. The hybrid content wrap adds only about 2 ms per unwrap; the committed centerpiece is nearly free.
- ML-DSA-87 Secure Enclave sign: 12.9 ms mean, 22 ms p95, 29 ms p99, 47 ms max, versus `ES256` at 4.5 ms (about 2.9 times, plus 4.7 KB per signature). Per-request dual-signing ships in v1; latency is a UX-tuning matter, not a build-or-not gate, with a testing watch on hot-path burst latency: ML-DSA signing is designed to pipeline and batch where the request pattern allows.

## 13. Review record

The specification closed its review with these resolutions, recorded here because they are part of the public assurance story:

1. **KeyCombine KAT byte-compare:** confirmed. Both authors generated the vectors independently from the merged specification text; PRK, KEK, and wrapped key were identical on both vectors. Committed as the CI KAT (section 11.5).
2. **FixedInfo field order:** frozen by the matched KAT (`alg`, `epk`, `ek`, `rk_ec`, `rk_pq`, `L`, `party_v`).
3. **SP 800-227 section 4.6 conformance:** PASS, clause by clause; zero clauses contradicted.
4. **Algorithm-identifier naming versus IETF registries:** keep Signet Drive's own identifiers (both ends of the wire are owned, so there is no interop-by-codepoint need); revisit alignment when the IETF drafts settle.
5. **Server-response dual-sign and key custody:** confirmed (store the 32-byte seed; the correlated-custody residual named in section 8.8).
