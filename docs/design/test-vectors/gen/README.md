# Golden-vector generator

Produces the committed reference bytes under [`../golden/`](../golden/). Run once; the **output is committed** and consumed by the crypto test suites. This generator is **never a CI runtime dependency**; re-running CI re-checks the Rust implementation against the frozen reference.

## Regenerate

```sh
cd docs/design/test-vectors/gen
npm install        # installs the pinned JOSE library (see package.json)
npm run gen        # writes ../golden/wrap-chain.json     (wrap chain + file envelope)
npm run gen:kem    # writes ../golden/kem-wrap.json       (human KEM-key wrap chain)
npm run gen:chunk  # writes ../golden/chunk-envelope.json (multipart chunk envelope)
```

`gen:kem` and `gen:chunk` need no npm dependencies; they use only Node's built-in WebCrypto.

`node_modules/` and `package-lock.json` are git-ignored; only the scripts, `package.json`, this README, and the generated `../golden/*.json` are committed.

## What it generates, and why it is independent

- **`ecdh_es_a256kw_dek` / `ecdh_es_a256kw_metadata` (JOSE conformance lineage).**
  A pure-JS JOSE library on the Node WebCrypto lineage, a different codebase and language from the
  RustCrypto implementation under test, produces a real `ECDH-ES+A256KW` JWE wrapping a CEK to the
  recipient. The metadata vector sets `apv = root_folder_id`, the folder binding of
  [Envelope Format](../../Signet-Drive-Envelope-Format.md) section 7.2, which JOSE folds into the
  Concat-KDF `PartyVInfo` exactly as the production `wrap_metadata_key` does.

  JOSE's CEK is internal, so the Rust test proves the unwrap recovered the *exact* CEK by
  AES-256-GCM-decrypting the JWE payload with it (only the right CEK yields the known plaintext).
  This validates the full composition (ECDH P-256, then Concat-KDF-SHA-256 with the A256KW
  constants, then AES-KW), not mere self-consistency. The recipient is RFC 7518 Appendix C's
  published "Bob" key.

- **`file_envelope_cat02` (our novel bytes).** Node WebCrypto AES-256-GCM produces the
  ciphertext plus tag for the Category 02 TC02-01 inputs; the single-PUT `[magic][alg][IV]` frame
  is assembled around it. The production `envelope::seal_file` must reproduce the bytes exactly,
  pinning the framing on top of an independently generated GCM output.

- **`kem_privkey_wrap` (Category 01; Envelope Format section 8, the human KEM-key wrap chain).**
  `kem_wrap_gen.mjs` runs the exact chain the web client runs in-browser:
  `HKDF-SHA-256(prf_output)` to derive wrap key `W`, then an `AES-256-GCM` wrap of a PKCS#8 ECDH
  P-256 key (AAD = `"signet-drive-kem-wrap-v1"`). Node WebCrypto is the production reference, so
  byte agreement proves the reference implementation matches what real sign-up and sign-in
  produce. Fully deterministic: a designated synthetic PRF output (`0x00..0x1f`), the published
  "Bob" key as the wrapped PKCS#8, and a fixed IV. Fills Category 01 TC01-02.

- **`chunk_envelope` (Envelope Format section 4.2, the multipart chunk envelope).**
  `chunk_envelope_gen.mjs` runs the section 4.2 chunk chain via Node WebCrypto: IV =
  `HKDF-SHA-256(DEK, empty salt, "signet-drive-multipart-iv-v1" || idx_be, 12)`, then
  `AES-256-GCM(DEK, IV, plaintext, AAD = file_id || idx_be || is_last(1))`, framed
  `[0x02][0x01][idx_be][IV][ct||tag]`. Node WebCrypto is a third lineage, independent of both
  RustCrypto and the browser WebCrypto the web client ships; all three consume this committed
  file, so all three must agree byte-for-byte.

This is the **Layer-2** fill-in for test-vector categories 01 (PRF to wrap-key derivation) and
02 (file envelope) and the `ECDH-ES+A256KW` wrap chain (Envelope Format sections 5 and 7.2), per
the [test-vectors README](../README.md) two-layer model.
