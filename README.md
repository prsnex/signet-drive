# Signet Drive

Signet Drive is cloud storage for humans and AI agents, with the same capabilities for both. Files are encrypted on your device before upload; the server stores ciphertext and holds no decryption keys. No one but you can read your files, including us.


## Trust model

Signet Drive does not ask users to trust its operators. It publishes the means to check them:

- **Open source.** The client code is in this repository: the web client, the CLI, and the cryptography they share, published under Apache-2.0. Files are encrypted by this code before upload, so confidentiality does not rest on server behavior. Server code is not published at this time.
- **Reproducible builds.** The released client artifacts rebuild byte-identically from this source: the CLI binary, the web bundle, and the WASM crypto module. The verification tooling is in [`verify/`](verify/); it becomes runnable by outside parties once the public hash history it anchors to is live (see below).
- **Key transparency log.** Every published public key is recorded in an append-only Merkle log with signed receipts. Key substitution leaves evidence. Log roots are committed to [signet-drive-transparency-log](https://github.com/prsnex/signet-drive-transparency-log).

Cryptography: AES-256-GCM for content; hybrid P-256 plus ML-KEM-1024 key wrapping; hybrid ES256 plus ML-DSA-87 signatures on enrollment, per-request signing, and server responses (human login remains a classical passkey pending PQ-WebAuthn support); X25519MLKEM768 transport. Content confidentiality holds if either the classical or the post-quantum component holds. The full construction is specified in [the crypto specification](docs/design/Signet-Drive-PQR-Crypto-Spec.md).


## Verify a release

Start in [`verify/`](verify/). The fastest check is the Linux binary: container-built, digest-pinned, machine-independent.

```sh
verify/verify-release.sh --tag <release>
```

The script prints its own hash and version, anchors the release manifest in a public hash history, rebuilds from source, and reports one of three named verdicts. **That hash history has not been started yet.** Until it is, the script stops at the anchor step with a prerequisite failure (exit 64) and produces no verdict: an unanchored claim is not verified, by design. This section will change when the history is live. Once the history is live, AI agents can run the full verification loop unattended.


## Service and self-hosting

The operated service is at https://drive.mysignet.ca. This repository contains the client and cryptography code only; it does not stand up a complete self-hosted instance, because the server component is not published. The license permits building and using everything here. The transparency log, hash commitments, and attestations cover our deployment only.


## Repository model

This public repository is produced by a per-release curated export from a private working tree. Its history begins at the first public release by design; every commit is a signed, tagged release export. See [CONTRIBUTING.md](CONTRIBUTING.md) for how contributions land, [SECURITY.md](SECURITY.md) for vulnerability reporting, and [TRADEMARKS.md](TRADEMARKS.md) for name use.


## License

Apache-2.0. See [LICENSE](LICENSE).
