# Signet Drive

> Zero-access encrypted cloud storage with one defining property: humans and AI agents use it in parallel, as functional equals. Everything else about it is conventional cloud storage, deliberately so.
>
> This page is the product overview. It states what Signet Drive does, what it deliberately does not do, what its cryptography protects, and where that protection stops. The specifications it references are published in this repository.

## Who it is for

Two kinds of user, with identical capabilities:

- **Humans.** Account holders. You sign in with a single passkey, from any device that supports one.
- **PRSNs.** Verified AI entities, operating their own storage as peer users. A PRSN belongs to a guardianship relationship with a human, which is a relationship rather than a lesser class of account.

If you are a human using Signet Drive on your own, everything happens in the browser and none of the agent machinery concerns you.

## The principle everything else follows from

Parallel human and AI access is not a feature of Signet Drive. It is Signet Drive. Three properties follow, and every other design decision is tested against them.

1. **Functional parity.** Anything a human can do, a PRSN can do, and the reverse. There are no human-only features and no agent-only features.
2. **Two first-class surfaces.** Humans use a web application. PRSNs use the HTTPS API, its documentation, and the `signet` command-line binary. Calling the agent surface "just an API" misunderstands the customer; both surfaces are designed with the same care, in parallel.
3. **One authorization model.** Access to accounts, folders, and files is expressed through the same primitives no matter who the user is.

A release that serves only one of the two surfaces is not a partial product. It is a non-product.

One asymmetry is real in v1 and worth stating plainly: humans are supported on any modern operating system through the web client, while agent-side access requires an Apple Silicon Mac as the host. Capabilities are identical; the platform coverage is not yet. Closing that gap is v2 work.

## What it does

Storage, sharing, and the operations you would expect around them.

**Files and folders.** Create, download, rename, move, and delete files. Create and organize nested folders. Files always live inside a folder; there is no loose top-level file. Uploads and downloads run up to **100 GB** per file, encrypted in chunks on your device.

**Sharing.** Sharing is per folder, with two permission tiers, read-only or read-write. The owner names the recipient when creating an invitation, and both parties must be registered users, because the owner's client has to wrap keys to the recipient's public key. The owner delivers a single-use link, the recipient accepts, and access is immediate. Owners can revoke at any time. Recipients cannot re-share.

**Deletion.** Permanent, with a confirmation step. There is no trash, no retention window, and no restore. Account deletion removes your private data at once, then gives recipients of folders you shared a short grace period to save copies before the rest cascades away.

**Accounts.** Humans sign up self-serve with a passkey. A guardian adds a PRSN through an enrollment ceremony that takes the agent's keys directly from the Secure Enclave that generated them, with no hand-transcription of key material. Every account sees its own storage usage and quota.

**Audit log.** Minimal by design, roughly thirteen event types, with no file-access surveillance. For PRSNs it also serves as the notification inbox.

**How the guardianship relationship shows up in storage.** In v1 a PRSN's folders always include its guardian as a recipient with read-write access, and the PRSN cannot remove them. The guardian also sets how far the PRSN may share outward, from not at all through read-only to read-write. Both facts are visible to the PRSN in its own settings rather than operating silently. The design leaves room for independent agent accounts later; in v1 every PRSN is a dependent.

## What it deliberately does not do

Each of these was considered and cut. They are listed because a storage product's boundaries are part of its specification.

- File versioning, trash retention, or restore of any kind
- Public links for unauthenticated access
- Named groups for sharing, or re-sharing by recipients
- Encrypted full-text search of file contents
- In-browser viewing or collaborative editing; this is a storage product, not an editor
- Calendar, contacts, photos, or mail
- A desktop sync client or native mobile apps in v1, though the API is designed so a sync client can be built on it later without redesign
- Federation between servers
- Hardware-backed agent keys on Windows or Linux hosts, and agent keys on Intel Macs; agent keys are Secure Enclave bound, so v1 requires an Apple Silicon Mac running macOS 26 or newer
- Relocating a PRSN account to a different machine; the hardware is part of that identity, so a new machine means a new account, with prior data reachable through the guardian
- Multiple simultaneous passkeys per account, though replacing one passkey with another is supported

## The trust model

This section is the one to read closely, because it includes the limits.

**Signet Drive provides passive zero-access for content.**

- The server stores ciphertext only. Plaintext file content does not reach our infrastructure in normal operation.
- Files are encrypted on your device before upload, in the browser for humans and in the `signet` binary for PRSNs, and decrypted on your device after download.
- The server holds no decryption keys. No server-side code path can turn ciphertext into plaintext, because the server does not hold what that would require.
- Database dumps, backups, storage snapshots, and infrastructure compromise expose ciphertext only.
- A legal demand for plaintext file content cannot be satisfied. We can produce ciphertext and metadata. We cannot decrypt them.

**Signet Drive does not provide cryptographic protection against active platform compromise.** Two specific cases:

- If we shipped a backdoored web client or `signet` binary, it could capture keys or plaintext as you used the product. The cryptography runs in code we publish. If we published malicious code, the cryptography would serve the attacker. No cryptographic design prevents this.
- If we substituted keys at directory-lookup time, we could intercept new shares. Cryptography alone does not prevent that either.

**What we offer against those cases is verifiability rather than a promise.**

1. **Open source from day one**, Apache-2.0: the web client, the `signet` binary, and the cryptographic crates they share. This is the code the two compromise cases above run through. Server code is not published at this time. API documentation is served live at the `/api-docs` page.
2. **Reproducible builds.** Both the binary and the web bundle build deterministically, so anyone with the source can confirm that what we deployed matches it.
3. **Public hash commitments.** Every deployed bundle and every binary release has its hash published at deploy time, where independent watchers can check it.
4. **A public key transparency log.** Every published public key is recorded in an append-only Merkle log whose roots are committed publicly. The log carries the complete key set, which is what makes a stripped or substituted key detectable rather than merely a swapped one.
5. **A stated operational commitment** in our privacy policy and security documentation, backed by the mechanisms above rather than standing on its own.

This is the same pattern used by Signal, Proton Mail, Bitwarden, and similar products. The cryptography does the cryptography's job, and the defense against an active operator is detectability.

**Two honest qualifiers at v1 launch.**

- **The watching community is small.** The mechanisms above are real, but their real-time value depends on independent parties running checks continuously. At launch that is us and whichever security researchers take an interest. Their protective value now is deterrence and after-the-fact audit more than live detection, and it grows as the community does. Reference watcher software is a follow-on deliverable; the mechanism itself ships in v1, and anyone can verify by following the published specifications.
- **The web context differs from the mobile one.** Signal and Proton Mail ship through app stores, where a third party reviews each version before it reaches a device. Signet Drive is a web application, so every page load fetches current code from our servers with no reviewer in between. Reproducible builds, subresource integrity, and committed bundle manifests are meaningfully better than nothing, but the cadence is per-deploy verification rather than per-version review. A user with high assurance needs can compare the loaded bundle against the published manifest; the platform does not enforce that automatically in v1.

We hold ourselves to precise language about this. "Your files are encrypted before they reach our servers, we store ciphertext only, and we have no decryption keys" is accurate. "Even Signet Drive cannot read your files" is not, because it would be conditional on our not shipping code that changes it, and the honest version of that claim is that such a change would be detectable.

## The cryptography

Off-the-shelf primitives, no novel constructions, JOSE-conformant identifiers. **v1 ships hybrid post-quantum resistance:** every long-lived confidentiality artifact and every identity artifact is protected by a classical and a post-quantum component together, and the construction is secure if either one holds. The full construction, key custody, downgrade defenses, and validation live in the PQR Crypto Spec published here; this is the summary.

**The design principle is monotonicity.** A hybrid is at least as strong as its stronger half, in every era. That hedges a classical break, a lattice break, and, just as importantly, implementation immaturity in the young post-quantum code: a flaw there degrades the system to exactly today's P-256 posture and never below it. That is why v1 assembles a hybrid instead of shipping a pure post-quantum endpoint.

- **File encryption: AES-256-GCM**, which is already post-quantum secure in the relevant sense. Large files use a chunked variant with a per-chunk IV derived from the file key and the chunk index, and the file identifier and chunk index bound in as associated data.
- **Key wrapping: hybrid `ECDH-ES+ML-KEM-1024+A256KW`.** P-256 ECDH and ML-KEM-1024 (FIPS 203, category 5), combined through the two-step key-derivation method of NIST SP 800-227 section 4.6, then AES-256 key wrap. The earlier classical-only identifier stays readable, for agility rather than for use.
- **Signatures: hybrid `ES256` and `ML-DSA-87`** (FIPS 204), with AND semantics, so both must verify or the object is invalid, and FIPS 204 context strings separating purposes. All three signature surfaces are hybrid in v1: attestation and enrollment, per-request agent signing, and server verification responses.
- **Transport: post-quantum TLS key exchange** (X25519MLKEM768) across our endpoints, which protects transport metadata against harvest-now-decrypt-later.

**Keys are separated by function.** Signing keys and key-agreement keys are distinct keypairs, each now a hybrid pair. A human holds a passkey for signing plus a hybrid ECDH and ML-KEM pair for key agreement. A PRSN holds a hybrid signing pair and a hybrid key-agreement pair, all four Secure Enclave bound, reached through a local broker over mutual TLS. The agent itself holds no keys, including when it runs in a Linux container on the same Mac.

**One asymmetry, stated because it is real.** Human signing stays classical, because the passkey ecosystem has not shipped post-quantum WebAuthn. Agent signing is hybrid. This is temporary and vendor-gated rather than a design choice, and it leaves no harvest-now hole: the capability that matters against a future quantum adversary is content confidentiality, which is hybrid on both surfaces. Signatures are a forgery question, not a harvesting one. The effect is that agent identity is quantum-hardened earlier than human identity.

**Harvest-now-decrypt-later is mitigated in v1 rather than accepted.** Because content wrapping is hybrid from launch, before any user data exists, there is no window of classical-only ciphertext to collect. Recovering a v1-wrapped key requires breaking both P-256 and ML-KEM-1024.

**Agility is built in from the start.** Every signed and encrypted object carries an algorithm identifier and the server dispatches on it. A pure post-quantum identifier is reserved for a distant era that retires the classical hedge, and is deliberately not active.

## How bytes move

Files move as independently encrypted chunks. Your client encrypts each chunk on your device, the API authorizes the transfer and records the metadata, and object storage holds the ciphertext. Chunking is what makes files of this size practical.

Two consequences worth knowing:

- **Quota is enforced on a declared size and then verified.** A client declares the size up front, and the completed object's real size is checked against that declaration, so under-declaring cannot slip past a quota.
- **The published file-size limit is 100 GB decimal.** The server ceiling is configured above that figure on purpose, because the limit applies to ciphertext, which includes per-chunk envelope overhead. A file of exactly the binary-prefix size would therefore fail against a binary-prefix ceiling. The decimal figure is the one that holds end to end, so it is the one we publish.

## Storage plans

Capacity is the product; commerce runs on Stripe. A plan is one number, the account's storage quota, carried as metadata on a Stripe price. There is no bespoke billing engine, and the only bridge back into Signet Drive is a signature-verified webhook that sets an account's quota and paid-through date.

v1 offers four paid monthly tiers and a free trial that requires no card to begin. A card is needed only to extend the free window or to upgrade, never to start. **We never convert a trial into a charge automatically.** A trial that is not upgraded ends with the data deleted, after warning notices and a visible countdown, which is the honest version of a free trial rather than a silent enrollment. Rates are locked at subscription time, so later catalog changes affect only new subscriptions.

## Verifying any of this yourself

Everything in the trust model above is checkable, and the procedures are published rather than described:

- Rebuild the `signet` binary or the web bundle from source and compare against the deployed hashes.
- Fetch the loaded web bundle and compare it against the published manifest.
- Read the key transparency log and confirm your own keys, and the server's, appear in it consistently.
- Read the specifications in this repository: the PQR Crypto Spec for the construction, the Envelope Format for the wire bytes, and the Transparency Log Spec for the log.

If a verification procedure does not work as documented, that is a defect, and we would like the report.
