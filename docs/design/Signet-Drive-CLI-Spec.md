# Signet Drive `signet` CLI Specification

## Status

The `signet` command-line client is the first-class PRSN-side surface for Signet Drive, the PRSN's functional equal of the human web client. It is both the PRSN's cryptographic tool, for signing, key wrapping and file and name encryption, and its drive-management surface, for seeing, addressing, creating, organizing and sharing folders and files. The load-bearing principle is parallel human and PRSN access at functional parity.

This is the public edition of the specification of record. It states the interface contract of the shipped client, the commands, their arguments and outputs, their exit codes, the configuration, and the security model. It omits the internal design history, the build narrative and the internal design documents the specification of record cites. It is regenerated when the interface changes, and substantive changes are noted in release notes.

**Reference points.**

- [Signet Drive Envelope Format](Signet-Drive-Envelope-Format.md), the bytes on the wire that the client produces and consumes.
- [Signet Drive Transparency Log Specification](Signet-Drive-Transparency-Log-Spec.md), which `signet transparency-verify` and the share commands enforce.
- [Signet Drive PQR Crypto Specification](Signet-Drive-PQR-Crypto-Spec.md), the hybrid post-quantum constructions.
- The server-side schema, the server key lifecycle, and the drive-management design rationale live in internal documents. The parts that bind a client are specified here.

## Scope

This document covers the interface contract of the client.

- The subcommands that exist and their purpose.
- Argument and option conventions.
- Output format conventions, JSON for structured data and binary for file content.
- Exit codes.
- The configuration file's location and schema.
- The key identification model.
- The self-update mechanism.
- Apple Silicon Secure Enclave behavior, the only supported key storage in v1.
- Cross-cutting concerns, such as verbosity, error JSON and idempotency.

Out of scope are the exact wording of help text and error messages, where the categories and exit codes are specified and the human-readable strings are not, and internal implementation details such as how the Security framework is wrapped or how arguments are parsed.

## Design conventions

**Long-form options are primary.** The standard forms are `--key`, `--in`, `--out`, `--signing`, `--kem`, `--label`, `--algorithm`, `--to-pubkey`, `--wrap-envelope`, and so on. Short forms exist only for the very common ones, `-v` for verbose, `-q` for quiet and `-h` for help.

**Path-first addressing, uniformly.** Every drive verb that addresses a target takes a positional `[PATH]`, with `--folder-id` and `--file-id` as the precision fallback. `--to` is reserved for destinations and recipients. `share create [NAME]` takes the share's path, which is its name, and `file upload [DEST-PATH] --in <src>` takes the path whose last segment is the new file's name. The older `--name`, `--to` and `--folder-id` forms are kept.

**base64url values may begin with a hyphen and are accepted as they are.** Every argument whose value is inline base64url, such as recipient and server keys, and the positional one-time codes accept a leading hyphen, since about one value in sixty-four encodes hyphen-first and a parser's default would read it as a flag. File paths, hex values and classical X9.63 keys are out of scope by format.

**File input and output.** `--in <path>` and `--out <path>` for file operations, and standard input and output if neither is given. Files larger than a configurable threshold, by default 16 MB, are streamed.

**Sensitive material never appears on the command line.** DEKs, metadata keys and other secret material are never accepted as command-line arguments, because process argument lists are visible to other processes and to shell history. An operation that needs a secret either generates it internally and never exposes it, as `signet encrypt` does with the DEK, or reads it from a wrap envelope encrypted to the user's KEM key, as `signet decrypt --wrap-envelope <FILE>` does. Public key material is acceptable on the command line, since it is not secret.

**Output format.** The default is machine-readable. JSON for structured data, binary for file content, hex for small fixed-size values, and one value per line for lists. The `--pretty` flag produces human-friendly output, pretty-printed JSON and tables for lists.

**Error model.** All errors go to standard error, and standard output is for success output only. The default is one human-readable line, `signet error: <category>: <message>`. With `--json-errors`, standard error emits one JSON object per error, `{"error": {"code": "<machine_id>", "message": "<text>", "details": {...}}}`.

**Exit codes.**

| Range | Category |
|---|---|
| 0 | Success. |
| 1 | Generic error, when no specific category fits. |
| 2 | Invalid arguments, at the command-line level. |
| 8 | Informational non-error, such as an update being available. |
| 10 to 19 | Key and authentication errors. 10 `authentication_failed` (the server did not accept the request's authentication, HTTP 401). 11 a key already exists. 12 key not found. 13 invalid signature. 14 `attestation_expired`. 15 attestation revoked. 16 `cli_outdated` (any server-bound command below the minimum version). 17 `authorization_denied` (a capability refusal, HTTP 403). |
| 18 | `insufficient_storage`. The upload cannot fit, because it exceeds the server's single-file ceiling or the Guardian group's pooled quota has less room than it needs. Raised client-side before any byte is sent. The same command succeeds unchanged once space exists. |
| 20 to 29 | Input and output errors. 21 filesystem error. 22 input read error. 23 output write error. 24 invalid input format. 25 name too long. 26 `not_found` (HTTP 404, distinct from a client-side resolver miss, which is exit 2). 27 `conflict` (HTTP 409). |
| 30 to 39 | Network errors. 31 `network_error`, not resumable. 32 `transfer_stalled`, a direct-to-storage part transfer that exhausted its attempt budget, resumable by re-running the same upload command. |
| 40 to 49 | Cryptographic errors. 40 encryption failure. 41 unsupported algorithm. 42 decryption failure, typically a tag mismatch. 43 a rewrap target rejected. |
| 50 to 59 | Configuration errors. 51 is the platform check, an Apple Silicon Mac is required. |
| 60 to 69 | Transparency and verification errors. 60 a TRANSPARENCY VIOLATION. 62 `unanchored` or `epoch_changed`, described below. |
| 70 to 79 | Device-access errors. 70 an internal fault on that surface. 77 the authorization-refusal family (`access_paused`, `token_denied`, `token_request_failed`). |

Exit 62 `unanchored` means that what was checked holds as far as it goes, but there is no public anchor to hold it to, because the anchor files are unreachable, do not yet carry the server's epoch, or carry no published root for it. It is informational and not a pass. A script must not read it as verified, and `valid` is false beside it. A write path that cannot anchor an epoch of 2 or later refuses with 62 rather than bind keys it cannot check, and succeeds once the files update. Exit 62 `epoch_changed` means the server changed its served epoch during the command's attempts, and the command is to be run again.

Specific exit codes within each range are documented per subcommand below.

**One epoch per command.** A command that binds keys or proves inclusion, which is `share invite`, `recipient`, `share create`, an upload into a share, `transparency-verify`, and `attestation-verify` online, anchors the server's epoch once per attempt, and every epoch-bound read names that epoch. If the server serves another epoch partway through, whether by refusing the anchored one or by answering a part read with another epoch, the command re-anchors and re-reads once. Nothing is wrapped or posted inside an attempt, so a change of epoch leaves nothing half-bound. A second change ends the command with exit 62 `epoch_changed`. A server that contradicts itself twice within one anchored epoch is a violation, exit 60. An absent `epoch` field in any server answer means epoch 1.

**Logging.** Silent on success by default, with only errors on standard error. `--verbose` or `-v` prints progress messages to standard error. `--quiet` or `-q` suppresses standard error entirely, and the exit code carries the result.

## Configuration

The configuration file is `~/.config/signet/config.toml`, in TOML, created on first run if absent.

```toml
# ~/.config/signet/config.toml

server_base_url = "https://drive.mysignet.ca"  # default; overridable via SIGNET_SERVER_URL
default_signing_key = "default-signing"       # used when --key is not given for signing operations
default_kem_key = "default-kem"               # used when --key is not given for KEM operations
output_format = "machine"                     # "machine" | "pretty"
errors_format = "human"                       # "human" | "json"
log_level = "warn"                            # "trace" | "debug" | "info" | "warn" | "error"
```

**Environment variable overrides.**

- `SIGNET_SERVER_URL` overrides `server_base_url`.
- `SIGNET_DEFAULT_SIGNING_KEY` and `SIGNET_DEFAULT_KEM_KEY` override the defaults.
- `SIGNET_CONFIG` names an alternate configuration file.
- `SIGNET_HANDLE` names the PRSN this client acts as, for the commands that resolve keys by handle.
- `SIGNET_ANCHOR_REPO` names the transparency log's anchor repository for a self-run server, as `owner/repo`.
- `SIGNET_KEYS_DIR` is the software keystore's directory, for development, test and CI only. Production PRSN keys are bound to the Secure Enclave and never live in this directory.
- `SIGNET_KEY_TIER` forces the keystore backend for development, test and CI, `software` or `secure_enclave`, overriding auto-detection. A software keystore cannot back a real PRSN, since the server's attestation enforces Secure Enclave key protection.
- `SIGNET_BROKER_ADDR` and `SIGNET_BROKER_CREDENTIAL` select the local broker path (the device-access surface below).
- Per-invocation flags such as `--server-url` and `--key` override the environment, which overrides the file.

## Key identification model

Keys are identified by **label**, a human-readable string assigned at `signet keygen` time with `--label <name>`. Each subcommand that needs a key takes `--key <label>`. When `--key` is omitted, the client uses the configured default for the operation's purpose.

**Label format, enforced at keygen.** `<prsn-handle>-<purpose>`, where `<prsn-handle>` is the account's handle, lowercase ASCII of 2 to 64 characters ending in `-ai`, and `<purpose>` is `signing`, `kem`, `signing-pq` or `kem-pq`. Examples are `hlin-ai-signing` and `hlin-ai-kem`. One key set per PRSN, on a single host of the user's choice. Keygen rejects a malformed label with exit code 2 and an error naming the format. The label is the PRSN identity assertion, and the client uses keys by label with no separate identity mechanism.

**The four keys of a hybrid identity.** A PRSN holds a classical signing key (ES256), a classical KEM key (ECDH), a post-quantum signing key (ML-DSA-87) and a post-quantum KEM key (ML-KEM-1024), with the labels `<handle>-signing`, `<handle>-kem`, `<handle>-signing-pq` and `<handle>-kem-pq`.

**Key storage.** PRSN keys are bound to the Secure Enclave. Key protection is always `secure_enclave`. The client auto-detects its environment. Native on an Apple Silicon Mac, keys live in the device's Secure Enclave directly. In a Linux container on that Mac, which has no enclave of its own, the client runs in a delegation mode, where the keys live in the host's Secure Enclave and each cryptographic operation is delegated to a host-side signer or, on the device-access path, to the local broker.

On the Mac host, keys are created in the Secure Enclave with the access policy that permits use while the user session is unlocked on this device only, with no biometric flag. The label is the lookup handle, stored as the key's keychain label and queried by it at use time. Keys are non-extractable from the Secure Enclave, since no software path can read their bytes. Persistent Secure Enclave keys live in the data-protection keychain, which requires the `signet` binary to be code-signed with a provisioning-profile-authorized keychain-access-groups entitlement. A Developer ID signature alone does not authorize it.

**Per-PRSN scoping.** The label encodes the PRSN's identity. To sign as another PRSN by accident, a harness would have to name a label with the other handle's prefix. This defends against accidental cross-PRSN use from misconfiguration. It does not defend against deliberately malicious code in the same harness, which the security model below names as the residual risk.

## User verification, the user-session-unlock model

Secure Enclave keys are created with an access policy of available while unlocked, on this device only, and no biometric or user-presence flag. Three things follow.

- There is no consent gesture at keygen. Key creation is non-interactive, because autonomous PRSN deployments such as scheduled jobs and container-based agents have no human at the Mac to tap. The protections are the Secure Enclave's non-extractability and the entitlement isolation, not a gesture.
- Any process running as the macOS user may use the keys while the user session is unlocked. There is no client-layer session tracking and no per-process Touch ID.
- Key access ends when the user logs out, sleeps the Mac with a passcode required on wake, or reboots. macOS re-authentication is the human's gesture.

The model fits every v1 deployment pattern. An interactive agent session, an autonomous scheduled job, an agent on inbound webhooks, and a PRSN running in a container on a host that stays logged in all work, because in each the macOS user session is unlocked.

There is no `signet auth` subcommand. The macOS user-session login is the authorization.

The client's enforcement is structural against accidents and not against malice. The trust boundary is harness honesty plus macOS user-account isolation. Deliberately malicious code in the same harness can name any key label that exists on the host. A later release may strengthen this with OS-level process isolation.

## Subcommand surface

The client has three groups plus one onboarding command. The crypto and key tooling (twenty commands), the drive-management surface (twenty-two commands), and the PRSN device-access surface (seven commands), plus `signet enroll`.

### Crypto and key tooling

Key management.

- `signet keygen` generates a signing or KEM keypair in the Secure Enclave.
- `signet fingerprint` prints a public-key fingerprint.
- `signet pubkey` prints public key bytes.
- `signet keys list` lists the configured key labels.
- `signet keys delete` deletes a key.

Cryptographic operations.

- `signet sign` signs canonical bytes.
- `signet encrypt` encrypts a file with AES-256-GCM and wraps the DEK to one or more recipients, with the DEK never exposed.
- `signet decrypt` decrypts a file using a wrap envelope addressed to the caller's KEM key.
- `signet rewrap` re-wraps a DEK from the caller to a new recipient without exposing it.
- `signet encrypt-name` encrypts a folder or file name under a wrapped metadata key.
- `signet decrypt-name` decrypts a folder or file name.

Verification.

- `signet attestation-verify` verifies a server-signed attestation verification response.
- `signet transparency-verify` verifies a key's inclusion in the transparency log against the public anchor, or watches the log for the caller's own account.

Synchronization.

- `signet audit` fetches audit log events since a given event.

Utilities.

- `signet rand` prints CSPRNG output.
- `signet base64url-no-pad` encodes and decodes.
- `signet update` checks for a newer version.
- `signet version` prints the client version.
- `signet help <cmd>` prints per-subcommand help.
- `signet uninstall [--yes]`, on macOS, reverses the graphical install. It stops and best-effort deregisters the local broker, removes the app bundle, the `signet` path shim, the broker credential and logs. The Secure Enclave keys are preserved, since they are the PRSN's identity and removing the install is not removing the account. It confirms before acting unless `--yes` is given, and without a terminal it requires `--yes`.

### Drive management

Grouped noun-verb commands for folder, file and share management, plus flat account reads. Folders and files are addressed by name and path, such as `/Finance/Q3 report.pdf`, resolved client-side, with `--folder-id` and `--file-id` as the precision fallback.

Account reads. `signet whoami`, `signet quota`, `signet recipient <handle>`.

Folder management. `signet folder create`, `list`, `rename`, `move`, `delete`.

File management. `signet file upload`, `download`, `list`, `rename`, `move`, `delete`.

Sharing. `signet share create`, `list`, `recipients`, `invite`, `invitations`, `cancel-invite`, `preview`, `accept`, `remove`, `leave`.

Folder and file deletion is confirmation-guarded. Non-interactive use requires `--yes`, and a terminal gets a prompt listing the targets. Deletes are permanent, and there is no trash.

### Onboarding

`signet enroll [CODE]` onboards this PRSN onto a Guardian's account. The human starts the enrollment in the web application and hands the agent a one-time code.

## PRSN device-access commands

The broker-mediated access surface. This section owns the command surface, and the flow and protocol semantics are owned by internal design documents. The agent commands' `--credential` defaults to `<config-dir>/garnet/<handle>.json` for the active `SIGNET_HANDLE`.

**Runtime selection.** When `SIGNET_BROKER_ADDR` is set, the ordinary crypto commands route their Secure Enclave operations through the local broker over mutual TLS. Otherwise they use the host signer if mounted, or the native Secure Enclave. A confirmed PRSN therefore uses the ordinary commands, and the explicit `signet device <op>` forms below are the broker-path surface for first contact, the token and certificate lifecycle, and diagnostics.

### This device, `signet device ...`

The alias `signet garnet ...` is retained for existing scripts.

- `signet device pickup [--credential <path>]` is first contact. It is signature-authenticated, and takes no pairing code. It generates the device keypair, picks up the server-issued leaf certificate, the pinned anchor, the broker's pin and a server-only access token, and persists the possession credential with mode 0600. It prints the credential fingerprint for the Guardian's confirmation. Until the Guardian confirms, every broker operation fails closed. It runs under full public web PKI validation.
- `signet device renew [--audience <broker|server>] [--credential <path>]` mints or refreshes an access token against the live grant over the mutual-TLS ingress. The device certificate is the refresh credential, and identity is taken from the authenticated leaf, never from the request body. `--audience` defaults to `broker`. A broker token is issued only after the Guardian confirms the enrollment.
- `signet device renew-cert [--credential <path>]` rotates the device certificate before expiry over the same ingress. It submits a fresh CSR, the server issues a new certificate with the same handle and a new serial and cuts the old one atomically, and the client re-mints its tokens. The new certificate is persisted first, so a crash is safe. No pairing code and no re-confirmation are needed.
- `signet device keygen [--signing|--kem] [--algorithm <id>] [--broker <addr>] [--credential <path>]` and `signet device sign [--input-format <fmt>] [--output-format <fmt>] [--in <path>] [--out <path>] [--broker <addr>] [--credential <path>]` are the explicit Secure Enclave operation surface through the broker, for diagnostics and end-to-end testing. They take the same formats as `signet keygen` and `signet sign`. They need a broker token. `--broker` defaults to `127.0.0.1:8765`.

### Local broker, `signet broker ...`

- `signet broker serve [--credential <path>] [--bind <addr>] [--software-keystore <dir>]` runs the always-on Secure Enclave broker, a loopback mutual-TLS listener that performs enclave operations for the Guardian's authorized PRSNs, gating each operation on mutual TLS, a certificate-bound token and a live-grant check. The always-on launch agent installed by the graphical install runs it. `--credential` defaults to `<config-dir>/broker/credential.json` and `--bind` to `127.0.0.1:8765`. On a Mac host it also presents the menu-bar status item. If the credential is not present yet, it exits cleanly with code 0, and the launch agent holds it stopped until `signet broker provision` writes the credential. `--software-keystore <dir>` uses a software keystore for development and CI. The listener is loopback only and never routable.
- `signet broker provision <CODE> [--credential <path>]` provisions the broker's own identity from a Guardian-minted setup code. It generates the keys, drives the server's provisioning endpoint, writes the broker credential that `serve` loads, and starts the launch agent so serving begins at once.

## Per-subcommand specifications

### `signet enroll`

Onboard this PRSN onto a Guardian's Signet account. The human Guardian opens the enrollment from the web application and hands the agent the one-time code. The agent is never authenticated. It holds only the single-use code and the submit token it claims at join, and all authorization is the human's, whose session created and confirms the enrollment and whose passkey gesture issues the attestation.

Usage.

```
signet enroll [CODE] [--server-url <URL>]
```

`CODE` is optional and the command is idempotent. Omit it when already enrolled, and `enroll` then does nothing, with `SIGNET_HANDLE` set so the client knows which PRSN it is. There is no agent-first path.

Behavior.

1. Join. `POST /v1/prsn-enrollments/join` claims the single-use submit token that gates the key submission. The server returns it over this direct connection, never through the browser, and a second agent presenting a leaked code is refused.
2. Poll `GET /v1/prsn-enrollments/status` until the human has confirmed and named the PRSN in the browser.
3. Generate four keys in the Secure Enclave, the classical signing (ES256) and KEM (ECDH) pair and the post-quantum pair, ML-DSA-87 for `<handle>-signing-pq` and ML-KEM-1024 for `<handle>-kem-pq`.
4. Begin proof of possession. `POST /v1/prsn-enrollments/keys` submits the four public keys, their fingerprints and the key protection, which the server requires to be the Secure Enclave. The server returns a challenge and a nonce wrapped to the just-submitted hybrid KEM pair.
5. Complete proof of possession. `POST /v1/prsn-enrollments/keys/pop` submits the dual signature, ES256 and ML-DSA-87 over the shared challenge, and the decrypted nonce. Every enrollment is thereby an end-to-end self-test of the whole hybrid path on this machine. Begin may be called again while confirmed, so a crashed enrollment restarts cleanly.
6. Poll until completed. The human's passkey gesture issues the four-key attestation, which enters the transparency log as four entries.

Any failure after key generation removes all four just-generated keys.

Output, to standard output, as JSON, with progress narrated to standard error.

```json
{
  "handle": "<handle>",
  "key_protection": "secure_enclave",
  "attestation_id": "<uuid>"
}
```

Exit codes. 0 on success, including the already-enrolled no-op. 1 when the enrollment expired, was cancelled or failed while waiting. 2 invalid arguments. 31 network error.

### `signet keygen`

Generate a new keypair, signing or KEM, bound to the Secure Enclave. A software keystore is available for development, test and CI only and cannot back a real PRSN.

Usage.

```
signet keygen --signing --label <NAME> [--algorithm <ALG>]
signet keygen --kem --label <NAME> [--algorithm <ALG>]
```

Required. One of `--signing` or `--kem`, which are mutually exclusive, and `--label <NAME>` in the format `<prsn-handle>-<purpose>`, whose purpose segment must match the flag.

Optional. `--algorithm <ALG>`, which defaults to `ES256` for signing and `ECDH-ES+A256KW` for KEM. A `-signing-pq` label takes `ML-DSA-87` and a `-kem-pq` label takes `ML-KEM-1024`, the key-type FIPS names.

Validation. Keygen rejects with exit 2 a label that does not match the format, a handle that does not end in `-ai`, is not lowercase ASCII, or fails the handle pattern `^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$`, or a purpose that does not match the flag.

Output, as JSON.

```json
{
  "label": "hlin-ai-signing",
  "algorithm": "ES256",
  "purpose": "signing",
  "fingerprint": "<lowercase hex SHA-256 of DER SubjectPublicKeyInfo>",
  "storage": "secure-enclave"
}
```

Behavior. Stores the key in the Secure Enclave with the label as the lookup handle. On a Mac without Apple Silicon it refuses. It refuses if a key with the same label and purpose exists, in which case `signet keys delete` comes first.

Exit codes. 0 success. 11 a key already exists with this label. 50 configuration error. 51 platform not supported.

### `signet fingerprint`

Print the public-key fingerprint for a key label.

```
signet fingerprint --signing [--key <LABEL>]
signet fingerprint --kem [--key <LABEL>]
```

Output. By default, the lowercase hex SHA-256 of the DER SubjectPublicKeyInfo on one line with no trailing newline. For a post-quantum key, the fingerprint is over the raw FIPS bytes. With `--json`, an object with `label`, `purpose`, `algorithm` and `fingerprint`.

Exit codes. 0. 12 key not found.

### `signet pubkey`

Print the public key bytes.

```
signet pubkey --signing [--key <LABEL>] [--format <FORMAT>] [--base64url]
signet pubkey --kem [--key <LABEL>] [--format <FORMAT>] [--base64url]
```

`--format` is `x963` by default, or `pem`, `jwk` or `der`. `--base64url` encodes raw bytes as base64url without padding, for embedding in JSON or shell variables.

Output. Raw bytes for `x963` and `der`, or PEM or JWK text.

Exit codes. 0. 12 key not found.

### `signet sign`

Sign canonical bytes.

```
signet sign [--key <LABEL>] [--input-format <FMT>] [--output-format <FMT>] [--in <FILE>] [--out <FILE>]
```

`--input-format` is `bytes` by default, or `hex` or `base64url`. `--output-format` is `raw` by default, the 64-byte `r||s` for ECDSA P-256, or `der`, `base64url-raw` or `base64url-der`. The server accepts both raw and DER, and raw is canonical.

ECDSA signatures are non-deterministic. The Secure Enclave supplies hardware randomness, and the client does not offer a deterministic mode. The input is limited to 1 MB as a sanity check.

Exit codes. 0. 12 key not found. 22 input read error. 41 the key's algorithm does not sign, for instance a KEM key.

### `signet encrypt`

Encrypt a file with AES-256-GCM and wrap the per-file DEK to one or more recipients in one invocation. The DEK is generated internally, used and zeroized, and never crosses the process boundary.

This is a standalone local utility that produces the Envelope Format's single-shot file envelope (section 4.1), for encrypting a file to recipients and handing the blob and wraps off out of band. It is not how a PRSN puts a file in its drive. That is `signet file upload`, which uses the multipart direct-to-storage transport. There is no multipart mode on this command.

Usage.

```
signet encrypt \
  --in <FILE> \
  --out <FILE> \
  --aad-file-id <UUID> \
  --to-pubkey <PUBKEY_VALUE> [--to-pubkey <PUBKEY_VALUE> ...] \
  --wraps-out <FILE>
```

Required. `--in`, the plaintext path. `--out`, the ciphertext path. `--aad-file-id <UUID>`, the file identifier used as additional authenticated data. One or more `--to-pubkey <PUBKEY_VALUE>`, each recipient's KEM public key, whose format is auto-detected among base64url X9.63 bytes, JWK JSON, PEM, and `@/path/to/file` for a file's contents. `--wraps-out <FILE>`, the JSON file receiving one wrap envelope per recipient, in command-line order.

Output. The ciphertext on disk, the wraps file, and a JSON manifest on standard output with `file_id`, `size_bytes`, `ciphertext_size_bytes`, `etag`, `recipients_wrapped` and `wraps_file`. Each wrap envelope follows the Envelope Format section 5.

```json
[
  {
    "v": 1,
    "alg": "ECDH-ES+A256KW",
    "epk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." },
    "ct": "<base64url of 40-byte wrapped DEK>",
    "rfp": "<recipient KEM pubkey fingerprint, lowercase hex>"
  }
]
```

Exit codes. 0. 22 input read error. 23 output write error. 24 an invalid `--to-pubkey` value or format. 40 encryption failure. 2 for a repeated recipient key.

The DEK comes from the operating system's CSPRNG and is zeroized in memory before exit.

### `signet decrypt`

Decrypt a file using a wrap envelope addressed to the caller's KEM key. The DEK is unwrapped internally, used and zeroized, and never exposed. This is the local counterpart of `signet encrypt`. To download and decrypt a file from the drive, use `signet file download`.

```
signet decrypt \
  --in <FILE> \
  --out <FILE> \
  --aad-file-id <UUID> \
  --wrap-envelope <FILE> \
  [--key <LABEL>]
```

`--wrap-envelope` may be `-` to read from standard input. `--key` defaults to the KEM default and must be a KEM key.

Behavior. Reads the wrap envelope and verifies its algorithm, unwraps the DEK with the named KEM key in the Secure Enclave, decrypts the file, and zeroizes the DEK.

Exit codes. 0. 12 key not found. 22 input read error. 24 invalid envelope JSON. 41 unsupported algorithm in the envelope. 42 decryption failure, typically a tag mismatch, meaning the wrong key or corrupted ciphertext.

### `signet rewrap`

Re-wrap a DEK from the caller to a new recipient, used when adding a recipient to an existing share folder. The DEK is unwrapped and re-wrapped internally and never exposed.

```
signet rewrap \
  --wrap-envelope-in <FILE> \
  --to-pubkey <PUBKEY_VALUE> \
  --wrap-out <FILE> \
  [--key <LABEL>]
```

Exit codes. 0. 12 key not found. 22 input read error. 23 output write error. 24 invalid envelope JSON. 41 unsupported algorithm. 42 unwrap failure, the wrong key for the input envelope. 43 the target key rejected.

### `signet encrypt-name`

Encrypt a folder or file name under a folder's metadata key, which is unwrapped internally from the provided wrap envelope and never exposed.

```
signet encrypt-name \
  --metadata-key-wrap <FILE> \
  --root-folder-id <UUID> \
  --target-id <UUID> \
  --name <STRING> \
  [--key <LABEL>]
```

The name is UTF-8 of at most 255 bytes. The additional authenticated data is the root folder identifier followed by the target identifier, 16 bytes each.

Output, as JSON per the Envelope Format section 7.3.

```json
{
  "v": 1,
  "alg": "A256GCM",
  "iv": "<base64url>",
  "ct": "<base64url>",
  "tag": "<base64url>"
}
```

Exit codes. 0. 12 key not found. 22 input read error. 24 invalid metadata-key wrap. 25 name too long. 42 metadata key unwrap failure.

### `signet decrypt-name`

Decrypt a folder or file name using the folder's metadata key.

```
signet decrypt-name \
  --metadata-key-wrap <FILE> \
  --root-folder-id <UUID> \
  --target-id <UUID> \
  --in <FILE> \
  [--key <LABEL>]
```

Output. The decrypted name as a UTF-8 string.

Exit codes. 0. 12 key not found. 22 input read error. 24 invalid envelope JSON. 42 tag mismatch, meaning corruption or the wrong key or additional data.

### `signet attestation-verify`

Verify a server-signed attestation verification response (Envelope Format section 9). The client fetches the response from the server, or accepts one from a file or standard input, verifies the server's signature, and prints the attestation's contents.

```
signet attestation-verify --attestation-id <UUID> [--server-url <URL>]
signet attestation-verify --in <FILE>
```

Optional. `--server-pubkey <PUBKEY_VALUE>`, the server's signing public key for offline verification, otherwise fetched from `/v1/server-info` and cached. `--server-pq-pubkey <PUBKEY_VALUE>`, the server's ML-DSA-87 verification key for offline verification. Once a server post-quantum key is known, a classical-only response or receipt is rejected, and a receipt that names a post-quantum key identifier must carry a verifying ML-DSA-87 co-signature.

Behavior.

1. Fetch the verification response, from the server or from `--in`.
2. Fetch the server's signing key for the response's key identifier, from `/v1/server-info` or the local cache.
3. Verify the response signature over the canonical bytes, per the Envelope Format section 9 (RFC 8785).
4. Verify each inline log receipt per the Envelope Format section 10a. The receipt's own server signature is checked, since the response signature does not cover the receipts, and its binding to the attested key is checked, by fingerprint and purpose. A present but invalid receipt is exit 60.
5. On a signature failure in step 3, re-fetch `/v1/server-info` once before exiting with 13, which covers a key rotation between the cache and the response.
6. Print the attestation's contents.

**From epoch 2, online.** The command anchors the server's epoch before it fetches the response, and a response whose receipts name another epoch causes one re-anchor. The receipts must also carry the subject's VRF index, equal to the index recomputed from the pinned epoch key, the subject's account identifier and the proof carried inside the signed object. `receipt_binding` reports `index` when the binding was by index and `attestation` when it was the attestation's own, which is the epoch 1 case and the offline case.

Output, as JSON.

```json
{
  "valid": true,
  "subject_account_id": "<UUID>",
  "subject_handle": "<handle>",
  "subject_signing_pubkey_fingerprint": "<hex>",
  "subject_kem_pubkey_fingerprint": "<hex>",
  "expires_at": <unix seconds or null>,
  "status": "active",
  "prsn_sharing_capability": "<none|read_only|read_write>",
  "transparency": "<verified|partial|absent>",
  "receipt_binding": "<index|attestation>"
}
```

When invalid, the object carries `"valid": false`, a machine-readable `reason` and `details`.

Exit codes. 0 valid and active. 13 invalid server signature. 14 attestation expired. 15 attestation revoked. 24 malformed response. 31 server unreachable. 60 the server's key is not trusted or not in the log, or, from epoch 2, a receipt under another account's index or a proof that does not verify. 62 online in an epoch of 2 or later that cannot be anchored, with nothing bound, or `epoch_changed`.

### `signet transparency-verify`

Verify that a key is in the public transparency log, bound to that key, against the log's public anchor. With `--self`, watch the log for every key logged under this account.

```
signet transparency-verify --fingerprint <HEX> --purpose <signing|kem|signing_pq|kem_pq> [--published-root <HEX> --published-size <N>] [--anchor-repo <OWNER/REPO>]
signet transparency-verify --inclusion-proof <FILE> --published-root <HEX> --published-size <N>
signet transparency-verify --self [--key <LABEL>] [--anchor-repo <OWNER/REPO>]
```

**The anchor.** The public files `roots.jsonl` and `vrf-keys.jsonl` in the server's anchor repository, read from `raw.githubusercontent.com` with no credential. The client maps the servers it knows to their repositories, and a self-run server names its own with `--anchor-repo` or `SIGNET_ANCHOR_REPO`. The server's own report of its last committed root is never the anchor. With `--published-root` and `--published-size`, that root is the anchor, and the proof-file form runs offline against it.

**Checks, in order.**

1. The epoch the server serves, against the files. An epoch the files do not carry yet is `unanchored` for up to fifteen minutes from this client's first sighting, then a violation. A server below an epoch this client has already anchored is a violation, which is the ratchet. A new epoch's genesis must bind the previous epoch's end line and the epoch's VRF key.
2. The leaf, recomputed from the served entry and bound to the asked fingerprint and purpose before anything else.
3. Inclusion over the recomputed leaf, then the proof's root against the latest published root of the epoch, by equality or by an RFC 6962 consistency proof.

The epoch is anchored first, and the proof and the consistency proof are then read at it, so a cut between the reads is a refusal and one re-anchor, never a proof from one epoch judged under another.

**`--self`, the owner's watch.** Scans the epoch's published prefix, requires the Merkle root over the recomputed leaves to equal the published root, so that no entry can be left out of the scan, and reports every key logged under this account's VRF index, each marked `held` by whether this client's keystore holds it. Epoch 1 has no index, so `--self` exits 62 there.

Output, as JSON. `valid` is true only when the inclusion holds and is anchored, with `published_root_status` of `match` or `consistent_advance`. `inclusion_holds` says what was proven either way, and `unanchored_reason` names why when there is no anchor. A proof from an ended epoch reports `published_root_status` of `epoch_retired` with that epoch's final size and root, and `matches_epoch_end` says whether the proof's root equals the published end line. `--self` prints a `verdict` of `clean`, `foreign_key` or `not_yet_published`, the `epoch`, the counts scanned and published, and the keys found.

Exit codes. 0 valid and anchored, or an `epoch_retired` answer, or `--self` clean. 13 the proof does not verify. 24 the server did not serve the stored entry, so the leaf cannot be bound. 31 network error. 60 a TRANSPARENCY VIOLATION, which is a leaf that does not recompute or belongs to another key, a root that neither matches nor extends the published one, a broken epoch rule, or under `--self` a key under this account's index that this client does not hold. 62 `unanchored` or `epoch_changed`.

### `signet audit`

Fetch audit log events since a given event, for a PRSN harness catching up at session entry.

```
signet audit [--key <LABEL>] [--since <EVENT_ID>] [--limit <N>] [--server-url <URL>]
```

Without `--since`, the most recent `N` events are returned, with `--limit` defaulting to 100. The harness may persist the last-seen event identifier locally and pass it as `--since` for cursor-precise polling. The server keeps no cursor.

Output. One JSON event per line.

```json
{"event_id": "<UUID>", "event_type": "share_recipient_added_to_my_folder", "event_time": "<RFC3339>", "target_resource_id": "<UUID>", "target_resource_type": "folder", "event_data": {...}}
```

Exit codes. 0. 13, 14 or 15 authentication errors. 31 network error.

### `signet rand`

CSPRNG output for nonces and random bytes.

```
signet rand --hex <NUM_BYTES>
signet rand --base64url <NUM_BYTES>
signet rand --bytes <NUM_BYTES>
```

At most 1 MiB, and a larger request is exit 2. Output has no trailing newline.

### `signet base64url-no-pad`

Encode and decode base64url without padding (RFC 4648, section 5).

```
signet base64url-no-pad encode [--in <FILE>]
signet base64url-no-pad decode [--in <FILE>]
```

Exit codes. 0. 22 input error. 24 invalid input on decode.

### `signet update`

Check for a newer version and report it. The client never rewrites or installs itself. Updating is a human action.

```
signet update [--check-only] [--server-url <URL>] [--json]
```

Behavior. Fetch `<server_base_url>/cli/latest-version`, compare to the running version, and when newer, report it and direct the human to re-run the installer.

With `--json`, the output carries `current_version`, `latest_version`, `newer_available` and `how_to_update`.

Exit codes. 0 up to date. 8 newer available, which is informational. 31 network error.

### `signet version`

```
signet version [--json]
```

Prints the version, build date, commit and platform, as one line or as JSON.

### `signet keys list`

```
signet keys list [--json]
```

Lists every key label on this host with its purpose, algorithm, storage and fingerprint, as a table or as JSON. A hybrid identity lists four keys.

### `signet keys delete`

```
signet keys delete --label <HANDLE> [--purpose signing|kem|signing-pq|kem-pq] [--force]
```

Here `--label` takes the PRSN handle, such as `hlin-ai`, not a full label, and `--purpose` selects which of the handle's keys to delete. Omitting `--purpose` deletes every key the handle holds. Without `--force`, the command prompts. With `--force` and a sweep that matches more than one key, `--confirm-delete-both` is also required, since deleting a PRSN's key identity is a serious action.

Exit codes. 0 deleted. 1 the prompt was declined. 2 a multi-key sweep without the confirmation flag. 12 key not found. 21 filesystem error.

### `signet help`

```
signet help [<subcommand>]
signet --help
```

## Drive-management surface

These commands bring the client to functional parity with the human web client for folder and file management and sharing. They introduce no new cryptography. They orchestrate the existing primitives, name encryption, the metadata-key and DEK wraps, and re-wrapping, over signed HTTP and the multipart transport.

### Conventions for this surface

- **Grouped noun-verb.** `signet folder|file|share <verb>` for management, and flat `whoami`, `quota` and `recipient` for reads.
- **Name and path addressing, with the identifier as the precision fallback.** Folders and files are addressed by path, resolved client-side, because the server cannot read end-to-end encrypted names. Every addressing command also accepts `--folder-id` or `--file-id`, and for files `--root-folder-id`. Names are not unique, since the zero-knowledge server cannot enforce uniqueness, and a path segment that matches more than one entry is a collision, exit 2, with the candidates' identifiers listed so the caller can pass one.
- **Name decryption on `list`.** The server returns encrypted names. The client fetches the hierarchy root's metadata key and decrypts each entry, caching the key per root within one invocation. This needs both `--key`, the signing key for authentication, and `--kem-key`, for the metadata key.
- **Keys.** Every server-bound command takes `[--key <signing>]` and, where cryptography is involved, `[--kem-key <kem>]`, defaulting to the configured defaults. All accept `--server-url`.
- **Output.** JSON by default. `list` commands are tabular by default with `--json` for the structured form. Secrets never appear on the command line, and all key material flows through the keystore.
- **Exit codes** reuse the documented ranges. Resolver collisions and misses are 2. A recipient or Guardian fingerprint mismatch is 60. Authentication is 10 to 19, with HTTP 401 as 10 and HTTP 403 as 17. HTTP 404 is 26 and HTTP 409 is 27. Server and network errors are 30 to 39.

### Account reads

`signet whoami [--key <LABEL>]` prints the authenticated account's identity, `account_id`, `account_type` and `handle`, and for a PRSN its `prsn_sharing_capability` and its Guardian's handle.

`signet quota [--key <LABEL>]` prints `bytes_used`, `bytes_quota` and `bytes_available`, the quota being Guardian-pooled.

`signet recipient <handle> [--key <LABEL>]` resolves a handle to its verified KEM public key, for out-of-band checking and as the resolution `share invite` reuses. It reads `GET /v1/recipients/{handle}`, requires the key to match its stated fingerprint before the key is surfaced, and from epoch 2 verifies the account's VRF proof and reports the `epoch` and `account_index`. Output is `handle`, `account_type`, `kem_pubkey`, `kem_pubkey_fingerprint`, and from epoch 2 the index fields. Exit 60 on a fingerprint mismatch, which is a possible key substitution.

### `signet folder`

All take `[--key] [--kem-key]`.

- `create (<path> | --name <N> [--parent-id <ID> [--root-folder-id <ID>]])`. A top-level folder mints a fresh metadata key, wrapped to its owner, and binds its name to its own identifier. A nested folder reuses its root's key. A PRSN can create only nested folders, since a PRSN's top-level folders are share folders made with `signet share create`.
- `list [<path> | --parent-id <ID>]`. The folders under the path, or the top level, with names decrypted.
- `rename (<path> | --folder-id <ID> [--root-folder-id <ID>]) --name <NEW>`. Re-encrypts the name under the folder's root key.
- `move (<path> | --folder-id <ID>) (--to <dest-path> | --to-parent-id <ID>)`. Moves under a new parent within the same root, which the server enforces. No name re-encryption, since the additional data binds the root and the identifier, both unchanged.
- `delete (<path>... | --folder-id <ID>...)`. Deletes one or many. Children and files cascade server-side.

### `signet file`

All take `[--key] [--kem-key]`.

- `upload [DEST-PATH] --in <FILE>`, or `--in <FILE> (--to <folder-path> | --folder-id <ID> [--root-folder-id <ID>]) --name <N>`, optionally `--chunk-size <BYTES>`. Uploads through the multipart direct-to-storage transport, where the API issues pre-signed URLs and is never in the byte path. A fresh DEK seals each chunk and is wrapped to the owner, and the name is encrypted under the folder's metadata key. Output is `file_id`, `folder_id`, `plaintext_bytes` and `chunk_count`. Each part transfer runs with stall detection and retries on a fresh connection up to a server-tuned budget, with retries announced on standard error as counts only. An exhausted budget pauses the upload with exit 32, and re-running the same command resumes from the parts storage already holds.
- `download (<path> | --file-id <ID>) --out <FILE>`. Fetches and decrypts, reading each chunk by range and streaming to disk.
- `list (<folder-path> | --folder-id <ID> [--root-folder-id <ID>])`. A folder's files with names decrypted, as rows of `name`, `file_id`, `size_bytes`, `created_at` and `modified_at`, where `size_bytes` is the stored ciphertext size.
- `rename (<path> | --file-id <ID> --root-folder-id <ID>) --name <NEW>`.
- `move (<path> | --file-id <ID>) (--to <dest-folder-path> | --to-folder-id <ID>)`. Within the same root.
- `delete (<path>... | --file-id <ID>...)`.

### `signet share`

Sharing is per top-level share folder. Initiating a share, with `create` or `invite`, is capability-gated for a PRSN. The server enforces the owner's `prsn_sharing_capability`, which is `none`, `read_only` or `read_write`, and refuses cleanly when the PRSN may not issue the requested permission. Receiving a share, with `preview`, `accept`, `list` and download, is not gated. All take `[--key]`, and the commands that touch keys also take `[--kem-key]`.

- `create [NAME]`, or `--name <N>`. Creates a top-level share folder. Mints a metadata key, wraps it to the owner and, for a PRSN owner, to the Guardian, who is the mandatory recipient, resolved and fingerprint-verified, encrypts the name, and posts. From epoch 2 the Guardian's key is bound to the Guardian's VRF index.
- `list`. The share folders shared with the caller, with names decrypted through the caller's own metadata-key wrap. A name that cannot be decrypted lists as `null` and never hides the rest.
- `recipients (<path> | --folder-id <ID>)`. A share folder's recipients, with `handle`, `permission`, `is_mandatory_guardian` and `recipient_account_id`.
- `invite (<path> | --folder-id <ID> [--root-folder-id <ID>]) --to <handle> [--permission read_only|read_write]`. Resolves and verifies the recipient's KEM key, wraps the folder's metadata key to them, and re-wraps every file's DEK under the folder tree to them, with the DEK never leaving the process, then posts the pre-computed wraps as one invitation. The one-time link is shown once, at `invite`. A lost link is a cancel and a new invitation, since the token is never served again. A pending invitation write-locks its folder until it is accepted or cancelled.
- `invitations (<path> | --folder-id <ID>)`. The folder's pending invitations, with recipient, permission, expiry and identifier.
- `cancel-invite --invitation-id <ID>`. The owner cancels a pending invitation. The row is deleted, so the link dies and the folder's writes resume by construction.
- `preview --token <T>`. Previews an invitation addressed to the caller, with `inviter_handle`, `permission`, `file_count`, `expires_at` and `accepted_at`, and never the folder or file names.
- `accept --token <T>`. Accepts. The server activates the pre-staged wraps in one transaction. Output is `share_folder_id`, `permission` and `files_granted`.
- `remove (<path> | --folder-id <ID>) --recipient-id <ACCOUNT_ID>`. The owner removes a recipient. The mandatory Guardian cannot be removed.
- `leave (<path> | --folder-id <ID>)`. A recipient removes themselves, typically by `--folder-id` from `share list`, since a folder shared with them is not in their own tree to resolve by path. The mandatory Guardian cannot leave.

The whole surface is exercised end to end without a browser by two attested PRSNs under one Guardian. One creates a share, uploads a file, and invites the other. The other previews, accepts, lists, and downloads, with the bytes identical, including a file in a subfolder, which proves the recursive re-wrap.

## Cross-cutting concerns

### Per-request signing, the hybrid dual

Every authenticated API command signs its requests per the Envelope Format section 6.2. When the identity holds a post-quantum signing key, which every account enrolled through the four-key ceremony does, the client emits the dual signature, the fixed-width concatenation of the raw ES256 `r||s` (64 bytes) and the ML-DSA-87 signature (4627 bytes), 4691 bytes in all, base64url in the `Signet-Signature` header, both halves over the identical canonical bytes, with the ML-DSA half under the FIPS 204 context `signet:req:v1`. A two-key identity keeps signing classically. There is no command-surface change. The switch is a per-request keystore probe. A hybrid-attested account's classical request is refused by the server with `401 dual_signature_required`, which means the local keystore lost its post-quantum half, and `signet enroll` restores it. A `signature_format_unknown` refusal on a dual signature means the server's attestation is still classical, and the four-key enrollment needs finishing.

### Sanity checks at command time

When a command takes `--key <LABEL>`, the client looks the key up by label, reads its purpose and algorithm, checks that they match the asserted purpose (so `signet sign` rejects a KEM key with exit 41), re-checks that the key's stored label matches the asserted label, and checks that the label still matches the `<prsn-handle>-<purpose>` format.

### Standard input and output

A command that accepts standard input reads it to end of file before processing. Files given with `--in` above 16 MB are streamed. Standard output is buffered and flushed at exit.

### Progress messages

With `--verbose`, progress goes to standard error at milestones, formatted `[<TIMESTAMP>] <LEVEL>: <MESSAGE>` with RFC 3339 timestamps.

### Idempotency

Local operations are inherently idempotent, with the exception that `signet sign` is non-deterministic, so the same bytes signed twice give two different valid signatures. Server-bound commands include an `Idempotency-Key` header, a UUID generated at the start of the command, so the server deduplicates retries.

### Network error handling

Server-bound commands retry transient errors, timeouts, 5xx responses and refused connections, with exponential backoff of 1, 2, 4 and 8 seconds and at most 3 retries, configurable with `--max-retries <N>`, before exiting 31. A `429 rate_limited` response's `Retry-After` is honored, and the sleep counts against the retries.

### Version drift

The client sends its version in a `Signet-Cli-Version` header on every server-bound request, and the server compares it against two thresholds.

Below the recommended version, the server adds a `Signet-Cli-Update-Recommended: true` response header, the client prints one line to standard error, `signet: A newer version is available; run 'signet update' to upgrade.`, at most once per invocation and regardless of `--quiet`, and the operation continues with its own exit code.

Below the minimum version, the server rejects the request with `400 cli_outdated`, the client prints an error naming the running and the minimum versions, and exits 16. The minimum is raised conservatively, mainly in response to security-critical fixes. Routine updates raise the recommended threshold, and emergencies raise the minimum.

## Configuration evolution

New configuration fields in future versions leave existing files valid. Unknown fields are ignored on read and defaults applied. There is no schema version field in v1, and one will be added if an incompatible change ever requires it.

## Security model

- **Keys never leave the Secure Enclave.** The client invokes the Security framework, and signing and decryption happen in the enclave. The client never sees private key bytes.
- **Apple Silicon is required in v1.** A setup-time check enforces it. Other hosts are a later release.
- **No network calls except as specified.** `signet audit`, `signet update`, `signet attestation-verify` online, `signet transparency-verify` online, which also reads the public anchor files, the drive-management commands, and the device-access commands. Every other subcommand is purely local. There is no telemetry, no error reporting service and no usage metrics.
- **The harness is a trust boundary.** The client is invoked from a PRSN's harness. If the harness is compromised, an attacker can invoke `signet sign` within the limits of the attestation's lifetime and the Guardian's revocation.
- **The user-session-unlock model.** There is no consent gesture at keygen. The protections are the enclave's non-extractability and the entitlement isolation. Key access by any process running as the macOS user is permitted while the session is unlocked, and ends when it locks.
- **DEKs and metadata keys never appear on the command line.** Sensitive material flows through wrap envelopes encrypted to the user's KEM key, never through process arguments or environment variables.
- **There is no key export.** No command exposes private key bytes. The Secure Enclave's non-extractability is the architectural floor.
