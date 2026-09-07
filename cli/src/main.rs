// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! `signet` — the Signet Drive command-line interface (CLI Spec v08).
//!
//! Thin entry point: parse args (clap), load config, open the keystore, dispatch to
//! `signet_cli::commands`, and map any error to the spec's exit code (rendering it
//! human or `--json-errors` JSON to stderr). PR1 ships the key-management surface
//! (keygen / fingerprint / pubkey / keys list / keys delete); crypto-op,
//! verification, and utility commands follow.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use clap::{Parser, Subcommand};

use signet_cli::commands;
use signet_cli::config::Config;
use signet_cli::enroll;
use signet_cli::error::CliError;
use signet_cli::host_channel;
use signet_cli::host_signer::{self, Registry};
use signet_cli::keystore::{self, Purpose};
use signet_cli::output::OutputMode;
use signet_cli::status;

#[derive(Parser)]
#[command(
    name = "signet",
    version,
    about = "Signet Drive command-line interface"
)]
struct Cli {
    /// Suppress stderr (rely on the exit code).
    #[arg(short, long, global = true)]
    quiet: bool,
    /// Human-friendly (indented) output for structured commands.
    #[arg(long, global = true)]
    pretty: bool,
    /// Emit errors as one JSON object per error on stderr.
    #[arg(long = "json-errors", global = true)]
    json_errors: bool,
    /// Override the server base URL (config `server_base_url` / `SIGNET_SERVER_URL`).
    #[arg(long = "server-url", global = true)]
    server_url: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a signing or KEM keypair (Secure Enclave / software per tier).
    Keygen {
        #[arg(long)]
        signing: bool,
        #[arg(long)]
        kem: bool,
        /// The ML-DSA-87 signing keypair (the hybrid identity's PQ half).
        #[arg(long = "signing-pq")]
        signing_pq: bool,
        /// The ML-KEM-1024 KEM keypair (the hybrid identity's PQ half).
        #[arg(long = "kem-pq")]
        kem_pq: bool,
        /// Key label `<prsn-handle>-<purpose>` (e.g. `hlin-ai-signing`).
        #[arg(long)]
        label: String,
        #[arg(long)]
        algorithm: Option<String>,
    },
    /// Output a public-key fingerprint (lowercase hex SHA-256 of DER SPKI).
    Fingerprint {
        #[arg(long)]
        signing: bool,
        #[arg(long)]
        kem: bool,
        #[arg(long)]
        key: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Output public key bytes (for the Guardian attestation wizard).
    Pubkey {
        #[arg(long)]
        signing: bool,
        #[arg(long)]
        kem: bool,
        /// The ML-DSA-87 verifying key (raw FIPS 204 bytes).
        #[arg(long = "signing-pq")]
        signing_pq: bool,
        /// The ML-KEM-1024 encapsulation key (raw FIPS 203 bytes).
        #[arg(long = "kem-pq")]
        kem_pq: bool,
        #[arg(long)]
        key: Option<String>,
        /// `x963` (default) | `der` | `pem` | `jwk`.
        #[arg(long, default_value = "x963")]
        format: String,
        /// base64url-no-pad encode raw byte output (x963/der, and PQ keys).
        #[arg(long)]
        base64url: bool,
    },
    /// Key management (list, delete).
    Keys {
        #[command(subcommand)]
        sub: KeysCommand,
    },
    /// Sign canonical bytes with a signing key (ES256), or with `--dual` the
    /// per-request hybrid dual-signature (ES256 ‖ ML-DSA-87) a hybrid account
    /// puts on the wire.
    Sign {
        #[arg(long)]
        key: Option<String>,
        #[arg(long = "input-format", default_value = "bytes")]
        input_format: String,
        #[arg(long = "output-format", default_value = "raw")]
        output_format: String,
        #[arg(long = "in")]
        input: Option<PathBuf>,
        #[arg(long = "out")]
        output: Option<PathBuf>,
        /// Emit the per-request dual: `ES256 raw r‖s (64 B) ‖ ML-DSA-87 (4627 B)`
        /// Both halves cover the identical input bytes, the ML-DSA half under
        /// the `signet:req:v1` FIPS 204 context (as the context parameter, never
        /// prepended). Exactly what a hybrid-attested account's signed requests
        /// carry; the server rejects classical-only signatures from such
        /// accounts (`dual_signature_required`). Requires this identity's
        /// `signing-pq` key; raw/base64url-raw output only (DER is a
        /// classical-signature wire form).
        #[arg(long)]
        dual: bool,
    },
    /// AES-256-GCM encrypt a file + wrap the DEK to one or more recipients.
    Encrypt {
        #[arg(long = "in")]
        input: PathBuf,
        #[arg(long = "out")]
        output: PathBuf,
        #[arg(long = "aad-file-id")]
        aad_file_id: String,
        /// base64url values legitimately begin with `-` (~1/64); allow them.
        #[arg(long = "to-pubkey", allow_hyphen_values = true)]
        to_pubkey: Vec<String>,
        /// The recipient's ML-KEM-1024 encapsulation key (base64url, 1568 B),
        /// paired 1:1 by position with --to-pubkey; every wrap is hybrid
        /// (mandatory hybrid write).
        #[arg(long = "to-pq-pubkey", allow_hyphen_values = true)]
        to_pq_pubkey: Vec<String>,
        #[arg(long = "wraps-out")]
        wraps_out: PathBuf,
    },
    /// Decrypt a file using a wrap envelope addressed to my KEM key.
    Decrypt {
        #[arg(long = "in")]
        input: PathBuf,
        #[arg(long = "out")]
        output: PathBuf,
        #[arg(long = "aad-file-id")]
        aad_file_id: String,
        #[arg(long = "wrap-envelope")]
        wrap_envelope: String,
        #[arg(long)]
        key: Option<String>,
    },
    /// Rewrap a DEK from me to a new recipient (without exposing the DEK).
    Rewrap {
        #[arg(long = "wrap-envelope-in")]
        wrap_envelope_in: String,
        /// base64url values legitimately begin with `-` (~1/64); allow them.
        #[arg(long = "to-pubkey", allow_hyphen_values = true)]
        to_pubkey: String,
        /// The recipient's ML-KEM-1024 encapsulation key (base64url, 1568 B);
        /// every re-wrap is hybrid (mandatory hybrid write).
        #[arg(long = "to-pq-pubkey", allow_hyphen_values = true)]
        to_pq_pubkey: Option<String>,
        #[arg(long = "wrap-out")]
        wrap_out: PathBuf,
        #[arg(long)]
        key: Option<String>,
    },
    /// Encrypt a folder/file name with a folder's metadata key.
    EncryptName {
        #[arg(long = "metadata-key-wrap")]
        metadata_key_wrap: String,
        #[arg(long = "root-folder-id")]
        root_folder_id: String,
        #[arg(long = "target-id")]
        target_id: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        key: Option<String>,
    },
    /// Decrypt a folder/file name.
    DecryptName {
        #[arg(long = "metadata-key-wrap")]
        metadata_key_wrap: String,
        #[arg(long = "root-folder-id")]
        root_folder_id: String,
        #[arg(long = "target-id")]
        target_id: String,
        #[arg(long = "in")]
        input: String,
        #[arg(long)]
        key: Option<String>,
    },
    /// CSPRNG output (one of --hex / --base64url / --bytes, with a byte count).
    Rand {
        #[arg(long)]
        hex: Option<usize>,
        #[arg(long)]
        base64url: Option<usize>,
        #[arg(long)]
        bytes: Option<usize>,
    },
    /// base64url-no-pad encode/decode.
    #[command(name = "base64url-no-pad")]
    Base64UrlNoPad {
        #[command(subcommand)]
        op: Base64Op,
    },
    /// Print CLI version info.
    Version {
        #[arg(long)]
        json: bool,
    },
    /// Report the broker daemon's health: whether its LaunchAgent is running, its
    /// provisioning state, and the installed version (plus the host-signer fallback when
    /// present). Local and network-free; the data source behind the menu-bar status item.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Verify a server-signed attestation verification response.
    AttestationVerify {
        #[arg(long = "attestation-id")]
        attestation_id: Option<String>,
        #[arg(long = "in")]
        input: Option<String>,
        /// base64url values legitimately begin with `-` (~1/64); allow them.
        #[arg(long = "server-pubkey", allow_hyphen_values = true)]
        server_pubkey: Option<String>,
        /// The server's ML-DSA-87 verification key (base64url raw FIPS 204
        /// bytes) for offline dual-signature verification (online it
        /// resolves from /v1/server-info automatically).
        #[arg(long = "server-pq-pubkey", allow_hyphen_values = true)]
        server_pq_pubkey: Option<String>,
    },
    /// Verify a transparency-log inclusion proof.
    TransparencyVerify {
        #[arg(long = "inclusion-proof")]
        inclusion_proof: Option<String>,
        #[arg(long)]
        fingerprint: Option<String>,
        #[arg(long)]
        purpose: Option<String>,
        /// A published root (hex) from the public roots.jsonl. Requires
        /// --published-size: a root is a snapshot at a size, and without the
        /// size the extension question cannot be asked.
        #[arg(long = "published-root", requires = "published_size")]
        published_root: Option<String>,
        /// The log_size from the same roots.jsonl line as --published-root.
        #[arg(long = "published-size", requires = "published_root")]
        published_size: Option<u64>,
    },
    /// Fetch audit-log entries since a given event_id (signed request).
    Audit {
        #[arg(long)]
        key: Option<String>,
        #[arg(long)]
        since: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: u32,
    },
    /// Check whether a newer Signet release is published (exit 8 = one is
    /// available; the menu-bar item offers the assisted update).
    Update {
        #[arg(long)]
        json: bool,
    },
    /// Remove Signet from this Mac: the reverse of the install. Stops and removes the
    /// broker daemon, the app, and the `signet` command, plus the broker login and logs.
    /// Your Secure-Enclave keys are PRESERVED (this removes the install, not your PRSN
    /// identity). Confirms first unless `--yes`. macOS only.
    Uninstall {
        /// Skip the confirmation prompt (for scripted / non-interactive removal).
        #[arg(long)]
        yes: bool,
    },
    /// Folder operations: create / list folders, addressed by path.
    Folder {
        #[command(subcommand)]
        sub: FolderCommand,
    },
    /// File operations: upload, download and list. Multipart, direct to storage.
    File {
        #[command(subcommand)]
        sub: FileCommand,
    },
    /// Share-folder operations: create / list / recipients / invite / preview /
    /// accept / remove / leave.
    Share {
        #[command(subcommand)]
        sub: ShareCommand,
    },
    /// Print the authenticated account's identity: handle, account type, and (for
    /// a PRSN) its Guardian and sharing capability. A signed `GET /v1/me`.
    Whoami {
        /// Signing key for request auth (default: config `default_signing_key`).
        #[arg(long)]
        key: Option<String>,
    },
    /// Print storage usage and quota (bytes used / quota / available). A signed
    /// `GET /v1/me/quota`; Guardian-pooled and group-scoped.
    Quota {
        /// Signing key for request auth (default: config `default_signing_key`).
        #[arg(long)]
        key: Option<String>,
    },
    /// Resolve + verify a recipient handle's KEM public key, for an
    /// out-of-band key check. A signed `GET /v1/recipients/{handle}`.
    Recipient {
        /// The recipient handle (e.g. `maren` or `some-ai`).
        handle: String,
        /// Signing key for request auth (default: config `default_signing_key`).
        #[arg(long)]
        key: Option<String>,
    },
    /// Enroll this PRSN with a Guardian's Signet account. Your human Guardian starts
    /// the enrollment from the Signet web app ("+ Add PRSN") and hands you the one-time
    /// CODE; this joins it, then keygen-into-Secure-Enclave → the human's passkey
    /// attestation. Idempotent: omit CODE to no-op when already enrolled (set
    /// SIGNET_HANDLE so I know which PRSN I am).
    Enroll {
        /// The one-time code from the web "Add PRSN" page (your human starts the
        /// enrollment there and hands it to you). Omit it if you're already enrolled;
        /// `enroll` then no-ops (needs SIGNET_HANDLE to identify you). Codes are
        /// base64url and may begin with `-`, which is accepted as-is.
        #[arg(allow_hyphen_values = true)]
        code: Option<String>,
    },
    /// Host-side delegation-channel management for containerized PRSNs.
    HostChannel {
        #[command(subcommand)]
        sub: HostChannelCommand,
    },
    /// Run the host-side signer: the per-user macOS LaunchAgent that performs
    /// Secure-Enclave crypto for containerized PRSNs. Installed and started
    /// automatically; you don't normally run this by hand. It serves the
    /// channels in `<host-signer-dir>/registry.toml` (written by `host-channel
    /// provision`) and idles until the first channel is provisioned. macOS only.
    HostSigner,
    /// Run the local Secure-Enclave broker: the mutual-TLS service that performs
    /// Secure-Enclave crypto for authorized PRSNs, loopback-only. It supersedes
    /// `host-signer`. Provisioning (issuing the broker its K2-signed identity) is a
    /// separate step; `serve` loads that identity file and runs.
    Broker {
        #[command(subcommand)]
        sub: BrokerCommand,
    },
    /// Connect this PRSN to Signet Drive. Once your guardian has authorized you from their
    /// account page, this claims your authorization by signed pickup: your attested,
    /// SE-bound key is the proof, and there is no code to enter. This is the verb for
    /// first contact. `signet device pickup` does the same thing and remains available
    /// for scripts.
    Connect {
        /// Where to write the PoP credential (defaults to a per-handle file in the config directory).
        #[arg(long)]
        credential: Option<PathBuf>,
    },
    /// This device's key operations: the broker-mediated path to hardware-held keys.
    /// Normally self-provisioning: once your guardian authorizes you, any signet use
    /// claims your credential by SIGNED pickup and acquires tokens automatically; these
    /// verbs exist for explicit provisioning + scripts.
    //
    // bug162 (S172, Chris ruled `device`): the DISPLAYED name only. The Rust variant stays
    // `Garnet` deliberately — the internal codename is unique and therefore greppable (645
    // refs in cli+server find exactly this subsystem), and the defect was never that we HAVE
    // a codename, it is that the codename leaked onto surfaces users read. `alias` is hidden
    // by default in clap, so every existing `signet garnet …` script keeps working.
    // ⚠ `device` chosen over `enclave` because non-Mac hosts (v2, ROOTS §C-2.2) use TPM 2.0,
    // which nobody calls an enclave — hardware-specific vocabulary would need renaming again
    // exactly when we port. Reverting is deleting `name = "device"`.
    #[command(name = "device", alias = "garnet")]
    Garnet {
        #[command(subcommand)]
        sub: GarnetCommand,
    },
}

/// The agent-side subcommands. `pickup` is first contact: signature-authenticated,
/// so your attested, SE-bound key IS the authentication. There is no pairing code and
/// nothing for your guardian to relay. The token verbs (`renew` / `renew-cert`) and the SE-op
/// verbs (`keygen` / `sign`) self-acquire what they need.
#[derive(Subcommand)]
enum GarnetCommand {
    /// Claim this PRSN's proof-of-possession credential by SIGNED pickup (first contact). Your
    /// guardian authorizes you from their Signet Drive account page; this signs the pickup with
    /// your attested key, generates your K4 keypair, picks up the server-issued cert, the pinned
    /// CA anchor, and access tokens, and writes the credential. The authorization is confirmed
    /// automatically: the signature is the proof. Rarely needed by hand (any signet command
    /// that needs the broker does this automatically).
    Pickup {
        /// Where to write the PoP credential (defaults to a per-handle file in the config directory).
        #[arg(long)]
        credential: Option<PathBuf>,
    },
    /// Acquire or refresh an access token. Over the agent-to-server mutual-TLS
    /// channel (presenting your K4 cert: the cert is the refresh credential), ask the server for a
    /// fresh token for an audience against your live grant, and store it in your PoP credential.
    /// Rarely needed by hand; tokens self-acquire. This exists for scripts and refresh.
    Renew {
        /// The audience: `broker` (SE ops) or `server` (account access).
        #[arg(long, default_value = "broker")]
        audience: String,
        /// The PoP credential to renew (default: `the per-handle credential file` for the active
        /// `SIGNET_HANDLE`). The token endpoint is the ingress the server advertised at pickup,
        /// carried in the credential.
        #[arg(long)]
        credential: Option<PathBuf>,
    },
    /// Refresh this PRSN's K4 client certificate before it expires. Over the
    /// agent→server mutual-TLS channel (presenting your CURRENT cert), submit a fresh CSR; the server
    /// issues a new cert (same handle, new serial) and cuts the old one, then your access tokens are
    /// re-minted against the new cert. No pairing code and no guardian re-confirm; renewal only
    /// refreshes the cert on an already-confirmed grant.
    RenewCert {
        /// The PoP credential to renew (default: `the per-handle credential file` for the active
        /// `SIGNET_HANDLE`). The cert-renewal and token routes share the ingress the server
        /// advertised at pickup, carried in the credential.
        #[arg(long)]
        credential: Option<PathBuf>,
    },
    /// Create this PRSN's Secure-Enclave keypair via the local broker (the broker performs the keygen
    /// in the host SE for your authenticated handle; you never touch the SE). The broker token
    /// self-acquires when absent; nothing to run first.
    Keygen {
        /// The signing keypair (ES256).
        #[arg(long)]
        signing: bool,
        /// The KEM keypair (ECDH P-256).
        #[arg(long)]
        kem: bool,
        /// Override the default algorithm for the chosen purpose.
        #[arg(long)]
        algorithm: Option<String>,
        /// The local broker's loopback address.
        #[arg(long, default_value = "127.0.0.1:8765")]
        broker: SocketAddr,
        /// The PoP credential (default: `the per-handle credential file` for `SIGNET_HANDLE`).
        #[arg(long)]
        credential: Option<PathBuf>,
    },
    /// Sign a message with this PRSN's Secure-Enclave signing key via the local broker. Same
    /// input/output formats as `signet sign`; the broker returns the raw `r‖s` ES256 signature.
    Sign {
        #[arg(long = "input-format", default_value = "bytes")]
        input_format: String,
        #[arg(long = "output-format", default_value = "raw")]
        output_format: String,
        #[arg(long = "in")]
        input: Option<PathBuf>,
        #[arg(long = "out")]
        output: Option<PathBuf>,
        /// The local broker's loopback address.
        #[arg(long, default_value = "127.0.0.1:8765")]
        broker: SocketAddr,
        /// The PoP credential (default: `the per-handle credential file` for `SIGNET_HANDLE`).
        #[arg(long)]
        credential: Option<PathBuf>,
    },
}

/// The Secure-Enclave broker subcommands: `provision` (obtain the broker's K2-signed identity) then
/// `serve` (load that identity file + run the listener). Health lives in `signet status`.
#[derive(Subcommand)]
enum BrokerCommand {
    /// Provision the broker's K2-signed identity (K3 + K_bc) from a guardian-minted code and write
    /// its credential file. Your human Guardian opens broker provisioning from their Signet account
    /// and hands you the one-time CODE; this generates the broker's keys, drives the server's
    /// provision endpoint, and writes the `BrokerCredential` `serve` loads. Note this code is for
    /// the BROKER only. You never need one to claim your own access, which is signature-proved.
    Provision {
        /// The one-time provisioning code the guardian minted (they hand it to the
        /// install). Codes are base64url and may begin with `-`; accepted as-is.
        #[arg(allow_hyphen_values = true)]
        code: String,
        /// Where to write the broker's identity credential (the file `serve --credential` loads).
        /// Defaults to the canonical broker credential path the LaunchAgent reads.
        #[arg(long)]
        credential: Option<PathBuf>,
    },
    /// Start the broker listener from its provisioned identity file and serve until killed.
    Serve {
        /// Path to the broker's identity credential (the `BrokerCredential` file from provisioning).
        /// Defaults to the canonical broker credential path (what the LaunchAgent passes).
        #[arg(long)]
        credential: Option<PathBuf>,
        /// The loopback address to bind. The broker MUST be loopback-only (it is never routable;
        /// the zero-access-under-server-compromise invariant rests on its inbound unreachability).
        #[arg(long, default_value = signet_cli::broker::DEFAULT_BROKER_BIND)]
        bind: SocketAddr,
        /// Use a software keystore at this directory instead of the host Secure Enclave (dev/CI;
        /// the production broker uses the device SE for the PRSN keys it operates).
        #[arg(long)]
        software_keystore: Option<PathBuf>,
    },
}

/// File operations. `upload`/`download` re-homed from the former flat `signet
/// upload`/`signet download`, now also path-addressable (`--to` / a file path);
/// `list` decrypts names. The transport crypto impls are unchanged.
#[derive(Subcommand)]
enum FileCommand {
    /// Upload a file via the multipart transport, direct to storage.
    Upload {
        /// Destination file path (e.g. /Finance/report.pdf): the last segment is
        /// the new file's name, the rest is the destination folder. Or use
        /// --to/--folder-id + --name.
        path: Option<String>,
        #[arg(long = "in")]
        input: PathBuf,
        /// Destination folder path (e.g. /Finance): one of <path> / --to / --folder-id.
        #[arg(long = "to")]
        to: Option<String>,
        /// Destination folder id (the precision fallback for --to).
        #[arg(long = "folder-id")]
        folder_id: Option<String>,
        /// The folder hierarchy's root (with --folder-id; defaults to --folder-id for a top-level folder).
        #[arg(long = "root-folder-id")]
        root_folder_id: Option<String>,
        /// The new file's name (with --to/--folder-id; <path> carries it in its last segment).
        #[arg(long)]
        name: Option<String>,
        /// Per-chunk plaintext size in bytes (default 16 MiB).
        #[arg(long = "chunk-size")]
        chunk_size: Option<usize>,
        /// Signing key for request auth (default: config `default_signing_key`).
        #[arg(long)]
        key: Option<String>,
        /// KEM key for the DEK self-wrap (default: config `default_kem_key`).
        #[arg(long = "kem-key")]
        kem_key: Option<String>,
    },
    /// Download and decrypt a file to disk.
    Download {
        /// File path to download (e.g. /Finance/report.pdf): one of <path> / --file-id.
        path: Option<String>,
        /// File id (the precision fallback for <path>).
        #[arg(long = "file-id")]
        file_id: Option<String>,
        #[arg(long = "out")]
        output: PathBuf,
        /// Signing key for request auth (default: config `default_signing_key`).
        #[arg(long)]
        key: Option<String>,
        /// KEM key for the DEK unwrap (default: config `default_kem_key`).
        #[arg(long = "kem-key")]
        kem_key: Option<String>,
    },
    /// List the files in a folder, decrypting each name.
    List {
        /// Folder path whose files to list (e.g. /Finance/Q3).
        path: Option<String>,
        /// Folder id (the precision fallback for <folder-path>).
        #[arg(long = "folder-id")]
        folder_id: Option<String>,
        /// The folder's root (with --folder-id; defaults to --folder-id for a top-level folder).
        #[arg(long = "root-folder-id")]
        root_folder_id: Option<String>,
        /// Machine-readable JSON instead of a table.
        #[arg(long)]
        json: bool,
        /// Signing key for request auth (default: config `default_signing_key`).
        #[arg(long)]
        key: Option<String>,
        /// KEM key for the metadata-key decap (default: config `default_kem_key`).
        #[arg(long = "kem-key")]
        kem_key: Option<String>,
    },
    /// Rename a file (re-encrypts its name under the folder's root key).
    Rename {
        /// File path. Or use --file-id --root-folder-id.
        path: Option<String>,
        #[arg(long = "file-id")]
        file_id: Option<String>,
        /// The file's root (required with --file-id).
        #[arg(long = "root-folder-id")]
        root_folder_id: Option<String>,
        /// The new name.
        #[arg(long)]
        name: String,
        #[arg(long)]
        key: Option<String>,
        #[arg(long = "kem-key")]
        kem_key: Option<String>,
    },
    /// Move a file into another folder (same root only).
    Move {
        /// File path to move. Or use --file-id.
        path: Option<String>,
        #[arg(long = "file-id")]
        file_id: Option<String>,
        /// Destination folder path. Or use --to-folder-id.
        #[arg(long)]
        to: Option<String>,
        #[arg(long = "to-folder-id")]
        to_folder_id: Option<String>,
        #[arg(long)]
        key: Option<String>,
        #[arg(long = "kem-key")]
        kem_key: Option<String>,
    },
    /// Delete one or more files.
    Delete {
        /// File paths to delete.
        paths: Vec<String>,
        /// File ids to delete (repeatable; precision fallback).
        #[arg(long = "file-id")]
        file_id: Vec<String>,
        /// Skip the confirmation prompt (required for non-interactive / scripted
        /// use: deletes are permanent; there is no trash).
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        key: Option<String>,
        #[arg(long = "kem-key")]
        kem_key: Option<String>,
    },
}

/// Folder operations: create / list / rename / move / delete, path-addressed.
#[derive(Subcommand)]
enum FolderCommand {
    /// List folders under a path (top-level when omitted), decrypting each name.
    List {
        /// Folder path whose children to list (e.g. /Finance). Omit for top-level.
        path: Option<String>,
        /// Parent folder id (the precision fallback for <path>).
        #[arg(long = "parent-id")]
        parent_id: Option<String>,
        /// Machine-readable JSON instead of a table.
        #[arg(long)]
        json: bool,
        /// Signing key for request auth (default: config `default_signing_key`).
        #[arg(long)]
        key: Option<String>,
        /// KEM key for the metadata-key decap (default: config `default_kem_key`).
        #[arg(long = "kem-key")]
        kem_key: Option<String>,
    },
    /// Create a private folder (top-level) or a nested subfolder.
    Create {
        /// New folder path; the last segment is the new name, the rest is the parent
        /// (e.g. /Finance/Q3). A single segment creates a top-level folder.
        path: Option<String>,
        /// Parent folder id (precision fallback; pair with --name). Omit for top-level.
        #[arg(long = "parent-id")]
        parent_id: Option<String>,
        /// The parent's root (with --parent-id; defaults to --parent-id for a top-level parent).
        #[arg(long = "root-folder-id")]
        root_folder_id: Option<String>,
        /// New folder name (with --parent-id, or to create a top-level folder by name).
        #[arg(long)]
        name: Option<String>,
        /// Signing key for request auth (default: config `default_signing_key`).
        #[arg(long)]
        key: Option<String>,
        /// KEM key for the metadata-key wrap (default: config `default_kem_key`).
        #[arg(long = "kem-key")]
        kem_key: Option<String>,
    },
    /// Rename a folder (re-encrypts its name).
    Rename {
        /// Folder path. Or use --folder-id [--root-folder-id].
        path: Option<String>,
        #[arg(long = "folder-id")]
        folder_id: Option<String>,
        /// The folder's root (with --folder-id; defaults to --folder-id for a top-level folder).
        #[arg(long = "root-folder-id")]
        root_folder_id: Option<String>,
        /// The new name.
        #[arg(long)]
        name: String,
        #[arg(long)]
        key: Option<String>,
        #[arg(long = "kem-key")]
        kem_key: Option<String>,
    },
    /// Move a folder under a new parent (same root only).
    Move {
        /// Folder path to move. Or use --folder-id.
        path: Option<String>,
        #[arg(long = "folder-id")]
        folder_id: Option<String>,
        /// Destination parent folder path. Or use --to-parent-id.
        #[arg(long)]
        to: Option<String>,
        #[arg(long = "to-parent-id")]
        to_parent_id: Option<String>,
        #[arg(long)]
        key: Option<String>,
        #[arg(long = "kem-key")]
        kem_key: Option<String>,
    },
    /// Delete one or more folders (children cascade).
    Delete {
        /// Folder paths to delete.
        paths: Vec<String>,
        /// Folder ids to delete (repeatable; precision fallback).
        #[arg(long = "folder-id")]
        folder_id: Vec<String>,
        /// Skip the confirmation prompt (required for non-interactive / scripted
        /// use: deletes are permanent, children cascade; there is no trash).
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        key: Option<String>,
        #[arg(long = "kem-key")]
        kem_key: Option<String>,
    },
}

/// Share-folder operations. `create` makes a top-level share folder (a PRSN's
/// folders are all share folders); list/recipients/preview/accept/remove/leave are
/// the thin recipient + management surface; `invite` recursively re-wraps each
/// file's DEK to the recipient.
#[derive(Subcommand)]
enum ShareCommand {
    /// Create a top-level share folder (Guardian auto-wrapped for a PRSN owner).
    Create {
        /// The share folder's name (top-level, so its path IS its name: e.g.
        /// `Projects` or `/Projects`). Or use --name.
        path: Option<String>,
        /// The share folder's name (the flag form of <path>).
        #[arg(long)]
        name: Option<String>,
        /// Signing key for request auth (default: config `default_signing_key`).
        #[arg(long)]
        key: Option<String>,
        /// KEM key for the metadata-key wrap (default: config `default_kem_key`).
        #[arg(long = "kem-key")]
        kem_key: Option<String>,
    },
    /// List the share folders shared with me (names decrypted).
    List {
        /// Machine-readable JSON instead of the table.
        #[arg(long)]
        json: bool,
        #[arg(long)]
        key: Option<String>,
        #[arg(long = "kem-key")]
        kem_key: Option<String>,
    },
    /// List a share folder's recipients (handles, permissions, the mandatory Guardian).
    Recipients {
        /// Share folder path (e.g. /Shared): one of <path> / --folder-id.
        path: Option<String>,
        /// Share folder id (precision fallback for <path>).
        #[arg(long = "folder-id")]
        folder_id: Option<String>,
        /// Machine-readable JSON instead of the table.
        #[arg(long)]
        json: bool,
        #[arg(long)]
        key: Option<String>,
        #[arg(long = "kem-key")]
        kem_key: Option<String>,
    },
    /// Preview an invitation by token (inviter, permission, file count, timing).
    Preview {
        /// The single-use invitation token (delivered out-of-band).
        #[arg(long)]
        token: String,
        /// Signing key for request auth (default: config `default_signing_key`).
        #[arg(long)]
        key: Option<String>,
    },
    /// Accept an invitation by token (activates the pre-staged wraps).
    Accept {
        /// The single-use invitation token (delivered out-of-band).
        #[arg(long)]
        token: String,
        /// Signing key for request auth (default: config `default_signing_key`).
        #[arg(long)]
        key: Option<String>,
    },
    /// List a share folder's PENDING invitations (owner view: recipient,
    /// permission, expiry, id). A pending invitation write-locks the folder;
    /// its one-time link is shown only once, at `invite`.
    Invitations {
        /// Share folder path: one of <path> / --folder-id.
        path: Option<String>,
        /// Share folder id (precision fallback for <path>).
        #[arg(long = "folder-id")]
        folder_id: Option<String>,
        /// Machine-readable JSON instead of the table.
        #[arg(long)]
        json: bool,
        #[arg(long)]
        key: Option<String>,
        #[arg(long = "kem-key")]
        kem_key: Option<String>,
    },
    /// Cancel a PENDING invitation (owner action): the folder's writes resume
    /// and the invitation's one-time link stops working.
    CancelInvite {
        /// Share folder path: one of <path> / --folder-id.
        path: Option<String>,
        /// Share folder id (precision fallback for <path>).
        #[arg(long = "folder-id")]
        folder_id: Option<String>,
        /// The invitation to cancel (from `share invitations`).
        #[arg(long = "invitation-id")]
        invitation_id: String,
        #[arg(long)]
        key: Option<String>,
        #[arg(long = "kem-key")]
        kem_key: Option<String>,
    },
    /// Remove a recipient from a share folder (owner action).
    Remove {
        /// Share folder path: one of <path> / --folder-id.
        path: Option<String>,
        /// Share folder id (precision fallback for <path>).
        #[arg(long = "folder-id")]
        folder_id: Option<String>,
        /// The recipient's account id (from `share recipients`).
        #[arg(long = "recipient-id")]
        recipient_id: String,
        #[arg(long)]
        key: Option<String>,
        #[arg(long = "kem-key")]
        kem_key: Option<String>,
    },
    /// Leave a share folder shared with me (recipient self-removal).
    Leave {
        /// Share folder path: one of <path> / --folder-id (recipients use --folder-id).
        path: Option<String>,
        /// Share folder id (precision fallback for <path>).
        #[arg(long = "folder-id")]
        folder_id: Option<String>,
        #[arg(long)]
        key: Option<String>,
        #[arg(long = "kem-key")]
        kem_key: Option<String>,
    },
    /// Invite a recipient to a share folder (recursively re-wraps each file's DEK to
    /// them). PRSN-initiated sharing is capability-gated (server-enforced).
    Invite {
        /// Share folder path: one of <path> / --folder-id.
        path: Option<String>,
        /// Share folder id (precision fallback for <path>).
        #[arg(long = "folder-id")]
        folder_id: Option<String>,
        /// Root folder id (defaults to --folder-id; a share folder is its own root).
        #[arg(long = "root-folder-id")]
        root_folder_id: Option<String>,
        /// The recipient handle to invite (e.g. `maren` or `some-ai`).
        #[arg(long)]
        to: String,
        /// Permission to grant: `read_only` (default) or `read_write`.
        #[arg(long, default_value = "read_only")]
        permission: String,
        #[arg(long)]
        key: Option<String>,
        #[arg(long = "kem-key")]
        kem_key: Option<String>,
    },
}

#[derive(Subcommand)]
enum Base64Op {
    /// Encode stdin/--in to base64url-no-pad text.
    Encode {
        #[arg(long = "in")]
        input: Option<PathBuf>,
    },
    /// Decode base64url-no-pad stdin/--in to raw bytes.
    Decode {
        #[arg(long = "in")]
        input: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum KeysCommand {
    /// List configured key labels for this host.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Delete keys by PRSN handle; `--purpose` selects one, else every key the
    /// handle holds (all four for a hybrid identity).
    Delete {
        /// The PRSN handle (e.g. `hlin-ai`); deletes its `-signing`/`-kem` (and,
        /// for a hybrid identity, `-signing-pq`/`-kem-pq`) keys.
        #[arg(long)]
        label: String,
        /// `signing` | `kem` | `signing-pq` | `kem-pq`; omit to target every
        /// purpose the handle holds.
        #[arg(long)]
        purpose: Option<String>,
        #[arg(long)]
        force: bool,
        #[arg(long = "confirm-delete-both")]
        confirm_delete_both: bool,
    },
}

/// Host-side management of the bind-mounted delegation channels that let a
/// containerized PRSN reach the host Secure Enclave (Account-and-Kit §f.7).
#[derive(Subcommand)]
enum HostChannelCommand {
    /// Provision a new channel for a containerized PRSN (run on the host, before the
    /// container's `signet enroll`): generates the secret + registers the channel +
    /// emits the bind-mount/run snippet.
    Provision {
        /// A stable channel id (default: random). Distinct from the PRSN handle.
        #[arg(long = "channel-id")]
        channel_id: Option<String>,
    },
    /// List provisioned channels (+ each one's pinned PRSN handle, if enrolled).
    List,
    /// Remove a channel: its registry entry + host-side folders (NOT the PRSN's keys
    /// or account, which are device-bound).
    Remove {
        #[arg(long = "channel-id")]
        channel_id: String,
        #[arg(long)]
        force: bool,
    },
}

fn main() {
    // A Finder/LaunchServices double-click of `signet.app` launches the binary with no
    // subcommand and no controlling terminal — clap would just error. Intercept that
    // GUI launch and run the one-time graphical self-install instead (Punch-List §1-27).
    // A terminal `signet` with no args still falls through to clap's help.
    #[cfg(target_os = "macos")]
    if signet_cli::install::is_gui_launch() {
        std::process::exit(signet_cli::install::run());
    }
    let cli = Cli::parse();
    std::process::exit(real_main(cli));
}

fn real_main(cli: Cli) -> i32 {
    let mut config = match Config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("signet error: {}: {}", e.code, e.message);
            return e.exit_code;
        }
    };
    if let Some(url) = &cli.server_url {
        config.server_base_url = url.clone();
    }
    let errors_json = cli.json_errors || config.errors_format == "json";
    let pretty = cli.pretty || config.output_format == "pretty";
    let out = OutputMode { pretty };

    match dispatch(&cli, &config, &out) {
        Ok(()) => 0,
        Err(e) => {
            render_error(&e, errors_json, cli.quiet);
            e.exit_code
        }
    }
}

/// `signet host-signer`: serve the host-delegation channels for containerized PRSNs
/// against the host Secure Enclave, then run the adaptive poll loop until launchd
/// stops it (SIGTERM). Loads the registry, or idles with zero channels if none has
/// been provisioned yet (the always-on LaunchAgent runs from install, before the first
/// `host-channel provision`). macOS-only (it needs the host SE).
fn run_host_signer() -> Result<(), CliError> {
    let dir = signet_cli::config::host_signer_dir();
    let registry = Registry::load_or_init(&dir.join("registry.toml"), &dir.join("state"))?;

    // On macOS the always-on host-signer also presents a menu-bar status item
    // (Launch-Punch-List §1-29). AppKit must own the main thread, so the serve loop
    // moves to a background thread — where it opens its own host SE keystore (the SE
    // keystore is not `Send`, so it is created in-thread) — and the menu-bar blocks
    // the main thread in `NSApplication::run` until launchd kills the process
    // (SIGTERM). Pinned-handle state is persisted on write, so an abrupt stop loses
    // nothing (graceful signal handling is a refinement, not a correctness need).
    #[cfg(target_os = "macos")]
    {
        let shutdown = std::sync::Arc::new(AtomicBool::new(false));
        let serve_shutdown = std::sync::Arc::clone(&shutdown);
        std::thread::Builder::new()
            .name("host-signer-serve".into())
            .spawn(move || {
                let keystore = match open_host_keystore() {
                    Ok(k) => k,
                    Err(e) => {
                        eprintln!("signet host-signer: host keystore unavailable: {e}");
                        return;
                    }
                };
                if let Err(e) = host_signer::run(registry, keystore.as_ref(), &serve_shutdown) {
                    eprintln!("signet host-signer: serve loop ended: {e}");
                }
            })
            .map_err(|e| CliError::new(70, "internal", format!("host-signer serve thread: {e}")))?;
        // Row-29 currency fast-follow: a best-effort, short-timeout check of the
        // configured server's /cli/latest-version before AppKit takes the main
        // thread. Never retried — offline costs ≤2s once, and the version line
        // just drops its currency suffix (menubar::latest_version_best_effort).
        let latest_version = Config::load()
            .ok()
            .and_then(|c| signet_cli::menubar::latest_version_best_effort(&c.server_base_url));
        signet_cli::menubar::run(latest_version);
        Ok(())
    }

    // Non-macOS has no host Secure Enclave (and no menu bar); keep the original
    // main-thread serve, which `open_host_keystore` rejects with a clear
    // unsupported-platform error.
    #[cfg(not(target_os = "macos"))]
    {
        let keystore = open_host_keystore()?;
        let shutdown = AtomicBool::new(false);
        host_signer::run(registry, keystore.as_ref(), &shutdown)
    }
}

/// Bug025: the CLI-side equivalent of the web's two-step delete confirmation
/// (deletes are permanent: no trash, no restore). Mirrors
/// `signet uninstall`'s guard exactly: `--yes` skips; without it a
/// non-interactive context REFUSES (an autonomous PRSN can't answer a prompt;
/// passing the flag is its deliberate confirmation), and a TTY gets a y/N
/// prompt listing the targets. Returns Ok(false) on an interactive decline.
fn confirm_delete(what: &str, targets: &[String], assume_yes: bool) -> Result<bool, CliError> {
    use std::io::IsTerminal;
    if assume_yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        return Err(CliError::invalid_args(
            "refusing to delete without confirmation in a non-interactive context. \
             Re-run with --yes (deletes are permanent; there is no trash)."
                .to_string(),
        ));
    }
    eprintln!("About to permanently delete {} {what}:", targets.len());
    for t in targets {
        eprintln!("  {t}");
    }
    eprint!("This cannot be undone. Proceed? [y/N] ");
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| CliError::invalid_args(format!("could not read confirmation: {e}")))?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes" | "YES"))
}

/// `signet uninstall`: remove the macOS install (the reverse of the graphical install).
/// macOS-only; on other platforms there is no such install to remove.
#[cfg(target_os = "macos")]
fn run_uninstall(assume_yes: bool) -> Result<(), CliError> {
    signet_cli::uninstall::run(assume_yes)
}

#[cfg(not(target_os = "macos"))]
fn run_uninstall(_assume_yes: bool) -> Result<(), CliError> {
    Err(CliError::unsupported_platform(
        "`signet uninstall` is macOS-only: there is no Signet install to remove on this \
         platform."
            .to_string(),
    ))
}

/// Dispatch `signet broker …`; `provision` (obtain the broker's K2-signed identity) and `serve`
/// (load that identity file + run the listener). `base_url`/`out` are used by `provision` only.
fn run_broker(sub: &BrokerCommand, base_url: &str, out: &OutputMode) -> Result<(), CliError> {
    match sub {
        BrokerCommand::Provision { code, credential } => {
            let credential = credential
                .clone()
                .unwrap_or_else(signet_cli::config::broker_credential_path);
            signet_cli::broker_provision::run(base_url, code, &credential, out)
        }
        BrokerCommand::Serve {
            credential,
            bind,
            software_keystore,
        } => {
            let credential = credential
                .clone()
                .unwrap_or_else(signet_cli::config::broker_credential_path);
            run_broker_serve(&credential, *bind, software_keystore.as_deref())
        }
    }
}

/// `signet broker serve`; load the provisioned credential and serve until killed (the
/// LaunchAgent owns lifecycle). On macOS with the real host Secure Enclave (the production
/// daemon path) the always-on broker also presents a menu-bar status item; the software-
/// keystore path (dev/CI) and non-macOS serve headless on the main thread.
fn run_broker_serve(
    credential: &Path,
    bind: SocketAddr,
    software_keystore: Option<&Path>,
) -> Result<(), CliError> {
    // macOS production path (real host Secure Enclave): the broker is ALWAYS-ON from install
    // (Bug030(1)/S120) and presents the menu-bar status item (liveness + version) even before
    // the first PRSN is provisioned — so a guardian can see at a glance that Signet is running.
    // AppKit must own the main thread; the crypto serve-loop (when there is a credential) runs
    // on a background thread. Dev/CI (software keystore) and non-macOS serve headless below.
    #[cfg(target_os = "macos")]
    if software_keystore.is_none() {
        return run_broker_serve_with_menubar(credential, bind);
    }

    // Headless path (dev/CI software keystore, non-macOS): no menu-bar to keep the process
    // alive, so keep the graceful no-credential exit (0) rather than erroring — an
    // unprovisioned headless broker has nothing to serve and shouldn't spam its log.
    if !credential.exists() {
        eprintln!(
            "signet broker serve: no broker credential at {} yet. Nothing to serve \
             (run `signet broker provision <CODE>` first).",
            credential.display()
        );
        return Ok(());
    }
    let cred = signet_cli::broker_credential::BrokerCredential::load(credential)?;
    let keystore = open_broker_keystore(software_keystore)?;
    let shutdown = AtomicBool::new(false);
    signet_cli::broker::serve_from_credential(&cred, bind, keystore.as_ref(), &shutdown)
}

/// The macOS production daemon path: present the menu-bar status item on the main thread from
/// install time, and (only when a credential exists) serve the crypto loop on a
/// background thread (the host SE keystore is opened in-thread, since it is not `Send`).
///
/// When the credential is absent (a fresh install, before the guardian's first PRSN), the
/// broker shows the menu-bar in a "ready; no PRSNs yet" state and does **nothing
/// security-sensitive**: no Secure Enclave is opened and no mutual-TLS listener is bound, so
/// the S1 local-only-broker property holds for a credential-less broker. `signet broker
/// provision` writes the credential and kickstarts this daemon, so it restarts here with the
/// credential present. Blocks until launchd terminates the process.
#[cfg(target_os = "macos")]
fn run_broker_serve_with_menubar(credential: &Path, bind: SocketAddr) -> Result<(), CliError> {
    // Serve the crypto loop only when a valid credential is present AND it passes the K3
    // binding self-check (bug087 fix 3). A missing credential (fresh install) is the healthy
    // "ready" state; an UNREADABLE credential or a FAILED binding check is IMPAIRED — the
    // daemon stays up (menu-bar liveness, KeepAlive=true never thrashes) but REFUSES to open
    // the listener, because a listener whose every handshake dies presents as "running" while
    // serving nothing (the bug087 lie). A broker that isn't serving does nothing
    // security-sensitive (no SE opened, no listener; S1 held).
    use signet_cli::menubar::BrokerMenuState;
    let (cred, state) = if credential.exists() {
        match signet_cli::broker_credential::BrokerCredential::load(credential) {
            Ok(c) => match c.verify_k3_binding() {
                Ok(()) => (Some(c), BrokerMenuState::Serving),
                Err(e) => {
                    eprintln!(
                        "signet broker serve: REFUSING to serve: the credential failed its \
                         K3 binding self-check: {e}"
                    );
                    (None, BrokerMenuState::Impaired)
                }
            },
            Err(e) => {
                eprintln!(
                    "signet broker serve: broker credential present but unreadable ({e}): \
                     NOT serving; re-provision with `signet broker provision <CODE>`."
                );
                (None, BrokerMenuState::Impaired)
            }
        }
    } else {
        eprintln!(
            "signet broker serve: no broker credential yet. Showing the menu-bar (ready; no \
             PRSNs). Add a PRSN with `signet broker provision <CODE>`."
        );
        (None, BrokerMenuState::Ready)
    };
    if let Some(cred) = cred {
        let shutdown = std::sync::Arc::new(AtomicBool::new(false));
        let serve_shutdown = std::sync::Arc::clone(&shutdown);
        std::thread::Builder::new()
            .name("broker-serve".into())
            .spawn(move || {
                let keystore = match open_broker_se_keystore() {
                    Ok(k) => k,
                    Err(e) => {
                        eprintln!("signet broker serve: host keystore unavailable: {e}");
                        return;
                    }
                };
                if let Err(e) = signet_cli::broker::serve_from_credential(
                    &cred,
                    bind,
                    keystore.as_ref(),
                    &serve_shutdown,
                ) {
                    eprintln!("signet broker serve: serve loop ended: {e}");
                }
            })
            .map_err(|e| CliError::new(70, "internal", format!("broker serve thread: {e}")))?;
    }
    // Best-effort currency check before AppKit takes the main thread (menubar drops the
    // currency suffix on offline/serverless). Same shape as the host-signer's row-29 check.
    // bug049: the server URL ALSO rides into run_broker so the menu can re-verify currency
    // each time it opens — this startup check is the initial state, no longer the only one.
    let server_base_url = Config::load().ok().map(|c| c.server_base_url);
    let latest_version = server_base_url
        .as_deref()
        .and_then(signet_cli::menubar::latest_version_best_effort);
    signet_cli::menubar::run_broker(server_base_url, latest_version, state);
    Ok(())
}

/// Dispatch `signet garnet …`; the agent-side Garnet use surface. `pickup` is the only command in
/// this increment (token acquisition + the SE-op commands follow). `base_url` is the deployment
/// origin reached for pickup (full public-web-PKI validation; the K2 anchor it returns cannot
/// validate its own delivery).
fn run_garnet(sub: &GarnetCommand, base_url: &str, out: &OutputMode) -> Result<(), CliError> {
    match sub {
        GarnetCommand::Pickup { credential } => {
            signet_cli::garnet::pickup_command(base_url, credential.as_deref(), out)
        }
        GarnetCommand::Renew {
            audience,
            credential,
        } => signet_cli::garnet::renew_command(audience, credential.as_deref(), out),
        GarnetCommand::RenewCert { credential } => {
            signet_cli::garnet::renew_cert_command(credential.as_deref(), out)
        }
        GarnetCommand::Keygen {
            signing,
            kem,
            algorithm,
            broker,
            credential,
        } => {
            let purpose = commands::purpose_from_flags(*signing, *kem, false, false)?;
            signet_cli::garnet::keygen_command(
                *broker,
                purpose,
                algorithm.as_deref(),
                credential.as_deref(),
                out,
            )
        }
        GarnetCommand::Sign {
            input_format,
            output_format,
            input,
            output,
            broker,
            credential,
        } => signet_cli::garnet::sign_command(
            *broker,
            input_format,
            output_format,
            input.as_deref(),
            output.as_deref(),
            credential.as_deref(),
        ),
    }
}

/// The broker's backing keystore: the host Secure Enclave (production), or a software keystore at
/// `software_keystore` (dev/CI; exercises the broker's transport plumbing without an entitled,
/// codesigned binary). The SE holds the PRSN keys the broker operates; the broker holds none itself.
fn open_broker_keystore(
    software_keystore: Option<&Path>,
) -> Result<Box<dyn keystore::Keystore + Sync>, CliError> {
    if let Some(dir) = software_keystore {
        return Ok(Box::new(keystore::SoftwareKeystore::open(
            dir.to_path_buf(),
        )?));
    }
    open_broker_se_keystore()
}

#[cfg(target_os = "macos")]
fn open_broker_se_keystore() -> Result<Box<dyn keystore::Keystore + Sync>, CliError> {
    Ok(Box::new(keystore::SecureEnclaveKeystore::open()?))
}

#[cfg(not(target_os = "macos"))]
fn open_broker_se_keystore() -> Result<Box<dyn keystore::Keystore + Sync>, CliError> {
    Err(CliError::unsupported_platform(
        "signet broker serve needs the host Secure Enclave (macOS); pass --software-keystore <dir> for dev/CI",
    ))
}

/// The host's backing keystore for `host-signer`: the native Secure Enclave directly.
/// The host-signer *is* the host SE provider for containerized PRSNs, so it uses the
/// device SE; never keystore auto-detection, which would also consider the
/// container-delegation backend.
#[cfg(target_os = "macos")]
fn open_host_keystore() -> Result<Box<dyn keystore::Keystore>, CliError> {
    Ok(Box::new(keystore::SecureEnclaveKeystore::open()?))
}

#[cfg(not(target_os = "macos"))]
fn open_host_keystore() -> Result<Box<dyn keystore::Keystore>, CliError> {
    Err(CliError::unsupported_platform(
        "signet host-signer requires macOS (the host Secure Enclave)",
    ))
}

fn dispatch(cli: &Cli, config: &Config, out: &OutputMode) -> Result<(), CliError> {
    match &cli.command {
        Command::Keygen {
            signing,
            kem,
            signing_pq,
            kem_pq,
            label,
            algorithm,
        } => {
            let purpose = commands::purpose_from_flags(*signing, *kem, *signing_pq, *kem_pq)?;
            let keystore = keystore::open(config)?;
            commands::keygen(keystore.as_ref(), label, purpose, algorithm.as_deref(), out)
        }
        Command::Fingerprint {
            signing,
            kem,
            key,
            json,
        } => {
            let purpose = commands::purpose_from_flags(*signing, *kem, false, false)?;
            let keystore = keystore::open(config)?;
            commands::fingerprint(
                keystore.as_ref(),
                key.as_deref(),
                purpose,
                *json,
                config,
                out,
            )
        }
        Command::Pubkey {
            signing,
            kem,
            signing_pq,
            kem_pq,
            key,
            format,
            base64url,
        } => {
            let purpose = commands::purpose_from_flags(*signing, *kem, *signing_pq, *kem_pq)?;
            let keystore = keystore::open(config)?;
            commands::pubkey(
                keystore.as_ref(),
                key.as_deref(),
                purpose,
                format,
                *base64url,
                config,
                out,
            )
        }
        Command::Keys { sub } => match sub {
            KeysCommand::List { json } => {
                let keystore = keystore::open(config)?;
                commands::keys_list(keystore.as_ref(), *json, out)
            }
            KeysCommand::Delete {
                label,
                purpose,
                force,
                confirm_delete_both,
            } => {
                let purpose = match purpose.as_deref() {
                    Some("signing") => Some(Purpose::Signing),
                    Some("kem") => Some(Purpose::Kem),
                    Some("signing-pq") => Some(Purpose::SigningPq),
                    Some("kem-pq") => Some(Purpose::KemPq),
                    Some(other) => {
                        return Err(CliError::invalid_args(format!(
                            "unknown --purpose '{other}' (expected signing|kem|signing-pq|kem-pq)"
                        )));
                    }
                    None => None,
                };
                let keystore = keystore::open(config)?;
                commands::keys_delete(
                    keystore.as_ref(),
                    label,
                    purpose,
                    *force,
                    *confirm_delete_both,
                )
            }
        },
        Command::HostChannel { sub } => {
            let dir = signet_cli::config::host_signer_dir();
            match sub {
                HostChannelCommand::Provision { channel_id } => {
                    host_channel::provision(&dir, channel_id.as_deref(), out)?;
                    // Reload the always-on host-signer so it serves the new channel now
                    // (best-effort — the agent is normally already running from install).
                    if host_channel::kickstart_host_signer() {
                        eprintln!("✓ host-signer reloaded. Now serving this channel.");
                    } else {
                        eprintln!(
                            "⚠ couldn't reload the host-signer automatically (is the Signet \
                             app installed and running?). It will pick up this channel on its \
                             next start, or reload it now:\n  launchctl kickstart -k \
                             gui/$(id -u)/ai.prsnex.signet.host-signer"
                        );
                    }
                    Ok(())
                }
                HostChannelCommand::List => host_channel::list(&dir, out),
                HostChannelCommand::Remove { channel_id, force } => {
                    host_channel::remove(&dir, channel_id, *force, out)
                }
            }
        }
        Command::HostSigner => run_host_signer(),
        Command::Uninstall { yes } => run_uninstall(*yes),
        Command::Broker { sub } => run_broker(sub, &config.server_base_url, out),
        // The public verb (S168): same machinery as `garnet pickup`, friendlier name.
        Command::Connect { credential } => {
            signet_cli::garnet::pickup_command(&config.server_base_url, credential.as_deref(), out)
        }
        Command::Garnet { sub } => run_garnet(sub, &config.server_base_url, out),
        Command::Sign {
            key,
            input_format,
            output_format,
            input,
            output,
            dual,
        } => {
            let keystore = keystore::open(config)?;
            commands::sign(
                keystore.as_ref(),
                key.as_deref(),
                input_format,
                output_format,
                input.as_deref(),
                output.as_deref(),
                *dual,
                config,
            )
        }
        Command::Encrypt {
            input,
            output,
            aad_file_id,
            to_pubkey,
            to_pq_pubkey,
            wraps_out,
        } => commands::encrypt(
            input,
            output,
            aad_file_id,
            to_pubkey,
            to_pq_pubkey,
            wraps_out,
            out,
        ),
        Command::Decrypt {
            input,
            output,
            aad_file_id,
            wrap_envelope,
            key,
        } => {
            let keystore = keystore::open(config)?;
            commands::decrypt(
                keystore.as_ref(),
                input,
                output,
                aad_file_id,
                wrap_envelope,
                key.as_deref(),
                config,
            )
        }
        Command::Rewrap {
            wrap_envelope_in,
            to_pubkey,
            to_pq_pubkey,
            wrap_out,
            key,
        } => {
            let keystore = keystore::open(config)?;
            commands::rewrap(
                keystore.as_ref(),
                wrap_envelope_in,
                to_pubkey,
                to_pq_pubkey.as_deref(),
                wrap_out,
                key.as_deref(),
                config,
            )
        }
        Command::EncryptName {
            metadata_key_wrap,
            root_folder_id,
            target_id,
            name,
            key,
        } => {
            let keystore = keystore::open(config)?;
            commands::encrypt_name(
                keystore.as_ref(),
                metadata_key_wrap,
                root_folder_id,
                target_id,
                name,
                key.as_deref(),
                config,
                out,
            )
        }
        Command::DecryptName {
            metadata_key_wrap,
            root_folder_id,
            target_id,
            input,
            key,
        } => {
            let keystore = keystore::open(config)?;
            commands::decrypt_name(
                keystore.as_ref(),
                metadata_key_wrap,
                root_folder_id,
                target_id,
                input,
                key.as_deref(),
                config,
                out,
            )
        }
        Command::Rand {
            hex,
            base64url,
            bytes,
        } => {
            let (format, n) = match (hex, base64url, bytes) {
                (Some(n), None, None) => ("hex", *n),
                (None, Some(n), None) => ("base64url", *n),
                (None, None, Some(n)) => ("bytes", *n),
                _ => {
                    return Err(CliError::invalid_args(
                        "specify exactly one of --hex / --base64url / --bytes",
                    ));
                }
            };
            commands::rand(format, n, out)
        }
        Command::Base64UrlNoPad { op } => match op {
            Base64Op::Encode { input } => commands::base64url_encode(input.as_deref(), out),
            Base64Op::Decode { input } => commands::base64url_decode(input.as_deref(), out),
        },
        Command::Version { json } => commands::version(*json, out),
        Command::Status { json } => status::status(*json, out),
        Command::AttestationVerify {
            attestation_id,
            input,
            server_pubkey,
            server_pq_pubkey,
        } => commands::attestation_verify(
            attestation_id.as_deref(),
            input.as_deref(),
            &config.server_base_url,
            server_pubkey.as_deref(),
            server_pq_pubkey.as_deref(),
            out,
        ),
        Command::TransparencyVerify {
            inclusion_proof,
            fingerprint,
            purpose,
            published_root,
            published_size,
        } => commands::transparency_verify(
            inclusion_proof.as_deref(),
            fingerprint.as_deref(),
            purpose.as_deref(),
            published_root.as_deref(),
            *published_size,
            &config.server_base_url,
            out,
        ),
        Command::Audit { key, since, limit } => {
            let keystore = keystore::open(config)?;
            commands::audit(
                keystore.as_ref(),
                key.as_deref(),
                since.as_deref(),
                *limit,
                &config.server_base_url,
                config,
                out,
            )
        }
        Command::Update { json } => commands::update(&config.server_base_url, *json, out),
        Command::Folder { sub } => match sub {
            FolderCommand::List {
                path,
                parent_id,
                json,
                key,
                kem_key,
            } => {
                let keystore = keystore::open(config)?;
                commands::folder_list(
                    keystore.as_ref(),
                    path.as_deref(),
                    parent_id.as_deref(),
                    *json,
                    key.as_deref(),
                    kem_key.as_deref(),
                    &config.server_base_url,
                    config,
                    out,
                )
            }
            FolderCommand::Create {
                path,
                parent_id,
                root_folder_id,
                name,
                key,
                kem_key,
            } => {
                let keystore = keystore::open(config)?;
                commands::folder_create(
                    keystore.as_ref(),
                    path.as_deref(),
                    parent_id.as_deref(),
                    root_folder_id.as_deref(),
                    name.as_deref(),
                    key.as_deref(),
                    kem_key.as_deref(),
                    &config.server_base_url,
                    config,
                    out,
                )
            }
            FolderCommand::Rename {
                path,
                folder_id,
                root_folder_id,
                name,
                key,
                kem_key,
            } => {
                let keystore = keystore::open(config)?;
                commands::folder_rename(
                    keystore.as_ref(),
                    path.as_deref(),
                    folder_id.as_deref(),
                    root_folder_id.as_deref(),
                    name,
                    key.as_deref(),
                    kem_key.as_deref(),
                    &config.server_base_url,
                    config,
                    out,
                )
            }
            FolderCommand::Move {
                path,
                folder_id,
                to,
                to_parent_id,
                key,
                kem_key,
            } => {
                let keystore = keystore::open(config)?;
                commands::folder_move(
                    keystore.as_ref(),
                    path.as_deref(),
                    folder_id.as_deref(),
                    to.as_deref(),
                    to_parent_id.as_deref(),
                    key.as_deref(),
                    kem_key.as_deref(),
                    &config.server_base_url,
                    config,
                    out,
                )
            }
            FolderCommand::Delete {
                paths,
                folder_id,
                yes,
                key,
                kem_key,
            } => {
                let mut targets: Vec<String> = paths.clone();
                targets.extend(folder_id.iter().map(|id| format!("--folder-id {id}")));
                if !confirm_delete("folder(s) (children cascade)", &targets, *yes)? {
                    eprintln!("Delete cancelled. Nothing was changed.");
                    return Ok(());
                }
                let keystore = keystore::open(config)?;
                commands::folder_delete(
                    keystore.as_ref(),
                    paths,
                    folder_id,
                    key.as_deref(),
                    kem_key.as_deref(),
                    &config.server_base_url,
                    config,
                    out,
                )
            }
        },
        Command::File { sub } => match sub {
            FileCommand::Upload {
                path,
                input,
                to,
                folder_id,
                root_folder_id,
                name,
                chunk_size,
                key,
                kem_key,
            } => {
                let keystore = keystore::open(config)?;
                commands::upload(
                    keystore.as_ref(),
                    path.as_deref(),
                    input,
                    to.as_deref(),
                    folder_id.as_deref(),
                    root_folder_id.as_deref(),
                    name.as_deref(),
                    *chunk_size,
                    key.as_deref(),
                    kem_key.as_deref(),
                    &config.server_base_url,
                    config,
                    out,
                )
            }
            FileCommand::Download {
                path,
                file_id,
                output,
                key,
                kem_key,
            } => {
                let keystore = keystore::open(config)?;
                commands::download(
                    keystore.as_ref(),
                    path.as_deref(),
                    file_id.as_deref(),
                    output,
                    key.as_deref(),
                    kem_key.as_deref(),
                    &config.server_base_url,
                    config,
                    out,
                )
            }
            FileCommand::List {
                path,
                folder_id,
                root_folder_id,
                json,
                key,
                kem_key,
            } => {
                let keystore = keystore::open(config)?;
                commands::file_list(
                    keystore.as_ref(),
                    path.as_deref(),
                    folder_id.as_deref(),
                    root_folder_id.as_deref(),
                    *json,
                    key.as_deref(),
                    kem_key.as_deref(),
                    &config.server_base_url,
                    config,
                    out,
                )
            }
            FileCommand::Rename {
                path,
                file_id,
                root_folder_id,
                name,
                key,
                kem_key,
            } => {
                let keystore = keystore::open(config)?;
                commands::file_rename(
                    keystore.as_ref(),
                    path.as_deref(),
                    file_id.as_deref(),
                    root_folder_id.as_deref(),
                    name,
                    key.as_deref(),
                    kem_key.as_deref(),
                    &config.server_base_url,
                    config,
                    out,
                )
            }
            FileCommand::Move {
                path,
                file_id,
                to,
                to_folder_id,
                key,
                kem_key,
            } => {
                let keystore = keystore::open(config)?;
                commands::file_move(
                    keystore.as_ref(),
                    path.as_deref(),
                    file_id.as_deref(),
                    to.as_deref(),
                    to_folder_id.as_deref(),
                    key.as_deref(),
                    kem_key.as_deref(),
                    &config.server_base_url,
                    config,
                    out,
                )
            }
            FileCommand::Delete {
                paths,
                file_id,
                yes,
                key,
                kem_key,
            } => {
                let mut targets: Vec<String> = paths.clone();
                targets.extend(file_id.iter().map(|id| format!("--file-id {id}")));
                if !confirm_delete("file(s)", &targets, *yes)? {
                    eprintln!("Delete cancelled. Nothing was changed.");
                    return Ok(());
                }
                let keystore = keystore::open(config)?;
                commands::file_delete(
                    keystore.as_ref(),
                    paths,
                    file_id,
                    key.as_deref(),
                    kem_key.as_deref(),
                    &config.server_base_url,
                    config,
                    out,
                )
            }
        },
        Command::Share { sub } => match sub {
            ShareCommand::Create {
                path,
                name,
                key,
                kem_key,
            } => {
                let keystore = keystore::open(config)?;
                commands::share_create(
                    keystore.as_ref(),
                    path.as_deref(),
                    name.as_deref(),
                    key.as_deref(),
                    kem_key.as_deref(),
                    &config.server_base_url,
                    config,
                    out,
                )
            }
            ShareCommand::List { json, key, kem_key } => {
                let keystore = keystore::open(config)?;
                commands::share_list(
                    keystore.as_ref(),
                    *json,
                    key.as_deref(),
                    kem_key.as_deref(),
                    &config.server_base_url,
                    config,
                    out,
                )
            }
            ShareCommand::Recipients {
                path,
                folder_id,
                json,
                key,
                kem_key,
            } => {
                let keystore = keystore::open(config)?;
                commands::share_recipients(
                    keystore.as_ref(),
                    path.as_deref(),
                    folder_id.as_deref(),
                    *json,
                    key.as_deref(),
                    kem_key.as_deref(),
                    &config.server_base_url,
                    config,
                    out,
                )
            }
            ShareCommand::Preview { token, key } => {
                let keystore = keystore::open(config)?;
                commands::share_preview(
                    keystore.as_ref(),
                    token,
                    key.as_deref(),
                    &config.server_base_url,
                    config,
                    out,
                )
            }
            ShareCommand::Accept { token, key } => {
                let keystore = keystore::open(config)?;
                commands::share_accept(
                    keystore.as_ref(),
                    token,
                    key.as_deref(),
                    &config.server_base_url,
                    config,
                    out,
                )
            }
            ShareCommand::Invitations {
                path,
                folder_id,
                json,
                key,
                kem_key,
            } => {
                let keystore = keystore::open(config)?;
                commands::share_invitations(
                    keystore.as_ref(),
                    path.as_deref(),
                    folder_id.as_deref(),
                    *json,
                    key.as_deref(),
                    kem_key.as_deref(),
                    &config.server_base_url,
                    config,
                    out,
                )
            }
            ShareCommand::CancelInvite {
                path,
                folder_id,
                invitation_id,
                key,
                kem_key,
            } => {
                let keystore = keystore::open(config)?;
                commands::share_cancel_invite(
                    keystore.as_ref(),
                    path.as_deref(),
                    folder_id.as_deref(),
                    invitation_id,
                    key.as_deref(),
                    kem_key.as_deref(),
                    &config.server_base_url,
                    config,
                    out,
                )
            }
            ShareCommand::Remove {
                path,
                folder_id,
                recipient_id,
                key,
                kem_key,
            } => {
                let keystore = keystore::open(config)?;
                commands::share_remove(
                    keystore.as_ref(),
                    path.as_deref(),
                    folder_id.as_deref(),
                    recipient_id,
                    key.as_deref(),
                    kem_key.as_deref(),
                    &config.server_base_url,
                    config,
                    out,
                )
            }
            ShareCommand::Leave {
                path,
                folder_id,
                key,
                kem_key,
            } => {
                let keystore = keystore::open(config)?;
                commands::share_leave(
                    keystore.as_ref(),
                    path.as_deref(),
                    folder_id.as_deref(),
                    key.as_deref(),
                    kem_key.as_deref(),
                    &config.server_base_url,
                    config,
                    out,
                )
            }
            ShareCommand::Invite {
                path,
                folder_id,
                root_folder_id,
                to,
                permission,
                key,
                kem_key,
            } => {
                let keystore = keystore::open(config)?;
                commands::share_invite(
                    keystore.as_ref(),
                    path.as_deref(),
                    folder_id.as_deref(),
                    root_folder_id.as_deref(),
                    to,
                    permission,
                    key.as_deref(),
                    kem_key.as_deref(),
                    &config.server_base_url,
                    config,
                    out,
                )
            }
        },
        Command::Whoami { key } => {
            let keystore = keystore::open(config)?;
            commands::whoami(
                keystore.as_ref(),
                key.as_deref(),
                &config.server_base_url,
                config,
                out,
            )
        }
        Command::Quota { key } => {
            let keystore = keystore::open(config)?;
            commands::quota(
                keystore.as_ref(),
                key.as_deref(),
                &config.server_base_url,
                config,
                out,
            )
        }
        Command::Recipient { handle, key } => {
            let keystore = keystore::open(config)?;
            commands::recipient(
                keystore.as_ref(),
                handle,
                key.as_deref(),
                &config.server_base_url,
                config,
                out,
            )
        }
        Command::Enroll { code } => {
            enroll::enroll(&config.server_base_url, code.as_deref(), config, out)
        }
    }
}

fn render_error(error: &CliError, errors_json: bool, quiet: bool) {
    // Exit code 8 ("informational — newer version available") is not a failure;
    // `update` already printed its own output, so don't render an error line.
    if error.exit_code == 8 {
        return;
    }
    if errors_json {
        let obj = serde_json::json!({
            "error": { "code": error.code, "message": error.message }
        });
        eprintln!("{obj}");
    } else if !quiet {
        eprintln!("signet error: {}: {}", error.code, error.message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `signet broker serve` with no provisioned credential exits **cleanly** (Ok) on the
    /// **headless** path; software keystore / non-macOS, where there is no menu-bar to keep
    /// the process alive; not with an error, so it doesn't spam its log. (The macOS
    /// production path is always-on and shows the menu-bar *instead* of exiting;
    /// Bug030(1)/S120; that path needs the Secure Enclave + AppKit and isn't unit-tested
    /// here.) `software_keystore = Some` selects the headless path here.
    #[test]
    fn broker_serve_with_no_credential_exits_cleanly() {
        let missing = std::path::PathBuf::from("/nonexistent/signet-broker-credential-xyz.json");
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let ks = std::path::PathBuf::from("/tmp/signet-broker-serve-test-ks");
        assert!(run_broker_serve(&missing, bind, Some(ks.as_path())).is_ok());
    }
}
