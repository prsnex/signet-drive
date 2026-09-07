// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! The host-signer's request dispatch (Account-and-Kit spec §f) — the per-op
//! execution that maps a delegated [`Op`] from a containerized PRSN onto the host
//! keystore.
//!
//! This is the *logic* of the host signer, deliberately separate from its
//! transport + lifecycle. The `signet host-signer` subcommand wires a
//! [`signet_channel::transport::ChannelServer`] per channel to [`handle_op`] and
//! runs the adaptive poll loop; this module just turns one authenticated [`Op`]
//! into a [`Response`].
//!
//! It is generic over the [`Keystore`] backend, so the full delegation round-trip
//! is testable cross-platform with the `software` backend — the production binary
//! backs it with `secure_enclave` (the host Mac's Enclave).
//!
//! **Scoping (defense in depth).** A request arrives on a specific channel, which
//! the host-side registry maps to exactly one PRSN handle. [`handle_op`] refuses
//! any label whose handle is not that PRSN's. The channel capability already stops
//! a container from reaching a *sibling's* channel ([`signet_channel`] §f.3); this
//! additionally refuses a forged cross-PRSN label dropped on a PRSN's *own*
//! channel. Key *purpose* is left to the keystore's own guards (so a delegated
//! `sign` on a KEM key returns the same `unsupported_algorithm` as the native
//! path).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::sleep;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use signet_channel::ChannelError;
use signet_channel::auth::ChannelSecret;
use signet_channel::transport::ChannelServer;
use signet_channel::wire::{KeyEntry, Op, OpErr, OpOk, Response};

use crate::error::{CliError, Result};
use crate::keystore::{KeyLabel, Keystore};

/// Execute one delegated [`Op`] against `keystore`, scoped to `prsn_handle`, and
/// produce the wire [`Response`]. Any [`CliError`] becomes an [`OpErr`] carrying
/// the stable code + message, so the in-container client can re-raise it faithfully.
pub fn handle_op(keystore: &dyn Keystore, prsn_handle: &str, op: Op) -> Response {
    match dispatch(keystore, prsn_handle, op) {
        Ok(ok) => Response::Ok(ok),
        Err(e) => Response::Err(OpErr {
            code: e.code.to_string(),
            message: e.message,
        }),
    }
}

fn dispatch(ks: &dyn Keystore, prsn_handle: &str, op: Op) -> Result<OpOk> {
    match op {
        Op::Keygen { label, algorithm } => {
            let label = scoped_label(&label, prsn_handle)?;
            let m = ks.generate(&label, &algorithm)?;
            Ok(OpOk::Keygen {
                public_key: m.public_key,
                fingerprint: m.fingerprint,
                algorithm: m.algorithm,
            })
        }
        Op::Sign { label, msg } => {
            let label = scoped_label(&label, prsn_handle)?;
            Ok(OpOk::Sign {
                signature: ks.sign(&label, &msg)?.to_vec(),
            })
        }
        Op::Ecdh {
            label,
            peer_pub_x963,
        } => {
            let label = scoped_label(&label, prsn_handle)?;
            Ok(OpOk::Ecdh {
                shared_secret: ks.ecdh(&label, &peer_pub_x963)?.to_vec(),
            })
        }
        Op::MlKemDecapsulate { label, ek } => {
            let label = scoped_label(&label, prsn_handle)?;
            // Length-exact at the wire seam (FIPS 203; the backend would fail
            // anyway — this fails fast with a nameable error).
            if ek.len() != signet_crypto::hybrid_wrap::MLKEM1024_CT_LEN {
                return Err(CliError::invalid_args(format!(
                    "ml-kem ciphertext must be {} bytes, got {}",
                    signet_crypto::hybrid_wrap::MLKEM1024_CT_LEN,
                    ek.len()
                )));
            }
            Ok(OpOk::MlKemDecapsulate {
                shared_secret: ks.ml_kem_decapsulate(&label, &ek)?.to_vec(),
            })
        }
        Op::MlDsaSign { label, msg, ctx } => {
            let label = scoped_label(&label, prsn_handle)?;
            crate::keystore::validate_mldsa_ctx(&ctx)?;
            Ok(OpOk::MlDsaSign {
                signature: ks.ml_dsa_sign(&label, &msg, &ctx)?,
            })
        }
        Op::Meta { label } => {
            let label = scoped_label(&label, prsn_handle)?;
            let m = ks.meta(&label)?;
            Ok(OpOk::Meta {
                public_key: m.public_key,
                fingerprint: m.fingerprint,
                algorithm: m.algorithm,
                purpose: m.purpose,
            })
        }
        Op::Exists { label } => {
            let label = scoped_label(&label, prsn_handle)?;
            Ok(OpOk::Exists {
                exists: ks.exists(&label)?,
            })
        }
        Op::List => {
            // The backend may hold several PRSNs' keys (one host-signer serves all
            // of a Guardian's containers); this channel is one PRSN's, so filter to
            // its handle. Anything not parseable / not this handle is skipped.
            let keys = ks
                .list()?
                .into_iter()
                .filter(|m| {
                    KeyLabel::parse(&m.label, None)
                        .map(|l| l.handle() == prsn_handle)
                        .unwrap_or(false)
                })
                .map(|m| KeyEntry {
                    label: m.label,
                    purpose: m.purpose,
                    algorithm: m.algorithm,
                    fingerprint: m.fingerprint,
                    public_key: m.public_key,
                })
                .collect();
            Ok(OpOk::List { keys })
        }
        // Reached only if `ChannelState::handle` did not intercept it (it does, in
        // both the pinned and unpinned states) — defensive + exhaustive. If we are
        // here the channel is pinned to `prsn_handle`, so report it.
        Op::Identity => Ok(OpOk::Identity {
            handle: Some(prsn_handle.to_string()),
        }),
        Op::Delete { label } => {
            let label = scoped_label(&label, prsn_handle)?;
            ks.delete(&label)?;
            Ok(OpOk::Delete)
        }
    }
}

/// Parse `label` and require its handle to be `prsn_handle`. A label for another
/// PRSN is refused (authorization). Purpose is *not* enforced here — the keystore
/// op enforces it, so a delegated mismatch returns the same code as the native path.
fn scoped_label(label: &str, prsn_handle: &str) -> Result<KeyLabel> {
    let parsed = KeyLabel::parse(label, None)?;
    if parsed.handle() != prsn_handle {
        return Err(CliError::authorization_denied(format!(
            "label '{label}' does not belong to this channel's PRSN ('{prsn_handle}')"
        )));
    }
    Ok(parsed)
}

// ── The daemon: registry + per-channel handle binding + serve loop ─────────────

/// The host-signer registry — operator-authored at container creation (one entry
/// per containerized PRSN). The `signet host-signer` subcommand reads it at startup.
/// Keep it 0600 in the user's private area: it holds the per-PRSN secrets.
#[derive(Debug, Serialize, Deserialize)]
pub struct Registry {
    /// Where per-channel pinned-handle state files live (the host-signer writes here).
    pub state_dir: PathBuf,
    /// One entry per channel/PRSN (TOML `[[channel]]`).
    #[serde(default, rename = "channel")]
    pub channels: Vec<ChannelConfig>,
}

/// One channel in the [`Registry`].
#[derive(Debug, Serialize, Deserialize)]
pub struct ChannelConfig {
    /// Stable channel id — matches the container's `SIGNET_HOST_CHANNEL_ID` + the AAD.
    pub id: String,
    /// Host path to the bind-mounted channel folder.
    pub dir: PathBuf,
    /// The per-PRSN secret, hex (32 bytes / 64 hex chars) — mirrors the copy in the
    /// container's private filesystem.
    pub secret_hex: String,
}

impl Registry {
    /// Load + parse a registry TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path).map_err(|e| {
            CliError::config(format!(
                "reading host-signer registry {}: {e}",
                path.display()
            ))
        })?;
        toml::from_str(&text)
            .map_err(|e| CliError::config(format!("parsing host-signer registry: {e}")))
    }

    /// Load the registry, or — when the file does not exist yet — start with an
    /// **empty** registry rooted at `default_state_dir`. The `signet host-signer`
    /// LaunchAgent runs from first install, before any channel is provisioned, so a
    /// missing `registry.toml` is the normal idle state (zero channels), not an error;
    /// `host-channel provision` writes the file on the first channel. By convention
    /// `default_state_dir` is `<host-signer-dir>/state` (what `provision` records).
    pub fn load_or_init(path: &Path, default_state_dir: &Path) -> Result<Self> {
        if path.exists() {
            Self::load(path)
        } else {
            Ok(Self {
                state_dir: default_state_dir.to_path_buf(),
                channels: Vec::new(),
            })
        }
    }
}

fn parse_secret_hex(hex_str: &str) -> Result<ChannelSecret> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|_| CliError::config("channel secret_hex is not hex"))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| CliError::config("channel secret must be 32 bytes (64 hex chars)"))?;
    Ok(ChannelSecret::from_bytes(arr))
}

/// Per-channel mutable state: the PRSN handle bound to this channel — pinned on the
/// first successful keygen (trust-on-first-use) and persisted so it survives a
/// host-signer restart.
pub struct ChannelState {
    pinned_handle: Option<String>,
    pin_path: PathBuf,
}

impl ChannelState {
    /// Construct for a channel, loading any persisted pinned handle.
    pub fn load(channel_id: &str, state_dir: &Path) -> Result<Self> {
        let pin_path = state_dir.join(format!("{channel_id}.handle"));
        let pinned_handle = match fs::read_to_string(&pin_path) {
            Ok(s) => {
                let h = s.trim().to_string();
                if h.is_empty() { None } else { Some(h) }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                return Err(CliError::config(format!(
                    "reading pinned handle {}: {e}",
                    pin_path.display()
                )));
            }
        };
        Ok(Self {
            pinned_handle,
            pin_path,
        })
    }

    /// Handle one op on this channel against `keystore`, enforcing the channel↔PRSN
    /// binding (Account-and-Kit §f.3):
    /// - Once a handle is pinned, every op is scoped to it ([`handle_op`] refuses a
    ///   cross-PRSN label).
    /// - Before any pin, only a **keygen** is allowed; on its first *success* the
    ///   handle is pinned. A channel can therefore only ever bind to — and then
    ///   operate — the keys it created itself (keygen on an existing label fails, so
    ///   it cannot hijack another PRSN's keys). Sign/ECDH before a pin are refused.
    pub fn handle(&mut self, keystore: &dyn Keystore, op: Op) -> Response {
        // Identity is answerable in *any* state: it reports whether/what handle is
        // pinned to this channel (the PRSN's own, public, channel-scoped handle) and
        // needs no SE access. It must work *before* enrollment too (→ `None`) so the
        // in-container client can cross-check its launch-binding (`SIGNET_HANDLE`) at
        // startup. Intercept it before the pin/keygen gate below.
        if matches!(op, Op::Identity) {
            return Response::Ok(OpOk::Identity {
                handle: self.pinned_handle.clone(),
            });
        }
        if let Some(handle) = &self.pinned_handle {
            return handle_op(keystore, handle, op);
        }
        // Not yet enrolled: only a keygen may establish the channel's handle.
        let label = match &op {
            Op::Keygen { label, .. } => label.clone(),
            _ => {
                return Response::Err(OpErr {
                    code: "authorization_denied".to_string(),
                    message: "this channel has no enrolled PRSN yet (run `signet enroll` first)"
                        .to_string(),
                });
            }
        };
        let handle = match KeyLabel::parse(&label, None) {
            Ok(l) => l.handle().to_string(),
            Err(e) => {
                return Response::Err(OpErr {
                    code: e.code.to_string(),
                    message: e.message,
                });
            }
        };
        let response = handle_op(keystore, &handle, op);
        if matches!(response, Response::Ok(_)) {
            self.pinned_handle = Some(handle.clone());
            if let Err(e) = self.persist(&handle) {
                // Non-fatal: the keygen itself succeeded. But a restart would forget
                // the pin and refuse this PRSN's sign/ECDH — so surface it loudly.
                eprintln!(
                    "signet host-signer: WARNING could not persist the pinned handle ({e}); \
                     a restart will not remember it"
                );
            }
        }
        response
    }

    fn persist(&self, handle: &str) -> Result<()> {
        if let Some(parent) = self.pin_path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                CliError::config(format!("creating state dir {}: {e}", parent.display()))
            })?;
        }
        fs::write(&self.pin_path, handle.as_bytes())
            .map_err(|e| CliError::config(format!("writing {}: {e}", self.pin_path.display())))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.pin_path, fs::Permissions::from_mode(0o600)).map_err(
                |e| CliError::config(format!("securing {}: {e}", self.pin_path.display())),
            )?;
        }
        Ok(())
    }
}

/// Evict a channel after this many *consecutive* polls find its folder missing
/// (`ENOENT`). A bind-mounted *local* channel folder does not reappear at the same
/// path once gone (`provision` creates a fresh dir for a new channel), so a sustained
/// absence means the channel was deleted out from under us — e.g. `docker rm` without
/// `signet host-channel remove`. The threshold rides out a brief mid-teardown flap;
/// at the loop's 50 ms idle ceiling it is ~1 s. Without eviction the daemon would poll
/// the dead path forever, logging the same error every cycle (S059 finding: a stale
/// channel spammed 210K lines / 19 MB).
const EVICT_AFTER_MISSING_POLLS: u32 = 20;

/// One channel the daemon is actively serving, plus the consecutive-missing-poll
/// counter that drives dead-channel eviction.
struct Active {
    server: ChannelServer,
    state: ChannelState,
    /// The channel id — carried for log/eviction messages (the registry's `id`).
    id: String,
    /// Consecutive polls that found the folder gone; reset on any successful poll.
    missing_polls: u32,
}

/// What one poll of one channel produced.
struct PollOutcome {
    /// At least one request was answered (drives the loop's busy/idle backoff).
    worked: bool,
    /// The folder has been gone long enough to treat the channel as deleted; the
    /// daemon should drop it from the active set.
    evict: bool,
}

impl Active {
    /// Poll this channel once against `keystore`, updating the missing-poll counter
    /// and deciding eviction. A vanished folder is counted (and, past the threshold,
    /// logged exactly once and evicted); any other error is logged per-cycle as
    /// before — those are not expected to persist, and silencing them would hide a
    /// real fault. One bad channel never takes the daemon down.
    fn poll(&mut self, keystore: &dyn Keystore) -> PollOutcome {
        // Destructure into disjoint borrows so the handler closure can hold
        // `&mut state` while `server` is borrowed by `poll_once`.
        let Active {
            server,
            state,
            id,
            missing_polls,
        } = self;
        match server.poll_once(&mut |op| state.handle(keystore, op)) {
            Ok(n) => {
                *missing_polls = 0;
                PollOutcome {
                    worked: n > 0,
                    evict: false,
                }
            }
            Err(ChannelError::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                *missing_polls = missing_polls.saturating_add(1);
                let evict = *missing_polls == EVICT_AFTER_MISSING_POLLS;
                if evict {
                    eprintln!(
                        "signet host-signer: channel {id} folder is gone; evicting it \
                         (run `signet host-channel remove {id}` to clean up the registry)"
                    );
                }
                PollOutcome {
                    worked: false,
                    evict,
                }
            }
            Err(e) => {
                *missing_polls = 0;
                eprintln!("signet host-signer: channel {id} poll error: {e}");
                PollOutcome {
                    worked: false,
                    evict: false,
                }
            }
        }
    }
}

/// Run the host-signer: serve every registered channel against `keystore` until
/// `shutdown` is set. Single-threaded, adaptive poll across all channels (≤
/// `max_prsns_per_guardian` ≈ 8, so one loop is ample); the keystore's `&self` ops
/// are shared across channels (one host SE). A per-channel poll error is logged and
/// the loop continues — one bad channel must not take the daemon down; a channel
/// whose folder has vanished is evicted in-memory (the operator-authored registry
/// file is never rewritten — a restart re-reads it and re-evicts if still gone).
pub fn run(registry: Registry, keystore: &dyn Keystore, shutdown: &AtomicBool) -> Result<()> {
    let mut channels: Vec<Active> = Vec::new();
    for cfg in &registry.channels {
        let secret = parse_secret_hex(&cfg.secret_hex)?;
        let server = ChannelServer::new(cfg.dir.clone(), cfg.id.clone(), secret);
        let state = ChannelState::load(&cfg.id, &registry.state_dir)?;
        channels.push(Active {
            server,
            state,
            id: cfg.id.clone(),
            missing_polls: 0,
        });
    }

    let mut idle: u32 = 0;
    while !shutdown.load(Ordering::Relaxed) {
        let mut worked = false;
        let mut i = 0;
        while i < channels.len() {
            let outcome = channels[i].poll(keystore);
            worked |= outcome.worked;
            if outcome.evict {
                channels.remove(i);
            } else {
                i += 1;
            }
        }
        if worked {
            idle = 0;
            sleep(Duration::from_millis(1));
        } else {
            idle = idle.saturating_add(1);
            sleep(idle_backoff(idle));
        }
    }
    Ok(())
}

/// Idle poll backoff: ramps to a 50 ms ceiling, keeping the LaunchAgent's idle CPU
/// near zero while a busy pass is serviced immediately.
fn idle_backoff(idle_rounds: u32) -> Duration {
    let ms = (1u64 << idle_rounds.min(6)).min(50);
    Duration::from_millis(ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::SoftwareKeystore;

    const HANDLE: &str = "hlin-ai";

    fn keystore() -> (SoftwareKeystore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let ks = SoftwareKeystore::open(dir.path().to_path_buf()).unwrap();
        (ks, dir)
    }

    /// Generate a signing key via dispatch, sign via dispatch, verify the signature.
    #[test]
    fn keygen_then_sign_verifies() {
        let (ks, _d) = keystore();
        let keygen = handle_op(
            &ks,
            HANDLE,
            Op::Keygen {
                label: "hlin-ai-signing".into(),
                algorithm: "ES256".into(),
            },
        );
        let pubkey = match keygen {
            Response::Ok(OpOk::Keygen { public_key, .. }) => public_key,
            other => panic!("expected keygen ok, got {other:?}"),
        };
        assert_eq!(pubkey.len(), 65);

        let msg = b"SIGNET-V1 delegated message";
        let sig = match handle_op(
            &ks,
            HANDLE,
            Op::Sign {
                label: "hlin-ai-signing".into(),
                msg: msg.to_vec(),
            },
        ) {
            Response::Ok(OpOk::Sign { signature }) => signature,
            other => panic!("expected sign ok, got {other:?}"),
        };
        let sig: [u8; 64] = sig.try_into().expect("64-byte signature");
        signet_crypto::ecdsa::verify_es256(&pubkey, msg, &sig)
            .expect("delegated signature verifies under the pubkey");
    }

    /// ECDH via dispatch agrees with the peer-side computation.
    #[test]
    fn ecdh_agrees_with_peer() {
        let (ks, _d) = keystore();
        let kem_pub = match handle_op(
            &ks,
            HANDLE,
            Op::Keygen {
                label: "hlin-ai-kem".into(),
                algorithm: "ECDH-ES+A256KW".into(),
            },
        ) {
            Response::Ok(OpOk::Keygen { public_key, .. }) => public_key,
            other => panic!("expected keygen ok, got {other:?}"),
        };
        let (eph_scalar, eph_pub) = signet_crypto::ecdh::generate_keypair();
        let z_host = match handle_op(
            &ks,
            HANDLE,
            Op::Ecdh {
                label: "hlin-ai-kem".into(),
                peer_pub_x963: eph_pub,
            },
        ) {
            Response::Ok(OpOk::Ecdh { shared_secret }) => shared_secret,
            other => panic!("expected ecdh ok, got {other:?}"),
        };
        let z_peer = signet_crypto::ecdh::ecdh_p256(&eph_scalar, &kem_pub).unwrap();
        assert_eq!(z_host.as_slice(), z_peer.as_slice());
    }

    /// exists / list / delete behave through dispatch.
    #[test]
    fn exists_list_delete() {
        let (ks, _d) = keystore();
        handle_op(
            &ks,
            HANDLE,
            Op::Keygen {
                label: "hlin-ai-signing".into(),
                algorithm: "ES256".into(),
            },
        );
        assert!(matches!(
            handle_op(
                &ks,
                HANDLE,
                Op::Exists {
                    label: "hlin-ai-signing".into()
                }
            ),
            Response::Ok(OpOk::Exists { exists: true })
        ));
        match handle_op(&ks, HANDLE, Op::List) {
            Response::Ok(OpOk::List { keys }) => {
                assert!(keys.iter().any(|k| k.label == "hlin-ai-signing"));
            }
            other => panic!("expected list ok, got {other:?}"),
        }
        assert!(matches!(
            handle_op(
                &ks,
                HANDLE,
                Op::Delete {
                    label: "hlin-ai-signing".into()
                }
            ),
            Response::Ok(OpOk::Delete)
        ));
        assert!(matches!(
            handle_op(
                &ks,
                HANDLE,
                Op::Exists {
                    label: "hlin-ai-signing".into()
                }
            ),
            Response::Ok(OpOk::Exists { exists: false })
        ));
    }

    /// A label for a different PRSN is refused, even on this channel.
    #[test]
    fn cross_prsn_label_is_refused() {
        let (ks, _d) = keystore();
        let resp = handle_op(
            &ks,
            HANDLE,
            Op::Keygen {
                label: "mira-ai-signing".into(),
                algorithm: "ES256".into(),
            },
        );
        match resp {
            Response::Err(OpErr { code, .. }) => assert_eq!(code, "authorization_denied"),
            other => panic!("expected authorization_denied, got {other:?}"),
        }
    }

    /// A delegated `sign` on a KEM key returns the keystore's purpose-guard error
    /// (same code as the native path).
    #[test]
    fn sign_on_kem_key_is_refused() {
        let (ks, _d) = keystore();
        handle_op(
            &ks,
            HANDLE,
            Op::Keygen {
                label: "hlin-ai-kem".into(),
                algorithm: "ECDH-ES+A256KW".into(),
            },
        );
        match handle_op(
            &ks,
            HANDLE,
            Op::Sign {
                label: "hlin-ai-kem".into(),
                msg: b"x".to_vec(),
            },
        ) {
            Response::Err(OpErr { code, .. }) => assert_eq!(code, "unsupported_algorithm"),
            other => panic!("expected unsupported_algorithm, got {other:?}"),
        }
    }

    /// The PQ ops (PQR item 2) dispatch end-to-end on the software tier (item
    /// 7a: real software PQ implementations — the four-key enrollment PoP runs
    /// on this tier in tests/harnesses): keygen → ML-DSA sign round-trips
    /// through the wire dispatch, and decap on a missing key surfaces the
    /// stable key_not_found rather than a refusal.
    #[test]
    fn pq_ops_dispatch_and_refuse_on_software_tier() {
        let (ks, _d) = keystore();
        // No key yet → the op-level failure is key_not_found (not a tier refusal).
        match handle_op(
            &ks,
            HANDLE,
            Op::MlKemDecapsulate {
                label: "hlin-ai-kem-pq".into(),
                ek: vec![0xE2; signet_crypto::hybrid_wrap::MLKEM1024_CT_LEN],
            },
        ) {
            Response::Err(OpErr { code, .. }) => assert_eq!(code, "key_not_found"),
            other => panic!("expected key_not_found, got {other:?}"),
        }
        // Keygen + sign work end-to-end through the dispatch.
        match handle_op(
            &ks,
            HANDLE,
            Op::Keygen {
                label: "hlin-ai-signing-pq".into(),
                algorithm: "ML-DSA-87".into(),
            },
        ) {
            Response::Ok(OpOk::Keygen { public_key, .. }) => {
                assert_eq!(public_key.len(), 2592, "FIPS 204 vk length");
            }
            other => panic!("expected keygen ok, got {other:?}"),
        }
        match handle_op(
            &ks,
            HANDLE,
            Op::MlDsaSign {
                label: "hlin-ai-signing-pq".into(),
                msg: b"m".to_vec(),
                ctx: b"signet:req:v1".to_vec(),
            },
        ) {
            Response::Ok(OpOk::MlDsaSign { signature }) => {
                assert_eq!(signature.len(), 4627, "FIPS 204 signature length");
            }
            other => panic!("expected ml-dsa signature, got {other:?}"),
        }
    }

    /// The dispatch-seam validations fail fast with nameable errors: a
    /// wrong-length `ek` and an oversized FIPS 204 `ctx` never reach the backend.
    #[test]
    fn pq_ops_validate_ek_and_ctx_at_dispatch() {
        let (ks, _d) = keystore();
        match handle_op(
            &ks,
            HANDLE,
            Op::MlKemDecapsulate {
                label: "hlin-ai-kem-pq".into(),
                ek: vec![0xE2; 1567],
            },
        ) {
            Response::Err(OpErr { code, message }) => {
                assert_eq!(code, "invalid_arguments");
                assert!(
                    message.contains("1568"),
                    "message names the length: {message}"
                );
            }
            other => panic!("expected invalid_arguments, got {other:?}"),
        }
        match handle_op(
            &ks,
            HANDLE,
            Op::MlDsaSign {
                label: "hlin-ai-signing-pq".into(),
                msg: b"m".to_vec(),
                ctx: vec![0u8; 256],
            },
        ) {
            Response::Err(OpErr { code, .. }) => assert_eq!(code, "invalid_arguments"),
            other => panic!("expected invalid_arguments, got {other:?}"),
        }
    }

    /// Cross-PRSN scoping applies to the PQ ops exactly as to the classical ones.
    #[test]
    fn pq_ops_are_scoped_to_the_channels_prsn() {
        let (ks, _d) = keystore();
        match handle_op(
            &ks,
            HANDLE,
            Op::MlKemDecapsulate {
                label: "mira-ai-kem-pq".into(),
                ek: vec![0xE2; signet_crypto::hybrid_wrap::MLKEM1024_CT_LEN],
            },
        ) {
            Response::Err(OpErr { code, .. }) => assert_eq!(code, "authorization_denied"),
            other => panic!("expected authorization_denied, got {other:?}"),
        }
    }

    /// PQ keygen works on the software tier (item 7a — real software PQ keys
    /// for the dev/test tier; a real PRSN stays SE-only, server-enforced).
    #[test]
    fn pq_keygen_works_on_software_tier() {
        // Item 7a: the software tier holds real PQ keys (dev/test only — a real
        // PRSN stays SE-only, enforced server-side at enrollment).
        let (ks, _d) = keystore();
        match handle_op(
            &ks,
            HANDLE,
            Op::Keygen {
                label: "hlin-ai-kem-pq".into(),
                algorithm: "ML-KEM-1024".into(),
            },
        ) {
            Response::Ok(OpOk::Keygen { public_key, .. }) => {
                assert_eq!(public_key.len(), 1568, "FIPS 203 ek length");
            }
            other => panic!("expected keygen ok, got {other:?}"),
        }
    }

    /// List on a backend holding two PRSNs' keys returns only this channel's PRSN.
    #[test]
    fn list_is_scoped_to_the_channels_prsn() {
        let (ks, _d) = keystore();
        for label in ["hlin-ai-signing", "mira-ai-signing"] {
            // Generate directly (bypass dispatch's scoping) to seed both PRSNs.
            ks.generate(&KeyLabel::parse(label, None).unwrap(), "ES256")
                .unwrap();
        }
        match handle_op(&ks, HANDLE, Op::List) {
            Response::Ok(OpOk::List { keys }) => {
                assert_eq!(keys.len(), 1);
                assert_eq!(keys[0].label, "hlin-ai-signing");
            }
            other => panic!("expected list ok, got {other:?}"),
        }
    }

    #[test]
    fn registry_parses() {
        let toml = "state_dir = \"/tmp/state\"\n\
                    [[channel]]\nid = \"c1\"\ndir = \"/tmp/chan1\"\nsecret_hex = \"aa\"\n\
                    [[channel]]\nid = \"c2\"\ndir = \"/tmp/chan2\"\nsecret_hex = \"bb\"\n";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.toml");
        std::fs::write(&path, toml).unwrap();
        let reg = Registry::load(&path).unwrap();
        assert_eq!(reg.channels.len(), 2);
        assert_eq!(reg.channels[0].id, "c1");
        assert_eq!(reg.channels[1].dir, std::path::PathBuf::from("/tmp/chan2"));
    }

    #[test]
    fn channel_state_refuses_ops_before_enrollment() {
        let (ks, _kd) = keystore();
        let sd = tempfile::tempdir().unwrap();
        let mut st = ChannelState::load("c1", sd.path()).unwrap();
        match st.handle(
            &ks,
            Op::Sign {
                label: "hlin-ai-signing".into(),
                msg: b"x".to_vec(),
            },
        ) {
            Response::Err(OpErr { code, .. }) => assert_eq!(code, "authorization_denied"),
            other => panic!("expected refusal before enrollment, got {other:?}"),
        }
        // Identity is answerable even before enrollment → None, so the in-container
        // cross-check can run at startup without tripping the pre-enroll gate.
        match st.handle(&ks, Op::Identity) {
            Response::Ok(OpOk::Identity { handle }) => assert_eq!(handle, None),
            other => panic!("expected Identity(None) before enrollment, got {other:?}"),
        }
        assert!(st.pinned_handle.is_none());
    }

    #[test]
    fn channel_state_pins_on_first_keygen_and_scopes() {
        let (ks, _kd) = keystore();
        let sd = tempfile::tempdir().unwrap();
        let mut st = ChannelState::load("c1", sd.path()).unwrap();
        // First keygen establishes the channel's handle.
        assert!(matches!(
            st.handle(
                &ks,
                Op::Keygen {
                    label: "hlin-ai-signing".into(),
                    algorithm: "ES256".into()
                }
            ),
            Response::Ok(OpOk::Keygen { .. })
        ));
        assert_eq!(st.pinned_handle.as_deref(), Some("hlin-ai"));
        // Scoped: sign for the pinned handle works.
        assert!(matches!(
            st.handle(
                &ks,
                Op::Sign {
                    label: "hlin-ai-signing".into(),
                    msg: b"x".to_vec()
                }
            ),
            Response::Ok(OpOk::Sign { .. })
        ));
        // A keygen for a *different* PRSN on this pinned channel is refused.
        match st.handle(
            &ks,
            Op::Keygen {
                label: "mira-ai-signing".into(),
                algorithm: "ES256".into(),
            },
        ) {
            Response::Err(OpErr { code, .. }) => assert_eq!(code, "authorization_denied"),
            other => panic!("expected cross-PRSN refusal, got {other:?}"),
        }
    }

    #[test]
    fn channel_state_pin_persists_across_reload() {
        let (ks, _kd) = keystore();
        let sd = tempfile::tempdir().unwrap();
        {
            let mut st = ChannelState::load("c1", sd.path()).unwrap();
            st.handle(
                &ks,
                Op::Keygen {
                    label: "hlin-ai-signing".into(),
                    algorithm: "ES256".into(),
                },
            );
        }
        // A fresh state for the same channel reads the persisted pin → sign works
        // immediately (a host-signer restart does not require re-keygen).
        let mut reloaded = ChannelState::load("c1", sd.path()).unwrap();
        assert_eq!(reloaded.pinned_handle.as_deref(), Some("hlin-ai"));
        assert!(matches!(
            reloaded.handle(
                &ks,
                Op::Sign {
                    label: "hlin-ai-signing".into(),
                    msg: b"x".to_vec()
                }
            ),
            Response::Ok(OpOk::Sign { .. })
        ));
    }

    /// The daemon end-to-end: `run` serving a registered channel against a software
    /// keystore, with a `DelegatedKeystore` client over the same channel + secret.
    /// Note `channel_id` ("c1") is distinct from the PRSN handle ("hlin-ai") — the
    /// TOFU pin binds them on the first keygen.
    #[test]
    fn run_serves_a_channel_end_to_end() {
        use crate::keystore::{DelegatedKeystore, Purpose};
        use std::sync::Arc;

        let chan = tempfile::tempdir().unwrap();
        let state_dir = tempfile::tempdir().unwrap();
        let ks_dir = tempfile::tempdir().unwrap();
        let secret = [9u8; 32];

        let registry = Registry {
            state_dir: state_dir.path().to_path_buf(),
            channels: vec![ChannelConfig {
                id: "c1".into(),
                dir: chan.path().to_path_buf(),
                secret_hex: hex::encode(secret),
            }],
        };

        let shutdown = Arc::new(AtomicBool::new(false));
        let daemon_shutdown = Arc::clone(&shutdown);
        let ks_path = ks_dir.path().to_path_buf();
        let daemon = std::thread::spawn(move || {
            let backing = SoftwareKeystore::open(ks_path).unwrap();
            let _ = run(registry, &backing, &daemon_shutdown);
        });

        let client = DelegatedKeystore::open(chan.path(), "c1", ChannelSecret::from_bytes(secret));
        let signing = KeyLabel::from_handle("hlin-ai", Purpose::Signing).unwrap();
        // enroll-style: the first keygen pins the channel to hlin-ai...
        let m = client.generate(&signing, "ES256").unwrap();
        assert_eq!(m.public_key.len(), 65);
        assert_eq!(m.storage, "secure-enclave");
        // ...then a delegated sign works, verifying under the returned pubkey.
        let msg = b"daemon end-to-end";
        let sig = client.sign(&signing, msg).unwrap();
        signet_crypto::ecdsa::verify_es256(&m.public_key, msg, &sig).unwrap();

        shutdown.store(true, Ordering::Relaxed);
        daemon.join().unwrap();
    }

    #[test]
    fn load_or_init_missing_file_yields_empty_registry() {
        let dir = tempfile::tempdir().unwrap();
        let registry_path = dir.path().join("registry.toml");
        let state_dir = dir.path().join("state");
        assert!(!registry_path.exists()); // the always-on LaunchAgent's first-launch state
        let reg = Registry::load_or_init(&registry_path, &state_dir).unwrap();
        assert!(reg.channels.is_empty());
        assert_eq!(reg.state_dir, state_dir);
    }

    #[test]
    fn load_or_init_existing_file_loads_it() {
        let dir = tempfile::tempdir().unwrap();
        let registry_path = dir.path().join("registry.toml");
        std::fs::write(
            &registry_path,
            "state_dir = \"/tmp/st\"\n[[channel]]\nid = \"c1\"\ndir = \"/tmp/c1\"\nsecret_hex = \"aa\"\n",
        )
        .unwrap();
        // When the file exists, its on-disk contents win (the default is ignored).
        let reg = Registry::load_or_init(&registry_path, &dir.path().join("ignored")).unwrap();
        assert_eq!(reg.channels.len(), 1);
        assert_eq!(reg.channels[0].id, "c1");
        assert_eq!(reg.state_dir, PathBuf::from("/tmp/st"));
    }

    #[test]
    fn run_with_no_channels_idles_then_stops() {
        use std::sync::Arc;
        // The always-on host-signer must run cleanly with ZERO channels — idle until a
        // container is provisioned — not error. It idles, then stops on shutdown.
        let ks_dir = tempfile::tempdir().unwrap();
        let state_dir = tempfile::tempdir().unwrap();
        let registry = Registry {
            state_dir: state_dir.path().to_path_buf(),
            channels: vec![],
        };
        let shutdown = Arc::new(AtomicBool::new(false));
        let s2 = Arc::clone(&shutdown);
        let ks_path = ks_dir.path().to_path_buf();
        let h = std::thread::spawn(move || {
            let ks = SoftwareKeystore::open(ks_path).unwrap();
            run(registry, &ks, &s2)
        });
        std::thread::sleep(Duration::from_millis(20)); // let it idle a few poll cycles
        shutdown.store(true, Ordering::Relaxed);
        assert!(h.join().unwrap().is_ok());
    }

    #[test]
    fn a_vanished_channel_folder_is_evicted_after_sustained_misses() {
        // S059 finding: a deleted channel folder must not be polled — and logged —
        // forever. `Active::poll` counts consecutive ENOENTs and evicts past the
        // threshold (logging exactly once), without touching the registry file.
        let chan = tempfile::tempdir().unwrap();
        let state_dir = tempfile::tempdir().unwrap();
        let (ks, _ksd) = keystore();

        let mut active = Active {
            server: ChannelServer::new(
                chan.path().to_path_buf(),
                "c1",
                ChannelSecret::from_bytes([7u8; 32]),
            ),
            state: ChannelState::load("c1", state_dir.path()).unwrap(),
            id: "c1".into(),
            missing_polls: 0,
        };

        // Folder present + empty: a clean idle poll, nothing to evict.
        let o = active.poll(&ks);
        assert!(!o.worked && !o.evict);
        assert_eq!(active.missing_polls, 0);

        // The channel folder is deleted (e.g. `docker rm` without `host-channel remove`).
        drop(chan);

        // Below the threshold: counted, not yet evicted.
        for n in 1..EVICT_AFTER_MISSING_POLLS {
            let o = active.poll(&ks);
            assert!(!o.evict, "evicted too early at miss {n}");
            assert_eq!(active.missing_polls, n);
        }
        // At the threshold: evicted (exactly once).
        let o = active.poll(&ks);
        assert!(o.evict);
        assert_eq!(active.missing_polls, EVICT_AFTER_MISSING_POLLS);
    }
}
