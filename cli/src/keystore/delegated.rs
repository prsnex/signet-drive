// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! The `secure_enclave` keystore via **host-delegation** — the in-container
//! delegation client (Account-and-Kit spec §f.2).
//!
//! A containerized PRSN holds no keys. This backend forwards every [`Keystore`]
//! op to the host-signer over the bind-mounted-folder channel (`signet-channel`),
//! which performs it in the *host* Mac's Secure Enclave and returns the result.
//! It reports `key_protection = secure_enclave` — the keys live in *an* SE (the
//! host's), so the custody grade is identical to a native PRSN's.
//!
//! No raw crypto here: the channel seals/authenticates every message under the
//! per-PRSN secret (`signet-channel` §f.4); this backend only marshals
//! [`Keystore`] calls to/from [`Op`]/[`Response`] and re-raises a host-signer
//! [`OpErr`] as the matching [`CliError`] (faithful exit code).

use std::path::PathBuf;
use std::time::Duration;

use signet_channel::auth::ChannelSecret;
use signet_channel::transport::ChannelClient;
use signet_channel::wire::{Op, OpOk, Response};

use super::{KeyLabel, KeyMeta, Keystore, Tier, cli_error_from_wire, unexpected};
use crate::error::{CliError, Result};

/// Per-op wait ceiling. The S055 spike measured ~5 ms RTT; this generous bound
/// absorbs host-signer scheduling without hanging forever if the agent is down.
const OP_TIMEOUT: Duration = Duration::from_secs(30);

/// The in-container delegation keystore. Holds no key material — only the channel
/// client (folder + per-PRSN secret).
pub struct DelegatedKeystore {
    client: ChannelClient,
    timeout: Duration,
}

impl DelegatedKeystore {
    /// Open a delegation client over `channel_dir`, identified as `channel_id` and
    /// authenticated by `secret` (the per-PRSN secret provisioned into this
    /// container's private filesystem at creation).
    pub fn open(
        channel_dir: impl Into<PathBuf>,
        channel_id: impl Into<String>,
        secret: ChannelSecret,
    ) -> Self {
        Self {
            client: ChannelClient::new(channel_dir, channel_id, secret),
            timeout: OP_TIMEOUT,
        }
    }

    /// Send one op + unwrap the success result, re-raising a host-signer error as
    /// the matching [`CliError`].
    fn request(&self, op: Op) -> Result<OpOk> {
        match self
            .client
            .request(&op, self.timeout)
            .map_err(channel_err)?
        {
            Response::Ok(ok) => Ok(ok),
            Response::Err(e) => Err(cli_error_from_wire(&e.code, e.message)),
        }
    }

    /// Rebuild a [`KeyMeta`] from wire fields, stamping `storage` with this
    /// backend's tier (the keys are in the host SE).
    fn meta_from(
        &self,
        label: String,
        purpose: String,
        algorithm: String,
        fingerprint: String,
        public_key: Vec<u8>,
    ) -> KeyMeta {
        KeyMeta {
            label,
            purpose,
            algorithm,
            storage: Tier::SecureEnclave.as_str().to_string(),
            fingerprint,
            public_key,
        }
    }

    /// The PRSN handle the host-signer has pinned to **this channel** (TOFU on the
    /// first enrollment keygen), or `None` if the channel is not yet enrolled. This
    /// is the *independent*, host-side source the launch-binding cross-check compares
    /// against the harness-asserted `SIGNET_HANDLE` (see `keystore::open`'s
    /// `verify_channel_identity`). A host-side state read — no SE access, no key
    /// material, scoped to this channel.
    pub fn pinned_identity(&self) -> Result<Option<String>> {
        match self.request(Op::Identity)? {
            OpOk::Identity { handle } => Ok(handle),
            other => Err(unexpected(&other)),
        }
    }
}

impl Keystore for DelegatedKeystore {
    fn tier(&self) -> Tier {
        Tier::SecureEnclave
    }

    fn generate(&self, label: &KeyLabel, algorithm: &str) -> Result<KeyMeta> {
        match self.request(Op::Keygen {
            label: label.full(),
            algorithm: algorithm.to_string(),
        })? {
            OpOk::Keygen {
                public_key,
                fingerprint,
                algorithm,
            } => Ok(self.meta_from(
                label.full(),
                label.purpose().as_str().to_string(),
                algorithm,
                fingerprint,
                public_key,
            )),
            other => Err(unexpected(&other)),
        }
    }

    fn meta(&self, label: &KeyLabel) -> Result<KeyMeta> {
        match self.request(Op::Meta {
            label: label.full(),
        })? {
            OpOk::Meta {
                public_key,
                fingerprint,
                algorithm,
                purpose,
            } => Ok(self.meta_from(label.full(), purpose, algorithm, fingerprint, public_key)),
            other => Err(unexpected(&other)),
        }
    }

    fn sign(&self, label: &KeyLabel, msg: &[u8]) -> Result<[u8; 64]> {
        match self.request(Op::Sign {
            label: label.full(),
            msg: msg.to_vec(),
        })? {
            OpOk::Sign { signature } => signature
                .try_into()
                .map_err(|_| CliError::generic("host-signer returned a non-64-byte signature")),
            other => Err(unexpected(&other)),
        }
    }

    fn ecdh(&self, label: &KeyLabel, peer_pub_x963: &[u8]) -> Result<[u8; 32]> {
        match self.request(Op::Ecdh {
            label: label.full(),
            peer_pub_x963: peer_pub_x963.to_vec(),
        })? {
            OpOk::Ecdh { shared_secret } => shared_secret
                .try_into()
                .map_err(|_| CliError::generic("host-signer returned a non-32-byte shared secret")),
            other => Err(unexpected(&other)),
        }
    }

    fn ml_kem_decapsulate(&self, label: &KeyLabel, ek: &[u8]) -> Result<[u8; 32]> {
        match self.request(Op::MlKemDecapsulate {
            label: label.full(),
            ek: ek.to_vec(),
        })? {
            OpOk::MlKemDecapsulate { shared_secret } => shared_secret.try_into().map_err(|_| {
                CliError::generic("host-signer returned a non-32-byte ml-kem shared secret")
            }),
            other => Err(unexpected(&other)),
        }
    }

    fn ml_dsa_sign(&self, label: &KeyLabel, msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>> {
        crate::keystore::validate_mldsa_ctx(ctx)?;
        match self.request(Op::MlDsaSign {
            label: label.full(),
            msg: msg.to_vec(),
            ctx: ctx.to_vec(),
        })? {
            OpOk::MlDsaSign { signature } => {
                if signature.len() != crate::keystore::ML_DSA_87_SIG_LEN {
                    return Err(CliError::generic(format!(
                        "host-signer returned a {}-byte ml-dsa signature (expected {})",
                        signature.len(),
                        crate::keystore::ML_DSA_87_SIG_LEN
                    )));
                }
                Ok(signature)
            }
            other => Err(unexpected(&other)),
        }
    }

    fn list(&self) -> Result<Vec<KeyMeta>> {
        match self.request(Op::List)? {
            OpOk::List { keys } => Ok(keys
                .into_iter()
                .map(|k| {
                    self.meta_from(k.label, k.purpose, k.algorithm, k.fingerprint, k.public_key)
                })
                .collect()),
            other => Err(unexpected(&other)),
        }
    }

    fn delete(&self, label: &KeyLabel) -> Result<()> {
        match self.request(Op::Delete {
            label: label.full(),
        })? {
            OpOk::Delete => Ok(()),
            other => Err(unexpected(&other)),
        }
    }

    fn exists(&self, label: &KeyLabel) -> Result<bool> {
        match self.request(Op::Exists {
            label: label.full(),
        })? {
            OpOk::Exists { exists } => Ok(exists),
            other => Err(unexpected(&other)),
        }
    }
}

/// Map a channel transport failure to a [`CliError`].
fn channel_err(e: signet_channel::ChannelError) -> CliError {
    use signet_channel::ChannelError as Ce;
    match e {
        Ce::Timeout => CliError::new(
            30,
            "network_error",
            "the host-signer did not respond in time (is it running + the container channel mounted?)",
        ),
        Ce::Auth => CliError::authentication_failed(
            "the host-signer rejected the channel message (per-PRSN secret mismatch or tampering)",
        ),
        other => CliError::generic(format!("host-signer channel error: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_signer::handle_op;
    use crate::keystore::{Purpose, SoftwareKeystore};
    use signet_channel::transport::ChannelServer;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    const HANDLE: &str = "hlin-ai";
    const SECRET: [u8; 32] = [42u8; 32];

    /// The full delegation path: a host-signer (ChannelServer + handle_op over a
    /// `software` keystore) in a thread, a DelegatedKeystore client at the same
    /// channel folder, exercising the whole Keystore trait — cross-platform, no SE.
    #[test]
    fn full_delegation_round_trip() {
        let chan = tempfile::tempdir().unwrap();
        let ks_dir = tempfile::tempdir().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));

        let server_shutdown = Arc::clone(&shutdown);
        let chan_path = chan.path().to_path_buf();
        let ks_path = ks_dir.path().to_path_buf();
        let server = std::thread::spawn(move || {
            let backing = SoftwareKeystore::open(ks_path).unwrap();
            let mut srv = ChannelServer::new(&chan_path, HANDLE, ChannelSecret::from_bytes(SECRET));
            let mut handler = |op: Op| handle_op(&backing, HANDLE, op);
            let _ = srv.serve(&mut handler, &server_shutdown);
        });

        let client =
            DelegatedKeystore::open(chan.path(), HANDLE, ChannelSecret::from_bytes(SECRET));
        let signing = KeyLabel::from_handle(HANDLE, Purpose::Signing).unwrap();
        let kem = KeyLabel::from_handle(HANDLE, Purpose::Kem).unwrap();

        // Delegated keygen reports the SE tier and a real pubkey.
        let sm = client.generate(&signing, "ES256").unwrap();
        assert_eq!(sm.storage, "secure-enclave");
        assert_eq!(sm.public_key.len(), 65);

        // Identity echo: the host-signer reports this channel's pinned handle — the
        // independent source the launch-binding cross-check compares to SIGNET_HANDLE.
        assert_eq!(client.pinned_identity().unwrap().as_deref(), Some(HANDLE));

        let km = client.generate(&kem, "ECDH-ES+A256KW").unwrap();

        // Delegated sign verifies under the returned pubkey.
        let msg = b"delegated round-trip";
        let sig = client.sign(&signing, msg).unwrap();
        signet_crypto::ecdsa::verify_es256(&sm.public_key, msg, &sig).unwrap();

        // Delegated ECDH agrees with the peer-side computation.
        let (eph_scalar, eph_pub) = signet_crypto::ecdh::generate_keypair();
        let z = client.ecdh(&kem, &eph_pub).unwrap();
        let z_peer = signet_crypto::ecdh::ecdh_p256(&eph_scalar, &km.public_key).unwrap();
        assert_eq!(z, z_peer);

        // exists / list / delete, all reporting the SE tier.
        assert!(client.exists(&signing).unwrap());
        let listed = client.list().unwrap();
        assert!(listed.iter().any(|m| m.label == "hlin-ai-signing"));
        assert!(listed.iter().all(|m| m.storage == "secure-enclave"));
        client.delete(&signing).unwrap();
        assert!(!client.exists(&signing).unwrap());

        // An op failure is re-raised with the faithful exit code (a deleted key →
        // key_not_found / exit 12, the same as the native path).
        let err = client.sign(&signing, msg).unwrap_err();
        assert_eq!(err.code, "key_not_found");
        assert_eq!(err.exit_code, 12);

        shutdown.store(true, Ordering::Relaxed);
        server.join().unwrap();
    }

    /// A wrong per-PRSN secret: the host-signer drops the (unauthenticated) request,
    /// so the client times out rather than getting a forged answer.
    #[test]
    fn wrong_secret_times_out() {
        let chan = tempfile::tempdir().unwrap();
        let ks_dir = tempfile::tempdir().unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));

        let server_shutdown = Arc::clone(&shutdown);
        let chan_path = chan.path().to_path_buf();
        let ks_path = ks_dir.path().to_path_buf();
        let server = std::thread::spawn(move || {
            let backing = SoftwareKeystore::open(ks_path).unwrap();
            let mut srv = ChannelServer::new(&chan_path, HANDLE, ChannelSecret::from_bytes(SECRET));
            let mut handler = |op: Op| handle_op(&backing, HANDLE, op);
            let _ = srv.serve(&mut handler, &server_shutdown);
        });

        // Client holds a *different* secret → its requests never authenticate.
        let mut client =
            DelegatedKeystore::open(chan.path(), HANDLE, ChannelSecret::from_bytes([7u8; 32]));
        client.timeout = Duration::from_millis(150); // keep the test fast
        let signing = KeyLabel::from_handle(HANDLE, Purpose::Signing).unwrap();
        let err = client.generate(&signing, "ES256").unwrap_err();
        assert_eq!(err.code, "network_error"); // timed out (request dropped, unauthenticated)

        shutdown.store(true, Ordering::Relaxed);
        server.join().unwrap();
    }
}
