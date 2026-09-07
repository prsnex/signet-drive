// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! The `software` keystore backend.
//!
//! Keys live as files under the keystore dir (`~/.config/signet/keys/` by default,
//! `$SIGNET_KEYS_DIR` in containers). Each key's private scalar is held
//! **AES-256-GCM-sealed under a keystore KEK** — the same at-rest envelope shape as
//! the server's signing key (`server_key.rs`): `nonce(12) ‖ ct‖tag`, with an AAD
//! binding the blob to its label (domain separation; prevents swapping one key
//! file's ciphertext under another label).
//!
//! **Honest at-rest framing (named for the pre-launch crypto-code review,
//! S011 §8 item 3):** the `software` tier's KEK is stored locally
//! (`keystore.kek`, 0600), so at-rest protection is bounded by host disk
//! encryption + file permissions — *not* hardware non-extractability. **For a
//! real PRSN this tier is rejected (SE-only, S052); `software` is dev/test/CI
//! only** — it backs the CI-testable path and the non-macOS target build, never
//! a production PRSN.

use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ml_kem::{EncodedSizeUser, KemCore};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::{KeyLabel, KeyMeta, Keystore, Purpose, Tier};
use crate::error::{CliError, Result};

const KEK_FILE: &str = "keystore.kek";
const AT_REST_AAD_DOMAIN: &[u8] = b"signet-cli-keystore-v1\0";

/// The on-disk key record (`<handle>-<purpose>.json`).
#[derive(Serialize, Deserialize)]
struct StoredKey {
    label: String,
    purpose: String,
    algorithm: String,
    tier: String,
    fingerprint: String,
    /// X9.63 uncompressed public key, base64url-no-pad.
    public_key_b64url: String,
    /// `nonce(12) ‖ AES-256-GCM(scalar)`, standard base64.
    scalar_blob_b64: String,
}

pub struct SoftwareKeystore {
    dir: PathBuf,
    kek: Zeroizing<[u8; 32]>,
}

impl SoftwareKeystore {
    /// Open (creating if absent) the keystore at `dir`, loading or minting the KEK.
    pub fn open(dir: PathBuf) -> Result<Self> {
        ensure_dir(&dir)?;
        let kek = load_or_create_kek(&dir)?;
        Ok(Self { dir, kek })
    }

    fn key_path(&self, label: &KeyLabel) -> PathBuf {
        self.dir.join(format!("{}.json", label.full()))
    }

    fn read_stored(&self, label: &KeyLabel) -> Result<StoredKey> {
        let path = self.key_path(label);
        let text = std::fs::read_to_string(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => CliError::key_not_found(format!(
                "no key '{}'. 'signet keys list' shows what this keystore holds",
                label.full()
            )),
            _ => CliError::filesystem(format!("reading {}: {e}", path.display())),
        })?;
        serde_json::from_str(&text)
            .map_err(|e| CliError::filesystem(format!("parsing {}: {e}", path.display())))
    }

    fn open_scalar(&self, label: &KeyLabel, stored: &StoredKey) -> Result<Zeroizing<[u8; 32]>> {
        let plain = self.open_bytes(label, stored)?;
        let scalar: [u8; 32] = plain
            .as_slice()
            .try_into()
            .map_err(|_| CliError::decrypt_failed("decrypted scalar wrong length"))?;
        Ok(Zeroizing::new(scalar))
    }

    /// Seal an arbitrary-length secret under the keystore KEK (the classical
    /// 32-byte scalars and the PQ seeds — 32 (ML-DSA ξ) / 64 (ML-KEM d‖z) —
    /// share one envelope shape).
    fn seal_bytes(&self, label: &KeyLabel, secret: &[u8]) -> Result<String> {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ct = signet_crypto::aead::seal(&self.kek, &nonce, secret, &at_rest_aad(label))?;
        let mut blob = Vec::with_capacity(12 + ct.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        Ok(STANDARD.encode(blob))
    }

    fn open_bytes(&self, label: &KeyLabel, stored: &StoredKey) -> Result<Zeroizing<Vec<u8>>> {
        let blob = STANDARD
            .decode(&stored.scalar_blob_b64)
            .map_err(|_| CliError::filesystem("malformed stored scalar blob"))?;
        if blob.len() < 12 {
            return Err(CliError::filesystem("stored scalar blob truncated"));
        }
        let (nonce, ct) = blob.split_at(12);
        let nonce: &[u8; 12] = nonce.try_into().expect("12-byte nonce");
        Ok(Zeroizing::new(signet_crypto::aead::open(
            &self.kek,
            nonce,
            ct,
            &at_rest_aad(label),
        )?))
    }
}

impl Keystore for SoftwareKeystore {
    fn tier(&self) -> Tier {
        Tier::Software
    }

    fn generate(&self, label: &KeyLabel, algorithm: &str) -> Result<KeyMeta> {
        if self.key_path(label).exists() {
            return Err(CliError::key_exists(format!(
                "a key '{}' already exists; delete it first",
                label.full()
            )));
        }
        // The PQ purposes hold the FIPS seed(s) as the sealed secret (32-byte
        // ML-DSA ξ; 64-byte ML-KEM d‖z) and regenerate the expanded key per op —
        // real software PQ keys (item 7a: the enrollment PoP runs on this tier
        // in tests/harnesses; a production PRSN stays SE-only, server-enforced).
        // PQ fingerprints are `fingerprint_raw` (§8.5), not the classical SPKI form.
        let (secret, public_key, fingerprint): (Zeroizing<Vec<u8>>, Vec<u8>, String) =
            match label.purpose() {
                Purpose::Signing => {
                    let (scalar, public) = signet_crypto::ecdsa::generate_keypair();
                    let fp = signet_crypto::pubkey::fingerprint(&public)?;
                    (Zeroizing::new(scalar.to_vec()), public, fp)
                }
                Purpose::Kem => {
                    let (scalar, public) = signet_crypto::ecdh::generate_keypair();
                    let fp = signet_crypto::pubkey::fingerprint(&public)?;
                    (Zeroizing::new(scalar.to_vec()), public, fp)
                }
                Purpose::SigningPq => {
                    let mut seed = Zeroizing::new([0u8; 32]);
                    OsRng.fill_bytes(&mut *seed);
                    let sk = ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa87>::from_seed(
                        &ml_dsa::Seed::try_from(&seed[..]).expect("32-byte seed"),
                    );
                    let public = sk.verifying_key().encode().to_vec();
                    let fp = signet_crypto::pubkey::fingerprint_raw(&public);
                    (Zeroizing::new(seed.to_vec()), public, fp)
                }
                Purpose::KemPq => {
                    let mut dz = Zeroizing::new([0u8; 64]);
                    OsRng.fill_bytes(&mut *dz);
                    let d = ml_kem::B32::try_from(&dz[..32]).expect("32-byte d");
                    let z = ml_kem::B32::try_from(&dz[32..]).expect("32-byte z");
                    let (_dk, ek) = ml_kem::MlKem1024::generate_deterministic(&d, &z);
                    let public = ek.as_bytes().to_vec();
                    let fp = signet_crypto::pubkey::fingerprint_raw(&public);
                    (Zeroizing::new(dz.to_vec()), public, fp)
                }
            };
        let scalar_blob_b64 = self.seal_bytes(label, &secret)?;
        let stored = StoredKey {
            label: label.full(),
            purpose: label.purpose().as_str().to_string(),
            algorithm: algorithm.to_string(),
            tier: Tier::Software.as_str().to_string(),
            fingerprint: fingerprint.clone(),
            public_key_b64url: URL_SAFE_NO_PAD.encode(&public_key),
            scalar_blob_b64,
        };
        let bytes = serde_json::to_vec_pretty(&stored)
            .map_err(|e| CliError::generic(format!("serializing key record: {e}")))?;
        write_secret_file(&self.key_path(label), &bytes)?;
        Ok(KeyMeta {
            label: stored.label,
            purpose: stored.purpose,
            algorithm: stored.algorithm,
            storage: stored.tier,
            fingerprint,
            public_key,
        })
    }

    fn meta(&self, label: &KeyLabel) -> Result<KeyMeta> {
        let stored = self.read_stored(label)?;
        to_meta(stored)
    }

    fn sign(&self, label: &KeyLabel, msg: &[u8]) -> Result<[u8; 64]> {
        if label.purpose() != Purpose::Signing {
            return Err(CliError::unsupported_algorithm(
                "sign requires a signing (ES256) key",
            ));
        }
        let stored = self.read_stored(label)?;
        let scalar = self.open_scalar(label, &stored)?;
        Ok(signet_crypto::ecdsa::sign_es256(&scalar, msg)?)
    }

    fn ecdh(&self, label: &KeyLabel, peer_pub_x963: &[u8]) -> Result<[u8; 32]> {
        if label.purpose() != Purpose::Kem {
            return Err(CliError::unsupported_algorithm(
                "ecdh requires a KEM (ECDH) key",
            ));
        }
        let stored = self.read_stored(label)?;
        let scalar = self.open_scalar(label, &stored)?;
        Ok(signet_crypto::ecdh::ecdh_p256(&scalar, peer_pub_x963)?)
    }

    fn ml_kem_decapsulate(&self, label: &KeyLabel, ek: &[u8]) -> Result<[u8; 32]> {
        use kem::Decapsulate;
        if label.purpose() != Purpose::KemPq {
            return Err(CliError::unsupported_algorithm(
                "ml-kem decapsulation requires a kem-pq (ML-KEM-1024) key",
            ));
        }
        let stored = self.read_stored(label)?;
        let dz = self.open_bytes(label, &stored)?;
        if dz.len() != 64 {
            return Err(CliError::decrypt_failed("stored ML-KEM seed wrong length"));
        }
        let d = ml_kem::B32::try_from(&dz[..32]).expect("32-byte d");
        let z = ml_kem::B32::try_from(&dz[32..]).expect("32-byte z");
        let (dk, _ek) = ml_kem::MlKem1024::generate_deterministic(&d, &z);
        let ct = ml_kem::Ciphertext::<ml_kem::MlKem1024>::try_from(ek)
            .map_err(|_| CliError::invalid_data("ml-kem ciphertext must be 1568 bytes"))?;
        let ss = dk
            .decapsulate(&ct)
            .map_err(|_| CliError::decrypt_failed("ml-kem decapsulation failed"))?;
        Ok(ss.into())
    }

    fn ml_dsa_sign(&self, label: &KeyLabel, msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>> {
        if label.purpose() != Purpose::SigningPq {
            return Err(CliError::unsupported_algorithm(
                "ml-dsa signing requires a signing-pq (ML-DSA-87) key",
            ));
        }
        super::validate_mldsa_ctx(ctx)?;
        let stored = self.read_stored(label)?;
        let seed = self.open_bytes(label, &stored)?;
        if seed.len() != 32 {
            return Err(CliError::decrypt_failed("stored ML-DSA seed wrong length"));
        }
        let sk = ml_dsa::ExpandedSigningKey::<ml_dsa::MlDsa87>::from_seed(
            &ml_dsa::Seed::try_from(&seed[..]).expect("32-byte seed"),
        );
        // Hedged signing, matching the spec §8 point 3 MUST (and the SE default).
        // SysRng is the OS CSPRNG on ml-dsa's own rand_core lineage (0.10 —
        // distinct from the tree's 0.6 OsRng), via the crate's re-export chain.
        let mut rng = ml_dsa::common::getrandom::SysRng;
        let sig = sk
            .sign_randomized(msg, ctx, &mut rng)
            .map_err(|_| CliError::generic("ml-dsa signing failed"))?;
        Ok(sig.encode().to_vec())
    }

    fn list(&self) -> Result<Vec<KeyMeta>> {
        let mut out = Vec::new();
        let entries = std::fs::read_dir(&self.dir)
            .map_err(|e| CliError::filesystem(format!("reading keystore dir: {e}")))?;
        for entry in entries {
            let entry = entry.map_err(|e| CliError::filesystem(format!("keystore entry: {e}")))?;
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let text = std::fs::read_to_string(&path)
                .map_err(|e| CliError::filesystem(format!("reading {}: {e}", path.display())))?;
            if let Ok(stored) = serde_json::from_str::<StoredKey>(&text) {
                out.push(to_meta(stored)?);
            }
        }
        out.sort_by(|a, b| a.label.cmp(&b.label));
        Ok(out)
    }

    fn delete(&self, label: &KeyLabel) -> Result<()> {
        let path = self.key_path(label);
        if !path.exists() {
            return Err(CliError::key_not_found(format!(
                "no key '{}'. 'signet keys list' shows what this keystore holds",
                label.full()
            )));
        }
        std::fs::remove_file(&path)
            .map_err(|e| CliError::filesystem(format!("deleting {}: {e}", path.display())))
    }

    fn exists(&self, label: &KeyLabel) -> Result<bool> {
        Ok(self.key_path(label).exists())
    }
}

fn to_meta(stored: StoredKey) -> Result<KeyMeta> {
    let public_key = URL_SAFE_NO_PAD
        .decode(&stored.public_key_b64url)
        .map_err(|_| CliError::filesystem("malformed stored public key"))?;
    Ok(KeyMeta {
        label: stored.label,
        purpose: stored.purpose,
        algorithm: stored.algorithm,
        storage: stored.tier,
        fingerprint: stored.fingerprint,
        public_key,
    })
}

fn at_rest_aad(label: &KeyLabel) -> Vec<u8> {
    let mut aad = AT_REST_AAD_DOMAIN.to_vec();
    aad.extend_from_slice(label.full().as_bytes());
    aad
}

fn load_or_create_kek(dir: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let path = dir.join(KEK_FILE);
    if path.exists() {
        let bytes = std::fs::read(&path)
            .map_err(|e| CliError::filesystem(format!("reading keystore KEK: {e}")))?;
        let kek: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| CliError::config("keystore KEK is not 32 bytes"))?;
        Ok(Zeroizing::new(kek))
    } else {
        let mut kek = [0u8; 32];
        OsRng.fill_bytes(&mut kek);
        write_secret_file(&path, &kek)?;
        Ok(Zeroizing::new(kek))
    }
}

fn ensure_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).map_err(|e| {
        CliError::filesystem(format!("creating keystore dir {}: {e}", dir.display()))
    })?;
    set_mode(dir, 0o700)
        .map_err(|e| CliError::filesystem(format!("securing keystore dir: {e}")))?;
    Ok(())
}

/// Write secret bytes to a 0600 file.
fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)
        .map_err(|e| CliError::output_write(format!("writing {}: {e}", path.display())))?;
    set_mode(path, 0o600)
        .map_err(|e| CliError::output_write(format!("securing {}: {e}", path.display())))?;
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}
