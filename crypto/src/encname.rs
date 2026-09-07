// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Encrypted file/folder names (Envelope §7.3).
//!
//! A file or folder name is encrypted with its share folder's **metadata key**
//! (a per-root-folder AES key, itself wrapped to each recipient via the §7.2
//! `ECDH-ES+A256KW` wrap). `A256GCM`; the AAD is `root_folder_id ‖ target_id`
//! (the 16-byte UUIDs), so a name ciphertext is bound to *its* file/folder under
//! *its* root — the server can't move an encrypted name to another target.
//!
//! Unlike the file envelope (§4.1, which glues `[IV][ct][tag]`), the name
//! envelope is a JSON object with the IV, ciphertext, and tag as **separate**
//! base64url-no-pad fields (the CLI `signet encrypt-name` output shape).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::aead;
use crate::alg::AlgId;
use crate::error::{CryptoError, Result};

const GCM_TAG_LEN: usize = 16;

/// The §7.3 encrypted-name envelope (JSON; base64url-no-pad fields).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameEnvelope {
    pub v: u32,
    pub alg: String,
    pub iv: String,
    pub ct: String,
    pub tag: String,
}

/// AAD binding a name to its folder + target: `root_folder_id ‖ target_id`.
fn name_aad(root_folder_id: &[u8; 16], target_id: &[u8; 16]) -> [u8; 32] {
    let mut aad = [0u8; 32];
    aad[..16].copy_from_slice(root_folder_id);
    aad[16..].copy_from_slice(target_id);
    aad
}

/// Encrypt a UTF-8 `name` under a folder's `metadata_key` (Envelope §7.3). The
/// IV is fresh random per call (the metadata key is reused across names, so a
/// unique IV per encryption is required).
pub fn encrypt_name(
    metadata_key: &[u8; 32],
    root_folder_id: &[u8; 16],
    target_id: &[u8; 16],
    name: &str,
) -> Result<NameEnvelope> {
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let sealed = aead::seal(
        metadata_key,
        &iv,
        name.as_bytes(),
        &name_aad(root_folder_id, target_id),
    )?; // ciphertext || tag
    let split = sealed
        .len()
        .checked_sub(GCM_TAG_LEN)
        .ok_or(CryptoError::InvalidInput("aead output shorter than tag"))?;
    Ok(NameEnvelope {
        v: 1,
        alg: AlgId::A256Gcm.as_jose().to_string(),
        iv: URL_SAFE_NO_PAD.encode(iv),
        ct: URL_SAFE_NO_PAD.encode(&sealed[..split]),
        tag: URL_SAFE_NO_PAD.encode(&sealed[split..]),
    })
}

/// Decrypt a §7.3 name envelope; returns the UTF-8 name. `root_folder_id` +
/// `target_id` MUST match the values it was encrypted under, or the GCM tag
/// fails ([`CryptoError::Authentication`]).
pub fn decrypt_name(
    metadata_key: &[u8; 32],
    root_folder_id: &[u8; 16],
    target_id: &[u8; 16],
    envelope: &NameEnvelope,
) -> Result<String> {
    if AlgId::from_jose(&envelope.alg)? != AlgId::A256Gcm {
        return Err(CryptoError::UnknownAlgorithm);
    }
    let iv: [u8; 12] = URL_SAFE_NO_PAD
        .decode(envelope.iv.as_bytes())
        .map_err(|_| CryptoError::InvalidInput("name iv base64url"))?
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidInput("name iv length"))?;
    let mut ct_and_tag = URL_SAFE_NO_PAD
        .decode(envelope.ct.as_bytes())
        .map_err(|_| CryptoError::InvalidInput("name ct base64url"))?;
    let tag = URL_SAFE_NO_PAD
        .decode(envelope.tag.as_bytes())
        .map_err(|_| CryptoError::InvalidInput("name tag base64url"))?;
    ct_and_tag.extend_from_slice(&tag);
    let plain = aead::open(
        metadata_key,
        &iv,
        &ct_and_tag,
        &name_aad(root_folder_id, target_id),
    )?;
    String::from_utf8(plain).map_err(|_| CryptoError::InvalidInput("decrypted name not utf-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_round_trips() {
        let key = [7u8; 32];
        let root = [1u8; 16];
        let target = [2u8; 16];
        let env = encrypt_name(&key, &root, &target, "schema.md").unwrap();
        assert_eq!(env.alg, "A256GCM");
        assert_eq!(
            decrypt_name(&key, &root, &target, &env).unwrap(),
            "schema.md"
        );
    }

    #[test]
    fn wrong_target_fails_closed() {
        let key = [7u8; 32];
        let root = [1u8; 16];
        let env = encrypt_name(&key, &root, &[2u8; 16], "secret.md").unwrap();
        // A different target_id (the AAD) must reject.
        assert_eq!(
            decrypt_name(&key, &root, &[3u8; 16], &env).unwrap_err(),
            CryptoError::Authentication
        );
    }
}
