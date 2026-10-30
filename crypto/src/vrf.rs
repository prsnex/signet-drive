// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! The transparency log's v3 account index: a VRF over the account id
//! (Transparency-Log Epoch-2 design v03 §2, decided by Gus 2026-10-29).
//!
//! A log entry carries `index = VRF(server VRF key, alpha(account_id))` instead
//! of the account id. Only the server can compute it; anyone given the proof can
//! check it; and it is unique per account, so the server cannot mint a second
//! index for one account and hide a substituted key under it (the owner's watch,
//! design §2 property (b)). Deleting an account touches nothing in the log.
//!
//! The suite is **ECVRF-RISTRETTO255-SHA512** (c2sp.org/vrf-r255; RFC 9381's
//! ECVRF construction over the RFC 9496 ristretto255 group), via the pinned
//! `vrf-r255` crate (crate read: `homes/gus/tasks/Signet VRF crate read`). This
//! module only frames the input and holds the key; it implements no part of the
//! VRF itself.
//!
//! The index is the VRF output β **whole**, 64 bytes, never truncated.
//!
//! ⚠ `vrf_r255::SecretKey` derives `Copy` and `Debug`: a stray `{:?}` would print
//! the scalar, and copies cannot be reliably zeroized. [`VrfSecretKey`] holds the
//! key as zeroizing bytes, has a redacting `Debug`, and rebuilds the crate's key
//! only for the duration of one [`VrfSecretKey::prove`].

use core::fmt;

use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

/// The suite name as it appears in `vrf-keys.jsonl` and `/v1/server-info`.
pub const VRF_SUITE: &str = "ECVRF-RISTRETTO255-SHA512";

/// Byte length of a VRF public key (a compressed ristretto255 point).
pub const PUBLIC_KEY_LEN: usize = 32;
/// Byte length of a VRF proof (`Gamma ‖ c ‖ s`, 32 + 16 + 32).
pub const PROOF_LEN: usize = 80;
/// Byte length of the index (the VRF output β, SHA-512).
pub const INDEX_LEN: usize = 64;

/// The domain that frames every alpha, so a proof made for the log's account
/// index can never be presented as a VRF value for any other use of the key.
pub const ALPHA_DOMAIN: &[u8] = b"signet-pubkey-log-v3-account-index";

/// The VRF input for an account: `ALPHA_DOMAIN ‖ 0x00 ‖ account_id (16 raw bytes)`.
/// The `0x00` separates the fixed domain from the fixed-length id; both lengths
/// are fixed, so the framing is unambiguous.
pub fn alpha(account_id: &[u8; 16]) -> Vec<u8> {
    let mut a = Vec::with_capacity(ALPHA_DOMAIN.len() + 1 + 16);
    a.extend_from_slice(ALPHA_DOMAIN);
    a.push(0x00);
    a.extend_from_slice(account_id);
    a
}

/// The server's VRF secret key. Never logged, never serialized except by
/// [`VrfSecretKey::to_bytes`] for encrypted-at-rest storage.
pub struct VrfSecretKey {
    bytes: Zeroizing<[u8; 32]>,
    public: [u8; PUBLIC_KEY_LEN],
}

impl fmt::Debug for VrfSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VrfSecretKey")
            .field("public", &hex::encode(self.public))
            .finish_non_exhaustive()
    }
}

impl VrfSecretKey {
    /// A fresh key from the OS RNG. Retries on the (negligible) non-canonical
    /// draw rather than reducing, so every key is a uniformly random scalar.
    pub fn generate() -> Self {
        loop {
            let mut raw = Zeroizing::new([0u8; 32]);
            OsRng.fill_bytes(&mut raw[..]);
            if let Ok(key) = Self::from_bytes(&raw) {
                return key;
            }
        }
    }

    /// Load a key from its 32-byte canonical scalar encoding. Refuses a
    /// non-canonical scalar and the zero key (whose public key is the identity).
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let sk = Option::<vrf_r255::SecretKey>::from(vrf_r255::SecretKey::from_bytes(*bytes))
            .ok_or(CryptoError::InvalidInput("VRF secret key"))?;
        let public = vrf_r255::PublicKey::from(sk).to_bytes();
        Ok(Self {
            bytes: Zeroizing::new(*bytes),
            public,
        })
    }

    /// The 32-byte canonical encoding, for encrypted-at-rest storage only.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.bytes)
    }

    /// The public key, as published in `vrf-keys.jsonl`.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.public
    }

    /// `(index, proof)` for an account: the VRF output β and the proof that
    /// binds it to this key and this account.
    pub fn prove(&self, account_id: &[u8; 16]) -> Result<([u8; INDEX_LEN], [u8; PROOF_LEN])> {
        let sk = Option::<vrf_r255::SecretKey>::from(vrf_r255::SecretKey::from_bytes(*self.bytes))
            .ok_or(CryptoError::InvalidInput("VRF secret key"))?;
        let a = alpha(account_id);
        let proof = sk.prove(&a);
        // The output is read back through the verifier, so a key/proof mismatch
        // could never yield an index the verifier would not also derive.
        let index = verify(&self.public, account_id, &proof.to_bytes())?;
        Ok((index, proof.to_bytes()))
    }
}

/// Verify `proof` for `account_id` under `public_key` and return the index it
/// proves. Fails closed: a malformed key, a malformed proof, and a proof that
/// does not verify are all refused, and no index is returned.
pub fn verify(
    public_key: &[u8; PUBLIC_KEY_LEN],
    account_id: &[u8; 16],
    proof: &[u8; PROOF_LEN],
) -> Result<[u8; INDEX_LEN]> {
    let pk = vrf_r255::PublicKey::from_bytes(*public_key)
        .ok_or(CryptoError::InvalidInput("VRF public key"))?;
    let pi = vrf_r255::Proof::from_bytes(*proof).ok_or(CryptoError::InvalidInput("VRF proof"))?;
    Option::<[u8; INDEX_LEN]>::from(pk.verify(&alpha(account_id), &pi))
        .ok_or(CryptoError::SignatureInvalid)
}
