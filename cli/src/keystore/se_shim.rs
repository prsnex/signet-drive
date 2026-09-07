// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Safe Rust wrappers over the Swift/CryptoKit Secure-Enclave PQC shim
//! (`cli/shim/SignetSeShim.swift`, compiled + linked by `cli/build.rs`) —
//! PQR item 1.
//!
//! `SecureEnclave.MLKEM1024`/`MLDSA87` are CryptoKit-Swift-only (no `SecKey`
//! path exists — verified against the macOS 26 SDK, S103), so these five calls
//! are the only route from the Rust keystore to the Enclave's PQC. Everything
//! that crosses the ABI is either public (ek/vk, ciphertext, signature) or an
//! SE-sealed opaque blob (`dataRepresentation` — useless off this device); the
//! one secret output, the decapsulated shared secret, is returned [`Zeroizing`]
//! and the transit buffer is wiped.
//!
//! This module is `cfg(target_os = "macos")` via its declaration in
//! [`super`]; Linux never compiles it (nor the Swift).

use zeroize::{Zeroize, Zeroizing};

use crate::error::{CliError, Result};

/// FIPS 204 ML-DSA-87 verification-key length (PQR Spec §2).
pub(crate) const MLDSA87_VK_LEN: usize = 2592;

/// Generous ceiling for the SE-sealed `dataRepresentation` blob (observed:
/// ~1.8 KB for ML-KEM-1024 in the S103 probe; ML-DSA-87 is larger). The shim
/// reports the exact size; this is only the transit-buffer capacity.
const BLOB_CAP: usize = 32 * 1024;
/// Transit-buffer capacity for the shim's truncated UTF-8 error messages.
const ERR_CAP: usize = 512;

// Status codes — keep in sync with shim/SignetSeShim.swift.
const SE_OK: i32 = 0;
const SE_ERR_UNAVAILABLE: i32 = -1;
const SE_ERR_BAD_BLOB: i32 = -3;

unsafe extern "C" {
    fn signet_se_pq_available() -> i32;
    fn signet_se_mlkem1024_keygen(
        blob_out: *mut u8,
        blob_cap: usize,
        blob_len: *mut usize,
        ek_out: *mut u8,
        ek_cap: usize,
        ek_len: *mut usize,
        err_out: *mut u8,
        err_cap: usize,
        err_len: *mut usize,
    ) -> i32;
    fn signet_se_mlkem1024_ek_from_blob(
        blob: *const u8,
        blob_len: usize,
        ek_out: *mut u8,
        ek_cap: usize,
        ek_len: *mut usize,
        err_out: *mut u8,
        err_cap: usize,
        err_len: *mut usize,
    ) -> i32;
    fn signet_se_mlkem1024_decap(
        blob: *const u8,
        blob_len: usize,
        ct: *const u8,
        ct_len: usize,
        ss_out: *mut u8,
        ss_cap: usize,
        err_out: *mut u8,
        err_cap: usize,
        err_len: *mut usize,
    ) -> i32;
    fn signet_se_mldsa87_keygen(
        blob_out: *mut u8,
        blob_cap: usize,
        blob_len: *mut usize,
        vk_out: *mut u8,
        vk_cap: usize,
        vk_len: *mut usize,
        err_out: *mut u8,
        err_cap: usize,
        err_len: *mut usize,
    ) -> i32;
    fn signet_se_mldsa87_vk_from_blob(
        blob: *const u8,
        blob_len: usize,
        vk_out: *mut u8,
        vk_cap: usize,
        vk_len: *mut usize,
        err_out: *mut u8,
        err_cap: usize,
        err_len: *mut usize,
    ) -> i32;
    fn signet_se_mldsa87_sign(
        blob: *const u8,
        blob_len: usize,
        msg: *const u8,
        msg_len: usize,
        ctx: *const u8,
        ctx_len: usize,
        sig_out: *mut u8,
        sig_cap: usize,
        sig_len: *mut usize,
        err_out: *mut u8,
        err_cap: usize,
        err_len: *mut usize,
    ) -> i32;
}

/// Whether the SE-PQC API is available at runtime (macOS 26+). A pure
/// availability probe — does not touch the Enclave.
pub(crate) fn pq_available() -> bool {
    (unsafe { signet_se_pq_available() }) == 1
}

/// A generated SE PQ key: the sealed blob (persist it) + the public key bytes
/// (FIPS 203 ek / FIPS 204 vk).
pub(crate) struct PqKeygenOut {
    pub blob: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// Map a shim status + error-buffer to a [`CliError`] with the shim's message.
fn shim_err(op: &str, status: i32, err_buf: &[u8], err_len: usize) -> CliError {
    let detail = String::from_utf8_lossy(&err_buf[..err_len.min(err_buf.len())]).to_string();
    match status {
        SE_ERR_UNAVAILABLE => CliError::unsupported_platform(format!(
            "{op}: Secure-Enclave PQC requires macOS 26 ({detail})"
        )),
        SE_ERR_BAD_BLOB => CliError::invalid_data(format!(
            "{op}: the stored Secure-Enclave key blob was rejected ({detail})"
        )),
        _ => CliError::generic(format!("{op} failed (shim status {status}): {detail}")),
    }
}

/// Generate an ML-KEM-1024 key in the Secure Enclave → (sealed blob, ek 1568 B).
pub(crate) fn mlkem1024_keygen() -> Result<PqKeygenOut> {
    let mut blob = vec![0u8; BLOB_CAP];
    let mut ek = vec![0u8; signet_crypto::hybrid_wrap::MLKEM1024_EK_LEN];
    let (mut blob_len, mut ek_len, mut err_len) = (0usize, 0usize, 0usize);
    let mut err = vec![0u8; ERR_CAP];
    let status = unsafe {
        signet_se_mlkem1024_keygen(
            blob.as_mut_ptr(),
            blob.len(),
            &mut blob_len,
            ek.as_mut_ptr(),
            ek.len(),
            &mut ek_len,
            err.as_mut_ptr(),
            err.len(),
            &mut err_len,
        )
    };
    if status != SE_OK {
        return Err(shim_err("SE ML-KEM-1024 keygen", status, &err, err_len));
    }
    if ek_len != signet_crypto::hybrid_wrap::MLKEM1024_EK_LEN {
        return Err(CliError::generic(format!(
            "SE ML-KEM-1024 keygen returned a {ek_len}-byte encapsulation key (want 1568)"
        )));
    }
    blob.truncate(blob_len);
    Ok(PqKeygenOut {
        blob,
        public_key: ek,
    })
}

/// Recover the encapsulation key (1568 B) from a sealed ML-KEM-1024 blob.
pub(crate) fn mlkem1024_ek_from_blob(blob: &[u8]) -> Result<Vec<u8>> {
    let mut ek = vec![0u8; signet_crypto::hybrid_wrap::MLKEM1024_EK_LEN];
    let (mut ek_len, mut err_len) = (0usize, 0usize);
    let mut err = vec![0u8; ERR_CAP];
    let status = unsafe {
        signet_se_mlkem1024_ek_from_blob(
            blob.as_ptr(),
            blob.len(),
            ek.as_mut_ptr(),
            ek.len(),
            &mut ek_len,
            err.as_mut_ptr(),
            err.len(),
            &mut err_len,
        )
    };
    if status != SE_OK {
        return Err(shim_err(
            "SE ML-KEM-1024 key restore",
            status,
            &err,
            err_len,
        ));
    }
    if ek_len != signet_crypto::hybrid_wrap::MLKEM1024_EK_LEN {
        return Err(CliError::generic(format!(
            "SE ML-KEM-1024 restore returned a {ek_len}-byte encapsulation key (want 1568)"
        )));
    }
    Ok(ek)
}

/// Decapsulate a 1568-byte ML-KEM-1024 ciphertext in the Enclave → `Z_mlkem`.
/// Per FIPS 203 implicit rejection (spec §10), a tampered ciphertext does NOT
/// error — it yields a pseudorandom secret; the failure surfaces downstream at
/// AES-KW.
pub(crate) fn mlkem1024_decap(blob: &[u8], ct: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if ct.len() != signet_crypto::hybrid_wrap::MLKEM1024_CT_LEN {
        return Err(CliError::invalid_args(format!(
            "ml-kem ciphertext must be {} bytes, got {}",
            signet_crypto::hybrid_wrap::MLKEM1024_CT_LEN,
            ct.len()
        )));
    }
    let mut ss = Zeroizing::new([0u8; 32]);
    let mut err_len = 0usize;
    let mut err = vec![0u8; ERR_CAP];
    let status = unsafe {
        signet_se_mlkem1024_decap(
            blob.as_ptr(),
            blob.len(),
            ct.as_ptr(),
            ct.len(),
            ss.as_mut_ptr(),
            ss.len(),
            err.as_mut_ptr(),
            err.len(),
            &mut err_len,
        )
    };
    if status != SE_OK {
        return Err(shim_err(
            "SE ML-KEM-1024 decapsulation",
            status,
            &err,
            err_len,
        ));
    }
    Ok(ss)
}

/// Generate an ML-DSA-87 key in the Secure Enclave → (sealed blob, vk 2592 B).
pub(crate) fn mldsa87_keygen() -> Result<PqKeygenOut> {
    let mut blob = vec![0u8; BLOB_CAP];
    let mut vk = vec![0u8; MLDSA87_VK_LEN];
    let (mut blob_len, mut vk_len, mut err_len) = (0usize, 0usize, 0usize);
    let mut err = vec![0u8; ERR_CAP];
    let status = unsafe {
        signet_se_mldsa87_keygen(
            blob.as_mut_ptr(),
            blob.len(),
            &mut blob_len,
            vk.as_mut_ptr(),
            vk.len(),
            &mut vk_len,
            err.as_mut_ptr(),
            err.len(),
            &mut err_len,
        )
    };
    if status != SE_OK {
        return Err(shim_err("SE ML-DSA-87 keygen", status, &err, err_len));
    }
    if vk_len != MLDSA87_VK_LEN {
        return Err(CliError::generic(format!(
            "SE ML-DSA-87 keygen returned a {vk_len}-byte verification key (want {MLDSA87_VK_LEN})"
        )));
    }
    blob.truncate(blob_len);
    Ok(PqKeygenOut {
        blob,
        public_key: vk,
    })
}

/// Recover the verification key (2592 B) from a sealed ML-DSA-87 blob.
pub(crate) fn mldsa87_vk_from_blob(blob: &[u8]) -> Result<Vec<u8>> {
    let mut vk = vec![0u8; MLDSA87_VK_LEN];
    let (mut vk_len, mut err_len) = (0usize, 0usize);
    let mut err = vec![0u8; ERR_CAP];
    let status = unsafe {
        signet_se_mldsa87_vk_from_blob(
            blob.as_ptr(),
            blob.len(),
            vk.as_mut_ptr(),
            vk.len(),
            &mut vk_len,
            err.as_mut_ptr(),
            err.len(),
            &mut err_len,
        )
    };
    if status != SE_OK {
        return Err(shim_err("SE ML-DSA-87 key restore", status, &err, err_len));
    }
    if vk_len != MLDSA87_VK_LEN {
        return Err(CliError::generic(format!(
            "SE ML-DSA-87 restore returned a {vk_len}-byte verification key (want {MLDSA87_VK_LEN})"
        )));
    }
    Ok(vk)
}

/// Sign `msg` with the SE-resident ML-DSA-87 key (hedged — the SE default),
/// `ctx` as the FIPS 204 context parameter (spec §8.7). → 4627-byte signature.
pub(crate) fn mldsa87_sign(blob: &[u8], msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>> {
    super::validate_mldsa_ctx(ctx)?;
    let mut sig = vec![0u8; super::ML_DSA_87_SIG_LEN];
    let (mut sig_len, mut err_len) = (0usize, 0usize);
    let mut err = vec![0u8; ERR_CAP];
    let status = unsafe {
        signet_se_mldsa87_sign(
            blob.as_ptr(),
            blob.len(),
            msg.as_ptr(),
            msg.len(),
            ctx.as_ptr(),
            ctx.len(),
            sig.as_mut_ptr(),
            sig.len(),
            &mut sig_len,
            err.as_mut_ptr(),
            err.len(),
            &mut err_len,
        )
    };
    if status != SE_OK {
        // Nothing secret in a failed sign buffer, but wipe for hygiene symmetry.
        sig.zeroize();
        return Err(shim_err("SE ML-DSA-87 signing", status, &err, err_len));
    }
    if sig_len != super::ML_DSA_87_SIG_LEN {
        return Err(CliError::generic(format!(
            "SE ML-DSA-87 signing returned a {sig_len}-byte signature (want {})",
            super::ML_DSA_87_SIG_LEN
        )));
    }
    Ok(sig)
}
