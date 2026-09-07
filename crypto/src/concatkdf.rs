// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Concat KDF — the NIST SP 800-56A single-step KDF with SHA-256, in the JOSE
//! `ECDH-ES` `OtherInfo` format (RFC 7518 §4.6.2).
//!
//! This is the key-derivation step of the `ECDH-ES+A256KW` wrap chain
//! (Envelope §5): the ECDH shared secret Z is run through this KDF to produce
//! the 256-bit AES-KW KEK. It is *not* HKDF — JOSE specifies Concat KDF for
//! ECDH-ES, and substituting HKDF would silently break interop with any
//! standards-conformant JOSE library.
//!
//! # P-015 folder binding
//!
//! The `OtherInfo` `PartyVInfo` slot (the JOSE `apv` header) carries agreed
//! contextual data into the derived key. v1 binds a metadata-key wrap to its
//! folder by setting `party_v = root_folder_id` (16 bytes): a blob unwrapped
//! under a *different* folder derives a different KEK, and AES-KW's integrity
//! check rejects it. `apu`/`apv` are part of standard JOSE ECDH-ES, so the
//! bound wrap stays differential-testable against a conformant JOSE library.

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const SHA256_OUT: usize = 32;

/// Append one JOSE `Datum`: a big-endian `uint32` length prefix followed by the
/// data bytes (RFC 7518 §4.6.2 — `AlgorithmID`, `PartyUInfo`, `PartyVInfo` are
/// each encoded this way).
fn push_datum(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Build the JOSE `OtherInfo` (RFC 7518 §4.6.2):
///
/// ```text
/// Datum(algorithm_id) || Datum(party_u) || Datum(party_v) || uint32_be(keydatalen_bits)
/// ```
///
/// `SuppPubInfo` is the `keydatalen` (in bits); `SuppPrivInfo` is empty in v1.
/// `algorithm_id` is the ASCII of the `alg`/`enc` value being derived for
/// (e.g. `"ECDH-ES+A256KW"`), per §4.6.2's Key-Agreement-with-Key-Wrapping case.
pub fn jose_other_info(
    algorithm_id: &[u8],
    party_u: &[u8],
    party_v: &[u8],
    keydatalen_bits: u32,
) -> Vec<u8> {
    let mut info = Vec::new();
    push_datum(&mut info, algorithm_id);
    push_datum(&mut info, party_u);
    push_datum(&mut info, party_v);
    info.extend_from_slice(&keydatalen_bits.to_be_bytes());
    info
}

/// SP 800-56A single-step KDF with SHA-256. Returns `out_len` bytes.
///
/// Each round `i` (1-based) computes `SHA-256(uint32_be(i) || z || other_info)`;
/// rounds are concatenated and truncated to `out_len`. v1 only ever derives a
/// 256-bit KEK (`out_len = 32`), a single round — but the loop is the general
/// construction so it stays a faithful KDF, not a one-off.
pub fn concat_kdf_sha256(z: &[u8], other_info: &[u8], out_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(out_len);
    let mut counter: u32 = 1;
    while out.len() < out_len {
        let mut hash = Sha256::new();
        hash.update(counter.to_be_bytes());
        hash.update(z);
        hash.update(other_info);
        out.extend_from_slice(&hash.finalize());
        counter += 1;
    }
    out.truncate(out_len);
    out
}

/// Derive the 256-bit `ECDH-ES+A256KW` key-wrapping KEK from the ECDH shared
/// secret `z` (Envelope §5 step 3). `party_v` binds the KEK to a context: empty
/// for the DEK wrap, `root_folder_id` (16 bytes) for the metadata-key wrap
/// (P-015). `party_u` is empty in v1.
///
/// The KEK is returned [`Zeroizing`] and the intermediate KDF buffer is wiped
/// (PQR Crypto Spec §4.6 — the combiner-intermediates zeroization clause covers
/// the classical combiner too).
pub fn ecdh_es_a256kw_kek(z: &[u8], party_v: &[u8]) -> Zeroizing<[u8; 32]> {
    let info = jose_other_info(
        crate::alg::AlgId::EcdhEsA256Kw.as_jose().as_bytes(),
        &[],
        party_v,
        256,
    );
    let mut kek = concat_kdf_sha256(z, &info, SHA256_OUT);
    let out = Zeroizing::new(
        <[u8; 32]>::try_from(&kek[..]).expect("concat_kdf_sha256(32) yields 32 bytes"),
    );
    kek.zeroize();
    out
}
