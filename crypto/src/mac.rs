// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! HMAC-SHA-256 (RFC 2104 / FIPS 198-1).
//!
//! A tier-1 validated primitive (see the crate-level "Validation" note): KAT'd
//! against the RFC 4231 HMAC-SHA-256 test vectors. Added in D2 for **Stripe
//! webhook signature verification** — Stripe signs each webhook event with
//! `HMAC-SHA-256(endpoint_secret, "<timestamp>.<payload>")`, surfaced in the
//! `Stripe-Signature` header's `v1` scheme. The Stripe-specific protocol (header
//! parsing, the signed-payload construction, the timestamp-tolerance check) lives
//! in the server's `stripe` module; this is only the keyed-MAC primitive plus a
//! constant-time verify.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Compute `HMAC-SHA-256(key, msg)`. HMAC admits a key of any length, so this is
/// infallible.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(msg);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// Constant-time check that `tag` equals `HMAC-SHA-256(key, msg)`. Returns
/// `false` for a wrong tag *or* a wrong-length tag — the underlying `verify_slice`
/// compares in constant time, so a near-miss tag leaks nothing via timing. This
/// is the authorization-boundary check for inbound Stripe webhooks: a forged
/// signature must never pass.
pub fn verify_sha256(key: &[u8], msg: &[u8], tag: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(msg);
    mac.verify_slice(tag).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 4231 HMAC-SHA-256 known-answer tests (an oracle independent of this
    // crate — the IETF vectors, not RustCrypto-vs-RustCrypto).
    #[test]
    fn rfc4231_tc1() {
        let key = [0x0b_u8; 20];
        let data = b"Hi There";
        let expected =
            hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
                .unwrap();
        assert_eq!(hmac_sha256(&key, data).as_slice(), expected.as_slice());
        assert!(verify_sha256(&key, data, &expected));
    }

    #[test]
    fn rfc4231_tc2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let expected =
            hex::decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
                .unwrap();
        assert_eq!(hmac_sha256(key, data).as_slice(), expected.as_slice());
        assert!(verify_sha256(key, data, &expected));
    }

    #[test]
    fn rfc4231_tc3() {
        let key = [0xaa_u8; 20];
        let data = [0xdd_u8; 50];
        let expected =
            hex::decode("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")
                .unwrap();
        assert_eq!(hmac_sha256(&key, &data).as_slice(), expected.as_slice());
        assert!(verify_sha256(&key, &data, &expected));
    }

    #[test]
    fn verify_rejects_tampered_tag() {
        let (key, data) = (b"endpoint-secret", b"a.payload");
        let mut tag = hmac_sha256(key, data);
        tag[0] ^= 0x01;
        assert!(!verify_sha256(key, data, &tag));
    }

    #[test]
    fn verify_rejects_wrong_length_tag() {
        let (key, data) = (b"endpoint-secret", b"a.payload");
        assert!(!verify_sha256(key, data, &[0u8; 16]));
        assert!(!verify_sha256(key, data, &[]));
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let data = b"a.payload";
        let tag = hmac_sha256(b"key-one", data);
        assert!(!verify_sha256(b"key-two", data, &tag));
    }
}
