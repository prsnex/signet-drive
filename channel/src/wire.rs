// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! The channel message types — the operation set (mirrors the `Keystore` trait,
//! Account-and-Kit spec §f.2) and the response shapes.
//!
//! These are the **plaintext** message bodies. They never touch the (same-user-
//! readable) channel folder directly: [`crate::auth`] seals each one under the
//! per-PRSN secret first. So the JSON here is an internal representation, not a
//! wire format an observer can read.
//!
//! Byte fields are base64url-encoded in the JSON (see the private `b64` helper) so
//! the structs stay typed (`Vec<u8>`) while the serialized form is compact text.

use serde::{Deserialize, Serialize};

use crate::error::{ChannelError, Result};

/// The wire protocol version. Bound into the AEAD AAD ([`crate::auth`]), so a peer
/// speaking a different version fails to *open* the frame rather than silently
/// misparsing a body.
pub const PROTOCOL_VERSION: u16 = 1;

/// A delegated key operation — one variant per `Keystore` trait method a
/// containerized PRSN must perform in the host Secure Enclave. The in-container
/// delegation client (a `Keystore` impl) emits these; the host-signer executes
/// them against the host SE.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    /// Generate the PRSN's keypair in the host SE (enrollment keygen).
    Keygen { label: String, algorithm: String },
    /// `ES256` over `msg` → raw `r‖s`. `msg` is the full message to sign (the SE
    /// hashes it with SHA-256), matching `Keystore::sign`'s contract.
    Sign {
        label: String,
        #[serde(with = "b64")]
        msg: Vec<u8>,
    },
    /// ECDH P-256 with `peer_pub_x963` → 32-byte shared secret Z. The result Z is
    /// **confidential** — the reason the channel is sealed, not merely MAC'd
    /// (a same-user reader must not learn Z; see [`crate::auth`]).
    Ecdh {
        label: String,
        #[serde(with = "b64")]
        peer_pub_x963: Vec<u8>,
    },
    /// ML-KEM-1024 decapsulation of the 1568-byte ciphertext `ek` → 32-byte shared
    /// secret `Z_mlkem` (PQR Crypto Spec §6 — the PQ half of the hybrid content-wrap,
    /// PQR item 2). Like [`Op::Ecdh`], the result is **confidential** and rides the
    /// sealed channel. Targets a `<handle>-kem-pq` key.
    MlKemDecapsulate {
        label: String,
        #[serde(with = "b64")]
        ek: Vec<u8>,
    },
    /// ML-DSA-87 hedged signature over `msg` with the FIPS 204 context `ctx`
    /// (≤ 255 bytes, supplied as the FIPS 204 context *parameter* — never prepended
    /// to `msg`; PQR Crypto Spec §8.7). The PQ half of the identity dual-signature
    /// (PQR item 2). Targets a `<handle>-signing-pq` key.
    MlDsaSign {
        label: String,
        #[serde(with = "b64")]
        msg: Vec<u8>,
        #[serde(with = "b64")]
        ctx: Vec<u8>,
    },
    /// Public-key metadata for an existing key.
    Meta { label: String },
    /// Whether a key exists.
    Exists { label: String },
    /// List every key held for this channel's PRSN. No parameters — the
    /// host-signer scopes the result to the channel's registered handle.
    List,
    /// The PRSN handle the host-signer has pinned to **this channel** (TOFU on the
    /// first enrollment keygen), or `None` if the channel is not yet enrolled. No SE
    /// access — a host-side state read. It lets a containerized PRSN learn its own
    /// identity from the *independent* host-side pin and **cross-check** it against
    /// the harness-asserted `SIGNET_HANDLE` (launch-binding verification — fail
    /// closed on mismatch; the pinned handle is the PRSN's own, public, channel-
    /// scoped — not a secret).
    Identity,
    /// Delete a key.
    Delete { label: String },
}

impl Op {
    /// Serialize to the plaintext body bytes that [`crate::auth`] seals.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| ChannelError::Serialization(e.to_string()))
    }

    /// Parse a plaintext body (after [`crate::auth`] has opened the frame).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| ChannelError::Serialization(e.to_string()))
    }
}

/// The successful result of an [`Op`], mirroring the `KeyMeta` / trait return
/// shapes. The variant must correspond to the request's [`Op`]; the in-container
/// client checks the correspondence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum OpOk {
    Keygen {
        #[serde(with = "b64")]
        public_key: Vec<u8>,
        fingerprint: String,
        algorithm: String,
    },
    Sign {
        #[serde(with = "b64")]
        signature: Vec<u8>,
    },
    Ecdh {
        #[serde(with = "b64")]
        shared_secret: Vec<u8>,
    },
    /// 32-byte `Z_mlkem` (confidential, like [`OpOk::Ecdh`]).
    MlKemDecapsulate {
        #[serde(with = "b64")]
        shared_secret: Vec<u8>,
    },
    /// The 4627-byte ML-DSA-87 signature.
    MlDsaSign {
        #[serde(with = "b64")]
        signature: Vec<u8>,
    },
    Meta {
        #[serde(with = "b64")]
        public_key: Vec<u8>,
        fingerprint: String,
        algorithm: String,
        purpose: String,
    },
    Exists {
        exists: bool,
    },
    List {
        keys: Vec<KeyEntry>,
    },
    /// The channel's pinned PRSN handle, or `None` if the channel is not yet enrolled.
    Identity {
        handle: Option<String>,
    },
    /// A successful delete (no payload).
    Delete,
}

/// One key in an [`OpOk::List`] result — the wire form of the host-signer's
/// `KeyMeta`. The in-container client reconstructs its own `KeyMeta`, filling the
/// `storage` field from its tier (the keys live in *an* SE — the host's).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEntry {
    pub label: String,
    pub purpose: String,
    pub algorithm: String,
    pub fingerprint: String,
    #[serde(with = "b64")]
    pub public_key: Vec<u8>,
}

/// An operation error — the host-signer could not perform the op (no such key,
/// wrong purpose, an SE error, …). Carries a stable `code` + a human `message`,
/// mirroring `CliError`'s shape so the in-container client can re-raise it
/// faithfully (this crate does not depend on `signet-cli`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpErr {
    pub code: String,
    pub message: String,
}

/// The response body: the op result, or an error. Carried sealed, same as [`Op`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Response {
    Ok(OpOk),
    Err(OpErr),
}

impl Response {
    /// Serialize to the plaintext body bytes that [`crate::auth`] seals.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| ChannelError::Serialization(e.to_string()))
    }

    /// Parse a plaintext body (after [`crate::auth`] has opened the frame).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| ChannelError::Serialization(e.to_string()))
    }
}

/// serde (de)serialization of a `Vec<u8>` field as a base64url-no-pad string.
mod b64 {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_roundtrips_through_bytes() {
        let ops = [
            Op::Keygen {
                label: "hlin-ai-signing".into(),
                algorithm: "ES256".into(),
            },
            Op::Sign {
                label: "hlin-ai-signing".into(),
                msg: vec![1, 2, 3, 4, 250, 251, 252],
            },
            Op::Ecdh {
                label: "hlin-ai-kem".into(),
                peer_pub_x963: vec![0x04; 65],
            },
            Op::MlKemDecapsulate {
                label: "hlin-ai-kem-pq".into(),
                ek: vec![0xE2; 1568],
            },
            Op::MlDsaSign {
                label: "hlin-ai-signing-pq".into(),
                msg: vec![1, 2, 3],
                ctx: b"signet:req:v1".to_vec(),
            },
            Op::Meta {
                label: "hlin-ai-kem".into(),
            },
            Op::Exists {
                label: "hlin-ai-signing".into(),
            },
            Op::List,
            Op::Identity,
            Op::Delete {
                label: "hlin-ai-kem".into(),
            },
        ];
        for op in ops {
            let bytes = op.to_bytes().unwrap();
            assert_eq!(Op::from_bytes(&bytes).unwrap(), op);
        }
    }

    #[test]
    fn response_roundtrips_through_bytes() {
        let responses = [
            Response::Ok(OpOk::Sign {
                signature: vec![7u8; 64],
            }),
            Response::Ok(OpOk::Ecdh {
                shared_secret: vec![9u8; 32],
            }),
            Response::Ok(OpOk::MlKemDecapsulate {
                shared_secret: vec![0x0Bu8; 32],
            }),
            Response::Ok(OpOk::MlDsaSign {
                signature: vec![0x0Cu8; 4627],
            }),
            Response::Ok(OpOk::Exists { exists: false }),
            Response::Err(OpErr {
                code: "key_not_found".into(),
                message: "no key 'hlin-ai-signing'".into(),
            }),
            Response::Ok(OpOk::List {
                keys: vec![KeyEntry {
                    label: "hlin-ai-signing".into(),
                    purpose: "signing".into(),
                    algorithm: "ES256".into(),
                    fingerprint: "ab12".into(),
                    public_key: vec![0x04; 65],
                }],
            }),
            Response::Ok(OpOk::Identity {
                handle: Some("hlin-ai".into()),
            }),
            Response::Ok(OpOk::Identity { handle: None }),
            Response::Ok(OpOk::Delete),
        ];
        for resp in responses {
            let bytes = resp.to_bytes().unwrap();
            assert_eq!(Response::from_bytes(&bytes).unwrap(), resp);
        }
    }

    #[test]
    fn byte_fields_serialize_as_base64url_text() {
        // A byte field must be compact base64url text in the JSON, not a number
        // array — confirms the `b64` helper is wired (keeps frames small).
        let op = Op::Sign {
            label: "hlin-ai-signing".into(),
            msg: vec![0xff, 0x00, 0x10],
        };
        let json = String::from_utf8(op.to_bytes().unwrap()).unwrap();
        assert!(
            json.contains("\"_wAQ\""),
            "expected base64url msg, got {json}"
        );
    }
}
