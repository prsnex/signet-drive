// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! The SE-broker request framing (Garnet Phase-2, Auth-Core Spec v03 §3).
//!
//! The broker speaks a minimal request/response protocol **inside** the mutual-TLS connection: a
//! `u32` big-endian length prefix + a JSON body, one op per connection (for #3). The body reuses
//! the existing [`signet_channel::wire`] `Op` / `Response` types verbatim — but NOT the channel
//! crate's AEAD-sealed-folder *transport*, which Garnet replaces with mutual-TLS. The agent's
//! access token rides as a field on the request: §3.6 says the `Authorization: Bearer <jws>` is
//! satisfied semantically — there is no benefit to dragging in an HTTP stack for one header.
//!
//! The length prefix is **bounds-checked** ([`MAX_FRAME_BYTES`]) so a hostile/garbled prefix cannot
//! make the broker allocate an arbitrary buffer (a network-listener surface the mount model lacked).

use std::io::{self, Read, Write};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use signet_channel::wire::Op;

/// Maximum framed body size. A broker op is small (a `Sign` message, an `Ecdh` peer key, a JWS
/// token); 4 MiB is generous headroom while capping a length-prefix memory-exhaustion attempt.
pub const MAX_FRAME_BYTES: u32 = 4 * 1024 * 1024;

/// A broker request: the agent's cert-bound access token (the §3.6 Bearer, carried as a field
/// inside the already-mutual-TLS-authenticated connection) + the single SE op to perform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerRequest {
    /// The agent's `signet-broker`-audience access token (a JWS, §3) — verified per-op by the broker.
    pub token: String,
    /// The SE operation to perform (the existing delegation op set).
    pub op: Op,
}

/// Read one length-prefixed JSON frame (`u32` BE length + body) of type `T` from `r`, bounds-checked.
/// A length of 0 or one exceeding [`MAX_FRAME_BYTES`] is rejected before any allocation.
pub fn read_frame<R: Read, T: DeserializeOwned>(r: &mut R) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf);
    if len == 0 || len > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "garnet broker: frame length out of bounds",
        ));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Write `value` as one length-prefixed JSON frame (`u32` BE length + body) to `w`, then flush.
pub fn write_frame<W: Write, T: Serialize>(w: &mut W, value: &T) -> io::Result<()> {
    let body =
        serde_json::to_vec(value).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let len: u32 = body
        .len()
        .try_into()
        .ok()
        .filter(|n| *n <= MAX_FRAME_BYTES)
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "garnet broker: frame too large")
        })?;
    w.write_all(&len.to_be_bytes())?;
    w.write_all(&body)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;
    use signet_channel::wire::{OpErr, Response};

    #[test]
    fn request_round_trips() {
        let req = BrokerRequest {
            token: "header.claims.sig".to_string(),
            op: Op::Sign {
                label: "hlin-ai-signing".to_string(),
                msg: vec![1, 2, 3, 4],
            },
        };
        let mut buf = Vec::new();
        write_frame(&mut buf, &req).unwrap();
        let back: BrokerRequest = read_frame(&mut buf.as_slice()).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn response_round_trips() {
        let resp = Response::Err(OpErr {
            code: "authorization_denied".to_string(),
            message: "label handle does not match".to_string(),
        });
        let mut buf = Vec::new();
        write_frame(&mut buf, &resp).unwrap();
        let back: Response = read_frame(&mut buf.as_slice()).unwrap();
        assert_eq!(back, resp);
    }

    #[test]
    fn rejects_an_oversized_length_prefix() {
        // A prefix claiming > MAX_FRAME_BYTES is rejected before any allocation.
        let mut framed = (MAX_FRAME_BYTES + 1).to_be_bytes().to_vec();
        framed.extend_from_slice(b"whatever");
        let err = read_frame::<_, BrokerRequest>(&mut framed.as_slice()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_a_zero_length_prefix() {
        let framed = 0u32.to_be_bytes().to_vec();
        let err = read_frame::<_, BrokerRequest>(&mut framed.as_slice()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_a_truncated_body() {
        // The prefix claims 100 bytes but only 3 follow → read_exact hits EOF.
        let mut framed = 100u32.to_be_bytes().to_vec();
        framed.extend_from_slice(b"abc");
        let err = read_frame::<_, BrokerRequest>(&mut framed.as_slice()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn rejects_a_non_json_body() {
        let mut framed = 5u32.to_be_bytes().to_vec();
        framed.extend_from_slice(b"@@@@@");
        let err = read_frame::<_, BrokerRequest>(&mut framed.as_slice()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
