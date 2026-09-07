// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Channel error type.
//!
//! Hand-rolled (matching `signet-crypto`'s `CryptoError` + the CLI's `CliError`),
//! no `thiserror` dependency. The security-relevant variant is [`ChannelError::Auth`]:
//! it is the single opaque failure for *any* AEAD-open rejection — wrong secret,
//! tampered frame, wrong direction, or wrong AAD (channel/version/nonce binding) —
//! so a caller cannot distinguish *why* a frame was rejected (no oracle).

use std::fmt;

/// A failure on the delegation channel.
#[derive(Debug)]
pub enum ChannelError {
    /// AEAD open failed: wrong per-PRSN secret, a tampered frame, the wrong
    /// direction key, or an AAD mismatch (version / channel / request-nonce
    /// binding). Deliberately undifferentiated — the host-signer rejects and the
    /// client raises, neither revealing which check failed.
    Auth,
    /// A request nonce was already served on this channel (replay rejected).
    Replay,
    /// A frame was structurally invalid (too short for the nonce, etc.).
    MalformedFrame,
    /// (De)serialization of a message body failed.
    Serialization(String),
    /// A filesystem / channel I/O error.
    Io(std::io::Error),
    /// Timed out waiting for the peer (the response, or a request).
    Timeout,
}

impl fmt::Display for ChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChannelError::Auth => write!(f, "channel message failed authentication"),
            ChannelError::Replay => write!(f, "channel request nonce already seen (replay)"),
            ChannelError::MalformedFrame => write!(f, "malformed channel frame"),
            ChannelError::Serialization(e) => write!(f, "channel message serialization: {e}"),
            ChannelError::Io(e) => write!(f, "channel I/O: {e}"),
            ChannelError::Timeout => write!(f, "channel timed out waiting for the peer"),
        }
    }
}

impl std::error::Error for ChannelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ChannelError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ChannelError {
    fn from(e: std::io::Error) -> Self {
        ChannelError::Io(e)
    }
}

/// The crate result alias.
pub type Result<T> = std::result::Result<T, ChannelError>;
