// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Output conventions (CLI Spec v08 §"Output format conventions").
//!
//! Default is machine-readable (compact JSON for structured data, raw bytes for
//! file content, hex for fixed-size values). `--pretty` (or `output_format =
//! "pretty"`) switches structured output to indented JSON. All success output →
//! stdout; errors → stderr (handled in `main`).

use std::io::Write;

use serde::Serialize;

use crate::error::{CliError, Result};

#[derive(Debug, Clone, Copy)]
pub struct OutputMode {
    pub pretty: bool,
}

impl OutputMode {
    /// Serialize `value` to stdout as JSON (one object, trailing newline),
    /// compact by default or indented under `--pretty`.
    pub fn print_json<T: Serialize>(&self, value: &T) -> Result<()> {
        let text = if self.pretty {
            serde_json::to_string_pretty(value)
        } else {
            serde_json::to_string(value)
        }
        .map_err(|e| CliError::generic(format!("serializing output: {e}")))?;
        println!("{text}");
        Ok(())
    }

    /// Write raw bytes to stdout (file content / binary public keys; no newline).
    pub fn write_bytes(&self, bytes: &[u8]) -> Result<()> {
        std::io::stdout()
            .write_all(bytes)
            .map_err(|e| CliError::output_write(format!("writing stdout: {e}")))
    }

    /// Write a UTF-8 string to stdout with no trailing newline (fingerprints,
    /// PEM already carries its own trailing newline).
    pub fn write_str(&self, s: &str) -> Result<()> {
        self.write_bytes(s.as_bytes())
    }
}
