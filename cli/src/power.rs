// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Transfer-scoped sleep suppression (bug050 rider).
//!
//! A large-file transfer can run for hours (the 100 GB target); a Mac left
//! idle will system-sleep mid-transfer and kill it. While a transfer is
//! active we hold the equivalent of a power assertion by spawning
//! `/usr/bin/caffeinate -i -w <our pid>`:
//!
//!   * `-i` prevents **idle system sleep only** — deliberately NOT display
//!     sleep and NOT the screen lock. The lock is the user's (or their MDM's)
//!     security policy and the SE custody boundary (§Resolved #8); we never
//!     fight it. The byte transfer itself survives a lock (presigned PUTs +
//!     an in-memory DEK need no Secure Enclave) — proven live S124.
//!   * `-w <pid>` bounds the assertion to our process lifetime even if we
//!     crash without dropping the guard — caffeinate exits when we do.
//!
//! Spawning the system binary is deliberate over an IOKit FFI: zero new
//! dependencies, the exact battle-tested assertion semantics, and a child
//! process the OS cleans up unconditionally. Best-effort by design: if the
//! spawn fails (non-macOS, missing binary), transfers behave exactly as
//! before this module existed.

/// RAII guard: holds the assertion while alive; releases on drop.
pub struct TransferAssertion {
    #[cfg(target_os = "macos")]
    child: Option<std::process::Child>,
}

impl TransferAssertion {
    /// Hold a prevent-idle-system-sleep assertion for this process's lifetime
    /// or the guard's, whichever ends first. Never fails: on any error (or on
    /// non-macOS) the guard is inert.
    pub fn hold() -> Self {
        #[cfg(target_os = "macos")]
        {
            let child = std::process::Command::new("/usr/bin/caffeinate")
                .args(["-i", "-w", &std::process::id().to_string()])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .ok();
            TransferAssertion { child }
        }
        #[cfg(not(target_os = "macos"))]
        {
            TransferAssertion {}
        }
    }
}

impl Drop for TransferAssertion {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The guard is inert-safe: construct + drop must never panic, on any
    /// platform, whether or not caffeinate exists.
    #[test]
    fn hold_and_drop_never_panic() {
        let guard = TransferAssertion::hold();
        drop(guard);
    }

    /// On macOS the spawned assertion process dies with the guard.
    #[cfg(target_os = "macos")]
    #[test]
    fn assertion_child_is_reaped_on_drop() {
        let guard = TransferAssertion::hold();
        let pid = guard.child.as_ref().map(|c| c.id());
        drop(guard);
        if let Some(pid) = pid {
            // After drop the child must be gone: kill(pid, 0) errors once the
            // process no longer exists (it was killed AND waited/reaped).
            let alive = libc_kill_probe(pid as i32);
            assert!(!alive, "caffeinate child {pid} must not outlive the guard");
        }
    }

    /// Probe process existence via /bin/kill -0 (no libc dependency).
    #[cfg(target_os = "macos")]
    fn libc_kill_probe(pid: i32) -> bool {
        std::process::Command::new("/bin/kill")
            .args(["-0", &pid.to_string()])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}
