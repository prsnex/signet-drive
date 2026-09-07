// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Garnet broker-side revocation enforcement — **check-at-use** (Auth-Core Spec v03 §6).
//!
//! The SE-broker performs a Secure-Enclave op only for a grant it has confirmed **live**.
//! Rather than poll a broadcast revocation list, the broker confirms the grant at the
//! *moment of an op* via a live grant-status query to the server (the same per-request
//! live-grant read the account path runs), and **leases** that confirmation for a short
//! window so a burst of ops shares one check. This module is the pure decision core of
//! that logic — the §6 fail-closed state machine — with **no I/O**: the grant-status query
//! itself happens in the caller (the mTLS listener), which feeds the [`GrantStatusOutcome`]
//! back here. Keeping it pure makes the security-critical fail-closed rules deterministic
//! and exhaustively unit-testable (the §8 build-gate negative tests below).
//!
//! ## The §6 rules this enforces
//!
//! * **Lease.** After a successful confirm, serve without re-checking for
//!   `revocation_lease_seconds` (the normal-operation SE-revocation bound — a revoke is cut
//!   ≤ lease after the last confirm). The first op after the lease lapses re-confirms. An
//!   idle PRSN does no op, so it makes no call.
//! * **Three answers, fail-closed.** On a required re-confirm: `Live` ⇒ refresh the lease and
//!   serve; a definitive `Revoked` ⇒ **immediate hard fail-closed, no grace**; `Unreachable`
//!   ⇒ serve on last-known-good only within `lease + outage_grace`, else fail closed. A clear
//!   "revoked" is **never** graced; only *unreachability* is.
//! * **Outage-grace decoupled from the lease.** `revocation_outage_grace_seconds` is how long
//!   past the lease a *server-unreachable* blip is tolerated on last-known-good — independent
//!   of the lease, so a deployment gets fast revocation (short lease) *and* blip tolerance
//!   (longer grace) at once. A same-host attacker who blocks the check can only delay the cut
//!   to `lease + grace`, then fail-closed.
//! * **Trusted time (re-anchored REV-4).** Token `exp` is checked against trusted time derived
//!   as `last_confirm.server_time + monotonic_elapsed` — advanced by the **monotonic clock**
//!   (an [`Instant`], which a host wall-clock change cannot roll back) off a **server-supplied**
//!   anchor, and held to a **monotonic floor** so a server clock regression cannot move it
//!   backward either. So neither a same-user host-clock rollback nor a server clock step can
//!   revive an expired token at the SE.
//! * **Cold start / restart.** With no successful confirm yet there is no trusted time, so the
//!   broker **refuses all SE ops** until its first `Live` confirm (it cannot serve without
//!   reaching the server anyway — there is no host-clock fallback, and no cached revocation
//!   state to roll back).
//!
//! ## Concurrency note (boundary with the listener)
//!
//! A [`GrantLease`] is **per-grant** state (one per `grant_id` the broker serves). The mTLS
//! listener owns the per-`grant_id` keying + the lock around each lease — this module is
//! single-grant logic with **no** process-scoped "current identity" (the §7 isolation
//! invariant lives in the listener, with its own concurrent-multi-PRSN build-gate test).

use std::time::{Duration, Instant};

/// The check-at-use control values (sourced from `system_config`; passed in so this module is
/// pure + deterministic). Suffix-per-unit per the 1-Pager `system_config` convention.
#[derive(Debug, Clone, Copy)]
pub struct LeaseConfig {
    /// `revocation_lease_seconds` — the normal-operation re-check cadence (the SE-revocation bound).
    pub lease: Duration,
    /// `revocation_outage_grace_seconds` — extra tolerance for a *server-unreachable* blip, on
    /// last-known-good, before failing closed. Decoupled from `lease`.
    pub outage_grace: Duration,
    /// `token_skew_seconds` — the clock-skew tolerance applied to the token `exp` check.
    pub token_skew: Duration,
}

/// bug125 (audit F-006) — the broker's OWN bounds on server-supplied revocation-SLA values.
///
/// These mirror migration 0022's `min_value`/`max_value`, deliberately as a **second, independent
/// copy**. The server clamps on write; the broker clamps again on read, because **the broker is
/// the enforcer** and must not inherit its security bound from a peer's validation. A server that
/// is compromised, rolled back, or simply buggy cannot stretch the SE-revocation window past
/// `LEASE_MAX` here. (This grants a compromised server nothing it lacked — it could already answer
/// `Live` forever — but the ceiling is what keeps the *stated* SLA a fact rather than a promise.)
///
/// ⚠ Two copies of a number is normally the drift hazard my own rules warn about. It is correct
/// here precisely because the point is *independence*: if these silently tracked the server's
/// values they would not be a bound at all. The pinning test asserts they match 0022.
const LEASE_MIN_SECS: u64 = 5;
const LEASE_MAX_SECS: u64 = 120;
const OUTAGE_GRACE_MIN_SECS: u64 = 0;
const OUTAGE_GRACE_MAX_SECS: u64 = 600;

impl LeaseConfig {
    /// Adopt server-supplied revocation-SLA values, clamped to the broker's own bounds.
    ///
    /// `token_skew` is carried over from `self` deliberately: F-006 is about the two
    /// **revocation-SLA** knobs (0022), and a token-validation parameter is a separate concern
    /// with a separate knob (`token_skew_seconds`, 0018). Widening this to "the server supplies
    /// the whole config" would hand a peer control of token-expiry tolerance for no finding's
    /// sake — scope held on purpose.
    ///
    /// Negative or absurd inputs cannot produce a longer window: the `i64 → u64` conversion
    /// floors at the minimum rather than wrapping.
    ///
    /// ⚠ **THE INVARIANT IS THE TOTAL BUDGET, NOT EITHER COMPONENT** (Chris's ruling, S160).
    ///
    /// The attacker-facing bound is **`lease + outage_grace`**, because `on_grant_status` serves
    /// last-known-good for exactly that long when the server is unreachable — so a same-host
    /// attacker who blocks the broker→server check delays the SE cut by the **sum**, not by the
    /// lease. (A definitive `Revoked` is never graced and is cut within the lease alone.)
    ///
    /// **Two earlier attempts got this wrong, in opposite directions, and both are instructive:**
    /// the first let the server *widen* a locally-tightened bound (caught by
    /// `garnet_command_e2e`, which configures `lease = 0`); the second took a per-component
    /// minimum against the compiled defaults, which silently capped the lease at 30 while
    /// migration 0022 advertised 5–120 — **a documented knob that does nothing across part of
    /// its range, i.e. F-006 itself, one level up** (Gus's catch).
    ///
    /// So: the server may allocate the budget however it likes — `120/0`, `30/90`, `5/115` all
    /// **reach the enforcer** — but a total exceeding the deployment's compiled budget is
    /// **refused whole and logged**, never silently trimmed. Refusing the allocation rather than
    /// clamping a component is what keeps the operator's *intent* legible: a half-applied
    /// setting is exactly the "reports success while doing no work" shape this bug is about.
    ///
    /// Computed from the compiled configuration each time (never folded over a previously
    /// adopted value), so an earlier tight setting cannot permanently pin a later valid one.
    pub fn with_server_values(self, lease_seconds: i64, outage_grace_seconds: i64) -> Self {
        let lease = Duration::from_secs(
            (lease_seconds.max(0) as u64).clamp(LEASE_MIN_SECS, LEASE_MAX_SECS),
        );
        let outage_grace = Duration::from_secs(
            (outage_grace_seconds.max(0) as u64)
                .clamp(OUTAGE_GRACE_MIN_SECS, OUTAGE_GRACE_MAX_SECS),
        );
        // The deployment's compiled budget — the worst-case SE-revocation latency it accepts.
        let budget = self.lease + self.outage_grace;
        if lease + outage_grace > budget {
            // Over budget: keep the compiled configuration wholesale. Loud, because an operator
            // who set a value that never took effect must be able to find out why — a silently
            // ignored control is the defect this whole bug is about. (`eprintln!` rather than
            // `tracing`: the CLI carries no tracing dependency, and the broker's other
            // operational messages go to stderr the same way — `broker.rs:258`.)
            eprintln!(
                "signet broker: server-supplied revocation SLA (lease {}s + grace {}s = {}s) \
                 exceeds this deployment's total budget of {}s; keeping the compiled \
                 configuration (lease {}s + grace {}s)",
                lease.as_secs(),
                outage_grace.as_secs(),
                (lease + outage_grace).as_secs(),
                budget.as_secs(),
                self.lease.as_secs(),
                self.outage_grace.as_secs(),
            );
            return self;
        }
        Self {
            lease,
            outage_grace,
            token_skew: self.token_skew,
        }
    }
}

/// bug125 (F-006) — the revocation-SLA values as the server reported them, **unclamped**.
///
/// Kept as raw `i64`s rather than a `LeaseConfig` on purpose: this is *what the peer said*, and
/// it becomes policy only after [`LeaseConfig::with_server_values`] clamps it. Keeping the
/// untrusted input and the enforced bound in visibly different types is what stops a later edit
/// from quietly plumbing a peer's number straight into the enforcer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerSla {
    pub lease_seconds: i64,
    pub outage_grace_seconds: i64,
}

/// The outcome of a grant-status query. The query (network I/O) happens in the caller; this
/// enum is what it feeds back to [`GrantLease::on_grant_status`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantStatusOutcome {
    /// The server confirmed the grant authorizes access (active **and** enrollment-confirmed
    /// **and** the cert not revoked). `server_time` is the authoritative trusted-time anchor
    /// (unix seconds) — querying the server directly is what gives the broker an authoritative
    /// *current* time (a token's `iat` would be only a lower bound, gameable by holding tokens).
    ///
    /// bug125 (F-006): `sla` carries the live `system_config` revocation-SLA values when the
    /// server supplied them. **`None` is meaningful, not an error** — a server that predates the
    /// field simply leaves the broker on its compiled defaults, so an older server and a newer
    /// broker interoperate without a flag day.
    Live {
        server_time: i64,
        sla: Option<ServerSla>,
    },
    /// A definitive server "no": grant `revoked`, cert revoked, or not enrollment-confirmed.
    /// Cut immediately, **no grace** — the server gave an authoritative negative.
    Revoked,
    /// The server could not be reached / answered ambiguously (timeout, 5xx, TLS failure). The
    /// only outcome that is graced (within `lease + outage_grace`), because it is not a "no".
    Unreachable,
}

impl GrantStatusOutcome {
    /// A `Live` outcome from a server that supplied **no** revocation-SLA values — the
    /// pre-bug125 shape, and the one every caller wants unless it is specifically exercising
    /// F-006. One home for the `sla: None` case so adding a future field does not become
    /// another N-site edit.
    pub fn live(server_time: i64) -> Self {
        Self::Live {
            server_time,
            sla: None,
        }
    }

    /// A `Live` outcome carrying server-supplied revocation-SLA values (bug125 / F-006).
    pub fn live_with_sla(server_time: i64, lease_seconds: i64, outage_grace_seconds: i64) -> Self {
        Self::Live {
            server_time,
            sla: Some(ServerSla {
                lease_seconds,
                outage_grace_seconds,
            }),
        }
    }
}

/// Why an op is refused. Carried on [`Decision::FailClosed`] for the caller's diagnostics/logs
/// (the caller maps these to the agent-facing error / the "access paused" surface).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailReason {
    /// The server returned a definitive `Revoked` (immediate, no grace).
    Revoked,
    /// The server is unreachable and the last-known-good window (`lease + outage_grace`) has
    /// elapsed — or this is a cold start with no confirm yet (no trusted time).
    Unreachable,
    /// The token's `exp` is at/before trusted time (beyond skew) — expired against the
    /// server-anchored, monotonic-floored clock (not the host wall-clock).
    TokenExpired,
}

/// The decision for a single SE op.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Serve the op — the grant is live within the lease and the token is unexpired.
    Serve,
    /// A fresh grant-status confirm is required (cold, or the lease has lapsed). The caller MUST
    /// query the server and feed the [`GrantStatusOutcome`] to [`GrantLease::on_grant_status`].
    ReconfirmRequired,
    /// Refuse the op, fail-closed.
    FailClosed(FailReason),
}

/// The last successful (`Live`) confirm: the server-supplied trusted-time anchor and the
/// monotonic instant we received it.
#[derive(Debug, Clone, Copy)]
struct Confirm {
    /// The server's authoritative time at the confirm (unix seconds).
    server_time: i64,
    /// The monotonic instant the confirm was received (advances trusted time; cannot roll back).
    at: Instant,
}

/// Per-grant lease state. One per `grant_id` the broker serves (the listener keys + locks these).
#[derive(Debug, Clone)]
pub struct GrantLease {
    /// The last successful confirm, or `None` when cold (no confirm yet ⇒ refuse until one).
    last_confirm: Option<Confirm>,
    /// A monotonic floor on trusted time (unix seconds): the highest trusted time ever computed.
    /// Holds trusted time non-decreasing across confirms so a **server** clock regression cannot
    /// move it backward (the host clock is already defeated by the monotonic [`Instant`] age).
    trusted_floor: i64,
    /// bug125 (F-006): the server-supplied revocation SLA in force for THIS grant, already
    /// clamped, or `None` while the server has never supplied one (⇒ the caller's compiled
    /// defaults apply). Per-grant rather than process-wide because the listener already keys and
    /// locks leases per `grant_id` — so the live values need **no new shared mutable state and no
    /// change to the worker-pool concurrency model**, which is why this wiring is safe to do in a
    /// launch-hardening round.
    server_sla: Option<LeaseConfig>,
}

impl Default for GrantLease {
    fn default() -> Self {
        Self::new()
    }
}

impl GrantLease {
    /// A fresh, cold lease — no confirm yet, so it refuses SE ops until the first `Live`.
    pub fn new() -> Self {
        Self {
            last_confirm: None,
            trusted_floor: i64::MIN,
            server_sla: None,
        }
    }

    /// bug125 (F-006) — the config actually in force: the server-supplied SLA once one has been
    /// adopted, else the caller's compiled defaults. By value (`LeaseConfig` is `Copy`) so the
    /// caller holds no borrow of `self` across its own mutations.
    ///
    /// ⚠ **Fail-safe direction:** if the server has never supplied values, this returns the
    /// defaults, which are *tighter* than the maximum an operator could set. There is no path
    /// where a missing value produces a longer window than an explicit one.
    fn effective(&self, defaults: &LeaseConfig) -> LeaseConfig {
        self.server_sla.unwrap_or(*defaults)
    }

    /// Decide for an SE op at monotonic `now`, given the token's `exp` (unix seconds).
    ///
    /// Returns [`Decision::ReconfirmRequired`] when cold or the lease has lapsed (the caller then
    /// queries grant-status and calls [`on_grant_status`](Self::on_grant_status)); otherwise the
    /// lease is valid, so it serves — or fails closed if the token is expired against trusted time.
    pub fn decide(&self, now: Instant, token_exp: i64, cfg: &LeaseConfig) -> Decision {
        // bug125: `cfg` is the compiled DEFAULT; the live value is whatever the server last
        // supplied for this grant.
        let cfg = self.effective(cfg);
        match self.last_confirm {
            // Cold: no trusted time and no confirmed liveness — must confirm before any op.
            None => Decision::ReconfirmRequired,
            Some(confirm) => {
                let age = now.saturating_duration_since(confirm.at);
                if age >= cfg.lease {
                    // Lease lapsed — re-confirm before serving.
                    Decision::ReconfirmRequired
                } else {
                    // Lease valid — the only remaining gate is the token's own expiry.
                    self.token_exp_decision(confirm, age, token_exp, &cfg)
                }
            }
        }
    }

    /// Feed the grant-status outcome after a [`Decision::ReconfirmRequired`]. Updates the lease
    /// and returns the final decision. Never returns [`Decision::ReconfirmRequired`] (the confirm
    /// has just happened).
    pub fn on_grant_status(
        &mut self,
        outcome: GrantStatusOutcome,
        now: Instant,
        token_exp: i64,
        cfg: &LeaseConfig,
    ) -> Decision {
        match outcome {
            GrantStatusOutcome::Live { server_time, sla } => {
                // bug125 (F-006): adopt the live SLA, CLAMPED to the broker's own bounds, before
                // it is used for anything. Adopting here — on the affirmative, alongside the
                // trusted-time anchor — is what makes the values arrive with the very answer that
                // proves liveness. A `None` leaves the previously-adopted value (or the defaults)
                // in force rather than resetting, so a server that stops sending the field cannot
                // silently widen an already-tightened window.
                if let Some(sla) = sla {
                    // Always derived from the COMPILED configuration, never from a previously
                    // adopted value: `with_server_values` takes a minimum, so folding it over
                    // itself would ratchet the window permanently tighter and a legitimate
                    // relaxation could never take effect.
                    self.server_sla =
                        Some(cfg.with_server_values(sla.lease_seconds, sla.outage_grace_seconds));
                }
                let cfg = self.effective(cfg);
                // Anchor trusted time to the server's time, but never below the monotonic floor
                // (defeats a server clock regression). Refresh the lease.
                let anchored = server_time.max(self.trusted_floor);
                self.trusted_floor = anchored;
                let confirm = Confirm {
                    server_time: anchored,
                    at: now,
                };
                self.last_confirm = Some(confirm);
                // Age 0 at a fresh confirm — gate on the token's own expiry.
                self.token_exp_decision(confirm, Duration::ZERO, token_exp, &cfg)
            }
            // A definitive "no" — immediate fail-closed, no grace, regardless of any held lease.
            GrantStatusOutcome::Revoked => Decision::FailClosed(FailReason::Revoked),
            GrantStatusOutcome::Unreachable => {
                let cfg = self.effective(cfg);
                match self.last_confirm {
                    // Serve on last-known-good only within lease + outage_grace; else fail closed.
                    Some(confirm) => {
                        let age = now.saturating_duration_since(confirm.at);
                        if age < cfg.lease + cfg.outage_grace {
                            self.token_exp_decision(confirm, age, token_exp, &cfg)
                        } else {
                            Decision::FailClosed(FailReason::Unreachable)
                        }
                    }
                    // Cold + unreachable — no trusted time, no confirmed liveness: refuse.
                    None => Decision::FailClosed(FailReason::Unreachable),
                }
            }
        }
    }

    /// Trusted time = `max(confirm.server_time + age, trusted_floor)` (unix seconds). Serve unless
    /// the token expired against it (with skew). The floor keeps trusted time monotonic; the
    /// `Instant` age keeps it immune to a host wall-clock rollback. Does not mutate (`decide`
    /// must be `&self`); the floor only advances on a `Live` confirm.
    fn token_exp_decision(
        &self,
        confirm: Confirm,
        age: Duration,
        token_exp: i64,
        cfg: &LeaseConfig,
    ) -> Decision {
        let trusted_now = confirm
            .server_time
            .saturating_add(age.as_secs() as i64)
            .max(self.trusted_floor);
        let skew = cfg.token_skew.as_secs() as i64;
        if token_exp.saturating_add(skew) < trusted_now {
            Decision::FailClosed(FailReason::TokenExpired)
        } else {
            Decision::Serve
        }
    }
}

#[cfg(test)]
mod tests {
    //! The NORMATIVE §8 broker-side build-gate tests for check-at-use, plus the happy paths.
    //! Pure + deterministic: monotonic time is an [`Instant`] base + fixed offsets, and the
    //! grant-status outcome is an input — so every fail-closed rule is exercised without I/O.
    //! "The contract isn't real until these pass."

    use super::*;

    /// Unix-seconds anchor used as the server time in `Live` outcomes.
    const T0: i64 = 1_750_000_000;
    /// A token expiring well after T0 (so token-expiry never spuriously trips a liveness test).
    const TOKEN_EXP: i64 = T0 + 10_000;

    fn cfg() -> LeaseConfig {
        LeaseConfig {
            lease: Duration::from_secs(30),
            outage_grace: Duration::from_secs(90),
            token_skew: Duration::from_secs(30),
        }
    }

    /// A monotonic base instant; tests derive `base + offset` for deterministic ages.
    fn base() -> Instant {
        Instant::now()
    }

    fn after(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    // ---- Cold start ----

    #[test]
    fn cold_decide_requires_a_confirm() {
        let lease = GrantLease::new();
        assert_eq!(
            lease.decide(base(), TOKEN_EXP, &cfg()),
            Decision::ReconfirmRequired
        );
    }

    #[test]
    fn cold_plus_unreachable_fails_closed() {
        // The first op can't reach the server: no trusted time, no confirmed liveness ⇒ refuse.
        let mut lease = GrantLease::new();
        let d = lease.on_grant_status(GrantStatusOutcome::Unreachable, base(), TOKEN_EXP, &cfg());
        assert_eq!(d, Decision::FailClosed(FailReason::Unreachable));
    }

    // ---- Live / lease ----

    #[test]
    fn live_confirm_serves() {
        let mut lease = GrantLease::new();
        let d = lease.on_grant_status(GrantStatusOutcome::live(T0), base(), TOKEN_EXP, &cfg());
        assert_eq!(d, Decision::Serve);
    }

    #[test]
    fn lease_is_honored_then_requires_reconfirm() {
        let b = base();
        let mut lease = GrantLease::new();
        lease.on_grant_status(GrantStatusOutcome::live(T0), b, TOKEN_EXP, &cfg());

        // Within the 30s lease: serve without re-confirming (a burst shares one check).
        assert_eq!(
            lease.decide(after(b, 5), TOKEN_EXP, &cfg()),
            Decision::Serve
        );
        assert_eq!(
            lease.decide(after(b, 29), TOKEN_EXP, &cfg()),
            Decision::Serve
        );

        // At / past the lease boundary: a re-confirm is required.
        assert_eq!(
            lease.decide(after(b, 30), TOKEN_EXP, &cfg()),
            Decision::ReconfirmRequired
        );
        assert_eq!(
            lease.decide(after(b, 120), TOKEN_EXP, &cfg()),
            Decision::ReconfirmRequired
        );
    }

    // ---- Revoked (immediate, no grace) ----

    #[test]
    fn revoked_is_immediate_fail_closed_even_within_grace() {
        let b = base();
        let mut lease = GrantLease::new();
        lease.on_grant_status(GrantStatusOutcome::live(T0), b, TOKEN_EXP, &cfg());

        // 10s later (well inside lease+grace) the re-confirm returns Revoked: cut NOW, no grace.
        let d = lease.on_grant_status(GrantStatusOutcome::Revoked, after(b, 10), TOKEN_EXP, &cfg());
        assert_eq!(d, Decision::FailClosed(FailReason::Revoked));
    }

    // ---- Unreachable: graced within lease+grace, fails closed past it ----

    #[test]
    fn unreachable_within_grace_serves_on_last_known_good() {
        let b = base();
        let mut lease = GrantLease::new();
        lease.on_grant_status(GrantStatusOutcome::live(T0), b, TOKEN_EXP, &cfg());

        // Lease(30)+grace(90)=120s window. At 100s, server unreachable ⇒ still serve.
        let d = lease.on_grant_status(
            GrantStatusOutcome::Unreachable,
            after(b, 100),
            TOKEN_EXP,
            &cfg(),
        );
        assert_eq!(d, Decision::Serve);
    }

    #[test]
    fn unreachable_past_grace_fails_closed() {
        let b = base();
        let mut lease = GrantLease::new();
        lease.on_grant_status(GrantStatusOutcome::live(T0), b, TOKEN_EXP, &cfg());

        // At 121s (past lease+grace=120s), server unreachable ⇒ fail closed.
        let d = lease.on_grant_status(
            GrantStatusOutcome::Unreachable,
            after(b, 121),
            TOKEN_EXP,
            &cfg(),
        );
        assert_eq!(d, Decision::FailClosed(FailReason::Unreachable));
    }

    #[test]
    fn unreachable_grace_boundary_is_exact() {
        let b = base();
        let mut lease = GrantLease::new();
        lease.on_grant_status(GrantStatusOutcome::live(T0), b, TOKEN_EXP, &cfg());
        // Exactly at the boundary (120s) is NOT within the window (`age < lease+grace`).
        assert_eq!(
            lease.on_grant_status(
                GrantStatusOutcome::Unreachable,
                after(b, 120),
                TOKEN_EXP,
                &cfg()
            ),
            Decision::FailClosed(FailReason::Unreachable)
        );
    }

    // ---- Token expiry against trusted (server-anchored, monotonic) time ----

    #[test]
    fn token_expired_against_trusted_time_fails_closed() {
        let b = base();
        let mut lease = GrantLease::new();
        // Confirm at server_time T0 with a token that already expired 100s before T0 (beyond skew).
        let expired = T0 - 100;
        let d = lease.on_grant_status(GrantStatusOutcome::live(T0), b, expired, &cfg());
        assert_eq!(d, Decision::FailClosed(FailReason::TokenExpired));
    }

    #[test]
    fn token_within_skew_still_serves() {
        let b = base();
        let mut lease = GrantLease::new();
        // exp is 10s before server time, but skew is 30s ⇒ still valid.
        let d = lease.on_grant_status(GrantStatusOutcome::live(T0 + 10), b, T0, &cfg());
        assert_eq!(d, Decision::Serve);
    }

    #[test]
    fn token_expires_as_trusted_time_advances_by_monotonic_age() {
        // Confirm at T0 with a token expiring at T0+20. Trusted time advances by the MONOTONIC
        // age (server_time + elapsed Instant), not the host wall-clock. Within the lease:
        //   at +10s ⇒ trusted T0+10 < exp T0+20 ⇒ serve;
        //   at +25s ⇒ trusted T0+25 > exp+skew? exp+skew = T0+50, so still serve (skew);
        // push the token expiry close so the boundary is crossed inside the lease.
        let b = base();
        let mut lease = GrantLease::new();
        let exp = T0 + 5; // exp+skew = T0+35
        lease.on_grant_status(GrantStatusOutcome::live(T0), b, exp, &cfg());
        // +30 is the lease boundary (ReconfirmRequired), so check at +29: trusted T0+29 < T0+35.
        assert_eq!(lease.decide(after(b, 29), exp, &cfg()), Decision::Serve);
        // Now a fresh confirm at a later server_time pushes trusted time past exp+skew.
        let mut lease2 = GrantLease::new();
        lease2.on_grant_status(GrantStatusOutcome::live(T0 + 100), b, exp, &cfg());
        assert_eq!(
            lease2.decide(after(b, 1), exp, &cfg()),
            Decision::FailClosed(FailReason::TokenExpired)
        );
    }

    // ---- Trusted-time monotonic floor (server clock regression cannot revive a token) ----

    #[test]
    fn server_clock_regression_cannot_move_trusted_time_backward() {
        let b = base();
        let mut lease = GrantLease::new();
        // First confirm at a high server_time, establishing the floor.
        lease.on_grant_status(GrantStatusOutcome::live(T0 + 1_000), b, TOKEN_EXP, &cfg());
        // A token that expired at T0+500 — already past the floor (T0+1000).
        let stale_exp = T0 + 500;
        // A later confirm reports a REGRESSED server_time (T0). Without the floor, trusted time
        // would drop to ~T0 and the stale token would look valid. The floor holds it at T0+1000.
        let d = lease.on_grant_status(
            GrantStatusOutcome::live(T0),
            after(b, 40),
            stale_exp,
            &cfg(),
        );
        assert_eq!(d, Decision::FailClosed(FailReason::TokenExpired));
    }

    // ---- bug125 / audit F-006: the server-supplied revocation SLA actually reaches the enforcer ----
    //
    // Before bug125 these knobs were seeded, range-clamped and settable through
    // `PATCH /v1/admin/config/{key}` — and read by nothing. An operator could tighten the
    // SE-revocation bound, get a success response, and change nothing. These tests exist to make
    // that state unrepresentable: each one fails if the adoption path is removed.

    #[test]
    fn server_supplied_lease_is_adopted_and_tightens_the_revocation_bound() {
        // THE test for F-006. The compiled default lease is 30s; the operator sets 10s. At 20s of
        // age the lease must ALREADY have lapsed (⇒ re-confirm), which it would not under the
        // default. If the adoption path is deleted, this assertion flips to `Serve` — the exact
        // pre-bug125 behaviour, which is what makes this a test rather than decoration.
        let b = base();
        let mut lease = GrantLease::new();
        lease.on_grant_status(
            GrantStatusOutcome::live_with_sla(T0, 10, 90),
            b,
            TOKEN_EXP,
            &cfg(),
        );
        assert_eq!(
            lease.decide(after(b, 20), TOKEN_EXP, &cfg()),
            Decision::ReconfirmRequired,
            "a server-set 10s lease must lapse by 20s; still serving means the knob is inert again"
        );
        // Control: under the same conditions the compiled 30s default would still be serving,
        // so the assertion above is discriminating rather than trivially true.
        let mut default_lease = GrantLease::new();
        default_lease.on_grant_status(GrantStatusOutcome::live(T0), b, TOKEN_EXP, &cfg());
        assert_eq!(
            default_lease.decide(after(b, 20), TOKEN_EXP, &cfg()),
            Decision::Serve,
            "control: the 30s default must still be inside its lease at 20s"
        );
    }

    #[test]
    fn server_supplied_outage_grace_is_adopted() {
        // Default grace is 90s (so lease+grace = 120s). The operator sets grace 0 — meaning
        // "fail closed immediately on unreachability". At 40s of age (past the 30s lease, far
        // inside the DEFAULT grace) an unreachable server must now fail closed.
        let b = base();
        let mut lease = GrantLease::new();
        lease.on_grant_status(
            GrantStatusOutcome::live_with_sla(T0, 30, 0),
            b,
            TOKEN_EXP,
            &cfg(),
        );
        let d = lease.on_grant_status(
            GrantStatusOutcome::Unreachable,
            after(b, 40),
            TOKEN_EXP,
            &cfg(),
        );
        assert_eq!(d, Decision::FailClosed(FailReason::Unreachable));
    }

    #[test]
    fn a_server_supplied_lease_can_never_widen_the_compiled_bound() {
        // ⚠ The fail-safe asymmetry, and the defect that produced it. A server asking for a
        // full day cannot stretch the SE-revocation window: the effective lease is the MINIMUM
        // of the clamped server value and the deployment's compiled bound (30s here).
        //
        // This is the case `garnet_command_e2e` caught: it configures lease=0 so that every op
        // re-confirms, and an earlier version of this code let the server's 30s override it —
        // silently widening a bound the deployment had deliberately tightened.
        let b = base();
        let mut lease = GrantLease::new();
        lease.on_grant_status(
            GrantStatusOutcome::live_with_sla(T0, 86_400, 86_400),
            b,
            TOKEN_EXP,
            &cfg(),
        );
        // Inside the COMPILED bound (30s), not the server's or the clamp ceiling: still serving.
        assert_eq!(
            lease.decide(after(b, 29), TOKEN_EXP, &cfg()),
            Decision::Serve
        );
        // At the compiled bound the lease has lapsed — the server's request is irrelevant.
        assert_eq!(
            lease.decide(after(b, 30), TOKEN_EXP, &cfg()),
            Decision::ReconfirmRequired,
            "the server must not widen the deployment's compiled revocation bound"
        );
    }

    #[test]
    fn a_zero_lease_deployment_re_confirms_on_every_op() {
        // The `garnet_command_e2e` configuration, pinned as a unit test so the regression is
        // caught here rather than only by a full end-to-end run: a deployment that sets
        // lease=0 (re-confirm on EVERY op, the strictest possible setting) must keep that
        // behaviour even while the server reports its own perfectly valid 30s.
        let b = base();
        let zero = LeaseConfig {
            lease: Duration::from_secs(0),
            outage_grace: Duration::from_secs(90),
            token_skew: Duration::from_secs(30),
        };
        let mut lease = GrantLease::new();
        lease.on_grant_status(
            GrantStatusOutcome::live_with_sla(T0, 30, 90),
            b,
            TOKEN_EXP,
            &zero,
        );
        assert_eq!(
            lease.decide(b, TOKEN_EXP, &zero),
            Decision::ReconfirmRequired,
            "lease=0 means re-confirm on every op; the server must not relax it"
        );
    }

    #[test]
    fn an_operator_may_reallocate_the_budget_and_it_reaches_the_enforcer() {
        // ⭐ Gus's objection, pinned. An earlier version took a per-component minimum against
        // the compiled defaults, so a lease above 30 silently did nothing while migration 0022
        // advertised 5–120 — a documented knob inert across part of its range, which is F-006
        // itself one level up.
        //
        // The budget (lease + outage_grace = 120s at defaults) is the invariant, so an operator
        // may spend it differently: the un-graced maximum-lease posture 120/0 is EXACTLY on
        // budget and must take effect.
        let c = cfg().with_server_values(120, 0);
        assert_eq!(
            c.lease,
            Duration::from_secs(120),
            "a 120s lease is settable when the grace is spent down to 0 — 0022's own range"
        );
        assert_eq!(c.outage_grace, Duration::from_secs(0));
        assert_eq!(
            c.lease + c.outage_grace,
            cfg().lease + cfg().outage_grace,
            "…and the total worst-case latency is unchanged, which is the ruled invariant"
        );

        // A mid-range reallocation also lands.
        let c = cfg().with_server_values(5, 115);
        assert_eq!(c.lease, Duration::from_secs(5));
        assert_eq!(c.outage_grace, Duration::from_secs(115));
    }

    #[test]
    fn an_over_budget_allocation_is_refused_whole_not_trimmed() {
        // Refusing the allocation rather than clamping one component keeps the operator's
        // INTENT legible: a half-applied setting (tight lease, silently-trimmed grace) is
        // exactly the "reports success while doing no work" shape this bug is about.
        let c = cfg().with_server_values(120, 600);
        assert_eq!(
            c.lease,
            cfg().lease,
            "over budget ⇒ compiled config kept whole"
        );
        assert_eq!(c.outage_grace, cfg().outage_grace);
    }

    #[test]
    fn absurd_or_negative_server_values_cannot_widen_the_window() {
        // A negative lease must floor at the MINIMUM, never wrap to a huge unsigned value.
        let c = cfg().with_server_values(-1, -1);
        assert_eq!(c.lease, Duration::from_secs(LEASE_MIN_SECS));
        assert_eq!(c.outage_grace, Duration::from_secs(OUTAGE_GRACE_MIN_SECS));
        // i64::MIN is the wrap-hazard input specifically.
        let c = cfg().with_server_values(i64::MIN, i64::MIN);
        assert_eq!(c.lease, Duration::from_secs(LEASE_MIN_SECS));
        // From the other direction the CEILING is the compiled bound, not the clamp maximum —
        // `LEASE_MAX_SECS` bounds what the server may ask for; `self` bounds what it may get.
        let c = cfg().with_server_values(i64::MAX, i64::MAX);
        assert_eq!(c.lease, cfg().lease);
        assert_eq!(c.outage_grace, cfg().outage_grace);
    }

    #[test]
    fn token_skew_is_not_server_controlled() {
        // Scope pin: F-006 covers the two revocation-SLA knobs only. A server must not be able to
        // move token-expiry tolerance, so `with_server_values` leaves `token_skew` alone.
        let c = cfg().with_server_values(60, 120);
        assert_eq!(c.token_skew, cfg().token_skew);
    }

    #[test]
    fn an_absent_sla_leaves_the_compiled_defaults_in_force() {
        // Version skew is not an error: a server that never sends the fields simply leaves the
        // broker on its defaults (30s lease ⇒ still serving at 20s).
        let b = base();
        let mut lease = GrantLease::new();
        lease.on_grant_status(GrantStatusOutcome::live(T0), b, TOKEN_EXP, &cfg());
        assert_eq!(
            lease.decide(after(b, 20), TOKEN_EXP, &cfg()),
            Decision::Serve
        );
    }

    #[test]
    fn a_later_absent_sla_cannot_widen_an_already_tightened_window() {
        // ⚠ The fail-safe direction. Once an operator has tightened the lease to 10s, a
        // subsequent answer that omits the fields (a rolled-back server, a partial response)
        // must NOT silently restore the looser 30s default.
        let b = base();
        let mut lease = GrantLease::new();
        lease.on_grant_status(
            GrantStatusOutcome::live_with_sla(T0, 10, 90),
            b,
            TOKEN_EXP,
            &cfg(),
        );
        lease.on_grant_status(
            GrantStatusOutcome::live(T0 + 1),
            after(b, 1),
            TOKEN_EXP,
            &cfg(),
        );
        assert_eq!(
            lease.decide(after(b, 20), TOKEN_EXP, &cfg()),
            Decision::ReconfirmRequired,
            "an omitted SLA must not widen a window the operator already tightened"
        );
    }

    #[test]
    fn broker_clamp_bounds_match_migration_0022() {
        // The pinning test promised by the `LEASE_*`/`OUTAGE_GRACE_*` doc-comment. Two independent
        // copies of a bound are only defensible if a drift is loud, so assert the broker's
        // ceiling/floor against the seed row's declared range. If the seed changes, this fails and
        // the change becomes a decision instead of a silent divergence.
        // S210: the range was declared by migration 0022; since the v1 re-baseline the seed row
        // lives in 0001_baseline.sql (generated from that chain), so the assertion reads it there.
        let sql = include_str!("../../migrations/0001_baseline.sql");
        for (knob, min, max) in [
            ("revocation_lease_seconds", LEASE_MIN_SECS, LEASE_MAX_SECS),
            (
                "revocation_outage_grace_seconds",
                OUTAGE_GRACE_MIN_SECS,
                OUTAGE_GRACE_MAX_SECS,
            ),
        ] {
            // ⚠ Anchor on the ROW'S OWN KEY, not on the name appearing anywhere on the line:
            // in the baseline each seed row is ONE line including its description, and the
            // lease row's description names the outage knob — `contains(knob)` matched the
            // wrong row and CI failed on the first run against the baseline (S210). The
            // chain's 0022 had the description on its own line, which is why this passed
            // there by accident.
            let anchor = format!("VALUES ('{knob}',");
            let line = sql
                .lines()
                .find(|l| l.contains(&anchor) && l.contains("'integer'"))
                .unwrap_or_else(|| panic!("{knob} seed row not found in the baseline"));
            assert!(
                line.contains(&format!("'{min}'")) && line.contains(&format!("'{max}'")),
                "{knob}: broker bounds ({min},{max}) do not match the seed row (declared by 0022, now in the baseline): {line}"
            );
        }
    }
}
