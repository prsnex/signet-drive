// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! Rate governor for direct-to-storage transfers (bug060).
//!
//! # What it is for
//!
//! Two transfer failure modes pull in opposite directions:
//!
//! * **FM1 — slow but steady.** Parts legitimately take tens of seconds. Needs a
//!   *long* tolerance or healthy uploads die (this was bug060).
//! * **FM2 — fast but stalling.** A connection silently dies. Needs a *short*
//!   tolerance or a dead flow wastes minutes (this was bug047).
//!
//! A single fixed number of seconds cannot serve both: every value is
//! simultaneously too short for some link and too long for another. The governing
//! invariant that falls out —
//!
//! > **No absolute wall-time constant may bound a quantity proportional to
//! > `bytes ÷ rate`.**
//!
//! — is satisfied by measuring the link and expressing durations as multiples of
//! what the link should take, never as fixed seconds.
//!
//! # The AIMD shape
//!
//! The estimator hunts the true rate the way TCP hunts capacity:
//!
//! * **Additive-ish increase:** each completed part folds its observed rate into
//!   an EWMA, so the estimate tracks a link that improves.
//! * **Multiplicative decrease, in two places.** [`Self::penalize_stall`] halves the
//!   *estimate* after a part exhausts its attempts, so later parts and later runs get
//!   a proportionally wider allowance. And within a part, `http::put_presigned`
//!   *doubles the per-attempt ceiling* on each `transfer_stalled` retry, so an
//!   over-optimistic estimate self-corrects inside the part's own attempt budget.
//!
//!   The second half was missing until S127 (Gus, G1) and this paragraph described
//!   it anyway: the ceiling was computed once and reused for all ten attempts, so a
//!   rate drop steeper than `k` condemned every one of them under the same wrong
//!   bound, failed the part, and aborted the upload — recovery only across manual
//!   re-runs. Bounded and resumable, but the opposite of "self-corrects rather than
//!   repeatedly condemning healthy transfers". Recorded because the gap between what
//!   this module claimed and what it did was itself the finding.
//!
//! The asymmetry is deliberate and matches the cost asymmetry: over-estimating the
//! rate produces a too-tight ceiling that can kill a healthy transfer (bad);
//! under-estimating merely delays detection of a genuinely dead one (mild).
//!
//! # Why this surface has no adaptive part sizing
//!
//! The web governor sizes parts from the measured rate, because there part
//! completion is the only honest clock and part *duration* therefore sets
//! dead-flow detection latency. The CLI has no equivalent need and, more to the
//! point, no input:
//!
//! * a fresh upload commits its chunk plan at multipart-initiate, **before any
//!   part has been transferred**, so there is no measurement to size from; and
//! * a resumed upload's `chunk_size` is pinned by the server and validated on
//!   resume — it cannot change mid-upload without re-initiating.
//!
//! Since the transport's dead-flow detector is rate-free and size-independent,
//! part size on this surface is an efficiency choice (retry granularity), never a
//! correctness one — so the default stands and nothing speculative is built. The
//! natural future seam, if field data ever asks for it, is re-planning at the
//! **resume boundary** (a fresh initiate for the remaining bytes): no mid-upload
//! machinery, no envelope-format change.
//!
//! # On the CLI, ceilings are belt-and-braces
//!
//! The CLI's dead-flow detector is the transport's **rate-free no-progress gap**,
//! which is size-independent and needs no estimate at all. The per-part ceiling
//! here exists only to close the residual the gap detector cannot see: a
//! pathological trickle that moves a byte just often enough to keep resetting the
//! gap. That is why `k` is generous on this surface — margin costs nothing in
//! dead-flow latency. (On the web the trade is real: XHR is blind mid-part, so
//! there the ceiling *is* the detector.)

use std::time::Duration;

/// EWMA weight for a newly completed part. In the 0.3–0.5 band indicated by the
/// S126 rate-stability measurement (80 samples, 10 min: the achievable rate varied
/// 3.5x within a single window, so the estimate must track briskly). A weighting
/// factor is dimensionless and therefore rate-free — no invariant concern.
const ALPHA: f64 = 0.4;

/// Below this, a "rate" is noise or a divide-by-zero hazard rather than a
/// measurement (bytes per second).
const MIN_CREDIBLE_RATE: f64 = 1024.0;

/// How long a persisted rate estimate stays usable for a warm start. Covers the
/// dominant resume case — an interruption within the same session, on the same
/// link — while refusing to size today's upload from yesterday's café wifi. A
/// cliff rather than a decay curve: there is nothing to calibrate a decay against.
pub const RATE_FRESHNESS: Duration = Duration::from_secs(15 * 60);

/// Server-served governor parameters (migration 0037). Defaults apply when an
/// older server omits them.
#[derive(Debug, Clone, Copy)]
pub struct GovernorKnobs {
    pub ceiling_k: u32,
    pub target_part_seconds: u64,
    pub part_min_bytes: usize,
    pub part_max_bytes: usize,
}

impl Default for GovernorKnobs {
    fn default() -> Self {
        Self {
            ceiling_k: 4,
            target_part_seconds: 10,
            part_min_bytes: 5 * 1024 * 1024,
            part_max_bytes: 64 * 1024 * 1024,
        }
    }
}

impl GovernorKnobs {
    /// Read from a multipart initiate/resume response, clamping to the same bounds
    /// the server schema enforces so a corrupt value can neither disable the
    /// ceiling nor produce an illegal part size.
    pub fn from_response(value: &serde_json::Value) -> Self {
        let d = Self::default();
        let g = value.get("governor");
        let int = |name: &str, lo: i64, hi: i64, fallback: i64| -> i64 {
            g.and_then(|g| g.get(name))
                .and_then(serde_json::Value::as_i64)
                .map(|v| v.clamp(lo, hi))
                .unwrap_or(fallback)
        };
        Self {
            ceiling_k: int("ceiling_k_cli", 2, 20, d.ceiling_k as i64) as u32,
            target_part_seconds: int("target_part_seconds", 2, 120, d.target_part_seconds as i64)
                as u64,
            part_min_bytes: int(
                "part_min_bytes",
                5 * 1024 * 1024,
                64 * 1024 * 1024,
                d.part_min_bytes as i64,
            ) as usize,
            part_max_bytes: int(
                "part_max_bytes",
                5 * 1024 * 1024,
                1024 * 1024 * 1024,
                d.part_max_bytes as i64,
            ) as usize,
        }
    }
}

/// Tracks the observed transfer rate and derives bounds from it.
#[derive(Debug, Clone)]
pub struct TransferGovernor {
    knobs: GovernorKnobs,
    /// Bytes per second. `None` until a part completes or a warm start supplies
    /// one — and `None` is a *correct, safe* state, not a missing value: it means
    /// "no ceiling yet", which is exactly right on a surface whose real detector
    /// is rate-free.
    rate_est: Option<f64>,
    /// 3a-i (S175): the estimate's epoch, advanced on every halving. Each transfer
    /// ATTEMPT stamps the generation it started under ([`Self::generation`]); a
    /// stall penalises only if the generation is unchanged since that stamp — so
    /// when one link event trips N concurrent parts at once, the FIRST reporter
    /// halves and the rest find the epoch advanced and stay quiet. One event, one
    /// response. Two genuinely sequential degradations still cost two halvings,
    /// because an attempt started after the first halving carries the new stamp.
    ///
    /// ⚠ NOT a feedback loop: derived from this control's own actions, never from
    /// link measurement — it only ever SUPPRESSES firings of the existing AIMD
    /// reflex (Gus's §7 check, S175; Chris's S172 no-feedback-control ruling
    /// stays closed).
    generation: u64,
}

impl TransferGovernor {
    pub fn new(knobs: GovernorKnobs) -> Self {
        Self {
            knobs,
            rate_est: None,
            generation: 0,
        }
    }

    /// Start warm from a persisted estimate, if it is still fresh enough to
    /// describe the current link.
    pub fn with_warm_start(knobs: GovernorKnobs, rate_bps: f64, age: Duration) -> Self {
        let rate_est = (age <= RATE_FRESHNESS && rate_bps >= MIN_CREDIBLE_RATE).then_some(rate_bps);
        Self {
            knobs,
            rate_est,
            generation: 0,
        }
    }

    /// The current estimate epoch. Read this at ATTEMPT start (each retry
    /// re-stamps, so a retry's evidence stays fresh) and hand it back to
    /// [`Self::penalize_stall`] if that attempt stalls.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The current estimate, for persistence across a resume.
    pub fn rate_estimate(&self) -> Option<f64> {
        self.rate_est
    }

    /// Fold a completed part's observed rate into the estimate (the "increase"
    /// half of AIMD).
    pub fn observe_part(&mut self, bytes: usize, elapsed: Duration) {
        let secs = elapsed.as_secs_f64();
        if secs <= 0.0 || bytes == 0 {
            return;
        }
        let observed = bytes as f64 / secs;
        if observed < MIN_CREDIBLE_RATE {
            return;
        }
        self.rate_est = Some(match self.rate_est {
            Some(prev) => ALPHA * observed + (1.0 - ALPHA) * prev,
            None => observed,
        });
    }

    /// Halve the estimate after a stalled attempt (the "multiplicative decrease"
    /// half). An over-optimistic estimate is the only way this governor can harm a
    /// healthy transfer, so it retreats fast and rebuilds slowly.
    ///
    /// 3a-i: `start_generation` is the epoch the stalled ATTEMPT began under
    /// ([`Self::generation`]). If the epoch has advanced since — another part of
    /// the same burst already answered this link event — the call is a no-op, so
    /// N simultaneous trips cost ONE halving, not a 2⁻ᴺ collapse.
    ///
    /// ⚠ Rider 1 (Gus, S175): the compare and the halve-and-advance are ONE
    /// critical section BY CONSTRUCTION — both live inside this single `&mut`
    /// call, so under the fan-out's shared lock the check-then-act race cannot
    /// be written. Do not split this into a caller-side check.
    pub fn penalize_stall(&mut self, start_generation: u64) {
        if start_generation != self.generation {
            return; // this link event has already been answered
        }
        if let Some(rate) = self.rate_est {
            let halved = rate / 2.0;
            self.rate_est = (halved >= MIN_CREDIBLE_RATE).then_some(halved);
            self.generation += 1;
        }
    }

    /// The per-attempt ceiling for a part of `bytes`, or `None` when there is no
    /// credible estimate yet.
    ///
    /// `None` means "do not bound this attempt by duration" — correct on the CLI,
    /// where the rate-free gap detector is already complete without any estimate
    /// (the first part of the first upload therefore runs unbounded except by the
    /// gap, exactly as designed).
    pub fn ceiling(&self, bytes: usize) -> Option<Duration> {
        let rate = self.rate_est?;
        let expected = bytes as f64 / rate;
        Some(Duration::from_secs_f64(
            (expected * self.knobs.ceiling_k as f64).clamp(1.0, 86_400.0),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MB: usize = 1024 * 1024;

    fn knobs() -> GovernorKnobs {
        GovernorKnobs::default()
    }

    #[test]
    fn no_estimate_means_no_ceiling() {
        // The first part of a first upload must not be bounded by a duration: there
        // is nothing to derive one from, and inventing a constant would be exactly
        // the defect this module exists to prevent.
        let g = TransferGovernor::new(knobs());
        assert!(g.ceiling(16 * MB).is_none());
        assert!(g.rate_estimate().is_none());
    }

    #[test]
    fn ceiling_is_a_multiple_of_expected_duration_not_a_constant() {
        let mut g = TransferGovernor::new(knobs());
        // 1 MB/s observed.
        g.observe_part(4 * MB, Duration::from_secs(4));
        let small = g.ceiling(4 * MB).unwrap();
        let large = g.ceiling(32 * MB).unwrap();
        // Eight times the bytes must yield ~eight times the ceiling. A fixed
        // constant would make these equal — which is precisely bug060.
        let ratio = large.as_secs_f64() / small.as_secs_f64();
        assert!(
            (ratio - 8.0).abs() < 0.1,
            "ceiling must scale with bytes: {small:?} vs {large:?} (ratio {ratio})"
        );
    }

    #[test]
    fn a_slower_link_gets_a_longer_ceiling_for_the_same_bytes() {
        let mut fast = TransferGovernor::new(knobs());
        fast.observe_part(16 * MB, Duration::from_secs(2));
        let mut slow = TransferGovernor::new(knobs());
        slow.observe_part(16 * MB, Duration::from_secs(20));
        assert!(
            slow.ceiling(16 * MB).unwrap() > fast.ceiling(16 * MB).unwrap(),
            "the same part on a slower link must be allowed more time"
        );
    }

    #[test]
    fn stall_halves_the_estimate_and_widens_the_ceiling() {
        let mut g = TransferGovernor::new(knobs());
        g.observe_part(8 * MB, Duration::from_secs(8));
        let before = g.ceiling(8 * MB).unwrap();
        let stamp = g.generation();
        g.penalize_stall(stamp);
        let after = g.ceiling(8 * MB).unwrap();
        // Retreating on the estimate must RELAX the bound, never tighten it —
        // otherwise a stall would make the next attempt likelier to fail too.
        let ratio = after.as_secs_f64() / before.as_secs_f64();
        assert!(
            (ratio - 2.0).abs() < 0.05,
            "a stall must double the allowance: {before:?} -> {after:?}"
        );
    }

    #[test]
    fn repeated_stalls_cannot_drive_the_estimate_to_absurdity() {
        let mut g = TransferGovernor::new(knobs());
        g.observe_part(8 * MB, Duration::from_secs(8));
        for _ in 0..40 {
            // Sequential, re-stamped stalls: each is fresh evidence and each
            // legitimately halves — the de-dup must not dampen a genuinely
            // repeating degradation.
            let stamp = g.generation();
            g.penalize_stall(stamp);
        }
        // Once the estimate stops being credible it is dropped entirely, which
        // yields "no ceiling" rather than an infinite or zero one.
        assert!(g.rate_estimate().is_none());
        assert!(g.ceiling(8 * MB).is_none());
    }

    #[test]
    fn a_burst_of_simultaneous_stalls_halves_exactly_once() {
        // 3a-i (S175): one link event trips N concurrent parts at once. All N
        // attempts were stamped under the SAME generation; only the first
        // reporter may halve, or a single event costs a 2^-N collapse.
        let mut g = TransferGovernor::new(knobs());
        g.observe_part(8 * MB, Duration::from_secs(8)); // 1 MB/s
        let before = g.rate_estimate().unwrap();
        let stamp = g.generation();
        for _ in 0..4 {
            g.penalize_stall(stamp); // four parts, one burst, one stamp
        }
        let after = g.rate_estimate().unwrap();
        let ratio = before / after;
        assert!(
            (ratio - 2.0).abs() < 1e-9,
            "a 4-part burst must cost exactly ONE halving, not four: {before} -> {after}"
        );
    }

    #[test]
    fn sequential_degradations_still_halve_twice() {
        // The de-dup removes same-cause duplicates ONLY. An attempt that began
        // AFTER the first halving carries the new stamp; if it still stalls,
        // that is fresh evidence and legitimately halves again.
        let mut g = TransferGovernor::new(knobs());
        g.observe_part(8 * MB, Duration::from_secs(8));
        let before = g.rate_estimate().unwrap();
        let first = g.generation();
        g.penalize_stall(first);
        let second = g.generation();
        assert_ne!(first, second, "a halving must advance the epoch");
        g.penalize_stall(second);
        let after = g.rate_estimate().unwrap();
        let ratio = before / after;
        assert!(
            (ratio - 4.0).abs() < 1e-9,
            "two sequential degradations must cost TWO halvings: {before} -> {after}"
        );
    }

    #[test]
    fn a_stale_straggler_cannot_penalize_and_cannot_advance_the_epoch() {
        // A part that started two generations ago and only now reports its stall
        // must change nothing — its evidence describes a link state the estimate
        // has already answered twice.
        let mut g = TransferGovernor::new(knobs());
        g.observe_part(8 * MB, Duration::from_secs(8));
        let ancient = g.generation();
        g.penalize_stall(ancient); // gen advances
        let gen1 = g.generation();
        g.penalize_stall(gen1); // gen advances again
        let settled = g.rate_estimate().unwrap();
        let epoch = g.generation();
        g.penalize_stall(ancient); // the straggler
        assert_eq!(g.rate_estimate().unwrap(), settled, "no penalty");
        assert_eq!(g.generation(), epoch, "no epoch movement either");
    }

    #[test]
    fn ewma_tracks_a_changing_link_without_chasing_one_sample() {
        let mut g = TransferGovernor::new(knobs());
        g.observe_part(10 * MB, Duration::from_secs(10)); // 1 MB/s
        let first = g.rate_estimate().unwrap();
        g.observe_part(10 * MB, Duration::from_secs(5)); // 2 MB/s
        let second = g.rate_estimate().unwrap();
        assert!(
            second > first,
            "the estimate must rise toward a faster link"
        );
        assert!(
            second < 2.0 * MB as f64,
            "but it must not jump straight to the newest sample"
        );
    }

    #[test]
    fn warm_start_accepts_a_fresh_estimate_and_rejects_a_stale_one() {
        let fresh =
            TransferGovernor::with_warm_start(knobs(), 2.0 * MB as f64, Duration::from_secs(60));
        assert!(fresh.rate_estimate().is_some());
        let stale = TransferGovernor::with_warm_start(
            knobs(),
            2.0 * MB as f64,
            RATE_FRESHNESS + Duration::from_secs(1),
        );
        assert!(
            stale.rate_estimate().is_none(),
            "a stale estimate must fall back to the bootstrap path, not mis-size today's upload"
        );
        // An implausible persisted value is refused regardless of freshness.
        let junk = TransferGovernor::with_warm_start(knobs(), 1.0, Duration::from_secs(1));
        assert!(junk.rate_estimate().is_none());
    }

    #[test]
    fn knobs_from_response_clamp_to_the_server_schema_bounds() {
        let hostile = serde_json::json!({
            "governor": {
                "ceiling_k_cli": 9999,
                "target_part_seconds": 0,
                "part_min_bytes": 1,
                "part_max_bytes": 1,
            }
        });
        let k = GovernorKnobs::from_response(&hostile);
        assert!(k.ceiling_k <= 20, "k must be clamped");
        assert!(k.target_part_seconds >= 2);
        assert!(
            k.part_min_bytes >= 5 * MB,
            "a corrupt value must never take the part size below the storage floor"
        );
        // A response with no governor block at all yields the defaults.
        let empty = GovernorKnobs::from_response(&serde_json::json!({}));
        assert_eq!(empty.ceiling_k, GovernorKnobs::default().ceiling_k);
    }
}
