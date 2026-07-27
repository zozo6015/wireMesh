//! Per-peer-pair punch back-off (mesh-convergence fix T3, plan
//! `docs/superpowers/plans/2026-07-28-mesh-convergence-fixes.md`).
//!
//! Rationale (`docs/research/ops-finding-multi-gateway-convergence.md` §3):
//! in the 2026-07-27 incident, px's pair with home could never complete
//! inbound (px's NAT drops unsolicited inbound to its observed mapping), so
//! punch directives re-punched every few seconds INDEFINITELY. That storm
//! wasn't just wasted effort: each attempt opens the transient same-port
//! `SO_REUSEPORT` punch socket, which — held open near-continuously —
//! plausibly stole inbound WireGuard datagrams on :51820 from boringtun's
//! own socket (the exact starvation hazard from
//! `docs/research/cycle4c-relay-stability-note.md`), observed as
//! "initiations arrive but are never answered" on MULTIPLE gateways. A
//! permanently-undialable pair must decay to slow retries instead of
//! degrading the rest of the fabric.
//!
//! Pure and unit-testable, same discipline as `path.rs`: no sockets, no
//! clocks — every method takes an injected `now: Instant`, and jitter
//! randomness is injected via the constructor seed (a deterministic PRNG),
//! so replaying the same event sequence yields identical windows. The
//! existing `try_start_punch` in-flight guard bounds CONCURRENCY (one punch
//! per peer at a time); this type bounds RATE (how often a pair may punch
//! at all). One instance per peer pair; `main.rs` keeps them keyed by peer
//! `gateway_id` and consults [`PunchBackoff::decide`] before EVERY punch
//! attempt — controller `PunchDirective`s and tick-driven
//! `StartPunch`/`ProbeDirect` alike.
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

/// Consecutive failed punches before the first back-off window opens
/// (plan T3: N=3 — transient failures are normal during NAT traversal;
/// only a persistent pattern is a storm).
pub const FAILURE_THRESHOLD: u32 = 3;

/// First back-off window's un-jittered length (plan T3: base 30s).
pub const BACKOFF_BASE: Duration = Duration::from_secs(30);

/// Ceiling on any back-off window (plan T3: cap 5min) — a permanently
/// undialable pair keeps retrying, just slowly.
pub const BACKOFF_CAP: Duration = Duration::from_secs(300);

/// What the driver should do with a punch attempt it is about to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchDecision {
    /// Run the punch.
    Allow,
    /// Skip it: the pair is inside an open back-off window ending at
    /// `until`. Stable — repeated decides inside the window return the same
    /// `until` (deciding never extends or re-rolls a window; only
    /// [`PunchBackoff::record_failure`] opens one).
    Skip { until: Instant },
}

/// One peer pair's punch back-off state. See the module doc for why this
/// exists and the finding citation.
#[derive(Debug, Clone)]
pub struct PunchBackoff {
    /// splitmix64 PRNG state for the jitter draws, seeded by the
    /// constructor — injected randomness so tests are deterministic (the
    /// same testability rule as `path.rs`'s injected `now`). Jitter
    /// decorrelates the two ends of a pair (and distinct pairs) so their
    /// backed-off retries don't re-synchronize into simultaneous storms.
    rng_state: u64,
    /// Consecutive failures since the last success / candidate-set change.
    /// NOT reset by a window merely expiring — the post-expiry retry is
    /// half-open: if it fails too, the next window doubles.
    consecutive_failures: u32,
    /// The last candidate SET this pair was decided against. Compared as an
    /// unordered set: candidate ordering carries no meaning, so a mere
    /// reordering (or duplicate) of the same members is not new information,
    /// but a genuinely different set (a fresh observed mapping, new local
    /// endpoints) is fresh information worth punching immediately — it resets
    /// the counter and clears any window.
    last_candidates: Option<BTreeSet<String>>,
    /// The open back-off window's end, if one is open.
    window_until: Option<Instant>,
}

impl PunchBackoff {
    /// One instance per peer pair. `jitter_seed` is the injected randomness
    /// source for the window jitter (any value; the driver should vary it
    /// per pair/side so windows decorrelate).
    pub fn new(jitter_seed: u64) -> Self {
        PunchBackoff {
            rng_state: jitter_seed,
            consecutive_failures: 0,
            last_candidates: None,
            window_until: None,
        }
    }

    /// Decide whether a punch attempt with `candidates` may run at `now`.
    /// Consulted before EVERY attempt. A candidate set differing from the
    /// last-seen one resets the failure counter, clears any open window,
    /// and allows immediately (fresh candidates = fresh information); the
    /// SAME set reordered or duplicated is not a change (otherwise a mere
    /// candidate reordering would quietly re-arm the storm the incident
    /// produced).
    pub fn decide(&mut self, now: Instant, candidates: &[String]) -> PunchDecision {
        let set: BTreeSet<String> = candidates.iter().cloned().collect();
        match &self.last_candidates {
            Some(prev) if *prev != set => {
                self.last_candidates = Some(set);
                self.consecutive_failures = 0;
                self.window_until = None;
                return PunchDecision::Allow;
            }
            Some(_) => {}
            None => self.last_candidates = Some(set),
        }
        match self.window_until {
            Some(until) if now < until => PunchDecision::Skip { until },
            Some(_) => {
                // The window has passed: half-open — allow one retry, but
                // keep the failure counter, so a further failure opens the
                // next (doubled) window rather than starting over.
                self.window_until = None;
                PunchDecision::Allow
            }
            None => PunchDecision::Allow,
        }
    }

    /// Record one attempt that ran and did not confirm a candidate
    /// (`punch_candidates` returned `Ok(None)` or `Err`). From the
    /// [`FAILURE_THRESHOLD`]-th consecutive failure on, opens a back-off
    /// window `until = now + delay` with
    /// `raw = BACKOFF_BASE * 2^(count - FAILURE_THRESHOLD)` (saturating)
    /// and `delay = min(raw * (1 + j), BACKOFF_CAP)`, `j ∈ [0, 0.5)` drawn
    /// deterministically from the constructor seed.
    pub fn record_failure(&mut self, now: Instant) {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= FAILURE_THRESHOLD {
            let exp = (self.consecutive_failures - FAILURE_THRESHOLD).min(31);
            let raw = BACKOFF_BASE.saturating_mul(1u32 << exp);
            let delay = raw.mul_f64(1.0 + self.next_jitter()).min(BACKOFF_CAP);
            self.window_until = Some(now + delay);
        }
    }

    /// A punch confirmed a candidate: the pair is provably dialable right
    /// now, so any open window clears immediately (no waiting out its
    /// `until`) and the consecutive counter restarts from zero.
    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.window_until = None;
    }

    /// The open back-off window's end, if any — a read-only convenience for
    /// the driver's "log once per state change" rule (plan T3: a skipped
    /// directive must not log per directive; the driver logs when this
    /// changes, i.e. when a window opens/extends via [`record_failure`]).
    pub fn backoff_until(&self) -> Option<Instant> {
        self.window_until
    }

    /// splitmix64 step reduced to `[0.0, 0.5)` — deterministic per seed, no
    /// OS randomness in the decision surface.
    fn next_jitter(&mut self) -> f64 {
        self.rng_state = self.rng_state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.rng_state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        // 53 high-quality bits -> [0,1), halved to [0, 0.5).
        ((z >> 11) as f64 / (1u64 << 53) as f64) * 0.5
    }
}
