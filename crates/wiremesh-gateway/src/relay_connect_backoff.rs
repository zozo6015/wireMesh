//! Per-(peer, relay) relay-connect back-off (Phase B, D2 / BACKLOG item 19).
//!
//! Rationale: `main.rs::ensure_relay_transport`'s error arm used to be a bare
//! `eprintln!` + `return` — no retry state, no back-off, no signal. It is
//! re-spawned from two `MarkRelayNeeded`-driven sites, so a relay that could
//! never work for this gateway (version-skewed ALPN, revoked cert, CA
//! mismatch, or simply dead) produced a **silent, indefinitely repeating,
//! per-tick retry** with one indistinguishable line per attempt. This type
//! bounds the RATE, and [`wiremesh_relay::RelayConnectFailure`] makes the
//! cause distinguishable; the two together are what D2 asks for.
//!
//! Same discipline as [`crate::punch_backoff`] and `path.rs`: pure and
//! unit-testable — no sockets, no clocks. Every method takes an injected
//! `now: Instant`, and jitter randomness is injected via the constructor
//! seed (a deterministic PRNG), so replaying the same event sequence yields
//! identical windows. `try_start_relay_connect` bounds CONCURRENCY (one
//! connect per peer at a time); this type bounds how often a (peer, relay)
//! pair may attempt at all.
//!
//! # Permanent vs transient (the one judgement call, ruled 2026-08-25)
//!
//! [`crate::punch_backoff`] waits for [`FAILURE_THRESHOLD`] consecutive
//! failures because transient failures are normal during NAT traversal. That
//! is true here for `Unreachable`/`Other` — a relay can be briefly
//! unreachable — but NOT for `AlpnMismatch` or `PeerRejectedCredentials`:
//! those are properties of the two peers' *configuration*, and retry number
//! two will fail exactly like retry number one. So a permanently-classified
//! cause opens a back-off window **immediately**, which is precisely the
//! silent-indefinite-retry shape D2 exists to kill.
use std::time::{Duration, Instant};

use wiremesh_relay::RelayConnectFailure;

/// Consecutive TRANSIENT failures before the first back-off window opens.
/// Mirrors [`crate::punch_backoff::FAILURE_THRESHOLD`] and for the same
/// reason: a relay can be momentarily unreachable, and backing off on the
/// first blip would slow real re-pathing for nothing.
pub const FAILURE_THRESHOLD: u32 = 3;

/// A PERMANENTLY-classified cause backs off from the first failure. See the
/// module doc.
pub const PERMANENT_FAILURE_THRESHOLD: u32 = 1;

/// First back-off window's un-jittered length.
pub const BACKOFF_BASE: Duration = Duration::from_secs(30);

/// Ceiling on any back-off window — a permanently unusable relay keeps being
/// retried, just slowly, so a fixed config error still recovers on its own
/// once fixed.
pub const BACKOFF_CAP: Duration = Duration::from_secs(300);

/// What the driver should do with a relay-connect attempt it is about to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayConnectDecision {
    /// Run the connect attempt.
    Allow,
    /// Skip it: this (peer, relay) is inside an open back-off window ending
    /// at `until`. Stable — repeated decides inside the window return the
    /// same `until`; only [`RelayConnectBackoff::record_failure`] opens one.
    Skip { until: Instant },
}

/// Whether the driver should emit a log line for this failure.
///
/// The rate-limiting requirement is "not silenced, not once-per-tick": an
/// operator must be able to see the cause without the line repeating every
/// tick forever. So a line is emitted on the FIRST failure, on any CHANGE of
/// classified cause, and once per newly-opened window — and suppressed for
/// the identical repeated cause in between.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogDecision {
    /// Emit the line.
    Log,
    /// Suppress: same cause as the last logged one, inside an open window.
    Suppress,
}

/// One (peer, relay) pair's relay-connect back-off state.
#[derive(Debug, Clone)]
pub struct RelayConnectBackoff {
    /// splitmix64 PRNG state for the jitter draws, seeded by the constructor
    /// — injected randomness so tests are deterministic. Jitter decorrelates
    /// distinct pairs so their backed-off retries don't re-synchronize.
    rng_state: u64,
    /// Consecutive failures since the last success. NOT reset by a window
    /// merely expiring — the post-expiry retry is half-open: if it fails
    /// too, the next window doubles.
    consecutive_failures: u32,
    /// The last classified cause, so a CHANGE of cause is loggable even
    /// inside an open window (a relay that goes from unreachable to
    /// cert-rejecting is new information an operator needs).
    last_cause: Option<RelayConnectFailure>,
    /// The open back-off window's end, if one is open.
    window_until: Option<Instant>,
}

impl RelayConnectBackoff {
    /// One instance per (peer, relay) pair. `jitter_seed` is the injected
    /// randomness source for the window jitter.
    pub fn new(jitter_seed: u64) -> Self {
        RelayConnectBackoff {
            rng_state: jitter_seed,
            consecutive_failures: 0,
            last_cause: None,
            window_until: None,
        }
    }

    /// Decide whether a connect attempt may run at `now`. Consulted before
    /// EVERY attempt.
    pub fn decide(&mut self, now: Instant) -> RelayConnectDecision {
        match self.window_until {
            Some(until) if now < until => RelayConnectDecision::Skip { until },
            Some(_) => {
                // The window has passed: half-open — allow one retry, but
                // keep the failure counter, so a further failure opens the
                // next (doubled) window rather than starting over.
                self.window_until = None;
                RelayConnectDecision::Allow
            }
            None => RelayConnectDecision::Allow,
        }
    }

    /// Record one failed connect attempt and its classified `cause`, opening
    /// a back-off window once the threshold for that cause is reached:
    /// [`PERMANENT_FAILURE_THRESHOLD`] for `AlpnMismatch` /
    /// `PeerRejectedCredentials`, [`FAILURE_THRESHOLD`] for the rest.
    ///
    /// Returns whether the driver should log this failure — see
    /// [`LogDecision`].
    pub fn record_failure(&mut self, now: Instant, cause: RelayConnectFailure) -> LogDecision {
        let cause_changed = self.last_cause != Some(cause);
        let first_failure = self.consecutive_failures == 0;
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.last_cause = Some(cause);

        let threshold = if is_permanent(cause) {
            PERMANENT_FAILURE_THRESHOLD
        } else {
            FAILURE_THRESHOLD
        };

        let mut opened_window = false;
        if self.consecutive_failures >= threshold {
            let exp = (self.consecutive_failures - threshold).min(31);
            let raw = BACKOFF_BASE.saturating_mul(1u32 << exp);
            let delay = raw.mul_f64(1.0 + self.next_jitter()).min(BACKOFF_CAP);
            self.window_until = Some(now + delay);
            opened_window = true;
        }

        if first_failure || cause_changed || opened_window {
            LogDecision::Log
        } else {
            LogDecision::Suppress
        }
    }

    /// A connect succeeded: this relay is provably usable right now, so any
    /// open window clears immediately and the counter restarts from zero.
    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.last_cause = None;
        self.window_until = None;
    }

    /// The open back-off window's end, if any — read-only, for the driver's
    /// log line.
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

/// Whether a cause can only be fixed by changing configuration somewhere —
/// i.e. whether retrying it soon is provably pointless. See the module doc.
pub fn is_permanent(cause: RelayConnectFailure) -> bool {
    match cause {
        RelayConnectFailure::AlpnMismatch | RelayConnectFailure::PeerRejectedCredentials(_) => true,
        RelayConnectFailure::Unreachable | RelayConnectFailure::Other => false,
    }
}
