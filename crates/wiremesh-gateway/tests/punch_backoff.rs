//! T3 pin — punch back-off (mesh-convergence fix cycle, plan
//! `docs/superpowers/plans/2026-07-28-mesh-convergence-fixes.md`, evidence
//! `docs/research/ops-finding-multi-gateway-convergence.md` §3: px's pair
//! with home can never complete inbound, so punch directives re-punched
//! every few seconds indefinitely; the near-continuously-open transient
//! `SO_REUSEPORT` punch socket then stole inbound WG datagrams on :51820
//! from boringtun — the punch storm didn't just waste effort, it broke
//! OTHER pairs' handshakes).
//!
//! TDD: this file is authored AHEAD of the implementation and is EXPECTED
//! to fail to compile until T3 lands. The punch decision currently lives
//! inline in `main.rs` (the `SyncEvent::Punch` arm and `run_path_ticks`'s
//! `to_punch` loop, deduped only by `try_start_punch`'s in-flight guard —
//! which bounds CONCURRENCY, not RATE). These tests are written against the
//! smallest natural pure surface, same approach as T2's `on_handshake`:
//!
//! Target surface (new pure module `src/punch_backoff.rs`,
//! `pub mod punch_backoff;` in `lib.rs` — no sockets, no clocks: every
//! method takes an injected `now: Instant`, like `path.rs`):
//!
//!     pub const FAILURE_THRESHOLD: u32 = 3;
//!     pub const BACKOFF_BASE: Duration = Duration::from_secs(30);
//!     pub const BACKOFF_CAP: Duration = Duration::from_secs(300); // 5 min
//!
//!     #[derive(Debug, Clone, Copy, PartialEq, Eq)]
//!     pub enum PunchDecision {
//!         Allow,
//!         Skip { until: Instant },
//!     }
//!
//!     pub struct PunchBackoff { .. }   // ONE instance PER PEER PAIR
//!     impl PunchBackoff {
//!         pub fn new(jitter_seed: u64) -> Self;
//!         pub fn decide(&mut self, now: Instant, candidates: &[String])
//!             -> PunchDecision;
//!         pub fn record_failure(&mut self, now: Instant);
//!         pub fn record_success(&mut self);
//!     }
//!
//! Normative semantics (plan T3):
//!
//!  - `decide` is consulted before EVERY punch attempt — both a controller
//!    `PunchDirective` and a tick-driven `StartPunch` — with that attempt's
//!    candidate list.
//!  - Candidate lists compare as UNORDERED SETS (order and duplicates are
//!    irrelevant — `set_peer_endpoint` reorders candidates, and a reorder is
//!    not new information). A decide whose candidate SET differs from the
//!    last-seen one RESETS the consecutive-failure counter, clears any open
//!    back-off window, and returns `Allow` (fresh candidates = fresh
//!    information worth punching).
//!  - `record_failure(now)`: one attempt that ran and did not confirm
//!    (`punch_candidates` returned `Ok(None)` or `Err`). On the
//!    `FAILURE_THRESHOLD`-th (and every later) CONSECUTIVE failure, a
//!    back-off window opens: `until = now + delay` with
//!        raw   = BACKOFF_BASE * 2^(count - FAILURE_THRESHOLD)  (saturating)
//!        delay = min(raw * (1 + j), BACKOFF_CAP),  j in [0.0, 0.5)
//!    where `j` is drawn DETERMINISTICALLY from `jitter_seed` (injected
//!    randomness so tests stay deterministic — any deterministic PRNG).
//!  - While `now < until` (half-open window), `decide` with an unchanged
//!    candidate set returns `Skip { until }` with the SAME `until` on every
//!    call — deciding never extends or re-rolls the window. At
//!    `now >= until` it returns `Allow` again; the failure counter is NOT
//!    reset by mere expiry (only success or a candidate-set change resets
//!    it), so the next failure doubles the window.
//!  - `record_success()` (a punch confirmed a candidate): resets the
//!    counter to zero and clears any open window immediately.
//!
//! Driver contract (implementer notes, not directly pinned here):
//!  - `main.rs` keeps one `PunchBackoff` per peer gateway_id (e.g.
//!    `Arc<Mutex<HashMap<u64, PunchBackoff>>>` on `PathCtx`), consulted in
//!    BOTH spawn sites before `try_start_punch`; `punch_and_apply` reports
//!    the outcome (confirmed Some → `record_success`; `Ok(None)`/`Err` →
//!    `record_failure`).
//!  - A skipped directive logs once per STATE CHANGE (entering back-off),
//!    not once per skipped directive (plan T3) — log behavior is not
//!    pinned here.

// The doc comment above column-aligns its continuation lines under the list
// item they belong to. Clippy wants them at the minimum indent, which
// ragged-edges a table a human laid out on purpose, so the disagreement is
// recorded here rather than resolved against the reader.
#![expect(
    clippy::doc_overindented_list_items,
    reason = "the doc comment aligns its continuation lines on purpose; the lint's fix ragged-edges a hand-aligned table"
)]

use std::time::{Duration, Instant};

use wiremesh_gateway::punch_backoff::{
    PunchBackoff, PunchDecision, BACKOFF_BASE, BACKOFF_CAP, FAILURE_THRESHOLD,
};

fn cands() -> Vec<String> {
    vec![
        "203.0.113.5:51820".to_string(),
        "10.0.125.12:51820".to_string(),
    ]
}

/// Unwrap a `Skip` decision's `until`, panicking (with context) on `Allow`.
fn skip_until(d: PunchDecision) -> Instant {
    match d {
        PunchDecision::Skip { until } => until,
        PunchDecision::Allow => panic!("expected Skip, got Allow"),
    }
}

/// Drive `b` to `n` consecutive failures (decide-then-fail each time),
/// starting at `t`, spacing attempts 1s apart. Returns the instant of the
/// last recorded failure.
fn fail_n(b: &mut PunchBackoff, t: Instant, n: u32, candidates: &[String]) -> Instant {
    let mut at = t;
    for i in 0..n {
        at = t + Duration::from_secs(i as u64);
        // Every attempt the driver actually runs was allowed first.
        assert!(
            matches!(b.decide(at, candidates), PunchDecision::Allow),
            "attempt {} of {n} should still be allowed",
            i + 1
        );
        b.record_failure(at);
    }
    at
}

/// T3 plan contract constants: N=3, base 30s, cap 5min.
#[test]
fn t3_contract_constants() {
    assert_eq!(
        FAILURE_THRESHOLD, 3,
        "plan T3: back off after N=3 consecutive failures"
    );
    assert_eq!(BACKOFF_BASE, Duration::from_secs(30), "plan T3: base 30s");
    assert_eq!(BACKOFF_CAP, Duration::from_secs(300), "plan T3: cap 5min");
}

/// T3(a): one or two consecutive failures do NOT back off — the pair is
/// still allowed to punch (transient failures are normal during NAT
/// traversal; only a persistent pattern is a storm).
#[test]
fn t3_failures_below_threshold_stay_allowed() {
    let t0 = Instant::now();
    let mut b = PunchBackoff::new(7);
    let c = cands();

    assert!(
        matches!(b.decide(t0, &c), PunchDecision::Allow),
        "fresh pair must be allowed"
    );
    b.record_failure(t0);
    assert!(
        matches!(b.decide(t0, &c), PunchDecision::Allow),
        "1 failure: still allowed"
    );
    b.record_failure(t0 + Duration::from_secs(1));
    assert!(
        matches!(
            b.decide(t0 + Duration::from_secs(1), &c),
            PunchDecision::Allow
        ),
        "2 failures: still allowed"
    );
}

/// T3(b): the 3rd consecutive failure opens a ~30s window: `Skip` with
/// `until - now` inside the jitter-tolerant bounds [30s, 45s]
/// (raw 30s * (1 + j), j in [0, 0.5)).
#[test]
fn t3_third_failure_backs_off_about_30s() {
    // Bounds must hold for ANY seed — jitter shifts the value, never the range.
    for seed in [0u64, 1, 7, 42, 1337] {
        let t0 = Instant::now();
        let mut b = PunchBackoff::new(seed);
        let c = cands();
        let t_fail = fail_n(&mut b, t0, 3, &c);

        let until = skip_until(b.decide(t_fail, &c));
        let delay = until.saturating_duration_since(t_fail);
        assert!(
            delay >= Duration::from_secs(30) && delay <= Duration::from_secs(45),
            "seed {seed}: 3rd failure window must be in [30s, 45s], got {delay:?}"
        );
    }
}

/// T3(c): each further consecutive failure doubles the window toward the
/// 5min cap and NEVER exceeds it. Bounds (not exact equality — jittered):
/// 4th failure [60s, 90s], 5th [120s, 180s], 6th and beyond [240s, 300s]
/// (raw hits/passes the cap; delay is clamped to <= 300s).
#[test]
fn t3_backoff_doubles_toward_cap_and_never_exceeds_it() {
    let stage_bounds: [(u64, u64); 6] = [
        (60, 90),
        (120, 180),
        (240, 300),
        (240, 300),
        (240, 300),
        (240, 300),
    ];
    for seed in [0u64, 1, 7, 42, 1337] {
        let t0 = Instant::now();
        let mut b = PunchBackoff::new(seed);
        let c = cands();
        let mut now = fail_n(&mut b, t0, 3, &c);
        let mut until = skip_until(b.decide(now, &c));

        for (i, (lo, hi)) in stage_bounds.iter().enumerate() {
            // Wait the window out, get the one allowed retry, fail it again.
            now = until + Duration::from_millis(1);
            assert!(
                matches!(b.decide(now, &c), PunchDecision::Allow),
                "seed {seed}: after the window passes, one retry is allowed (stage {i})"
            );
            b.record_failure(now);
            until = skip_until(b.decide(now, &c));
            let delay = until.saturating_duration_since(now);
            assert!(
                delay >= Duration::from_secs(*lo) && delay <= Duration::from_secs(*hi),
                "seed {seed}: failure #{} window must be in [{lo}s, {hi}s], got {delay:?}",
                4 + i
            );
            assert!(
                delay <= BACKOFF_CAP,
                "seed {seed}: no window may ever exceed the 5min cap, got {delay:?}"
            );
        }
    }
}

/// T3(d): a punch SUCCESS clears the back-off immediately (same instant —
/// no waiting out the window) and resets the consecutive counter, so the
/// next back-off again requires 3 FRESH consecutive failures.
#[test]
fn t3_success_resets_immediately_and_counter_restarts() {
    let t0 = Instant::now();
    let mut b = PunchBackoff::new(42);
    let c = cands();
    let t_fail = fail_n(&mut b, t0, 3, &c);
    assert!(matches!(b.decide(t_fail, &c), PunchDecision::Skip { .. }));

    b.record_success();
    assert!(
        matches!(b.decide(t_fail, &c), PunchDecision::Allow),
        "success must clear the window immediately, not at its until-instant"
    );

    // Counter restarted: two fresh failures stay allowed, the third backs off.
    let t1 = t_fail + Duration::from_secs(60);
    b.record_failure(t1);
    b.record_failure(t1 + Duration::from_secs(1));
    assert!(
        matches!(
            b.decide(t1 + Duration::from_secs(1), &c),
            PunchDecision::Allow
        ),
        "post-success failures 1..2 must be allowed again (counter was reset)"
    );
    b.record_failure(t1 + Duration::from_secs(2));
    assert!(
        matches!(
            b.decide(t1 + Duration::from_secs(2), &c),
            PunchDecision::Skip { .. }
        ),
        "3rd post-success consecutive failure backs off again"
    );
}

/// T3(e): a CHANGED candidate set (the controller learned something new —
/// e.g. a fresh observed mapping or new local endpoints) resets the counter
/// and clears any open window: the very next decide is `Allow`, and the
/// counter restarts from zero.
#[test]
fn t3_candidate_set_change_resets() {
    let t0 = Instant::now();
    let mut b = PunchBackoff::new(9);
    let old = cands();
    let t_fail = fail_n(&mut b, t0, 3, &old);
    assert!(matches!(b.decide(t_fail, &old), PunchDecision::Skip { .. }));

    // New observed mapping for the peer → different candidate set.
    let fresh = vec![
        "198.51.100.7:41000".to_string(),
        "10.0.125.12:51820".to_string(),
    ];
    assert!(
        matches!(b.decide(t_fail, &fresh), PunchDecision::Allow),
        "a changed candidate set must clear the back-off and allow immediately"
    );

    // And the consecutive counter restarted with it.
    b.record_failure(t_fail);
    b.record_failure(t_fail + Duration::from_secs(1));
    assert!(
        matches!(
            b.decide(t_fail + Duration::from_secs(1), &fresh),
            PunchDecision::Allow
        ),
        "failures 1..2 against the fresh set must be allowed (counter was reset)"
    );
}

/// T3(e) boundary: candidate lists compare as SETS — the same candidates
/// reordered (or duplicated) are NOT new information and must not clear an
/// open back-off (otherwise `set_peer_endpoint`'s candidate reorder would
/// quietly re-arm the storm).
#[test]
fn t3_same_set_reordered_is_not_a_change() {
    let t0 = Instant::now();
    let mut b = PunchBackoff::new(3);
    let c = vec![
        "203.0.113.5:51820".to_string(),
        "10.0.125.12:51820".to_string(),
    ];
    let t_fail = fail_n(&mut b, t0, 3, &c);
    let until = skip_until(b.decide(t_fail, &c));

    let reordered = vec![
        "10.0.125.12:51820".to_string(),
        "203.0.113.5:51820".to_string(),
    ];
    let until2 = skip_until(b.decide(t_fail + Duration::from_secs(1), &reordered));
    assert_eq!(
        until, until2,
        "reordering the same candidate set must not reset the window"
    );
}

/// T3(f): skip decisions are STABLE within the window — the same directive
/// arriving repeatedly gets the same `until` every time (deciding never
/// extends or re-rolls the window) — and the instant the window has passed,
/// punching is allowed again.
#[test]
fn t3_skip_is_stable_within_window_then_expires() {
    let t0 = Instant::now();
    let mut b = PunchBackoff::new(21);
    let c = cands();
    let t_fail = fail_n(&mut b, t0, 3, &c);

    let u1 = skip_until(b.decide(t_fail + Duration::from_secs(1), &c));
    let u2 = skip_until(b.decide(t_fail + Duration::from_secs(5), &c));
    let u3 = skip_until(b.decide(t_fail + Duration::from_secs(20), &c));
    assert_eq!(
        u1, u2,
        "repeated directives inside the window see one stable until"
    );
    assert_eq!(u2, u3, "deciding must not extend the window");

    assert!(
        matches!(
            b.decide(u1 + Duration::from_millis(1), &c),
            PunchDecision::Allow
        ),
        "once the until-instant passes, the pair may punch again"
    );
}

/// Deterministic-jitter pin: jitter randomness is INJECTED (the seed
/// parameter), so two instances with the same seed replaying the same
/// event sequence produce identical windows — no OS randomness in the
/// decision surface (same testability rule as `path.rs`'s injected `now`).
#[test]
fn t3_jitter_is_deterministic_per_seed() {
    let t0 = Instant::now();
    let c = cands();
    let mut a = PunchBackoff::new(42);
    let mut b = PunchBackoff::new(42);
    let ta = fail_n(&mut a, t0, 3, &c);
    let tb = fail_n(&mut b, t0, 3, &c);
    assert_eq!(ta, tb);
    assert_eq!(
        skip_until(a.decide(ta, &c)),
        skip_until(b.decide(tb, &c)),
        "same seed + same events must yield the same window"
    );
}
