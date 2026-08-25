//! PR5 / design C5-D2 (BACKLOG item 19) pin — per-(peer, relay) relay-connect
//! back-off.
//!
//! ./dev.sh run "cargo test -p wiremesh-gateway --test relay_connect_backoff"
//!
//! # The defect this bounds
//!
//! `main.rs::ensure_relay_transport`'s error arm was a bare `eprintln!` +
//! `return`: no retry state, no back-off, no signal. It is re-spawned from two
//! `MarkRelayNeeded`-driven sites, so a relay that could NEVER work for this
//! gateway — version-skewed ALPN, revoked cert, CA mismatch — produced a
//! silent, indefinitely repeating, per-tick retry with one indistinguishable
//! line per attempt. This type bounds the RATE;
//! `wiremesh_relay::RelayConnectFailure` makes the cause distinguishable.
//! `try_start_relay_connect` bounds CONCURRENCY, which is a different thing
//! and does not overlap.
//!
//! # Why these tests live in `tests/` rather than in-module
//!
//! Mirrors `tests/punch_backoff.rs`, the sibling this module is modelled on:
//! the whole surface is `pub`, the module is pure (no sockets, no clocks —
//! `now` is injected and jitter comes from a constructor seed), so nothing
//! here needs private access. Keeping it out of the production file also
//! keeps the author/test-author split a FILE boundary rather than a
//! `#[cfg(test)]` marker inside a file two agents share (design §13.2).
//!
//! # The one judgement call, and why it is worth a test each way
//!
//! `punch_backoff` waits for three consecutive failures because transient
//! failures are normal during NAT traversal. That holds here for
//! `Unreachable`/`Other`, but NOT for `AlpnMismatch` /
//! `PeerRejectedCredentials`: those are properties of the two peers'
//! CONFIGURATION, so retry number two fails exactly like retry number one.
//! A permanent cause therefore opens a window on the FIRST failure. Both
//! thresholds are pinned below, because collapsing them in either direction
//! is a plausible-looking simplification: one threshold for everything either
//! restores the silent retry storm (if 3) or backs off on a single blip
//! (if 1).

use std::time::{Duration, Instant};

use wiremesh_gateway::relay_connect_backoff::{
    is_permanent, LogDecision, RelayConnectBackoff, RelayConnectDecision, BACKOFF_BASE,
    BACKOFF_CAP, FAILURE_THRESHOLD, PERMANENT_FAILURE_THRESHOLD,
};
use wiremesh_relay::RelayConnectFailure;

/// The driver's real loop for one attempt that fails: consult `decide`, then
/// report the outcome. Tests use this rather than calling `record_failure`
/// directly so they exercise the sequence `ensure_relay_transport` actually
/// performs — a `record_failure` that the driver would never have reached
/// (because `decide` said `Skip`) proves nothing about the shipped behaviour.
fn attempt_and_fail(
    b: &mut RelayConnectBackoff,
    now: Instant,
    cause: RelayConnectFailure,
) -> (RelayConnectDecision, Option<LogDecision>) {
    match b.decide(now) {
        RelayConnectDecision::Allow => {
            let log = b.record_failure(now, cause);
            (RelayConnectDecision::Allow, Some(log))
        }
        skip => (skip, None),
    }
}

/// The length of the currently-open window, measured from `now`.
fn window_len(b: &RelayConnectBackoff, now: Instant) -> Duration {
    b.backoff_until().expect("a window must be open") - now
}

// --- thresholds -------------------------------------------------------------

#[test]
fn transient_failures_back_off_only_at_the_threshold() {
    let t0 = Instant::now();
    let mut b = RelayConnectBackoff::new(1);

    for i in 1..FAILURE_THRESHOLD {
        let now = t0 + Duration::from_secs(i as u64);
        attempt_and_fail(&mut b, now, RelayConnectFailure::Unreachable);
        assert_eq!(
            b.decide(now),
            RelayConnectDecision::Allow,
            "transient failure {i} of {FAILURE_THRESHOLD} must NOT back off yet: a relay can be \
             momentarily unreachable, and backing off on the first blip would slow real \
             re-pathing for nothing (the `punch_backoff` rationale, which DOES apply to \
             Unreachable/Other)"
        );
        assert_eq!(b.backoff_until(), None);
    }

    let now = t0 + Duration::from_secs(FAILURE_THRESHOLD as u64);
    attempt_and_fail(&mut b, now, RelayConnectFailure::Unreachable);
    assert!(
        matches!(b.decide(now), RelayConnectDecision::Skip { .. }),
        "the {FAILURE_THRESHOLD}th consecutive transient failure must open a window"
    );
}

#[test]
fn a_permanent_cause_backs_off_on_the_very_first_failure() {
    for cause in [
        RelayConnectFailure::AlpnMismatch,
        RelayConnectFailure::PeerRejectedCredentials(44),
    ] {
        let t0 = Instant::now();
        let mut b = RelayConnectBackoff::new(7);

        attempt_and_fail(&mut b, t0, cause);

        assert!(
            matches!(b.decide(t0), RelayConnectDecision::Skip { .. }),
            "{cause:?} is a property of the two peers' CONFIGURATION — retry number two fails \
             exactly like retry number one. Waiting {FAILURE_THRESHOLD} failures before backing \
             off would reproduce the silent, indefinitely repeating per-tick retry that D2 \
             exists to kill. Threshold for a permanent cause is \
             {PERMANENT_FAILURE_THRESHOLD}."
        );
    }
}

#[test]
fn is_permanent_classifies_by_variant_never_by_the_alert_payload() {
    assert!(is_permanent(RelayConnectFailure::AlpnMismatch));
    // WHICH TLS alert arrives depends on the cause and on the rustls version
    // (the variant's own doc says: match the VARIANT, not the payload). Every
    // alert value must classify identically, or a rustls upgrade silently
    // reclassifies a permanent failure as transient and restores the retry
    // storm for the one case — revoked credentials — where it is most costly.
    for alert in [0u8, 42, 44, 48, 49, 116, 255] {
        assert!(
            is_permanent(RelayConnectFailure::PeerRejectedCredentials(alert)),
            "PeerRejectedCredentials({alert}) must be permanent regardless of the alert byte"
        );
    }
    assert!(!is_permanent(RelayConnectFailure::Unreachable));
    assert!(
        !is_permanent(RelayConnectFailure::Other),
        "`Other` is reachable-and-not-a-dead-end (the relay's own application-level \
         registration rejections land here AFTER a successful TLS handshake), so it must stay \
         transient — classifying it permanent would back off a recoverable id collision for \
         five minutes"
    );
}

// --- window growth, cap, jitter --------------------------------------------

#[test]
fn the_first_window_is_the_base_lengthened_only_by_jitter() {
    let t0 = Instant::now();
    let mut b = RelayConnectBackoff::new(12345);
    for i in 0..FAILURE_THRESHOLD {
        let now = t0 + Duration::from_secs(i as u64);
        attempt_and_fail(&mut b, now, RelayConnectFailure::Unreachable);
    }
    let now = t0 + Duration::from_secs((FAILURE_THRESHOLD - 1) as u64);
    let len = window_len(&b, now);

    assert!(
        len >= BACKOFF_BASE,
        "jitter must only ever LENGTHEN a window (drawn from [0.0, 0.5)); a window shorter than \
         the base would retry sooner than the policy allows. got {len:?}"
    );
    assert!(
        len < BACKOFF_BASE.mul_f64(1.5),
        "jitter is bounded at +50%: an unbounded draw would make the back-off unpredictable and \
         the cap meaningless. got {len:?}"
    );
}

#[test]
fn windows_grow_until_the_cap_and_never_exceed_it() {
    let t0 = Instant::now();
    let mut b = RelayConnectBackoff::new(99);
    let mut now = t0;
    let mut prev: Option<Duration> = None;
    let mut reached_cap = false;

    // Far more rounds than the exponent can usefully grow: this also pins that
    // the saturating shift and `mul_f64` never overflow or panic.
    for round in 0..40 {
        let (decision, _) = attempt_and_fail(&mut b, now, RelayConnectFailure::Unreachable);
        assert_eq!(
            decision,
            RelayConnectDecision::Allow,
            "round {round}: the driver only records a failure for an attempt `decide` allowed"
        );
        if let Some(until) = b.backoff_until() {
            let len = until - now;
            assert!(
                len <= BACKOFF_CAP,
                "round {round}: window {len:?} exceeds the cap {BACKOFF_CAP:?}. The cap is what \
                 guarantees a permanently-unusable relay keeps being retried — just slowly — so \
                 a config error that someone FIXES recovers on its own instead of needing a \
                 gateway restart."
            );
            if len >= BACKOFF_CAP.mul_f64(0.99) {
                reached_cap = true;
            }
            if let Some(p) = prev {
                if !reached_cap {
                    assert!(
                        len > p,
                        "round {round}: windows must grow while below the cap (raw doubles, and \
                         2x beats the +50% jitter ceiling, so growth is strict): {p:?} -> {len:?}"
                    );
                }
            }
            prev = Some(len);
            // Expire the window so the next round is the half-open retry.
            now = until + Duration::from_secs(1);
        } else {
            now += Duration::from_secs(1);
        }
    }
    assert!(
        reached_cap,
        "40 consecutive failures must have reached the cap; if not, the exponent is not growing \
         and the cap is untested"
    );
}

// --- liveness: never starved -----------------------------------------------

#[test]
fn an_expired_window_allows_again_so_a_pair_is_never_starved_forever() {
    let t0 = Instant::now();
    let mut b = RelayConnectBackoff::new(3);
    attempt_and_fail(&mut b, t0, RelayConnectFailure::AlpnMismatch);
    let until = b
        .backoff_until()
        .expect("permanent cause opens a window immediately");

    assert!(matches!(
        b.decide(until - Duration::from_millis(1)),
        RelayConnectDecision::Skip { .. }
    ));
    assert_eq!(
        b.decide(until),
        RelayConnectDecision::Allow,
        "at `now >= until` the pair must be allowed to try again. This is the LIVENESS half of \
         D2 and it is why the cap exists: a peer reachable ONLY via relay must never be starved \
         permanently by a back-off, or a fixed config error would still need a gateway restart \
         to recover."
    );
}

#[test]
fn an_expired_window_is_half_open_the_failure_counter_survives() {
    let t0 = Instant::now();
    let mut b = RelayConnectBackoff::new(5);
    for i in 0..FAILURE_THRESHOLD {
        attempt_and_fail(
            &mut b,
            t0 + Duration::from_secs(i as u64),
            RelayConnectFailure::Unreachable,
        );
    }
    let first_until = b.backoff_until().unwrap();
    let first_len = first_until - (t0 + Duration::from_secs((FAILURE_THRESHOLD - 1) as u64));

    // The window expires; the driver retries once (half-open) and fails again.
    let now = first_until;
    let (decision, _) = attempt_and_fail(&mut b, now, RelayConnectFailure::Unreachable);
    assert_eq!(decision, RelayConnectDecision::Allow);
    let second_len = window_len(&b, now);

    assert!(
        second_len > first_len,
        "mere EXPIRY must not reset the consecutive-failure counter — only success does. If it \
         did, a permanently-broken relay would settle into a fixed {first_len:?} retry loop \
         forever instead of decaying towards the cap, which is the retry storm again with a \
         longer period. {first_len:?} -> {second_len:?}"
    );
}

#[test]
fn deciding_inside_a_window_never_extends_or_re_rolls_it() {
    let t0 = Instant::now();
    let mut b = RelayConnectBackoff::new(77);
    attempt_and_fail(&mut b, t0, RelayConnectFailure::AlpnMismatch);
    let until = b.backoff_until().unwrap();

    for i in 1..10 {
        let now = t0 + Duration::from_secs(i);
        assert_eq!(
            b.decide(now),
            RelayConnectDecision::Skip { until },
            "every decide inside the window must return the SAME `until`; a decide that re-rolled \
             jitter or pushed the deadline out would let a busy tick loop starve the pair \
             indefinitely — the window would never arrive"
        );
    }
}

// --- success resets ---------------------------------------------------------

#[test]
fn record_success_clears_the_window_and_restarts_the_count() {
    let t0 = Instant::now();
    let mut b = RelayConnectBackoff::new(11);
    attempt_and_fail(&mut b, t0, RelayConnectFailure::AlpnMismatch);
    assert!(b.backoff_until().is_some());

    b.record_success();

    assert_eq!(
        b.backoff_until(),
        None,
        "a success proves the relay is usable RIGHT NOW"
    );
    assert_eq!(b.decide(t0), RelayConnectDecision::Allow);

    // ... and the counter restarted: one transient failure must not re-open a
    // window, or the pair would carry its history across a proven-good connect.
    attempt_and_fail(&mut b, t0, RelayConnectFailure::Unreachable);
    assert_eq!(
        b.backoff_until(),
        None,
        "after a success the transient count restarts from zero, so failure 1 of \
         {FAILURE_THRESHOLD} must not back off"
    );
}

// --- log rate limiting ------------------------------------------------------

#[test]
fn the_first_failure_logs_and_an_identical_repeat_is_suppressed() {
    let t0 = Instant::now();
    let mut b = RelayConnectBackoff::new(21);

    let (_, log1) = attempt_and_fail(&mut b, t0, RelayConnectFailure::Unreachable);
    assert_eq!(
        log1,
        Some(LogDecision::Log),
        "the FIRST failure always logs — an operator must be able to see the cause at all; the \
         requirement is 'not silenced, not once-per-tick'"
    );

    let (_, log2) = attempt_and_fail(
        &mut b,
        t0 + Duration::from_secs(1),
        RelayConnectFailure::Unreachable,
    );
    assert_eq!(
        log2,
        Some(LogDecision::Suppress),
        "an identical repeated cause below the threshold must be suppressed — this is the \
         one-indistinguishable-line-per-attempt shape D2 exists to kill"
    );
}

#[test]
fn a_change_of_cause_always_logs() {
    let t0 = Instant::now();
    let mut b = RelayConnectBackoff::new(31);
    attempt_and_fail(&mut b, t0, RelayConnectFailure::Unreachable);
    attempt_and_fail(
        &mut b,
        t0 + Duration::from_secs(1),
        RelayConnectFailure::Unreachable,
    );

    let (_, log) = attempt_and_fail(
        &mut b,
        t0 + Duration::from_secs(2),
        RelayConnectFailure::Other,
    );
    assert_eq!(
        log,
        Some(LogDecision::Log),
        "a CHANGE of classified cause is new information an operator needs — a relay that goes \
         from unreachable to cert-rejecting is a different problem with a different fix, and \
         suppressing it would hide the transition inside an otherwise-quiet window"
    );
}

#[test]
fn opening_a_window_logs_even_for_an_unchanged_cause() {
    let t0 = Instant::now();
    let mut b = RelayConnectBackoff::new(41);
    let mut last = None;
    for i in 0..FAILURE_THRESHOLD {
        let (_, log) = attempt_and_fail(
            &mut b,
            t0 + Duration::from_secs(i as u64),
            RelayConnectFailure::Unreachable,
        );
        last = log;
    }
    assert_eq!(
        last,
        Some(LogDecision::Log),
        "entering back-off is a state change and must be visible: it is the moment the gateway \
         STOPS trying this relay for a while, which is exactly what an operator debugging a \
         relay-only peer needs to see. Suppressing it would make the pair go quiet with no \
         explanation."
    );
}

// --- determinism and decorrelation -----------------------------------------

#[test]
fn the_same_seed_replays_identical_windows() {
    let t0 = Instant::now();
    let run = |seed: u64| {
        let mut b = RelayConnectBackoff::new(seed);
        attempt_and_fail(&mut b, t0, RelayConnectFailure::AlpnMismatch);
        b.backoff_until().unwrap() - t0
    };
    assert_eq!(
        run(2024),
        run(2024),
        "jitter randomness is INJECTED via the constructor seed precisely so that replaying the \
         same event sequence yields identical windows; a test that could not replay a window \
         could not pin the cap or the growth either"
    );
}

#[test]
fn distinct_pairs_draw_distinct_jitter() {
    let t0 = Instant::now();
    let lens: Vec<Duration> = (0..8)
        .map(|seed| {
            let mut b = RelayConnectBackoff::new(seed);
            attempt_and_fail(&mut b, t0, RelayConnectFailure::AlpnMismatch);
            b.backoff_until().unwrap() - t0
        })
        .collect();

    assert!(
        lens.iter().any(|l| *l != lens[0]),
        "jitter exists to DECORRELATE distinct (peer, relay) pairs so their backed-off retries \
         do not re-synchronise into a thundering herd against one relay. Seeds 0..8 all drawing \
         the same window means the seed is not reaching the draw. got {lens:?}"
    );
}
