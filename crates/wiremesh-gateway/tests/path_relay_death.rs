//! Path-SM unit coverage for the RELAY-DEATH action split (aether-prod-fi-01
//! incident, v0.3.0): a `Relayed` peer whose relay transport DIES must not be
//! funneled through the same `MarkRelayNeeded` action that healthy re-relay
//! escalation uses.
//!
//! ## The wedge these tests pin the fix for
//!
//! In production, gateway A was `Relayed` toward peer B; B restarted fresh
//! and punched A direct, tearing down B's relay leg. A's relay transport then
//! died (downlink recv error -> `is_healthy()` false), and A wedged in a ~40s
//! sawtooth forever: the `Relayed` arm's relay-death branch returned
//! `MarkRelayNeeded`, whose driver arm immediately reconnected a relay on a
//! fresh socket WITHOUT clearing the peer's `relay_pointed` pin (that pin is
//! only cleared by a successful direct endpoint commit or roster pruning;
//! `teardown_relay_transport` runs only on reaching `Direct`). Every
//! subsequent `Disconnected -> Connecting` + `StartPunch` cycle then
//! instantly deferred its punch trial (`punch_and_apply`'s make-before-break
//! guard: Connecting && !relay_pointed), `Connecting` timed out, the path
//! re-relayed toward a relay the peer had LEFT, the leg timed out again, and
//! the cycle repeated indefinitely — the peer could never get a clean direct
//! punch window.
//!
//! ## The pinned fix semantics
//!
//! The `Relayed` arm's relay-death branch (`tick(now, relay_available =
//! false)`) emits a NEW dedicated action — pinned here as
//! **`PathAction::RelayDied`** — instead of `MarkRelayNeeded`. The state
//! transition itself is unchanged (`Relayed -> Disconnected`), but the
//! distinct action tells the driver to (a) tear down the dead transport,
//! (b) CLEAR the peer's `relay_pointed` pin, and (c) NOT immediately
//! reconnect a relay — so the very next `Disconnected -> Connecting ->
//! StartPunch` cycle gets one clean direct-punch window. If that punch
//! fails, the EXISTING `Connecting`-timeout -> `Disconnected` +
//! `MarkRelayNeeded` ladder re-relays exactly as today, so relay-needing
//! pairs (symmetric NAT) still recover — one punch cycle slower after a
//! relay blip, by design. Every OTHER `MarkRelayNeeded` emission site is
//! asserted unchanged below.
//!
//! ## Why this lives in `tests/` rather than `src/path.rs`'s in-module tests
//!
//! This project's workflow separates test authorship from implementation
//! (CLAUDE.md agent rules): the fix's implementer owns `src/path.rs`, so
//! these tests may not be added to its in-module `mod tests`. The whole SM
//! surface they need (`Path::{new, tick, on_handshake}`, `PathState`,
//! `PathAction`, the timing constants, and the `backoff` field) is `pub` and
//! re-exported via `wiremesh_gateway::path` (the same route
//! `tests/relay_matrix.rs` already imports `PROBE_DIRECT_INTERVAL` through),
//! so an integration-test file drives it just as deterministically — same
//! injected-`now` style as the in-module tests. Precedent:
//! `tests/directive_should_punch.rs` already unit-tests one pure `path`
//! helper from `tests/`; no existing file covers the `Path` state machine's
//! own `tick`/transition surface though, and the relay-death semantics
//! deserve a focused file rather than being appended to that helper's.
//!
//! NOTE: this file is intentionally compile-RED against pre-fix code — it
//! references `PathAction::RelayDied`, which does not exist until the fix
//! lands. That is the TDD contract: the variant name and its emission site
//! are exactly what these tests pin.

use std::time::{Duration, Instant};

use wiremesh_gateway::path::{
    Path, PathAction, PathState, BACKOFF_INITIAL, CONNECT_TIMEOUT, DEGRADED_AFTER,
    DEGRADED_DEAD_AFTER, PROBE_DIRECT_INTERVAL,
};

/// Drives a fresh `Path` into `Relayed` the same way the in-module tests do:
/// let `Connecting` time out with a relay available. Returns the path and
/// the instant it entered `Relayed`.
fn relayed_path(t0: Instant) -> (Path, Instant) {
    let mut p = Path::new(t0);
    let entered = t0 + CONNECT_TIMEOUT;
    let action = p.tick(entered, true);
    assert_eq!(p.state, PathState::Relayed, "precondition: reached Relayed");
    assert_eq!(
        action,
        Some(PathAction::MarkRelayNeeded),
        "precondition: entering Relayed still emits MarkRelayNeeded (unchanged)"
    );
    (p, entered)
}

/// THE fix: a `Relayed` peer whose relay transport died (`relay_available =
/// false`) transitions to `Disconnected` exactly as before, but emits the
/// dedicated `RelayDied` action — NOT `MarkRelayNeeded` — so the driver
/// tears down the dead transport, clears `relay_pointed`, and does NOT
/// immediately re-relay (which is what re-blocked the direct punch forever
/// in the aether-prod-fi-01 wedge).
#[test]
fn relayed_relay_death_emits_relay_died_and_disconnects() {
    let t0 = Instant::now();
    let (mut p, entered) = relayed_path(t0);

    let died_at = entered + Duration::from_secs(3);
    let action = p.tick(died_at, false);
    assert_eq!(
        p.state,
        PathState::Disconnected,
        "relay death still re-paths to Disconnected (transition unchanged)"
    );
    assert_eq!(
        action,
        Some(PathAction::RelayDied),
        "relay death must emit the dedicated RelayDied action, not MarkRelayNeeded — \
         MarkRelayNeeded's driver arm reconnects a relay immediately without clearing \
         relay_pointed, which is exactly the punch-blocking wedge"
    );
}

/// After a relay death, the normal `Disconnected` backoff still leads to
/// `Connecting` + `StartPunch` — the one clean direct-punch window the fix
/// exists to grant (with `relay_pointed` cleared by the driver's `RelayDied`
/// handling, the punch guard now passes instead of deferring).
#[test]
fn relay_death_then_backoff_yields_a_start_punch_window() {
    let t0 = Instant::now();
    let (mut p, entered) = relayed_path(t0);

    let died_at = entered + Duration::from_secs(3);
    assert_eq!(p.tick(died_at, false), Some(PathAction::RelayDied));
    assert_eq!(p.state, PathState::Disconnected);

    // Before the backoff elapses: parked, no action.
    let backoff = p.backoff;
    assert_eq!(p.tick(died_at + Duration::from_millis(1), false), None);
    assert_eq!(p.state, PathState::Disconnected);

    // Backoff expiry: the clean punch window.
    let action = p.tick(died_at + backoff, false);
    assert_eq!(p.state, PathState::Connecting);
    assert_eq!(
        action,
        Some(PathAction::StartPunch),
        "the Disconnected -> Connecting cycle after a relay death must still start a \
         punch — this is the direct-recovery window the RelayDied semantics unblock"
    );
}

/// If that clean punch window fails, the EXISTING ladder re-relays exactly
/// as today: `Connecting` times out -> `Disconnected` + `MarkRelayNeeded`
/// (no relay yet), and a later `Connecting` timeout with a live relay lands
/// in `Relayed` (+ `MarkRelayNeeded`) with a fresh probe grace period. This
/// is what keeps relay-needing pairs (symmetric NAT) recovering after a
/// relay blip — one punch cycle slower, by design, but never stranded.
#[test]
fn relay_death_then_failed_punch_re_relays_via_existing_ladder() {
    let t0 = Instant::now();
    let (mut p, entered) = relayed_path(t0);

    // Death -> Disconnected -> (backoff) -> Connecting.
    let died_at = entered + Duration::from_secs(1);
    assert_eq!(p.tick(died_at, false), Some(PathAction::RelayDied));
    let backoff = p.backoff;
    let connecting_at = died_at + backoff;
    assert_eq!(p.tick(connecting_at, false), Some(PathAction::StartPunch));
    assert_eq!(p.state, PathState::Connecting);

    // The punch fails (no handshake lands). Connecting times out with no
    // relay transport re-established yet: park Disconnected AND ask the
    // driver for relay coverage — the unchanged MarkRelayNeeded ladder.
    let timeout_at = connecting_at + CONNECT_TIMEOUT;
    let action = p.tick(timeout_at, false);
    assert_eq!(p.state, PathState::Disconnected);
    assert_eq!(
        action,
        Some(PathAction::MarkRelayNeeded),
        "post-death Connecting timeout without a relay must still emit MarkRelayNeeded \
         — the re-relay ladder for relay-needing pairs is unchanged"
    );

    // Next cycle, a relay transport is live again: Connecting timeout lands
    // in Relayed + MarkRelayNeeded, unchanged.
    let backoff2 = p.backoff;
    let reconnect_at = timeout_at + backoff2;
    assert_eq!(p.tick(reconnect_at, false), Some(PathAction::StartPunch));
    let re_relayed_at = reconnect_at + CONNECT_TIMEOUT;
    let action = p.tick(re_relayed_at, true);
    assert_eq!(p.state, PathState::Relayed);
    assert_eq!(action, Some(PathAction::MarkRelayNeeded));

    // And the re-entered Relayed spell gets its own full probe grace period
    // (the death must have reset the probe gate, not inherited a stale one).
    let action = p.tick(re_relayed_at + PROBE_DIRECT_INTERVAL - Duration::from_secs(1), true);
    assert_eq!(action, None, "fresh Relayed spell must get a full undisturbed grace period");
    assert_eq!(p.state, PathState::Relayed);
}

/// UNCHANGED: the `Connecting`-timeout arm still emits `MarkRelayNeeded` in
/// BOTH its branches (relay available -> `Relayed`; none -> `Disconnected`).
/// The RelayDied split touches only the `Relayed` arm's death branch.
#[test]
fn connecting_timeout_still_marks_relay_needed_both_branches() {
    // No relay: park Disconnected, signal relay needed.
    let t0 = Instant::now();
    let mut p = Path::new(t0);
    let action = p.tick(t0 + CONNECT_TIMEOUT, false);
    assert_eq!(p.state, PathState::Disconnected);
    assert_eq!(action, Some(PathAction::MarkRelayNeeded));

    // Relay available: enter Relayed, still MarkRelayNeeded.
    let t1 = Instant::now();
    let mut p = Path::new(t1);
    let action = p.tick(t1 + CONNECT_TIMEOUT, true);
    assert_eq!(p.state, PathState::Relayed);
    assert_eq!(action, Some(PathAction::MarkRelayNeeded));
}

/// UNCHANGED: the `Degraded` arm still emits `Retry` while not-yet-dead, and
/// `MarkRelayNeeded` in BOTH dead branches (relay available -> `Relayed`;
/// none -> `Disconnected`).
#[test]
fn degraded_arms_still_retry_then_mark_relay_needed_both_branches() {
    // Dead with no relay -> Disconnected + MarkRelayNeeded.
    let t0 = Instant::now();
    let mut p = Path::new(t0);
    p.on_handshake(t0, true);
    let action = p.tick(t0 + DEGRADED_AFTER, false);
    assert_eq!(p.state, PathState::Degraded);
    assert_eq!(action, Some(PathAction::Retry));
    // Still inside the dead grace: Retry, unchanged.
    let action = p.tick(t0 + DEGRADED_AFTER + DEGRADED_DEAD_AFTER - Duration::from_secs(1), false);
    assert_eq!(p.state, PathState::Degraded);
    assert_eq!(action, Some(PathAction::Retry));
    let action = p.tick(t0 + DEGRADED_AFTER + DEGRADED_DEAD_AFTER, false);
    assert_eq!(p.state, PathState::Disconnected);
    assert_eq!(action, Some(PathAction::MarkRelayNeeded));

    // Dead with a relay -> Relayed + MarkRelayNeeded.
    let t1 = Instant::now();
    let mut p = Path::new(t1);
    p.on_handshake(t1, true);
    assert_eq!(p.tick(t1 + DEGRADED_AFTER, false), Some(PathAction::Retry));
    let action = p.tick(t1 + DEGRADED_AFTER + DEGRADED_DEAD_AFTER, true);
    assert_eq!(p.state, PathState::Relayed);
    assert_eq!(action, Some(PathAction::MarkRelayNeeded));
}

/// UNCHANGED: `Relayed` with a LIVE relay keeps today's behavior exactly —
/// a full undisturbed grace period after entry, then `ProbeDirect` at the
/// rate-limited cadence (never `RelayDied`, never `MarkRelayNeeded`, never a
/// state change).
#[test]
fn relayed_with_live_relay_unchanged_grace_then_rate_limited_probe() {
    let t0 = Instant::now();
    let (mut p, entered) = relayed_path(t0);

    // Grace period: no action, still Relayed.
    for secs in [1, 10, 19] {
        let action = p.tick(entered + Duration::from_secs(secs), true);
        assert_eq!(action, None, "no probe inside the grace period ({secs}s)");
        assert_eq!(p.state, PathState::Relayed);
    }

    // Grace elapsed: exactly one ProbeDirect, then quiet until the next
    // interval.
    let action = p.tick(entered + PROBE_DIRECT_INTERVAL, true);
    assert_eq!(action, Some(PathAction::ProbeDirect));
    assert_eq!(p.state, PathState::Relayed);
    let action = p.tick(entered + PROBE_DIRECT_INTERVAL + Duration::from_secs(1), true);
    assert_eq!(action, None);
    assert_eq!(p.state, PathState::Relayed);
}

/// A handshake completing after the death-recovery punch still resets the
/// pair's backoff (the 4c Task 8 review fix), so a later, unrelated
/// disconnect starts its retry cadence fresh — the RelayDied path must not
/// bypass `on_handshake`'s existing reset semantics.
#[test]
fn direct_recovery_after_relay_death_resets_backoff() {
    let t0 = Instant::now();
    let (mut p, entered) = relayed_path(t0);

    // Death, then one failed punch cycle to escalate backoff above initial.
    let died_at = entered + Duration::from_secs(1);
    assert_eq!(p.tick(died_at, false), Some(PathAction::RelayDied));
    let b1 = p.backoff;
    let connecting_at = died_at + b1;
    assert_eq!(p.tick(connecting_at, false), Some(PathAction::StartPunch));
    let timeout_at = connecting_at + CONNECT_TIMEOUT;
    assert_eq!(p.tick(timeout_at, false), Some(PathAction::MarkRelayNeeded));
    assert!(
        p.backoff > BACKOFF_INITIAL,
        "backoff should have escalated across the death/punch cycles, got {:?}",
        p.backoff
    );

    // The next punch window's handshake lands (rx-corroborated): Direct,
    // and the backoff resets.
    let b2 = p.backoff;
    assert_eq!(p.tick(timeout_at + b2, false), Some(PathAction::StartPunch));
    p.on_handshake(timeout_at + b2 + Duration::from_secs(2), true);
    assert_eq!(p.state, PathState::Direct);
    assert_eq!(p.backoff, BACKOFF_INITIAL);
}
