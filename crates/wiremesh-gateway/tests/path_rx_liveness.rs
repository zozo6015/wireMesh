//! T2 pin — path liveness requires rx corroboration (mesh-convergence fix
//! cycle, plan `docs/superpowers/plans/2026-07-28-mesh-convergence-fixes.md`,
//! evidence `docs/research/ops-finding-multi-gateway-convergence.md` §4:
//! boringtun's `last_handshake_time` was observed live advancing "13-70s
//! ago" with `rx_bytes=0` sustained, and gw-home's path SM reported
//! `direct` for a dead tunnel).
//!
//! TDD: this file is authored AHEAD of the implementation and is EXPECTED
//! to fail to compile until T2 lands. The current machine's handshake
//! input (`Path::on_handshake(now)`) does not carry rx evidence, so these
//! tests are written against the SMALLEST natural extension of that input:
//!
//!     pub fn on_handshake(&mut self, now: Instant, rx_corroborated: bool)
//!
//! where `rx_corroborated` is "an rx_bytes delta accompanied this
//! handshake evidence within the liveness window" — computed by the driver
//! from the same `uapi::get_peer_liveness` feed it already diffs
//! (`main.rs::run_path_ticks` keeps `last_seen` / `last_rx` maps). Target
//! semantics (plan T2):
//!
//!  - `rx_corroborated == true`  → exactly the old `on_handshake`: enter
//!    Direct from anywhere, refresh `last_handshake`/`last_inbound`,
//!    reset backoff.
//!  - `rx_corroborated == false` → NOT liveness: must not enter Direct,
//!    must not refresh `last_inbound` (so the existing silence rules —
//!    `DEGRADED_AFTER`, `DEGRADED_DEAD_AFTER` — keep running on the real
//!    last-corroborated instant), and must not defeat escalation to
//!    Disconnected/relay-needed.
//!
//! These pins are deliberately compatible with either implementation shape
//! (ignore uncorroborated advances outright, or remember them and promote
//! on a within-window rx delta): every asserted scenario has rx flat
//! throughout the window, or corroborated at the event itself.
//!
//! Notes for the implementer:
//!  - This SUPERSEDES the driver-level "first-ever handshake is trusted
//!    unconditionally" exception in `main.rs::run_path_ticks` (the long
//!    comment block there) — that exception is exactly the hole the
//!    incident drove through (gw-home claimed direct with peer rx=0 on a
//!    first session). The historical reason for the exception (a genuine
//!    first handshake's corroborating data packet could lag unboundedly,
//!    sticking `establish_direct` in Connecting in the netns nat matrix)
//!    is addressed by T1: with `persistent_keepalive_interval=25` on every
//!    peer, a real completed handshake is followed by authenticated
//!    inbound within one keepalive interval, so the driver can (and must)
//!    corroborate within the window instead of trusting the timestamp.
//!    The driver may need to remember a pending handshake advance and call
//!    `on_handshake(now, true)` when rx moves within the window — do NOT
//!    weaken the machine to make the old driver shape fit.
//!  - Existing `path.rs::tests` call the 1-arg `on_handshake(now)`; they
//!    pin genuinely-corroborated transitions and should be mechanically
//!    updated to `on_handshake(now, true)` (their asserted behavior is
//!    unchanged and re-pinned here under the new vocabulary).
//!  - `on_authenticated_inbound(now)` (rx-delta-only liveness, the
//!    keepalive case) is unchanged.

use std::time::Duration;
use std::time::Instant;

use wiremesh_gateway::path::{
    Path, PathAction, PathState, BACKOFF_INITIAL, CONNECT_TIMEOUT, DEGRADED_AFTER,
    DEGRADED_DEAD_AFTER,
};

/// T2(a): a handshake-time advance with NO rx delta is not liveness — the
/// machine must not enter Direct on it, and the Connecting timeout must
/// still fire on schedule as if the phantom evidence never happened
/// (Connecting → Disconnected with `MarkRelayNeeded`, per the existing
/// no-relay semantics).
#[test]
fn t2_uncorroborated_handshake_does_not_enter_direct() {
    let t0 = Instant::now();
    let mut p = Path::new(t0);
    assert_eq!(p.state, PathState::Connecting);

    // boringtun advances last_handshake_time, but rx_bytes stayed flat.
    p.on_handshake(t0 + Duration::from_secs(3), false);
    assert_eq!(
        p.state,
        PathState::Connecting,
        "a handshake-time advance with flat rx must NOT report Direct (finding §4)"
    );

    // Still inside the connect window: no transition.
    let action = p.tick(t0 + Duration::from_secs(9), false);
    assert_eq!(p.state, PathState::Connecting);
    assert_eq!(action, None);

    // The connect timeout fires on the ORIGINAL schedule — phantom evidence
    // must not have extended it.
    let action = p.tick(t0 + CONNECT_TIMEOUT, false);
    assert_eq!(p.state, PathState::Disconnected);
    assert_eq!(action, Some(PathAction::MarkRelayNeeded));
}

/// T2(b): a handshake WITH an rx delta is the existing, correct behavior —
/// keep it pinned under the new vocabulary: Connecting → Direct, both
/// timestamps refreshed.
#[test]
fn t2_corroborated_handshake_enters_direct() {
    let t0 = Instant::now();
    let mut p = Path::new(t0);

    let hs_at = t0 + Duration::from_secs(3);
    p.on_handshake(hs_at, true);
    assert_eq!(p.state, PathState::Direct);
    assert_eq!(p.last_handshake, Some(hs_at));
    assert_eq!(p.last_inbound, Some(hs_at));
}

/// T2(c): an established Direct path whose rx flatlines while the
/// handshake time keeps advancing (the boringtun false-advance observed
/// live in the incident) must degrade per the EXISTING silence rules
/// (`DEGRADED_AFTER` from the last corroborated inbound) — not stay Direct
/// forever because the phantom advances kept refreshing liveness.
#[test]
fn t2_direct_with_flat_rx_degrades_despite_handshake_advances() {
    let t0 = Instant::now();
    let mut p = Path::new(t0);
    p.on_handshake(t0, true);
    assert_eq!(p.state, PathState::Direct);

    // The peer's NAT mapping has silently died: rx is flat from t0 on, but
    // the local boringtun keeps advancing last_handshake_time while
    // retrying the unanswered session.
    for secs in [15u64, 30, 44] {
        p.on_handshake(t0 + Duration::from_secs(secs), false);
        let action = p.tick(t0 + Duration::from_secs(secs), false);
        assert_eq!(
            p.state,
            PathState::Direct,
            "still inside the DEGRADED_AFTER window at {secs}s — no early degrade"
        );
        assert_eq!(action, None);
    }

    // The full liveness window elapses with zero corroborated inbound:
    // the existing silence rule applies, phantom handshakes notwithstanding.
    let action = p.tick(t0 + DEGRADED_AFTER, false);
    assert_eq!(
        p.state,
        PathState::Degraded,
        "45s of flat rx must degrade even though handshake-time kept advancing"
    );
    assert_eq!(action, Some(PathAction::Retry));
}

/// T2(a)+(c): once Degraded, per-tick uncorroborated handshake advances
/// (boringtun retries a dead session every tick — the exact quirk in
/// `docs/research/cycle4b-path-liveness-note.md`) must not bounce the path
/// back to Direct, and must not defeat the `DEGRADED_DEAD_AFTER`
/// escalation to Disconnected/relay-needed. This is the failover-defeating
/// loop from the incident.
#[test]
fn t2_degraded_not_revived_by_uncorroborated_handshake_and_still_escalates() {
    let t0 = Instant::now();
    let mut p = Path::new(t0);
    p.on_handshake(t0, true);
    p.tick(t0 + DEGRADED_AFTER, false);
    assert_eq!(p.state, PathState::Degraded);
    let degraded_at = t0 + DEGRADED_AFTER;

    // Phantom advance on every driver tick while Degraded.
    for secs in 1..DEGRADED_DEAD_AFTER.as_secs() {
        let now = degraded_at + Duration::from_secs(secs);
        p.on_handshake(now, false);
        assert_eq!(
            p.state,
            PathState::Degraded,
            "an uncorroborated handshake advance at +{secs}s must not revive Degraded to Direct"
        );
        let action = p.tick(now, false);
        assert_eq!(p.state, PathState::Degraded);
        assert_eq!(action, Some(PathAction::Retry));
    }

    // Escalation still happens on schedule: the dead path reaches
    // Disconnected and asks for relay coverage instead of claiming Direct.
    let action = p.tick(degraded_at + DEGRADED_DEAD_AFTER, false);
    assert_eq!(p.state, PathState::Disconnected);
    assert_eq!(action, Some(PathAction::MarkRelayNeeded));
}

/// T2(b): genuine recovery is untouched — a corroborated handshake from
/// Degraded recovers to Direct with the full recovery semantics (backoff
/// reset included, per the 4c Task 8 review fix).
#[test]
fn t2_degraded_recovers_to_direct_on_corroborated_handshake() {
    let t0 = Instant::now();
    let mut p = Path::new(t0);
    p.on_handshake(t0, true);
    p.tick(t0 + DEGRADED_AFTER, false);
    assert_eq!(p.state, PathState::Degraded);

    let hs_at = t0 + DEGRADED_AFTER + Duration::from_secs(1);
    p.on_handshake(hs_at, true);
    assert_eq!(p.state, PathState::Direct);
    assert_eq!(p.last_handshake, Some(hs_at));
    assert_eq!(p.last_inbound, Some(hs_at));
    assert_eq!(p.backoff, BACKOFF_INITIAL);
}

/// T2(a): while Relayed, an uncorroborated handshake advance must NOT be
/// mistaken for the make-before-break Direct cutover — that would tear
/// down the only working path (the relay) on phantom evidence. Only a
/// corroborated handshake cuts over.
#[test]
fn t2_relayed_not_cut_over_by_uncorroborated_handshake() {
    let t0 = Instant::now();
    let mut p = Path::new(t0);

    // Drive into Relayed via the Connecting timeout with a relay available.
    let action = p.tick(t0 + CONNECT_TIMEOUT, true);
    assert_eq!(p.state, PathState::Relayed);
    assert_eq!(action, Some(PathAction::MarkRelayNeeded));

    p.on_handshake(t0 + CONNECT_TIMEOUT + Duration::from_secs(2), false);
    assert_eq!(
        p.state,
        PathState::Relayed,
        "phantom handshake evidence must not cut a working relay path over to Direct"
    );

    // A corroborated one is the real cutover.
    let hs_at = t0 + CONNECT_TIMEOUT + Duration::from_secs(4);
    p.on_handshake(hs_at, true);
    assert_eq!(p.state, PathState::Direct);
}
