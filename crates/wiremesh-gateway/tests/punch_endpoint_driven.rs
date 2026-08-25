//! Puncher-socket-isolation productionization — UNIT pins for T1/T2/T3 (plan
//! `docs/superpowers/plans/2026-07-29-puncher-socket-productionization.md`;
//! design `docs/superpowers/specs/2026-07-28-puncher-socket-isolation-design.md`,
//! spike verdict **GO-WITH-NUDGE 4/4**).
//!
//! TDD: this file is authored AHEAD of the implementation and is EXPECTED to
//! FAIL TO COMPILE until the new endpoint-driven-punch surface lands in
//! `wiremesh_gateway::punch`. It pins the pure/observable behavior of approach
//! B — boringtun-endpoint-driven punching with a prompt-init NUDGE and NO
//! separate `SO_REUSEPORT` punch socket — following the same "author the test
//! against the smallest natural extension of the module surface, then let the
//! implementer build it" discipline as `path_rx_liveness.rs`.
//!
//! ## The seams this file SPECIFIES for the implementer
//!
//! The old reuseport puncher (`punch::punch_candidates`, which bound the WG
//! listen port with `observe::reuseport_udp` and blasted PING/PONG) is being
//! DELETED (design §Scope). It is replaced by three small, pure/injected
//! surfaces on `wiremesh_gateway::punch`, all pinned below:
//!
//!  1. `pub fn nudge_target(allowed_ips: &[String]) -> Option<Ipv4Addr>` —
//!     PURE. The overlay (inner) address the prompt-init nudge is sent toward:
//!     a routable host inside the peer's first valid allowed-ips CIDR, so the
//!     kernel routes the nudge packet through `wg0` and boringtun (seeing
//!     "data to send, no session") initiates a handshake immediately rather
//!     than waiting for its ~26s persistent-keepalive tick (spike finding 1).
//!     NOTE this is derived from the peer's OVERLAY allowed-ips, never from the
//!     underlay candidate `ip:port` — the nudge is an inner packet, the punch
//!     it triggers is boringtun's own outbound handshake init.
//!
//!  2. `pub trait NudgeSink { fn nudge(&self, overlay_ip: Ipv4Addr) -> anyhow::Result<()>; }`
//!     plus `pub fn nudge_peer<N: NudgeSink>(sink: &N, allowed_ips: &[String])
//!     -> anyhow::Result<bool>` — the injected tun-writer SEAM. `nudge_peer`
//!     computes `nudge_target` and, when there is one, emits EXACTLY ONE nudge
//!     through the sink (returns `Ok(true)`); with no usable target it emits
//!     none (`Ok(false)`). The nudge-observability problem (a real nudge is a
//!     packet written toward the tun, not unit-observable) is resolved by this
//!     trait: production supplies a `NudgeSink` that sends ONE datagram from an
//!     EPHEMERAL UDP socket (NOT the WG listen port, NOT `SO_REUSEPORT`) toward
//!     `overlay_ip`; tests supply a recording mock. That the entire punch path
//!     can be exercised here with a mock sink and ZERO real sockets is the
//!     unit-level evidence that the reuseport punch socket is gone (T1).
//!
//!  3. `pub struct CandidateTrial` + `pub enum TrialStep { Punch(SocketAddr),
//!     Waiting, Exhausted }` — the PURE sequential candidate-trial decider
//!     (T3), in the `path.rs` style (injected `now: Instant`, no sockets, no
//!     clocks). `poll(now, per_candidate_timeout)` yields `Punch(addr)` EXACTLY
//!     ONCE per candidate (the driver's cue to set the endpoint + nudge once —
//!     never spammed), `Waiting` while the current candidate's window is still
//!     open, and `Exhausted` when every candidate has been tried without a
//!     handshake (the driver then falls back to the existing `Relayed` path).
//!
//! ## What the implementer still wires (NOT pinned here — netns validates it)
//!
//! - Removing `punch::punch_candidates` / its `observe::reuseport_udp` use and
//!   the `#[cfg(test)]` + `punch_netns.rs` tests that call it.
//! - Driving `CandidateTrial` + `set_peer_endpoint` (make-before-break /
//!   incremental apply — NEVER a boringtun in-place `update_peer` modify, spike
//!   finding 2) + `nudge_peer` from `run_path_ticks`, still gated by
//!   `PunchBackoff` (unchanged — it bounds how often a trial may start).
//! - T4: un-`#[ignore]`ing the two `convergence_matrix.rs` done-bar tests
//!   (`t8_convergence_incident_lifecycle`, line ~1216; and
//!   `t8_keepalive_holds_path_state_under_punch_contention`, line ~1308), which
//!   are expected to PASS once no puncher socket steals established sessions.
//!   Left to the implementer + the dedicated netns runner (they are
//!   `#![cfg(feature = "netns-tests")]`, long-running, and only green post-impl).
//!
//! Run (plain, no netns feature needed):
//!   ./dev.sh run "cargo test -p wiremesh-gateway --test punch_endpoint_driven"

use std::cell::RefCell;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use wiremesh_gateway::punch::{nudge_peer, nudge_target, CandidateTrial, NudgeSink, TrialStep};

// --- T1/T2: the prompt-init NUDGE (endpoint-driven, tun, once) ---------------

/// A `NudgeSink` that records every overlay IP it was asked to nudge — the
/// injected tun-writer stand-in. Interior mutability via `RefCell` because
/// `NudgeSink::nudge` takes `&self` (the real impl holds a socket) and these
/// tests are single-threaded.
struct RecordingSink {
    calls: RefCell<Vec<Ipv4Addr>>,
    fail: bool,
}

impl RecordingSink {
    fn new() -> Self {
        RecordingSink {
            calls: RefCell::new(Vec::new()),
            fail: false,
        }
    }
    fn failing() -> Self {
        RecordingSink {
            calls: RefCell::new(Vec::new()),
            fail: true,
        }
    }
    fn calls(&self) -> Vec<Ipv4Addr> {
        self.calls.borrow().clone()
    }
}

impl NudgeSink for RecordingSink {
    fn nudge(&self, overlay_ip: Ipv4Addr) -> anyhow::Result<()> {
        self.calls.borrow_mut().push(overlay_ip);
        if self.fail {
            anyhow::bail!("simulated tun-write failure");
        }
        Ok(())
    }
}

/// The nudge target is a routable host INSIDE the peer's first allowed-ips
/// CIDR — so the kernel routes the nudge through `wg0` and boringtun maps it to
/// this peer (longest-prefix match on allowed-ips) and initiates the handshake.
/// For a subnet CIDR that is the first host (`network | 1`).
#[test]
fn nudge_target_is_first_host_in_the_first_subnet_cidr() {
    assert_eq!(
        nudge_target(&["10.10.2.0/24".to_string()]),
        Some(Ipv4Addr::new(10, 10, 2, 1)),
        "a /24 peer CIDR nudges toward its first host .1"
    );
    assert_eq!(
        nudge_target(&["10.0.0.0/8".to_string()]),
        Some(Ipv4Addr::new(10, 0, 0, 1)),
        "the host part is masked from the network, +1"
    );
    assert_eq!(
        nudge_target(&["10.10.9.0/24".to_string()]),
        Some(Ipv4Addr::new(10, 10, 9, 1)),
    );
}

/// A `/32` host-route allowed-ip (a single peer address) nudges toward that
/// exact address — there is no "network + 1" host below it.
#[test]
fn nudge_target_host_route_uses_the_address_itself() {
    assert_eq!(
        nudge_target(&["10.10.2.5/32".to_string()]),
        Some(Ipv4Addr::new(10, 10, 2, 5)),
    );
}

/// No usable CIDR → no target (the driver then has nothing to nudge toward and
/// `nudge_peer` is a no-op). Malformed leading entries are skipped in favor of
/// the first valid CIDR.
#[test]
fn nudge_target_skips_malformed_and_is_none_without_a_cidr() {
    assert_eq!(nudge_target(&[]), None, "empty allowed-ips → no target");
    assert_eq!(
        nudge_target(&["not-a-cidr".to_string()]),
        None,
        "a single malformed entry yields no target"
    );
    assert_eq!(
        nudge_target(&["garbage".to_string(), "10.10.9.0/24".to_string()]),
        Some(Ipv4Addr::new(10, 10, 9, 1)),
        "the first VALID CIDR is used when earlier entries are malformed"
    );
    // NIT-8: a `/0` default route is skipped (its first host `0.0.0.1` is never
    // a real overlay peer), in favor of the next valid CIDR — or None if it's
    // the only entry.
    assert_eq!(
        nudge_target(&["0.0.0.0/0".to_string()]),
        None,
        "a lone /0 yields no target"
    );
    assert_eq!(
        nudge_target(&["0.0.0.0/0".to_string(), "10.10.9.0/24".to_string()]),
        Some(Ipv4Addr::new(10, 10, 9, 1)),
        "a leading /0 is skipped in favor of the next real CIDR"
    );
}

/// The core T2 pin: `nudge_peer` emits EXACTLY ONE nudge, through the injected
/// sink (the tun-writer seam — never a UDP socket on the WG port), toward the
/// derived overlay target. "Exactly one" is the anti-spam guarantee (spike:
/// the nudge fires once per endpoint-set, not on a loop). That this runs with a
/// mock sink and touches NO real socket is the unit-level proof the reuseport
/// punch socket is gone from the punch path (T1).
#[test]
fn nudge_peer_emits_exactly_one_nudge_to_the_overlay_target() {
    let sink = RecordingSink::new();
    let emitted = nudge_peer(&sink, &["10.10.2.0/24".to_string()]).expect("nudge ok");
    assert!(emitted, "a usable target must produce a nudge");
    assert_eq!(
        sink.calls(),
        vec![Ipv4Addr::new(10, 10, 2, 1)],
        "exactly one nudge, to the first host of the peer's CIDR"
    );
}

/// With no usable overlay target, `nudge_peer` is a true no-op: it returns
/// `Ok(false)` and NEVER touches the sink (no packet, no socket).
#[test]
fn nudge_peer_without_a_target_is_a_no_op() {
    let sink = RecordingSink::new();
    let emitted = nudge_peer(&sink, &[]).expect("no-target nudge is not an error");
    assert!(!emitted, "no target → nothing emitted");
    assert!(
        sink.calls().is_empty(),
        "the sink must not be touched when there is no target"
    );
}

/// A failing tun-write surfaces as an error (the driver logs it and lets the
/// path SM retry) — and it is attempted exactly once, not retried in a loop.
#[test]
fn nudge_peer_propagates_a_sink_error_after_one_attempt() {
    let sink = RecordingSink::failing();
    let r = nudge_peer(&sink, &["10.10.2.0/24".to_string()]);
    assert!(
        r.is_err(),
        "a sink failure must propagate, not be swallowed"
    );
    assert_eq!(
        sink.calls().len(),
        1,
        "the nudge is attempted once before failing, never spammed"
    );
}

// --- T3: sequential candidate trial ------------------------------------------

const TO: Duration = Duration::from_secs(5);

fn cand(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// The heart of T3: try candidates ONE AT A TIME. `poll` yields `Punch(c0)`
/// once, then `Waiting` until the per-candidate timeout elapses with no
/// handshake, then advances to `Punch(c1)`, and so on; when the last candidate
/// times out, `Exhausted` (the driver's cue to fall back to `Relayed`). Each
/// candidate is punched EXACTLY ONCE — the design's sequential trial replacing
/// the old parallel PING blast, and the anti-spam guarantee at the trial level.
#[test]
fn trial_advances_through_candidates_one_at_a_time() {
    let t0 = Instant::now();
    let mut trial = CandidateTrial::new(
        &[
            "198.51.100.1:51820".to_string(),
            "198.51.100.2:51820".to_string(),
            "198.51.100.3:51820".to_string(),
        ],
        t0,
    );

    // First poll: punch candidate 0.
    assert_eq!(
        trial.poll(t0, TO),
        TrialStep::Punch(cand("198.51.100.1:51820"))
    );
    // Inside candidate 0's window: keep waiting — do NOT re-punch (no spam).
    assert_eq!(
        trial.poll(t0 + Duration::from_secs(1), TO),
        TrialStep::Waiting
    );
    assert_eq!(
        trial.poll(t0 + Duration::from_secs(4), TO),
        TrialStep::Waiting
    );
    // Candidate 0's window elapses with no handshake: advance to candidate 1.
    assert_eq!(
        trial.poll(t0 + Duration::from_secs(5), TO),
        TrialStep::Punch(cand("198.51.100.2:51820"))
    );
    // Candidate 1's window (relative to when it started, t0+5).
    assert_eq!(
        trial.poll(t0 + Duration::from_secs(9), TO),
        TrialStep::Waiting
    );
    assert_eq!(
        trial.poll(t0 + Duration::from_secs(10), TO),
        TrialStep::Punch(cand("198.51.100.3:51820"))
    );
    // Last candidate times out: exhausted → Relayed fallback.
    assert!(
        !trial.is_exhausted(),
        "not exhausted while candidate 2's window is open"
    );
    assert_eq!(
        trial.poll(t0 + Duration::from_secs(15), TO),
        TrialStep::Exhausted
    );
    assert!(
        trial.is_exhausted(),
        "all candidates tried without a handshake"
    );
    // Stays exhausted on further polls (idempotent terminal state).
    assert_eq!(
        trial.poll(t0 + Duration::from_secs(30), TO),
        TrialStep::Exhausted
    );
}

/// MAJOR-4 regression: candidate 0's per-candidate window must begin when its
/// `Punch` is ACTUALLY returned (the first `poll`), NOT at `CandidateTrial::new`.
/// The driver builds the trial and only polls it a moment later (after the
/// backoff/guard checks), so seeding the window in `new` would shave that gap
/// off the first candidate and let it advance/exhaust early. Here the trial is
/// built at `t0` but first polled at `t0 + 3s`; candidate 0 must still get its
/// FULL `TO` window measured from `t0 + 3s`.
#[test]
fn trial_first_candidate_gets_full_window_from_first_punch() {
    let t0 = Instant::now();
    let mut trial = CandidateTrial::new(
        &[
            "198.51.100.1:51820".to_string(),
            "198.51.100.2:51820".to_string(),
        ],
        t0,
    );

    // First poll happens 3s AFTER construction: this is when candidate 0 is
    // punched, so its window is [t0+3, t0+3+TO).
    let first_punch = t0 + Duration::from_secs(3);
    assert_eq!(
        trial.poll(first_punch, TO),
        TrialStep::Punch(cand("198.51.100.1:51820"))
    );

    // Just before the window (measured from first_punch, NOT t0) elapses:
    // still waiting on candidate 0 — a `new`-seeded window would have advanced
    // by now (t0 + 3 + 4 = t0 + 7 > t0 + TO=5).
    assert_eq!(
        trial.poll(first_punch + TO - Duration::from_secs(1), TO),
        TrialStep::Waiting
    );
    // Exactly at the full window from first_punch: advance to candidate 1.
    assert_eq!(
        trial.poll(first_punch + TO, TO),
        TrialStep::Punch(cand("198.51.100.2:51820"))
    );
}

/// MAJOR-5 regression: v1 is IPv4-only, so an IPv6 `SocketAddr` candidate must
/// be filtered out and can NEVER produce a `Punch` — a trial with only IPv6
/// candidates is immediately `Exhausted`, and a mixed list trials only the IPv4
/// ones.
#[test]
fn trial_rejects_ipv6_candidates() {
    let t0 = Instant::now();

    // IPv6-only: nothing dialable → immediately exhausted, never a Punch.
    let mut ipv6_only = CandidateTrial::new(&["[2001:db8::1]:51820".to_string()], t0);
    assert_eq!(ipv6_only.poll(t0, TO), TrialStep::Exhausted);
    assert!(
        ipv6_only.is_exhausted(),
        "an IPv6 candidate must never be punched"
    );

    // Mixed: the IPv6 entry is dropped, the IPv4 one is trialed.
    let mut mixed = CandidateTrial::new(
        &[
            "[2001:db8::2]:51820".to_string(),
            "198.51.100.9:51820".to_string(),
        ],
        t0,
    );
    assert_eq!(
        mixed.poll(t0, TO),
        TrialStep::Punch(cand("198.51.100.9:51820"))
    );
    assert_eq!(mixed.poll(t0 + TO, TO), TrialStep::Exhausted);
}

/// A single valid candidate: punched once, then exhausted after its window.
#[test]
fn trial_single_candidate_then_exhausted() {
    let t0 = Instant::now();
    let mut trial = CandidateTrial::new(&["198.51.100.7:51820".to_string()], t0);
    assert_eq!(
        trial.poll(t0, TO),
        TrialStep::Punch(cand("198.51.100.7:51820"))
    );
    assert_eq!(
        trial.poll(t0 + Duration::from_secs(4), TO),
        TrialStep::Waiting
    );
    assert_eq!(trial.poll(t0 + TO, TO), TrialStep::Exhausted);
    assert!(trial.is_exhausted());
}

/// Undialable candidates are filtered up front (same guard the removed
/// `punch_candidates` applied: unspecified `0.0.0.0`, loopback, and
/// unparseable) so a trial only ever presents dialable candidates.
#[test]
fn trial_filters_unspecified_loopback_and_malformed_candidates() {
    let t0 = Instant::now();
    let mut trial = CandidateTrial::new(
        &[
            "0.0.0.0:51820".to_string(),
            "127.0.0.1:9".to_string(),
            "garbage".to_string(),
            "198.51.100.7:51820".to_string(),
        ],
        t0,
    );
    // Only the one dialable candidate is trialed.
    assert_eq!(
        trial.poll(t0, TO),
        TrialStep::Punch(cand("198.51.100.7:51820"))
    );
    assert_eq!(trial.poll(t0 + TO, TO), TrialStep::Exhausted);
    assert!(trial.is_exhausted());
}

/// An empty (or all-invalid) candidate list is immediately exhausted — the
/// driver goes straight to the `Relayed` fallback with nothing to punch.
#[test]
fn trial_with_no_dialable_candidates_is_immediately_exhausted() {
    let t0 = Instant::now();

    let mut empty = CandidateTrial::new(&[], t0);
    assert_eq!(empty.poll(t0, TO), TrialStep::Exhausted);
    assert!(empty.is_exhausted());

    let mut all_invalid = CandidateTrial::new(&["nope".to_string(), "0.0.0.0:1".to_string()], t0);
    assert_eq!(all_invalid.poll(t0, TO), TrialStep::Exhausted);
    assert!(all_invalid.is_exhausted());
}
