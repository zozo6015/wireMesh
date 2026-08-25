//! Endpoint-driven hole punch (puncher-socket-isolation productionization —
//! plan `docs/superpowers/plans/2026-07-29-puncher-socket-productionization.md`,
//! design `docs/superpowers/specs/2026-07-28-puncher-socket-isolation-design.md`,
//! spike verdict **GO-WITH-NUDGE 4/4**).
//!
//! ## What changed and why
//!
//! The Cycle-4b puncher opened a transient `SO_REUSEPORT` UDP socket on the
//! SAME port boringtun's WireGuard listener uses (`:51820`) and blasted
//! `PING`/`PONG` to confirm a NAT mapping. `SO_REUSEPORT` makes the kernel hash
//! *inbound* datagrams across every socket in the group, so a peer's WireGuard
//! handshake could be delivered to the punch socket and dropped instead of
//! reaching boringtun. Held open near-continuously under a permanently
//! un-punchable peer's retries, it starved established peers' sessions
//! (handshake→0, rx frozen) — the confirmed §3 "punch-socket starvation" on the
//! production zolab/FI/px mesh, where NO pair achieved a direct path.
//!
//! This module DELETES that separate socket. The punch's only job was to send
//! an outbound datagram from `:51820` toward a peer candidate to open the NAT
//! mapping — and boringtun ALREADY does exactly that when given a peer endpoint
//! and no live session: it emits a handshake initiation from `:51820`. So the
//! productionized punch is **boringtun's own handshake traffic**, driven by:
//!
//!  1. [`nudge_target`] + [`NudgeSink`]/[`nudge_peer`] — the prompt-init NUDGE.
//!     boringtun 0.6.0 only initiates on its persistent-keepalive tick (~26s at
//!     keepalive=25); setting the peer endpoint via UAPI does NOT trigger an
//!     immediate init (spike finding 1). So right after setting the endpoint we
//!     write ONE packet toward the peer's OVERLAY IP (a routable host inside the
//!     peer's allowed-ips): the kernel routes it through `wg0`, boringtun sees
//!     "data to send, no session", and initiates the handshake NOW. This is the
//!     standard WireGuard "ping to trigger a handshake" technique — it uses the
//!     tun, never a competing UDP socket on the WG port.
//!
//!  2. [`CandidateTrial`] — the SEQUENTIAL candidate decider. It replaces the
//!     old parallel PING blast: try one candidate at a time (set its endpoint +
//!     nudge once), wait a per-candidate window for the handshake to land
//!     (detected out of band by the T2 rx-corroborated liveness in `path.rs` /
//!     `run_path_ticks`), advance to the next on timeout, and report `Exhausted`
//!     when every candidate has been tried — the driver's cue for the existing
//!     `Relayed` fallback. Same pure/injected-`now` discipline as `path.rs`.
//!
//! The endpoint MUST be set via the make-before-break / incremental device
//! apply (v0.1.2), NEVER a boringtun in-place `update_peer` modify — that panics
//! boringtun 0.6.0 ("Modifying existing peers is not yet supported"), the second
//! load-bearing spike finding. `main.rs::set_peer_endpoint` already does this
//! (full `replace_peers` rebuild from the pinned desired state), so the driver
//! reuses it verbatim.
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

/// The OVERLAY (inner) address the prompt-init nudge is sent toward: a routable
/// host inside the peer's FIRST valid allowed-ips CIDR. Sending a packet here
/// makes the kernel route it through `wg0` (the peer's allowed-ips are routed to
/// the tun), so boringtun maps it to this peer by longest-prefix match and, with
/// no live session, initiates the WG handshake immediately (spike finding 1).
///
/// Derived from the peer's OVERLAY allowed-ips, NEVER from the underlay
/// candidate `ip:port` — the nudge is an inner packet; the punch it triggers is
/// boringtun's own outbound handshake init from the WG socket.
///
/// - For a subnet CIDR (`/1`..`/31`) it is the first host, `network | 1`
///   (conventionally the peer gateway's own segment address).
/// - For a `/32` host route it is the address itself — there is no lower host.
/// - A `/0` CIDR is SKIPPED (a default route toward `0.0.0.1` is never a real
///   overlay peer target; no gateway advertises `0.0.0.0/0` as its allowed-ips).
/// - Malformed leading entries are skipped in favor of the first VALID CIDR;
///   an empty or all-malformed list yields `None` (nothing to nudge toward).
pub fn nudge_target(allowed_ips: &[String]) -> Option<Ipv4Addr> {
    for cidr in allowed_ips {
        let Some((ip, prefix)) = cidr.split_once('/') else {
            continue;
        };
        let Ok(addr) = ip.parse::<Ipv4Addr>() else {
            continue;
        };
        let Ok(prefix) = prefix.parse::<u32>() else {
            continue;
        };
        if prefix > 32 {
            continue;
        }
        // Skip a `/0` default route (NIT-8): its first host is `0.0.0.1`, never
        // a real overlay peer — no gateway advertises `0.0.0.0/0`.
        if prefix == 0 {
            continue;
        }
        // First VALID CIDR wins.
        if prefix == 32 {
            // Host route: the address itself is the (only) host.
            return Some(addr);
        }
        let base = u32::from(addr);
        let mask = u32::MAX << (32 - prefix);
        let network = base & mask;
        return Some(Ipv4Addr::from(network.wrapping_add(1)));
    }
    None
}

/// The injected tun-writer seam for the prompt-init nudge. A real nudge is a
/// packet written toward the tun (not unit-observable), so the emission is
/// abstracted behind this trait: production supplies a sink that sends ONE
/// datagram from an EPHEMERAL UDP socket (NOT the WG listen port, NOT
/// `SO_REUSEPORT`) toward `overlay_ip`; tests supply a recording mock. The whole
/// punch path can then be exercised with a mock sink and ZERO real sockets —
/// the unit-level evidence that the reuseport punch socket is gone.
pub trait NudgeSink {
    /// Emit exactly one nudge packet toward `overlay_ip`. Errors propagate to
    /// the caller (the driver logs and lets the path SM retry).
    fn nudge(&self, overlay_ip: Ipv4Addr) -> anyhow::Result<()>;
}

/// Derive the peer's overlay nudge target from `allowed_ips` and, if there is
/// one, emit EXACTLY ONE nudge through `sink` (returns `Ok(true)`). With no
/// usable target the sink is never touched (returns `Ok(false)`). A sink error
/// propagates after the single attempt — the nudge is never retried in a loop
/// (the anti-spam guarantee: one nudge per endpoint-set).
pub fn nudge_peer<N: NudgeSink>(sink: &N, allowed_ips: &[String]) -> anyhow::Result<bool> {
    match nudge_target(allowed_ips) {
        Some(target) => {
            sink.nudge(target)?;
            Ok(true)
        }
        None => Ok(false),
    }
}

/// One step the [`CandidateTrial`] asks the driver to take. Pure data — this
/// module never touches sockets or UAPI itself.
#[derive(Debug, PartialEq)]
pub enum TrialStep {
    /// Set this candidate as the peer's WG endpoint and nudge boringtun ONCE.
    /// Emitted exactly once per candidate (never spammed).
    Punch(SocketAddr),
    /// The current candidate's window is still open — keep waiting for the
    /// handshake to land; do NOT re-punch.
    Waiting,
    /// Every dialable candidate has been tried without a handshake. Idempotent
    /// terminal state: the driver falls back to the existing `Relayed` path.
    Exhausted,
}

/// Pure, sequential candidate-trial decider (design §Flow step 4, T3), in the
/// `path.rs` style: injected `now: Instant`, no sockets, no clocks. It hands the
/// driver one candidate at a time — `Punch(addr)` EXACTLY ONCE per candidate,
/// `Waiting` while that candidate's per-candidate window is still open, and
/// `Exhausted` once the last candidate's window elapses with no handshake.
///
/// Success is NOT observed here: a completed WG handshake is detected out of
/// band by the T2 rx-corroborated liveness in `run_path_ticks` (the driver
/// stops polling the trial the moment the peer's path reaches `Direct`). This
/// type only sequences the WHICH-candidate-and-WHEN decision.
#[derive(Debug, Clone, PartialEq)]
pub struct CandidateTrial {
    /// Dialable candidates only (unspecified/loopback/malformed filtered out up
    /// front — the same guard the removed `punch_candidates` applied).
    candidates: Vec<SocketAddr>,
    /// Index of the candidate currently being tried.
    idx: usize,
    /// Whether the current candidate has already been emitted as `Punch`.
    punched_current: bool,
    /// When the current candidate's window began — the instant it was actually
    /// punched (the `now` of the `poll` that returned its `Punch`), NOT `new`'s
    /// `now`. Seeded to `new`'s `now` only as a placeholder; the FIRST `Punch`
    /// overwrites it so candidate 0 gets its full `per_candidate_timeout` window
    /// even when the first `poll` lands after construction (MAJOR-4).
    current_started: Instant,
    /// Terminal flag: set once every candidate has been tried (or there were
    /// no dialable candidates to begin with).
    exhausted: bool,
}

impl CandidateTrial {
    /// Build a trial over `candidates` as of `now`. Undialable candidates
    /// (unspecified `0.0.0.0`, loopback, or unparseable) are dropped up front,
    /// exactly like the removed `punch_candidates`; a trial with no dialable
    /// candidates is immediately `Exhausted` (the driver goes straight to the
    /// `Relayed` fallback).
    pub fn new(candidates: &[String], now: Instant) -> Self {
        let candidates: Vec<SocketAddr> = candidates
            .iter()
            .filter_map(|c| c.parse::<SocketAddr>().ok())
            // v1 is IPv4-only end to end (spec §1; `uapi::validate_ipv4_endpoint`
            // rejects a non-IPv4 endpoint at the wire). Drop any IPv6 candidate
            // here too so a punch can NEVER target an IPv6 address (MAJOR-5),
            // alongside the unspecified/loopback exclusions.
            .filter(|addr| {
                addr.is_ipv4() && !addr.ip().is_unspecified() && !addr.ip().is_loopback()
            })
            .collect();
        let exhausted = candidates.is_empty();
        CandidateTrial {
            candidates,
            idx: 0,
            punched_current: false,
            current_started: now,
            exhausted,
        }
    }

    /// Advance the trial. Returns `Punch(addr)` the first time each candidate is
    /// presented (and again immediately when advancing to the next candidate),
    /// `Waiting` inside a candidate's `per_candidate_timeout` window, and
    /// `Exhausted` once the last candidate's window elapses. Idempotent once
    /// `Exhausted`.
    pub fn poll(&mut self, now: Instant, per_candidate_timeout: Duration) -> TrialStep {
        if self.exhausted {
            return TrialStep::Exhausted;
        }
        // First presentation of the current candidate: punch it once. Begin
        // its timeout window HERE (MAJOR-4) — at the instant the `Punch` is
        // actually returned — not in `new`, so candidate 0 gets the full
        // `per_candidate_timeout` even if this first `poll` runs after `new`.
        if !self.punched_current {
            self.punched_current = true;
            self.current_started = now;
            return TrialStep::Punch(self.candidates[self.idx]);
        }
        // Current candidate already punched — is its window still open?
        if now.saturating_duration_since(self.current_started) < per_candidate_timeout {
            return TrialStep::Waiting;
        }
        // Window elapsed with no handshake: advance to the next candidate.
        self.idx += 1;
        if self.idx >= self.candidates.len() {
            self.exhausted = true;
            return TrialStep::Exhausted;
        }
        self.current_started = now;
        // `punched_current` stays true — punch the new candidate now.
        TrialStep::Punch(self.candidates[self.idx])
    }

    /// Whether every dialable candidate has been tried without a handshake.
    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }
}
