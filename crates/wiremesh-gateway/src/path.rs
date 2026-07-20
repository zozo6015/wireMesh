//! Per-peer path state machine (spec §6.1 state diagram, master spec §6.1
//! is authoritative). Pure and unit-testable: every method takes an
//! injected `now: Instant` rather than calling `Instant::now()` internally,
//! so tests are fully deterministic. Wiring this into the gateway boot loop
//! (driving `tick`/`on_handshake` from real UAPI polling via
//! `uapi::get_latest_handshakes`) is Task 10 — this module only delivers
//! the pure machinery.
use std::time::{Duration, Instant};

/// WireGuard persistent-keepalive interval (spec §6.1): every peer sends a
/// keepalive at this cadence, so authenticated inbound traffic should never
/// naturally go quiet for longer than this while a path is healthy.
pub const KEEPALIVE: Duration = Duration::from_secs(15);

/// How long `Connecting` waits for a first WG handshake before deciding it
/// needs relay help (spec §6.1: "no handshake within 10s").
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long `Direct` tolerates no authenticated inbound before downgrading
/// to `Degraded` (spec §6.1: "no authenticated inbound for 45s").
pub const DEGRADED_AFTER: Duration = Duration::from_secs(45);

/// Additional grace `Degraded` gets, beyond `DEGRADED_AFTER`, before it's
/// considered dead and — absent a relay — drops to `Disconnected`. The
/// spec's state diagram doesn't assign this its own number, so this reuses
/// `CONNECT_TIMEOUT` for symmetry with `Connecting`'s "give up and ask for
/// relay help" grace period.
pub const DEGRADED_DEAD_AFTER: Duration = CONNECT_TIMEOUT;

/// Initial `Disconnected -> Connecting` retry backoff.
pub const BACKOFF_INITIAL: Duration = Duration::from_secs(2);

/// Backoff ceiling.
pub const BACKOFF_MAX: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PathState {
    Connecting,
    Direct,
    Degraded,
    /// Make-before-break relay path. Real relay transport lands in Cycle
    /// 4c; in 4b this state is only reachable when `tick` is called with
    /// `relay_available = true`, which the driver never does yet (no relay
    /// transport exists) — wired-but-inert stub.
    Relayed,
    Disconnected,
}

impl PathState {
    /// Lowercase label used in metrics and logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            PathState::Connecting => "connecting",
            PathState::Direct => "direct",
            PathState::Degraded => "degraded",
            PathState::Relayed => "relayed",
            PathState::Disconnected => "disconnected",
        }
    }
}

/// An action `Path::tick` asks the caller (Task 10's driver) to perform.
/// Pure data — this module never touches sockets or UAPI itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathAction {
    /// (Re-)enter `Connecting` and kick off a fresh hole-punch attempt now
    /// (fires on `Disconnected -> Connecting` backoff expiry).
    StartPunch,
    /// The convergence budget for direct is exhausted (or a live path went
    /// dead) with no relay available: the driver should ensure a relay is
    /// requested/health-checked for this peer. In Cycle 4b, since relay
    /// transport doesn't exist yet, this just leaves the peer parked in
    /// `Disconnected`.
    MarkRelayNeeded,
    /// Still waiting (degraded, not yet dead): retry whatever low-rate
    /// recovery probe is already appropriate — no fresh punch session, no
    /// relay escalation yet.
    Retry,
}

/// One peer's direct-path state. See module docs for the timers driving
/// transitions; see spec §6.1's `stateDiagram-v2` for the authoritative
/// picture this implements.
#[derive(Debug, Clone)]
pub struct Path {
    pub state: PathState,
    pub last_handshake: Option<Instant>,
    pub last_inbound: Option<Instant>,
    pub connecting_since: Instant,
    pub backoff: Duration,
    /// When the current `Degraded` spell began (drives `DEGRADED_DEAD_AFTER`).
    degraded_since: Option<Instant>,
    /// When the current `Disconnected` spell began (drives backoff timing).
    disconnected_since: Option<Instant>,
}

impl Path {
    /// A brand-new peer path starts `Connecting` as of `now`.
    pub fn new(now: Instant) -> Self {
        Path {
            state: PathState::Connecting,
            last_handshake: None,
            last_inbound: None,
            connecting_since: now,
            backoff: BACKOFF_INITIAL,
            degraded_since: None,
            disconnected_since: None,
        }
    }

    /// A completed WireGuard handshake: recovers to `Direct` from any of
    /// `Connecting`/`Degraded`/`Relayed` (spec §6.1). Also counts as
    /// authenticated inbound. A handshake while already `Direct` is a
    /// harmless no-op transition-wise, but still refreshes the timestamps.
    pub fn on_handshake(&mut self, now: Instant) {
        self.last_handshake = Some(now);
        self.last_inbound = Some(now);
        self.state = PathState::Direct;
        self.degraded_since = None;
        self.disconnected_since = None;
    }

    /// Any authenticated inbound datagram (keepalive or data) that isn't
    /// itself a new handshake — advances liveness without forcing a state
    /// change. A `Degraded` path doesn't jump back to `Direct` on a stray
    /// keepalive; only a real handshake recovery does (spec §6.1).
    pub fn on_authenticated_inbound(&mut self, now: Instant) {
        self.last_inbound = Some(now);
    }

    /// Time-driven transitions. Returns the action the driver should take,
    /// if any. `relay_available` reflects whether a healthy relay path
    /// exists for this peer right now (always `false` in Cycle 4b — no
    /// relay transport yet).
    pub fn tick(&mut self, now: Instant, relay_available: bool) -> Option<PathAction> {
        match self.state {
            PathState::Connecting => {
                if now.saturating_duration_since(self.connecting_since) >= CONNECT_TIMEOUT {
                    if relay_available {
                        self.state = PathState::Relayed;
                    } else {
                        self.state = PathState::Disconnected;
                        self.disconnected_since = Some(now);
                    }
                    Some(PathAction::MarkRelayNeeded)
                } else {
                    None
                }
            }
            PathState::Direct => {
                let last = self.last_inbound.or(self.last_handshake);
                match last {
                    Some(last) if now.saturating_duration_since(last) >= DEGRADED_AFTER => {
                        self.state = PathState::Degraded;
                        self.degraded_since = Some(now);
                        Some(PathAction::Retry)
                    }
                    _ => None,
                }
            }
            PathState::Degraded => {
                let since = self.degraded_since.unwrap_or(now);
                if now.saturating_duration_since(since) >= DEGRADED_DEAD_AFTER {
                    if relay_available {
                        self.state = PathState::Relayed;
                    } else {
                        self.state = PathState::Disconnected;
                        self.disconnected_since = Some(now);
                    }
                    Some(PathAction::MarkRelayNeeded)
                } else {
                    Some(PathAction::Retry)
                }
            }
            PathState::Relayed => {
                // Make-before-break direct re-probe and relay-unhealthy
                // re-path (spec §6.1's `Relayed` self-loops) are Cycle 4c —
                // wired-but-inert stub here.
                None
            }
            PathState::Disconnected => {
                let since = self.disconnected_since.unwrap_or(now);
                if now.saturating_duration_since(since) >= self.backoff {
                    self.state = PathState::Connecting;
                    self.connecting_since = now;
                    self.disconnected_since = None;
                    // Double the backoff for the NEXT disconnection, capped.
                    self.backoff = std::cmp::min(self.backoff * 2, BACKOFF_MAX);
                    Some(PathAction::StartPunch)
                } else {
                    None
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connecting_to_direct_on_handshake() {
        let t0 = Instant::now();
        let mut p = Path::new(t0);
        assert_eq!(p.state, PathState::Connecting);

        let hs_at = t0 + Duration::from_secs(3);
        p.on_handshake(hs_at);
        assert_eq!(p.state, PathState::Direct);
        assert_eq!(p.last_handshake, Some(hs_at));
        assert_eq!(p.last_inbound, Some(hs_at));
    }

    #[test]
    fn connecting_times_out_to_disconnected_without_relay() {
        let t0 = Instant::now();
        let mut p = Path::new(t0);

        // Not yet at the timeout: no transition, no action.
        let action = p.tick(t0 + Duration::from_secs(9), false);
        assert_eq!(p.state, PathState::Connecting);
        assert_eq!(action, None);

        // At (>=) the timeout with no relay: parks in Disconnected, and
        // still signals relay is needed (Task 10/4c wiring point).
        let action = p.tick(t0 + CONNECT_TIMEOUT, false);
        assert_eq!(p.state, PathState::Disconnected);
        assert_eq!(action, Some(PathAction::MarkRelayNeeded));
    }

    #[test]
    fn connecting_times_out_to_relayed_when_relay_available() {
        // Real relay transport is Cycle 4c, but the branch itself should
        // still be correct/inert (`relay_available` is always false in the
        // real 4b driver — this only proves the state-machine logic).
        let t0 = Instant::now();
        let mut p = Path::new(t0);
        let action = p.tick(t0 + CONNECT_TIMEOUT, true);
        assert_eq!(p.state, PathState::Relayed);
        assert_eq!(action, Some(PathAction::MarkRelayNeeded));
    }

    #[test]
    fn direct_degrades_after_no_inbound() {
        let t0 = Instant::now();
        let mut p = Path::new(t0);
        p.on_handshake(t0);
        assert_eq!(p.state, PathState::Direct);

        // Just before the threshold: still Direct.
        let action = p.tick(t0 + DEGRADED_AFTER - Duration::from_secs(1), false);
        assert_eq!(p.state, PathState::Direct);
        assert_eq!(action, None);

        // At (>=) the threshold with no inbound: degrades.
        let action = p.tick(t0 + DEGRADED_AFTER, false);
        assert_eq!(p.state, PathState::Degraded);
        assert_eq!(action, Some(PathAction::Retry));
    }

    #[test]
    fn keepalive_inbound_prevents_degrade() {
        let t0 = Instant::now();
        let mut p = Path::new(t0);
        p.on_handshake(t0);
        // A keepalive arrives inside the window, refreshing liveness.
        p.on_authenticated_inbound(t0 + KEEPALIVE);
        let action = p.tick(t0 + KEEPALIVE + DEGRADED_AFTER - Duration::from_secs(1), false);
        assert_eq!(p.state, PathState::Direct);
        assert_eq!(action, None);
    }

    #[test]
    fn degraded_recovers_to_direct_on_handshake() {
        let t0 = Instant::now();
        let mut p = Path::new(t0);
        p.on_handshake(t0);
        p.tick(t0 + DEGRADED_AFTER, false);
        assert_eq!(p.state, PathState::Degraded);

        p.on_handshake(t0 + DEGRADED_AFTER + Duration::from_secs(1));
        assert_eq!(p.state, PathState::Direct);
    }

    #[test]
    fn degraded_drops_to_disconnected_when_dead_and_no_relay() {
        let t0 = Instant::now();
        let mut p = Path::new(t0);
        p.on_handshake(t0);
        p.tick(t0 + DEGRADED_AFTER, false);
        assert_eq!(p.state, PathState::Degraded);

        let dead_at = t0 + DEGRADED_AFTER + DEGRADED_DEAD_AFTER;
        let action = p.tick(dead_at, false);
        assert_eq!(p.state, PathState::Disconnected);
        assert_eq!(action, Some(PathAction::MarkRelayNeeded));
    }

    #[test]
    fn disconnected_backoff_increases_then_caps() {
        let mut t = Instant::now();
        let mut p = Path::new(t);

        // Force into Disconnected (Connecting timeout, no relay).
        t += CONNECT_TIMEOUT;
        let action = p.tick(t, false);
        assert_eq!(p.state, PathState::Disconnected);
        assert_eq!(action, Some(PathAction::MarkRelayNeeded));

        let mut observed_backoffs = Vec::new();
        for _ in 0..6 {
            // Not yet elapsed: no transition.
            assert_eq!(p.tick(t + Duration::from_millis(1), false), None);

            // Elapse exactly the current backoff: back to Connecting with
            // StartPunch, and the stored backoff doubles for next time.
            let this_backoff = p.backoff;
            t += this_backoff;
            let action = p.tick(t, false);
            assert_eq!(p.state, PathState::Connecting);
            assert_eq!(action, Some(PathAction::StartPunch));
            observed_backoffs.push(this_backoff);

            // Immediately re-timeout Connecting to cycle back to
            // Disconnected for the next loop iteration.
            t += CONNECT_TIMEOUT;
            let action = p.tick(t, false);
            assert_eq!(p.state, PathState::Disconnected);
            assert_eq!(action, Some(PathAction::MarkRelayNeeded));
        }

        assert_eq!(
            observed_backoffs,
            vec![
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(8),
                Duration::from_secs(16),
                Duration::from_secs(30), // capped from 32
                Duration::from_secs(30),
            ]
        );
    }
}
