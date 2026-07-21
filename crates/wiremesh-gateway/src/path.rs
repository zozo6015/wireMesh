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

/// Cadence of the `Relayed` make-before-break background direct-recovery
/// probe (`PathAction::ProbeDirect`). Debug note (Cycle 4c Task 9 stability
/// fix): this used to fire on EVERY `tick` (~1s cadence) while `Relayed`,
/// which stacked back-to-back hole-punch attempts (the driver's punch window
/// is several seconds, so a fresh `ProbeDirect` was requested again before
/// the previous punch had even finished, logging "punch already in flight;
/// skipping" continuously) and kept the driver's transient same-port
/// `SO_REUSEPORT` punch socket open nearly 100% of the time. That socket
/// shares the WG listen port with `RelayTransport`'s local downlink delivery
/// target (also `127.0.0.1:<wg_listen_port>` — see `main.rs`'s
/// `ensure_relay_transport` `local_peer_hint`), so an almost-always-open
/// punch socket intermittently stole inbound relayed WireGuard datagrams
/// that the kernel's `SO_REUSEPORT` group would otherwise have delivered to
/// boringtun's own socket, starving the relay path of traffic even though
/// the relay itself was healthy. A low background rate (this constant) plus
/// the grace period below give the relay path long, undisturbed windows to
/// actually carry traffic. See docs/research/cycle4c-relay-stability-note.md.
pub const PROBE_DIRECT_INTERVAL: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PathState {
    Connecting,
    Direct,
    Degraded,
    /// Make-before-break relay path (spec §6.1). Traffic flows over a live
    /// `RelayTransport` while the driver periodically probes for a direct
    /// path in the background (`PathAction::ProbeDirect`); a completed WG
    /// handshake (`on_handshake`) cuts over straight to `Direct` and the
    /// relay is torn down. If the relay itself goes unhealthy with nothing
    /// else available, `tick` re-paths to `Disconnected` so the driver finds
    /// another one.
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
    /// The driver needs to (re-)establish relay coverage for this peer.
    /// Fires in two situations: entering `Relayed` (a convergence budget was
    /// exhausted, or a live path died, WITH a relay available) — the driver
    /// should ensure a live `RelayTransport` exists for this peer and its WG
    /// endpoint points at it; and parking in `Disconnected` with NO relay
    /// available — the driver should keep trying to find/health-check a
    /// relay for next time, since there's nothing else to do meanwhile.
    MarkRelayNeeded,
    /// Still waiting (degraded, not yet dead): retry whatever low-rate
    /// recovery probe is already appropriate — no fresh punch session, no
    /// relay escalation yet.
    Retry,
    /// Make-before-break: while `Relayed` and the relay stays available, ask
    /// the driver to run a low-rate background direct hole-punch probe. The
    /// relay keeps carrying traffic in the meantime; only a completed WG
    /// handshake (`on_handshake`) actually cuts over to `Direct`.
    ProbeDirect,
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
    /// While `Relayed`: the instant of the last `ProbeDirect` emission, OR
    /// (if none emitted yet this `Relayed` spell) the instant the peer
    /// entered `Relayed` — gates `PROBE_DIRECT_INTERVAL` so the background
    /// direct-recovery probe fires at a low rate rather than every tick, and
    /// so a freshly-entered `Relayed` path gets one full, undisturbed
    /// interval before the first probe ever touches it. `None` outside
    /// `Relayed` (reset on leaving it, so a later re-entry starts its own
    /// fresh grace period).
    relayed_probe_last: Option<Instant>,
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
            relayed_probe_last: None,
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
        self.relayed_probe_last = None;
        // Review fix (4c Task 8, IMPORTANT): a completed handshake means the
        // path recovered, so the next disconnect should start backoff fresh
        // rather than inheriting an already-escalated value from an earlier,
        // unrelated disconnect (which could otherwise push a later relay
        // re-path past the <=15s SLA).
        self.backoff = BACKOFF_INITIAL;
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
    /// exists for this peer right now (the driver computes this from a live,
    /// healthy `RelayTransport` — Cycle 4c).
    pub fn tick(&mut self, now: Instant, relay_available: bool) -> Option<PathAction> {
        match self.state {
            PathState::Connecting => {
                if now.saturating_duration_since(self.connecting_since) >= CONNECT_TIMEOUT {
                    if relay_available {
                        self.state = PathState::Relayed;
                        // Start this Relayed spell's probe grace period now
                        // (see `relayed_probe_last` doc) rather than probing
                        // on the very next tick.
                        self.relayed_probe_last = Some(now);
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
                        // See the `Connecting` arm above: start this spell's
                        // probe grace period now.
                        self.relayed_probe_last = Some(now);
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
                if relay_available {
                    // The relay is still carrying traffic. Only ask the
                    // driver to run its background direct-recovery probe
                    // (make-before-break) at a low, bounded rate
                    // (`PROBE_DIRECT_INTERVAL`) rather than every tick — see
                    // `relayed_probe_last`'s doc for why firing every tick
                    // was actively harmful (it starved the relay path of
                    // traffic, not just wasted effort). Stay `Relayed`
                    // either way — only a real handshake (`on_handshake`)
                    // cuts over to `Direct`.
                    let due = self.relayed_probe_last.map_or(true, |last| {
                        now.saturating_duration_since(last) >= PROBE_DIRECT_INTERVAL
                    });
                    if due {
                        self.relayed_probe_last = Some(now);
                        Some(PathAction::ProbeDirect)
                    } else {
                        None
                    }
                } else {
                    // The relay path itself died with nothing else
                    // available: re-path to `Disconnected` so the normal
                    // backoff/StartPunch cycle (and a fresh relay search)
                    // takes over.
                    self.state = PathState::Disconnected;
                    self.disconnected_since = Some(now);
                    self.relayed_probe_last = None;
                    Some(PathAction::MarkRelayNeeded)
                }
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

    /// Debug fix (Cycle 4c Task 9 stability): `ProbeDirect` used to fire on
    /// EVERY tick while `Relayed`, which (via the driver's transient
    /// same-port `SO_REUSEPORT` punch socket) intermittently stole inbound
    /// relayed traffic and starved the relay path — see
    /// `docs/research/cycle4c-relay-stability-note.md`. A freshly-entered
    /// `Relayed` spell must get one full, undisturbed `PROBE_DIRECT_INTERVAL`
    /// before the first background probe ever fires.
    #[test]
    fn relayed_grants_a_full_grace_period_before_the_first_probe() {
        let t0 = Instant::now();
        let mut p = Path::new(t0);

        // Drive into Relayed via the Connecting timeout with a relay
        // available.
        let action = p.tick(t0 + CONNECT_TIMEOUT, true);
        assert_eq!(p.state, PathState::Relayed);
        assert_eq!(action, Some(PathAction::MarkRelayNeeded));

        // Ticking repeatedly during the grace period must ask for NO action
        // and must stay Relayed — the relay path gets an undisturbed window
        // to actually carry traffic (e.g. complete the WG handshake).
        for secs in [1, 5, 10, 19] {
            let action = p.tick(t0 + CONNECT_TIMEOUT + Duration::from_secs(secs), true);
            assert_eq!(action, None, "must not probe before the grace period elapses ({secs}s)");
            assert_eq!(p.state, PathState::Relayed);
        }
    }

    /// Once the grace period elapses, `ProbeDirect` fires exactly once, then
    /// stays quiet again until the next `PROBE_DIRECT_INTERVAL` — a low,
    /// bounded background rate, not every tick.
    #[test]
    fn relayed_probes_direct_at_a_low_bounded_rate() {
        let t0 = Instant::now();
        let mut p = Path::new(t0);

        p.tick(t0 + CONNECT_TIMEOUT, true);
        assert_eq!(p.state, PathState::Relayed);

        let entered = t0 + CONNECT_TIMEOUT;

        // Right at (>=) the grace period: fires once.
        let action = p.tick(entered + PROBE_DIRECT_INTERVAL, true);
        assert_eq!(action, Some(PathAction::ProbeDirect));
        assert_eq!(p.state, PathState::Relayed);

        // Immediately after: must NOT fire again (would otherwise stack a
        // fresh punch attempt on top of the one just requested).
        let action = p.tick(entered + PROBE_DIRECT_INTERVAL + Duration::from_secs(1), true);
        assert_eq!(action, None);

        // Still quiet just short of the next interval.
        let action =
            p.tick(entered + PROBE_DIRECT_INTERVAL + PROBE_DIRECT_INTERVAL - Duration::from_secs(1), true);
        assert_eq!(action, None);

        // A full interval after the last probe: fires again.
        let action = p.tick(entered + PROBE_DIRECT_INTERVAL + PROBE_DIRECT_INTERVAL, true);
        assert_eq!(action, Some(PathAction::ProbeDirect));
        assert_eq!(p.state, PathState::Relayed);
    }

    #[test]
    fn relayed_repaths_to_disconnected_when_relay_lost() {
        let t0 = Instant::now();
        let mut p = Path::new(t0);

        // Drive into Relayed.
        let action = p.tick(t0 + CONNECT_TIMEOUT, true);
        assert_eq!(p.state, PathState::Relayed);
        assert_eq!(action, Some(PathAction::MarkRelayNeeded));

        // The relay path itself is now gone: re-path to Disconnected and
        // ask the driver to re-establish a path.
        let lost_at = t0 + CONNECT_TIMEOUT + Duration::from_secs(2);
        let action = p.tick(lost_at, false);
        assert_eq!(p.state, PathState::Disconnected);
        assert_eq!(action, Some(PathAction::MarkRelayNeeded));
    }

    /// Review fix (4c Task 8, IMPORTANT): `backoff` only ever grew across a
    /// peer's lifetime, so a later relay re-path could exceed the <=15s SLA
    /// because it inherited an already-escalated backoff from an earlier,
    /// unrelated disconnect. A completed handshake means the path recovered,
    /// so `on_handshake` must reset `backoff` back to `BACKOFF_INITIAL` —
    /// the next disconnect should start fresh, not from the ceiling.
    #[test]
    fn on_handshake_resets_backoff() {
        let mut t = Instant::now();
        let mut p = Path::new(t);

        // Drive the same Disconnected -> Connecting -> Disconnected cycle as
        // `disconnected_backoff_increases_then_caps` far enough to escalate
        // backoff above BACKOFF_INITIAL (2s -> 4s -> 8s after 2 cycles).
        t += CONNECT_TIMEOUT;
        let action = p.tick(t, false);
        assert_eq!(p.state, PathState::Disconnected);
        assert_eq!(action, Some(PathAction::MarkRelayNeeded));

        for _ in 0..2 {
            let this_backoff = p.backoff;
            t += this_backoff;
            let action = p.tick(t, false);
            assert_eq!(p.state, PathState::Connecting);
            assert_eq!(action, Some(PathAction::StartPunch));

            t += CONNECT_TIMEOUT;
            let action = p.tick(t, false);
            assert_eq!(p.state, PathState::Disconnected);
            assert_eq!(action, Some(PathAction::MarkRelayNeeded));
        }

        assert!(
            p.backoff > BACKOFF_INITIAL,
            "backoff should have escalated above the initial value by now, got {:?}",
            p.backoff
        );

        // Recovery: a completed handshake resets backoff to BACKOFF_INITIAL
        // so the next disconnect's retry cadence starts fresh.
        p.on_handshake(t + Duration::from_secs(1));
        assert_eq!(p.backoff, BACKOFF_INITIAL);
    }

    #[test]
    fn relayed_recovers_to_direct_on_handshake() {
        let t0 = Instant::now();
        let mut p = Path::new(t0);

        // Drive into Relayed.
        let action = p.tick(t0 + CONNECT_TIMEOUT, true);
        assert_eq!(p.state, PathState::Relayed);
        assert_eq!(action, Some(PathAction::MarkRelayNeeded));

        // A completed direct handshake is the make-before-break cutover:
        // recover straight to Direct, refreshing liveness timestamps.
        let hs_at = t0 + CONNECT_TIMEOUT + Duration::from_secs(3);
        p.on_handshake(hs_at);
        assert_eq!(p.state, PathState::Direct);
        assert_eq!(p.last_handshake, Some(hs_at));
        assert_eq!(p.last_inbound, Some(hs_at));
    }
}
