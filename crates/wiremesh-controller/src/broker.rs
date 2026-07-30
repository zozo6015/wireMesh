//! (Cycle-4b Task 5, spec §4) The Sync **broker**: the one component that
//! turns the controller's otherwise purely *declarative* Sync stream into an
//! *imperative* "punch now" signal aimed at BOTH members of a gateway pair.
//!
//! Every other `SyncMessage` (`Snapshot`/`Delta`) describes desired state and
//! the delta fan-out deliberately *self-excludes* the subject gateway (see
//! `crate::services::sync`'s `subject_gateway_id()` skip). A hole-punch is the
//! opposite: it must reach BOTH peers of a pair, at (approximately) the same
//! instant, each carrying the *other's* candidate set. So the broker does NOT
//! ride the `ChangeEvent`/`Delta` self-skip path — it keeps its OWN registry
//! of live `Sync.Watch` connections (keyed by the AUTHENTICATED gateway id the
//! mTLS layer resolved) and addresses each pair member's stream explicitly.
//!
//! # The go-skew critical section (Phase-0 Finding 2)
//!
//! Broker go-skew must stay below the inter-peer one-way latency or a
//! Linux-NAT'd peer's mapping is poisoned for ~30s. Two levers, both used:
//!
//! 1. **Back-to-back sends.** [`Broker::emit_pair`] issues both `PunchDirective`s
//!    with NO `.await` (and no other yield point) between the two `try_send`s —
//!    the µs-scale primary guarantee, mirroring the spike `broker.rs`'s two
//!    back-to-back `write_all`s.
//! 2. **Common `go_unix_ms`.** Both directives carry the SAME near-future
//!    wall-clock fire instant (`now + PUNCH_LEAD_MS`), so both punchers start
//!    on the same tick regardless of delivery jitter — the corroborating
//!    guarantee.
//!
//! # Triggers
//!
//! A pair is (re-)punched when (a) a gateway connects (its `Watch` opens), (b)
//! a candidate changes for either member (the broker subscribes to the same
//! [`ChangeEvent`] broadcast every mutation site publishes on — an
//! `EndpointObserved` is emitted by both the UDP observation endpoint and
//! `Sync.Report`'s local-endpoint path), and (c) a bounded periodic retry:
//! the periodic sweep re-punches connected+candidate'd pairs only up to
//! [`MAX_PERIODIC_ATTEMPTS`] consecutive times, the budget reset on any
//! candidate change or reconnect.
//!
//! # Path-state skip (directive-storm fix; make-before-break awareness)
//!
//! In 4b the controller could not observe a pair's data-plane state, so every
//! trigger above re-punched unconditionally — and because the periodic budget
//! resets on ANY candidate change or reconnect, an already-settled pair kept
//! receiving `PunchDirective`s forever (each one burst-firing the gateway's
//! "deferring direct punch" make-before-break defer line). Gateways now
//! attach their per-peer path states to `Sync.Report`
//! (`ReportRequest.peer_paths`, forwarded here via [`Broker::on_report`]),
//! and EVERY emit path funnels through [`Broker::emit_pair`], which skips a
//! pair entirely — no directives, no periodic-budget consumption — iff BOTH
//! members' latest stored reports mark the OTHER member "direct" OR
//! "relayed": a settled pair must not be fought over (a punch toward a
//! `Relayed` peer would disturb a flowing relay path; the `Relayed→Direct`
//! cutover fast-follow will revisit this skip when a deliberate,
//! rehandshake-driven direct probe exists). Anything one-sided, absent, or in
//! any other state fails OPEN toward punching (empty `peer_paths` = old
//! client = the 4b behavior), and a reporter's stored states are cleared when
//! it reconnects ([`Broker::on_gateway_connected`]) so a restarted gateway's
//! stale "direct" claim never suppresses the punch it now needs.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use tokio::sync::{broadcast, mpsc, oneshot};

use wiremesh_proto::v1::sync_message::Body;
use wiremesh_proto::v1::{PeerPath, PunchDirective, RotateDirective, SyncMessage};

use crate::db::AWAITING_SUBMISSION_SENTINEL;
use crate::db_async::DbHandle;
use crate::projection::ChangeEvent;

/// The registry of live `Sync.Watch` connections' punch channels, keyed by the
/// AUTHENTICATED gateway id (the CN the mTLS layer resolved — never anything
/// client-supplied). Constructed once in `serve()` and shared (a clone) with
/// both the [`Broker`] and every `SyncSvc::watch` connection, exactly like the
/// `ChangeEvent` broadcast sender. A `std::sync::Mutex` (not a tokio one)
/// because it is only ever held across purely-synchronous work — never across
/// an `.await` — which is precisely what makes the two back-to-back
/// `try_send`s in [`Broker::emit_pair`] an atomic, yield-free critical section.
pub type PunchRegistry = Arc<Mutex<HashMap<i64, mpsc::Sender<SyncMessage>>>>;

/// How far into the future the common `go_unix_ms` fire instant is stamped —
/// a near-future instant both punchers can start on together despite delivery
/// jitter (spec §4 go-skew, lever (b)). 300ms is generous headroom over the
/// broker's own µs-scale back-to-back emit while still being a barely-perceptible
/// startup delay for the punch itself.
pub const PUNCH_LEAD_MS: u64 = 300;

/// Capacity of each per-connection punch mpsc channel. Small: a connection
/// only ever has a handful of not-yet-flushed directives in flight (one per
/// peer per trigger). Bounded on purpose so [`Broker::emit_pair`] uses a
/// non-blocking `try_send` (no `.await`) — a full channel means the gateway
/// isn't draining its stream and dropping a redundant re-punchable directive
/// is the right thing, not blocking the broker's critical section.
pub const PUNCH_CHANNEL_CAPACITY: usize = 16;

/// Max consecutive PERIODIC re-punches for a pair before the periodic sweep
/// backs off (reset to zero on any candidate change or reconnect for that
/// pair). Bounds the retry for pairs whose data-plane state the controller
/// does NOT (yet) know is settled — for a pair BOTH sides have reported
/// settled, `emit_pair_periodic` still consults this ceiling first, but the
/// path-state skip inside [`Broker::emit_pair`] then emits nothing and
/// returns `false`, so no attempt is ever CONSUMED from the budget; this
/// budget remains the only bound for old clients that never report
/// `peer_paths`.
const MAX_PERIODIC_ATTEMPTS: u32 = 5;

/// Periodic retry cadence for the background sweep (trigger (c)).
const RETRY_INTERVAL: Duration = Duration::from_secs(5);

/// Memory backstop on how many per-peer path states ONE reporter can have
/// stored at a time ([`Broker::on_report`] drops a report's excess NEW peer
/// ids beyond it). The peer ids inside `peer_paths` are client-supplied and
/// never validated against the roster here (`on_report` is deliberately
/// synchronous — no DB lookup on the Report hot path), so without a cap a
/// single authenticated gateway could grow its entry without bound. This is
/// NOT an authz filter — the fabric is single-tenant and every reporter is
/// mTLS-authenticated, so severity is low (a misbehaving peer is an operator
/// problem, not a tenant boundary) — just a bound. Generous: real fabrics
/// are orders of magnitude below 4096 gateways, and `pair_settled` only ever
/// reads ids that are genuine roster peers, so capping can never suppress a
/// legitimate punch.
const MAX_PEER_PATHS_PER_REPORTER: usize = 4096;

/// Constructs a fresh, empty [`PunchRegistry`] — one per controller instance,
/// created in `serve()` and shared with the broker and every Watch connection.
pub fn new_registry() -> PunchRegistry {
    Arc::new(Mutex::new(HashMap::new()))
}

/// The broker (spec §4). Holds the shared connection [`PunchRegistry`], a
/// [`DbHandle`] to read pair membership + candidate sets, and the per-pair
/// periodic-retry budget. Constructed once in `serve()` behind an `Arc` so the
/// background trigger loop ([`Broker::spawn`]) and every `SyncSvc::watch`
/// connection (which calls [`Broker::register`] / [`Broker::on_gateway_connected`])
/// share one instance.
pub struct Broker {
    db: DbHandle,
    registry: PunchRegistry,
    /// Per-unordered-pair count of consecutive PERIODIC re-punches, keyed by
    /// `(min(a,b), max(a,b))`. Reset (removed) on any candidate change or
    /// reconnect for the pair — see [`Broker::reset_pair`].
    periodic_attempts: Mutex<HashMap<(i64, i64), u32>>,
    /// (Directive-storm fix) Latest gateway-reported path state per
    /// `reporter -> (peer -> lowercase state string)`, fed by
    /// [`Broker::on_report`] from `ReportRequest.peer_paths` and read by
    /// [`Broker::emit_pair`]'s both-settled skip. A reporter's whole entry is
    /// cleared on its reconnect ([`Broker::on_gateway_connected`]) — a
    /// restarted gateway may have no tunnel at all, and its stale "direct"
    /// claim must not suppress the punch it now needs. Same locking style as
    /// `periodic_attempts`: a `std::sync::Mutex` held only across
    /// purely-synchronous map work, never an `.await`.
    peer_path_states: Mutex<HashMap<i64, HashMap<i64, String>>>,
}

impl Broker {
    /// Builds a broker over a shared [`PunchRegistry`] (the SAME clone every
    /// `SyncSvc::watch` connection registers into).
    pub fn new(db: DbHandle, registry: PunchRegistry) -> Arc<Self> {
        Arc::new(Self {
            db,
            registry,
            periodic_attempts: Mutex::new(HashMap::new()),
            peer_path_states: Mutex::new(HashMap::new()),
        })
    }

    /// (Directive-storm fix) Records `reporter_gateway_id`'s latest view of
    /// its peers' path states from a `Sync.Report`'s `peer_paths`, read by
    /// [`Broker::emit_pair`]'s both-settled skip. Two wire shapes
    /// (CodeRabbit follow-up — `ReportRequest.peer_paths_snapshot`):
    ///
    /// - `snapshot == true` (a NEW client's steady-state report, which
    ///   always serializes its COMPLETE path map): REPLACE this reporter's
    ///   stored map with the report's content. An empty snapshot is a
    ///   genuine "I track no paths" and clears the reporter's entries
    ///   entirely — without this, a reporter that pruned a peer (or lost
    ///   all its paths) would keep exporting stale settled states until its
    ///   next reconnect.
    /// - `snapshot == false` (an old client, or the gateway's rotation-tick
    ///   unary epoch-ack report — not a path snapshot): legacy upsert-only,
    ///   LATEST wins per `(reporter, peer)`, and empty is a NO-OP — it must
    ///   never wipe stored states (an epoch ack mid-rotation must not make
    ///   the broker start re-punching a settled pair).
    ///
    /// KNOWN RACE (owner-adjudicated: valid but DEFERRED): a Report from a
    /// gateway's PREVIOUS session — network-delayed past its restart — can
    /// be processed after [`Broker::on_gateway_connected`]'s clear, and,
    /// being `snapshot == true`, REPLACE the fresh (empty) state with
    /// pre-restart claims. Impact is bounded: the settled skip is an
    /// OPTIMIZATION over 4b's punch-blindly behavior, `pair_settled` needs
    /// BOTH directions to agree, the gateway's own tick-driven `StartPunch`
    /// recovery is directive-independent, and any later fresh snapshot (or
    /// reconnect) corrects the stored states. The same stale-report race
    /// predates this field for `local_endpoints` and `relay_health`; the
    /// shared fix is a per-boot session generation carried in Watch+Report
    /// (the controller rejecting mismatches), tracked as a Sync-hardening
    /// fast-follow alongside the keepalive mirrors — see
    /// `docs/research/ops-finding-sync-half-open-stream.md`.
    ///
    /// `reporter_gateway_id` is the AUTHENTICATED gateway id `Sync.Report`
    /// resolved from the mTLS peer certificate — never anything
    /// client-supplied; the peer ids INSIDE `peer_paths` are client-supplied
    /// and unvalidated, bounded per reporter by
    /// [`MAX_PEER_PATHS_PER_REPORTER`] (a memory backstop — see its doc;
    /// applied to both shapes).
    pub fn on_report(&self, reporter_gateway_id: i64, peer_paths: &[PeerPath], snapshot: bool) {
        if !snapshot && peer_paths.is_empty() {
            return;
        }
        let Ok(mut states) = self.peer_path_states.lock() else {
            return;
        };
        if snapshot && peer_paths.is_empty() {
            // Empty SNAPSHOT: the reporter genuinely tracks no paths — drop
            // its whole entry (not just its values) so it costs no memory.
            states.remove(&reporter_gateway_id);
            return;
        }
        let entry = states.entry(reporter_gateway_id).or_default();
        if snapshot {
            // Snapshot REPLACE: start from empty so peers absent from this
            // report (pruned by the gateway) drop out rather than linger.
            entry.clear();
        }
        for pp in peer_paths {
            let peer = pp.peer_gateway_id as i64;
            // At the cap, still allow UPDATES for already-tracked peers
            // (skipping only NEW ids), so a legitimate peer's state can
            // never be starved out by junk ids earlier in the list.
            if entry.len() >= MAX_PEER_PATHS_PER_REPORTER && !entry.contains_key(&peer) {
                continue;
            }
            entry.insert(peer, pp.state.clone());
        }
    }

    /// (Directive-storm fix) True iff the pair `(a, b)` is SETTLED: BOTH
    /// members' latest stored reports mark the OTHER member's state as
    /// "direct" OR "relayed" (a mixed direct/relayed pair is just as settled
    /// — neither end wants a punch fighting its path). Anything one-sided,
    /// absent, or in any other state ("connecting", "degraded",
    /// "disconnected", or an unknown future label) is NOT settled — the
    /// broker fails open toward punching.
    fn pair_settled(&self, a: i64, b: i64) -> bool {
        let Ok(states) = self.peer_path_states.lock() else {
            return false;
        };
        let settled = |reporter: i64, peer: i64| {
            states
                .get(&reporter)
                .and_then(|peers| peers.get(&peer))
                .is_some_and(|s| s == "direct" || s == "relayed")
        };
        settled(a, b) && settled(b, a)
    }

    /// (Directive-storm fix) Drops every stored path state `gateway_id` has
    /// reported — see `peer_path_states`'s doc for why this happens on its
    /// reconnect.
    fn clear_reported_states(&self, gateway_id: i64) {
        if let Ok(mut states) = self.peer_path_states.lock() {
            states.remove(&gateway_id);
        }
    }

    /// Registers `sender` under `gateway_id` and returns a [`RegistrationGuard`]
    /// whose `Drop` deregisters it — so a panic/early-return anywhere in the
    /// Watch handler still removes the stale entry. Overwrites any prior entry
    /// for the same gateway id (a reconnect); the older connection's guard uses
    /// `Sender::same_channel` on drop so it removes ONLY its own entry, never
    /// the newer one that replaced it.
    pub fn register(
        self: &Arc<Self>,
        gateway_id: i64,
        sender: mpsc::Sender<SyncMessage>,
    ) -> RegistrationGuard {
        if let Ok(mut reg) = self.registry.lock() {
            reg.insert(gateway_id, sender.clone());
        }
        RegistrationGuard {
            registry: self.registry.clone(),
            gateway_id,
            sender,
        }
    }

    /// (Key-rotation Task 3) The gateway ids currently registered in the
    /// punch registry — i.e. every gateway with a currently-open `Sync.Watch`
    /// stream. Used by `SyncSvc::drive_rotation` to compute a rotation's
    /// `expected_peers` (every OTHER currently-connected gateway, since only
    /// a peer that's actually connected right now can plausibly have acked a
    /// live WireGuard session with the rotating epoch). Not `async` — the
    /// registry is a plain `std::sync::Mutex`, held only long enough to copy
    /// the keys out.
    pub fn connected_gateway_ids(&self) -> Vec<i64> {
        match self.registry.lock() {
            Ok(reg) => reg.keys().copied().collect(),
            Err(_) => Vec::new(),
        }
    }

    /// (Key-rotation) If `keys` (a gateway's full `(epoch, pubkey, state)`
    /// row set from a `ChangeEvent::KeyRotated`) contains a `pending` epoch
    /// still carrying the [`AWAITING_SUBMISSION_SENTINEL`] pubkey — i.e. a
    /// rotation that has just been initiated and whose gateway hasn't yet
    /// submitted its real key — deliver a [`RotateDirective`] for that epoch
    /// to `gateway_id`'s registered Watch channel (a non-blocking `try_send`,
    /// like every other broker emit). A no-op if the gateway isn't currently
    /// connected (nothing registered) or the channel is full — the rotation
    /// sweep/timer re-emits KeyRotated on subsequent ticks, and an unconnected
    /// gateway can't be rotating a live session anyway.
    pub fn send_rotate_if_pending(&self, gateway_id: i64, keys: &[(i64, String, String)]) {
        let Some((epoch, _, _)) = keys
            .iter()
            .find(|(_, pubkey, state)| state == "pending" && pubkey == AWAITING_SUBMISSION_SENTINEL)
        else {
            return;
        };
        let msg = SyncMessage {
            body: Some(Body::Rotate(RotateDirective { epoch: *epoch as u32 })),
        };
        let sent = match self.registry.lock() {
            Ok(reg) => reg.get(&gateway_id).map(|tx| tx.try_send(msg).is_ok()).unwrap_or(false),
            Err(_) => false,
        };
        if sent {
            eprintln!(
                "wiremesh-controller: sent RotateDirective(epoch={}) to gateway {gateway_id}",
                *epoch
            );
        }
    }

    /// Trigger (a): a gateway's `Watch` stream just opened. Clears every path
    /// state this gateway previously reported (a reconnect may be a process
    /// restart with no tunnels at all — its stale "direct"/"relayed" claims
    /// must not keep suppressing punches its pairs now need; the natural home
    /// for the clear, since this is also where pair budgets reset), then
    /// resets the periodic budget for every pair this gateway belongs to (a
    /// fresh connection is a fresh opportunity) and attempts a punch for each
    /// — a no-op for any peer not also connected or without a candidate yet.
    pub async fn on_gateway_connected(&self, gateway_id: i64) {
        self.clear_reported_states(gateway_id);
        self.punch_peers_of(gateway_id, true).await;
    }

    /// Spawns the background trigger loop: it `select!`s over {a candidate
    /// change on `change_rx` (trigger (b)), the periodic retry tick (trigger
    /// (c)), shutdown}. Returns the task's `JoinHandle` so `serve()` folds it
    /// into the same bounded-join-then-abort teardown every other server task
    /// gets.
    pub fn spawn(
        self: Arc<Self>,
        mut change_rx: broadcast::Receiver<ChangeEvent>,
        mut shutdown: oneshot::Receiver<()>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(RETRY_INTERVAL);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            // `tokio::time::interval`'s first tick fires immediately; consume
            // it so the very first thing the loop does isn't a premature sweep
            // before anything is even registered.
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = &mut shutdown => break,
                    _ = interval.tick() => {
                        self.periodic_sweep().await;
                    }
                    ev = change_rx.recv() => match ev {
                        // A candidate for `gateway_id` changed (observation
                        // endpoint or `Sync.Report`'s local-endpoint path) —
                        // re-punch its pairs, resetting their periodic budget.
                        Ok(ChangeEvent::EndpointObserved { gateway_id, .. }) => {
                            self.punch_peers_of(gateway_id, true).await;
                        }
                        // (Key-rotation) A rotation was just initiated
                        // (`Admin.RotateKey` / the rotation timer inserted a
                        // fresh `pending` epoch still carrying the
                        // `awaiting-submission` sentinel) — tell the rotating
                        // gateway to mint+submit its real key and begin
                        // make-before-break by delivering a `RotateDirective`
                        // on ITS OWN Watch stream. This is the one
                        // controller->rotating-gateway imperative signal (the
                        // declarative KeyRotated delta self-skips the subject
                        // gateway, so it can never learn of its own rotation
                        // that way); it rides the same per-connection registry
                        // channel a `PunchDirective` does. A KeyRotated event
                        // whose pending epoch already holds a REAL key (a
                        // re-emit after submission/promote/retire) carries no
                        // sentinel row, so `send_rotate_if_pending` is a no-op
                        // — the directive fires exactly once, at rotation
                        // start.
                        Ok(ChangeEvent::KeyRotated { gateway_id, keys, .. }) => {
                            self.send_rotate_if_pending(gateway_id, &keys);
                        }
                        // No other event changes a candidate set the broker
                        // acts on.
                        Ok(_) => {}
                        // Missed some events (the broker only needs to know a
                        // candidate *may* have changed — the next periodic
                        // sweep re-punches anyway); keep going.
                        Err(broadcast::error::RecvError::Lagged(_)) => {}
                        // The controller is shutting down (every sender
                        // dropped) — end the loop.
                        Err(broadcast::error::RecvError::Closed) => break,
                    },
                }
            }
        })
    }

    /// Punches every peer of `gateway_id` (peers = active gateways in a
    /// DIFFERENT segment). With `reset`, clears each pair's periodic budget
    /// first. Each attempt is a no-op unless both members are connected and
    /// each has ≥1 candidate.
    async fn punch_peers_of(&self, gateway_id: i64, reset: bool) {
        let peers = match self.peer_ids_of(gateway_id).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("wiremesh-controller: broker peer lookup for {gateway_id} failed: {e}");
                return;
            }
        };
        for peer in peers {
            if reset {
                self.reset_pair(gateway_id, peer);
            }
            self.emit_pair(gateway_id, peer).await;
        }
    }

    /// Trigger (c): every connected pair (both members registered) gets one
    /// periodic re-punch, bounded per pair by [`MAX_PERIODIC_ATTEMPTS`].
    async fn periodic_sweep(&self) {
        let connected: Vec<i64> = match self.registry.lock() {
            Ok(reg) => reg.keys().copied().collect(),
            Err(_) => return,
        };
        for gw in &connected {
            let peers = match self.peer_ids_of(*gw).await {
                Ok(p) => p,
                Err(_) => continue,
            };
            for peer in peers {
                // Handle each unordered pair once (only from its lower id) and
                // only when both ends are actually connected.
                if peer <= *gw || !connected.contains(&peer) {
                    continue;
                }
                self.emit_pair_periodic(*gw, peer).await;
            }
        }
    }

    /// The active gateways that are `gateway_id`'s peers: every OTHER active
    /// gateway in a DIFFERENT segment (spec §4 — cross-segment gateways are
    /// the pairs that need hole-punching).
    async fn peer_ids_of(&self, gateway_id: i64) -> anyhow::Result<Vec<i64>> {
        let my_segment = match self.db.gateway_identity_by_id(gateway_id).await? {
            Some(identity) => identity.segment_id,
            None => return Ok(Vec::new()),
        };
        let others = self.db.list_other_gateways(gateway_id).await?;
        Ok(others
            .into_iter()
            .filter(|g| g.segment_id != my_segment)
            .map(|g| g.id)
            .collect())
    }

    /// Emits a paired `PunchDirective` to both `a` and `b` iff both are
    /// connected, each has ≥1 candidate, and the pair is not already SETTLED
    /// (both members' latest reports mark the other "direct"/"relayed" —
    /// [`Broker::pair_settled`], the directive-storm fix's make-before-break
    /// awareness). Returns `true` iff both directives were sent.
    ///
    /// The settled skip sits HERE, on the one funnel every trigger flows
    /// through — reconnect and candidate-change ([`Broker::punch_peers_of`])
    /// and the periodic sweep ([`Broker::emit_pair_periodic`]) alike — so a
    /// candidate change can reset a pair's periodic budget but can never
    /// bypass the skip and re-punch a settled pair (exactly the reset path
    /// that kept the directive storm alive). Skipping returns `false`, so
    /// the periodic wrapper consumes no budget either.
    ///
    /// All the fallible/awaiting work (candidate reads) happens BEFORE the
    /// critical section. The critical section itself — locking the registry,
    /// re-checking both are still present, and the two `try_send`s — contains
    /// NO `.await` and no other yield point, so the two "go"s leave
    /// back-to-back (the primary go-skew guarantee, spec §4 lever (a)).
    async fn emit_pair(&self, a: i64, b: i64) -> bool {
        // Cheap presence pre-check so we don't do candidate DB reads for a
        // pair that plainly isn't both-connected yet.
        {
            let reg = match self.registry.lock() {
                Ok(reg) => reg,
                Err(_) => return false,
            };
            if !reg.contains_key(&a) || !reg.contains_key(&b) {
                return false;
            }
        }

        // Path-state skip (directive-storm fix): a pair BOTH sides report
        // settled ("direct"/"relayed" toward each other) gets NO directive at
        // all — a punch would only make each gateway's make-before-break
        // guard defer it (and could disturb a flowing relay path). One-sided,
        // absent, or any other state falls through and emits as before (fail
        // open — old clients never report `peer_paths`). The `Relayed→Direct`
        // cutover fast-follow will revisit this skip once a deliberate,
        // rehandshake-driven direct probe exists to punch FOR.
        if self.pair_settled(a, b) {
            return false;
        }

        let a_candidates = match self.db.candidates_for(a).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("wiremesh-controller: broker candidates_for({a}) failed: {e}");
                return false;
            }
        };
        let b_candidates = match self.db.candidates_for(b).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("wiremesh-controller: broker candidates_for({b}) failed: {e}");
                return false;
            }
        };
        if a_candidates.is_empty() || b_candidates.is_empty() {
            return false;
        }

        // ONE common fire instant for both members (spec §4 lever (b)).
        let go_unix_ms = now_unix_ms() + PUNCH_LEAD_MS;
        // `a` is told to punch toward `b` (carrying b's candidates), and
        // vice-versa.
        let for_a = SyncMessage {
            body: Some(Body::Punch(PunchDirective {
                peer_gateway_id: b as u64,
                candidates: b_candidates,
                go_unix_ms,
            })),
        };
        let for_b = SyncMessage {
            body: Some(Body::Punch(PunchDirective {
                peer_gateway_id: a as u64,
                candidates: a_candidates,
                go_unix_ms,
            })),
        };

        // ---- CRITICAL SECTION: no `.await`, no yield, between the two
        // `try_send`s (spec §4 / Phase-0 Finding 2). ----
        let reg = match self.registry.lock() {
            Ok(reg) => reg,
            Err(_) => return false,
        };
        let (Some(tx_a), Some(tx_b)) = (reg.get(&a), reg.get(&b)) else {
            return false;
        };
        let a_sent = tx_a.try_send(for_a).is_ok();
        let b_sent = tx_b.try_send(for_b).is_ok();
        // ---- end critical section ----
        a_sent && b_sent
    }

    /// [`Broker::emit_pair`] wrapped in the per-pair periodic budget: skips once
    /// the pair has been periodically re-punched [`MAX_PERIODIC_ATTEMPTS`]
    /// consecutive times (with no intervening candidate change/reconnect to
    /// reset it), and counts a successful emit against that budget. A SETTLED
    /// pair is skipped inside `emit_pair` itself (the path-state skip returns
    /// `false`), so it consumes none of this budget — the periodic sweep goes
    /// fully quiet for it rather than burning attempts.
    async fn emit_pair_periodic(&self, a: i64, b: i64) {
        let key = pair_key(a, b);
        {
            let attempts = match self.periodic_attempts.lock() {
                Ok(m) => m,
                Err(_) => return,
            };
            if attempts.get(&key).copied().unwrap_or(0) >= MAX_PERIODIC_ATTEMPTS {
                return;
            }
        }
        if self.emit_pair(a, b).await {
            if let Ok(mut attempts) = self.periodic_attempts.lock() {
                *attempts.entry(key).or_insert(0) += 1;
            }
        }
    }

    /// Clears a pair's periodic-retry budget — called on any candidate change
    /// or reconnect for either member, so a genuinely new opportunity gets the
    /// full retry allowance again.
    fn reset_pair(&self, a: i64, b: i64) {
        if let Ok(mut attempts) = self.periodic_attempts.lock() {
            attempts.remove(&pair_key(a, b));
        }
    }
}

/// Normalizes an unordered gateway pair to a canonical `(low, high)` key so
/// `(a,b)` and `(b,a)` share one budget entry.
fn pair_key(a: i64, b: i64) -> (i64, i64) {
    if a <= b {
        (a, b)
    } else {
        (b, a)
    }
}

/// Milliseconds since the Unix epoch. Production code (not a workflow script),
/// so wall-clock `SystemTime` is the right source for a `go_unix_ms` two peers
/// on different hosts compare against.
fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Deregisters a Watch connection's punch channel on drop (see
/// [`Broker::register`]). A guard rather than an explicit deregister call so
/// the entry is removed even if the Watch handler panics or returns early —
/// and it removes ONLY the entry that is still *its own* channel (via
/// `Sender::same_channel`), so a reconnect that already overwrote the entry
/// isn't clobbered when this older guard finally drops.
pub struct RegistrationGuard {
    registry: PunchRegistry,
    gateway_id: i64,
    sender: mpsc::Sender<SyncMessage>,
}

impl Drop for RegistrationGuard {
    fn drop(&mut self) {
        if let Ok(mut reg) = self.registry.lock() {
            let still_ours = reg
                .get(&self.gateway_id)
                .map(|s| s.same_channel(&self.sender))
                .unwrap_or(false);
            if still_ours {
                reg.remove(&self.gateway_id);
            }
        }
    }
}
