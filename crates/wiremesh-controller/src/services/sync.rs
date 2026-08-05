//! `Sync` service (Task 7): the ONLY mTLS-gated surface in cycle-2. Unlike
//! Enrollment (server-TLS only — the caller has no client cert yet),
//! `serve()` binds this service's TCP listener with a
//! `tonic::transport::ServerTlsConfig` whose `client_ca_root` is the
//! embedded CA's own bundle and `client_auth_optional` left at its default
//! `false` — meaning tonic/rustls REJECT the TLS handshake outright for any
//! connection that doesn't present a client certificate chaining to that CA.
//! A request handler in this file only ever runs once that handshake has
//! already succeeded.
//!
//! Gateway identity is derived ONLY from the peer certificate tonic/rustls
//! already validated (`Request::peer_certs`) — specifically its subject
//! CN, looked up against `gateway.name` (the same value `EnrollmentSvc`
//! derived from the enrollment token and stamped as the issued leaf's
//! subject CN; see `services::enrollment`). Nothing client-supplied is
//! trusted as identity: `WatchRequest`'s single field
//! (`session_generation`) is a per-boot liveness nonce used only to reject
//! reports from a gateway process that has since been replaced — it never
//! selects or influences WHICH gateway the request is treated as.

use std::collections::{BTreeSet, HashMap};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

use base64::Engine as _;
use time::OffsetDateTime;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::wrappers::{BroadcastStream, ReceiverStream};
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status};

use wiremesh_proto::v1::sync_server::Sync;
use wiremesh_proto::v1::sync_message::Body;
use wiremesh_proto::v1::{
    ReportRequest, ReportResponse, SubmitEpochKeyRequest, SubmitEpochKeyResponse, SyncMessage,
    WatchRequest,
};

use crate::broker::{Broker, RegistrationGuard, PUNCH_CHANNEL_CAPACITY};
use crate::db::GatewayIdentity;
use crate::db_async::DbHandle;
use crate::projection::{self, ChangeEvent};
use crate::rotation::{self, RotationDecision, RotationState};

pub type WatchStream = Pin<Box<dyn Stream<Item = Result<SyncMessage, Status>> + Send + 'static>>;

pub struct SyncSvc {
    db: DbHandle,
    /// Fan-out source for delta events (Task 8): every projection-affecting
    /// mutation that adds/changes a gateway publishes one
    /// [`ChangeEvent`] here (see `crate::services::enrollment`); every live
    /// `Sync.Watch` connection below subscribes its own receiver and
    /// forwards relevant events as `Delta`s down its still-open stream.
    change_tx: broadcast::Sender<ChangeEvent>,
    /// (Cycle-4b Task 5) The Sync broker. Every `Watch` connection registers
    /// its per-connection punch channel into the broker's shared registry
    /// (keyed by the AUTHENTICATED gateway id) so the broker can push a
    /// `PunchDirective` explicitly to BOTH members of a pair — deliberately
    /// NOT the `subject_gateway_id()` self-skip path the deltas below use.
    broker: Arc<Broker>,
    /// (Cycle-4c Task 6) In-memory relay health votes: `relay_id -> (gw_id ->
    /// healthy)`. Populated exclusively by `report`'s `req.relay_health`
    /// handling below. Deliberately NOT persisted — lost on controller
    /// restart is an accepted tradeoff (see the design notes' "known
    /// limitation" section): a relay defaults back to whatever its DB
    /// `status` already was (unaffected by this map resetting), and any
    /// gateway that still considers a relay live/dead simply re-reports on
    /// its next `Report` call. `Arc` so every `SyncSvc` produced by cloning
    /// (if ever) — and, more immediately, every concurrent `report` call
    /// against the same shared service instance — sees and mutates the SAME
    /// map rather than a private copy.
    ///
    /// This is a `tokio::sync::Mutex` (NOT `std::sync::Mutex`) DELIBERATELY:
    /// the guard is held across the entire read-decide-write critical
    /// section in `report()` below, including the `.await`s on
    /// `relay_status`/`set_relay_status`/`emit_relays_changed`. Holding a
    /// `std::sync::Mutex` guard across an `.await` would be both a bug (a
    /// blocking lock parked across a suspension point) and exactly the
    /// TOCTOU hazard this type was chosen to close: two concurrent `Report`
    /// calls touching the same relay must never interleave their decisions,
    /// or one can act on a vote aggregate that's already stale by the time
    /// it writes the DB status, spuriously evicting a relay another gateway
    /// concurrently vouches for. Serializing the whole read-decide-write
    /// behind this async mutex makes each decision atomic with respect to
    /// the live vote map.
    relay_health: Arc<Mutex<HashMap<i64, HashMap<i64, bool>>>>,
    /// (Key-rotation Task 3) Ephemeral per-gateway rotation tracker, keyed by
    /// the ROTATING gateway's id: `RotationTracker { pending_epoch,
    /// prior_active_epoch, started_at, promoted_at, live_acks }`. Deliberately
    /// NOT threaded in from `AdminSvc::rotate_key` at rotation-start time —
    /// this crate uses a LAZY-REBUILD approach instead (see
    /// `SyncSvc::drive_rotation`'s doc comment): the first time a Report's
    /// `epoch_acks` or a `SubmitEpochKey` call touches a gateway that has a
    /// DB `pending` epoch but no entry here yet, one is constructed on the
    /// spot with `started_at = Instant::now()`. This is smaller than also
    /// threading a shared `Arc` into `AdminSvc` (which is constructed before
    /// the broker/registry exist in `lib.rs::serve`), and it gives correct
    /// crash-recovery behavior for free: a controller restart simply rebuilds
    /// every in-flight rotation's tracker (with a fresh grace/abort clock)
    /// from whatever `pending` rows are still in the DB, rather than losing
    /// track of them until an operator notices. `tokio::sync::Mutex` for the
    /// same reason as `relay_health` — the guard is held across `.await`
    /// points (DB reads/writes) in the read-decide-write critical section.
    rotations: Arc<Mutex<HashMap<i64, RotationTracker>>>,
    /// (Sync session generation) `gateway_id -> the per-BOOT nonce that
    /// gateway sent on its most recent `Sync.Watch` open`. Read by [`report`]
    /// to reject a `Sync.Report` from a gateway process that has since been
    /// replaced.
    ///
    /// # What this closes
    ///
    /// `Broker::on_gateway_connected` clears a reconnecting gateway's stored
    /// `peer_paths` (a restarted gateway may have no tunnel at all, so its
    /// stale "direct" claims must not suppress the punches it now needs). A
    /// `Report` issued by that gateway's PREVIOUS process, delayed on the
    /// network, could land after the clear and — being a snapshot — restore
    /// the pre-restart claims. Same shape for `local_endpoints` (the
    /// original instance of the race) and `relay_health`. With the
    /// generation recorded at Watch-open, such a report is identifiable and
    /// rejected synchronously, with no DB hop.
    ///
    /// # Deliberately NOT persisted, and deliberately NOT learned from a Report
    ///
    /// In-memory only. A controller restart empties it, which makes every
    /// gateway "unknown" (stored 0) and therefore ACCEPTED until its Watch
    /// reopens seconds later — the fail-open direction, chosen because the
    /// alternative degrades the whole fabric during the restart window (see
    /// the predicate in `report`).
    ///
    /// It is also never written from a `Report`, only from a Watch open. A
    /// report-write would let a stale report install the stale generation
    /// and then reject the FRESH reports that follow — strictly worse than
    /// the bug being fixed.
    ///
    /// # No eviction on stream drop
    ///
    /// Entries are overwritten, never removed. Removing on stream drop would
    /// be wrong twice over: the drop of a dying OLD connection can be
    /// observed after the NEW connection has already recorded its
    /// generation (erasing it), and keeping the entry across a momentary
    /// Watch outage is what lets the rotation tick's unary epoch-ack Report
    /// — which dials its own short-lived channel — still be accepted.
    ///
    /// A `std::sync::Mutex` (unlike the two above): the guard only ever
    /// spans a single synchronous map read or write and is never held across
    /// an `.await`. `Arc` so the map is shared regardless of whether tonic
    /// holds this service behind an `Arc` or clones it per request.
    sessions: Arc<std::sync::Mutex<HashMap<i64, u64>>>,
}

/// (Key-rotation Task 3) One gateway's in-flight rotation bookkeeping, kept
/// in memory only (never persisted — see [`SyncSvc::rotations`]'s doc
/// comment for the lazy-rebuild/crash-recovery story). Converted into a
/// [`RotationState`] fresh on every `drive_rotation` call, alongside a live
/// DB read for the real-key flag and the broker's live connected-peer set.
pub(crate) struct RotationTracker {
    pending_epoch: u32,
    prior_active_epoch: u32,
    started_at: Instant,
    promoted_at: Option<Instant>,
    live_acks: BTreeSet<u64>,
}

impl SyncSvc {
    pub fn new(
        db: DbHandle,
        change_tx: broadcast::Sender<ChangeEvent>,
        broker: Arc<Broker>,
    ) -> Self {
        Self {
            db,
            change_tx,
            broker,
            relay_health: Arc::new(Mutex::new(HashMap::new())),
            rotations: Arc::new(Mutex::new(HashMap::new())),
            sessions: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// (Sync session generation) Records `generation` as `gateway_id`'s
    /// current Sync session, overwriting any previous value. Called from
    /// [`SyncSvc::watch_gateway`] and NOWHERE else — see the
    /// [`SyncSvc::sessions`] doc for why a `Report` must never write here.
    ///
    /// A `generation` of 0 (a legacy gateway, or any client that does not
    /// implement the scheme) is recorded verbatim: it makes the gate inert
    /// for that gateway, which is exactly the intended legacy behavior.
    ///
    /// A poisoned lock is swallowed: the gate is an optimization over
    /// accepting everything, and turning a poisoned mutex into a failed
    /// `Watch` would take the fabric down over bookkeeping.
    fn record_session_generation(&self, gateway_id: i64, generation: u64) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.insert(gateway_id, generation);
        }
    }

    /// (Sync session generation) The generation currently recorded for
    /// `gateway_id`, or 0 for "unknown" — no Watch has been seen for it since
    /// this controller process started. A poisoned lock also reads as
    /// unknown, i.e. fail-open (accept), for the reason above.
    fn recorded_session_generation(&self, gateway_id: i64) -> u64 {
        self.sessions
            .lock()
            .ok()
            .and_then(|sessions| sessions.get(&gateway_id).copied())
            .unwrap_or(0)
    }

    /// (Sync session generation) THE gate. The single definition of the
    /// reject predicate, shared by every mutating gateway->controller RPC —
    /// currently `Sync.Report` and `Sync.SubmitEpochKey`. Deliberately one
    /// function rather than a copy per handler: this is a correctness-
    /// critical predicate whose two fail-open legs are easy to "simplify"
    /// away independently, and divergence between copies is precisely the
    /// failure class this program has been bitten by before. A new mutating
    /// RPC should call this, not re-derive it.
    ///
    /// Returns `Err(FAILED_PRECONDITION)` iff the caller's generation
    /// CONFLICTS with the one recorded at that gateway's current Watch open:
    ///
    /// ```text
    /// reject iff stored != 0 && req != 0 && stored != req
    /// ```
    ///
    /// The predicate is NOT "the values differ". Both zero-legs are
    /// load-bearing fail-opens:
    ///
    ///  - `req == 0` — a LEGACY client that does not implement the scheme.
    ///    It must keep working.
    ///  - `stored == 0` — UNKNOWN. `sessions` is in-memory, so after a
    ///    CONTROLLER restart every gateway reads 0 until its Watch reopens.
    ///    A plain `stored != req` would reject every call in that window:
    ///    candidate publication stops, the broker stops learning path
    ///    states, punches stop, epoch submissions fail — trading a narrow
    ///    correctness race for a broad availability outage. Unknown must
    ///    fail OPEN.
    ///
    /// This is also what fixes the gateway's nonce as necessarily NONZERO: 0
    /// is the wire's legacy/unknown sentinel (see `sync.proto` and
    /// `wiremesh_gateway::sync::session_generation`).
    ///
    /// `rpc` names the calling RPC for the log/status line only.
    fn check_session_generation(
        &self,
        gateway_id: i64,
        req_generation: u64,
        rpc: &str,
    ) -> Result<(), Status> {
        let stored = self.recorded_session_generation(gateway_id);
        if stored != 0 && req_generation != 0 && stored != req_generation {
            // One line per rejection. There is no Prometheus surface in this
            // crate, so the log IS the operator signal; both values are named
            // so a rejection can be tied to a specific gateway restart.
            eprintln!(
                "wiremesh-controller: rejecting {rpc} from gateway {gateway_id} — session \
                 generation {req_generation} does not match the generation {stored} recorded at \
                 its current Sync.Watch open; this call is from a previous gateway process"
            );
            return Err(Status::failed_precondition(format!(
                "{rpc} session_generation {req_generation} does not match the session_generation \
                 {stored} recorded for this gateway's current Sync.Watch; reconnect Watch before \
                 retrying"
            )));
        }
        Ok(())
    }

    /// (Cycle-4c Task 6; CodeRabbit round 3) Re-reads the current
    /// active-relay set + persisted revision as ONE atomic pair
    /// (`Db::relays_snapshot`, single lock hold) and publishes ONE
    /// `ChangeEvent::RelaysChanged` — the shared tail end of both the
    /// enrollment path (`EnrollmentSvc::enroll`'s relay-enrollment branch)
    /// and this file's health-driven eviction/re-admission path. Reading
    /// both fields under one lock hold (rather than two separate
    /// `active_relays()` + `current_revision()` calls, per the Cycle-4c
    /// Task 5 review fix) guarantees the revision attached to the emitted
    /// delta is consistent with the advertised `relays` — closing a race
    /// where a concurrent relay mutation committing between two separate
    /// reads could broadcast a stale relay set tagged with a newer revision
    /// (see `Db::relays_snapshot`'s doc comment) — so an open `Sync.Watch`
    /// stream never sees the revision regress relative to the relay set it
    /// just applied (see `projection.rs`). Best-effort: a failure reading
    /// the snapshot is silently swallowed (mirrors every other best-effort
    /// `change_tx.send` call in this crate — a transient DB read failure
    /// here must never turn an otherwise-successful `Report`/`Enroll` call
    /// into an error response), and `send` itself only ever errors when
    /// there are currently no `Sync.Watch` subscribers, which is not a
    /// failure either.
    async fn emit_relays_changed(&self) {
        if let Ok((active, revision)) = self.db.relays_snapshot().await {
            let relay_infos = active
                .into_iter()
                .map(|(id, endpoint)| wiremesh_proto::v1::RelayInfo {
                    relay_id: id as u64,
                    endpoint,
                })
                .collect();
            let _ = self
                .change_tx
                .send(ChangeEvent::RelaysChanged { relay_infos, revision });
        }
    }

    /// (Key-rotation Task 3) Runs one round of the ack-driven promote/retire/
    /// abort state machine for `rotating_gateway_id`: (re)builds a
    /// [`RotationState`] snapshot, calls [`rotation::decide`], and executes
    /// whatever it returns. Called from both `report` (after recording any
    /// `epoch_acks` targeting this gateway) and `submit_epoch_key` (a real
    /// key arriving may itself immediately satisfy an already-fully-acked
    /// rotation).
    ///
    /// LAZY-REBUILD: if `self.rotations` has no tracker for this gateway yet,
    /// one is constructed here — but ONLY if the DB currently shows a
    /// `pending` epoch for it; a gateway with no pending epoch has nothing in
    /// flight, so this is a no-op. See `SyncSvc::rotations`'s doc comment for
    /// why this (rather than seeding a tracker at `AdminSvc::rotate_key` time)
    /// is this crate's chosen approach.
    ///
    /// Best-effort: every DB error along the way is logged and swallowed
    /// rather than propagated, so a transient DB blip while driving a
    /// rotation never fails the CALLER's own RPC (a `Report` whose acks
    /// already recorded successfully, or a `SubmitEpochKey` whose real key
    /// already committed) — the next Report/SubmitEpochKey call simply
    /// re-drives the same decision.
    ///
    /// Locking note: this acquires `self.rotations` itself (a *second*,
    /// separate critical section from the one `report`'s `epoch_acks` block
    /// uses to record incoming acks) rather than being handed an
    /// already-held guard — `tokio::sync::Mutex` is not reentrant, so a
    /// single `drive_rotation` helper reusable from both `report` and
    /// `submit_epoch_key` cannot also be called while the caller still holds
    /// the same lock. `report`'s ack-recording block therefore fully
    /// completes (and releases the guard) before calling this per touched
    /// rotating gateway — still one continuous synchronous span with no
    /// intervening `.await` back out to the caller's caller, just not
    /// literally one unbroken lock hold across both phases.
    async fn drive_rotation(&self, rotating_gateway_id: i64) {
        drive_rotation_for(
            &self.db,
            &self.change_tx,
            &self.broker,
            &self.rotations,
            rotating_gateway_id,
        )
        .await;
    }

    /// (Key-rotation Task 4) A clone of this `SyncSvc`'s shared in-memory
    /// rotation-tracker map's `Arc` — `serve()` calls this once, right after
    /// constructing the `SyncSvc`, so the rotation-initiation timer and
    /// decision-sweep background tasks it spawns operate on the EXACT SAME
    /// map `Sync.Report`/`Sync.SubmitEpochKey` mutate through this service,
    /// rather than a second, independent map that would never see (or be
    /// seen by) `drive_rotation`'s lazy-rebuilds. See the `rotations` field's
    /// doc comment for why this crate uses one shared, lazily-populated map
    /// rather than threading trackers through `AdminSvc` at rotation-start
    /// time.
    pub(crate) fn rotations_handle(&self) -> Arc<Mutex<HashMap<i64, RotationTracker>>> {
        self.rotations.clone()
    }
}

/// (Key-rotation Task 4) Free-function core of [`SyncSvc::drive_rotation`],
/// extracted so both the tonic service methods (`report`/`submit_epoch_key`,
/// via the thin `SyncSvc::drive_rotation` wrapper above) AND the
/// [`sweep_rotations`] background task can run the exact same ack-driven
/// promote/retire/abort logic against the exact same shared `rotations` map,
/// without either side needing a `&SyncSvc` (the sweep task only ever holds
/// cloned handles — see `serve()`). Behavior is unchanged from the
/// pre-Task-4 `SyncSvc::drive_rotation` this was lifted out of verbatim; see
/// that method's (now much shorter) doc comment history in git blame for the
/// full design rationale (lazy-rebuild, locking discipline, best-effort error
/// handling) — none of it changed, only its home.
pub(crate) async fn drive_rotation_for(
    db: &DbHandle,
    change_tx: &broadcast::Sender<ChangeEvent>,
    broker: &Broker,
    rotations: &Arc<Mutex<HashMap<i64, RotationTracker>>>,
    rotating_gateway_id: i64,
) {
    let keys = match db.all_keys_for_gateway(rotating_gateway_id).await {
        Ok(k) => k,
        Err(e) => {
            eprintln!(
                "wiremesh-controller: drive_rotation_for({rotating_gateway_id}) failed reading \
                 keys: {e}"
            );
            return;
        }
    };

    let mut rotations = rotations.lock().await;

    if !rotations.contains_key(&rotating_gateway_id) {
        if let Some((pending_epoch, _, _)) = keys.iter().find(|(_, _, state)| state == "pending") {
            let prior_active_epoch = keys
                .iter()
                .find(|(_, _, state)| state == "active")
                .map(|(epoch, _, _)| *epoch as u32)
                .unwrap_or(0);
            rotations.insert(
                rotating_gateway_id,
                RotationTracker {
                    pending_epoch: *pending_epoch as u32,
                    prior_active_epoch,
                    started_at: Instant::now(),
                    promoted_at: None,
                    live_acks: BTreeSet::new(),
                },
            );
        }
    }

    let Some(tracker) = rotations.get(&rotating_gateway_id) else {
        // No DB `pending` epoch and no tracker already in flight (e.g. a
        // stray ack about a gateway that isn't currently rotating, or a
        // rotation whose retire already completed) — nothing to drive.
        return;
    };

    let pending_has_real_key = keys.iter().any(|(epoch, pubkey, state)| {
        *epoch as u32 == tracker.pending_epoch && state == "pending" && pubkey != "awaiting-submission"
    });

    let expected_peers: BTreeSet<u64> = broker
        .connected_gateway_ids()
        .into_iter()
        .filter(|id| *id != rotating_gateway_id)
        .map(|id| id as u64)
        .collect();

    let state = RotationState {
        pending_epoch: tracker.pending_epoch,
        pending_has_real_key,
        prior_active_epoch: tracker.prior_active_epoch,
        started_at: tracker.started_at,
        promoted_at: tracker.promoted_at,
        expected_peers,
        live_acks: tracker.live_acks.clone(),
    };

    match rotation::decide(&state, Instant::now()) {
        RotationDecision::Wait => {}
        RotationDecision::Promote { epoch } => match db.promote_epoch(rotating_gateway_id, epoch).await {
            Ok(()) => {
                if let Some(t) = rotations.get_mut(&rotating_gateway_id) {
                    t.promoted_at = Some(Instant::now());
                }
                if let Err(e) = projection::emit_key_rotated(db, change_tx, rotating_gateway_id).await {
                    eprintln!(
                        "wiremesh-controller: emit_key_rotated after promote({rotating_gateway_id}, \
                         {epoch}) failed: {e}"
                    );
                }
            }
            Err(e) => eprintln!(
                "wiremesh-controller: promote_epoch({rotating_gateway_id}, {epoch}) failed: {e}"
            ),
        },
        RotationDecision::Retire { epoch } => match db.retire_epoch(rotating_gateway_id, epoch).await {
            Ok(()) => {
                rotations.remove(&rotating_gateway_id);
                if let Err(e) = projection::emit_key_rotated(db, change_tx, rotating_gateway_id).await {
                    eprintln!(
                        "wiremesh-controller: emit_key_rotated after retire({rotating_gateway_id}, \
                         {epoch}) failed: {e}"
                    );
                }
            }
            Err(e) => eprintln!(
                "wiremesh-controller: retire_epoch({rotating_gateway_id}, {epoch}) failed: {e}"
            ),
        },
        RotationDecision::Abort { epoch, reason } => {
            match db.drop_pending_epoch(rotating_gateway_id, epoch).await {
                Ok(()) => {
                    rotations.remove(&rotating_gateway_id);
                    if let Err(e) = projection::emit_key_rotated(db, change_tx, rotating_gateway_id).await
                    {
                        eprintln!(
                            "wiremesh-controller: emit_key_rotated after abort({rotating_gateway_id}, \
                             {epoch}) failed: {e}"
                        );
                    }
                }
                Err(e) => eprintln!(
                    "wiremesh-controller: drop_pending_epoch({rotating_gateway_id}, {epoch}) \
                     (reason: {reason}) failed: {e}"
                ),
            }
        }
    }
}

/// (Key-rotation Task 4) The decision-sweep background task's per-tick body
/// (spawned by `serve()` at `Config::rotation_sweep_interval`, default 5s).
/// Ensures every in-flight rotation actually gets driven — and every
/// crash-orphaned `retiring` row eventually cleaned up — even with no
/// triggering `Sync.Report`/`Sync.SubmitEpochKey` call ever arriving again:
///
///   1. `db.gateways_with_rotation_state()` finds every gateway with a
///      `pending` or `retiring` `gateway_key` row — the population this
///      sweep needs to look at at all.
///   2. For a gateway with a `pending` row: lazily rebuild its
///      `RotationTracker` (fresh `started_at`) if none is currently held —
///      the same crash-recovery rebuild `drive_rotation_for` itself does —
///      then call `drive_rotation_for`, which fires grace-promote/abort/
///      retire via `rotation::decide` exactly as an ack-triggered call would.
///   3. For a gateway with a `retiring` row but NO in-memory tracker: this is
///      an ORPHANED row — the promote already committed and the tracker was
///      lost (e.g. a controller crash/restart in the 30s `RETIRE_GRACE`
///      window), so nothing will ever call `decide` for it again. Retire
///      (delete) it DIRECTLY here, without going through `decide` — this is
///      safe because the new epoch is already `active` (the promote that
///      created this `retiring` row already committed), and make-before-break
///      on the data plane keeps the peer's old `Device` alive until the
///      peer's own logic tears it down; there is no live tracker's grace
///      timer to respect since nothing is tracking one anymore. A `retiring`
///      row that DOES still have a live tracker is deliberately left alone
///      here — that one is `decide`'s (`RotationDecision::Retire`'s) job via
///      step 2 above, not this direct path's.
///
/// Keys are re-read fresh between steps 2 and 3 for a given gateway (rather
/// than reusing the step-1 snapshot) since step 2's `drive_rotation_for` call
/// may itself have just mutated this gateway's `gateway_key` rows.
pub(crate) async fn sweep_rotations(
    db: &DbHandle,
    change_tx: &broadcast::Sender<ChangeEvent>,
    broker: &Broker,
    rotations: &Arc<Mutex<HashMap<i64, RotationTracker>>>,
) {
    let gateway_ids = match db.gateways_with_rotation_state().await {
        Ok(ids) => ids,
        Err(e) => {
            eprintln!("wiremesh-controller: sweep_rotations failed reading rotation state: {e}");
            return;
        }
    };

    for gateway_id in gateway_ids {
        let keys = match db.all_keys_for_gateway(gateway_id).await {
            Ok(k) => k,
            Err(e) => {
                eprintln!(
                    "wiremesh-controller: sweep_rotations({gateway_id}) failed reading keys: {e}"
                );
                continue;
            }
        };

        // Step 2: a `pending` row — ensure a tracker exists, then drive the
        // real decision (grace-promote/abort).
        if let Some((pending_epoch, _, _)) = keys.iter().find(|(_, _, state)| state == "pending") {
            let pending_epoch = *pending_epoch as u32;
            {
                let mut guard = rotations.lock().await;
                if !guard.contains_key(&gateway_id) {
                    let prior_active_epoch = keys
                        .iter()
                        .find(|(_, _, state)| state == "active")
                        .map(|(epoch, _, _)| *epoch as u32)
                        .unwrap_or(0);
                    guard.insert(
                        gateway_id,
                        RotationTracker {
                            pending_epoch,
                            prior_active_epoch,
                            started_at: Instant::now(),
                            promoted_at: None,
                            live_acks: BTreeSet::new(),
                        },
                    );
                }
            }
            drive_rotation_for(db, change_tx, broker, rotations, gateway_id).await;
        }

        // Step 3: any `retiring` row(s) with NO in-memory tracker are
        // orphaned — re-read keys fresh (step 2 above may have just changed
        // them) before deciding what's still `retiring`.
        let keys = match db.all_keys_for_gateway(gateway_id).await {
            Ok(k) => k,
            Err(e) => {
                eprintln!(
                    "wiremesh-controller: sweep_rotations({gateway_id}) failed re-reading keys \
                     before orphan check: {e}"
                );
                continue;
            }
        };
        let retiring_epochs: Vec<u32> = keys
            .iter()
            .filter(|(_, _, state)| state == "retiring")
            .map(|(epoch, _, _)| *epoch as u32)
            .collect();
        if retiring_epochs.is_empty() {
            continue;
        }
        let has_tracker = rotations.lock().await.contains_key(&gateway_id);
        if has_tracker {
            // A live tracker still governs this gateway's retire timing via
            // `decide`'s RETIRE_GRACE — not this sweep's direct path.
            continue;
        }
        for epoch in retiring_epochs {
            match db.retire_epoch(gateway_id, epoch).await {
                Ok(()) => {
                    if let Err(e) = projection::emit_key_rotated(db, change_tx, gateway_id).await {
                        eprintln!(
                            "wiremesh-controller: emit_key_rotated after sweep-orphan-retire\
                             ({gateway_id}, {epoch}) failed: {e}"
                        );
                    }
                }
                Err(e) => eprintln!(
                    "wiremesh-controller: sweep_rotations orphaned-retiring retire_epoch\
                     ({gateway_id}, {epoch}) failed: {e}"
                ),
            }
        }
    }
}

/// (Key-rotation Task 4) The rotation-initiation timer background task's
/// per-tick body (spawned by `serve()` at `Config::rotation_interval`,
/// default 30 days — and NOT spawned at all when that is `None`, which is how
/// an operator disables automatic rotation; this is the only caller). For
/// every currently `active` gateway that is NOT
/// already mid-rotation (i.e. not present in
/// [`DbHandle::gateways_with_rotation_state`]), starts a fresh rotation via
/// `db.rotate_key` with no operator action at all, then publishes a
/// `KeyRotated` delta the same way `AdminSvc::rotate_key` does for an
/// explicit `Admin.RotateKey` call. A gateway already mid-rotation (a
/// `pending` or `retiring` row already on file) is deliberately skipped —
/// stacking a second rotation on top of an in-flight one would leave more
/// than one non-`active` epoch in flight at once, which nothing in this
/// crate's promote/retire/abort model is designed to reason about.
pub(crate) async fn initiate_due_rotations(db: &DbHandle, change_tx: &broadcast::Sender<ChangeEvent>) {
    let mid_rotation: std::collections::HashSet<i64> = match db.gateways_with_rotation_state().await {
        Ok(ids) => ids.into_iter().collect(),
        Err(e) => {
            eprintln!(
                "wiremesh-controller: initiate_due_rotations failed reading rotation state: {e}"
            );
            return;
        }
    };

    let active_ids = match db.active_gateway_ids().await {
        Ok(ids) => ids,
        Err(e) => {
            eprintln!("wiremesh-controller: initiate_due_rotations failed reading active gateways: {e}");
            return;
        }
    };

    for gateway_id in active_ids {
        if mid_rotation.contains(&gateway_id) {
            continue;
        }

        let now = match OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)
        {
            Ok(now) => now,
            Err(e) => {
                eprintln!("wiremesh-controller: initiate_due_rotations failed formatting current time: {e}");
                return;
            }
        };

        match db
            .rotate_key(gateway_id, "rotation-timer".to_string(), now)
            .await
        {
            Ok(_outcome) => {
                if let Err(e) = projection::emit_key_rotated(db, change_tx, gateway_id).await {
                    eprintln!(
                        "wiremesh-controller: emit_key_rotated after rotation-timer initiate\
                         ({gateway_id}) failed: {e}"
                    );
                }
            }
            Err(e) => eprintln!(
                "wiremesh-controller: initiate_due_rotations rotate_key({gateway_id}) failed: {e}"
            ),
        }
    }
}

/// Wraps the `Watch` response stream with its [`RegistrationGuard`] so the
/// connection's broker registry entry is removed exactly when the stream is
/// dropped (client disconnect, RPC end, or a dropped `Response`) — the guard
/// is a plain field, so it drops with the struct and no explicit deregister
/// call is needed. Poll is a straight delegation to the inner stream.
struct GuardedWatchStream {
    _guard: RegistrationGuard,
    inner: WatchStream,
}

impl Stream for GuardedWatchStream {
    type Item = Result<SyncMessage, Status>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

/// (Mesh-convergence T6) The two `Sync.Watch` code paths, split out of the
/// trait `watch` dispatcher below so a GATEWAY's full desired-state watch and
/// a RELAY's revocation-scoped watch share NOTHING structurally — in
/// particular the relay path never touches the punch broker or the rotation
/// machinery the gateway path wires up (see `watch_relay`'s doc comment for
/// the id-collision hazard that makes that separation load-bearing).
impl SyncSvc {
    /// A GATEWAY's `Sync.Watch`: the full desired-state stream (snapshot with
    /// peers + policy + relays, then live deltas + broker-driven punches).
    /// Behavior is byte-for-byte what the pre-T6 `watch` method did once the
    /// CN resolved to a gateway — only its home moved.
    ///
    /// `session_generation` is the client-supplied per-BOOT nonce from
    /// `WatchRequest` (see [`SyncSvc::sessions`]). It is NOT identity — the
    /// authenticated `gw` came from the mTLS peer cert — it only labels which
    /// process of that gateway this stream belongs to.
    async fn watch_gateway(
        &self,
        gw: GatewayIdentity,
        self_cert_pem: String,
        session_generation: u64,
    ) -> Result<Response<WatchStream>, Status> {
        // (Sync session generation) FIRST statement, and the ordering is
        // LOAD-BEARING — before `change_tx.subscribe()`, before
        // `broker.register`, and above all before the `tokio::spawn` of
        // `on_gateway_connected` (whose `clear_reported_states` is what this
        // whole mechanism exists to make STICK). Recorded any later and a
        // pre-restart `Report` landing in the window between the clear and
        // the record would still read a stale/absent generation, be accepted,
        // and re-install the very state the clear just removed — the race
        // would survive verbatim.
        self.record_session_generation(gw.id, session_generation);

        // Subscribe BEFORE building the snapshot. `build_snapshot` has
        // internal `await` points (each `DbHandle` call hops onto
        // `spawn_blocking`), so a `ChangeEvent` published in the window
        // between the snapshot's DB read and here would otherwise be LOST:
        // committed too late to appear in the snapshot, yet published before
        // a receiver existed to buffer it — the gateway would silently miss
        // that peer until its next reconnect. Subscribing first closes the
        // window: any event arriving during snapshot-building is buffered in
        // `rx` and delivered as a Delta right after the snapshot. At worst
        // that's a redundant upsert for a peer already in the snapshot
        // (whose Delta `revision` may even equal the snapshot's in the rare
        // overlap) — harmless, since `upserted_peers` is idempotent on the
        // client.
        let self_gateway_id = gw.id;
        let rx = self.change_tx.subscribe();

        // (Cycle-4b Task 5) The per-connection broker punch channel: the broker
        // pushes `SyncMessage{Punch}` here (keyed by this connection's
        // AUTHENTICATED gateway id), merged into the outgoing stream below
        // alongside the broadcast deltas. `guard`'s Drop deregisters this
        // channel when the stream ends (see `GuardedWatchStream`), so a
        // panic/early-return still cleans up the registry entry.
        let (punch_tx, punch_rx) = mpsc::channel::<SyncMessage>(PUNCH_CHANNEL_CAPACITY);
        let guard = self.broker.register(self_gateway_id, punch_tx);

        let snapshot = projection::build_snapshot(&self.db, gw.id, self_cert_pem)
            .await
            .map_err(|e| Status::internal(format!("building Sync snapshot: {e}")))?;

        let snapshot_msg = SyncMessage {
            body: Some(Body::Snapshot(snapshot)),
        };
        // First message on the stream is always the full snapshot (must
        // stay true — `tests/sync_snapshot.rs` asserts it). The stream then
        // stays OPEN: every subsequent projection-affecting mutation
        // published on `change_tx` (currently only gateway enrollment —
        // see `crate::services::enrollment`) is forwarded as a `Delta`,
        // for as long as this gRPC call is alive.
        // `lagged` latches once this connection's receiver falls behind the
        // broadcast channel's ring buffer: from that point on, the
        // gateway's view of the projection is provably INCOMPLETE (deltas
        // it never saw were dropped), so silently continuing (the old
        // behavior) would leave it stale indefinitely with no client-side
        // way to detect the gap. Instead, `map_while` below emits exactly
        // ONE final `Err(Unavailable)` item and then ends the stream (once
        // `lagged` is set, every subsequent poll returns `None`, which
        // `map_while` treats as end-of-stream) — tonic surfaces that `Err`
        // item as the RPC's final status, forcing the gateway to reconnect
        // and re-fetch a fresh, fully-consistent snapshot rather than
        // silently trusting a gapped delta stream.
        let mut lagged = false;
        let delta_stream = BroadcastStream::new(rx)
            .map_while(move |item| {
                if lagged {
                    return None;
                }
                match item {
                    Ok(event) => {
                        // A gateway must never receive a delta
                        // "adding"/"updating" itself as its own peer —
                        // skip it (`Some(None)`), but keep the stream open.
                        if event.subject_gateway_id() == self_gateway_id {
                            Some(None)
                        } else {
                            let delta = projection::delta_for_change(event);
                            Some(Some(Ok(SyncMessage {
                                body: Some(Body::Delta(delta)),
                            })))
                        }
                    }
                    Err(BroadcastStreamRecvError::Lagged(skipped)) => {
                        eprintln!(
                            "wiremesh-controller: Sync.Watch for gateway {self_gateway_id} lagged \
                             behind the change broadcast by {skipped} event(s); terminating the \
                             stream so the gateway reconnects and re-snapshots"
                        );
                        lagged = true;
                        Some(Some(Err(Status::unavailable(format!(
                            "Sync.Watch lagged behind the change broadcast by {skipped} event(s); \
                             reconnect to receive a fresh, consistent snapshot"
                        )))))
                    }
                }
            })
            .filter_map(|opt| opt);

        // (Cycle-4b Task 5) The per-connection punch stream, MERGED with the
        // broadcast deltas. `select!`-style fairness between {broadcast delta,
        // broker punch channel} is exactly what `StreamExt::merge` provides —
        // whichever has an item ready is yielded. The `Snapshot` stays the
        // guaranteed FIRST message (chained ahead of the merge), so existing
        // snapshot/delta/self-skip behavior is unchanged; punches are simply an
        // additional interleaved item type. Unlike deltas, a punch is NOT
        // subject to the `subject_gateway_id()` self-skip — the broker already
        // targeted THIS connection's channel explicitly.
        let punch_stream = ReceiverStream::new(punch_rx).map(Ok::<SyncMessage, Status>);
        let merged = delta_stream.merge(punch_stream);

        let inner: WatchStream =
            Box::pin(tokio_stream::once(Ok(snapshot_msg)).chain(merged));

        // (Cycle-4b Task 5) Trigger (a): now that this connection is registered,
        // give the broker a chance to punch any peer that is already connected
        // with a mutual candidate set. Spawned (not awaited) so building the
        // Watch response doesn't block on peer/candidate DB reads; the registry
        // insert above already happened, so the spawned task sees this
        // connection as present.
        let broker = self.broker.clone();
        tokio::spawn(async move {
            broker.on_gateway_connected(self_gateway_id).await;
        });

        let stream: WatchStream = Box::pin(GuardedWatchStream {
            _guard: guard,
            inner,
        });
        Ok(Response::new(stream))
    }

    /// (Mesh-convergence T6, ops-finding "Relay Finding B") The
    /// REVOCATION-SCOPED `Sync.Watch` an enrolled RELAY is authorized for —
    /// the fix for the finding's "the relay's revocation Sync watch is
    /// rejected by the controller" (its offline denylist never refreshing
    /// after enrollment).
    ///
    /// Structurally DISJOINT from [`SyncSvc::watch_gateway`]: a relay does not
    /// punch, does not `Report`, and does not rotate keys, so this path shares
    /// NONE of the gateway broker/rotation wiring. In particular it must NOT
    /// call `broker.register(..)` / `broker.on_gateway_connected(..)` — relay
    /// row ids and gateway row ids are SEPARATE sqlite sequences that DO
    /// collide (relay id 1 == gateway id 1), so registering a relay under its
    /// numeric id would pollute `Broker::connected_gateway_ids` (which
    /// rotation's expected-peer set reads) and mis-route a real gateway's
    /// `PunchDirective` channel. This method therefore never touches the
    /// broker at all, and there is no `RegistrationGuard` to drop.
    ///
    /// The stream opens with a revocation-only `StateSnapshot`
    /// ([`projection::build_relay_revocation_snapshot`] — empty peers/policy/
    /// relays) and thereafter forwards ONLY revocation-bearing deltas
    /// ([`projection::relay_revocation_delta`], which returns `None` for every
    /// peer/policy/relay-set/key-rotation event). Lag handling matches the
    /// gateway path: a receiver that falls behind the broadcast ring gets one
    /// terminal `Unavailable` and the stream ends, forcing a reconnect + fresh
    /// consistent revocation snapshot rather than a silently-gapped denylist.
    async fn watch_relay(
        &self,
        relay_id: i64,
        self_cert_pem: String,
    ) -> Result<Response<WatchStream>, Status> {
        // Subscribe BEFORE snapshotting for the same reason the gateway path
        // does (see `watch_gateway`): a revocation published in the window
        // between the snapshot's DB read and here must be buffered in `rx`,
        // not lost. At worst the relay sees a serial once in the snapshot and
        // again in a delta — harmless, its denylist is a set.
        let rx = self.change_tx.subscribe();

        let snapshot = projection::build_relay_revocation_snapshot(&self.db, self_cert_pem)
            .await
            .map_err(|e| Status::internal(format!("building relay revocation snapshot: {e}")))?;
        let snapshot_msg = SyncMessage {
            body: Some(Body::Snapshot(snapshot)),
        };

        let mut lagged = false;
        let delta_stream = BroadcastStream::new(rx)
            .map_while(move |item| {
                if lagged {
                    return None;
                }
                match item {
                    // Forward ONLY revocation-bearing events; every other
                    // event (peer upserts, policy, relay-set, key rotation)
                    // maps to `None` and is dropped here (`Some(None)` keeps
                    // the stream open). This is the delta-side security
                    // boundary — a relay never receives gateway desired-state
                    // (no `upserted_peers`/`removed_peer_ids`, no policy, and —
                    // since the broker/rotation channels are never wired up
                    // above — no `PunchDirective`/`RotateDirective` either).
                    Ok(event) => match projection::relay_revocation_delta(event) {
                        Some(delta) => Some(Some(Ok(SyncMessage {
                            body: Some(Body::Delta(delta)),
                        }))),
                        None => Some(None),
                    },
                    Err(BroadcastStreamRecvError::Lagged(skipped)) => {
                        eprintln!(
                            "wiremesh-controller: relay Sync.Watch (relay {relay_id}) lagged \
                             behind the change broadcast by {skipped} event(s); terminating the \
                             stream so the relay reconnects and re-snapshots its denylist"
                        );
                        lagged = true;
                        Some(Some(Err(Status::unavailable(format!(
                            "Sync.Watch lagged behind the change broadcast by {skipped} event(s); \
                             reconnect to receive a fresh, consistent snapshot"
                        )))))
                    }
                }
            })
            .filter_map(|opt| opt);

        // No broker registration, no punch stream, no `on_gateway_connected`
        // — see this method's doc comment. Nothing to guard on drop (there is
        // no registry entry), so the raw stream is returned directly.
        let inner: WatchStream =
            Box::pin(tokio_stream::once(Ok(snapshot_msg)).chain(delta_stream));
        Ok(Response::new(inner))
    }
}

#[tonic::async_trait]
impl Sync for SyncSvc {
    type WatchStream = WatchStream;

    /// Authorizes and dispatches a `Sync.Watch`. Identity comes EXCLUSIVELY
    /// from the mTLS peer cert's subject CN (see `peer_identity`): a gateway's
    /// CN is a `gateway.name`; a relay's is `relay-<secret_hash_hex>` == its
    /// `relay.name` (see `services::enrollment`). Resolve GATEWAY first (the
    /// common case — full desired-state watch); on a miss, try RELAY
    /// (revocation-scoped watch — ops-finding "Relay Finding B": before T6 the
    /// relay's watch was rejected outright and its offline denylist never
    /// refreshed post-enrollment). Only a CN that matches NEITHER is denied.
    async fn watch(
        &self,
        request: Request<WatchRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let (identity_cn, self_cert_pem) = peer_identity(&request)?;
        // (Sync session generation) Read before dispatch; passed ONLY to the
        // gateway path. `watch_relay` deliberately never sees it — a relay
        // never calls `Sync.Report`, so there is no per-relay reported state
        // a stale report could corrupt, and relay row ids collide with
        // gateway row ids (see `watch_relay`'s doc comment), so recording one
        // under a relay id would corrupt a real gateway's entry.
        let session_generation = request.get_ref().session_generation;

        if let Some(gw) = self
            .db
            .find_gateway_by_name(identity_cn.clone())
            .await
            .map_err(|e| Status::internal(format!("looking up gateway by cert CN: {e}")))?
        {
            return self.watch_gateway(gw, self_cert_pem, session_generation).await;
        }

        if let Some(relay_id) = self
            .db
            .find_relay_by_name(identity_cn)
            .await
            .map_err(|e| Status::internal(format!("looking up relay by cert CN: {e}")))?
        {
            return self.watch_relay(relay_id, self_cert_pem).await;
        }

        Err(Status::permission_denied(
            "client certificate's CN does not match any enrolled gateway or relay",
        ))
    }

    async fn report(
        &self,
        request: Request<ReportRequest>,
    ) -> Result<Response<ReportResponse>, Status> {
        let (gateway_name, _self_cert_pem) = peer_identity(&request)?;

        let gw = self
            .db
            .find_gateway_by_name(gateway_name)
            .await
            .map_err(|e| Status::internal(format!("looking up gateway by cert CN: {e}")))?
            .ok_or_else(|| {
                Status::permission_denied(
                    "client certificate's CN does not match any enrolled gateway",
                )
            })?;

        let req = request.into_inner();

        // (Sync session generation) The gate, evaluated after the gateway is
        // authenticated and BEFORE any state this handler writes. It covers
        // the WHOLE handler deliberately — `Broker::on_report`,
        // `set_applied_version`, `set_local_candidates` (+ its
        // `EndpointObserved` publish), the relay-health pipeline, and the
        // epoch-ack pipeline all consume the same request, and
        // `local_endpoints` is the ORIGINAL instance of this stale-report
        // race (see `Broker::on_report`'s note).
        //
        // The predicate itself (and why it is not simply "the values
        // differ") lives in ONE place — see `check_session_generation`.
        self.check_session_generation(gw.id, req.session_generation, "Sync.Report")?;

        // (Directive-storm fix) Record this gateway's per-peer path states
        // FIRST — before `set_local_candidates` below can publish an
        // `EndpointObserved` — so a single Report carrying BOTH a candidate
        // change and settled `peer_paths` has its states already stored by
        // the time the broker's candidate-change trigger runs, and the
        // both-settled skip applies to that very trigger (a candidate change
        // must never bypass the skip). `peer_paths_snapshot` distinguishes a
        // new client's full-map snapshot (REPLACE, empty clears) from the
        // legacy upsert-only shape where empty is a no-op (old client /
        // rotation-tick epoch ack) — see `Broker::on_report`. Async since
        // round 4: on the rare settled→unsettled EDGE the broker also resets
        // the pair's budget and emits an immediate synchronized punch pair
        // from here (see `Broker::on_report`'s edge doc); the store update
        // itself remains a cheap synchronous map write, so the steady-state
        // Report path still costs nothing.
        self.broker
            .on_report(gw.id, &req.peer_paths, req.peer_paths_snapshot)
            .await;

        self.db
            .set_applied_version(gw.id, req.applied_version)
            .await
            .map_err(|e| Status::internal(format!("recording applied_version: {e}")))?;

        // (Cycle-4b Task 8, spec §5/§6.1 — supersedes the Task 4 "empty is a
        // no-op" behavior) The gateway now reports its COMPLETE current
        // local-address set on every `Report` call (there is no per-endpoint
        // add/remove RPC — see `wiremesh_gateway::sync::report`'s doc
        // comment). An empty `local_endpoints` is therefore no longer
        // ambiguous ("didn't report" vs. "reported nothing"): it means the
        // gateway genuinely has no routable local address right now, and
        // must REPLACE (clear) any previously-reported set the same way a
        // non-empty report replaces a different non-empty set —
        // `Db::set_local_candidates`'s full-REPLACE contract already handles
        // this uniformly, so the call is no longer conditioned on
        // non-emptiness.
        let revision = self
            .db
            .set_local_candidates(gw.id, req.local_endpoints)
            .await
            .map_err(|e| Status::internal(format!("recording local_endpoints: {e}")))?;

        // `None` means the deduplicated incoming set was IDENTICAL to
        // what's already stored (see `Db::set_local_candidates`'s doc
        // comment) — nothing changed, so there is nothing new for an
        // already-connected peer to learn; skip the publish entirely
        // (mirrors `crate::observe::handle_probe`'s identical early-return
        // on an unchanged observed endpoint).
        if let Some(revision) = revision {
            // Re-reads the gateway's current identity/allowed_ips/keys and
            // its FULL current candidate set (observed + locals) — same
            // "full peer refresh" pattern `crate::observe::handle_probe`
            // already uses for the sibling `EndpointObserved` event, reused
            // as-is here since its `Delta` shape already carries
            // `candidate_endpoints` straight off `Db::candidates_for` (see
            // that event's doc comment).
            if let Ok(Some(identity)) = self.db.gateway_identity_by_id(gw.id).await {
                if let (Ok(allowed_ips), Ok(keys), Ok(candidate_endpoints)) = (
                    self.db.cidrs_for_segment(identity.segment_id).await,
                    self.db.all_keys_for_gateway(gw.id).await,
                    self.db.candidates_for(gw.id).await,
                ) {
                    let _ = self.change_tx.send(ChangeEvent::EndpointObserved {
                        gateway_id: gw.id,
                        segment_name: identity.segment_name,
                        allowed_ips,
                        keys,
                        candidate_endpoints,
                        revision,
                    });
                }
            }
        }

        // (Cycle-4c Task 6, R-3; TOCTOU fix) Relay health pipeline: aggregate
        // this gateway's votes into the shared `relay_id -> (gw_id ->
        // healthy)` map, then for every relay THIS report touched, compare
        // the fresh aggregate (healthy-override: a relay is unhealthy iff it
        // has >=1 vote on record and NONE of them is `true`) against its
        // current DB status, flipping + tracking a change where they now
        // differ. This runs synchronously on the `Report` call that tips the
        // aggregate, so eviction/re-admission is trivially inside the 15s
        // R-3 budget.
        //
        // The `tokio::sync::Mutex` guard is acquired ONCE and held across
        // this entire block — the vote-map mutation AND every touched
        // relay's DB read-decide-write AND the final emit. This is
        // deliberate: holding the lock only around the synchronous map
        // update (as a `std::sync::Mutex` would force) leaves a window
        // between "compute aggregate" and "write DB status" where a
        // concurrent `Report` on the same relay could tip the true
        // aggregate the other way, and the first call would still write its
        // now-stale verdict — spuriously evicting a relay another gateway
        // currently vouches for. Serializing the whole read-decide-write
        // behind one held guard means no two `Report` calls can interleave
        // their decisions for the same relay: each verdict is computed from
        // the live map at the moment it's about to be written.
        if !req.relay_health.is_empty() {
            let mut health = self.relay_health.lock().await;

            let mut touched = Vec::with_capacity(req.relay_health.len());
            for vote in &req.relay_health {
                let relay_id = vote.relay_id as i64;
                health
                    .entry(relay_id)
                    .or_default()
                    .insert(gw.id, vote.healthy);
                if !touched.contains(&relay_id) {
                    touched.push(relay_id);
                }
            }

            let mut any_changed = false;
            for relay_id in touched {
                // Recomputed from the LIVE map at decision time (not a
                // pre-snapshotted value) — the guard has been held
                // continuously since the mutation above, so this is exactly
                // the current aggregate.
                let votes = health
                    .get(&relay_id)
                    .expect("relay_id just inserted above must have an entry in the map");
                let healthy_agg = votes.values().any(|&h| h);

                let current_status = self
                    .db
                    .relay_status(relay_id)
                    .await
                    .map_err(|e| Status::internal(format!("reading relay status: {e}")))?;
                let Some(current_status) = current_status else {
                    // Unknown relay id (e.g. a stale report about a relay
                    // row that no longer exists) — nothing to flip.
                    continue;
                };
                let desired_status = if healthy_agg { "active" } else { "inactive" };
                if current_status != desired_status {
                    self.db
                        .set_relay_status(relay_id, desired_status.to_string())
                        .await
                        .map_err(|e| Status::internal(format!("flipping relay status: {e}")))?;
                    any_changed = true;
                }
            }

            if any_changed {
                self.emit_relays_changed().await;
            }
            // `health` (the guard) drops here, at the very end of the
            // block — only now can another `Report` call's relay-health
            // block proceed.
        }

        // (Key-rotation Task 3) Ack-driven rotation pipeline. Per the ack
        // direction rule (see `.superpowers/sdd/task-3-brief.md`): an
        // `EpochAck{peer_gateway_id, epoch, live}` sent by THIS reporting
        // gateway (`gw.id`) means "I (`gw.id`) have a live WireGuard session
        // with the ROTATING gateway `peer_gateway_id`'s epoch `epoch` key" —
        // so the ack advances `peer_gateway_id`'s tracker, recording that
        // `gw.id` has acked, not the other way around.
        //
        // The `rotations` guard is held across this whole ack-recording
        // loop (one critical section: read tracker-or-lazily-create-it,
        // then mutate `live_acks`) so two concurrent `Report` calls acking
        // the same rotating gateway can't interleave their inserts. It is
        // then released BEFORE calling `drive_rotation` per touched
        // rotating gateway below — see `drive_rotation`'s doc comment for
        // why a single reusable helper can't also be called while this
        // block still holds the same non-reentrant lock.
        if !req.epoch_acks.is_empty() {
            let mut touched_rotating_gateways: Vec<i64> = Vec::new();
            {
                let mut rotations = self.rotations.lock().await;
                for ack in &req.epoch_acks {
                    let rotating_id = ack.peer_gateway_id as i64;

                    if !rotations.contains_key(&rotating_id) {
                        if let Ok(keys) = self.db.all_keys_for_gateway(rotating_id).await {
                            if let Some((pending_epoch, _, _)) =
                                keys.iter().find(|(_, _, state)| state == "pending")
                            {
                                let prior_active_epoch = keys
                                    .iter()
                                    .find(|(_, _, state)| state == "active")
                                    .map(|(epoch, _, _)| *epoch as u32)
                                    .unwrap_or(0);
                                rotations.insert(
                                    rotating_id,
                                    RotationTracker {
                                        pending_epoch: *pending_epoch as u32,
                                        prior_active_epoch,
                                        started_at: Instant::now(),
                                        promoted_at: None,
                                        live_acks: BTreeSet::new(),
                                    },
                                );
                            }
                        }
                    }

                    if let Some(tracker) = rotations.get_mut(&rotating_id) {
                        if ack.epoch == tracker.pending_epoch && ack.live {
                            tracker.live_acks.insert(gw.id as u64);
                        }
                    }

                    if !touched_rotating_gateways.contains(&rotating_id) {
                        touched_rotating_gateways.push(rotating_id);
                    }
                }
                // `rotations` (the guard) drops here.
            }

            for rotating_id in touched_rotating_gateways {
                self.drive_rotation(rotating_id).await;
            }
        }

        Ok(Response::new(ReportResponse {}))
    }

    /// (Key-rotation Task 2) A gateway submits the REAL WireGuard public key
    /// it generated for a pending rotation epoch — the private key never
    /// leaves the gateway, only the pubkey travels on the wire. Identity is
    /// resolved exactly as `report`/`watch` do: the mTLS peer certificate's
    /// subject CN, looked up against `gateway.name`, never anything
    /// client-supplied in the request body.
    ///
    /// [`crate::db::Db::set_epoch_pubkey`] does the actual overwrite (and
    /// only succeeds for a genuinely pending, sentinel-holding epoch row —
    /// see its doc comment); its "no pending epoch" failure is mapped to
    /// `FailedPrecondition` (the caller asked for something that isn't
    /// true right now, not a caller-identity or internal-server problem),
    /// any other DB error to `Internal`. On success, the shared
    /// `emit_key_rotated` helper (also used by `AdminSvc::rotate_key`)
    /// re-reads the gateway's full key set and fans out a
    /// `ChangeEvent::KeyRotated` so already-connected peers immediately see
    /// the now-real key instead of the sentinel.
    async fn submit_epoch_key(
        &self,
        request: Request<SubmitEpochKeyRequest>,
    ) -> Result<Response<SubmitEpochKeyResponse>, Status> {
        let (gateway_name, _self_cert_pem) = peer_identity(&request)?;

        let gw = self
            .db
            .find_gateway_by_name(gateway_name)
            .await
            .map_err(|e| Status::internal(format!("looking up gateway by cert CN: {e}")))?
            .ok_or_else(|| {
                Status::permission_denied(
                    "client certificate's CN does not match any enrolled gateway",
                )
            })?;

        let req = request.into_inner();

        // (Sync session generation) Same gate, same predicate, same
        // fail-open legs as `report` — and NOT belt-and-braces.
        // `Db::set_epoch_pubkey` is a compare-and-swap that only ever
        // overwrites the `awaiting-submission` sentinel, so a stale
        // submission cannot clobber a real key; but it CAN WIN that swap.
        // With a submission in flight across a gateway restart,
        // `Broker::send_rotate_if_pending` re-issues a `RotateDirective` for
        // the still-sentinel epoch, the new process mints a DIFFERENT key
        // and submits it under the same epoch, and whichever lands first
        // wins — the pre-restart one usually, since it was sent first. The
        // controller would then advertise a pubkey the restarted gateway is
        // not serving on that epoch's tun; no peer could ack it, and
        // `rotation::decide` rule 4 promotes on the grace timeout REGARDLESS
        // of ack state, so the wrong key goes `active` rather than the
        // rotation aborting (see `docs/research/key-rotation-teardown-notes.md`
        // §E). Gating here makes the FRESH submission the one that wins.
        self.check_session_generation(gw.id, req.session_generation, "Sync.SubmitEpochKey")?;

        self.db
            .set_epoch_pubkey(gw.id, req.epoch, req.pubkey)
            .await
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("no pending epoch") {
                    Status::failed_precondition(msg)
                } else {
                    Status::internal(format!("submitting epoch key: {e}"))
                }
            })?;

        projection::emit_key_rotated(&self.db, &self.change_tx, gw.id).await?;

        // (Key-rotation Task 3) A real key arriving may itself immediately
        // satisfy an already-fully-acked rotation (e.g. peers acked the
        // still-sentinel epoch's eventual real key before this submission —
        // though in practice a peer can't have a live WG session with a
        // sentinel, so this mainly matters once acks and submission race).
        // Drive the same decide-and-execute `report`'s `epoch_acks` block
        // uses.
        self.drive_rotation(gw.id).await;

        Ok(Response::new(SubmitEpochKeyResponse {}))
    }
}

/// Extracts the calling gateway's identity from the mTLS session: the
/// subject CN of the FIRST certificate in the peer's chain (the leaf the
/// gateway presented), plus that same certificate re-PEM-encoded as
/// `self_cert_pem` for the snapshot. This is the security-critical
/// identity-extraction path this task's brief calls out — identity comes
/// exclusively from the certificate rustls/tonic already cryptographically
/// verified chains to the CA (`ServerTlsConfig::client_ca_root`, configured
/// in `serve()`); nothing in `request`'s message body or metadata is
/// consulted.
///
/// `Request::peer_certs()` is documented by tonic as returning `Some` only
/// for TLS-enabled server connections that actually negotiated a client
/// cert — since `serve()` configures Sync's listener with
/// `client_auth_optional` left at its default `false`, tonic/rustls refuse
/// the handshake itself for a certless client, so in practice this is
/// never `None` by the time a request reaches here. It's still handled as a
/// hard authentication failure rather than `.expect()`-ing, in case a
/// future refactor of the TLS config ever loosens that guarantee.
fn peer_identity<T>(request: &Request<T>) -> Result<(String, String), Status> {
    let certs = request.peer_certs().ok_or_else(|| {
        Status::unauthenticated(
            "Sync requires a client certificate chaining to the fabric CA (mTLS handshake \
             did not yield one)",
        )
    })?;
    let leaf = certs.first().ok_or_else(|| {
        Status::unauthenticated("Sync client presented an empty certificate chain")
    })?;

    let (_, cert) = x509_parser::parse_x509_certificate(leaf)
        .map_err(|e| Status::internal(format!("parsing peer certificate: {e}")))?;
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .ok_or_else(|| Status::permission_denied("peer certificate has no subject CN"))?;

    Ok((cn.to_string(), der_to_pem(leaf)))
}

/// Re-encodes raw certificate DER bytes as a PEM `CERTIFICATE` block
/// (RFC 7468: 64-character base64 lines).
fn der_to_pem(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 output is always ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}
