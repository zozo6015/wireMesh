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
use crate::db::{is_usable_candidate_endpoint, CasOutcome, DropPendingOutcome, GatewayIdentity};
use crate::db_async::DbHandle;
use crate::projection::{self, ChangeEvent};
use crate::rotation::{self, RotationDecision, RotationState};

pub type WatchStream = Pin<Box<dyn Stream<Item = Result<SyncMessage, Status>> + Send + 'static>>;

/// (Backlog item 1) The maximum number of locally-reported candidate
/// endpoints the controller will store for one gateway
/// (`ReportRequest.local_endpoints`).
///
/// **Why a cap exists at all.** `local_endpoints` is `repeated string` with
/// no constraint and nothing overrides tonic's 4MB `max_decoding_message_size`
/// — roughly 200k strings — every one of which would be persisted, fanned out
/// to every other gateway in every snapshot and delta, and run through
/// [`crate::db::Db::candidates_for`]'s O(n²) `Vec::contains` dedup. One
/// authenticated gateway must not get to choose how much work the controller
/// and all of its peers do.
///
/// **Why 32.** A local candidate is one `ip:wg_port` per routable local IPv4
/// address (`wiremesh_gateway::netif`: one per `inet` line, loopback and
/// link-local filtered, all at the single WG port). A real segment gateway has
/// 1-4; a container host with extra bridges is still in the single digits. 32
/// is about an order of magnitude of headroom over the honest worst case while
/// staying small enough that both the quadratic dedup and the per-peer fanout
/// stay free — and well under what a NAT puncher could work through anyway,
/// since it must try candidates in sequence against a bounded punch window.
pub const MAX_LOCAL_CANDIDATES: usize = 32;

/// How many rejected endpoints are quoted in the filter's log line, and how
/// many bytes of each. The offending strings are attacker-chosen and can be
/// megabytes long and arbitrarily numerous, so a log that quoted them all
/// would just relocate the flood into the controller's stderr. Quoted with
/// `{:?}`, which escapes the newlines a UAPI-injection payload carries.
const REJECTED_SAMPLE_COUNT: usize = 3;
const REJECTED_SAMPLE_BYTES: usize = 64;

/// (Backlog item 1) Reduce one gateway's reported `local_endpoints` to the
/// set the fabric can actually use: entries [`is_usable_candidate_endpoint`]
/// accepts, deduplicated, bounded by [`MAX_LOCAL_CANDIDATES`].
///
/// `SocketAddrV4` (not `SocketAddr`) is the same predicate the controller
/// already applies to a relay's endpoint at both registration paths
/// (`services::enrollment::enroll`, `services::admin::register_relay`) and
/// the same one `wiremesh_gateway::uapi::validate_ipv4_endpoint` applies at
/// the far end of this data's journey — which is the point. What the
/// controller stores here it re-advertises verbatim as
/// `Peer.candidate_endpoints` to every OTHER gateway, where it becomes
/// `PeerState::primary_endpoint()` and is written to the WireGuard UAPI. An
/// entry that fails the parse there is not a degraded peer: `encode_set`'s
/// `Err` unwinds out of `apply_state` past both loops in the gateway's
/// `run()` and exits the process, on every peer at once. A stock gateway
/// cannot emit garbage (`netif::local_wg_endpoints` formats from an
/// already-parsed `Ipv4Addr`); the threat is a compromised or version-skewed
/// gateway holding a valid fabric-CA cert.
///
/// FILTER, never reject. `Sync.Report` still returns `Ok`: the same request
/// also carries `applied_version`, `peer_paths`, `relay_health` and
/// `epoch_acks`, and failing it over one bad address string would wedge
/// rotation and path state too. A gateway that got one of four addresses
/// wrong keeps the other three rather than losing its direct path outright.
/// A report whose entries are ALL unusable therefore filters to empty, which
/// `Db::set_local_candidates`' full-REPLACE contract CLEARS — deliberately
/// the same as an explicitly-empty report (cycle-4b Task 8), and the only
/// party it costs is the gateway that sent it.
fn usable_local_candidates(gateway_id: i64, gateway_name: &str, reported: Vec<String>) -> Vec<String> {
    let mut kept: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut rejected = 0usize;
    let mut samples: Vec<String> = Vec::new();
    let mut over_cap = 0usize;

    for ep in reported {
        if !is_usable_candidate_endpoint(&ep) {
            rejected += 1;
            if samples.len() < REJECTED_SAMPLE_COUNT {
                let mut end = REJECTED_SAMPLE_BYTES.min(ep.len());
                while end > 0 && !ep.is_char_boundary(end) {
                    end -= 1;
                }
                samples.push(format!("{:?}", &ep[..end]));
            }
            continue;
        }
        // Dedup BEFORE the cap so the bound counts DISTINCT candidates: a
        // gateway repeating one address must not eat the whole budget.
        // `set_local_candidates` dedups again (it sorts first), so this is
        // about what the cap means, not about the stored shape.
        if !seen.insert(ep.clone()) {
            continue;
        }
        if kept.len() == MAX_LOCAL_CANDIDATES {
            over_cap += 1;
            continue;
        }
        kept.push(ep);
    }

    if rejected > 0 {
        eprintln!(
            "wiremesh-controller: gateway {gateway_name:?} (id {gateway_id}) reported {rejected} \
             local endpoint(s) that are not IPv4 ip:port and were DROPPED (kept {}); a stock \
             gateway cannot produce these, so this is a compromised or version-skewed peer. \
             First {}: {}",
            kept.len(),
            samples.len(),
            samples.join(", ")
        );
    }
    if over_cap > 0 {
        eprintln!(
            "wiremesh-controller: gateway {gateway_name:?} (id {gateway_id}) reported \
             {} distinct valid local endpoints, over the {MAX_LOCAL_CANDIDATES} cap; the \
             {over_cap} beyond it were DROPPED",
            kept.len() + over_cap
        );
    }

    kept
}

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
    /// The instant THIS tracker instance was inserted into the shared map.
    ///
    /// Deliberately a separate field from `started_at` even though every
    /// insertion site currently stamps both with the same `Instant::now()`.
    /// They answer different questions and must be free to diverge:
    /// `started_at` is the ROTATION's clock (what `rotation::decide`'s
    /// `GRACE_PROMOTE`/`ABORT_AFTER` measure from, and something a future
    /// change could legitimately seed from a persisted rotation start), while
    /// `installed_at` is the identity/ordering stamp for THIS in-memory
    /// instance. It is read by exactly two things, both of which would be
    /// silently wrong if it ever tracked the rotation rather than the entry:
    ///
    ///  - [`evict_decision`], to refuse to evict a tracker that is NEWER than
    ///    the DB snapshot the caller is arbitrating with;
    ///  - [`TrackerToken`], to tell "the same tracker I read" apart from "a
    ///    fresh tracker rebuilt toward the same epoch number while I was
    ///    awaiting".
    installed_at: Instant,
}

/// May a held [`RotationTracker`] be evicted, given a `gateway_key` snapshot
/// that was read at `read_at`?
///
/// # Two independent reasons to KEEP, both load-bearing
///
/// **`db_pending == None` is an unconditional keep.** "Live tracker, no
/// `pending` row" IS the stranded-post-promote state, and that tracker still
/// owes a [`RotationDecision::Retire`] for its prior active epoch
/// `RETIRE_GRACE` after the promote. A plain
/// `Some(tracker_pending) != db_pending` evicts there, which hands the retire
/// to [`sweep_rotations`]' step-3 orphan path — and that path deletes
/// IMMEDIATELY, with no grace at all. The 30s `RETIRE_GRACE` would collapse to
/// ~0 on every normal rotation, cutting off every peer still finishing a
/// handshake on the old key. The `None`-means-keep asymmetry is the whole
/// reason this is a named function rather than an inline `!=`.
///
/// **A tracker installed AFTER `read_at` is an unconditional keep.** The keys
/// snapshot is read with the `rotations` guard RELEASED (it is an awaited
/// `spawn_blocking` DB hop — see [`drive_rotation_for`]'s locking discipline),
/// so a rotation can start, and install its tracker, while the caller is
/// awaiting. That tracker is newer than the caller's knowledge of the DB, so
/// the caller's `db_pending` cannot arbitrate it: evicting on that evidence
/// tears down a rotation that has only just begun, discarding its acks (they
/// fail the `ack.epoch == tracker.pending_epoch` test in [`SyncSvc::report`])
/// and restarting its `started_at`.
fn evict_decision(
    tracker_pending: u32,
    tracker_installed_at: Instant,
    db_pending: Option<u32>,
    read_at: Instant,
) -> bool {
    let Some(db_pending) = db_pending else {
        // Stranded post-promote: this tracker still owes a Retire.
        return false;
    };
    if tracker_installed_at > read_at {
        // Newer than the snapshot that would be used to condemn it.
        return false;
    }
    tracker_pending != db_pending
}

/// The full identity of ONE [`RotationTracker`] instance. The gateway id it is
/// keyed by is NOT enough — see [`tracker_write_back`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TrackerToken {
    pending_epoch: u32,
    installed_at: Instant,
}

impl TrackerToken {
    fn of(tracker: &RotationTracker) -> Self {
        Self {
            pending_epoch: tracker.pending_epoch,
            installed_at: tracker.installed_at,
        }
    }
}

/// Whether a conclusion computed from a [`RotationTracker`] read under the
/// guard, then `.await`ed on with the guard RELEASED, may still be written
/// back onto the entry now under the guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteBack {
    /// Same tracker instance — the write-back is about the thing it was
    /// computed for.
    Apply,
    /// A DIFFERENT tracker instance now occupies the slot: a newer rotation
    /// started (or a lazy rebuild ran) while the caller was awaiting.
    Replaced,
    /// The entry is gone entirely — the rotation was retired or aborted while
    /// the caller was awaiting.
    Vanished,
}

/// May a deferred write-back into `rotations[gateway_id]` still be applied?
///
/// # The bug this exists to prevent
///
/// [`drive_rotation_for`] executes its decision (a DB mutation plus
/// `emit_key_rotated`) with the `rotations` guard RELEASED, then re-takes it to
/// apply the in-memory effect. Matching on the gateway id alone, a blind
/// `promoted_at = Some(..)` / `remove(..)` there lands on whatever entry
/// happens to be in the slot — which, for a rotation that started during the
/// gap, is a brand-new tracker. A blind `remove` would delete it (discarding
/// the new rotation's acks and clock); a blind `promoted_at` would credit one
/// rotation's promote to another, and `decide`'s rule 1 would then short-
/// circuit the new rotation straight into a `Retire` of the wrong epoch.
///
/// Both axes of the token matter independently: the epoch alone misses a
/// rebuild toward the SAME epoch number, and the install instant alone misses
/// a same-instant replacement. This mirrors
/// `wiremesh_gateway::rotation::overlap_write_back`, which solves the
/// identical bug class one crate over.
///
/// On anything but [`WriteBack::Apply`] the correct action is to leave the
/// entry alone and log: the next sweep tick re-reads it and drives it from
/// scratch.
fn tracker_write_back(taken: TrackerToken, current: Option<TrackerToken>) -> WriteBack {
    match current {
        None => WriteBack::Vanished,
        Some(cur) if cur == taken => WriteBack::Apply,
        Some(_) => WriteBack::Replaced,
    }
}

/// The in-memory effect [`drive_rotation_for`] applies to a tracker AFTER its
/// decision's DB mutation has committed — gated by [`tracker_write_back`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrackerEffect {
    /// The promote committed: stamp `promoted_at` so `decide`'s rule 1 starts
    /// the `RETIRE_GRACE` clock.
    Promoted,
    /// The rotation is over (retired or aborted): drop the tracker, which also
    /// hands any remaining `retiring` rows to [`sweep_rotations`]' orphan path.
    Finished,
    /// (task #32) The abort's CAS came back a confirmed
    /// [`DropPendingOutcome::RowAbsent`]: the `pending` row this tracker names
    /// does not exist, so the rotation it describes is over and the tracker is
    /// WEDGED — it can never satisfy its own abort, [`evict_decision`]'s
    /// `None`-means-keep leg will never clear it, and the gateway has no
    /// `pending`/`retiring` row so [`sweep_rotations`] cannot even see it. Drop
    /// it — but ONLY if it is still unpromoted.
    ///
    /// That extra condition is the whole safety argument for removing on a
    /// bail, and it must be re-checked HERE rather than assumed from the
    /// decision: `RotationDecision::Abort` is only produced for a tracker with
    /// `promoted_at == None` (`decide`'s rule 2), which is why such a tracker
    /// owns no live `retiring` row of its own — but the guard was RELEASED
    /// across the CAS, and a concurrent driver's promote can commit AND stamp
    /// `promoted_at` inside that window. Removing the tracker then discards a
    /// `RotationDecision::Retire` that is owed `RETIRE_GRACE` from now and
    /// hands a SECONDS-OLD `retiring` row to `sweep_rotations`' step-3 orphan
    /// path, which deletes grace-free. That is the same 30s-to-~0 collapse
    /// `evict_decision`'s `None` leg and both `Err` arms below exist to
    /// prevent; do not "simplify" this into a plain [`Self::Finished`].
    ///
    /// (task #32, round 2) Note precisely WHICH window this covers, because it
    /// is the narrower of two and it is not the primary defence. It catches a
    /// racing promote whose in-memory WRITE-BACK has already landed. It cannot
    /// catch one whose DB COMMIT has landed but whose write-back has not — the
    /// promote arm commits to SQLite across a `spawn_blocking` hop and only
    /// then re-takes the guard, so `promoted_at` is genuinely still `None`
    /// there. That wider window is closed one layer down, by
    /// [`DropPendingOutcome`] reporting whether the row SURVIVED the failed
    /// DELETE; this variant is only reached once that already said the row is
    /// absent. Belt and braces — keep both.
    FinishedIfUnpromoted,
}

/// Re-takes the `rotations` guard and applies `effect` to `gateway_id`'s
/// tracker IFF it is still the same instance `taken` names.
///
/// NO `.await` inside the guard — `clippy::await_holding_lock` does not fire
/// for `tokio::sync::MutexGuard`, so this discipline is held by construction
/// and by comment, not by the linter.
async fn apply_tracker_effect(
    rotations: &Arc<Mutex<HashMap<i64, RotationTracker>>>,
    gateway_id: i64,
    taken: TrackerToken,
    effect: TrackerEffect,
) {
    let mut guard = rotations.lock().await;
    let current = guard.get(&gateway_id).map(TrackerToken::of);
    match tracker_write_back(taken, current) {
        WriteBack::Apply => match effect {
            TrackerEffect::Promoted => {
                if let Some(t) = guard.get_mut(&gateway_id) {
                    t.promoted_at = Some(Instant::now());
                }
            }
            TrackerEffect::Finished => {
                guard.remove(&gateway_id);
            }
            TrackerEffect::FinishedIfUnpromoted => {
                if guard
                    .get(&gateway_id)
                    .is_some_and(|t| t.promoted_at.is_some())
                {
                    eprintln!(
                        "wiremesh-controller: rotation tracker for gateway {gateway_id} promoted \
                         while its abort was executing — keeping it so its Retire still runs \
                         under RETIRE_GRACE"
                    );
                } else {
                    guard.remove(&gateway_id);
                }
            }
        },
        WriteBack::Replaced => eprintln!(
            "wiremesh-controller: rotation tracker for gateway {gateway_id} was replaced while \
             its {effect:?} decision was executing (a newer rotation started) — leaving the new \
             tracker alone; the next sweep tick re-drives it"
        ),
        WriteBack::Vanished => eprintln!(
            "wiremesh-controller: rotation tracker for gateway {gateway_id} vanished while its \
             {effect:?} decision was executing — nothing to write back"
        ),
    }
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
///
/// # Locking discipline (read before editing)
///
/// This function takes the `rotations` guard TWICE and holds NO `.await`
/// inside either hold:
///
///  1. **Read the DB first, unlocked.** `all_keys_for_gateway` is a
///     `spawn_blocking` hop. "Read the pending epoch fresh under the lock" is
///     not merely awkward, it is the held-across-I/O problem itself — every
///     concurrent `Report`, `SubmitEpochKey` and sweep tick for EVERY gateway
///     would queue behind one gateway's DB read. `read_at` is stamped
///     immediately before that read so [`evict_decision`] knows exactly how
///     old the resulting snapshot is.
///  2. **Guard held, purely synchronous:** evict-if-it-disagrees, lazily
///     rebuild, build the [`RotationState`], call [`rotation::decide`], and
///     take a [`TrackerToken`] naming the exact tracker instance the decision
///     was computed from. Then drop the guard.
///  3. **Execute the decision unlocked** — the DB mutation plus
///     `emit_key_rotated`.
///  4. **Re-take the guard** and apply the in-memory effect only if the token
///     still matches ([`apply_tracker_effect`]).
///
/// `clippy::await_holding_lock` does NOT fire for `tokio::sync::MutexGuard`,
/// so nothing mechanically enforces step 2 and step 4's "no `.await` inside" —
/// it is held by construction and by this comment.
///
/// # Why executing unlocked is SAFE: the DB writes are compare-and-swap
///
/// Because the guard is released across the mutation, two drivers (a sweep
/// tick and an ack-triggered `Report`, say) can reach the same decision
/// concurrently. That is contained entirely by
/// [`Db::promote_epoch`](crate::db::Db::promote_epoch),
/// [`Db::retire_epoch`](crate::db::Db::retire_epoch) and
/// [`Db::drop_pending_epoch`](crate::db::Db::drop_pending_epoch) being
/// state-guarded CAS that report a zero-row match — [`CasOutcome::NoMatch`],
/// or one of [`DropPendingOutcome`]'s two zero-row variants — when the row is
/// not in the state the decision assumed: the loser logs and writes nothing,
/// and the in-memory effect is gated behind the "it committed" variant. **If
/// anyone ever "simplifies" those three into unconditional `UPDATE`/`DELETE`s
/// that silently affect zero rows — or folds a zero-row match in with the
/// committed case — this whole design becomes unsafe**: a stale decision would
/// then appear to succeed and the tracker would be mutated to match a DB state
/// that never happened.
///
/// # (task #32) A confirmed bail is not a DB error, and the two differ per arm
///
/// A zero-row match and `Err` used to be the same value here (both an `anyhow`
/// `Err`), which forced the conservative rule "never react". They are now
/// distinct, and the tracker disposition is:
///
/// ```text
///            committed   zero rows                      Err(_)
/// Promote     stamp       keep                           keep
/// Retire      remove      keep                           keep
/// Abort       remove      remove* if the row is ABSENT   keep
///                         keep    if the row SURVIVED
/// ```
///
/// The whole `Err` column stays `keep`: a transient DB error is evidence of
/// nothing, and a removed tracker hands any live `retiring` row to
/// [`sweep_rotations`]' grace-free step-3 orphan path.
///
/// `Retire`'s zero-row cell also stays `keep`, deliberately: a `Retire` tracker
/// HAS promoted, so it lacks `Abort`'s safety argument entirely, and a lost
/// retire CAS self-heals anyway — the driver that WON it removes the tracker
/// through its own [`TrackerToken`].
///
/// The `Abort` row is the fix, and it is the only cell that splits on WHY the
/// CAS matched nothing. `RowAbsent` means the rotation is over and left no
/// `retiring` row; `RowSuperseded` means a concurrent promote won and there is
/// now a seconds-old `retiring` row this tracker is the only thing shielding.
/// [`DropPendingOutcome`] carries that distinction because in-memory state
/// cannot: the promoter commits before it re-takes the guard. `remove*` is
/// conditional even then — see [`TrackerEffect::FinishedIfUnpromoted`].
pub(crate) async fn drive_rotation_for(
    db: &DbHandle,
    change_tx: &broadcast::Sender<ChangeEvent>,
    broker: &Broker,
    rotations: &Arc<Mutex<HashMap<i64, RotationTracker>>>,
    rotating_gateway_id: i64,
) {
    // Stamped BEFORE the read, not after: `evict_decision` needs the earliest
    // instant at which `keys` could possibly be true, so that any tracker
    // installed during the await is unambiguously newer than this snapshot.
    let read_at = Instant::now();
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

    // The DB's current `pending` epoch for this gateway, if any — read off
    // the `keys` snapshot already in hand, so the staleness check below
    // costs no extra query.
    let db_pending_epoch: Option<u32> = keys
        .iter()
        .find(|(_, _, state)| state == "pending")
        .map(|(epoch, _, _)| *epoch as u32);

    // --- Critical section 1: decide. NO `.await` below until the drop. ---
    let plan = {
        let mut rotations = rotations.lock().await;

        // (Second-rotation stranded tracker; see
        // `docs/research/second-rotation-stranded-tracker.md`) Evict a tracker
        // that is talking about a DIFFERENT rotation than the one the DB
        // currently has pending — the predicate, and the two reasons it is
        // asymmetric rather than a plain `!=`, live in `evict_decision`.
        if rotations
            .get(&rotating_gateway_id)
            .is_some_and(|t| evict_decision(t.pending_epoch, t.installed_at, db_pending_epoch, read_at))
        {
            rotations.remove(&rotating_gateway_id);
        }

        if !rotations.contains_key(&rotating_gateway_id) {
            if let Some(pending_epoch) = db_pending_epoch {
                let prior_active_epoch = keys
                    .iter()
                    .find(|(_, _, state)| state == "active")
                    .map(|(epoch, _, _)| *epoch as u32)
                    .unwrap_or(0);
                let now = Instant::now();
                rotations.insert(
                    rotating_gateway_id,
                    RotationTracker {
                        pending_epoch,
                        prior_active_epoch,
                        started_at: now,
                        promoted_at: None,
                        live_acks: BTreeSet::new(),
                        installed_at: now,
                    },
                );
            }
        }

        // No DB `pending` epoch and no tracker already in flight (e.g. a
        // stray ack about a gateway that isn't currently rotating, or a
        // rotation whose retire already completed) — nothing to drive, and in
        // particular nothing here may touch a `retiring` row: that genuinely
        // trackerless case belongs to `sweep_rotations`' orphan path.
        rotations.get(&rotating_gateway_id).map(|tracker| {
            let pending_has_real_key = keys.iter().any(|(epoch, pubkey, state)| {
                *epoch as u32 == tracker.pending_epoch
                    && state == "pending"
                    && pubkey != "awaiting-submission"
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

            (
                rotation::decide(&state, Instant::now()),
                TrackerToken::of(tracker),
            )
        })
        // The guard drops here, before any `.await` below.
    };
    let Some((decision, taken)) = plan else {
        return;
    };

    // --- Execute, guard RELEASED. ---
    match decision {
        RotationDecision::Wait => {}
        RotationDecision::Promote { epoch } => match db.promote_epoch(rotating_gateway_id, epoch).await {
            Ok(CasOutcome::Applied) => {
                apply_tracker_effect(rotations, rotating_gateway_id, taken, TrackerEffect::Promoted)
                    .await;
                if let Err(e) = projection::emit_key_rotated(db, change_tx, rotating_gateway_id).await {
                    eprintln!(
                        "wiremesh-controller: emit_key_rotated after promote({rotating_gateway_id}, \
                         {epoch}) failed: {e}"
                    );
                }
            }
            // A CONFIRMED bail. Another driver reached the same decision first
            // (or the epoch is no longer a real-keyed `pending` row at all).
            // The loser must NOT stamp `promoted_at` — that is the "stale
            // decision mutating the tracker to match a DB state that never
            // happened" this function's locking discussion warns about — and
            // must not remove the tracker either: if the winner promoted, the
            // tracker it left behind is the only thing holding the new
            // `retiring` row's grace open.
            Ok(CasOutcome::NoMatch) => eprintln!(
                "wiremesh-controller: promote_epoch({rotating_gateway_id}, {epoch}) matched no \
                 row (another driver got there first, or the epoch is no longer a real-keyed \
                 pending row) — leaving the tracker alone"
            ),
            Err(e) => eprintln!(
                "wiremesh-controller: promote_epoch({rotating_gateway_id}, {epoch}) failed: {e}"
            ),
        },
        RotationDecision::Retire { epoch } => match db.retire_epoch(rotating_gateway_id, epoch).await {
            Ok(CasOutcome::Applied) => {
                apply_tracker_effect(rotations, rotating_gateway_id, taken, TrackerEffect::Finished)
                    .await;
                if let Err(e) = projection::emit_key_rotated(db, change_tx, rotating_gateway_id).await {
                    eprintln!(
                        "wiremesh-controller: emit_key_rotated after retire({rotating_gateway_id}, \
                         {epoch}) failed: {e}"
                    );
                }
            }
            // DO NOT "clean up" the tracker on EITHER of the two arms below —
            // and note they are now genuinely different things (task #32 made
            // `retire_epoch` return the distinction this comment used to ask
            // for), yet the verdict is the same for both:
            //
            //  - `NoMatch` is a CONFIRMED bail, but unlike the `Abort` arm's
            //    this one gets no safety argument: a tracker that reached
            //    `Retire` HAS promoted (`decide`'s rule 1), so it may well own
            //    a live `retiring` row, and it can own an OLDER one besides.
            //    It also needs no removal — whichever driver WON the CAS
            //    removes the tracker through its own `TrackerToken`.
            //  - `Err` is evidence of nothing at all; the next sweep tick
            //    retries.
            //
            // A removed tracker hands any live `retiring` row straight to
            // `sweep_rotations`' step-3 orphan path, which deletes grace-free.
            // That collapses `RETIRE_GRACE` from 30s to ~0 on a normal
            // rotation. Leaving the tracker in place costs one retry on the
            // next sweep tick; removing it costs make-before-break. See
            // `evict_decision`, whose `None`-means-keep leg exists for the same
            // reason and IS unit-pinned.
            Ok(CasOutcome::NoMatch) => eprintln!(
                "wiremesh-controller: retire_epoch({rotating_gateway_id}, {epoch}) matched no row \
                 (another driver retired it first) — leaving the tracker alone"
            ),
            Err(e) => eprintln!(
                "wiremesh-controller: retire_epoch({rotating_gateway_id}, {epoch}) failed: {e}"
            ),
        },
        RotationDecision::Abort { epoch, reason } => {
            match db.drop_pending_epoch(rotating_gateway_id, epoch).await {
                Ok(DropPendingOutcome::Dropped) => {
                    apply_tracker_effect(
                        rotations,
                        rotating_gateway_id,
                        taken,
                        TrackerEffect::Finished,
                    )
                    .await;
                    if let Err(e) = projection::emit_key_rotated(db, change_tx, rotating_gateway_id).await
                    {
                        eprintln!(
                            "wiremesh-controller: emit_key_rotated after abort({rotating_gateway_id}, \
                             {epoch}) failed: {e}"
                        );
                    }
                }
                // (task #32) THE FIX. A CONFIRMED bail whose row is GONE: the
                // `pending` row this tracker names does not exist, so the
                // rotation it describes is over and the tracker is WEDGED —
                // `decide` hands it this same unsatisfiable `Abort` on every
                // tick, `evict_decision`'s `None`-means-keep leg never clears
                // it, and the gateway is invisible to `sweep_rotations` (no
                // `pending`/`retiring` rows). The cost lands on the NEXT
                // rotation, which loses its first — and, per Role-B cutover,
                // only — ack to `report`'s `ack.epoch ==
                // tracker.pending_epoch` check and silently falls back to the
                // 90s grace promote.
                //
                // Safe to remove because an aborting tracker has `promoted_at
                // == None` (`decide`'s rule 2), so it owns no live `retiring`
                // row of its own. A row from an EARLIER rotation may still be
                // present — but this decision required `ABORT_AFTER` (300s) to
                // have elapsed since `started_at`, and any such row predates
                // that, so its 30s `RETIRE_GRACE` expired 10x over. The one
                // window where that reasoning does NOT hold — a concurrent
                // promote whose write-back lands inside this arm's own await —
                // is what `FinishedIfUnpromoted` re-checks under the guard.
                Ok(DropPendingOutcome::RowAbsent) => {
                    eprintln!(
                        "wiremesh-controller: drop_pending_epoch({rotating_gateway_id}, {epoch}) \
                         (reason: {reason}) matched no row and the row is GONE — this rotation \
                         is over; dropping its wedged tracker"
                    );
                    apply_tracker_effect(
                        rotations,
                        rotating_gateway_id,
                        taken,
                        TrackerEffect::FinishedIfUnpromoted,
                    )
                    .await;
                }
                // (task #32, round 2) The SAME confirmed bail, the opposite
                // meaning — and the reason `DropPendingOutcome` exists. The row
                // is still on file, so a concurrent PROMOTE beat this abort:
                // `promote_epoch` flipped this epoch to `active` and demoted
                // the prior active epoch to `retiring` in one transaction. That
                // `retiring` row is SECONDS old and owed the full
                // `RETIRE_GRACE`, and this tracker is both the only thing that
                // will ever retire it under grace (`decide` rule 1) and the
                // only thing making `sweep_rotations` step 3 skip this gateway
                // instead of taking its deliberately grace-free orphan delete.
                // So: KEEP it.
                //
                // `FinishedIfUnpromoted` cannot catch this and is not a second
                // line of defence for it — the promoter COMMITS to SQLite
                // before it re-takes the guard, so `promoted_at` is genuinely
                // still `None` at this instant. Only the durable row state,
                // read inside the failed DELETE's own transaction, can see the
                // committed promote regardless of write-back timing.
                //
                // Keeping is self-healing rather than merely cautious: a
                // promote mutates neither `pending_epoch` nor `installed_at`,
                // so the promoter's `TrackerToken` still matches this instance,
                // its write-back returns `WriteBack::Apply` and stamps
                // `promoted_at`, and `decide` rule 1 then yields `Wait` until
                // the grace elapses and `Retire` after — never this
                // unsatisfiable `Abort` again.
                Ok(DropPendingOutcome::RowSuperseded { state }) => eprintln!(
                    "wiremesh-controller: drop_pending_epoch({rotating_gateway_id}, {epoch}) \
                     (reason: {reason}) matched no row, but the row is still on file as \
                     '{state}' — a concurrent promote won this race, so the rotation \
                     SUCCEEDED rather than ended; keeping the tracker so the retire it now \
                     owes runs under RETIRE_GRACE"
                ),
                // Do NOT remove the tracker on this `Err`. A transient DB error
                // is evidence of nothing — the rotation may well still be in
                // flight — and the removal is what reaches the grace-free
                // orphan path, taking any EARLIER rotation's still-live
                // `retiring` row with it.
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
///   2. For a gateway with a `pending` row: first evict any held
///      `RotationTracker` whose `pending_epoch` disagrees with that row (a
///      previous rotation's stranded tracker — see
///      `docs/research/second-rotation-stranded-tracker.md`), then lazily
///      rebuild its `RotationTracker` (fresh `started_at`) if none is
///      currently held — the same check-and-evict plus crash-recovery
///      rebuild `drive_rotation_for` itself does.
///   2b. Then call `drive_rotation_for` for EVERY gateway in the step-1 set,
///      `pending` row or not, which fires grace-promote/abort/retire via
///      `rotation::decide` exactly as an ack-triggered call would.
///
///      **This unconditional call is the fix for the stranded promoted
///      tracker.** It used to live inside step 2's `if let Some(pending)`,
///      which meant a tracker with `promoted_at = Some` — a rotation that has
///      already promoted, so it has no `pending` row left, only a `retiring`
///      one — was reachable by NOTHING: not by step 2 (no pending row), not by
///      step 3 (it still holds a tracker), and not by `report` (the gateway
///      acks exactly once per Role-B cutover, so no further Report carries a
///      non-empty `epoch_acks`). `decide`'s rule 1 is the ONLY producer of
///      `RotationDecision::Retire`, so the `retiring` row was stranded on disk
///      forever — and because `Db::gateways_with_rotation_state` selects
///      `state IN ('pending','retiring')` and `initiate_due_rotations` skips
///      every id it returns, that one row excluded its gateway from the
///      rotation timer PERMANENTLY. Automatic rotation was self-disabling
///      after a single round. Running the driver for the whole step-1 set
///      costs one extra `all_keys_for_gateway` per mid-rotation gateway per
///      tick and closes it; for a gateway with neither tracker nor pending row
///      `drive_rotation_for` returns immediately, leaving step 3 untouched.
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
/// Keys are re-read fresh between steps 2b and 3 for a given gateway (rather
/// than reusing the step-1 snapshot) since step 2b's `drive_rotation_for` call
/// may itself have just mutated this gateway's `gateway_key` rows. That
/// re-read is also what makes the multi-`retiring`-row case CONVERGE in a
/// single tick: after two rotations a gateway can hold two `retiring` rows
/// (epoch 0 from rotation 1, epoch 1 from rotation 2) while the surviving
/// tracker knows only epoch 1 as its `prior_active_epoch`. Step 2b drives that
/// tracker to `Retire { epoch: 1 }` and removes it; the re-read then sees
/// epoch 0 still `retiring` with NO tracker held, so step 3's orphan path
/// takes it in the very same iteration.
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
        // Stamped before the read for the same reason as in
        // `drive_rotation_for`: `evict_decision` must be able to tell a
        // tracker installed DURING this await apart from one that predates
        // the snapshot it would be condemned by.
        let read_at = Instant::now();
        let keys = match db.all_keys_for_gateway(gateway_id).await {
            Ok(k) => k,
            Err(e) => {
                eprintln!(
                    "wiremesh-controller: sweep_rotations({gateway_id}) failed reading keys: {e}"
                );
                continue;
            }
        };

        // Step 2: a `pending` row — ensure a tracker exists. (`drive_rotation_for`
        // does the identical evict-and-rebuild from its own fresher read, but
        // doing it here too is what keeps a gateway holding BOTH a `pending`
        // and a `retiring` row shielded from step 3's immediate, grace-free
        // orphan path if that call's DB read happens to fail.)
        if let Some((pending_epoch, _, _)) = keys.iter().find(|(_, _, state)| state == "pending") {
            let pending_epoch = *pending_epoch as u32;
            let mut guard = rotations.lock().await;
            // (Second-rotation stranded tracker) Same check-and-evict as
            // `drive_rotation_for`, through the same `evict_decision` — same
            // reason, same `None`-means-keep-it asymmetry, same
            // installed-after-the-read protection. Held under the SAME guard
            // as the rebuild immediately below so no concurrent `report` can
            // observe (or re-ack into) the evicted-but-not-yet-rebuilt
            // window, and with NO `.await` anywhere inside the hold.
            if guard.get(&gateway_id).is_some_and(|t| {
                evict_decision(t.pending_epoch, t.installed_at, Some(pending_epoch), read_at)
            }) {
                guard.remove(&gateway_id);
            }
            if !guard.contains_key(&gateway_id) {
                let prior_active_epoch = keys
                    .iter()
                    .find(|(_, _, state)| state == "active")
                    .map(|(epoch, _, _)| *epoch as u32)
                    .unwrap_or(0);
                let now = Instant::now();
                guard.insert(
                    gateway_id,
                    RotationTracker {
                        pending_epoch,
                        prior_active_epoch,
                        started_at: now,
                        promoted_at: None,
                        live_acks: BTreeSet::new(),
                        installed_at: now,
                    },
                );
            }
        }

        // Step 2b: drive the real decision for EVERY gateway in the step-1
        // set — deliberately NOT nested inside the `pending`-row branch
        // above. A promoted rotation has no `pending` row and its tracker's
        // `Retire` is produced by nothing else; see this function's doc
        // comment. `tokio::sync::Mutex` is not reentrant, so this must run
        // with the step-2 guard already dropped (it is — the `if let` block
        // above ends first).
        drive_rotation_for(db, change_tx, broker, rotations, gateway_id).await;

        // Step 3: any `retiring` row(s) with NO in-memory tracker are
        // orphaned — re-read keys fresh before deciding what's still
        // `retiring`. The re-read is load-bearing, not defensive: step 2b just
        // above may have retired a row AND removed its tracker in this same
        // iteration, and that is exactly how two stranded rows converge in one
        // tick (2b takes the newest, step 3 then sees the older one with no
        // tracker held).
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
        // This path is INTENTIONALLY grace-free, and must stay that way.
        //
        // It is reached only when no tracker exists, which means one of:
        // a controller restart lost the in-memory tracker (crash recovery — the
        // row is arbitrarily old and its grace expired long ago), or step 2b
        // just retired a newer epoch and removed its tracker, leaving an OLDER
        // row behind (whose grace also elapsed, by construction, since it was
        // stranded by a promote that happened before the one 2b just handled).
        //
        // Adding a grace here looks like the obvious fix if you arrive from a
        // failing two-row convergence test, and it is wrong twice over: it
        // delays crash recovery for no benefit, and it silently converts a
        // deterministic single-tick convergence into a timing-dependent one.
        // The grace that matters is enforced by `decide` rule 1 while a tracker
        // is alive; by the time control reaches here, there is no tracker whose
        // clock could still be running.
        for epoch in retiring_epochs {
            match db.retire_epoch(gateway_id, epoch).await {
                Ok(CasOutcome::Applied) => {
                    if let Err(e) = projection::emit_key_rotated(db, change_tx, gateway_id).await {
                        eprintln!(
                            "wiremesh-controller: emit_key_rotated after sweep-orphan-retire\
                             ({gateway_id}, {epoch}) failed: {e}"
                        );
                    }
                }
                // Nothing was deleted and the revision did not move, so there
                // is nothing to publish: a concurrent driver retired this row
                // between the re-read above and this CAS.
                Ok(CasOutcome::NoMatch) => {}
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
            // Cloned rather than moved: `gateway_name` is the authenticated
            // cert CN, and `usable_local_candidates` below names it in the
            // log line that reports a peer sending unusable endpoints — an
            // id alone would not tell an operator which gateway to go fix.
            .find_gateway_by_name(gateway_name.clone())
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
        //
        // (Backlog item 1) `local_endpoints` is the one genuinely
        // remote-supplied, free-form value on this surface, and whatever is
        // stored here is re-advertised verbatim to every other gateway and
        // written to their WireGuard UAPI. Filter it to what is actually
        // dialable BEFORE it is persisted — see `usable_local_candidates`
        // for the predicate, the cap, and why this filters rather than
        // rejecting the RPC.
        let local_endpoints = usable_local_candidates(gw.id, &gateway_name, req.local_endpoints);
        let revision = self
            .db
            .set_local_candidates(gw.id, local_endpoints)
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
        // The `rotations` guard is held across the whole ack-recording pass
        // (ONE critical section: tracker-or-lazily-create-it, then mutate
        // `live_acks`) so two concurrent `Report` calls acking the same
        // rotating gateway can't interleave their inserts. It is then
        // released BEFORE calling `drive_rotation` per touched rotating
        // gateway below — see `drive_rotation`'s doc comment for why a single
        // reusable helper can't also be called while this block still holds
        // the same non-reentrant lock.
        //
        // The DB read the lazy create needs is deliberately hoisted OUT of
        // that critical section and out of the per-ack loop. It used to sit
        // inside both: `all_keys_for_gateway` is a `spawn_blocking` hop, so
        // the guard — shared by every gateway's rotation, the sweep tick and
        // every concurrent Report — was parked across one gateway's DB read,
        // once per ack. Hoisting it also dedupes the read per distinct
        // rotating gateway rather than repeating it per ack. The record pass
        // itself is NOT split: both the create and the `live_acks.insert`
        // still happen under one continuous hold.
        if !req.epoch_acks.is_empty() {
            // Distinct rotating gateway ids, in first-seen order.
            let mut touched_rotating_gateways: Vec<i64> = Vec::new();
            for ack in &req.epoch_acks {
                let rotating_id = ack.peer_gateway_id as i64;
                if !touched_rotating_gateways.contains(&rotating_id) {
                    touched_rotating_gateways.push(rotating_id);
                }
            }

            // Unlocked: one read per distinct rotating gateway, reduced to
            // the `(pending_epoch, prior_active_epoch)` seed a lazy create
            // needs. `None` — no `pending` row, or the read failed — means
            // "do not create a tracker for this one", exactly as before.
            let mut seeds: Vec<(i64, Option<(u32, u32)>)> =
                Vec::with_capacity(touched_rotating_gateways.len());
            for &rotating_id in &touched_rotating_gateways {
                let seed = match self.db.all_keys_for_gateway(rotating_id).await {
                    Ok(keys) => keys
                        .iter()
                        .find(|(_, _, state)| state == "pending")
                        .map(|(pending_epoch, _, _)| {
                            let prior_active_epoch = keys
                                .iter()
                                .find(|(_, _, state)| state == "active")
                                .map(|(epoch, _, _)| *epoch as u32)
                                .unwrap_or(0);
                            (*pending_epoch as u32, prior_active_epoch)
                        }),
                    Err(_) => None,
                };
                seeds.push((rotating_id, seed));
            }

            {
                // ONE critical section, NO `.await` inside it.
                let mut rotations = self.rotations.lock().await;

                for (rotating_id, seed) in &seeds {
                    if rotations.contains_key(rotating_id) {
                        continue;
                    }
                    if let Some((pending_epoch, prior_active_epoch)) = *seed {
                        let now = Instant::now();
                        rotations.insert(
                            *rotating_id,
                            RotationTracker {
                                pending_epoch,
                                prior_active_epoch,
                                started_at: now,
                                promoted_at: None,
                                live_acks: BTreeSet::new(),
                                installed_at: now,
                            },
                        );
                    }
                }

                for ack in &req.epoch_acks {
                    let rotating_id = ack.peer_gateway_id as i64;
                    if let Some(tracker) = rotations.get_mut(&rotating_id) {
                        if ack.epoch == tracker.pending_epoch && ack.live {
                            tracker.live_acks.insert(gw.id as u64);
                        }
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
    /// see its doc comment); its [`CasOutcome::NoMatch`] is mapped to
    /// `FailedPrecondition` (the caller asked for something that isn't
    /// true right now, not a caller-identity or internal-server problem),
    /// any DB error to `Internal`. On success, the shared
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

        let epoch = req.epoch;
        match self.db.set_epoch_pubkey(gw.id, epoch, req.pubkey).await {
            Ok(CasOutcome::Applied) => {}
            // (task #32) A CONFIRMED bail, read off the typed outcome rather
            // than grepped out of the error text: the caller asked for
            // something that isn't true right now (no such epoch, or its
            // sentinel has already been filled in by a submission that won the
            // swap). `FailedPrecondition` tells the gateway's client code to
            // stop retrying a submission that can never land.
            Ok(CasOutcome::NoMatch) => {
                return Err(Status::failed_precondition(format!(
                    "SubmitEpochKey: no pending epoch {epoch} awaiting a key submission for \
                     gateway {}",
                    gw.id
                )))
            }
            // A genuine DB failure, which IS worth retrying — and which the
            // old `msg.contains("no pending epoch")` check would have
            // reclassified the moment anyone reworded that `bail!`.
            Err(e) => return Err(Status::internal(format!("submitting epoch key: {e}"))),
        }

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

#[cfg(test)]
mod tests {
    //! Deterministic coverage for the two pure decisions the rotation-tracker
    //! eviction turns on.
    //!
    //! # Why these live here and not in `tests/`
    //!
    //! The eviction interleaving cannot be pinned through tonic. Everything it
    //! turns on — the instant a `RotationTracker` was installed relative to the
    //! instant `all_keys_for_gateway` returned, and whether the entry under the
    //! lock at write-back time is still the one the caller read — is in-process,
    //! sub-millisecond, and unaddressable from an RPC client. An integration
    //! test that "usually" loses the race is worse than no test. So the decision
    //! is extracted into pure functions and exercised directly, the same way
    //! `wiremesh_gateway::rotation`'s `overlap_write_back` /
    //! `new_epoch_watch_keys` are (see
    //! `crates/wiremesh-gateway/tests/overlap_write_back.rs` for the precedent,
    //! including its "each axis alone" discipline, followed below).
    //!
    //! # The two decisions under test
    //!
    //! These were written before the extraction existed, against the signatures
    //! below, and were red until it landed. Both lift logic that was previously
    //! inlined in `drive_rotation_for` and duplicated in `sweep_rotations`'
    //! step 2:
    //!
    //! ```ignore
    //! /// May the held tracker be evicted, given a keys snapshot read at `read_at`?
    //! fn evict_decision(
    //!     tracker_pending: u32,
    //!     tracker_installed_at: Instant,
    //!     db_pending: Option<u32>,
    //!     read_at: Instant,
    //! ) -> bool;
    //!
    //! /// The full identity of ONE tracker — the peer id alone is not enough.
    //! #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    //! struct TrackerToken { pending_epoch: u32, installed_at: Instant }
    //!
    //! #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    //! enum WriteBack { Apply, Replaced, Vanished }
    //!
    //! fn tracker_write_back(taken: TrackerToken, current: Option<TrackerToken>) -> WriteBack;
    //! ```
    //!
    //! The NAMES here are this test author's proposal and the implementer may
    //! change them; the CASES and their verdicts are the contract and must not
    //! be weakened to fit whatever gets built.
    //!
    //! # And what the verdicts DO
    //!
    //! A verdict is only half the contract — `Replaced` and `Vanished` differ
    //! today only in a log string, so pinning the labels alone would be close
    //! to restating a derived `PartialEq`. The final group drives the real
    //! [`apply_tracker_effect`] against a hand-built `rotations` map and
    //! asserts the resulting map state: a stale promote must not stamp a newer
    //! tracker, a stale finish must not remove one, and a vanished entry must
    //! not be resurrected. Those are the branches an integration test cannot
    //! reach (see that group's comment), and they need no test-only production
    //! hook because `apply_tracker_effect` depends on nothing but the map.
    //!
    //! # (task #32) The CAS-bail decision: when may a tracker be removed?
    //!
    //! The FINAL group drives the real [`drive_rotation_for`] and
    //! [`sweep_rotations`] against a real SQLite database. Unlike the eviction
    //! interleaving above, the wedge they cover is a STATE — "a tracker whose
    //! pending epoch has no row" — not a window, so it can simply be built,
    //! and needs no race, no sleep and no timing budget. The DB-layer half of
    //! the same contract lives in `crate::db`'s `cas_tests`.
    //!
    //! There is no `should_remove_tracker` predicate and no `CasArm` enum: the
    //! disposition is not a function of the arm alone, so it lives inline in
    //! [`drive_rotation_for`]'s three `match` arms, is named by
    //! [`TrackerEffect`], and is pinned BEHAVIORALLY here rather than as a
    //! pure function. The types it reads are [`crate::db::CasOutcome`]
    //! (`Applied` / `NoMatch`, for promote and retire) and
    //! [`crate::db::DropPendingOutcome`] (`Dropped` / `RowAbsent` /
    //! `RowSuperseded`, for the abort — which is the one CAS whose two
    //! zero-row causes demand opposite reactions).
    //!
    //! The verdict table IS the contract:
    //!
    //! ```text
    //!            committed   zero rows                     Err(_)
    //! Promote    false       false                         false
    //! Retire     true        false                         false
    //! Abort      true        TRUE  if the row is ABSENT     false
    //!                        false if the row SURVIVED
    //! ```
    //!
    //! Four cells carry the whole change, and each is pinned behaviorally in
    //! the final group:
    //!
    //!  - **`Abort` x zero rows x row ABSENT = true** — THE FIX. A confirmed
    //!    bail with nothing left on file is proof the rotation is over, and an
    //!    aborting tracker has `promoted_at == None`, so it owns no live
    //!    `retiring` row of its own. Pinned by
    //!    `a_confirmed_cas_bail_removes_the_wedged_tracker`.
    //!  - **`Abort` x zero rows x row SURVIVED = false** — THE REGRESSION the
    //!    round-2 group exists for. The same zero-row CAS, the opposite fact:
    //!    a concurrent promote flipped this epoch to `active` and demoted the
    //!    prior one to `retiring`, seconds ago. `promoted_at` cannot see it
    //!    (the promoter commits before its write-back), so the durable row
    //!    state has to. Pinned by
    //!    `a_promote_that_won_the_abort_cas_keeps_the_tracker` and
    //!    `a_promote_that_won_the_abort_cas_must_not_collapse_retire_grace`.
    //!  - **the entire `Err` column = false** — THE TRAP. A transient DB error
    //!    is evidence of nothing, and a removed tracker hands any live
    //!    `retiring` row to `sweep_rotations`' grace-free step-3 orphan path.
    //!    Pinned by `a_transient_db_error_never_removes_the_tracker` and
    //!    `a_transient_db_error_must_not_expose_an_older_retiring_row_to_the_orphan_path`.
    //!  - **`Retire` x `Ok(NoMatch)` = false** — deliberately conservative,
    //!    and the one judgement call in this table. The reviewer's safety
    //!    argument for removal-on-bail rests on `promoted_at == None`, which
    //!    is true only of `Abort`; a `Retire` tracker HAS promoted, and an
    //!    older `retiring` row may still be on file. A retire that lost its
    //!    CAS also self-heals without any removal here — the driver that WON
    //!    it removes the tracker through its own `TrackerToken`.

    use super::*;
    use std::time::Duration;

    /// A reference "the DB snapshot was read at this instant" clock, plus the
    /// two relative instants every case below needs.
    fn read_at() -> Instant {
        // A fixed base far enough into this process's monotonic clock that
        // `before()` cannot underflow.
        Instant::now() + Duration::from_secs(3600)
    }
    /// An instant strictly BEFORE the snapshot read — a tracker that was
    /// already installed when the keys were fetched, so the snapshot is
    /// authoritative about it.
    fn before(t: Instant) -> Instant {
        t - Duration::from_secs(5)
    }
    /// An instant strictly AFTER the snapshot read — a tracker installed while
    /// the caller was awaiting its DB read, which the snapshot therefore knows
    /// nothing about.
    fn after(t: Instant) -> Instant {
        t + Duration::from_millis(1)
    }

    // --- evict_decision --------------------------------------------------

    /// THE #28 FIX. A tracker installed AFTER the keys snapshot was taken
    /// describes a rotation that snapshot predates, so the snapshot's
    /// `db_pending` is stale with respect to it and can say nothing about
    /// whether it is stale. Evicting on that evidence destroys a rotation that
    /// has just started — its acks are then discarded (they fail the
    /// `ack.epoch == tracker.pending_epoch` test in `report`) and its
    /// `started_at` restarts.
    #[test]
    fn tracker_installed_after_the_snapshot_read_is_never_evicted() {
        let t = read_at();
        assert!(
            !evict_decision(7, after(t), Some(9), t),
            "the tracker was installed AFTER the keys snapshot was read, so the snapshot's \
             pending epoch is older than the tracker and cannot prove it stale — evicting \
             here tears down a rotation that started during the caller's own await"
        );
    }

    /// The tracker predates the snapshot AND names a different pending epoch
    /// than the DB currently holds: a previous rotation's tracker left behind
    /// while a newer rotation is genuinely in flight. This is the case the
    /// eviction exists for, so it must be reachable — an implementation that
    /// never evicts lets `decide`'s rule 1 short-circuit on the old tracker's
    /// `promoted_at` and the new rotation never sees an ack.
    #[test]
    fn stale_tracker_disagreeing_with_the_db_pending_row_is_evicted() {
        let t = read_at();
        assert!(
            evict_decision(7, before(t), Some(9), t),
            "a tracker installed before the snapshot that names epoch 7 while the DB's \
             pending row is epoch 9 is a previous rotation's leftover and must be evicted"
        );
    }

    /// Agreement is not eviction. The ordinary steady state of an in-flight
    /// rotation.
    #[test]
    fn tracker_agreeing_with_the_db_pending_row_is_kept() {
        let t = read_at();
        assert!(
            !evict_decision(7, before(t), Some(7), t),
            "the tracker names the same epoch as the DB's pending row — this is the ordinary \
             in-flight rotation and evicting it would reset started_at and drop every ack \
             already recorded"
        );
    }

    /// LOAD-BEARING. `db_pending == None` is the STRANDED-POST-PROMOTE state:
    /// the promote already committed (so there is no `pending` row left) and
    /// the tracker still owes a `RotationDecision::Retire` for its prior
    /// active epoch, `RETIRE_GRACE` after the promote.
    ///
    /// A plain inequality (`Some(tracker_pending) != db_pending`) evicts here,
    /// which does NOT merely lose bookkeeping: with no tracker held,
    /// `sweep_rotations`' step-3 orphan path stops skipping the gateway, and
    /// that path deletes `retiring` rows IMMEDIATELY with no grace at all. The
    /// 30s `RETIRE_GRACE` collapses to ~0 on every normal rotation, and every
    /// peer still finishing its handshake on the old key loses it — a
    /// make-before-break violation on the fabric's most routine operation.
    #[test]
    fn no_db_pending_epoch_never_evicts() {
        let t = read_at();
        assert!(
            !evict_decision(7, before(t), None, t),
            "COLLAPSED RETIRE_GRACE: the DB has no pending epoch, which IS the \
             stranded-post-promote state — that tracker still owes its prior epoch's Retire \
             30s after the promote. Evicting it hands the retire to sweep_rotations' orphan \
             path, which deletes immediately, so RETIRE_GRACE goes from 30s to ~0 on every \
             normal rotation and peers still on the old key are cut off mid-handshake. \
             `db_pending == None` must be an unconditional keep"
        );
    }

    /// The same rule with the OTHER input axis varied, so an implementation
    /// that happens to keep the case above for an unrelated reason (e.g. by
    /// treating `None` as equal to the tracker's own epoch) still has to get
    /// it right in general: no `db_pending`, no eviction, whatever the
    /// tracker's epoch is.
    #[test]
    fn no_db_pending_epoch_never_evicts_for_any_tracker_epoch() {
        let t = read_at();
        for tracker_pending in [0u32, 1, 7, 4242] {
            assert!(
                !evict_decision(tracker_pending, before(t), None, t),
                "no pending row in the DB must mean no eviction regardless of the tracker's \
                 own pending epoch ({tracker_pending}) — see \
                 `no_db_pending_epoch_never_evicts` for what evicting here costs"
            );
        }
    }

    /// And with the timing axis varied too: a tracker installed after the read
    /// with no DB pending row is doubly protected, and must stay kept.
    #[test]
    fn no_db_pending_epoch_never_evicts_even_for_a_freshly_installed_tracker() {
        let t = read_at();
        assert!(
            !evict_decision(7, after(t), None, t),
            "neither of the two reasons to keep a tracker (installed after the read; no DB \
             pending row) may be turned into a reason to evict by the presence of the other"
        );
    }

    // --- tracker_write_back ----------------------------------------------

    fn token(pending_epoch: u32, installed_at: Instant) -> TrackerToken {
        TrackerToken { pending_epoch, installed_at }
    }

    /// The ordinary case: nothing moved while the caller was awaiting, so the
    /// conclusion it computed is about the entry that is still there. `Apply`
    /// has to be reachable — a gate that never applies would be "safe" and
    /// would also mean no tracker ever records a promote or an ack.
    #[test]
    fn unchanged_entry_applies() {
        let t = read_at();
        let taken = token(7, before(t));
        assert_eq!(
            tracker_write_back(taken, Some(taken)),
            WriteBack::Apply,
            "the entry under the lock is the same tracker the caller read; refusing the \
             write-back here would stall every rotation"
        );
    }

    /// THE EPOCH AXIS, ALONE. Same install instant, different pending epoch —
    /// the gateway re-rotated and a new tracker was inserted while the caller
    /// awaited. An implementation comparing only `installed_at` returns
    /// `Apply` here and writes the old rotation's `promoted_at`/`live_acks`
    /// onto the new one.
    #[test]
    fn different_epoch_same_install_instant_is_replaced() {
        let t = read_at();
        let installed = before(t);
        assert_eq!(
            tracker_write_back(token(7, installed), Some(token(9, installed))),
            WriteBack::Replaced,
            "the entry under the lock tracks a DIFFERENT pending epoch — applying the \
             caller's conclusions to it would credit one rotation's acks (or its promote) to \
             another"
        );
    }

    /// THE INSTANT AXIS, ALONE. Same pending epoch, different install instant
    /// — the tracker was evicted and rebuilt toward the SAME epoch number
    /// while the caller awaited (a lazy rebuild in `sweep_rotations`, or a
    /// controller whose epoch numbering repeats). An implementation comparing
    /// only `pending_epoch` returns `Apply` here and writes a
    /// `promoted_at`/ack set belonging to the torn-down tracker onto the fresh
    /// one, which then either retires early or never retires at all.
    #[test]
    fn same_epoch_different_install_instant_is_replaced() {
        let t = read_at();
        assert_eq!(
            tracker_write_back(token(7, before(t)), Some(token(7, after(t)))),
            WriteBack::Replaced,
            "the epoch number matches but this is a DIFFERENT tracker instance — a rebuild \
             toward the same epoch must not inherit the previous instance's promoted_at or \
             live_acks"
        );
    }

    /// The entry is gone: the rotation completed (retired/aborted) while the
    /// caller was awaiting.
    #[test]
    fn missing_entry_vanished() {
        let t = read_at();
        assert_eq!(
            tracker_write_back(token(7, before(t)), None),
            WriteBack::Vanished,
            "no entry under the lock at all — the write-back must not resurrect a tracker \
             for a rotation that has already finished"
        );
    }

    // --- apply_tracker_effect: the verdicts AS ACTED ON --------------------
    //
    // The four cases above pin the verdict; these pin what the caller does
    // with it, which is where the damage would actually land. They matter
    // because `apply_tracker_effect` is the only consumer, and its `Replaced`
    // and `Vanished` arms are unreachable from any integration test: the
    // window they cover is between `drive_rotation_for` releasing the guard
    // and re-taking it, spanned only by one `spawn_blocking` SQLite CAS. No
    // RPC client can land a competing mutation inside it.
    //
    // `apply_tracker_effect` needs nothing but the shared map — no DB, no
    // broker, no controller — so these drive the real function directly rather
    // than restating it.

    fn tracker(pending_epoch: u32, installed_at: Instant) -> RotationTracker {
        RotationTracker {
            pending_epoch,
            prior_active_epoch: 0,
            started_at: installed_at,
            promoted_at: None,
            live_acks: BTreeSet::new(),
            installed_at,
        }
    }

    fn map_with(entries: Vec<(i64, RotationTracker)>) -> Arc<Mutex<HashMap<i64, RotationTracker>>> {
        Arc::new(Mutex::new(entries.into_iter().collect()))
    }

    const GW: i64 = 42;

    /// `Apply`, acted on: the promote stamp lands. Without this, the tests
    /// below are all satisfied by an `apply_tracker_effect` that does nothing
    /// at all — which would leave `promoted_at` permanently `None`, so
    /// `decide`'s rule 1 never fires and the retire this whole branch exists
    /// to drive never happens.
    #[tokio::test]
    async fn apply_stamps_promoted_at_on_the_same_tracker() {
        let t = read_at();
        let rotations = map_with(vec![(GW, tracker(7, before(t)))]);
        let taken = token(7, before(t));

        apply_tracker_effect(&rotations, GW, taken, TrackerEffect::Promoted).await;

        let guard = rotations.lock().await;
        assert!(
            guard
                .get(&GW)
                .expect("the tracker must still be present after a Promoted effect")
                .promoted_at
                .is_some(),
            "the entry is the same instance the decision was computed from, so the promote \
             stamp must land — otherwise RETIRE_GRACE never starts and no rotation ever retires"
        );
    }

    /// `Replaced`, acted on — THE PROMOTE CASE. A newer rotation's tracker now
    /// occupies the slot. Stamping ITS `promoted_at` from the old rotation's
    /// decision would make `decide`'s rule 1 short-circuit the new rotation
    /// immediately into a `Retire` of the wrong epoch, and its pending epoch
    /// would never promote.
    #[tokio::test]
    async fn replaced_promote_does_not_stamp_the_newer_tracker() {
        let t = read_at();
        let rotations = map_with(vec![(GW, tracker(9, after(t)))]);
        let stale = token(7, before(t));

        apply_tracker_effect(&rotations, GW, stale, TrackerEffect::Promoted).await;

        let guard = rotations.lock().await;
        let current = guard
            .get(&GW)
            .expect("a Replaced write-back must leave the newer tracker in place");
        assert_eq!(
            current.pending_epoch, 9,
            "the newer rotation's tracker must survive untouched"
        );
        assert!(
            current.promoted_at.is_none(),
            "the newer rotation has NOT promoted — crediting it with the previous rotation's \
             promote sends decide()'s rule 1 straight to a Retire of the wrong epoch and the \
             new pending epoch never promotes"
        );
    }

    /// `Replaced`, acted on — THE FINISHED CASE. The blind `remove` this gate
    /// replaced would delete a live rotation's tracker, discarding its
    /// accumulated acks and restarting its 90s clock.
    #[tokio::test]
    async fn replaced_finish_does_not_remove_the_newer_tracker() {
        let t = read_at();
        let rotations = map_with(vec![(GW, tracker(9, after(t)))]);
        let stale = token(7, before(t));

        apply_tracker_effect(&rotations, GW, stale, TrackerEffect::Finished).await;

        let guard = rotations.lock().await;
        assert_eq!(
            guard.get(&GW).map(|t| t.pending_epoch),
            Some(9),
            "a finished OLD rotation must not evict the tracker of the NEW one that replaced \
             it — doing so discards the new rotation's live_acks and restarts its clock"
        );
    }

    /// `Vanished`, acted on: nothing is created. Both effects go through the
    /// same arm, and `Promoted`'s `get_mut` would be a silent no-op anyway —
    /// so this is really a guard against a future `insert`/`entry().or_*`
    /// rewrite resurrecting a tracker for a rotation that is already over,
    /// which would then wedge the gateway in `gateways_with_rotation_state`.
    #[tokio::test]
    async fn vanished_write_back_creates_nothing() {
        let t = read_at();
        let taken = token(7, before(t));

        for effect in [TrackerEffect::Promoted, TrackerEffect::Finished] {
            let rotations = map_with(vec![]);
            apply_tracker_effect(&rotations, GW, taken, effect).await;
            assert!(
                rotations.lock().await.is_empty(),
                "the entry was already gone when the {effect:?} write-back arrived — it must \
                 not be resurrected"
            );
        }
    }

    // --- task #32: the wedged tracker, driven through the real driver -------
    //
    // Everything below drives the REAL `drive_rotation_for` against a real
    // SQLite database. Unlike the eviction interleaving above, this one does
    // NOT need a race to reproduce: the wedge is a STATE, not a window.
    //
    // `report` does its now-unlocked `all_keys_for_gateway`, sees `pending =
    // N`, an `Abort`'s `drop_pending_epoch` commits, and `report` then takes
    // the guard and seeds a `RotationTracker` for a pending epoch N that no
    // longer exists. The race is only how the map got into that state; the
    // state itself is just "a tracker whose pending epoch has no row", and a
    // test can simply build it. That is why these are real end-to-end
    // assertions rather than pure-function stand-ins, and why none of them
    // needs a sleep, a retry or a timing budget.
    //
    // What the wedge costs (it is NOT a stuck rotation timer): with no
    // `pending`/`retiring` rows the gateway is not returned by
    // `gateways_with_rotation_state`, so the timer keeps working. The wedged
    // tracker instead EATS THE NEXT ROTATION'S FIRST ACK — `report`'s
    // ack-recording pass does not run `evict_decision`, so the ack fails the
    // `ack.epoch == tracker.pending_epoch` test and is dropped, and a gateway
    // acks exactly ONCE per Role-B cutover. That rotation then falls back to
    // the 90s grace promote instead of promoting on acks.

    /// A file-backed controller DB (plus the temp dir that must outlive it),
    /// holding one gateway in one segment and whatever `(epoch, pubkey,
    /// state)` key rows the caller asks for.
    ///
    /// File-backed rather than `Db::open_memory` because two things here need
    /// a SECOND `rusqlite` connection onto the same database: seeding rows the
    /// public `Db` API cannot create without a full token-backed enrollment,
    /// and installing the `BEFORE DELETE` trigger that makes a DELETE fail for
    /// real. `open_memory` gives every connection its own private database, so
    /// neither would be visible to the driver under test.
    fn seeded_db(keys: &[(i64, &str, &str)]) -> (tempfile::TempDir, DbHandle) {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("controller.db");
        let db = crate::db::Db::open(&path).expect("opening the controller DB");
        {
            let conn = raw_conn(dir.path());
            conn.execute(
                "INSERT INTO segment (id, name, description) VALUES (1, 'seg-a', NULL)",
                [],
            )
            .expect("seeding a segment");
            conn.execute(
                "INSERT INTO gateway (id, segment_id, name, status, backend) \
                 VALUES (?1, 1, 'gw-a', 'active', 'nftables')",
                rusqlite::params![GW],
            )
            .expect("seeding a gateway");
            for (epoch, pubkey, state) in keys {
                conn.execute(
                    "INSERT INTO gateway_key (gateway_id, epoch, pubkey, state) \
                     VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![GW, epoch, pubkey, state],
                )
                .expect("seeding a gateway_key row");
            }
        }
        (dir, DbHandle::new(db))
    }

    /// A second, independent connection to the same database file, used only
    /// by this module's setup and its assertions.
    fn raw_conn(dir: &std::path::Path) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open(dir.join("controller.db"))
            .expect("second connection to the controller DB");
        conn.busy_timeout(Duration::from_secs(5))
            .expect("setting a busy timeout");
        conn
    }

    /// Makes any DELETE of a `pending` `gateway_key` row fail with a real
    /// `rusqlite` error, while leaving every SELECT — and every DELETE of a
    /// `retiring` row — working normally.
    ///
    /// This is how a TRANSIENT DATABASE ERROR is injected without touching a
    /// line of production code: `drop_pending_epoch`'s DELETE returns `Err`,
    /// but `all_keys_for_gateway` still returns the real key set, so
    /// `drive_rotation_for` reaches its `Abort` arm exactly as it would on a
    /// healthy database and then fails there. Narrowed to `pending` rows on
    /// purpose: `sweep_rotations`' step-3 orphan path must stay able to delete
    /// `retiring` rows, or the consequence test below could not tell "the row
    /// survived because the tracker protected it" from "the row survived
    /// because nothing can be deleted at all".
    fn fail_pending_deletes(dir: &std::path::Path) {
        raw_conn(dir)
            .execute(
                "CREATE TRIGGER injected_transient_failure \
                 BEFORE DELETE ON gateway_key WHEN OLD.state = 'pending' \
                 BEGIN SELECT RAISE(ABORT, 'injected transient database failure'); END",
                [],
            )
            .expect("installing the failure trigger");
    }

    /// How far past [`rotation::ABORT_AFTER`] [`aborting_tracker`] backdates.
    /// It only has to cover the gap between the `Instant::now()` that computes
    /// `started_at` and the one `drive_rotation_for` later hands to
    /// `rotation::decide`; a whole second is free and makes the intent plain.
    const ABORT_MARGIN: Duration = Duration::from_secs(1);

    /// `Instant::now() - d`, saturating at the present instead of panicking
    /// when the monotonic clock cannot represent a point that far back.
    ///
    /// `Instant` is `CLOCK_MONOTONIC`, which counts from SYSTEM BOOT, not from
    /// process start, and `Instant::checked_sub` only promises `Some` when the
    /// result is representable — which a machine booted less than `d` ago
    /// cannot guarantee on every platform. CI runners routinely start jobs
    /// seconds after boot, so this is reachable, and an `.expect()` there fails
    /// a *rotation* test with a message about clocks: a puzzle, not a
    /// diagnosis. Saturating keeps the arithmetic total and hands the reporting
    /// job to [`aborting_tracker`]'s postcondition, which can state the actual
    /// consequence.
    ///
    /// The sibling helpers [`before`] and [`after`] do NOT need this: `read_at`
    /// deliberately returns `Instant::now() + 3600s`, so subtracting from it
    /// cannot underflow. That is the same hazard, already solved by
    /// construction — but only for instants that never meet a real
    /// `Instant::now()`. These trackers do, so they cannot use that trick.
    fn saturating_ago(d: Duration) -> Instant {
        let now = Instant::now();
        now.checked_sub(d).unwrap_or(now)
    }

    /// A tracker whose rotation started long enough ago that `rotation::decide`
    /// is already past [`rotation::ABORT_AFTER`] — i.e. whose very next
    /// decision is a `RotationDecision::Abort`. `promoted_at` is `None`, which
    /// is what makes `Abort` reachable at all (rule 1 short-circuits
    /// otherwise), and is also the reviewer's safety argument for why removing
    /// THIS tracker on a confirmed bail cannot strand a live `retiring` row of
    /// its own.
    ///
    /// That promise is ASSERTED, not assumed — see the postcondition below.
    fn aborting_tracker(pending_epoch: u32, prior_active_epoch: u32) -> RotationTracker {
        let started_at = saturating_ago(rotation::ABORT_AFTER + ABORT_MARGIN);
        let tracker = RotationTracker {
            pending_epoch,
            prior_active_epoch,
            started_at,
            promoted_at: None,
            live_acks: BTreeSet::new(),
            installed_at: started_at,
        };

        // POSTCONDITION — the helper's entire promise, checked against the real
        // `rotation::decide` rather than inferred from the arithmetic above.
        //
        // Every caller needs `drive_rotation_for` to reach its `Abort` arm, and
        // none of them assert that it did. A tracker that quietly decided
        // `Wait` instead would never run the CAS at all, and the two "the
        // tracker must survive" tests would then pass VACUOUSLY — green for the
        // wrong reason, which is the worst outcome available here. This is also
        // what turns a clock too young to express a 300s-old rotation into a
        // diagnosis rather than a mystery.
        //
        // The probe mirrors exactly what `drive_rotation_for` builds for these
        // fixtures: no real key (no call site seeds a real-keyed `pending` row)
        // and no connected peers (the test broker has no registrations). The
        // `Instant::now()` here is strictly EARLIER than the one the driver will
        // pass to `decide`, and elapsed time only grows, so a pass here cannot
        // turn into a failure there.
        let probe = RotationState {
            pending_epoch: tracker.pending_epoch,
            pending_has_real_key: false,
            prior_active_epoch: tracker.prior_active_epoch,
            started_at: tracker.started_at,
            promoted_at: tracker.promoted_at,
            expected_peers: BTreeSet::new(),
            live_acks: tracker.live_acks.clone(),
        };
        assert!(
            matches!(
                rotation::decide(&probe, Instant::now()),
                RotationDecision::Abort { .. }
            ),
            "aborting_tracker did not produce a tracker that ABORTS. `started_at` was \
             backdated by ABORT_AFTER + {ABORT_MARGIN:?}, yet `decide` declined to abort — \
             which is what happens when this machine's monotonic clock (CLOCK_MONOTONIC, \
             counted from SYSTEM BOOT, not process start) is younger than that, so the \
             backdating saturated at the present. Every test using this helper needs \
             drive_rotation_for to reach its Abort arm; without it the compare-and-swap \
             never runs and the 'tracker must survive' assertions pass VACUOUSLY. The \
             machine's uptime is the problem here, not the code under test"
        );

        tracker
    }

    /// `(epoch, state)` for every key row [`GW`] currently has, sorted.
    async fn key_states(db: &DbHandle) -> Vec<(i64, String)> {
        let mut rows: Vec<(i64, String)> = db
            .all_keys_for_gateway(GW)
            .await
            .expect("reading the key states")
            .into_iter()
            .map(|(epoch, _, state)| (epoch, state))
            .collect();
        rows.sort();
        rows
    }

    /// THE FIX. A tracker for a `pending` epoch that no longer has a row is
    /// WEDGED: `rotation::decide` hands it an `Abort` forever, and
    /// `drop_pending_epoch`'s compare-and-swap matches zero rows every single
    /// time, so it can never satisfy its own abort and nothing ever removes
    /// it. It then eats the next rotation's one and only ack.
    ///
    /// A CONFIRMED bail — as distinct from an error — is proof the rotation
    /// this tracker describes is over, so the tracker must go. Nothing else in
    /// the system will ever clear it: `evict_decision`'s `db_pending == None`
    /// leg is an unconditional KEEP (correctly — that is also the
    /// stranded-post-promote state), and the gateway is invisible to
    /// `sweep_rotations` because it has no `pending`/`retiring` rows left.
    #[tokio::test]
    async fn a_confirmed_cas_bail_removes_the_wedged_tracker() {
        // Exactly the DB state an already-committed abort leaves behind: the
        // prior active epoch survived (an abort is non-destructive) and the
        // pending row the tracker is about is GONE.
        let (_dir, db) = seeded_db(&[(0, "EPOCH0==", "active")]);
        let (change_tx, _change_rx) = broadcast::channel(16);
        let broker = Broker::new(db.clone(), crate::broker::new_registry());
        let rotations = map_with(vec![(GW, aborting_tracker(1, 0))]);

        // (task #32, round 2) This is unambiguously the ROW-ABSENT leg, and
        // the assertion below depends on it: a NoMatch whose row still EXISTS
        // means a promote won and the tracker must be KEPT instead (see
        // `a_promote_that_won_the_abort_cas_keeps_the_tracker`). Stated here so
        // the two cases cannot be conflated by a future edit to this setup.
        assert!(
            !key_states(&db)
                .await
                .iter()
                .any(|(epoch, _)| *epoch == 1),
            "this test's premise is that epoch 1 has NO row at all — if a row exists in any \
             state, this is the superseded-by-promote case and expects the opposite outcome"
        );

        drive_rotation_for(&db, &change_tx, &broker, &rotations, GW).await;

        assert!(
            rotations.lock().await.is_empty(),
            "WEDGED ROTATION TRACKER (task #32): the tracker names pending epoch 1, the DB \
             has no epoch-1 row, and drop_pending_epoch therefore matched ZERO ROWS — a \
             CONFIRMED compare-and-swap bail, not a database failure. That is proof the \
             rotation is over. Leaving the tracker in place wedges it permanently: \
             evict_decision's `db_pending == None` leg keeps it forever, the gateway has no \
             pending/retiring rows so sweep_rotations never looks at it, and decide() will \
             hand it the same unsatisfiable Abort on every tick. The cost lands on the NEXT \
             rotation, which loses its first (and, per Role-B cutover, only) ack to the \
             `ack.epoch == tracker.pending_epoch` check in report() and silently falls back \
             to the 90s grace promote"
        );
        assert_eq!(
            key_states(&db).await,
            vec![(0, "active".to_string())],
            "removing a wedged tracker is a purely IN-MEMORY correction — it must not \
             delete, demote or otherwise touch a single key row"
        );
    }

    /// THE TRAP. The same code path, reached with a genuine database failure
    /// instead of a bail. The tracker must SURVIVE.
    ///
    /// This is the distinction the whole change exists to make available.
    /// Removing the tracker on any `Err` also fires on a transient blip, and a
    /// removed tracker stops shielding this gateway from `sweep_rotations`'
    /// step-3 orphan path, which deletes `retiring` rows with no grace at all.
    /// `RETIRE_GRACE` collapsing from 30s to ~0 has been reachable by three
    /// independent routes on this codebase already; this would be the fourth.
    #[tokio::test]
    async fn a_transient_db_error_never_removes_the_tracker() {
        let (dir, db) = seeded_db(&[
            (0, "EPOCH0==", "active"),
            (1, "awaiting-submission", "pending"),
        ]);
        fail_pending_deletes(dir.path());
        let (change_tx, _change_rx) = broadcast::channel(16);
        let broker = Broker::new(db.clone(), crate::broker::new_registry());
        let rotations = map_with(vec![(GW, aborting_tracker(1, 0))]);

        drive_rotation_for(&db, &change_tx, &broker, &rotations, GW).await;

        // Non-vacuity first: if the row is gone, the DELETE succeeded, no
        // error was injected, and the assertion below would pass for the
        // wrong reason.
        assert_eq!(
            key_states(&db).await,
            vec![(0, "active".to_string()), (1, "pending".to_string())],
            "the injected failure trigger did not fire — drop_pending_epoch's DELETE \
             succeeded, so this test never reached the error path it exists to cover and \
             proves nothing"
        );
        assert!(
            rotations.lock().await.contains_key(&GW),
            "RETIRE_GRACE COLLAPSE: drop_pending_epoch failed with a genuine DATABASE ERROR, \
             not a compare-and-swap bail. The rotation is still in flight (its pending row is \
             right there) and the next sweep tick will retry it. Removing the tracker here \
             costs make-before-break — see the standing comments on both the Retire and Abort \
             error arms, and `evict_decision`'s unit-pinned `None`-means-keep leg. Only a \
             CONFIRMED bail may remove a tracker"
        );
    }

    /// The consequence, made concrete — because "the tracker survived" is only
    /// bookkeeping until you follow it into `sweep_rotations`.
    ///
    /// The gateway holds a `retiring` row from an EARLIER rotation (epoch 0)
    /// alongside the aborting rotation's `pending` row. That older row is
    /// exactly the one the `Abort` arm's standing comment names: an aborting
    /// tracker owns no live `retiring` row of its OWN (`promoted_at == None`),
    /// but it is still the only thing making `sweep_rotations` step 3 skip
    /// this gateway. Remove it on a transient error and the very next sweep
    /// tick deletes epoch 0 grace-free.
    #[tokio::test]
    async fn a_transient_db_error_must_not_expose_an_older_retiring_row_to_the_orphan_path() {
        let (dir, db) = seeded_db(&[
            (0, "EPOCH0==", "retiring"),
            (1, "EPOCH1==", "active"),
            (2, "awaiting-submission", "pending"),
        ]);
        fail_pending_deletes(dir.path());
        let (change_tx, _change_rx) = broadcast::channel(16);
        let broker = Broker::new(db.clone(), crate::broker::new_registry());
        let rotations = map_with(vec![(GW, aborting_tracker(2, 1))]);

        // The whole sweep, not just the driver: step 2b fails the abort, and
        // step 3 then decides what to do with the `retiring` row based on
        // whether a tracker is still held.
        sweep_rotations(&db, &change_tx, &broker, &rotations).await;

        assert_eq!(
            key_states(&db).await,
            vec![
                (0, "retiring".to_string()),
                (1, "active".to_string()),
                (2, "pending".to_string()),
            ],
            "RETIRE_GRACE COLLAPSED TO ZERO. The abort's drop_pending_epoch hit a transient \
             DATABASE ERROR. If that error removed the tracker, sweep_rotations step 3 stops \
             skipping this gateway, sees epoch 0 still 'retiring' with no tracker held, and \
             deletes it on the spot — that path is deliberately grace-free, so every peer \
             still finishing a handshake on epoch 0 loses it immediately. Note the trigger \
             installed here blocks only PENDING deletes, so a surviving epoch 0 means the \
             tracker protected it, not that deletion was impossible"
        );
        assert!(
            rotations.lock().await.contains_key(&GW),
            "and the tracker itself must still be held after the sweep — that is the thing \
             step 3 keys off"
        );
    }

    // --- (task #32, round 2) TrackerEffect::FinishedIfUnpromoted ------------
    //
    // The variant had NO direct coverage. The only test reaching it
    // (`a_confirmed_cas_bail_removes_the_wedged_tracker`) has `promoted_at:
    // None`, so it exercises the remove leg only — and the whole suite passes
    // identically if someone replaces the variant with a plain
    // `TrackerEffect::Finished`, which its own doc comment tells them not to
    // do. These two pin both legs directly, following the template the
    // `apply_tracker_effect` group above already established.

    /// The REMOVE leg, pinned directly rather than incidentally: an unpromoted
    /// tracker whose abort CAS confirmed the rotation is over must go, or it
    /// wedges and eats the next rotation's only ack.
    #[tokio::test]
    async fn finished_if_unpromoted_removes_an_unpromoted_tracker() {
        let t = read_at();
        let rotations = map_with(vec![(GW, tracker(7, before(t)))]);
        let taken = token(7, before(t));

        apply_tracker_effect(&rotations, GW, taken, TrackerEffect::FinishedIfUnpromoted).await;

        assert!(
            rotations.lock().await.is_empty(),
            "the tracker never promoted (`promoted_at == None`), so it owns no live retiring \
             row and its abort CAS confirmed the rotation is over — it must be removed. An \
             implementation that keeps it here re-introduces the wedge task #32 fixed"
        );
    }

    /// The KEEP leg — the entire reason this is not a plain
    /// [`TrackerEffect::Finished`], and the leg nothing tested.
    ///
    /// The guard was RELEASED across the abort's CAS, so a concurrent
    /// promoter's `promote_epoch` can commit AND its write-back land inside
    /// that window. The tracker then holds `promoted_at == Some(_)` and owns a
    /// live `retiring` row that is owed `RETIRE_GRACE` from the promote —
    /// removing it hands that row to `sweep_rotations`' grace-free step-3
    /// orphan path.
    ///
    /// Downgrade this call site to `TrackerEffect::Finished` and only this
    /// assertion notices.
    #[tokio::test]
    async fn finished_if_unpromoted_keeps_a_tracker_that_promoted_during_the_abort() {
        let t = read_at();
        let mut promoted = tracker(7, before(t));
        promoted.promoted_at = Some(Instant::now());
        let rotations = map_with(vec![(GW, promoted)]);
        let taken = token(7, before(t));

        apply_tracker_effect(&rotations, GW, taken, TrackerEffect::FinishedIfUnpromoted).await;

        let guard = rotations.lock().await;
        assert!(
            guard.get(&GW).is_some_and(|t| t.promoted_at.is_some()),
            "RETIRE_GRACE COLLAPSE: a promote committed and stamped this tracker while the \
             abort's CAS was in flight. The tracker now owns a live `retiring` row whose 30s \
             grace started at that promote, and `decide`'s rule 1 is the ONLY thing that will \
             ever retire it under grace. Removing it here drops that Retire and hands the \
             seconds-old row to sweep_rotations' step-3 orphan path, which deletes \
             grace-free. This is exactly the case `FinishedIfUnpromoted` exists for — a plain \
             TrackerEffect::Finished passes every other test in this file"
        );
    }

    // --- (task #32, round 2) THE REGRESSION ---------------------------------
    //
    // `FinishedIfUnpromoted` closes the window where the promoter's WRITE-BACK
    // has already landed. It does not close the window where the promoter's DB
    // COMMIT has landed but its write-back has not — and that window is the
    // wider of the two, because the Promote arm commits to SQLite (a
    // `spawn_blocking` hop) and only then re-takes the guard:
    //
    //   1. Aborter reads keys, sees the sentinel, decides Abort{E}.
    //   2. The gateway's SubmitEpochKey lands; `set_epoch_pubkey` commits a
    //      real key. A promoter (that RPC's own `drive_rotation`, or a sweep
    //      tick) now reads a real-keyed pending epoch 301s old, so `decide`
    //      rule 4 fires and `promote_epoch` COMMITS: E -> 'active', the prior
    //      active epoch P -> 'retiring'.
    //   3. The aborter's `drop_pending_epoch(E)` matches 0 rows: Ok(NoMatch).
    //   4. The aborter wins the guard, reads `promoted_at == None` — the
    //      promoter has not reached its write-back — and REMOVES the tracker.
    //   5. The promoter's write-back gets `Vanished` and stamps nothing.
    //   6. `sweep_rotations` step 3 finds `retiring = [P]` with no tracker and
    //      takes the intentionally grace-free delete path.
    //
    // P was demoted SECONDS ago. Pre-retype this interleaving was safe: step 3
    // returned `Err`, the aborter kept the tracker, the promoter stamped
    // `promoted_at`, and the retire ran under the full 30s. So this is a
    // REGRESSION introduced by the typed outcome, and the fourth independent
    // route to a collapsed RETIRE_GRACE on this codebase.
    //
    // # Why these are deterministic and carry no sleeps
    //
    // As in round 1, the race is only how the state ARISES; the state itself is
    // constructible. At the instant the aborter's CAS returns, the durable
    // state is fully determined — E 'active', P 'retiring' — and so is the
    // in-memory state — one unpromoted tracker naming E. Both are seeded
    // directly, and the real `drive_rotation_for` is then run against them.
    //
    // The one thing that cannot be seeded is the promoter's write-back, which
    // must land AFTER the aborter's. It is not faked: the Promote arm's entire
    // in-memory effect is `apply_tracker_effect(rotations, id, taken,
    // TrackerEffect::Promoted)`, so the test calls exactly that, with exactly
    // the token the promoter would hold — a promote mutates neither
    // `pending_epoch` nor `installed_at`, so the promoter's token and the
    // aborter's are the same value, which is precisely why the write-back
    // returns `Apply` and the keep path self-heals.

    /// The DB state the moment a promote has won the abort's CAS: the aborting
    /// tracker's epoch is now `active`, and the prior active epoch was demoted
    /// to `retiring` in the same transaction.
    fn post_promote_db() -> (tempfile::TempDir, DbHandle) {
        seeded_db(&[(0, "EPOCH0==", "retiring"), (1, "REALKEY==", "active")])
    }

    /// THE REGRESSION, at the tracker. A confirmed `NoMatch` whose row is still
    /// THERE — moved to `active` by a promote — is not evidence the rotation is
    /// over. It is evidence the rotation SUCCEEDED, and the tracker still owes
    /// the `Retire` of the row that promote just created.
    #[tokio::test]
    async fn a_promote_that_won_the_abort_cas_keeps_the_tracker() {
        let (_dir, db) = post_promote_db();
        let (change_tx, _change_rx) = broadcast::channel(16);
        let broker = Broker::new(db.clone(), crate::broker::new_registry());
        let rotations = map_with(vec![(GW, aborting_tracker(1, 0))]);

        drive_rotation_for(&db, &change_tx, &broker, &rotations, GW).await;

        assert!(
            rotations.lock().await.contains_key(&GW),
            "RETIRE_GRACE COLLAPSE (the fourth route). drop_pending_epoch matched zero rows, \
             but epoch 1 is still THERE — a concurrent promote flipped it to 'active' and \
             demoted epoch 0 to 'retiring' in the same transaction. That is the opposite of \
             'the rotation is over': epoch 0 is a SECONDS-OLD retiring row owed the full 30s \
             grace, and this tracker is the only thing that will ever retire it under grace \
             (decide's rule 1) and the only thing making sweep_rotations step 3 skip the \
             gateway. Re-checking `promoted_at` under the guard does not catch this — the \
             promoter commits to SQLite BEFORE it re-takes the guard, so `promoted_at` is \
             still None right now. The cause of the NoMatch has to come from the durable row \
             state, read inside the failed DELETE's own transaction"
        );
        assert_eq!(
            key_states(&db).await,
            vec![(0, "retiring".to_string()), (1, "active".to_string())],
            "and the losing abort must not have touched a row"
        );
    }

    /// THE HARM, followed all the way to the deleted row.
    ///
    /// The test above pins the tracker; this one pins what losing it costs. It
    /// runs the promoter's write-back and then a real `sweep_rotations`, and
    /// asserts the seconds-old `retiring` row is still there.
    ///
    /// It also pins the SELF-HEALING property that makes the keep correct
    /// rather than merely cautious: the promoter's token still matches, so its
    /// write-back returns `Apply` and stamps `promoted_at`, which turns the
    /// tracker's next decision from an unsatisfiable `Abort` into `Wait` and
    /// then `Retire` under the full grace. Without that, keeping the tracker
    /// would simply be a different wedge.
    #[tokio::test]
    async fn a_promote_that_won_the_abort_cas_must_not_collapse_retire_grace() {
        let (_dir, db) = post_promote_db();
        let (change_tx, _change_rx) = broadcast::channel(16);
        let broker = Broker::new(db.clone(), crate::broker::new_registry());

        let tracker = aborting_tracker(1, 0);
        // The promoter read the tracker under the guard before its own CAS, so
        // it holds a token naming this same instance. A promote changes neither
        // field the token carries.
        let promoter_token = TrackerToken::of(&tracker);
        let rotations = map_with(vec![(GW, tracker)]);

        // (1) The aborter: real driver, real CAS, real NoMatch.
        drive_rotation_for(&db, &change_tx, &broker, &rotations, GW).await;

        // (2) The promoter's write-back, arriving second — verbatim what the
        // Promote arm does once its `promote_epoch` returned Applied.
        apply_tracker_effect(&rotations, GW, promoter_token, TrackerEffect::Promoted).await;

        assert!(
            rotations
                .lock()
                .await
                .get(&GW)
                .is_some_and(|t| t.promoted_at.is_some()),
            "SELF-HEALING BROKEN: keeping the tracker is only correct because the promoter's \
             write-back can still land on it — same pending_epoch, same installed_at, so \
             tracker_write_back returns Apply and stamps promoted_at, which is what turns the \
             tracker's next decision from an unsatisfiable Abort into a Retire under full \
             grace. If the tracker was removed at step (1), this write-back got `Vanished` \
             and stamped nothing, and the tracker is now gone with a live retiring row on disk"
        );

        // (3) The very next sweep. In the broken ordering this is the SAME
        // iteration that would have deleted the row: step 2b drives nothing
        // (no tracker), and step 3 then finds `retiring = [0]` unshielded.
        sweep_rotations(&db, &change_tx, &broker, &rotations).await;

        assert_eq!(
            key_states(&db).await,
            vec![(0, "retiring".to_string()), (1, "active".to_string())],
            "RETIRE_GRACE COLLAPSED TO ~0 ON A SECONDS-OLD ROW. Epoch 0 was demoted to \
             'retiring' by a promote that committed moments ago; it is owed the full 30s so \
             every peer still finishing a handshake on the old key keeps it. Dropping the \
             tracker on a NoMatch whose row was merely SUPERSEDED (not gone) removes the only \
             thing making sweep_rotations step 3 skip this gateway, and that path deletes \
             immediately and deliberately. Pre-retype this same interleaving was safe — the \
             CAS returned Err, the tracker stayed, the promoter stamped promoted_at, and the \
             retire ran under grace — so this is a REGRESSION, not a pre-existing gap"
        );
        assert!(
            rotations.lock().await.contains_key(&GW),
            "and the tracker must survive the sweep too: decide's rule 1 sees promoted_at \
             stamped moments ago, so it must return Wait, not Retire, until RETIRE_GRACE has \
             actually elapsed"
        );
    }
}
