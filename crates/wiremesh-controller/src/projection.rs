//! The Sync `StateSnapshot` projection (Task 7): assembles everything a
//! single connecting gateway needs to know into one wire message, straight
//! off the DB (`db_async::DbHandle`) plus whatever the mTLS layer already
//! resolved about the caller (its own identity and cert).
//!
//! `policy_ir`/`policy_version` are sourced from
//! [`crate::db::Db::latest_policy`] (cycle-3 Task 4): the exact
//! canonical-JSON bytes `Db::apply_fabric` compiled and stored at apply
//! time, served VERBATIM — this module never recompiles, so a snapshot can
//! never drift from what was actually validated and versioned. Still
//! empty/`0` on a fresh controller that has never had a policy applied.
//! `relay_infos` (Cycle-4c Task 5) is every currently `active` relay row, off
//! [`crate::db::Db::active_relays`] — empty on a fresh controller with none
//! enrolled/registered yet. `revision` is
//! the persisted `state_revision` counter
//! ([`crate::db::Db::current_revision`]) — a value that survives a
//! controller restart, so a reconnecting gateway never sees the revision go
//! backwards (which would break T8 delta comparison / T9 fail-static
//! resync).

use tokio::sync::broadcast;
use tonic::Status;
use wiremesh_proto::v1::{Delta, Peer, PeerKey, RelayInfo, StateSnapshot};

use crate::db::AWAITING_SUBMISSION_SENTINEL;
use crate::db_async::DbHandle;
use crate::routes;

/// (Key-rotation Task 8a) Maps a gateway's FULL raw `(epoch, pubkey, state)`
/// key rows (straight off [`crate::db::Db::all_keys_for_gateway`]/
/// [`crate::db::Db::keys_snapshot`]/`routes::peers_of`) to the wire
/// [`PeerKey`] shape, WITHHOLDING any row that's still carrying
/// [`AWAITING_SUBMISSION_SENTINEL`] — a `pending` epoch [`crate::db::Db::rotate_key`]
/// just created but the rotating gateway hasn't yet replaced with its real
/// pubkey via `Sync.SubmitEpochKey` (`crate::db::Db::set_epoch_pubkey`). A
/// peer has no use for a key that doesn't exist yet, and a gateway that
/// actually tried to configure a WireGuard peer entry with that literal
/// string as a pubkey would fail outright. This is the single choke point
/// every site that builds a peer's advertised `keys` (both `build_snapshot`
/// and every `delta_for_change` arm below) must route through, so a fresh
/// snapshot and every delta withhold the sentinel consistently.
fn advertisable_peer_keys(keys: Vec<(i64, String, String)>) -> Vec<PeerKey> {
    keys.into_iter()
        .filter(|(_, pubkey, state)| {
            !(state == "pending" && pubkey == AWAITING_SUBMISSION_SENTINEL)
        })
        .map(|(epoch, pubkey, state)| PeerKey {
            epoch: epoch as u32,
            pubkey,
            state,
        })
        .collect()
}

/// A projection-affecting mutation, broadcast (via a
/// `tokio::sync::broadcast::Sender<ChangeEvent>` shared by every service
/// that can mutate the projection and every live `Sync.Watch` connection —
/// see `crate::services::sync`, `crate::services::enrollment`, and
/// `crate::services::admin`) so an already-open Sync stream can push an
/// incremental [`Delta`] instead of waiting for the gateway to reconnect
/// and re-fetch a full snapshot.
///
/// Cycle-2 scope: `GatewayEnrolled` (Task 8) and `KeyRotated` (Task 11).
/// Cycle-3 adds `PolicyUpdated` (Task 4) and `SegmentCidrsChanged` (Task 5).
#[derive(Clone, Debug)]
pub enum ChangeEvent {
    /// A new gateway enrolled — a full-mesh peer every OTHER
    /// already-connected gateway must learn about.
    GatewayEnrolled {
        new_gateway_id: i64,
        segment_name: String,
        /// The new gateway's segment's CIDRs — becomes the upserted peer's
        /// `allowed_ips`.
        allowed_ips: Vec<String>,
        /// (Mesh-convergence T6, CodeRabbit) The cert serial(s) this
        /// enrollment revoked — non-empty ONLY for a `rebind` (which replaces
        /// the segment's prior gateway and revokes its cert), empty for an
        /// ordinary enrollment. Folded into this event's `Delta.revoked_serials`
        /// so an already-open `Sync.Watch` — GATEWAY *and* RELAY — denylists
        /// the replaced gateway's serial immediately (mirroring
        /// `GatewayDrained`, which carries both a peer change and its
        /// `revoked_serials` in one delta). Without this a relay's offline
        /// denylist would silently miss rebind revocations until it reconnects.
        revoked_serials: Vec<String>,
        /// The persisted revision the mutation bumped to
        /// ([`crate::db_async::DbHandle::current_revision`], read AFTER the
        /// mutation's transaction committed) — strictly greater than any
        /// snapshot/delta revision a connected gateway has already seen.
        revision: u64,
    },
    /// (Task 11) `Admin.RotateKey` created a new `pending` `gateway_key`
    /// epoch for `gateway_id` — every OTHER already-connected gateway's
    /// peer view of it must be upserted with its FULL current key set (all
    /// epochs/states), so an open Sync.Watch stream stays consistent with
    /// what a fresh snapshot would show.
    KeyRotated {
        gateway_id: i64,
        segment_name: String,
        allowed_ips: Vec<String>,
        /// `(epoch, pubkey, state)` for every `gateway_key` row of
        /// `gateway_id`, straight off [`crate::db::Db::all_keys_for_gateway`]
        /// — includes the just-inserted `pending` row.
        keys: Vec<(i64, String, String)>,
        /// (Key-rotation Task 8a) `gateway_id`'s FULL current candidate set
        /// (observed + locals, deduplicated, observed first) — straight off
        /// [`crate::db::Db::candidates_for`], mirroring `EndpointObserved`/
        /// `SegmentCidrsChanged`'s identical widening: a rotation must not
        /// make an already-open `Sync.Watch` stream forget a peer's
        /// previously reported/observed candidate endpoint.
        candidate_endpoints: Vec<String>,
        revision: u64,
    },
    /// (Task 12, G-7) `Admin.Drain` removed `gateway_id` and revoked its
    /// cert(s) — every OTHER already-connected gateway must withdraw it as a
    /// peer (`Delta::removed_peer_ids`) and learn its revoked cert serial(s),
    /// the same way a fresh snapshot would no longer list it as a peer and
    /// would carry its serial(s) in `revoked_serials`.
    GatewayDrained {
        gateway_id: i64,
        /// Serial(s) [`crate::db::Db::drain_gateway`] just revoked — folded
        /// into this delta's `revoked_serials` so an already-open
        /// `Sync.Watch` stream doesn't have to wait for a reconnect/fresh
        /// snapshot to see them denylisted.
        revoked_serials: Vec<String>,
        revision: u64,
    },
    /// (Task 15) The controller's UDP observation endpoint recorded a new
    /// candidate endpoint for `gateway_id` — every OTHER already-connected
    /// gateway's peer view of it must be upserted with its FULL current
    /// state (keys + allowed_ips + the new candidate), so an open
    /// `Sync.Watch` stream stays consistent with what a fresh snapshot
    /// would show. Bonus over this task's minimum bar (a fresh snapshot
    /// already reflects the candidate — see `crate::observe`'s module doc
    /// comment) but costs little given `KeyRotated` already established the
    /// full-peer-refresh pattern.
    EndpointObserved {
        gateway_id: i64,
        segment_name: String,
        allowed_ips: Vec<String>,
        keys: Vec<(i64, String, String)>,
        /// (Cycle-4b Task 3) The gateway's FULL current candidate set
        /// (observed + locals, deduplicated, observed first) — straight off
        /// [`crate::db::Db::candidates_for`], not just the freshly observed
        /// value, so an already-open `Sync.Watch` stream's view of this peer
        /// stays consistent with what a fresh snapshot would show (mirroring
        /// `SegmentCidrsChanged`'s identical widening below).
        candidate_endpoints: Vec<String>,
        revision: u64,
    },
    /// (Task 16) `Admin.RevokeCert` revoked a single certificate by serial —
    /// distinct from `GatewayDrained`: this does NOT remove any gateway row
    /// or peer (a gateway can have its cert revoked without being drained,
    /// e.g. ahead of a planned re-enrollment), so no `upserted_peers`/
    /// `removed_peer_ids` change — only the revoked-serials denylist grows.
    /// Every already-connected gateway's next `Delta` must carry `serial` in
    /// `revoked_serials` so it doesn't have to wait for a reconnect/fresh
    /// snapshot to see it denylisted, mirroring `GatewayDrained`'s identical
    /// push.
    CertRevoked { serial: String, revision: u64 },
    /// (Cycle-3 Task 4) `Admin.Apply` compiled and stored a genuinely NEW
    /// policy version (design D-C3-8: fingerprint-based, not every apply
    /// that merely re-submits an unchanged policy) — every ALREADY-connected
    /// gateway must learn the new IR, not just gateways that connect after
    /// the fact (those get it via `build_snapshot`). `ir` is the exact
    /// canonical-JSON bytes stored in `policy_version.compiled_ir`.
    PolicyUpdated {
        version: u64,
        ir: Vec<u8>,
        revision: u64,
    },
    /// (Cycle-3 Task 5) `Admin.Apply` REPLACED an existing segment's `cidr`
    /// rows (its declared CIDR set changed) — every OTHER already-connected
    /// gateway's peer view of `gateway_id` (the segment's own enrolled
    /// gateway) must be upserted with its FULL current state (keys +
    /// GROWN/SHRUNK `allowed_ips` + its current candidate endpoint, if any),
    /// mirroring [`ChangeEvent::KeyRotated`]'s full-peer-refresh pattern — an
    /// open `Sync.Watch` stream stays consistent with what a fresh snapshot
    /// would show without waiting for a reconnect. Only published for a
    /// segment that actually has an enrolled gateway
    /// (`Db::active_gateway_for_segment` returned `Some`) — a CIDR change on
    /// a segment with no gateway yet has no peer to upsert.
    SegmentCidrsChanged {
        gateway_id: i64,
        segment_name: String,
        allowed_ips: Vec<String>,
        /// `(epoch, pubkey, state)` for every `gateway_key` row of
        /// `gateway_id`, straight off [`crate::db::Db::all_keys_for_gateway`]
        /// — same full-key-set rationale as `KeyRotated`.
        keys: Vec<(i64, String, String)>,
        /// `gateway_id`'s FULL current candidate set (observed + locals,
        /// deduplicated, observed first — same [`crate::db::Db::candidates_for`]
        /// lookup `build_snapshot`/`routes::peers_of` use) — a CIDR refresh
        /// must not erase a known candidate from an already-open
        /// `Sync.Watch` stream's view of this peer.
        candidate_endpoints: Vec<String>,
        revision: u64,
    },
    /// (Cycle-4c Task 5) Relay enrollment created a new `active` `relay` row
    /// — every already-connected gateway must learn the FULL current
    /// active-relay set (not just the one just enrolled), so a delta stays
    /// consistent with what a fresh `build_snapshot` would show, mirroring
    /// `KeyRotated`/`SegmentCidrsChanged`'s full-refresh rationale.
    RelaysChanged {
        relay_infos: Vec<RelayInfo>,
        revision: u64,
    },
}

impl ChangeEvent {
    /// The gateway id this event is ABOUT. Used by `SyncSvc::watch` to skip
    /// forwarding an event to the very connection whose own gateway it
    /// describes — a gateway must never receive a delta "adding"/"updating"
    /// itself as its own peer (the full-mesh projection always excludes
    /// self; see `Db::list_other_gateways`).
    pub fn subject_gateway_id(&self) -> i64 {
        match self {
            ChangeEvent::GatewayEnrolled { new_gateway_id, .. } => *new_gateway_id,
            ChangeEvent::KeyRotated { gateway_id, .. } => *gateway_id,
            ChangeEvent::GatewayDrained { gateway_id, .. } => *gateway_id,
            ChangeEvent::EndpointObserved { gateway_id, .. } => *gateway_id,
            // Not "about" any single gateway (a revoked cert's serial is
            // known, but which gateway subject_id it belonged to is not
            // threaded through this event) — `0` is never a real
            // AUTOINCREMENT `gateway.id` (SQLite AUTOINCREMENT starts at 1),
            // so this never accidentally matches a real `self_gateway_id`
            // and skips forwarding to someone who should see it. Every
            // connected gateway, including the one whose own cert was just
            // revoked, is meant to learn about a revocation.
            ChangeEvent::CertRevoked { .. } => 0,
            // Not "about" any single gateway either — every connected
            // gateway (this task's `already_connected_gateway_receives_
            // policy_delta_on_live_apply` test included) must receive a
            // newly compiled policy, mirroring `CertRevoked`'s rationale
            // above.
            ChangeEvent::PolicyUpdated { .. } => 0,
            ChangeEvent::SegmentCidrsChanged { gateway_id, .. } => *gateway_id,
            // Not "about" any single gateway — a newly enrolled relay is a
            // fabric-wide fact every connected gateway must learn, mirroring
            // `CertRevoked`/`PolicyUpdated`'s rationale above (and, like
            // them, `0` never collides with a real `gateway.id`).
            ChangeEvent::RelaysChanged { .. } => 0,
        }
    }
}

/// Turns a [`ChangeEvent`] into the [`Delta`] a `Sync.Watch` connection
/// forwards to its gateway.
///
/// `#[allow(deprecated)]`: every branch below must set `deprecated_relays`
/// (field 4, kept at its original `repeated string` type and never
/// populated — see `sync.proto`'s doc comment) since it's a required struct
/// field of the generated `Delta` type; this is the one place that's
/// expected to still reference it, deliberately, as an always-empty value.
#[allow(deprecated)]
pub fn delta_for_change(event: ChangeEvent) -> Delta {
    match event {
        ChangeEvent::GatewayEnrolled {
            new_gateway_id,
            segment_name,
            allowed_ips,
            revoked_serials,
            revision,
        } => Delta {
            revision,
            upserted_peers: vec![Peer {
                gateway_id: new_gateway_id as u64,
                segment_name,
                // A freshly enrolled gateway's epoch-0 baseline key is
                // deliberately NOT included here: `EnrollmentSvc` publishes
                // this event before Task 11 existed and a peer will pick up
                // the baseline key on its next full snapshot/reconnect, or
                // on the gateway's first `RotateKey`. Keeping this delta
                // minimal (identity + allowed_ips only) matches the
                // pre-Task-11 wire shape this test suite already relies on
                // (`tests/sync_delta.rs` doesn't assert on `keys`).
                keys: Vec::new(),
                candidate_endpoints: Vec::new(),
                allowed_ips,
            }],
            removed_peer_ids: Vec::new(),
            deprecated_relays: Vec::new(),
            relay_infos: Vec::new(),
            relays_updated: false,
            policy_ir: Vec::new(),
            policy_version: 0,
            // (Mesh-convergence T6, CodeRabbit) Empty for an ordinary enroll
            // (wire shape unchanged); on a `rebind` this carries the replaced
            // gateway's revoked serial(s) so a GATEWAY watcher denylists them
            // in the same delta that upserts the replacement peer.
            revoked_serials,
        },
        ChangeEvent::KeyRotated {
            gateway_id,
            segment_name,
            allowed_ips,
            keys,
            candidate_endpoints,
            revision,
        } => Delta {
            revision,
            upserted_peers: vec![Peer {
                gateway_id: gateway_id as u64,
                segment_name,
                keys: advertisable_peer_keys(keys),
                candidate_endpoints,
                allowed_ips,
            }],
            removed_peer_ids: Vec::new(),
            deprecated_relays: Vec::new(),
            relay_infos: Vec::new(),
            relays_updated: false,
            policy_ir: Vec::new(),
            policy_version: 0,
            revoked_serials: Vec::new(),
        },
        ChangeEvent::GatewayDrained {
            gateway_id,
            revoked_serials,
            revision,
        } => Delta {
            revision,
            // No peer identity is upserted — the drained gateway is being
            // withdrawn, not updated.
            upserted_peers: Vec::new(),
            removed_peer_ids: vec![gateway_id as u64],
            deprecated_relays: Vec::new(),
            relay_infos: Vec::new(),
            relays_updated: false,
            policy_ir: Vec::new(),
            policy_version: 0,
            revoked_serials,
        },
        ChangeEvent::EndpointObserved {
            gateway_id,
            segment_name,
            allowed_ips,
            keys,
            candidate_endpoints,
            revision,
        } => Delta {
            revision,
            upserted_peers: vec![Peer {
                gateway_id: gateway_id as u64,
                segment_name,
                keys: advertisable_peer_keys(keys),
                candidate_endpoints,
                allowed_ips,
            }],
            removed_peer_ids: Vec::new(),
            deprecated_relays: Vec::new(),
            relay_infos: Vec::new(),
            relays_updated: false,
            policy_ir: Vec::new(),
            policy_version: 0,
            revoked_serials: Vec::new(),
        },
        ChangeEvent::CertRevoked { serial, revision } => Delta {
            revision,
            // No peer identity changes — see this variant's doc comment.
            upserted_peers: Vec::new(),
            removed_peer_ids: Vec::new(),
            deprecated_relays: Vec::new(),
            relay_infos: Vec::new(),
            relays_updated: false,
            policy_ir: Vec::new(),
            policy_version: 0,
            revoked_serials: vec![serial],
        },
        ChangeEvent::PolicyUpdated {
            version,
            ir,
            revision,
        } => Delta {
            revision,
            // No peer/revocation change — only the policy fields carry
            // anything, per this variant's doc comment.
            upserted_peers: Vec::new(),
            removed_peer_ids: Vec::new(),
            deprecated_relays: Vec::new(),
            relay_infos: Vec::new(),
            relays_updated: false,
            policy_ir: ir,
            policy_version: version,
            revoked_serials: Vec::new(),
        },
        ChangeEvent::SegmentCidrsChanged {
            gateway_id,
            segment_name,
            allowed_ips,
            keys,
            candidate_endpoints,
            revision,
        } => Delta {
            revision,
            upserted_peers: vec![Peer {
                gateway_id: gateway_id as u64,
                segment_name,
                keys: advertisable_peer_keys(keys),
                candidate_endpoints,
                allowed_ips,
            }],
            removed_peer_ids: Vec::new(),
            deprecated_relays: Vec::new(),
            relay_infos: Vec::new(),
            relays_updated: false,
            policy_ir: Vec::new(),
            policy_version: 0,
            revoked_serials: Vec::new(),
        },
        ChangeEvent::RelaysChanged {
            relay_infos,
            revision,
        } => Delta {
            revision,
            // No peer/revocation change — only `relay_infos` carries
            // anything, per this variant's doc comment. `relays_updated:
            // true` is the whole point of this event/arm: it's what lets
            // `apply_delta` (gateway side) replace the relay set even when
            // `relay_infos` is empty (last-relay eviction) — see
            // `Delta.relays_updated`'s doc comment in `sync.proto`.
            upserted_peers: Vec::new(),
            removed_peer_ids: Vec::new(),
            deprecated_relays: Vec::new(),
            relay_infos,
            relays_updated: true,
            policy_ir: Vec::new(),
            policy_version: 0,
            revoked_serials: Vec::new(),
        },
    }
}

/// Builds the full `StateSnapshot` for `gateway_id` connecting to Sync.
///
/// `self_cert_pem` is passed in rather than looked up from the DB: the DB
/// never stores a gateway's cert PEM (only its serial/issuer handle, in
/// `certificate`) — the caller (`services::sync::SyncSvc::watch`) already
/// has the exact PEM bytes from the mTLS peer certificate it just used to
/// identify the gateway, so re-deriving/storing a second copy would be
/// redundant and could drift from what's actually on the wire.
///
/// `#[allow(deprecated)]`: constructing `StateSnapshot` requires setting
/// `deprecated_relays` (see `delta_for_change`'s identical note).
#[allow(deprecated)]
pub async fn build_snapshot(
    db: &DbHandle,
    gateway_id: i64,
    self_cert_pem: String,
) -> anyhow::Result<StateSnapshot> {
    // Persisted, restart-surviving revision (see this module's doc comment).
    let revision = db.current_revision().await?;
    let peer_routes = routes::peers_of(db, gateway_id).await?;
    let peers = peer_routes
        .into_iter()
        .map(|p| Peer {
            gateway_id: p.gateway_id as u64,
            segment_name: p.segment_name,
            // (Key-rotation Task 8a) Same sentinel-withholding guard every
            // `delta_for_change` arm uses, applied here too so a FRESH
            // snapshot never advertises a pending epoch that's still
            // carrying the "awaiting-submission" placeholder pubkey.
            keys: advertisable_peer_keys(p.keys),
            // (Task 15; cycle-4b Task 3 widened this to the full set —
            // observed + locally-reported addresses, deduplicated, observed
            // first) See `crate::routes::PeerRoute::candidate_endpoints`'s
            // doc comment / `Db::candidates_for`.
            candidate_endpoints: p.candidate_endpoints,
            allowed_ips: p.allowed_ips,
        })
        .collect();

    // (Cycle-4c Task 5) Every currently `active` relay, straight off
    // `Db::active_relays` — see this module's doc comment. Carried on the
    // wire in `relay_infos` (field 8) — see `sync.proto`'s doc comment on
    // `deprecated_relays` (field 4) for why the structured data lives in a
    // new field rather than the original one.
    let relay_infos = db
        .active_relays()
        .await?
        .into_iter()
        .map(|(id, endpoint)| RelayInfo {
            relay_id: id as u64,
            endpoint,
        })
        .collect();

    let revoked_serials = db.revoked_serials().await?;

    // (Cycle-3 Task 4) The latest compiled policy's exact stored bytes —
    // never recompiled here (see this module's doc comment). `None` (fresh
    // controller, no policy ever applied) maps to the same empty/`0`
    // placeholder cycle-2 always sent.
    let (policy_version, policy_ir) = match db.latest_policy().await? {
        Some((version, compiled_ir_json)) => (version, compiled_ir_json.into_bytes()),
        None => (0, Vec::new()),
    };

    Ok(StateSnapshot {
        revision,
        self_cert_pem,
        peers,
        deprecated_relays: Vec::new(),
        relay_infos,
        policy_ir,
        policy_version,
        revoked_serials,
    })
}

/// (Mesh-convergence T6, ops-finding "Relay Finding B") The REVOCATION-SCOPED
/// snapshot an enrolled RELAY receives when it opens `Sync.Watch` (the
/// operation the finding reports as wrongly rejected: a relay's leaf CN is
/// `relay-<secret_hash_hex>`, never a `gateway.name`, so the gateway-only CN
/// lookup denied it and its offline denylist never refreshed after
/// enrollment).
///
/// A relay is NOT a gateway and must never receive gateway desired-state:
/// this snapshot carries ONLY what the relay's denylist consumer needs —
/// `revoked_serials` (its `Denylist::replace_all` input) and the persisted
/// `revision` — with `peers`, `relay_infos`, and `policy_ir`/`policy_version`
/// all deliberately EMPTY/`0`. That omission is the security boundary
/// (`services::sync`'s relay watch branch mirrors it for deltas), not an
/// optimization: a relay bridges opaque WireGuard datagrams and has no use
/// for — and must not be told — the mesh's peer set or compiled policy.
/// `self_cert_pem` is echoed back the same way [`build_snapshot`] echoes a
/// gateway's, so the relay's consumer sees the identical `StateSnapshot`
/// shape (first message on the stream) it already expects.
///
/// `#[allow(deprecated)]`: constructing `StateSnapshot` requires setting
/// `deprecated_relays` (see [`build_snapshot`]'s identical note).
#[allow(deprecated)]
pub async fn build_relay_revocation_snapshot(
    db: &DbHandle,
    self_cert_pem: String,
) -> anyhow::Result<StateSnapshot> {
    // (CodeRabbit) `revision` and `revoked_serials` MUST come from one atomic
    // read — a revocation committing between two separate reads would hand the
    // relay a `revision`/`revoked_serials` pair from different instants. See
    // `Db::revocation_snapshot`.
    let (revision, revoked_serials) = db.revocation_snapshot().await?;
    Ok(StateSnapshot {
        revision,
        self_cert_pem,
        peers: Vec::new(),
        deprecated_relays: Vec::new(),
        relay_infos: Vec::new(),
        policy_ir: Vec::new(),
        policy_version: 0,
        revoked_serials,
    })
}

/// (Mesh-convergence T6, ops-finding "Relay Finding B") Turns a
/// [`ChangeEvent`] into the REVOCATION-ONLY [`Delta`] an enrolled relay's
/// `Sync.Watch` forwards — or `None` for any event that carries no
/// revocation, so the relay's stream stays limited to the denylist-relevant
/// subset.
///
/// This is the delta-side twin of [`build_relay_revocation_snapshot`]'s
/// security boundary. Three `ChangeEvent`s bear revocation:
///
///   * [`ChangeEvent::CertRevoked`] — `Admin.RevokeCert` (the relay's
///     `Denylist::union` input);
///   * [`ChangeEvent::GatewayDrained`] — a drain revokes the drained
///     gateway's cert serial(s); its `revoked_serials` are forwarded, but its
///     `removed_peer_ids` (gateway peer-set desired-state) are DROPPED — a
///     relay must never learn peer removals.
///   * [`ChangeEvent::GatewayEnrolled`] with a non-empty `revoked_serials` —
///     a `rebind` enrollment replaces the segment's prior gateway and revokes
///     its cert (CodeRabbit T6 finding). Its `revoked_serials` are forwarded,
///     but its `upserted_peers` (the replacement gateway's identity —
///     desired-state) are DROPPED, exactly as `GatewayDrained`'s peer-removal
///     is. An ordinary (non-rebind) enroll carries no serials and returns
///     `None`, so nothing peer-shaped ever reaches a relay.
///
/// Every other event (key rotations, policy updates, relay-set changes,
/// endpoint observations) returns `None` and never reaches a relay. Critically
/// this means a relay's stream also never carries `upserted_peers`,
/// `policy_ir`, a `PunchDirective`, or a `RotateDirective` — the last two
/// aren't even broadcast events (the punch broker and rotation directives are
/// per-gateway channels the relay watch branch never wires up at all — see
/// `services::sync`).
///
/// `#[allow(deprecated)]`: constructing `Delta` requires setting
/// `deprecated_relays` (see [`delta_for_change`]'s identical note).
#[allow(deprecated)]
pub fn relay_revocation_delta(event: ChangeEvent) -> Option<Delta> {
    let (revoked_serials, revision) = match event {
        ChangeEvent::CertRevoked { serial, revision } => (vec![serial], revision),
        ChangeEvent::GatewayDrained {
            revoked_serials,
            revision,
            ..
        }
        | ChangeEvent::GatewayEnrolled {
            revoked_serials,
            revision,
            ..
        } => {
            if revoked_serials.is_empty() {
                // A drain that revoked nothing, or an ordinary (non-rebind)
                // enroll, has no denylist news for a relay — don't forward an
                // empty, contentless delta.
                return None;
            }
            (revoked_serials, revision)
        }
        _ => return None,
    };
    Some(Delta {
        revision,
        upserted_peers: Vec::new(),
        removed_peer_ids: Vec::new(),
        deprecated_relays: Vec::new(),
        relay_infos: Vec::new(),
        relays_updated: false,
        policy_ir: Vec::new(),
        policy_version: 0,
        revoked_serials,
    })
}

/// (Key-rotation Task 2; DRY extraction) Re-reads `gateway_id`'s current
/// segment identity, `allowed_ips`, and FULL current key set (all
/// epochs/states), then publishes a [`ChangeEvent::KeyRotated`] — the shared
/// "re-read and fan out" tail end of anything that changes a gateway's key
/// set: originally `AdminSvc::rotate_key` (which still calls this after
/// `Db::rotate_key` commits) and now also `SyncSvc::submit_epoch_key` (after
/// `Db::set_epoch_pubkey` overwrites the pending epoch's sentinel with the
/// gateway's real pubkey) — both need every OTHER already-connected
/// gateway's peer view of `gateway_id` upserted, same as a fresh snapshot
/// would show.
///
/// A missing identity here means `gateway_id` vanished between the caller's
/// mutation and this re-read — treated as an internal error (shouldn't
/// happen: nothing in the controller deletes `gateway` rows outright).
/// `change_tx.send`'s only error case (no current `Sync.Watch` subscribers)
/// is not a failure and is silently ignored, mirroring every other
/// best-effort publish in this crate.
///
/// (Key-rotation Task 3) `keys`/`revision` are read via
/// [`crate::db_async::DbHandle::keys_snapshot`] — a single atomic lock hold
/// over BOTH reads, not two separate `all_keys_for_gateway` +
/// `current_revision` calls — so a `KeyRotated` delta's key set and the
/// revision it's tagged with are always a single consistent snapshot. See
/// [`crate::db::Db::keys_snapshot`]'s doc comment (mirrors
/// [`crate::db::Db::relays_snapshot`]'s identical TOCTOU rationale): without
/// this, a promote/retire racing a concurrent mutation between two separate
/// reads could broadcast a stale key set tagged with a newer revision.
pub(crate) async fn emit_key_rotated(
    db: &DbHandle,
    change_tx: &broadcast::Sender<ChangeEvent>,
    gateway_id: i64,
) -> Result<(), Status> {
    let identity = db
        .gateway_identity_by_id(gateway_id)
        .await
        .map_err(|e| Status::internal(format!("re-reading gateway after key change: {e}")))?
        .ok_or_else(|| {
            Status::internal(format!(
                "gateway {gateway_id} vanished immediately after a key-rotation mutation committed"
            ))
        })?;
    let allowed_ips = db
        .cidrs_for_segment(identity.segment_id)
        .await
        .map_err(|e| Status::internal(format!("reading segment cidrs after key change: {e}")))?;
    let (keys, revision) = db
        .keys_snapshot(gateway_id)
        .await
        .map_err(|e| Status::internal(format!("reading gateway keys after key change: {e}")))?;
    // (Key-rotation Task 8a) `gateway_id`'s FULL current candidate set —
    // preserved on the KeyRotated delta so a rotation doesn't clobber an
    // already-open Sync.Watch stream's view of a previously reported/
    // observed candidate endpoint (mirroring EndpointObserved/
    // SegmentCidrsChanged's identical widening).
    let candidate_endpoints = db.candidates_for(gateway_id).await.map_err(|e| {
        Status::internal(format!("reading gateway candidates after key change: {e}"))
    })?;

    let _ = change_tx.send(ChangeEvent::KeyRotated {
        gateway_id,
        segment_name: identity.segment_name,
        allowed_ips,
        keys,
        candidate_endpoints,
        revision,
    });

    Ok(())
}
