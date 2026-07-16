//! The Sync `StateSnapshot` projection (Task 7): assembles everything a
//! single connecting gateway needs to know into one wire message, straight
//! off the DB (`db_async::DbHandle`) plus whatever the mTLS layer already
//! resolved about the caller (its own identity and cert).
//!
//! Cycle-2 scope, per the engineering design's amendments: `policy_ir` is
//! always an empty v0 IR (`policy_version = 0`) — the policy pipeline is a
//! later task — and `relays` is always empty (relay support is later too).
//! `revision` is the persisted `state_revision` counter
//! ([`crate::db::Db::current_revision`]) — a value that survives a
//! controller restart, so a reconnecting gateway never sees the revision go
//! backwards (which would break T8 delta comparison / T9 fail-static
//! resync).

use wiremesh_proto::v1::{Delta, Peer, PeerKey, StateSnapshot};

use crate::db_async::DbHandle;
use crate::routes;

/// A projection-affecting mutation, broadcast (via a
/// `tokio::sync::broadcast::Sender<ChangeEvent>` shared by every service
/// that can mutate the projection and every live `Sync.Watch` connection —
/// see `crate::services::sync`, `crate::services::enrollment`, and
/// `crate::services::admin`) so an already-open Sync stream can push an
/// incremental [`Delta`] instead of waiting for the gateway to reconnect
/// and re-fetch a full snapshot.
///
/// Cycle-2 scope: `GatewayEnrolled` (Task 8) and `KeyRotated` (Task 11).
/// Segment CIDR changes and revocation are later tasks' events, added as
/// further variants once they exist.
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
        candidate_endpoint: String,
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
        }
    }
}

/// Turns a [`ChangeEvent`] into the [`Delta`] a `Sync.Watch` connection
/// forwards to its gateway.
pub fn delta_for_change(event: ChangeEvent) -> Delta {
    match event {
        ChangeEvent::GatewayEnrolled {
            new_gateway_id,
            segment_name,
            allowed_ips,
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
            relays: Vec::new(),
            policy_ir: Vec::new(),
            policy_version: 0,
            revoked_serials: Vec::new(),
        },
        ChangeEvent::KeyRotated {
            gateway_id,
            segment_name,
            allowed_ips,
            keys,
            revision,
        } => Delta {
            revision,
            upserted_peers: vec![Peer {
                gateway_id: gateway_id as u64,
                segment_name,
                keys: keys
                    .into_iter()
                    .map(|(epoch, pubkey, state)| PeerKey {
                        epoch: epoch as u32,
                        pubkey,
                        state,
                    })
                    .collect(),
                candidate_endpoints: Vec::new(),
                allowed_ips,
            }],
            removed_peer_ids: Vec::new(),
            relays: Vec::new(),
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
            relays: Vec::new(),
            policy_ir: Vec::new(),
            policy_version: 0,
            revoked_serials,
        },
        ChangeEvent::EndpointObserved {
            gateway_id,
            segment_name,
            allowed_ips,
            keys,
            candidate_endpoint,
            revision,
        } => Delta {
            revision,
            upserted_peers: vec![Peer {
                gateway_id: gateway_id as u64,
                segment_name,
                keys: keys
                    .into_iter()
                    .map(|(epoch, pubkey, state)| PeerKey {
                        epoch: epoch as u32,
                        pubkey,
                        state,
                    })
                    .collect(),
                candidate_endpoints: vec![candidate_endpoint],
                allowed_ips,
            }],
            removed_peer_ids: Vec::new(),
            relays: Vec::new(),
            policy_ir: Vec::new(),
            policy_version: 0,
            revoked_serials: Vec::new(),
        },
        ChangeEvent::CertRevoked { serial, revision } => Delta {
            revision,
            // No peer identity changes — see this variant's doc comment.
            upserted_peers: Vec::new(),
            removed_peer_ids: Vec::new(),
            relays: Vec::new(),
            policy_ir: Vec::new(),
            policy_version: 0,
            revoked_serials: vec![serial],
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
            keys: p
                .keys
                .into_iter()
                .map(|(epoch, pubkey, state)| PeerKey {
                    epoch: epoch as u32,
                    pubkey,
                    state,
                })
                .collect(),
            // (Task 15) At most one candidate: the peer's most recently
            // observed address, if the controller's UDP observation
            // endpoint has ever recorded one for it. Cycle-2 keeps a single
            // last-observed-wins candidate rather than a bounded history
            // (see `Db::set_candidate_endpoint`'s doc comment).
            candidate_endpoints: p.candidate_endpoint.into_iter().collect(),
            allowed_ips: p.allowed_ips,
        })
        .collect();

    let revoked_serials = db.revoked_serials().await?;

    Ok(StateSnapshot {
        revision,
        self_cert_pem,
        peers,
        // Relay support is a later task — cycle-2 ships a direct-only mesh.
        relays: Vec::new(),
        // Empty v0 policy IR (engineering design §11): the policy pipeline
        // compiles real IR starting in a later task.
        policy_ir: Vec::new(),
        policy_version: 0,
        revoked_serials,
    })
}
