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
/// see `crate::services::sync` and `crate::services::enrollment`) so an
/// already-open Sync stream can push an incremental [`Delta`] instead of
/// waiting for the gateway to reconnect and re-fetch a full snapshot.
///
/// Cycle-2/Task 8 scope: the only event produced today is "a new gateway
/// enrolled" (a full-mesh peer every OTHER already-connected gateway must
/// learn about). Key rotation, segment CIDR changes, and revocation are
/// later tasks' events, added as further variants/fields once they exist —
/// deliberately not modeled as an enum yet since there's only one case.
#[derive(Clone, Debug)]
pub struct ChangeEvent {
    /// The newly enrolled gateway's id — a `Sync.Watch` connection for THIS
    /// SAME gateway must skip its own event (it would otherwise receive a
    /// delta "adding" itself as its own peer).
    pub new_gateway_id: i64,
    pub segment_name: String,
    /// The new gateway's segment's CIDRs — becomes the upserted peer's
    /// `allowed_ips`.
    pub allowed_ips: Vec<String>,
    /// The persisted revision the mutation bumped to
    /// ([`crate::db_async::DbHandle::current_revision`], read AFTER the
    /// mutation's transaction committed) — strictly greater than any
    /// snapshot/delta revision a connected gateway has already seen.
    pub revision: u64,
}

/// Turns a [`ChangeEvent`] into the [`Delta`] a `Sync.Watch` connection
/// forwards to its gateway. A freshly enrolled gateway has no
/// `gateway_key` rows yet (key management is Task 11), so `keys` is always
/// empty here — same as `build_snapshot`'s peers before any key exists.
pub fn delta_for_change(event: ChangeEvent) -> Delta {
    Delta {
        revision: event.revision,
        upserted_peers: vec![Peer {
            gateway_id: event.new_gateway_id as u64,
            segment_name: event.segment_name,
            keys: Vec::new(),
            candidate_endpoints: Vec::new(),
            allowed_ips: event.allowed_ips,
        }],
        removed_peer_ids: Vec::new(),
        // Relay/policy/revocation deltas are later tasks' scope — cycle-2's
        // only change source is "a gateway enrolled" (see `ChangeEvent`).
        relays: Vec::new(),
        policy_ir: Vec::new(),
        policy_version: 0,
        revoked_serials: Vec::new(),
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
            // Candidate endpoints (NAT-traversal discovery) are Task 15's
            // scope — always empty in cycle-2's Sync projection.
            candidate_endpoints: Vec::new(),
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
