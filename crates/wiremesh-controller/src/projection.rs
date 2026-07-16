//! The Sync `StateSnapshot` projection (Task 7): assembles everything a
//! single connecting gateway needs to know into one wire message, straight
//! off the DB (`db_async::DbHandle`) plus whatever the mTLS layer already
//! resolved about the caller (its own identity and cert).
//!
//! Cycle-2 scope, per the engineering design's amendments: `policy_ir` is
//! always an empty v0 IR (`policy_version = 0`) — the policy pipeline is a
//! later task — and `relays` is always empty (relay support is later too).
//! `revision` is a simple monotonic counter (see `services::sync::SyncSvc`),
//! not derived from any versioned DB state; a single connect only needs
//! *some* value `>= 1`, not a globally meaningful revision number.

use wiremesh_proto::v1::{Peer, PeerKey, StateSnapshot};

use crate::db_async::DbHandle;
use crate::routes;

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
    revision: u64,
) -> anyhow::Result<StateSnapshot> {
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
