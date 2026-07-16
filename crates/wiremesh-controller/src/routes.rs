//! Route/peer computation for the Sync projection (Task 7): the full-mesh
//! set of peers a given gateway must learn about — every OTHER enrolled
//! gateway, each with its segment's CIDRs (the peer's `allowed_ips`) and its
//! active WireGuard key(s), if any.
//!
//! Cycle-2 has no notion of segment reachability policy at the routing
//! layer (that's `policy_ir`, still an empty v0 IR) — every gateway is
//! meshed with every other gateway. Pruning the mesh by policy is future
//! work, not this task's.

use crate::db_async::DbHandle;

/// One peer this gateway must learn about, ready to be turned into a
/// `wiremesh_proto::v1::Peer` by [`crate::projection::build_snapshot`].
pub struct PeerRoute {
    pub gateway_id: i64,
    pub segment_name: String,
    /// `(epoch, pubkey, state)` for EVERY `gateway_key` row of this peer —
    /// `pending`/`active`/`retiring` alike (see
    /// [`crate::db::Db::all_keys_for_gateway`]), so a mid-rotation `pending`
    /// epoch (Task 11's `RotateKey`) is visible to peers the same way it
    /// would be in a fresh snapshot. Empty only if the peer somehow has no
    /// `gateway_key` rows at all (shouldn't happen post-Task-11: every
    /// enrolled gateway gets an epoch-0 `active` baseline).
    pub keys: Vec<(i64, String, String)>,
    /// The peer's segment's CIDRs — this peer's `allowed_ips`.
    pub allowed_ips: Vec<String>,
}

/// The full-mesh peer set for `self_gateway_id`: every other enrolled
/// gateway, each with its segment's CIDRs and active keys. A deployment
/// with only one enrolled gateway (`self_gateway_id` itself) yields an
/// empty `Vec` — there is no one else to mesh with yet.
pub async fn peers_of(db: &DbHandle, self_gateway_id: i64) -> anyhow::Result<Vec<PeerRoute>> {
    let others = db.list_other_gateways(self_gateway_id).await?;

    let mut peers = Vec::with_capacity(others.len());
    for gw in others {
        let allowed_ips = db.cidrs_for_segment(gw.segment_id).await?;
        let keys = db.all_keys_for_gateway(gw.id).await?;
        peers.push(PeerRoute {
            gateway_id: gw.id,
            segment_name: gw.segment_name,
            keys,
            allowed_ips,
        });
    }
    Ok(peers)
}
