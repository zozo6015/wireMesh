//! Task 11's failing test: `RotateKey(gateway_id)` starts a make-before-break
//! key-epoch rotation for a gateway.
//!
//! Boots a real controller, enrolls gateway A ("aws") and a peer gateway B
//! ("gcp") that will observe A's key states via its own `Sync.Watch` stream,
//! then calls the (not-yet-existing) `Admin.RotateKey(gateway_id = a.id())`.
//! That must:
//!
//!   1. insert a new `pending` `GATEWAY_KEY(epoch = n+1)` row for A, and push
//!      a `Delta` down B's still-open Sync stream carrying A as an upserted
//!      peer whose `keys` include one with `state == "pending"`;
//!   2. survive a controller restart — after `h.restart().await`, the
//!      pending epoch must still be readable back out of the DB (via the
//!      testkit's `debug_key_states` admin/debug helper), proving the
//!      rotation's bookkeeping is DB-backed, not just in-memory.
//!
//! None of this exists yet: `RotateKeyRequest` doesn't exist on
//! `wiremesh_proto::v1`, `AdminClient::rotate_key` doesn't exist,
//! `StubGateway::id()` doesn't exist (only `segment_id()` does), and
//! `TestController::debug_key_states` doesn't exist. So today this file does
//! not even COMPILE — that's the expected RED state for this step. The
//! implementer adds all four (growing `admin.proto` with `RotateKey` and
//! `RotateKeyRequest{gateway_id}`, a `src/keys.rs` state machine wired into
//! `src/services/admin.rs`, a `src/projection.rs` peer-key emission, and the
//! testkit accessors) to turn this green.
use std::time::Duration;

use tokio_stream::StreamExt;
use wiremesh_proto::v1::{sync_message, RotateKeyRequest};

#[tokio::test]
async fn key_rotation_advances_epoch_states_and_survives_restart() {
    let mut h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    // Peer that observes A's key states over its own Sync.Watch stream.
    let b = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;

    let mut b_stream = b.open_sync().await;
    // Consume B's initial StateSnapshot (enrolling B after A is already up
    // means the snapshot already contains A as a peer — with no pending
    // epoch key yet, since rotation hasn't happened).
    let snap_msg = b_stream
        .next()
        .await
        .expect("Sync.Watch stream ended before delivering B's initial snapshot")
        .expect("Sync.Watch stream yielded an error instead of B's initial snapshot");
    match snap_msg.body {
        Some(sync_message::Body::Snapshot(_)) => {}
        other => panic!("expected the first Sync.Watch message to be a StateSnapshot, got: {other:?}"),
    }

    h.admin_client()
        .await
        .rotate_key(RotateKeyRequest {
            gateway_id: a.id(),
        })
        .await
        .expect("Admin.RotateKey(gateway_id = a.id()) must succeed");

    // B must see a Delta announcing A's new pending-epoch key, bounded by a
    // timeout so a missing delta fails fast instead of hanging the suite.
    let msg = tokio::time::timeout(Duration::from_secs(5), b_stream.next())
        .await
        .expect("timed out waiting for the delta triggered by Admin.RotateKey")
        .expect("Sync.Watch stream ended before delivering the rotation delta")
        .expect("Sync.Watch stream yielded an error instead of the rotation delta");

    let delta = match msg.body {
        Some(sync_message::Body::Delta(d)) => d,
        other => panic!("expected a Delta after Admin.RotateKey, got: {other:?}"),
    };

    let a_peer = delta
        .upserted_peers
        .iter()
        .find(|p| p.gateway_id == a.id())
        .unwrap_or_else(|| {
            panic!(
                "expected the rotation delta's upserted_peers to include gateway A \
                 (id = {}), got: {:?}",
                a.id(),
                delta.upserted_peers
            )
        });
    assert!(
        a_peer.keys.iter().any(|k| k.state == "pending"),
        "expected gateway A's peer entry in the rotation delta to carry a PeerKey \
         with state == \"pending\", got keys: {:?}",
        a_peer.keys
    );

    // Restart mid-rotation: the pending epoch's bookkeeping must resume from
    // the DB snapshot, not just live in the pre-restart controller's memory.
    h.restart().await;

    let states = h.debug_key_states(a.id()).await;
    assert!(
        states.iter().any(|(_, st)| st == "pending"),
        "expected a pending GATEWAY_KEY epoch for gateway A to survive the \
         controller restart, got states: {states:?}"
    );
}
