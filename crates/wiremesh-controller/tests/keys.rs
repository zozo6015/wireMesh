//! Task 11's failing test: `RotateKey(gateway_id)` starts a make-before-break
//! key-epoch rotation for a gateway.
//!
//! Boots a real controller, enrolls gateway A ("aws") and a peer gateway B
//! ("gcp") that will observe A's key states via its own `Sync.Watch` stream,
//! then calls the (not-yet-existing) `Admin.RotateKey(gateway_id = a.id())`.
//! That must:
//!
//!   1. insert a new `pending` `GATEWAY_KEY(epoch = n+1)` row for A in the
//!      DB — but (Key-rotation Task 8a's projection guard, see
//!      `tests/projection_guard.rs`) NOT advertise it to B over the wire
//!      yet, since it still carries the `"awaiting-submission"` sentinel
//!      pubkey (Task 2): the `Delta` pushed down B's still-open Sync stream
//!      upserts A with its active key intact and its `keys` containing NO
//!      entry with `state == "pending"` until A submits its real key via
//!      `Sync.SubmitEpochKey`;
//!   2. survive a controller restart — after `h.restart().await`, the
//!      pending epoch must still be readable back out of the DB (via the
//!      testkit's `debug_key_states` admin/debug helper), proving the
//!      rotation's bookkeeping is DB-backed, not just in-memory.
//!
use std::time::Duration;

use tokio_stream::StreamExt;
use wiremesh_proto::v1::{sync_message, RotateKeyRequest};

/// Bounds the wait for the initial `Sync.Watch` snapshot so a controller
/// that never emits one (a real regression) fails this test fast instead of
/// hanging the whole suite.
const INITIAL_SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn key_rotation_advances_epoch_states_and_survives_restart() {
    let mut h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    // Peer that observes A's key states over its own Sync.Watch stream.
    let b = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;

    let mut b_stream = b.open_sync().await;
    // Consume B's initial StateSnapshot (enrolling B after A is already up
    // means the snapshot already contains A as a peer — with no pending
    // epoch key yet, since rotation hasn't happened). Capture A's
    // pre-rotation key states here too, so the post-rotation assertions
    // below can prove the rotation strictly ADDS a new, higher-epoch
    // pending key rather than reusing the current epoch or replacing the
    // existing active one.
    let snap_msg = tokio::time::timeout(INITIAL_SNAPSHOT_TIMEOUT, b_stream.next())
        .await
        .expect("timed out waiting for B's initial Sync.Watch snapshot")
        .expect("Sync.Watch stream ended before delivering B's initial snapshot")
        .expect("Sync.Watch stream yielded an error instead of B's initial snapshot");
    let pre_rotation_a_keys: Vec<(u32, String)> = match snap_msg.body {
        Some(sync_message::Body::Snapshot(s)) => s
            .peers
            .iter()
            .find(|p| p.gateway_id == a.id())
            .map(|p| p.keys.iter().map(|k| (k.epoch, k.state.clone())).collect())
            .unwrap_or_default(),
        other => panic!("expected the first Sync.Watch message to be a StateSnapshot, got: {other:?}"),
    };
    let pre_rotation_max_epoch = pre_rotation_a_keys.iter().map(|(e, _)| *e).max();
    assert!(
        pre_rotation_a_keys
            .iter()
            .any(|(_, st)| st == "active"),
        "expected gateway A to already have an active epoch-0 key before any rotation, \
         got: {pre_rotation_a_keys:?}"
    );

    h.admin_client()
        .await
        .rotate_key(RotateKeyRequest {
            gateway_id: a.id(),
        })
        .await
        .expect("Admin.RotateKey(gateway_id = a.id()) must succeed");

    // B must see a Delta upserting A (its active key intact, the pending
    // sentinel withheld per the Task 8a projection guard — see the
    // assertions below), bounded by a timeout so a missing delta fails fast
    // instead of hanging the suite.
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
    // (Key-rotation Task 8a — projection guard, see tests/projection_guard.rs)
    // A freshly rotated epoch's pubkey is still the "awaiting-submission"
    // sentinel (Task 2) until A calls Sync.SubmitEpochKey — the controller
    // must NOT advertise a peer key that doesn't exist yet, so the delta
    // right after Admin.RotateKey must carry NO "pending" PeerKey at all,
    // while still carrying A's existing active key untouched. (Before the
    // guard, this delta DID include a "pending" sentinel key; that's why
    // this section changed — see this test file's RED-run note in the
    // Task-8a report.)
    assert!(
        a_peer.keys.iter().all(|k| k.state != "pending"),
        "expected the sentinel-holding pending epoch to be WITHHELD from the \
         advertised rotation delta until A submits its real key (projection guard), \
         got keys: {:?}",
        a_peer.keys
    );
    assert!(
        a_peer
            .keys
            .iter()
            .any(|k| k.epoch == 0 && k.state == "active"),
        "expected gateway A's peer entry in the rotation delta to still carry its \
         active epoch-0 key even though the pending sentinel is withheld, got keys: {:?}",
        a_peer.keys
    );
    // The previous active epoch must still be present — make-before-break
    // means rotation ADDS a pending key (in the DB — see the debug_key_states
    // assertions below), it must never REPLACE the existing active one.
    for (epoch, state) in &pre_rotation_a_keys {
        if state == "active" {
            assert!(
                a_peer
                    .keys
                    .iter()
                    .any(|k| k.epoch == *epoch && k.state == "active"),
                "expected the pre-rotation active epoch {epoch} to remain active after \
                 rotation, got keys: {:?}",
                a_peer.keys
            );
        }
    }

    // The DB-level pending epoch (withheld from the wire by the projection
    // guard, but still real bookkeeping) is what the restart assertions
    // below prove survives a controller restart — read it via
    // debug_key_states rather than the (now guard-withheld) delta.
    let post_rotate_states = h.debug_key_states(a.id()).await;
    let (pending_epoch, _pubkey, pending_state) = post_rotate_states
        .iter()
        .max_by_key(|(epoch, _, _)| *epoch)
        .unwrap_or_else(|| {
            panic!(
                "expected at least one GATEWAY_KEY row for gateway A after rotation, \
                 got: {post_rotate_states:?}"
            )
        });
    assert_eq!(
        pending_state, "pending",
        "expected the highest-epoch row right after Admin.RotateKey to be 'pending', \
         got states: {post_rotate_states:?}"
    );
    // A broken rotation that reuses the current epoch (rather than
    // allocating a new, strictly higher one) must be caught here, not just
    // "some pending row exists".
    if let Some(prior_max) = pre_rotation_max_epoch {
        assert!(
            *pending_epoch > prior_max,
            "expected the new pending epoch ({pending_epoch}) to be strictly greater \
             than the prior max epoch ({prior_max}), got states: {post_rotate_states:?}"
        );
    }
    let pending_epoch = *pending_epoch;

    // Restart mid-rotation: the pending epoch's bookkeeping must resume from
    // the DB snapshot, not just live in the pre-restart controller's memory.
    h.restart().await;

    let states = h.debug_key_states(a.id()).await;
    assert!(
        states
            .iter()
            .any(|(epoch, _pubkey, st)| *epoch == pending_epoch && st == "pending"),
        "expected pending GATEWAY_KEY epoch {pending_epoch} for gateway A to survive the \
         controller restart, got states: {states:?}"
    );
    for (epoch, state) in &pre_rotation_a_keys {
        if state == "active" {
            assert!(
                states
                    .iter()
                    .any(|(e, _pubkey, st)| e == epoch && st == "active"),
                "expected the original active epoch {epoch} to also survive the \
                 controller restart, got states: {states:?}"
            );
        }
    }
}
