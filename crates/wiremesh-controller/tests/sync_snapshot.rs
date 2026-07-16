//! Boots a real controller, enrolls a single stub gateway into a fresh
//! segment ("aws", 10.0.0.0/16), then opens `Sync.Watch` over mTLS (the
//! gateway presents its enrolled client cert; the controller's Sync server
//! trusts its own embedded CA as the client-CA root). On connect the
//! controller must push a *full* `StateSnapshot` as the first message on the
//! stream — this is the projection Task 7 introduces on top of the DB.
//!
//! With only a single gateway enrolled (no peers on the other side of any
//! full-mesh pairing), the snapshot's `peers` list must be empty, but the
//! rest of the envelope must still be populated: `self_cert_pem` is this
//! gateway's own leaf cert as the controller sees it, `policy_version` is 0
//! (empty v0 policy IR, per the engineering design's cycle-2 scope), and
//! `revision` is a monotonic counter starting at (or above) 1 for the first
//! snapshot ever produced.
//!
use std::time::Duration;

use tokio_stream::StreamExt;
use wiremesh_proto::v1::sync_message;

/// Bounds the wait for the initial `Sync.Watch` snapshot so a controller
/// that never emits one (a real regression) fails this test fast instead of
/// hanging the whole suite.
const INITIAL_SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn single_gateway_receives_a_full_snapshot() {
    let h = wiremesh_testkit::TestController::start().await;
    let gw = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;

    let mut stream = gw.open_sync().await;
    let msg = tokio::time::timeout(INITIAL_SNAPSHOT_TIMEOUT, stream.next())
        .await
        .expect("timed out waiting for the initial Sync.Watch snapshot")
        .expect("Sync.Watch stream ended before delivering a message")
        .expect("Sync.Watch stream yielded an error instead of a message");

    let snap = match msg.body {
        Some(sync_message::Body::Snapshot(s)) => s,
        other => panic!("expected the first Sync.Watch message to be a StateSnapshot, got: {other:?}"),
    };

    assert_eq!(
        snap.policy_version, 0,
        "cycle-2 ships an empty v0 policy IR, so policy_version must be 0"
    );
    assert!(
        snap.peers.is_empty(),
        "only one gateway is enrolled, so full-mesh peering must yield no peers, got: {:?}",
        snap.peers
    );
    assert_eq!(
        snap.self_cert_pem,
        gw.cert_pem(),
        "self_cert_pem must be the enrolled gateway's own leaf certificate"
    );
    assert!(
        snap.revision >= 1,
        "revision must be a monotonic counter starting at 1 or higher, got: {}",
        snap.revision
    );
}
