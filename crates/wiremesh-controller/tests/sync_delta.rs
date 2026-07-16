//! Boots a real controller, enrolls gateway A ("aws", 10.0.0.0/16), opens
//! `Sync.Watch` and consumes its initial `StateSnapshot`, then enrolls a
//! SECOND gateway B ("gcp", 10.1.0.0/16). That second enrollment is a
//! projection-affecting mutation (it adds a full-mesh peer for A), so the
//! controller must push a `Delta` down A's still-open stream announcing B as
//! a new peer, with a `revision` strictly newer than the snapshot's.
//!
//! This is Task 8's contract for delta fan-out on mutation
//! (`crates/wiremesh-controller/src/projection.rs`'s broadcast fan-out,
//! `src/services/admin.rs`/`services::enrollment` publishing on mutation):
//! a projection-affecting mutation must push a `Delta` to every other
//! already-connected gateway's open `Sync.Watch` stream, bounded by the
//! `timeout` below so a regression (no delta ever pushed) fails fast
//! instead of hanging the suite.
use std::time::Duration;

use tokio_stream::StreamExt;
use wiremesh_proto::v1::sync_message;

#[tokio::test]
async fn second_gateway_triggers_a_delta_to_the_first() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;

    let mut a_stream = a.open_sync().await;
    let snap_msg = a_stream
        .next()
        .await
        .expect("Sync.Watch stream ended before delivering the initial snapshot")
        .expect("Sync.Watch stream yielded an error instead of the initial snapshot");
    let snap_rev = match snap_msg.body {
        Some(sync_message::Body::Snapshot(s)) => s.revision,
        other => panic!("expected the first Sync.Watch message to be a StateSnapshot, got: {other:?}"),
    };

    // Enrolling a SECOND gateway is a projection-affecting mutation (it adds
    // a full-mesh peer for A) and must push a Delta down A's still-open
    // stream — bounded by a timeout so a missing delta fails fast instead of
    // hanging the test suite.
    let _b = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;

    let msg = tokio::time::timeout(Duration::from_secs(5), a_stream.next())
        .await
        .expect("timed out waiting for the delta triggered by enrolling the second gateway")
        .expect("Sync.Watch stream ended before delivering the delta")
        .expect("Sync.Watch stream yielded an error instead of the delta");

    let delta = match msg.body {
        Some(sync_message::Body::Delta(d)) => d,
        other => panic!("expected a Delta after enrolling the second gateway, got: {other:?}"),
    };

    assert_eq!(
        delta.upserted_peers.len(),
        1,
        "expected exactly one upserted peer (the newly enrolled gcp gateway), got: {:?}",
        delta.upserted_peers
    );
    assert_eq!(
        delta.upserted_peers[0].segment_name, "gcp",
        "the upserted peer must be the newly enrolled gcp gateway"
    );
    assert!(
        delta.revision > snap_rev,
        "delta revision ({}) must be strictly newer than the initial snapshot's revision ({})",
        delta.revision,
        snap_rev
    );
}
