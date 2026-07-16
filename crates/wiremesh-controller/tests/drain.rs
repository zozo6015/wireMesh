//! Task 12's contract: `Drain(gateway_id)` withdraws a gateway from its
//! peers' projected state and removes it (revoking its cert) — G-7.
//!
//! Boots a real controller, enrolls gateway A ("aws") and gateway B ("gcp")
//! (a full-mesh peer of A), opens A's `Sync.Watch` stream and consumes its
//! initial snapshot (which already carries B as a peer), then calls
//! `Admin.Drain(gateway_id = b.id())`. That must:
//!
//!   1. push a `Delta` down A's still-open Sync stream whose
//!      `removed_peer_ids` contains B's gateway id (B withdrawn as a peer)
//!      AND whose `revoked_serials` contains B's certificate serial (B's
//!      cert actually revoked, not just its gateway row marked inactive);
//!   2. mark B's gateway row inactive (`status = 'removed'`) and its cert
//!      revoked — checked via the testkit's `gateway_exists` accessor
//!      returning `false` for B afterward.
use std::time::Duration;

use tokio_stream::StreamExt;
use wiremesh_proto::v1::{sync_message, DrainRequest};

#[tokio::test]
async fn drain_withdraws_the_gateway_from_its_peers() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;
    let b_serial = b.cert_serial().expect("reading B's certificate serial");

    let mut a_stream = a.open_sync().await;
    // Consume A's initial StateSnapshot (enrolling B after A is already up
    // means the snapshot already contains B as a peer).
    let snap_msg = a_stream
        .next()
        .await
        .expect("Sync.Watch stream ended before delivering A's initial snapshot")
        .expect("Sync.Watch stream yielded an error instead of A's initial snapshot");
    match snap_msg.body {
        Some(sync_message::Body::Snapshot(_)) => {}
        other => panic!(
            "expected the first Sync.Watch message to be a StateSnapshot, got: {other:?}"
        ),
    }

    h.admin_client()
        .await
        .drain(DrainRequest {
            gateway_id: b.id(),
        })
        .await
        .expect("Admin.Drain(gateway_id = b.id()) must succeed");

    // A must see a Delta withdrawing B as a peer, bounded by a timeout so a
    // missing delta fails fast instead of hanging the suite.
    let msg = tokio::time::timeout(Duration::from_secs(5), a_stream.next())
        .await
        .expect("timed out waiting for the delta triggered by Admin.Drain")
        .expect("Sync.Watch stream ended before delivering the drain delta")
        .expect("Sync.Watch stream yielded an error instead of the drain delta");

    let delta = match msg.body {
        Some(sync_message::Body::Delta(d)) => d,
        other => panic!("expected a Delta after Admin.Drain, got: {other:?}"),
    };

    assert!(
        delta.removed_peer_ids.contains(&b.id()),
        "expected the drain delta's removed_peer_ids to contain gateway B (id = {}), \
         got: {:?}",
        b.id(),
        delta.removed_peer_ids
    );
    assert!(
        delta.revoked_serials.contains(&b_serial),
        "draining B must revoke certificate serial {b_serial}; got: {:?}",
        delta.revoked_serials
    );

    // B's gateway row must be gone (and its cert revoked) after drain.
    assert!(
        !h.gateway_exists(b.id()).await,
        "expected gateway B (id = {}) to no longer exist after Admin.Drain",
        b.id()
    );
}
