//! Cycle-4b Task 4 (spec §5/§6.1): `Sync.Report`'s `local_endpoints` field
//! (added additively in Task 2; the multi-candidate DB model —
//! `Db::set_local_candidates`/`Db::candidates_for` — landed in Task 3, see
//! `tests/candidates.rs`) must actually be PERSISTED and SURFACED by the
//! `Report` handler in `crates/wiremesh-controller/src/services/sync.rs`:
//! a gateway reporting its own routable local `ip:wg_port` address(es)
//! becomes a candidate endpoint every OTHER gateway's projection can see,
//! the same way a controller-OBSERVED endpoint already is (Task 15/
//! `tests/observe.rs`).
//!
//! Three contracts, mirroring `tests/observe.rs`'s snapshot-based style plus
//! `tests/sync_delta.rs`'s live-delta style:
//!
//!  1. A reported local endpoint lands in `Db::candidates_for` AND in a
//!     peer's fresh snapshot `candidate_endpoints`.
//!  2. It also reaches an ALREADY-connected peer's open `Sync.Watch` stream
//!     as a `Delta` (no reconnect required) — the controller must publish a
//!     `ChangeEvent` when the local set actually changes.
//!  3. (Cycle-4b Task 8 — supersedes the Task 4 "empty is a no-op" behavior
//!     documented above when this test was first written) An EMPTY
//!     `local_endpoints` report now CLEARS any previously-reported local
//!     candidate: Task 8 makes the gateway report its COMPLETE current
//!     local-address set every round (no per-endpoint add/remove RPC), so an
//!     empty list unambiguously means "I have no routable local address
//!     right now" and must be applied via `Db::set_local_candidates`'s
//!     full-REPLACE contract like any other reported set. This is a
//!     deliberate semantic change, not a weakened test: skipping the DB call
//!     on an empty report (the old behavior) would leave a gateway that
//!     lost its only local address stuck advertising a stale, no-longer-
//!     valid candidate forever.
use std::time::Duration;

use tokio_stream::StreamExt;
use wiremesh_proto::v1::{sync_message, StateSnapshot};

/// Pulls a `StateSnapshot` out of the first message of a freshly opened
/// `Sync.Watch` stream — same helper `tests/observe.rs` defines for the same
/// purpose (each `tests/*.rs` file is its own binary, so duplicating this
/// small unwrap is the established convention rather than a shared crate
/// dependency).
fn expect_snapshot(
    msg: Option<Result<wiremesh_proto::v1::SyncMessage, tonic::Status>>,
) -> StateSnapshot {
    let msg = msg
        .expect("Sync.Watch stream ended before delivering a message")
        .expect("Sync.Watch stream yielded an error instead of a message");
    match msg.body {
        Some(sync_message::Body::Snapshot(s)) => s,
        other => {
            panic!("expected the first Sync.Watch message to be a StateSnapshot, got: {other:?}")
        }
    }
}

/// Reads `gw_id`'s current merged candidate set straight off the
/// controller's on-disk DB — same "open a second connection to the same
/// `controller.db` file" pattern `TestController::gateway_exists`/
/// `count_audit` already use (see those methods' doc comments for why this
/// is safe: `Db::open` re-enables `foreign_keys` and sets a 5s
/// `busy_timeout`).
async fn candidates_for(h: &wiremesh_testkit::TestController, gw_id: u64) -> Vec<String> {
    let db_path = h.data_dir().join("controller.db");
    tokio::task::spawn_blocking(move || {
        let db = wiremesh_controller::db::Db::open(&db_path)
            .expect("opening controller DB for candidates_for");
        db.candidates_for(gw_id as i64)
            .expect("querying candidates_for")
    })
    .await
    .expect("candidates_for blocking task panicked")
}

#[tokio::test]
async fn reported_local_endpoint_becomes_a_db_and_peer_candidate() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;

    a.report(0, &["10.0.0.5:51820"])
        .await
        .expect("Sync.Report with local_endpoints");

    assert_eq!(
        candidates_for(&h, a.id()).await,
        vec!["10.0.0.5:51820".to_string()],
        "A's reported local endpoint must be persisted as a candidate via Db::candidates_for"
    );

    // B's projection must show A's reported local endpoint. Open a FRESH
    // Sync.Watch stream (rather than reusing one opened before the report)
    // so its initial snapshot reflects the post-report state.
    let mut b_stream = b.open_sync().await;
    let snap = expect_snapshot(b_stream.next().await);
    let a_peer = snap
        .peers
        .iter()
        .find(|p| p.gateway_id == a.id())
        .unwrap_or_else(|| {
            panic!(
                "B's snapshot must list A (gateway_id {}) as a peer, got: {:?}",
                a.id(),
                snap.peers
            )
        });
    assert!(
        a_peer
            .candidate_endpoints
            .iter()
            .any(|c| c == "10.0.0.5:51820"),
        "A's peer entry in B's snapshot must list the reported local endpoint, got: {:?}",
        a_peer.candidate_endpoints
    );
}

#[tokio::test]
async fn reported_local_endpoint_pushes_a_live_delta_to_an_already_connected_peer() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;

    // B opens its Sync.Watch stream BEFORE A reports its local endpoint, so
    // the subsequent Report must reach it as a live Delta rather than only
    // being visible on a fresh reconnect.
    let mut b_stream = b.open_sync().await;
    let snap = expect_snapshot(b_stream.next().await);
    let snap_rev = snap.revision;

    a.report(0, &["10.0.0.5:51820"])
        .await
        .expect("Sync.Report with local_endpoints");

    let msg = tokio::time::timeout(Duration::from_secs(5), b_stream.next())
        .await
        .expect("timed out waiting for the delta triggered by A's local-endpoint report")
        .expect("Sync.Watch stream ended before delivering the delta")
        .expect("Sync.Watch stream yielded an error instead of the delta");

    let delta = match msg.body {
        Some(sync_message::Body::Delta(d)) => d,
        other => panic!("expected a Delta after A's local-endpoint report, got: {other:?}"),
    };

    assert!(
        delta.revision > snap_rev,
        "delta revision ({}) must be strictly newer than the initial snapshot's revision ({})",
        delta.revision,
        snap_rev
    );
    assert_eq!(
        delta.upserted_peers.len(),
        1,
        "expected exactly one upserted peer (A), got: {:?}",
        delta.upserted_peers
    );
    assert_eq!(delta.upserted_peers[0].gateway_id, a.id());
    assert!(
        delta.upserted_peers[0]
            .candidate_endpoints
            .iter()
            .any(|c| c == "10.0.0.5:51820"),
        "the delta's upserted peer must carry A's newly reported local endpoint, got: {:?}",
        delta.upserted_peers[0].candidate_endpoints
    );
}

#[tokio::test]
async fn empty_local_endpoints_report_clears_previously_reported_locals() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;

    // A first reports a real local endpoint (establishing a baseline
    // candidate + revision)...
    a.report(0, &["10.0.0.5:51820"])
        .await
        .expect("Sync.Report with local_endpoints");
    let baseline = candidates_for(&h, a.id()).await;
    assert_eq!(baseline, vec!["10.0.0.5:51820".to_string()]);

    let mut b_stream = b.open_sync().await;
    let snap = expect_snapshot(b_stream.next().await);
    let snap_rev = snap.revision;

    // ...then reports again with an EMPTY local_endpoints list (cycle4b
    // Task 8: the gateway now sends its COMPLETE current local-address set
    // every round, so an empty list means it genuinely has none right now —
    // e.g. it lost its only interface address, or moved behind a NAT that
    // hands out no routable address at all). This must CLEAR the
    // previously-reported candidate, not preserve it.
    a.report(1, &[])
        .await
        .expect("Sync.Report with empty local_endpoints");

    assert_eq!(
        candidates_for(&h, a.id()).await,
        Vec::<String>::new(),
        "an empty local_endpoints report must clear a previously-reported local candidate"
    );

    // A delta clearing the candidate MUST reach B's still-open stream — the
    // change is real (a candidate disappeared), so it must publish a
    // ChangeEvent, mirroring how the earlier "reported" case does.
    let msg = tokio::time::timeout(Duration::from_secs(5), b_stream.next())
        .await
        .expect("timed out waiting for the delta triggered by A's clearing report")
        .expect("Sync.Watch stream ended before delivering the delta")
        .expect("Sync.Watch stream yielded an error instead of the delta");
    let delta = match msg.body {
        Some(sync_message::Body::Delta(d)) => d,
        other => panic!("expected a Delta after A's clearing report, got: {other:?}"),
    };
    assert!(
        delta.revision > snap_rev,
        "delta revision ({}) must be strictly newer than the initial snapshot's revision ({})",
        delta.revision,
        snap_rev
    );
    assert_eq!(
        delta.upserted_peers.len(),
        1,
        "expected exactly one upserted peer (A)"
    );
    assert_eq!(delta.upserted_peers[0].gateway_id, a.id());
    assert!(
        delta.upserted_peers[0].candidate_endpoints.is_empty(),
        "A's peer entry in the delta must no longer list the cleared local endpoint, got: {:?}",
        delta.upserted_peers[0].candidate_endpoints
    );
}
