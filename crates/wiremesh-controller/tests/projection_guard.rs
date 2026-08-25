//! Key-rotation Task 8a's failing tests: the controller's projection must
//! never advertise a `pending` epoch to peers while its pubkey is still the
//! `"awaiting-submission"` sentinel `Db::rotate_key` inserts (Task 2) — a
//! peer has no use for a key that doesn't exist yet, and a gateway that
//! actually tried to configure a WireGuard peer entry with that literal
//! string as a pubkey would fail outright. The pending epoch must only
//! become visible in a peer's `StateSnapshot`/`Delta` once the rotating
//! gateway has replaced the sentinel with its real pubkey via
//! `Sync.SubmitEpochKey` (Task 2; see `tests/epoch_key_submit.rs`).
//!
//! Separately (but adjacent, since both live in `projection.rs`'s
//! `delta_for_change`): the `ChangeEvent::KeyRotated` delta arm currently
//! clobbers the rotating gateway's `candidate_endpoints` to `Vec::new()`
//! (`projection.rs:258`) instead of carrying its FULL current candidate set
//! the way `ChangeEvent::EndpointObserved`/`SegmentCidrsChanged` already do
//! (see those variants' doc comments in `projection.rs`) — a rotation must
//! not make an already-open `Sync.Watch` stream forget a peer's previously
//! reported/observed candidate endpoint.
//!
//! Both are RED against the current (pre-Task-8a) code:
//!   - `sentinel_pending_not_advertised_until_submitted` fails because the
//!     sentinel pending key IS currently advertised immediately after
//!     `Admin.RotateKey` (no guard exists yet).
//!   - `key_rotated_delta_preserves_candidate_endpoints` fails because the
//!     `KeyRotated` delta arm currently sends `candidate_endpoints:
//!     Vec::new()` unconditionally, clobbering A's previously reported
//!     candidate.
//!
//! Mirrors `tests/keys.rs`/`tests/report_local_endpoints.rs`'s harness
//! conventions (`TestController`, `enroll_one`, `open_sync`,
//! `admin_client().rotate_key`, `submit_epoch_key`, `report`,
//! `debug_key_states`).
use std::time::Duration;

use tokio_stream::StreamExt;
use wiremesh_proto::v1::{sync_message, Delta, Peer, RotateKeyRequest, SyncMessage};

/// Bounds the wait for the initial `Sync.Watch` snapshot so a controller
/// that never emits one (a real regression) fails this test fast instead of
/// hanging the whole suite. Mirrors `tests/keys.rs`'s identical constant.
const INITIAL_SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(5);

/// Bounds the wait for any single `Delta` pushed down an already-open
/// `Sync.Watch` stream, same rationale as `INITIAL_SNAPSHOT_TIMEOUT`.
const DELTA_TIMEOUT: Duration = Duration::from_secs(5);

/// Consumes and asserts on the first message of a freshly opened
/// `Sync.Watch` stream being a `StateSnapshot` — every test below opens B's
/// stream after A already exists, so B's very first message is always its
/// initial snapshot (already containing A as a peer), which must be drained
/// before any subsequent `Delta` reads.
async fn consume_initial_snapshot(b_stream: &mut tonic::Streaming<SyncMessage>) {
    let msg = tokio::time::timeout(INITIAL_SNAPSHOT_TIMEOUT, b_stream.next())
        .await
        .expect("timed out waiting for B's initial Sync.Watch snapshot")
        .expect("Sync.Watch stream ended before delivering B's initial snapshot")
        .expect("Sync.Watch stream yielded an error instead of B's initial snapshot");
    match msg.body {
        Some(sync_message::Body::Snapshot(_)) => {}
        other => {
            panic!("expected the first Sync.Watch message to be a StateSnapshot, got: {other:?}")
        }
    }
}

/// Reads the next `Delta` off `b_stream`, bounded by `DELTA_TIMEOUT` so a
/// missing delta (a real regression) fails this test fast instead of hanging
/// the whole suite.
async fn next_delta(b_stream: &mut tonic::Streaming<SyncMessage>) -> Delta {
    let msg = tokio::time::timeout(DELTA_TIMEOUT, b_stream.next())
        .await
        .expect("timed out waiting for a Delta on B's Sync.Watch stream")
        .expect("Sync.Watch stream ended before delivering a Delta")
        .expect("Sync.Watch stream yielded an error instead of a Delta");
    match msg.body {
        Some(sync_message::Body::Delta(d)) => d,
        other => panic!("expected a Delta on B's Sync.Watch stream, got: {other:?}"),
    }
}

/// A `pending` epoch's sentinel pubkey (`Db::rotate_key`'s
/// `"awaiting-submission"` placeholder, see `tests/epoch_key_submit.rs`)
/// must NOT be advertised to peers until the rotating gateway submits its
/// real key. Immediately after `Admin.RotateKey`, an already-connected
/// peer's delta must still upsert the rotating gateway (with its active key
/// and candidates intact) — it must just withhold the sentinel-holding
/// pending key. Only after `Sync.SubmitEpochKey` overwrites the sentinel
/// does the pending epoch appear.
#[tokio::test]
async fn sentinel_pending_not_advertised_until_submitted() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    // Peer that observes A's key states over its own Sync.Watch stream.
    let b = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;

    let mut b_stream = b.open_sync().await;
    consume_initial_snapshot(&mut b_stream).await;

    h.admin_client()
        .await
        .rotate_key(RotateKeyRequest { gateway_id: a.id() })
        .await
        .expect("Admin.RotateKey(gateway_id = a.id()) must succeed");

    // The rotation still must publish A as an upserted peer (it must NOT
    // vanish from the delta just because the pending guard withholds its
    // sentinel key) — only the `pending` PeerKey itself must be missing.
    let delta = next_delta(&mut b_stream).await;
    let a_peer = delta
        .upserted_peers
        .iter()
        .find(|p| p.gateway_id == a.id())
        .unwrap_or_else(|| {
            panic!(
                "expected the rotation delta's upserted_peers to still include gateway A \
                 (id = {}) with its active key + candidates intact — the projection guard \
                 must only withhold the sentinel PENDING key, not drop A as a peer \
                 entirely — got: {:?}",
                a.id(),
                delta.upserted_peers
            )
        });
    assert!(
        a_peer
            .keys
            .iter()
            .any(|k| k.epoch == 0 && k.state == "active"),
        "expected A's peer entry in the rotation delta to still carry its active epoch-0 \
         key, got keys: {:?}",
        a_peer.keys
    );
    assert!(
        a_peer.keys.iter().all(|k| k.state != "pending"),
        "expected the sentinel-holding ('awaiting-submission') pending epoch to be \
         WITHHELD from the advertised delta immediately after Admin.RotateKey (the \
         projection guard: a peer must never be told about a key that doesn't exist \
         yet) — got keys: {:?}",
        a_peer.keys
    );

    // The guard only affects what's ADVERTISED, not what's stored — the
    // pending epoch must still be readable straight out of the DB via
    // debug_key_states, exactly like tests/keys.rs's restart assertions
    // rely on.
    let states = h.debug_key_states(a.id()).await;
    let (pending_epoch, _pubkey, pending_state) = states
        .iter()
        .max_by_key(|(epoch, _, _)| *epoch)
        .unwrap_or_else(|| {
            panic!(
                "expected at least one GATEWAY_KEY row for gateway A after rotation, \
                 got: {states:?}"
            )
        });
    assert_eq!(
        pending_state, "pending",
        "expected the highest-epoch DB row right after Admin.RotateKey to be 'pending' \
         even though it's withheld from the wire, got states: {states:?}"
    );
    let pending_epoch = *pending_epoch;

    a.submit_epoch_key(pending_epoch, "REALKEYA==")
        .await
        .expect("Sync.SubmitEpochKey must succeed for A's pending epoch");

    // Now that A has replaced the sentinel with a real pubkey, the pending
    // epoch must appear in B's next delta.
    let delta2 = next_delta(&mut b_stream).await;
    let a_peer2 = delta2
        .upserted_peers
        .iter()
        .find(|p| p.gateway_id == a.id())
        .unwrap_or_else(|| {
            panic!(
                "expected the post-submit delta's upserted_peers to include gateway A \
                 (id = {}), got: {:?}",
                a.id(),
                delta2.upserted_peers
            )
        });
    let pending_key = a_peer2
        .keys
        .iter()
        .find(|k| k.state == "pending")
        .unwrap_or_else(|| {
            panic!(
                "expected A's peer entry to now carry a 'pending' PeerKey after A \
                 submitted its real key for epoch {pending_epoch}, got keys: {:?}",
                a_peer2.keys
            )
        });
    assert_eq!(
        pending_key.pubkey, "REALKEYA==",
        "expected the now-advertised pending key's pubkey to be A's submitted real key, \
         got keys: {:?}",
        a_peer2.keys
    );
}

/// A `KeyRotated` delta must PRESERVE the rotating gateway's
/// `candidate_endpoints` (its full current candidate set), not clobber it
/// to empty — mirroring how `EndpointObserved`/`SegmentCidrsChanged` deltas
/// already carry the full candidate set on every peer upsert.
#[tokio::test]
async fn key_rotated_delta_preserves_candidate_endpoints() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;

    let mut b_stream = b.open_sync().await;
    consume_initial_snapshot(&mut b_stream).await;

    // Give A a candidate endpoint (mirrors
    // tests/report_local_endpoints.rs's `reported_local_endpoint_...`
    // tests): this populates A's local candidates via
    // Db::set_local_candidates, which candidates_for merges into the
    // gateway's advertised candidate set.
    a.report(0, &["203.0.113.7:51820"])
        .await
        .expect("Sync.Report with local_endpoints must succeed");

    // Consume B's resulting EndpointObserved delta so it isn't mistaken for
    // a later rotation delta.
    let observed_delta = next_delta(&mut b_stream).await;
    let observed_a_peer = observed_delta
        .upserted_peers
        .iter()
        .find(|p| p.gateway_id == a.id())
        .unwrap_or_else(|| {
            panic!(
                "expected A's reported local endpoint to produce an EndpointObserved \
                 delta upserting A, got: {:?}",
                observed_delta.upserted_peers
            )
        });
    assert!(
        observed_a_peer
            .candidate_endpoints
            .iter()
            .any(|c| c == "203.0.113.7:51820"),
        "expected A's reported local endpoint to appear in B's EndpointObserved delta \
         before rotation even starts, got: {:?}",
        observed_a_peer.candidate_endpoints
    );

    h.admin_client()
        .await
        .rotate_key(RotateKeyRequest { gateway_id: a.id() })
        .await
        .expect("Admin.RotateKey(gateway_id = a.id()) must succeed");

    let states = h.debug_key_states(a.id()).await;
    let (pending_epoch, _pubkey, _state) = states
        .iter()
        .max_by_key(|(epoch, _, _)| *epoch)
        .unwrap_or_else(|| {
            panic!(
                "expected at least one GATEWAY_KEY row for gateway A after rotation, \
                 got: {states:?}"
            )
        });
    let pending_epoch = *pending_epoch;

    a.submit_epoch_key(pending_epoch, "REALKEYA==")
        .await
        .expect("Sync.SubmitEpochKey must succeed for A's pending epoch");

    // Scan forward through B's deltas: the RotateKey delta withholds the
    // sentinel pending key entirely (per the projection guard proven by
    // `sentinel_pending_not_advertised_until_submitted` above), so the
    // delta that actually carries a real `pending` key for A is the one
    // triggered by Sync.SubmitEpochKey. Bound the scan so a genuinely
    // missing delta fails fast rather than hanging the suite.
    let mut found: Option<Peer> = None;
    for _ in 0..5 {
        let delta = next_delta(&mut b_stream).await;
        if let Some(a_peer) = delta.upserted_peers.iter().find(|p| p.gateway_id == a.id()) {
            if a_peer
                .keys
                .iter()
                .any(|k| k.state == "pending" && k.pubkey == "REALKEYA==")
            {
                found = Some(a_peer.clone());
                break;
            }
        }
    }
    let a_peer = found.unwrap_or_else(|| {
        panic!(
            "never observed a Delta upserting gateway A with a real ('REALKEYA==') \
             pending key within 5 deltas of Sync.SubmitEpochKey"
        )
    });

    assert!(
        !a_peer.candidate_endpoints.is_empty(),
        "expected the KeyRotated delta's candidate_endpoints to be PRESERVED (matching \
         EndpointObserved/SegmentCidrsChanged's full-candidate-set behavior), not \
         clobbered to empty — got: {:?}",
        a_peer.candidate_endpoints
    );
    assert!(
        a_peer
            .candidate_endpoints
            .iter()
            .any(|c| c == "203.0.113.7:51820"),
        "expected A's previously reported candidate endpoint to survive the KeyRotated \
         delta, got: {:?}",
        a_peer.candidate_endpoints
    );
}
