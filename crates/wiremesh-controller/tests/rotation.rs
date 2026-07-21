//! Task 3's failing integration test: ack-driven epoch promote/retire.
//!
//! Boots a real controller, enrolls gateway A ("aws") whose key is being
//! rotated and gateway B ("gcp") as A's peer/acker. Drives the whole
//! ack-driven happy path through the real RPC surface:
//!
//!   1. `Admin.RotateKey(gateway_id = a.id())` creates a new `pending`
//!      epoch for A (sentinel pubkey, per Task 2).
//!   2. `Sync.SubmitEpochKey` lets A submit its real WireGuard pubkey for
//!      that pending epoch (Task 2).
//!   3. B — a currently-connected peer (its `Sync.Watch` stream is open) —
//!      reports via the new `Sync.Report.epoch_acks` field that it has a
//!      live WireGuard session with A's new epoch. Per the Task 3 brief,
//!      this ack is recorded against the ROTATING gateway (A), not the
//!      reporter (B): `EpochAck{peer_gateway_id: A, epoch: n1, live: true}`
//!      sent by B means "B confirms A's epoch n1 is live".
//!   4. Once every currently-connected peer (here: just B) has acked, the
//!      controller must promote A's epoch n1 from `pending` to `active`
//!      and demote the prior epoch-0 out of `active` (to `retiring`, or
//!      already gone) — all driven off `rotation::decide` (this crate's new
//!      pure state machine) executed synchronously on the acking `Report`.
//!
//! This file will not even COMPILE until Task 3 lands `rotation::decide`,
//! `Db::promote_epoch`/`retire_epoch`, the `SyncSvc`/`AdminSvc` rotation
//! driver wiring, AND the testkit's `StubGateway::report_epoch_acks` helper
//! (this test calls it; per the Task-3 assignment, the test author does NOT
//! implement it — only the implementer does). That compile failure is the
//! expected RED for this half of Task 3 (see also the pure-`decide` unit
//! tests at the bottom of `crates/wiremesh-controller/src/rotation.rs`).

use std::time::Duration;

use tokio_stream::StreamExt;
use wiremesh_proto::v1::{sync_message, RotateKeyRequest};

/// Bounds the wait for B's initial `Sync.Watch` snapshot so a controller
/// that never emits one (a real regression) fails this test fast instead of
/// hanging the whole suite.
const INITIAL_SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(5);

/// Upper bound on how long we'll poll `debug_key_states` waiting for the
/// promote to land. Promotion is expected to run SYNCHRONOUSLY off B's
/// acking `Report` call (Task 3 fires `decide`+execute immediately from
/// both `report` and `submit_epoch_key`, per the brief — there's no
/// background sweep in this task), so this is generous slack, not a real
/// polling interval for an async background job.
const PROMOTE_POLL_BUDGET: Duration = Duration::from_secs(3);
const PROMOTE_POLL_STEP: Duration = Duration::from_millis(100);

#[tokio::test]
async fn ack_driven_rotation_promotes_and_retires() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    // B is A's peer and will be the one acking A's new epoch as live.
    let b = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;

    // Open B's Sync stream so B counts as a currently-connected peer (the
    // `expected_peers` set `rotation::decide` requires to be non-empty
    // before it can ever declare `all_acked`) and so the rotation's deltas
    // are actually being observed by someone, matching real gateway
    // behavior. Consume its initial StateSnapshot so a later read isn't
    // confused by backlog.
    let mut b_stream = b.open_sync().await;
    let _initial_snapshot = tokio::time::timeout(INITIAL_SNAPSHOT_TIMEOUT, b_stream.next())
        .await
        .expect("timed out waiting for B's initial Sync.Watch snapshot")
        .expect("Sync.Watch stream ended before delivering B's initial snapshot")
        .expect("Sync.Watch stream yielded an error instead of B's initial snapshot");
    match _initial_snapshot.body {
        Some(sync_message::Body::Snapshot(_)) => {}
        other => panic!("expected the first Sync.Watch message to be a StateSnapshot, got: {other:?}"),
    }

    // Start the rotation: A gets a new pending epoch carrying the
    // "awaiting-submission" sentinel pubkey (Task 2 behavior).
    h.admin_client()
        .await
        .rotate_key(RotateKeyRequest {
            gateway_id: a.id(),
        })
        .await
        .expect("Admin.RotateKey(gateway_id = a.id()) must succeed");

    let post_rotate_states = h.debug_key_states(a.id()).await;
    let (n1, pending_pubkey, pending_state) = post_rotate_states
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
    assert_eq!(
        pending_pubkey, "awaiting-submission",
        "expected the freshly-rotated epoch to still carry the sentinel pubkey before \
         A has submitted a real key, got states: {post_rotate_states:?}"
    );
    let n1 = *n1;

    // A submits its real key for the pending epoch — this must NOT by
    // itself promote the epoch (no acks have landed yet).
    a.submit_epoch_key(n1, "REALKEYA==")
        .await
        .expect("Sync.SubmitEpochKey must succeed for gateway A's pending epoch");

    // B acks A's new epoch as live. Per the ack-direction rule in the Task
    // 3 brief, this ack is recorded against A (the rotating gateway named
    // by `peer_gateway_id`), not against B (the reporter).
    b.report_epoch_acks(0, &[(a.id(), n1, true)])
        .await
        .expect("StubGateway::report_epoch_acks must succeed for B acking A's new epoch");

    // Every expected peer (just B) has now acked epoch n1 live, so the
    // controller should promote synchronously off this Report. Poll with a
    // bounded budget rather than asserting on the very next read, to absorb
    // ordinary async scheduling jitter without masking a real regression.
    let mut last_seen = h.debug_key_states(a.id()).await;
    let mut promoted = last_seen
        .iter()
        .any(|(epoch, _, state)| *epoch == n1 && state == "active");
    let deadline = tokio::time::Instant::now() + PROMOTE_POLL_BUDGET;
    while !promoted && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(PROMOTE_POLL_STEP).await;
        last_seen = h.debug_key_states(a.id()).await;
        promoted = last_seen
            .iter()
            .any(|(epoch, _, state)| *epoch == n1 && state == "active");
    }
    assert!(
        promoted,
        "epoch {n1} for gateway A never promoted to 'active' within {PROMOTE_POLL_BUDGET:?} \
         of B's live ack (Sync.Report carrying epoch_acks) — last observed \
         debug_key_states: {last_seen:?}"
    );
    assert!(
        last_seen
            .iter()
            .any(|(epoch, pubkey, state)| *epoch == n1 && state == "active" && pubkey == "REALKEYA=="),
        "expected epoch {n1} to be 'active' with the real submitted pubkey REALKEYA==, \
         got: {last_seen:?}"
    );
    // The prior epoch-0 key must no longer be active: either demoted to
    // 'retiring' (not yet past RETIRE_GRACE) or already deleted.
    if let Some((_, _, state)) = last_seen.iter().find(|(epoch, _, _)| *epoch == 0) {
        assert_eq!(
            state, "retiring",
            "expected the prior epoch-0 key to be demoted to 'retiring' immediately \
             after epoch {n1} promotes (must not still be 'active'), got: {last_seen:?}"
        );
    }
    // Retirement (deleting the 'retiring' epoch-0 row) fires RETIRE_GRACE
    // (30s) after promotion — asserting the actual delete is the netns
    // done-bar's job (Task 10), not this test's; sleeping 30s here would
    // just make the suite slow for no additional coverage at this layer.
}
