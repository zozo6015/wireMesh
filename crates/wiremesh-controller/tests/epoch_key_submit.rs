//! Task 2's failing test: `Sync.SubmitEpochKey(epoch, pubkey)` lets a
//! gateway submit the REAL WireGuard public key it generated for a pending
//! rotation epoch, overwriting the `Db::rotate_key`-inserted sentinel
//! (`"awaiting-submission"`) that Task 2 replaces today's fake
//! `placeholder-pubkey-gw{id}-epoch{n}` value with.
//!
//! Exercises the whole real path: `Admin.RotateKey` inserts the pending row
//! (sentinel pubkey), the gateway calls `Sync.SubmitEpochKey` over its own
//! mTLS identity to overwrite the sentinel with its real pubkey, and
//! `Admin.DebugKeyStates` (extended by Task 2 to also carry the pubkey) is
//! used throughout to observe the DB-backed state.
//!
//! This file will not even COMPILE until Task 2 lands:
//!   - `TestController::debug_key_states` must return `Vec<(u32, String,
//!     String)>` = `(epoch, pubkey, state)` (today it returns `Vec<(u32,
//!     String)>` = `(epoch, state)`, with no pubkey);
//!   - `StubGateway::submit_epoch_key(&self, epoch, pubkey)` does not exist
//!     yet (mirrors the existing `StubGateway::report` method: a fresh mTLS
//!     `SyncClient` using the gateway's own identity, calling the
//!     newly-real `Sync.SubmitEpochKey`, which as of Task 1 is stubbed to
//!     `Err(Status::unimplemented(..))`).
//! That compile failure is the expected RED for this task.

use wiremesh_proto::v1::RotateKeyRequest;

/// A gateway can submit its real pubkey for a pending epoch, and that
/// submission overwrites the `"awaiting-submission"` sentinel WITHOUT
/// promoting the epoch out of `pending` state (promotion is Task 3's job,
/// not this RPC's).
#[tokio::test]
async fn rotate_then_submit_replaces_sentinel_with_real_pubkey() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;

    // Pre-rotation: gateway A already has its epoch-0 baseline key, active.
    let pre_states = h.debug_key_states(a.id()).await;
    assert!(
        pre_states
            .iter()
            .any(|(epoch, _pubkey, state)| *epoch == 0 && state == "active"),
        "expected gateway A to already have an active epoch-0 key before any \
         rotation, got: {pre_states:?}"
    );

    h.admin_client()
        .await
        .rotate_key(RotateKeyRequest {
            gateway_id: a.id(),
        })
        .await
        .expect("Admin.RotateKey(gateway_id = a.id()) must succeed");

    // After rotation: a NEW pending row exists, carrying the sentinel
    // pubkey (not yet a real key — the gateway hasn't submitted one), and
    // the epoch-0 active row is untouched.
    let post_rotate_states = h.debug_key_states(a.id()).await;
    let (pending_epoch, pending_pubkey, pending_state) = post_rotate_states
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
        "expected the highest-epoch row after Admin.RotateKey to be 'pending', got \
         states: {post_rotate_states:?}"
    );
    assert_eq!(
        pending_pubkey, "awaiting-submission",
        "expected Db::rotate_key to insert the 'awaiting-submission' sentinel pubkey \
         for the new pending epoch (not a real key yet, and not the old cycle-2 \
         placeholder-pubkey-gw{{id}}-epoch{{n}} fake), got states: {post_rotate_states:?}"
    );
    let pending_epoch = *pending_epoch;
    assert!(
        post_rotate_states
            .iter()
            .any(|(epoch, _pubkey, state)| *epoch == 0 && state == "active"),
        "expected the pre-rotation active epoch-0 key to remain untouched by \
         Admin.RotateKey, got states: {post_rotate_states:?}"
    );

    // The gateway submits its real pubkey for the pending epoch.
    a.submit_epoch_key(pending_epoch, "REALKEY==")
        .await
        .expect("Sync.SubmitEpochKey must succeed for a genuinely pending, \
                 sentinel-holding epoch");

    // The sentinel must now be overwritten with the real pubkey, and the
    // epoch must STILL be 'pending' — submitting a key is not the same as
    // promoting it (that's Task 3's job).
    let post_submit_states = h.debug_key_states(a.id()).await;
    let (_epoch, submitted_pubkey, submitted_state) = post_submit_states
        .iter()
        .find(|(epoch, _, _)| *epoch == pending_epoch)
        .unwrap_or_else(|| {
            panic!(
                "expected epoch {pending_epoch} to still be present after \
                 Sync.SubmitEpochKey, got states: {post_submit_states:?}"
            )
        });
    assert_eq!(
        submitted_pubkey, "REALKEY==",
        "expected Sync.SubmitEpochKey to overwrite the 'awaiting-submission' sentinel \
         with the gateway-submitted real pubkey, got states: {post_submit_states:?}"
    );
    assert_eq!(
        submitted_state, "pending",
        "submitting an epoch key must NOT promote it out of 'pending' — promotion is \
         Task 3's job, not Sync.SubmitEpochKey's — got states: {post_submit_states:?}"
    );
    assert!(
        post_submit_states
            .iter()
            .any(|(epoch, _pubkey, state)| *epoch == 0 && state == "active"),
        "expected the epoch-0 active key to remain untouched by Sync.SubmitEpochKey, \
         got states: {post_submit_states:?}"
    );
}

/// Submitting a key for an epoch that has no matching pending,
/// sentinel-holding `GATEWAY_KEY` row (here: an epoch that was never
/// created by a rotation at all) must be rejected rather than silently
/// accepted or silently no-op'd.
#[tokio::test]
async fn submit_to_nonexistent_epoch_is_rejected() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;

    let result = a.submit_epoch_key(999, "X==").await;
    assert!(
        result.is_err(),
        "expected Sync.SubmitEpochKey(epoch = 999) to fail for gateway A, which has no \
         pending epoch 999 (no rotation was ever started), got: {result:?}"
    );
}
