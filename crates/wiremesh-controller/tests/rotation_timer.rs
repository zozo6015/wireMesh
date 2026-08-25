//! Task 4's failing integration tests: the 30-day rotation-initiation timer
//! and the 5s decision sweep (both spawned background cadences in
//! `serve()`), driven at test-friendly small intervals via the new
//! `TestController::start_with_rotation_intervals(rotation, sweep)`.
//!
//! Three behaviors, per `.superpowers/sdd/task-4-brief.md`:
//!
//!   1. `timer_initiates_rotation_for_idle_gateway` — the rotation-initiation
//!      timer must call `rotate_key` for an `active` gateway that is NOT
//!      already mid-rotation (no `pending`/`retiring` epoch), producing a
//!      fresh `pending` epoch with no admin action at all.
//!   2. `timer_skips_gateway_already_mid_rotation` — the SAME timer must NOT
//!      stack a second rotation onto a gateway that already has a `pending`
//!      epoch (whether from an explicit `Admin.RotateKey` or a prior timer
//!      tick): across several ticks, there must still be exactly ONE
//!      `pending` epoch.
//!   3. `sweep_retires_orphaned_retiring_row_after_crash` — the decision
//!      sweep must retire a `retiring` row that has no in-memory
//!      `RotationTracker` (left behind by a crash/restart inside the 30s
//!      `RETIRE_GRACE` window between promote and retire), WITHOUT waiting
//!      the full 30s grace — this is the Task-3-review carry validated
//!      without a 30s (or 300s) sleep, by restarting the controller right
//!      after promote to manufacture the orphan deterministically.
//!
//! This file will not even COMPILE until Task 4 lands
//! `TestController::start_with_rotation_intervals` (does not exist yet) and
//! wires the timer/sweep loops into `serve()` — that compile failure is the
//! expected RED for this task. Once it compiles, a controller that doesn't
//! actually run the timer/sweep (or runs them but with wrong skip/orphan
//! logic) is expected to fail these tests' polls (via the `panic!` messages
//! below), not hang — see [`poll_key_states`]'s bounded budget.

use std::time::Duration;

use tokio_stream::StreamExt;
use wiremesh_proto::v1::{sync_message, RotateKeyRequest};

/// Polls `h.debug_key_states(gateway_id)` until `predicate` is satisfied or
/// `budget` elapses, sleeping `step` between reads. Returns the last-observed
/// snapshot either way, so callers can assert on it directly with a message
/// that shows what was actually seen — a working implementation should
/// satisfy `predicate` well before `budget`, while a broken one fails fast
/// with a clear "last observed" panic instead of hanging the suite on a
/// single unbounded sleep.
async fn poll_key_states(
    h: &wiremesh_testkit::TestController,
    gateway_id: u64,
    budget: Duration,
    step: Duration,
    mut predicate: impl FnMut(&[(u32, String, String)]) -> bool,
) -> Vec<(u32, String, String)> {
    let mut states = h.debug_key_states(gateway_id).await;
    let deadline = tokio::time::Instant::now() + budget;
    while !predicate(&states) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(step).await;
        states = h.debug_key_states(gateway_id).await;
    }
    states
}

/// Counts rows in a `debug_key_states` snapshot whose state is `"pending"` —
/// used to assert the timer initiates exactly one rotation, never zero (it
/// must fire) or two-plus (it must not stack onto a gateway already
/// mid-rotation).
fn pending_count(states: &[(u32, String, String)]) -> usize {
    states
        .iter()
        .filter(|(_, _, state)| state == "pending")
        .count()
}

/// The rotation-initiation timer must, on its own — with no `Admin.RotateKey`
/// call from this test at all — create a `pending` epoch for an idle
/// (single-`active`-epoch, not-mid-rotation) gateway once `rotation_interval`
/// elapses.
#[tokio::test]
async fn timer_initiates_rotation_for_idle_gateway() {
    let h = wiremesh_testkit::TestController::start_with_rotation_intervals(
        // `Some(..)` = automatic rotation ENABLED (`None` disables initiation
        // entirely — see `tests/rotation_disabled.rs`).
        Some(Duration::from_secs(1)),
        Duration::from_millis(500),
    )
    .await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;

    // Ties the ENABLED direction of the disabled-state accessor to observed
    // behaviour: this controller demonstrably DOES initiate a rotation below,
    // so it must not report itself as having automatic rotation disabled. Its
    // counterpart (a controller that provably never initiates, reporting
    // `true`) is `rotation_disabled.rs::disabled_timer_never_initiates_a_rotation`
    // — between them, an accessor stubbed to either constant fails.
    assert!(
        !h.automatic_rotation_disabled(),
        "a controller with a live 1s rotation-initiation timer must not report automatic \
         rotation as disabled"
    );

    let pre_states = h.debug_key_states(a.id()).await;
    assert_eq!(
        pending_count(&pre_states),
        0,
        "expected gateway A to start with no pending epoch (only its epoch-0 \
         baseline), got: {pre_states:?}"
    );

    // Poll rather than a single fixed sleep: with a 1s rotation_interval the
    // first real initiation should land shortly after 1s (the brief's
    // documented choice consumes tokio::time::interval's immediate first
    // tick before looping), so give it a generous multi-tick budget.
    let states = poll_key_states(
        &h,
        a.id(),
        Duration::from_secs(5),
        Duration::from_millis(200),
        |states| pending_count(states) >= 1,
    )
    .await;

    assert_eq!(
        pending_count(&states),
        1,
        "expected the rotation-initiation timer (1s rotation_interval) to create \
         exactly one pending epoch for idle gateway A within 5s with no admin action, \
         got: {states:?}"
    );
}

/// The SAME timer must skip a gateway that already has a `pending` epoch
/// (here: created by an explicit `Admin.RotateKey` call before any timer tick
/// could fire) across multiple ticks — it must never stack a second
/// concurrent rotation onto a gateway that is already mid-rotation.
#[tokio::test]
async fn timer_skips_gateway_already_mid_rotation() {
    let h = wiremesh_testkit::TestController::start_with_rotation_intervals(
        Some(Duration::from_secs(1)),
        Duration::from_millis(500),
    )
    .await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;

    h.admin_client()
        .await
        .rotate_key(RotateKeyRequest { gateway_id: a.id() })
        .await
        .expect("Admin.RotateKey(gateway_id = a.id()) must succeed");

    let post_rotate_states = h.debug_key_states(a.id()).await;
    assert_eq!(
        pending_count(&post_rotate_states),
        1,
        "expected exactly one pending epoch immediately after the explicit \
         Admin.RotateKey, got: {post_rotate_states:?}"
    );

    // Let several timer ticks (1s rotation_interval) pass while A stays
    // mid-rotation the whole time — long enough to cover ~3 ticks with slack
    // for scheduling jitter, short enough not to bloat the suite.
    tokio::time::sleep(Duration::from_millis(3500)).await;

    let states = h.debug_key_states(a.id()).await;
    assert_eq!(
        pending_count(&states),
        1,
        "expected the rotation-initiation timer to SKIP gateway A (already mid-rotation \
         with a pending epoch) across ~3 ticks of a 1s rotation_interval, not stack a \
         second pending epoch on top of the first, got: {states:?}"
    );
}

/// The decision sweep must retire a `retiring` row left orphaned by a crash —
/// i.e. one with no in-memory `RotationTracker` — without waiting the full
/// 30s `RETIRE_GRACE`. Manufactures the orphan deterministically: drive a
/// real ack-promoted rotation to the point where the prior epoch is
/// `retiring` (per Task 3, RETIRE_GRACE hasn't elapsed yet so no in-process
/// retire has happened), then `restart()` the controller — which loses the
/// tracker but keeps the on-disk `retiring` row — and assert the sweep (500ms
/// interval) cleans it up promptly on the new controller instance.
#[tokio::test]
async fn sweep_retires_orphaned_retiring_row_after_crash() {
    let mut h = wiremesh_testkit::TestController::start_with_rotation_intervals(
        // A long rotation_interval so the timer itself never initiates a
        // SECOND rotation on A mid-test and confuses which epoch is which —
        // this test only cares about the sweep, not the timer. (Deliberately
        // still ENABLED-but-slow rather than `None`: the disabled-timer
        // counterpart of this scenario is
        // `rotation_disabled.rs::sweep_still_drives_in_flight_rotations_with_the_timer_disabled`.)
        Some(Duration::from_secs(3600)),
        Duration::from_millis(500),
    )
    .await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    // B is A's peer and will be the one acking A's new epoch as live, same
    // as the Task 3 ack-driven-promotion test.
    let b = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;

    let mut b_stream = b.open_sync().await;
    let _initial_snapshot = tokio::time::timeout(Duration::from_secs(5), b_stream.next())
        .await
        .expect("timed out waiting for B's initial Sync.Watch snapshot")
        .expect("Sync.Watch stream ended before delivering B's initial snapshot")
        .expect("Sync.Watch stream yielded an error instead of B's initial snapshot");
    match _initial_snapshot.body {
        Some(sync_message::Body::Snapshot(_)) => {}
        other => {
            panic!("expected the first Sync.Watch message to be a StateSnapshot, got: {other:?}")
        }
    }

    h.admin_client()
        .await
        .rotate_key(RotateKeyRequest { gateway_id: a.id() })
        .await
        .expect("Admin.RotateKey(gateway_id = a.id()) must succeed");

    let post_rotate_states = h.debug_key_states(a.id()).await;
    let (n1, _pending_pubkey, pending_state) = post_rotate_states
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
    let n1 = *n1;

    a.submit_epoch_key(n1, "REALA==")
        .await
        .expect("Sync.SubmitEpochKey must succeed for gateway A's pending epoch");
    b.report_epoch_acks(0, &[(a.id(), n1, true)])
        .await
        .expect("StubGateway::report_epoch_acks must succeed for B acking A's new epoch");

    // Promotion fires synchronously off B's acking Report (Task 3), well
    // before the 500ms sweep would ever need to rebuild a tracker for this —
    // poll for both epoch n1 active AND epoch-0 demoted to retiring, which
    // is the state this test needs BEFORE restarting to manufacture the
    // orphan.
    let pre_restart_states = poll_key_states(
        &h,
        a.id(),
        Duration::from_secs(5),
        Duration::from_millis(100),
        move |states| {
            let n1_active = states
                .iter()
                .any(|(epoch, _, state)| *epoch == n1 && state == "active");
            let epoch0_retiring = states
                .iter()
                .any(|(epoch, _, state)| *epoch == 0 && state == "retiring");
            n1_active && epoch0_retiring
        },
    )
    .await;
    assert!(
        pre_restart_states
            .iter()
            .any(|(epoch, _, state)| *epoch == n1 && state == "active"),
        "expected epoch {n1} to promote to 'active' off B's live ack before the restart, \
         got: {pre_restart_states:?}"
    );
    assert!(
        pre_restart_states
            .iter()
            .any(|(epoch, _, state)| *epoch == 0 && state == "retiring"),
        "expected the prior epoch-0 key to be demoted to 'retiring' (RETIRE_GRACE not yet \
         elapsed) immediately after epoch {n1} promotes — this is the row the restart \
         below must orphan — got: {pre_restart_states:?}"
    );

    // Crash: restart drops the in-memory RotationTracker map entirely (a
    // fresh RunningController/SyncSvc is built), but the on-disk 'retiring'
    // epoch-0 row survives (it's persisted, not in-memory) — exactly the
    // orphaned-retiring-row scenario the sweep must clean up, per the Task 3
    // review carry.
    h.restart().await;

    // The sweep (500ms interval on the restarted controller — `restart()`
    // must preserve the small interval this test started with, not revert
    // to the 30-day default) must detect the orphaned 'retiring' row (no
    // tracker survives a restart) and retire (delete) it directly, without
    // waiting the full 30s RETIRE_GRACE.
    let post_restart_states = poll_key_states(
        &h,
        a.id(),
        Duration::from_secs(5),
        Duration::from_millis(200),
        |states| !states.iter().any(|(epoch, _, _)| *epoch == 0),
    )
    .await;

    assert!(
        !post_restart_states.iter().any(|(epoch, _, _)| *epoch == 0),
        "expected the sweep to retire (delete) the orphaned 'retiring' epoch-0 row \
         (its RotationTracker was lost on restart) within 5s of a 500ms sweep interval, \
         got: {post_restart_states:?}"
    );
    assert!(
        post_restart_states
            .iter()
            .any(|(epoch, _, state)| *epoch == n1 && state == "active"),
        "expected epoch {n1} to remain 'active' across the restart and sweep — only the \
         orphaned retiring row should be cleaned up, got: {post_restart_states:?}"
    );
}
