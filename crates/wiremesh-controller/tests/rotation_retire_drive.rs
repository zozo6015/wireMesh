//! The promoted rotation's `Retire` is never driven — and the real damage is
//! a permanently wedged rotation timer, not a data-plane fault.
//!
//! ./dev.sh run "cargo test -p wiremesh-controller --test rotation_retire_drive \
//!   -- --test-threads=1 --nocapture"
//!
//! # The defect these tests pin
//!
//! `rotation::decide`'s rule 1 is the ONLY producer of
//! `RotationDecision::Retire`, and it fires only for a live `RotationTracker`
//! whose `promoted_at` is `Some` and whose `RETIRE_GRACE` has elapsed. Nothing
//! in the controller ever evaluates a tracker in that state:
//!
//!   * `sweep_rotations` step 2 calls `drive_rotation_for` from INSIDE
//!     `if let Some((pending_epoch, ..)) = keys.iter().find(.. == "pending")`.
//!     A promoted rotation has no `pending` row left, so the sweep never
//!     reaches the one call that could produce the `Retire`.
//!   * `sweep_rotations` step 3 (the orphan path, which deletes a `retiring`
//!     row directly and immediately) explicitly `continue`s when a tracker IS
//!     still held — correctly, because that path has no grace timer, but it
//!     means the tracker-held case falls through to nobody.
//!   * `SyncSvc::report`'s rotation block is guarded by
//!     `if !req.epoch_acks.is_empty()`; a steady-state gateway report carries
//!     an empty `epoch_acks`, and the gateway acks exactly once per Role-B
//!     cutover, so no later report re-enters the driver either.
//!
//! So after a normal, fully successful rotation the prior epoch's `retiring`
//! row is stranded on disk forever.
//!
//! # What that actually breaks
//!
//! NOT the data plane. A `retiring` row does reach peers' rosters, but no
//! gateway code reads it — `active_key()`, `pending_key()` and
//! `active_pubkey_b64` are the only consumers of `PeerState::keys`. Nothing
//! here asserts a traffic effect, because there isn't one.
//!
//! What it breaks is AUTOMATIC ROTATION, permanently:
//! `Db::gateways_with_rotation_state` selects `state IN ('pending',
//! 'retiring')`, and `initiate_due_rotations` skips every id in that set. One
//! stranded `retiring` row therefore excludes its gateway from the rotation
//! timer for the life of the deployment. (`Admin.RotateKey` is unguarded, so
//! manual rotation still works — which is exactly why this hides.)
//!
//! [`timer_still_rotates_a_gateway_after_a_completed_rotation`] is that
//! finding, driven through the real timer rather than asserted on rows.
//!
//! # Why these tests are slow
//!
//! `rotation::RETIRE_GRACE` is a hard `const` (30s) with no config knob —
//! unlike the rotation-initiation and decision-sweep cadences, which
//! `TestController::start_with_rotation_intervals` can shrink. Observing a
//! retire that is SUPPOSED to happen therefore costs a real ~30s wait. The
//! existing `tests/rotation.rs` deliberately declines to pay it (see its
//! closing comment) and stops at the promote; this file is where that wait
//! lives instead. Shortening it would mean asserting something weaker than
//! "the row is gone", which is the whole point.

use std::time::Duration;

use tokio_stream::StreamExt;
use wiremesh_proto::v1::{sync_message, RotateKeyRequest};
use wiremesh_testkit::{StubGateway, TestController};

/// Bounds the wait for a gateway's initial `Sync.Watch` snapshot so a
/// controller that never emits one fails fast instead of hanging the suite.
const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(5);

/// The decision-sweep cadence every test here boots with — fast enough that
/// "the sweep had ample opportunity" is never in doubt when an assertion goes
/// red.
const SWEEP_INTERVAL: Duration = Duration::from_millis(500);

/// Poll granularity for `debug_key_states` reads.
const POLL_STEP: Duration = Duration::from_millis(200);

/// Budget for a promote that is expected to fire SYNCHRONOUSLY off an acking
/// `Sync.Report` — generous slack for scheduling jitter, not a real interval.
const PROMOTE_BUDGET: Duration = Duration::from_secs(10);

/// Budget for a retire that is expected `RETIRE_GRACE` (30s) after promotion,
/// plus slack for the sweep tick that has to notice it.
const RETIRE_BUDGET: Duration = Duration::from_secs(45);

/// Polls `h.debug_key_states(gateway_id)` until `predicate` holds or `budget`
/// elapses, returning the last-observed snapshot either way so the caller can
/// assert on it with a message that shows what was actually there. Same shape
/// as `tests/rotation_timer.rs`'s helper.
async fn poll_key_states(
    h: &TestController,
    gateway_id: u64,
    budget: Duration,
    mut predicate: impl FnMut(&[(u32, String, String)]) -> bool,
) -> Vec<(u32, String, String)> {
    let mut states = h.debug_key_states(gateway_id).await;
    let deadline = tokio::time::Instant::now() + budget;
    while !predicate(&states) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(POLL_STEP).await;
        states = h.debug_key_states(gateway_id).await;
    }
    states
}

/// Every gateway id the controller currently considers mid-rotation — read
/// straight off the on-disk DB via the SAME query
/// `initiate_due_rotations` consults for its skip check
/// (`Db::gateways_with_rotation_state`). Read directly rather than through a
/// debug RPC for the same reason `TestController::gateway_exists` does: this
/// is test-harness introspection, not a wire contract. Used only to make a
/// failure message name the mechanism; the behavioural assertion is always on
/// the timer itself.
async fn mid_rotation_gateway_ids(h: &TestController) -> Vec<i64> {
    let db_path = h.data_dir().join("controller.db");
    tokio::task::spawn_blocking(move || {
        let db = wiremesh_controller::db::Db::open(&db_path)
            .expect("opening the controller DB for mid_rotation_gateway_ids");
        db.gateways_with_rotation_state()
            .expect("querying gateways_with_rotation_state")
    })
    .await
    .expect("mid_rotation_gateway_ids blocking task panicked")
}

/// Opens `gw`'s `Sync.Watch` stream and consumes its initial `StateSnapshot`,
/// so the gateway counts as a currently-connected peer (the non-empty
/// `expected_peers` set `rotation::decide`'s rule 3 requires before it can
/// ever declare `all_acked`). The returned stream must be held for as long as
/// the caller needs that peer to stay connected.
async fn open_watch(gw: &StubGateway) -> tonic::Streaming<wiremesh_proto::v1::SyncMessage> {
    let mut stream = gw.open_sync().await;
    let first = tokio::time::timeout(SNAPSHOT_TIMEOUT, stream.next())
        .await
        .expect("timed out waiting for the gateway's initial Sync.Watch snapshot")
        .expect("Sync.Watch stream ended before delivering the initial snapshot")
        .expect("Sync.Watch stream yielded an error instead of the initial snapshot");
    match first.body {
        Some(sync_message::Body::Snapshot(_)) => {}
        other => panic!("expected the first Sync.Watch message to be a StateSnapshot, got: {other:?}"),
    }
    stream
}

/// The highest-numbered `pending` epoch currently on file for `gateway_id`,
/// if any.
fn pending_epoch(states: &[(u32, String, String)]) -> Option<u32> {
    states
        .iter()
        .filter(|(_, _, state)| state == "pending")
        .map(|(epoch, _, _)| *epoch)
        .max()
}

/// Drives an already-`pending` epoch `n` all the way to `active`: `a` submits
/// its real key for it, `b` (a connected peer) acks it live, and the promote
/// is polled for. Returns the instant the promote was first OBSERVED — always
/// at or after the controller's own promote instant, so a later "not yet
/// `RETIRE_GRACE`" check computed from it is conservative in the safe
/// direction.
async fn promote_pending_epoch(
    h: &TestController,
    a: &StubGateway,
    b: &StubGateway,
    n: u32,
    pubkey: &str,
) -> tokio::time::Instant {
    a.submit_epoch_key(n, pubkey)
        .await
        .expect("Sync.SubmitEpochKey must succeed for gateway A's pending epoch");
    b.report_epoch_acks(0, &[(a.id(), n, true)])
        .await
        .expect("StubGateway::report_epoch_acks must succeed for B acking A's new epoch");

    let states = poll_key_states(h, a.id(), PROMOTE_BUDGET, |states| {
        states
            .iter()
            .any(|(epoch, _, state)| *epoch == n && state == "active")
    })
    .await;
    let observed_at = tokio::time::Instant::now();
    assert!(
        states
            .iter()
            .any(|(epoch, _, state)| *epoch == n && state == "active"),
        "epoch {n} for gateway A never promoted to 'active' within {PROMOTE_BUDGET:?} of B's \
         live ack — this file's tests all build on a COMPLETED rotation, so nothing below is \
         meaningful without it; last observed: {states:?}"
    );
    observed_at
}

/// Runs one complete rotation of `a` (admin-initiated, real key submitted,
/// acked live by `b`, promoted) and returns `(new_epoch, promote_observed_at)`.
async fn complete_one_rotation(
    h: &TestController,
    a: &StubGateway,
    b: &StubGateway,
    pubkey: &str,
) -> (u32, tokio::time::Instant) {
    h.admin_client()
        .await
        .rotate_key(RotateKeyRequest { gateway_id: a.id() })
        .await
        .expect("Admin.RotateKey(gateway_id = a.id()) must succeed");

    let states = h.debug_key_states(a.id()).await;
    let n = pending_epoch(&states).unwrap_or_else(|| {
        panic!("expected a 'pending' GATEWAY_KEY row for gateway A right after Admin.RotateKey, got: {states:?}")
    });

    let promoted_at = promote_pending_epoch(h, a, b, n, pubkey).await;
    (n, promoted_at)
}

/// ONE completed rotation must leave gateway A with EXACTLY ONE key row.
///
/// This is the cheapest assertion that catches the whole family at once: the
/// stranded `retiring` row after a single rotation, and — because every
/// rotation strands one more — the unbounded per-rotation accumulation that
/// follows. A gateway that has finished rotating holds exactly its one
/// `active` epoch; anything else is a row nothing will ever clean up.
///
/// The rotation timer is DISABLED (`None`) so nothing but the rotation this
/// test drives can add rows, and the decision sweep runs at 500ms so it gets
/// ~60 chances inside the budget.
#[tokio::test]
async fn one_completed_rotation_leaves_exactly_one_key_row() {
    let h = TestController::start_with_rotation_intervals(None, SWEEP_INTERVAL).await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;
    let _b_stream = open_watch(&b).await;

    let pre = h.debug_key_states(a.id()).await;
    assert_eq!(
        pre.len(),
        1,
        "a freshly enrolled gateway must hold exactly its epoch-0 baseline row — if this is \
         already wrong the rest of this test proves nothing; got: {pre:?}"
    );

    let (n1, _promoted_at) = complete_one_rotation(&h, &a, &b, "REALKEYA==").await;

    let states = poll_key_states(&h, a.id(), RETIRE_BUDGET, |states| states.len() == 1).await;

    assert_eq!(
        states.len(),
        1,
        "after ONE completed rotation (epoch {n1} promoted to 'active'), gateway A must hold \
         exactly one key row within {RETIRE_BUDGET:?} — the prior epoch's 'retiring' row is \
         supposed to be deleted RETIRE_GRACE (30s) after the promote. Every extra row here is \
         one nothing will ever clean up, and each further rotation adds another; got: {states:?}"
    );
    assert!(
        states
            .iter()
            .any(|(epoch, _, state)| *epoch == n1 && state == "active"),
        "the one surviving row must be the newly promoted epoch {n1}, still 'active' — a \
         cleanup that deleted the wrong row would also satisfy the count above; got: {states:?}"
    );
}

/// The prior epoch's `retiring` row must be deleted `RETIRE_GRACE` after the
/// promote WITHOUT any second rotation and WITHOUT a controller restart.
///
/// Those two escapes are exactly what the existing coverage relies on, which
/// is why the gap survived:
///   * `rotation_timer.rs::sweep_retires_orphaned_retiring_row_after_crash`
///     `restart()`s the controller, which drops the in-memory tracker and so
///     hands the row to the sweep's ORPHAN path (immediate, no grace);
///   * `docs/research/second-rotation-stranded-tracker.md`'s eviction only
///     fires when a SECOND rotation opens a new `pending` row.
///
/// A controller that just runs — one rotation, no restart, no follow-up — is
/// the case with no owner at all. The timer is `None` here specifically so
/// that no second rotation can appear and rescue the row.
#[tokio::test]
async fn promoted_rotation_retires_prior_epoch_with_no_second_rotation_and_no_restart() {
    let h = TestController::start_with_rotation_intervals(None, SWEEP_INTERVAL).await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;
    let _b_stream = open_watch(&b).await;

    let (n1, _promoted_at) = complete_one_rotation(&h, &a, &b, "REALKEYA==").await;

    // Immediately after the promote the prior epoch is legitimately still
    // present as 'retiring' — RETIRE_GRACE has not elapsed. Pin that, so the
    // deletion asserted below is a real transition and not a row that was
    // never created.
    let just_after = h.debug_key_states(a.id()).await;
    assert!(
        just_after
            .iter()
            .any(|(epoch, _, state)| *epoch == 0 && state == "retiring"),
        "expected the prior epoch-0 row to be demoted to 'retiring' the moment epoch {n1} \
         promotes (inside RETIRE_GRACE) — this is the row that must later be deleted; \
         got: {just_after:?}"
    );

    // The unavoidable ~30s: RETIRE_GRACE is a hard `const` in
    // `crate::rotation` with no `Config` knob, so unlike the sweep/timer
    // cadences it cannot be shrunk for the test. Polling (rather than one
    // flat sleep) means a working implementation finishes as soon as the
    // sweep tick after 30s, and a broken one still fails with the last
    // snapshot in the message rather than hanging.
    let states = poll_key_states(&h, a.id(), RETIRE_BUDGET, |states| {
        !states.iter().any(|(epoch, _, _)| *epoch == 0)
    })
    .await;

    assert!(
        !states.iter().any(|(epoch, _, _)| *epoch == 0),
        "the prior epoch-0 'retiring' row must be deleted within {RETIRE_BUDGET:?} of epoch \
         {n1}'s promote (RETIRE_GRACE is 30s) with NO second rotation and NO controller \
         restart. Nothing drives a promoted rotation's tracker to its \
         RotationDecision::Retire: sweep_rotations only calls drive_rotation_for for a \
         gateway that still has a 'pending' row, and its orphan path skips any gateway that \
         still holds a tracker. Got: {states:?}"
    );
    assert!(
        states
            .iter()
            .any(|(epoch, _, state)| *epoch == n1 && state == "active"),
        "epoch {n1} must remain 'active' — only the retiring row is supposed to go; \
         got: {states:?}"
    );
}

/// THE FINDING: a gateway that has completed one rotation must still be
/// eligible for the NEXT automatic one.
///
/// This is the consequence that actually costs something in production. A
/// stranded `retiring` row keeps its gateway inside
/// `Db::gateways_with_rotation_state`, and `initiate_due_rotations` skips
/// every id in that set — so the rotation-initiation timer silently stops
/// rotating that gateway forever, while `Admin.RotateKey` (unguarded) keeps
/// working and hides it.
///
/// Driven through the real timer, not through row inspection: the assertion
/// is "a second pending epoch appears on its own", which is precisely the
/// behaviour a deployment loses. The DB set is read only to name the
/// mechanism in the failure message.
///
/// Cadence: a 2s `rotation_interval` and a 500ms sweep. The budget has to
/// cover RETIRE_GRACE (30s, uncompressible) plus a timer tick, hence 60s.
#[tokio::test]
async fn timer_still_rotates_a_gateway_after_a_completed_rotation() {
    let h = TestController::start_with_rotation_intervals(
        Some(Duration::from_secs(2)),
        SWEEP_INTERVAL,
    )
    .await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;
    let _b_stream = open_watch(&b).await;

    // First rotation: initiated by the TIMER itself (no Admin.RotateKey
    // anywhere in this test), so the "the timer works for this gateway"
    // baseline is established by the same mechanism the assertion below
    // needs to still be alive.
    let states = poll_key_states(&h, a.id(), Duration::from_secs(15), |states| {
        pending_epoch(states).is_some()
    })
    .await;
    let n1 = pending_epoch(&states).unwrap_or_else(|| {
        panic!(
            "the rotation-initiation timer (2s interval) never created a pending epoch for \
             idle gateway A within 15s — without a timer-initiated first rotation this test \
             cannot say anything about the SECOND one; got: {states:?}"
        )
    });

    promote_pending_epoch(&h, &a, &b, n1, "REALKEYA==").await;

    // Now: no admin action, no restart, nothing but time. The timer must
    // eventually pick A up again. 60s covers RETIRE_GRACE (30s) plus several
    // 2s ticks.
    let budget = Duration::from_secs(60);
    let states = poll_key_states(&h, a.id(), budget, |states| {
        pending_epoch(states).is_some_and(|n| n > n1)
    })
    .await;

    let mid_rotation = mid_rotation_gateway_ids(&h).await;
    assert!(
        pending_epoch(&states).is_some_and(|n| n > n1),
        "after completing rotation to epoch {n1}, gateway A (id {}) must become eligible for \
         automatic rotation again — the timer (2s interval) must create a further pending \
         epoch within {budget:?}. It cannot, because the prior epoch's 'retiring' row is \
         never deleted, Db::gateways_with_rotation_state still returns A, and \
         initiate_due_rotations skips every id in that set. Automatic rotation for this \
         gateway is wedged permanently (Admin.RotateKey still works, which is what hides it). \
         gateways_with_rotation_state = {mid_rotation:?}; A's keys = {states:?}",
        a.id()
    );
}

/// A second rotation started INSIDE the first one's `RETIRE_GRACE` must
/// promote promptly, must not steal the first retire's grace, and must leave
/// no rows behind.
///
/// Three separate things, and the middle one is the trap:
///
///  (a) epoch n2 promotes in seconds, not 30-40s. This pins the stranded-
///      tracker eviction (`docs/research/second-rotation-stranded-tracker.md`):
///      without it, `decide`'s rule 1 short-circuits on the OLD tracker's
///      `promoted_at`, every ack for n2 is discarded, and n2 only lands via
///      the grace path much later.
///
///  (b) epoch 0 is still on file well before its OWN 30s from promote-1.
///      This is the near-miss guard. The tempting way to make (c) pass is to
///      widen the eviction to a plain `Some(t.pending_epoch) != db_pending`,
///      which also evicts the stranded post-promote tracker — handing its
///      retire to `sweep_rotations`' orphan path, which deletes IMMEDIATELY
///      and so collapses RETIRE_GRACE from 30s to ~0 on every normal
///      rotation. That is a make-before-break regression, not a fix.
///      Currently green, and it must STAY green.
///
///  (c) eventually both epoch 0 and epoch n1 are gone and exactly one row is
///      left. Note this needs BOTH retiring rows handled: the tracker for
///      epoch 0's retire is (correctly) evicted when the second rotation
///      opens, and the surviving tracker only knows n1 as its
///      `prior_active_epoch`.
#[tokio::test]
async fn second_rotation_inside_retire_grace_keeps_the_grace_and_leaves_one_row() {
    let h = TestController::start_with_rotation_intervals(None, SWEEP_INTERVAL).await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;
    let _b_stream = open_watch(&b).await;

    let (n1, promote1_at) = complete_one_rotation(&h, &a, &b, "REALKEYA1==").await;

    // Second rotation, immediately — comfortably inside epoch 0's 30s grace.
    let (n2, promote2_at) = complete_one_rotation(&h, &a, &b, "REALKEYA2==").await;
    assert!(
        n2 > n1,
        "the second Admin.RotateKey must open a strictly higher epoch than {n1}, got {n2}"
    );

    // (a) The whole point of the eviction: n2 promoted off B's ack, not off
    // the 90s GRACE_PROMOTE path. `complete_one_rotation` polls with a 10s
    // budget, so reaching here at all already bounds it, but state the
    // timing explicitly so a regression reads as "promotion got slow" rather
    // than an opaque timeout.
    let promote2_delay = promote2_at.saturating_duration_since(promote1_at);
    assert!(
        promote2_delay < Duration::from_secs(15),
        "epoch {n2} took {promote2_delay:?} after epoch {n1}'s promote to go active — a \
         second rotation started inside RETIRE_GRACE must promote off its peer acks within \
         seconds. Taking ~30-40s means the previous rotation's stranded tracker was NOT \
         evicted, so decide()'s rule 1 short-circuited on its promoted_at and every ack for \
         epoch {n2} was discarded"
    );

    // (b) Epoch 0 must still be there well inside its own 30s from promote-1.
    // `promote1_at` is the instant the promote was OBSERVED (>= the real
    // one), so this check lands strictly earlier than 18s of true grace —
    // conservative in the safe direction.
    let check_at = promote1_at + Duration::from_secs(18);
    let now = tokio::time::Instant::now();
    if check_at > now {
        tokio::time::sleep(check_at - now).await;
    }
    let mid_grace = h.debug_key_states(a.id()).await;
    assert!(
        mid_grace
            .iter()
            .any(|(epoch, _, state)| *epoch == 0 && state == "retiring"),
        "epoch 0 must STILL be on file as 'retiring' ~18s after its promote — its 30s \
         RETIRE_GRACE has not elapsed, and the second rotation must not shorten it. If this \
         is red, the stranded-tracker eviction was widened to fire when the DB has NO pending \
         epoch, which hands the post-promote retire to sweep_rotations' orphan path — that \
         path deletes immediately and collapses RETIRE_GRACE from 30s to ~0 on EVERY normal \
         rotation, breaking make-before-break for every peer still on the old key. \
         Got: {mid_grace:?}"
    );

    // (c) Both retiring rows must eventually go. Epoch 0's own grace expires
    // at promote1 + 30s and epoch n1's at promote2 + 30s, so measure the
    // budget from the later promote.
    let deadline = promote2_at + RETIRE_BUDGET;
    let states = poll_key_states(
        &h,
        a.id(),
        deadline.saturating_duration_since(tokio::time::Instant::now()),
        |states| states.len() == 1,
    )
    .await;

    assert_eq!(
        states.len(),
        1,
        "after two completed rotations gateway A must be left with exactly one key row (epoch \
         {n2}, 'active'). BOTH prior epochs have to be retired: epoch 0 at promote-1 + 30s and \
         epoch {n1} at promote-2 + 30s. Note that epoch 0's tracker is (correctly) evicted when \
         the second rotation opens, and the surviving tracker only knows {n1} as its \
         prior_active_epoch — so a fix that only drives the newest tracker's Retire still \
         strands epoch 0 here. Got: {states:?}"
    );
    assert!(
        states
            .iter()
            .any(|(epoch, _, state)| *epoch == n2 && state == "active"),
        "the one surviving row must be epoch {n2}, 'active'; got: {states:?}"
    );
}
