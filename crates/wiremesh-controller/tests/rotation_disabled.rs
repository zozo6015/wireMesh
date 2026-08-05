//! Behavioural tests for `Config::rotation_interval: None` — automatic
//! key-rotation initiation DISABLED.
//!
//! Context: `services::sync::initiate_due_rotations` rotates every active
//! gateway's WireGuard key on a 30-day timer. Automatic rotation is currently
//! known-broken (the SECOND rotation of a gateway cannot complete, and the
//! in-step pair rotation the timer produces by default breaks the data plane),
//! so until the structural fix lands an operator must be able to switch the
//! timer off. `None` is that switch, and these tests pin the three things it
//! must and must not do:
//!
//!   0. `disabled_state_is_observable_and_survives_restart` — the disabled
//!      state is detectable programmatically, not only by a human reading the
//!      boot banner off stderr, and it stays detectable across a restart.
//!   1. `disabled_timer_never_initiates_a_rotation` — with `None`, no
//!      rotation is EVER initiated on its own, across many ticks of a sweep
//!      that keeps running the whole time. The control for this test is
//!      `rotation_timer.rs::timer_initiates_rotation_for_idle_gateway`, which
//!      proves an ENABLED 1s timer produces a `pending` epoch within ~1-2s on
//!      an identically-shaped gateway.
//!   2. `manual_rotate_key_still_works_with_the_timer_disabled` — disabling
//!      the TIMER must not disable rotation as a CAPABILITY. An operator who
//!      has switched off the schedule must still be able to rotate a
//!      compromised key on demand via `Admin.RotateKey`, and that rotation
//!      must run all the way to promotion.
//!   3. `sweep_still_drives_in_flight_rotations_with_the_timer_disabled` —
//!      the CRITICAL one. The decision sweep (`Config::rotation_sweep_interval`
//!      / `services::sync::sweep_rotations`) is a SEPARATE task from the
//!      initiation timer: it drives promote/retire/abort for rotations that
//!      are already underway and performs crash recovery. An implementation
//!      that guards too much — gating the sweep on `rotation_interval` too —
//!      would strand any rotation that was in flight when the operator turned
//!      the timer off, which is strictly worse than the outage this knob
//!      exists to avoid. Disabling initiation must never disable the sweep.
//!
//! Testkit contract these depend on (see the report accompanying this file):
//! `TestController::start_with_rotation_intervals` takes
//! `Option<std::time::Duration>` for the rotation interval — mirroring
//! `Config::rotation_interval` exactly — and `restart()` preserves it, so a
//! restarted controller stays disabled rather than silently reverting to the
//! 30-day default.

use std::time::Duration;

use tokio_stream::StreamExt;
use wiremesh_proto::v1::{sync_message, RotateKeyRequest};

/// Rows in a `debug_key_states` snapshot whose state is `"pending"` — an
/// initiated-but-not-yet-promoted rotation. With the timer disabled and no
/// admin action, this must stay `0` forever.
fn pending_count(states: &[(u32, String, String)]) -> usize {
    states.iter().filter(|(_, _, state)| state == "pending").count()
}

/// Polls `h.debug_key_states(gateway_id)` until `predicate` holds or `budget`
/// elapses, returning the last-observed snapshot either way — same bounded-poll
/// idiom as `rotation_timer.rs`, so a broken implementation fails fast with a
/// "last observed" panic instead of hanging the suite.
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

/// The disabled state must be DETECTABLE by something other than a human
/// reading stderr.
///
/// This accessor is a proxy for `warn_automatic_rotation_disabled()`'s boot
/// banner, and it is deliberately not a test of the banner text — nothing here
/// asserts that any particular string was printed. What it pins is that the
/// fact the banner conveys is observable at all. That matters because two
/// separate safety arguments rest on the banner: it is this binary's ONLY
/// runtime signal that rotation is off (the controller exposes no metrics
/// endpoint, unlike the gateway), and it is the stated justification for
/// rejecting over-long intervals — see `MAX_ROTATION_INTERVAL_SECS`, whose
/// whole rationale is that a never-firing timer would disable rotation
/// *without* the banner. A refactor that dropped the `eprintln!` would leave a
/// fabric with rotation permanently off and nothing at all to say so; with the
/// state exposed, that refactor has something to fail against.
///
/// Both directions are asserted, against two controllers that differ only in
/// this setting, so an accessor stubbed to a constant cannot pass. The `false`
/// direction is additionally tied to observed behaviour in
/// `rotation_timer.rs::timer_initiates_rotation_for_idle_gateway` (a controller
/// that provably DOES rotate), and the `true` direction in
/// `disabled_timer_never_initiates_a_rotation` (one that provably does not).
#[tokio::test]
async fn disabled_state_is_observable_and_survives_restart() {
    // ENABLED: a long interval, so the timer never actually fires during the
    // test — the accessor must report on how the controller was CONFIGURED
    // (i.e. whether the initiation task exists), not on whether a rotation has
    // happened to occur yet.
    let enabled = wiremesh_testkit::TestController::start_with_rotation_intervals(
        Some(Duration::from_secs(3600)),
        Duration::from_millis(500),
    )
    .await;
    assert!(
        !enabled.automatic_rotation_disabled(),
        "a controller booted with rotation_interval = Some(1h) has a live rotation-initiation \
         timer and must NOT report automatic rotation as disabled — reporting `true` here \
         would tell an operator their fabric is unprotected when it is not, and would let a \
         constant-returning stub satisfy the disabled case below"
    );
    drop(enabled);

    // DISABLED.
    let mut h = wiremesh_testkit::TestController::start_with_rotation_intervals(
        None,
        Duration::from_millis(500),
    )
    .await;
    assert!(
        h.automatic_rotation_disabled(),
        "a controller booted with rotation_interval = None has no rotation-initiation task \
         and must report automatic rotation as DISABLED"
    );

    // And it must still say so after a restart. A restart is the one moment a
    // controller could silently re-arm rotation (or silently stay disabled)
    // with no operator watching the console — the boot banner scrolls past
    // once, whereas this remains queryable afterwards.
    h.restart().await;
    assert!(
        h.automatic_rotation_disabled(),
        "a RESTARTED controller must still report automatic rotation as disabled — the \
         setting is preserved across restarts (see the restart-preservation assertions in \
         the tests below), so the reported state has to be preserved with it, or the two \
         disagree precisely when nobody is looking at the boot output"
    );
}

/// With `rotation_interval: None`, the rotation-initiation timer must not run
/// at all: no gateway ever acquires a `pending` epoch without an operator
/// asking for one.
///
/// Sampled repeatedly rather than slept-through-once, so a regression that
/// initiates late (or on the sweep's cadence, or in a hot loop) is caught at
/// whichever tick it first fires, with the tick number in the panic. Two
/// gateways, because `initiate_due_rotations` walks all active gateways and a
/// partial regression could hit only one of them. The sweep runs at 200ms
/// throughout — ~30 sweep ticks inside the window — so this also pins that
/// the still-running sweep never initiates a rotation of its own.
#[tokio::test]
async fn disabled_timer_never_initiates_a_rotation() {
    let h = wiremesh_testkit::TestController::start_with_rotation_intervals(
        // Automatic rotation DISABLED — the escape hatch under test.
        None,
        Duration::from_millis(200),
    )
    .await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;

    // The observable flag and the observed behaviour, pinned against the SAME
    // controller: everything below proves this instance never initiates a
    // rotation, so this assertion is what stops the flag drifting away from
    // the reality it reports. See
    // `disabled_state_is_observable_and_survives_restart` for what the flag is
    // for.
    assert!(
        h.automatic_rotation_disabled(),
        "a controller booted with rotation_interval = None must REPORT itself as having \
         automatic rotation disabled"
    );

    for (label, id) in [("A", a.id()), ("B", b.id())] {
        let states = h.debug_key_states(id).await;
        assert_eq!(
            pending_count(&states),
            0,
            "gateway {label} must start with no pending epoch (just its epoch-0 baseline), \
             got: {states:?}"
        );
    }

    // 30 samples over ~6s. The enabled control (`rotation_timer.rs`, 1s
    // interval) lands its first initiation within ~1-2s, so this window
    // covers several times over the period at which a "disabled" timer that
    // is in fact running at any test-scale cadence would fire — including a
    // zero/hot-loop interval, which would trip on the very first sample.
    const SAMPLES: usize = 30;
    const STEP: Duration = Duration::from_millis(200);
    for sample in 1..=SAMPLES {
        tokio::time::sleep(STEP).await;
        for (label, id) in [("A", a.id()), ("B", b.id())] {
            let states = h.debug_key_states(id).await;
            assert_eq!(
                pending_count(&states),
                0,
                "with rotation_interval = None the initiation timer must NEVER run: \
                 gateway {label} acquired a pending epoch on its own at sample {sample}/{SAMPLES} \
                 (~{}ms after boot, no admin action taken). Automatic rotation is the \
                 scheduled fabric-wide outage this knob exists to switch off. Got: {states:?}",
                sample * 200
            );
        }
    }

    // The assertions above would also hold vacuously against a controller
    // that had lost these gateways entirely, so pin that each is still
    // present with exactly its untouched epoch-0 `active` key.
    for (label, id) in [("A", a.id()), ("B", b.id())] {
        let states = h.debug_key_states(id).await;
        let active: Vec<_> = states
            .iter()
            .filter(|(_, _, state)| state == "active")
            .collect();
        assert_eq!(
            active.len(),
            1,
            "gateway {label} must still hold exactly one active key after ~6s with rotation \
             disabled, got: {states:?}"
        );
        assert_eq!(
            active[0].0, 0,
            "gateway {label}'s single active key must still be its original epoch 0 — with \
             the timer disabled nothing may have advanced the epoch, got: {states:?}"
        );
    }
}

/// Disabling the automatic TIMER must not disable rotation as a CAPABILITY:
/// `Admin.RotateKey` — the path an operator uses to replace a key they believe
/// is compromised — must still initiate a rotation AND still run it through to
/// promotion (submit + peer ack → new epoch `active`, prior epoch `retiring`)
/// with `rotation_interval: None`.
#[tokio::test]
async fn manual_rotate_key_still_works_with_the_timer_disabled() {
    let mut h = wiremesh_testkit::TestController::start_with_rotation_intervals(
        None,
        Duration::from_millis(200),
    )
    .await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    // B is A's peer and is what acks A's new epoch as live, driving promotion
    // — same shape as `rotation_timer.rs`'s ack-driven case.
    let b = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;

    let mut b_stream = b.open_sync().await;
    let initial = tokio::time::timeout(Duration::from_secs(5), b_stream.next())
        .await
        .expect("timed out waiting for B's initial Sync.Watch snapshot")
        .expect("Sync.Watch stream ended before delivering B's initial snapshot")
        .expect("Sync.Watch stream yielded an error instead of B's initial snapshot");
    assert!(
        matches!(initial.body, Some(sync_message::Body::Snapshot(_))),
        "expected the first Sync.Watch message to be a StateSnapshot, got: {:?}",
        initial.body
    );

    h.admin_client()
        .await
        .rotate_key(RotateKeyRequest { gateway_id: a.id() })
        .await
        .expect(
            "Admin.RotateKey must still succeed with rotation_interval = None — the knob \
             disables the automatic SCHEDULE, not the operator's ability to rotate a \
             compromised key on demand",
        );

    let states = h.debug_key_states(a.id()).await;
    assert_eq!(
        pending_count(&states),
        1,
        "an explicit Admin.RotateKey must create exactly one pending epoch even with the \
         automatic timer disabled, got: {states:?}"
    );
    let n1 = states
        .iter()
        .filter(|(_, _, state)| state == "pending")
        .map(|(epoch, _, _)| *epoch)
        .max()
        .expect("the pending epoch just asserted above must exist");

    a.submit_epoch_key(n1, "REALA==")
        .await
        .expect("Sync.SubmitEpochKey must succeed for gateway A's pending epoch");
    b.report_epoch_acks(0, &[(a.id(), n1, true)])
        .await
        .expect("StubGateway::report_epoch_acks must succeed for B acking A's new epoch");

    let states = poll_key_states(
        &h,
        a.id(),
        Duration::from_secs(5),
        Duration::from_millis(100),
        move |states| {
            states
                .iter()
                .any(|(epoch, _, state)| *epoch == n1 && state == "active")
        },
    )
    .await;
    assert!(
        states
            .iter()
            .any(|(epoch, _, state)| *epoch == n1 && state == "active"),
        "a MANUALLY initiated rotation must run to completion with the timer disabled — \
         epoch {n1} should have promoted to 'active' off B's live ack, got: {states:?}"
    );
    assert!(
        states
            .iter()
            .any(|(epoch, _, state)| *epoch == 0 && state == "retiring"),
        "the prior epoch-0 key must be demoted to 'retiring' when epoch {n1} promotes \
         (RETIRE_GRACE has not elapsed, and a live tracker still governs it), got: {states:?}"
    );

    // Restart safety: the disabled setting is not a one-boot accident of the
    // initial `serve()` call. A restarted controller must still be disabled.
    // Gateway B is the probe here: it is single-`active`-only (idle), which is
    // precisely the population an enabled `initiate_due_rotations` targets on
    // its very next tick.
    h.restart().await;
    assert!(
        h.automatic_rotation_disabled(),
        "the restarted controller must still REPORT automatic rotation as disabled — the \
         reported state and the observed behaviour asserted just below have to agree"
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    let b_states = h.debug_key_states(b.id()).await;
    assert_eq!(
        pending_count(&b_states),
        0,
        "after a restart the controller must still have automatic rotation DISABLED — idle \
         gateway B must not acquire a pending epoch, got: {b_states:?}"
    );
}

/// **The critical one.** The decision sweep must keep running when the
/// initiation timer is disabled: it is what drives an ALREADY-IN-FLIGHT
/// rotation to completion and what performs crash recovery. Turning off the
/// schedule must never strand a rotation that is already underway.
///
/// Manufactured the same deterministic way as
/// `rotation_timer.rs::sweep_retires_orphaned_retiring_row_after_crash`: drive
/// a real ack-promoted rotation until the prior epoch is `retiring` (its
/// in-memory `RotationTracker` still alive, RETIRE_GRACE not yet elapsed),
/// then `restart()` — which drops the tracker but keeps the on-disk `retiring`
/// row. Nothing but the sweep can ever clean that row up: with no tracker,
/// no `decide` call will ever run for it again. If the sweep is (wrongly)
/// gated on `rotation_interval`, the row is stranded forever and this test
/// fails — which is exactly the regression it is here to catch.
///
/// The whole scenario runs with `rotation_interval: None` from the first boot
/// through the restart, so it also pins that `restart()` preserves the
/// disabled setting rather than reverting to the 30-day default.
///
/// NOT INDEPENDENT EVIDENCE, for whoever reads this next: this test and
/// `rotation_timer.rs::sweep_retires_orphaned_retiring_row_after_crash` both
/// manufacture the orphan the same way — by restarting the controller to drop
/// the in-memory `RotationTracker` while the on-disk `retiring` row survives.
/// If that path ever changes shape (say a tracker is rebuilt from the DB on
/// boot, or `retiring` rows are reconciled during startup rather than by the
/// sweep), BOTH tests go red together and neither corroborates the other. They
/// differ only in whether the initiation timer is on, which is the one thing
/// this test is actually about.
#[tokio::test]
async fn sweep_still_drives_in_flight_rotations_with_the_timer_disabled() {
    let mut h = wiremesh_testkit::TestController::start_with_rotation_intervals(
        // Automatic initiation OFF for the entire test...
        None,
        // ...while the decision sweep keeps its own, independent cadence.
        Duration::from_millis(500),
    )
    .await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;

    let mut b_stream = b.open_sync().await;
    let initial = tokio::time::timeout(Duration::from_secs(5), b_stream.next())
        .await
        .expect("timed out waiting for B's initial Sync.Watch snapshot")
        .expect("Sync.Watch stream ended before delivering B's initial snapshot")
        .expect("Sync.Watch stream yielded an error instead of B's initial snapshot");
    assert!(
        matches!(initial.body, Some(sync_message::Body::Snapshot(_))),
        "expected the first Sync.Watch message to be a StateSnapshot, got: {:?}",
        initial.body
    );

    // Get a rotation IN FLIGHT with the timer off — the manual/Admin path is
    // the only way to start one now, which is the point.
    h.admin_client()
        .await
        .rotate_key(RotateKeyRequest { gateway_id: a.id() })
        .await
        .expect("Admin.RotateKey(gateway_id = a.id()) must succeed with the timer disabled");

    let post_rotate = h.debug_key_states(a.id()).await;
    let n1 = post_rotate
        .iter()
        .filter(|(_, _, state)| state == "pending")
        .map(|(epoch, _, _)| *epoch)
        .max()
        .unwrap_or_else(|| {
            panic!(
                "expected a pending epoch for gateway A right after Admin.RotateKey, \
                 got: {post_rotate:?}"
            )
        });

    a.submit_epoch_key(n1, "REALA==")
        .await
        .expect("Sync.SubmitEpochKey must succeed for gateway A's pending epoch");
    b.report_epoch_acks(0, &[(a.id(), n1, true)])
        .await
        .expect("StubGateway::report_epoch_acks must succeed for B acking A's new epoch");

    let pre_restart = poll_key_states(
        &h,
        a.id(),
        Duration::from_secs(5),
        Duration::from_millis(100),
        move |states| {
            states
                .iter()
                .any(|(epoch, _, state)| *epoch == n1 && state == "active")
                && states
                    .iter()
                    .any(|(epoch, _, state)| *epoch == 0 && state == "retiring")
        },
    )
    .await;
    assert!(
        pre_restart
            .iter()
            .any(|(epoch, _, state)| *epoch == n1 && state == "active"),
        "expected epoch {n1} to promote to 'active' off B's live ack before the restart, \
         got: {pre_restart:?}"
    );
    assert!(
        pre_restart
            .iter()
            .any(|(epoch, _, state)| *epoch == 0 && state == "retiring"),
        "expected epoch 0 to be 'retiring' (RETIRE_GRACE not yet elapsed) once epoch {n1} \
         promotes — this is the row the restart below orphans — got: {pre_restart:?}"
    );

    // Crash: the in-memory RotationTracker map is rebuilt empty, while the
    // on-disk 'retiring' epoch-0 row survives. Only `sweep_rotations` can
    // finish this rotation now.
    h.restart().await;

    let post_restart = poll_key_states(
        &h,
        a.id(),
        Duration::from_secs(5),
        Duration::from_millis(200),
        |states| !states.iter().any(|(epoch, _, _)| *epoch == 0),
    )
    .await;
    assert!(
        !post_restart.iter().any(|(epoch, _, _)| *epoch == 0),
        "the decision sweep MUST still run with rotation_interval = None: the orphaned \
         'retiring' epoch-0 row (tracker lost on restart) had to be retired within 5s of a \
         500ms sweep interval. Still present, so disabling automatic INITIATION also \
         disabled the SWEEP — which strands every rotation already in flight when an \
         operator turns the timer off. Got: {post_restart:?}"
    );
    assert!(
        post_restart
            .iter()
            .any(|(epoch, _, state)| *epoch == n1 && state == "active"),
        "epoch {n1} must remain 'active' across the restart and sweep — only the orphaned \
         retiring row should be cleaned up, got: {post_restart:?}"
    );

    // And the sweep finishing that rotation must not have re-armed the
    // disabled timer: A is now single-`active`-only (idle), which is exactly
    // what an enabled `initiate_due_rotations` would pick up on its next tick.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let settled = h.debug_key_states(a.id()).await;
    assert_eq!(
        pending_count(&settled),
        0,
        "with rotation_interval = None, gateway A must stay idle after its in-flight \
         rotation completes — nothing may initiate a fresh one, got: {settled:?}"
    );
}
