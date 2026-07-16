//! Proves C-7 (fail-static / restore): after a controller restart against
//! the SAME data-dir (same SQLite DB + CA key — see
//! `wiremesh_testkit::TestController::restart`), an already-enrolled gateway
//! reconnects to `Sync.Watch` **with its existing cert** (no re-enrollment)
//! and the controller still serves it — proving the controller's identity
//! and state are durable across a restart, not re-created from scratch.
//!
//! `TestController::restart`, `StubGateway::persist_state`, and
//! `StubGateway::reconnect` do not exist yet — they're added by the Task 9
//! implementer alongside the restart/persist/reconnect harness plumbing this
//! test drives. Until then this fails to compile, which is the expected RED
//! state for this step.
use tokio_stream::StreamExt;
use wiremesh_proto::v1::sync_message;

#[tokio::test]
async fn gateway_resyncs_after_controller_restart_without_reenrolling() {
    let mut h = wiremesh_testkit::TestController::start().await;
    let gw = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;

    let pre_restart_revision = {
        let mut s = gw.open_sync().await;
        let msg = s
            .next()
            .await
            .expect("initial Sync.Watch stream ended before delivering a message")
            .expect("initial Sync.Watch stream yielded an error instead of a message");
        match msg.body {
            Some(sync_message::Body::Snapshot(snap)) => snap.revision,
            other => panic!(
                "expected the first Sync.Watch message to be a StateSnapshot, got: {other:?}"
            ),
        }
        // `s` drops here, closing the stream before the gateway "goes dark".
    };

    // Gateway writes its identity bundle to disk (fail-static: it must
    // survive without depending on the controller being up).
    gw.persist_state();

    // Same data-dir + ca.key; controller comes back up as if the process
    // had crashed and restarted, or the host rebooted.
    h.restart().await;

    // Reconnect with the SAME cert — must succeed (no re-enroll) and yield a
    // fresh snapshot, proving the restarted controller still recognizes this
    // gateway's existing certificate as valid and knows its enrolled state.
    let mut s2 = gw
        .reconnect(&h)
        .await
        .expect("reconnecting with the existing cert after controller restart must succeed");
    let msg = s2
        .next()
        .await
        .expect("post-restart Sync.Watch stream ended before delivering a message")
        .expect("post-restart Sync.Watch stream yielded an error instead of a message");

    let post_restart_revision = match msg.body {
        Some(sync_message::Body::Snapshot(snap)) => snap.revision,
        other => panic!(
            "expected the post-restart Sync.Watch message to be a StateSnapshot (proving \
             the gateway authenticated with its existing cert and was resynced, not \
             re-enrolled), got: {other:?}"
        ),
    };

    // The revision counter is DB-persistent (Task 7), so it must not have
    // reset across the restart — it must be at least what it was before.
    assert!(
        post_restart_revision >= pre_restart_revision,
        "revision must survive the restart (persistent, monotonic), got pre={pre_restart_revision} post={post_restart_revision}"
    );
}
