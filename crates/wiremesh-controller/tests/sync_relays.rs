//! Cycle-4c Task 5: controller relay advertisement over Sync.
//!
//! Today `build_snapshot`/`delta_for_change` hardcode `relays: Vec::new()`
//! (see `crates/wiremesh-controller/src/projection.rs`), and relay
//! enrollment (`services/enrollment.rs`, Task 4) emits no `ChangeEvent` and
//! does not validate `endpoint`'s shape. This suite pins the Task 5 contract:
//!
//! 1. `build_snapshot` must populate `StateSnapshot.relay_infos` with a
//!    `RelayInfo { relay_id, endpoint }` for every ACTIVE `relay` row
//!    (`Db::list_relays()` returns `(id, name, endpoint, status)`).
//! 2. Relay enrollment must publish a `ChangeEvent::RelaysChanged` (broadcast
//!    to every already-connected gateway, mirroring `CertRevoked`/
//!    `PolicyUpdated`'s `subject_gateway_id() == 0`) whose
//!    `delta_for_change` carries the FULL current active-relay set in
//!    `Delta.relay_infos`.
//! 3. The relay `endpoint` must be validated as `ip:port` at enrollment — a
//!    malformed endpoint must be rejected AND must not create a relay row
//!    (so it can never be advertised).
//!
//! Mirrors `tests/sync_snapshot.rs` (single-shot `Sync.Watch` snapshot
//! inspection) and `tests/sync_delta.rs` (already-connected gateway
//! receiving a delta after a subsequent mutation) exactly — same
//! `wiremesh_testkit::TestController`/`enroll_one` harness, same bounded
//! `tokio::time::timeout` pattern so a regression (no relays advertised, or
//! no delta ever pushed) fails fast instead of hanging the suite. Relay
//! creation goes through `wiremesh_testkit::enroll_relay` (Task 4's helper:
//! mints a `relay`-kind token, redeems it via `Enrollment.Enroll` with
//! `endpoint` set, returns `(cert_pem, ca_bundle_pem, relay_id)` — the third
//! element is `EnrollResponse.gateway_id` reinterpreted as the relay's row
//! id, since relay enrollment has no dedicated response field).
//!
//! None of this exists yet as of this writing: every test below is expected
//! RED.
use std::time::Duration;

use tokio_stream::StreamExt;
use wiremesh_proto::v1::sync_message;

/// Bounds the wait for the initial `Sync.Watch` snapshot / a subsequent
/// delta, mirroring `sync_snapshot.rs`/`sync_delta.rs`'s timeouts — a
/// controller that never emits what's expected is a real regression and
/// should fail this test fast instead of hanging the whole suite.
const SYNC_TIMEOUT: Duration = Duration::from_secs(5);

/// Before any relay is enrolled, and after one is, `build_snapshot` must
/// reflect the active-relay set correctly: empty when there are none, and
/// carrying a `RelayInfo` for the enrolled relay once one exists.
#[tokio::test]
async fn snapshot_advertises_active_relays() {
    let h = wiremesh_testkit::TestController::start().await;
    let gw = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;

    // BEFORE any relay is enrolled: a fresh gateway's snapshot must
    // advertise no relays at all.
    let mut stream = gw.open_sync().await;
    let msg = tokio::time::timeout(SYNC_TIMEOUT, stream.next())
        .await
        .expect("timed out waiting for the initial Sync.Watch snapshot")
        .expect("Sync.Watch stream ended before delivering a message")
        .expect("Sync.Watch stream yielded an error instead of a message");
    let snap_before = match msg.body {
        Some(sync_message::Body::Snapshot(s)) => s,
        other => {
            panic!("expected the first Sync.Watch message to be a StateSnapshot, got: {other:?}")
        }
    };
    assert!(
        snap_before.relay_infos.is_empty(),
        "before any relay is enrolled, the snapshot's relays must be empty, got: {:?}",
        snap_before.relay_infos
    );

    // Enroll a relay with a valid ip:port endpoint.
    let endpoint = "203.0.113.9:51820";
    let (_cert_pem, _ca_bundle_pem, relay_id) = wiremesh_testkit::enroll_relay(&h, endpoint).await;
    assert!(
        relay_id > 0,
        "enroll_relay must return a positive relay id, got {relay_id}"
    );

    // A NEW Sync.Watch (fresh connection, so a full snapshot) must now
    // advertise the enrolled relay.
    let gw2 = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;
    let mut stream2 = gw2.open_sync().await;
    let msg2 = tokio::time::timeout(SYNC_TIMEOUT, stream2.next())
        .await
        .expect("timed out waiting for the post-relay-enrollment Sync.Watch snapshot")
        .expect("Sync.Watch stream ended before delivering a message")
        .expect("Sync.Watch stream yielded an error instead of a message");
    let snap_after = match msg2.body {
        Some(sync_message::Body::Snapshot(s)) => s,
        other => {
            panic!("expected the first Sync.Watch message to be a StateSnapshot, got: {other:?}")
        }
    };

    assert_eq!(
        snap_after.relay_infos.len(),
        1,
        "after enrolling one active relay, the snapshot must advertise exactly one, got: {:?}",
        snap_after.relay_infos
    );
    assert_eq!(
        snap_after.relay_infos[0].endpoint, endpoint,
        "the advertised relay's endpoint must match the one declared at enrollment"
    );
    assert_eq!(
        snap_after.relay_infos[0].relay_id, relay_id as u64,
        "the advertised relay's relay_id must match the enrolled relay's row id"
    );
}

/// Mirrors `tests/sync_delta.rs`'s already-connected pattern: a gateway with
/// an already-open `Sync.Watch` (initial snapshot already consumed, with
/// empty relays) must receive a `Delta` carrying the newly enrolled relay
/// when that relay is enrolled AFTER the stream was opened.
#[tokio::test]
async fn relay_enrollment_pushes_relays_delta_to_connected_gateway() {
    let h = wiremesh_testkit::TestController::start().await;
    let gw = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;

    let mut stream = gw.open_sync().await;
    let snap_msg = stream
        .next()
        .await
        .expect("Sync.Watch stream ended before delivering the initial snapshot")
        .expect("Sync.Watch stream yielded an error instead of the initial snapshot");
    let snap = match snap_msg.body {
        Some(sync_message::Body::Snapshot(s)) => s,
        other => {
            panic!("expected the first Sync.Watch message to be a StateSnapshot, got: {other:?}")
        }
    };
    assert!(
        snap.relay_infos.is_empty(),
        "the initial snapshot (before any relay is enrolled) must have empty relays, got: {:?}",
        snap.relay_infos
    );
    let snap_rev = snap.revision;

    // Enrolling a relay AFTER the gateway's stream is already open is a
    // projection-affecting mutation and must push a Delta down that
    // still-open stream, bounded by a timeout so a missing delta fails fast
    // instead of hanging the test suite.
    let endpoint = "198.51.100.7:51820";
    let (_cert_pem, _ca_bundle_pem, relay_id) = wiremesh_testkit::enroll_relay(&h, endpoint).await;

    let msg = tokio::time::timeout(SYNC_TIMEOUT, stream.next())
        .await
        .expect("timed out waiting for the delta triggered by enrolling the relay")
        .expect("Sync.Watch stream ended before delivering the delta")
        .expect("Sync.Watch stream yielded an error instead of the delta");

    let delta = match msg.body {
        Some(sync_message::Body::Delta(d)) => d,
        other => panic!("expected a Delta after enrolling the relay, got: {other:?}"),
    };

    assert_eq!(
        delta.relay_infos.len(),
        1,
        "expected exactly one relay in the delta (the newly enrolled one), got: {:?}",
        delta.relay_infos
    );
    assert_eq!(
        delta.relay_infos[0].endpoint, endpoint,
        "the delta's relay entry must carry the newly enrolled relay's endpoint"
    );
    assert_eq!(
        delta.relay_infos[0].relay_id, relay_id as u64,
        "the delta's relay entry must carry the newly enrolled relay's id"
    );
    assert!(
        delta.revision > snap_rev,
        "delta revision ({}) must be strictly newer than the initial snapshot's revision ({})",
        delta.revision,
        snap_rev
    );
}

/// (Cycle-4c review fix) `Admin.RegisterRelay` is a SECOND way to add a
/// relay, distinct from self-enrollment (`enroll_relay` above, which goes
/// through `Enrollment.Enroll` with a `relay`-kind token). Before this fix,
/// `AdminSvc::register_relay` inserted the relay row + audit but never
/// bumped the persisted revision or published a `ChangeEvent::RelaysChanged`,
/// so an already-connected gateway's open `Sync.Watch` stream would never
/// learn about a relay registered this way until it happened to reconnect
/// (the exact same gap `relay_enrollment_pushes_relays_delta_to_connected_gateway`
/// above pins for the enrollment path). This test mirrors that harness
/// exactly, substituting `Admin.RegisterRelay` for `enroll_relay`.
#[tokio::test]
async fn register_relay_pushes_relay_infos_delta_to_connected_gateway() {
    use wiremesh_proto::v1::RegisterRelayRequest;

    let h = wiremesh_testkit::TestController::start().await;
    let gw = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;

    let mut stream = gw.open_sync().await;
    let snap_msg = stream
        .next()
        .await
        .expect("Sync.Watch stream ended before delivering the initial snapshot")
        .expect("Sync.Watch stream yielded an error instead of the initial snapshot");
    let snap = match snap_msg.body {
        Some(sync_message::Body::Snapshot(s)) => s,
        other => {
            panic!("expected the first Sync.Watch message to be a StateSnapshot, got: {other:?}")
        }
    };
    assert!(
        snap.relay_infos.is_empty(),
        "the initial snapshot (before any relay is registered) must have empty relay_infos, got: {:?}",
        snap.relay_infos
    );
    let snap_rev = snap.revision;

    // Register a relay via the ADMIN surface (not enrollment) AFTER the
    // gateway's stream is already open — this must push a Delta down that
    // still-open stream, bounded by a timeout so a missing delta fails fast
    // instead of hanging the test suite.
    let endpoint = "203.0.113.99:4443";
    let mut admin = h.admin_client().await;
    let registered = admin
        .register_relay(RegisterRelayRequest {
            name: "admin-registered-relay".into(),
            endpoint: endpoint.into(),
        })
        .await
        .expect("Admin.RegisterRelay")
        .into_inner();
    assert_eq!(registered.endpoint, endpoint);

    let msg = tokio::time::timeout(SYNC_TIMEOUT, stream.next())
        .await
        .expect("timed out waiting for the delta triggered by Admin.RegisterRelay")
        .expect("Sync.Watch stream ended before delivering the delta")
        .expect("Sync.Watch stream yielded an error instead of the delta");

    let delta = match msg.body {
        Some(sync_message::Body::Delta(d)) => d,
        other => panic!("expected a Delta after Admin.RegisterRelay, got: {other:?}"),
    };

    assert_eq!(
        delta.relay_infos.len(),
        1,
        "expected exactly one relay in the delta (the admin-registered one), got: {:?}",
        delta.relay_infos
    );
    assert_eq!(
        delta.relay_infos[0].endpoint, endpoint,
        "the delta's relay entry must carry the admin-registered relay's endpoint"
    );
    assert_eq!(
        delta.relay_infos[0].relay_id, registered.id,
        "the delta's relay entry must carry the admin-registered relay's id"
    );
    assert!(
        delta.revision > snap_rev,
        "delta revision ({}) must be strictly newer than the initial snapshot's revision ({})",
        delta.revision,
        snap_rev
    );
}

/// A relay `endpoint` that is not a well-formed `ip:port` (no port at all,
/// here) must be rejected at enrollment, and — the part a merely-failing
/// RPC call doesn't by itself prove — must leave no relay row behind, so it
/// can never later be advertised in a snapshot or delta.
#[tokio::test]
async fn relay_enrollment_rejects_malformed_endpoint() {
    use rusqlite::Connection;
    use wiremesh_proto::v1::{EnrollRequest, MintTokenRequest};

    let h = wiremesh_testkit::TestController::start().await;
    let mut admin = h.admin_client().await;

    let tok = admin
        .mint_token(MintTokenRequest {
            kind: "relay".into(),
            bound_cidrs: vec![],
            rebind_segment_id: 0,
        })
        .await
        .unwrap()
        .into_inner()
        .token;

    let (csr, _kp) = wiremesh_testkit::gen_csr("relay-bad-endpoint");
    let mut enr = h.enrollment_client().await;

    enr.enroll(EnrollRequest {
        token: tok,
        csr_pem: csr,
        cidrs: vec![],
        wg_pubkey: String::new(),
        endpoint: "not-an-address".to_string(),
        client_version: String::new(),
    })
    .await
    .expect_err("a malformed (non ip:port) relay endpoint must be rejected by Enrollment.Enroll");

    let db_path = h.data_dir().join("controller.db");
    let relay_count = tokio::task::spawn_blocking(move || {
        let conn =
            Connection::open(&db_path).expect("opening controller.db for relay-count inspection");
        conn.query_row("SELECT COUNT(*) FROM relay", [], |row| row.get::<_, i64>(0))
            .expect("counting relay rows")
    })
    .await
    .expect("blocking relay-count task panicked");

    assert_eq!(
        relay_count, 0,
        "a rejected (malformed-endpoint) relay enrollment attempt must not create any relay row"
    );
}
