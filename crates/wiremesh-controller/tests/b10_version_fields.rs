//! (B10 / X-6) The version fields are ADDITIVE and, in Phase B, WRITE-ONLY.
//!
//! Two properties live here:
//!
//!   * a client that never reports them enrolls and syncs normally, and its
//!     columns hold NULL — not `''`, not 0;
//!   * every `StateSnapshot` the controller builds carries the controller's
//!     own version pair.
//!
//! # Where the OTHER skew direction is tested, and why not here
//!
//! "New gateway ↔ old controller" cannot be exercised at runtime without an
//! old controller binary, which design §5.1 explicitly forbids requiring
//! ("simulate `old` by constructing the proto message with the new fields left
//! at default; a genuinely old binary is not required and must not be"). It is
//! covered instead by
//! `wiremesh-proto/tests/codegen.rs::state_snapshot_decodes_with_the_version_fields_cleared`
//! (the wire half: 9/10 absent decodes to `""`) and by the never-consulted
//! source guard in `wiremesh-operator/tests/` (the behavioural half: no code
//! branches on them, so there is nothing that COULD gate). Naming both here so
//! a reader does not conclude the direction is untested.

use wiremesh_testkit::{enroll_one, TestController};

/// `(version, max_ir_schema)` straight off the gateway row, read through a
/// second connection the way `TestController::gateway_exists` does.
///
/// Read as `Option` deliberately: the whole point of §5.1's nullable choice is
/// that "never reported" is NULL and nothing else, so a test that read these
/// as `String`/`u32` would silently turn a NULL into `""`/0 and assert the
/// very ambiguity the column shape exists to prevent.
async fn stored_version_pair(h: &TestController, gateway_id: i64) -> (Option<String>, Option<i64>) {
    let db_path = h.data_dir().join("controller.db");
    tokio::task::spawn_blocking(move || {
        let conn = rusqlite::Connection::open(&db_path).expect("second connection to the DB");
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .expect("busy timeout");
        conn.query_row(
            "SELECT version, max_ir_schema FROM gateway WHERE id = ?1",
            rusqlite::params![gateway_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the enrolled gateway row must exist")
    })
    .await
    .expect("blocking DB read")
}

/// An old client — one that sets neither field — enrolls, opens a Watch, and
/// its columns hold NULL.
///
/// This is the "old gateway ↔ new controller" direction. The stub gateway is
/// genuinely such a client: `wiremesh-testkit` sends `client_version: ""` and
/// `max_ir_schema: 0`, which is byte-for-byte what a pre-B10 binary puts on
/// the wire, because proto3 does not distinguish absent from default.
#[tokio::test]
async fn an_old_client_with_absent_version_fields_enrolls_and_syncs() {
    let h = TestController::start().await;
    let gw = enroll_one(&h, "aws", "10.0.0.0/16").await;

    // Enrolment succeeded (the helper panics otherwise) and the Watch opens —
    // the two operations B10 must not have broken.
    let _stream = gw.open_sync().await;

    let (version, schema) = stored_version_pair(&h, gw.id() as i64).await;
    assert_eq!(
        (version, schema),
        (None, None),
        "a client that reported no version must store NULL in BOTH columns. proto3 hands the \
         controller `\"\"` and 0 for absent fields, so writing them through would give each \
         column a SECOND spelling of \"unknown\" beside NULL — and every later reader would \
         have to know which one it was looking at. The mapping is `db::store_version` / \
         `db::store_schema`, and it must be applied at the write site, not at the read site"
    );
}

/// Every gateway `StateSnapshot` carries the controller's version pair.
///
/// Advisory in Phase B: the gateway stores nothing and gates on nothing. The
/// pair exists so that a Phase-C gateway can report skew, and it has to be on
/// the wire from 1.0 or there is nothing to compare against later.
#[tokio::test]
async fn a_gateway_snapshot_carries_the_controller_version_pair() {
    use tokio_stream::StreamExt;
    use wiremesh_proto::v1::sync_message;

    let h = TestController::start().await;
    let gw = enroll_one(&h, "aws", "10.0.0.0/16").await;
    let mut stream = gw.open_sync().await;

    let msg = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
        .await
        .expect("a snapshot must arrive within 5s")
        .expect("the Watch stream must yield")
        .expect("the first Sync message must not be an error");
    let snapshot = match msg.body {
        Some(sync_message::Body::Snapshot(s)) => s,
        other => panic!("the first Sync message must be a Snapshot; got {other:?}"),
    };

    assert!(
        !snapshot.controller_version.is_empty(),
        "the snapshot's `controller_version` is empty. Every Watch opens with a snapshot, so \
         this is the one place a gateway is guaranteed to learn what it is talking to — an \
         empty value here is indistinguishable from a pre-B10 controller, which is exactly \
         the skew the field exists to make visible"
    );
    assert!(
        !snapshot.min_supported_version.is_empty(),
        "the snapshot's `min_supported_version` is empty. It is a constant the controller \
         also logs at boot; shipping it empty means a Phase-C gateway can never tell \
         \"this controller supports me\" from \"this controller predates the field\""
    );
}
