//! Cycle-4c Task 6: controller relay HEALTH pipeline (R-3, ≤15s eviction
//! budget) — `Report.relay_health` (`repeated RelayHealth{relay_id,
//! healthy}`, the proto field Task 1 already added to `ReportRequest`; see
//! `wiremesh_proto::v1::RelayHealth` / `proto/wiremesh/v1/sync.proto`) is
//! today completely IGNORED by the controller: `services/sync.rs::report`
//! reads `req.applied_version` and `req.local_endpoints` and never touches
//! `req.relay_health` at all. There is no per-relay health aggregation, no
//! status flip, and no eviction event, so every test below is expected RED.
//!
//! Aggregation rule under test (design: healthy-override, robust against any
//! single gateway's transient view):
//!   - a relay is UNHEALTHY iff it has >=1 report AND NO gateway currently
//!     reports it healthy.
//!   - a relay is HEALTHY iff >=1 gateway currently reports it healthy.
//! When a relay's aggregate flips to unhealthy the controller must set its
//! `relay.status = 'inactive'` and emit a `ChangeEvent::RelaysChanged` (the
//! SAME event Cycle-4c Task 5 already wired — see `tests/sync_relays.rs`)
//! carrying the new active-relay set, so the relay both disappears from a
//! fresh `Sync.Watch` snapshot AND is pushed as a `Delta` to already-
//! connected gateways. It must re-appear (status back to 'active', another
//! `RelaysChanged`) once any gateway reports it healthy again. Eviction is
//! synchronous on the `Report` call that tips the aggregate, so it is
//! trivially inside the 15s R-3 budget — these tests use the same bounded
//! `tokio::time::timeout` pattern as `tests/sync_delta.rs`/
//! `tests/sync_relays.rs` so a regression (no eviction ever happens) fails
//! fast instead of hanging the suite.
//!
//! ASSUMPTION the implementer must satisfy (test-authoring-time contract):
//! `wiremesh_testkit::StubGateway` gains a new method
//!
//! ```ignore
//! pub async fn report_with_relay_health(
//!     &self,
//!     applied_version: u64,
//!     local_endpoints: &[&str],
//!     relay_health: &[(i64, bool)], // (relay_id, healthy)
//! ) -> anyhow::Result<()>
//! ```
//!
//! mirroring the existing `StubGateway::report(applied_version,
//! local_endpoints)` (see `crates/wiremesh-testkit/src/lib.rs`, which today
//! hardcodes `relay_health: vec![]` on the `ReportRequest` it sends) but
//! additionally populating `ReportRequest.relay_health` with one
//! `RelayHealth { relay_id: relay_id as u64, healthy }` per tuple. `relay_id`
//! is `i64` here (not `u64`) because that's what `wiremesh_testkit::
//! enroll_relay`'s return tuple's third element already is (mirroring the DB
//! row id type), cast up to the proto's `uint64` inside the helper — exactly
//! like `tests/sync_relays.rs` casts `relay_id as u64` when comparing against
//! `RelayInfo.relay_id`. This file does NOT modify the testkit; it only
//! calls the method under this assumed signature, so the crate will fail to
//! compile until the implementer adds it (part of why this suite is RED).
//!
//! This file is controller-only (per Task 6 scope): no gateway-side relay
//! transport or health REPORTING logic is exercised — a `StubGateway`
//! supplies `relay_health` directly, standing in for what Task 7/8's real
//! gateway will compute from its own QUIC-ping health.
use std::collections::HashSet;
use std::time::Duration;

use tokio_stream::StreamExt;
use wiremesh_proto::v1::{sync_message, RelayInfo, StateSnapshot};

/// Bounds the wait for a snapshot/delta, mirroring `sync_relays.rs`/
/// `sync_delta.rs`'s timeouts — a controller that never emits what's
/// expected is a real regression and should fail this test fast instead of
/// hanging the whole suite.
const SYNC_TIMEOUT: Duration = Duration::from_secs(5);

/// Pulls a `StateSnapshot` out of the first message of a freshly opened
/// `Sync.Watch` stream — same small per-file helper `tests/sync_relays.rs`/
/// `tests/report_local_endpoints.rs` each duplicate (each `tests/*.rs` file
/// is its own binary, so this is the established convention rather than a
/// shared crate dependency).
fn expect_snapshot(msg: Option<Result<wiremesh_proto::v1::SyncMessage, tonic::Status>>) -> StateSnapshot {
    let msg = msg
        .expect("Sync.Watch stream ended before delivering a message")
        .expect("Sync.Watch stream yielded an error instead of a message");
    match msg.body {
        Some(sync_message::Body::Snapshot(s)) => s,
        other => panic!("expected the first Sync.Watch message to be a StateSnapshot, got: {other:?}"),
    }
}

/// The set of relay ids advertised in a `relays: &[RelayInfo]` slice —
/// order-independent, since neither `StateSnapshot.relays` nor
/// `Delta.relays`'s ordering is part of the contract under test here (only
/// membership and count are).
fn relay_id_set(relays: &[RelayInfo]) -> HashSet<u64> {
    relays.iter().map(|r| r.relay_id).collect()
}

fn find_relay(relays: &[RelayInfo], id: u64) -> Option<&RelayInfo> {
    relays.iter().find(|r| r.relay_id == id)
}

/// A relay reported unhealthy by the only gateway that has reported on it at
/// all must be evicted: its status flips to `inactive`, it disappears from
/// every subsequent advertisement, and the already-connected gateway that
/// filed the report receives a live `RelaysChanged` delta carrying the
/// reduced active-relay set. Uses TWO relays (R1, R2) so the eviction delta
/// is non-empty (per the design notes' "empty-clears" carry: evicting the
/// LAST relay would yield an empty `Delta.relays` that the gateway's
/// `apply_delta` currently ignores — not exercised here, that's a documented
/// carry, not this test's concern).
#[tokio::test]
async fn reported_unhealthy_relay_is_evicted_from_advertisement() {
    let h = wiremesh_testkit::TestController::start().await;

    let (_cert1, _ca1, r1_id) = wiremesh_testkit::enroll_relay(&h, "203.0.113.10:51820").await;
    let (_cert2, _ca2, r2_id) = wiremesh_testkit::enroll_relay(&h, "203.0.113.20:51820").await;
    assert!(r1_id > 0 && r2_id > 0 && r1_id != r2_id);
    let r1 = r1_id as u64;
    let r2 = r2_id as u64;

    let gw = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    let mut stream = gw.open_sync().await;

    let snap = expect_snapshot(stream.next().await);
    assert_eq!(
        relay_id_set(&snap.relays),
        HashSet::from([r1, r2]),
        "before any health report, the initial snapshot must advertise both enrolled relays, got: {:?}",
        snap.relays
    );

    // Mark R1 unhealthy. This is the ONLY report on record for R1, so per
    // the aggregation rule it must flip the aggregate (and thus the DB
    // status) to unhealthy/inactive.
    gw.report_with_relay_health(0, &[], &[(r1_id, false)])
        .await
        .expect("Sync.Report with relay_health marking R1 unhealthy");

    // (a) The already-connected gateway's still-open stream must receive a
    // live RelaysChanged delta reflecting the eviction.
    let msg = tokio::time::timeout(SYNC_TIMEOUT, stream.next())
        .await
        .expect("timed out waiting for the delta triggered by R1's unhealthy report")
        .expect("Sync.Watch stream ended before delivering the delta")
        .expect("Sync.Watch stream yielded an error instead of the delta");
    let delta = match msg.body {
        Some(sync_message::Body::Delta(d)) => d,
        other => panic!("expected a Delta after reporting R1 unhealthy, got: {other:?}"),
    };
    assert!(
        delta.revision > snap.revision,
        "delta revision ({}) must be strictly newer than the initial snapshot's revision ({})",
        delta.revision,
        snap.revision
    );
    assert_eq!(
        delta.relays.len(),
        1,
        "expected exactly one relay (R2) left advertised after evicting R1, got: {:?}",
        delta.relays
    );
    assert!(
        find_relay(&delta.relays, r2).is_some(),
        "the eviction delta must still carry R2, got: {:?}",
        delta.relays
    );
    assert!(
        find_relay(&delta.relays, r1).is_none(),
        "the eviction delta must NOT carry R1 (it was just reported unhealthy), got: {:?}",
        delta.relays
    );

    // (b) A freshly-opened second gateway's snapshot must advertise only R2.
    let gw2 = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;
    let mut stream2 = gw2.open_sync().await;
    let snap2 = expect_snapshot(stream2.next().await);
    assert_eq!(
        relay_id_set(&snap2.relays),
        HashSet::from([r2]),
        "a fresh snapshot taken after R1's eviction must advertise only R2, got: {:?}",
        snap2.relays
    );
}

/// After a relay has been evicted for being unhealthy, a gateway reporting
/// it healthy again must re-admit it: the aggregate (and DB status) flips
/// back to active, a live delta re-adds it to an already-connected
/// gateway's stream, and a fresh snapshot lists it again alongside the
/// never-evicted R2.
#[tokio::test]
async fn readmitted_relay_reappears_when_reported_healthy() {
    let h = wiremesh_testkit::TestController::start().await;

    let (_cert1, _ca1, r1_id) = wiremesh_testkit::enroll_relay(&h, "203.0.113.30:51820").await;
    let (_cert2, _ca2, r2_id) = wiremesh_testkit::enroll_relay(&h, "203.0.113.40:51820").await;
    let r1 = r1_id as u64;
    let r2 = r2_id as u64;

    let gw = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    let mut stream = gw.open_sync().await;
    let snap = expect_snapshot(stream.next().await);
    assert_eq!(relay_id_set(&snap.relays), HashSet::from([r1, r2]));

    // Evict R1 first (same mechanism as the eviction test above), consuming
    // the resulting delta so the stream is positioned for the re-admission
    // delta that follows.
    gw.report_with_relay_health(0, &[], &[(r1_id, false)])
        .await
        .expect("Sync.Report marking R1 unhealthy");
    let evict_msg = tokio::time::timeout(SYNC_TIMEOUT, stream.next())
        .await
        .expect("timed out waiting for the eviction delta")
        .expect("Sync.Watch stream ended before delivering the eviction delta")
        .expect("Sync.Watch stream yielded an error instead of the eviction delta");
    let evict_delta = match evict_msg.body {
        Some(sync_message::Body::Delta(d)) => d,
        other => panic!("expected an eviction Delta, got: {other:?}"),
    };
    assert_eq!(
        relay_id_set(&evict_delta.relays),
        HashSet::from([r2]),
        "precondition: R1 must be evicted (only R2 advertised) before testing re-admission, got: {:?}",
        evict_delta.relays
    );
    let evict_rev = evict_delta.revision;

    // Now report R1 healthy again — this must flip the aggregate (and DB
    // status) back to active and re-advertise it.
    gw.report_with_relay_health(1, &[], &[(r1_id, true)])
        .await
        .expect("Sync.Report marking R1 healthy again");

    let msg = tokio::time::timeout(SYNC_TIMEOUT, stream.next())
        .await
        .expect("timed out waiting for the re-admission delta triggered by R1's healthy report")
        .expect("Sync.Watch stream ended before delivering the re-admission delta")
        .expect("Sync.Watch stream yielded an error instead of the re-admission delta");
    let delta = match msg.body {
        Some(sync_message::Body::Delta(d)) => d,
        other => panic!("expected a Delta after reporting R1 healthy again, got: {other:?}"),
    };
    assert!(
        delta.revision > evict_rev,
        "re-admission delta revision ({}) must be strictly newer than the eviction delta's revision ({})",
        delta.revision,
        evict_rev
    );
    assert_eq!(
        relay_id_set(&delta.relays),
        HashSet::from([r1, r2]),
        "the re-admission delta must carry BOTH relays (R1 back, R2 still present), got: {:?}",
        delta.relays
    );

    // A fresh snapshot must also list both again.
    let gw2 = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;
    let mut stream2 = gw2.open_sync().await;
    let snap2 = expect_snapshot(stream2.next().await);
    assert_eq!(
        relay_id_set(&snap2.relays),
        HashSet::from([r1, r2]),
        "a fresh snapshot taken after R1's re-admission must advertise both relays again, got: {:?}",
        snap2.relays
    );
}

/// Healthy-override: if TWO gateways report on the same relay and they
/// disagree, a single unhealthy view must NOT evict a relay that another
/// gateway currently vouches for as healthy. Connects two stub gateways
/// (gwA, gwB) — the harness supports this already (`tests/sync_delta.rs`/
/// `tests/report_local_endpoints.rs` both enroll two gateways via
/// `enroll_one` in the same test), so this is the preferred two-gateway
/// variant rather than a same-gateway flip-flop.
#[tokio::test]
async fn one_gateway_unhealthy_does_not_evict_a_relay_another_vouches_for() {
    let h = wiremesh_testkit::TestController::start().await;

    let (_cert1, _ca1, r1_id) = wiremesh_testkit::enroll_relay(&h, "203.0.113.50:51820").await;
    let r1 = r1_id as u64;

    let gw_a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    let gw_b = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;

    // gwB vouches for R1 as healthy first...
    gw_b
        .report_with_relay_health(0, &[], &[(r1_id, true)])
        .await
        .expect("Sync.Report: gwB marks R1 healthy");
    // ...then gwA reports R1 unhealthy. Per the healthy-override rule, the
    // aggregate must stay HEALTHY (gwB's vote still stands), so R1 must
    // remain active/advertised.
    gw_a
        .report_with_relay_health(0, &[], &[(r1_id, false)])
        .await
        .expect("Sync.Report: gwA marks R1 unhealthy");

    // A fresh gateway's snapshot is the ground truth for "currently
    // advertised" — R1 must still be there.
    let gw_c = wiremesh_testkit::enroll_one(&h, "azure", "10.2.0.0/16").await;
    let mut stream_c = gw_c.open_sync().await;
    let snap = expect_snapshot(stream_c.next().await);
    assert!(
        find_relay(&snap.relays, r1).is_some(),
        "R1 must still be advertised after only ONE of two reporting gateways calls it \
         unhealthy (the other vouches for it as healthy), got: {:?}",
        snap.relays
    );

    // Cross-check directly against the DB row's status (independent of the
    // Sync projection), mirroring the raw-`rusqlite`-query convention
    // `tests/sync_relays.rs::relay_enrollment_rejects_malformed_endpoint`
    // already uses in this crate's test suite.
    let db_path = h.data_dir().join("controller.db");
    let status = tokio::task::spawn_blocking(move || {
        let conn = rusqlite::Connection::open(&db_path)
            .expect("opening controller.db for relay-status inspection");
        conn.query_row(
            "SELECT status FROM relay WHERE id = ?1",
            [r1_id],
            |row| row.get::<_, String>(0),
        )
        .expect("querying R1's relay.status")
    })
    .await
    .expect("blocking relay-status task panicked");
    assert_eq!(
        status, "active",
        "R1's DB row must stay status='active' when a healthy vote from another gateway \
         is still on record"
    );
}
