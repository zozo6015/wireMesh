//! Task 16's failing test: `Admin.RevokeCert(serial)` must (1) push the
//! revoked serial into the `revoked_serials` denylist of the next `Delta`
//! delivered to every gateway with an already-open `Sync.Watch` stream, and
//! (2) append an audit-log row with `action == "revoke"` that `Admin.AuditQuery`
//! can retrieve.
//!
//! Boots a real controller, enrolls gateway A ("aws") — which will observe
//! the revocation via its own still-open Sync stream — and a second gateway,
//! "victim" ("gcp"), whose leaf cert serial gets revoked. After consuming A's
//! initial `StateSnapshot`, this calls the (not-yet-existing)
//! `Admin.RevokeCert(RevokeCertRequest{ serial })` for the victim's cert
//! serial and asserts:
//!
//!   1. A's still-open Sync stream receives a `Delta` whose `revoked_serials`
//!      contains the victim's serial (bounded by a timeout so a missing push
//!      fails fast instead of hanging the suite);
//!   2. `Admin.AuditQuery` (filtered to `action == "revoke"`, via an assumed
//!      `AuditQueryRequest.action` field) returns at least one entry whose
//!      `action` is exactly `"revoke"`.
//!
//! None of this exists yet: `RevokeCertRequest`/`RevokeCertResponse` aren't
//! defined on `wiremesh_proto::v1` (only `Admin.Drain` revokes certs today,
//! as a side effect of removing a gateway entirely — there is no standalone
//! "revoke just this cert" RPC), `AdminClient::revoke_cert` doesn't exist,
//! and `AuditQueryRequest` today has only a `limit` field (see
//! `proto/wiremesh/v1/admin.proto`) — no `action` filter. So today this file
//! does not even COMPILE — that's the expected RED state for this step. The
//! implementer adds `RevokeCert`/`RevokeCertRequest` to `admin.proto`, an
//! `action` filter field on `AuditQueryRequest`, the `src/services/admin.rs`
//! handler (denylist push via `src/projection.rs` + `db.audit(..., "revoke", ...)`),
//! and the `fabricctl audit export` surface, to turn this green.
use std::time::Duration;

use tokio_stream::StreamExt;
use wiremesh_proto::v1::{sync_message, AuditQueryRequest, RevokeCertRequest};

#[tokio::test]
async fn revoke_pushes_serial_to_connected_gateways_and_audits() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    let victim = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;

    let mut a_stream = a.open_sync().await;
    let snap_msg = a_stream
        .next()
        .await
        .expect("Sync.Watch stream ended before delivering A's initial snapshot")
        .expect("Sync.Watch stream yielded an error instead of A's initial snapshot");
    match snap_msg.body {
        Some(sync_message::Body::Snapshot(_)) => {}
        other => panic!("expected the first Sync.Watch message to be a StateSnapshot, got: {other:?}"),
    }

    let victim_serial = victim
        .cert_serial()
        .expect("reading the victim gateway's leaf cert serial");

    h.admin_client()
        .await
        .revoke_cert(RevokeCertRequest {
            serial: victim_serial.clone(),
        })
        .await
        .expect("Admin.RevokeCert(serial = victim's cert serial) must succeed");

    // A must see a Delta carrying the revoked serial in its denylist,
    // bounded by a timeout so a missing push fails fast instead of hanging
    // the suite.
    let msg = tokio::time::timeout(Duration::from_secs(5), a_stream.next())
        .await
        .expect("timed out waiting for the delta triggered by Admin.RevokeCert")
        .expect("Sync.Watch stream ended before delivering the revocation delta")
        .expect("Sync.Watch stream yielded an error instead of the revocation delta");

    let delta = match msg.body {
        Some(sync_message::Body::Delta(d)) => d,
        other => panic!("expected a Delta after Admin.RevokeCert, got: {other:?}"),
    };

    assert!(
        delta.revoked_serials.contains(&victim_serial),
        "expected the revocation delta's revoked_serials to contain the victim's \
         cert serial ({victim_serial}), got: {:?}",
        delta.revoked_serials
    );

    // The revocation must also be audited: Admin.AuditQuery filtered to
    // action == "revoke" must return at least one matching row.
    let audit = h
        .admin_client()
        .await
        .audit_query(AuditQueryRequest {
            action: "revoke".into(),
            limit: 0,
        })
        .await
        .expect("Admin.AuditQuery(action = \"revoke\") must succeed")
        .into_inner();

    assert!(
        audit.entries.iter().any(|e| e.action == "revoke"),
        "expected at least one audit entry with action == \"revoke\" after \
         Admin.RevokeCert, got entries: {:?}",
        audit.entries
    );
}
