//! (Issue #7) `Sync.Watch`/`Sync.Report`'s identity resolution
//! (`Db::find_gateway_by_name`, driven by the peer certificate's CN — see
//! `services::sync::peer_identity`) must reject a gateway whose row is no
//! longer `status = 'active'`. Before this fix, `find_gateway_by_name` had
//! no status filter at all: a DRAINED gateway (`status = 'removed'`) or a
//! REBIND-REPLACED gateway (`status = 'replaced'`) could still present its
//! still-TLS-valid cert and have its name resolve to a live
//! `GatewayIdentity`, letting it open `Sync.Watch` and pull a full
//! projection snapshot of the fabric it no longer belongs to — a topology
//! disclosure. `rebind.rs`'s own doc comment documented this exact gap as
//! "a replaced gateway could still open a `Sync.Watch` connection this
//! cycle."
//!
//! Both cases below must now be refused (identity resolves to `None` ->
//! `PermissionDenied`), while an ordinary active gateway is unaffected.
use wiremesh_proto::v1::{DrainRequest, MintTokenRequest};

/// A drained gateway's cert is still TLS-valid (drain revokes it in the DB
/// denylist, but cycle-2's Sync mTLS handshake doesn't check
/// `revoked_serials` against the presented client cert — see `rebind.rs`).
/// The identity-resolution status filter is the layer that must stop it:
/// after `Admin.Drain`, the drained gateway's own attempt to (re)open
/// `Sync.Watch` must be rejected.
#[tokio::test]
async fn drained_gateway_can_no_longer_open_sync_watch() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;

    h.admin_client()
        .await
        .drain(DrainRequest { gateway_id: a.id() })
        .await
        .expect("Admin.Drain(gateway_id = a.id()) must succeed");

    let err = a
        .reconnect(&h)
        .await
        .expect_err(
            "a drained gateway must no longer be able to open Sync.Watch — its identity \
             must no longer resolve on the Sync path",
        );
    let msg = err.to_string();
    assert!(
        msg.contains("PermissionDenied") || msg.contains("permission_denied"),
        "expected a PermissionDenied rejection (identity no longer resolves), got: {msg}"
    );
}

/// A rebind-replaced gateway's OLD cert is likewise still TLS-valid, and its
/// gateway row now has `status = 'replaced'`. Its old identity must no
/// longer resolve on the Sync path either — the replacement gateway is the
/// only one that legitimately represents this segment now.
#[tokio::test]
async fn rebind_replaced_gateway_can_no_longer_open_sync_watch() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    let seg_id = a.segment_id();

    let mut admin = h.admin_client().await;
    let tok = admin
        .mint_token(MintTokenRequest {
            kind: "rebind".into(),
            bound_cidrs: vec![],
            rebind_segment_id: seg_id,
        })
        .await
        .expect("minting a rebind token bound to segment aws")
        .into_inner()
        .token;

    let _b = wiremesh_testkit::StubGateway::enroll(&h, &tok, &["10.0.0.0/16"])
        .await
        .expect("replacement gateway enrolling via rebind token must succeed");

    // A (now `status = 'replaced'`) tries to reconnect with its OLD,
    // still-TLS-valid cert.
    let err = a.reconnect(&h).await.expect_err(
        "a rebind-replaced gateway must no longer be able to open Sync.Watch with its old \
         cert — its identity must no longer resolve on the Sync path",
    );
    let msg = err.to_string();
    assert!(
        msg.contains("PermissionDenied") || msg.contains("permission_denied"),
        "expected a PermissionDenied rejection (identity no longer resolves), got: {msg}"
    );
}

/// Control: an ordinary ACTIVE gateway must be unaffected by the status
/// filter and can still open `Sync.Watch` normally.
#[tokio::test]
async fn active_gateway_can_still_open_sync_watch() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;

    a.reconnect(&h)
        .await
        .expect("an active gateway must still be able to open Sync.Watch");
}
