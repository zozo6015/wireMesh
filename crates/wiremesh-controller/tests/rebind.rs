//! Proves Task 10's rebind-token behavior: a `rebind` token minted against an
//! EXISTING segment's `segment_id` lets a REPLACEMENT gateway enroll with
//! that same segment's CIDRs WITHOUT tripping the CIDR self-overlap check
//! that would reject an ordinary `gateway` token trying to claim CIDRs
//! already owned by a segment — and, on success, the replaced gateway's old
//! cert serial is pushed onto the revoked denylist: it's marked
//! `revoked_at` in the DB and appears in a fresh `Sync.Watch` snapshot's
//! `revoked_serials`. That denylist bookkeeping is what THIS test proves.
//!
//! (Issue #7, fixed) It USED TO be true that this denylist bookkeeping was
//! all that stood between a replaced gateway and the fabric: its cert is
//! still TLS-valid, and cycle-2's Sync mTLS handshake still doesn't check
//! `revoked_serials` against the presented client cert (a documented
//! cycle-4 gap — see `docs/research/cycle2-controller-notes.md`). But
//! `Db::find_gateway_by_name` — the identity-resolution step `Sync.Watch`/
//! `Sync.Report` run AFTER the TLS handshake succeeds — now filters to
//! `status = 'active'`, so a replaced gateway's old cert, even though still
//! TLS-valid, no longer resolves to a live identity and can no longer open
//! `Sync.Watch` at all. See `sync_identity_active_only.rs` for that
//! coverage.
use tokio_stream::StreamExt;
use wiremesh_proto::v1::{
    sync_message, CreateSegmentRequest, EnrollRequest, MintTokenRequest,
};

#[tokio::test]
async fn rebind_replaces_gateway_without_overlap_and_revokes_old_cert() {
    let h = wiremesh_testkit::TestController::start().await;

    // Original gateway for segment "aws".
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    let old_serial = a
        .cert_serial()
        .expect("parsing original gateway's cert serial");
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

    // Replacement gateway enrolls declaring the SAME CIDRs segment aws
    // already owns. An ordinary `gateway` token would be rejected here as a
    // self-overlap (the CIDR already belongs to an existing segment) — a
    // `rebind` token bound to that same segment must be exempted from that
    // check and succeed.
    let b = wiremesh_testkit::StubGateway::enroll(&h, &tok, &["10.0.0.0/16"])
        .await
        .expect(
            "replacement gateway enrolling with a rebind token on its own segment's \
             CIDRs must NOT be rejected as a CIDR overlap",
        );

    let new_serial = b
        .cert_serial()
        .expect("parsing replacement gateway's cert serial");
    assert_ne!(
        new_serial, old_serial,
        "the replacement gateway must receive a freshly issued cert, distinct from the \
         original gateway's serial"
    );

    // The original gateway's cert must now be revoked: a fresh Sync
    // snapshot's denylist must contain its old serial.
    let mut s = b.open_sync().await;
    let msg = s
        .next()
        .await
        .expect("Sync.Watch stream ended before delivering a message")
        .expect("Sync.Watch stream yielded an error instead of a message");
    let snap = match msg.body {
        Some(sync_message::Body::Snapshot(snap)) => snap,
        other => panic!("expected the first Sync.Watch message to be a StateSnapshot, got: {other:?}"),
    };

    assert!(
        snap.revoked_serials.contains(&old_serial),
        "rebinding must revoke the replaced gateway's old cert serial ({old_serial}); \
         revoked_serials was: {:?}",
        snap.revoked_serials
    );
}

/// Occupancy invariant (regression guard): a segment must have exactly ONE
/// active gateway at a time. Once a gateway is enrolled for segment "aws",
/// a SECOND ordinary `gateway` token — even one correctly bound to aws's own
/// CIDR — must be refused with `AlreadyExists` (the SegmentAlreadyBound
/// occupancy guard). The sanctioned way to swap the gateway is a `rebind`
/// token (exercised above), not a second gateway token. This behavior is
/// already implemented; the test is a committed regression guard, expected
/// GREEN.
#[tokio::test]
async fn second_gateway_token_rejected_on_occupied_segment() {
    let h = wiremesh_testkit::TestController::start().await;

    // Segment aws now has an active gateway.
    let _a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;

    let mut admin = h.admin_client().await;
    let tok = admin
        .mint_token(MintTokenRequest {
            kind: "gateway".into(),
            bound_cidrs: vec!["10.0.0.0/16".into()],
            rebind_segment_id: 0,
        })
        .await
        .expect("minting a second gateway token bound to aws's CIDR")
        .into_inner()
        .token;

    // Raw enrollment client (not StubGateway::enroll) so we can assert the
    // precise tonic status code the occupancy guard returns.
    let (csr, _kp) = wiremesh_testkit::gen_csr("gw-aws-2");
    let mut enr = h.enrollment_client().await;
    let err = enr
        .enroll(EnrollRequest {
            token: tok,
            csr_pem: csr,
            cidrs: vec!["10.0.0.0/16".into()],
            wg_pubkey: String::new(),
            endpoint: String::new(),
        })
        .await
        .expect_err(
            "a second gateway token on an already-occupied segment must be refused, \
             not enrolled",
        );
    assert_eq!(
        err.code(),
        tonic::Code::AlreadyExists,
        "enrolling a second gateway into an occupied segment must fail with \
         AlreadyExists (SegmentAlreadyBound), got: {err:?}"
    );
}

/// Rebind scope invariant (regression guard): a `rebind` token is bound to
/// exactly ONE segment (its `rebind_segment_id`) and must not be usable to
/// grab a DIFFERENT segment's CIDRs. A rebind token minted for aws, redeemed
/// while declaring gcp's CIDR, must be refused with `PermissionDenied` —
/// otherwise a rebind token would be a bearer credential for every segment.
/// Already-implemented behavior; committed regression guard, expected GREEN.
#[tokio::test]
async fn rebind_token_for_one_segment_refused_against_another() {
    let h = wiremesh_testkit::TestController::start().await;

    // Segment aws (with a gateway) and a separate, unrelated segment gcp.
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    let aws_seg_id = a.segment_id();

    let mut admin = h.admin_client().await;
    admin
        .create_segment(CreateSegmentRequest {
            name: "gcp".into(),
            cidrs: vec!["10.1.0.0/16".into()],
        })
        .await
        .expect("creating segment gcp");

    // Rebind token scoped to aws.
    let tok = admin
        .mint_token(MintTokenRequest {
            kind: "rebind".into(),
            bound_cidrs: vec![],
            rebind_segment_id: aws_seg_id,
        })
        .await
        .expect("minting a rebind token bound to segment aws")
        .into_inner()
        .token;

    // Try to redeem the aws-rebind token while declaring gcp's CIDR — the
    // rebind's segment scope must refuse it.
    let (csr, _kp) = wiremesh_testkit::gen_csr("gw-gcp");
    let mut enr = h.enrollment_client().await;
    let err = enr
        .enroll(EnrollRequest {
            token: tok,
            csr_pem: csr,
            cidrs: vec!["10.1.0.0/16".into()],
            wg_pubkey: String::new(),
            endpoint: String::new(),
        })
        .await
        .expect_err(
            "a rebind token scoped to aws must not be redeemable into gcp by declaring \
             gcp's CIDRs",
        );
    assert_eq!(
        err.code(),
        tonic::Code::PermissionDenied,
        "redeeming an aws-scoped rebind token against gcp's CIDRs must fail with \
         PermissionDenied, got: {err:?}"
    );
}
