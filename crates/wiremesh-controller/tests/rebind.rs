//! Proves Task 10's rebind-token behavior: a `rebind` token minted against an
//! EXISTING segment's `segment_id` lets a REPLACEMENT gateway enroll with
//! that same segment's CIDRs WITHOUT tripping the CIDR self-overlap check
//! that would reject an ordinary `gateway` token trying to claim CIDRs
//! already owned by a segment — and, on success, the replaced gateway's old
//! cert serial is pushed onto the revoked denylist (visible in a fresh
//! `Sync.Watch` snapshot's `revoked_serials`), so the retired gateway can no
//! longer authenticate.
//!
//! `StubGateway::segment_id()` does not exist yet — it's added by the Task 10
//! implementer alongside the rebind branch in `services::enrollment`/`db`/
//! `services::admin` this test drives. Until then this fails to compile,
//! which is the expected RED state for this step. Once it compiles, the
//! remaining RED is behavioral: the rebind token's enroll being rejected as
//! a CIDR overlap, and/or the old serial being absent from
//! `revoked_serials`.
use tokio_stream::StreamExt;
use wiremesh_proto::v1::{sync_message, MintTokenRequest};

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
