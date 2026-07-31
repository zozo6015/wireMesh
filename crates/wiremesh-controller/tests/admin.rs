//! Spins the Admin service on a Unix socket in a tempdir (via the
//! `wiremesh-testkit` harness) and connects a real `tonic` gRPC client over
//! that UDS to exercise `CreateSegment` and `MintToken` end-to-end.
use wiremesh_proto::v1::{CreateSegmentRequest, MintTokenRequest};

#[tokio::test]
async fn create_segment_and_mint_token_over_uds() {
    let h = wiremesh_testkit::TestController::start().await;
    let mut admin = h.admin_client().await;

    let seg = admin
        .create_segment(CreateSegmentRequest {
            name: "aws".into(),
            cidrs: vec!["10.0.0.0/16".into()],
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(seg.name, "aws");

    let tok = admin
        .mint_token(MintTokenRequest {
            kind: "gateway".into(),
            bound_cidrs: vec!["10.0.0.0/16".into()],
            rebind_segment_id: 0,
        })
        .await
        .unwrap()
        .into_inner();
    assert!(
        tok.token.starts_with("wiremesh://"),
        "token must start with wiremesh://, got: {}",
        tok.token
    );
    assert!(
        tok.token.contains("@sha256:"),
        "token must embed the CA root fingerprint as @sha256:<fp>, got: {}",
        tok.token
    );
}

/// Backlog 10 PR-A Item 2b (was RED when written; GREEN since the fix):
/// `CreateSegment` with an EMPTY `cidrs` list used to succeed —
/// `services/admin.rs`'s handler checked only that `name` was non-empty and
/// that each PRESENT cidr parsed; a zero-length list vacuously passed both
/// and stored a segment no policy can meaningfully reference (compiling
/// against it yielded an IR block whose side matches nothing — Item 2a's
/// bug — and enrollment against it has no CIDRs to bind). The enrollment
/// path already rejected exactly this at its own boundary
/// (`enrollment.rs`: "cidrs must not be empty"); `CreateSegment` now does
/// the same: `invalid_argument`, naming the empty cidrs list. (The `Apply`
/// fabric path and the `insert_segment_tx` db layer carry the same guard.)
#[tokio::test]
async fn create_segment_with_empty_cidrs_is_invalid_argument() {
    let h = wiremesh_testkit::TestController::start().await;
    let mut admin = h.admin_client().await;

    let status = admin
        .create_segment(CreateSegmentRequest {
            name: "no-cidrs".into(),
            cidrs: vec![],
        })
        .await
        .err()
        .expect(
            "CreateSegment with an empty cidrs list must be rejected with \
             invalid_argument, not stored as a zero-CIDR segment",
        );

    assert_eq!(
        status.code(),
        tonic::Code::InvalidArgument,
        "empty cidrs is a bad request (mirror enrollment.rs's own \
         empty-cidrs guard), got {:?}: {}",
        status.code(),
        status.message()
    );
    assert!(
        status.message().to_lowercase().contains("cidr"),
        "the error must name the empty cidrs list, got: {}",
        status.message()
    );
}
