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
