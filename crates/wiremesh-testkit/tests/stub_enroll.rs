//! Task 6 (RED): drives `StubGateway::enroll` — the not-yet-implemented
//! testkit helper that wraps a full CSR-generate + `Enrollment.Enroll` round
//! trip behind a single call, mirroring what a real gateway does at
//! bootstrap. This is intentionally a thin end-to-end assertion (cert +
//! CA bundle come back as PEM certificates); the token-scoping and
//! single-use semantics it rides on top of are already covered by
//! `wiremesh-controller/tests/enroll.rs`.
use wiremesh_proto::v1::{CreateSegmentRequest, MintTokenRequest};

#[tokio::test]
async fn stub_gateway_enrolls_and_holds_a_cert() {
    let h = wiremesh_testkit::TestController::start().await;
    let mut admin = h.admin_client().await;

    admin
        .create_segment(CreateSegmentRequest {
            name: "aws".into(),
            cidrs: vec!["10.0.0.0/16".into()],
        })
        .await
        .unwrap();

    let tok = admin
        .mint_token(MintTokenRequest {
            kind: "gateway".into(),
            bound_cidrs: vec!["10.0.0.0/16".into()],
            rebind_segment_id: 0,
        })
        .await
        .unwrap()
        .into_inner()
        .token;

    let gw = wiremesh_testkit::StubGateway::enroll(&h, &tok, &["10.0.0.0/16"])
        .await
        .unwrap();

    assert!(
        gw.cert_pem().contains("BEGIN CERTIFICATE"),
        "cert_pem must be a PEM certificate, got: {}",
        gw.cert_pem()
    );
    assert!(
        gw.ca_bundle_pem().contains("BEGIN CERTIFICATE"),
        "ca_bundle_pem must be a PEM certificate, got: {}",
        gw.ca_bundle_pem()
    );
}
