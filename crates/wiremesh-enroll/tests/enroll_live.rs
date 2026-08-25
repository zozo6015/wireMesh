//! Live integration test: enroll against a real (in-process) controller and
//! assert the returned identity material is a genuine signed leaf.

use wiremesh_proto::v1::{CreateSegmentRequest, MintTokenRequest};

#[tokio::test]
async fn enroll_redeems_token_and_returns_signed_leaf() {
    let h = wiremesh_testkit::TestController::start().await;
    let mut admin = h.admin_client().await;

    // A segment must exist so the bound CIDR resolves at mint/enroll time.
    admin
        .create_segment(CreateSegmentRequest {
            name: "aws".into(),
            cidrs: vec!["10.0.0.0/16".into()],
        })
        .await
        .unwrap();

    let cidrs = vec!["10.0.0.0/16".to_string()];
    let token = admin
        .mint_token(MintTokenRequest {
            kind: "gateway".into(),
            bound_cidrs: cidrs.clone(),
            rebind_segment_id: 0,
        })
        .await
        .unwrap()
        .into_inner()
        .token;

    let out = wiremesh_enroll::enroll(
        &h.tcp_addr().to_string(),
        h.ca_bundle_pem(),
        &token,
        &cidrs,
        "", // gateway wg_pubkey — empty is accepted (matches controller enroll test)
        "",
        "gateway",
    )
    .await
    .expect("enrollment should succeed against a live controller");

    assert!(
        out.cert_pem.contains("BEGIN CERTIFICATE"),
        "cert_pem must be a signed PEM leaf, got: {}",
        out.cert_pem
    );
    assert!(
        out.ca_bundle_pem.contains("BEGIN CERTIFICATE"),
        "ca_bundle_pem must be a PEM certificate, got: {}",
        out.ca_bundle_pem
    );
    assert!(out.gateway_id > 0, "controller must assign a gateway_id");
    assert!(
        !out.observe_key.is_empty(),
        "controller must return an observe_key"
    );
    assert!(
        out.key_pem.contains("PRIVATE KEY"),
        "key_pem must be the locally-generated private key"
    );
}
