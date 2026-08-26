//! Boots a real controller (via `wiremesh-testkit`), mints a single-use
//! `gateway` enrollment token over the Admin UDS, then exercises the
//! Enrollment RPC over the controller's TCP port (server-TLS, no client
//! cert): a CSR presented with that token must come back with a signed leaf
//! cert + CA bundle, and a *second* enroll attempt with the same (now spent)
//! token must be rejected as `PermissionDenied` — the token is single-use.
use wiremesh_proto::v1::{CreateSegmentRequest, EnrollRequest, MintTokenRequest};

#[tokio::test]
async fn enroll_issues_cert_then_token_is_single_use() {
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

    let (csr, _kp) = wiremesh_testkit::gen_csr("gw-aws");
    let mut enr = h.enrollment_client().await;

    let resp = enr
        .enroll(EnrollRequest {
            token: tok.clone(),
            csr_pem: csr.clone(),
            cidrs: vec!["10.0.0.0/16".into()],
            wg_pubkey: String::new(),
            endpoint: String::new(),
            client_version: String::new(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(
        resp.cert_pem.contains("BEGIN CERTIFICATE"),
        "cert_pem must be a PEM certificate, got: {}",
        resp.cert_pem
    );
    assert!(
        resp.ca_bundle_pem.contains("BEGIN CERTIFICATE"),
        "ca_bundle_pem must be a PEM certificate, got: {}",
        resp.ca_bundle_pem
    );

    // Token is now spent — a second enroll with the same token must be
    // rejected, exactly as PermissionDenied (single-use enforcement).
    let err = enr
        .enroll(EnrollRequest {
            token: tok,
            csr_pem: csr,
            cidrs: vec!["10.0.0.0/16".into()],
            wg_pubkey: String::new(),
            endpoint: String::new(),
            client_version: String::new(),
        })
        .await
        .unwrap_err();
    assert_eq!(
        err.code(),
        tonic::Code::PermissionDenied,
        "reusing a spent enrollment token must fail with PermissionDenied, got: {:?}",
        err
    );
}

/// Authorization scope: a token minted bound to segment "aws" (10.0.0.0/16)
/// must NOT be redeemable into segment "gcp" (10.1.0.0/16) by declaring gcp's
/// CIDRs at enroll time. The controller must enforce the token's minted
/// `bound_cidrs` against the CIDRs the gateway declares — otherwise a token
/// scoped to one segment is a bearer credential for every segment.
#[tokio::test]
async fn token_bound_to_one_segment_cannot_enroll_into_another() {
    let h = wiremesh_testkit::TestController::start().await;
    let mut admin = h.admin_client().await;

    admin
        .create_segment(CreateSegmentRequest {
            name: "aws".into(),
            cidrs: vec!["10.0.0.0/16".into()],
        })
        .await
        .unwrap();
    admin
        .create_segment(CreateSegmentRequest {
            name: "gcp".into(),
            cidrs: vec!["10.1.0.0/16".into()],
        })
        .await
        .unwrap();

    // Token is minted bound to the aws segment's CIDR only.
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

    let (csr, _kp) = wiremesh_testkit::gen_csr("gw-x");
    let mut enr = h.enrollment_client().await;

    // Redeeming the aws-bound token while declaring the gcp segment's CIDR
    // must be refused: the declared CIDRs fall outside the token's bound set.
    let err = enr
        .enroll(EnrollRequest {
            token: tok,
            csr_pem: csr,
            cidrs: vec!["10.1.0.0/16".into()],
            wg_pubkey: String::new(),
            endpoint: String::new(),
            client_version: String::new(),
        })
        .await
        .unwrap_err();
    let code = err.code();
    assert!(
        code == tonic::Code::PermissionDenied || code == tonic::Code::FailedPrecondition,
        "enrolling a token outside its bound_cidrs must be refused with \
         PermissionDenied or FailedPrecondition, got: {:?} ({:?})",
        code,
        err
    );
}
