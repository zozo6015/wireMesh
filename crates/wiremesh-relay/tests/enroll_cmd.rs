//! `wiremesh-relay-enroll` writes a `ca.pem`/`relay.pem`/`relay.key` identity,
//! each mode 0600, that the relay server loads from its certdir.

use std::os::unix::fs::PermissionsExt;
use wiremesh_proto::v1::MintTokenRequest;
use wiremesh_relay::enroll::{run_enroll, EnrollArgs};

#[tokio::test]
async fn enroll_writes_relay_identity_0600() {
    let h = wiremesh_testkit::TestController::start().await;
    let mut admin = h.admin_client().await;
    let token = admin
        .mint_token(MintTokenRequest {
            kind: "relay".into(),
            bound_cidrs: vec![],
            rebind_segment_id: 0,
        })
        .await
        .unwrap()
        .into_inner()
        .token;

    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("controller-ca.pem");
    std::fs::write(&ca_path, h.ca_bundle_pem()).unwrap();
    let certdir = dir.path().join("relay-id");

    run_enroll(EnrollArgs {
        token,
        controller: h.tcp_addr().to_string(),
        ca_path,
        certdir: certdir.clone(),
        endpoint: "203.0.113.10:51820".into(),
    })
    .await
    .expect("relay enroll should succeed against a live controller");

    for name in ["ca.pem", "relay.pem", "relay.key"] {
        let p = certdir.join(name);
        let meta = std::fs::metadata(&p).unwrap_or_else(|_| panic!("{name} must exist"));
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o600,
            "{name} must be mode 0600"
        );
    }
    let relay_pem = std::fs::read_to_string(certdir.join("relay.pem")).unwrap();
    assert!(
        relay_pem.contains("BEGIN CERTIFICATE"),
        "relay.pem must be a signed leaf certificate"
    );
}
