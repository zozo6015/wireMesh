//! `wiremesh-gateway enroll` writes an `Identity` that the gateway's own boot
//! path (`Identity::load`) can read back.

use wiremesh_gateway::enroll::{run_enroll, EnrollArgs};
use wiremesh_gateway::identity::Identity;
use wiremesh_gateway::uapi::base64_pub_from_priv;
use wiremesh_proto::v1::{CreateSegmentRequest, MintTokenRequest};

#[tokio::test]
async fn enroll_writes_loadable_identity() {
    let h = wiremesh_testkit::TestController::start().await;
    let mut admin = h.admin_client().await;
    admin
        .create_segment(CreateSegmentRequest {
            name: "aws".into(),
            cidrs: vec!["10.0.0.0/16".into()],
        })
        .await
        .unwrap();
    let token = admin
        .mint_token(MintTokenRequest {
            kind: "gateway".into(),
            bound_cidrs: vec!["10.0.0.0/16".into()],
            rebind_segment_id: 0,
        })
        .await
        .unwrap()
        .into_inner()
        .token;

    let dir = tempfile::tempdir().unwrap();
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, h.ca_bundle_pem()).unwrap();
    let state_dir = dir.path().join("state");

    run_enroll(EnrollArgs {
        token,
        controller: h.tcp_addr().to_string(),
        ca_path,
        state_dir: state_dir.clone(),
        cidrs: vec!["10.0.0.0/16".into()],
    })
    .await
    .expect("gateway enroll should succeed against a live controller");

    // The gateway's real boot path must be able to load what enroll wrote.
    let id = Identity::load(&state_dir).expect("Identity::load must read the enrolled identity");
    assert!(id.gateway_id > 0, "controller assigns a gateway_id");
    assert!(id.cert_pem.contains("BEGIN CERTIFICATE"), "leaf cert stored");
    assert!(id.ca_bundle_pem.contains("BEGIN CERTIFICATE"), "CA bundle stored");
    // The stored WG private key must derive to a real public key.
    let pubkey = base64_pub_from_priv(&id.wg_private_key_b64).expect("derive WG pubkey");
    assert!(!pubkey.is_empty(), "WG private key must be valid");
}
