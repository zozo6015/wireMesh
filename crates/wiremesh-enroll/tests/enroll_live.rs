//! Live integration test: enroll against a real (in-process) controller and
//! assert the returned identity material is a genuine signed leaf.

use wiremesh_proto::v1::{CreateSegmentRequest, ListGatewaysRequest, MintTokenRequest};

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
        "", // client_version (B10) — mechanical signature update, see PR body
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

/// (B10 / X-6) The sentinel round-trip: whatever the CALLER passes as
/// `client_version` is what reaches the controller.
///
/// # Why a sentinel and not a version comparison
///
/// The defect this pins is "`wiremesh-enroll` reads `env!(...)` itself instead
/// of taking the caller's", and **no comparison of version VALUES can detect
/// it**: every crate in this workspace carries `version = "0.1.0"` in git and
/// `scripts/set-version.sh` rewrites them only transiently inside a release
/// job, so this crate's version and the gateway's are the SAME STRING in every
/// local and CI run. "Equals the caller's version" would pass on the buggy
/// code; "is never 0.1.0" would fail on the correct code. A value no crate
/// could carry sidesteps both.
///
/// Read back through `Admin.ListGateways` rather than the DB: this crate has
/// no `rusqlite`, and the sentinel is non-empty so the NULL-versus-empty
/// distinction that forces a raw read elsewhere does not arise here. The raw
/// column IS asserted, for the legacy case, in
/// `wiremesh-controller/tests/b10_version_fields.rs`.
///
/// The complementary guard — that this crate never names `CARGO_PKG_VERSION`
/// at all — lives in `wiremesh-operator/tests/release_version_stamping.rs`.
/// Neither substitutes for the other: this proves the parameter is threaded,
/// that proves the macro has not crept back in beside it.
#[tokio::test]
async fn a_caller_supplied_client_version_reaches_the_controller() {
    /// Deliberately not a version any crate could hold, so it cannot be
    /// confused with a real `CARGO_PKG_VERSION` in any build.
    const SENTINEL: &str = "9.9.9-test-sentinel";

    let h = wiremesh_testkit::TestController::start().await;
    let mut admin = h.admin_client().await;
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
        "",
        "",
        "gateway",
        SENTINEL,
    )
    .await
    .expect("enrollment should succeed against a live controller");

    let listed = admin
        .list_gateways(ListGatewaysRequest {})
        .await
        .expect("Admin.ListGateways")
        .into_inner()
        .gateways;
    let me = listed
        .iter()
        .find(|g| g.id == out.gateway_id)
        .expect("the gateway just enrolled must appear in the roster");

    assert_eq!(
        me.version, SENTINEL,
        "the caller's `client_version` did not reach the controller. Either the parameter is \
         not threaded into the `EnrollRequest`, or the enrollment handler is not storing it. \
         The SENTINEL is what makes this test meaningful: a version comparison could not \
         tell a caller-supplied value from one this crate read out of its own \
         `env!(\"CARGO_PKG_VERSION\")`, because every crate here is `0.1.0` in git and only \
         a release job rewrites that"
    );
}
