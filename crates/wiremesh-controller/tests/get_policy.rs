//! Task 6 (cycle 3): tests for the `Admin.GetPolicy` RPC —
//! `.superpowers/sdd/task-6-brief.md`. Placed in its own file rather than
//! folded into `tests/policy_pipeline.rs` (already 1000+ lines covering the
//! compile/CIDR-diffing pipeline behind `Apply`) because `GetPolicy` is a
//! distinct read-only RPC surface, not another `Apply` behavior — matching
//! how every other single-RPC-ish concern in this crate already gets its
//! own file (`admin_auth.rs`, `drain.rs`, `keys.rs`, `revoke_audit.rs`,
//! `sync_delta.rs`, `sync_snapshot.rs`).
//!
//! `AdminSvc::get_policy` is implemented: `version: 0` resolves to the
//! latest compiled policy, an explicit version looks that version up
//! exactly, and an unknown version fails `NotFound`. `GetPolicy` is also in
//! `wiremesh_controller::auth::READONLY_METHODS`, so a `read-only` bearer
//! token can call it like any other read. The tests below verify all three:
//! latest-version lookup with a parseable IR, `NotFound` on an unknown
//! version, and the read-only auth tier.
use wiremesh_policy::PolicyIR;
use wiremesh_proto::v1::GetPolicyRequest;
use wiremesh_testkit::TestController;

/// Same two-segment-plus-policy fabric as `tests/policy_pipeline.rs`'s
/// `FABRIC_WITH_POLICY` (the master-spec §5.1 worked example), duplicated
/// here rather than shared across test binaries — each `tests/*.rs` file
/// compiles as its own independent binary, so there is no `super`/shared
/// module to pull the original constant from without adding one (out of
/// scope for this tests-only step).
const FABRIC_WITH_POLICY: &str = r#"
segments:
  - name: proxmox-lab
    cidrs: ["10.10.0.0/16"]
  - name: aws-prod
    cidrs: ["172.16.0.0/12"]
policy:
  - from: proxmox-lab
    to: aws-prod
    rules:
      - deny:  { ports: [22], proto: tcp }
      - allow: { dst: 172.16.1.50/32, ports: [5432], proto: tcp }
      - allow: { dst: 172.16.2.0/24, ports: [443, "8000-8080"], proto: tcp }
"#;

/// (1) `GetPolicy{version: 0}` ("0 = latest") after one apply must return
/// the just-compiled version 1: a non-empty `source_yaml`, a `compiled_ir`
/// that `PolicyIR::from_json` actually parses with `version == 1`, and
/// non-empty `created_by`/`created_at` bookkeeping columns.
#[tokio::test]
async fn get_policy_latest_returns_version_1_with_parseable_ir() {
    let h = TestController::start().await;

    let diff = h.apply(FABRIC_WITH_POLICY).await;
    assert!(
        diff.policy_updated,
        "baseline apply must compile a policy, got diff: {:?}",
        diff
    );

    let resp = h
        .admin_client()
        .await
        .get_policy(GetPolicyRequest { version: 0 })
        .await
        .expect("GetPolicy{version: 0} must succeed once a policy has been applied")
        .into_inner();

    assert_eq!(
        resp.version, 1,
        "the first-ever compiled policy must be version 1, got {}",
        resp.version
    );
    assert!(
        !resp.source_yaml.is_empty(),
        "GetPolicy's source_yaml must be non-empty once a real policy has been applied"
    );
    assert!(
        resp.source_yaml.contains("proxmox-lab"),
        "source_yaml must be the actual applied policy source (containing 'proxmox-lab'), got: {}",
        resp.source_yaml
    );

    let ir = PolicyIR::from_json(&resp.compiled_ir)
        .expect("GetPolicy's compiled_ir must parse as a real PolicyIR");
    assert_eq!(
        ir.version, 1,
        "the parsed IR's version must match the returned version, got {}",
        ir.version
    );

    assert!(
        !resp.created_by.is_empty(),
        "created_by must be non-empty (the UDS admin client's implicit-admin actor \
         attribution, e.g. \"unix-socket\"), got: {:?}",
        resp.created_by
    );
    assert!(
        !resp.created_at.is_empty(),
        "created_at must be a non-empty timestamp, got: {:?}",
        resp.created_at
    );
}

/// (2) `GetPolicy{version: 99}`, a version that has never existed, must
/// fail `NotFound` — not `Unimplemented` (once implemented), not a generic
/// `Internal`, and not silently returning some other version.
#[tokio::test]
async fn get_policy_unknown_version_is_not_found() {
    let h = TestController::start().await;

    // A real policy exists (version 1) precisely so this test can't pass
    // by accident via some "no policy at all" fallback path — 99 is
    // unknown even though *a* policy is present.
    let diff = h.apply(FABRIC_WITH_POLICY).await;
    assert!(
        diff.policy_updated,
        "baseline apply must compile a policy, got diff: {:?}",
        diff
    );

    let err = h
        .admin_client()
        .await
        .get_policy(GetPolicyRequest { version: 99 })
        .await
        .expect_err("GetPolicy for a version that was never compiled must fail");

    assert_eq!(
        err.code(),
        tonic::Code::NotFound,
        "expected NotFound for an unknown policy version, got: {err:?}"
    );
}

/// (3) `GetPolicy` sits in the same auth tier as `ListSegments`: a
/// `read-only`-role bearer token (over the TCP Admin listener) must be
/// allowed to call it — same positive-control pattern as
/// `tests/admin_auth.rs`'s `read_only_token_can_list`, just for this RPC,
/// verifying `GetPolicy` is present in
/// `wiremesh_controller::auth::READONLY_METHODS`.
#[tokio::test]
async fn read_only_token_can_call_get_policy() {
    let h = TestController::start().await;

    let diff = h.apply(FABRIC_WITH_POLICY).await;
    assert!(
        diff.policy_updated,
        "baseline apply must compile a policy, got diff: {:?}",
        diff
    );

    let ro = h.mint_api_token("read-only").await;
    let mut admin = h.admin_client_with_bearer(&ro).await;

    let resp = admin
        .get_policy(GetPolicyRequest { version: 0 })
        .await
        .expect("a read-only-role bearer token must be allowed to GetPolicy (a read)")
        .into_inner();

    assert_eq!(
        resp.version, 1,
        "expected the read-only token's GetPolicy call to see the same version-1 policy, got {}",
        resp.version
    );
}
