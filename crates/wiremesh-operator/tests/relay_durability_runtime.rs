//! FAILING tests (test-author, operator hardening round, Backlog 4) — Fix 1:
//! RELAY DURABILITY, the parts assertable against the EXISTING public API.
//!
//! This file COMPILES TODAY and is **runtime-RED**: `relay_deployment` exists,
//! but currently ships the relay identity in an `emptyDir` (workloads.rs:689),
//! sets no Deployment strategy (workloads.rs:715-727), and the token is minted
//! strictly once (relay.rs `needs_token` only). Consequence (critical): ANY pod
//! recreation — node reboot, upgrade, eviction — destroys the certs and the
//! init-container re-enrolls against a SPENT single-use token → `Init:Error`
//! wedge. The expected fix mirrors the gateway exactly:
//!
//!   * a per-relay PVC (`<name>-relay-data`, kind-specific — mirrors
//!     `<name>-gateway-data`) replacing the `certs` emptyDir;
//!   * `strategy: Recreate` (an RWO PVC must never surge a 2nd pod), routed
//!     through `deployment_apply_body` at the apply boundary so SSA clears the
//!     API-server defaulter's `rollingUpdate` block (same 422 bug the
//!     gateway/controller already fixed — ops-finding-pvc-adoption-migration.md
//!     bug 1). The relay reconciler must apply via `apply_deployment` (today it
//!     uses the plain `apply`) — that reconciler wiring is review-verified, the
//!     builder + apply-body shape is pinned here.
//!
//! The NEW surfaces (relay PVC builder, CRD storage fields, mint gating) are
//! pinned in `relay_durability_pinned.rs` (compile-red).

use wiremesh_operator::crd::{WiremeshRelay, WiremeshRelaySpec};
use wiremesh_operator::workloads::{deployment_apply_body, relay_deployment};

/// Build a relay spec through serde so this file keeps compiling unchanged
/// after the implementer ADDS optional fields to `WiremeshRelaySpec` (struct
/// literals would break; JSON with defaults will not).
fn relay(name: &str) -> WiremeshRelay {
    let spec: WiremeshRelaySpec =
        serde_json::from_value(serde_json::json!({ "endpoint": "203.0.113.9:4443" }))
            .expect("minimal relay spec deserializes");
    WiremeshRelay::new(name, spec)
}

fn build(name: &str) -> k8s_openapi::api::apps::v1::Deployment {
    relay_deployment(&relay(name), "wm:9500", "wm:9400", "wm-ca", "relay-eu-token")
        .expect("valid endpoint must build")
}

#[test]
fn relay_deployment_uses_recreate_strategy() {
    // The relay now owns an RWO identity PVC (see the PVC test below), so a
    // default RollingUpdate would surge a second pod that cannot mount the RWO
    // claim, wedging the rollout — exactly the reasoning already applied to the
    // gateway/controller Deployments (`gateway_and_controller_use_recreate_strategy`).
    let d = build("relay-eu");
    let strat = d
        .spec
        .expect("deployment spec")
        .strategy
        .expect("relay Deployment must set a strategy (RWO PVC must not surge a 2nd pod)");
    assert_eq!(
        strat.type_.as_deref(),
        Some("Recreate"),
        "relay Deployment must use the Recreate strategy"
    );
}

#[test]
fn relay_certs_volume_is_pvc_not_emptydir() {
    // DURABILITY INVARIANT (the critical finding): the relay's enrolled identity
    // (ca.pem / relay.pem / relay.key) must survive pod recreation. The `certs`
    // volume MUST be a PersistentVolumeClaim referencing the kind-specific
    // `<name>-relay-data` claim, NOT an emptyDir — an emptyDir is destroyed on
    // every pod recreation, forcing a re-enroll against a spent single-use
    // token → Init:Error wedge.
    let d = build("relay-eu");
    let pod = d.spec.unwrap().template.spec.unwrap();
    let certs = pod
        .volumes
        .as_ref()
        .unwrap()
        .iter()
        .find(|v| v.name == "certs")
        .expect("certs volume");
    assert!(
        certs.empty_dir.is_none(),
        "certs volume must NOT be an emptyDir (identity would be lost on pod recreation)"
    );
    let claim = certs
        .persistent_volume_claim
        .as_ref()
        .expect("certs volume must be a PersistentVolumeClaim");
    assert_eq!(
        claim.claim_name, "relay-eu-relay-data",
        "certs PVC references the relay's kind-specific <name>-relay-data claim \
         (mirrors the gateway's <name>-gateway-data; must not collide with the \
         controller's <name>-data)"
    );
}

#[test]
fn relay_apply_body_nulls_rolling_update_under_recreate() {
    // Same SSA defaulter-conflict bug the gateway/controller already fixed: a
    // typed `rolling_update: None` serializes to an OMITTED field, so applying
    // `type: Recreate` over an existing RollingUpdate Deployment leaves the
    // defaulter's `rollingUpdate` block in place → 422
    // (`spec.strategy.rollingUpdate: Forbidden ... when type is 'Recreate'`).
    // The relay's apply body must carry an EXPLICIT `rollingUpdate: null`.
    // (`Value::index` returns Null for a MISSING key too, so the `contains_key`
    // check below is what actually pins "present null" vs "absent".)
    //
    // Reconciler wiring (review-verified, not unit-testable): relay.rs must
    // switch its Deployment apply from `apply` to `apply_deployment`.
    let body = deployment_apply_body(&build("relay-eu"));
    let strat = body
        .get("spec")
        .and_then(|s| s.get("strategy"))
        .unwrap_or_else(|| panic!("relay apply body must carry spec.strategy: {body:#}"));
    assert_eq!(
        strat.get("type").and_then(|t| t.as_str()),
        Some("Recreate"),
        "relay apply body strategy.type must be Recreate"
    );
    let obj = strat.as_object().expect("strategy is a JSON object");
    assert!(
        obj.contains_key("rollingUpdate"),
        "relay apply body must include an EXPLICIT strategy.rollingUpdate key: {strat:#}"
    );
    assert!(
        strat["rollingUpdate"].is_null(),
        "relay apply body strategy.rollingUpdate must be JSON null so SSA removes \
         the defaulter's block: {strat:#}"
    );
}
