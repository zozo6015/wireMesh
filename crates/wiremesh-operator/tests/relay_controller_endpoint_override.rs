//! Backlog 2d: `WiremeshRelay` gains a CRD override for the relay's
//! `--controller` (sync) dial target. **Landed** —
//! `crd::WiremeshRelaySpec::controller_endpoint` exists and
//! `workloads::relay_deployment` wires it in; all 5 tests below pin that
//! surface and pass on current `main`.
//!
//! # Why
//!
//! The relay's `--controller` target is today derived unconditionally from the
//! controller Service's in-cluster ClusterIP. Since the control plane moved
//! off zolab k8s to the px Debian host, an in-cluster relay can no longer be
//! pointed at it — the identical failure that motivated the gateway's
//! `syncEndpoint`/`observeEndpoint` overrides
//! (`tests/gateway_endpoint_overrides.rs`, which this file mirrors as a
//! matched pair).
//!
//! # Pinned surface
//!
//! `crd::WiremeshRelaySpec` carries one optional override (camelCase serde,
//! omitted when unset — parity with every other optional spec field):
//! ```ignore
//! pub controller_endpoint: Option<String>,  // serializes "controllerEndpoint"
//! ```
//! `workloads::relay_deployment` keeps its signature (the reconciler still
//! passes the ClusterIP-derived `controller_sync` default); the MAIN
//! container's `--controller` arg carries
//! `spec.controller_endpoint.as_deref().unwrap_or(controller_sync)`.
//!
//! The ENROLL init-container is deliberately NOT overridable here — it stays
//! on the in-cluster enroll endpoint, exactly like the gateway's carve-out.
//!
//! **Validation is NOT this file's job to prove for the reconciler ordering**:
//! unlike the gateway (whose `apply_gateway` and its argv-building are both
//! plain sync code reachable from a unit test), the relay reconciler's
//! `admin: Arc<AdminExec>` field is a concrete cluster-exec type with no fake
//! in this crate (see `relay_durability_pinned.rs`'s own docstring: "these
//! reconciler flows are cluster-only"), so the "`validate_dial_target` runs
//! in the reconciler BEFORE any mint/PVC/Deployment side effect" requirement
//! cannot be exercised by an automated test here — it is a code-review
//! invariant, same as it already is for the gateway (mirror
//! `apply_gateway`'s loop at the top of `apply_relay`, before the mint check).
//! What CAN be pinned at this level is the flip side: the pure builder must
//! NOT duplicate that validation (see test 5 below).

use wiremesh_operator::crd::{WiremeshRelay, WiremeshRelaySpec};
use wiremesh_operator::workloads::relay_deployment;

const CLUSTER_SYNC: &str = "10.43.0.10:9500";
const CLUSTER_ENROLL: &str = "10.43.0.10:9400";

fn spec(controller_endpoint: Option<String>) -> WiremeshRelaySpec {
    WiremeshRelaySpec {
        endpoint: "203.0.113.9:4443".into(),
        node_name: None,
        image: None,
        storage_class: None,
        storage_size: None,
        controller_endpoint,
    }
}

fn pod_of(s: WiremeshRelaySpec) -> k8s_openapi::api::core::v1::PodSpec {
    let r = WiremeshRelay::new("relay-eu", s);
    let d = relay_deployment(&r, CLUSTER_SYNC, CLUSTER_ENROLL, "wm-ca", "relay-eu-token")
        .expect("relay_deployment must succeed for a well-formed spec");
    d.spec.unwrap().template.spec.unwrap()
}

/// The value following `flag` in an argv list (flag/value pairs).
fn arg_after(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

#[test]
fn controller_endpoint_override_flows_into_relay_arg() {
    // DNS hostname override (external LB / DDNS controller — the px host
    // topology), mirroring the gateway's syncEndpoint test.
    let pod = pod_of(spec(Some("wg.zozotk.go.ro:9500".into())));
    let main = pod
        .containers
        .iter()
        .find(|c| c.name == "relay")
        .expect("relay container");
    let args = main.args.as_ref().expect("relay args");
    assert_eq!(
        arg_after(args, "--controller").as_deref(),
        Some("wg.zozotk.go.ro:9500"),
        "controllerEndpoint override must replace the ClusterIP --controller target: {args:?}"
    );
}

#[test]
fn absent_controller_endpoint_keeps_cluster_ip_default() {
    // Regression guard: no override → exactly today's ClusterIP wiring.
    let pod = pod_of(spec(None));
    let main = pod.containers.iter().find(|c| c.name == "relay").unwrap();
    let args = main.args.as_ref().unwrap();
    assert_eq!(
        arg_after(args, "--controller").as_deref(),
        Some(CLUSTER_SYNC),
        "no override must leave the ClusterIP-derived --controller target unchanged: {args:?}"
    );
}

#[test]
fn enroll_init_container_is_never_overridden_by_controller_endpoint() {
    // The relay's enroll init-container dials the in-cluster enroll listener
    // (its own `--controller` argv, distinct from the main container's sync
    // target) and must stay there even when controllerEndpoint is set — the
    // same carve-out the gateway pins for its enroll init-container.
    let pod = pod_of(spec(Some("wg.zozotk.go.ro:9500".into())));
    let enroll = pod
        .init_containers
        .as_ref()
        .unwrap()
        .iter()
        .find(|c| c.name == "enroll")
        .expect("enroll init container");
    let args = enroll.args.as_ref().unwrap();
    assert_eq!(
        arg_after(args, "--controller").as_deref(),
        Some(CLUSTER_ENROLL),
        "enroll --controller must keep the in-cluster enroll endpoint even when \
         controllerEndpoint overrides the main container's sync target: {args:?}"
    );
}

#[test]
fn controller_endpoint_serializes_camel_case_and_omits_when_unset() {
    let v = serde_json::to_value(spec(Some("wg.zozotk.go.ro:9500".into()))).unwrap();
    assert_eq!(
        v.get("controllerEndpoint").and_then(|x| x.as_str()),
        Some("wg.zozotk.go.ro:9500"),
        "controller_endpoint must serialize as controllerEndpoint"
    );

    let bare = serde_json::to_value(spec(None)).unwrap();
    assert!(
        bare.get("controllerEndpoint").is_none(),
        "omitted when unset"
    );

    // A legacy CR without the field still deserializes (additive change —
    // required for `crd_manifest_freshness.rs`'s no-conversion-webhook,
    // no-storage-migration story to hold).
    let legacy: WiremeshRelaySpec = serde_json::from_value(serde_json::json!({
        "endpoint": "203.0.113.9:4443"
    }))
    .expect("legacy relay CR (no controllerEndpoint) must still deserialize");
    assert!(legacy.controller_endpoint.is_none());
}

#[test]
fn relay_deployment_does_not_validate_controller_endpoint_itself() {
    // The "one asymmetry" the backlog calls out: `relay_deployment` already
    // fails closed on a bad `endpoint` (the address the relay binds and
    // advertises), so validating `controllerEndpoint` there TOO would give
    // the relay two validation call sites for the same class of value.
    // Rejection must live solely in the reconciler's `validate_dial_target`
    // gate (mirroring `apply_gateway`'s loop), run BEFORE any
    // mint/PVC/Deployment side effect — so the pure builder must pass a
    // malformed override straight through rather than erroring on it.
    let r = WiremeshRelay::new("r", spec(Some("not a host port; rm -rf /".into())));
    let d = relay_deployment(&r, CLUSTER_SYNC, CLUSTER_ENROLL, "wm-ca", "r-token").expect(
        "relay_deployment must NOT reject a malformed controllerEndpoint — validation \
         belongs to the reconciler alone (validate_dial_target), never duplicated in the \
         builder (that would create two validation sites for the same value)",
    );
    let pod = d.spec.unwrap().template.spec.unwrap();
    let main = pod.containers.iter().find(|c| c.name == "relay").unwrap();
    let args = main.args.as_ref().unwrap();
    assert_eq!(
        arg_after(args, "--controller").as_deref(),
        Some("not a host port; rm -rf /"),
        "verbatim passthrough as a single argv element — no shell, no validation-mangling: {args:?}"
    );
}
