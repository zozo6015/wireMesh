//! FAILING tests (test-author, operator hardening round, Backlog 4) — Fix 6a
//! (B4b/B6): CRD observe/sync ENDPOINT OVERRIDES. **compile-RED** until the
//! spec fields exist.
//!
//! # The live-found bug (kube-proxy SNAT poisoning)
//!
//! The gateway dials the controller's observe UDP via the Service ClusterIP;
//! kube-proxy SNATs the hostNetwork pod's source, so the controller observed
//! `gw-home`'s public mapping as a node-internal address (10.42.10.1) —
//! poisoning the punch candidates. Operators must be able to point observe
//! (and sync, for controllers reached through an external LB — the zolab Envoy
//! passthrough) at a source-preserving endpoint instead of the ClusterIP.
//!
//! # Pinned implementer surface
//!
//! `crd::WiremeshGatewaySpec` gains two optional overrides (camelCase serde,
//! omitted when unset — parity with every other optional spec field):
//! ```ignore
//! pub observe_endpoint: Option<String>,  // serializes "observeEndpoint"
//! pub sync_endpoint: Option<String>,     // serializes "syncEndpoint"
//! ```
//! `workloads::gateway_deployment` keeps its signature (the reconciler still
//! passes the ClusterIP-derived defaults) but the MAIN container's args must
//! carry the override when present:
//!   * `--observe <spec.observe_endpoint | controller_observe>`
//!   * `--controller-sync <spec.sync_endpoint | controller_sync>`
//! Values are `host:port` — the gateway binary accepts DNS hostnames on both
//! flags (re-resolved per reconnect/tick), so overrides pass through VERBATIM
//! as single argv elements (no shell, no validation-mangling; the builder's
//! no-shell invariant already pins argv safety).
//!
//! The ENROLL init-container is deliberately NOT overridable here: enrollment
//! goes to the in-cluster enroll listener and is not affected by SNAT
//! observation — pinned below so the override cannot silently leak into it.

use wiremesh_operator::crd::{WiremeshGateway, WiremeshGatewaySpec};
use wiremesh_operator::workloads::gateway_deployment;

const CLUSTER_SYNC: &str = "10.43.0.10:9500";
const CLUSTER_ENROLL: &str = "10.43.0.10:9400";
const CLUSTER_OBSERVE: &str = "10.43.0.10:9600";

fn spec(observe_endpoint: Option<String>, sync_endpoint: Option<String>) -> WiremeshGatewaySpec {
    WiremeshGatewaySpec {
        segment_ref: "home".into(),
        node_name: None,
        node_selector: None,
        wg_port: None,
        tun: None,
        image: None,
        storage_class: None,
        storage_size: None,
        observe_endpoint,
        sync_endpoint,
        metrics_bind: None,
    }
}

fn pod_of(s: WiremeshGatewaySpec) -> k8s_openapi::api::core::v1::PodSpec {
    let gw = WiremeshGateway::new("gw-home", s);
    let d = gateway_deployment(
        &gw,
        CLUSTER_SYNC,
        CLUSTER_ENROLL,
        CLUSTER_OBSERVE,
        "wm-ca",
        "gw-home-token",
        &["10.0.125.0/24".to_string()],
    );
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
fn overrides_flow_into_gateway_args() {
    // Hostname sync override (external LB / DDNS controller) + IP observe
    // override (source-preserving UDP LB — the zolab 10.0.125.45 topology).
    let pod = pod_of(spec(
        Some("10.0.125.45:9600".into()),
        Some("wg.zozotk.go.ro:9500".into()),
    ));
    let main = pod
        .containers
        .iter()
        .find(|c| c.name == "gateway")
        .expect("gateway container");
    let args = main.args.as_ref().expect("gateway args");
    assert_eq!(
        arg_after(args, "--observe").as_deref(),
        Some("10.0.125.45:9600"),
        "observeEndpoint override must replace the ClusterIP observe target: {args:?}"
    );
    assert_eq!(
        arg_after(args, "--controller-sync").as_deref(),
        Some("wg.zozotk.go.ro:9500"),
        "syncEndpoint override must replace the ClusterIP sync target (hostnames \
         are valid — the gateway re-resolves them): {args:?}"
    );
}

#[test]
fn absent_overrides_keep_cluster_ip_defaults() {
    // Regression guard: no override → exactly today's ClusterIP wiring.
    let pod = pod_of(spec(None, None));
    let main = pod
        .containers
        .iter()
        .find(|c| c.name == "gateway")
        .expect("gateway container");
    let args = main.args.as_ref().expect("gateway args");
    assert_eq!(
        arg_after(args, "--observe").as_deref(),
        Some(CLUSTER_OBSERVE)
    );
    assert_eq!(
        arg_after(args, "--controller-sync").as_deref(),
        Some(CLUSTER_SYNC)
    );
}

#[test]
fn overrides_are_independent() {
    // Only observe overridden → sync stays on the ClusterIP, and vice versa.
    let pod = pod_of(spec(Some("10.0.125.45:9600".into()), None));
    let main = pod.containers.iter().find(|c| c.name == "gateway").unwrap();
    let args = main.args.as_ref().unwrap();
    assert_eq!(
        arg_after(args, "--observe").as_deref(),
        Some("10.0.125.45:9600")
    );
    assert_eq!(
        arg_after(args, "--controller-sync").as_deref(),
        Some(CLUSTER_SYNC),
        "sync must not inherit the observe override"
    );

    let pod = pod_of(spec(None, Some("wg.zozotk.go.ro:9500".into())));
    let main = pod.containers.iter().find(|c| c.name == "gateway").unwrap();
    let args = main.args.as_ref().unwrap();
    assert_eq!(
        arg_after(args, "--observe").as_deref(),
        Some(CLUSTER_OBSERVE)
    );
    assert_eq!(
        arg_after(args, "--controller-sync").as_deref(),
        Some("wg.zozotk.go.ro:9500")
    );
}

#[test]
fn enroll_init_container_is_never_overridden() {
    // Enrollment stays on the in-cluster enroll endpoint even when both
    // overrides are set — the overrides exist for SNAT/LB topology on the
    // long-lived observe/sync channels, not for the one-shot enroll RPC.
    let pod = pod_of(spec(
        Some("10.0.125.45:9600".into()),
        Some("wg.zozotk.go.ro:9500".into()),
    ));
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
        "enroll --controller must keep the in-cluster enroll endpoint: {args:?}"
    );
}

#[test]
fn override_fields_serialize_camel_case_and_omit_when_unset() {
    let v = serde_json::to_value(spec(
        Some("10.0.125.45:9600".into()),
        Some("wg.zozotk.go.ro:9500".into()),
    ))
    .unwrap();
    assert_eq!(
        v.get("observeEndpoint").and_then(|x| x.as_str()),
        Some("10.0.125.45:9600"),
        "observe_endpoint must serialize as observeEndpoint"
    );
    assert_eq!(
        v.get("syncEndpoint").and_then(|x| x.as_str()),
        Some("wg.zozotk.go.ro:9500"),
        "sync_endpoint must serialize as syncEndpoint"
    );

    let bare = serde_json::to_value(spec(None, None)).unwrap();
    assert!(bare.get("observeEndpoint").is_none(), "omitted when unset");
    assert!(bare.get("syncEndpoint").is_none(), "omitted when unset");

    // A legacy CR without the fields still deserializes (additive change).
    let legacy: WiremeshGatewaySpec =
        serde_json::from_value(serde_json::json!({ "segmentRef": "home" }))
            .expect("legacy gateway CR must still deserialize");
    assert!(legacy.observe_endpoint.is_none() && legacy.sync_endpoint.is_none());
}
