//! WireMesh operator Custom Resource Definitions.
//!
//! All five kinds are **cluster-scoped** (kube-derive is cluster-scoped unless
//! `namespaced` is set) — the controller is single-tenant, so there is one
//! fabric per cluster. Group `wiremesh.io`, version `v1alpha1`.

use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinition;
use kube::{CustomResource, CustomResourceExt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A status condition (mirrors the k8s meta/v1 Condition shape, minus timestamps).
#[derive(Serialize, Deserialize, Clone, Debug, Default, JsonSchema, PartialEq, Eq)]
pub struct Condition {
    #[serde(rename = "type")]
    pub type_: String,
    pub status: String,
    pub reason: String,
    pub message: String,
}

/// Shared status for the config kinds (Segment/Policy/Relay).
#[derive(Serialize, Deserialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WiremeshResourceStatus {
    #[serde(default)]
    pub applied: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_version: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

// --------------------------------------------------------------------------
// WiremeshController (singleton) — the operator owns the controller workload.
// --------------------------------------------------------------------------
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "wiremesh.io",
    version = "v1alpha1",
    kind = "WiremeshController",
    status = "WiremeshControllerStatus",
    shortname = "wmctrl"
)]
#[serde(rename_all = "camelCase")]
pub struct WiremeshControllerSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_size: Option<String>,
    #[schemars(range(max = 65535))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_tcp_port: Option<u16>,
    #[schemars(range(max = 65535))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_tcp_port: Option<u16>,
    #[schemars(range(max = 65535))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observe_udp_port: Option<u16>,
    /// `WIREMESH_ROTATION_INTERVAL` passthrough. Unset (`None`) does NOT
    /// disable rotation by omission — the operator emits `off` explicitly,
    /// keeping automatic key rotation disabled per the project-wide rule
    /// (root `CLAUDE.md`, "Key rotation") until the in-step rotation done-bar
    /// passes. Set (`Some`) is passed through verbatim; grammar validation
    /// (`off`/`<n>d`/`<n>h`/...) lives on the controller boot path, not here.
    /// The operator owns this env key under SSA force-apply
    /// (`controllers::apply`/`apply_deployment`, `.force()` on both), so a
    /// hand-set value on the Deployment IS reconciled back to match this
    /// field on every pass — that's deliberate while the done-bar is
    /// outstanding, not a bug to route around.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_interval: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WiremeshControllerStatus {
    #[serde(default)]
    pub ready: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_version: Option<u64>,
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

// --------------------------------------------------------------------------
// WiremeshSegment — name + CIDRs; aggregated into the fabric YAML.
// --------------------------------------------------------------------------
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "wiremesh.io",
    version = "v1alpha1",
    kind = "WiremeshSegment",
    status = "WiremeshResourceStatus",
    shortname = "wmseg"
)]
#[serde(rename_all = "camelCase")]
pub struct WiremeshSegmentSpec {
    pub segment_name: String,
    pub cidrs: Vec<String>,
}

// --------------------------------------------------------------------------
// WiremeshPolicy — a from→to allow block; aggregated into the fabric YAML.
// --------------------------------------------------------------------------
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AllowRule {
    pub proto: String,
    #[serde(default)]
    pub ports: Vec<u16>,
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
pub struct PolicyRule {
    pub allow: AllowRule,
}

#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "wiremesh.io",
    version = "v1alpha1",
    kind = "WiremeshPolicy",
    status = "WiremeshResourceStatus",
    shortname = "wmpol"
)]
#[serde(rename_all = "camelCase")]
pub struct WiremeshPolicySpec {
    pub from: String,
    pub to: String,
    pub rules: Vec<PolicyRule>,
}

// --------------------------------------------------------------------------
// WiremeshGateway — a privileged hostNetwork gateway for one segment.
// --------------------------------------------------------------------------
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "wiremesh.io",
    version = "v1alpha1",
    kind = "WiremeshGateway",
    status = "WiremeshGatewayStatus",
    shortname = "wmgw"
)]
#[serde(rename_all = "camelCase")]
pub struct WiremeshGatewaySpec {
    /// The `WiremeshSegment` (by `.metadata.name`) this gateway fronts.
    pub segment_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_selector: Option<BTreeMap<String, String>>,
    #[schemars(range(max = 65535))]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wg_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tun: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// StorageClass for the per-gateway identity PVC (`<name>-data`). Omitted →
    /// the cluster default class. Parity with `WiremeshControllerSpec`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,
    /// Size of the per-gateway identity PVC. Omitted → the 128Mi default (the
    /// persisted identity is a few KB). Parity with `WiremeshControllerSpec`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_size: Option<String>,
    /// Override for the gateway's `--observe` target (`host:port`; DNS hostnames
    /// are accepted — the gateway re-resolves per tick). Needed when the
    /// ClusterIP observe path is SNAT'd by kube-proxy (poisoning the observed
    /// public mapping); point this at a source-preserving UDP LB instead.
    /// Absent → the controller Service ClusterIP (today's default). The enroll
    /// init-container is NEVER affected by this override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observe_endpoint: Option<String>,
    /// Override for the gateway's `--controller-sync` target (`host:port`; DNS
    /// hostnames accepted — re-resolved per reconnect). For controllers reached
    /// through an external LB / DDNS name. Absent → the controller Service
    /// ClusterIP. The enroll init-container is NEVER affected by this override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync_endpoint: Option<String>,
    /// Override for the gateway's `--metrics` bind target (`ip:port`, a LOCAL
    /// bind address, not a fabric dial target — no DNS hostnames, since the
    /// binary parses this as a literal `std::net::SocketAddr`). Absent →
    /// today's hardcoded `0.0.0.0:9090`. IPv4 and IPv6 are both accepted
    /// (see `workloads::validate_bind_target`); port `0` (OS-assigned) is
    /// valid. The enroll init-container is NEVER affected by this override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics_bind: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WiremeshGatewayStatus {
    #[serde(default)]
    pub enrolled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_state: Option<String>,
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

// --------------------------------------------------------------------------
// WiremeshRelay — a relay registration + workload.
// --------------------------------------------------------------------------
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "wiremesh.io",
    version = "v1alpha1",
    kind = "WiremeshRelay",
    status = "WiremeshResourceStatus",
    shortname = "wmrelay"
)]
#[serde(rename_all = "camelCase")]
pub struct WiremeshRelaySpec {
    /// Publicly reachable `ip:port` the relay advertises.
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// StorageClass for the per-relay identity PVC (`<name>-relay-data`).
    /// Omitted → the cluster default class. Parity with `WiremeshGatewaySpec`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,
    /// Size of the per-relay identity PVC. Omitted → the 128Mi default (the
    /// enrolled certs are a few KB). Parity with `WiremeshGatewaySpec`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_size: Option<String>,
    /// Override for the relay's `--controller` (sync) target (`host:port`; DNS
    /// hostnames accepted). For controllers reached through an external LB /
    /// DDNS name. Absent → the controller Service ClusterIP (today's default).
    /// The enroll init-container is NEVER affected by this override — parity
    /// with `WiremeshGatewaySpec::sync_endpoint`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_endpoint: Option<String>,
}

/// All five CRDs, for the `crdgen` binary and for the operator's install/verify.
pub fn all_crds() -> Vec<CustomResourceDefinition> {
    vec![
        WiremeshController::crd(),
        WiremeshSegment::crd(),
        WiremeshPolicy::crd(),
        WiremeshGateway::crd(),
        WiremeshRelay::crd(),
    ]
}

/// The committed CRD bundles, rendered as one multi-document YAML string.
///
/// This is the whole body of the `crdgen` binary, lifted out of it so that
/// `tests/crd_manifest_freshness.rs` can assert against the SAME rendering the
/// binary emits. A test that rebuilt this loop for itself could drift from the
/// binary and go on passing while `crdgen` wrote something else — which is the
/// exact class of drift that test exists to catch.
///
/// Byte-level shape is load-bearing (the test compares raw file bytes): each
/// document opens with its own `---` line, `serde_yaml::to_string` emits no
/// leading separator of its own and already ends in a newline, so the result
/// ends with exactly one.
pub fn render_crd_yaml() -> anyhow::Result<String> {
    let mut out = String::new();
    for crd in all_crds() {
        out.push_str("---\n");
        out.push_str(&serde_yaml::to_string(&crd)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::Resource;

    #[test]
    fn crd_yaml_roundtrips() {
        let seg = WiremeshSegment::new(
            "aws",
            WiremeshSegmentSpec { segment_name: "aws".into(), cidrs: vec!["10.10.1.0/24".into()] },
        );
        let y = serde_yaml::to_string(&seg).unwrap();
        let back: WiremeshSegment = serde_yaml::from_str(&y).unwrap();
        assert_eq!(back.spec.segment_name, "aws");
        assert_eq!(back.spec.cidrs, vec!["10.10.1.0/24".to_string()]);
    }

    #[test]
    fn crd_derive_compiles_all_five() {
        // Construct one of each kind — a compile-proof that every derive works.
        let _ = WiremeshController::new("wm", WiremeshControllerSpec::default_for_test());
        let _ = WiremeshSegment::new("s", WiremeshSegmentSpec { segment_name: "s".into(), cidrs: vec![] });
        let _ = WiremeshPolicy::new("p", WiremeshPolicySpec { from: "a".into(), to: "b".into(), rules: vec![] });
        let _ = WiremeshGateway::new("g", WiremeshGatewaySpec { segment_ref: "s".into(), node_name: None, node_selector: None, wg_port: None, tun: None, image: None, storage_class: None, storage_size: None, observe_endpoint: None, sync_endpoint: None, metrics_bind: None });
        let _ = WiremeshRelay::new("r", WiremeshRelaySpec { endpoint: "203.0.113.9:4443".into(), node_name: None, image: None, storage_class: None, storage_size: None, controller_endpoint: None });
        // Kind names are what the apiserver registers.
        assert_eq!(WiremeshSegment::kind(&()), "WiremeshSegment");
    }

    #[test]
    fn gateway_spec_carries_storage_fields_camel_case() {
        // The gateway persists its identity on a per-gateway PVC. Its size/class
        // must be overridable from the CR via `storageClass`/`storageSize` —
        // matching WiremeshController's existing fields (camelCase serde, both
        // Option, omitted when unset via skip_serializing_if).
        let spec = WiremeshGatewaySpec {
            segment_ref: "aws".into(),
            node_name: None,
            node_selector: None,
            wg_port: None,
            tun: None,
            image: None,
            storage_class: Some("fast-ssd".into()),
            storage_size: Some("256Mi".into()),
            observe_endpoint: None,
            sync_endpoint: None,
            metrics_bind: None,
        };
        let v = serde_json::to_value(&spec).unwrap();
        assert_eq!(
            v.get("storageClass").and_then(|x| x.as_str()),
            Some("fast-ssd"),
            "storageClass must serialize camelCase (parity with WiremeshController)"
        );
        assert_eq!(
            v.get("storageSize").and_then(|x| x.as_str()),
            Some("256Mi"),
            "storageSize must serialize camelCase (parity with WiremeshController)"
        );

        // Both omitted when unset (skip_serializing_if = "Option::is_none").
        let bare = WiremeshGatewaySpec {
            segment_ref: "aws".into(),
            node_name: None,
            node_selector: None,
            wg_port: None,
            tun: None,
            image: None,
            storage_class: None,
            storage_size: None,
            observe_endpoint: None,
            sync_endpoint: None,
            metrics_bind: None,
        };
        let vb = serde_json::to_value(&bare).unwrap();
        assert!(vb.get("storageClass").is_none(), "storageClass omitted when unset");
        assert!(vb.get("storageSize").is_none(), "storageSize omitted when unset");
    }

    #[test]
    fn crdgen_emits_five_cluster_scoped_crds() {
        let crds = all_crds();
        assert_eq!(crds.len(), 5);
        // Asserted IN EMISSION ORDER, not sorted. `all_crds()` is what decides
        // the document order of both committed YAML bundles, and
        // `tests/crd_manifest_freshness.rs` compares those bundles BYTE FOR
        // BYTE — so this sequence is part of the generated file's contract, not
        // an implementation detail.
        //
        // This assertion previously sorted first, which meant reordering
        // `all_crds()` was pinned by nothing. That mattered: a reorder that is
        // ALSO regenerated into both YAML files leaves the freshness test green
        // while silently changing the document order of every user's CRD
        // bundle. This is the only thing that catches it.
        //
        // Keep `all_crds()` returning an explicit `vec![..]`. Iterating a
        // `HashMap` there would make the freshness test nondeterministically
        // flaky — a failure that looks like a bad test rather than a real one.
        let kinds: Vec<String> = crds.iter().map(|c| c.spec.names.kind.clone()).collect();
        assert_eq!(
            kinds,
            vec![
                "WiremeshController",
                "WiremeshSegment",
                "WiremeshPolicy",
                "WiremeshGateway",
                "WiremeshRelay"
            ],
            "all_crds() order is the document order of the generated CRD bundles"
        );
        for c in &crds {
            assert_eq!(c.spec.scope, "Cluster", "{} must be cluster-scoped", c.spec.names.kind);
            assert_eq!(c.spec.group, "wiremesh.io");
        }
    }

    // Test-only default so `crd_derive_compiles_all_five` stays readable.
    impl WiremeshControllerSpec {
        fn default_for_test() -> Self {
            WiremeshControllerSpec {
                image: None,
                storage_class: None,
                storage_size: None,
                admin_tcp_port: None,
                sync_tcp_port: None,
                observe_udp_port: None,
                rotation_interval: None,
            }
        }
    }
}
