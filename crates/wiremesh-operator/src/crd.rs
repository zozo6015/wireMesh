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
        let _ = WiremeshGateway::new("g", WiremeshGatewaySpec { segment_ref: "s".into(), node_name: None, node_selector: None, wg_port: None, tun: None, image: None, storage_class: None, storage_size: None });
        let _ = WiremeshRelay::new("r", WiremeshRelaySpec { endpoint: "203.0.113.9:4443".into(), node_name: None, image: None });
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
        };
        let vb = serde_json::to_value(&bare).unwrap();
        assert!(vb.get("storageClass").is_none(), "storageClass omitted when unset");
        assert!(vb.get("storageSize").is_none(), "storageSize omitted when unset");
    }

    #[test]
    fn crdgen_emits_five_cluster_scoped_crds() {
        let crds = all_crds();
        assert_eq!(crds.len(), 5);
        let mut kinds: Vec<String> = crds.iter().map(|c| c.spec.names.kind.clone()).collect();
        kinds.sort();
        assert_eq!(
            kinds,
            vec![
                "WiremeshController",
                "WiremeshGateway",
                "WiremeshPolicy",
                "WiremeshRelay",
                "WiremeshSegment"
            ]
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
            }
        }
    }
}
