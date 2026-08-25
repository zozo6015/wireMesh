//! Regression pins (test-author, final operator round) for the relay's
//! SCHEDULER-AWARE NODE PINNING — the behavior change in d495d66 that shipped
//! with no test of its own. **Compiles and is expected GREEN**: it pins behavior
//! already landed in `workloads.rs`, so its job is to keep a future edit from
//! silently reverting to `spec.nodeName`.
//!
//! # Why this matters (the wedge it prevents)
//!
//! The relay now owns an RWO identity PVC (`relay_pvc`, `<name>-relay-data`).
//! Default storage classes — k3s `local-path`, most NFS/CSI provisioners — use
//! `volumeBindingMode: WaitForFirstConsumer`, which binds a PVC only AFTER the
//! SCHEDULER places the consuming pod. Setting `spec.nodeName` directly
//! BYPASSES the scheduler, so a WFC PVC never receives its "first consumer"
//! event → PVC stays `Pending` → pod hangs `Pending` forever. That is exactly
//! the bug already fixed gateway-side (`gw-home` pinned to `zolab-worker1`),
//! and the relay inherited it the moment it gained a PVC.
//!
//! The fix keeps the SAME pin but expresses it as a `kubernetes.io/hostname`
//! nodeSelector, which the scheduler honors — so the pod is placed (triggering
//! WFC binding) yet still lands only on the chosen node.
//!
//! Mirrors the shape of the src-side `workloads::tests::gateway_pinning_is_scheduler_aware`
//! (added in b3e61ad). NOTE a deliberate asymmetry: `WiremeshRelaySpec` has NO
//! `nodeSelector` field (unlike `WiremeshGatewaySpec`), so the relay builder
//! passes `None` for the explicit-selector argument — the "explicit selector
//! preserved / explicit hostname wins" cases have no relay analogue and are not
//! asserted here. If a `nodeSelector` field is ever added to the relay CRD,
//! those cases must be added too.

use k8s_openapi::api::core::v1::PodSpec;
use wiremesh_operator::crd::{WiremeshRelay, WiremeshRelaySpec};
use wiremesh_operator::workloads::relay_deployment;

const HOSTNAME_KEY: &str = "kubernetes.io/hostname";

/// Build a relay spec through serde so this file keeps compiling unchanged if
/// optional fields are added to `WiremeshRelaySpec` later.
fn relay_pod(node_name: Option<&str>) -> PodSpec {
    let mut spec = serde_json::json!({ "endpoint": "203.0.113.9:4443" });
    if let Some(n) = node_name {
        spec["nodeName"] = serde_json::Value::String(n.to_string());
    }
    let spec: WiremeshRelaySpec = serde_json::from_value(spec).expect("relay spec deserializes");
    let r = WiremeshRelay::new("relay-eu", spec);
    let d = relay_deployment(&r, "wm:9500", "wm:9400", "wm-ca", "relay-eu-token")
        .expect("valid endpoint must build");
    d.spec.unwrap().template.spec.unwrap()
}

#[test]
fn relay_pinning_is_scheduler_aware() {
    // 1. CR nodeName set → pod.nodeName is NOT set; the pin is expressed as a
    //    kubernetes.io/hostname nodeSelector the scheduler honors.
    let p = relay_pod(Some("zolab-worker1"));
    assert_eq!(
        p.node_name, None,
        "spec.nodeName must NOT be set directly — it bypasses the scheduler, so the relay's \
         WaitForFirstConsumer PVC would never bind (PVC Pending → pod Pending forever)"
    );
    let sel = p.node_selector.as_ref().expect(
        "nodeName must be folded into a nodeSelector so the scheduler still places the pod",
    );
    assert_eq!(
        sel.get(HOSTNAME_KEY).map(String::as_str),
        Some("zolab-worker1"),
        "the CR's nodeName must be pinned via a kubernetes.io/hostname nodeSelector"
    );

    // 2. CR pins nothing → neither a nodeName nor a synthesized selector.
    let p = relay_pod(None);
    assert_eq!(p.node_name, None, "no nodeName when the CR pins nothing");
    assert!(
        p.node_selector
            .as_ref()
            .map(|m| m.is_empty())
            .unwrap_or(true),
        "no nodeSelector (and no synthesized hostname key) when the CR sets no nodeName; got {:?}",
        p.node_selector
    );
}

#[test]
fn relay_node_pinning_and_identity_pvc_coexist() {
    // The two halves of the fix must hold TOGETHER: the whole reason pinning had
    // to become scheduler-aware is the PVC. A pinned relay must still mount its
    // identity PVC (not an emptyDir), otherwise the pin was made "safe" by
    // regressing durability.
    let p = relay_pod(Some("zolab-worker1"));
    assert_eq!(p.node_name, None, "still scheduler-aware");
    assert_eq!(
        p.node_selector
            .as_ref()
            .and_then(|s| s.get(HOSTNAME_KEY))
            .map(String::as_str),
        Some("zolab-worker1"),
    );

    let certs = p
        .volumes
        .as_ref()
        .expect("pod volumes")
        .iter()
        .find(|v| v.name == "certs")
        .expect("certs volume");
    assert!(
        certs.empty_dir.is_none(),
        "the identity volume must NOT be an emptyDir (that is the durability half of this fix)"
    );
    assert_eq!(
        certs
            .persistent_volume_claim
            .as_ref()
            .expect("certs volume must be a PersistentVolumeClaim")
            .claim_name,
        "relay-eu-relay-data",
        "the pinned relay still mounts its kind-specific identity PVC"
    );

    // And the main container actually mounts it (a PVC volume nothing mounts
    // would bind but persist nothing).
    let main = p
        .containers
        .iter()
        .find(|c| c.name == "relay")
        .expect("relay container");
    assert!(
        main.volume_mounts
            .as_ref()
            .expect("relay container volume mounts")
            .iter()
            .any(|m| m.name == "certs"),
        "the relay container must mount the certs PVC"
    );
}
