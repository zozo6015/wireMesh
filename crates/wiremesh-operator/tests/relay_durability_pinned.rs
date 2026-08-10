//! FAILING tests (test-author, operator hardening round, Backlog 4) — Fix 1:
//! RELAY DURABILITY, the NEW surfaces. **compile-RED**: this file does not
//! compile until the implementer adds the pinned APIs.
//!
//! # Pinned implementer surfaces
//!
//! 1. `crd::WiremeshRelaySpec` gains the same optional storage fields the
//!    gateway grew for ITS identity PVC (camelCase serde, omitted when unset):
//!    ```ignore
//!    pub storage_class: Option<String>,   // serializes "storageClass"
//!    pub storage_size: Option<String>,    // serializes "storageSize"
//!    ```
//!    (Existing struct literals in src tests must be updated by the implementer.)
//!
//! 2. `workloads::relay_pvc` — mirrors `gateway_pvc`'s shape exactly:
//!    ```ignore
//!    pub fn relay_pvc(name: &str, spec: &WiremeshRelaySpec) -> PersistentVolumeClaim
//!    ```
//!    `<name>-relay-data` (kind-specific), RWO, default 128Mi (the certs are a
//!    few KB), instance labels, storageClass/storageSize overrides.
//!
//! 3. `controllers::relay::should_mint_token` — the mint decision factored as a
//!    pure fn with the SAME contract as the gateway's (gateway.rs:55):
//!    ```ignore
//!    pub fn should_mint_token(identity_persisted: bool, token_secret: Option<&Secret>) -> bool
//!    // == !identity_persisted || needs_token(token_secret)
//!    ```
//!    Today relay.rs:45 gates the mint on `needs_token` ALONE, so once a
//!    populated (but SPENT) token Secret exists, a relay that lost its certs
//!    can never get a fresh token → permanent Init:Error. The reconciler must
//!    key the mint off "is the identity durably persisted", exactly like the
//!    gateway.
//!
//! # Wiring guidance (integration-level, NOT pinned here)
//!
//! * `identity_persisted` input: PVC exists AND there is corroboration the
//!   enroll actually completed (the gateway uses its roster row; the relay has
//!   no `list_relays` on `AdminExec` today — Deployment availability or a new
//!   relay-roster probe are both acceptable; on a probe FAILURE be CONSERVATIVE
//!   → not persisted → mint a spare token, which lapses unused).
//! * PVC create-only guard: reuse the shared `pvc_needs_create`
//!   (see `reconcile_guards.rs`) — a bound PVC's storage fields are immutable.
//! * These reconciler flows are cluster-only; this file pins the pure surfaces.

use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::ByteString;
use std::collections::BTreeMap;
use wiremesh_operator::controllers::relay::should_mint_token;
use wiremesh_operator::crd::WiremeshRelaySpec;
use wiremesh_operator::workloads::relay_pvc;

fn spec(storage_class: Option<String>, storage_size: Option<String>) -> WiremeshRelaySpec {
    WiremeshRelaySpec {
        endpoint: "203.0.113.9:4443".into(),
        node_name: None,
        image: None,
        storage_class,
        storage_size,
        controller_endpoint: None,
    }
}

#[test]
fn relay_spec_carries_storage_fields_camel_case() {
    // Parity with WiremeshGatewaySpec/WiremeshControllerSpec: storageClass /
    // storageSize, camelCase, both Option, omitted when unset.
    let v = serde_json::to_value(spec(Some("fast-ssd".into()), Some("256Mi".into()))).unwrap();
    assert_eq!(
        v.get("storageClass").and_then(|x| x.as_str()),
        Some("fast-ssd"),
        "storageClass must serialize camelCase"
    );
    assert_eq!(
        v.get("storageSize").and_then(|x| x.as_str()),
        Some("256Mi"),
        "storageSize must serialize camelCase"
    );

    let bare = serde_json::to_value(spec(None, None)).unwrap();
    assert!(bare.get("storageClass").is_none(), "storageClass omitted when unset");
    assert!(bare.get("storageSize").is_none(), "storageSize omitted when unset");

    // Roundtrip: a legacy CR without the new fields still deserializes.
    let legacy: WiremeshRelaySpec =
        serde_json::from_value(serde_json::json!({ "endpoint": "203.0.113.9:4443" }))
            .expect("legacy relay CR (no storage fields) must still deserialize");
    assert!(legacy.storage_class.is_none() && legacy.storage_size.is_none());
}

#[test]
fn relay_pvc_shape_mirrors_gateway_pvc() {
    let pvc = relay_pvc("relay-eu", &spec(None, None));
    assert_eq!(
        pvc.metadata.name.as_deref(),
        Some("relay-eu-relay-data"),
        "relay PVC uses the kind-specific <name>-relay-data scheme (mirrors the \
         gateway's <name>-gateway-data; must NOT collide with the controller's <name>-data)"
    );
    let s = pvc.spec.as_ref().expect("PVC spec");
    assert_eq!(
        s.access_modes.as_ref().unwrap(),
        &vec!["ReadWriteOnce".to_string()],
        "relay identity PVC is RWO (node-local, single writer)"
    );
    let req = s.resources.as_ref().unwrap().requests.as_ref().unwrap();
    assert_eq!(req.get("storage").unwrap().0, "128Mi", "default relay PVC size is 128Mi");
    assert!(s.storage_class_name.is_none(), "no storageClass unless the CR sets one");
    let labels = pvc.metadata.labels.as_ref().expect("labels");
    assert_eq!(
        labels.get("app.kubernetes.io/instance").map(String::as_str),
        Some("relay-eu"),
        "PVC carries the instance label"
    );

    // Overrides flow through from the CR.
    let pvc2 = relay_pvc("relay-eu", &spec(Some("fast-ssd".into()), Some("256Mi".into())));
    let s2 = pvc2.spec.as_ref().unwrap();
    assert_eq!(s2.storage_class_name.as_deref(), Some("fast-ssd"), "storageClass override honored");
    assert_eq!(
        s2.resources.as_ref().unwrap().requests.as_ref().unwrap().get("storage").unwrap().0,
        "256Mi",
        "storageSize override honored"
    );
}

#[test]
fn relay_should_mint_token_keys_off_identity_persisted_not_needs_token_alone() {
    // THE WEDGE: today the relay mints strictly once (`needs_token` only). A
    // relay whose certs emptyDir/PVC is fresh-or-lost still holds a populated —
    // but SPENT — token Secret, so no fresh token is ever minted and the enroll
    // init-container fails forever. The mint decision must mirror the gateway:
    //   should_mint_token(identity_persisted, token_secret)
    //       == !identity_persisted || needs_token(token_secret)
    let mut data = BTreeMap::new();
    data.insert("token".to_string(), ByteString(b"wiremesh://spent".to_vec()));
    let populated = Secret { data: Some(data), ..Default::default() };

    assert!(
        should_mint_token(false, Some(&populated)),
        "identity NOT persisted + stale populated token → re-mint (this is the wedge-killer)"
    );
    assert!(
        !should_mint_token(true, Some(&populated)),
        "identity persisted + populated token → no re-mint (steady state; tokens stay single-mint)"
    );
    assert!(should_mint_token(true, None), "no token secret → mint even if identity persisted");
    assert!(should_mint_token(false, None), "no token secret + not persisted → mint");
    let empty = Secret::default();
    assert!(should_mint_token(true, Some(&empty)), "token secret without token key → mint");
}
