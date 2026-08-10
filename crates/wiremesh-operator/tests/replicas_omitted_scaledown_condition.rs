//! Backlog 2b, piece 3 (`replicas`) + piece 4 (the gateway misreport / the
//! "Unfiled gap" bullet). **Two different maturity levels in one file:**
//! piece 3's builder assertions are RED today and mechanically checkable;
//! piece 4's readiness/condition truth table is NOT unit-testable in this
//! crate at all (see "What this file does NOT prove" below) and is pinned
//! here only as a documented code-review invariant.
//!
//! # Piece 3 — omit `replicas` unconditionally, no CRD field
//!
//! `replicas: Some(1)` is force-applied by all three workload builders
//! (`controller_deployment` at `workloads.rs:494`, `gateway_deployment` at
//! `workloads.rs:734`, `relay_deployment` at `workloads.rs:928` — verified
//! against current HEAD, after the concurrent `metricsBind` landing, all
//! three still `Some(1)` as of this file), so
//! `kubectl scale --replicas=0` reverts on the very next reconcile. The fix
//! per the backlog is to **omit the field unconditionally — no CRD field.**
//! A field would still be force-applied under SSA (moving the knob, not
//! fixing it) and would advertise a capability the workloads don't actually
//! support safely on their own (hostNetwork, a fixed WG port, an RWO PVC,
//! `Recreate` chosen specifically so a second pod never surges — see
//! `recreate_strategy`'s doc comment).
//!
//! ## What the upgrade itself does (REASONED, NOT VERIFIED — it can't be
//! ## exercised without a live apiserver)
//!
//! `DeploymentSpec.replicas` is a nullable `int32`: *"a pointer to
//! distinguish between explicit zero and not specified. Defaults to 1."*
//! The obvious worry when rolling out the omitting build is: SSA drops the
//! field, the API-server defaulter re-sets `1`, and a Deployment a human had
//! deliberately scaled to 0 comes back up. We believe it does NOT, because
//! **SSA can only REMOVE a field the applying manager currently owns** —
//! dropping a field from the apply body releases the claim, it does not
//! order a deletion, and the removal only follows if that claim was the last
//! one. The three reachable cases:
//!
//! 1. **Operator running, steady state** — it owns `replicas: 1`, so the new
//!    build's apply does remove it and the defaulter re-sets `1`. `1 → 1`,
//!    nothing observable.
//! 2. **Operator running, human scales to 0** — today's build force-reasserts
//!    `1` on the next reconcile (the very bug piece 3 fixes), so this state
//!    cannot survive to meet the upgrade.
//! 3. **Operator down, human scales to 0** — `kubectl scale` is a non-apply
//!    Update against the `scale` subresource, so ownership of
//!    `spec.replicas` TRANSFERS to the `kubectl-scale` field manager and
//!    leaves the operator's managed-fields entry. The new build then applies
//!    without `replicas` owning nothing → nothing is removed → **the
//!    Deployment stays at 0.**
//!
//! Case 3 is the only route by which a pre-upgrade scale-to-0 reaches the new
//! build, and it is exactly the case where the field is not removed — so the
//! upgrade should be a no-op for scaled-down workloads.
//!
//! **Not confirmed against a real apiserver.** SSA ownership semantics are
//! subtle (subresource-vs-resource ownership; what a force-apply that omits a
//! field does to a co-owner's entry). Someone should apply the new build over
//! a Deployment scaled to 0 by a stopped operator and check `replicas`
//! afterwards before this is relied on operationally. It is stated here as
//! reasoning, not as a tested guarantee — mirrored on `released_replicas` in
//! `workloads.rs`.
//!
//! # Piece 4 — the gateway misreport (owner decision: IN SCOPE)
//!
//! Gateway readiness is roster-based, not Deployment-based:
//! `controllers::gateway::apply_gateway` computes `enrolled =
//! row.is_some()` from the controller's gateway roster
//! (`controllers/gateway.rs:637`) and never reads the gateway Deployment's
//! status at all. So once scaling a gateway to 0 is possible (piece 3), a
//! gateway a human deliberately took down keeps reporting `Enrolled: True`
//! off a still-active roster row — the CR silently claims a live data plane
//! that is dead.
//!
//! **`Enrolled` must NOT change meaning.** The gateway genuinely IS
//! enrolled — the roster row is real, and conflating a control-plane fact
//! (enrollment) with a data-plane fact (liveness) would corrupt a signal
//! that is currently trustworthy. The fix is a SEPARATE `ScaledDown`
//! condition, so the CR can say both true things at once: enrolled, and
//! scaled down.
//!
//! # Why omitting `replicas` needs a `ScaledDown` condition at all
//!
//! Two reconcilers read `available_replicas` (verified as the *only* two
//! read sites, this round, via `git grep -n available_replicas`):
//!
//! - `controllers::controller::reconcile` (`controller.rs:61-65`):
//!   `live.status.and_then(|s| s.available_replicas).unwrap_or(0) >= 1`
//!   drives `status.ready`, the `Ready` condition
//!   (`AllComponentsReady`/`WaitingForController`), and a 300s-vs-10s
//!   requeue.
//! - `controllers::relay::reconcile` (`relay.rs:217`): the identical
//!   expression drives `status.applied`, the message `"relay deployed"` vs
//!   `"relay pod starting"`, and a 300s-vs-15s requeue.
//!
//! Once `replicas` can legitimately be `0`, a deliberately-scaled-down
//! workload becomes bit-for-bit indistinguishable from a permanently-starting
//! one under this expression: `available_replicas` is `0` either way. Left
//! alone, that means a scaled-down `WiremeshController`/`WiremeshRelay`
//! reports not-ready **forever** and requeues every 10s/15s in a hot loop
//! that can never resolve — which is arguably worse than today's
//! can't-scale-down bug, not a fix for it. The reconcilers must read the
//! DESIRED count (`live.spec.replicas`) alongside the available one and emit
//! a `ScaledDown` condition when desired is `Some(0)`.
//!
//! ## The required truth table (pin this by code review — see below)
//!
//! | `live.spec.replicas` (desired) | `available_replicas` | Outcome |
//! |---|---|---|
//! | `None` (omitted) or `Some(n>=1)` | `>= 1` | ready/applied = true; `Ready`/no-ScaledDown |
//! | `Some(0)` | `0` (always, nothing can become available) | ready/applied = **false**, but reported as `ScaledDown` — NOT `WaitingForController`/"pod starting"; requeue need not stay on the fast 10s/15s cadence forever the way a genuine stall does |
//! | `None` (omitted) or `Some(n>=1)` | `0` | genuinely starting: ready/applied = false, `WaitingForController`/"relay pod starting", fast requeue is correct |
//!
//! `None` (the omitted-field steady state this backlog item produces) MUST
//! be treated the same as `Some(n>=1)` — it means "server-side default of 1",
//! never "scaled down". Only an explicit `Some(0)` is a scale-down.
//!
//! # What this file does NOT prove
//!
//! The truth table above lives ENTIRELY inline in `async fn reconcile(...)`
//! in `controller.rs` and `relay.rs` — both take a live kube `Client`
//! (`Api::<Deployment>::namespaced(...).get(...)`) with no fake apiserver in
//! this crate, the identical limitation `relay_controller_endpoint_override.rs`
//! and `gateway_metrics_bind_override.rs` both already document for their own
//! reconciler-side invariants. Unlike `should_mint_token`/`identity_persisted`/
//! `needs_rebind`/`adoption_needs_stale_drain` in `controllers/gateway.rs` —
//! which the SAME reconciler-testability problem was solved for by extracting
//! them as free `pub fn`s taking plain values — no such extraction exists yet
//! for the ready/desired-replicas computation in `controller.rs` or
//! `relay.rs`, nor for the `Enrolled`/condition block in `apply_gateway`
//! (`gateway.rs:637-650`, also fully inline). **This file does not invent a
//! fake reconcile harness to work around that.** Implementing piece 4
//! following that established extraction pattern (e.g. a pure
//! `fn workload_readiness(desired: Option<i32>, available: i32) -> Readiness`
//! shared by `controller.rs`/`relay.rs`) would make the truth table above
//! mechanically pinnable the same way `mint_action`/`adoption_needs_stale_drain`
//! already are in `gateway.rs` — noted here as a design suggestion, not
//! performed, since this file is tests-only and does not touch `src/`.
//!
//! ## A design gap the backlog text did not flag: `WiremeshRelay` has nowhere
//! ## to put a `ScaledDown` condition today
//!
//! `WiremeshController`'s status (`WiremeshControllerStatus`) and
//! `WiremeshGateway`'s status (`WiremeshGatewayStatus`) both already carry a
//! `conditions: Vec<Condition>` field. **`WiremeshRelay`'s status
//! (`WiremeshResourceStatus`) does not** — it has only `applied`,
//! `applied_version`, `message` (`crd.rs:26-33`), and that same type is
//! shared verbatim by `WiremeshSegment` and `WiremeshPolicy`. Landing a
//! `ScaledDown` *condition* on the relay (as the backlog's piece 3 bullet
//! asks for, "on `WiremeshController` and `WiremeshRelay` only") therefore
//! requires a status-shape decision that isn't made yet: either add
//! `conditions: Vec<Condition>` to the shared `WiremeshResourceStatus` (a
//! no-op for Segment/Policy, which would just carry an always-empty vec), or
//! give `WiremeshRelay` a dedicated status type. Flagging this for whoever
//! implements piece 4 — it is a real decision point, not a typo in this file.
//!
//! # What IS pinned below
//!
//! 1. The three builders really do force `replicas: Some(1)` today (RED
//!    tests 1-3 — they assert `None` and fail against current HEAD).
//! 2. `deployment_apply_body`'s JSON apply body — the thing that actually
//!    goes over the wire via SSA — genuinely OMITS the `replicas` key (not
//!    `"replicas": null`) once the builders are fixed; an explicit `null`
//!    and an omitted key both happen to release SSA ownership for a scalar
//!    field, but only omission matches what `deployment_apply_body`'s own
//!    doc comment describes it doing elsewhere (the `rollingUpdate` null
//!    injection is the one deliberate exception, and it is scoped to
//!    `strategy` only — `replicas` must not grow a similar special case).
//! 3. A trip wire that no `replicas`-shaped field (`replicas`, `scale`,
//!    `replicaCount`, `desiredReplicas`, ...) was added to any of the three
//!    CRD spec types — green today, and it stays green after the fix, since
//!    the backlog is explicit that a field would be the wrong fix. It pins
//!    each type's EXACT serialized key set off a FULLY POPULATED spec, which
//!    is what makes it capable of seeing an `Option` field at all (see the
//!    comment on section 5).

use wiremesh_operator::crd::{
    WiremeshControllerSpec, WiremeshGateway, WiremeshGatewaySpec, WiremeshRelay, WiremeshRelaySpec,
};
use wiremesh_operator::workloads::{
    controller_deployment, deployment_apply_body, gateway_deployment, relay_deployment,
};

const CLUSTER_SYNC: &str = "10.43.0.10:9500";
const CLUSTER_ENROLL: &str = "10.43.0.10:9400";
const CLUSTER_OBSERVE: &str = "10.43.0.10:9600";

fn ctrl_spec() -> WiremeshControllerSpec {
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

/// Every field of `WiremeshGatewaySpec` spelled out — mirrors the concurrent
/// `gateway_metrics_bind_override.rs`'s `spec()` helper. `metrics_bind`
/// landed on `crd::WiremeshGatewaySpec` during this same round (concurrent
/// work, verified present as of this file); included here as a plain `None`
/// since it's orthogonal to `replicas`.
fn gw_spec() -> WiremeshGatewaySpec {
    WiremeshGatewaySpec {
        segment_ref: "home".into(),
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
    }
}

fn relay_spec() -> WiremeshRelaySpec {
    WiremeshRelaySpec {
        endpoint: "203.0.113.9:4443".into(),
        node_name: None,
        image: None,
        storage_class: None,
        storage_size: None,
        controller_endpoint: None,
    }
}

// ---------------------------------------------------------------------------
// 1-3. RED: all three builders force `replicas: Some(1)` today. Each asserts
//      the fixed contract (`None`) and therefore fails against current HEAD —
//      the failure IS the finding: proof the force-clobber described in the
//      backlog is real, not hypothetical.
// ---------------------------------------------------------------------------

#[test]
fn controller_deployment_omits_replicas() {
    let spec = ctrl_spec();
    let d = controller_deployment("wm", &spec, "ghcr.io/x/wiremesh-operator:test");
    assert_eq!(
        d.spec.unwrap().replicas,
        None,
        "controller_deployment must OMIT spec.replicas (not force Some(1)) so \
         `kubectl scale --replicas=0` on the controller survives reconcile; a \
         typed Some(1) is force-applied under SSA and reverts any manual \
         scale-down on the very next pass (Backlog 2b piece 3)"
    );
}

#[test]
fn gateway_deployment_omits_replicas() {
    let gw = WiremeshGateway::new("gw-home", gw_spec());
    let d = gateway_deployment(
        &gw,
        CLUSTER_SYNC,
        CLUSTER_ENROLL,
        CLUSTER_OBSERVE,
        "wm-ca",
        "gw-home-token",
        &["10.0.125.0/24".to_string()],
    );
    assert_eq!(
        d.spec.unwrap().replicas,
        None,
        "gateway_deployment must OMIT spec.replicas (not force Some(1)) — same \
         force-clobber as the controller, and the gateway is the workload this \
         backlog item is actually motivated by (Backlog 2b piece 3)"
    );
}

#[test]
fn relay_deployment_omits_replicas() {
    let r = WiremeshRelay::new("relay-eu", relay_spec());
    let d = relay_deployment(&r, CLUSTER_SYNC, CLUSTER_ENROLL, "wm-ca", "relay-eu-token")
        .expect("relay_deployment must succeed for a well-formed spec");
    assert_eq!(
        d.spec.unwrap().replicas,
        None,
        "relay_deployment must OMIT spec.replicas (not force Some(1)) — same \
         force-clobber as the other two workloads (Backlog 2b piece 3)"
    );
}

// ---------------------------------------------------------------------------
// 4. RED: the JSON that actually crosses the wire under SSA must OMIT the
//    "replicas" key entirely (not serialize an explicit null) for all three
//    workloads, once the builders are fixed. `deployment_apply_body` already
//    performs one deliberate null-injection (clearing `rollingUpdate` under
//    `Recreate`) — this test guards that `replicas` does not silently need or
//    grow a second one.
// ---------------------------------------------------------------------------

#[test]
fn deployment_apply_body_omits_replicas_key_for_all_three_workloads() {
    let ctrl = controller_deployment("wm", &ctrl_spec(), "ghcr.io/x/wiremesh-operator:test");
    let gw_dep = gateway_deployment(
        &WiremeshGateway::new("gw-home", gw_spec()),
        CLUSTER_SYNC,
        CLUSTER_ENROLL,
        CLUSTER_OBSERVE,
        "wm-ca",
        "gw-home-token",
        &["10.0.125.0/24".to_string()],
    );
    let relay_dep = relay_deployment(
        &WiremeshRelay::new("relay-eu", relay_spec()),
        CLUSTER_SYNC,
        CLUSTER_ENROLL,
        "wm-ca",
        "relay-eu-token",
    )
    .expect("relay_deployment must succeed for a well-formed spec");

    for (label, dep) in [("controller", &ctrl), ("gateway", &gw_dep), ("relay", &relay_dep)] {
        let body = deployment_apply_body(dep);
        let spec_obj = body.get("spec").and_then(|s| s.as_object()).unwrap_or_else(|| {
            panic!("{label}: apply body has no spec object: {body}")
        });
        assert!(
            !spec_obj.contains_key("replicas"),
            "{label}: deployment_apply_body's JSON must OMIT the \"replicas\" \
             key (present-but-null and omitted both release SSA ownership for \
             a scalar field, but omission is what the rest of this codebase's \
             apply-body contract does everywhere except the one documented \
             `rollingUpdate` exception) — got: {spec_obj:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// 5. Green-on-arrival guard: no replicas-shaped field was added to any of the
//    three CRD spec types. The backlog is explicit that a field would still
//    be force-applied (moving the knob, not fixing it) and would advertise a
//    capability (hostNetwork + fixed WG port + RWO PVC + Recreate strategy)
//    that does not actually support arbitrary replica counts — trip wire, not
//    a proof, same idiom as `spec_key_set_has_no_extra_args_field` in the
//    concurrent `gateway_metrics_bind_override.rs`.
//
//    WHY the specs below are FULLY POPULATED and not the `ctrl_spec()`/
//    `gw_spec()`/`relay_spec()` helpers used by tests 1-4: every optional CRD
//    field carries `#[serde(default, skip_serializing_if = "Option::is_none")]`,
//    so an all-`None` spec serializes to just its required fields
//    (`gw_spec()` → `{"segmentRef":"home"}`). A `pub replicas: Option<i32>`
//    added in the house style — by far the most likely form of the mistake
//    this guards against — would then serialize to NOTHING and leave the
//    guard green. Only a non-`Option` field could ever trip it. Populating
//    every field makes any addition visible in the key set regardless of its
//    type, which is the whole point of the trip wire.
// ---------------------------------------------------------------------------

/// Every `WiremeshControllerSpec` field `Some`, so the serialized key set is
/// the type's FULL surface. Values are arbitrary-but-valid; only key presence
/// matters here.
fn full_ctrl_spec() -> WiremeshControllerSpec {
    WiremeshControllerSpec {
        image: Some("ghcr.io/x/wiremesh-controller:test".into()),
        storage_class: Some("fast".into()),
        storage_size: Some("1Gi".into()),
        admin_tcp_port: Some(9300),
        sync_tcp_port: Some(9500),
        observe_udp_port: Some(9600),
        rotation_interval: Some("off".into()),
    }
}

/// Every `WiremeshGatewaySpec` field `Some` — same construction as
/// `spec_key_set_has_no_extra_args_field` in `gateway_metrics_bind_override.rs`.
fn full_gw_spec() -> WiremeshGatewaySpec {
    WiremeshGatewaySpec {
        segment_ref: "home".into(),
        node_name: Some("node-1".into()),
        node_selector: Some(std::collections::BTreeMap::new()),
        wg_port: Some(51820),
        tun: Some("wg0".into()),
        image: Some("ghcr.io/x/wiremesh-gateway:test".into()),
        storage_class: Some("fast".into()),
        storage_size: Some("1Gi".into()),
        observe_endpoint: Some("10.0.0.1:9600".into()),
        sync_endpoint: Some("10.0.0.1:9500".into()),
        metrics_bind: Some("10.0.0.1:9090".into()),
    }
}

/// Every `WiremeshRelaySpec` field `Some`.
fn full_relay_spec() -> WiremeshRelaySpec {
    WiremeshRelaySpec {
        endpoint: "203.0.113.9:4443".into(),
        node_name: Some("node-1".into()),
        image: Some("ghcr.io/x/wiremesh-relay:test".into()),
        storage_class: Some("fast".into()),
        storage_size: Some("1Gi".into()),
        controller_endpoint: Some("10.0.0.1:9500".into()),
    }
}

#[test]
fn no_replicas_shaped_field_on_controller_spec() {
    assert_spec_key_set(
        &serde_json::to_value(full_ctrl_spec()).unwrap(),
        "WiremeshControllerSpec",
        &[
            "image",
            "storageClass",
            "storageSize",
            "adminTcpPort",
            "syncTcpPort",
            "observeUdpPort",
            "rotationInterval",
        ],
    );
}

#[test]
fn no_replicas_shaped_field_on_gateway_spec() {
    assert_spec_key_set(
        &serde_json::to_value(full_gw_spec()).unwrap(),
        "WiremeshGatewaySpec",
        &[
            "segmentRef",
            "nodeName",
            "nodeSelector",
            "wgPort",
            "tun",
            "image",
            "storageClass",
            "storageSize",
            "observeEndpoint",
            "syncEndpoint",
            "metricsBind",
        ],
    );
}

#[test]
fn no_replicas_shaped_field_on_relay_spec() {
    assert_spec_key_set(
        &serde_json::to_value(full_relay_spec()).unwrap(),
        "WiremeshRelaySpec",
        &["endpoint", "nodeName", "image", "storageClass", "storageSize", "controllerEndpoint"],
    );
}

/// Pin `type_name`'s EXACT serialized key set — and, for a replicas-shaped
/// addition specifically, say why that one is forbidden.
///
/// The exact-set assertion is the strong property: it catches ANY new field,
/// whatever it is named, and it can only do so because the caller's spec is
/// fully populated (see the section comment above). The `replica`/`scale` scan
/// runs FIRST purely so it wins the failure message — an exact-set mismatch
/// tells you a field appeared, not why THIS particular field is the one
/// Backlog 2b rules out.
fn assert_spec_key_set(v: &serde_json::Value, type_name: &str, expected: &[&str]) {
    let keys: std::collections::BTreeSet<String> =
        v.as_object().unwrap().keys().cloned().collect();

    for k in &keys {
        let lower = k.to_lowercase();
        assert!(
            !lower.contains("replica") && !lower.contains("scale"),
            "{type_name} gained a replicas-shaped field ({k:?}) — Backlog 2b is \
             explicit that `replicas` must be OMITTED UNCONDITIONALLY with NO \
             CRD field; a field is not the fix, it moves the force-clobber \
             instead of removing it, and advertises a scaling capability these \
             workloads (hostNetwork, fixed WG port, RWO PVC, Recreate strategy) \
             don't actually support. Full key set: {keys:?}"
        );
    }

    let expected: std::collections::BTreeSet<String> =
        expected.iter().copied().map(String::from).collect();
    assert_eq!(
        keys, expected,
        "{type_name}'s serialized key set changed. If this added a scaling \
         knob under a name the scan above doesn't match (`instances`, \
         `podCount`, ...): DO NOT — see Backlog 2b piece 3. Any other new \
         field: populate it in this file's full_*_spec() helper and update \
         this pin deliberately."
    );
}
