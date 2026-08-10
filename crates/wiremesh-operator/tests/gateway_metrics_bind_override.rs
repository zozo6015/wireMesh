//! FAILING tests (test-author round, Backlog 2b, piece 1/4) — `metricsBind`.
//! **compile-RED until the spec field + validator exist.**
//!
//! # Why
//!
//! Upstream `Container.args` is `x-kubernetes-list-type: atomic` (unlike `env`,
//! which is a `list-map-keys: [name]` merge) — there is no per-element survival
//! under SSA, so the gateway's `--metrics 0.0.0.0:9090` is hand-clobbered
//! wholesale on every reconcile and today has no override. This file pins ONE
//! new typed field, `metricsBind`, that makes it configurable.
//!
//! # Pinned implementer surface
//!
//! `crd::WiremeshGatewaySpec` gains one optional override (camelCase serde,
//! omitted when unset — parity with `observeEndpoint`/`syncEndpoint`, suggested
//! placement immediately after `sync_endpoint`):
//! ```ignore
//! pub metrics_bind: Option<String>,  // serializes "metricsBind"
//! ```
//! `workloads::gateway_deployment` keeps its signature (infallible, returns
//! `Deployment` — NOT `Result`, exactly like today) but the MAIN container's
//! `--metrics` arg must carry `spec.metrics_bind.as_deref().unwrap_or("0.0.0.0:9090")`
//! (that literal is today's unconditional default at `workloads.rs:619` —
//! verified against current HEAD, unchanged by this work). The ENROLL
//! init-container never had a `--metrics` arg and must not gain one.
//!
//! A NEW validator, `workloads::validate_bind_target(&str) -> anyhow::Result<()>`,
//! is required — **`validate_dial_target` must NOT be reused** for a bind
//! address. Three concrete divergences, each verified against the actual code
//! this round (not assumed):
//!
//! 1. `validate_dial_target` ACCEPTS DNS hostnames (dial targets re-resolve at
//!    connect time). A bind address never resolves anything — the gateway's
//!    `--metrics` flag parses the value as a literal `std::net::SocketAddr`
//!    (`crates/wiremesh-gateway/src/config.rs:74`, `.parse()` with the target
//!    type inferred from `metrics_addr: SocketAddr`), so a hostname there is
//!    rejected AT BOOT (`parse_metrics_still_requires_socket_addr_literal`,
//!    `config.rs:194`, asserts exactly this for `"localhost:9100"`) —
//!    CrashLoopBackOff if the operator ever waved one through.
//! 2. `validate_dial_target` REJECTS port `0`. Port 0 is legitimate for a BIND
//!    address (OS-assigned) and is in fact the gateway's own historical
//!    `--metrics`-absent default (`config.rs:87`,
//!    `SocketAddr::from(([127,0,0,1], 0))`) — rejecting it here would strand a
//!    legitimate config `validate_dial_target` was never designed to allow.
//! 3. **Correction to the backlog text, verified against `config.rs` and
//!    ratified by the owner (2026-08-10):** the backlog says the
//!    intended-but-wrong validator "rejects `[::]:9090` and every other IPv6
//!    form" and concludes `metricsBind` therefore "inherits an IPv4-only bind
//!    constraint whichever validator is written." That inheritance is NOT
//!    true of the raw binary: `--metrics` parses via plain
//!    `SocketAddr::from_str`, which DOES accept bracketed IPv6 literals
//!    (`[::1]:9090` parses to a valid `SocketAddr::V6` — nothing in
//!    `GatewayConfig::parse` rejects it, unlike `validate_host_port`, which
//!    has an explicit IPv6 rejection branch that guards ONLY
//!    `--controller-sync`/`--observe`, `config.rs:63,68` — `--metrics` never
//!    goes through it). **Owner decision: `validate_bind_target` MUST ACCEPT
//!    IPv6.** A metrics bind is a LOCAL observability socket, not a fabric
//!    address — the project's IPv4-only rule governs dial targets and
//!    WireGuard endpoints (exactly what `validate_host_port` covers), and its
//!    absence on `--metrics` is a deliberate binary design choice, not an
//!    oversight. Rejecting IPv6 here would make the operator STRICTER than
//!    the binary for no binary-side reason, stranding a legitimate config —
//!    `[::]:9090` on a dual-stack cluster is a reasonable thing to want. Do
//!    NOT "restore consistency" with `validate_host_port` by tightening this
//!    later; the two validators guard different classes of address on
//!    purpose.
//!
//! **No `extraArgs` field.** The gateway's arg parser is last-wins
//! (`GatewayConfig::parse`, `config.rs:58`), so an appended generic list could
//! silently override `--state-dir`, destroying PVC identity and forcing a
//! re-enroll against a spent single-use token. `spec_key_set_has_no_extra_args_field`
//! below is a trip wire (not a proof — JSON key enumeration, not a type-system
//! guarantee) so that field's absence stays a conscious choice on every future
//! touch of this struct.
//!
//! # What this file does NOT prove
//!
//! Fail-closed reconciler validation (mirroring `apply_gateway`'s existing
//! `observeEndpoint`/`syncEndpoint` loop, `controllers/gateway.rs:299-313`,
//! which runs `workloads::validate_dial_target` BEFORE any mint/PVC/Deployment
//! side effect) is NOT exercised here: that loop is inline in `apply_gateway`,
//! an `async fn` taking a live `Context` (kube `Client`) with no fake in this
//! crate — same limitation the relay's analogous file documents
//! (`relay_controller_endpoint_override.rs`). It is a code-review invariant:
//! add `("metricsBind", gw.spec.metrics_bind.as_deref())` as a THIRD tuple in
//! that same loop, calling the new `validate_bind_target` (not
//! `validate_dial_target`). What CAN be pinned at this level is the flip side
//! — the pure builder must NOT also validate, which would create two
//! validation sites for one value (`gateway_deployment_does_not_validate_metrics_bind_itself`).

use wiremesh_operator::crd::{WiremeshGateway, WiremeshGatewaySpec};
use wiremesh_operator::workloads::{gateway_deployment, validate_bind_target};

const CLUSTER_SYNC: &str = "10.43.0.10:9500";
const CLUSTER_ENROLL: &str = "10.43.0.10:9400";
const CLUSTER_OBSERVE: &str = "10.43.0.10:9600";

/// Today's unconditional `--metrics` literal (`workloads.rs:619`), pinned as a
/// constant so a future accidental change to the default shows up as an
/// explicit diff against this file, not a silently-updated string.
const TODAY_DEFAULT_METRICS_BIND: &str = "0.0.0.0:9090";

fn spec(metrics_bind: Option<String>) -> WiremeshGatewaySpec {
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
        metrics_bind,
    }
}

fn pod_of(s: WiremeshGatewaySpec) -> k8s_openapi::api::core::v1::PodSpec {
    let gw = WiremeshGateway::new("gw-home", s);
    // `gateway_deployment` returns `Deployment` directly (infallible) today —
    // NOT `Result`. This must stay true: validation belongs to the reconciler
    // alone (see module docs).
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
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
}

// ---------------------------------------------------------------------------
// 1. Round-trip: the field flows into the gateway container's --metrics arg.
// ---------------------------------------------------------------------------

#[test]
fn metrics_bind_override_flows_into_gateway_arg() {
    let pod = pod_of(spec(Some("10.0.9.9:9191".into())));
    let main = pod.containers.iter().find(|c| c.name == "gateway").expect("gateway container");
    let args = main.args.as_ref().expect("gateway args");
    assert_eq!(
        arg_after(args, "--metrics").as_deref(),
        Some("10.0.9.9:9191"),
        "metricsBind override must replace the hardcoded 0.0.0.0:9090 --metrics target: {args:?}"
    );
}

// ---------------------------------------------------------------------------
// 2. Absent field keeps today's default, verbatim.
// ---------------------------------------------------------------------------

#[test]
fn absent_metrics_bind_keeps_todays_default_unchanged() {
    let pod = pod_of(spec(None));
    let main = pod.containers.iter().find(|c| c.name == "gateway").expect("gateway container");
    let args = main.args.as_ref().expect("gateway args");
    assert_eq!(
        arg_after(args, "--metrics").as_deref(),
        Some(TODAY_DEFAULT_METRICS_BIND),
        "no override must leave today's hardcoded --metrics default unchanged: {args:?}"
    );
}

// ---------------------------------------------------------------------------
// 3. Serde surface: camelCase, omitted when unset, legacy CR still parses.
// ---------------------------------------------------------------------------

#[test]
fn metrics_bind_serializes_camel_case_and_omits_when_unset() {
    let v = serde_json::to_value(spec(Some("10.0.9.9:9191".into()))).unwrap();
    assert_eq!(
        v.get("metricsBind").and_then(|x| x.as_str()),
        Some("10.0.9.9:9191"),
        "metrics_bind must serialize as metricsBind"
    );

    let bare = serde_json::to_value(spec(None)).unwrap();
    assert!(bare.get("metricsBind").is_none(), "metricsBind omitted when unset");

    // A legacy CR without the field still deserializes (additive change —
    // required for crd_manifest_freshness.rs's no-conversion-webhook,
    // no-storage-migration story to hold).
    let legacy: WiremeshGatewaySpec =
        serde_json::from_value(serde_json::json!({ "segmentRef": "home" }))
            .expect("legacy gateway CR (no metricsBind) must still deserialize");
    assert!(legacy.metrics_bind.is_none());
}

// ---------------------------------------------------------------------------
// 4. Scope: the enroll init-container never had --metrics and must not gain
//    one via this override.
// ---------------------------------------------------------------------------

#[test]
fn enroll_init_container_is_never_affected_by_metrics_bind() {
    let pod = pod_of(spec(Some("10.0.9.9:9191".into())));
    let enroll = pod
        .init_containers
        .as_ref()
        .unwrap()
        .iter()
        .find(|c| c.name == "enroll")
        .expect("enroll init container");
    let args = enroll.args.as_ref().unwrap();
    assert!(
        !args.iter().any(|a| a == "--metrics"),
        "metricsBind must never leak into the enroll init-container's argv \
         (it has no --metrics flag today and must not gain one): {args:?}"
    );
}

// ---------------------------------------------------------------------------
// 5. The pure builder must NOT validate metricsBind — two validation sites
//    for one value is the defect the module docs call out. Mirrors
//    relay_controller_endpoint_override.rs's
//    `relay_deployment_does_not_validate_controller_endpoint_itself`.
// ---------------------------------------------------------------------------

#[test]
fn gateway_deployment_does_not_validate_metrics_bind_itself() {
    let pod = pod_of(spec(Some("not a bind target; rm -rf /".into())));
    let main = pod.containers.iter().find(|c| c.name == "gateway").unwrap();
    let args = main.args.as_ref().unwrap();
    assert_eq!(
        arg_after(args, "--metrics").as_deref(),
        Some("not a bind target; rm -rf /"),
        "verbatim passthrough as a single argv element — no shell, no \
         validation-mangling. Rejection belongs SOLELY to the reconciler's \
         fail-closed loop (mirror apply_gateway's observeEndpoint/syncEndpoint \
         validation, using the NEW validate_bind_target — never duplicated in \
         the builder): {args:?}"
    );
}

// ---------------------------------------------------------------------------
// 6. No extraArgs. Trip wire, not a proof: enumerates the full serialized key
//    set so a future field addition (extraArgs or otherwise) is a conscious,
//    visible diff against this pin rather than a silent addition.
// ---------------------------------------------------------------------------

#[test]
fn spec_key_set_has_no_extra_args_field() {
    let full = WiremeshGatewaySpec {
        segment_ref: "home".into(),
        node_name: Some("node-1".into()),
        node_selector: Some(std::collections::BTreeMap::new()),
        wg_port: Some(51820),
        tun: Some("wg0".into()),
        image: Some("img".into()),
        storage_class: Some("fast".into()),
        storage_size: Some("1Gi".into()),
        observe_endpoint: Some("10.0.0.1:9600".into()),
        sync_endpoint: Some("10.0.0.1:9500".into()),
        metrics_bind: Some("10.0.0.1:9090".into()),
    };
    let v = serde_json::to_value(&full).unwrap();
    let keys: std::collections::BTreeSet<String> =
        v.as_object().unwrap().keys().cloned().collect();
    let expected: std::collections::BTreeSet<String> = [
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
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(
        keys, expected,
        "WiremeshGatewaySpec's serialized key set changed. If this added \
         `extraArgs`: DO NOT — backlog 2b is explicit that a generic args \
         passthrough is unsafe (the gateway's arg parser is last-wins, so an \
         appended list could silently override --state-dir, destroying PVC \
         identity and forcing a re-enroll against a spent single-use token). \
         Any other new field: update this pin deliberately."
    );
}

// ---------------------------------------------------------------------------
// 7. validate_bind_target's accept/reject set. See the module docs for the
//    verified divergence from validate_dial_target and from the raw binary.
// ---------------------------------------------------------------------------

#[test]
fn validate_bind_target_accepts_port_zero() {
    // Legitimate bind address (OS-assigned port) — and the gateway's own
    // --metrics-absent historical default (config.rs:87). The binary accepts
    // it; the validator must not strand it.
    assert!(
        validate_bind_target("127.0.0.1:0").is_ok(),
        "port 0 is a legitimate bind address and must not be rejected"
    );
}

#[test]
fn validate_bind_target_accepts_ipv4_literals() {
    assert!(validate_bind_target("0.0.0.0:9090").is_ok());
    assert!(validate_bind_target("10.0.0.5:9100").is_ok());
    assert!(validate_bind_target("127.0.0.1:9090").is_ok());
}

#[test]
fn validate_bind_target_accepts_ipv6_forms() {
    // Owner decision (2026-08-10, see module docs point 3): a metrics bind is
    // a LOCAL observability socket, not a fabric address — the project's
    // IPv4-only rule governs dial targets / WireGuard endpoints
    // (`validate_host_port`'s job), not this. The binary's raw
    // `SocketAddr::from_str` parse already accepts these (nothing in
    // `GatewayConfig::parse` rejects IPv6 for `--metrics`), so a validator
    // that rejected them here would be STRICTER than the binary for no
    // binary-side reason and strand a legitimate `[::]:9090` dual-stack
    // config. Do NOT "restore consistency" with `validate_host_port` by
    // tightening this later — the two validators guard different classes of
    // address on purpose.
    for good in ["[::]:9090", "[::1]:9100"] {
        assert!(
            validate_bind_target(good).is_ok(),
            "IPv6 bind target {good:?} must be ACCEPTED — the binary itself \
             accepts it, and a metrics bind is a local socket, not a fabric \
             dial target"
        );
    }
}

#[test]
fn validate_bind_target_rejects_dns_names() {
    // The binary's --metrics parse requires a literal SocketAddr
    // (config.rs:74) — a hostname here is a boot-time CrashLoopBackOff.
    for bad in ["localhost:9100", "example.com:9090"] {
        assert!(
            validate_bind_target(bad).is_err(),
            "DNS name {bad:?} must be rejected — the gateway's --metrics flag \
             requires a literal SocketAddr and rejects hostnames at boot \
             (config.rs parse_metrics_still_requires_socket_addr_literal)"
        );
    }
}

#[test]
fn validate_bind_target_rejects_bare_or_missing_port() {
    assert!(validate_bind_target("9090").is_err(), "a bare port with no host must be rejected");
    assert!(validate_bind_target("0.0.0.0").is_err(), "a host with no port must be rejected");
}
