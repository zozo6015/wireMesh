//! Backlog 2b (third bullet): closes the coverage gap left by
//! `gateway_endpoint_overrides.rs`'s `enroll_init_container_is_never_overridden`
//! and `relay_controller_endpoint_override.rs`'s
//! `enroll_init_container_is_never_overridden_by_controller_endpoint`. Those
//! two each pin exactly one element (`--controller`) of one enroll
//! init-container's argv. Nothing pinned `--cidr`, `--token-file`, or
//! `--state-dir` on the gateway side, and NOTHING pinned the relay's
//! `wiremesh-relay-enroll` argv at all. This file closes both gaps.
//!
//! # Why this matters (restated, because it is the whole point of the file)
//!
//! Both enroll init-containers' `args` (and `command`) are
//! `x-kubernetes-list-type: atomic` upstream — there is no per-element
//! survival the way there is for `env`. They are also bound to CIDRs
//! (gateway) and an endpoint (relay) that the single-use enrollment token is
//! **cryptographically committed to**. If a future change plumbs a generic
//! override (an `extraArgs`-shaped field, a careless refactor of the
//! endpoint-override wiring, anything) into either enroll argv, the effect
//! is not a config mistake an operator can shrug off — the enroll RPC's
//! `--cidr`/`--endpoint` no longer matches what the token was minted
//! against, the controller rejects it, and the fix is burning a
//! single-use token and re-enrolling. See `workloads::gateway_deployment`'s
//! and `workloads::relay_deployment`'s own doc comments, which describe the
//! same hazard from the builder side.
//!
//! # Status: green by design
//!
//! Like `wiremesh-gateway/tests/uapi_endpoint_validation.rs`, these are
//! CHARACTERIZATION tests of behaviour that already exists and is already
//! correct — there is no bug being reproduced here. They pass against
//! current `main` and are expected to. The point is that until this file
//! existed, nothing would have caught a change that made them fail; each
//! test below says explicitly what production change it exists to catch.
//!
//! # Scope
//!
//! Only the two enroll init-containers' `command`/`args`. The MAIN
//! containers' `--observe`/`--controller-sync`/`--controller` overrides are
//! already covered by `gateway_endpoint_overrides.rs` and
//! `relay_controller_endpoint_override.rs`; this file does not duplicate
//! that.

use wiremesh_operator::crd::{
    WiremeshGateway, WiremeshGatewaySpec, WiremeshRelay, WiremeshRelaySpec,
};
use wiremesh_operator::workloads::{gateway_deployment, relay_deployment};

const CLUSTER_SYNC: &str = "10.43.0.10:9500";
const CLUSTER_ENROLL: &str = "10.43.0.10:9400";
const CLUSTER_OBSERVE: &str = "10.43.0.10:9600";

// Two CIDRs (not one) so the pinned list also proves the `--cidr` repeat-flag
// loop emits one `--cidr <value>` pair per segment CIDR, in order — a single
// CIDR wouldn't distinguish "loops correctly" from "only ever handles the
// first entry".
const CIDRS: [&str; 2] = ["10.0.125.0/24", "10.0.200.0/24"];

const RELAY_ENDPOINT: &str = "203.0.113.9:4443";

// Distinctive override values, deliberately unlike the CLUSTER_* constants
// above, so an override value leaking into the enroll argv cannot be
// mistaken for the correct in-cluster value by accident.
const OVERRIDE_OBSERVE: &str = "10.0.125.45:9600";
const OVERRIDE_SYNC: &str = "wg.zozotk.go.ro:9500";
const OVERRIDE_RELAY_CONTROLLER: &str = "wg.zozotk.go.ro:9500";

fn gw_spec(observe_endpoint: Option<String>, sync_endpoint: Option<String>) -> WiremeshGatewaySpec {
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

fn gw_pod(s: WiremeshGatewaySpec) -> k8s_openapi::api::core::v1::PodSpec {
    let gw = WiremeshGateway::new("gw-home", s);
    let d = gateway_deployment(
        &gw,
        CLUSTER_SYNC,
        CLUSTER_ENROLL,
        CLUSTER_OBSERVE,
        "wm-ca",
        "gw-home-token",
        &CIDRS.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
    );
    d.spec.unwrap().template.spec.unwrap()
}

fn gw_enroll(pod: &k8s_openapi::api::core::v1::PodSpec) -> &k8s_openapi::api::core::v1::Container {
    pod.init_containers
        .as_ref()
        .expect("gateway pod must have init containers")
        .iter()
        .find(|c| c.name == "enroll")
        .expect("gateway enroll init container")
}

fn relay_spec(controller_endpoint: Option<String>) -> WiremeshRelaySpec {
    WiremeshRelaySpec {
        endpoint: RELAY_ENDPOINT.into(),
        node_name: None,
        image: None,
        storage_class: None,
        storage_size: None,
        controller_endpoint,
    }
}

fn relay_pod(s: WiremeshRelaySpec) -> k8s_openapi::api::core::v1::PodSpec {
    let r = WiremeshRelay::new("relay-eu", s);
    let d = relay_deployment(&r, CLUSTER_SYNC, CLUSTER_ENROLL, "wm-ca", "relay-eu-token")
        .expect("relay_deployment must succeed for a well-formed spec");
    d.spec.unwrap().template.spec.unwrap()
}

fn relay_enroll(
    pod: &k8s_openapi::api::core::v1::PodSpec,
) -> &k8s_openapi::api::core::v1::Container {
    pod.init_containers
        .as_ref()
        .expect("relay pod must have init containers")
        .iter()
        .find(|c| c.name == "enroll")
        .expect("relay enroll init container")
}

// ---------------------------------------------------------------------------
// Gateway enroll init-container
// ---------------------------------------------------------------------------

#[test]
fn gateway_enroll_full_arg_list_is_pinned() {
    // Full argv, every element, in order. Enumerated from
    // `workloads::gateway_deployment`'s `enroll_args` construction:
    //   ["enroll",
    //    "--token-file", "/etc/wiremesh-token/token",
    //    "--controller", <controller_enroll>,
    //    "--ca", "/etc/wiremesh-ca/ca.pem",
    //    "--state-dir", <DATA_DIR = "/var/lib/wiremesh">,
    //    "--cidr", <cidr>, ...]  (one --cidr pair per segment CIDR)
    //
    // Breaks on: adding/removing/renaming/reordering any enroll flag,
    // changing the hardcoded `--token-file`/`--ca` paths or the `DATA_DIR`
    // value, or changing the `--cidr` loop's flag or ordering.
    let pod = gw_pod(gw_spec(None, None));
    let enroll = gw_enroll(&pod);
    let args = enroll.args.as_ref().expect("enroll args");

    let expected: Vec<String> = vec![
        "enroll",
        "--token-file",
        "/etc/wiremesh-token/token",
        "--controller",
        CLUSTER_ENROLL,
        "--ca",
        "/etc/wiremesh-ca/ca.pem",
        "--state-dir",
        "/var/lib/wiremesh",
        "--cidr",
        CIDRS[0],
        "--cidr",
        CIDRS[1],
    ]
    .into_iter()
    .map(str::to_string)
    .collect();

    assert_eq!(
        args, &expected,
        "gateway enroll init-container argv drifted from the pinned list: {args:?}"
    );
}

#[test]
fn gateway_enroll_command_is_pinned() {
    // Breaks on: switching the enroll init-container off a direct
    // `["wiremesh-gateway"]` invocation (e.g. wrapping it in `/bin/sh -c`,
    // which would let a CRD value be shell-interpreted — exactly what
    // `enroll_init_containers_use_no_shell` in `workloads.rs` also guards).
    let pod = gw_pod(gw_spec(None, None));
    let enroll = gw_enroll(&pod);
    assert_eq!(
        enroll.command.as_deref(),
        Some(["wiremesh-gateway".to_string()].as_slice()),
        "gateway enroll init-container command must stay exactly [\"wiremesh-gateway\"]"
    );
}

#[test]
fn gateway_enroll_args_and_command_survive_observe_and_sync_overrides() {
    // Breaks on: any change that lets `spec.observe_endpoint` /
    // `spec.sync_endpoint` reach the enroll init-container — those overrides
    // exist for the long-lived observe/sync channels (SNAT/LB topology), not
    // the one-shot enroll RPC, which must keep dialing the in-cluster
    // `controller_enroll` target no matter what the main container's args
    // say. A mismatch here means the enroll `--cidr`s could in principle
    // travel to the wrong controller, or (more subtly) a future refactor
    // that threads the override further than intended could leak it into
    // `--controller` itself, silently redirecting the one-shot enroll RPC
    // for a token the far end never issued.
    let baseline_pod = gw_pod(gw_spec(None, None));
    let baseline_args = gw_enroll(&baseline_pod).args.clone();
    let baseline_command = gw_enroll(&baseline_pod).command.clone();

    let overridden_pod = gw_pod(gw_spec(
        Some(OVERRIDE_OBSERVE.to_string()),
        Some(OVERRIDE_SYNC.to_string()),
    ));
    let overridden_enroll = gw_enroll(&overridden_pod);

    assert_eq!(
        overridden_enroll.args, baseline_args,
        "observeEndpoint/syncEndpoint overrides must not change a single element of the \
         enroll init-container's argv: {:?}",
        overridden_enroll.args
    );
    assert_eq!(
        overridden_enroll.command, baseline_command,
        "observeEndpoint/syncEndpoint overrides must not change the enroll init-container's command: {:?}",
        overridden_enroll.command
    );
}

// ---------------------------------------------------------------------------
// Relay enroll init-container (`wiremesh-relay-enroll`)
// ---------------------------------------------------------------------------

#[test]
fn relay_enroll_full_arg_list_is_pinned() {
    // Full argv, every element, in order. Enumerated from
    // `workloads::relay_deployment`'s enroll `Container`:
    //   ["--token-file", "/etc/wiremesh-token/token",
    //    "--controller", <controller_enroll>,
    //    "--ca", "/etc/wiremesh-ca/ca.pem",
    //    "--certdir", <DATA_DIR = "/var/lib/wiremesh">,
    //    "--endpoint", <spec.endpoint>]
    //
    // Breaks on: adding/removing/renaming/reordering any enroll flag,
    // changing the hardcoded `--token-file`/`--ca` paths or the `--certdir`
    // value, or the `--endpoint` value no longer being the relay's own
    // advertised `spec.endpoint`.
    let pod = relay_pod(relay_spec(None));
    let enroll = relay_enroll(&pod);
    let args = enroll.args.as_ref().expect("enroll args");

    let expected: Vec<String> = vec![
        "--token-file",
        "/etc/wiremesh-token/token",
        "--controller",
        CLUSTER_ENROLL,
        "--ca",
        "/etc/wiremesh-ca/ca.pem",
        "--certdir",
        "/var/lib/wiremesh",
        "--endpoint",
        RELAY_ENDPOINT,
    ]
    .into_iter()
    .map(str::to_string)
    .collect();

    assert_eq!(
        args, &expected,
        "relay enroll init-container (wiremesh-relay-enroll) argv drifted from the pinned list: {args:?}"
    );
}

#[test]
fn relay_enroll_command_is_pinned() {
    // Breaks on: switching the relay enroll init-container off a direct
    // `["wiremesh-relay-enroll"]` invocation (e.g. routing it through a
    // shell), the exact hazard the gateway's `enroll_init_containers_use_no_shell`
    // test already guards on the gateway side — this is that guard's relay
    // counterpart, absent until now.
    let pod = relay_pod(relay_spec(None));
    let enroll = relay_enroll(&pod);
    assert_eq!(
        enroll.command.as_deref(),
        Some(["wiremesh-relay-enroll".to_string()].as_slice()),
        "relay enroll init-container command must stay exactly [\"wiremesh-relay-enroll\"]"
    );
}

#[test]
fn relay_enroll_args_and_command_survive_controller_endpoint_override() {
    // Breaks on: any change that lets `spec.controller_endpoint` reach the
    // relay's enroll init-container. `controllerEndpoint` exists to retarget
    // the main container's long-lived `--controller` (sync) dial after the
    // control plane moved off zolab k8s (see
    // `relay_controller_endpoint_override.rs`) — the one-shot enroll RPC
    // must keep dialing the in-cluster `controller_enroll` target
    // regardless, the same carve-out the gateway's overrides already
    // respect.
    let baseline_pod = relay_pod(relay_spec(None));
    let baseline_args = relay_enroll(&baseline_pod).args.clone();
    let baseline_command = relay_enroll(&baseline_pod).command.clone();

    let overridden_pod = relay_pod(relay_spec(Some(OVERRIDE_RELAY_CONTROLLER.to_string())));
    let overridden_enroll = relay_enroll(&overridden_pod);

    assert_eq!(
        overridden_enroll.args, baseline_args,
        "controllerEndpoint override must not change a single element of the relay enroll \
         init-container's argv: {:?}",
        overridden_enroll.args
    );
    assert_eq!(
        overridden_enroll.command, baseline_command,
        "controllerEndpoint override must not change the relay enroll init-container's command: {:?}",
        overridden_enroll.command
    );
}
