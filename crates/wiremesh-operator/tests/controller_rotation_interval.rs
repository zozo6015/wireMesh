//! FAILING tests (test-author, Backlog 2a): CRD surface for
//! `WIREMESH_ROTATION_INTERVAL`. **compile-RED** until `WiremeshControllerSpec`
//! gains the field — mirrors the compile-RED convention established by
//! `tests/gateway_endpoint_overrides.rs` for the observe/sync endpoint
//! overrides.
//!
//! # The trap this file exists to catch
//!
//! `WIREMESH_ROTATION_INTERVAL=off` is a LIVE production mitigation on this
//! fabric (see `docs/BACKLOG.md` item 2a and the root `CLAUDE.md` "Key
//! rotation" section) — automatic key rotation is disabled fabric-wide because
//! the in-step rotation case is still red. Both operator apply paths
//! (`controllers::apply`, `controllers::apply_deployment`) use
//! `PatchParams::apply(FIELD_MANAGER).force()`, and `Container.env` carries
//! `x-kubernetes-list-type: map` (`list-map-keys: [name]`) — so SSA force-owns
//! **per key**. An operator that emits `WIREMESH_ROTATION_INTERVAL` with ANY
//! default (even an empty string) OWNS that key from then on, and the next
//! reconcile silently overwrites a human's hand-set `off`, one`kubectl set
//! env` at a time, re-enabling the fabric-wide rotation outage on exactly the
//! clusters that had mitigated it.
//!
//! The fix must emit the key ONLY when `spec.rotation_interval` is `Some` —
//! never populate it, never default it. Pinned in
//! [`Pinned surface`](#pinned-surface) below.
//!
//! # Pinned surface
//!
//! `crd::WiremeshControllerSpec` gains one optional field (camelCase serde,
//! omitted when unset — parity with every other optional spec field on this
//! struct and the precedent at `tests/gateway_endpoint_overrides.rs`):
//! ```ignore
//! pub rotation_interval: Option<String>,  // serializes "rotationInterval"
//! ```
//! `workloads::controller_deployment` keeps its signature. The container's
//! `env` vec (today `Some(vec![..7 entries..])`, see the doc comment on
//! `controller_deployment` and `docs/BACKLOG.md` 2a) gets a conditional
//! EIGHTH push: `WIREMESH_ROTATION_INTERVAL` appears iff
//! `spec.rotation_interval` is `Some`, carrying that value verbatim (the
//! operator does not parse/validate/trim it — grammar validation is tracked
//! separately, see BACKLOG 2a "Validation").
//!
//! Grammar validation (`parse_rotation_interval`, planned to move from
//! `wiremesh-controller` into `wiremesh-enroll` per BACKLOG 2a) and any
//! reconcile-time fail-closed check are OUT OF SCOPE for this file — nothing
//! here should be read as pinning that surface.

use wiremesh_operator::crd::WiremeshControllerSpec;
use wiremesh_operator::workloads::controller_deployment;

/// Every field of `WiremeshControllerSpec` spelled out (mirrors
/// `workloads.rs`'s private `ctrl_spec()` test helper, which cannot be reused
/// from an integration test) — the `rotation_interval` field below is the
/// literal, single line that fails to compile against current `main`.
fn ctrl_spec(rotation_interval: Option<String>) -> WiremeshControllerSpec {
    WiremeshControllerSpec {
        image: None,
        storage_class: None,
        storage_size: None,
        admin_tcp_port: None,
        sync_tcp_port: None,
        observe_udp_port: None,
        rotation_interval,
    }
}

/// The seven `WIREMESH_*` entries `controller_deployment` emits today,
/// independent of `rotation_interval` — name, then the value it takes under
/// `ctrl_spec(..)`'s all-`None` (default-port) inputs used throughout this
/// file.
const BASELINE_ENV: &[(&str, &str)] = &[
    ("WIREMESH_DATA_DIR", "/var/lib/wiremesh"),
    ("WIREMESH_TCP_PORT", "9400"),
    ("WIREMESH_SYNC_TCP_PORT", "9500"),
    ("WIREMESH_SOCKET_PATH", "/run/wiremesh/controller.sock"),
    ("WIREMESH_ADMIN_TCP_PORT", "9443"),
    ("WIREMESH_OBSERVE_UDP_PORT", "9600"),
    ("WIREMESH_BIND_IP", "0.0.0.0"),
];

/// `(name, value)` pairs for the `controller` container's env, owned so the
/// caller can assert on them after the `Deployment` (and its borrowed
/// `EnvVar`s) go out of scope — sidesteps any question of whether
/// `k8s_openapi::api::core::v1::EnvVar` implements `Clone`.
fn controller_container_env(spec: &WiremeshControllerSpec) -> Vec<(String, Option<String>)> {
    let d = controller_deployment("wm", spec, "ghcr.io/x/wiremesh-operator:test");
    let pod = d.spec.unwrap().template.spec.unwrap();
    let c = pod.containers.iter().find(|c| c.name == "controller").expect("controller container");
    c.env
        .as_ref()
        .expect("controller container always sets env")
        .iter()
        .map(|e| (e.name.clone(), e.value.clone()))
        .collect()
}

fn assert_baseline_present(env: &[(String, Option<String>)]) {
    for (name, value) in BASELINE_ENV {
        let found = env.iter().find(|(n, _)| n == name);
        assert_eq!(
            found.and_then(|(_, v)| v.as_deref()),
            Some(*value),
            "existing entry {name} must be unaffected by the rotation_interval field: {env:?}"
        );
    }
}

/// **Expected failure today: compile error.** `ctrl_spec` above passes a
/// `rotation_interval` field that does not exist on `WiremeshControllerSpec`
/// on `main` — `cargo test -p wiremesh-operator` fails to build this file at
/// all until the field is added. This is intentional: every test below is
/// unreachable until that happens.
#[test]
fn field_compiles_and_round_trips_through_serde() {
    let v = serde_json::to_value(ctrl_spec(Some("45m".into()))).unwrap();
    assert_eq!(
        v.get("rotationInterval").and_then(|x| x.as_str()),
        Some("45m"),
        "rotation_interval must serialize as camelCase rotationInterval"
    );

    let bare = serde_json::to_value(ctrl_spec(None)).unwrap();
    assert!(
        bare.get("rotationInterval").is_none(),
        "rotationInterval must be OMITTED (not null, not present) when unset — \
         skip_serializing_if = \"Option::is_none\", parity with every other \
         optional field on WiremeshControllerSpec"
    );

    // Round-trip back.
    let spec: WiremeshControllerSpec = serde_json::from_value(v).unwrap();
    assert_eq!(spec.rotation_interval.as_deref(), Some("45m"));
}

/// **Expected failure today: compile error** (same root cause as the test
/// above). Once the field exists, this pins the specific literal this whole
/// item is about: a CR that already carries `rotationInterval: off` — the
/// live mitigation — must round-trip that value unchanged. A operator that
/// silently normalized/dropped `off` would defeat the mitigation as surely as
/// a wrongly-defaulted emit would.
#[test]
fn the_off_literal_round_trips_unchanged() {
    let v = serde_json::to_value(ctrl_spec(Some("off".into()))).unwrap();
    assert_eq!(v.get("rotationInterval").and_then(|x| x.as_str()), Some("off"));
    let spec: WiremeshControllerSpec = serde_json::from_value(v).unwrap();
    assert_eq!(spec.rotation_interval.as_deref(), Some("off"));
}

/// **Expected failure today: compile error** (same root cause). Additive-CRD
/// safety: a CR persisted before this field existed (no `rotationInterval`
/// key in its stored JSON at all) must still deserialize — the precedent this
/// mirrors is `override_fields_serialize_camel_case_and_omit_when_unset` in
/// `tests/gateway_endpoint_overrides.rs`.
#[test]
fn legacy_controller_cr_without_the_field_still_deserializes() {
    let legacy: WiremeshControllerSpec = serde_json::from_value(serde_json::json!({}))
        .expect("a controller CR persisted before this field existed must still deserialize");
    assert!(legacy.rotation_interval.is_none());
}

/// **THE central trap test. Expected failure today: compile error** (same
/// root cause as the field-existence tests above) — but once the field
/// compiles, this is the assertion that actually matters: it must keep
/// failing for a DIFFERENT reason if the implementation defaults the env
/// entry instead of omitting it (e.g. `env("WIREMESH_ROTATION_INTERVAL",
/// spec.rotation_interval.clone().unwrap_or_default())`, which would push an
/// entry with an EMPTY STRING value when `None` — still present, still
/// force-owned, still a landmine). This test asserts NO entry with that name
/// exists at all, so a defaulted-empty-string implementation fails it just as
/// hard as a defaulted-30d one would.
///
/// Why this matters: the moment the operator emits this key with any value —
/// including `""` — SSA's per-key force-ownership (`Container.env` is
/// `x-kubernetes-list-type: map`) means the operator OWNS it, and the next
/// reconcile clobbers a human's hand-set `off`, silently re-enabling
/// automatic key rotation on exactly the clusters that disabled it to escape
/// the fabric-wide rotation outage (see root `CLAUDE.md`, "Key rotation").
#[test]
fn no_rotation_env_entry_when_field_is_unset() {
    let env = controller_container_env(&ctrl_spec(None));
    assert!(
        env.iter().find(|(n, _)| n == "WIREMESH_ROTATION_INTERVAL").is_none(),
        "spec.rotation_interval == None must emit NO WIREMESH_ROTATION_INTERVAL \
         env entry at all (not an empty one, not a defaulted one) — emitting \
         any value here makes the operator OWN the key under SSA force-apply, \
         and the next reconcile would silently clobber a human's hand-set \
         `off`, re-enabling the fabric-wide rotation outage this field exists \
         to let operators mitigate: {env:?}"
    );
    assert_eq!(env.len(), 7, "no eighth entry should appear when unset: {env:?}");
    assert_baseline_present(&env);
}

/// **Expected failure today: compile error** (same root cause). The mirror
/// case: when the field IS set, exactly one entry with that value appears —
/// not zero, not duplicated, and the other seven entries are untouched.
#[test]
fn exactly_one_rotation_env_entry_when_field_is_set() {
    let env = controller_container_env(&ctrl_spec(Some("12h".into())));
    let matches: Vec<&(String, Option<String>)> =
        env.iter().filter(|(n, _)| n == "WIREMESH_ROTATION_INTERVAL").collect();
    assert_eq!(
        matches.len(),
        1,
        "exactly one WIREMESH_ROTATION_INTERVAL entry must appear when \
         spec.rotation_interval is Some, never zero or duplicated: {env:?}"
    );
    assert_eq!(matches[0].1.as_deref(), Some("12h"), "the entry's value must be the CR's value verbatim");
    assert_eq!(env.len(), 8, "exactly one eighth entry, no more: {env:?}");
    assert_baseline_present(&env);
}

/// **Expected failure today: compile error** (same root cause). Explicit
/// belt-and-suspenders for the `off` literal specifically, since that is the
/// value actually deployed as a live mitigation today (BACKLOG 2a, root
/// `CLAUDE.md`) — passed through into the env value verbatim, not normalized
/// or rejected by the operator (grammar validation is out of scope here).
#[test]
fn rotation_env_entry_carries_the_off_literal_verbatim() {
    let env = controller_container_env(&ctrl_spec(Some("off".into())));
    let entry = env
        .iter()
        .find(|(n, _)| n == "WIREMESH_ROTATION_INTERVAL")
        .expect("WIREMESH_ROTATION_INTERVAL entry must be present when Some(\"off\")");
    assert_eq!(entry.1.as_deref(), Some("off"));
}
