//! CRD surface for `WIREMESH_ROTATION_INTERVAL` (Backlog 2a).
//!
//! # Contract INVERSION — owner-approved, 2026-08-10
//!
//! This file previously pinned "omit the env entry when `rotation_interval`
//! is `None`". That contract is now WRONG and has been inverted.
//!
//! **Contract:**
//! - `rotation_interval: None` → emit `WIREMESH_ROTATION_INTERVAL=off`
//!   **explicitly** (not omitted).
//! - `rotation_interval: Some(v)` → emit `v` verbatim.
//! - The env vec is therefore **always eight entries**, never seven.
//!
//! Tests below marked "INVERTED" assert the literal opposite of what this
//! file asserted before — that is deliberate, not drift.
//!
//! # Why — the ORIGINAL reason expired on 2026-08-12; the contract did not
//!
//! When this file was written, the reason was a live bug:
//! `wiremesh_controller::rotation_interval_from_env` treated an ABSENT
//! `WIREMESH_ROTATION_INTERVAL` as **armed**, falling back to
//! `Config::default_rotation_interval()` (30 days). Omitting the key therefore
//! did not mean "leave rotation alone", it meant "arm automatic rotation at the
//! controller's 30-day default" — so the old "omit when unset" behavior left
//! every operator-managed controller silently rotating keys on a schedule
//! nobody chose.
//!
//! **That premise is gone.** As of the 2026-08-12 owner decision, the
//! controller's own default flipped: an absent `WIREMESH_ROTATION_INTERVAL`
//! resolves to `Ok(None)` — no rotation-initiation timer, exactly as if `off`
//! had been written. Automatic rotation is opt-in there too now, so omitting
//! this key would no longer arm anything, and these assertions are no longer
//! what stands between the fleet and a scheduled outage. Do not read the
//! reasoning below as describing current controller behaviour; the contract
//! is unchanged, but it now rests on the two reasons
//! `crates/wiremesh-operator/src/workloads.rs` gives at the emission site:
//!
//!   1. **The rendered Deployment STATES the fabric's rotation posture**
//!      rather than leaving it to be inferred from a missing key. Someone
//!      reading a live manifest, or diffing two clusters, sees `off` written
//!      down instead of having to know what the controller does with silence.
//!   2. **It stays correct against an older controller** — one predating the
//!      2026-08-12 flip, which still reads an absent variable as "rotate every
//!      30 days". Operator and controller are separately-versioned artifacts
//!      and a fleet can be mixed mid-upgrade; emitting `off` is what makes the
//!      manifest mean the same thing on both.
//!
//! **Risk profile, for whoever weighs this file next:** it dropped from
//! "prevents a live, fabric-wide bug" to "prevents cosmetic ambiguity, plus
//! old-controller compatibility". Nothing here was weakened when the premise
//! changed — the emission contract is unchanged and every assertion still pins
//! it exactly — but that is what it is worth now, and a future reader who
//! over-weights it (or who reads the old rationale and concludes the
//! controller still arms itself on silence) will be reasoning from a world
//! that ended on 2026-08-12.
//!
//! The original "omit" rationale was that emitting *any* default would let
//! SSA `.force()` (`Container.env` is `x-kubernetes-list-type: map`,
//! `list-map-keys: [name]`) clobber a human's hand-set `off` on the next
//! reconcile. That risk hasn't gone away — but the *direction* of the clobber
//! has flipped: the default now emitted IS `off`, so the only reconcile this
//! contract can silently perform is toward the safe state, never away from
//! it. A hand-set `45m` on the Deployment being reconciled back to the CR's
//! value is intended: `spec.rotationInterval` is the one place the interval is
//! declared, and arming the timer is a choice made there, deliberately. That
//! choice is still not recommended — the in-step rotation done-bar passed in
//! v0.9.1 (`crates/wiremesh-gateway/tests/key_rotation.rs` is green, with no
//! `#[ignore]` left), but the rotation wedge is still open: `docs/BACKLOG.md`
//! item 9, where one part-failed rotation leaves a gateway silently ignoring
//! every later directive until it is restarted.
//!
//! # Pinned surface (unchanged from before)
//!
//! `crd::WiremeshControllerSpec` carries one optional field (camelCase
//! serde, omitted from the *serialized spec* when unset — only the emitted
//! ENV changed, not the CRD's on-the-wire shape):
//! ```ignore
//! pub rotation_interval: Option<String>,  // serializes "rotationInterval"
//! ```
//! Grammar validation (`parse_rotation_interval`) and any reconcile-time
//! fail-closed check remain OUT OF SCOPE for this file.

use wiremesh_operator::crd::WiremeshControllerSpec;
use wiremesh_operator::workloads::controller_deployment;

/// Every field of `WiremeshControllerSpec` spelled out (mirrors
/// `workloads.rs`'s private `ctrl_spec()` test helper, which cannot be reused
/// from an integration test).
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

/// The seven `WIREMESH_*` entries `controller_deployment` emits regardless of
/// `rotation_interval` — name, then the value it takes under
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
    let c = pod
        .containers
        .iter()
        .find(|c| c.name == "controller")
        .expect("controller container");
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
        "rotationInterval must be OMITTED (not null, not present) from the \
         SERIALIZED SPEC when unset — skip_serializing_if = \"Option::is_none\", \
         parity with every other optional field on WiremeshControllerSpec. This \
         is unchanged by the env-emission contract inversion: only the \
         controller Deployment's emitted ENV defaults to `off` now, never the \
         CRD's own on-the-wire shape."
    );

    // Round-trip back.
    let spec: WiremeshControllerSpec = serde_json::from_value(v).unwrap();
    assert_eq!(spec.rotation_interval.as_deref(), Some("45m"));
}

/// A CR that already carries `rotationInterval: off` — the live mitigation —
/// must round-trip that value unchanged. An operator that silently
/// normalized/dropped `off` would defeat the mitigation as surely as a
/// wrongly-defaulted emit would.
#[test]
fn the_off_literal_round_trips_unchanged() {
    let v = serde_json::to_value(ctrl_spec(Some("off".into()))).unwrap();
    assert_eq!(
        v.get("rotationInterval").and_then(|x| x.as_str()),
        Some("off")
    );
    let spec: WiremeshControllerSpec = serde_json::from_value(v).unwrap();
    assert_eq!(spec.rotation_interval.as_deref(), Some("off"));
}

/// Additive-CRD safety: a CR persisted before this field existed (no
/// `rotationInterval` key in its stored JSON at all) must still deserialize
/// — the precedent this mirrors is
/// `override_fields_serialize_camel_case_and_omit_when_unset` in
/// `tests/gateway_endpoint_overrides.rs`. Deserializing to `None` here is
/// exactly what makes the env-emission fallback (test below) load-bearing:
/// every pre-existing CR in the fleet is `None` today, and after this change
/// each one starts emitting `off` on its next reconcile.
#[test]
fn legacy_controller_cr_without_the_field_still_deserializes() {
    let legacy: WiremeshControllerSpec = serde_json::from_value(serde_json::json!({}))
        .expect("a controller CR persisted before this field existed must still deserialize");
    assert!(legacy.rotation_interval.is_none());
}

/// **THE central trap test — INVERTED from the old contract.** The old
/// version of this test asserted "no entry at all when unset"; that was
/// exactly the bug. `None` must now produce EXACTLY ONE
/// `WIREMESH_ROTATION_INTERVAL` entry, whose value is the literal `off` — not
/// omitted, not empty, not the controller's 30-day default silently taking
/// over.
///
/// Why this matters — updated 2026-08-12, and the update matters as much as
/// the test. This assertion was written against a controller whose
/// `rotation_interval_from_env` treated an ABSENT env var as **armed** (a
/// fallback to `Config::default_rotation_interval()`, 30 days), so omitting
/// the key meant "arm automatic rotation at the controller's 30-day default"
/// and this test was what stopped it. **That is no longer true**: since the
/// 2026-08-12 owner decision an absent `WIREMESH_ROTATION_INTERVAL` resolves
/// to no timer at all, so omitting the key would arm nothing.
///
/// The contract stands on its two surviving reasons (see this file's module
/// doc and the emission site in `workloads.rs`): the rendered Deployment
/// should STATE the fabric's rotation posture rather than imply it by
/// absence, and the manifest must stay correct against a controller old
/// enough to still read silence as "rotate every 30 days" — operator and
/// controller are separately-versioned and a fleet can be mixed mid-upgrade.
/// What this test prevents is therefore no longer a live outage but an
/// ambiguous manifest plus a version-skew hazard. Every assertion below is
/// unchanged.
#[test]
fn none_emits_off_explicitly_not_omitted() {
    let env = controller_container_env(&ctrl_spec(None));
    let matches: Vec<&(String, Option<String>)> = env
        .iter()
        .filter(|(n, _)| n == "WIREMESH_ROTATION_INTERVAL")
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "spec.rotation_interval == None must emit EXACTLY ONE \
         WIREMESH_ROTATION_INTERVAL entry (never zero, never duplicated). \
         Omitting it leaves the rendered Deployment silent about the fabric's \
         rotation posture, so a reader has to know what the controller does \
         with an absent variable to know what this cluster does — and the \
         answer depends on the controller's version: since 2026-08-12 absence \
         means no timer, but a controller predating that flip still reads it \
         as \"rotate every 30 days\", which an operator/controller version skew \
         makes reachable in a real fleet. Emitting `off` explicitly is what \
         makes the manifest mean the same thing on both: {env:?}"
    );
    assert_eq!(
        matches[0].1.as_deref(),
        Some("off"),
        "the None-case entry's value must be the literal `off`, not empty and \
         not any other default — anything else either leaves rotation armed or \
         fails closed for the wrong reason: {env:?}"
    );
    assert_eq!(
        env.len(),
        8,
        "the env vec is always eight entries now, never seven: {env:?}"
    );
    assert_baseline_present(&env);
}

/// The mirror case: when the field IS explicitly set, exactly one entry with
/// that value appears — not zero, not duplicated, and the other seven
/// entries are untouched.
#[test]
fn some_emits_exactly_one_entry_with_the_value_verbatim() {
    let env = controller_container_env(&ctrl_spec(Some("12h".into())));
    let matches: Vec<&(String, Option<String>)> = env
        .iter()
        .filter(|(n, _)| n == "WIREMESH_ROTATION_INTERVAL")
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "exactly one WIREMESH_ROTATION_INTERVAL entry must appear when \
         spec.rotation_interval is Some, never zero or duplicated: {env:?}"
    );
    assert_eq!(
        matches[0].1.as_deref(),
        Some("12h"),
        "the entry's value must be the CR's value verbatim"
    );
    assert_eq!(env.len(), 8, "exactly one eighth entry, no more: {env:?}");
    assert_baseline_present(&env);
}

/// `Some("off")` must be indistinguishable, at the env level, from the `None`
/// case — that IS the point of the inversion: a human who hand-sets
/// `rotationInterval: off` and an operator that defaults to it because the
/// field was never set both converge on the exact same rendered
/// `WIREMESH_ROTATION_INTERVAL=off` entry.
#[test]
fn explicit_off_is_indistinguishable_from_unset() {
    let explicit = controller_container_env(&ctrl_spec(Some("off".into())));
    let unset = controller_container_env(&ctrl_spec(None));
    assert_eq!(
        explicit, unset,
        "Some(\"off\") and None must render byte-identical env vecs — that is \
         the entire point of defaulting None to the off literal rather than to \
         some other sentinel: {explicit:?} vs {unset:?}"
    );
}

/// Belt-and-suspenders for the `off` literal specifically, since that is the
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

/// The other seven entries must stay byte-identical to `BASELINE_ENV` across
/// every case this file exercises (`None`, `Some("off")`, `Some("45m")`) —
/// the rotation-interval contract inversion must not perturb anything else
/// in the container's env, in either name or value, in either order.
#[test]
fn the_other_seven_entries_are_byte_identical_across_every_case() {
    for spec in [
        ctrl_spec(None),
        ctrl_spec(Some("off".into())),
        ctrl_spec(Some("45m".into())),
    ] {
        let env = controller_container_env(&spec);
        let non_rotation: Vec<&(String, Option<String>)> = env
            .iter()
            .filter(|(n, _)| n != "WIREMESH_ROTATION_INTERVAL")
            .collect();
        assert_eq!(
            non_rotation.len(),
            7,
            "seven non-rotation entries expected: {env:?}"
        );
        for (name, value) in BASELINE_ENV {
            let found = non_rotation.iter().find(|(n, _)| n == name);
            assert_eq!(
                found.and_then(|(_, v)| v.as_deref()),
                Some(*value),
                "entry {name} must be byte-identical regardless of rotation_interval: {env:?}"
            );
        }
    }
}
