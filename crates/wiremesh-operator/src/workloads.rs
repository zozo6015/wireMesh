//! Pure builders that turn the CRDs into Kubernetes workload objects
//! (`k8s-openapi` types). No cluster I/O — the reconcilers apply these.
//!
//! Port/env/arg wiring mirrors the real binaries:
//! - controller: env-configured (`WIREMESH_DATA_DIR`, `WIREMESH_TCP_PORT`,
//!   `WIREMESH_SYNC_TCP_PORT`, `WIREMESH_SOCKET_PATH`, `WIREMESH_ADMIN_TCP_PORT`,
//!   `WIREMESH_OBSERVE_UDP_PORT`, `WIREMESH_BIND_IP` — see
//!   `crates/wiremesh-controller/src/main.rs`).
//! - gateway: `--controller-sync/--observe/--tun/--wg-port/--state-dir` plus the
//!   `enroll` subcommand (`crates/wiremesh-gateway/src/{config,enroll}.rs`).
//! - relay: `relay <bind> <certdir> --controller <sync>` plus the
//!   `wiremesh-relay-enroll` bin.
//!
//! Gateway/relay pods bootstrap their identity with an `enroll` init-container
//! (the piece the `wiremesh-enroll` crate unblocked) that shares the
//! state/cert dir with the main container.
//!
//! NOTE (see `docs/research/operator-admin-channel-gap.md`): the controller
//! Service intentionally does NOT expose `admin-tcp` — the Admin TCP listener
//! is plaintext-bearer and binds loopback-only by design. The operator's admin
//! channel is resolved in the reconciler phase.

use anyhow::Context;
use crate::crd::{
    WiremeshControllerSpec, WiremeshGateway, WiremeshGatewaySpec, WiremeshRelay,
    WiremeshRelaySpec,
};
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec, DeploymentStrategy};
use k8s_openapi::api::core::v1::{
    Container, ContainerPort, EmptyDirVolumeSource, EnvVar, HostPathVolumeSource, KeyToPath,
    PodSpec, PodTemplateSpec, PersistentVolumeClaim, PersistentVolumeClaimSpec,
    PersistentVolumeClaimVolumeSource, SecretVolumeSource, SecurityContext, Service, ServicePort,
    ServiceSpec, Volume, VolumeMount, VolumeResourceRequirements,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use std::collections::BTreeMap;

const DEFAULT_CONTROLLER_IMAGE: &str = "ghcr.io/zozo6015/wiremesh-controller:latest";
const DEFAULT_GATEWAY_IMAGE: &str = "ghcr.io/zozo6015/wiremesh-gateway:latest";
const DEFAULT_RELAY_IMAGE: &str = "ghcr.io/zozo6015/wiremesh-relay:latest";
/// The operator's own image, used for the controller pod's admin-exec sidecar.
/// The reconciler overrides this with the operator's actual running image.
pub const DEFAULT_OPERATOR_IMAGE: &str = "ghcr.io/zozo6015/wiremesh-operator:latest";

const ENROLL_TCP_PORT: i32 = 9400; // WIREMESH_TCP_PORT (Enrollment RPC, server-TLS)
const SYNC_TCP_PORT: i32 = 9500; // WIREMESH_SYNC_TCP_PORT (mTLS)
const ADMIN_TCP_PORT: i32 = 9443; // WIREMESH_ADMIN_TCP_PORT (loopback-only)
const OBSERVE_UDP_PORT: i32 = 9600; // WIREMESH_OBSERVE_UDP_PORT

const DATA_DIR: &str = "/var/lib/wiremesh";
const RUN_DIR: &str = "/run/wiremesh";
const UDS_PATH: &str = "/run/wiremesh/controller.sock";

/// The stable label the controller pod carries (independent of the CR's name),
/// so the operator's admin-exec transport can find it by a fixed selector.
pub const CONTROLLER_COMPONENT_LABEL: (&str, &str) = ("app.kubernetes.io/component", "controller");

/// The Secret holding the mesh CA — a cert-manager `Certificate`'s output
/// (`tls.crt`/`tls.key`). The controller seeds its CA from it (so its identity
/// is cert-manager-rooted); gateways/relays mount its cert as their enroll
/// trust anchor.
pub const CONTROLLER_CA_SECRET: &str = "wiremesh-controller-ca";

/// The label selector the admin-exec transport uses to find the controller pod.
pub fn controller_pod_selector() -> String {
    format!(
        "app.kubernetes.io/name=wiremesh,{}={}",
        CONTROLLER_COMPONENT_LABEL.0, CONTROLLER_COMPONENT_LABEL.1
    )
}

/// The `app` label every object for one instance shares (also the Service
/// selector).
fn labels(name: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("app.kubernetes.io/name".to_string(), "wiremesh".to_string());
    m.insert("app.kubernetes.io/instance".to_string(), name.to_string());
    m
}

fn env(name: &str, value: impl Into<String>) -> EnvVar {
    EnvVar { name: name.to_string(), value: Some(value.into()), ..Default::default() }
}

/// The `Recreate` Deployment strategy: kill the old pod before starting the new
/// one. Both the controller and gateway own an RWO PVC (and the gateway is also
/// hostNetwork), so a default RollingUpdate would surge a second pod that cannot
/// mount the RWO PVC (or bind the host net), wedging the rollout.
fn recreate_strategy() -> DeploymentStrategy {
    DeploymentStrategy { type_: Some("Recreate".into()), rolling_update: None, ..Default::default() }
}

/// `spec.replicas` for every workload Deployment: **deliberately released.**
///
/// The operator server-side-applies with `.force()`, so any value it sets here
/// is re-asserted on every reconcile — a typed `Some(1)` made
/// `kubectl scale --replicas=0` revert on the very next pass, i.e. an operator
/// could never take a workload down without deleting the CR. Omitting the field
/// drops it from the apply body, which is what releases SSA ownership: the field
/// then belongs to whoever last set it (`kubectl scale`), and it sticks.
///
/// **Why omission and not a CRD `replicas` field** — the next person to read this
/// will propose the field, so: a CRD field would still be force-applied under
/// SSA, which MOVES the knob rather than fixing it (`kubectl scale` would still
/// revert; you'd have to edit the CR instead), and it would advertise a scaling
/// capability these workloads do not have. They are hostNetwork, bind a fixed
/// WireGuard port, mount an RWO PVC, and use `Recreate` (see
/// `recreate_strategy`) chosen precisely so a second pod never surges. `0` and
/// `1` are the only counts that work; a field implying otherwise is a lie in the
/// API surface. Releasing the field gives operators the one meaningful
/// transition (off/on) without claiming the rest.
///
/// **What happens on the upgrade itself** (REASONED, NOT VERIFIED against a
/// live apiserver — see the caveat at the end). `DeploymentSpec.replicas` is a
/// nullable int32 — *"a pointer to distinguish between explicit zero and not
/// specified. Defaults to 1."* The obvious worry is that the first post-upgrade
/// apply drops the field, the defaulter re-sets `1`, and a Deployment a human
/// had deliberately scaled to 0 comes back up. We believe it does NOT, and the
/// mechanism is SSA ownership: **an apply can only REMOVE a field its own field
/// manager currently owns.** Dropping a field from the apply body is not an
/// instruction to delete it; it is a release of the applier's claim, and the
/// removal only follows if that claim was the last one standing.
///
/// The reachable cases:
///
/// 1. **Operator running, steady state.** The operator owns `replicas: 1`. The
///    new build applies without it → owned, so removed → defaulter re-sets `1`.
///    Net effect `1 → 1`: nothing observable.
/// 2. **Operator running, human runs `kubectl scale --replicas=0`.** The old
///    build force-reasserts `1` on the next reconcile — that is the bug this
///    function exists to fix. So this state cannot still be in effect when the
///    upgrade lands.
/// 3. **Operator down, human runs `kubectl scale --replicas=0`.** `kubectl
///    scale` is a non-apply Update against the `scale` subresource, so
///    ownership of `spec.replicas` TRANSFERS to the `kubectl-scale` field
///    manager and drops out of the operator's managed-fields entry. The new
///    build then applies without `replicas` while owning nothing → nothing is
///    removed → **the Deployment stays at 0.**
///
/// Case 3 is the only route by which a pre-upgrade scale-to-0 can survive to
/// meet the new build, and it is precisely the case where the field is not
/// removed. So the upgrade should be a no-op for scaled-down workloads, which
/// is also the behaviour you would want.
///
/// **This has NOT been confirmed against a real apiserver.** SSA ownership
/// semantics are subtle (subresource-vs-resource ownership, and what a
/// force-apply that omits a field does to a co-owner's entry, are both easy to
/// get wrong on paper). Confirm it on a live cluster — apply the new build over
/// a Deployment scaled to 0 by a stopped operator and check `replicas` after —
/// before relying on it operationally.
fn released_replicas() -> Option<i32> {
    None
}

/// Build the JSON body to hand to `Patch::Apply` for a Deployment, clearing the
/// API-server defaulter's `rollingUpdate` block when the strategy is `Recreate`.
///
/// WHY (see `docs/research/ops-finding-pvc-adoption-migration.md`, bug 1): the
/// typed builders set `strategy.type: Recreate` with `rolling_update: None`, but
/// a typed `None` serializes to an OMITTED field, not a JSON `null`. When the
/// operator server-side-applies that body over a Deployment that was originally
/// created with the default RollingUpdate strategy, the `rollingUpdate` block is
/// owned by the API-server DEFAULTER (a different field manager). SSA leaves a
/// field the apply body omits in place, so the merged object ends up with BOTH
/// `type: Recreate` AND a `rollingUpdate` block, which the API server rejects:
/// `spec.strategy.rollingUpdate: Forbidden ... when type is 'Recreate'` (422).
/// The reconcile then loops on that 422 and never rolls out the new pod spec.
///
/// The fix is to emit an EXPLICIT `spec.strategy.rollingUpdate: null` in the
/// apply body — a present null is what tells SSA to REMOVE the defaulter's
/// field. The typed builders keep returning `type: Recreate`; this null
/// injection happens only at the apply boundary. Idempotent: re-applying a
/// Deployment already at `Recreate` (with no `rollingUpdate`) still injects the
/// same null, and a Deployment on some other strategy is passed through
/// untouched.
pub fn deployment_apply_body(dep: &Deployment) -> serde_json::Value {
    let mut body = serde_json::to_value(dep)
        .expect("a k8s-openapi Deployment always serializes to JSON");
    let is_recreate = body
        .get("spec")
        .and_then(|s| s.get("strategy"))
        .and_then(|s| s.get("type"))
        .and_then(|t| t.as_str())
        == Some("Recreate");
    if is_recreate {
        if let Some(strategy) = body
            .get_mut("spec")
            .and_then(|s| s.get_mut("strategy"))
            .and_then(|s| s.as_object_mut())
        {
            // An EXPLICIT null (present key) — not an omitted field — so SSA
            // removes the defaulter's rollingUpdate block.
            strategy.insert("rollingUpdate".to_string(), serde_json::Value::Null);
        }
    }
    body
}

fn tcp_port(name: &str, port: i32) -> ContainerPort {
    ContainerPort {
        name: Some(name.to_string()),
        container_port: port,
        protocol: Some("TCP".to_string()),
        ..Default::default()
    }
}

/// Syntax-only validation of a CRD-supplied `host:port` dial target
/// (`spec.observeEndpoint` / `spec.syncEndpoint`). Mirrors the gateway binary's
/// own `config::validate_host_port` rules so a bad override is rejected AT
/// RECONCILE — fail closed, like the relay's `endpoint` — instead of rolling
/// out a pod whose argv the binary refuses at boot (CrashLoopBackOff).
/// Duplicated rather than imported: the operator does not (and should not)
/// depend on the gateway crate, which pulls boringtun + the eBPF enforcer.
///
/// Deliberately does NO DNS lookup — a hostname that doesn't resolve right now
/// must still validate, because the gateway re-resolves per reconnect/tick and
/// boots fail-static with the resolver down. Rejected:
/// - no `:port`, an empty host, or a non-`u16` port;
/// - port `0` ("OS-assigned"; never a reachable dial target — same reasoning as
///   the relay endpoint check);
/// - IPv6 literals, bracketed or bare (v1 is IPv4-only end to end);
/// - an IPv4-SHAPED host (digits and dots only — an all-numeric TLD is not a
///   legal DNS name) that is not a valid literal, e.g. `10.0.0.300:9600`, which
///   would otherwise be waved through as a "hostname" that can never resolve.
pub fn validate_dial_target(s: &str) -> anyhow::Result<()> {
    let (host, port) = s
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("expected host:port, got {s:?}"))?;
    if host.is_empty() {
        anyhow::bail!("empty host in {s:?}");
    }
    let port: u16 = port
        .parse()
        .with_context(|| format!("invalid port in {s:?}"))?;
    anyhow::ensure!(port != 0, "port 0 in {s:?} is not a reachable dial target");
    // `host.contains(':')` is load-bearing, not redundant with the parse below:
    // `rsplit_once` splits on the LAST colon, so a bare IPv6 literal like
    // `fe80::1` yields host `"fe80:"` + port `"1"` — the port parses, the host
    // is neither bracketed nor a parseable `IpAddr`, and it isn't
    // digits-and-dots, so every other check waves it through. Any leftover
    // colon in the host means the input was an IPv6-ish or otherwise malformed
    // shape; fail closed.
    if host.starts_with('[')
        || host.contains(':')
        || matches!(host.parse(), Ok(std::net::IpAddr::V6(_)))
    {
        anyhow::bail!("IPv6 dial target {s:?} is unsupported (v1 is IPv4-only)");
    }
    if host.chars().all(|c| c.is_ascii_digit() || c == '.') {
        s.parse::<std::net::SocketAddr>()
            .map(|_| ())
            .with_context(|| format!("invalid IP literal in {s:?}"))?;
    }
    Ok(())
}

/// Syntax-only validation of a CRD-supplied `ip:port` BIND target
/// (`spec.metricsBind`). NOT `validate_dial_target` — a bind address is a
/// different class of value than a fabric dial target, and reusing that
/// validator would be wrong in three directions at once:
///
/// - The gateway's `--metrics` flag parses the value as a literal
///   `std::net::SocketAddr` (`GatewayConfig::parse`,
///   `crates/wiremesh-gateway/src/config.rs`) — unlike `--controller-sync`/
///   `--observe`, it is never routed through `validate_host_port`, so it
///   never accepts (or needs to accept) a DNS hostname. `validate_dial_target`
///   accepts hostnames on purpose (dial targets re-resolve at connect time);
///   here that would let a hostname through the CRD only to CrashLoopBackOff
///   at boot on the binary's own `SocketAddr::from_str`.
/// - Port `0` is a legitimate BIND address (OS-assigned) and is in fact the
///   binary's own `--metrics`-absent historical default
///   (`SocketAddr::from(([127, 0, 0, 1], 0))`). `validate_dial_target`
///   rejects port 0 because an unreachable dial target is never useful; that
///   reasoning does not apply to a bind address.
/// - IPv6 is ACCEPTED here. `validate_dial_target` rejects it because v1's
///   fabric dial/WireGuard-endpoint surface is IPv4-only end to end
///   (`validate_host_port` carries the same restriction for
///   `--controller-sync`/`--observe`) — but that rule governs FABRIC
///   addresses, and a metrics bind is a local observability socket, not a
///   fabric address. Nothing in `GatewayConfig::parse` rejects IPv6 for
///   `--metrics` (no IPv6-reject branch guards it, unlike the other two
///   flags), so rejecting it here would make the operator STRICTER than the
///   binary for no binary-side reason and strand a legitimate `[::]:9090`
///   dual-stack config. Owner decision, 2026-08-10: do NOT "restore
///   consistency" with `validate_host_port` by tightening this later — the
///   two validators deliberately guard different classes of address.
///
/// So: exactly "parses as `std::net::SocketAddr`" — no more, no less. That
/// makes this validator neither stricter nor looser than the binary it
/// guards, which is the whole point (stricter strands a legitimate config;
/// looser ships a CrashLoopBackOff).
pub fn validate_bind_target(s: &str) -> anyhow::Result<()> {
    s.parse::<std::net::SocketAddr>()
        .map(|_| ())
        .with_context(|| format!("invalid bind target {s:?} (expected ip:port, IPv4 or IPv6)"))
}

/// A CRD-supplied WireGuard interface name flows into the gateway's argv, so
/// clamp it to a valid Linux ifname (defense-in-depth against argv flag
/// smuggling — a leading `-` or shell metacharacters). Falls back to `wg0` for
/// anything that is not a plain 1-15 char `[A-Za-z0-9_-]` name not starting
/// with `-`. (Values still reach the binary positionally, but this keeps a
/// hostile CRD from ever placing a `-flag`-looking token there.)
fn safe_ifname(tun: Option<&str>) -> String {
    match tun {
        Some(t)
            if !t.is_empty()
                && t.len() <= 15
                && !t.starts_with('-')
                && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') =>
        {
            t.to_string()
        }
        _ => "wg0".to_string(),
    }
}

// --------------------------------------------------------------------------
// Controller
// --------------------------------------------------------------------------

/// The controller's data PVC (`<name>-data`), mounted at `/var/lib/wiremesh`.
pub fn controller_pvc(name: &str, spec: &WiremeshControllerSpec) -> PersistentVolumeClaim {
    let mut requests = BTreeMap::new();
    requests.insert(
        "storage".to_string(),
        Quantity(spec.storage_size.clone().unwrap_or_else(|| "1Gi".to_string())),
    );
    PersistentVolumeClaim {
        metadata: ObjectMeta {
            name: Some(format!("{name}-data")),
            labels: Some(labels(name)),
            ..Default::default()
        },
        spec: Some(PersistentVolumeClaimSpec {
            access_modes: Some(vec!["ReadWriteOnce".to_string()]),
            resources: Some(VolumeResourceRequirements {
                requests: Some(requests),
                ..Default::default()
            }),
            storage_class_name: spec.storage_class.clone(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// The controller Service. Exposes the ports gateways/relays dial — enroll-tcp,
/// sync-tcp, observe-udp — but NOT admin-tcp (loopback-only by design).
pub fn controller_service(name: &str, spec: &WiremeshControllerSpec) -> Service {
    let sync = spec.sync_tcp_port.map(|p| p as i32).unwrap_or(SYNC_TCP_PORT);
    let observe = spec.observe_udp_port.map(|p| p as i32).unwrap_or(OBSERVE_UDP_PORT);
    Service {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(labels(name)),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            selector: Some(labels(name)),
            ports: Some(vec![
                ServicePort {
                    name: Some("enroll-tcp".to_string()),
                    port: ENROLL_TCP_PORT,
                    target_port: Some(IntOrString::Int(ENROLL_TCP_PORT)),
                    protocol: Some("TCP".to_string()),
                    ..Default::default()
                },
                ServicePort {
                    name: Some("sync-tcp".to_string()),
                    port: sync,
                    target_port: Some(IntOrString::Int(sync)),
                    protocol: Some("TCP".to_string()),
                    ..Default::default()
                },
                ServicePort {
                    name: Some("observe-udp".to_string()),
                    port: observe,
                    target_port: Some(IntOrString::Int(observe)),
                    protocol: Some("UDP".to_string()),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// The admin-exec sidecar: the operator image running `idle` in the controller
/// pod, sharing the controller's UDS run-dir. The operator reconciler `kube
/// exec`s `wiremesh-operator operator-admin <op>` in this container, which then
/// talks to the controller's implicit-admin UDS (no bearer token needed). This
/// is the operator↔controller admin channel (spec §0 amendment).
/// Seeds the controller's CA (`<data_dir>/ca.pem` + `ca.key`) from the
/// cert-manager `Certificate` Secret (`tls.crt`/`tls.key`) before the controller
/// boots — so the controller's mesh CA is cert-manager-rooted. All paths are
/// constant (no CRD input interpolated). `install` sets the mode atomically.
///
/// Seed **once**: if the controller PVC already holds a CA, keep it untouched
/// (overwriting on every restart/rotation would invalidate every identity issued
/// under the prior CA). And if no CA Secret is mounted (the volume is `optional`
/// — see below), no-op and let the controller self-generate. So the CA Secret is
/// a *bootstrap* input, never a hard startup prerequisite.
fn ca_seed_init_container(image: &str) -> Container {
    Container {
        name: "ca-seed".to_string(),
        image: Some(image.to_string()),
        command: Some(vec!["/bin/sh".to_string(), "-c".to_string()]),
        args: Some(vec![format!(
            "if [ -e {DATA_DIR}/ca.pem ] || [ -e {DATA_DIR}/ca.key ]; then \
                 if [ -e {DATA_DIR}/ca.pem ] && [ -e {DATA_DIR}/ca.key ]; then exit 0; fi; \
                 echo 'wiremesh ca-seed: incomplete existing CA state on the PVC' >&2; exit 1; \
             fi; \
             if [ ! -e /mnt/ca-secret/tls.crt ] || [ ! -e /mnt/ca-secret/tls.key ]; then \
                 echo 'wiremesh ca-seed: no CA secret mounted; controller will self-generate its CA' >&2; exit 0; \
             fi; \
             install -m 0644 /mnt/ca-secret/tls.crt {DATA_DIR}/ca.pem && \
             install -m 0600 /mnt/ca-secret/tls.key {DATA_DIR}/ca.key"
        )]),
        volume_mounts: Some(vec![
            VolumeMount { name: "data".to_string(), mount_path: DATA_DIR.to_string(), ..Default::default() },
            VolumeMount {
                name: "ca-secret".to_string(),
                mount_path: "/mnt/ca-secret".to_string(),
                read_only: Some(true),
                ..Default::default()
            },
        ]),
        ..Default::default()
    }
}

pub fn admin_exec_sidecar(operator_image: &str) -> Container {
    Container {
        name: "admin-exec".to_string(),
        image: Some(operator_image.to_string()),
        command: Some(vec!["wiremesh-operator".to_string(), "idle".to_string()]),
        // Read-only view of the UDS is enough — operator-admin only dials it.
        volume_mounts: Some(vec![VolumeMount {
            name: "run".to_string(),
            mount_path: RUN_DIR.to_string(),
            ..Default::default()
        }]),
        ..Default::default()
    }
}

/// The controller Deployment: 1 replica, PVC at `/var/lib/wiremesh`, the eight
/// `WIREMESH_*` env vars (`WIREMESH_ROTATION_INTERVAL` is always present —
/// `off` when `spec.rotation_interval` is unset, the verbatim value when
/// set), listener ports, and the admin-exec sidecar (running `operator_image`)
/// the operator execs admin ops into over the shared UDS.
pub fn controller_deployment(name: &str, spec: &WiremeshControllerSpec, operator_image: &str) -> Deployment {
    let image = spec.image.clone().unwrap_or_else(|| DEFAULT_CONTROLLER_IMAGE.to_string());
    let sync = spec.sync_tcp_port.map(|p| p as i32).unwrap_or(SYNC_TCP_PORT);
    let admin = spec.admin_tcp_port.map(|p| p as i32).unwrap_or(ADMIN_TCP_PORT);
    let observe = spec.observe_udp_port.map(|p| p as i32).unwrap_or(OBSERVE_UDP_PORT);

    let container_env = vec![
        env("WIREMESH_DATA_DIR", DATA_DIR),
        env("WIREMESH_TCP_PORT", ENROLL_TCP_PORT.to_string()),
        env("WIREMESH_SYNC_TCP_PORT", sync.to_string()),
        env("WIREMESH_SOCKET_PATH", UDS_PATH),
        env("WIREMESH_ADMIN_TCP_PORT", admin.to_string()),
        env("WIREMESH_OBSERVE_UDP_PORT", observe.to_string()),
        // Bind enroll/sync/observe to all interfaces so the Service can route
        // to them (the Admin TCP listener stays loopback-only regardless).
        env("WIREMESH_BIND_IP", "0.0.0.0"),
        // Always present, never conditional. Automatic rotation off is the
        // project-wide default (root CLAUDE.md, "Key rotation"), and since
        // 2026-08-12 the controller agrees — an absent variable means no timer
        // there too. Emitting `off` anyway is deliberate on two counts: the
        // rendered Deployment states the fabric's rotation posture rather than
        // leaving it to be inferred from a missing key, and it stays correct
        // against a controller old enough to still fall back to its
        // armed-by-default (30-day) behavior. The operator owns this key under
        // SSA force-apply (`Container.env` is a `list-map-keys: [name]` merge
        // key), so a hand-set `off` IS reconciled back on every pass; the CR
        // field is where the interval is declared. See
        // `WiremeshControllerSpec::rotation_interval`. Literal duplicated
        // from `wiremesh-controller::ROTATION_DISABLED_LITERAL` (private,
        // and this crate has no production dependency on that crate) — keep
        // the two in sync by hand.
        env("WIREMESH_ROTATION_INTERVAL", spec.rotation_interval.as_deref().unwrap_or("off")),
    ];

    let container = Container {
        name: "controller".to_string(),
        image: Some(image),
        env: Some(container_env),
        ports: Some(vec![
            tcp_port("enroll-tcp", ENROLL_TCP_PORT),
            tcp_port("sync-tcp", sync),
        ]),
        volume_mounts: Some(vec![
            VolumeMount { name: "data".to_string(), mount_path: DATA_DIR.to_string(), ..Default::default() },
            VolumeMount { name: "run".to_string(), mount_path: RUN_DIR.to_string(), ..Default::default() },
        ]),
        ..Default::default()
    };

    let image = spec.image.clone().unwrap_or_else(|| DEFAULT_CONTROLLER_IMAGE.to_string());
    let pod = PodSpec {
        // Seed the controller's CA from the cert-manager `Certificate` Secret
        // (tls.crt/tls.key → the data-dir ca.pem/ca.key) BEFORE the controller
        // boots, so the controller's mesh CA is cert-manager-rooted and the same
        // CA can be handed to gateways/relays for enroll trust.
        init_containers: Some(vec![ca_seed_init_container(&image)]),
        containers: vec![container, admin_exec_sidecar(operator_image)],
        volumes: Some(vec![
            Volume {
                name: "data".to_string(),
                persistent_volume_claim: Some(PersistentVolumeClaimVolumeSource {
                    claim_name: format!("{name}-data"),
                    ..Default::default()
                }),
                ..Default::default()
            },
            Volume {
                name: "run".to_string(),
                empty_dir: Some(EmptyDirVolumeSource::default()),
                ..Default::default()
            },
            Volume {
                name: "ca-secret".to_string(),
                // `optional` so the pod still starts when no cert-manager CA
                // Secret exists — the ca-seed init-container then no-ops and the
                // controller self-generates its CA (see ca_seed_init_container).
                secret: Some(SecretVolumeSource {
                    secret_name: Some(CONTROLLER_CA_SECRET.to_string()),
                    optional: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ]),
        ..Default::default()
    };

    // Stamp a stable `component: controller` label on the POD (so the operator's
    // admin-exec transport can find the controller pod regardless of the CR's
    // user-chosen name). The Deployment SELECTOR stays `labels(name)` — a
    // selector is immutable after create, and it still matches the pod (a
    // selector is a subset match), so this is safe against an existing Deployment.
    let mut pod_labels = labels(name);
    pod_labels.insert(CONTROLLER_COMPONENT_LABEL.0.to_string(), CONTROLLER_COMPONENT_LABEL.1.to_string());

    Deployment {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(labels(name)),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            // Released, never force-applied — see `released_replicas`.
            replicas: released_replicas(),
            strategy: Some(recreate_strategy()),
            selector: LabelSelector { match_labels: Some(labels(name)), ..Default::default() },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta { labels: Some(pod_labels), ..Default::default() }),
                spec: Some(pod),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

// --------------------------------------------------------------------------
// Gateway
// --------------------------------------------------------------------------

/// Scheduler-aware node pinning for the gateway pod.
///
/// The gateway now mounts a per-gateway PVC (`gateway_pvc`). Default storage
/// classes — k3s `local-path`, most NFS/CSI provisioners — use
/// `volumeBindingMode: WaitForFirstConsumer`, which binds a PVC only AFTER the
/// scheduler has placed the consuming pod onto a node. Setting `spec.nodeName`
/// directly (the old pinning) BYPASSES the scheduler entirely, so a WFC PVC never
/// gets its "first consumer" scheduling event → the PVC stays `Pending` → the pod
/// hangs `Pending` forever (observed live: `gw-home` pinned to `zolab-worker1`).
///
/// The fix keeps the SAME node pin but expresses it as a
/// `kubernetes.io/hostname` nodeSelector, which the scheduler honors — so the pod
/// is placed (triggering WFC binding) yet still lands only on the chosen node. An
/// explicit CR `nodeSelector` is preserved, and an explicit `kubernetes.io/hostname`
/// key in it WINS over the folded-in `nodeName` (`or_insert`). Cross-node failover
/// remains out of scope (a node-local RWO PVC still binds on one node).
///
/// Takes the two pin inputs rather than a whole spec so the RELAY — which now
/// owns an identity PVC too, but whose CRD has only `nodeName` (no
/// `nodeSelector`) — routes through the same helper instead of re-introducing
/// the direct-`nodeName` bug on its own workload.
fn scheduler_aware_node_selector(
    node_name: Option<&str>,
    node_selector: Option<&BTreeMap<String, String>>,
) -> Option<BTreeMap<String, String>> {
    let mut sel = node_selector.cloned().unwrap_or_default();
    if let Some(n) = node_name {
        // `or_insert`: an explicit hostname key in the CR's nodeSelector wins.
        sel.entry("kubernetes.io/hostname".to_string()).or_insert_with(|| n.to_string());
    }
    if sel.is_empty() {
        None
    } else {
        Some(sel)
    }
}

/// The gateway's identity PVC (`<name>-gateway-data`, kind-specific so it never
/// collides with the controller's `<name>-data`), mounted at `/var/lib/wiremesh`.
/// Persists the enrolled `Identity` (`identity.json`/`wg_private.key`) across pod
/// recreation so an upgrade/reschedule/reboot never destroys it (which would
/// force a re-enroll against a spent single-use token). Mirrors `controller_pvc`:
/// RWO (node-local, single writer), instance labels, a small default (128Mi —
/// the state is a few KB) overridable via `storageClass`/`storageSize` on the CR.
pub fn gateway_pvc(name: &str, spec: &WiremeshGatewaySpec) -> PersistentVolumeClaim {
    let mut requests = BTreeMap::new();
    requests.insert(
        "storage".to_string(),
        Quantity(spec.storage_size.clone().unwrap_or_else(|| "128Mi".to_string())),
    );
    PersistentVolumeClaim {
        metadata: ObjectMeta {
            name: Some(format!("{name}-gateway-data")),
            labels: Some(labels(name)),
            ..Default::default()
        },
        spec: Some(PersistentVolumeClaimSpec {
            access_modes: Some(vec!["ReadWriteOnce".to_string()]),
            resources: Some(VolumeResourceRequirements {
                requests: Some(requests),
                ..Default::default()
            }),
            storage_class_name: spec.storage_class.clone(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// A privileged, hostNetwork gateway Deployment for one segment. An `enroll`
/// init-container turns the mounted token + CA into an on-disk `Identity`
/// (shared `state` volume, PVC-backed so it survives pod recreation); the main
/// container runs the data plane.
///
/// **Endpoint overrides** (`spec.observeEndpoint`/`spec.syncEndpoint`): when
/// set on the CR they replace the ClusterIP-derived `--observe` /
/// `--controller-sync` targets VERBATIM (single argv elements, no shell — the
/// gateway binary accepts DNS hostnames on both flags and re-resolves them).
/// Needed when kube-proxy SNATs the ClusterIP observe path (poisoning the
/// observed public mapping) or the controller is reached through an external
/// LB. The enroll init-container deliberately keeps `controller_enroll` — the
/// one-shot enroll RPC must reach the in-cluster controller and is unaffected
/// by SNAT observation.
///
/// **Pod recreation on CIDR change (rebind):** the segment CIDRs flow into the
/// enroll init-container argv (`--cidr …`), so a segment-CIDR edit changes the
/// pod template; with the `Recreate` strategy the apply then replaces the pod
/// and the (idempotent) enroll init re-runs — redeeming the refreshed rebind
/// token whenever the persisted identity is absent, and skipping otherwise. No
/// separate template-annotation bump is needed: the template already carries
/// the CIDRs.
pub fn gateway_deployment(
    gw: &WiremeshGateway,
    controller_sync: &str,
    controller_enroll: &str,
    controller_observe: &str,
    ca_secret: &str,
    token_secret: &str,
    cidrs: &[String],
) -> Deployment {
    let name = gw.metadata.name.clone().unwrap_or_else(|| "wiremesh-gateway".to_string());
    let image = gw.spec.image.clone().unwrap_or_else(|| DEFAULT_GATEWAY_IMAGE.to_string());
    let tun = safe_ifname(gw.spec.tun.as_deref());
    let wg_port = gw.spec.wg_port.unwrap_or(51820);

    // enroll init-container: reads the token from the mounted secret FILE
    // (`--token-file`, no shell/command-substitution) and the CA from the
    // mounted CA secret, writes Identity into the shared state. Invoked
    // directly (no `/bin/sh -c`) so no CRD value is ever shell-interpreted.
    // The `--cidr`s MUST match the segment CIDRs the enrollment token is bound
    // to (the controller rejects an empty/mismatched cidrs list).
    let mut enroll_args = vec![
        "enroll".to_string(),
        "--token-file".to_string(), "/etc/wiremesh-token/token".to_string(),
        "--controller".to_string(), controller_enroll.to_string(),
        "--ca".to_string(), "/etc/wiremesh-ca/ca.pem".to_string(),
        "--state-dir".to_string(), DATA_DIR.to_string(),
    ];
    for c in cidrs {
        enroll_args.push("--cidr".to_string());
        enroll_args.push(c.clone());
    }
    let enroll = Container {
        name: "enroll".to_string(),
        image: Some(image.clone()),
        command: Some(vec!["wiremesh-gateway".to_string()]),
        args: Some(enroll_args),
        volume_mounts: Some(vec![
            VolumeMount { name: "state".to_string(), mount_path: DATA_DIR.to_string(), ..Default::default() },
            VolumeMount { name: "token".to_string(), mount_path: "/etc/wiremesh-token".to_string(), read_only: Some(true), ..Default::default() },
            VolumeMount { name: "ca".to_string(), mount_path: "/etc/wiremesh-ca".to_string(), read_only: Some(true), ..Default::default() },
        ]),
        ..Default::default()
    };

    // CR-level overrides win over the ClusterIP defaults (observe: SNAT-free
    // UDP path; sync: external LB / DDNS). Passed through verbatim — the
    // builder's no-shell invariant keeps them single argv elements.
    let sync_target = gw.spec.sync_endpoint.as_deref().unwrap_or(controller_sync);
    let observe_target = gw.spec.observe_endpoint.as_deref().unwrap_or(controller_observe);
    let metrics_target = gw.spec.metrics_bind.as_deref().unwrap_or("0.0.0.0:9090");
    let main = Container {
        name: "gateway".to_string(),
        image: Some(image),
        args: Some(vec![
            "--controller-sync".to_string(), sync_target.to_string(),
            "--observe".to_string(), observe_target.to_string(),
            "--tun".to_string(), tun,
            "--wg-port".to_string(), wg_port.to_string(),
            "--state-dir".to_string(), DATA_DIR.to_string(),
            "--metrics".to_string(), metrics_target.to_string(),
        ]),
        security_context: Some(SecurityContext { privileged: Some(true), ..Default::default() }),
        volume_mounts: Some(vec![
            VolumeMount { name: "state".to_string(), mount_path: DATA_DIR.to_string(), ..Default::default() },
            VolumeMount { name: "tun".to_string(), mount_path: "/dev/net/tun".to_string(), ..Default::default() },
        ]),
        ..Default::default()
    };

    let pod = PodSpec {
        host_network: Some(true),
        // A hostNetwork pod defaults to dnsPolicy "Default" (host resolv.conf,
        // no cluster DNS). Use ClusterFirstWithHostNet so cluster names still
        // resolve — belt-and-suspenders even though we now pass ClusterIPs.
        dns_policy: Some("ClusterFirstWithHostNet".to_string()),
        // Never set `nodeName` directly — it bypasses the scheduler and a
        // WaitForFirstConsumer PVC would never bind. Pin via a
        // `kubernetes.io/hostname` nodeSelector instead (see
        // `scheduler_aware_node_selector`).
        node_name: None,
        node_selector: scheduler_aware_node_selector(
            gw.spec.node_name.as_deref(),
            gw.spec.node_selector.as_ref(),
        ),
        init_containers: Some(vec![enroll]),
        containers: vec![main],
        volumes: Some(vec![
            // Identity lives on a per-gateway PVC (`<name>-gateway-data`,
            // kind-specific to avoid colliding with the controller's
            // `<name>-data`), NOT an emptyDir — an emptyDir is destroyed on every
            // pod recreation, forcing a re-enroll against a spent single-use token.
            Volume {
                name: "state".to_string(),
                persistent_volume_claim: Some(PersistentVolumeClaimVolumeSource {
                    claim_name: format!("{name}-gateway-data"),
                    ..Default::default()
                }),
                ..Default::default()
            },
            Volume {
                name: "tun".to_string(),
                host_path: Some(HostPathVolumeSource { path: "/dev/net/tun".to_string(), type_: Some("CharDevice".to_string()) }),
                ..Default::default()
            },
            Volume {
                name: "token".to_string(),
                secret: Some(SecretVolumeSource { secret_name: Some(token_secret.to_string()), ..Default::default() }),
                ..Default::default()
            },
            Volume {
                name: "ca".to_string(),
                // The CA Secret is a cert-manager Certificate (`tls.crt`/`tls.key`);
                // expose ONLY the CA cert as `ca.pem` (what enroll `--ca` reads) —
                // never the CA private key.
                secret: Some(SecretVolumeSource {
                    secret_name: Some(ca_secret.to_string()),
                    items: Some(vec![KeyToPath {
                        key: "tls.crt".to_string(),
                        path: "ca.pem".to_string(),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ]),
        ..Default::default()
    };

    Deployment {
        metadata: ObjectMeta { name: Some(name.clone()), labels: Some(labels(&name)), ..Default::default() },
        spec: Some(DeploymentSpec {
            // Released, never force-applied — see `released_replicas`.
            replicas: released_replicas(),
            strategy: Some(recreate_strategy()),
            selector: LabelSelector { match_labels: Some(labels(&name)), ..Default::default() },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta { labels: Some(labels(&name)), ..Default::default() }),
                spec: Some(pod),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

// --------------------------------------------------------------------------
// Relay
// --------------------------------------------------------------------------

/// The relay's identity PVC (`<name>-relay-data`, kind-specific so it never
/// collides with the gateway's `<name>-gateway-data` or the controller's
/// `<name>-data`), mounted at `/var/lib/wiremesh`. Persists the enrolled certs
/// (`ca.pem`/`relay.pem`/`relay.key`) across pod recreation so a node reboot/
/// upgrade/eviction never destroys them (which would force a re-enroll against
/// a spent single-use token → `Init:Error` wedge). Mirrors `gateway_pvc`: RWO
/// (node-local, single writer), instance labels, a small default (128Mi — the
/// certs are a few KB) overridable via `storageClass`/`storageSize` on the CR.
pub fn relay_pvc(name: &str, spec: &WiremeshRelaySpec) -> PersistentVolumeClaim {
    let mut requests = BTreeMap::new();
    requests.insert(
        "storage".to_string(),
        Quantity(spec.storage_size.clone().unwrap_or_else(|| "128Mi".to_string())),
    );
    PersistentVolumeClaim {
        metadata: ObjectMeta {
            name: Some(format!("{name}-relay-data")),
            labels: Some(labels(name)),
            ..Default::default()
        },
        spec: Some(PersistentVolumeClaimSpec {
            access_modes: Some(vec!["ReadWriteOnce".to_string()]),
            resources: Some(VolumeResourceRequirements {
                requests: Some(requests),
                ..Default::default()
            }),
            storage_class_name: spec.storage_class.clone(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// A relay Deployment. An enroll init-container writes the relay's
/// `ca.pem`/`relay.pem`/`relay.key` into a shared cert dir (PVC-backed — see
/// `relay_pvc` — so the identity survives pod recreation) and is IDEMPOTENT:
/// `wiremesh-relay-enroll` skips when a complete identity is already present
/// (`wiremesh_relay::enroll::probe_identity`), so a restart never re-redeems
/// the spent single-use token. The main container runs the QUIC bridge over
/// that identity. `strategy: Recreate` because the RWO identity
/// PVC must never surge a second pod (mirror of the gateway/controller
/// reasoning); the reconciler must apply this through `deployment_apply_body`
/// (`apply_deployment`) so SSA clears the API-server defaulter's
/// `rollingUpdate` block (the same 422 the gateway/controller already fixed).
///
/// **Fails closed** on an invalid `endpoint`: v1 is IPv4-only, so the endpoint
/// must be a valid IPv4 `host:port` (the same `SocketAddrV4` the controller
/// itself requires at relay enrollment, `enrollment.rs:121`). An `Err` here
/// makes the reconciler reject the CR rather than deploy a relay that binds a
/// fallback port diverging from what it advertised/enrolled.
pub fn relay_deployment(
    r: &WiremeshRelay,
    controller_sync: &str,
    controller_enroll: &str,
    ca_secret: &str,
    token_secret: &str,
) -> anyhow::Result<Deployment> {
    let name = r.metadata.name.clone().unwrap_or_else(|| "wiremesh-relay".to_string());
    let image = r.spec.image.clone().unwrap_or_else(|| DEFAULT_RELAY_IMAGE.to_string());
    let endpoint = r.spec.endpoint.clone();
    // Validate the advertised endpoint (IPv4 host:port) up front — no silent
    // fallback. The QUIC bridge binds all interfaces on this port.
    let addr: std::net::SocketAddrV4 = endpoint.parse().with_context(|| {
        format!("WiremeshRelay endpoint {endpoint:?} must be a valid IPv4 host:port (v1 is IPv4-only)")
    })?;
    // Port 0 parses but means "OS-assigned/any" — a relay that bound :0 would
    // advertise an unusable endpoint, so reject it explicitly.
    let bind_port = addr.port();
    anyhow::ensure!(
        bind_port != 0,
        "WiremeshRelay endpoint {endpoint:?} must specify a non-zero port"
    );
    // `controllerEndpoint` override flows verbatim into argv — NOT validated
    // here. Validation lives solely in the reconciler's `validate_dial_target`
    // gate (mirroring the gateway's observe/sync overrides); duplicating it in
    // the builder would give this one value two validation call sites.
    let sync = r.spec.controller_endpoint.as_deref().unwrap_or(controller_sync).to_string();

    // enroll init-container: `--token-file` (no shell), invoked directly so the
    // CRD-supplied `endpoint` reaches the binary as one argv element (never
    // shell-interpreted); the controller further validates it is IPv4 host:port.
    let enroll = Container {
        name: "enroll".to_string(),
        image: Some(image.clone()),
        command: Some(vec!["wiremesh-relay-enroll".to_string()]),
        args: Some(vec![
            "--token-file".to_string(), "/etc/wiremesh-token/token".to_string(),
            "--controller".to_string(), controller_enroll.to_string(),
            "--ca".to_string(), "/etc/wiremesh-ca/ca.pem".to_string(),
            "--certdir".to_string(), DATA_DIR.to_string(),
            "--endpoint".to_string(), endpoint.clone(),
        ]),
        volume_mounts: Some(vec![
            VolumeMount { name: "certs".to_string(), mount_path: DATA_DIR.to_string(), ..Default::default() },
            VolumeMount { name: "token".to_string(), mount_path: "/etc/wiremesh-token".to_string(), read_only: Some(true), ..Default::default() },
            VolumeMount { name: "ca".to_string(), mount_path: "/etc/wiremesh-ca".to_string(), read_only: Some(true), ..Default::default() },
        ]),
        ..Default::default()
    };

    let main = Container {
        name: "relay".to_string(),
        image: Some(image),
        args: Some(vec![
            format!("0.0.0.0:{bind_port}"),
            DATA_DIR.to_string(),
            "--controller".to_string(),
            sync,
        ]),
        ports: Some(vec![ContainerPort {
            name: Some("quic".to_string()),
            container_port: bind_port as i32,
            protocol: Some("UDP".to_string()),
            ..Default::default()
        }]),
        volume_mounts: Some(vec![VolumeMount {
            name: "certs".to_string(),
            mount_path: DATA_DIR.to_string(),
            ..Default::default()
        }]),
        ..Default::default()
    };

    let pod = PodSpec {
        // Never set `nodeName` directly: it BYPASSES the scheduler, so the
        // relay's new RWO identity PVC (`relay_pvc`) would never get its
        // "first consumer" scheduling event under the common
        // `volumeBindingMode: WaitForFirstConsumer` storage classes (k3s
        // local-path, most CSI) → PVC Pending → pod Pending forever. This is
        // the exact bug already fixed for the gateway; the relay inherits it
        // the moment it gains a PVC. Pin via a `kubernetes.io/hostname`
        // nodeSelector instead (see `scheduler_aware_node_selector`).
        node_name: None,
        node_selector: scheduler_aware_node_selector(r.spec.node_name.as_deref(), None),
        init_containers: Some(vec![enroll]),
        containers: vec![main],
        volumes: Some(vec![
            // The enrolled identity lives on the per-relay PVC
            // (`<name>-relay-data`), NOT an emptyDir — an emptyDir is destroyed
            // on every pod recreation, forcing a re-enroll against a spent
            // single-use token (Init:Error wedge).
            Volume {
                name: "certs".to_string(),
                persistent_volume_claim: Some(PersistentVolumeClaimVolumeSource {
                    claim_name: format!("{name}-relay-data"),
                    ..Default::default()
                }),
                ..Default::default()
            },
            Volume {
                name: "token".to_string(),
                secret: Some(SecretVolumeSource { secret_name: Some(token_secret.to_string()), ..Default::default() }),
                ..Default::default()
            },
            Volume {
                name: "ca".to_string(),
                // The CA Secret is a cert-manager Certificate (`tls.crt`/`tls.key`);
                // expose ONLY the CA cert as `ca.pem` (what enroll `--ca` reads) —
                // never the CA private key.
                secret: Some(SecretVolumeSource {
                    secret_name: Some(ca_secret.to_string()),
                    items: Some(vec![KeyToPath {
                        key: "tls.crt".to_string(),
                        path: "ca.pem".to_string(),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ]),
        ..Default::default()
    };

    Ok(Deployment {
        metadata: ObjectMeta { name: Some(name.clone()), labels: Some(labels(&name)), ..Default::default() },
        spec: Some(DeploymentSpec {
            // Released, never force-applied — see `released_replicas`.
            replicas: released_replicas(),
            strategy: Some(recreate_strategy()),
            selector: LabelSelector { match_labels: Some(labels(&name)), ..Default::default() },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta { labels: Some(labels(&name)), ..Default::default() }),
                spec: Some(pod),
            },
            ..Default::default()
        }),
        ..Default::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{WiremeshGateway, WiremeshGatewaySpec, WiremeshRelay, WiremeshRelaySpec};

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

    fn gw_spec(segment: &str, storage_class: Option<String>, storage_size: Option<String>) -> WiremeshGatewaySpec {
        WiremeshGatewaySpec {
            segment_ref: segment.into(),
            node_name: None,
            node_selector: None,
            wg_port: None,
            tun: None,
            image: None,
            storage_class,
            storage_size,
            observe_endpoint: None,
            sync_endpoint: None,
            metrics_bind: None,
        }
    }

    fn gw_spec_pinned(
        node_name: Option<String>,
        node_selector: Option<BTreeMap<String, String>>,
    ) -> WiremeshGatewaySpec {
        WiremeshGatewaySpec {
            segment_ref: "aws".into(),
            node_name,
            node_selector,
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

    #[test]
    fn gateway_pinning_is_scheduler_aware() {
        // FUNCTIONAL BUG: the gateway pod now mounts a PVC. Default storage
        // classes (k3s local-path, nfs) are WaitForFirstConsumer, which binds the
        // PVC only once a POD IS SCHEDULED onto a node. Setting `spec.nodeName`
        // directly BYPASSES the scheduler, so a WFC PVC never binds → PVC Pending →
        // pod stuck forever. The operator must instead fold the CR's `nodeName`
        // into a `kubernetes.io/hostname` nodeSelector so the scheduler places the
        // pod (and the WFC PVC binds) while still pinning it to the chosen node.
        const HOSTNAME_KEY: &str = "kubernetes.io/hostname";
        let build = |spec: WiremeshGatewaySpec| {
            let gw = WiremeshGateway::new("gw-aws", spec);
            let d = gateway_deployment(
                &gw, "10.0.0.1:9500", "10.0.0.1:9400", "10.0.0.1:9600", "wm-ca", "gw-aws-token",
                &["10.10.0.0/16".to_string()],
            );
            d.spec.unwrap().template.spec.unwrap()
        };

        // 1. CR nodeName only → pod.node_name is None; nodeName folded into a
        //    kubernetes.io/hostname selector.
        let p = build(gw_spec_pinned(Some("zolab-worker1".into()), None));
        assert_eq!(
            p.node_name, None,
            "spec.nodeName must NOT be set directly (it bypasses the scheduler → a WaitForFirstConsumer PVC never binds)"
        );
        let sel = p.node_selector.expect("nodeName must be folded into a nodeSelector");
        assert_eq!(
            sel.get(HOSTNAME_KEY).map(String::as_str),
            Some("zolab-worker1"),
            "nodeName is pinned via a kubernetes.io/hostname nodeSelector so the scheduler places the pod"
        );

        // 2. CR nodeName + explicit nodeSelector → hostname added AND the explicit
        //    selector keys preserved.
        let mut extra = BTreeMap::new();
        extra.insert("disktype".to_string(), "ssd".to_string());
        let p = build(gw_spec_pinned(Some("zolab-worker1".into()), Some(extra)));
        assert_eq!(p.node_name, None, "still no direct nodeName");
        let sel = p.node_selector.expect("selector present");
        assert_eq!(
            sel.get(HOSTNAME_KEY).map(String::as_str),
            Some("zolab-worker1"),
            "hostname selector folded in alongside the explicit selector"
        );
        assert_eq!(
            sel.get("disktype").map(String::as_str),
            Some("ssd"),
            "the CR's explicit nodeSelector keys are preserved"
        );

        // 3. CR nodeSelector only (no nodeName) → passed through unchanged; no
        //    hostname key synthesized; node_name None.
        let mut only = BTreeMap::new();
        only.insert("disktype".to_string(), "ssd".to_string());
        let p = build(gw_spec_pinned(None, Some(only)));
        assert_eq!(p.node_name, None);
        let sel = p.node_selector.expect("explicit selector passed through");
        assert_eq!(sel.get("disktype").map(String::as_str), Some("ssd"));
        assert!(
            !sel.contains_key(HOSTNAME_KEY),
            "no hostname selector synthesized when the CR sets no nodeName"
        );

        // 4. CR neither → no pinning at all.
        let p = build(gw_spec_pinned(None, None));
        assert_eq!(p.node_name, None, "no nodeName");
        assert!(
            p.node_selector.as_ref().map(|m| m.is_empty()).unwrap_or(true),
            "no nodeSelector when the CR pins nothing"
        );
    }

    #[test]
    fn gateway_pvc_shape() {
        // The gateway persists its identity on a small per-gateway PVC so pod
        // recreation (upgrade/reschedule/reboot) never destroys it. Mirrors
        // controller_pvc: RWO, `<name>-data`, instance labels, a small default
        // (128Mi — the state is KB) overridable via storageClass/storageSize.
        let pvc = gateway_pvc("gw-aws", &gw_spec("aws", None, None));
        assert_eq!(
            pvc.metadata.name.as_deref(),
            Some("gw-aws-gateway-data"),
            "gateway PVC uses the kind-specific <name>-gateway-data scheme (must NOT collide with the controller's <name>-data)"
        );
        let spec = pvc.spec.as_ref().expect("PVC spec");
        assert_eq!(
            spec.access_modes.as_ref().unwrap(),
            &vec!["ReadWriteOnce".to_string()],
            "gateway identity PVC is RWO (node-local, single writer)"
        );
        let req = spec.resources.as_ref().unwrap().requests.as_ref().unwrap();
        assert_eq!(req.get("storage").unwrap().0, "128Mi", "default gateway PVC size is 128Mi");
        assert!(spec.storage_class_name.is_none(), "no storageClass unless the CR sets one");
        // Instance label parity with controller_pvc (GC/selection).
        let labels = pvc.metadata.labels.as_ref().expect("labels");
        assert_eq!(
            labels.get("app.kubernetes.io/instance").map(String::as_str),
            Some("gw-aws"),
            "PVC carries the instance label"
        );

        // storageClass / storageSize overrides flow through from the CR.
        let pvc2 = gateway_pvc("gw-aws", &gw_spec("aws", Some("fast-ssd".into()), Some("256Mi".into())));
        let spec2 = pvc2.spec.as_ref().unwrap();
        assert_eq!(spec2.storage_class_name.as_deref(), Some("fast-ssd"), "storageClass override honored");
        assert_eq!(
            spec2.resources.as_ref().unwrap().requests.as_ref().unwrap().get("storage").unwrap().0,
            "256Mi",
            "storageSize override honored"
        );
    }

    #[test]
    fn gateway_state_volume_is_pvc_not_emptydir() {
        // AVAILABILITY INVARIANT: the gateway's identity (identity.json /
        // wg_private.key) must survive pod recreation. The `state` volume MUST be
        // a PersistentVolumeClaim referencing `<name>-data`, NOT an emptyDir
        // (emptyDir is destroyed on every pod recreation → forced re-enroll).
        let gw = WiremeshGateway::new("gw-aws", gw_spec("aws", None, None));
        let d = gateway_deployment(
            &gw, "10.0.0.1:9500", "10.0.0.1:9400", "10.0.0.1:9600", "wm-ca", "gw-aws-token",
            &["10.10.0.0/16".to_string()],
        );
        let pod = d.spec.unwrap().template.spec.unwrap();
        let state = pod
            .volumes
            .as_ref()
            .unwrap()
            .iter()
            .find(|v| v.name == "state")
            .expect("state volume");
        assert!(
            state.empty_dir.is_none(),
            "state volume must NOT be an emptyDir (identity would be lost on pod recreation)"
        );
        let claim = state
            .persistent_volume_claim
            .as_ref()
            .expect("state volume must be a PersistentVolumeClaim");
        assert_eq!(
            claim.claim_name, "gw-aws-gateway-data",
            "state PVC references the gateway's kind-specific <name>-gateway-data claim (not the controller's <name>-data)"
        );
    }

    #[test]
    fn controller_deployment_has_pvc_and_admin_exec_sidecar() {
        let d = controller_deployment("wm", &ctrl_spec(), "ghcr.io/x/wiremesh-operator:test");
        let pod = d.spec.unwrap().template.spec.unwrap();
        // PVC mounted at /var/lib/wiremesh on the controller container.
        let ctr = pod.containers.iter().find(|c| c.name == "controller").unwrap();
        let mounts = ctr.volume_mounts.as_ref().unwrap();
        assert!(
            mounts.iter().any(|m| m.name == "data" && m.mount_path == "/var/lib/wiremesh"),
            "controller must mount its PVC at /var/lib/wiremesh"
        );
        let data_vol = pod.volumes.as_ref().unwrap().iter().find(|v| v.name == "data").unwrap();
        assert_eq!(data_vol.persistent_volume_claim.as_ref().unwrap().claim_name, "wm-data");
        // admin-exec sidecar (operator image) sharing the UDS run-dir.
        let sidecar = pod.containers.iter().find(|c| c.name == "admin-exec").expect("admin-exec sidecar");
        assert_eq!(sidecar.image.as_deref(), Some("ghcr.io/x/wiremesh-operator:test"));
        assert!(
            sidecar.volume_mounts.as_ref().unwrap().iter().any(|m| m.mount_path == "/run/wiremesh"),
            "admin-exec sidecar must share the controller UDS run-dir"
        );
    }

    #[test]
    fn controller_pvc_requests_storage() {
        let pvc = controller_pvc("wm", &ctrl_spec());
        let req = pvc.spec.unwrap().resources.unwrap().requests.unwrap();
        assert_eq!(req.get("storage").unwrap().0, "1Gi");
    }

    #[test]
    fn controller_service_exposes_sync_not_admin() {
        let svc = controller_service("wm", &ctrl_spec());
        let ports = svc.spec.unwrap().ports.unwrap();
        let names: Vec<&str> = ports.iter().filter_map(|p| p.name.as_deref()).collect();
        assert!(names.contains(&"sync-tcp"), "gateways/relays dial sync-tcp");
        assert!(names.contains(&"enroll-tcp"), "enroll-tcp must be exposed");
        // admin-tcp is loopback-only by design and must NOT be exposed.
        assert!(!names.contains(&"admin-tcp"), "admin-tcp must not be on the Service");
    }

    #[test]
    fn gateway_and_controller_use_recreate_strategy() {
        // Both workloads own an RWO PVC (and the gateway is also hostNetwork), so
        // the Deployment must use the `Recreate` strategy — a RollingUpdate would
        // surge a second pod that cannot mount the RWO PVC (or bind the host net),
        // wedging the rollout. Kill the old pod first, then start the new one.
        let gw = WiremeshGateway::new("gw-aws", gw_spec("aws", None, None));
        let gd = gateway_deployment(
            &gw, "10.0.0.1:9500", "10.0.0.1:9400", "10.0.0.1:9600", "wm-ca", "gw-aws-token",
            &["10.10.0.0/16".to_string()],
        );
        let cd = controller_deployment("wm", &ctrl_spec(), "op:test");
        for (d, what) in [(gd, "gateway"), (cd, "controller")] {
            let strat = d
                .spec
                .unwrap()
                .strategy
                .unwrap_or_else(|| panic!("{what} Deployment must set a strategy"));
            assert_eq!(
                strat.type_.as_deref(),
                Some("Recreate"),
                "{what} Deployment must use the Recreate strategy (RWO PVC / hostNetwork must not surge a 2nd pod)"
            );
        }
    }

    #[test]
    fn gateway_is_privileged_hostnetwork() {
        let gw = WiremeshGateway::new(
            "gw-aws",
            WiremeshGatewaySpec {
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
            },
        );
        let d = gateway_deployment(&gw, "10.0.0.1:9500", "10.0.0.1:9400", "10.0.0.1:9600", "wm-ca", "gw-aws-token", &["10.10.0.0/16".to_string()]);
        let pod = d.spec.unwrap().template.spec.unwrap();
        assert_eq!(pod.host_network, Some(true), "gateway pod must be hostNetwork");
        assert!(
            pod.containers.iter().any(|c| c
                .security_context
                .as_ref()
                .and_then(|s| s.privileged)
                == Some(true)),
            "a gateway container must be privileged"
        );
        let vols = pod.volumes.as_ref().unwrap();
        assert!(
            vols.iter().any(|v| v
                .host_path
                .as_ref()
                .map(|h| h.path == "/dev/net/tun")
                .unwrap_or(false)),
            "gateway must expose /dev/net/tun"
        );
        assert!(
            vols.iter().any(|v| v
                .secret
                .as_ref()
                .and_then(|s| s.secret_name.as_deref())
                == Some("gw-aws-token")),
            "gateway must mount the enrollment-token secret"
        );
    }

    #[test]
    fn enroll_init_containers_use_no_shell() {
        // A hostile CRD value must never be shell-interpreted: the enroll
        // init-containers invoke the binary directly (no /bin/sh -c) and carry
        // no command-substitution / shell-metacharacter args.
        let gw = WiremeshGateway::new(
            "gw",
            WiremeshGatewaySpec {
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
            },
        );
        let gd = gateway_deployment(&gw, "10.0.0.1:9500", "10.0.0.1:9400", "10.0.0.1:9600", "wm-ca", "gw-token", &["10.0.0.0/8".to_string()]);
        let r = WiremeshRelay::new(
            "r",
            WiremeshRelaySpec {
                endpoint: "203.0.113.9:4443".into(),
                node_name: None,
                image: None,
                storage_class: None,
                storage_size: None,
                controller_endpoint: None,
            },
        );
        let rd = relay_deployment(&r, "wm:9500", "wm:9400", "wm-ca", "r-token").unwrap();

        for d in [gd, rd] {
            let pod = d.spec.unwrap().template.spec.unwrap();
            let enroll = pod.init_containers.as_ref().unwrap().iter().find(|c| c.name == "enroll").unwrap();
            let cmd = enroll.command.as_ref().unwrap();
            assert!(!cmd.iter().any(|c| c == "/bin/sh" || c == "sh" || c == "-c"), "no shell wrapper: {cmd:?}");
            for a in enroll.args.as_ref().unwrap() {
                assert!(!a.contains("$("), "no command substitution in {a:?}");
            }
            // `--token-file` is used (token never in argv/shell).
            assert!(enroll.args.as_ref().unwrap().iter().any(|a| a == "--token-file"));
        }
    }

    #[test]
    fn safe_ifname_rejects_flag_smuggling() {
        assert_eq!(safe_ifname(Some("wg0")), "wg0");
        assert_eq!(safe_ifname(Some("wg-eth1")), "wg-eth1");
        assert_eq!(safe_ifname(Some("--metrics")), "wg0", "leading-dash rejected");
        assert_eq!(safe_ifname(Some("a; rm -rf /")), "wg0", "metachars rejected");
        assert_eq!(safe_ifname(Some("waytoolonginterfacename")), "wg0", "over-length rejected");
        assert_eq!(safe_ifname(None), "wg0");
    }

    #[test]
    fn relay_enrolls_and_binds_endpoint_port() {
        let r = WiremeshRelay::new(
            "relay-eu",
            WiremeshRelaySpec { endpoint: "203.0.113.9:4443".into(), node_name: None, image: None, storage_class: None, storage_size: None, controller_endpoint: None },
        );
        let d = relay_deployment(&r, "wm:9500", "wm:9400", "wm-ca", "relay-eu-token").unwrap();
        let pod = d.spec.unwrap().template.spec.unwrap();
        // enroll init container present.
        assert!(pod.init_containers.as_ref().unwrap().iter().any(|c| c.name == "enroll"));
        // main relay binds the advertised endpoint's port.
        let main = pod.containers.iter().find(|c| c.name == "relay").unwrap();
        let args = main.args.as_ref().unwrap();
        assert!(args.iter().any(|a| a == "0.0.0.0:4443"), "relay binds the endpoint port: {args:?}");
    }

    #[test]
    fn relay_deployment_fails_closed_on_invalid_endpoint() {
        for bad in ["not-an-endpoint", "203.0.113.9", "example.com:4443", "[::1]:4443", "203.0.113.9:4443; rm -rf /", "203.0.113.9:0"] {
            let r = WiremeshRelay::new(
                "r",
                WiremeshRelaySpec { endpoint: bad.into(), node_name: None, image: None, storage_class: None, storage_size: None, controller_endpoint: None },
            );
            assert!(
                relay_deployment(&r, "wm:9500", "wm:9400", "wm-ca", "r-token").is_err(),
                "endpoint {bad:?} must be rejected (v1 is IPv4 host:port only)"
            );
        }
    }

    #[test]
    fn controller_binds_all_interfaces_for_service_routing() {
        // The controller must bind enroll/sync/observe to 0.0.0.0 (not the
        // loopback default) so the ClusterIP Service can route to the pod —
        // otherwise gateways get `Connection refused` (the bug found on-cluster).
        let d = controller_deployment("wm", &ctrl_spec(), "op:test");
        let pod = d.spec.unwrap().template.spec.unwrap();
        let ctr = pod.containers.iter().find(|c| c.name == "controller").unwrap();
        let env = ctr.env.as_ref().unwrap();
        let bind = env.iter().find(|e| e.name == "WIREMESH_BIND_IP").expect("WIREMESH_BIND_IP env");
        assert_eq!(bind.value.as_deref(), Some("0.0.0.0"), "controller must bind all interfaces");
    }

    #[test]
    fn controller_seeds_ca_from_cert_manager_secret() {
        // A `ca-seed` init-container copies the cert-manager Certificate Secret
        // (tls.crt/tls.key) into the controller data-dir as ca.pem/ca.key BEFORE
        // boot, so the controller's mesh CA is cert-manager-rooted.
        let d = controller_deployment("wm", &ctrl_spec(), "op:test");
        let pod = d.spec.unwrap().template.spec.unwrap();
        let seed = pod
            .init_containers
            .as_ref()
            .expect("init containers")
            .iter()
            .find(|c| c.name == "ca-seed")
            .expect("ca-seed init container");
        // Mounts BOTH the data volume (dest) and the CA-secret volume (source, RO).
        let mounts = seed.volume_mounts.as_ref().unwrap();
        assert!(
            mounts.iter().any(|m| m.name == "data" && m.mount_path == "/var/lib/wiremesh"),
            "ca-seed must mount the controller data dir"
        );
        assert!(
            mounts.iter().any(|m| m.name == "ca-secret" && m.read_only == Some(true)),
            "ca-seed must mount the CA secret read-only"
        );
        // Args seed BOTH ca.pem (from tls.crt) and ca.key (from tls.key).
        let args = seed.args.as_ref().unwrap().join(" ");
        assert!(args.contains("tls.crt") && args.contains("ca.pem"), "seeds ca.pem from tls.crt: {args:?}");
        assert!(args.contains("tls.key") && args.contains("ca.key"), "seeds ca.key from tls.key: {args:?}");
        // Seed ONCE: never clobber an existing CA on the PVC (guards a restart/
        // rotation from invalidating already-issued identities).
        assert!(
            args.contains(&format!("[ -e {DATA_DIR}/ca.pem ]")),
            "ca-seed must skip when a CA already exists on the PVC: {args:?}"
        );
        // No-op when no CA secret is mounted (so it is not a hard startup dep).
        assert!(
            args.contains("/mnt/ca-secret/tls.crt") && args.contains("self-generate"),
            "ca-seed must no-op (self-generate) when no CA secret is mounted: {args:?}"
        );
        // The pod sources the CA-secret volume from CONTROLLER_CA_SECRET, and the
        // volume is OPTIONAL so an absent Secret does not block controller boot.
        let ca_vol = pod.volumes.as_ref().unwrap().iter().find(|v| v.name == "ca-secret").expect("ca-secret volume");
        let ca_src = ca_vol.secret.as_ref().expect("ca-secret is a Secret source");
        assert_eq!(
            ca_src.secret_name.as_deref(),
            Some(CONTROLLER_CA_SECRET),
            "ca-secret volume must source the cert-manager CA Secret"
        );
        assert_eq!(ca_src.optional, Some(true), "the CA secret volume must be optional (no hard startup dependency)");
    }

    #[test]
    fn gateway_and_relay_ca_mount_exposes_cert_only_never_key() {
        // SECURITY INVARIANT: gateways/relays trust the CA but must NEVER receive
        // the CA private key. The CA volume must project ONLY tls.crt -> ca.pem.
        let gw = WiremeshGateway::new(
            "gw",
            WiremeshGatewaySpec {
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
            },
        );
        let gd = gateway_deployment(&gw, "10.0.0.1:9500", "10.0.0.1:9400", "10.0.0.1:9600", "wm-ca", "gw-token", &["10.0.0.0/8".to_string()]);
        let r = WiremeshRelay::new(
            "r",
            WiremeshRelaySpec { endpoint: "203.0.113.9:4443".into(), node_name: None, image: None, storage_class: None, storage_size: None, controller_endpoint: None },
        );
        let rd = relay_deployment(&r, "wm:9500", "wm:9400", "wm-ca", "r-token").unwrap();

        for d in [gd, rd] {
            let pod = d.spec.unwrap().template.spec.unwrap();
            let ca_vol = pod.volumes.as_ref().unwrap().iter().find(|v| v.name == "ca").expect("ca volume");
            let src = ca_vol.secret.as_ref().expect("ca volume is a Secret source");
            assert_eq!(src.secret_name.as_deref(), Some("wm-ca"));
            let items = src.items.as_ref().expect("CA volume MUST use explicit items (never project the whole Secret)");
            // Exactly one projected item: tls.crt -> ca.pem.
            assert_eq!(items.len(), 1, "CA volume must project exactly one key");
            assert_eq!(items[0].key, "tls.crt");
            assert_eq!(items[0].path, "ca.pem");
            // The CA private key must never be projected under any path.
            assert!(
                !items.iter().any(|i| i.key == "tls.key"),
                "the CA private key (tls.key) must NEVER reach a gateway/relay"
            );
        }
    }

    // ---- T1: strategy:Recreate apply must clear the defaulter's rollingUpdate ----

    /// Assert the strategy carried by an APPLY BODY is `Recreate` AND explicitly
    /// nulls `rollingUpdate` — a JSON `null` that IS PRESENT, not an omitted key.
    ///
    /// The distinction is load-bearing: a typed `rolling_update: None` serializes
    /// to an OMITTED field, so a server-side apply leaves the API-server
    /// defaulter's `rollingUpdate` block in place → the merged object has
    /// `type: Recreate` AND a `rollingUpdate` block → the API server 422s
    /// (`spec.strategy.rollingUpdate: Forbidden ... when type is 'Recreate'`).
    /// Only an explicit `null` in the apply body tells SSA to REMOVE the
    /// defaulter's field. `Value::index` returns `Value::Null` for a MISSING key
    /// too, so `.is_null()` alone can't tell "present null" from "absent" — the
    /// `contains_key` check is what actually pins the fix.
    fn assert_strategy_nulls_rolling_update(body: &serde_json::Value, what: &str) {
        let strat = body
            .get("spec")
            .and_then(|s| s.get("strategy"))
            .unwrap_or_else(|| panic!("{what} apply body must carry spec.strategy: {body:#}"));
        assert_eq!(
            strat.get("type").and_then(|t| t.as_str()),
            Some("Recreate"),
            "{what} apply body strategy.type must be Recreate"
        );
        let obj = strat
            .as_object()
            .unwrap_or_else(|| panic!("{what} strategy must be a JSON object: {strat:#}"));
        assert!(
            obj.contains_key("rollingUpdate"),
            "{what} apply body must include an EXPLICIT strategy.rollingUpdate key (an omitted \
             field lets SSA keep the API-server defaulter's block → 422): {strat:#}"
        );
        assert!(
            strat["rollingUpdate"].is_null(),
            "{what} apply body strategy.rollingUpdate must be JSON null so SSA removes the \
             defaulter's block: {strat:#}"
        );
    }

    #[test]
    fn gateway_apply_body_nulls_rolling_update_under_recreate() {
        // BUG (zolab e2e): applying `strategy.type: Recreate` over an existing
        // RollingUpdate Deployment 422s because a typed `rolling_update: None`
        // serializes to OMITTED, so SSA won't remove the defaulter's rollingUpdate
        // block. The applied body must set `spec.strategy.rollingUpdate = null`.
        //
        // IMPLEMENTER SURFACE (must be added — this test won't compile until then):
        //   pub fn deployment_apply_body(dep: &Deployment) -> serde_json::Value
        // returning the JSON body to hand to `Patch::Apply`, with
        // `spec.strategy.rollingUpdate` injected as `Value::Null` whenever
        // `spec.strategy.type == "Recreate"`. The gateway reconciler's apply of
        // `gateway_deployment(...)` must route through this helper. Keep the typed
        // builder returning `type: Recreate`; the null-injection is at the apply
        // boundary. Must be idempotent (re-null-ing an already-null field is a
        // no-op).
        let gw = WiremeshGateway::new("gw-aws", gw_spec("aws", None, None));
        let d = gateway_deployment(
            &gw, "10.0.0.1:9500", "10.0.0.1:9400", "10.0.0.1:9600", "wm-ca", "gw-aws-token",
            &["10.10.0.0/16".to_string()],
        );
        let body = deployment_apply_body(&d);
        assert_strategy_nulls_rolling_update(&body, "gateway");
    }

    #[test]
    fn controller_apply_body_nulls_rolling_update_under_recreate() {
        // Same defaulter-conflict bug on the controller Deployment's apply path.
        // The controller reconciler's apply of `controller_deployment(...)` must
        // route through `deployment_apply_body` so the applied body nulls
        // `spec.strategy.rollingUpdate`.
        let d = controller_deployment("wm", &ctrl_spec(), "op:test");
        let body = deployment_apply_body(&d);
        assert_strategy_nulls_rolling_update(&body, "controller");
    }
}
