//! Pure builders that turn the CRDs into Kubernetes workload objects
//! (`k8s-openapi` types). No cluster I/O — the reconcilers apply these.
//!
//! Port/env/arg wiring mirrors the real binaries:
//! - controller: env-configured (`WIREMESH_DATA_DIR`, `WIREMESH_TCP_PORT`,
//!   `WIREMESH_SYNC_TCP_PORT`, `WIREMESH_SOCKET_PATH`, `WIREMESH_ADMIN_TCP_PORT`,
//!   `WIREMESH_OBSERVE_UDP_PORT` — see `crates/wiremesh-controller/src/main.rs`).
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
    WiremeshControllerSpec, WiremeshGateway, WiremeshRelay,
};
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::{
    Container, ContainerPort, EmptyDirVolumeSource, EnvVar, HostPathVolumeSource, PodSpec,
    PodTemplateSpec, PersistentVolumeClaim, PersistentVolumeClaimSpec,
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

fn tcp_port(name: &str, port: i32) -> ContainerPort {
    ContainerPort {
        name: Some(name.to_string()),
        container_port: port,
        protocol: Some("TCP".to_string()),
        ..Default::default()
    }
}

/// Host part of a `host:port` address (everything before the last `:`).
fn host_of(addr: &str) -> &str {
    addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr)
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

/// The controller Deployment: 1 replica, PVC at `/var/lib/wiremesh`, the six
/// `WIREMESH_*` env vars, listener ports, and the admin-exec sidecar (running
/// `operator_image`) the operator execs admin ops into over the shared UDS.
pub fn controller_deployment(name: &str, spec: &WiremeshControllerSpec, operator_image: &str) -> Deployment {
    let image = spec.image.clone().unwrap_or_else(|| DEFAULT_CONTROLLER_IMAGE.to_string());
    let sync = spec.sync_tcp_port.map(|p| p as i32).unwrap_or(SYNC_TCP_PORT);
    let admin = spec.admin_tcp_port.map(|p| p as i32).unwrap_or(ADMIN_TCP_PORT);
    let observe = spec.observe_udp_port.map(|p| p as i32).unwrap_or(OBSERVE_UDP_PORT);

    let container = Container {
        name: "controller".to_string(),
        image: Some(image),
        env: Some(vec![
            env("WIREMESH_DATA_DIR", DATA_DIR),
            env("WIREMESH_TCP_PORT", ENROLL_TCP_PORT.to_string()),
            env("WIREMESH_SYNC_TCP_PORT", sync.to_string()),
            env("WIREMESH_SOCKET_PATH", UDS_PATH),
            env("WIREMESH_ADMIN_TCP_PORT", admin.to_string()),
            env("WIREMESH_OBSERVE_UDP_PORT", observe.to_string()),
        ]),
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

    let pod = PodSpec {
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
        ]),
        ..Default::default()
    };

    Deployment {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(labels(name)),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(1),
            selector: LabelSelector { match_labels: Some(labels(name)), ..Default::default() },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta { labels: Some(labels(name)), ..Default::default() }),
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

/// A privileged, hostNetwork gateway Deployment for one segment. An `enroll`
/// init-container turns the mounted token + CA into an on-disk `Identity`
/// (shared `state` volume); the main container runs the data plane.
pub fn gateway_deployment(
    gw: &WiremeshGateway,
    controller_sync: &str,
    controller_enroll: &str,
    ca_secret: &str,
    token_secret: &str,
) -> Deployment {
    let name = gw.metadata.name.clone().unwrap_or_else(|| "wiremesh-gateway".to_string());
    let image = gw.spec.image.clone().unwrap_or_else(|| DEFAULT_GATEWAY_IMAGE.to_string());
    let tun = safe_ifname(gw.spec.tun.as_deref());
    let wg_port = gw.spec.wg_port.unwrap_or(51820);
    let observe = format!("{}:{OBSERVE_UDP_PORT}", host_of(controller_sync));

    // enroll init-container: reads the token from the mounted secret FILE
    // (`--token-file`, no shell/command-substitution) and the CA from the
    // mounted CA secret, writes Identity into the shared state. Invoked
    // directly (no `/bin/sh -c`) so no CRD value is ever shell-interpreted.
    let enroll = Container {
        name: "enroll".to_string(),
        image: Some(image.clone()),
        command: Some(vec!["wiremesh-gateway".to_string()]),
        args: Some(vec![
            "enroll".to_string(),
            "--token-file".to_string(), "/etc/wiremesh-token/token".to_string(),
            "--controller".to_string(), controller_enroll.to_string(),
            "--ca".to_string(), "/etc/wiremesh-ca/ca.pem".to_string(),
            "--state-dir".to_string(), DATA_DIR.to_string(),
        ]),
        volume_mounts: Some(vec![
            VolumeMount { name: "state".to_string(), mount_path: DATA_DIR.to_string(), ..Default::default() },
            VolumeMount { name: "token".to_string(), mount_path: "/etc/wiremesh-token".to_string(), read_only: Some(true), ..Default::default() },
            VolumeMount { name: "ca".to_string(), mount_path: "/etc/wiremesh-ca".to_string(), read_only: Some(true), ..Default::default() },
        ]),
        ..Default::default()
    };

    let main = Container {
        name: "gateway".to_string(),
        image: Some(image),
        args: Some(vec![
            "--controller-sync".to_string(), controller_sync.to_string(),
            "--observe".to_string(), observe,
            "--tun".to_string(), tun,
            "--wg-port".to_string(), wg_port.to_string(),
            "--state-dir".to_string(), DATA_DIR.to_string(),
            "--metrics".to_string(), "0.0.0.0:9090".to_string(),
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
        node_name: gw.spec.node_name.clone(),
        node_selector: gw.spec.node_selector.clone(),
        init_containers: Some(vec![enroll]),
        containers: vec![main],
        volumes: Some(vec![
            Volume { name: "state".to_string(), empty_dir: Some(EmptyDirVolumeSource::default()), ..Default::default() },
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
                secret: Some(SecretVolumeSource { secret_name: Some(ca_secret.to_string()), ..Default::default() }),
                ..Default::default()
            },
        ]),
        ..Default::default()
    };

    Deployment {
        metadata: ObjectMeta { name: Some(name.clone()), labels: Some(labels(&name)), ..Default::default() },
        spec: Some(DeploymentSpec {
            replicas: Some(1),
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

/// A relay Deployment. An enroll init-container writes the relay's
/// `ca.pem`/`relay.pem`/`relay.key` into a shared cert dir; the main container
/// runs the QUIC bridge over it.
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
    let sync = controller_sync.to_string();

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
        node_name: r.spec.node_name.clone(),
        init_containers: Some(vec![enroll]),
        containers: vec![main],
        volumes: Some(vec![
            Volume { name: "certs".to_string(), empty_dir: Some(EmptyDirVolumeSource::default()), ..Default::default() },
            Volume {
                name: "token".to_string(),
                secret: Some(SecretVolumeSource { secret_name: Some(token_secret.to_string()), ..Default::default() }),
                ..Default::default()
            },
            Volume {
                name: "ca".to_string(),
                secret: Some(SecretVolumeSource { secret_name: Some(ca_secret.to_string()), ..Default::default() }),
                ..Default::default()
            },
        ]),
        ..Default::default()
    };

    Ok(Deployment {
        metadata: ObjectMeta { name: Some(name.clone()), labels: Some(labels(&name)), ..Default::default() },
        spec: Some(DeploymentSpec {
            replicas: Some(1),
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
        }
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
            },
        );
        let d = gateway_deployment(&gw, "wm:9500", "wm:9400", "wm-ca", "gw-aws-token");
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
            },
        );
        let gd = gateway_deployment(&gw, "wm:9500", "wm:9400", "wm-ca", "gw-token");
        let r = WiremeshRelay::new(
            "r",
            WiremeshRelaySpec {
                endpoint: "203.0.113.9:4443".into(),
                node_name: None,
                image: None,
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
            WiremeshRelaySpec { endpoint: "203.0.113.9:4443".into(), node_name: None, image: None },
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
                WiremeshRelaySpec { endpoint: bad.into(), node_name: None, image: None },
            );
            assert!(
                relay_deployment(&r, "wm:9500", "wm:9400", "wm-ca", "r-token").is_err(),
                "endpoint {bad:?} must be rejected (v1 is IPv4 host:port only)"
            );
        }
    }
}
