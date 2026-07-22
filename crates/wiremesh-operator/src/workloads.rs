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
const DEFAULT_FABRICCTL_IMAGE: &str = "ghcr.io/zozo6015/wiremesh-fabricctl:latest";

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

/// The admin-token bootstrap sidecar: a native sidecar (init container with
/// `restartPolicy: Always`) that shares the controller's UDS run-dir, waits for
/// the socket, and mints the operator's admin token over the implicit-admin
/// UDS. Writing that token into `out_secret` is wired by the WiremeshController
/// reconciler (Task 5) — this builder produces the container shape.
pub fn bootstrap_init_container(admin_uds: &str, out_secret: &str) -> Container {
    Container {
        name: "admin-token-bootstrap".to_string(),
        image: Some(DEFAULT_FABRICCTL_IMAGE.to_string()),
        // Native sidecar: starts alongside the controller, does not gate the
        // main container on completion (it never completes — it idles once the
        // token is minted).
        restart_policy: Some("Always".to_string()),
        command: Some(vec!["/bin/sh".to_string(), "-c".to_string()]),
        args: Some(vec![format!(
            "until [ -S {admin_uds} ]; do sleep 1; done; \
             fabricctl token mint operator --role admin --socket {admin_uds} \
               > {RUN_DIR}/operator.token; \
             echo 'admin-token-bootstrap: minted operator token'; sleep infinity"
        )]),
        env: Some(vec![env("TOKEN_SECRET_NAME", out_secret)]),
        volume_mounts: Some(vec![VolumeMount {
            name: "run".to_string(),
            mount_path: RUN_DIR.to_string(),
            ..Default::default()
        }]),
        ..Default::default()
    }
}

/// The controller Deployment: 1 replica, PVC at `/var/lib/wiremesh`, the six
/// `WIREMESH_*` env vars, listener ports, and the admin-token bootstrap sidecar.
pub fn controller_deployment(name: &str, spec: &WiremeshControllerSpec) -> Deployment {
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
        init_containers: Some(vec![bootstrap_init_container(UDS_PATH, &format!("{name}-admin-token"))]),
        containers: vec![container],
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
    let tun = gw.spec.tun.clone().unwrap_or_else(|| "wg0".to_string());
    let wg_port = gw.spec.wg_port.unwrap_or(51820);
    let observe = format!("{}:{OBSERVE_UDP_PORT}", host_of(controller_sync));

    // enroll init-container: reads the token from the mounted secret file and
    // the CA from the mounted CA secret, writes Identity into the shared state.
    let enroll = Container {
        name: "enroll".to_string(),
        image: Some(image.clone()),
        command: Some(vec!["/bin/sh".to_string(), "-c".to_string()]),
        args: Some(vec![format!(
            "wiremesh-gateway enroll --token \"$(cat /etc/wiremesh-token/token)\" \
             --controller {controller_enroll} --ca /etc/wiremesh-ca/ca.pem \
             --state-dir {DATA_DIR}"
        )]),
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
pub fn relay_deployment(
    r: &WiremeshRelay,
    controller_sync: &str,
    controller_enroll: &str,
    ca_secret: &str,
    token_secret: &str,
) -> Deployment {
    let name = r.metadata.name.clone().unwrap_or_else(|| "wiremesh-relay".to_string());
    let image = r.spec.image.clone().unwrap_or_else(|| DEFAULT_RELAY_IMAGE.to_string());
    let endpoint = r.spec.endpoint.clone();
    // The QUIC bridge binds all interfaces on the advertised endpoint's port.
    let bind_port = endpoint.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok()).unwrap_or(51820);
    let sync = controller_sync.to_string();

    let enroll = Container {
        name: "enroll".to_string(),
        image: Some(image.clone()),
        command: Some(vec!["/bin/sh".to_string(), "-c".to_string()]),
        args: Some(vec![format!(
            "wiremesh-relay-enroll --token \"$(cat /etc/wiremesh-token/token)\" \
             --controller {controller_enroll} --ca /etc/wiremesh-ca/ca.pem \
             --certdir {DATA_DIR} --endpoint {endpoint}"
        )]),
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
    fn controller_deployment_has_pvc_and_bootstrap_init() {
        let d = controller_deployment("wm", &ctrl_spec());
        let pod = d.spec.unwrap().template.spec.unwrap();
        // PVC mounted at /var/lib/wiremesh.
        let ctr = &pod.containers[0];
        let mounts = ctr.volume_mounts.as_ref().unwrap();
        assert!(
            mounts.iter().any(|m| m.name == "data" && m.mount_path == "/var/lib/wiremesh"),
            "controller must mount its PVC at /var/lib/wiremesh"
        );
        let data_vol = pod.volumes.as_ref().unwrap().iter().find(|v| v.name == "data").unwrap();
        assert_eq!(
            data_vol.persistent_volume_claim.as_ref().unwrap().claim_name,
            "wm-data"
        );
        // Bootstrap init container present + named.
        let inits = pod.init_containers.as_ref().unwrap();
        assert!(
            inits.iter().any(|c| c.name == "admin-token-bootstrap"),
            "controller must have the admin-token-bootstrap init container"
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
    fn relay_enrolls_and_binds_endpoint_port() {
        let r = WiremeshRelay::new(
            "relay-eu",
            WiremeshRelaySpec { endpoint: "203.0.113.9:4443".into(), node_name: None, image: None },
        );
        let d = relay_deployment(&r, "wm:9500", "wm:9400", "wm-ca", "relay-eu-token");
        let pod = d.spec.unwrap().template.spec.unwrap();
        // enroll init container present.
        assert!(pod.init_containers.as_ref().unwrap().iter().any(|c| c.name == "enroll"));
        // main relay binds the advertised endpoint's port.
        let main = pod.containers.iter().find(|c| c.name == "relay").unwrap();
        let args = main.args.as_ref().unwrap();
        assert!(args.iter().any(|a| a == "0.0.0.0:4443"), "relay binds the endpoint port: {args:?}");
    }
}
