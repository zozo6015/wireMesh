//! CRD reconcilers (kube-rs `Controller` runtime). Each submodule owns one
//! kind; this module holds the shared context, error type, and the
//! server-side-apply / owner-reference / DNS helpers they all use.
//!
//! **Validation status:** the pure helpers (`service_dns`, the name/guard fns
//! in each submodule) are unit-tested in-container. The reconcile loops
//! themselves (apiserver I/O, finalizers, requeue) are proven by the `kind`
//! e2e (plan Task 9) — they compile here but are NOT cluster-tested in the dev
//! container.
//!
//! **Admin transport (spec §0 amendment):** the controller's Admin TCP is
//! loopback-only, so in-cluster admin ops (`Apply`/`MintToken`/`RegisterRelay`/
//! `Drain`) go through the UDS via an admin-exec sidecar — see
//! [`crate::admin_exec`]. The `fabric`/`gateway`/`relay` reconcilers take an
//! `AdminExec` so the transport is swappable (a gRPC `FabricAdmin` for local
//! tests, kube `exec` in production).

pub mod controller;
pub mod fabric;
pub mod gateway;
pub mod relay;

use crate::crd::WiremeshController;
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::api::{ListParams, Patch, PatchParams};
use kube::{Api, Client, Resource, ResourceExt};
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;
use std::sync::Arc;

/// The field-manager string the operator uses for every server-side apply.
pub const FIELD_MANAGER: &str = "wiremesh-operator";

/// Shared reconcile context: the kube client, the namespace the operator
/// materializes workloads into, and the admin transport.
#[derive(Clone)]
pub struct Context {
    pub client: Client,
    /// The namespace the operator runs in and creates workloads into.
    pub namespace: String,
    /// How the operator reaches the controller Admin API (UDS exec sidecar in
    /// production; a direct gRPC client in tests). Shared, cheap to clone.
    pub admin: Arc<crate::admin_exec::AdminExec>,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("kube api error: {0}")]
    Kube(#[from] kube::Error),
    #[error("admin op failed: {0}")]
    Admin(#[source] anyhow::Error),
    #[error("resource is missing {0}")]
    MissingField(&'static str),
}

/// `<name>.<ns>.svc:<port>` — the in-cluster DNS a peer dials a Service at.
pub fn service_dns(name: &str, namespace: &str, port: u16) -> String {
    format!("{name}.{namespace}.svc:{port}")
}

/// An `OwnerReference` to `owner` so the child objects the operator creates are
/// garbage-collected by Kubernetes when the CR is deleted. A cluster-scoped CR
/// may own namespaced children (k8s allows cluster-scoped→namespaced).
pub fn owner_ref<K>(owner: &K) -> Result<OwnerReference, Error>
where
    K: Resource<DynamicType = ()>,
{
    Ok(OwnerReference {
        api_version: K::api_version(&()).to_string(),
        kind: K::kind(&()).to_string(),
        name: owner.name_any(),
        uid: owner.uid().ok_or(Error::MissingField(".metadata.uid"))?,
        controller: Some(true),
        block_owner_deletion: Some(true),
    })
}

/// Server-side-apply a namespaced object (idempotent, force-owned by the
/// operator's field manager).
pub async fn apply<K>(api: &Api<K>, obj: &K) -> Result<K, Error>
where
    K: Resource + Serialize + DeserializeOwned + Clone + Debug,
    K::DynamicType: Default,
{
    let name = obj.meta().name.clone().ok_or(Error::MissingField(".metadata.name"))?;
    let pp = PatchParams::apply(FIELD_MANAGER).force();
    Ok(api.patch(&name, &pp, &Patch::Apply(obj)).await?)
}

/// The controller's control-plane endpoints gateways/relays dial, as **numeric
/// `IP:port`** (the controller Service's ClusterIP). Numeric — because the
/// gateway/relay binaries parse these flags into `std::net::SocketAddr` (no DNS
/// resolution) — and a ClusterIP is stable for the Service's lifetime and
/// reachable from hostNetwork pods via kube-proxy, so no cluster DNS is needed.
pub struct ControllerAddrs {
    /// Sync (mTLS) — `--controller-sync` / relay `--controller`.
    pub sync: String,
    /// Enrollment RPC (server-TLS) — the enroll init-container `--controller`.
    pub enroll: String,
    /// Observation UDP — gateway `--observe`.
    pub observe: String,
}

/// Resolve the (single-tenant) controller's endpoints from its Service's
/// ClusterIP. Errs (→ requeue) if no `WiremeshController` exists yet or its
/// Service has no ClusterIP assigned.
pub async fn controller_endpoints(ctx: &Context) -> Result<ControllerAddrs, Error> {
    let ctrls = Api::<WiremeshController>::all(ctx.client.clone())
        .list(&ListParams::default())
        .await?;
    let c = ctrls.items.first().ok_or(Error::MissingField("WiremeshController (none exists)"))?;
    let name = c.name_any();
    let sync_port = c.spec.sync_tcp_port.unwrap_or(9500);
    let observe_port = c.spec.observe_udp_port.unwrap_or(9600);
    let enroll_port = 9400; // WIREMESH_TCP_PORT (enrollment listener)

    let svc = Api::<Service>::namespaced(ctx.client.clone(), &ctx.namespace).get(&name).await?;
    let ip = svc
        .spec
        .and_then(|s| s.cluster_ip)
        .filter(|ip| !ip.is_empty() && ip != "None")
        .ok_or(Error::MissingField("controller Service clusterIP (not assigned yet)"))?;
    // v1 is IPv4-only, and `ip:port` (unbracketed) is only well-formed for IPv4.
    // On a dual-stack cluster with an IPv6-primary Service, reject clearly rather
    // than emit a malformed address the gateway/relay can't parse.
    if ip.parse::<std::net::Ipv4Addr>().is_err() {
        return Err(Error::MissingField(
            "controller Service clusterIP must be IPv4 (v1 is IPv4-only); set the Service ipFamilies to IPv4",
        ));
    }

    Ok(ControllerAddrs {
        sync: format!("{ip}:{sync_port}"),
        enroll: format!("{ip}:{enroll_port}"),
        observe: format!("{ip}:{observe_port}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_dns_is_cluster_fqdn() {
        assert_eq!(service_dns("wiremesh-controller", "wiremesh", 9500), "wiremesh-controller.wiremesh.svc:9500");
    }
}
