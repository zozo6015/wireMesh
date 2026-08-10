//! CRD reconcilers (kube-rs `Controller` runtime). Each submodule owns one
//! kind; this module holds the shared context, error type, and the
//! server-side-apply / owner-reference / DNS helpers they all use.
//!
//! **Validation status:** the pure helpers (`service_dns`, the name/guard fns
//! in each submodule) are unit-tested in-container. The reconcile loops
//! themselves (apiserver I/O, finalizers, requeue) are **not** covered by any
//! automated test — they compile here, but that is all. A `kind` e2e harness
//! was planned (plan Task 9) to prove them; it was never built — no kind
//! config, script, workflow, or cluster-creating test exists anywhere in this
//! repo. The reconcile loops' only validation to date has been MANUAL, against
//! real clusters (zolab, then the px host — see the `zolab e2e` bug comments
//! in `workloads.rs` and `controllers/gateway.rs`, which record real findings
//! from that manual testing, not automated coverage).
//!
//! **Admin transport (spec §0 amendment):** the controller's Admin TCP is
//! loopback-only, so in-cluster admin ops (`Apply`/`MintToken`/`RegisterRelay`/
//! `Drain`) go through the UDS via an admin-exec sidecar — see
//! [`crate::admin_exec`]. The `fabric`/`gateway`/`relay` reconcilers take an
//! `AdminExec` so the transport is swappable (a gRPC `FabricAdmin` for local
//! tests, kube `exec` in production).
//!
//! # Teardown order (delete-path finalizers)
//!
//! The clean teardown order is: **delete the dependent CRs first**
//! (`WiremeshGateway` → gateway drain; `WiremeshSegment` → controller-side
//! segment delete; `WiremeshPolicy`/`WiremeshRelay` — no controller-side
//! cleanup), and delete the **`WiremeshController` CR last**. But
//! `kubectl delete -f all.yaml` (or a namespace/cluster teardown) makes no such
//! promise — the controller CR (and with it the controller pod, via owner-ref
//! GC) may be gone before the dependent finalizers run, at which point every
//! admin call can only fail and the CRs would wedge in `Terminating` forever.
//!
//! So the delete-path cleanup is **best-effort with respect to a GONE
//! controller** ([`cleanup_should_skip`]): when the `WiremeshController` CR is
//! absent, or no controller pod is Running, the finalizer logs a loud warning
//! naming exactly what was skipped (the drain id / the segment delete) and
//! completes — the controller-side state died with the controller, so there is
//! nothing left to clean. When the controller IS present, a genuine RPC error
//! still hard-fails the finalizer (kube retries it) — best-effort is never a
//! silent swallow of real failures. Accepted trade-off (decided with the
//! reviewer): a merely-restarting controller pod (CR present, pod briefly not
//! Running) will skip the cleanup — a missed drain/segment-delete is a manual
//! `fabricctl` fix, whereas a Terminating-wedged CR blocks whole-namespace
//! teardown.

pub mod controller;
pub mod fabric;
pub mod gateway;
pub mod relay;

use crate::crd::WiremeshController;
use k8s_openapi::api::apps::v1::Deployment;
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
    /// Serializes every fabric list→render→`Admin.Apply` critical section (and
    /// the Segment finalizer's delete+re-render). Without it two concurrent
    /// reconciles can interleave list→apply so an Apply-path render that still
    /// saw a segment resurrects it into the fabric AFTER its finalizer deleted
    /// it. The CR **list must happen inside** the locked section — see
    /// `fabric::apply_fabric`. Arc'd because `Context` is `Clone`.
    pub fabric_apply_lock: Arc<tokio::sync::Mutex<()>>,
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

/// Every identity/data PVC the operator owns is CREATE-ONLY: create it when
/// absent, and NEVER apply/patch an existing one. A bound PVC's
/// `storageClassName` and `resources.requests.storage` are immutable, so
/// re-applying them on every reconcile 422s the whole reconcile forever.
/// Shared choke point for the controller, gateway, and relay reconcilers.
pub fn pvc_needs_create(
    existing: Option<&k8s_openapi::api::core::v1::PersistentVolumeClaim>,
) -> bool {
    existing.is_none()
}

/// The delete-path best-effort decision (see the module doc's *Teardown order*
/// section): should a finalizer SKIP its controller-side cleanup because the
/// controller is GONE?
///
/// * `true` → the `WiremeshController` CR is absent (the CR is the source of
///   truth — an orphaned pod still matching the selector is being GC'd), or no
///   controller pod is Running (the admin exec can only fail). Log a loud
///   warning naming what was skipped and complete the finalizer.
/// * `false` → the controller is present and Running: perform the cleanup, and
///   keep hard-failing (→ finalizer retry) on a genuine RPC error.
pub fn cleanup_should_skip(controller_cr_exists: bool, controller_pod_running: bool) -> bool {
    !controller_cr_exists || !controller_pod_running
}

/// Probe the two [`cleanup_should_skip`] inputs from the cluster:
/// `controller_cr_exists` ← any `WiremeshController` CR listed;
/// `controller_pod_running` ← a Running pod matching the SAME selector the
/// admin transport resolves its exec target with (`AdminExec::Exec`'s
/// `pod_label`, which honors `WIREMESH_CONTROLLER_LABEL`; falling back to
/// [`crate::workloads::controller_pod_selector`]). Probing a different selector
/// than the transport actually uses could declare the controller "gone" while
/// the admin channel works perfectly.
///
/// **Never skips in gRPC admin mode.** With `WIREMESH_ADMIN_ADDR` set the
/// operator dials the Admin API directly — no in-cluster controller pod (and no
/// `WiremeshController` CR) is required for the cleanup to succeed, so the
/// "controller is gone" inference does not apply and the cleanup must run.
///
/// CONSERVATIVE on a probe failure: treat the controller as PRESENT (don't
/// skip) — the cleanup then proceeds and a genuine failure hard-fails into the
/// normal finalizer retry, never silently skipping on a transient apiserver
/// hiccup.
pub async fn controller_cleanup_skip(ctx: &Context) -> bool {
    use k8s_openapi::api::core::v1::Pod;
    if ctx.admin.is_grpc() {
        // Direct-gRPC transport: the admin API is reachable independently of
        // any CR/pod, so there is nothing to infer "gone" from.
        return false;
    }
    let cr_exists = match Api::<WiremeshController>::all(ctx.client.clone())
        .list(&ListParams::default())
        .await
    {
        Ok(list) => !list.items.is_empty(),
        Err(e) => {
            tracing::warn!(
                "cleanup probe: listing WiremeshController CRs failed ({e}); treating the \
                 controller as present (cleanup will proceed and retry on failure)"
            );
            true
        }
    };
    let selector = ctx
        .admin
        .pod_label()
        .map(|s| s.to_string())
        .unwrap_or_else(crate::workloads::controller_pod_selector);
    let pod_running = match Api::<Pod>::namespaced(ctx.client.clone(), &ctx.namespace)
        .list(&ListParams::default().labels(&selector))
        .await
    {
        Ok(list) => list
            .items
            .iter()
            .any(|p| p.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Running")),
        Err(e) => {
            tracing::warn!(
                "cleanup probe: listing controller pods failed ({e}); treating a controller \
                 pod as Running (cleanup will proceed and retry on failure)"
            );
            true
        }
    };
    cleanup_should_skip(cr_exists, pod_running)
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

/// Server-side-apply a Deployment through its JSON apply body
/// (`workloads::deployment_apply_body`) rather than the typed object, so a
/// `Recreate` strategy explicitly nulls the API-server defaulter's
/// `rollingUpdate` block. Applying the typed Deployment directly (via `apply`)
/// omits the field, leaving the defaulter's block in place → the merged object
/// 422s (`rollingUpdate: Forbidden ... when type is 'Recreate'`). See
/// `docs/research/ops-finding-pvc-adoption-migration.md` (bug 1).
pub async fn apply_deployment(api: &Api<Deployment>, dep: &Deployment) -> Result<(), Error> {
    let name = dep.meta().name.clone().ok_or(Error::MissingField(".metadata.name"))?;
    let pp = PatchParams::apply(FIELD_MANAGER).force();
    let body = crate::workloads::deployment_apply_body(dep);
    api.patch(&name, &pp, &Patch::Apply(body)).await?;
    Ok(())
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
