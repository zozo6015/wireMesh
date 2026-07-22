//! `WiremeshController` reconciler: materializes the controller PVC + Service +
//! Deployment (with the admin-token bootstrap sidecar), waits for it to be
//! available and the admin token minted, and reports `status.ready`.

use super::{apply, owner_ref, service_dns, Context, Error};
use crate::crd::{Condition, WiremeshController, WiremeshControllerStatus};
use crate::workloads;
use futures::StreamExt;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{PersistentVolumeClaim, Secret, Service};
use kube::api::{Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::watcher;
use kube::{Api, ResourceExt};
use std::sync::Arc;
use std::time::Duration;

/// The Secret the bootstrap sidecar writes the operator's admin token into.
pub fn admin_token_secret(controller_name: &str) -> String {
    format!("{controller_name}-admin-token")
}

async fn reconcile(cr: Arc<WiremeshController>, ctx: Arc<Context>) -> Result<Action, Error> {
    let ns = ctx.namespace.clone();
    let name = cr.name_any();
    let client = ctx.client.clone();
    let oref = owner_ref(cr.as_ref())?;

    // Server-side-apply the three child objects (owner-referenced → GC'd with
    // the CR). Namespace is stamped here since the builders are namespace-free.
    let mut pvc = workloads::controller_pvc(&name, &cr.spec);
    pvc.metadata.namespace = Some(ns.clone());
    pvc.metadata.owner_references = Some(vec![oref.clone()]);
    apply(&Api::<PersistentVolumeClaim>::namespaced(client.clone(), &ns), &pvc).await?;

    let mut svc = workloads::controller_service(&name, &cr.spec);
    svc.metadata.namespace = Some(ns.clone());
    svc.metadata.owner_references = Some(vec![oref.clone()]);
    apply(&Api::<Service>::namespaced(client.clone(), &ns), &svc).await?;

    let mut dep = workloads::controller_deployment(&name, &cr.spec);
    dep.metadata.namespace = Some(ns.clone());
    dep.metadata.owner_references = Some(vec![oref.clone()]);
    apply(&Api::<Deployment>::namespaced(client.clone(), &ns), &dep).await?;

    // Ready iff the Deployment reports an available replica AND the bootstrap
    // sidecar has populated the admin-token Secret.
    let live = Api::<Deployment>::namespaced(client.clone(), &ns).get(&name).await?;
    let available = live
        .status
        .and_then(|s| s.available_replicas)
        .unwrap_or(0)
        >= 1;
    let token_ready = matches!(
        Api::<Secret>::namespaced(client.clone(), &ns)
            .get_opt(&admin_token_secret(&name))
            .await?,
        Some(s) if s.data.as_ref().map(|d| d.contains_key("token")).unwrap_or(false)
    );
    let ready = available && token_ready;

    // The advertised control-plane endpoint gateways/relays dial (sync-tcp).
    // (admin-tcp is loopback-only and never exposed — spec §0.)
    let sync_port = cr.spec.sync_tcp_port.unwrap_or(9500);
    let status = WiremeshControllerStatus {
        ready,
        admin_endpoint: Some(service_dns(&name, &ns, sync_port)),
        observed_version: None,
        conditions: vec![Condition {
            type_: "Ready".into(),
            status: if ready { "True" } else { "False" }.into(),
            reason: if ready { "AllComponentsReady" } else { "WaitingForController" }.into(),
            message: if ready {
                "controller Deployment available and admin token minted".into()
            } else {
                "waiting for controller Deployment + admin-token bootstrap".into()
            },
        }],
    };
    Api::<WiremeshController>::all(client.clone())
        .patch_status(
            &name,
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({ "status": status })),
        )
        .await?;

    Ok(Action::requeue(Duration::from_secs(if ready { 300 } else { 10 })))
}

fn error_policy(_cr: Arc<WiremeshController>, err: &Error, _ctx: Arc<Context>) -> Action {
    tracing::warn!("WiremeshController reconcile error: {err}");
    Action::requeue(Duration::from_secs(15))
}

/// Run the `WiremeshController` controller loop until shutdown.
pub async fn run(ctx: Arc<Context>) {
    let client = ctx.client.clone();
    Controller::new(Api::<WiremeshController>::all(client.clone()), watcher::Config::default())
        .owns(Api::<Deployment>::namespaced(client.clone(), &ctx.namespace), watcher::Config::default())
        .owns(Api::<Service>::namespaced(client.clone(), &ctx.namespace), watcher::Config::default())
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            match res {
                Ok((obj, _)) => tracing::info!("WiremeshController reconciled: {}", obj.name),
                Err(e) => tracing::warn!("WiremeshController reconcile failed: {e}"),
            }
        })
        .await;
}
