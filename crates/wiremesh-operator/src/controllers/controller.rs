//! `WiremeshController` reconciler: materializes the controller PVC + Service +
//! Deployment (with the admin-token bootstrap sidecar), waits for it to be
//! available and the admin token minted, and reports `status.ready`.

use super::{apply, apply_deployment, owner_ref, service_dns, Context, Error, Readiness};
use crate::crd::{Condition, WiremeshController, WiremeshControllerStatus};
use crate::workloads;
use futures::StreamExt;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{PersistentVolumeClaim, Service};
use kube::api::{Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::watcher;
use kube::{Api, ResourceExt};
use std::sync::Arc;
use std::time::Duration;

async fn reconcile(cr: Arc<WiremeshController>, ctx: Arc<Context>) -> Result<Action, Error> {
    let ns = ctx.namespace.clone();
    let name = cr.name_any();
    let client = ctx.client.clone();
    let oref = owner_ref(cr.as_ref())?;

    // Server-side-apply the child objects (owner-referenced → GC'd with the
    // CR). Namespace is stamped here since the builders are namespace-free.
    //
    // The PVC is CREATE-ONLY (shared `pvc_needs_create` guard, same as the
    // gateway/relay reconcilers): a bound PVC's `storageClassName` /
    // `resources.requests.storage` are immutable, so re-applying it on every
    // pass 422s permanently the moment a user edits `spec.storageSize`/
    // `storageClass` on the CR — wedging the whole reconcile (the Service and
    // Deployment applies below would never run again).
    let pvc_api = Api::<PersistentVolumeClaim>::namespaced(client.clone(), &ns);
    let existing_pvc = pvc_api.get_opt(&format!("{name}-data")).await?;
    if super::pvc_needs_create(existing_pvc.as_ref()) {
        let mut pvc = workloads::controller_pvc(&name, &cr.spec);
        pvc.metadata.namespace = Some(ns.clone());
        pvc.metadata.owner_references = Some(vec![oref.clone()]);
        apply(&pvc_api, &pvc).await?;
    }

    let mut svc = workloads::controller_service(&name, &cr.spec);
    svc.metadata.namespace = Some(ns.clone());
    svc.metadata.owner_references = Some(vec![oref.clone()]);
    apply(&Api::<Service>::namespaced(client.clone(), &ns), &svc).await?;

    let operator_image = std::env::var("OPERATOR_IMAGE")
        .unwrap_or_else(|_| workloads::DEFAULT_OPERATOR_IMAGE.to_string());
    let mut dep = workloads::controller_deployment(&name, &cr.spec, &operator_image);
    dep.metadata.namespace = Some(ns.clone());
    dep.metadata.owner_references = Some(vec![oref.clone()]);
    // Route through deployment_apply_body so the Recreate strategy explicitly
    // nulls the defaulter's rollingUpdate (avoids the 422 on apply-over-existing;
    // ops-finding-pvc-adoption-migration.md bug 1).
    apply_deployment(&Api::<Deployment>::namespaced(client.clone(), &ns), &dep).await?;

    // Ready iff the Deployment reports an available replica AND it is meant to
    // be up. (No admin-token bootstrap: the operator reaches Admin over the
    // pod-local implicit-admin UDS via the admin-exec sidecar — spec §0.)
    //
    // The desired count matters now that the operator releases `spec.replicas`
    // rather than force-applying `1` (`workloads::released_replicas`): a
    // controller scaled to 0 on purpose reports `availableReplicas: 0` exactly
    // like one that can never start. Calling that `WaitingForController`
    // forever — and requeuing every 10s to re-confirm it — would be a false
    // alarm with nothing behind it. See `super::workload_readiness`.
    let live = Api::<Deployment>::namespaced(client.clone(), &ns)
        .get(&name)
        .await?;
    let readiness = super::deployment_readiness(&live);
    let ready = readiness == Readiness::Available;
    let scaled_down = readiness == Readiness::ScaledDown;

    // The advertised control-plane endpoint gateways/relays dial (sync-tcp).
    // (admin-tcp is loopback-only and never exposed — spec §0.)
    let sync_port = cr.spec.sync_tcp_port.unwrap_or(9500);
    let status =
        WiremeshControllerStatus {
            ready,
            admin_endpoint: Some(service_dns(&name, &ns, sync_port)),
            observed_version: None,
            // `Ready` keeps its meaning (an available replica) and stays FALSE while
            // scaled down — the control plane really is not serving. What changes is
            // the reason it gives, and the second condition beside it: `ScaledDown`
            // separates "deliberately off" from "trying and failing", so
            // `kubectl describe` and any alerting rule can tell them apart. Both
            // conditions are always emitted (True/False) rather than only-when-true,
            // so a consumer never has to read absence as false.
            conditions: vec![
            Condition {
                type_: "Ready".into(),
                status: if ready { "True" } else { "False" }.into(),
                reason: match readiness {
                    Readiness::Available => "AllComponentsReady",
                    Readiness::ScaledDown => "ScaledDown",
                    Readiness::Starting => "WaitingForController",
                }
                .into(),
                message: match readiness {
                    Readiness::Available => "controller Deployment available".into(),
                    Readiness::ScaledDown => {
                        "controller Deployment is scaled to 0 replicas — not serving, by request"
                            .into()
                    }
                    Readiness::Starting => {
                        "waiting for controller Deployment to become available".into()
                    }
                },
            },
            Condition {
                type_: "ScaledDown".into(),
                status: if scaled_down { "True" } else { "False" }.into(),
                reason: if scaled_down { "ReplicasZero" } else { "ReplicasNonZero" }.into(),
                message: if scaled_down {
                    "spec.replicas is explicitly 0 on the controller Deployment; the operator \
                     released the field, so this is a deliberate scale-down and will not be \
                     reverted"
                        .into()
                } else {
                    "controller Deployment is not scaled down".into()
                },
            },
        ],
        };
    Api::<WiremeshController>::all(client.clone())
        .patch_status(
            &name,
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({ "status": status })),
        )
        .await?;

    // A scale-down requeues on the settled cadence, not the 10s not-ready one:
    // nothing will change until a human scales back up, and that arrives through
    // the Deployment watch (`.owns` below) rather than by polling.
    Ok(Action::requeue(Duration::from_secs(
        if ready || scaled_down {
            super::SETTLED_REQUEUE_SECS
        } else {
            10
        },
    )))
}

fn error_policy(_cr: Arc<WiremeshController>, err: &Error, _ctx: Arc<Context>) -> Action {
    tracing::warn!("WiremeshController reconcile error: {err}");
    Action::requeue(Duration::from_secs(15))
}

/// Run the `WiremeshController` controller loop until shutdown.
pub async fn run(ctx: Arc<Context>) {
    let client = ctx.client.clone();
    Controller::new(
        Api::<WiremeshController>::all(client.clone()),
        watcher::Config::default(),
    )
    .owns(
        Api::<Deployment>::namespaced(client.clone(), &ctx.namespace),
        watcher::Config::default(),
    )
    .owns(
        Api::<Service>::namespaced(client.clone(), &ctx.namespace),
        watcher::Config::default(),
    )
    // Watch the data PVC too (parity with the gateway/relay reconcilers):
    // a deleted or externally-edited PVC enqueues its owning CR at once
    // rather than waiting out the 300s requeue. The apply itself stays
    // CREATE-ONLY (`pvc_needs_create`) — this only affects when we look.
    .owns(
        Api::<PersistentVolumeClaim>::namespaced(client.clone(), &ctx.namespace),
        watcher::Config::default(),
    )
    .run(reconcile, error_policy, ctx)
    .for_each(|res| async move {
        match res {
            Ok((obj, _)) => tracing::info!("WiremeshController reconciled: {}", obj.name),
            Err(e) => tracing::warn!("WiremeshController reconcile failed: {e}"),
        }
    })
    .await;
}
