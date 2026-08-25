//! Fabric reconciler: any `WiremeshSegment`/`WiremeshPolicy` change re-renders
//! the whole fabric YAML and `Apply`s it (idempotent). A `WiremeshSegment`
//! finalizer deletes the segment on removal (Apply is create/update-only).
//!
//! NOTE: uses the shared `AdminExec` transport (gRPC in tests; UDS exec sidecar
//! in production — see `crate::admin_exec`). Finalizer wiring for Policy is not
//! needed (removing a policy just re-renders without it); the Segment finalizer
//! is the one deletion that needs an explicit `delete_segment`.

use super::{Context, Error};
use crate::crd::{WiremeshPolicy, WiremeshResourceStatus, WiremeshSegment};
use futures::StreamExt;
use kube::api::{ListParams, Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::finalizer::{finalizer, Event};
use kube::runtime::watcher;
use kube::{Api, ResourceExt};
use std::sync::Arc;
use std::time::Duration;

const SEGMENT_FINALIZER: &str = "wiremesh.io/segment-cleanup";

/// Render + Apply the full fabric from ALL segments + policies. Shared by the
/// apply path and (after a segment delete) the finalizer's post-delete render.
///
/// Serialized on `ctx.fabric_apply_lock`: the CR LIST must happen INSIDE the
/// critical section, otherwise a concurrent Segment finalizer's
/// delete+re-render can interleave with an Apply-path render that still saw
/// the segment — resurrecting the ghost segment into the fabric after its
/// delete. The finalizer's Cleanup arm holds the same lock across its whole
/// delete+apply sequence (via [`apply_fabric_locked`], since a tokio `Mutex`
/// is not reentrant).
async fn apply_fabric(ctx: &Context) -> Result<(), Error> {
    let _guard = ctx.fabric_apply_lock.lock().await;
    apply_fabric_locked(ctx).await
}

/// The body of [`apply_fabric`]; the caller MUST hold `ctx.fabric_apply_lock`.
async fn apply_fabric_locked(ctx: &Context) -> Result<(), Error> {
    let client = ctx.client.clone();
    let segs = Api::<WiremeshSegment>::all(client.clone())
        .list(&ListParams::default())
        .await?;
    let pols = Api::<WiremeshPolicy>::all(client.clone())
        .list(&ListParams::default())
        .await?;
    // Exclude objects being deleted: during a Segment finalizer the object still
    // appears in the list (it has a deletionTimestamp but isn't gone yet), so
    // including it would re-add the very segment the finalizer just deleted.
    let seg_specs: Vec<_> = segs
        .iter()
        .filter(|s| s.metadata.deletion_timestamp.is_none())
        .map(|s| s.spec.clone())
        .collect();
    // The set of segment names that will be in the fabric.
    let live_segments: std::collections::HashSet<&str> =
        seg_specs.iter().map(|s| s.segment_name.as_str()).collect();
    // Exclude policies being deleted, AND any policy that references a segment
    // no longer present (or being deleted): the controller's policy validator
    // rejects a fabric with a dangling `from`/`to`, which would make the Segment
    // delete-finalizer's post-delete re-render fail forever and wedge the CR in
    // Terminating. Dropping the dangling policy is the graceful convergence.
    let pol_specs: Vec<_> = pols
        .iter()
        .filter(|p| p.metadata.deletion_timestamp.is_none())
        .map(|p| p.spec.clone())
        .filter(|p| {
            live_segments.contains(p.from.as_str()) && live_segments.contains(p.to.as_str())
        })
        .collect();
    let yaml = crate::fabric::render_fabric_yaml(&seg_specs, &pol_specs);
    ctx.admin.apply(&yaml).await.map_err(Error::Admin)?;
    Ok(())
}

async fn reconcile(seg: Arc<WiremeshSegment>, ctx: Arc<Context>) -> Result<Action, Error> {
    let api = Api::<WiremeshSegment>::all(ctx.client.clone());
    finalizer(&api, SEGMENT_FINALIZER, seg, |event| async {
        match event {
            Event::Apply(seg) => {
                apply_fabric(&ctx).await?;
                let status = WiremeshResourceStatus {
                    applied: true,
                    applied_version: None,
                    message: Some("fabric applied".into()),
                };
                api.patch_status(
                    &seg.name_any(),
                    &PatchParams::default(),
                    &Patch::Merge(serde_json::json!({ "status": status })),
                )
                .await?;
                Ok(Action::requeue(Duration::from_secs(300)))
            }
            Event::Cleanup(seg) => {
                // BEST-EFFORT with respect to a GONE controller (see the
                // `controllers` module doc's *Teardown order*): with the
                // WiremeshController CR (or its pod) already gone, the segment
                // delete + re-render can only fail forever and this CR would
                // wedge in `Terminating`. Skip loudly and complete the
                // finalizer; a present-but-erroring controller still
                // hard-fails below (finalizer retry).
                if super::controller_cleanup_skip(&ctx).await {
                    tracing::warn!(
                        "segment {name} finalizer: controller is GONE (WiremeshController CR \
                         absent or no Running controller pod) — SKIPPING the controller-side \
                         segment delete and the fabric re-render. If a controller still exists \
                         elsewhere, delete the segment manually (fabricctl).",
                        name = seg.spec.segment_name,
                    );
                    return Ok(Action::await_change());
                }
                // Segment removed from the fabric: delete it in the controller,
                // then re-render so peers/policy referencing it are updated.
                // The fabric lock is held across the WHOLE delete+re-render so
                // a concurrent Apply-path render (whose list still saw this
                // segment) cannot slot in between and resurrect it.
                let _guard = ctx.fabric_apply_lock.lock().await;
                ctx.admin
                    .delete_segment_by_name(&seg.spec.segment_name)
                    .await
                    .map_err(Error::Admin)?;
                apply_fabric_locked(&ctx).await?;
                Ok(Action::await_change())
            }
        }
    })
    .await
    .map_err(|e: kube::runtime::finalizer::Error<Error>| {
        Error::Admin(anyhow::anyhow!("finalizer: {e}"))
    })
}

fn error_policy(_seg: Arc<WiremeshSegment>, err: &Error, _ctx: Arc<Context>) -> Action {
    tracing::warn!("fabric reconcile error: {err}");
    Action::requeue(Duration::from_secs(15))
}

/// Run the fabric controller: primary = Segments, and Policy changes re-trigger
/// a reconcile of every segment (so the aggregate re-renders).
pub async fn run(ctx: Arc<Context>) {
    use kube::runtime::reflector::ObjectRef;
    let client = ctx.client.clone();
    let controller = Controller::new(
        Api::<WiremeshSegment>::all(client.clone()),
        watcher::Config::default(),
    );
    // The primary store lets a Policy change enqueue a reconcile for every
    // Segment, so the aggregate fabric re-renders (the runtime dedups).
    let store = controller.store();
    controller
        .watches(
            Api::<WiremeshPolicy>::all(client.clone()),
            watcher::Config::default(),
            move |_pol| {
                store
                    .state()
                    .into_iter()
                    .map(|s| ObjectRef::from_obj(&*s))
                    .collect::<Vec<_>>()
            },
        )
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            if let Err(e) = res {
                tracing::warn!("fabric reconcile failed: {e}");
            }
        })
        .await;
}
