//! `WiremeshGateway` reconciler: mint a single-use enrollment token (once),
//! store it in a Secret, deploy the privileged hostNetwork gateway, and report
//! `status.enrolled`/`gateway_id`. Finalizer drains the gateway on delete.

use super::{apply, owner_ref, service_dns, Context, Error};
use crate::crd::{Condition, WiremeshController, WiremeshGateway, WiremeshGatewayStatus, WiremeshSegment};
use crate::workloads;
use futures::StreamExt;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::ByteString;
use kube::api::{ListParams, Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::finalizer::{finalizer, Event};
use kube::runtime::watcher;
use kube::{Api, ResourceExt};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

const GATEWAY_FINALIZER: &str = "wiremesh.io/gateway-drain";
/// Convention: the CA bundle the operator publishes for gateway/relay enroll
/// `--ca` (extracted from the controller — see the CA-bundle plumbing).
pub const CONTROLLER_CA_SECRET: &str = "wiremesh-controller-ca";

pub fn token_secret_name(gateway_name: &str) -> String {
    format!("wiremesh-gw-{gateway_name}-token")
}

/// Mint only when no populated token Secret already exists (single-use tokens
/// must not be re-minted on every reconcile).
pub fn needs_token(existing: Option<&Secret>) -> bool {
    match existing {
        None => true,
        Some(s) => !s.data.as_ref().map(|d| d.contains_key("token")).unwrap_or(false),
    }
}

/// The controller's sync + enroll endpoints (single-tenant: one controller per
/// cluster, so the operator uses THE `WiremeshController`).
async fn controller_endpoints(ctx: &Context) -> Result<(String, String), Error> {
    let ctrls = Api::<WiremeshController>::all(ctx.client.clone()).list(&ListParams::default()).await?;
    let c = ctrls.items.first().ok_or(Error::MissingField("WiremeshController (none exists)"))?;
    let name = c.name_any();
    let sync = c.spec.sync_tcp_port.unwrap_or(9500);
    // Enrollment RPC listens on WIREMESH_TCP_PORT (workloads ENROLL_TCP_PORT).
    let enroll = 9400;
    Ok((service_dns(&name, &ctx.namespace, sync), service_dns(&name, &ctx.namespace, enroll)))
}

async fn reconcile(gw: Arc<WiremeshGateway>, ctx: Arc<Context>) -> Result<Action, Error> {
    let api = Api::<WiremeshGateway>::all(ctx.client.clone());
    finalizer(&api, GATEWAY_FINALIZER, gw, |event| async {
        match event {
            Event::Apply(gw) => apply_gateway(&gw, &ctx).await,
            Event::Cleanup(gw) => cleanup_gateway(&gw, &ctx).await,
        }
    })
    .await
    .map_err(|e: kube::runtime::finalizer::Error<Error>| Error::Admin(anyhow::anyhow!("finalizer: {e}")))
}

async fn apply_gateway(gw: &WiremeshGateway, ctx: &Context) -> Result<Action, Error> {
    let ns = ctx.namespace.clone();
    let name = gw.name_any();
    let client = ctx.client.clone();
    let secrets = Api::<Secret>::namespaced(client.clone(), &ns);
    let token_secret = token_secret_name(&name);

    // Resolve the segment's CIDRs (the token is bound to them).
    let seg = Api::<WiremeshSegment>::all(client.clone())
        .get(&gw.spec.segment_ref)
        .await?;
    let cidrs = seg.spec.cidrs.clone();

    // Mint the enrollment token ONCE.
    if needs_token(secrets.get_opt(&token_secret).await?.as_ref()) {
        let token = ctx.admin.mint_gateway_token(&cidrs).await.map_err(Error::Admin)?;
        let mut data = BTreeMap::new();
        data.insert("token".to_string(), ByteString(token.into_bytes()));
        let mut sec = Secret {
            metadata: kube::core::ObjectMeta {
                name: Some(token_secret.clone()),
                namespace: Some(ns.clone()),
                owner_references: Some(vec![owner_ref(gw)?]),
                ..Default::default()
            },
            data: Some(data),
            ..Default::default()
        };
        sec.type_ = Some("Opaque".into());
        apply(&secrets, &sec).await?;
    }

    // Deploy the gateway.
    let (sync, enroll) = controller_endpoints(ctx).await?;
    let mut dep = workloads::gateway_deployment(gw, &sync, &enroll, CONTROLLER_CA_SECRET, &token_secret);
    dep.metadata.namespace = Some(ns.clone());
    dep.metadata.owner_references = Some(vec![owner_ref(gw)?]);
    apply(&Api::<Deployment>::namespaced(client.clone(), &ns), &dep).await?;

    // Status from the controller's gateway roster.
    let gateways = ctx.admin.list_gateways().await.map_err(Error::Admin)?;
    let row = gateways.iter().find(|g| g.segment == seg.spec.segment_name);
    let enrolled = row.is_some();
    let status = WiremeshGatewayStatus {
        enrolled,
        gateway_id: row.map(|g| g.id),
        path_state: row.map(|g| g.status.clone()),
        conditions: vec![Condition {
            type_: "Enrolled".into(),
            status: if enrolled { "True" } else { "False" }.into(),
            reason: if enrolled { "GatewayRegistered" } else { "AwaitingEnrollment" }.into(),
            message: if enrolled { "gateway registered with the controller".into() } else { "gateway not yet enrolled".into() },
        }],
    };
    api_status(ctx, &name, status).await?;
    Ok(Action::requeue(Duration::from_secs(if enrolled { 300 } else { 15 })))
}

async fn cleanup_gateway(gw: &WiremeshGateway, ctx: &Context) -> Result<Action, Error> {
    // Drain the gateway in the controller (withdraw + revoke) before the
    // workload is GC'd with the CR.
    let seg_name = Api::<WiremeshSegment>::all(ctx.client.clone())
        .get_opt(&gw.spec.segment_ref)
        .await?
        .map(|s| s.spec.segment_name);
    if let Some(seg_name) = seg_name {
        let gateways = ctx.admin.list_gateways().await.map_err(Error::Admin)?;
        if let Some(row) = gateways.iter().find(|g| g.segment == seg_name) {
            ctx.admin.drain(row.id).await.map_err(Error::Admin)?;
        }
    }
    Ok(Action::await_change())
}

async fn api_status(ctx: &Context, name: &str, status: WiremeshGatewayStatus) -> Result<(), Error> {
    Api::<WiremeshGateway>::all(ctx.client.clone())
        .patch_status(name, &PatchParams::default(), &Patch::Merge(serde_json::json!({ "status": status })))
        .await?;
    Ok(())
}

fn error_policy(_gw: Arc<WiremeshGateway>, err: &Error, _ctx: Arc<Context>) -> Action {
    tracing::warn!("WiremeshGateway reconcile error: {err}");
    Action::requeue(Duration::from_secs(15))
}

pub async fn run(ctx: Arc<Context>) {
    let client = ctx.client.clone();
    Controller::new(Api::<WiremeshGateway>::all(client.clone()), watcher::Config::default())
        .owns(Api::<Deployment>::namespaced(client.clone(), &ctx.namespace), watcher::Config::default())
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            if let Err(e) = res {
                tracing::warn!("WiremeshGateway reconcile failed: {e}");
            }
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::Secret;

    #[test]
    fn token_secret_name_is_stable() {
        assert_eq!(token_secret_name("gw-aws"), "wiremesh-gw-gw-aws-token");
    }

    #[test]
    fn needs_token_guard() {
        assert!(needs_token(None), "no secret → mint");
        let empty = Secret::default();
        assert!(needs_token(Some(&empty)), "secret without token key → mint");
        let mut data = BTreeMap::new();
        data.insert("token".to_string(), ByteString(b"wiremesh://...".to_vec()));
        let populated = Secret { data: Some(data), ..Default::default() };
        assert!(!needs_token(Some(&populated)), "populated token → skip mint");
    }
}
