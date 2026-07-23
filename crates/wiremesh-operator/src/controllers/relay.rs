//! `WiremeshRelay` reconciler: mint a single-use relay enrollment token (once),
//! store it in a Secret, and deploy the relay. The relay pod's enroll
//! init-container redeems the token with its `--endpoint` — which both issues
//! the relay's cert and creates the advertised relay record (matching the
//! testkit relay-enroll flow), so no separate `RegisterRelay` call is needed.
//! On CR delete the relay pod is GC'd (owner ref) and the controller's health
//! pipeline evicts the stale relay.

use super::{apply, owner_ref, Context, Error};
use crate::controllers::gateway::CONTROLLER_CA_SECRET;
use crate::crd::{WiremeshRelay, WiremeshResourceStatus};
use crate::workloads;
use futures::StreamExt;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::ByteString;
use kube::api::{Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::watcher;
use kube::{Api, ResourceExt};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

pub fn token_secret_name(relay_name: &str) -> String {
    format!("wiremesh-relay-{relay_name}-token")
}

/// Mint only when no populated token Secret already exists.
pub fn needs_token(existing: Option<&Secret>) -> bool {
    match existing {
        None => true,
        Some(s) => !s.data.as_ref().map(|d| d.contains_key("token")).unwrap_or(false),
    }
}

async fn reconcile(relay: Arc<WiremeshRelay>, ctx: Arc<Context>) -> Result<Action, Error> {
    let ns = ctx.namespace.clone();
    let name = relay.name_any();
    let client = ctx.client.clone();
    let secrets = Api::<Secret>::namespaced(client.clone(), &ns);
    let token_secret = token_secret_name(&name);

    // Mint the relay enrollment token ONCE.
    if needs_token(secrets.get_opt(&token_secret).await?.as_ref()) {
        let token = ctx.admin.mint_relay_token().await.map_err(Error::Admin)?;
        let mut data = BTreeMap::new();
        data.insert("token".to_string(), ByteString(token.into_bytes()));
        let mut sec = Secret {
            metadata: kube::core::ObjectMeta {
                name: Some(token_secret.clone()),
                namespace: Some(ns.clone()),
                owner_references: Some(vec![owner_ref(relay.as_ref())?]),
                ..Default::default()
            },
            data: Some(data),
            ..Default::default()
        };
        sec.type_ = Some("Opaque".into());
        apply(&secrets, &sec).await?;
    }

    // Deploy the relay (fails closed on an invalid endpoint — v1 IPv4 only).
    let addrs = super::controller_endpoints(&ctx).await?;
    let mut dep = workloads::relay_deployment(relay.as_ref(), &addrs.sync, &addrs.enroll, CONTROLLER_CA_SECRET, &token_secret)
        .map_err(Error::Admin)?;
    dep.metadata.namespace = Some(ns.clone());
    dep.metadata.owner_references = Some(vec![owner_ref(relay.as_ref())?]);
    apply(&Api::<Deployment>::namespaced(client.clone(), &ns), &dep).await?;

    let live = Api::<Deployment>::namespaced(client.clone(), &ns).get(&name).await?;
    let ready = live.status.and_then(|s| s.available_replicas).unwrap_or(0) >= 1;
    let status = WiremeshResourceStatus {
        applied: ready,
        applied_version: None,
        message: Some(if ready { "relay deployed".into() } else { "relay pod starting".into() }),
    };
    Api::<WiremeshRelay>::all(client.clone())
        .patch_status(&name, &PatchParams::default(), &Patch::Merge(serde_json::json!({ "status": status })))
        .await?;
    Ok(Action::requeue(Duration::from_secs(if ready { 300 } else { 15 })))
}

fn error_policy(_relay: Arc<WiremeshRelay>, err: &Error, _ctx: Arc<Context>) -> Action {
    tracing::warn!("WiremeshRelay reconcile error: {err}");
    Action::requeue(Duration::from_secs(15))
}

pub async fn run(ctx: Arc<Context>) {
    let client = ctx.client.clone();
    Controller::new(Api::<WiremeshRelay>::all(client.clone()), watcher::Config::default())
        .owns(Api::<Deployment>::namespaced(client.clone(), &ctx.namespace), watcher::Config::default())
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            if let Err(e) = res {
                tracing::warn!("WiremeshRelay reconcile failed: {e}");
            }
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_token_secret_name_is_stable() {
        assert_eq!(token_secret_name("relay-eu"), "wiremesh-relay-relay-eu-token");
    }

    #[test]
    fn needs_token_guard() {
        assert!(needs_token(None));
        let mut data = BTreeMap::new();
        data.insert("token".to_string(), ByteString(b"tok".to_vec()));
        let populated = Secret { data: Some(data), ..Default::default() };
        assert!(!needs_token(Some(&populated)));
    }
}
