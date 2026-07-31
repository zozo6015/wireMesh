//! `WiremeshRelay` reconciler: mint a single-use relay enrollment token,
//! store it in a Secret, and deploy the relay (identity on a per-relay PVC —
//! `workloads::relay_pvc` — so pod recreation never wipes the enrolled certs).
//! The relay pod's enroll init-container redeems the token with its
//! `--endpoint` — which both issues the relay's cert and creates the
//! advertised relay record (matching the testkit relay-enroll flow), so no
//! separate `RegisterRelay` call is needed. The mint decision mirrors the
//! gateway's: keyed off "is the identity durably persisted", not off the token
//! Secret alone (a populated-but-SPENT token must not suppress the re-mint a
//! certs-less relay needs — the Init:Error wedge). On CR delete the relay pod
//! is GC'd (owner ref) and the controller's health pipeline evicts the stale
//! relay.

use super::{apply, apply_deployment, owner_ref, Context, Error};

use crate::crd::{WiremeshRelay, WiremeshResourceStatus};
use crate::workloads;
use futures::StreamExt;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{PersistentVolumeClaim, Secret};
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

/// Whether to mint a fresh relay enrollment token — the SAME contract as the
/// gateway's (`gateway::should_mint_token`): when the identity is NOT durably
/// persisted, a fresh UNSPENT token is required even if a stale populated token
/// Secret lingers (that token was already redeemed by the enroll that produced
/// the lost/never-written certs — reusing it wedges the enroll init-container
/// in a permanent `Init:Error`). Once the identity is persisted (steady state)
/// defer to `needs_token` and never re-mint on a plain pod recreation.
pub fn should_mint_token(identity_persisted: bool, token_secret: Option<&Secret>) -> bool {
    !identity_persisted || needs_token(token_secret)
}

async fn reconcile(relay: Arc<WiremeshRelay>, ctx: Arc<Context>) -> Result<Action, Error> {
    let ns = ctx.namespace.clone();
    let name = relay.name_any();
    let client = ctx.client.clone();
    let secrets = Api::<Secret>::namespaced(client.clone(), &ns);
    let deployments = Api::<Deployment>::namespaced(client.clone(), &ns);
    let token_secret = token_secret_name(&name);

    // Observe the identity PVC's PRE-reconcile state BEFORE we create it (the
    // same pattern as the gateway): its existence feeds both the mint decision
    // and the create-only guard. The PVC is `<name>-relay-data`
    // (workloads::relay_pvc) — kind-specific, distinct from the gateway's
    // `<name>-gateway-data` and the controller's `<name>-data`.
    let pvc_api = Api::<PersistentVolumeClaim>::namespaced(client.clone(), &ns);
    let pvc_name = format!("{name}-relay-data");
    let existing_pvc = pvc_api.get_opt(&pvc_name).await?;
    let pvc_exists = existing_pvc.is_some();

    // `identity_persisted` corroboration: the PVC exists AND the relay
    // Deployment reports an available replica. Availability means the enroll
    // init-container COMPLETED (init containers gate pod readiness — either by
    // enrolling or, in steady state, by SKIPPING because the identity is
    // already on the PVC) and the QUIC bridge is serving off those certs —
    // proof the identity was actually written. There is no `list_relays` on
    // `AdminExec` (no relay roster probe), so Deployment availability is the
    // cheapest pod-exec-free corroboration available. CONSERVATIVE on any
    // probe gap/failure (per the documented rule): not persisted → mint a
    // spare token, which simply lapses unused because `wiremesh-relay-enroll`
    // skips when a complete identity is present (`enroll::probe_identity`).
    let relay_available = match deployments.get_opt(&name).await {
        Ok(dep) => {
            dep.and_then(|d| d.status).and_then(|s| s.available_replicas).unwrap_or(0) >= 1
        }
        Err(e) => {
            tracing::warn!(
                "relay {name}: Deployment availability probe failed ({e}); treating the \
                 identity as NOT persisted (conservative: mint a spare enrollment token)"
            );
            false
        }
    };
    let identity_persisted = pvc_exists && relay_available;

    // Mint whenever the identity is not durably persisted OR no populated token
    // Secret exists (`should_mint_token`, the gateway contract). The force-
    // apply replaces any stale (spent) token — the wedge-killer.
    if should_mint_token(identity_persisted, secrets.get_opt(&token_secret).await?.as_ref()) {
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

    // Persist the relay identity on a per-relay PVC (owner-referenced → GC'd
    // with the CR). CREATE-ONLY via the shared guard: a bound PVC's
    // storageClassName/requests.storage are immutable (reuses the get_opt
    // above — no double-get). Namespace stamped here (builders are
    // namespace-free), mirroring the gateway reconciler.
    if super::pvc_needs_create(existing_pvc.as_ref()) {
        let mut pvc = workloads::relay_pvc(&name, &relay.spec);
        pvc.metadata.namespace = Some(ns.clone());
        pvc.metadata.owner_references = Some(vec![owner_ref(relay.as_ref())?]);
        apply(&pvc_api, &pvc).await?;
    }

    // Deploy the relay (fails closed on an invalid endpoint — v1 IPv4 only).
    let addrs = super::controller_endpoints(&ctx).await?;
    let mut dep = workloads::relay_deployment(relay.as_ref(), &addrs.sync, &addrs.enroll, crate::workloads::CONTROLLER_CA_SECRET, &token_secret)
        .map_err(Error::Admin)?;
    dep.metadata.namespace = Some(ns.clone());
    dep.metadata.owner_references = Some(vec![owner_ref(relay.as_ref())?]);
    // Route through deployment_apply_body (`apply_deployment`) so the Recreate
    // strategy explicitly nulls the defaulter's rollingUpdate — the plain
    // `apply` would 422 over an existing RollingUpdate Deployment
    // (ops-finding-pvc-adoption-migration.md bug 1, now that the relay carries
    // an RWO PVC and the Recreate strategy).
    apply_deployment(&deployments, &dep).await?;

    let live = deployments.get(&name).await?;
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
        .owns(Api::<PersistentVolumeClaim>::namespaced(client.clone(), &ctx.namespace), watcher::Config::default())
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
