//! `WiremeshGateway` reconciler: mint a single-use enrollment token (once),
//! store it in a Secret, deploy the privileged hostNetwork gateway, and report
//! `status.enrolled`/`gateway_id`. Finalizer drains the gateway on delete.

use super::{apply, owner_ref, Context, Error};
use crate::crd::{Condition, WiremeshGateway, WiremeshGatewayStatus, WiremeshSegment};
use crate::workloads;
use futures::StreamExt;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{PersistentVolumeClaim, Secret};
use k8s_openapi::ByteString;
use kube::api::{Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::finalizer::{finalizer, Event};
use kube::runtime::watcher;
use kube::{Api, ResourceExt};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

const GATEWAY_FINALIZER: &str = "wiremesh.io/gateway-drain";

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

/// Whether to mint a fresh enrollment token, tying token freshness to the
/// identity PVC's freshness. A fresh (absent) PVC holds no persisted identity,
/// so the enroll init must redeem an UNSPENT token — even if a stale populated
/// token Secret from a prior generation still lingers (reusing that spent
/// single-use token is the adoption-path crash-loop bug). Once the PVC exists
/// (steady state) the identity is durable, so we defer to `needs_token` and
/// never re-mint on a plain pod recreation.
pub fn should_mint_token(pvc_exists: bool, token_secret: Option<&Secret>) -> bool {
    !pvc_exists || needs_token(token_secret)
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

    // Observe the identity PVC's PRE-reconcile existence BEFORE we create it, so
    // token minting can be tied to PVC freshness (see should_mint_token). The
    // PVC is `<name>-data` (workloads::gateway_pvc).
    let pvc_api = Api::<PersistentVolumeClaim>::namespaced(client.clone(), &ns);
    let pvc_name = format!("{name}-data");
    let pvc_exists = pvc_api.get_opt(&pvc_name).await?.is_some();

    // Mint the enrollment token when the token Secret is absent/empty OR the PVC
    // is fresh (absent). A fresh empty PVC has no persisted identity, so the
    // enroll init must redeem an UNSPENT token — reusing the stale single-use
    // token from a leftover Secret would crash-loop (the adoption-path bug). An
    // existing PVC (steady state) already holds the identity, so pod recreation
    // never re-mints. The force-apply below replaces any stale token Secret.
    //
    // NOTE on idempotency: a crash between the mint and the Secret write below
    // orphans that token — the next reconcile mints a fresh one. This is
    // low-harm by design: enrollment tokens are single-use AND expiring, so an
    // unredeemed orphan simply lapses. A stronger guarantee would need a
    // controller-side idempotency key on MintToken (a possible follow-up).
    if should_mint_token(pvc_exists, secrets.get_opt(&token_secret).await?.as_ref()) {
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

    // Persist the gateway identity on a per-gateway PVC (owner-referenced → GC'd
    // with the CR). This is what survives pod recreation so an upgrade/reschedule/
    // reboot never wipes the identity and forces a re-enroll. Namespace is stamped
    // here since the builder is namespace-free (mirrors the controller reconciler).
    let mut pvc = workloads::gateway_pvc(&name, &gw.spec);
    pvc.metadata.namespace = Some(ns.clone());
    pvc.metadata.owner_references = Some(vec![owner_ref(gw)?]);
    apply(&pvc_api, &pvc).await?;

    // Deploy the gateway. The enroll token is bound to `cidrs`, so those MUST
    // be passed through to the enroll init-container (--cidr).
    let addrs = super::controller_endpoints(ctx).await?;
    let mut dep = workloads::gateway_deployment(
        gw, &addrs.sync, &addrs.enroll, &addrs.observe, crate::workloads::CONTROLLER_CA_SECRET, &token_secret, &cidrs,
    );
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
    // workload is GC'd with the CR. Prefer the id we recorded in status — the
    // referenced Segment CR may already be deleted, so we must NOT depend on
    // resolving it (that would silently skip the drain).
    let gateway_id = match gw.status.as_ref().and_then(|s| s.gateway_id) {
        Some(id) => Some(id),
        None => {
            // Fallback: resolve via the segment name if the CR still exists.
            let seg_name = Api::<WiremeshSegment>::all(ctx.client.clone())
                .get_opt(&gw.spec.segment_ref)
                .await?
                .map(|s| s.spec.segment_name);
            match seg_name {
                Some(name) => ctx
                    .admin
                    .list_gateways()
                    .await
                    .map_err(Error::Admin)?
                    .iter()
                    .find(|g| g.segment == name)
                    .map(|g| g.id),
                None => None,
            }
        }
    };
    if let Some(id) = gateway_id {
        ctx.admin.drain(id).await.map_err(Error::Admin)?;
    } else {
        tracing::warn!("gateway {} cleanup: no gateway_id to drain (never enrolled?)", gw.name_any());
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
        .owns(Api::<PersistentVolumeClaim>::namespaced(client.clone(), &ctx.namespace), watcher::Config::default())
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

    #[test]
    fn should_mint_token_ties_freshness_to_pvc() {
        // ADOPTION-PATH BUG: recreating the gateway pod onto a FRESH empty PVC
        // makes the enroll init redeem the already-spent token from the existing
        // Secret and crash-loop, because `needs_token(Some(populated))` is false
        // so no fresh token is minted. Token freshness must be tied to PVC
        // freshness: a fresh (absent) PVC needs a new unspent token even when a
        // stale populated token Secret still exists; a PVC that already exists
        // (steady state) must NOT trigger a re-mint.
        let mut data = BTreeMap::new();
        data.insert("token".to_string(), ByteString(b"wiremesh://spent".to_vec()));
        let populated = Secret { data: Some(data), ..Default::default() };

        // Fresh PVC (absent) + stale populated token → MUST re-mint.
        assert!(
            should_mint_token(false, Some(&populated)),
            "fresh/absent PVC + stale populated token → re-mint (the empty volume needs an unspent token)"
        );
        // Steady state: PVC exists + token present → do NOT re-mint.
        assert!(
            !should_mint_token(true, Some(&populated)),
            "existing PVC + populated token → no re-mint"
        );
        // Token Secret absent → mint regardless of PVC existence.
        assert!(should_mint_token(true, None), "no token secret → mint (even if PVC exists)");
        assert!(should_mint_token(false, None), "no token secret + fresh PVC → mint");
        // Token Secret present but without the token key → mint.
        let empty = Secret::default();
        assert!(should_mint_token(true, Some(&empty)), "token secret without token key → mint");
    }
}
