//! `WiremeshRelay` reconciler: mint a single-use relay enrollment token,
//! store it in a Secret, and deploy the relay (identity on a per-relay PVC —
//! `workloads::relay_pvc` — so pod recreation never wipes the enrolled certs).
//! The relay pod's enroll init-container redeems the token with its
//! `--endpoint` — which both issues the relay's cert and creates the
//! advertised relay record (matching the testkit relay-enroll flow), so no
//! separate `RegisterRelay` call is needed. The mint decision mirrors the
//! gateway's: keyed off "is the identity durably persisted" (PVC + a
//! controller relay-roster row for this CR's endpoint), not off the token
//! Secret alone (a populated-but-SPENT token must not suppress the re-mint a
//! certs-less relay needs — the Init:Error wedge). On CR delete the relay pod
//! is GC'd (owner ref) and the controller's health pipeline evicts the stale
//! relay.

use super::{apply, apply_deployment, owner_ref, Context, Error};

use crate::admin_exec::RelayRow;
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

/// Whether the relay's identity is durably PERSISTED: the PVC exists AND the
/// controller's relay roster holds a row for this CR's `endpoint`. Parity with
/// `gateway::identity_persisted` (PVC + roster corroboration), with two
/// relay-specific properties that are each easy to break by accident:
///
/// **Matched by ENDPOINT, never by name.** The controller names an enrolled
/// relay `relay-<token-hash>` (`services/enrollment.rs`), which shares nothing
/// with the CR's name; the endpoint is the CR's `spec.endpoint` verbatim. A
/// name match would never hit → the identity would read as never-persisted →
/// a spare token minted on EVERY reconcile forever. The comparison is exact:
/// a neighbouring port or a host that merely contains this one is a DIFFERENT
/// relay.
///
/// **Deliberately NOT status-filtered.** The health pipeline evicts by flipping
/// `status` (`Db::set_relay_status`, documented there as "a HEALTH-eviction
/// state ... not a revocation/de-enrollment"); it never deletes the row. So
/// presence at ANY status is exactly the historical fact being asked — "this
/// relay completed an enrollment" — and an evicted-but-enrolled relay does not
/// re-mint a spare token for the whole outage. (Contrast the gateway's
/// `active_in_segment`, whose status filter guards the one-gateway-per-segment
/// occupancy invariant — a different question.)
///
/// The PVC is still required: a roster row from a previous incarnation must not
/// suppress the mint for a pod whose PVC was replaced or does not exist yet —
/// that identity has nowhere to live, and suppressing there is the `Init:Error`
/// wedge. An EMPTY roster yields false, which is also what the reconciler's
/// conservative failed-probe arm substitutes.
pub fn relay_identity_persisted(pvc_exists: bool, roster: &[RelayRow], endpoint: &str) -> bool {
    pvc_exists && roster.iter().any(|r| r.endpoint == endpoint)
}

async fn reconcile(relay: Arc<WiremeshRelay>, ctx: Arc<Context>) -> Result<Action, Error> {
    let ns = ctx.namespace.clone();
    let name = relay.name_any();
    let client = ctx.client.clone();
    let secrets = Api::<Secret>::namespaced(client.clone(), &ns);
    let deployments = Api::<Deployment>::namespaced(client.clone(), &ns);
    let token_secret = token_secret_name(&name);

    // FAIL CLOSED on a malformed `controllerEndpoint` override (mirrors the
    // gateway's `apply_gateway` loop exactly): it flows verbatim into the
    // relay's argv, and the binary rejects a bad `host:port` at boot —
    // deploying it anyway would just CrashLoopBackOff a pod. Erroring here
    // surfaces the reason on the CR's reconcile instead. Validated BEFORE any
    // mint/PVC/Deployment side effect — first thing in the function, ahead of
    // even the roster/PVC observation reads below.
    for (field, value) in [("controllerEndpoint", relay.spec.controller_endpoint.as_deref())] {
        if let Some(v) = value {
            workloads::validate_dial_target(v).map_err(|e| {
                Error::Admin(anyhow::anyhow!("WiremeshRelay {name}: spec.{field}: {e}"))
            })?;
        }
    }

    // Observe the identity PVC's PRE-reconcile state BEFORE we create it (the
    // same pattern as the gateway): its existence feeds both the mint decision
    // and the create-only guard. The PVC is `<name>-relay-data`
    // (workloads::relay_pvc) — kind-specific, distinct from the gateway's
    // `<name>-gateway-data` and the controller's `<name>-data`.
    let pvc_api = Api::<PersistentVolumeClaim>::namespaced(client.clone(), &ns);
    let pvc_name = format!("{name}-relay-data");
    let existing_pvc = pvc_api.get_opt(&pvc_name).await?;
    let pvc_exists = existing_pvc.is_some();

    // `identity_persisted` corroboration: the PVC exists AND the controller's
    // relay roster holds a row for this CR's endpoint — exact parity with the
    // gateway (`gateway::identity_persisted`: PVC + roster row). The decision
    // itself is pure and lives in `relay_identity_persisted` (which documents
    // the endpoint-match and no-status-filter properties); this arm owns only
    // the I/O and the conservative failure rule.
    //
    // WHY NOT Deployment availability (the earlier basis): availability is a
    // LIVENESS signal, and the question here is "was an identity ever written
    // to this PVC", which is a HISTORICAL fact. Any restart, rollout, eviction
    // or node outage drops availability to 0 while the identity sits intact on
    // the PVC, re-classifying it as unpersisted and re-minting a spare token on
    // EVERY 15s reconcile for the whole outage — thousands of dead
    // `enrollment_token` rows + audit entries for an overnight node failure.
    // (`Admin.ListRelays` did exist all along; only the operator's `AdminExec`
    // wrapper lacked it, which is what made availability look like the only
    // option.)
    //
    // WHY NOT PVC-existence alone: a PVC can exist holding NO identity — the
    // first enroll can crash AFTER spending its single-use token but BEFORE
    // writing the certs. That relay still needs a fresh token, and PVC-only
    // would suppress the mint forever (`Init:Error` wedge) — the very bug the
    // gateway's roster corroboration exists to prevent.
    //
    // The roster row is durable across outages BY DESIGN: the health pipeline
    // EVICTS by flipping `status` (`Db::set_relay_status`, documented there as
    // "a HEALTH-eviction state ... not a revocation/de-enrollment"), it never
    // deletes the row. So presence — at ANY status — is exactly "this relay
    // completed an enrollment", and is deliberately NOT status-filtered (unlike
    // the gateway's `active_in_segment`, where the filter guards the
    // one-gateway-per-segment occupancy invariant). A genuinely replaced PVC is
    // still caught: `pvc_exists` is false on the pass that recreates it.
    //
    // CONSERVATIVE on a probe failure (unchanged rule): treat as NOT enrolled →
    // mint a spare token, which lapses unused because `wiremesh-relay-enroll`
    // skips when a complete identity is present (`enroll::probe_identity`).
    let roster = match ctx.admin.list_relays().await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(
                "relay {name}: controller relay-roster query failed ({e}); treating the \
                 identity as NOT persisted (conservative: mint a spare enrollment token)"
            );
            // An empty roster flows through `relay_identity_persisted` to false
            // — the conservative "not enrolled" verdict.
            Vec::new()
        }
    };
    let identity_persisted =
        relay_identity_persisted(pvc_exists, &roster, &relay.spec.endpoint);

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
