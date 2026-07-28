//! `WiremeshGateway` reconciler: mint a single-use enrollment token (once),
//! store it in a Secret, deploy the privileged hostNetwork gateway, and report
//! `status.enrolled`/`gateway_id`. Finalizer drains the gateway on delete.

use super::{apply, apply_deployment, owner_ref, Context, Error};
use crate::crd::{Condition, WiremeshGateway, WiremeshGatewayStatus, WiremeshSegment};
use crate::workloads;
use futures::StreamExt;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{PersistentVolumeClaim, Secret};
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

/// Whether the gateway's identity is durably PERSISTED. Requires BOTH the PVC to
/// exist (somewhere to persist to) AND the gateway to be active in the controller
/// roster (proof an identity was actually written and enrolled). The PVC alone is
/// NOT proof: a first enroll can crash AFTER spending its single-use token but
/// BEFORE writing `identity.json`, leaving an empty PVC that still needs a fresh
/// token. Keying token freshness off this (not raw `pvc_exists`) is the fix for
/// the CodeRabbit adoption-path crash-loop finding.
pub fn identity_persisted(pvc_exists: bool, gateway_active: bool) -> bool {
    pvc_exists && gateway_active
}

/// Whether to mint a fresh enrollment token, tied to whether the identity is
/// durably PERSISTED (see `identity_persisted`) — NOT to the bare PVC's
/// existence. When the identity is not persisted (fresh/empty PVC, or a first
/// enroll that crashed after spending its token), a fresh UNSPENT token is
/// required even if a stale populated token Secret lingers (reusing that spent
/// single-use token is the adoption-path crash-loop bug). Once the identity is
/// persisted (steady state) we defer to `needs_token` and never re-mint on a
/// plain pod recreation.
pub fn should_mint_token(identity_persisted: bool, token_secret: Option<&Secret>) -> bool {
    !identity_persisted || needs_token(token_secret)
}

/// The gateway identity PVC is CREATE-ONLY: create it when absent, and NEVER
/// apply/patch an existing one. A bound PVC's `storageClassName` and
/// `resources.requests.storage` are immutable, so re-applying them on every
/// reconcile churns or errors. Mirrors the `needs_token` create-once guard.
pub fn pvc_needs_create(existing: Option<&PersistentVolumeClaim>) -> bool {
    existing.is_none()
}

/// Decide whether a genuine emptyDir→PVC ADOPTION requires draining a stale
/// gateway from the controller roster before the new pod can enroll.
///
/// WHY (see `docs/research/ops-finding-pvc-adoption-migration.md`, bug 2): when a
/// gateway pod is recreated onto a FRESH empty PVC, the OLD gateway id (enrolled
/// from the now-gone emptyDir) is still `active` in the roster, so the new pod's
/// plain-token enroll is rejected ("segment already has an active gateway; use a
/// rebind token"). The operator must detect adoption and drain that stale id to
/// free the segment; but it must do so ONLY on a genuine adoption — NEVER on a
/// healthy steady-state gateway.
///
/// The `!pvc_freshly_created` gate is the load-bearing safety property: an
/// existing PVC (steady state) short-circuits to `None`, so a running gateway
/// whose own id is legitimately active is never drained. On the fresh-PVC path,
/// drain only when a roster id is active for the segment AND it is not this
/// gateway's own enrolled id. During real adoption the caller passes
/// `own_enrolled_id = None` (a fresh PVC holds no identity this pod can prove is
/// its own); the equality guard is defense-in-depth for an inconsistent
/// fresh-PVC-with-known-own-id case only.
///
/// SOLE-GATEWAY GUARD (`sole_gateway_for_segment`): the controller roster keys a
/// gateway to its segment by NAME only, so if TWO `WiremeshGateway` CRs target
/// the same segment, the roster's "active" id for that segment may belong to a
/// healthy PEER's live gateway, not a stale predecessor of THIS CR. Draining it
/// would kill a running peer. So we refuse to drain unless this CR is the SOLE
/// gateway CR for the segment — only then is an active roster id on the fresh-PVC
/// path unambiguously this CR's own stale predecessor. With a peer present, the
/// safe action is to leave the id alone (a missed drain is a manual cleanup; a
/// wrong drain is an outage).
pub fn adoption_needs_stale_drain(
    pvc_freshly_created: bool,
    active_roster_id_for_segment: Option<u64>,
    own_enrolled_id: Option<u64>,
    sole_gateway_for_segment: bool,
) -> Option<u64> {
    if !pvc_freshly_created {
        return None; // steady state: NEVER drain a healthy gateway.
    }
    if !sole_gateway_for_segment {
        // A peer CR shares this segment — the active roster id (matched by
        // segment NAME) may be the peer's LIVE gateway. Never risk draining it.
        return None;
    }
    match active_roster_id_for_segment {
        Some(id) if Some(id) != own_enrolled_id => Some(id),
        _ => None,
    }
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

    // Observe the identity PVC's PRE-reconcile state BEFORE we create it. Its
    // existence gates both the mint decision (via identity_persisted) and the
    // create-only guard below. The PVC is `<name>-gateway-data`
    // (workloads::gateway_pvc) — kind-specific, distinct from the controller's
    // `<name>-data`.
    let pvc_api = Api::<PersistentVolumeClaim>::namespaced(client.clone(), &ns);
    let pvc_name = format!("{name}-gateway-data");
    let existing_pvc = pvc_api.get_opt(&pvc_name).await?;
    let pvc_exists = existing_pvc.is_some();

    // Read the controller roster ONCE and reuse it for both the mint decision and
    // the status below. `gateway_active` = is THIS CR's segment present in the
    // roster (the same "enrolled" signal the status uses)? CONSERVATIVE on a
    // roster-query failure: treat as NOT active → identity NOT persisted → mint a
    // fresh token. That is harmless — a spare token simply goes unused once the
    // persisted identity makes the enroll init skip — and it avoids wedging the
    // reconcile on a transient controller hiccup.
    let roster = match ctx.admin.list_gateways().await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(
                "gateway {name}: controller roster query failed ({e}); treating gateway as \
                 not-active (conservative: mint a spare enrollment token)"
            );
            Vec::new()
        }
    };
    // Find THIS CR's segment row in the roster ONCE and reuse it for the mint
    // decision, the adoption-drain decision, and the status below (matched by
    // segment NAME — the only key the roster carries).
    let seg_row = roster.iter().find(|g| g.segment == seg.spec.segment_name);
    let gateway_active = seg_row.is_some();

    // ADOPTION DETECTION (v0.2.2 — see docs/research/ops-finding-pvc-adoption-
    // migration.md, bug 2). On the one-time emptyDir→PVC transition the pod is
    // recreated onto a FRESH empty PVC, but the OLD gateway id (enrolled from the
    // now-gone emptyDir) is STILL `active` in the roster. The new pod's plain-token
    // enroll is then rejected ("segment already has an active gateway; use a rebind
    // token") → adoption stalls in Init:Error. Detect it and drain the stale id to
    // FREE THE SEGMENT so the plain-token enroll is no longer rejected. (The fresh
    // token is minted regardless because the fresh PVC makes `pvc_exists` false →
    // `identity_persisted` false → `should_mint_token` true; the drain does NOT
    // flip `gateway_active` within this reconcile — that snapshot was read above
    // and is not re-read. The drain's SOLE purpose is unblocking the enroll.)
    //
    // SAFETY (load-bearing): `adoption_needs_stale_drain` fires ONLY when the PVC is
    // freshly created THIS reconcile (`existing_pvc.is_none()`) AND this CR is the
    // sole gateway for the segment. In steady state the PVC already exists, so the
    // fn returns None unconditionally — a healthy running gateway is NEVER drained.
    // On the fresh-PVC path this pod has no persisted identity it can prove is its
    // own, so `own_enrolled_id` is `None` — NOT `status.gateway_id`, which during
    // adoption still holds the stale old id and would (via the equality guard)
    // DEFEAT the drain and re-introduce the bug. The equality guard in the pure fn
    // is defense-in-depth only.
    //
    // SOLE-GATEWAY GUARD: the roster matches a gateway to its segment by NAME only,
    // so if a SECOND WiremeshGateway CR targets this segment, the active roster id
    // could be that PEER's LIVE gateway — draining it would be an outage. Count the
    // WiremeshGateway CRs referencing this segment (by `segment_ref`); == 1 means
    // this CR is the only one, so an active roster id is unambiguously this CR's own
    // stale predecessor. SAFE FALLBACK on a list failure: `false` (never drain) — a
    // missed drain is a manual cleanup, a false positive kills a live peer.
    let sole_gateway_for_segment = match Api::<WiremeshGateway>::all(client.clone())
        .list(&ListParams::default())
        .await
    {
        Ok(list) => list.items.iter().filter(|g| g.spec.segment_ref == gw.spec.segment_ref).count() == 1,
        Err(e) => {
            tracing::warn!(
                "gateway {name}: listing WiremeshGateway CRs failed ({e}); treating as NOT the \
                 sole gateway for the segment (conservative: skip the adoption drain)"
            );
            false
        }
    };
    if let Some(stale_id) = adoption_needs_stale_drain(
        existing_pvc.is_none(),
        seg_row.map(|g| g.id),
        None,
        sole_gateway_for_segment,
    ) {
        tracing::info!(
            "gateway {name}: adoption: draining stale gateway id {stale_id} to free segment \
             {segment} (emptyDir→PVC transition; the new pod will enroll fresh)",
            segment = seg.spec.segment_name,
        );
        ctx.admin.drain(stale_id).await.map_err(Error::Admin)?;
    }

    // The identity is durably persisted ONLY when the PVC exists AND the gateway
    // is active in the roster — a PVC alone can hold no identity (a first enroll
    // that crashed after spending its token). Mint whenever it is NOT persisted OR
    // the token Secret is absent/empty. The force-apply below replaces any stale
    // token Secret.
    //
    // NOTE on idempotency: a crash between the mint and the Secret write below
    // orphans that token — the next reconcile mints a fresh one. This is
    // low-harm by design: enrollment tokens are single-use AND expiring, so an
    // unredeemed orphan simply lapses. A stronger guarantee would need a
    // controller-side idempotency key on MintToken (a possible follow-up).
    let identity_persisted = identity_persisted(pvc_exists, gateway_active);
    if should_mint_token(identity_persisted, secrets.get_opt(&token_secret).await?.as_ref()) {
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
    // reboot never wipes the identity and forces a re-enroll. CREATE-ONLY: a bound
    // PVC's storageClassName/requests.storage are immutable, so we never patch an
    // existing one (reusing the get_opt above — no double-get). Namespace is
    // stamped here since the builder is namespace-free (mirrors the controller
    // reconciler).
    if pvc_needs_create(existing_pvc.as_ref()) {
        let mut pvc = workloads::gateway_pvc(&name, &gw.spec);
        pvc.metadata.namespace = Some(ns.clone());
        pvc.metadata.owner_references = Some(vec![owner_ref(gw)?]);
        apply(&pvc_api, &pvc).await?;
    }

    // Deploy the gateway. The enroll token is bound to `cidrs`, so those MUST
    // be passed through to the enroll init-container (--cidr).
    let addrs = super::controller_endpoints(ctx).await?;
    let mut dep = workloads::gateway_deployment(
        gw, &addrs.sync, &addrs.enroll, &addrs.observe, crate::workloads::CONTROLLER_CA_SECRET, &token_secret, &cidrs,
    );
    dep.metadata.namespace = Some(ns.clone());
    dep.metadata.owner_references = Some(vec![owner_ref(gw)?]);
    // Route through deployment_apply_body so the Recreate strategy explicitly
    // nulls the defaulter's rollingUpdate (avoids the 422 on apply-over-existing;
    // ops-finding-pvc-adoption-migration.md bug 1).
    apply_deployment(&Api::<Deployment>::namespaced(client.clone(), &ns), &dep).await?;

    // Status from the controller's gateway roster (reuse `seg_row` from above).
    let row = seg_row;
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
    fn should_mint_token_keys_off_identity_persisted_not_raw_pvc_exists() {
        // ADOPTION-PATH / CRASH-LOOP BUG (CodeRabbit findings 5+6): raw
        // `pvc_exists` is NOT proof of a persisted identity. A PVC can exist while
        // holding NO valid identity — e.g. the first enroll crashed AFTER the
        // single-use token was spent but BEFORE identity.json was written. Such a
        // gateway still needs a FRESH token, yet `pvc_exists == true` would wrongly
        // suppress minting → crash-loop. The mint decision must key off a SEMANTIC
        // `identity_persisted` signal, not the bare PVC's existence.
        //
        // Pure fn contract:
        //   should_mint_token(identity_persisted, token_secret)
        //       == !identity_persisted || needs_token(token_secret)
        let mut data = BTreeMap::new();
        data.insert("token".to_string(), ByteString(b"wiremesh://spent".to_vec()));
        let populated = Secret { data: Some(data), ..Default::default() };

        // Not persisted (fresh/empty PVC OR failed-enroll) + stale populated token
        // → MUST re-mint (the volume needs an unspent token to enroll).
        assert!(
            should_mint_token(false, Some(&populated)),
            "identity NOT persisted + stale populated token → re-mint"
        );
        // Persisted (PVC holds a valid identity, gateway active in roster) + token
        // present → do NOT re-mint (steady state).
        assert!(
            !should_mint_token(true, Some(&populated)),
            "identity persisted + populated token → no re-mint"
        );
        // Token Secret absent → mint regardless of persistence.
        assert!(should_mint_token(true, None), "no token secret → mint even if identity persisted");
        assert!(should_mint_token(false, None), "no token secret + not persisted → mint");
        // Token Secret present but without the token key → mint.
        let empty = Secret::default();
        assert!(should_mint_token(true, Some(&empty)), "token secret without token key → mint");
    }

    #[test]
    fn identity_persisted_requires_both_pvc_and_roster_active() {
        // The SEMANTIC signal `should_mint_token` must consume is NOT raw
        // `pvc_exists` — a PVC can exist while holding no valid identity (a first
        // enroll that crashed after spending its token). "Identity persisted" is
        // true ONLY when BOTH hold: the PVC exists AND the gateway is active in the
        // controller roster (proof an identity was actually written and enrolled).
        //
        // Pure fn contract: identity_persisted(pvc_exists, gateway_active)
        //     == pvc_exists && gateway_active
        assert!(identity_persisted(true, true), "PVC present AND active in roster → persisted");
        assert!(!identity_persisted(true, false), "PVC present but NOT enrolled/active → NOT persisted (mint)");
        assert!(!identity_persisted(false, true), "no PVC → NOT persisted even if a stale roster row exists");
        assert!(!identity_persisted(false, false), "neither → NOT persisted");
        // Implementer wiring: identity_persisted = pvc_exists && gateway_active,
        // where gateway_active comes from the controller roster (list_gateways for
        // this CR's segment). On a roster-query FAILURE, be CONSERVATIVE — treat as
        // NOT active (→ not persisted → mint a spare token, which simply goes unused
        // once the real identity skips enroll). Then feed the result to
        // `should_mint_token(identity_persisted, token_secret)`.
    }

    #[test]
    fn pvc_needs_create_is_create_only() {
        // IMMUTABILITY (CodeRabbit finding): a bound PVC's storageClassName /
        // resources.requests.storage are immutable — re-applying (patching) them on
        // every reconcile churns/errors. The gateway PVC must be CREATE-ONLY:
        // created when absent, never patched when it already exists. Mirror the
        // `needs_token` create-once guard with a pure `pvc_needs_create`.
        assert!(pvc_needs_create(None), "absent PVC → create it");
        let existing = PersistentVolumeClaim::default();
        assert!(
            !pvc_needs_create(Some(&existing)),
            "existing PVC → do NOT re-apply/patch (storage fields are immutable after bind)"
        );
    }

    #[test]
    fn adoption_drains_stale_gateway_but_never_a_healthy_one() {
        // ADOPTION BUG (v0.2.1 zolab e2e): on the one-time emptyDir→PVC transition
        // the pod is recreated onto a FRESH empty PVC, but the OLD gateway id
        // (enrolled from the now-gone emptyDir) is STILL `active` in the roster, so
        // the new pod's plain-token enroll is rejected ("segment already has an
        // active gateway; use a rebind token"), and `identity_persisted` is true
        // (fresh PVC + old id active) so no fresh token is minted either → adoption
        // stalls in Init:Error. The operator must DETECT adoption and drain the
        // stale id (freeing the segment + flipping identity_persisted→false so a
        // fresh token mints) — but NEVER touch a healthy steady-state gateway.
        //
        // IMPLEMENTER SURFACE (must be added — this test won't compile until then):
        //   pub fn adoption_needs_stale_drain(
        //       pvc_freshly_created: bool,
        //       active_roster_id_for_segment: Option<u64>,
        //       own_enrolled_id: Option<u64>,
        //       sole_gateway_for_segment: bool,
        //   ) -> Option<u64>
        // Returns Some(stale_id) to drain ONLY when the PVC is freshly created
        // (no persisted identity this reconcile) AND a roster id is active for the
        // segment that is NOT this gateway's own enrolled id AND THIS CR is the
        // SOLE gateway CR for the segment; otherwise None.
        //
        // Reference logic that satisfies the truth table:
        //   if !pvc_freshly_created { return None; }        // steady state: NEVER drain
        //   if !sole_gateway_for_segment { return None; }   // shared segment: NEVER drain a peer
        //   match active_roster_id_for_segment {
        //       Some(id) if Some(id) != own_enrolled_id => Some(id),
        //       _ => None,
        //   }
        //
        // WIRING (specify exactly for the implementer):
        //   - pvc_freshly_created  ← existing_pvc.is_none()  (== pvc_needs_create,
        //     the PRE-reconcile PVC observation already computed as !pvc_exists).
        //   - active_roster_id_for_segment ← the roster row id for this CR's
        //     segment: roster.iter().find(|g| g.segment == seg.spec.segment_name)
        //         .map(|g| g.id)  (the same `row` used for status).
        //   - own_enrolled_id ← the id this pod can PROVE is its own. A freshly
        //     created PVC has NO persisted identity, so on the fresh-PVC path this
        //     MUST be None. Do NOT source it from `status.gateway_id`: during
        //     adoption status still holds the STALE old id (== the active roster
        //     id), so passing it would make Some(id)==own → None and DEFEAT the
        //     drain, re-introducing the bug. The equality guard in the pure fn is
        //     only defense-in-depth for an inconsistent fresh-PVC-with-own-id case.
        //   - sole_gateway_for_segment ← count the WiremeshGateway CRs whose
        //     spec.segment_ref resolves to this segment; == 1 means only THIS CR
        //     references it. The roster match is by SEGMENT NAME only, so a roster
        //     id "active for the segment" could belong to a DIFFERENT CR that also
        //     mis-references the same segment — draining it would kill a healthy
        //     peer gateway. List all WiremeshGateway CRs in apply_gateway
        //     (Api::<WiremeshGateway>::all(...).list(&ListParams::default()), or the
        //     controller runtime's store if exposed) and count segment_ref matches;
        //     if listing is unavailable, fall back to the SAFE default
        //     `sole_gateway_for_segment = false` (never drain) and log — a
        //     conservative miss just leaves the stale id for a manual drain, whereas
        //     a false positive kills a live peer.

        // 1. Fresh PVC + a stale active roster id, our own id unknown, SOLE CR for
        //    the segment → drain it (the real adoption case).
        assert_eq!(
            adoption_needs_stale_drain(true, Some(8), None, true),
            Some(8),
            "genuine adoption (fresh PVC, sole CR for the segment) with a stale active roster id → drain"
        );
        // 1b. Fresh PVC + active id that differs from a (differently) known own id,
        //     sole CR → still a stale id, drain it.
        assert_eq!(
            adoption_needs_stale_drain(true, Some(8), Some(5), true),
            Some(8),
            "fresh PVC + active roster id != own id + sole CR → drain the stale id"
        );

        // 2. CRITICAL SAFETY CASE: steady state (existing PVC, own id active) →
        //    NEVER drain. This is the load-bearing assertion — a regression here
        //    would drain a healthy running gateway.
        assert_eq!(
            adoption_needs_stale_drain(false, Some(9), Some(9), true),
            None,
            "steady state (existing PVC, own id active) → NEVER drain a healthy gateway"
        );

        // 2b. CRITICAL SAFETY CASE (shared segment): fresh PVC + stale active id but
        //     TWO CRs reference the segment (sole=false). The "active for the
        //     segment" id could be CR-A's HEALTHY live gateway (roster matches by
        //     segment NAME only), so CR-B's adoption must NOT drain it.
        assert_eq!(
            adoption_needs_stale_drain(true, Some(8), None, false),
            None,
            "two CRs on the same segment (sole=false) → NEVER drain a possibly-healthy peer, even on a fresh PVC"
        );

        // 3. Fresh PVC but no active roster id for the segment → nothing to drain
        //    (first-ever deploy).
        assert_eq!(
            adoption_needs_stale_drain(true, None, None, true),
            None,
            "fresh PVC + no active roster id → first-ever deploy, nothing to drain"
        );

        // 4. Existing PVC + active id == own id → None (steady-state, redundant
        //    with case 2 but pins that an existing PVC never drains).
        assert_eq!(
            adoption_needs_stale_drain(false, Some(9), Some(9), true),
            None,
            "existing PVC + active id == own id → no drain"
        );
        // 4b. Existing PVC never drains even if the active id looks unfamiliar
        //     (only the fresh-PVC path may ever drain).
        assert_eq!(
            adoption_needs_stale_drain(false, Some(7), Some(9), true),
            None,
            "existing PVC → NEVER drain regardless of the roster id (only adoption drains)"
        );
    }
}
