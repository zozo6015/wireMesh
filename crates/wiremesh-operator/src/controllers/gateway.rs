//! `WiremeshGateway` reconciler: mint a single-use enrollment token (once),
//! store it in a Secret, deploy the privileged hostNetwork gateway, and report
//! `status.enrolled`/`gateway_id`. Finalizer drains the gateway on delete.

use super::{apply, apply_deployment, owner_ref, Context, Error, Readiness};
use crate::admin_exec::GatewayRow;
use crate::crd::{Condition, WiremeshGateway, WiremeshGatewayStatus, WiremeshSegment};
use crate::workloads;

// The PVC create-only guard now lives at the shared `controllers` scope (the
// controller and relay reconcilers use the same choke point); re-exported here
// so existing gateway-side callers/importers stay stable.
pub use super::pvc_needs_create;
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

/// The roster row for `segment` whose `status == "active"` — never a
/// drained/replaced/draining/revoked row, regardless of roster ordering.
///
/// `Db::list_gateways` returns EVERY status ordered by id, so a stale drained
/// row (lower id) can precede the live active row. A first-match-by-segment
/// would return the stale row — mis-reporting status, draining the WRONG id on
/// CR delete, and (worst) making a drained-only roster read as "active" →
/// `identity_persisted` true → mint suppressed while the pod Init:Errors on a
/// spent token (the mint-suppression deadlock). This selector is the single
/// choke point every roster lookup routes through.
pub fn active_in_segment<'a>(roster: &'a [GatewayRow], segment: &str) -> Option<&'a GatewayRow> {
    roster.iter().find(|g| g.segment == segment && g.status == "active")
}

/// The rebind decision: compare the CIDRs the CURRENT token Secret was minted
/// against (`bound_cidrs`) with the segment's CURRENT CIDRs, as SETS (order is
/// cosmetic — rebinding on order churn would re-mint on every CR edit).
///
/// * `None` → no recorded binding (legacy pre-fix Secret) → `false`: we cannot
///   know what the token was bound to, and churning a rebind every reconcile
///   would be worse than waiting for the record to appear at the next
///   legitimate mint. (First-mint is owned by `should_mint_token`.)
/// * `Some(set-equal)` → `false`. `Some(differs)` → `true` → mint a REBIND
///   token and refresh the Secret.
pub fn needs_rebind(bound_cidrs: Option<&[String]>, segment_cidrs: &[String]) -> bool {
    match bound_cidrs {
        None => false,
        Some(bound) => {
            let bound: std::collections::HashSet<&str> = bound.iter().map(String::as_str).collect();
            let current: std::collections::HashSet<&str> =
                segment_cidrs.iter().map(String::as_str).collect();
            bound != current
        }
    }
}

/// The Secret data key under which [`token_secret_body`] records the CIDRs a
/// token was minted against (as a JSON array), so the next reconcile can read
/// that binding back for the [`needs_rebind`] decision. Absent on legacy
/// (pre-fix) Secrets → an UNKNOWN binding.
const BOUND_CIDRS_KEY: &str = "bound_cidrs";

/// Build the gateway enrollment-token Secret: the `token` key keeps its
/// existing shape (the enroll init-container mounts it as-is), plus a record of
/// the CIDRs the token was minted against (`BOUND_CIDRS_KEY`, JSON) so
/// [`bound_cidrs_of`] can recover them for the rebind decision.
/// Namespace/ownerRefs are stamped by the reconciler, as before.
pub fn token_secret_body(gateway_name: &str, token: &str, bound_cidrs: &[String]) -> Secret {
    let mut data = BTreeMap::new();
    data.insert("token".to_string(), ByteString(token.as_bytes().to_vec()));
    data.insert(
        BOUND_CIDRS_KEY.to_string(),
        ByteString(serde_json::to_vec(bound_cidrs).expect("a CIDR list serializes to JSON")),
    );
    let mut sec = Secret {
        metadata: kube::core::ObjectMeta {
            name: Some(token_secret_name(gateway_name)),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    };
    sec.type_ = Some("Opaque".into());
    sec
}

/// What the mint step must do this reconcile — see [`mint_action`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintAction {
    /// Roster unreadable while a rebind is pending: mint NOTHING and do not
    /// touch the token Secret (the pending rebind must stay derivable).
    Defer,
    /// Mint an ordinary gateway token bound to the segment CIDRs and (re)write
    /// the Secret's bound-CIDR record.
    MintOrdinary,
    /// Mint a `kind = "rebind"` token scoped to the segment id and refresh the
    /// Secret.
    MintRebind,
    /// Steady state: nothing to do.
    None,
}

/// The whole mint decision, pure — the reconciler matches on the result and
/// owns only the I/O (the mint calls, the Secret apply, the deferral warning).
///
/// `identity_persisted` is [`identity_persisted`]'s output
/// (`pvc_exists && gateway_active`); `gateway_active` is passed separately
/// because the rebind arm keys off it directly, and because a roster FAILURE
/// forces it false while `pvc_exists` may well be true.
///
/// # Why the order is load-bearing
///
/// `Defer` MUST come first. A failed `list_gateways` yields an empty roster,
/// which makes `gateway_active` false → `identity_persisted` false →
/// `should_mint_token` true, so the ordinary-mint arm is REACHABLE on a mere
/// controller hiccup. Taking it while a rebind is pending is doubly wrong:
///   * it mints a PLAIN token, which a still-occupied segment rejects with
///     `SegmentAlreadyBound`; and
///   * it rewrites the Secret's bound-CIDR record (via [`token_secret_body`]),
///     so [`needs_rebind`] reads false from then on and the required rebind is
///     PERMANENTLY LOST — nothing re-derives it. The gateway then sits on an
///     unusable plain token and wedges at the next re-enroll.
/// Deferring costs nothing: the not-enrolled requeue is 15s and the pending
/// rebind stays derivable from the untouched Secret.
///
/// The ordinary-mint arm also deliberately precedes the rebind arm: an
/// unpersisted identity (e.g. a replaced PVC) has nothing to keep, so it needs
/// an unspent ORDINARY token — the rebind arm is for an ENROLLED gateway whose
/// CIDRs moved underneath it.
pub fn mint_action(
    roster_ok: bool,
    gateway_active: bool,
    identity_persisted: bool,
    rebind_pending: bool,
    token_secret: Option<&Secret>,
) -> MintAction {
    if rebind_pending && !roster_ok {
        MintAction::Defer
    } else if should_mint_token(identity_persisted, token_secret) {
        MintAction::MintOrdinary
    } else if gateway_active && rebind_pending {
        MintAction::MintRebind
    } else {
        MintAction::None
    }
}

/// Reader half of the [`token_secret_body`] roundtrip: the exact CIDR set the
/// Secret's token was minted against, or `None` for a legacy Secret with no
/// record (an UNKNOWN binding — distinct from a recorded-empty one).
pub fn bound_cidrs_of(secret: &Secret) -> Option<Vec<String>> {
    let raw = secret.data.as_ref()?.get(BOUND_CIDRS_KEY)?;
    match serde_json::from_slice(&raw.0) {
        Ok(cidrs) => Some(cidrs),
        Err(e) => {
            // A PRESENT-but-corrupt record reads as "unknown" (→ no rebind), the
            // same as a legacy Secret — deliberately quiet in the control flow,
            // but never silent: a hand-edited/truncated record would otherwise
            // suppress rebinds forever with no trace of why.
            tracing::debug!(
                "token Secret {name:?}: ignoring unparseable {BOUND_CIDRS_KEY} record ({e}); \
                 treating the binding as UNKNOWN (no rebind until the next legitimate mint)",
                name = secret.metadata.name,
            );
            None
        }
    }
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

/// FRESH PRE-DRAIN re-validation gate (TOCTOU narrowing). `adoption_needs_stale_drain`
/// decides the drain from a snapshot read near the top of the reconcile; this gate is
/// re-checked from a SECOND, fresh roster + CR-list read taken immediately before the
/// drain call, so the drain fires only if nothing drifted in between.
///
/// Returns `true` — authorize the drain — ONLY when BOTH still hold on the fresh read:
///   * the segment's currently-active roster id is STILL present AND STILL exactly the
///     `stale_id` we snapshotted (`active_id_now == Some(stale_id)`); and
///   * this CR is STILL the sole gateway CR for the segment (`recount_now == 1`).
/// Any drift — a DIFFERENT active id, NO active id, or a peer CR now sharing the
/// segment — returns `false`, aborting the drain. (A fresh-read FAILURE is handled at
/// the call site by likewise aborting; a missed drain is a manual cleanup, a wrong
/// drain is a live-peer outage.)
fn drain_still_authorized(recount_now: usize, active_id_now: Option<u64>, stale_id: u64) -> bool {
    recount_now == 1 && active_id_now == Some(stale_id)
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

    // FAIL CLOSED on a malformed endpoint/bind override (mirrors the relay's
    // `endpoint` validation): these flow verbatim into the gateway's argv, and
    // the binary rejects a bad value at boot — deploying it anyway would just
    // CrashLoopBackOff a pod. Erroring here surfaces the reason on the CR's
    // reconcile instead. Validated BEFORE any mint/PVC/Deployment side effect.
    // `metricsBind` uses `validate_bind_target`, NOT `validate_dial_target` —
    // it's a local bind address, not a fabric dial target (see that
    // function's doc comment for the three-way divergence).
    let dial_fields: [(&str, Option<&str>); 2] = [
        ("observeEndpoint", gw.spec.observe_endpoint.as_deref()),
        ("syncEndpoint", gw.spec.sync_endpoint.as_deref()),
    ];
    for (field, value) in dial_fields {
        if let Some(v) = value {
            workloads::validate_dial_target(v).map_err(|e| {
                Error::Admin(anyhow::anyhow!("WiremeshGateway {name}: spec.{field}: {e}"))
            })?;
        }
    }
    if let Some(v) = gw.spec.metrics_bind.as_deref() {
        workloads::validate_bind_target(v).map_err(|e| {
            Error::Admin(anyhow::anyhow!("WiremeshGateway {name}: spec.metricsBind: {e}"))
        })?;
    }

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
    // `roster_ok` distinguishes "the controller says there is no active gateway"
    // from "we could not ask". Both yield an empty roster, but they must NOT be
    // treated alike by the rebind arm below — see the pending-rebind guard.
    let (roster, roster_ok) = match ctx.admin.list_gateways().await {
        Ok(rows) => (rows, true),
        Err(e) => {
            tracing::warn!(
                "gateway {name}: controller roster query failed ({e}); treating gateway as \
                 not-active (conservative: mint a spare enrollment token)"
            );
            (Vec::new(), false)
        }
    };
    // Find THIS CR's segment's ACTIVE row in the roster ONCE and reuse it for
    // the mint decision, the adoption-drain decision, and the status below.
    // ACTIVE-filtered (`active_in_segment`), never first-match-by-segment: the
    // roster is ordered by id and keeps drained/replaced rows, so a stale
    // drained row (lower id) would otherwise shadow the live active row —
    // mis-reporting status AND (via `gateway_active`) suppressing the mint a
    // drained-only segment actually needs (the mint-suppression deadlock).
    let seg_row = active_in_segment(&roster, &seg.spec.segment_name);
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
    //
    // The CR list + count runs ONLY on the fresh-PVC (adoption) path: in steady
    // state `existing_pvc.is_some()` → `adoption_needs_stale_drain` returns None
    // regardless of this flag, so computing it would waste an API list call on
    // every reconcile. Guard it behind the fresh-PVC condition and pass `false`
    // otherwise (harmless — the drain can't fire when the PVC already exists).
    if existing_pvc.is_none() {
        let sole_gateway_for_segment = match Api::<WiremeshGateway>::all(client.clone())
            .list(&ListParams::default())
            .await
        {
            Ok(list) => {
                list.items.iter().filter(|g| g.spec.segment_ref == gw.spec.segment_ref).count() == 1
            }
            Err(e) => {
                tracing::warn!(
                    "gateway {name}: listing WiremeshGateway CRs failed ({e}); treating as NOT the \
                     sole gateway for the segment (conservative: skip the adoption drain)"
                );
                false
            }
        };
        if let Some(stale_id) = adoption_needs_stale_drain(
            true, // existing_pvc.is_none() — we are inside the fresh-PVC branch.
            seg_row.map(|g| g.id),
            None,
            sole_gateway_for_segment,
        ) {
            // TOCTOU NARROWING (CodeRabbit MAJOR). `stale_id` was derived from the
            // roster + CR-list snapshots read earlier in this reconcile. Between those
            // reads and this drain, a CONCURRENT reconcile of a SECOND WiremeshGateway
            // on the same segment could enroll a new active gateway — so the id we are
            // about to drain might no longer be a stale predecessor but a live peer.
            // kube-rs offers NO segment-lock primitive, and a distributed lock for a
            // one-time adoption path is disproportionate. Instead we RE-VALIDATE against
            // a FRESH read taken immediately before the drain: re-fetch the controller
            // roster (the same source `seg_row` came from) and re-count this segment's
            // CRs, and drain ONLY IF the segment's active id is STILL exactly `stale_id`
            // AND this CR is STILL the sole gateway CR for the segment. If the active id
            // changed, vanished, a peer CR appeared, OR either re-read fails — ABORT
            // (warn + skip): a missed drain is manual cleanup, a wrong drain is an
            // outage. The fresh CR recount is the LAST async read before the drain, and
            // the `drain_still_authorized` check is pure (no `.await`), so nothing races
            // between the re-read and the drain call itself.
            //
            // This closes the window between the original snapshot and the drain down to
            // the drain call itself. The residual — an inherent controller cross-task
            // race that no in-process check can fully eliminate without a real lock — is
            // ACCEPTED, and is bounded by the one-gateway-per-segment design invariant
            // plus the fail-safe (any error or drift → never drain).
            let roster_recheck = ctx.admin.list_gateways().await;
            // Fresh CR recount — deliberately the FINAL async read before the drain.
            let recount_recheck = Api::<WiremeshGateway>::all(client.clone())
                .list(&ListParams::default())
                .await
                .map(|list| {
                    list.items
                        .iter()
                        .filter(|g| g.spec.segment_ref == gw.spec.segment_ref)
                        .count()
                });
            match (roster_recheck, recount_recheck) {
                (Ok(rows_now), Ok(recount_now)) => {
                    // ACTIVE-filtered like the snapshot read — a stale drained
                    // row must not masquerade as the segment's live gateway.
                    let active_id_now =
                        active_in_segment(&rows_now, &seg.spec.segment_name).map(|g| g.id);
                    if drain_still_authorized(recount_now, active_id_now, stale_id) {
                        tracing::info!(
                            "gateway {name}: adoption: draining stale gateway id {stale_id} to free \
                             segment {segment} (emptyDir→PVC transition; the new pod will enroll \
                             fresh)",
                            segment = seg.spec.segment_name,
                        );
                        ctx.admin.drain(stale_id).await.map_err(Error::Admin)?;
                    } else {
                        tracing::warn!(
                            "gateway {name}: adoption drain of stale id {stale_id} ABORTED — fresh \
                             pre-drain re-check no longer authorizes it (active_id_now={active_id_now:?}, \
                             sole-gateway recount={recount_now}); leaving the id for manual cleanup (a \
                             missed drain is safe; a wrong drain would be a live-peer outage)"
                        );
                    }
                }
                (roster_res, recount_res) => {
                    tracing::warn!(
                        "gateway {name}: adoption drain of stale id {stale_id} ABORTED — fresh \
                         pre-drain re-read failed (roster_ok={roster_ok}, recount_ok={recount_ok}); \
                         fail-safe skip (a missed drain is manual cleanup, a wrong drain is an outage)",
                        roster_ok = roster_res.is_ok(),
                        recount_ok = recount_res.is_ok(),
                    );
                }
            }
        }
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
    let existing_secret = secrets.get_opt(&token_secret).await?;
    // Evaluated INDEPENDENTLY of the roster: whether the segment's CIDRs moved
    // since this Secret's token was minted is a fact about the Secret, not about
    // the controller's view of the gateway.
    let rebind_pending =
        needs_rebind(existing_secret.as_ref().and_then(bound_cidrs_of).as_deref(), &cidrs);

    // The decision itself is pure and lives in ONE place (`mint_action`), so a
    // future edit cannot silently reorder the arms — in particular it cannot
    // let the ordinary-mint arm run ahead of the pending-rebind guard and
    // destroy the Secret's bound-CIDR record. Everything below is just the I/O
    // for whichever action was chosen.
    match mint_action(
        roster_ok,
        gateway_active,
        identity_persisted,
        rebind_pending,
        existing_secret.as_ref(),
    ) {
        MintAction::Defer => {
            // PENDING-REBIND GUARD (see `mint_action`'s doc for why this must
            // win over every other arm). Deferring costs nothing: the requeue
            // below is 15s while not-enrolled, and the pending rebind stays
            // derivable from the untouched Secret.
            tracing::warn!(
                "gateway {name}: segment {segment} CIDRs changed but the controller roster is \
                 unreadable — DEFERRING the mint to a later reconcile. Minting now would issue a \
                 plain token the occupied segment rejects AND overwrite the Secret's bound-CIDR \
                 record, losing the pending rebind.",
                segment = seg.spec.segment_name,
            );
        }
        MintAction::MintOrdinary => {
            let token = ctx.admin.mint_gateway_token(&cidrs).await.map_err(Error::Admin)?;
            // `token_secret_body` also RECORDS the CIDRs the token was minted
            // against, so later reconciles can detect a segment-CIDR change and
            // issue a rebind (see the rebind arm below).
            let mut sec = token_secret_body(&name, &token, &cidrs);
            sec.metadata.namespace = Some(ns.clone());
            sec.metadata.owner_references = Some(vec![owner_ref(gw)?]);
            apply(&secrets, &sec).await?;
        }
        MintAction::MintRebind => {
        // REBIND (segment-CIDR change on an enrolled gateway): the stored token
        // was minted against the OLD CIDR set, so any future re-enroll (fresh
        // PVC, adoption, node loss) would be rejected — on the CIDR set
        // (`BoundCidrMismatch`) and, since the segment still has an active
        // gateway, on the one-gateway-per-segment invariant
        // (`SegmentAlreadyBound`). Mint a REBIND token instead: `kind =
        // "rebind"` with EMPTY bound CIDRs and this segment's id as its scope
        // (`mint_gateway_rebind_token` — the controller keys the rebind path
        // off the KIND, and a rebind token's authorization IS the segment id).
        // At redemption the controller replaces (revokes) the segment's active
        // gateway rather than rejecting the enroll. Then force-apply the
        // refreshed Secret (SSA replaces the stale token). The Secret still
        // records the NEW segment CIDRs — that record is operator-side
        // bookkeeping for the next `needs_rebind` decision, independent of the
        // (empty) CIDRs on the wire.
        //
        // Pod recreation: NOT triggered separately — the segment CIDRs feed the
        // enroll init-container argv (`--cidr`) via `gateway_deployment`, so
        // the CIDR change itself alters the pod template and the Deployment's
        // Recreate strategy replaces the pod on the apply below. The idempotent
        // enroll init then redeems the rebind token if the persisted identity
        // is absent, and skips otherwise (the live identity stays valid; the
        // fabric apply already routes the new CIDRs, and the refreshed token
        // covers every future re-enroll).
            match ctx.admin.segment_id_by_name(&seg.spec.segment_name).await {
                Ok(Some(segment_id)) => {
                    let token = ctx
                        .admin
                        .mint_gateway_rebind_token(segment_id)
                        .await
                        .map_err(Error::Admin)?;
                    let mut sec = token_secret_body(&name, &token, &cidrs);
                    sec.metadata.namespace = Some(ns.clone());
                    sec.metadata.owner_references = Some(vec![owner_ref(gw)?]);
                    apply(&secrets, &sec).await?;
                    tracing::info!(
                        "gateway {name}: segment {segment} CIDRs changed — minted a rebind token \
                         and refreshed the token Secret (new bound CIDRs: {cidrs:?})",
                        segment = seg.spec.segment_name,
                    );
                }
                Ok(None) => {
                    // The fabric apply that introduces/renames the segment hasn't
                    // landed controller-side yet; the requeue will retry the rebind.
                    tracing::warn!(
                        "gateway {name}: rebind needed but segment {segment} is not registered \
                         in the controller yet; deferring to the next reconcile",
                        segment = seg.spec.segment_name,
                    );
                }
                Err(e) => return Err(Error::Admin(e)),
            }
        }
        // Steady state: single-use tokens must not be re-minted every reconcile.
        MintAction::None => {}
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
    let deployments = Api::<Deployment>::namespaced(client.clone(), &ns);
    apply_deployment(&deployments, &dep).await?;

    // Is the gateway workload deliberately scaled to 0?
    //
    // This reconciler reports LIVENESS nowhere else: `enrolled` below is derived
    // purely from the controller's roster, a control-plane fact, and no
    // Deployment status is consulted. That was harmless while the operator
    // force-applied `replicas: 1` — the pod was always meant to be up. Now that
    // `spec.replicas` is released (`workloads::released_replicas`) and
    // `kubectl scale --replicas=0` sticks, a gateway a human took down would
    // keep reporting `Enrolled: True` off a still-active roster row: the CR
    // would claim a live data plane that is dead. Shipping the scale-down
    // without this signal ships a known lie.
    //
    // `get_opt` so a MISSING Deployment (the read racing the apply above, or a
    // GC in flight) reads as "cannot prove a scale-down" → False, rather than
    // erroring the reconcile out before `Enrolled` — the load-bearing status
    // here — is ever written. Other API errors still propagate to the requeue,
    // exactly like every other call in this reconcile; the apply immediately
    // above would already have failed on them. The signal only ever fires on a
    // `spec.replicas` we actually read as 0.
    let scaled_down = matches!(
        deployments.get_opt(&name).await?.as_ref().map(super::deployment_readiness),
        Some(Readiness::ScaledDown)
    );

    // Status from the controller's gateway roster (reuse `seg_row` from above).
    let row = seg_row;
    let enrolled = row.is_some();
    let status = WiremeshGatewayStatus {
        enrolled,
        gateway_id: row.map(|g| g.id),
        path_state: row.map(|g| g.status.clone()),
        // `Enrolled` is UNCHANGED, deliberately: the gateway genuinely IS
        // enrolled while scaled down — the roster row is real, the certs are
        // real, and folding liveness into it would corrupt a signal that is
        // currently trustworthy. `ScaledDown` goes ALONGSIDE it so the CR states
        // both true things at once: enrolled, and not running.
        conditions: vec![
            Condition {
                type_: "Enrolled".into(),
                status: if enrolled { "True" } else { "False" }.into(),
                reason: if enrolled { "GatewayRegistered" } else { "AwaitingEnrollment" }.into(),
                message: if enrolled { "gateway registered with the controller".into() } else { "gateway not yet enrolled".into() },
            },
            Condition {
                type_: "ScaledDown".into(),
                status: if scaled_down { "True" } else { "False" }.into(),
                reason: if scaled_down { "ReplicasZero" } else { "ReplicasNonZero" }.into(),
                message: if scaled_down {
                    "gateway Deployment is scaled to 0 replicas — the enrollment is still valid, \
                     but no gateway pod is running and this segment carries no traffic"
                        .into()
                } else {
                    "gateway Deployment is not scaled down".into()
                },
            },
        ],
    };
    api_status(ctx, &name, status).await?;
    // A scale-down requeues on the settled cadence even when not enrolled: with
    // no pod, enrollment can never progress, so the 15s retry would spin on
    // something that cannot happen. A scale back up arrives through the
    // Deployment watch (`.owns` in `run`), not by polling.
    Ok(Action::requeue(Duration::from_secs(if enrolled || scaled_down {
        super::SETTLED_REQUEUE_SECS
    } else {
        15
    })))
}

async fn cleanup_gateway(gw: &WiremeshGateway, ctx: &Context) -> Result<Action, Error> {
    // BEST-EFFORT with respect to a GONE controller (see the `controllers`
    // module doc's *Teardown order*): if the WiremeshController CR was deleted
    // before this Gateway CR (`kubectl delete -f all.yaml`), every admin call
    // below can only fail forever and this CR would wedge in `Terminating`.
    // Skip-with-a-loud-warning and complete the finalizer — the roster state
    // died with the controller. A controller that is PRESENT but erroring still
    // hard-fails below (finalizer retry).
    if super::controller_cleanup_skip(ctx).await {
        tracing::warn!(
            "gateway {name} finalizer: controller is GONE (WiremeshController CR absent or no \
             Running controller pod) — SKIPPING the controller-side drain (status gateway_id: \
             {id:?}). If a controller still exists elsewhere, drain manually: `fabricctl drain`.",
            name = gw.name_any(),
            id = gw.status.as_ref().and_then(|s| s.gateway_id),
        );
        return Ok(Action::await_change());
    }

    // Drain the gateway in the controller (withdraw + revoke) before the
    // workload is GC'd with the CR. Prefer the id we recorded in status — the
    // referenced Segment CR may already be deleted, so we must NOT depend on
    // resolving it (that would silently skip the drain).
    let gateway_id = match gw.status.as_ref().and_then(|s| s.gateway_id) {
        Some(id) => Some(id),
        None => {
            // Fallback: resolve via the segment name if the CR still exists.
            // ACTIVE-filtered: a stale drained/replaced roster row must never
            // pick the drain target (draining the wrong id when stale entries
            // precede the live row was the reported bug).
            //
            // SOLE-CR GUARD (mirrors the adoption path): with no
            // `status.gateway_id`, this CR can prove NOTHING about which id is
            // its own — it may never have enrolled at all. The roster keys a
            // gateway to its segment by NAME only, so if a PEER
            // `WiremeshGateway` CR also targets this segment, the segment's
            // active id may be that peer's LIVE gateway and draining it would
            // be an outage. Only drain when this CR is the sole gateway CR for
            // the segment (it is still listed during its own finalizer, so the
            // expected sole count is 1). SAFE FALLBACK on a list failure:
            // never drain — a missed drain is a manual `fabricctl drain`, a
            // wrong drain kills a live peer.
            let seg_name = Api::<WiremeshSegment>::all(ctx.client.clone())
                .get_opt(&gw.spec.segment_ref)
                .await?
                .map(|s| s.spec.segment_name);
            match seg_name {
                Some(name) => {
                    let sole = match Api::<WiremeshGateway>::all(ctx.client.clone())
                        .list(&ListParams::default())
                        .await
                    {
                        Ok(list) => {
                            list.items
                                .iter()
                                .filter(|g| g.spec.segment_ref == gw.spec.segment_ref)
                                .count()
                                == 1
                        }
                        Err(e) => {
                            tracing::warn!(
                                "gateway {gwname} cleanup: listing WiremeshGateway CRs failed \
                                 ({e}); treating as NOT the sole gateway for segment {name} \
                                 (conservative: skip the fallback drain)",
                                gwname = gw.name_any(),
                            );
                            false
                        }
                    };
                    if !sole {
                        tracing::warn!(
                            "gateway {gwname} cleanup: no recorded gateway_id and this CR is \
                             not the sole WiremeshGateway for segment {name} — SKIPPING the \
                             fallback drain (the segment's active id may be a live peer's \
                             gateway). Drain manually if a stale id remains.",
                            gwname = gw.name_any(),
                        );
                        None
                    } else {
                        let roster = ctx.admin.list_gateways().await.map_err(Error::Admin)?;
                        active_in_segment(&roster, &name).map(|g| g.id)
                    }
                }
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

    #[test]
    fn drain_still_authorized_gates_on_fresh_predrain_recheck() {
        // TOCTOU NARROWING (CodeRabbit MAJOR): `adoption_needs_stale_drain` picks the
        // drain target from an EARLY snapshot; `drain_still_authorized` re-checks it
        // against a FRESH roster + CR-list read taken immediately before the drain, so
        // a concurrent reconcile that changed the segment's active gateway can no longer
        // make us drain a live peer. Authorize ONLY when the segment's active id is
        // STILL exactly the snapshotted stale id AND this CR is STILL the sole gateway
        // CR (recount == 1); any drift → false → abort.
        //
        // Pure fn contract:
        //   drain_still_authorized(recount_now, active_id_now, stale_id)
        //       == (recount_now == 1 && active_id_now == Some(stale_id))

        // Happy path: nothing drifted — the snapshotted stale id is still the sole
        // segment's active id and this CR is still alone → authorize the drain.
        assert!(
            drain_still_authorized(1, Some(8), 8),
            "recount still 1 AND active id still == stale id → authorize drain"
        );

        // The active id CHANGED between snapshot and drain (a peer enrolled a new
        // gateway) → the id we'd drain may be live → ABORT.
        assert!(
            !drain_still_authorized(1, Some(9), 8),
            "active id now differs from the stale id → abort (may be a live peer)"
        );

        // The active id VANISHED (already drained elsewhere / withdrawn) → nothing to
        // drain → ABORT.
        assert!(
            !drain_still_authorized(1, None, 8),
            "no active id on the fresh read → nothing to drain → abort"
        );

        // A peer CR now shares the segment (recount grew) → the active id could be the
        // peer's live gateway → ABORT even if the id still matches.
        assert!(
            !drain_still_authorized(2, Some(8), 8),
            "recount no longer 1 (peer CR appeared) → abort even if the id matches"
        );

        // Both drifted → ABORT.
        assert!(!drain_still_authorized(0, None, 8), "recount 0 and no active id → abort");
    }
}
