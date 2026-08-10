//! Backlog item 30: the `ScaledDown` readiness truth table, pinned.
//!
//! # Why this file exists
//!
//! Backlog 2b's `ScaledDown` logic was expected to ship as a **code-review
//! invariant with no automated test**. The sibling
//! `replicas_omitted_scaledown_condition.rs` says so in as many words (its
//! "What this file does NOT prove" section): the readiness computation lived
//! inline in `async fn reconcile(...)` in `controller.rs` and `relay.rs`, both
//! of which take a live kube `Client`, and this crate has no fake apiserver.
//! That file then suggested the way out — extract a pure
//! `fn workload_readiness(desired: Option<i32>, available: i32) -> Readiness`,
//! the same shape `should_mint_token`/`needs_rebind`/`adoption_needs_stale_drain`
//! already use to make `gateway.rs`'s guards testable.
//!
//! The implementation did exactly that. `controllers::workload_readiness` and
//! its `Deployment`-shaped wrapper `controllers::deployment_readiness` are pure
//! `pub fn`s over plain values, and all three reconcilers
//! (`controller.rs:68`, `relay.rs:237`, `gateway.rs:656`) route through them.
//! So the truth table is no longer a code-review-only invariant — it is
//! mechanically pinnable, and this file pins it. That closes item 30.
//!
//! # Status: green on arrival
//!
//! Same framing as `enroll_init_container_arg_pinning.rs` and
//! `candidate_cap_gateway_relation.rs`: these are CHARACTERIZATION tests of
//! behaviour that already exists and is already correct. **No bug is being
//! reproduced here and none of these are expected to fail** — this is not a
//! miscalibrated TDD attempt. (Contrast the sibling
//! `replicas_omitted_scaledown_condition.rs`, whose builder tests are RED
//! by design.) The point is that until this file existed, nothing would have
//! caught a change that broke the table; every test below names, in its doc
//! comment, the production change it exists to catch.
//!
//! # What is actually at stake
//!
//! Getting a row of this table wrong is not a cosmetic status bug. The
//! classification drives, in all three reconcilers, both the reported condition
//! AND the requeue cadence:
//!
//! * Misclassify a deliberate scale-down as `Starting` → the CR reports
//!   `WaitingForController` / `"relay pod starting"` **forever**, a false alarm
//!   that can never clear, and the reconciler requeues on the fast not-ready
//!   cadence (10s controller / 15s relay) in a hot loop with nothing to wait
//!   for. That is the failure mode `Readiness` was introduced to prevent, and
//!   it is strictly worse than the can't-scale-down bug it replaced.
//! * Misclassify a genuinely-starting workload as `ScaledDown` → the operator
//!   drops to the 300s settled cadence (`SETTLED_REQUEUE_SECS`) and tells the
//!   human the workload is off by request while it is actually stuck.
//!
//! # Placement
//!
//! An integration test in `tests/`, not an in-crate `#[cfg(test)] mod tests`:
//! `lib.rs` declares `pub mod controllers`, and `Readiness`,
//! `workload_readiness` and `deployment_readiness` are all `pub` within it, so
//! the whole surface under test is reachable through the crate's public API as
//! `wiremesh_operator::controllers::*`. **No visibility was widened for this
//! file** — nothing in `src/` was touched at all. `k8s_openapi` is a normal
//! dependency of this package and is therefore linkable from test targets, the
//! same way `gateway_metrics_bind_override.rs` and `reconcile_guards.rs`
//! already use it.

use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec, DeploymentStatus};
use wiremesh_operator::controllers::{deployment_readiness, workload_readiness, Readiness};

// ---------------------------------------------------------------------------
// 1. The two rows that carry real reasoning. If only two tests in this file
//    survive a future cleanup, these are the two — each guards a distinction a
//    plausible, well-intentioned rewrite would erase.
// ---------------------------------------------------------------------------

/// `desired == None` means UP, not off.
///
/// The field being unset is the steady state now that
/// `workloads::released_replicas` stopped force-applying it: SSA releases
/// ownership, and the API-server defaulter resolves the absent field to `1`.
/// This is precisely the distinction `DeploymentSpec.replicas` being a
/// *nullable* int32 exists to express — "a pointer to distinguish between
/// explicit zero and not specified".
///
/// **Breaks if:** anyone rewrites the guard as
/// `desired.unwrap_or(0) == 0`, `!matches!(desired, Some(n) if n >= 1)`, or
/// any other form that folds `None` in with `Some(0)`. Every healthy workload
/// in the fabric would then report `ScaledDown` — the operator would announce
/// that a running control plane is deliberately off.
#[test]
fn omitted_replicas_is_not_a_scale_down() {
    assert_eq!(
        workload_readiness(None, 1),
        Readiness::Available,
        "desired == None means the operator RELEASED spec.replicas and the \
         API-server defaulter resolved it to 1 — the steady state for every \
         healthy workload since `workloads::released_replicas`. It must never \
         be read as a scale-down: only an EXPLICIT Some(0) is one. Folding \
         None in with Some(0) would report every running controller, gateway \
         and relay in the fabric as deliberately off."
    );
    assert_eq!(
        workload_readiness(None, 0),
        Readiness::Starting,
        "desired == None with nothing available yet is a workload that is \
         MEANT to be up and is not up — the genuine wait-and-retry case that \
         must keep the fast requeue cadence. Classifying it as ScaledDown \
         would drop it to the 300s settled cadence and tell the human it is \
         off by request while it is actually stuck starting."
    );
}

/// `Some(0)` is checked BEFORE the available count, deliberately.
///
/// Mid-scale-down the old pod can still be counted available for a moment.
/// Reporting the intent (off) beats flipping to `Available` for a single pass
/// and then back — a transient wrong answer that alerting rules and
/// `kubectl wait` both see.
///
/// **Breaks if:** anyone reorders the function to test `available >= 1` first
/// (the "obvious" simplification — it reads as an early-out for the happy
/// path). Note that **every other row of the truth table still passes** under
/// that reordering: this single case is the only thing that catches it, which
/// is exactly why it gets its own test rather than living inside the sweep.
#[test]
fn explicit_zero_wins_over_a_still_available_replica() {
    assert_eq!(
        workload_readiness(Some(0), 1),
        Readiness::ScaledDown,
        "spec.replicas == 0 with a replica STILL counted available is the \
         mid-scale-down window: the pod is terminating but status has not \
         caught up. The desired count is the operator's intent and must win — \
         reporting Available here would flip the CR to ready for one reconcile \
         pass and straight back to ScaledDown, a transient lie visible to \
         `kubectl wait` and to any alerting rule watching the condition. This \
         is the ONE case that catches a reordering of `workload_readiness` to \
         check `available >= 1` first; every other row survives that rewrite."
    );
}

// ---------------------------------------------------------------------------
// 2. The full truth table, swept. Documents the complete contract in one
//    place; the two tests above are the ones with teeth.
// ---------------------------------------------------------------------------

/// The whole table from `workload_readiness`'s own doc comment, row by row.
///
/// **Breaks if:** any classification changes at all. Deliberately redundant
/// with the targeted tests above — this is the "did you mean to change the
/// contract?" guard, they are the "here is why this row is what it is" guards.
#[test]
fn full_truth_table() {
    let table: &[(Option<i32>, i32, Readiness)] = &[
        // desired unset → defaulter resolves to 1 → the workload is meant to be up.
        (None, 5, Readiness::Available),
        (None, 1, Readiness::Available),
        (None, 0, Readiness::Starting),
        // desired explicitly 1 → the singleton steady state, same as unset.
        (Some(1), 2, Readiness::Available),
        (Some(1), 1, Readiness::Available),
        (Some(1), 0, Readiness::Starting),
        // desired explicitly 0 → off by request, regardless of what status says.
        (Some(0), 0, Readiness::ScaledDown),
        (Some(0), 1, Readiness::ScaledDown),
        (Some(0), 3, Readiness::ScaledDown),
        // A partial rollout: see `partial_rollout_is_available_not_starting`.
        (Some(3), 2, Readiness::Available),
        (Some(3), 0, Readiness::Starting),
    ];
    for &(desired, available, expected) in table {
        assert_eq!(
            workload_readiness(desired, available),
            expected,
            "workload_readiness(desired = {desired:?}, available = {available}) \
             must classify as {expected:?}. This is the complete contract the \
             three reconcilers' conditions AND requeue cadences are computed \
             from (controller.rs, relay.rs, gateway.rs) — a changed row is \
             either a deliberate contract change that belongs in the function's \
             doc comment and this table together, or a regression."
        );
    }
}

/// A partially-rolled-out workload reports `Available`, not `Starting`.
///
/// Pinned as OBSERVED behaviour, read off the implementation rather than
/// assumed: `workload_readiness` tests `available >= 1`, not
/// `available >= desired`, so `Some(3)` desired with `2` available is
/// `Available`. That is the right answer here for two reasons. It preserves
/// the pre-`Readiness` semantics exactly (`available_replicas >= 1` was the
/// whole readiness test before this extraction, so no CR changed meaning when
/// the extraction landed); and `Readiness` answers "is this workload serving",
/// not "is the rollout complete". These workloads are singletons anyway —
/// hostNetwork, a fixed WG port, an RWO PVC, and a `Recreate` strategy chosen
/// so a second pod never surges — so `Some(n>1)` is not a supported
/// configuration to begin with, and no CRD field offers it
/// (`replicas_omitted_scaledown_condition.rs` guards that too).
///
/// **Breaks if:** anyone "tightens" the check to `available >= desired`. That
/// would flip a singleton with one healthy pod and a stale/incomplete status
/// into `Starting` — a not-ready report and a fast requeue loop against a
/// workload that is serving fine.
#[test]
fn partial_rollout_is_available_not_starting() {
    assert_eq!(
        workload_readiness(Some(3), 2),
        Readiness::Available,
        "readiness is `available >= 1` — 'is this workload serving' — NOT \
         `available >= desired` ('is the rollout complete'). That is the exact \
         semantics the reconcilers had before `Readiness` was extracted, and \
         keeping it is what made the extraction a refactor rather than a \
         behaviour change. Tightening it to `available >= desired` would report \
         a serving workload as not-ready and pin it to the fast requeue cadence."
    );
}

// ---------------------------------------------------------------------------
// 3. `deployment_readiness` — the wrapper that reads the two counts off a live
//    Deployment. The pure function above is only as good as the field
//    extraction feeding it.
// ---------------------------------------------------------------------------

fn deployment(replicas: Option<i32>, available: Option<i32>) -> Deployment {
    Deployment {
        spec: Some(DeploymentSpec { replicas, ..Default::default() }),
        status: Some(DeploymentStatus { available_replicas: available, ..Default::default() }),
        ..Default::default()
    }
}

/// `deployment_readiness` reads DESIRED from `spec.replicas` and AVAILABLE
/// from `status.availableReplicas` — and not, say, from `status.replicas` or
/// `status.readyReplicas`, which are different counts that would each be
/// wrong here in a different way.
///
/// **Breaks if:** the two arguments are swapped, or either is sourced from a
/// neighbouring field. `status.replicas` counts pods that exist including
/// terminating ones, so a scale-down would linger as `Available`;
/// `status.readyReplicas` is close but is not the field the pre-extraction
/// reconcilers used, so switching to it would be a silent behaviour change to
/// every CR's readiness.
#[test]
fn deployment_readiness_reads_spec_replicas_and_status_available_replicas() {
    assert_eq!(
        deployment_readiness(&deployment(Some(0), Some(0))),
        Readiness::ScaledDown,
        "spec.replicas = 0 on a live Deployment must classify as ScaledDown — \
         this is the read that produces the `ScaledDown` condition on \
         WiremeshController/WiremeshGateway and the 'relay scaled down (0 \
         replicas)' message on WiremeshRelay."
    );
    assert_eq!(
        deployment_readiness(&deployment(None, Some(1))),
        Readiness::Available,
        "spec.replicas omitted + one available replica is the healthy steady \
         state of every workload the operator manages; it must classify as \
         Available."
    );
    assert_eq!(
        deployment_readiness(&deployment(Some(1), Some(0))),
        Readiness::Starting,
        "spec.replicas = 1 with no available replica is the genuine \
         wait-and-retry case and must classify as Starting — the arguments \
         must not be swapped, which this row (unlike a symmetric one) detects."
    );
    assert_eq!(
        deployment_readiness(&deployment(Some(0), Some(2))),
        Readiness::ScaledDown,
        "the desired-wins-over-available ordering must survive the trip \
         through the Deployment wrapper too, not just the pure function."
    );
}

/// A missing `status` (or a missing `availableReplicas` within it) reads as
/// **0 available**, via the `unwrap_or(0)` in `deployment_readiness`.
///
/// This is the freshly-created Deployment: the apiserver has accepted the
/// object but no controller has written status yet. Zero available is the
/// truthful reading — nothing is serving.
///
/// **Breaks if:** the `unwrap_or(0)` becomes `unwrap_or(1)`, or the absent
/// status is treated as "assume healthy". A workload that never starts would
/// then report `Available` forever off a status block that never appears.
#[test]
fn absent_status_counts_as_zero_available() {
    let no_status = Deployment {
        spec: Some(DeploymentSpec { replicas: Some(1), ..Default::default() }),
        ..Default::default()
    };
    assert_eq!(
        deployment_readiness(&no_status),
        Readiness::Starting,
        "a Deployment with no status block at all (just created, no controller \
         has written status yet) has 0 available replicas — `unwrap_or(0)`. \
         Reading an absent status as healthy would report a workload that \
         never starts as Available forever."
    );

    let empty_status = deployment(Some(1), None);
    assert_eq!(
        deployment_readiness(&empty_status),
        Readiness::Starting,
        "status present but availableReplicas absent is the same 0 — \
         availableReplicas is omitted rather than serialized as 0 when no \
         replica is available, so this is the common shape, not an edge case."
    );
}

/// `ScaledDown` requires an AFFIRMATIVE read of `spec.replicas == 0`; an
/// object we cannot read the desired count from is never a scale-down.
///
/// `gateway.rs`'s reconcile leans on exactly this: it uses `get_opt` so a
/// missing Deployment reads as "cannot prove a scale-down" → the `ScaledDown`
/// condition goes False, rather than erroring the reconcile out before
/// `Enrolled` — the load-bearing status there — is ever written. This test
/// pins the same conservatism one level down, for a Deployment that exists but
/// carries no spec.
///
/// **Breaks if:** an absent `spec`/`spec.replicas` is ever defaulted to 0
/// instead of flowing through as `None`. A gateway mid-apply, or one whose
/// spec read raced a GC, would then be announced as deliberately scaled down
/// while its data plane is up.
#[test]
fn a_deployment_with_no_spec_is_never_scaled_down() {
    let bare = Deployment::default();
    assert_eq!(
        deployment_readiness(&bare),
        Readiness::Starting,
        "an object with no spec at all yields desired = None, which means \
         'defaulter resolves it to 1', not 'zero'. ScaledDown must only ever \
         come from a spec.replicas we actually READ as 0 — the same \
         conservatism `gateway.rs` applies with `get_opt` when the Deployment \
         is missing entirely. Defaulting an unreadable desired count to 0 \
         would announce a live gateway as deliberately taken down."
    );
}
