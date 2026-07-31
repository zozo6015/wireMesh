//! FAILING tests (test-author, operator hardening round, Backlog 4) — Fix 3:
//! FINALIZER BEST-EFFORT cleanup. **compile-RED** until the pinned fn exists.
//!
//! # The bug
//!
//! Both delete-path finalizers hard-fail when the controller is unreachable:
//! `cleanup_gateway` `?`s the drain (gateway.rs:417) and the Segment finalizer
//! `?`s `delete_segment_by_name` (fabric.rs:78-82). If the WiremeshController
//! CR (or its pod) was deleted BEFORE the dependent Gateway/Segment CRs — the
//! natural teardown order for `kubectl delete -f all.yaml` — every admin call
//! fails forever, the finalizer never completes, and the CRs wedge in
//! `Terminating` until someone hand-edits finalizers away.
//!
//! # Pinned implementer surface
//!
//! A shared pure decision fn in `controllers` (used by BOTH the gateway
//! finalizer and the segment finalizer):
//! ```ignore
//! pub fn cleanup_should_skip(controller_cr_exists: bool, controller_pod_running: bool) -> bool
//! ```
//! `true` → the controller is GONE: log a WARNING naming what was skipped
//! (drain id / segment delete) and complete the finalizer successfully (the
//! controller state died with the controller; there is nothing left to clean).
//! `false` → the controller is present: perform the cleanup and KEEP
//! hard-failing on a genuine RPC error (a live-but-erroring controller must
//! still retry — best-effort is only for controller-GONE, never a silent
//! swallow of real failures).
//!
//! # Wiring (integration-level, documented — NOT unit-testable here)
//!
//! * `controller_cr_exists` ← `Api::<WiremeshController>::all(client).list(..)`
//!   non-empty.
//! * `controller_pod_running` ← a Running pod matching
//!   `workloads::controller_pod_selector()` (the same probe `AdminExec::Exec`
//!   uses).
//! * A merely-restarting controller pod (CR exists, pod briefly not Running)
//!   WILL skip the drain — accepted trade-off, decided with the reviewer: a
//!   missed drain is a manual `fabricctl drain`; a Terminating-wedged CR blocks
//!   namespace/cluster teardown. The kube finalizer retry loop makes the
//!   not-Running window narrow in practice (the reconcile requeues until the
//!   finalizer completes, so a transient dip usually resolves before the CR is
//!   actually deleted).
//! * The finalizer flows themselves (kube apiserver, retries) are cluster-only
//!   — proven by the kind e2e, not here.

use wiremesh_operator::controllers::cleanup_should_skip;

#[test]
fn controller_present_and_running_never_skips() {
    // The ONLY case where cleanup must actually run — and where a genuine RPC
    // error must still hard-fail (retry), not be swallowed.
    assert!(
        !cleanup_should_skip(true, true),
        "controller CR present + pod Running → perform the drain/segment-delete"
    );
}

#[test]
fn missing_controller_cr_skips_with_warning() {
    // `kubectl delete -f all.yaml` deletes the WiremeshController CR first →
    // its Deployment/pod are GC'd. Dependent CR finalizers must not wedge.
    assert!(
        cleanup_should_skip(false, false),
        "no WiremeshController CR and no pod → skip cleanup (nothing to clean)"
    );
    assert!(
        cleanup_should_skip(false, true),
        "no WiremeshController CR → skip even if some stale pod still matches the \
         selector (the CR is the source of truth; an orphaned pod is being GC'd)"
    );
}

#[test]
fn missing_controller_pod_skips_with_warning() {
    assert!(
        cleanup_should_skip(true, false),
        "CR exists but no Running controller pod → the admin exec can only fail; \
         skip-with-warning instead of wedging the finalizer in Terminating"
    );
}
