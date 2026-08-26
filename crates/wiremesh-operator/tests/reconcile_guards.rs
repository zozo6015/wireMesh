//! FAILING tests (test-author, operator hardening round, Backlog 4) — Fix 4
//! (`apply_fabric` serialization) and Fix 5 (controller PVC create-only guard).
//! **compile-RED** until the pinned surfaces exist.
//!
//! # Fix 5 — controller PVC create-only guard
//!
//! controller.rs:26-29 server-side-applies the controller PVC on EVERY
//! reconcile pass. A bound PVC's `storageClassName` and
//! `resources.requests.storage` are immutable, so the moment a user edits
//! `spec.storageSize`/`storageClass` on the CR the SSA 422s permanently and the
//! reconcile loops forever (the controller Deployment/Service after the PVC
//! apply never get re-applied either). The gateway already has the guard
//! (`pvc_needs_create`, gateway.rs:59-65); the SAME shared guard must gate the
//! controller reconciler's PVC apply.
//!
//! Pinned surface: the guard promoted to the SHARED `controllers` module so
//! both reconcilers (and the relay reconciler gaining a PVC in Fix 1) use one
//! choke point:
//! ```ignore
//! // controllers/mod.rs — move, or `pub use gateway::pvc_needs_create;`
//! pub fn pvc_needs_create(existing: Option<&PersistentVolumeClaim>) -> bool
//! ```
//! Wiring (integration-level, review-verified): controller.rs must
//! `get_opt("<name>-data")` and apply the PVC ONLY when `pvc_needs_create` —
//! mirroring gateway.rs:352. The reconcile flow itself is cluster-only; the
//! shared-guard truth table is what is unit-pinned here.
//!
//! # Fix 4 — `apply_fabric` serialization (compile-pin only)
//!
//! fabric.rs:27-34 lists segments+policies then applies the rendered fabric.
//! Two concurrent reconciles interleave list→apply: a Segment finalizer's
//! `delete_segment` + post-delete re-render can race an Apply-path render that
//! STILL saw the segment → the ghost segment is resurrected into the fabric
//! after its delete. Expected fix: a `tokio::Mutex` in `Context` held across
//! the WHOLE list+render+apply critical section (the list MUST be inside).
//!
//! Pinned surface (compile-pin — `Context` is Clone, so the lock is Arc'd):
//! ```ignore
//! pub struct Context {
//!     ...,
//!     pub fabric_apply_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
//! }
//! ```
//! The lock DISCIPLINE (list inside the critical section; both the Apply arm
//! and the Cleanup arm's delete+re-render acquiring it) cannot be proven by a
//! unit test — no mock apiserver is fabricated here. That property is
//! REVIEW-VERIFIED: the reviewer must check both `finalizer` arms in fabric.rs
//! take the guard before their first list. This file only compile-pins the
//! field so the surface exists and has the right type.

use k8s_openapi::api::core::v1::PersistentVolumeClaim;
use wiremesh_operator::controllers::pvc_needs_create;

#[test]
fn shared_pvc_guard_is_create_only() {
    // Same truth table as the gateway's local guard — pinned at the SHARED
    // location all three reconcilers must route through.
    assert!(pvc_needs_create(None), "absent PVC → create it");
    let existing = PersistentVolumeClaim::default();
    assert!(
        !pvc_needs_create(Some(&existing)),
        "existing PVC → never re-apply/patch (storageClassName / requests.storage \
         are immutable after bind; re-applying 422s the whole reconcile forever)"
    );
}

/// Compile-pin for Fix 4: `Context.fabric_apply_lock` must exist with exactly
/// this type. Never called — its compilation IS the assertion.
#[allow(dead_code)]
fn _pin_fabric_apply_lock(
    ctx: &wiremesh_operator::controllers::Context,
) -> &std::sync::Arc<tokio::sync::Mutex<()>> {
    &ctx.fabric_apply_lock
}

#[test]
fn fabric_apply_lock_is_compile_pinned() {
    // Documentation-carrying marker: the real assertions for Fix 4 are (a) the
    // `_pin_fabric_apply_lock` compile-pin above and (b) the REVIEW check that
    // `apply_fabric`'s list happens INSIDE the locked section and that both
    // finalizer arms acquire the lock. A unit test cannot exercise the race
    // without fabricating a kube mock layer this crate deliberately lacks.
    //
    // The body references the compile-pin instead of asserting a constant:
    // `assert!(true)` trips `clippy::assertions_on_constants` under CI's
    // `-D warnings`, and silencing it with an `#[allow]` would hide the lint
    // for any future real assertion added here. Naming `_pin_fabric_apply_lock`
    // is also the more honest body -- the pin IS what this test guards.
    let _ = _pin_fabric_apply_lock;
}
