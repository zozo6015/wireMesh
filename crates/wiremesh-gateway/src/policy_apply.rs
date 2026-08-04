//! Off-loop policy installation (Backlog item 1 — Cycle-3 hardening PR-B).
//!
//! The Sync loop used to install policy INLINE: `apply_state(...).await?`
//! took the `enforcers` map lock and called `apply_if_changed` on every live
//! epoch, which reached `ebpf::apply_generation`'s `std::thread::sleep` of
//! the previous flip's 10s reap grace. One policy epoch therefore parked a
//! tokio runtime thread for ten seconds — the SAME `tokio::select!` loop that
//! consumes `SyncEvent::Punch` (a Cycle-4b go-skew violation, Phase-0 Finding
//! 2) and rotation events — held the enforcer-map lock throughout (starving
//! the metrics scrape, retire, Role-B collapse and rotation-insert paths),
//! cost N × 10s with several live epochs, and made any apply error fatal via
//! the `?` (see `docs/research/backlog-program-notes.md` §B9/§B10 for two
//! real outages of exactly that shape).
//!
//! This module is that install, moved behind a latest-wins mailbox:
//!
//! 1. the backend publishes its grace as a deadline instead of sleeping it
//!    (`wiremesh_enforcer::Enforcer::apply_ready_at`);
//! 2. [`PolicyApplyHandle::publish`] — deliberately NOT `async`, returning
//!    `()` — is all the Sync loop does, so it has neither an `.await` to
//!    stall on nor a `?` to die on;
//! 3. the worker waits the deadline out with `sleep_until` (no thread
//!    parked, no lock held) and runs the install on the blocking pool.
//!
//! It lives in the LIBRARY rather than `main.rs` because `main.rs` is the
//! binary: nothing in it is importable by an integration test, and the
//! properties above are exactly what
//! `tests/policy_apply_worker.rs` needs to assert. That the binary actually
//! USES the worker is not observable from here — it is covered by
//! `tests/policy_apply_liveness.rs` and by review.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::watch;

use crate::state::DesiredState;

/// Everything the worker needs from the live enforcer map. `main.rs`
/// implements it with a thin adapter over
/// `Arc<tokio::sync::Mutex<HashMap<u32, GatewayEnforcer>>>`; tests implement
/// it with a fake.
pub trait PolicyApplyTarget: Send + Sync + 'static {
    /// The latest instant at which EVERY live enforcer will accept the next
    /// apply — the `max` over each entry's `GatewayEnforcer::apply_ready_at()`.
    /// `None` = no constraint; a `Some` in the past is already satisfied.
    ///
    /// Returning a plain `Option<Instant>` (rather than any kind of guard)
    /// is the load-bearing part of this seam: the real adapter takes the
    /// enforcer-map lock, reads the deadlines and drops the lock before
    /// returning, and the signature makes holding that lock across the
    /// worker's wait structurally impossible.
    fn ready_at(&self) -> Option<Instant>;

    /// Perform the (now fast) install: re-lock the enforcer map and
    /// `apply_if_changed(ds)` every live entry. BLOCKING by contract — the
    /// worker always calls it inside `tokio::task::spawn_blocking`, so the
    /// real adapter is free to use `Mutex::blocking_lock()`.
    fn install(&self, ds: &DesiredState) -> anyhow::Result<()>;
}

/// Latest-wins mailbox handle. Cheap to clone: the Sync loop publishes
/// through it, the metrics scrape reads [`PolicyApplyHandle::failures`].
#[derive(Clone)]
pub struct PolicyApplyHandle {
    tx: Arc<watch::Sender<Option<DesiredState>>>,
    failures: Arc<AtomicU64>,
}

impl PolicyApplyHandle {
    /// Hand `ds` to the worker, superseding any state not yet installed.
    ///
    /// Not `async`, never blocks, never fails — that signature IS the
    /// guarantee this item exists to deliver, so keep it. `send_replace`
    /// rather than `send` because `send` reports `Err` when the receiver is
    /// gone, and a Sync loop that has to think about the worker's liveness
    /// is back to having an apply it can trip over.
    pub fn publish(&self, ds: DesiredState) {
        let _ = self.tx.send_replace(Some(ds));
    }

    /// Installs that returned `Err` since boot; the source of the
    /// `wiremesh_gateway_policy_apply_failures_total` counter.
    pub fn failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }
}

/// Spawn the policy-apply worker onto the current runtime and return its
/// mailbox handle. The task exits once the last [`PolicyApplyHandle`] is
/// dropped.
///
/// `retry_after` is the pause between attempts at a state whose install
/// failed. Failures are logged and counted, never propagated: a policy the
/// backend cannot consume must degrade to "the datapath keeps the last good
/// policy and the gateway keeps running", not to a dead process.
pub fn spawn_policy_apply_worker<T: PolicyApplyTarget>(
    target: Arc<T>,
    retry_after: Duration,
) -> PolicyApplyHandle {
    // `watch`, not a queue: a burst of epochs must collapse to the NEWEST
    // desired state. Installing the intermediates would be pure cost — the
    // enforcer is idempotent per policy version, and in production every
    // extra generation flip buys another full reap grace before the state
    // an operator actually wants can land.
    let (tx, mut rx) = watch::channel::<Option<DesiredState>>(None);
    let failures = Arc::new(AtomicU64::new(0));
    let handle = PolicyApplyHandle { tx: Arc::new(tx), failures: failures.clone() };

    tokio::spawn(async move {
        loop {
            // (1) Wait for a published state. `Err` = every handle dropped.
            if rx.changed().await.is_err() {
                return;
            }
            let Some(mut ds) = rx.borrow_and_update().clone() else {
                continue;
            };

            loop {
                // (2) Read the deadline and let go of whatever it touched.
                //
                // On the blocking pool because the real adapter reaches the
                // deadlines through a `tokio::sync::Mutex` and there is no
                // sound way to take one synchronously from inside a runtime
                // (`blocking_lock` panics there, and a `try_lock` that lost
                // a race would have to either invent "no constraint" —
                // authorizing exactly the early overwrite the grace exists
                // to prevent — or invent a deadline). The read itself is
                // still cheap and lock-free-on-return by contract; this only
                // moves the lock ACQUISITION off the runtime thread.
                let deadline = {
                    let target = target.clone();
                    match tokio::task::spawn_blocking(move || target.ready_at()).await {
                        Ok(d) => d,
                        // A panicking `ready_at` must not take the worker
                        // (or the gateway) with it. Treating it as "no
                        // deadline known" is the honest degradation: the
                        // alternative, refusing to apply policy at all, is
                        // strictly worse than one early generation flip.
                        Err(e) => {
                            eprintln!(
                                "wiremesh-gateway: policy-apply deadline query failed: {e}; \
                                 applying without waiting out a reap grace"
                            );
                            None
                        }
                    }
                };

                // (3) Wait it out asynchronously — the whole point: the
                // runtime thread stays free for the Punch arm, the metrics
                // scrape and everything else.
                if let Some(t) = deadline {
                    tokio::time::sleep_until(tokio::time::Instant::from_std(t)).await;
                }

                // (4) Re-read the mailbox: a state published DURING the wait
                // supersedes the one we were waiting for. This is what keeps
                // a burst of epochs at ONE grace period instead of N.
                match rx.has_changed() {
                    Ok(true) => {
                        if let Some(newer) = rx.borrow_and_update().clone() {
                            ds = newer;
                            // Re-run the deadline query for the state we
                            // actually intend to install rather than reusing
                            // a reading taken for a superseded one.
                            continue;
                        }
                    }
                    Ok(false) => {}
                    // Every handle is gone: nobody is left to care whether
                    // this state lands, and retrying it forever would leak
                    // the task.
                    Err(_) => return,
                }

                // (5) Install on the blocking pool — map creation, LPM
                // writes and (nft backend) an `nft -f -` fork/exec are real
                // blocking work, and this is the other half of the stall the
                // inline apply used to inflict on the Sync loop.
                let res = {
                    let target = target.clone();
                    let ds = ds.clone();
                    tokio::task::spawn_blocking(move || target.install(&ds)).await
                };
                match res {
                    Ok(Ok(())) => break,
                    // (6) Logged, counted, retried — never fatal, never
                    // wedged. The retry re-enters this loop, so a corrected
                    // policy published while a bad one is failing is picked
                    // up on the next attempt instead of grinding forever on
                    // the state the backend rejects.
                    Ok(Err(e)) => {
                        failures.fetch_add(1, Ordering::Relaxed);
                        eprintln!(
                            "wiremesh-gateway: policy apply failed (policy version {}): {e:#}; \
                             retrying in {retry_after:?} — datapath keeps the last good policy",
                            ds.policy_version
                        );
                    }
                    Err(e) => {
                        failures.fetch_add(1, Ordering::Relaxed);
                        eprintln!(
                            "wiremesh-gateway: policy apply task panicked (policy version {}): \
                             {e}; retrying in {retry_after:?}",
                            ds.policy_version
                        );
                    }
                }
                tokio::time::sleep(retry_after).await;
            }
        }
    });

    handle
}
