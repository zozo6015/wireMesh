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

/// Ceiling on the retry backoff. A permanently un-appliable policy (an
/// unconsumable IR, an empty-CIDR segment the nft backend rejects) would
/// otherwise emit a log line every `retry_after` forever — 12/min at the
/// production 5s, ~17k/day. The alertable signal is
/// `wiremesh_gateway_policy_apply_failures_total`, which keeps counting at
/// full rate; the log only has to stay diagnosable.
pub const RETRY_BACKOFF_MAX: Duration = Duration::from_secs(60);

/// Everything the worker needs from the live enforcer map. `main.rs`
/// implements it with a thin adapter over
/// `Arc<tokio::sync::Mutex<HashMap<u32, GatewayEnforcer>>>`; tests implement
/// it with a fake.
pub trait PolicyApplyTarget: Send + Sync + 'static {
    /// The latest instant at which every enforcer that installing `ds` would
    /// actually WRITE will accept that write — the `max` over the
    /// `GatewayEnforcer::apply_ready_at()` of those entries only. `None` = no
    /// constraint; a `Some` in the past is already satisfied.
    ///
    /// **`ds` is a parameter, not an oversight.** The install is version-
    /// gated per enforcer, so an entry already on `ds.policy_version` will
    /// not be touched and its deadline must not gate anything. Without this,
    /// a rotation overlap's freshly-created enforcer (whose first apply just
    /// armed a full grace) would delay a security-relevant TIGHTENING to a
    /// boot tun that is already clear to take it.
    ///
    /// Returning a plain `Option<Instant>` (rather than any kind of guard)
    /// is the load-bearing part of this seam: the real adapter takes the
    /// enforcer-map lock, reads the deadlines and drops the lock before
    /// returning, and the signature makes holding that lock across the
    /// worker's wait structurally impossible.
    fn ready_at(&self, ds: &DesiredState) -> Option<Instant>;

    /// Perform the (now fast) install: re-lock the enforcer map and
    /// `apply_if_changed(ds)` every live entry. BLOCKING by contract — the
    /// worker always calls it inside `tokio::task::spawn_blocking`, so the
    /// real adapter is free to use `Mutex::blocking_lock()`.
    ///
    /// The deadline [`PolicyApplyTarget::ready_at`] published was read
    /// BEFORE the lock was dropped and re-taken, so the set of enforcers can
    /// have grown in between (a rotation insert). An implementation must
    /// therefore re-check each entry's own deadline under the lock and
    /// refuse — with an `Err`, so the worker's retry picks it up — rather
    /// than write an entry whose grace it never consulted.
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
    /// guarantee this item exists to deliver, so keep it. `send_if_modified`
    /// (rather than `send`, which reports `Err` when the receiver is gone —
    /// a Sync loop that has to think about the worker's liveness is back to
    /// having an apply it can trip over).
    ///
    /// **A byte-identical re-publish is dropped**, and that is load-bearing,
    /// not an optimization. The controller sends a full `StateSnapshot` as
    /// the first message of EVERY Watch stream, so each Sync reconnect
    /// re-delivers the current desired state verbatim. Without this, a
    /// flapping link would start a fresh retry episode on every reconnect —
    /// resetting the backoff to its floor and re-emitting the failure log —
    /// which defeats [`RETRY_BACKOFF_MAX`]'s flood protection for exactly
    /// the wedged-policy case it exists for. Dropping it loses nothing: the
    /// worker either already installed this state (`apply_if_changed` would
    /// no-op) or is still retrying it in its own loop.
    ///
    /// Residual: a snapshot that differs only in a NON-policy field (a
    /// candidate endpoint that churned) is still a change and still resets
    /// the backoff. Bounding that would mean keeping failure state per
    /// policy version rather than per episode — a bigger change than this
    /// item, and the resulting install succeeds immediately anyway when the
    /// policy version is unchanged and already applied.
    pub fn publish(&self, ds: DesiredState) {
        self.tx.send_if_modified(|current| {
            if current.as_ref() == Some(&ds) {
                return false;
            }
            *current = Some(ds);
            true
        });
    }

    /// Installs that returned `Err` since boot; the source of the
    /// `wiremesh_gateway_policy_apply_failures_total` counter.
    pub fn failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }
}

/// How an interruptible retry pause ended. See [`pause_or_wake`].
enum Pause {
    /// The pause ran to completion; retry the same desired state.
    Elapsed,
    /// A newer desired state was published during the pause; it supersedes
    /// whatever we were retrying, and the retry cadence starts over.
    Adopted(DesiredState),
    /// A `None` was published — unreachable today (`publish` only ever sends
    /// `Some`); go back to waiting for a real state.
    Empty,
    /// Every handle is gone; the worker should exit.
    Closed,
}

/// Wait out `backoff`, but wake IMMEDIATELY if a new desired state arrives.
///
/// This is the operator's outage-response path: a wedged policy has driven
/// the backoff up (toward [`RETRY_BACKOFF_MAX`]), the operator pushes a
/// corrected one, and it must not sit out the remainder of a pause that the
/// BAD policy earned. A plain `sleep` made the corrected state's very first
/// attempt up to a full `RETRY_BACKOFF_MAX` late, with no feedback, right
/// after the operator watched the gateway reject the previous version.
///
/// `biased` so the mailbox arm is polled first: when both are ready the
/// change wins. Nothing can be lost either way — `watch` tracks changes with
/// a version counter, not with the `changed()` future, so a `changed()`
/// dropped by the timer arm leaves the flag set for the caller's next read.
async fn pause_or_wake(
    rx: &mut watch::Receiver<Option<DesiredState>>,
    backoff: Duration,
) -> Pause {
    tokio::select! {
        biased;
        r = rx.changed() => {
            if r.is_err() {
                return Pause::Closed;
            }
            match rx.borrow_and_update().clone() {
                Some(newer) => Pause::Adopted(newer),
                None => Pause::Empty,
            }
        }
        _ = tokio::time::sleep(backoff) => Pause::Elapsed,
    }
}

/// Spawn the policy-apply worker onto the current runtime and return its
/// mailbox handle. The task exits once the last [`PolicyApplyHandle`] is
/// dropped.
///
/// `retry_after` is the pause before the FIRST re-attempt at a state whose
/// install failed; consecutive failures double it up to
/// [`RETRY_BACKOFF_MAX`]. Failures are logged and counted, never propagated:
/// a policy the backend cannot consume must degrade to "the datapath keeps
/// the last good policy and the gateway keeps running", not to a dead
/// process — and not to a log flood either, which is why the backoff exists
/// (the counter, not the log line, is the alertable signal).
///
/// **A newly published state never waits out a backoff it did not earn.**
/// The retry pause is interruptible ([`pause_or_wake`]): a publish during it
/// wakes the worker at once, the new state is adopted there and then, and
/// the deadline query at step (2) is re-run for THAT state rather than the
/// superseded one. The remaining latency before its first install attempt is
/// therefore exactly: one `spawn_blocking` round trip for the deadline read,
/// plus any genuine reap grace still outstanding (up to the backend's 10s) if
/// a partially-applied previous attempt flipped a generation. That grace is
/// the safety property, not backoff — it cannot be skipped, and in the common
/// wedge case (a policy rejected by `check_lpm_capacity` or the IR decoder,
/// which fails BEFORE any flip) there is no grace outstanding and the
/// attempt is immediate.
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
            // Per-episode, so a state that lands first try never inherits a
            // previous state's punishment.
            let mut backoff = retry_after;

            loop {
                // (2) Read the deadline for THIS desired state and let go of
                // whatever it touched.
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
                    let probe = ds.clone();
                    match tokio::task::spawn_blocking(move || target.ready_at(&probe)).await {
                        Ok(d) => d,
                        // EXPLICIT CHOICE: a `ready_at` that panics is
                        // treated as a failed attempt, NOT as "no deadline,
                        // apply now". Applying without a deadline reading is
                        // the one thing in this whole design that can
                        // deliberately violate the reap grace — overwriting
                        // maps in-flight packets may still be reading — and
                        // "the datapath keeps the last good policy" is the
                        // strictly safer degradation, consistent with every
                        // other failure here. It also cannot wedge in
                        // practice: both backends' `apply_ready_at` is a
                        // total `Option::map`/`None`, so the realistic cause
                        // is runtime shutdown, where the task is going away
                        // anyway.
                        Err(e) => {
                            failures.fetch_add(1, Ordering::Relaxed);
                            eprintln!(
                                "wiremesh-gateway: policy-apply deadline query failed (policy \
                                 version {}): {e}; NOT applying without a reap-grace reading, \
                                 retrying in {backoff:?} (or sooner if a new policy arrives)",
                                ds.policy_version
                            );
                            match pause_or_wake(&mut rx, backoff).await {
                                Pause::Elapsed => {
                                    backoff = backoff.saturating_mul(2).min(RETRY_BACKOFF_MAX);
                                }
                                Pause::Adopted(newer) => {
                                    ds = newer;
                                    backoff = retry_after;
                                }
                                Pause::Empty => break,
                                Pause::Closed => return,
                            }
                            continue;
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
                //
                // No starvation bound, deliberately. Re-adopting loops back
                // to (2), and the deadline it re-reads can only move forward
                // when WE flip a generation — which cannot happen while we
                // are still waiting to install. So every iteration after the
                // first has an already-satisfied deadline and costs one
                // `spawn_blocking` round trip; starving the install would
                // require a publisher that beats that loop forever, which a
                // Watch stream (one message per controller reconcile) cannot
                // do. Force-installing after N supersessions would trade
                // this impossibility for the certainty of installing a state
                // we already know is stale.
                match rx.has_changed() {
                    Ok(true) => {
                        match rx.borrow_and_update().clone() {
                            Some(newer) => {
                                ds = newer;
                                // A fresh state deserves a fresh first
                                // attempt, not the previous one's backoff.
                                backoff = retry_after;
                                continue;
                            }
                            // Unreachable today (`publish` only ever sends
                            // `Some`), but falling through here would install
                            // the state we just learned was superseded. Wait
                            // for the next real publish instead.
                            None => break,
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
                    // wedged. The pause below is interruptible, so a
                    // corrected policy published while a bad one is failing
                    // is adopted the moment it arrives rather than after the
                    // wedged state's grown backoff.
                    Ok(Err(e)) => {
                        failures.fetch_add(1, Ordering::Relaxed);
                        eprintln!(
                            "wiremesh-gateway: policy apply failed (policy version {}): {e:#}; \
                             retrying in {backoff:?} (or sooner if a new policy arrives) — \
                             datapath keeps the last good policy",
                            ds.policy_version
                        );
                    }
                    Err(e) => {
                        failures.fetch_add(1, Ordering::Relaxed);
                        eprintln!(
                            "wiremesh-gateway: policy apply task panicked (policy version {}): \
                             {e}; retrying in {backoff:?} (or sooner if a new policy arrives)",
                            ds.policy_version
                        );
                    }
                }
                match pause_or_wake(&mut rx, backoff).await {
                    Pause::Elapsed => backoff = backoff.saturating_mul(2).min(RETRY_BACKOFF_MAX),
                    // Adopted HERE rather than falling through to step (4):
                    // looping back with the superseded `ds` would query the
                    // deadline — and possibly sleep on it — for a state we
                    // already know is dead, which would give back most of
                    // what waking early just bought.
                    Pause::Adopted(newer) => {
                        ds = newer;
                        backoff = retry_after;
                    }
                    Pause::Empty => break,
                    Pause::Closed => return,
                }
            }
        }
    });

    handle
}
