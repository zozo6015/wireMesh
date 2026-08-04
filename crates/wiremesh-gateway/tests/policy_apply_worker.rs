//! Backlog item 1 (Cycle-3 hardening PR-B — policy-apply worker restructure),
//! gateway half: the policy apply must move OFF the Sync loop into a
//! latest-wins worker that waits out the enforcer's reap deadline without
//! occupying a runtime thread, and whose failures are logged/counted/retried
//! instead of killing the process.
//!
//! PURE — no netns, no privileges, no root, no eBPF, no sockets. Every test
//! here drives the worker against an in-test fake enforcer target:
//!
//! ```text
//! ./dev.sh run "cargo test -p wiremesh-gateway --test policy_apply_worker \
//!   -- --nocapture"
//! ```
//!
//! (It also passes on a plain `cargo test` on the host — it is deliberately
//! the one part of this item that does not need the busy dev container.)
//!
//! ## The bug this pins away (verified on main)
//!
//! `main.rs`'s Sync loop applies desired state INLINE:
//!
//! ```ignore
//! Ok(Some(sync::SyncEvent::State(ds))) => {
//!     ...
//!     apply_state(&enforcers, applied.as_ref(), &ds, ...).await?;   // ~main.rs:647
//! ```
//!
//! and `apply_state` does, holding the enforcer-map lock (~main.rs:3030):
//!
//! ```ignore
//! let mut map = enforcers.lock().await;
//! for e in map.values_mut() { e.apply_if_changed(ds)?; }
//! ```
//!
//! Each `apply_if_changed` reaches `ebpf::apply_generation`, which
//! `std::thread::sleep`s out the remainder of the previous flip's 10s reap
//! grace (see `crates/wiremesh-enforcer/tests/reap_deadline.rs` for the
//! enforcer half). Consequences, all in one place:
//!
//!  - **the Sync loop is dead for ~10s per epoch** — the SAME `tokio::select!`
//!    loop consumes `SyncEvent::Punch`, so a controller-brokered
//!    `PunchDirective` is delayed past the Cycle-4b go-skew budget (Phase-0
//!    Finding 2), and so are rotation events;
//!  - **N live epochs cost N × 10s** (rotation overlap applies policy to
//!    every live tun);
//!  - **the enforcer-map lock is held throughout**, so the metrics scrape
//!    (~main.rs:424), retire (~3075), Role-B collapse (~3133) and rotation
//!    insert (~3363/3467) all stall behind it;
//!  - **any apply error is process-fatal** — the `?` on `apply_state(...).await?`
//!    exits the Sync loop and the gateway with it. (`docs/research/backlog-program-notes.md`
//!    §B9 records the same `?` crashing gateways on an unconsumable IR schema,
//!    and §B10 records an empty-CIDR segment doing it via the nft backend.)
//!
//! ## The ratified design pinned here (the seam the implementer must add)
//!
//! A NEW library module `wiremesh_gateway::policy_apply` — library, not
//! `main.rs`, precisely so these properties are testable at all (see
//! "What this file cannot pin" below):
//!
//! ```ignore
//! /// Everything the worker needs from the live enforcer map. `main.rs`
//! /// implements it with a thin adapter over
//! /// `Arc<tokio::sync::Mutex<HashMap<u32, GatewayEnforcer>>>`; tests
//! /// implement it with a fake.
//! pub trait PolicyApplyTarget: Send + Sync + 'static {
//!     /// Cheap and NON-BLOCKING: the latest instant at which every live
//!     /// enforcer will accept the next apply — `max` over each entry's
//!     /// `GatewayEnforcer::apply_ready_at()` (which forwards
//!     /// `Enforcer::apply_ready_at`). `None` = no constraint.
//!     ///
//!     /// The real adapter takes the enforcer-map lock, reads the deadlines,
//!     /// and DROPS the lock before returning — returning a plain
//!     /// `Option<Instant>` (not a guard) is what structurally forbids
//!     /// holding the map lock across the worker's wait.
//!     fn ready_at(&self) -> Option<std::time::Instant>;
//!
//!     /// Perform the (now fast) install: re-lock the enforcer map and
//!     /// `apply_if_changed(ds)` every live entry. BLOCKING by contract —
//!     /// the worker always calls it inside `tokio::task::spawn_blocking`,
//!     /// so the real adapter uses `Mutex::blocking_lock()`.
//!     fn install(&self, ds: &DesiredState) -> anyhow::Result<()>;
//! }
//!
//! /// Latest-wins mailbox handle. Cheap to clone (the Sync loop publishes
//! /// through it; the metrics task reads `failures()`).
//! #[derive(Clone)]
//! pub struct PolicyApplyHandle { /* watch::Sender + Arc<AtomicU64> */ }
//!
//! impl PolicyApplyHandle {
//!     /// Hand `ds` to the worker. NOT `async`, never blocks, never fails —
//!     /// this is what replaces `apply_state(...).await?` in the Sync loop,
//!     /// and its non-async signature is itself the structural guarantee
//!     /// that the loop can no longer stall on an apply.
//!     pub fn publish(&self, ds: DesiredState);
//!     /// Installs that returned `Err`; source of the
//!     /// `wiremesh_gateway_policy_apply_failures_total` metric.
//!     pub fn failures(&self) -> u64;
//! }
//!
//! /// Spawn the worker onto the current runtime. Drops out when the last
//! /// handle is dropped.
//! pub fn spawn_policy_apply_worker<T: PolicyApplyTarget>(
//!     target: std::sync::Arc<T>,
//!     retry_after: std::time::Duration,
//! ) -> PolicyApplyHandle;
//! ```
//!
//! plus, in `wiremesh_gateway::metrics` (alongside the existing
//! `render_path_state`/`render_path_transitions`/`render_peer_stats`
//! family):
//!
//! ```ignore
//! pub fn render_policy_apply_failures(total: u64) -> String;
//! ```
//!
//! Worker loop shape the tests below pin, in order:
//! **(1)** wait for a published state; **(2)** call `ready_at()` and DROP
//! whatever it touched; **(3)** `tokio::time::sleep_until` the deadline;
//! **(4)** re-read the mailbox — a state published during the wait
//! SUPERSEDES the one we were waiting for (this is what keeps a burst of
//! epochs at ONE grace period instead of N); **(5)** `spawn_blocking` the
//! install; **(6)** on `Err`, log + count + sleep `retry_after` + retry, and
//! keep serving.
//!
//! ## What this file cannot pin (read the call sites, not just this suite)
//!
//! That `main.rs` actually USES the worker — i.e. that the Sync loop's
//! `State` arm became a `handle.publish(ds)` with no `.await?` on an apply —
//! is not observable from any integration test, because `main.rs` is the
//! binary and no test can import it. Same caution as
//! `tests/apply_make_before_break.rs`'s: a worker that exists but is not
//! wired IS the bug. That wiring is covered end-to-end by
//! `tests/policy_apply_liveness.rs` (netns, real gateway process) and must
//! also be checked by review.
//!
//! ## RED status
//!
//! COMPILE-red until `wiremesh_gateway::policy_apply` and
//! `metrics::render_policy_apply_failures` land — the names and signatures
//! above ARE the pinned API.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use wiremesh_gateway::policy_apply::{spawn_policy_apply_worker, PolicyApplyTarget};
use wiremesh_gateway::state::DesiredState;

/// Short enough that the failure tests finish quickly, long enough that a
/// retry loop cannot be mistaken for a hot spin.
const RETRY_AFTER: Duration = Duration::from_millis(50);

/// The "is anything else able to run?" budget for the two current-thread
/// responsiveness tests. Chosen ~3x looser than any plausible scheduling
/// hiccup on a loaded container, and ~40x tighter than the 10s stall the old
/// structure produced — the discrimination is an order of magnitude, not a
/// hair.
const RESPONSIVE_WITHIN: Duration = Duration::from_millis(250);

/// The artificial grace/blocking duration the responsiveness tests use in
/// place of the production 10s, so the suite stays fast while keeping the
/// same shape.
const SLOW: Duration = Duration::from_millis(800);

fn ds(version: u64) -> DesiredState {
    DesiredState { revision: version, policy_version: version, ..Default::default() }
}

/// One recorded `install` call.
#[derive(Debug, Clone, Copy)]
struct Install {
    version: u64,
    started_at: Instant,
    ok: bool,
}

/// In-test stand-in for the live enforcer map. Records every `install`,
/// signals every `ready_at`/install-start/install-finish so tests can
/// synchronize on the worker's progress instead of sleeping and hoping, and
/// can be told to stall or fail.
struct FakeTarget {
    ready_at: Mutex<Option<Instant>>,
    installs: Mutex<Vec<Install>>,
    /// Signalled once per `ready_at()` call — the observation point that
    /// tells a test "the worker has picked the state up and is about to
    /// wait", making the during-the-wait tests deterministic.
    ready_calls: UnboundedSender<()>,
    /// Signalled when an `install` starts, and again (with its outcome) when
    /// it returns.
    install_started: UnboundedSender<u64>,
    install_done: UnboundedSender<(u64, bool)>,
    /// If set, `install` parks its (blocking-pool) thread this long. Models
    /// the real install's kernel work.
    block_for: Mutex<Option<Duration>>,
    /// If set, `install` waits for a send on this channel before returning —
    /// lets a test hold an install open while it publishes more states.
    gate: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    /// Number of upcoming installs that must return `Err`. `u64::MAX` = fail
    /// until told otherwise.
    fail_next: AtomicU64,
}

impl FakeTarget {
    fn new() -> (Arc<FakeTarget>, Signals) {
        let (ready_calls, ready_rx) = unbounded_channel();
        let (install_started, started_rx) = unbounded_channel();
        let (install_done, done_rx) = unbounded_channel();
        let t = Arc::new(FakeTarget {
            ready_at: Mutex::new(None),
            installs: Mutex::new(Vec::new()),
            ready_calls,
            install_started,
            install_done,
            block_for: Mutex::new(None),
            gate: Mutex::new(None),
            fail_next: AtomicU64::new(0),
        });
        (t, Signals { ready_rx, started_rx, done_rx })
    }

    fn set_ready_at(&self, t: Option<Instant>) {
        *self.ready_at.lock().unwrap() = t;
    }

    fn set_block_for(&self, d: Duration) {
        *self.block_for.lock().unwrap() = Some(d);
    }

    /// The next install blocks until `send(())` on the returned sender.
    fn gate_next(&self) -> std::sync::mpsc::Sender<()> {
        let (tx, rx) = std::sync::mpsc::channel();
        *self.gate.lock().unwrap() = Some(rx);
        tx
    }

    fn fail_next(&self, n: u64) {
        self.fail_next.store(n, Ordering::SeqCst);
    }

    fn stop_failing(&self) {
        self.fail_next.store(0, Ordering::SeqCst);
    }

    fn installs(&self) -> Vec<Install> {
        self.installs.lock().unwrap().clone()
    }

    fn installed_versions(&self) -> Vec<u64> {
        self.installs().iter().map(|i| i.version).collect()
    }

    fn ok_versions(&self) -> Vec<u64> {
        self.installs().iter().filter(|i| i.ok).map(|i| i.version).collect()
    }
}

impl PolicyApplyTarget for FakeTarget {
    fn ready_at(&self) -> Option<Instant> {
        let t = *self.ready_at.lock().unwrap();
        // Send AFTER reading, so a test woken by this signal is guaranteed
        // the worker has already taken the value it will wait on.
        let _ = self.ready_calls.send(());
        t
    }

    fn install(&self, ds: &DesiredState) -> anyhow::Result<()> {
        let version = ds.policy_version;
        let started_at = Instant::now();
        let _ = self.install_started.send(version);

        // Both guards are released BEFORE the stall they configure — an
        // `if let Some(..) = self.x.lock()...` would hold the mutex across
        // the sleep/recv, which is exactly the shape this whole item is
        // about not doing.
        let block = *self.block_for.lock().unwrap();
        if let Some(d) = block {
            std::thread::sleep(d);
        }
        let gate = self.gate.lock().unwrap().take();
        if let Some(rx) = gate {
            let _ = rx.recv();
        }

        let remaining = self.fail_next.load(Ordering::SeqCst);
        let ok = remaining == 0;
        if !ok && remaining != u64::MAX {
            self.fail_next.store(remaining - 1, Ordering::SeqCst);
        }

        self.installs.lock().unwrap().push(Install { version, started_at, ok });
        let _ = self.install_done.send((version, ok));

        if ok {
            Ok(())
        } else {
            Err(anyhow::anyhow!("fake install failure for policy version {version}"))
        }
    }
}

/// The three progress channels a test synchronizes on.
struct Signals {
    ready_rx: UnboundedReceiver<()>,
    started_rx: UnboundedReceiver<u64>,
    done_rx: UnboundedReceiver<(u64, bool)>,
}

async fn recv_within<T>(rx: &mut UnboundedReceiver<T>, d: Duration, what: &str) -> T {
    match tokio::time::timeout(d, rx.recv()).await {
        Ok(Some(v)) => v,
        Ok(None) => panic!("channel closed while waiting for {what} (worker exited?)"),
        Err(_) => panic!("timed out after {d:?} waiting for {what}"),
    }
}

/// Asserts nothing further arrives for `d` — used to pin that a SKIPPED
/// intermediate state really was skipped, not merely late.
async fn assert_quiet<T: std::fmt::Debug>(rx: &mut UnboundedReceiver<T>, d: Duration, what: &str) {
    if let Ok(Some(v)) = tokio::time::timeout(d, rx.recv()).await {
        panic!("expected no further {what} within {d:?}, but got {v:?}");
    }
}

// --- baseline -------------------------------------------------------------

/// Smoke: with no reap constraint, a published state is installed promptly
/// and exactly once. Everything below builds on this.
#[tokio::test]
async fn a_published_state_is_installed() {
    let (target, mut sig) = FakeTarget::new();
    let handle = spawn_policy_apply_worker(target.clone(), RETRY_AFTER);

    handle.publish(ds(7));

    let (v, ok) = recv_within(&mut sig.done_rx, Duration::from_secs(5), "the install").await;
    assert_eq!((v, ok), (7, true));
    assert_eq!(target.installed_versions(), vec![7]);
    assert_eq!(handle.failures(), 0, "a successful install must not count as a failure");
}

// --- (C) latest-wins ------------------------------------------------------

/// Several states published while an install is IN FLIGHT collapse to the
/// newest: the worker installs v1 (already committed when the burst starts)
/// and then jumps straight to v4. v2 and v3 being skipped is CORRECT — the
/// enforcer is idempotent per policy version and only the newest desired
/// state is worth the next generation flip (and, in production, the next
/// 10s grace).
///
/// Sabotage that must turn this red: replace the `watch` mailbox with any
/// queue that preserves every message (`mpsc`, `VecDeque`) — the recorded
/// versions become `[1, 2, 3, 4]`.
#[tokio::test]
async fn a_burst_published_during_an_install_collapses_to_the_newest() {
    let (target, mut sig) = FakeTarget::new();
    let release = target.gate_next();
    let handle = spawn_policy_apply_worker(target.clone(), RETRY_AFTER);

    handle.publish(ds(1));
    let started = recv_within(&mut sig.started_rx, Duration::from_secs(5), "install #1 to start").await;
    assert_eq!(started, 1, "the first published state must be the first installed");

    // The Sync loop keeps receiving snapshots while the install runs.
    handle.publish(ds(2));
    handle.publish(ds(3));
    handle.publish(ds(4));

    release.send(()).expect("release the gated install");
    let (v1, _) = recv_within(&mut sig.done_rx, Duration::from_secs(5), "install #1 to finish").await;
    assert_eq!(v1, 1);

    let (v2, ok) = recv_within(&mut sig.done_rx, Duration::from_secs(5), "the follow-up install").await;
    assert_eq!(
        (v2, ok),
        (4, true),
        "the follow-up install must be the NEWEST published state, not the oldest \
         un-installed one — intermediate states are superseded, not queued"
    );

    assert_quiet(&mut sig.done_rx, Duration::from_millis(500), "installs").await;
    assert_eq!(
        target.installed_versions(),
        vec![1, 4],
        "exactly two installs: the one already in flight, then the newest"
    );
}

/// A state published while the worker is WAITING OUT the reap deadline
/// supersedes the one it was waiting for. This is the property that keeps a
/// burst of policy epochs at ONE grace period instead of N — without it, a
/// three-epoch burst costs 30s of datapath staleness in production.
///
/// Determinism: the test does not publish v2 until the fake's `ready_at()`
/// has been called, which is the exact moment the worker has committed to
/// waiting.
///
/// Sabotage that must turn this red: capture the desired state BEFORE the
/// `sleep_until` and install that captured value afterwards without
/// re-reading the mailbox — recorded versions become `[1, 2]`.
#[tokio::test]
async fn a_state_published_during_the_grace_wait_supersedes_the_waiting_one() {
    let (target, mut sig) = FakeTarget::new();
    target.set_ready_at(Some(Instant::now() + SLOW));
    let handle = spawn_policy_apply_worker(target.clone(), RETRY_AFTER);

    handle.publish(ds(1));
    recv_within(&mut sig.ready_rx, Duration::from_secs(5), "the worker's deadline query").await;

    // The worker is now parked on the deadline. A fresher snapshot arrives.
    handle.publish(ds(2));

    let (v, ok) = recv_within(&mut sig.done_rx, Duration::from_secs(5), "the install").await;
    assert_eq!(
        (v, ok),
        (2, true),
        "the state published DURING the wait must be the one installed — v1 was \
         superseded before it ever reached the enforcer"
    );
    assert_quiet(&mut sig.done_rx, Duration::from_millis(500), "installs").await;
    assert_eq!(
        target.installed_versions(),
        vec![2],
        "v1 must never be installed: installing it first would cost a SECOND full reap \
         grace before v2 could land"
    );
}

// --- (A, caller side) + (F, essence) the deadline is honored --------------

/// The worker must not touch the enforcer map until the reap deadline the
/// backend published has passed. This is the caller-side half of the safety
/// property `crates/wiremesh-enforcer/tests/reap_deadline.rs` pins on the
/// backend side: the grace did not disappear, it moved.
///
/// It is also the honest, falsifiable form of "the enforcer-map lock is not
/// held across the grace wait": under this seam the worker cannot even
/// ACQUIRE the lock before the deadline, because `install` (the only method
/// that takes it) has not been called. The complementary "someone else can
/// take the lock meanwhile" assertion needs the real adapter and lives in
/// `tests/policy_apply_liveness.rs`.
///
/// Sabotage that must turn this red: drop the `sleep_until` (install starts
/// immediately), or clamp/ignore the deadline.
#[tokio::test]
async fn the_worker_does_not_touch_the_enforcers_before_the_deadline() {
    let (target, mut sig) = FakeTarget::new();
    let deadline = Instant::now() + SLOW;
    target.set_ready_at(Some(deadline));
    let handle = spawn_policy_apply_worker(target.clone(), RETRY_AFTER);

    handle.publish(ds(1));
    recv_within(&mut sig.done_rx, Duration::from_secs(5), "the install").await;

    let install = target.installs()[0];
    assert!(
        install.started_at >= deadline,
        "the install started {:?} BEFORE the published reap deadline — that is exactly \
         the overwrite of a still-readable outer-array slot the grace exists to prevent",
        deadline.saturating_duration_since(install.started_at)
    );
    assert!(
        install.started_at < deadline + Duration::from_secs(1),
        "the install must start promptly once the deadline passes, not a grace period \
         later; it started {:?} after the deadline",
        install.started_at.saturating_duration_since(deadline)
    );
}

/// A deadline already in the past is a SATISFIED constraint (the shape the
/// eBPF backend keeps publishing after its grace elapses — see
/// `reap_deadline.rs`'s lapse test): the worker must install immediately, not
/// round it up to a fresh grace period.
#[tokio::test]
async fn a_satisfied_deadline_does_not_delay_the_install() {
    let (target, mut sig) = FakeTarget::new();
    // Captured before a real sleep, so it is genuinely in the past without
    // doing `Instant::now() - d` (which can underflow early in a process).
    let past = Instant::now();
    tokio::time::sleep(Duration::from_millis(50)).await;
    target.set_ready_at(Some(past));
    let handle = spawn_policy_apply_worker(target.clone(), RETRY_AFTER);

    let published_at = Instant::now();
    handle.publish(ds(1));
    recv_within(&mut sig.done_rx, Duration::from_secs(5), "the install").await;

    let started = target.installs()[0].started_at;
    assert!(
        started.saturating_duration_since(published_at) < RESPONSIVE_WITHIN,
        "a deadline in the past must not delay the install; it waited {:?}",
        started.saturating_duration_since(published_at)
    );
}

// --- (D) the Sync loop keeps running while an apply is in flight ----------

/// **The headline property, structurally.** A `current_thread` runtime is the
/// harness: there is exactly ONE runtime thread, so any task that parks it
/// starves every other task — which is precisely what the old inline apply
/// did to the `SyncEvent::Punch` arm (same `tokio::select!` loop, same
/// thread) for ~10s per epoch.
///
/// The spawned task here STANDS IN for the Punch arm: it must be scheduled
/// within milliseconds of the publish, while the worker is still waiting out
/// its (artificially 800ms) reap deadline.
///
/// Sabotage that must turn this red: wait for the deadline with
/// `std::thread::sleep` instead of `tokio::time::sleep_until` — the stand-in
/// task is not scheduled until the full deadline has passed. (The original
/// bug is exactly this sleep, one call frame deeper.)
#[tokio::test(flavor = "current_thread")]
async fn a_concurrent_task_is_serviced_while_an_apply_waits_out_its_deadline() {
    let (target, mut sig) = FakeTarget::new();
    let deadline = Instant::now() + SLOW;
    target.set_ready_at(Some(deadline));
    let handle = spawn_policy_apply_worker(target.clone(), RETRY_AFTER);

    let published_at = Instant::now();
    handle.publish(ds(1));

    // Stand-in for the Sync loop's Punch arm: spawned immediately after the
    // publish, records when it actually got to run.
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = tx.send(Instant::now());
    });

    let ran_at = tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .expect("the stand-in punch task must be scheduled at all")
        .expect("stand-in punch task dropped");
    let latency = ran_at.saturating_duration_since(published_at);
    assert!(
        latency < RESPONSIVE_WITHIN,
        "a concurrent task waited {latency:?} to be scheduled while a policy apply was \
         pending its reap deadline (budget {RESPONSIVE_WITHIN:?}). In production this \
         task is the PunchDirective arm and the deadline is 10s — that is the Cycle-4b \
         go-skew violation this item exists to remove."
    );

    // And the apply itself still happened, after its deadline.
    recv_within(&mut sig.done_rx, Duration::from_secs(5), "the install").await;
    assert!(
        target.installs()[0].started_at >= deadline,
        "sanity: the deadline was genuinely still pending while the stand-in ran, so \
         the assertion above was not vacuous"
    );
}

/// Same harness, the other half of the stall: the INSTALL itself is
/// blocking work (map creation, LPM writes, an `nft -f -` fork/exec) and must
/// run on the blocking pool, not on the runtime.
///
/// Sabotage that must turn this red: call `target.install(...)` directly from
/// the worker's async task instead of inside `tokio::task::spawn_blocking`.
#[tokio::test(flavor = "current_thread")]
async fn a_concurrent_task_is_serviced_while_the_install_itself_runs() {
    let (target, mut sig) = FakeTarget::new();
    target.set_block_for(SLOW); // the install parks ITS thread for 800ms
    let handle = spawn_policy_apply_worker(target.clone(), RETRY_AFTER);

    let published_at = Instant::now();
    handle.publish(ds(1));

    // Wait until the install has genuinely started, so the stand-in task is
    // spawned INSIDE the blocking window rather than before it.
    recv_within(&mut sig.started_rx, Duration::from_secs(5), "the install to start").await;

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let _ = tx.send(Instant::now());
    });

    let ran_at = tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .expect("the stand-in punch task must be scheduled at all")
        .expect("stand-in punch task dropped");
    let latency = ran_at.saturating_duration_since(published_at);
    assert!(
        latency < RESPONSIVE_WITHIN,
        "a concurrent task waited {latency:?} (budget {RESPONSIVE_WITHIN:?}) — i.e. it \
         was blocked behind the {SLOW:?} install. The install must run inside \
         `spawn_blocking` so the runtime thread stays free for the Sync loop."
    );

    recv_within(&mut sig.done_rx, Duration::from_secs(5), "the install").await;
}

/// Publishing is what the Sync loop now does INSTEAD of applying, so it must
/// cost nothing even while an install is in flight and further states are
/// piling up. (The stronger, compile-level half of this guarantee is that
/// `publish` is not `async` and returns `()`: the Sync loop has no `.await`
/// and no `?` to stall or die on.)
#[tokio::test]
async fn publishing_never_blocks_the_sync_loop() {
    let (target, mut sig) = FakeTarget::new();
    let release = target.gate_next();
    let handle = spawn_policy_apply_worker(target.clone(), RETRY_AFTER);

    handle.publish(ds(1));
    recv_within(&mut sig.started_rx, Duration::from_secs(5), "install #1 to start").await;

    let t0 = Instant::now();
    for v in 2..=6 {
        handle.publish(ds(v));
    }
    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_millis(50),
        "five publishes took {elapsed:?} with an install in flight; publishing must \
         never wait on the worker"
    );

    release.send(()).expect("release the gated install");
    recv_within(&mut sig.done_rx, Duration::from_secs(5), "install #1").await;
    let (v, _) = recv_within(&mut sig.done_rx, Duration::from_secs(5), "the follow-up install").await;
    assert_eq!(v, 6, "and the newest of the burst is what lands");
}

// --- (E) apply errors are non-fatal ---------------------------------------

/// A failing install must be logged, COUNTED, and RETRIED — never fatal.
/// Today the equivalent failure propagates through `apply_state(...).await?`
/// and exits the gateway process (the audit's outage class: a single bad
/// policy IR or an empty-CIDR segment takes the datapath down).
///
/// Sabotage that must turn this red: propagate the install error out of the
/// worker loop (the worker task ends, `done_rx` closes, and `recv_within`
/// panics with "worker exited?"), or drop the failure counter.
#[tokio::test]
async fn install_failures_are_counted_and_retried_and_never_kill_the_worker() {
    let (target, mut sig) = FakeTarget::new();
    target.fail_next(2);
    let handle = spawn_policy_apply_worker(target.clone(), RETRY_AFTER);

    handle.publish(ds(1));

    let a = recv_within(&mut sig.done_rx, Duration::from_secs(5), "install attempt 1").await;
    let b = recv_within(&mut sig.done_rx, Duration::from_secs(5), "install attempt 2 (retry)").await;
    let c = recv_within(&mut sig.done_rx, Duration::from_secs(5), "install attempt 3 (retry)").await;
    assert_eq!(a, (1, false), "attempt 1 fails");
    assert_eq!(b, (1, false), "attempt 2 retries the SAME desired state and fails");
    assert_eq!(c, (1, true), "attempt 3 retries again and succeeds");

    assert_eq!(
        handle.failures(),
        2,
        "both failures must be counted (this counter is the source of \
         `wiremesh_gateway_policy_apply_failures_total`)"
    );
    assert_quiet(&mut sig.done_rx, Duration::from_millis(300), "installs").await;

    // The worker is still alive and still serving: a later state applies.
    handle.publish(ds(2));
    let (v, ok) = recv_within(&mut sig.done_rx, Duration::from_secs(5), "the next install").await;
    assert_eq!((v, ok), (2, true), "the worker must keep serving after a failure");
    assert_eq!(handle.failures(), 2, "a success must not change the failure count");
}

/// A state that can NEVER be installed (an unconsumable IR, a policy the
/// backend rejects) must not wedge the worker either: it retries, and the
/// moment a newer, installable state is published, that one lands. This is
/// the recovery path an operator actually uses — push a corrected policy —
/// and it only works if the worker is both alive and latest-wins.
#[tokio::test]
async fn a_permanently_failing_state_does_not_wedge_the_worker() {
    let (target, mut sig) = FakeTarget::new();
    target.fail_next(u64::MAX);
    let handle = spawn_policy_apply_worker(target.clone(), RETRY_AFTER);

    handle.publish(ds(1));
    for attempt in 1..=3 {
        let (v, ok) =
            recv_within(&mut sig.done_rx, Duration::from_secs(5), "a retry of the bad state").await;
        assert_eq!((v, ok), (1, false), "attempt {attempt} must keep retrying the bad state");
    }
    assert!(handle.failures() >= 3, "every failed attempt is counted");

    // Operator pushes a corrected policy. It is published while the backend
    // is STILL failing, so the first thing to prove is that the retry loop
    // re-reads the mailbox rather than grinding on the wedged state forever:
    // a failed attempt carrying version 2 must appear.
    handle.publish(ds(2));
    loop {
        let (v, ok) =
            recv_within(&mut sig.done_rx, Duration::from_secs(5), "an attempt at the new state")
                .await;
        assert!(!ok, "the backend is still failing, so no attempt may succeed yet");
        if v == 2 {
            break; // the retry loop picked the newer state up — latest-wins holds on retry too
        }
    }

    // Now the backend recovers; the very next attempt must land v2.
    target.stop_failing();
    loop {
        let (v, ok) = recv_within(&mut sig.done_rx, Duration::from_secs(5), "an install").await;
        if ok {
            assert_eq!(v, 2, "the corrected policy is what gets installed");
            break;
        }
    }
    assert_eq!(
        target.ok_versions(),
        vec![2],
        "the wedged state must never have been installed — only the corrected one"
    );
}

// --- (E) the metric ------------------------------------------------------

/// The counter behind the failures above is exposed as a Prometheus counter,
/// rendered by the same pure-renderer family as the rest of
/// `metrics.rs`. That it reaches the actual scrape BODY (the wiring failure
/// mode `serve_metrics_responds_with_rendered_body_over_tcp` was added to
/// guard) is asserted in `tests/policy_apply_liveness.rs`.
#[test]
fn policy_apply_failures_render_as_a_prometheus_counter() {
    let out = wiremesh_gateway::metrics::render_policy_apply_failures(3);
    assert!(
        out.contains("# TYPE wiremesh_gateway_policy_apply_failures_total counter"),
        "body: {out}"
    );
    assert!(out.contains("wiremesh_gateway_policy_apply_failures_total 3"), "body: {out}");

    // Zero must still be emitted: an absent series is indistinguishable from
    // a dead exporter, and "policy applies are failing" is exactly the alert
    // an operator needs to be able to write against a always-present series.
    let zero = wiremesh_gateway::metrics::render_policy_apply_failures(0);
    assert!(zero.contains("wiremesh_gateway_policy_apply_failures_total 0"), "body: {zero}");
}
