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
//!     /// The latest instant at which every enforcer that installing `ds`
//!     /// would actually WRITE will accept that write — `max` over the
//!     /// `GatewayEnforcer::apply_ready_at()` of THOSE entries only.
//!     /// `None` = no constraint.
//!     ///
//!     /// `ds` is a parameter because the install is version-gated per
//!     /// enforcer: an entry already on `ds.policy_version` will not be
//!     /// touched, so its grace protects nothing and must not gate. Without
//!     /// the filter, a rotation overlap's freshly-created enforcer (first
//!     /// apply = a full fresh grace) would delay a security-relevant
//!     /// policy TIGHTENING to a boot tun already clear to take it.
//!     ///
//!     /// The real adapter takes the enforcer-map lock, reads the deadlines,
//!     /// and DROPS the lock before returning — returning a plain
//!     /// `Option<Instant>` (not a guard) is what structurally forbids
//!     /// holding the map lock across the worker's wait.
//!     ///
//!     /// `ds_is_newest` means the same as on `install`; it is passed here
//!     /// only so the two agree on WHICH entries will be written.
//!     fn ready_at(&self, ds: &DesiredState, ds_is_newest: bool)
//!         -> Option<std::time::Instant>;
//!
//!     /// Perform the (now fast) install: re-lock the enforcer map and
//!     /// `apply_if_changed(ds)` every live entry. BLOCKING by contract —
//!     /// the worker always calls it inside `tokio::task::spawn_blocking`,
//!     /// so the real adapter uses `Mutex::blocking_lock()`.
//!     ///
//!     /// The reading `ready_at` returned was taken before the lock was
//!     /// dropped and re-taken, so a rotation insert can have added an
//!     /// enforcer in between whose grace was never consulted. An
//!     /// implementation must re-check each entry's own deadline UNDER THE
//!     /// LOCK and defer (returning `Err`, so the worker retries) rather
//!     /// than write it.
//!     ///
//!     /// `ds_is_newest` is true iff nothing has been published since the
//!     /// worker picked `ds` up. It disambiguates the one case `ds` alone
//!     /// cannot: an enforcer AHEAD of `ds.policy_version`. False means our
//!     /// snapshot is stale and writing it would DOWNGRADE a rotation tun
//!     /// that already has the newer policy; true means the controller
//!     /// genuinely rolled back and we must converge onto `ds`.
//!     fn install(&self, ds: &DesiredState, ds_is_newest: bool)
//!         -> anyhow::Result<()>;
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

use wiremesh_gateway::policy_apply::{
    needs_policy_write, spawn_policy_apply_worker, PolicyApplyHandle, PolicyApplyTarget,
};
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

/// Bounded wait for a WORKER-side counter to catch up with a TARGET-side
/// signal — see [`await_failures`]. Deliberately generous next to the ~0.1s
/// these tests actually take: it is only ever paid in full when the property
/// is genuinely broken, and a tight budget here would trade a real race for
/// a flaky one.
const COUNTER_VISIBILITY_BUDGET: Duration = Duration::from_secs(2);

/// Settle window for the mirror-image "this counter must NOT move"
/// assertions — see [`settle_counters`].
const COUNTER_SETTLE: Duration = Duration::from_millis(100);

/// A deadline far enough out that any test which accidentally waits on it
/// fails by TIMING OUT rather than by running slowly — used by the
/// version-filter tests, where the whole point is that this deadline must
/// never be waited on at all.
const FAR_DEADLINE: Duration = Duration::from_secs(10);

fn ds(version: u64) -> DesiredState {
    DesiredState {
        revision: version,
        policy_version: version,
        ..Default::default()
    }
}

/// One recorded `install` call.
#[derive(Debug, Clone, Copy)]
struct Install {
    version: u64,
    started_at: Instant,
    ok: bool,
    /// What the worker reported for `ds_is_newest` on this call.
    ds_is_newest: bool,
    /// `true` when the attempt failed because at least one entry was still
    /// inside its own reap grace at install time (the rotation-insert race),
    /// as opposed to a test-forced backend rejection. Diagnostic only — the
    /// pinned properties are the worker-side ones.
    deferred: bool,
}

/// One live enforcer, as the fake models it: exactly the two fields the real
/// adapter's version filter and under-the-lock deadline re-check consult
/// (`GatewayEnforcer::applied_version()` / `::apply_ready_at()`).
///
/// The fake models a SET of these rather than one flat deadline so that the
/// `ds` parameter on `ready_at` is genuinely exercised — with a single
/// unconstrained entry the filter would be satisfied by accident and the
/// version-threading tests below would prove nothing.
#[derive(Debug, Clone, Copy)]
struct FakeEntry {
    applied_version: Option<u64>,
    ready_at: Option<Instant>,
}

impl FakeEntry {
    /// A fresh, unconstrained enforcer: nothing applied yet, no pending reap.
    /// The default single-entry map every test that does not care about
    /// per-entry behaviour gets.
    fn fresh() -> FakeEntry {
        FakeEntry {
            applied_version: None,
            ready_at: None,
        }
    }
}

/// In-test stand-in for the live enforcer map. Records every `install`,
/// signals every `ready_at`/install-start/install-finish so tests can
/// synchronize on the worker's progress instead of sleeping and hoping, and
/// can be told to stall, fail, or panic.
struct FakeTarget {
    /// The modelled enforcer map. Starts as one [`FakeEntry::fresh`].
    entries: Mutex<Vec<FakeEntry>>,
    /// Every `(ds.policy_version, ds_is_newest)` handed to `ready_at`, in
    /// call order — lets a test pin that the deadline was read for the state
    /// actually being installed, not a stale or default one.
    ready_at_calls: Mutex<Vec<(u64, bool)>>,
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
    /// Number of upcoming `ready_at` calls that must PANIC. `u64::MAX` =
    /// panic until told otherwise. Models the safety-critical degradation
    /// path: the worker must treat an unreadable deadline as a failed
    /// attempt, never as "no deadline, apply now".
    panic_ready_at: AtomicU64,
    /// One-shot rotation-insert race: an entry appended at the END of the
    /// next `ready_at` call, i.e. AFTER the worker has already taken its
    /// deadline reading, exactly as `maybe_start_role_a`/`maybe_start_role_b`
    /// can insert a brand-new enforcer between the read and the install.
    insert_after_next_ready_at: Mutex<Option<FakeEntry>>,
}

impl FakeTarget {
    fn new() -> (Arc<FakeTarget>, Signals) {
        let (ready_calls, ready_rx) = unbounded_channel();
        let (install_started, started_rx) = unbounded_channel();
        let (install_done, done_rx) = unbounded_channel();
        let t = Arc::new(FakeTarget {
            entries: Mutex::new(vec![FakeEntry::fresh()]),
            ready_at_calls: Mutex::new(Vec::new()),
            installs: Mutex::new(Vec::new()),
            ready_calls,
            install_started,
            install_done,
            block_for: Mutex::new(None),
            gate: Mutex::new(None),
            fail_next: AtomicU64::new(0),
            panic_ready_at: AtomicU64::new(0),
            insert_after_next_ready_at: Mutex::new(None),
        });
        (
            t,
            Signals {
                ready_rx,
                started_rx,
                done_rx,
            },
        )
    }

    /// Convenience for the single-entry tests: set the one default
    /// enforcer's pending-reap deadline.
    fn set_ready_at(&self, t: Option<Instant>) {
        let mut entries = self.entries.lock().unwrap();
        assert_eq!(
            entries.len(),
            1,
            "set_ready_at is the single-entry convenience"
        );
        entries[0].ready_at = t;
    }

    /// Replace the modelled enforcer map wholesale (multi-entry tests).
    fn set_entries(&self, entries: Vec<FakeEntry>) {
        *self.entries.lock().unwrap() = entries;
    }

    fn entries(&self) -> Vec<FakeEntry> {
        self.entries.lock().unwrap().clone()
    }

    /// Arm the rotation-insert race: `entry` becomes visible only after the
    /// worker's NEXT deadline read has already returned.
    fn insert_after_next_ready_at(&self, entry: FakeEntry) {
        *self.insert_after_next_ready_at.lock().unwrap() = Some(entry);
    }

    fn panic_ready_at(&self, n: u64) {
        self.panic_ready_at.store(n, Ordering::SeqCst);
    }

    fn stop_panicking(&self) {
        self.panic_ready_at.store(0, Ordering::SeqCst);
    }

    /// Every `ds.policy_version` the worker asked a deadline for, in order.
    fn ready_at_versions(&self) -> Vec<u64> {
        self.ready_at_calls
            .lock()
            .unwrap()
            .iter()
            .map(|(v, _)| *v)
            .collect()
    }

    /// The same calls with the `ds_is_newest` flag the worker reported.
    fn ready_at_calls(&self) -> Vec<(u64, bool)> {
        self.ready_at_calls.lock().unwrap().clone()
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
        self.installs()
            .iter()
            .filter(|i| i.ok)
            .map(|i| i.version)
            .collect()
    }
}

impl PolicyApplyTarget for FakeTarget {
    /// The max deadline over only those entries the install would actually
    /// WRITE. Calls the REAL [`needs_policy_write`] rather than restating
    /// it: a fake that reimplements the decision can drift from the adapter,
    /// and a drift there is invisible to every test in this file.
    fn ready_at(&self, ds: &DesiredState, ds_is_newest: bool) -> Option<Instant> {
        let version = ds.policy_version;

        // No mutex guard may be alive when this panics: a poisoned fixture
        // mutex would turn every LATER `.lock().unwrap()` into a second,
        // unrelated panic and the test would fail for the wrong reason.
        let panics = self.panic_ready_at.load(Ordering::SeqCst);
        if panics > 0 {
            if panics != u64::MAX {
                self.panic_ready_at.store(panics - 1, Ordering::SeqCst);
            }
            self.ready_at_calls
                .lock()
                .unwrap()
                .push((version, ds_is_newest));
            let _ = self.ready_calls.send(());
            panic!("fake ready_at panic (policy version {version})");
        }

        let deadline = {
            let entries = self.entries.lock().unwrap();
            entries
                .iter()
                .filter(|e| needs_policy_write(e.applied_version, version, ds_is_newest))
                .filter_map(|e| e.ready_at)
                .max()
        };

        // The rotation-insert race: the new entry lands only NOW, after the
        // reading above was taken — so `install` is the first place its
        // grace can possibly be seen.
        let late = self.insert_after_next_ready_at.lock().unwrap().take();
        if let Some(entry) = late {
            self.entries.lock().unwrap().push(entry);
        }

        self.ready_at_calls
            .lock()
            .unwrap()
            .push((version, ds_is_newest));
        // Send AFTER reading, so a test woken by this signal is guaranteed
        // the worker has already taken the value it will wait on.
        let _ = self.ready_calls.send(());
        deadline
    }

    fn install(&self, ds: &DesiredState, ds_is_newest: bool) -> anyhow::Result<()> {
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

        // A test-forced backend rejection short-circuits before any entry is
        // written — a failing `apply_if_changed` leaves the real enforcer's
        // `applied_version` untouched too.
        let remaining = self.fail_next.load(Ordering::SeqCst);
        let forced_fail = remaining != 0;
        if forced_fail && remaining != u64::MAX {
            self.fail_next.store(remaining - 1, Ordering::SeqCst);
        }

        // The under-the-lock re-check: an entry still inside its own grace is
        // LEFT ALONE and the whole install reports `Err`, so the worker's
        // retry re-reads the deadline and completes it once the grace
        // elapses.
        //
        // SCOPE OF WHAT THIS PROVES. The write predicate above is the real
        // `needs_policy_write`, so tests exercising it exercise production
        // code. The rest of this method is FIXTURE — the deadline comparison,
        // the write, and the decision to report a deferral as `Err` are
        // modelled here to satisfy the trait's documented contract, not
        // shared with the adapter. A test that turns green because of one of
        // those lines proves the WORKER handles that shape correctly; it
        // says nothing about whether `main.rs` produces it. The adapter's own
        // copy needs review, or a unit test inside `main.rs`.
        let mut deferred = 0usize;
        if !forced_fail {
            let mut entries = self.entries.lock().unwrap();
            let now = Instant::now();
            for e in entries.iter_mut() {
                if !needs_policy_write(e.applied_version, version, ds_is_newest) {
                    continue; // nothing would be written; nothing to gate on
                }
                if e.ready_at.is_some_and(|t| t > now) {
                    deferred += 1;
                    continue;
                }
                e.applied_version = Some(version);
            }
        }

        let ok = !forced_fail && deferred == 0;
        self.installs.lock().unwrap().push(Install {
            version,
            started_at,
            ok,
            ds_is_newest,
            deferred: deferred > 0,
        });
        let _ = self.install_done.send((version, ok));

        if ok {
            Ok(())
        } else if forced_fail {
            Err(anyhow::anyhow!(
                "fake install failure for policy version {version}"
            ))
        } else {
            Err(anyhow::anyhow!(
                "{deferred} entr(ies) were still inside their reap grace; deferring policy \
                 version {version} for them"
            ))
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

/// **Sound observation barrier for WORKER-side state.** Waits until the
/// worker's failure counter has reached `want`, or fails on a bounded
/// deadline. Returns the first observed value at or above `want`, so a
/// caller can still pin an EXACT count on top of it.
///
/// ## Why this exists (do not "simplify" it back into a direct read)
///
/// Every `install_done` signal in this file is emitted by the FAKE TARGET,
/// from inside `install()`, BEFORE it returns. The worker can only record
/// the outcome after its `spawn_blocking(install).await` resolves — one
/// scheduling hop later. On the current-thread runtime these tests use, the
/// test task reliably wins that race, so
/// `recv(done_rx); assert!(handle.failures() >= n)` asserts one hop too
/// early and is unsatisfiable by ANY correct worker. That is a defect in the
/// harness's observation barrier, not in the product.
///
/// This does not weaken the property. "Every failed attempt is counted" is
/// still asserted in full: a worker that drops a failure, or never counts at
/// all, sits below `want` until the deadline and fails loudly with the count
/// it got stuck on. All that changed is that the counter is given a bounded
/// moment to become observable, instead of being read before it possibly
/// could be.
async fn await_failures(handle: &PolicyApplyHandle, want: u64) -> u64 {
    let deadline = Instant::now() + COUNTER_VISIBILITY_BUDGET;
    loop {
        let seen = handle.failures();
        if seen >= want {
            return seen;
        }
        if Instant::now() >= deadline {
            panic!(
                "the worker counted only {seen} apply failure(s) within \
                 {COUNTER_VISIBILITY_BUDGET:?} of {want} being observed at the enforcer \
                 — every failed attempt must be counted (this counter is the source of \
                 `wiremesh_gateway_policy_apply_failures_total`)"
            );
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Drains install signals until a FAILED attempt at `version` is seen.
/// Used where the desired state changes mid-wedge: the worker may still be
/// mid-attempt on the previous version when the newer one is published, so
/// "the next signal" is not reliably the one under test.
async fn next_failed_attempt_at(sig: &mut Signals, version: u64) {
    loop {
        let (v, ok) = recv_within(
            &mut sig.done_rx,
            Duration::from_secs(10),
            "an install attempt",
        )
        .await;
        assert!(
            !ok,
            "the backend is still failing, so no attempt may succeed yet"
        );
        if v == version {
            return;
        }
    }
}

/// The mirror image of [`await_failures`], for assertions of the form "this
/// counter must NOT have moved". The same one-hop gap applies in reverse: an
/// increment the worker makes WRONGLY would land after a naive read, so the
/// read would pass by luck. Settling first is strictly STRONGER than reading
/// immediately — it gives a miscounting worker time to be caught rather than
/// time to hide.
async fn settle_counters() {
    tokio::time::sleep(COUNTER_SETTLE).await;
}

// --- the write predicate (pure truth table) -------------------------------

/// `needs_policy_write` carries the security-relevant half of this item, and
/// every behavioural test in this file routes through it — including the
/// fake, which CALLS it rather than restating it. So it gets a pure,
/// exhaustive pin of its own: no worker, no timing, no fixture.
///
/// The four arms, each named so a regression points at the case rather than
/// at a row index. The AHEAD arms are asserted directly under BOTH flag
/// values rather than being inferred from the others, because they are the
/// whole reason the parameter exists.
#[test]
fn needs_policy_write_truth_table() {
    // Never applied: unconditional write. A fresh enforcer has nothing to
    // protect and nothing to downgrade, so the flag is irrelevant.
    for newest in [false, true] {
        assert!(
            needs_policy_write(None, 7, newest),
            "an enforcer that has never applied a policy must always be written \
             (ds_is_newest={newest})"
        );
    }

    // Behind: unconditional write. This is the ordinary case — a tun that
    // has not caught up must catch up whether or not our snapshot is the
    // newest one.
    for newest in [false, true] {
        assert!(
            needs_policy_write(Some(6), 7, newest),
            "an enforcer behind the target must be written (ds_is_newest={newest})"
        );
    }

    // Equal: never written. `apply_if_changed` would short-circuit anyway;
    // the point of skipping here is that such an entry's reap grace must not
    // gate an install that will not touch it.
    for newest in [false, true] {
        assert!(
            !needs_policy_write(Some(7), 7, newest),
            "an enforcer already on the target version must be skipped \
             (ds_is_newest={newest})"
        );
    }

    // AHEAD + our snapshot is NOT the newest: SKIP. This is the F1 nft
    // downgrade protection and the reason `ds_is_newest` exists. A rotation
    // insert applied a newer snapshot to that enforcer before putting it in
    // the map; writing our older policy over it downgrades a tun that is
    // carrying traffic. On eBPF the fresh entry's pending reap would defer
    // it anyway, but on nftables `apply_ready_at` is permanently `None`,
    // nothing defers, and the downgrade lands.
    assert!(
        !needs_policy_write(Some(8), 7, false),
        "an enforcer AHEAD of a STALE snapshot must NOT be written — that is a live \
         downgrade of a rotation tun, unmasked on the nftables backend"
    );

    // AHEAD + our snapshot IS the newest: WRITE. The controller genuinely
    // rolled back (DB restore, or a repoint at a different controller), so
    // the older version really is desired and the datapath is what is wrong.
    assert!(
        needs_policy_write(Some(8), 7, true),
        "an enforcer AHEAD of the NEWEST snapshot must be written — otherwise a \
         rolled-back controller never converges and the gateway stays pinned to an \
         abandoned policy"
    );
}

/// Boundaries. Two of these three are reachable in production and one is
/// purely defensive; the comments say which, so nobody reads the last as a
/// real scenario.
#[test]
fn needs_policy_write_boundaries() {
    // ADJACENT VERSIONS — reachable, and the exact shape of the bug the
    // strictly-less-than comparison exists to prevent: a rotation insert
    // leaves an entry on `v` while the worker still carries `v-1`. An
    // equality test (`applied != target`) would return true here and write
    // the OLDER policy. This is also where an off-by-one (`<=` for `<`,
    // `>=` for `>`) at either boundary shows up.
    assert!(
        needs_policy_write(Some(41), 42, false),
        "one behind is behind"
    );
    assert!(
        !needs_policy_write(Some(42), 42, false),
        "exactly equal is not behind"
    );
    assert!(
        !needs_policy_write(Some(43), 42, false),
        "one ahead of a stale snapshot: skip"
    );
    assert!(
        needs_policy_write(Some(43), 42, true),
        "one ahead of the newest: rollback write"
    );

    // TARGET 0 — reachable: a boot snapshot carrying no policy yet has
    // `policy_version: 0`, and `apply_if_changed` installs an empty IR at
    // that version. Also the case an implementation doing subtraction
    // instead of comparison (`target - av`) would underflow on.
    assert!(
        needs_policy_write(None, 0, false),
        "never-applied at version 0 must be written"
    );
    assert!(
        !needs_policy_write(Some(0), 0, true),
        "already at version 0: skip"
    );
    assert!(
        !needs_policy_write(Some(1), 0, false),
        "ahead of a stale version-0 snapshot: skip"
    );
    assert!(
        needs_policy_write(Some(1), 0, true),
        "ahead of the newest version-0 snapshot: write"
    );

    // u64::MAX — NOT reachable (the controller's version counter is
    // `MAX(version) + 1` in SQLite and `set_applied_version` rejects
    // anything past the INTEGER range). Kept as one cheap line because a
    // saturating or wrapping arithmetic implementation would misbehave at
    // the extreme while looking correct everywhere else.
    assert!(
        needs_policy_write(Some(0), u64::MAX, false),
        "0 is behind the maximum"
    );
    assert!(
        !needs_policy_write(Some(u64::MAX), u64::MAX, false),
        "the maximum equals itself"
    );
    assert!(
        !needs_policy_write(Some(u64::MAX), 0, false),
        "the maximum is ahead of 0: skip"
    );
}

/// Exhaustive sweep of a small domain, as a guard against a mis-ordered or
/// unreachable `match` arm that the hand-picked cases above could miss.
///
/// The expectation is written with `Ordering` rather than the named cases,
/// which is a RESTATEMENT of the same rule, not an independent derivation —
/// its value here is coverage of every combination, not a second opinion on
/// what the rule should be. The named tests above are the actual pins.
#[test]
fn needs_policy_write_sweep_matches_the_ordering_rule() {
    use std::cmp::Ordering;
    for applied in [None, Some(0u64), Some(1), Some(2), Some(3), Some(4)] {
        for target in 0u64..=4 {
            for newest in [false, true] {
                let expected = match applied {
                    None => true,
                    Some(av) => match av.cmp(&target) {
                        Ordering::Less => true,
                        Ordering::Equal => false,
                        Ordering::Greater => newest,
                    },
                };
                assert_eq!(
                    needs_policy_write(applied, target, newest),
                    expected,
                    "applied={applied:?} target={target} ds_is_newest={newest}"
                );
            }
        }
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
    // `failures()` is WORKER-side while the signal above is TARGET-side, so a
    // worker that wrongly counted this SUCCESS as a failure would increment
    // one scheduling hop after a naive read — see `settle_counters`.
    settle_counters().await;
    assert_eq!(
        handle.failures(),
        0,
        "a successful install must not count as a failure"
    );
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
    let started = recv_within(
        &mut sig.started_rx,
        Duration::from_secs(5),
        "install #1 to start",
    )
    .await;
    assert_eq!(
        started, 1,
        "the first published state must be the first installed"
    );

    // The Sync loop keeps receiving snapshots while the install runs.
    handle.publish(ds(2));
    handle.publish(ds(3));
    handle.publish(ds(4));

    release.send(()).expect("release the gated install");
    let (v1, _) = recv_within(
        &mut sig.done_rx,
        Duration::from_secs(5),
        "install #1 to finish",
    )
    .await;
    assert_eq!(v1, 1);

    let (v2, ok) = recv_within(
        &mut sig.done_rx,
        Duration::from_secs(5),
        "the follow-up install",
    )
    .await;
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
    recv_within(
        &mut sig.ready_rx,
        Duration::from_secs(5),
        "the worker's deadline query",
    )
    .await;

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

// --- per-entry deadline semantics (review findings 4+5) -------------------

/// **Review finding 4.** The deadline must be read for the enforcers the
/// install would actually WRITE. An entry already on `ds.policy_version`
/// will not be touched by `apply_if_changed`, so its pending reap protects
/// nothing and must not gate anything.
///
/// The concrete outage this prevents: during a rotation overlap a
/// freshly-created enforcer has just done its first apply and is therefore
/// sitting on a full 10s grace. If its deadline gated the whole install, a
/// security-relevant policy TIGHTENING would be held off the boot tun — which
/// is already on a different version and perfectly clear to take it — for a
/// grace period.
///
/// Sabotage that must turn this red: hand `ready_at` anything other than the
/// state about to be installed (a `DesiredState::default()`, a stale clone),
/// or drop the `ds` argument and go back to max-over-everything — entry
/// `already_on_v2` stops being filtered and the install waits
/// `FAR_DEADLINE`, blowing the 3s budget.
#[tokio::test]
async fn an_entry_already_on_the_target_version_does_not_gate_the_install() {
    let (target, mut sig) = FakeTarget::new();
    let far = Instant::now() + FAR_DEADLINE;
    target.set_entries(vec![
        // The rotation newcomer: just flipped, a full grace pending — but it
        // is ALREADY on the version we are about to install.
        FakeEntry {
            applied_version: Some(2),
            ready_at: Some(far),
        },
        // The boot tun: nothing applied yet, no pending reap. This is the
        // one the install must reach, promptly.
        FakeEntry::fresh(),
    ]);
    let handle = spawn_policy_apply_worker(target.clone(), RETRY_AFTER);

    let published_at = Instant::now();
    handle.publish(ds(2));

    let (v, ok) = recv_within(&mut sig.done_rx, Duration::from_secs(3), "the install").await;
    assert_eq!((v, ok), (2, true));
    let waited = target.installs()[0]
        .started_at
        .saturating_duration_since(published_at);
    assert!(
        waited < RESPONSIVE_WITHIN,
        "the install waited {waited:?} on a deadline belonging to an enforcer that was \
         already on policy version 2 — that entry would not have been written, so its \
         reap grace must not gate a tightening bound for the other tun"
    );
    assert_eq!(
        target.ready_at_versions(),
        vec![2],
        "the deadline must be read for the state actually being installed"
    );
    assert_eq!(
        target.entries()[1].applied_version,
        Some(2),
        "the entry that WAS behind must have been written"
    );
}

/// The same property across the supersession path — where a stale `ds` is
/// genuinely easy to leak, because the version filter makes the deadline
/// DIFFERENT for the two states.
///
/// The fixture inverts which entry gates: `gates_v2_only` is already on v1,
/// so it is filtered while v1 is the target and becomes gating the moment v2
/// is adopted. A worker that adopts v2 and installs it using the deadline it
/// computed for v1 therefore writes `gates_v2_only` while it is still inside
/// its grace — the adapter's under-the-lock re-check catches that and defers,
/// so the sabotage shows up as a spurious deferral (a counted failure and a
/// second install attempt) rather than as a silent overwrite.
///
/// Sabotage that must turn this red: install the newly adopted state without
/// looping back to re-read its deadline, or re-read it while still passing
/// the superseded `ds` — `failures()` becomes 1 and `installs` has two
/// entries instead of one.
#[tokio::test]
async fn re_adopting_a_newer_state_re_reads_the_deadline_for_that_newer_state() {
    let (target, mut sig) = FakeTarget::new();
    let t0 = Instant::now();
    let gates_v1 = t0 + Duration::from_millis(200);
    let gates_v2 = t0 + Duration::from_millis(500);
    target.set_entries(vec![
        // Nothing applied yet: gates BOTH states, and its short deadline is
        // what the worker parks on for v1.
        FakeEntry {
            applied_version: None,
            ready_at: Some(gates_v1),
        },
        // Already on v1, so filtered out while v1 is the target — and NOT
        // filtered once v2 is adopted, at which point its later deadline
        // becomes the binding one.
        FakeEntry {
            applied_version: Some(1),
            ready_at: Some(gates_v2),
        },
    ]);
    let handle = spawn_policy_apply_worker(target.clone(), RETRY_AFTER);

    handle.publish(ds(1));
    recv_within(
        &mut sig.ready_rx,
        Duration::from_secs(5),
        "the deadline query for v1",
    )
    .await;

    // Supersede during the (200ms) wait.
    handle.publish(ds(2));

    let (v, ok) = recv_within(&mut sig.done_rx, Duration::from_secs(5), "the install").await;
    assert_eq!(
        (v, ok),
        (2, true),
        "the superseding state is the one installed"
    );

    let started = target.installs()[0].started_at;
    assert!(
        started >= gates_v2,
        "the install ran {:?} before the deadline that applies to v2 — it reused the \
         deadline computed for v1, under which that enforcer was filtered out",
        gates_v2.saturating_duration_since(started)
    );
    assert_eq!(
        target.ready_at_versions(),
        vec![1, 2],
        "exactly one deadline read per adopted state, each for that state's own version"
    );
    assert_eq!(
        target.installs().len(),
        1,
        "one clean install, no deferral round trip"
    );
    settle_counters().await;
    assert_eq!(
        handle.failures(),
        0,
        "re-reading the deadline for the adopted state is what avoids writing an \
         enforcer inside its grace; a spurious deferral here means the worker carried \
         the superseded state's deadline forward"
    );
}

/// **Review finding 5.** An entry inserted between the deadline read and the
/// install — a rotation standing up a new tun — has a grace the worker never
/// consulted. It must be DEFERRED, not written: the install reports `Err`,
/// the worker counts it and retries, and the retry re-reads the deadline,
/// waits the newly-discovered grace out, and lands the state.
///
/// Before the fix this was benign only because the rotation handlers happen
/// to apply the same snapshot, so `apply_if_changed` short-circuited. Nothing
/// stated or enforced that; this pins the enforced version.
///
/// The discriminator is the failure COUNT, not just eventual success. A
/// worker that re-reads the deadline defers exactly ONCE, then waits and
/// succeeds. A worker that blindly re-attempted on the retry timer would
/// keep hammering the target — with a 600ms grace and 50ms backoff doubling
/// (50/100/200/400) that is four deferrals before one happens to land after
/// the grace, and it would land by luck rather than by waiting.
#[tokio::test]
async fn an_entry_inserted_after_the_deadline_read_is_deferred_then_landed_by_the_retry() {
    let (target, mut sig) = FakeTarget::new();
    let grace = Duration::from_millis(600);
    let late_deadline = Instant::now() + grace;
    // Arrives only after the worker has taken its (unconstrained) reading.
    target.insert_after_next_ready_at(FakeEntry {
        applied_version: None,
        ready_at: Some(late_deadline),
    });
    let handle = spawn_policy_apply_worker(target.clone(), RETRY_AFTER);

    handle.publish(ds(1));

    let (v, ok) = recv_within(
        &mut sig.done_rx,
        Duration::from_secs(5),
        "the first attempt",
    )
    .await;
    assert_eq!(
        (v, ok),
        (1, false),
        "the attempt must FAIL rather than write an enforcer whose grace was never read"
    );
    assert!(
        target.installs()[0].deferred,
        "sanity: the first attempt must have failed by DEFERRAL (the race), not by a \
         forced backend rejection"
    );

    let (v, ok) = recv_within(&mut sig.done_rx, Duration::from_secs(5), "the retry").await;
    assert_eq!(
        (v, ok),
        (1, true),
        "the retry must land the state once the grace elapses"
    );

    let landed_at = target.installs()[1].started_at;
    assert!(
        landed_at >= late_deadline,
        "the retry wrote the late entry {:?} BEFORE its grace expired — the deferral \
         must be resolved by waiting the grace out, not by retrying until one attempt \
         happens to slip past it",
        late_deadline.saturating_duration_since(landed_at)
    );
    for (i, e) in target.entries().iter().enumerate() {
        assert_eq!(
            e.applied_version,
            Some(1),
            "entry {i} must be on the target version once the state has landed"
        );
    }

    let failures = await_failures(&handle, 1).await;
    settle_counters().await;
    assert_eq!(
        handle.failures(),
        1,
        "exactly ONE deferral: the retry must re-read the deadline and wait it out. \
         More than one means the worker is blind-retrying on its backoff timer and \
         landing the state by luck (first observation was {failures})"
    );
    assert_quiet(&mut sig.done_rx, Duration::from_millis(300), "installs").await;
}

// --- rollback: an enforcer AHEAD of the target version --------------------

/// **A genuine controller rollback must converge.** A DB restore takes the
/// controller from v100 back to v50; the operator pushes v51; every gateway
/// is holding v100. Under a purely monotone "only ever move forward" filter
/// those gateways skip v51 — and every version after it — until the
/// controller has climbed back past 100. The fabric would sit on an
/// abandoned policy with no error anywhere, and the only recovery would be
/// restarting every gateway mid-incident. A DB restore is this project's
/// documented recovery path, so this is not an exotic case.
///
/// `ds_is_newest` is what distinguishes it from the transient case: nothing
/// newer has been published, so v51 really is the desired state and the
/// datapath being ahead of it is the thing to fix, not to preserve.
///
/// Sabotage that must turn this red: make the AHEAD arm of the write
/// predicate a flat `false` (pure monotone) — the entry stays on v100
/// forever and the datapath never converges. Note the install still returns
/// `Ok` in that case (nothing was deferred, nothing errored), which is
/// exactly why this asserts on the ENTRY STATE and not on the result: a
/// monotone skip is silent, and silence is the bug.
#[tokio::test]
async fn a_rollback_is_installed_when_our_snapshot_is_the_newest() {
    let (target, mut sig) = FakeTarget::new();
    // The datapath is ahead: the controller was at v100 before the restore.
    target.set_entries(vec![FakeEntry {
        applied_version: Some(100),
        ready_at: None,
    }]);
    let handle = spawn_policy_apply_worker(target.clone(), RETRY_AFTER);

    // The post-restore push. Nothing else is published, so this IS the
    // newest state.
    handle.publish(ds(51));

    let (v, ok) = recv_within(
        &mut sig.done_rx,
        Duration::from_secs(5),
        "the rollback install",
    )
    .await;
    assert_eq!((v, ok), (51, true));
    assert_eq!(
        target.entries()[0].applied_version,
        Some(51),
        "an enforcer AHEAD of the newest desired state must be rolled back onto it — a \
         monotone skip leaves the gateway pinned to a policy the operator has abandoned, \
         silently, until the controller climbs back past v100"
    );
    assert!(
        target.installs()[0].ds_is_newest,
        "the worker must report this snapshot as the newest one — that flag is the ONLY \
         thing distinguishing an authorized rollback from a stale snapshot racing a \
         rotation insert"
    );
    assert_eq!(
        target.ready_at_calls(),
        vec![(51, true)],
        "one deadline read, same verdict"
    );
    settle_counters().await;
    assert_eq!(
        handle.failures(),
        0,
        "a rollback is a normal install, not a failure"
    );
}

/// The mixed datapath the coordinator called out: one enforcer AHEAD (v100,
/// from before the restore) and one BEHIND (v40, a tun that never caught
/// up). Installing v51 must write BOTH, leaving the datapath uniformly on
/// v51 — the ahead one rolled back, the behind one rolled forward, in the
/// same pass.
///
/// **What this does NOT pin — read before trusting it.** The
/// `wiremesh_gateway_applied_policy_version` gauge is computed inside
/// `main.rs`'s adapter (`live_max`, the `max` over live enforcers' applied
/// versions, stored only on full success). It is not part of the
/// `PolicyApplyTarget` surface, so it is invisible from this seam and I have
/// not faked it — a fake gauge would only be asserting my own arithmetic.
/// What IS pinned here is the ground truth that gauge is derived from: after
/// this install every live enforcer holds exactly v51, so any correct
/// derivation reports 51. That the adapter uses `max`-over-live rather than
/// a running `fetch_max` (which would report 100 here) needs review, or a
/// unit test inside `main.rs`; see my report.
///
/// Sabotage that must turn this red: monotone AHEAD arm — the v100 entry is
/// skipped, the datapath is left split at v100/v51, and no gauge derivation
/// can report a single honest number for it.
#[tokio::test]
async fn a_rollback_converges_a_mixed_ahead_and_behind_datapath() {
    let (target, mut sig) = FakeTarget::new();
    target.set_entries(vec![
        FakeEntry {
            applied_version: Some(100),
            ready_at: None,
        }, // ahead
        FakeEntry {
            applied_version: Some(40),
            ready_at: None,
        }, // behind
    ]);
    let handle = spawn_policy_apply_worker(target.clone(), RETRY_AFTER);

    handle.publish(ds(51));

    let (v, ok) = recv_within(&mut sig.done_rx, Duration::from_secs(5), "the install").await;
    assert_eq!((v, ok), (51, true));
    for (i, e) in target.entries().iter().enumerate() {
        assert_eq!(
            e.applied_version,
            Some(51),
            "entry {i} must hold exactly the installed version — a split datapath \
             (one tun ahead, one behind) is precisely the case a running-maximum gauge \
             reports wrongly, and it must not arise in the first place"
        );
    }
    assert_eq!(
        target.installs().len(),
        1,
        "one pass writes both directions"
    );
    settle_counters().await;
    assert_eq!(handle.failures(), 0);
}

/// **The rollback write is authorized, not exempt.** Being allowed to write
/// an entry that is ahead of us says nothing about WHEN — the ahead entry
/// has its own post-flip reap grace, and pulling its maps out from under
/// in-flight packets is the same hazard as for any other write.
///
/// This also pins that `ready_at` and `install` agree on the entry set: the
/// ahead entry must be INCLUDED in the deadline (because it will be written)
/// so the grace is waited out up front, in the worker's async
/// `sleep_until`, rather than discovered by the under-the-lock re-check.
///
/// Sabotage that must turn this red: filter the ahead entry out of
/// `ready_at` while still writing it in `install` (e.g. apply the flag in
/// one and not the other) — the deadline comes back `None`, the install
/// starts at ~0ms, the re-check defers it, and both `installs().len() == 1`
/// and `failures() == 0` go red. Or skip the re-check on the rollback path
/// specifically, and the lower bound goes red.
#[tokio::test]
async fn a_rollback_write_still_waits_out_the_ahead_entrys_reap_grace() {
    let (target, mut sig) = FakeTarget::new();
    let grace_until = Instant::now() + Duration::from_millis(500);
    target.set_entries(vec![FakeEntry {
        applied_version: Some(100),
        ready_at: Some(grace_until),
    }]);
    let handle = spawn_policy_apply_worker(target.clone(), RETRY_AFTER);

    handle.publish(ds(51));

    let (v, ok) = recv_within(
        &mut sig.done_rx,
        Duration::from_secs(5),
        "the rollback install",
    )
    .await;
    assert_eq!((v, ok), (51, true));

    let started = target.installs()[0].started_at;
    assert!(
        started >= grace_until,
        "the rollback wrote the ahead enforcer {:?} before its reap grace expired. \
         Authorizing a write says which entries may be written, never when — the grace \
         protects in-flight packets and applies to the rollback path identically.",
        grace_until.saturating_duration_since(started)
    );
    assert_eq!(
        target.installs().len(),
        1,
        "the grace must be waited out UP FRONT: the ahead entry belongs in `ready_at`'s \
         answer because it will be written, so a second attempt here means `ready_at` \
         and `install` disagree about the entry set and the re-check had to catch it"
    );
    settle_counters().await;
    assert_eq!(
        handle.failures(),
        0,
        "a correctly-scheduled rollback defers nothing"
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
    recv_within(
        &mut sig.started_rx,
        Duration::from_secs(5),
        "the install to start",
    )
    .await;

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
    recv_within(
        &mut sig.started_rx,
        Duration::from_secs(5),
        "install #1 to start",
    )
    .await;

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
    let (v, _) = recv_within(
        &mut sig.done_rx,
        Duration::from_secs(5),
        "the follow-up install",
    )
    .await;
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

    let a = recv_within(
        &mut sig.done_rx,
        Duration::from_secs(5),
        "install attempt 1",
    )
    .await;
    let b = recv_within(
        &mut sig.done_rx,
        Duration::from_secs(5),
        "install attempt 2 (retry)",
    )
    .await;
    let c = recv_within(
        &mut sig.done_rx,
        Duration::from_secs(5),
        "install attempt 3 (retry)",
    )
    .await;
    assert_eq!(a, (1, false), "attempt 1 fails");
    assert_eq!(
        b,
        (1, false),
        "attempt 2 retries the SAME desired state and fails"
    );
    assert_eq!(c, (1, true), "attempt 3 retries again and succeeds");

    // WORKER-side read behind a TARGET-side signal — barrier per
    // `await_failures`. This particular read happens to be safe today only
    // because the worker must record attempt N's failure before it can start
    // attempt N+1; that is an internal ordering assumption about the
    // implementation, not part of the contract, so it gets the same sound
    // barrier as everywhere else rather than passing by luck.
    let seen = await_failures(&handle, 2).await;
    assert_eq!(
        seen, 2,
        "both failures must be counted, and ONLY those two (this counter is the source \
         of `wiremesh_gateway_policy_apply_failures_total`)"
    );
    assert_quiet(&mut sig.done_rx, Duration::from_millis(300), "installs").await;

    // The worker is still alive and still serving: a later state applies.
    handle.publish(ds(2));
    let (v, ok) = recv_within(&mut sig.done_rx, Duration::from_secs(5), "the next install").await;
    assert_eq!(
        (v, ok),
        (2, true),
        "the worker must keep serving after a failure"
    );
    settle_counters().await;
    assert_eq!(
        handle.failures(),
        2,
        "a success must not change the failure count"
    );
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
        let (v, ok) = recv_within(
            &mut sig.done_rx,
            Duration::from_secs(5),
            "a retry of the bad state",
        )
        .await;
        assert_eq!(
            (v, ok),
            (1, false),
            "attempt {attempt} must keep retrying the bad state"
        );
    }
    // WORKER-side read behind a TARGET-side signal — barrier per
    // `await_failures`. This is the exact race that made the assertion
    // unsatisfiable when it read `failures()` in the same breath as the third
    // failure signal: the counter is incremented one scheduling hop after
    // `install()` has already signalled, and the test task wins that race
    // every time on a current-thread runtime. The property is unchanged —
    // all three failed attempts must be counted.
    await_failures(&handle, 3).await;

    // Operator pushes a corrected policy. It is published while the backend
    // is STILL failing, so the first thing to prove is that the retry loop
    // re-reads the mailbox rather than grinding on the wedged state forever:
    // a failed attempt carrying version 2 must appear.
    handle.publish(ds(2));
    loop {
        let (v, ok) = recv_within(
            &mut sig.done_rx,
            Duration::from_secs(5),
            "an attempt at the new state",
        )
        .await;
        assert!(
            !ok,
            "the backend is still failing, so no attempt may succeed yet"
        );
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

/// **Review finding 6 — the safety-critical degradation path.** A deadline
/// query that cannot be completed must be treated as a FAILED ATTEMPT, never
/// as "no deadline, apply now".
///
/// This is the one path in the whole design that could deliberately violate
/// the reap grace: applying without a deadline reading overwrites outer-array
/// slots that in-flight packets may still be reading. "The datapath keeps the
/// last good policy" is the strictly safer degradation and is what every
/// other failure here does.
///
/// The "no install happened" assertion is a stable invariant, not a race:
/// `ready_at` panics for the whole first phase, so an install is unreachable
/// by construction for as long as it does.
///
/// NOTE for whoever reads the output: this test deliberately panics inside
/// `spawn_blocking`, so a PASSING run still prints `thread '...' panicked at
/// ... fake ready_at panic` several times. That is the fixture working.
///
/// Sabotage that must turn this red: treat a failed deadline query as `None`
/// and fall through to the install — `installs` stops being empty. Or drop
/// the counter increment on that arm — `await_failures` times out.
#[tokio::test]
async fn an_unreadable_deadline_is_a_counted_retry_and_never_an_ungated_apply() {
    let (target, mut sig) = FakeTarget::new();
    target.panic_ready_at(u64::MAX);
    let handle = spawn_policy_apply_worker(target.clone(), RETRY_AFTER);

    handle.publish(ds(1));

    // Counted: the only observable here is the counter — a failed deadline
    // query produces no install signal at all, which is the point.
    await_failures(&handle, 3).await;
    settle_counters().await;
    assert!(
        target.installs().is_empty(),
        "a deadline query that failed must NOT degrade into applying with no reap-grace \
         reading — that is the one path that can knowingly overwrite maps in-flight \
         packets are still reading. Installs seen: {:?}",
        target.installs()
    );
    assert!(
        target.ready_at_versions().len() >= 3,
        "sanity: the worker must keep re-asking for the deadline, not give up on it"
    );

    // Retried: once the query works again the state lands, with no further
    // intervention.
    target.stop_panicking();
    let (v, ok) = recv_within(
        &mut sig.done_rx,
        Duration::from_secs(5),
        "the recovered install",
    )
    .await;
    assert_eq!(
        (v, ok),
        (1, true),
        "the state must land once its deadline is readable again — a transient query \
         failure must not wedge the datapath on the last good policy forever"
    );
}

/// **The retry pause is interruptible, and adoption resets the cadence.**
///
/// Consecutive failures double the pause (toward `RETRY_BACKOFF_MAX`) so an
/// un-appliable policy cannot flood the log. But that backoff is a sentence
/// the BAD policy earned, and a CORRECTED policy must serve none of it —
/// this is the operator's outage-response path, entered right after they
/// watched the gateway reject the previous version.
///
/// Two distinct properties, both measured in one wedge episode:
///
///  1. **The corrected state's FIRST attempt is prompt** — it must not wait
///     out the pause already in flight. (An earlier revision used a plain
///     `tokio::time::sleep(backoff)`, so it did; that is what this now pins
///     away.)
///  2. **The cadence resets** — its SECOND attempt follows at
///     `retry_after`, not at the grown backoff. Waking early but keeping the
///     grown backoff would fix the first attempt and leave the next one
///     ~1.6s out.
///
/// **Residual-latency case pinned here: ZERO outstanding grace.** Every
/// entry has `ready_at: None` and the fake's forced failure short-circuits
/// before writing anything, so no generation flipped and there is no grace
/// to serve — the common wedge (a policy rejected by `check_lpm_capacity` or
/// the IR decoder, which fails before any flip). The remaining latency is
/// therefore one `spawn_blocking` round trip, and `RESPONSIVE_WITHIN` is a
/// fair budget. The non-zero-grace case — where waking early must NOT let
/// the corrected state jump a genuinely outstanding grace — is the separate
/// safety pin in `waking_early_still_waits_out_an_outstanding_reap_grace`.
///
/// Arithmetic at `RETRY_AFTER` = 50ms: attempts at 0/50/150/350/750ms, so
/// when the fifth failure is observed the worker is in an 800ms pause and
/// the next doubling would be 1600ms. Property 1 measures ~1ms against a
/// 250ms budget (old behaviour: ~800ms). Property 2 measures ~50ms against
/// a 400ms budget (no reset: ~1600ms).
///
/// The publish may land just BEFORE the worker reaches the pause; that is
/// fine and deliberately not synchronized against. `watch` tracks changes
/// with a channel-side version counter rather than inside the `changed()`
/// future, so a change published before the select is entered still resolves
/// its mailbox arm immediately.
///
/// Sabotage that must turn each red: (1) replace `pause_or_wake` with a
/// plain `sleep(backoff)` — the first attempt arrives ~800ms late;
/// (2) drop `backoff = retry_after` from the `Pause::Adopted` arm — the
/// second attempt arrives ~1.6s late.
#[tokio::test]
async fn a_corrected_policy_wakes_the_retry_pause_and_gets_a_fresh_cadence() {
    let (target, mut sig) = FakeTarget::new();
    target.fail_next(u64::MAX);
    let handle = spawn_policy_apply_worker(target.clone(), RETRY_AFTER);

    handle.publish(ds(1));
    for attempt in 1..=5 {
        let (v, ok) = recv_within(
            &mut sig.done_rx,
            Duration::from_secs(10),
            "a wedged attempt",
        )
        .await;
        assert_eq!((v, ok), (1, false), "wedged attempt {attempt} must fail");
    }

    // The corrected policy, published into an ~800ms pause. Kept
    // un-appliable for now, so the retry cadence stays observable rather
    // than ending at the first success.
    let published_at = Instant::now();
    handle.publish(ds(2));

    // (1) Promptness. `next_failed_attempt_at` returns on the first attempt
    // carrying version 2, so this latency is measured to the corrected
    // state's OWN first attempt — which also proves the publish was neither
    // lost nor slept through: a worker that dropped it would keep attempting
    // v1 until the recv budget expired.
    next_failed_attempt_at(&mut sig, 2).await;
    let first_attempt_latency = published_at.elapsed();
    assert!(
        first_attempt_latency < RESPONSIVE_WITHIN,
        "the corrected policy's FIRST attempt came {first_attempt_latency:?} after it was \
         published (budget {RESPONSIVE_WITHIN:?}) — it sat out the remainder of a pause \
         the REJECTED policy earned. Nothing was flipped by the failed attempts, so there \
         is no reap grace to serve here; the only legitimate delay is one spawn_blocking \
         round trip."
    );

    // (2) Cadence reset.
    let first_v2_attempt = Instant::now();
    next_failed_attempt_at(&mut sig, 2).await;
    let gap = first_v2_attempt.elapsed();
    assert!(
        gap < Duration::from_millis(400),
        "the corrected policy's second attempt came {gap:?} after its first — it \
         inherited the wedged state's grown backoff instead of getting a fresh \
         {RETRY_AFTER:?} cadence. Waking early is only half the fix if the state that \
         woke us then serves the previous policy's sentence anyway."
    );

    // And a state the worker adopted must actually get installed, not merely
    // attempted: it lands as soon as it can.
    target.stop_failing();
    loop {
        let (v, ok) = recv_within(&mut sig.done_rx, Duration::from_secs(10), "an install").await;
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

/// **The counterpart safety pin: waking early must not skip a real grace.**
///
/// Making the retry pause interruptible creates exactly one new way to get
/// this wrong — treating "the operator is waiting, go now" as licence to
/// install without re-reading the deadline. The backoff is a courtesy and
/// can be cut short; the reap grace protects outer-array slots that in-flight
/// packets may still be reading, and cannot.
///
/// **Residual-latency case pinned here: NON-ZERO outstanding grace** — the
/// case the zero-grace test above deliberately excludes. The fixture arms a
/// real deadline at the moment the corrected state is published, modelling a
/// previous attempt that flipped a generation before failing.
///
/// Two bounds, and the second is why the fixture has a second entry:
///
///  - **Lower** — the corrected state must land no EARLIER than the grace.
///    This is the safety property.
///  - **Upper** — and no later than the grace plus a small margin, because
///    the grace is the only delay it still owes. The second entry is already
///    on v2, so it is skipped outright when v2 is the target. A worker that
///    adopts the new state late — at step (4) instead of at the pause site —
///    instead queries the deadline while still holding the superseded v1,
///    and by then the pause's `changed()` has already consumed the change
///    flag, so it queries v1 as its NEWEST state: the entry is AHEAD of v1,
///    the rollback rule authorizes writing it, and its 2s deadline becomes
///    binding. That worker lands at ~2s instead of ~500ms. Without the
///    second entry the upper bound would be near-vacuous, since at this
///    point in the episode the backoff is only ~50ms.
///
/// Sabotage that must turn this red: install straight after `Pause::Adopted`
/// without looping back to re-read the deadline (lands at ~0ms — lower bound);
/// or move adoption out of the pause site back to step (4) (lands at ~2s —
/// upper bound).
#[tokio::test]
async fn waking_early_still_waits_out_an_outstanding_reap_grace() {
    let (target, mut sig) = FakeTarget::new();
    target.fail_next(1); // exactly one wedged attempt, then the backend is fine
                         // A deliberately roomy `retry_after` for this test only: it is the window
                         // the test has to arm the fixture and publish before the pause could
                         // elapse on its own. Nothing here measures the backoff — the grace does
                         // all the gating — so a longer one costs nothing and removes a race that
                         // would otherwise show up as the wrong version being installed.
    let handle = spawn_policy_apply_worker(target.clone(), Duration::from_millis(300));

    handle.publish(ds(1));
    let (v, ok) = recv_within(
        &mut sig.done_rx,
        Duration::from_secs(5),
        "the wedged attempt",
    )
    .await;
    assert_eq!((v, ok), (1, false));

    // Armed BEFORE the publish (which is what wakes the worker), so both
    // entries are already in effect by the time the deadline is re-read.
    let grace_until = Instant::now() + Duration::from_millis(500);
    let dead_state_grace = Instant::now() + Duration::from_secs(2);
    target.set_entries(vec![
        // The enforcer the corrected state must write: a real grace
        // outstanding, as if the failed attempt had flipped it.
        FakeEntry {
            applied_version: None,
            ready_at: Some(grace_until),
        },
        // Already on v2, so irrelevant to the state being installed — but it
        // gates the superseded v1 heavily. Only a worker still holding the
        // dead state when it queries the deadline can see this.
        FakeEntry {
            applied_version: Some(2),
            ready_at: Some(dead_state_grace),
        },
    ]);
    handle.publish(ds(2));

    let (v, ok) = recv_within(&mut sig.done_rx, Duration::from_secs(5), "the install").await;
    assert_eq!((v, ok), (2, true), "the corrected state lands");

    let landed = target.installs()[1].started_at;
    assert!(
        landed >= grace_until,
        "the corrected state was installed {:?} BEFORE the outstanding reap grace \
         expired. Waking the retry pause early is a courtesy owed to the operator; the \
         grace protects in-flight packets from reading a slot that is being overwritten, \
         and is not negotiable.",
        grace_until.saturating_duration_since(landed)
    );
    assert!(
        landed < grace_until + RESPONSIVE_WITHIN,
        "the corrected state landed {:?} after its own grace expired — the grace is the \
         ONLY delay it still owes. This much overshoot means the deadline was queried \
         (and slept on) for the SUPERSEDED state, i.e. the new state was adopted too \
         late to keep the worker off a dead state's deadline.",
        landed.saturating_duration_since(grace_until)
    );
    settle_counters().await;
    assert_eq!(
        handle.failures(),
        1,
        "only the original wedged attempt failed"
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
    assert!(
        out.contains("wiremesh_gateway_policy_apply_failures_total 3"),
        "body: {out}"
    );

    // Zero must still be emitted: an absent series is indistinguishable from
    // a dead exporter, and "policy applies are failing" is exactly the alert
    // an operator needs to be able to write against a always-present series.
    let zero = wiremesh_gateway::metrics::render_policy_apply_failures(0);
    assert!(
        zero.contains("wiremesh_gateway_policy_apply_failures_total 0"),
        "body: {zero}"
    );
}
