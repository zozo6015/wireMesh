//! Backlog item 1 (Cycle-3 hardening PR-B — policy-apply worker restructure),
//! enforcer half: `apply()` must stop PARKING A THREAD to wait out the
//! previous flip's reap grace, and must instead PUBLISH that grace as a
//! cheap, non-blocking deadline its caller honors.
//!
//! ## The bug this pins away (verified on main, `src/ebpf.rs`)
//!
//! `apply_generation` currently does, before overwriting the outer-array
//! slot the previous flip vacated:
//!
//! ```ignore
//! let elapsed = pending.flipped_at.elapsed();
//! if elapsed < reap_grace {
//!     std::thread::sleep(reap_grace - elapsed);   // up to REAP_GRACE = 10s
//! }
//! ```
//!
//! With the production `EnforcerConfig::default()` (`reap_grace` = 10s,
//! `lib.rs:74` → `ebpf::REAP_GRACE`) that is a ten-second block of whatever
//! thread called `apply()`. In `wiremesh-gateway` that thread is a tokio
//! runtime thread inside the Sync loop (`main.rs`'s `apply_state` →
//! `GatewayEnforcer::apply_if_changed` → here), so one policy epoch stalls
//! `PunchDirective` servicing (a Cycle-4b go-skew violation), the metrics
//! scrape, and rotation events — and it costs N × 10s when several epochs
//! are live during a rotation overlap. See `docs/research/backlog-program-notes.md`
//! §"B10 hardening audit" item (4).
//!
//! ## The ratified design pinned here
//!
//! 1. The [`wiremesh_enforcer::Enforcer`] trait gains a cheap, non-blocking
//!    query for the earliest instant at which the next `apply` may proceed:
//!
//!    ```ignore
//!    /// The earliest instant at which the next `apply` may proceed without
//!    /// overwriting an outer-array slot that in-flight packets may still be
//!    /// reading. `None` means "no constraint" (the nftables backend never
//!    /// has one; the eBPF backend has none before its first `apply`). A
//!    /// `Some(t)` already in the past is a SATISFIED constraint.
//!    ///
//!    /// Cheap and non-blocking by contract: it never sleeps, never does
//!    /// kernel work, and never holds a lock on return — its whole purpose
//!    /// is to let an async caller `sleep_until` the deadline without
//!    /// occupying a thread.
//!    fn apply_ready_at(&self) -> Option<std::time::Instant>;
//!    ```
//!
//!    eBPF returns `pending_reap.flipped_at + reap_grace`; nftables returns
//!    `None` (one atomic `nft -f -` transaction, no generations, no grace).
//!
//! 2. `apply_generation` NO LONGER sleeps. Honoring the deadline becomes the
//!    caller's job (in the gateway, the new policy-apply worker — see
//!    `crates/wiremesh-gateway/tests/policy_apply_worker.rs`).
//!
//! **The safety property is unchanged and is still pinned here** (test (a)
//! below): the deadline the backend publishes is still `flip + reap_grace`,
//! so a caller that honors it never overwrites a slot flipped away less than
//! `reap_grace` ago. Moving the wait does not shorten it.
//!
//! ## Requires netns + privileges
//!
//! Every test in this file loads and attaches a REAL eBPF program (or shells
//! out to a real `nft`) on a `wg0` inside a netns, exactly like
//! `tests/generations.rs`/`tests/nft_backend.rs`. There is no pure seam for
//! the deadline: it lives on `EbpfEnforcer`'s private `GenerationState`, only
//! reachable through a live, loaded backend.
//!
//! ```text
//! ./dev.sh run "cargo test -p wiremesh-enforcer --test reap_deadline \
//!   -- --test-threads=1 --nocapture"
//! ```
//!
//! `mod lab`-free per this crate's convention: the netns harness comes from
//! `wiremesh-testkit`'s `netns` module (see `tests/generations.rs`'s header
//! for the graduation history). `"aethrd"` is this file's distinct `wg_lab`
//! prefix so its netns/veth names never collide with another test binary's.
//!
//! ## RED status
//!
//! COMPILE-red until `Enforcer::apply_ready_at` lands (the name + signature
//! above ARE the pinned API). Test (b) is additionally RUNTIME-red against
//! today's sleeping `apply_generation`: it measures ~10s where it demands
//! well under one second.

use std::time::{Duration, Instant};
use wiremesh_enforcer::{probe, probe_with, BackendKind, EnforcerConfig};
use wiremesh_policy::{compile, parse_policy, PolicyIR, SegmentDef};
use wiremesh_testkit::netns::{join_netns, wg_lab};

/// Exact per-host /32 segments — these tests never send a packet, so the
/// segment widths only need to make a policy that compiles.
fn segments() -> Vec<SegmentDef> {
    vec![
        SegmentDef { name: "seg-a".into(), cidrs: vec!["10.10.0.1/32".parse().unwrap()] },
        SegmentDef { name: "seg-b".into(), cidrs: vec!["10.10.0.2/32".parse().unwrap()] },
    ]
}

/// A one-rule allow policy at `version`, compiled the same way the
/// controller compiles one. Distinct `port`s give distinct rule sets, so a
/// second `apply` is genuinely a NEW generation rather than a re-install of
/// identical bytes (the backend does not short-circuit either way, but a
/// changing policy is the honest shape of the production case).
fn policy(port: u16, version: u64) -> PolicyIR {
    let segs = segments();
    let yaml = format!(
        "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow:
          proto: tcp
          ports: [{port}]
"
    );
    let src = parse_policy(&yaml, &segs)
        .unwrap_or_else(|errors| panic!("expected valid policy, got errors: {errors:?}"));
    compile(&src, &segs, version)
        .unwrap_or_else(|errors| panic!("expected compile to succeed, got errors: {errors:?}"))
}

// --- (a) the SAFETY property survives the restructure ---------------------

/// The reap grace is still honored — it just moved from a `sleep` inside
/// `apply` to a deadline the caller must wait out. Pinned as an exact
/// two-sided bound rather than an approximation:
///
/// The `ACTIVE` flip happens at some instant `flip` with
/// `before <= flip <= after` (both captured immediately around the `apply`
/// call), and the published deadline must be exactly `flip + reap_grace`.
/// Therefore `before + grace <= deadline <= after + grace` — no slack
/// constant, no tolerance to tune, and it fails loudly for ANY deadline that
/// is short of a full grace period after the flip (which is the only way a
/// deadline-honoring caller could overwrite a still-readable slot).
///
/// A deliberately non-default `reap_grace` is used so the assertion pins the
/// CONFIGURED grace (the injectable `EnforcerConfig::reap_grace`, `lib.rs:61`)
/// rather than accidentally passing against a hard-coded 10s constant.
#[test]
fn apply_ready_at_is_the_flip_instant_plus_the_configured_reap_grace() {
    let grace = Duration::from_secs(3);
    let (lab, _a, b) = wg_lab("aethrd");
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    let cfg = EnforcerConfig { reap_grace: grace, ..EnforcerConfig::default() };
    let mut enforcer = probe("wg0", cfg).expect("probe should load + attach eBPF on wg0");

    // Before the FIRST apply neither outer-array slot has ever been written
    // by us, so there is nothing to reap and nothing to wait for. `None` is
    // the design's answer; the caller-relevant property (and what is
    // asserted) is the weaker, implementation-tolerant "no deadline in the
    // future" — a boot-time apply must never be made to wait.
    if let Some(t) = enforcer.apply_ready_at() {
        assert!(
            t <= Instant::now(),
            "before the first apply there is no pending reap, so the backend must not \
             publish a FUTURE deadline (design: `None`); got one {:?} away",
            t.saturating_duration_since(Instant::now())
        );
    }

    let ir = policy(9401, 1);
    let before = Instant::now();
    enforcer.apply(&ir).expect("first apply (one allow rule) must succeed");
    let after = Instant::now();

    let deadline = enforcer
        .apply_ready_at()
        .expect("after a flip there IS a pending reap, so a deadline must be published");
    assert!(
        deadline >= before + grace,
        "the published deadline must be at least a full reap_grace ({grace:?}) after the \
         flip — anything earlier lets a deadline-honoring caller overwrite a slot that \
         in-flight packets may still be reading (deadline is {:?} after `before`)",
        deadline.saturating_duration_since(before)
    );
    assert!(
        deadline <= after + grace,
        "the published deadline must be exactly flip + reap_grace, not longer — an \
         inflated deadline needlessly delays every policy update (deadline is {:?} after \
         `after`, grace is {grace:?})",
        deadline.saturating_duration_since(after)
    );

    drop(lab);
}

/// Once the grace has genuinely elapsed the constraint is satisfied, and the
/// backend must say so: a deadline that never lapses would stall every later
/// apply forever.
///
/// Asserted as "not in the future" rather than a specific shape, because
/// BOTH shapes are correct for a caller: the design's literal
/// `Some(flipped_at + reap_grace)` (now in the past) and an implementation
/// that collapses a satisfied constraint to `None`. Pinning one over the
/// other would be pinning an implementation detail; pinning "the caller is
/// not asked to wait" is the actual contract.
#[test]
fn apply_ready_at_stops_being_a_future_deadline_once_the_grace_elapses() {
    let grace = Duration::from_millis(300);
    let (lab, _a, b) = wg_lab("aethrd");
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    let cfg = EnforcerConfig { reap_grace: grace, ..EnforcerConfig::default() };
    let mut enforcer = probe("wg0", cfg).expect("probe should load + attach eBPF on wg0");

    enforcer.apply(&policy(9402, 1)).expect("first apply must succeed");
    assert!(
        enforcer.apply_ready_at().is_some_and(|t| t > Instant::now()),
        "sanity: immediately after the flip the deadline must still be in the future, \
         otherwise the lapse assertion below would be vacuous"
    );

    std::thread::sleep(grace * 2);

    if let Some(t) = enforcer.apply_ready_at() {
        assert!(
            t <= Instant::now(),
            "{:?} after a flip with a {grace:?} grace the constraint is satisfied; the \
             backend must not still be asking the caller to wait {:?}",
            grace * 2,
            t.saturating_duration_since(Instant::now())
        );
    }

    drop(lab);
}

// --- (b) no thread blocking -----------------------------------------------

/// `apply()` must return PROMPTLY even when a reap is pending — the wait
/// belongs to the caller now.
///
/// Deliberately run at the PRODUCTION `reap_grace` (`EnforcerConfig::default()`
/// = 10s) and deliberately calls `apply` a second time immediately, i.e. as a
/// caller that has NOT honored the deadline. That is safe here (no traffic is
/// in flight in this netns, so no packet can be reading the slot being
/// overwritten) and it is the only way to observe the removed sleep: against
/// today's `apply_generation` the second call parks the thread for ~10s.
///
/// The 1s budget is ~10x the observed cost of a real single-rule generation
/// install (map creation + LPM writes + the `ACTIVE` flip) and 10x under the
/// old behavior's 10s — a margin wide enough not to flake on a loaded
/// container, and narrow enough that the old code fails it by an order of
/// magnitude rather than by a hair.
#[test]
fn apply_does_not_park_the_calling_thread_for_the_reap_grace() {
    let (lab, _a, b) = wg_lab("aethrd");
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    let cfg = EnforcerConfig::default();
    assert_eq!(
        cfg.reap_grace,
        Duration::from_secs(10),
        "this test's whole point is the PRODUCTION grace; if the default changes, the \
         budget below must be re-justified"
    );
    let mut enforcer = probe("wg0", cfg).expect("probe should load + attach eBPF on wg0");

    // First apply: no pending reap, nothing to wait for either way.
    enforcer.apply(&policy(9403, 1)).expect("first apply must succeed");
    assert!(
        enforcer.apply_ready_at().is_some_and(|t| t > Instant::now()),
        "sanity: a reap must be pending, otherwise the second apply below has nothing \
         to (not) wait for and this test proves nothing"
    );

    // Second apply, back-to-back and WELL inside the 10s grace.
    let t0 = Instant::now();
    enforcer.apply(&policy(9404, 2)).expect("second apply must succeed");
    let elapsed = t0.elapsed();

    assert!(
        elapsed < Duration::from_secs(1),
        "apply() must not sleep out the reap grace on the calling thread — it took \
         {elapsed:?} with a pending reap and a 10s grace (the old `std::thread::sleep` \
         behavior); the wait belongs to the caller, which honors `apply_ready_at()`"
    );

    // ... and the flip really did happen: the deadline advanced to the NEW
    // flip's instant, so this was a real generation install that returned
    // fast, not a silently skipped no-op.
    let deadline = enforcer.apply_ready_at().expect("the second flip has a pending reap too");
    assert!(
        deadline > t0 + Duration::from_secs(9),
        "the second apply must have really flipped (its deadline must be ~10s after it \
         ran, not left over from the first flip); deadline is {:?} after t0",
        deadline.saturating_duration_since(t0)
    );

    drop(lab);
}

/// Three applies in a row: each one republishes the deadline off ITS OWN
/// flip, so a caller that honors the deadline is serialized at exactly one
/// grace period per generation — never accumulating a backlog of stale
/// deadlines, and never letting an old satisfied deadline authorize an
/// immediate overwrite of a freshly-vacated slot.
#[test]
fn each_flip_republishes_the_deadline_from_its_own_flip_instant() {
    let grace = Duration::from_millis(500);
    let (lab, _a, b) = wg_lab("aethrd");
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    let cfg = EnforcerConfig { reap_grace: grace, ..EnforcerConfig::default() };
    let mut enforcer = probe("wg0", cfg).expect("probe should load + attach eBPF on wg0");

    let mut previous: Option<Instant> = None;
    for (i, port) in [9411u16, 9412, 9413].into_iter().enumerate() {
        // Honor the previous deadline, as a real caller now must.
        if let Some(t) = enforcer.apply_ready_at() {
            let now = Instant::now();
            if t > now {
                std::thread::sleep(t - now);
            }
        }
        let before = Instant::now();
        enforcer
            .apply(&policy(port, i as u64 + 1))
            .unwrap_or_else(|e| panic!("apply #{i} must succeed: {e:#}"));
        let deadline = enforcer
            .apply_ready_at()
            .unwrap_or_else(|| panic!("apply #{i} must publish a deadline"));

        assert!(
            deadline >= before + grace,
            "apply #{i}'s deadline must be a full grace after ITS flip, not inherited \
             from an earlier one"
        );
        if let Some(prev) = previous {
            assert!(
                deadline > prev,
                "apply #{i}'s deadline must advance past the previous flip's ({prev:?} \
                 -> {deadline:?}); a stale deadline would authorize overwriting a slot \
                 vacated moments ago"
            );
        }
        previous = Some(deadline);
    }

    drop(lab);
}

// --- (c) the nftables backend has no such constraint ----------------------

/// The nftables fallback installs a whole ruleset in one atomic `nft -f -`
/// transaction — no generations, no outer-array slots, nothing to reap — so
/// it must publish NO constraint at all, before or after an apply.
///
/// Pinned as a literal `None` (unlike the eBPF lapsed case above, where two
/// shapes are defensible): there is no pending reap to describe here, so any
/// `Some` would be a fabricated deadline that needlessly delays every policy
/// update on the fallback backend.
#[test]
fn nftables_backend_publishes_no_apply_deadline() {
    let (lab, _a, b) = wg_lab("aethrd");
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    // `probe_with` (not `probe`): eBPF always loads successfully in the dev
    // container, so a plain `probe()` would never reach the nft backend —
    // the same forced-choice rationale `tests/nft_backend.rs` documents.
    let mut enforcer = probe_with(BackendKind::Nftables, "wg0", EnforcerConfig::default())
        .expect("nftables backend should install on wg0");
    assert_eq!(enforcer.kind(), BackendKind::Nftables, "sanity: forced-choice backend");

    assert!(
        enforcer.apply_ready_at().is_none(),
        "the nftables backend has no reap grace before its first apply"
    );

    enforcer.apply(&policy(9421, 1)).expect("nft apply must succeed");
    assert!(
        enforcer.apply_ready_at().is_none(),
        "the nftables backend has no reap grace after an apply either — one atomic \
         `nft -f -` transaction replaces the ruleset, so there is no old generation to \
         protect and no reason to make the caller wait"
    );

    enforcer.apply(&policy(9422, 2)).expect("second nft apply must succeed");
    assert!(
        enforcer.apply_ready_at().is_none(),
        "still none after a back-to-back re-apply"
    );

    drop(lab);
}
