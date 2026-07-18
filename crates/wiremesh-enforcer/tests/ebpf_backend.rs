//! Task 7, Step 1 (test author): the one privileged smoke test for this
//! task -- proves `probe()` actually loads+attaches the real eBPF backend on
//! a live WireGuard tun device inside a netns, and that `apply()` of an
//! empty `PolicyIR` succeeds against that live attachment. Per
//! `.superpowers/sdd/task-7-brief.md`'s Step 1: "in a netns with a
//! veth-backed WireGuard pair (harness arrives fully in Task 12 -- for this
//! smoke test copy the spike's `wg_lab` helper inline as a `#[path]`-free
//! local `mod`), `probe("wg0", ..)` returns `BackendKind::Ebpf` and
//! `apply(&empty_ir)` succeeds."
//!
//! NOT `#[ignore]`d (per the brief and CLAUDE.md: "Host is macOS; all
//! code/tests run inside the privileged Linux container ... tun/eBPF/netns/
//! nftables do not work on the host" -- the dev container this always runs
//! in via `./dev.sh run` is always privileged).
//!
//! Self-sufficient under the plain canonical command -- NO env var, NO
//! out-of-band build required:
//! ```text
//! ./dev.sh run "cargo test -p wiremesh-enforcer -- --test-threads=1 --nocapture"
//! ```
//! `mod lab` below uses the KERNEL WireGuard implementation directly
//! (`ip link add wgN type wireguard`) rather than the Phase 0 spike's
//! boringtun-based `spike-tunnel` userspace binary (which the spike's own
//! `wg_lab`, `spike/enforcer/enforcer/tests/common/mod.rs`, requires via a
//! pre-built binary path in `SPIKE_TUNNEL_BIN` -- fine for that spike, since
//! its own test harness always sets the env var, but not self-sufficient for
//! a bare `cargo test` here). This container's kernel (6.12.x-linuxkit) has
//! the `wireguard` netlink link type built in -- confirmed manually (`ip
//! link add wg-test type wireguard` inside `./dev.sh run`, then a full
//! two-netns kernel-WG lab that actually pings end to end) -- so no
//! userspace tunnel process/binary is needed at all: `ip link add wg0 type
//! wireguard` + `wg set` (same CLI the spike already uses to configure keys/
//! peers/allowed-ips) is the entire data plane, with nothing to spawn or
//! kill afterward.
//!
//! RED evidence (current skeleton): `probe`'s body is `todo!()` (Task 7 Step
//! 1's skeleton, `src/lib.rs`) -- the test below panics with that message
//! (after successfully bringing up the lab) until Step 3 (implementer) fills
//! in the real eBPF loader in `src/ebpf.rs` (not yet created).

// (Task 12) `wg_lab`/`join_netns` graduated into `wiremesh-testkit`'s
// `netns` module -- see that module's doc comments for the full history
// (this file's previous inline `mod lab` + `fn join_netns` copies, adapted
// from `spike/enforcer/enforcer/tests/common/mod.rs`, are now that module's
// single source of truth). `"aeth"` is this file's distinct `wg_lab` prefix,
// unchanged from its pre-graduation `Lab::new("aeth")` call -- kept so this
// file's netns/veth names still never collide with another test binary's
// lab running concurrently.
use wiremesh_testkit::netns::{join_netns, wg_lab};

#[test]
fn probe_attaches_ebpf_and_applies_empty_policy_on_wg0() {
    let (lab, _a, b) = wg_lab("aeth");
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    let mut enforcer =
        wiremesh_enforcer::probe("wg0", wiremesh_enforcer::EnforcerConfig::default())
            .expect("probe should load + attach eBPF on wg0 inside the privileged dev container");
    assert_eq!(
        enforcer.kind(),
        wiremesh_enforcer::BackendKind::Ebpf,
        "the privileged dev container always has eBPF available -- probe must pick it, not \
         fall back to nftables"
    );

    let empty_ir = wiremesh_policy::PolicyIR {
        schema: 1,
        version: 0,
        blocks: vec![],
    };
    enforcer
        .apply(&empty_ir)
        .expect("apply of an empty policy IR should succeed");

    drop(lab);
}

/// Task 7 review finding (Important): `EbpfEnforcer` discards the `LinkId`s
/// its two tc-classifier `.attach()` calls return and has no `Drop` impl of
/// its own -- so whether dropping an `Enforcer` actually detaches the tc
/// classifier (clean teardown) or leaks it in the kernel was unverified.
/// Task 8's reload path (drop the current `Enforcer`, then `probe()` the
/// same still-live iface again) depends on the answer either way. This test
/// investigates empirically rather than assuming:
///
///  1. `probe("wg0")`, `apply()` an EMPTY policy (default-deny -- the same
///     already-proven-observable mechanism
///     `spike/enforcer/enforcer/tests/enforce.rs`'s
///     `default_deny_drops_overlay_ping_and_counts` uses): ping a->b must
///     now FAIL, confirming enforcement is live.
///  2. `drop()` the first `Enforcer`, then -- the STRONGEST form, attempted
///     per the brief rather than skipped -- ping a->b BEFORE re-probing:
///     if the tc classifier was cleanly detached on drop, default-deny is
///     gone and ping should SUCCEED again; if it's still blocked, the
///     attachment outlived the Rust value that "owned" it. Logged via
///     `eprintln!` either way (not asserted on) -- see the note below on
///     why this is observation, not a pass/fail gate.
///  3. `probe("wg0")` a SECOND time, on the same live iface, must still
///     succeed (Task 8's exact dependency) and `apply()` on the new handle
///     must succeed and actively re-enforce default-deny (ping fails
///     again) -- true regardless of what step 2 found, since a leaked
///     first attachment would at worst stack with the second, not prevent
///     it from also denying.
///
/// Deliberately not a hard assertion on step 2's outcome: this is a real
/// open question about aya's tc attach semantics on this kernel (legacy
/// netlink tc filters historically outlive the loader process; the design
/// doc's §6 mentions the newer TCX link API on >= 6.6 kernels, which DOES
/// tie attachment lifetime to an open link fd -- this container's kernel is
/// 6.12.x) that this test is designed to answer by running it, not to
/// enforce a predetermined answer -- per CLAUDE.md, a "failing" behavior
/// here would be a real finding about the design, investigated and
/// recorded, not a test to weaken until it's green. Steps 1 and 3 (the
/// re-probe-succeeds contract Task 8 needs) ARE hard assertions.
#[test]
fn dropping_enforcer_detaches_and_allows_reprobe_on_same_iface() {
    let (lab, a, b) = wg_lab("aeth");
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    // Sanity: the kernel-WG tunnel alone (no enforcer attached yet) passes ICMP.
    assert!(
        a.exec(&["ping", "-c", "1", "-W", "3", "10.10.0.2"]).is_ok(),
        "overlay ping should work before any enforcer is attached"
    );

    let empty_ir = wiremesh_policy::PolicyIR {
        schema: 1,
        version: 0,
        blocks: vec![],
    };

    // --- First instance: attach + default-deny, confirm it's live. ---
    let mut enforcer1 =
        wiremesh_enforcer::probe("wg0", wiremesh_enforcer::EnforcerConfig::default())
            .expect("first probe should load + attach eBPF on wg0");
    enforcer1
        .apply(&empty_ir)
        .expect("apply of an empty policy IR should succeed on the first instance");
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(
        a.exec(&["ping", "-c", "2", "-W", "2", "10.10.0.2"]).is_err(),
        "default-deny from the first Enforcer instance should block ping"
    );

    // --- Drop it, then observe whether the tc attachment actually went away. ---
    drop(enforcer1);
    std::thread::sleep(std::time::Duration::from_millis(300));
    let ping_after_drop = a.exec(&["ping", "-c", "2", "-W", "2", "10.10.0.2"]);
    eprintln!(
        "dropping_enforcer_detaches_and_allows_reprobe_on_same_iface: ping after drop, \
         before re-probe: {}",
        if ping_after_drop.is_ok() {
            "SUCCEEDED -- tc classifier appears to have cleanly detached on Drop"
        } else {
            "still BLOCKED -- tc attachment outlived Drop (leaked); Task 8's reload path \
             will need an explicit detach, not just letting the Enforcer fall out of scope"
        }
    );

    // --- Re-probe the SAME live iface: Task 8's exact dependency. ---
    let mut enforcer2 =
        wiremesh_enforcer::probe("wg0", wiremesh_enforcer::EnforcerConfig::default())
            .expect("re-probe on the same iface after dropping the first instance must succeed");
    enforcer2
        .apply(&empty_ir)
        .expect("apply on the re-probed instance must succeed");
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(
        a.exec(&["ping", "-c", "2", "-W", "2", "10.10.0.2"]).is_err(),
        "default-deny from the SECOND Enforcer instance should block ping again"
    );

    drop(lab);
}
