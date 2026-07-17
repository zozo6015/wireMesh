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

// Adapted inline copy of the canonical two-node WireGuard tunnel lab helper
// (spike/enforcer/enforcer/tests/common/mod.rs, itself adapted from
// spike/tunnel/tests/common/mod.rs) -- each spike crate (and now this crate,
// ahead of Task 12's graduated shared testkit harness) is standalone, so
// this is copied rather than depended on directly. `#[path]`-free per the
// brief: defined inline as its own module in this same file, not via
// `#[path = "..."] mod common;` pointing at a separate file. Adapted beyond
// the spike's literal version (see the module doc above): kernel WireGuard
// instead of the boringtun `spike-tunnel` binary, so no `SPIKE_TUNNEL_BIN`
// env var and no spawned processes to track/kill.
mod lab {
    use natlab::{Lab, Ns};
    use std::io::Write;

    fn wg_keypair() -> (String, String) {
        let priv_out = std::process::Command::new("wg")
            .arg("genkey")
            .output()
            .unwrap();
        let privkey = String::from_utf8(priv_out.stdout).unwrap().trim().to_string();
        let pub_out = {
            let mut c = std::process::Command::new("wg")
                .arg("pubkey")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            c.stdin.as_mut().unwrap().write_all(privkey.as_bytes()).unwrap();
            c.wait_with_output().unwrap()
        };
        (privkey.clone(), String::from_utf8(pub_out.stdout).unwrap().trim().to_string())
    }

    /// Returns a running lab: overlay 10.10.0.1 <-> 10.10.0.2 over underlay
    /// 10.9.1.0/24, `wg0` created via the KERNEL WireGuard implementation
    /// directly inside each namespace (`ip link add wg0 type wireguard`) --
    /// no userspace tunnel process involved, so there is nothing for the
    /// caller to kill afterward (unlike the spike's boringtun-backed
    /// version).
    pub fn wg_lab() -> (Lab, Ns, Ns) {
        let mut lab = Lab::new("aeth").unwrap();
        let a = lab.ns("a").unwrap();
        let b = lab.ns("b").unwrap();
        lab.veth((&a, "u0", "10.9.1.1/24"), (&b, "u1", "10.9.1.2/24")).unwrap();

        let (apriv, apub) = wg_keypair();
        let (bpriv, bpub) = wg_keypair();

        // `allowed-ips` is WireGuard cryptokey routing's OWN allow-list, fully
        // independent of (and evaluated before) anything the eBPF enforcer
        // sees: a packet whose src (outbound) or claimed src (inbound) falls
        // outside it is silently dropped by the kernel WG implementation
        // itself, never reaching wg0's tc classifier at all. Widened from the
        // bare peer host `/32` to the whole overlay `/24` (root-caused via a
        // bare `ping -I <alias>` repro, zero eBPF involved) so tests that
        // source traffic from secondary IP aliases on `wg0` (e.g.
        // `tests/generations.rs`'s LPM tests, which bind to `10.10.0.8`/`.9`
        // in addition to the primary `10.10.0.1`) actually reach the peer
        // instead of being dropped before the enforcer ever runs.
        for (ns, privkey, peer_pub, my_ip, _peer_ip, peer_ep) in [
            (&a, &apriv, &bpub, "10.10.0.1/24", "10.10.0.2", "10.9.1.2:51820"),
            (&b, &bpriv, &apub, "10.10.0.2/24", "10.10.0.1", "10.9.1.1:51820"),
        ] {
            ns.exec(&["ip", "link", "add", "wg0", "type", "wireguard"]).unwrap();
            let kf = format!("/tmp/{}.key", ns.name);
            std::fs::write(&kf, privkey).unwrap();
            ns.exec(&[
                "wg", "set", "wg0", "listen-port", "51820", "private-key", &kf,
                "peer", peer_pub, "allowed-ips", "10.10.0.0/24",
                "endpoint", peer_ep,
            ]).unwrap();
            ns.exec(&["ip", "addr", "add", my_ip, "dev", "wg0"]).unwrap();
            ns.exec(&["ip", "link", "set", "wg0", "up", "mtu", "1280"]).unwrap();
        }

        (lab, a, b)
    }
}

use lab::wg_lab;

/// Joins the CALLING OS thread to `ns_name`'s network namespace via
/// `setns(2)`/`CLONE_NEWNET`, so subsequent in-process library calls
/// (`probe`/`apply`) run as if executing inside that namespace -- the same
/// effect `ip netns exec` gets a subprocess (what the spike's binary-based
/// tests use instead), but there is no `wiremesh-enforcer` CLI binary here,
/// only the library. Safe to do from a test: libtest always runs each
/// `#[test]` fn on its own freshly spawned OS thread (true even under
/// `--test-threads=1`, which only bounds how many run *concurrently* -- see
/// CLAUDE.md's "Network tests are serial" rule), and Linux namespace
/// membership changed via `setns` is scoped to the calling thread alone, not
/// the whole process -- so this cannot leak into any other test.
///
/// Only joins the NETWORK namespace, not `b`'s private mount namespace
/// (`natlab::Ns::exec`/`spawn` additionally `nsenter --mount=...` for a
/// boringtun UAPI-socket collision reason documented in
/// `spike/natlab/src/lib.rs` -- moot here now that this lab uses kernel
/// WireGuard, not boringtun, but harmless either way since this test runs
/// exactly one enforcer instance, no concurrent same-named pins/sockets to
/// disambiguate).
fn join_netns(ns_name: &str) -> anyhow::Result<()> {
    use std::os::unix::io::AsRawFd;
    let path = format!("/var/run/netns/{ns_name}");
    let file = std::fs::File::open(&path)
        .map_err(|e| anyhow::anyhow!("open {path}: {e}"))?;
    let rc = unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) };
    if rc != 0 {
        anyhow::bail!(
            "setns({path}, CLONE_NEWNET) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

#[test]
fn probe_attaches_ebpf_and_applies_empty_policy_on_wg0() {
    let (lab, _a, b) = wg_lab();
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
    let (lab, a, b) = wg_lab();
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
