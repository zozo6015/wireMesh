//! F6, the stateful half: `TunnelSet` must hold a torn-down rotation tun's
//! ifname AND port in quarantine, report them from `plans()` so the pure
//! allocator skips them, release them when the window elapses, drop a
//! quarantine entry that a `bring_up` has re-taken, and never let the
//! quarantine eat more than half the allocation window.
//!
//! ./dev.sh run "cargo test -p wiremesh-gateway --test rotation_slot_quarantine_netns \
//!   --features netns-tests -- --test-threads=1 --nocapture"
//!
//! # The defect these tests pin
//!
//! `plan_ifname` hands back the lowest free overlap slot and `plan_port` the
//! lowest free port, so a teardown immediately followed by an allocation
//! returned the very name and port just released. `RoleBDecision::Restart` runs
//! exactly that sequence with no `.await` between the two halves
//! (`retire_stale_overlap` -> `plan_tunnel` -> `bring_up`), i.e. microseconds
//! apart — and neither half of a teardown is synchronous:
//!
//!  - dropping the `Tunnel` stops boringtun's threads, but
//!    `/var/run/wireguard/<ifname>.sock` need not be unlinked yet, and
//!    `Tunnel::up` waits for that exact path to APPEAR — a stale socket
//!    satisfies the wait instantly and the caller then talks UAPI to a dead
//!    listener;
//!  - `ip link del` is best-effort and may still be in progress (or may have
//!    failed outright, which is only logged).
//!
//! # Why this file needs a netns rather than being pure
//!
//! The quarantine is only ever populated by `TunnelSet::tear_down`, which
//! requires a Device to have been brought up — a real kernel link, a real
//! boringtun `DeviceHandle`, a real UDP bind. The allocator half of F6 IS pure
//! and lives in `tests/rotation_slot_quarantine.rs`; everything that needs the
//! set's own bookkeeping is here.
//!
//! Model: `tunnelset_same_epoch_netns.rs` — one netns, no veth, no traffic.
//! Two of these tests are deliberately slow: the quarantine window is 5s of
//! wall clock and `TunnelSet` exposes no clock seam, so expiry can only be
//! observed by waiting for it.
#![cfg(feature = "netns-tests")]
use std::process::Command;
use std::time::{Duration, Instant};
use wiremesh_gateway::tunnelset::{plan_tunnel, TunnelId, TunnelPlan, TunnelSet};
use wiremesh_gateway::uapi::base64_pub_from_priv;
use wiremesh_testkit::netns::{join_netns_and_mountns, Lab};

const BASE_TUN: &str = "wg0";
const BASE_PORT: u16 = 51820;

/// Mirrors the private `tunnelset::QUARANTINE`. If the production window
/// changes, `quarantine_expires_and_the_slot_becomes_reusable` fails loudly
/// rather than quietly testing the wrong thing.
const QUARANTINE: Duration = Duration::from_secs(5);
/// Mirrors the private `tunnelset::MAX_QUARANTINE` (half of the 64-slot
/// `MAX_ROTATION_TUNS` window).
const MAX_QUARANTINE: usize = 32;

/// `wg genkey`, round-tripped through the real pubkey derivation so a bad key
/// fails here rather than deep inside boringtun (as `tunnelset_netns.rs` does).
fn gen_priv() -> String {
    let out = Command::new("wg").arg("genkey").output().unwrap();
    let priv_b64 = String::from_utf8(out.stdout).unwrap().trim().to_string();
    base64_pub_from_priv(&priv_b64).unwrap();
    priv_b64
}

fn has_ifname(plans: &[TunnelPlan], ifname: &str) -> bool {
    plans.iter().any(|p| p.ifname == ifname)
}

fn has_port(plans: &[TunnelPlan], port: u16) -> bool {
    plans.iter().any(|p| p.listen_port == port)
}

/// Bring up the boot tun (base name, base port — never planned, OD-1) and
/// return the set plus its private key, which every overlap reuses exactly as
/// `maybe_start_role_b` does.
fn set_with_boot_tun(boot_id: TunnelId) -> (TunnelSet, String) {
    let mut set = TunnelSet::new();
    let priv_b64 = gen_priv();
    set.bring_up(boot_id, BASE_TUN, &priv_b64, BASE_PORT, 1280)
        .expect("the boot tun must come up");
    (set, priv_b64)
}

/// **THE F6 CASE.** Stand up an overlap, tear it down, and immediately re-plan
/// — precisely the `Restart` sequence. The freed ifname and the freed port must
/// BOTH still be reported by `plans()`, so the allocator moves on, and the new
/// Device must actually come up on the slot it was given.
#[test]
fn a_freed_slot_is_not_handed_straight_back() {
    let mut lab = Lab::new("quarfree").unwrap();
    let a = lab.ns("a").unwrap();
    join_netns_and_mountns(&a).unwrap();

    let boot_id = TunnelId::Own { epoch: 1 };
    let (mut set, priv_b64) = set_with_boot_tun(boot_id);

    // Peer 7 rotates to pending epoch 1: stand an overlap up.
    let first_id = TunnelId::Overlap { gateway_id: 7, epoch: 1 };
    let first = plan_tunnel(first_id, BASE_TUN, BASE_PORT, &set.plans()).expect("first overlap");
    set.bring_up(first_id, &first.ifname, &priv_b64, first.listen_port, 1280)
        .expect("the first overlap Device must come up");

    // Peer 7 re-rotates to pending epoch 2: retire the stale overlap and
    // immediately plan the replacement, with nothing in between.
    set.tear_down(first_id).expect("retiring the stale overlap");
    assert!(set.get(first_id).is_none(), "the torn-down overlap must be out of the live set");

    let reserved = set.plans();
    assert!(
        has_ifname(&reserved, &first.ifname),
        "plans() must still report the just-freed ifname {:?} as reserved — boringtun may not \
         have unlinked its UAPI socket yet, and Tunnel::up cannot tell a stale socket from a new \
         one. plans() = {reserved:?}",
        first.ifname
    );
    assert!(
        has_port(&reserved, first.listen_port),
        "plans() must still report the just-freed port {} as reserved — the dying Device may \
         still hold the UDP bind. plans() = {reserved:?}",
        first.listen_port
    );

    let second_id = TunnelId::Overlap { gateway_id: 7, epoch: 2 };
    let second = plan_tunnel(second_id, BASE_TUN, BASE_PORT, &reserved)
        .expect("the restarted overlap must still be plannable");
    assert_ne!(
        second.ifname, first.ifname,
        "the Restart must not reuse the ifname it released microseconds ago"
    );
    assert_ne!(
        second.listen_port, first.listen_port,
        "the Restart must not reuse the listen port it released microseconds ago"
    );

    // And the plan is realizable: the whole point is a Device that is actually
    // new, not merely differently named.
    set.bring_up(second_id, &second.ifname, &priv_b64, second.listen_port, 1280)
        .expect("the restarted overlap Device must come up on its fresh slot");
    let out = Command::new("wg").args(["show", &second.ifname]).output().unwrap();
    assert!(out.status.success(), "wg show {} must succeed", second.ifname);
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .contains(&format!("listening port: {}", second.listen_port)),
        "the restarted overlap must be listening on its own port"
    );

    drop(lab);
}

/// The quarantine is a WINDOW, not a permanent reservation: once it elapses the
/// slot and port must become allocatable again, or a long-lived gateway would
/// leak allocation space one rotation at a time.
///
/// **Slow by necessity.** `TunnelSet` exposes no clock seam and adding one
/// would be a production change, so this waits out the real 5s window (plus a
/// small margin). Nothing else here sleeps.
#[test]
fn quarantine_expires_and_the_slot_becomes_reusable() {
    let mut lab = Lab::new("quarexp").unwrap();
    let a = lab.ns("a").unwrap();
    join_netns_and_mountns(&a).unwrap();

    let boot_id = TunnelId::Own { epoch: 1 };
    let (mut set, priv_b64) = set_with_boot_tun(boot_id);

    let id = TunnelId::Overlap { gateway_id: 7, epoch: 1 };
    let plan = plan_tunnel(id, BASE_TUN, BASE_PORT, &set.plans()).expect("overlap plan");
    set.bring_up(id, &plan.ifname, &priv_b64, plan.listen_port, 1280).unwrap();
    set.tear_down(id).unwrap();

    assert!(
        has_ifname(&set.plans(), &plan.ifname),
        "immediately after tear_down the slot is quarantined"
    );

    std::thread::sleep(QUARANTINE + Duration::from_millis(500));

    let reserved = set.plans();
    assert!(
        !has_ifname(&reserved, &plan.ifname),
        "after the {QUARANTINE:?} window the freed ifname {:?} must no longer be reported as \
         reserved — a permanent reservation would leak one slot per rotation. plans() = \
         {reserved:?}",
        plan.ifname
    );
    assert!(
        !has_port(&reserved, plan.listen_port),
        "and neither must the freed port {}. plans() = {reserved:?}",
        plan.listen_port
    );

    let again = plan_tunnel(
        TunnelId::Overlap { gateway_id: 8, epoch: 1 },
        BASE_TUN,
        BASE_PORT,
        &reserved,
    )
    .expect("planning after the quarantine expired");
    assert_eq!(
        (again.ifname.as_str(), again.listen_port),
        (plan.ifname.as_str(), plan.listen_port),
        "the lowest-free allocator must hand the expired slot back out — the quarantine delays \
         reuse, it does not retire the slot"
    );

    // And it is genuinely usable again, not just nameable.
    set.bring_up(
        TunnelId::Overlap { gateway_id: 8, epoch: 1 },
        &again.ifname,
        &priv_b64,
        again.listen_port,
        1280,
    )
    .expect("the recycled slot must be usable once the quarantine has expired");

    drop(lab);
}

/// A `bring_up` that re-takes a quarantined ifname/port must clear the
/// quarantine entry, or `plans()` would report the SAME resource twice — once
/// as live and once as reserved — and the allocator's view of what is free
/// would be wrong in a way that only shows up under churn.
///
/// The re-taking `bring_up` here uses a DIFFERENT `TunnelId` on the same
/// ifname and port, which is the shape that would double-report if the clear
/// keyed on the id alone.
#[test]
fn bring_up_clears_a_matching_quarantine_entry() {
    let mut lab = Lab::new("quarclr").unwrap();
    let a = lab.ns("a").unwrap();
    join_netns_and_mountns(&a).unwrap();

    let boot_id = TunnelId::Own { epoch: 1 };
    let (mut set, priv_b64) = set_with_boot_tun(boot_id);

    let first_id = TunnelId::Overlap { gateway_id: 7, epoch: 1 };
    let plan = plan_tunnel(first_id, BASE_TUN, BASE_PORT, &set.plans()).expect("overlap plan");
    set.bring_up(first_id, &plan.ifname, &priv_b64, plan.listen_port, 1280).unwrap();
    set.tear_down(first_id).unwrap();
    assert!(has_ifname(&set.plans(), &plan.ifname), "quarantined after tear_down");

    // A different overlap deliberately re-takes the quarantined name+port
    // (what the boot path, or a caller holding an older plan, would do).
    let second_id = TunnelId::Overlap { gateway_id: 99, epoch: 5 };
    set.bring_up(second_id, &plan.ifname, &priv_b64, plan.listen_port, 1280)
        .expect("re-taking a quarantined slot explicitly must be allowed — it is not live");

    let reserved = set.plans();
    assert_eq!(
        reserved.iter().filter(|p| p.ifname == plan.ifname).count(),
        1,
        "the ifname must be reported EXACTLY once (live), not twice (live + a stale quarantine \
         entry). plans() = {reserved:?}"
    );
    assert_eq!(
        reserved.iter().filter(|p| p.listen_port == plan.listen_port).count(),
        1,
        "and the port exactly once. plans() = {reserved:?}"
    );
    assert_eq!(
        reserved.len(),
        2,
        "only the boot tun and the re-taken overlap are reserved. plans() = {reserved:?}"
    );

    drop(lab);
}

/// **The quarantine must never starve the allocator.** `MAX_QUARANTINE` caps it
/// at half the 64-slot window and evicts OLDEST-FIRST, so even a gateway
/// churning overlaps as fast as it can always has 32 slots and 32 ports free.
///
/// Churns 33 distinct slots — one more than the cap — and asserts, in order of
/// how much they depend on the machine being fast:
///
///  - unconditionally: at most `MAX_QUARANTINE` entries are reserved by the
///    quarantine, the OLDEST is no longer among them, the NEWEST still is, and
///    a fresh allocation still succeeds;
///  - when the whole churn provably fit inside one quarantine window (so
///    nothing could have expired): exactly `MAX_QUARANTINE` remain, which is
///    the eviction path rather than the expiry path.
#[test]
fn quarantine_is_capped_at_half_the_window_and_evicts_oldest_first() {
    let mut lab = Lab::new("quarcap").unwrap();
    let a = lab.ns("a").unwrap();
    join_netns_and_mountns(&a).unwrap();

    let boot_id = TunnelId::Own { epoch: 1 };
    let (mut set, priv_b64) = set_with_boot_tun(boot_id);

    // One more than the cap, each on its own ifname and port so no bring_up
    // clears an earlier quarantine entry.
    let churn = MAX_QUARANTINE + 1;
    let mut freed: Vec<TunnelPlan> = Vec::new();
    let started = Instant::now();
    for i in 0..churn {
        let id = TunnelId::Overlap { gateway_id: 1000 + i as u64, epoch: 1 };
        let ifname = format!("{BASE_TUN}o{i}");
        let port = BASE_PORT + 1 + i as u16;
        set.bring_up(id, &ifname, &priv_b64, port, 1280)
            .unwrap_or_else(|e| panic!("churn {i}: bring_up {ifname}:{port}: {e:#}"));
        set.tear_down(id).unwrap_or_else(|e| panic!("churn {i}: tear_down {ifname}: {e:#}"));
        freed.push(TunnelPlan { id, ifname, listen_port: port });
    }
    let elapsed = started.elapsed();

    let reserved = set.plans();
    // The boot tun is live; everything else in `plans()` is quarantine.
    let quarantined: Vec<&TunnelPlan> = reserved.iter().filter(|p| p.ifname != BASE_TUN).collect();

    assert!(
        quarantined.len() <= MAX_QUARANTINE,
        "the quarantine must never hold more than {MAX_QUARANTINE} entries (half the 64-slot \
         window), or churn could make the gateway unable to stand up an overlap at all; it held \
         {} after {churn} teardowns. plans() = {reserved:?}",
        quarantined.len()
    );

    let oldest = &freed[0];
    let newest = &freed[churn - 1];
    assert!(
        !has_ifname(&reserved, &oldest.ifname),
        "the OLDEST teardown ({:?}) must be the one dropped — it has been down longest and is \
         likeliest to be truly gone. plans() = {reserved:?}",
        oldest.ifname
    );
    assert!(
        has_ifname(&reserved, &newest.ifname) && has_port(&reserved, newest.listen_port),
        "the NEWEST teardown ({:?} on {}) must still be quarantined — it was released \
         microseconds ago, which is exactly the case the quarantine exists for. plans() = \
         {reserved:?}",
        newest.ifname,
        newest.listen_port
    );

    // At least half the window is still allocatable, which is the whole reason
    // the cap exists.
    let next = plan_tunnel(
        TunnelId::Overlap { gateway_id: 7, epoch: 9 },
        BASE_TUN,
        BASE_PORT,
        &reserved,
    )
    .expect("an overlap must still be plannable after saturating the quarantine");
    for p in &reserved {
        assert_ne!(next.ifname, p.ifname, "the new plan must avoid every reserved ifname");
        assert_ne!(next.listen_port, p.listen_port, "and every reserved port");
    }

    // Strictly stronger claim, available only when nothing could have expired:
    // the drop above was EVICTION, not the 5s window elapsing.
    if elapsed < QUARANTINE {
        assert_eq!(
            quarantined.len(),
            MAX_QUARANTINE,
            "the {churn} teardowns took {elapsed:?}, all inside the {QUARANTINE:?} window, so \
             none can have expired: exactly {MAX_QUARANTINE} must remain and the missing one \
             must have been EVICTED oldest-first. plans() = {reserved:?}"
        );
    } else {
        eprintln!(
            "note: the {churn}-teardown churn took {elapsed:?}, which exceeds the {QUARANTINE:?} \
             quarantine window — the oldest entries may have EXPIRED rather than been evicted, \
             so this run did not exercise the MAX_QUARANTINE eviction path. The unconditional \
             assertions above still hold."
        );
    }

    drop(lab);
}
