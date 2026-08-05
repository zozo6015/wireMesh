//! F6, the pure half: the allocator must treat a RESERVED plan as taken on BOTH
//! the name and the port axis, and must fail hard rather than wrap when the
//! window is exhausted.
//!
//! ./dev.sh run "cargo test -p wiremesh-gateway --test rotation_slot_quarantine"
//!
//! # The defect this pairs with
//!
//! `plan_ifname` hands back the LOWEST free overlap slot and `plan_port` the
//! lowest free port. On the `RoleBDecision::Restart` path a teardown and an
//! allocation run back-to-back with no `.await` between them
//! (`retire_stale_overlap` -> `plan_tunnel` -> `bring_up`), so the new Device
//! was handed the very ifname and port the old one had released microseconds
//! earlier — while boringtun may not yet have unlinked
//! `/var/run/wireguard/<ifname>.sock` (which `Tunnel::up` waits for the
//! APPEARANCE of, so a stale socket satisfies it instantly) and the kernel may
//! not yet have deleted the link.
//!
//! The fix keeps `plan_tunnel` PURE and widens what it is told is taken:
//! `TunnelSet::plans()` now reports recently-torn-down plans alongside live
//! ones for a quarantine window. So the allocator itself only has to honour one
//! contract — **never hand back anything in the list it was given, on any
//! axis** — and that contract is what this file pins.
//!
//! `tests/rotation_slot_quarantine_netns.rs` pins the other half: that
//! `TunnelSet` actually puts a torn-down plan into that list, takes it out
//! again when it expires, and bounds how many it may hold.
//!
//! Nothing here asserts a naming scheme or a port formula — only that a plan
//! never collides with the reserved set, and that exhaustion is an `Err`.
use wiremesh_gateway::tunnelset::{plan_tunnel, TunnelId, TunnelPlan};

const BASE_TUN: &str = "wg0";
const BASE_PORT: u16 = 51820;
/// Mirrors `tunnelset::MAX_ROTATION_TUNS`, which is private. If the production
/// constant moves, `window_exhaustion_is_a_hard_error` below fails rather than
/// silently testing nothing.
const MAX_ROTATION_TUNS: u16 = 64;
/// Mirrors `tunnelset::MAX_QUARANTINE` — half the window, by construction.
const MAX_QUARANTINE: usize = (MAX_ROTATION_TUNS / 2) as usize;

fn boot() -> TunnelPlan {
    TunnelPlan {
        id: TunnelId::Own { epoch: 0 },
        ifname: BASE_TUN.to_string(),
        listen_port: BASE_PORT,
    }
}

fn overlap(gid: u64) -> TunnelId {
    TunnelId::Overlap { gateway_id: gid, epoch: 1 }
}

/// A plan never collides with ANYTHING it was told is reserved, on any of the
/// three axes. Checked as a helper so each caller names the scenario.
fn assert_disjoint_from_reserved(plan: &TunnelPlan, reserved: &[TunnelPlan], what: &str) {
    for r in reserved {
        assert_ne!(
            plan.ifname, r.ifname,
            "{what}: planned ifname {:?} is already reserved (by {:?}) — a reserved name may \
             still have a live kernel link or an unlinked-pending UAPI socket",
            plan.ifname, r.id
        );
        assert_ne!(
            plan.listen_port, r.listen_port,
            "{what}: planned port {} is already reserved (by {:?}) — two WG Devices cannot bind \
             the same UDP port, and a just-freed one may not be released yet",
            plan.listen_port, r.id
        );
    }
}

/// **THE F6 CASE, at the allocator.** `wg0o0` on `base+1` was just torn down
/// and is being reported as still reserved. The next overlap must get neither
/// that name nor that port — the two together are what the `Restart` path
/// handed straight back.
#[test]
fn a_reserved_freed_plan_is_reused_on_neither_axis() {
    let freed = TunnelPlan {
        id: overlap(7),
        ifname: format!("{BASE_TUN}o0"),
        listen_port: BASE_PORT + 1,
    };
    let reserved = vec![boot(), freed.clone()];

    let next = plan_tunnel(overlap(7), BASE_TUN, BASE_PORT, &reserved)
        .expect("a re-rotation must still be plannable while the previous slot is quarantined");

    assert_disjoint_from_reserved(&next, &reserved, "re-rotation over a quarantined slot");
    assert_eq!(next.id, overlap(7), "the plan is for the id it was asked about");
}

/// The PORT axis in isolation. The reserved entry holds `base+1` under a name
/// that is not in the overlap namespace at all, so the name axis is free and
/// only the port can force the allocator to move. An implementation that
/// reported quarantined names but not their ports would pass the previous test
/// and fail here — and in production would bind a UDP port a dying Device may
/// still hold.
#[test]
fn a_reserved_port_is_skipped_even_when_its_name_is_irrelevant() {
    let freed = TunnelPlan {
        id: TunnelId::Own { epoch: 9 },
        ifname: format!("{BASE_TUN}e9"),
        listen_port: BASE_PORT + 1,
    };
    let reserved = vec![boot(), freed.clone()];

    let next = plan_tunnel(overlap(7), BASE_TUN, BASE_PORT, &reserved)
        .expect("planning must succeed with 62 ports still free");

    assert_ne!(
        next.listen_port, freed.listen_port,
        "the reserved port must be skipped on its own merits, independently of the ifname"
    );
    assert_disjoint_from_reserved(&next, &reserved, "reserved port only");
}

/// The NAME axis in isolation, the mirror of the previous test: the reserved
/// entry holds `wg0o0` on a port outside the rotation window entirely, so only
/// the name can force the allocator to move.
#[test]
fn a_reserved_name_is_skipped_even_when_its_port_is_irrelevant() {
    let freed = TunnelPlan {
        id: overlap(7),
        ifname: format!("{BASE_TUN}o0"),
        listen_port: 1234,
    };
    let reserved = vec![boot(), freed.clone()];

    let next = plan_tunnel(overlap(8), BASE_TUN, BASE_PORT, &reserved)
        .expect("planning must succeed with 63 slots still free");

    assert_ne!(
        next.ifname, freed.ifname,
        "the reserved ifname must be skipped on its own merits, independently of the port"
    );
    assert_disjoint_from_reserved(&next, &reserved, "reserved name only");
}

/// Re-planning the SAME overlap id while its previous plan is reserved must
/// yield a genuinely different Device, not the same one back. This is the
/// `Restart` shape exactly: same peer, new pending epoch, previous overlap just
/// torn down.
#[test]
fn restarting_the_same_peer_gets_a_fresh_device() {
    let mut reserved = vec![boot()];
    let first = plan_tunnel(overlap(7), BASE_TUN, BASE_PORT, &reserved).expect("first overlap");
    // The Restart tears the first one down; the quarantine keeps reporting it.
    reserved.push(first.clone());
    let second = plan_tunnel(
        TunnelId::Overlap { gateway_id: 7, epoch: 2 },
        BASE_TUN,
        BASE_PORT,
        &reserved,
    )
    .expect("the restarted overlap");

    assert_ne!(
        first.ifname, second.ifname,
        "a Restart must land on a different ifname than the one it just released — reusing it \
         races boringtun's UAPI socket unlink, which Tunnel::up cannot distinguish from success"
    );
    assert_ne!(first.listen_port, second.listen_port, "and on a different UDP port");
}

/// **MAX_QUARANTINE cannot starve the allocator.** The quarantine is capped at
/// half the window precisely so that a churning gateway can always still
/// allocate. With the full 32 reserved by quarantine (plus the boot tun), the
/// remaining 32 slots and 32 ports must ALL be allocatable, each disjoint from
/// everything before it.
#[test]
fn a_full_quarantine_still_leaves_half_the_window_allocatable() {
    let mut reserved = vec![boot()];
    for i in 0..MAX_QUARANTINE {
        reserved.push(TunnelPlan {
            id: overlap(1000 + i as u64),
            ifname: format!("{BASE_TUN}o{i}"),
            listen_port: BASE_PORT + 1 + i as u16,
        });
    }

    let quarantined = reserved.clone();
    for n in 0..MAX_QUARANTINE {
        let id = overlap(n as u64);
        let plan = plan_tunnel(id, BASE_TUN, BASE_PORT, &reserved).unwrap_or_else(|e| {
            panic!(
                "allocation {n} of {MAX_QUARANTINE} must succeed with a FULL quarantine — the \
                 cap at half the window exists exactly so churn can never make the gateway \
                 unable to stand up an overlap: {e:#}"
            )
        });
        assert_disjoint_from_reserved(&plan, &quarantined, "full quarantine");
        assert_disjoint_from_reserved(&plan, &reserved, "full quarantine, cumulative");
        reserved.push(plan);
    }
}

/// Exhaustion is a HARD ERROR, never a silent wrap onto an in-use name or port.
/// Every overlap slot in the window is reserved; the planner must refuse rather
/// than hand back `wg0o0` (which the pre-fix allocator's `for slot in 0..MAX`
/// loop would never do, but a "wrap around" convenience fix would).
#[test]
fn window_exhaustion_is_a_hard_error() {
    let mut reserved = vec![boot()];
    for i in 0..MAX_ROTATION_TUNS {
        reserved.push(TunnelPlan {
            id: overlap(2000 + i as u64),
            ifname: format!("{BASE_TUN}o{i}"),
            listen_port: BASE_PORT + 1 + i,
        });
    }

    let err = plan_tunnel(overlap(1), BASE_TUN, BASE_PORT, &reserved);
    assert!(
        err.is_err(),
        "with all {MAX_ROTATION_TUNS} slots and all {MAX_ROTATION_TUNS} ports reserved the \
         planner must fail, not wrap onto an in-use resource; it returned {:?}",
        err.ok()
    );
}

/// The same exhaustion, one slot short: the LAST free slot must still be
/// handed out. A guard that failed one early would silently shrink the window.
#[test]
fn the_last_free_slot_is_still_allocatable() {
    let mut reserved = vec![boot()];
    for i in 0..(MAX_ROTATION_TUNS - 1) {
        reserved.push(TunnelPlan {
            id: overlap(3000 + i as u64),
            ifname: format!("{BASE_TUN}o{i}"),
            listen_port: BASE_PORT + 1 + i,
        });
    }

    let plan = plan_tunnel(overlap(1), BASE_TUN, BASE_PORT, &reserved)
        .expect("the single remaining slot must be allocatable");
    assert_disjoint_from_reserved(&plan, &reserved, "last free slot");
}

/// The port window never leaves `base_port + 1 ..= base_port + MAX`, whatever
/// the reserved set looks like. In particular it never returns `base_port`
/// itself — the boot tun's port — which is excluded structurally (the search
/// starts at offset 1) rather than by a check that could be forgotten.
#[test]
fn every_planned_port_stays_inside_the_rotation_window() {
    let mut reserved = vec![boot()];
    for n in 0..40u64 {
        let plan = plan_tunnel(overlap(n), BASE_TUN, BASE_PORT, &reserved)
            .unwrap_or_else(|e| panic!("allocation {n}: {e:#}"));
        assert!(
            plan.listen_port > BASE_PORT && plan.listen_port <= BASE_PORT + MAX_ROTATION_TUNS,
            "planned port {} is outside {}..={}",
            plan.listen_port,
            BASE_PORT + 1,
            BASE_PORT + MAX_ROTATION_TUNS
        );
        assert_ne!(plan.listen_port, BASE_PORT, "the boot tun's port must never be re-planned");
        reserved.push(plan);
    }
}

/// A base port so high that the whole rotation window would overflow `u16`:
/// the planner must fail rather than wrap around to a low port. `checked_add`
/// is the production guard; this is the assertion that it is load-bearing.
#[test]
fn a_port_window_that_overflows_u16_fails_rather_than_wrapping() {
    let reserved = vec![TunnelPlan {
        id: TunnelId::Own { epoch: 0 },
        ifname: BASE_TUN.to_string(),
        listen_port: u16::MAX,
    }];
    let out = plan_tunnel(overlap(1), BASE_TUN, u16::MAX, &reserved);
    assert!(
        out.is_err(),
        "base port {} leaves no in-window port; the planner must fail rather than wrap onto a \
         low, in-use port. It returned {:?}",
        u16::MAX,
        out.ok()
    );
}

/// A base port near the top of `u16`: the few ports that DO fit are usable, and
/// the ones that would overflow are simply skipped — a truncated window, not a
/// wrapped one.
#[test]
fn a_truncated_port_window_allocates_only_what_fits() {
    let base: u16 = u16::MAX - 3; // 65532: only 65533..=65535 exist
    let mut reserved = vec![TunnelPlan {
        id: TunnelId::Own { epoch: 0 },
        ifname: BASE_TUN.to_string(),
        listen_port: base,
    }];
    for n in 0..3u64 {
        let plan = plan_tunnel(overlap(n), BASE_TUN, base, &reserved)
            .unwrap_or_else(|e| panic!("port {} of the truncated window must be usable: {e:#}", n + 1));
        assert!(plan.listen_port > base, "planned port must be above the base");
        assert_disjoint_from_reserved(&plan, &reserved, "truncated window");
        reserved.push(plan);
    }
    assert!(
        plan_tunnel(overlap(99), BASE_TUN, base, &reserved).is_err(),
        "the fourth allocation has no port left and must fail rather than wrap"
    );
}
