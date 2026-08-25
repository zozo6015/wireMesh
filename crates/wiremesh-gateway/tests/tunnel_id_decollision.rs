//! Key-rotation T3: the `TunnelSet` three-axis collision between an OWN-epoch
//! tun and a Role-B OVERLAP tun that happen to carry the same epoch NUMBER.
//!
//! ./dev.sh run "cargo test -p wiremesh-gateway --test tunnel_id_decollision"
//!
//! # The defect these tests pin
//!
//! `TunnelSet` is keyed by a bare `u32` epoch that means **two different
//! things** depending on who inserted it:
//!
//! | | Role A (our own new tun) | Role B (overlap toward a rotating peer) |
//! |---|---|---|
//! | map key   | `n` (`main.rs:3692`)                | `pending_epoch` (`main.rs:3794`) |
//! | ifname    | `{base}e{n}` (`main.rs:3690`)       | `{base}e{pending_epoch}` (`main.rs:3772`) |
//! | port      | `base + (n - active)` (`:3688`)     | `base + (pending - peer_active)` (`:3770`) |
//!
//! All three axes collide the moment the two epoch numbers coincide, and
//! `initiate_due_rotations` (`controller/services/sync.rs:640-688`) walks
//! **every** active gateway off one global 30-day timer with no per-gateway
//! key-age filter — so the whole fabric marches N -> N+1 in the same tick and
//! the coincidence is the DEFAULT case, not an edge case. See
//! `docs/research/key-rotation-plan-verification.md` (headline + F3/F8).
//!
//! # What is pinned here, and what deliberately is NOT
//!
//! These are **behavioural** assertions about a de-collision decision, not
//! about a naming scheme. Nothing below asserts a literal ifname, a literal
//! port, or a port *formula*: the implementer is free to pick any scheme
//! (suffix, slot index, hash, allocator) as long as the resulting triples are
//! pairwise distinct on all three axes and every ifname clears the kernel's
//! 15-byte `IFNAMSIZ` budget. A scheme that de-collides the map key but leaves
//! the ifname or the port shared is still broken — two links cannot share a
//! name and two sockets cannot share a port — which is why each axis is
//! asserted separately rather than as one bundled "plans differ".
//!
//! # Production seam this file requires (does NOT exist yet — COMPILE-RED)
//!
//! In `crates/wiremesh-gateway/src/tunnelset.rs`:
//!
//! ```ignore
//! /// Identity of one live Device in a `TunnelSet`. Replaces the bare `u32`
//! /// epoch, which conflated our own epochs with peers' pending epochs.
//! #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
//! pub enum TunnelId {
//!     /// This gateway's own key epoch (the boot/active tun, or Role A's new one).
//!     Own { epoch: u32 },
//!     /// A transient Role-B overlap Device toward peer `gateway_id`'s
//!     /// pending epoch `epoch`. Runs OUR active key; the epoch is THEIRS.
//!     Overlap { gateway_id: u64, epoch: u32 },
//! }
//!
//! /// The three per-Device resources a tun needs, derived together so they
//! /// cannot drift apart: map key, interface name, WG listen port.
//! #[derive(Debug, Clone, PartialEq, Eq)]
//! pub struct TunnelPlan {
//!     pub id: TunnelId,
//!     pub ifname: String,
//!     pub listen_port: u16,
//! }
//!
//! /// Derive the plan for `id` against everything already live (`live`),
//! /// which the returned plan must not collide with on ANY of the three axes.
//! /// Pure: no I/O, no devices, safe to call anywhere. Returns `Err` rather
//! /// than emitting an ifname the kernel or `validate_iface` would reject.
//! pub fn plan_tunnel(
//!     id: TunnelId,
//!     base_tun: &str,
//!     base_port: u16,
//!     live: &[TunnelPlan],
//! ) -> anyhow::Result<TunnelPlan>;
//! ```
//!
//! `live` is load-bearing rather than decorative: the boot tun is NOT planned
//! (it is `base_tun` at `base_port` by definition, `main.rs:476-482`, OD-1), so
//! the only way `plan_tunnel` can honour F8's "don't collide with the active
//! tun" is to be told what is already up. A scheme that is injective by
//! construction may ignore the argument and still pass every test here.
use wiremesh_gateway::tunnelset::{plan_tunnel, TunnelId, TunnelPlan};

const BASE_TUN: &str = "wg0";
const BASE_PORT: u16 = 51820;

/// Standalone mirror of `wiremesh_enforcer::validate_iface`
/// (`crates/wiremesh-enforcer/src/lib.rs:235-251`), which is `pub(crate)` and
/// therefore invisible to this test crate. Kept byte-for-byte equivalent in
/// its accept/reject decision: non-empty, at most 15 BYTES (kernel IFNAMSIZ is
/// 15 + NUL), charset `[A-Za-z0-9_.-]`, not leading `-` (reads as an option
/// flag to every CLI the name reaches) or `.` (path traversal in bpffs pins).
/// A name that fails this surfaces in production only as a late, opaque
/// tc-attach failure, long after the Device is half-built.
fn iface_is_valid(iface: &str) -> bool {
    let charset_ok = iface
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    !iface.is_empty()
        && iface.len() <= 15
        && charset_ok
        && !iface.starts_with('-')
        && !iface.starts_with('.')
}

/// Assert two plans are distinct on ALL THREE axes independently. Separate
/// assertions (not one `assert_ne!(a, b)`) because a partial fix — distinct
/// keys, shared ifname — must fail loudly and name the axis it broke.
fn assert_three_way_distinct(a: &TunnelPlan, b: &TunnelPlan, what: &str) {
    assert_ne!(
        a.id, b.id,
        "{what}: map keys collide ({:?}) — `TunnelSet::bring_up` bails on a duplicate key and the \
         `?` at main.rs:3794 aborts the whole peer loop",
        a.id
    );
    assert_ne!(
        a.ifname, b.ifname,
        "{what}: ifnames collide ({:?}) — two tun links cannot share a name, and boringtun's UAPI \
         socket path `/var/run/wireguard/<ifname>.sock` is derived from it",
        a.ifname
    );
    assert_ne!(
        a.listen_port, b.listen_port,
        "{what}: listen ports collide ({}) — two WG Devices cannot bind the same UDP port",
        a.listen_port
    );
}

fn assert_plan_wellformed(p: &TunnelPlan, id: TunnelId) {
    assert_eq!(
        p.id, id,
        "plan_tunnel must return a plan for the id it was asked about"
    );
    assert!(
        iface_is_valid(&p.ifname),
        "planned ifname {:?} ({} bytes) would be rejected by the enforcer's validate_iface / the \
         kernel's IFNAMSIZ",
        p.ifname,
        p.ifname.len()
    );
}

/// **THE CORE DEFECT.** The fabric marches in step, so this gateway sitting at
/// active epoch 1 meets a peer that is rotating to pending epoch 1. Today Role
/// B computes `bring_up(1, "wg0e1", base+1)` and collides head-on with our own
/// ACTIVE tun's map entry (verification headline: "Jitter is NOT a
/// mitigation"). Both must be able to be live at once.
#[test]
fn own_active_and_overlap_at_the_same_epoch_number_coexist() {
    // The boot/active tun is not planned — it IS the base tun at the base
    // port (main.rs:476-482, OD-1). Seed it into `live` exactly as the gateway
    // would, so the planner has to route around it.
    let own_active = TunnelPlan {
        id: TunnelId::Own { epoch: 1 },
        ifname: BASE_TUN.to_string(),
        listen_port: BASE_PORT,
    };

    let overlap_id = TunnelId::Overlap {
        gateway_id: 7,
        epoch: 1,
    };
    let overlap = plan_tunnel(
        overlap_id,
        BASE_TUN,
        BASE_PORT,
        std::slice::from_ref(&own_active),
    )
    .expect(
        "planning a Role-B overlap toward peer 7's pending epoch 1 must succeed even \
                 though this gateway's OWN active epoch is also 1",
    );

    assert_plan_wellformed(&overlap, overlap_id);
    assert_three_way_distinct(
        &own_active,
        &overlap,
        "own active epoch 1 vs overlap toward peer 7 epoch 1",
    );
}

/// The other half of the same defect: we are Role A rotating to epoch 2 while
/// a peer is Role-B-rotating to pending epoch 2 in the very same tick (the
/// `initiate_due_rotations` in-step case). Both plans must be live
/// simultaneously — this is the pair that today produces
/// `epoch 2 already has a tunnel up; tear it down first`.
#[test]
fn own_new_and_overlap_at_the_same_epoch_number_coexist() {
    let own_active = TunnelPlan {
        id: TunnelId::Own { epoch: 1 },
        ifname: BASE_TUN.to_string(),
        listen_port: BASE_PORT,
    };
    let mut live = vec![own_active.clone()];

    let own_new_id = TunnelId::Own { epoch: 2 };
    let own_new = plan_tunnel(own_new_id, BASE_TUN, BASE_PORT, &live)
        .expect("Role A's own new epoch 2 tun must be plannable");
    assert_plan_wellformed(&own_new, own_new_id);
    live.push(own_new.clone());

    let overlap_id = TunnelId::Overlap {
        gateway_id: 7,
        epoch: 2,
    };
    let overlap = plan_tunnel(overlap_id, BASE_TUN, BASE_PORT, &live).expect(
        "a Role-B overlap toward peer 7's pending epoch 2 must be plannable while our own \
                 rotation to epoch 2 is in flight",
    );
    assert_plan_wellformed(&overlap, overlap_id);

    assert_three_way_distinct(
        &own_new,
        &overlap,
        "own new epoch 2 vs overlap toward peer 7 epoch 2",
    );
    assert_three_way_distinct(
        &own_active,
        &overlap,
        "own active epoch 1 vs overlap toward peer 7 epoch 2",
    );
}

/// Two DIFFERENT peers rotating to the same pending epoch number in the same
/// tick — the ordinary consequence of one global rotation timer. Today both
/// Role-B iterations compute the identical key/ifname/port, so the second
/// peer's `bring_up` bails and the `?` at `main.rs:3794` takes out every peer
/// after it too.
#[test]
fn two_peers_overlapping_at_the_same_epoch_number_are_distinct() {
    let mut live = vec![TunnelPlan {
        id: TunnelId::Own { epoch: 3 },
        ifname: BASE_TUN.to_string(),
        listen_port: BASE_PORT,
    }];

    let a_id = TunnelId::Overlap {
        gateway_id: 11,
        epoch: 4,
    };
    let a = plan_tunnel(a_id, BASE_TUN, BASE_PORT, &live).expect("first peer's overlap");
    assert_plan_wellformed(&a, a_id);
    live.push(a.clone());

    let b_id = TunnelId::Overlap {
        gateway_id: 12,
        epoch: 4,
    };
    let b = plan_tunnel(b_id, BASE_TUN, BASE_PORT, &live).expect("second peer's overlap");
    assert_plan_wellformed(&b, b_id);

    assert_three_way_distinct(&a, &b, "overlap toward peer 11 vs peer 12, both at epoch 4");
}

/// The full headline scenario: one global timer fires, this gateway rotates
/// 3 -> 4 AND all six of its peers rotate to pending epoch 4. Every tun that
/// must be simultaneously live — the base tun, our new one, and one overlap
/// per peer — has to be pairwise distinct on all three axes. This is the
/// assertion that would have caught the shipped fabric-wide outage.
#[test]
fn whole_fabric_rotating_in_step_yields_pairwise_distinct_tuns() {
    const PEERS: [u64; 6] = [11, 12, 13, 14, 15, 16];

    let mut live = vec![TunnelPlan {
        id: TunnelId::Own { epoch: 3 },
        ifname: BASE_TUN.to_string(),
        listen_port: BASE_PORT,
    }];

    let own_new_id = TunnelId::Own { epoch: 4 };
    let own_new = plan_tunnel(own_new_id, BASE_TUN, BASE_PORT, &live).expect("Role A own new tun");
    assert_plan_wellformed(&own_new, own_new_id);
    live.push(own_new);

    for gid in PEERS {
        let id = TunnelId::Overlap {
            gateway_id: gid,
            epoch: 4,
        };
        let plan = plan_tunnel(id, BASE_TUN, BASE_PORT, &live)
            .unwrap_or_else(|e| panic!("planning overlap toward peer {gid} at epoch 4: {e:#}"));
        assert_plan_wellformed(&plan, id);
        live.push(plan);
    }

    assert_eq!(
        live.len(),
        2 + PEERS.len(),
        "every tun in the in-step fabric must have been planned"
    );
    for i in 0..live.len() {
        for j in (i + 1)..live.len() {
            assert_three_way_distinct(&live[i], &live[j], "in-step fabric");
        }
    }
}

/// Role A and Role B are driven by independent events (a `RotateDirective` vs
/// a `State` delta advertising a peer's pending key), so either can be planned
/// first. Whichever order they arrive in, the resulting pair must be usable —
/// a scheme whose second plan depends destructively on ordering would work in
/// one interleaving and wedge in the other.
///
/// # The name is now literally true (piece 3)
///
/// This test only ever asserted that each ORDER produced a usable, pairwise
/// distinct pair — not that the two orders produced the same plans, which under
/// one shared free list they did not: Role-A-first put the own tun on `base + 1`
/// and the overlap on `base + 2`, Role-B-first swapped them. That swap is bug 5
/// in miniature — the own tun's port depending on who happened to be planned
/// first, while the peer computing where to dial it knows nothing about that
/// ordering. With the own port RESERVED and overlaps free-listing above it, both
/// orders yield identical plans, so the equality below is now assertable and is
/// the sharper statement. It fails immediately if the two ranges are ever merged
/// back into one free list.
#[test]
fn plan_order_does_not_change_the_outcome() {
    let boot = TunnelPlan {
        id: TunnelId::Own { epoch: 1 },
        ifname: BASE_TUN.to_string(),
        listen_port: BASE_PORT,
    };
    let own_id = TunnelId::Own { epoch: 2 };
    let ovl_id = TunnelId::Overlap {
        gateway_id: 9,
        epoch: 2,
    };

    // Role A first, then Role B.
    let a1 = plan_tunnel(own_id, BASE_TUN, BASE_PORT, std::slice::from_ref(&boot))
        .expect("A first: own");
    let b1 = plan_tunnel(ovl_id, BASE_TUN, BASE_PORT, &[boot.clone(), a1.clone()])
        .expect("A first: overlap");
    assert_three_way_distinct(&a1, &b1, "Role A planned first");
    assert_three_way_distinct(&boot, &b1, "Role A planned first, overlap vs boot tun");

    // Role B first, then Role A.
    let b2 = plan_tunnel(ovl_id, BASE_TUN, BASE_PORT, std::slice::from_ref(&boot))
        .expect("B first: overlap");
    let a2 = plan_tunnel(own_id, BASE_TUN, BASE_PORT, &[boot.clone(), b2.clone()])
        .expect("B first: own");
    assert_three_way_distinct(&a2, &b2, "Role B planned first");
    assert_three_way_distinct(&boot, &a2, "Role B planned first, own vs boot tun");

    // ...and the two orders agree, plan for plan.
    assert_eq!(
        a1, a2,
        "the own-epoch tun's plan must not depend on whether an overlap was planned first — a \
         peer computes its port as `candidate_port + OWN_TUN_PORT_OFFSET` and has no way to \
         know the local planning order"
    );
    assert_eq!(
        b1, b2,
        "and the overlap's plan must not depend on whether the own tun was planned first"
    );
}

/// Pure-function determinism: identical inputs, identical output. The rotation
/// tick re-derives a tun's ifname/port on paths that must agree with what
/// `bring_up` used (route flips, UAPI writes, teardown) — a planner that
/// returned a different port on the second call for the same inputs would
/// silently address the wrong Device.
#[test]
fn plan_is_deterministic_for_identical_inputs() {
    let live = vec![TunnelPlan {
        id: TunnelId::Own { epoch: 0 },
        ifname: BASE_TUN.to_string(),
        listen_port: BASE_PORT,
    }];
    let id = TunnelId::Overlap {
        gateway_id: 42,
        epoch: 1,
    };
    let first = plan_tunnel(id, BASE_TUN, BASE_PORT, &live).expect("first plan");
    let second = plan_tunnel(id, BASE_TUN, BASE_PORT, &live).expect("second plan");
    assert_eq!(
        first, second,
        "plan_tunnel must be a pure function of its inputs"
    );
}

/// IFNAMSIZ budget under a plausible worst case. `wg0e{n}` (the current
/// scheme) is not extensible — owner decision E in the verification calls this
/// out explicitly — and any scheme that concatenates a raw `gateway_id` blows
/// the 15-byte budget immediately. For the conventional base name, a
/// three-digit gateway id and a two-digit epoch (well beyond anything a 30-day
/// rotation cadence reaches) MUST still produce a usable name, not an error.
#[test]
fn ifname_fits_the_15_byte_budget_for_a_plausible_worst_case() {
    let live = vec![TunnelPlan {
        id: TunnelId::Own { epoch: 40 },
        ifname: BASE_TUN.to_string(),
        listen_port: BASE_PORT,
    }];
    for gid in [1u64, 99, 999] {
        for epoch in [41u32, 99] {
            let id = TunnelId::Overlap {
                gateway_id: gid,
                epoch,
            };
            let plan = plan_tunnel(id, BASE_TUN, BASE_PORT, &live).unwrap_or_else(|e| {
                panic!(
                    "gateway {gid} at epoch {epoch} on base {BASE_TUN:?} must be plannable: {e:#}"
                )
            });
            assert_plan_wellformed(&plan, id);
        }
    }
}

/// Total safety over the ifname axis: for ANY base name — including ones long
/// enough that no derived name can fit — `plan_tunnel` must either return a
/// name `validate_iface` accepts, or fail cleanly. It must never hand back an
/// over-long/invalid name, which today only surfaces as an opaque tc-attach
/// failure after the Device is already half-built.
#[test]
fn plan_never_yields_an_invalid_ifname_for_any_base_name() {
    // 1..=15 bytes: the whole space `--tun` can legally carry today.
    for len in 1..=15usize {
        let base: String = "w".repeat(len);
        for id in [
            TunnelId::Own { epoch: 7 },
            TunnelId::Overlap {
                gateway_id: 3,
                epoch: 7,
            },
            TunnelId::Overlap {
                gateway_id: 123_456,
                epoch: 4_000_000_000,
            },
        ] {
            let live = vec![TunnelPlan {
                id: TunnelId::Own { epoch: 0 },
                ifname: base.clone(),
                listen_port: BASE_PORT,
            }];
            if let Ok(plan) = plan_tunnel(id, &base, BASE_PORT, &live) {
                assert!(
                    iface_is_valid(&plan.ifname),
                    "base {base:?} + {id:?} produced ifname {:?} ({} bytes), which validate_iface \
                     rejects — plan_tunnel must return Err instead of an unusable name",
                    plan.ifname,
                    plan.ifname.len()
                );
                assert_ne!(
                    plan.ifname, base,
                    "a rotation tun must never reuse the base tun's name"
                );
            }
        }
    }
}

/// An overlap and an own-tun that share NOTHING but the epoch number are the
/// collision; an overlap and an own-tun at DIFFERENT epoch numbers must of
/// course also stay distinct. Cheap regression against a "fix" that keys on
/// the epoch number alone in the non-colliding direction.
#[test]
fn own_and_overlap_stay_distinct_across_different_epoch_numbers() {
    let boot = TunnelPlan {
        id: TunnelId::Own { epoch: 5 },
        ifname: BASE_TUN.to_string(),
        listen_port: BASE_PORT,
    };
    let own_id = TunnelId::Own { epoch: 6 };
    let own =
        plan_tunnel(own_id, BASE_TUN, BASE_PORT, std::slice::from_ref(&boot)).expect("own epoch 6");
    // Peer 8 is a laggard: it is only now rotating 5 -> 6 while we are already
    // planning our own 6, and peer 9 is further behind still (4 -> 5).
    let o6_id = TunnelId::Overlap {
        gateway_id: 8,
        epoch: 6,
    };
    let o6 =
        plan_tunnel(o6_id, BASE_TUN, BASE_PORT, &[boot.clone(), own.clone()]).expect("overlap 8@6");
    let o5_id = TunnelId::Overlap {
        gateway_id: 9,
        epoch: 5,
    };
    let o5 = plan_tunnel(
        o5_id,
        BASE_TUN,
        BASE_PORT,
        &[boot.clone(), own.clone(), o6.clone()],
    )
    .expect("overlap 9@5");

    for (i, a) in [&boot, &own, &o6, &o5].iter().enumerate() {
        for b in [&boot, &own, &o6, &o5].iter().skip(i + 1) {
            assert_three_way_distinct(a, b, "mixed-epoch fabric");
        }
    }
}
