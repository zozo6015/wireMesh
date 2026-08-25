//! F1: the rotation tick's deferred Role-B write-backs must be qualified by the
//! FULL overlap identity, not by the peer id alone.
//!
//! ./dev.sh run "cargo test -p wiremesh-gateway --test overlap_write_back"
//!
//! # The defect these tests pin
//!
//! `run_rotation_ticks` clones the shared `role_b` map, then per entry `.await`s
//! `read_live_peers` and — on the cutover arm — `send_epoch_ack`, which opens a
//! fresh mTLS channel and can take hundreds of milliseconds. It then writes its
//! conclusions back through `role_b.lock().get_mut(&peer_id)`.
//!
//! Matching on the peer id alone was safe only while an entry for a given peer
//! could never be REPLACED in place — true while `maybe_start_role_b`'s guard
//! was `contains_key(&gid)`, and false the moment `RoleBDecision::Restart`
//! started removing the stale overlap and inserting a new one. A peer that
//! re-rotates during the `.await` therefore gets:
//!
//!  - `cut_over = true` on an overlap whose session was NEVER observed, which
//!    feeds `route_owner` a proven-live claim and points that peer's CIDRs at a
//!    Device with no session — a direct make-before-break violation;
//!  - `done = true` on the NEW epoch's entry, permanently filtering it out of
//!    the tick's pending set, so it never cuts over and never acks;
//!  - on the collapse arm, a `remove` of the NEW entry while the teardown names
//!    the OLD Device, orphaning a live Device + enforcer forever.
//!
//! [`overlap_write_back`] is the pure gate every deferred write-back now passes
//! through. These tests are about THAT DECISION only — nothing here asserts how
//! the tick reacts to a given verdict (that is `main.rs`'s call-site
//! behaviour), only that the verdict itself is right.
//!
//! # Why both axes are exercised separately
//!
//! An implementation that compared only `pending_epoch` would pass every test
//! that varies the epoch, and an implementation that compared only `new_tun`
//! would pass every test that varies the tun. So each axis gets a case in which
//! it is the ONLY thing that differs — [`same_epoch_different_tun_is_replaced`]
//! and [`different_epoch_same_tun_is_replaced`] — and each of those two must go
//! red if its axis is dropped from the comparison.
use wiremesh_gateway::rotation::{overlap_write_back, OverlapIdentity, WriteBack};

fn ident(pending_epoch: u32, new_tun: &str) -> OverlapIdentity {
    OverlapIdentity {
        pending_epoch,
        new_tun: new_tun.to_string(),
    }
}

/// The ordinary case: nothing moved during the `.await`, so the conclusion the
/// caller computed is about the entry that is still there. This is the only
/// verdict under which a write-back may land, so it has to be reachable — a
/// gate that never says `Apply` would be "safe" and would also stall every
/// rotation permanently.
#[test]
fn identical_identity_applies() {
    let taken = ident(7, "wg0o0");
    let current = ident(7, "wg0o0");
    assert_eq!(
        overlap_write_back(&taken, Some(&current)),
        WriteBack::Apply,
        "an unchanged entry must accept the write-back it was cloned for; refusing here would \
         mean no Role-B overlap ever records its cutover or its done flag"
    );
}

/// THE TUN AXIS, ALONE. The peer re-rotated and rotated BACK onto the same
/// pending epoch NUMBER — a controller that restarted its epoch counter, a
/// roster replay — so the epoch is identical and only the freshly-allocated
/// overlap Device differs. `retire_stale_overlap` has already torn down
/// `wg0o0`; the entry under the lock belongs to `wg0o1`.
///
/// An implementation that compared only `pending_epoch` returns `Apply` here
/// and writes the old Device's conclusions onto the new one. This is the case
/// that makes `new_tun` load-bearing rather than decorative.
#[test]
fn same_epoch_different_tun_is_replaced() {
    let taken = ident(7, "wg0o0");
    let current = ident(7, "wg0o1");
    assert_eq!(
        overlap_write_back(&taken, Some(&current)),
        WriteBack::Replaced,
        "same pending epoch but a DIFFERENT overlap Device is a different overlap: the entry was \
         replaced during the await and the caller's conclusion is about a Device that no longer \
         exists. Qualifying on the epoch alone would wrongly Apply here"
    );
}

/// THE EPOCH AXIS, ALONE. The peer re-rotated to a newer pending epoch and the
/// new overlap happened to be allocated the SAME slot name (which the F6
/// quarantine now makes unlikely, but the gate must not depend on that — it is
/// the second of two independent guards, not a consumer of the first).
///
/// An implementation that compared only `new_tun` returns `Apply` here.
#[test]
fn different_epoch_same_tun_is_replaced() {
    let taken = ident(7, "wg0o0");
    let current = ident(8, "wg0o0");
    assert_eq!(
        overlap_write_back(&taken, Some(&current)),
        WriteBack::Replaced,
        "a different pending epoch is a different overlap even on the same ifname — the peer \
         moved past the epoch this conclusion was computed for. Qualifying on the tun alone \
         would wrongly Apply here"
    );
}

/// Both axes moved: the ordinary `RoleBDecision::Restart` shape, where the peer
/// advanced its pending epoch and the new overlap got a fresh slot.
#[test]
fn both_axes_different_is_replaced() {
    let taken = ident(7, "wg0o0");
    let current = ident(8, "wg0o1");
    assert_eq!(
        overlap_write_back(&taken, Some(&current)),
        WriteBack::Replaced,
        "the canonical Restart race — new epoch on a new Device — must never take a write-back \
         computed against the old one"
    );
}

/// The entry is gone entirely: the overlap was retired or collapsed while the
/// caller was awaiting. `Vanished` rather than `Replaced` because the caller
/// logs the two differently, and because a re-insert is not what happened —
/// there is nothing to drive next tick.
#[test]
fn absent_entry_is_vanished() {
    let taken = ident(7, "wg0o0");
    assert_eq!(
        overlap_write_back(&taken, None),
        WriteBack::Vanished,
        "no entry under the lock means the overlap was retired/collapsed during the await; the \
         write-back must not resurrect it"
    );
}

/// `Vanished` and `Replaced` must stay DISTINCT verdicts. A gate that collapsed
/// them into one "don't write" answer would still be safe, but the tick uses
/// the difference to say why it abandoned the pass (a peer re-rotating is
/// ordinary; an overlap disappearing under an in-flight ack is not), and a bool
/// is exactly the shape this bug came from.
#[test]
fn replaced_and_vanished_are_not_the_same_verdict() {
    let taken = ident(3, "wg0o2");
    let replaced = overlap_write_back(&taken, Some(&ident(4, "wg0o3")));
    let vanished = overlap_write_back(&taken, None);
    assert_ne!(
        replaced, vanished,
        "a replaced entry and a vanished one are different situations and must be reportable as \
         such"
    );
    assert_ne!(replaced, WriteBack::Apply);
    assert_ne!(vanished, WriteBack::Apply);
}

/// Totality over a small grid: `Apply` iff the identity is equal on BOTH axes,
/// for every pairing of two epochs and two tuns. This is the property the three
/// individual cases above illustrate, asserted exhaustively so no future
/// short-circuit (say, "epochs equal is good enough when the slot index is
/// low") can slip through between the sampled points.
#[test]
fn apply_exactly_when_both_axes_match() {
    let epochs = [0u32, 1, 4_294_967_295];
    let tuns = ["wg0o0", "wg0o1", "wg0o63"];
    for &te in &epochs {
        for tt in tuns {
            let taken = ident(te, tt);
            for &ce in &epochs {
                for ct in tuns {
                    let current = ident(ce, ct);
                    let expected = if te == ce && tt == ct {
                        WriteBack::Apply
                    } else {
                        WriteBack::Replaced
                    };
                    assert_eq!(
                        overlap_write_back(&taken, Some(&current)),
                        expected,
                        "taken=({te}, {tt}) vs current=({ce}, {ct}): Apply must mean the identity \
                         matched on BOTH the pending epoch and the overlap Device"
                    );
                }
            }
        }
    }
}

/// The gate is a pure decision, so asking twice must answer twice the same —
/// each of the three deferred write-backs in the tick calls it independently
/// against the same lock acquisition, and two of them disagreeing would be
/// exactly the split-brain the gate exists to remove.
#[test]
fn verdict_is_a_pure_function_of_its_inputs() {
    let taken = ident(9, "wg0o5");
    let current = ident(9, "wg0o5");
    let first = overlap_write_back(&taken, Some(&current));
    let second = overlap_write_back(&taken, Some(&current));
    assert_eq!(first, second, "overlap_write_back must be pure");
    assert_eq!(first, WriteBack::Apply);
}

/// The concrete F1 scenario, spelled out end to end at the decision level.
///
/// Peer 7 is rotating to pending epoch 1; we stand up `wg0o0` toward it and the
/// tick clones that entry. While we are inside `send_epoch_ack` (a fresh mTLS
/// channel), peer 7's `State` delta advertises pending epoch 2, so
/// `role_b_decisions` yields `Restart { stale_epoch: 1, pending_epoch: 2 }`,
/// `wg0o0` is torn down and `wg0o1` is inserted in its place. The ack returns
/// and the tick is about to write `cut_over = true`.
///
/// The verdict must be `Replaced`. Anything else marks an overlap whose session
/// was never observed as cut over, which `route_owner` then reads as a
/// proven-live path.
#[test]
fn restart_during_the_ack_await_must_not_take_the_cutover() {
    let cloned_before_the_await = ident(1, "wg0o0");
    let after_the_restart = ident(2, "wg0o1");
    assert_eq!(
        overlap_write_back(&cloned_before_the_await, Some(&after_the_restart)),
        WriteBack::Replaced,
        "cut_over must not be written onto the overlap that REPLACED the one the liveness read \
         was performed against — that is the make-before-break violation F1 describes"
    );
}
