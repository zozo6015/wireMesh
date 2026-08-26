//! B2 (BACKLOG item 9), the unwind at library level: `Rotation` and
//! `EpochKeys` driven TOGETHER through an aborted rotation, asserting the two
//! halves of the fix that the netns done-bar can only observe indirectly —
//! the state machine is rotatable again, and no private key was stranded.
//!
//! Plain test, no netns, no root, no feature gate:
//!
//! ./dev.sh run "cargo test -p wiremesh-gateway --test rotation_unwind"
//!
//! # Why this file exists next to `tests/rotation_wedge.rs`
//!
//! The netns done-bar proves the integrated behaviour with two real binaries,
//! and it is the falsification target for both sabotage runs. But it is slow,
//! privileged, serialized fabric-wide, and it can only see the store through
//! `epoch_keys.json`. This file pins the same invariants at the seam where
//! they are actually decided, in milliseconds, so a regression in either half
//! is attributable without a privileged container. It deliberately does NOT
//! duplicate the wedge's integrated claim: it says nothing about tuns,
//! enforcers, the controller, or the directive path.
//!
//! # What "the residue" means here
//!
//! `main.rs`'s `unwind_failed_rotation` is the real caller and it also tears
//! down a tun and evicts an enforcer — neither of which is reachable from a
//! `tests/*` binary (both live in the bin, and both need root). What IS
//! reachable is the ORDER-INDEPENDENT pair of library effects: scrub the
//! orphan mint, then reset the machine. This file drives that pair by hand,
//! in the order §3.2 Piece 2 fixes (resources first, `on_failed` LAST), so
//! that "the phase only returns to Idle after the resources it named are
//! gone" is at least expressed somewhere a unit run can read.

use wiremesh_gateway::epochkeys::EpochKeys;
use wiremesh_gateway::rotation::{Rotation, RotationAction, RotationPhase};

/// A gateway at rest: one active epoch 0, nothing pending. Returns the store
/// and epoch 0's private key so tests can assert it survives.
fn gateway_at_rest() -> (EpochKeys, String) {
    let mut seed = EpochKeys::default();
    let priv0 = seed.generate_next_at(0).unwrap().private_key_b64.clone();
    let keys = EpochKeys::from_legacy(&priv0).unwrap();
    (keys, priv0)
}

/// One aborted rotation, driven the way `handle_rotate` + the wrapper's `Err`
/// path drive it: accept the directive, mint+persist, fail, then unwind —
/// scrub FIRST, reset the machine LAST (design §3.2 Piece 2, step 5 is last).
/// Returns the minted (now discarded) private key.
fn abort_one_rotation(
    rot: &mut Rotation,
    keys: &mut EpochKeys,
    dir: &std::path::Path,
    directive_epoch: u32,
) -> String {
    let action = rot.on_directive(directive_epoch);
    assert!(
        matches!(action, Some(RotationAction::MintBringUpSubmit { .. })),
        "harness precondition: the directive must have been accepted before we can abort it"
    );

    // Piece 2c: the mint is filed under the CONTROLLER's epoch number, not a
    // locally-derived one. That is what keeps the store's numbering aligned
    // with the tun name, the port formula, `submit_epoch_key` and the
    // cutover's `promote`/`retire` across an abort — see `epochkeys.rs`'s
    // `generate_next_at` suite for why a local `max+1` drifts.
    let minted = keys.generate_next_at(directive_epoch).unwrap().clone();
    keys.persist(dir).unwrap();

    // ---- the rotation fails here (any of the eight fallible steps) ----

    keys.discard_pending(minted.epoch).unwrap();
    keys.persist(dir).unwrap();
    let abort = rot.on_failed();
    assert!(
        matches!(abort, Some(RotationAction::Abort { .. })),
        "the unwind's last step must actually reset the machine; got {abort:?}"
    );

    minted.private_key_b64
}

#[test]
fn abort_returns_both_the_machine_and_the_store_to_a_rotatable_state() {
    let dir = tempfile::tempdir().unwrap();
    let (mut keys, priv0) = gateway_at_rest();
    let mut rot = Rotation::new();

    abort_one_rotation(&mut rot, &mut keys, dir.path(), 1);

    assert_eq!(
        rot.phase,
        RotationPhase::Idle,
        "THE WEDGE (BACKLOG item 9): a rotation that failed part-way used to park the phase off \
         Idle forever, and `on_directive` is honoured only from Idle, so the gateway silently \
         ignored every later directive until the process restarted"
    );
    assert_eq!(
        keys.by_epoch(1).map(|k| k.epoch),
        None,
        "the aborted rotation's epoch must be absent from the store, leaving a HOLE — that is \
         expected and harmless, because every consumer resolves by state or by exact epoch"
    );
    assert!(
        !keys.epochs.iter().any(|k| k.state == "pending"),
        "the aborted mint must be gone from the store, or the next rotation inherits an orphan \
         private key it will never remove: store = {:?}",
        keys.epochs
    );
    assert_eq!(
        keys.active().map(|k| k.epoch),
        Some(0),
        "the epoch the data plane is running on must be untouched by the unwind"
    );
    assert_eq!(
        keys.active().map(|k| k.private_key_b64.clone()),
        Some(priv0),
        "the ACTIVE private key must survive the unwind byte-for-byte — the whole point of \
         aborting rather than half-rotating is that the gateway keeps working on its old key"
    );

    // The property the whole phase exists for: the very NEXT directive is
    // honoured. Nothing retries a RotateDirective (design C1), so this is the
    // only chance there is.
    let next = rot.on_directive(2);
    assert_eq!(
        next,
        Some(RotationAction::MintBringUpSubmit { epoch: 2 }),
        "the next directive after an aborted rotation must be honoured immediately — no \
         restart, no tick, no reconnect"
    );
}

#[test]
fn an_aborted_mint_leaves_no_private_key_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let (mut keys, priv0) = gateway_at_rest();
    let mut rot = Rotation::new();
    keys.persist(dir.path()).unwrap();

    let orphan_priv = abort_one_rotation(&mut rot, &mut keys, dir.path(), 1);

    let raw = std::fs::read_to_string(dir.path().join("epoch_keys.json"))
        .expect("epoch_keys.json must still exist after an aborted rotation");
    assert!(
        !raw.contains(&orphan_priv),
        "SECURITY: the aborted rotation's PRIVATE key is still in epoch_keys.json. The mint is \
         persisted before the fallible steps run (design §2.2 step 3), so an abort that does not \
         scrub leaves a live key on disk that nothing will ever remove — `EpochKeys::retire` \
         only accepts `\"retiring\"` entries. File:\n{raw}"
    );
    assert!(
        raw.contains(&priv0),
        "the active epoch's key must still be there — a gateway whose store lost its active key \
         cannot boot its data plane back up"
    );
    assert_eq!(
        EpochKeys::load(dir.path())
            .unwrap()
            .as_ref()
            .and_then(EpochKeys::active)
            .map(|k| k.epoch),
        Some(0),
        "a reboot after an aborted rotation must select the epoch the data plane was actually \
         running (`EpochKeys::select_boot_key`'s branch 1)"
    );
}

#[test]
fn repeated_aborts_do_not_accumulate_pending_keys() {
    let dir = tempfile::tempdir().unwrap();
    let (mut keys, _priv0) = gateway_at_rest();
    let mut rot = Rotation::new();

    let mut orphans = Vec::new();
    for directive_epoch in 1..=3 {
        orphans.push(abort_one_rotation(
            &mut rot,
            &mut keys,
            dir.path(),
            directive_epoch,
        ));
    }

    assert_eq!(
        keys.epochs.len(),
        1,
        "three aborted rotations must leave exactly the one active epoch. A mint is persisted on \
         EVERY directive and, before B2, nothing could remove a \
         `\"pending\"` entry — so orphan private keys grew without bound, one per failed \
         rotation, for the life of the gateway (design §2.2). Store = {:?}",
        keys.epochs
    );
    let raw = std::fs::read_to_string(dir.path().join("epoch_keys.json")).unwrap();
    for (i, orphan) in orphans.iter().enumerate() {
        assert!(
            !raw.contains(orphan),
            "SECURITY: orphan private key #{i} from a previously aborted rotation survived on \
             disk. File:\n{raw}"
        );
    }
}
