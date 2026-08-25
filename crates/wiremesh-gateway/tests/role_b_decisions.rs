//! Key-rotation T3: Role B's per-peer decision — the loop must consider EVERY
//! peer (one bad peer cannot silently take out the rest), and a peer that
//! re-rotates while we already hold an overlap toward it must not be dropped.
//!
//! ./dev.sh run "cargo test -p wiremesh-gateway --test role_b_decisions"
//!
//! # The two defects these tests pin
//!
//! **(a) One failure aborts the whole loop.** `maybe_start_role_b`
//! (`main.rs:3754-3854`) is a `for peer in &ds.peers` whose body contains
//! `tunnels.bring_up(...)?` (`:3794`), `anyhow::bail!` on a non-base64 pending
//! pubkey (`:3830-3832`), and two `return Err(...)` enforcer paths
//! (`:3812`, `:3817`). Any of them exits the FUNCTION, so every peer after the
//! offending one is skipped — on every `State` event, forever. The caller only
//! logs (`main.rs:985`), so the fabric degrades silently. With
//! `initiate_due_rotations` rotating every gateway off one timer
//! (`controller/services/sync.rs:640-688`), the first peer in roster order
//! reliably starves all the others.
//!
//! **(b) Re-rotation is dropped.** `if rot.role_b.lock().unwrap()
//! .contains_key(&aid) { continue; }` (`main.rs:3765`) keys on the peer id
//! ALONE, not on which epoch the overlap was built toward. Once we hold an
//! overlap toward peer P's pending epoch 1, P's next rotation (pending epoch 2)
//! is skipped silently and forever — and F9 (`docs/research/
//! key-rotation-plan-verification.md`) shows the entry can outlive the
//! rotation it belongs to, so this is not self-healing.
//!
//! # What is pinned, and what deliberately is NOT
//!
//! Only the DECISION per peer, never the mechanism. Nothing here says whether
//! a re-rotation collapses the stale overlap first or stands a second one up
//! beside it — both shapes satisfy the assertions below. Nothing here asserts
//! a tun name, a port, or a `TunnelId`; that is
//! `tests/tunnel_id_decollision.rs`'s job.
//!
//! # Production seam this file requires (does NOT exist yet — COMPILE-RED)
//!
//! In `crates/wiremesh-gateway/src/rotation.rs`:
//!
//! ```ignore
//! /// What Role B must do about ONE rotating peer this round.
//! #[derive(Debug, Clone, PartialEq, Eq)]
//! pub enum RoleBDecision {
//!     /// Nothing to do: not rotating, no real pending key, or we already
//!     /// hold an overlap toward exactly this pending epoch.
//!     Skip,
//!     /// Stand up an overlap Device toward this peer's pending epoch.
//!     Start { pending_epoch: u32 },
//!     /// We hold an overlap toward a pending epoch the peer has moved past:
//!     /// retire `stale_epoch`'s overlap and stand one up toward
//!     /// `pending_epoch`.
//!     Restart { stale_epoch: u32, pending_epoch: u32 },
//! }
//!
//! /// Decide, per peer, what Role B should do — pure, no I/O, no devices.
//! /// `overlapped` maps gateway_id -> the pending epoch our live overlap
//! /// Device targets. Returns EXACTLY ONE entry per peer in `ds.peers`, in
//! /// roster order: a peer we cannot act on yields `Skip`, never a truncated
//! /// list, so no peer can starve the ones behind it.
//! pub fn role_b_decisions(
//!     ds: &DesiredState,
//!     overlapped: &BTreeMap<u64, u32>,
//! ) -> Vec<(u64, RoleBDecision)>;
//! ```
//!
//! Implementers may ADD variants (e.g. a distinct `Unusable` for a malformed
//! pending pubkey); the assertions below are written to tolerate that. What
//! they do not tolerate is a missing entry, a reordered list, or a `Skip` for
//! a peer that has genuinely re-rotated.
//!
//! # Not reachable from here
//!
//! Defect (a)'s EXECUTION half — that a `bring_up` which really fails for peer
//! 2 still leaves peers 3..N attempted — lives in `main.rs`, a binary that
//! integration tests cannot link. Turning `?` into per-peer log-and-continue
//! around this decision list is a reviewer-enforced obligation, not something
//! any test in this crate can observe.
use std::collections::BTreeMap;

use wiremesh_gateway::rotation::{role_b_decisions, RoleBDecision};
use wiremesh_gateway::state::{DesiredState, PeerKeyInfo, PeerState};

/// A syntactically valid 44-char base64 WG public key, distinguished by
/// `tag`. Real base64 matters: `main.rs:3830` runs the pending pubkey through
/// `pubkey_b64_to_hex` and `bail!`s the whole loop when it does not decode, so
/// tests that want a peer to be ACTED ON must give it a decodable key.
fn pk(tag: &str) -> String {
    assert!(tag.len() <= 43 && tag.bytes().all(|b| b.is_ascii_alphanumeric()));
    let mut s = tag.to_string();
    while s.len() < 43 {
        s.push('A');
    }
    s.push('=');
    s
}

/// A peer advertising only an active key — steady state, nothing to overlap.
fn settled_peer(gid: u64, active_epoch: u32) -> PeerState {
    let active = pk(&format!("act{gid}e{active_epoch}"));
    PeerState {
        gateway_id: gid,
        segment_name: format!("seg-{gid}"),
        active_pubkey_b64: Some(active.clone()),
        keys: vec![PeerKeyInfo {
            epoch: active_epoch,
            pubkey_b64: active,
            state: "active".into(),
        }],
        // A reachable endpoint: `reconcile::pending_peer_configs` needs
        // `primary_endpoint()` to parse as `ip:port` before it can derive the
        // peer's offset endpoint, and `main.rs:3782` skips a peer whose config
        // it cannot build. Give every peer a usable one so a `Skip` in these
        // tests is never an artefact of a missing candidate.
        candidates: vec![format!("10.9.0.{gid}:51820")],
        allowed_ips: vec![format!("10.10.{gid}.0/24")],
    }
}

/// A peer mid-rotation: active epoch `n`, real-keyed pending epoch `n + 1`.
fn rotating_peer(gid: u64, active_epoch: u32, pending_epoch: u32) -> PeerState {
    let mut p = settled_peer(gid, active_epoch);
    p.keys.push(PeerKeyInfo {
        epoch: pending_epoch,
        pubkey_b64: pk(&format!("pnd{gid}e{pending_epoch}")),
        state: "pending".into(),
    });
    p
}

fn ds(peers: Vec<PeerState>) -> DesiredState {
    DesiredState {
        revision: 1,
        peers,
        ..Default::default()
    }
}

fn ids(decisions: &[(u64, RoleBDecision)]) -> Vec<u64> {
    decisions.iter().map(|(gid, _)| *gid).collect()
}

fn decision_for(decisions: &[(u64, RoleBDecision)], gid: u64) -> &RoleBDecision {
    &decisions
        .iter()
        .find(|(g, _)| *g == gid)
        .unwrap_or_else(|| panic!("no decision emitted for peer {gid}; got {decisions:?}"))
        .1
}

/// Steady state: no peer advertises a pending key, so Role B is a total no-op.
/// The baseline the other cases are read against.
#[test]
fn settled_peers_are_all_skipped() {
    let state = ds(vec![
        settled_peer(11, 3),
        settled_peer(12, 3),
        settled_peer(13, 3),
    ]);
    let d = role_b_decisions(&state, &BTreeMap::new());
    assert_eq!(
        ids(&d),
        vec![11, 12, 13],
        "one decision per peer, in roster order"
    );
    for (gid, dec) in &d {
        assert_eq!(
            *dec,
            RoleBDecision::Skip,
            "settled peer {gid} must not be overlapped"
        );
    }
}

/// The in-step fabric: every peer rotates in the same tick. Every one of them
/// must be told to Start — today the second peer's `bring_up` collides with
/// the first's and the `?` at `main.rs:3794` discards the rest of the loop.
#[test]
fn every_rotating_peer_in_an_in_step_fabric_is_started() {
    let state = ds(vec![
        rotating_peer(11, 3, 4),
        rotating_peer(12, 3, 4),
        rotating_peer(13, 3, 4),
        rotating_peer(14, 3, 4),
    ]);
    let d = role_b_decisions(&state, &BTreeMap::new());
    assert_eq!(ids(&d), vec![11, 12, 13, 14]);
    for gid in [11u64, 12, 13, 14] {
        assert_eq!(
            *decision_for(&d, gid),
            RoleBDecision::Start { pending_epoch: 4 },
            "peer {gid} rotates to epoch 4 like everyone else and must get its own overlap"
        );
    }
}

/// **ANTI-TRUNCATION.** A peer whose pending pubkey is not valid base64 is
/// exactly the `anyhow::bail!` at `main.rs:3830-3832` — today it destroys the
/// whole loop. The bad peer may be handled however the implementer likes as
/// long as nothing is stood up for it, but the peers BEHIND it must still be
/// considered and still be told to Start.
#[test]
fn one_unusable_peer_does_not_starve_the_peers_behind_it() {
    let mut bad = rotating_peer(12, 3, 4);
    // `!` is outside the base64 alphabet, so `pubkey_b64_to_hex` returns None.
    bad.keys.last_mut().unwrap().pubkey_b64 = "this-is-not-base64!!".to_string();

    let state = ds(vec![
        rotating_peer(11, 3, 4),
        bad,
        rotating_peer(13, 3, 4),
        rotating_peer(14, 3, 4),
    ]);
    let d = role_b_decisions(&state, &BTreeMap::new());

    assert_eq!(
        ids(&d),
        vec![11, 12, 13, 14],
        "the decision list must cover every peer in roster order — a peer that cannot be acted on \
         yields its own (non-actionable) decision, it does not truncate the list"
    );
    assert!(
        !matches!(
            decision_for(&d, 12),
            RoleBDecision::Start { .. } | RoleBDecision::Restart { .. }
        ),
        "peer 12's pending pubkey does not decode; nothing may be stood up for it (got {:?})",
        decision_for(&d, 12)
    );
    for gid in [11u64, 13, 14] {
        assert_eq!(
            *decision_for(&d, gid),
            RoleBDecision::Start { pending_epoch: 4 },
            "peer {gid} is well-formed and must be started regardless of peer 12's state"
        );
    }
}

/// The controller's `"awaiting-submission"` sentinel means the rotating peer
/// has not submitted a real pubkey yet (`PeerState::pending_key`,
/// `state.rs:89-96`). Nothing to overlap toward — Skip, and again without
/// disturbing the peers around it.
#[test]
fn sentinel_pending_key_is_skipped_without_disturbing_other_peers() {
    let mut sentinel = rotating_peer(12, 3, 4);
    sentinel.keys.last_mut().unwrap().pubkey_b64 = "awaiting-submission".to_string();

    let state = ds(vec![
        rotating_peer(11, 3, 4),
        sentinel,
        rotating_peer(13, 3, 4),
    ]);
    let d = role_b_decisions(&state, &BTreeMap::new());

    assert_eq!(ids(&d), vec![11, 12, 13]);
    assert_eq!(
        *decision_for(&d, 12),
        RoleBDecision::Skip,
        "a pending row still bearing the sentinel has no real WG key to overlap toward"
    );
    for gid in [11u64, 13] {
        assert_eq!(
            *decision_for(&d, gid),
            RoleBDecision::Start { pending_epoch: 4 }
        );
    }
}

/// Idempotence — the LEGITIMATE half of today's `contains_key` guard
/// (`main.rs:3765`). `maybe_start_role_b` runs on every `State` event, and a
/// peer sits mid-rotation across many of them; re-Starting the same overlap
/// would churn a live Device. Same peer, same pending epoch, already
/// overlapped => Skip.
#[test]
fn an_overlap_already_held_toward_the_same_epoch_is_not_restarted() {
    let state = ds(vec![rotating_peer(11, 3, 4), rotating_peer(12, 3, 4)]);
    let overlapped = BTreeMap::from([(11u64, 4u32)]);

    let d = role_b_decisions(&state, &overlapped);
    assert_eq!(ids(&d), vec![11, 12]);
    assert_eq!(
        *decision_for(&d, 11),
        RoleBDecision::Skip,
        "peer 11's overlap already targets epoch 4 — re-standing it would churn a live Device"
    );
    assert_eq!(
        *decision_for(&d, 12),
        RoleBDecision::Start { pending_epoch: 4 },
        "peer 12 has no overlap yet"
    );
}

/// **RE-ROTATION MUST NOT BE DROPPED.** Peer 11 rotated 3 -> 4 (we hold an
/// overlap toward 4) and is now rotating 4 -> 5. Today `contains_key(&aid)`
/// matches on the peer id alone and skips it silently and permanently, so we
/// never overlap toward epoch 5 and never ack it. Either de-collision shape is
/// acceptable: retire the stale overlap and restart, or start a second one.
/// What is NOT acceptable is `Skip`.
#[test]
fn a_peer_rotating_again_to_a_newer_epoch_is_acted_on() {
    let state = ds(vec![rotating_peer(11, 4, 5), rotating_peer(12, 3, 4)]);
    let overlapped = BTreeMap::from([(11u64, 4u32)]);

    let d = role_b_decisions(&state, &overlapped);
    assert_eq!(ids(&d), vec![11, 12]);

    let got = decision_for(&d, 11);
    assert!(
        matches!(
            got,
            RoleBDecision::Restart {
                stale_epoch: 4,
                pending_epoch: 5
            } | RoleBDecision::Start { pending_epoch: 5 }
        ),
        "peer 11 has re-rotated to pending epoch 5 while our overlap still targets epoch 4; it \
         must be acted on, not skipped (got {got:?})"
    );
    assert_eq!(
        *decision_for(&d, 12),
        RoleBDecision::Start { pending_epoch: 4 }
    );
}

/// The same trap, one step further out: our overlap targets an epoch the peer
/// has already promoted past AND the peer is mid-rotation again. The stale
/// entry must not veto the new rotation. (Distinct from the case above because
/// the stale epoch is now two behind, which is what F9's leaked entries look
/// like after a controller abort.)
#[test]
fn a_stale_overlap_two_epochs_behind_does_not_veto_a_new_rotation() {
    let state = ds(vec![rotating_peer(11, 5, 6)]);
    let overlapped = BTreeMap::from([(11u64, 4u32)]);

    let d = role_b_decisions(&state, &overlapped);
    assert_eq!(ids(&d), vec![11]);
    let got = decision_for(&d, 11);
    assert!(
        matches!(
            got,
            RoleBDecision::Restart {
                stale_epoch: 4,
                pending_epoch: 6
            } | RoleBDecision::Start { pending_epoch: 6 }
        ),
        "a leaked/stale overlap toward epoch 4 must not block overlapping toward epoch 6 \
         (got {got:?})"
    );
}

/// An empty roster is a clean empty decision list, not a panic — the gateway
/// sees this on its very first `State` before any peer exists.
#[test]
fn an_empty_roster_yields_no_decisions() {
    assert!(role_b_decisions(&ds(vec![]), &BTreeMap::new()).is_empty());
}
