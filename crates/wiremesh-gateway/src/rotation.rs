//! Pure key-rotation state machine (make-before-break).
//!
//! `Rotation` tracks a single gateway's own key-epoch rotation through three
//! phases: `Idle` (steady state, one active epoch) -> `Overlapping` (a new
//! epoch has been minted and brought up alongside the old one, but routes
//! still point at the old epoch's device) -> `CutOver` (routes have flipped
//! onto the new epoch; the old epoch is now retiring). This module has no
//! I/O — it only decides *what* to do (`RotationAction`) in response to
//! events; the caller (netns-integration task) is responsible for actually
//! minting keys, submitting them, flipping routes, and tearing down devices.
//!
//! The core safety property is MAKE-BEFORE-BREAK: routes never flip onto the
//! new epoch until a live session on it is corroborated by actual inbound
//! traffic (not just a handshake), and the old epoch's device is never torn
//! down until after that flip has happened.

use crate::state::{DesiredState, PeerState};
use crate::uapi::pubkey_b64_to_hex;
use std::collections::BTreeMap;

/// Where a single gateway's own rotation currently stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationPhase {
    /// Steady state: no rotation in flight.
    Idle,
    /// A new epoch has been minted and brought up; routes still point at the
    /// old epoch until a corroborated session on the new epoch is observed.
    Overlapping { new_epoch: u32 },
    /// Routes have flipped onto the new epoch; the old epoch is retiring.
    CutOver { new_epoch: u32 },
}

/// Side effect the caller must perform in response to a state transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationAction {
    /// Mint the new epoch's key material, bring up its device, and submit it
    /// to the controller.
    MintBringUpSubmit { epoch: u32 },
    /// Flip routes onto the given (now-corroborated-live) epoch.
    FlipRoutes { epoch: u32 },
    /// Tear down the given (now-retired) epoch's device.
    TearDown { epoch: u32 },
}

/// Pure rotation state machine for a single gateway. See module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotation {
    pub phase: RotationPhase,
}

impl Default for Rotation {
    fn default() -> Self {
        Self::new()
    }
}

impl Rotation {
    pub fn new() -> Self {
        Self { phase: RotationPhase::Idle }
    }

    /// A `RotateDirective` for `new_epoch` arrived from the controller. Only
    /// honored from `Idle` — a rotation already in flight ignores further
    /// directives (no re-entrant rotation).
    pub fn on_directive(&mut self, new_epoch: u32) -> Option<RotationAction> {
        match self.phase {
            RotationPhase::Idle => {
                self.phase = RotationPhase::Overlapping { new_epoch };
                Some(RotationAction::MintBringUpSubmit { epoch: new_epoch })
            }
            _ => None,
        }
    }

    /// A session/handshake observation on the new epoch's device arrived.
    /// `rx_corroborated` must be true (real inbound traffic seen, not just a
    /// handshake) before routes are allowed to flip — see module docs.
    pub fn on_new_epoch_session(&mut self, rx_corroborated: bool) -> Option<RotationAction> {
        match self.phase {
            RotationPhase::Overlapping { new_epoch } if rx_corroborated => {
                self.phase = RotationPhase::CutOver { new_epoch };
                Some(RotationAction::FlipRoutes { epoch: new_epoch })
            }
            _ => None,
        }
    }

    /// The controller (or a local timer) reports `epoch` as retired. Only
    /// honored from `CutOver` — tearing down the old epoch's device before
    /// cutover would break the data plane.
    pub fn on_epoch_retired(&mut self, epoch: u32) -> Option<RotationAction> {
        match self.phase {
            RotationPhase::CutOver { .. } => {
                self.phase = RotationPhase::Idle;
                Some(RotationAction::TearDown { epoch })
            }
            _ => None,
        }
    }
}

// --- Role B: the per-peer overlap decision (T3) ------------------------------

/// What Role B must do about ONE rotating peer this round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleBDecision {
    /// Nothing to do: not rotating, no real pending key, or we already hold an
    /// overlap toward exactly this pending epoch.
    Skip,
    /// Stand up an overlap Device toward this peer's pending epoch.
    Start { pending_epoch: u32 },
    /// We hold an overlap toward a pending epoch the peer has moved past:
    /// retire `stale_epoch`'s overlap and stand one up toward `pending_epoch`.
    Restart { stale_epoch: u32, pending_epoch: u32 },
    /// The peer advertises a real-keyed pending epoch we cannot act on — its
    /// pubkey does not decode to a 32-byte WireGuard key, so there is nothing
    /// valid to configure a Device with. Distinct from [`RoleBDecision::Skip`]
    /// so the executor can say WHY nothing was stood up (a controller/roster
    /// bug, not a steady state) instead of silently doing nothing.
    Unusable { pending_epoch: u32 },
}

/// Decide, per peer, what Role B should do — pure, no I/O, no devices.
/// `overlapped` maps `gateway_id` -> the pending epoch our live overlap Device
/// targets.
///
/// Returns EXACTLY ONE entry per peer in `ds.peers`, in roster order. That
/// totality is the point, and it replaces two defects at once:
///
///  - **One failure aborted the whole loop.** The imperative version was a
///    `for peer in &ds.peers` whose body could `?`/`bail!`/`return Err` — so
///    one peer with a malformed pending key, or one `bring_up` collision,
///    skipped every peer BEHIND it, on every `State` event, forever, while the
///    caller only logged. With the controller rotating every gateway off one
///    global timer, the first peer in roster order reliably starved the rest.
///    A peer we cannot act on now yields its own non-actionable decision; it
///    never truncates the list.
///  - **Re-rotation was dropped.** The old guard was `contains_key(&gid)` —
///    keyed on the peer id ALONE, not on which epoch the overlap was built
///    toward. Once we held an overlap toward peer P's pending epoch 1, P's
///    next rotation was skipped silently and permanently (and finding F9 shows
///    the entry can outlive the rotation it belongs to, so it is not
///    self-healing). Comparing the epoch keeps the LEGITIMATE half of that
///    guard — the same peer, mid-rotation across many `State` events, must not
///    have its live Device churned — while turning a genuine re-rotation into
///    [`RoleBDecision::Restart`].
pub fn role_b_decisions(
    ds: &DesiredState,
    overlapped: &BTreeMap<u64, u32>,
) -> Vec<(u64, RoleBDecision)> {
    ds.peers
        .iter()
        .map(|peer| {
            let gid = peer.gateway_id;
            (gid, decide_role_b(peer, overlapped.get(&gid).copied()))
        })
        .collect()
}

/// The single-peer half of [`role_b_decisions`]. `overlapped` is the pending
/// epoch of the overlap Device we already hold toward this peer, if any.
fn decide_role_b(peer: &PeerState, overlapped: Option<u32>) -> RoleBDecision {
    // Both halves are required: `pending_key` already filters the controller's
    // `"awaiting-submission"` sentinel (the peer has been told to rotate but
    // has not submitted a real pubkey yet — nothing to overlap TOWARD), and
    // without an active key there is no rotation in progress to speak of.
    let (Some(_active), Some(pending)) = (peer.active_key(), peer.pending_key()) else {
        return RoleBDecision::Skip;
    };
    let pending_epoch = pending.epoch;
    // Checked HERE, in the pure decision, precisely because the imperative
    // version checked it deep inside the loop body and `bail!`ed the entire
    // function on failure.
    if pubkey_b64_to_hex(&pending.pubkey_b64).is_none() {
        return RoleBDecision::Unusable { pending_epoch };
    }
    match overlapped {
        // Idempotence: same peer, same pending epoch, already overlapped.
        // Re-standing it would churn a live Device.
        Some(held) if held == pending_epoch => RoleBDecision::Skip,
        // We hold an overlap toward a DIFFERENT epoch — either the peer
        // re-rotated past the one we built for, or the entry leaked from an
        // aborted rotation (F9). Either way the stale entry must not veto the
        // rotation actually in flight.
        Some(stale) => RoleBDecision::Restart { stale_epoch: stale, pending_epoch },
        None => RoleBDecision::Start { pending_epoch },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directive_from_idle_mints_and_brings_up() {
        let mut r = Rotation::new();
        assert_eq!(r.phase, RotationPhase::Idle);

        let action = r.on_directive(1);
        assert_eq!(action, Some(RotationAction::MintBringUpSubmit { epoch: 1 }));
        assert_eq!(r.phase, RotationPhase::Overlapping { new_epoch: 1 });
    }

    #[test]
    fn session_without_rx_corroboration_does_not_flip() {
        let mut r = Rotation::new();
        r.on_directive(1);
        assert_eq!(r.phase, RotationPhase::Overlapping { new_epoch: 1 });

        // MAKE-BEFORE-BREAK: a handshake-only observation (no corroborating
        // inbound rx) must NOT flip routes onto the new epoch's tun.
        let action = r.on_new_epoch_session(false);
        assert_eq!(action, None);
        assert_eq!(r.phase, RotationPhase::Overlapping { new_epoch: 1 });
    }

    #[test]
    fn corroborated_session_flips_routes() {
        let mut r = Rotation::new();
        r.on_directive(1);

        let action = r.on_new_epoch_session(true);
        assert_eq!(action, Some(RotationAction::FlipRoutes { epoch: 1 }));
        assert_eq!(r.phase, RotationPhase::CutOver { new_epoch: 1 });
    }

    #[test]
    fn retire_after_cutover_tears_down_old() {
        let mut r = Rotation::new();
        r.on_directive(1);
        r.on_new_epoch_session(true);
        assert_eq!(r.phase, RotationPhase::CutOver { new_epoch: 1 });

        let action = r.on_epoch_retired(0);
        assert_eq!(action, Some(RotationAction::TearDown { epoch: 0 }));
        assert_eq!(r.phase, RotationPhase::Idle);
    }

    #[test]
    fn duplicate_directive_while_rotating_is_ignored() {
        let mut r = Rotation::new();
        r.on_directive(1);
        assert_eq!(r.phase, RotationPhase::Overlapping { new_epoch: 1 });

        let action = r.on_directive(2);
        assert_eq!(action, None);
        assert_eq!(r.phase, RotationPhase::Overlapping { new_epoch: 1 });
    }

    #[test]
    fn retire_while_overlapping_does_not_teardown() {
        let mut r = Rotation::new();
        r.on_directive(1);
        assert_eq!(r.phase, RotationPhase::Overlapping { new_epoch: 1 });

        // Routes have NOT flipped yet (still Overlapping): tearing down the
        // old epoch's device now would break the data plane. Must be a no-op.
        let action = r.on_epoch_retired(0);
        assert_eq!(action, None);
        assert_eq!(r.phase, RotationPhase::Overlapping { new_epoch: 1 });
    }

    #[test]
    fn session_corroboration_is_idempotent_after_cutover() {
        let mut r = Rotation::new();
        r.on_directive(1);
        r.on_new_epoch_session(true);
        assert_eq!(r.phase, RotationPhase::CutOver { new_epoch: 1 });

        // Already cut over: a second corroborated-session observation must
        // NOT re-emit FlipRoutes.
        let action = r.on_new_epoch_session(true);
        assert_eq!(action, None);
        assert_eq!(r.phase, RotationPhase::CutOver { new_epoch: 1 });
    }
}
