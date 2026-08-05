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
use std::collections::{BTreeMap, HashMap};

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

// --- Route ownership: which device ONE peer's CIDRs belong on --------------

/// The device a single peer's segment CIDRs belong on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteOwner {
    /// This gateway's OWN active tun — `wg0` in steady state, `wg0e<N>` after a
    /// Role-A cutover has moved the active epoch.
    ActiveTun,
    /// The transient Role-B overlap Device this gateway holds toward the peer.
    OverlapTun,
}

/// The Role-B overlap held toward ONE peer, reduced to the two facts route
/// ownership turns on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverlapClaim {
    /// This gateway's OWN active epoch at the moment the overlap Device was
    /// brought up — i.e. the epoch whose private key that Device runs, because
    /// `maybe_start_role_b` builds every overlap on the CURRENT active key.
    pub built_at_own_epoch: u32,
    /// The overlap's session toward the peer's pending key has been observed
    /// rx-corroborated live, so it is a usable path (the Role-B cutover has
    /// run, or is running at this very moment).
    pub cut_over: bool,
}

/// Derive which device ONE peer's CIDRs belong on, from this gateway's own
/// active epoch plus whatever Role-B overlap it holds toward that peer.
///
/// # Why this is derived rather than written
///
/// Three paths used to program a peer's routes, each writing the device it
/// individually believed in:
///
///  - the **Role-A cutover** flips every peer's CIDRs onto our new-epoch tun;
///  - the **Role-B cutover** flips the rotating peer's CIDRs onto the overlap
///    Device we built toward it;
///  - the **Role-B collapse** flips them back off that overlap.
///
/// In a ONE-SIDED rotation only ever one of the two cutovers runs, so their
/// ordering could not matter and each was individually correct. In-step
/// rotation — which is what the controller's single global timer produces by
/// default — runs BOTH on the same gateway toward the SAME peer, and whichever
/// finished last won. Observed symmetrically on both gateways: Role A flipped
/// the peer onto `wg0e1`, then Role B's (by then moot) cutover clobbered it
/// back onto `wg0o0`, and the settled fabric had no connectivity
/// (`docs/research/in-step-rotation-cutover-arbitration.md`).
///
/// So ownership is decided ONCE, here, and all three paths execute the answer.
///
/// # The rule, and why the epoch comparison is the discriminator
///
/// An overlap Device toward peer P runs OUR key for the epoch that was active
/// when it was stood up, and pairs with P's own new-epoch tun — whose peer
/// entry for us carries whatever key P's roster advertises as our ACTIVE one.
/// The moment our own rotation completes, P's roster advertises our NEW epoch,
/// P re-applies, and the overlap's session is dead by construction. An overlap
/// built on an epoch we have already rotated off can therefore never be a
/// peer's settled home — regardless of which cutover ran last.
///
/// That is exactly [`OverlapClaim::built_at_own_epoch`] `==`
/// `own_active_epoch`. It also carries F8 ("Role B has no active-tun
/// awareness"): the collapse path can no longer flip routes onto the BASE tun
/// while the active tun has moved out from under it, because it does not name
/// a device at all — it drops its claim and re-derives.
///
/// # Make-before-break is preserved by the CALLERS, not weakened here
///
/// This function says where routes belong, never when to move them. Each
/// caller still proves the device it is about to name is live first: Role A
/// only cuts over on an rx-corroborated session on the new tun, Role B only on
/// one over the overlap, and the collapse only drops its claim after the
/// ACTIVE tun is proven live toward the peer's new key. Ownership changing is
/// always the consequence of a corroboration, never of a clock.
pub fn route_owner(own_active_epoch: u32, overlap: Option<OverlapClaim>) -> RouteOwner {
    match overlap {
        // The overlap is a proven-live path AND still runs the key our peer's
        // roster advertises for us: it is where this peer's traffic belongs.
        Some(o) if o.cut_over && o.built_at_own_epoch == own_active_epoch => RouteOwner::OverlapTun,
        // Everything else — no overlap, an overlap not yet proven live, or an
        // overlap stranded on an epoch we have rotated off (the in-step case)
        // — belongs on our own active tun.
        _ => RouteOwner::ActiveTun,
    }
}

// --- Which peer key the new-epoch tun should currently be live on -----------

/// What Role A should watch its new-epoch tun for, per peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochWatch {
    /// Watch the new-epoch tun for an rx-corroborated session on this pubkey
    /// hex (lowercase, UAPI wire form).
    Key(String),
    /// The peer is gone from the roster. The same apply that dropped it from
    /// desired state dropped it from the device, so there is nothing to watch —
    /// and, more to the point, a departed peer cannot still depend on our old
    /// epoch, so it must not hold the retire grace hostage.
    Gone,
}

/// Which peer key this gateway's NEW-EPOCH tun should CURRENTLY show a live
/// session on, for every peer of an in-flight Role-A rotation.
///
/// # The bug this removes
///
/// The watch set used to be a snapshot taken once, when the `RotateDirective`
/// arrived: each peer's active-key hex at that instant. That is correct for
/// exactly as long as the peer's key does not move — i.e. for a ONE-SIDED
/// rotation, which is all the suite ever exercised. When the peer rotates too,
/// its promote unpins `wg0_pins[gid]` and the very same `apply_state` rebuilds
/// our active tun with the peer's NEW key. The peer's old key is then no longer
/// configured on the device at all, `read_live_peers` can never report it, and
/// so `all_live` is false on every subsequent tick: `retire_all_live_since`
/// resets forever and [`RotationAction::TearDown`] is never signalled.
///
/// The consequence is not cosmetic. The old epoch's Device and its enforcer
/// are never torn down, which means **the retired private key is never
/// actually retired** — the point of rotating — and one Device plus one
/// enforcer leak per rotation, permanently, on a long-lived fabric.
///
/// This is the third instance in this branch of one bug class: a pass watching
/// a thing the roster has moved past. The Role-B collapse watching `base_tun`
/// while `active` had moved was the ifname version (F8); this is the key
/// version.
///
/// # The rule
///
/// **Before the cutover** the answer is the snapshot, unconditionally.
/// `handle_rotate` wrote the new tun's peer set out-of-band and NOTHING
/// re-applies to it until the cutover flips `active` onto it — so whatever the
/// roster has done since, the device still holds exactly the keys the snapshot
/// recorded, and watching anything else would watch a key that is not there.
///
/// **After the cutover** the new tun IS the active tun, and `apply_state` owns
/// its peer set. So the answer is precisely what
/// [`crate::reconcile::device_config_pinned`] would select — the `wg0_pins`
/// entry if one exists, else the roster's `active_pubkey_b64` — because that
/// is, by construction, what was last written to the device. Deriving it from
/// the same two inputs the writer uses is what keeps the watcher and the
/// device from drifting again.
///
/// A peer absent from the roster is [`EpochWatch::Gone`]. A peer whose
/// selected key does not decode falls back to the snapshot hex: watching a
/// stale key merely delays the retire, whereas dropping the peer would let a
/// roster glitch retire a key a live peer still needs.
///
/// # If the peer rotates AGAIN mid-grace
///
/// The grace restarts, and that is the intended behaviour rather than a
/// tolerated one. A second rotation moves the peer's key on the device (unpin
/// or re-pin -> full `replace_peers`), boringtun rebuilds that peer's session
/// from scratch, and `rx_bytes` for the new key is 0 until real traffic
/// arrives — so `all_live` goes false for a tick or two and
/// `retire_all_live_since` resets. That is make-before-break doing its job:
/// while a peer's session is being rebuilt is precisely when it might still
/// fall back on our old key, and retiring the old Device underneath it is the
/// one thing the grace exists to prevent.
///
/// It cannot starve indefinitely. Each reset costs one `RETIRE_GRACE`
/// (`2 * ROTATION_KEEPALIVE` = 6s), and a reset needs a KEY CHANGE, not merely
/// traffic — so starvation would require the controller to promote a peer
/// epoch more often than every 6s. The controller rotates the fabric off one
/// 30-day timer and its promote SM is bounded by a grace of its own, so the
/// achievable cadence is many orders of magnitude slower. On a wide fabric
/// rotating in step the bound is (number of peers x the spread of their
/// promotes), not unbounded: each peer's key moves once per rotation. Only a
/// controller emitting sub-6s key churn could starve this, and such a
/// controller has already broken the fabric by other means.
pub fn new_epoch_watch_keys(
    snapshot: &[(u64, String)],
    cut_over: bool,
    ds: Option<&DesiredState>,
    pinned_pubkeys: &HashMap<u64, String>,
) -> Vec<(u64, EpochWatch)> {
    snapshot
        .iter()
        .map(|(gid, snapshot_hex)| {
            // Pre-cutover: `handle_rotate` owns the new tun's peer set and
            // nothing has re-applied to it. The snapshot IS the device.
            if !cut_over {
                return (*gid, EpochWatch::Key(snapshot_hex.clone()));
            }
            // No cached desired state to re-derive from — keep watching what
            // we know rather than inventing a verdict.
            let Some(ds) = ds else {
                return (*gid, EpochWatch::Key(snapshot_hex.clone()));
            };
            let Some(peer) = ds.peers.iter().find(|p| p.gateway_id == *gid) else {
                return (*gid, EpochWatch::Gone);
            };
            // EXACTLY `device_config_pinned`'s selection rule, because that is
            // the function that wrote this device.
            let selected = match pinned_pubkeys.get(gid) {
                Some(pinned) => Some(pinned.as_str()),
                None => peer.active_pubkey_b64.as_deref(),
            };
            let hex =
                selected.and_then(pubkey_b64_to_hex).unwrap_or_else(|| snapshot_hex.clone());
            (*gid, EpochWatch::Key(hex))
        })
        .collect()
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
