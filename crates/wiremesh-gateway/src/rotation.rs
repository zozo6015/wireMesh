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

impl RotationPhase {
    /// Stable lowercase label for the `wiremesh_gateway_rotation_phase`
    /// info-gauge (B2, design §3.2 Piece 4). Mirrors
    /// [`crate::path::PathState::as_str`] — the label is part of the metric's
    /// contract, so it is derived here rather than at the render site, and it
    /// deliberately does NOT carry the epoch number (a label whose value is
    /// unbounded is a Prometheus cardinality bug; the epoch is visible in the
    /// logs and in the key store).
    pub fn as_str(&self) -> &'static str {
        match self {
            RotationPhase::Idle => "idle",
            RotationPhase::Overlapping { .. } => "overlapping",
            RotationPhase::CutOver { .. } => "cutover",
        }
    }
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
    /// Unwind everything the given epoch's rotation built: its device, its
    /// enforcer entry, and its freshly-minted `"pending"` key. Emitted only by
    /// [`Rotation::on_failed`], i.e. only for a rotation that never reached
    /// cutover, so nothing this tears down is carrying traffic (B2).
    Abort { epoch: u32 },
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
        Self {
            phase: RotationPhase::Idle,
        }
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

    /// The setup half of a rotation FAILED before the data plane ever moved:
    /// return to `Idle` so the NEXT directive is honored, and tell the caller
    /// which epoch's half-built resources to unwind (BACKLOG item 9, B2).
    ///
    /// This is the only edge out of `Overlapping` other than a cutover, and it
    /// exists because [`Rotation::on_directive`] is honored only from `Idle`:
    /// a `handle_rotate` that advanced the phase and then failed used to park
    /// the machine off-`Idle` PERMANENTLY, so the gateway silently ignored
    /// every later directive until the process restarted, and never scrubbed
    /// the old key.
    ///
    /// # `CutOver` and `Idle` return `None`, and that is load-bearing
    ///
    /// **From `CutOver` this MUST stay a no-op.** By `CutOver` the routes have
    /// already flipped onto the new epoch and the old epoch is retiring under
    /// `RETIRE_GRACE`; an abort edge here would tear the old epoch's device and
    /// key down *after* the flip, on the one path whose grace clock is the only
    /// thing keeping a peer that has not caught up from losing its session.
    /// That is make-before-break collapsing into break-before-make — the fifth
    /// member of a family of four ALREADY-DOCUMENTED routes to `RETIRE_GRACE`
    /// ~= 0 (`docs/BACKLOG.md`, "Recurring traps"), every one of which looked
    /// like a simplification when it was written. The safe unlock for a wedged
    /// `CutOver` is not an abort; it needs either an admin-rotate guard on the
    /// controller or a gateway-visible "your old epoch is gone" signal, and it
    /// is filed rather than fixed here.
    ///
    /// From `Idle` there is simply nothing in flight to unwind. Both cases are
    /// non-destructive by construction: the phase is left exactly as it was.
    pub fn on_failed(&mut self) -> Option<RotationAction> {
        match self.phase {
            RotationPhase::Overlapping { new_epoch } => {
                self.phase = RotationPhase::Idle;
                Some(RotationAction::Abort { epoch: new_epoch })
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
    Restart {
        stale_epoch: u32,
        pending_epoch: u32,
    },
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
        Some(stale) => RoleBDecision::Restart {
            stale_epoch: stale,
            pending_epoch,
        },
        None => RoleBDecision::Start { pending_epoch },
    }
}

// --- Deferred write-backs into the shared Role-B map ------------------------

/// The two facts that identify ONE Role-B overlap: the peer pending epoch it
/// was stood up toward, and the Device that carries it. Together with the peer
/// id the entry is keyed by, this is the full identity of an overlap — the peer
/// id ALONE is not, which is the whole of [`overlap_write_back`]'s reason to
/// exist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlapIdentity {
    /// The rotating peer's pending epoch this overlap targets.
    pub pending_epoch: u32,
    /// The overlap Device's ifname (`wg0o<slot>`). Carried as well as the
    /// epoch because a peer that re-rotates and then rotates BACK to the same
    /// pending epoch number (a controller restarting its epoch counter, a
    /// roster replay) would be indistinguishable on the epoch alone, while the
    /// Device is freshly allocated every time.
    pub new_tun: String,
}

/// Whether a value read out of the shared `role_b` map, `.await`ed on, and now
/// about to be written back may still be written back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteBack {
    /// The entry under the lock is the SAME overlap the caller's clone was
    /// taken from. The write-back is about the thing it was computed for.
    Apply,
    /// There is an entry for this peer, but it is a DIFFERENT overlap — the
    /// peer re-rotated while the caller was awaiting, `retire_stale_overlap`
    /// dropped the old entry and `maybe_start_role_b` inserted a new one.
    Replaced,
    /// The entry is gone entirely: the peer's overlap was retired or collapsed
    /// while the caller was awaiting.
    Vanished,
}

/// May a deferred write-back into `role_b[peer]` still be applied?
///
/// # The bug this exists to prevent
///
/// The rotation tick CLONES `role_b`'s entries, then per entry `.await`s a UAPI
/// liveness read and — on the cutover arm — `send_epoch_ack`, which opens a
/// fresh mTLS channel and can take hundreds of milliseconds. It then writes its
/// conclusions back with `role_b.lock().get_mut(&peer_id)`, i.e. matching on the
/// peer id ALONE.
///
/// That was safe only for as long as an entry for a given peer could never be
/// REPLACED while it existed — which was true while `maybe_start_role_b`'s
/// guard was `contains_key(&gid)`, and stopped being true the moment
/// [`RoleBDecision::Restart`] started removing and re-inserting. A peer that
/// re-rotates mid-`await` now gets its entry torn down and a new one built
/// toward the newer pending epoch, and every id-only write-back lands on the
/// WRONG overlap:
///
///  - `cut_over = true` on an overlap whose session has never been observed,
///    which then feeds `route_owner` an [`OverlapClaim`] claiming a proven-live
///    path — a direct make-before-break violation, routing a peer's CIDRs at a
///    Device with no session;
///  - `done = true` on the new entry, which permanently filters it out of the
///    tick's pending set, so the new epoch never gets its own cutover or ack
///    and the peer stalls until the controller grace-promotes onto a dead key;
///  - on the collapse arm, `remove(&peer_id)` drops the NEW entry while the
///    teardown that follows names the OLD epoch's Device — leaving the new
///    overlap Device and its enforcer live with no `role_b` entry to ever
///    collapse them, and `maybe_start_role_b` looping forever on a `bring_up`
///    that bails "already has a tunnel up".
///
/// So every write-back states the identity it was computed against, and this
/// decides. On anything but [`WriteBack::Apply`] the correct action is to leave
/// the entry alone: the next tick re-reads it and drives it from scratch.
pub fn overlap_write_back(taken: &OverlapIdentity, current: Option<&OverlapIdentity>) -> WriteBack {
    match current {
        None => WriteBack::Vanished,
        Some(cur) if cur == taken => WriteBack::Apply,
        Some(_) => WriteBack::Replaced,
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
/// # Where the two functions must agree, exactly
///
/// [`crate::reconcile::device_config_pinned`] `filter_map`s a peer AWAY when
/// there is no pin and no `active_pubkey_b64` (the `?` on
/// `p.active_pubkey_b64.clone()`), so such a peer is simply NOT ON THE DEVICE.
/// This function therefore returns [`EpochWatch::Gone`] for it. Falling back to
/// the snapshot hex there — which is what it used to do, by collapsing "no key
/// selected" and "the selected key does not decode" into one `unwrap_or_else`
/// — would watch a key the device provably does not hold, so `all_live` would
/// be false on every tick, `retire_all_live_since` would reset forever, and the
/// old Device + enforcer would never be torn down. That is precisely the stall
/// this function exists to remove, re-entered through the fallback.
///
/// The snapshot fallback survives for the OTHER case only: a `Some` key that
/// fails to decode. That one is defensible, because an undecodable active key
/// also makes `uapi::encode_set` fail inside `apply_state`, so the device keeps
/// whatever it last held — which is what the snapshot records. Watching a stale
/// key merely delays the retire, whereas dropping the peer would let a decode
/// glitch retire a key a live peer still needs.
///
/// A peer absent from the roster is likewise [`EpochWatch::Gone`].
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
            // NOTHING selected mirrors `device_config_pinned`'s `?`: the writer
            // dropped this peer from the device, so there is no session to
            // watch for and watching one would stall the retire forever.
            let Some(selected) = selected else {
                return (*gid, EpochWatch::Gone);
            };
            // Selected but undecodable: `encode_set` would have failed for the
            // same reason, so the device still holds what the snapshot recorded.
            let hex = pubkey_b64_to_hex(selected).unwrap_or_else(|| snapshot_hex.clone());
            (*gid, EpochWatch::Key(hex))
        })
        .collect()
}

// --- The endpoint the Role-B collapse arm must dial -------------------------

/// The endpoint the Role-B collapse arm must pin for ONE peer, or `None` when
/// it must pin nothing and leave today's behaviour untouched.
///
/// `own_active_epoch` is this gateway's own active epoch RIGHT NOW;
/// `built_at_own_epoch` is the epoch whose private key the Role-B overlap
/// toward this peer runs ([`OverlapClaim::built_at_own_epoch`]);
/// `peer_candidate` is the peer's advertised `ip:port`.
///
/// # The equal-epochs `None` is load-bearing
///
/// **Equal** means our overlap tun and our active tun run the SAME private
/// key — we never cut over. That is every ONE-SIDED rotation, and there the
/// existing base-port behaviour is *eventually* correct: the peer's retire is
/// gated on OUR overlap's session, which is live, so the peer retires,
/// `renormalize_active_listen_port` puts its active key back on its base port,
/// and our unchanged dial starts working. Convergence by waiting. Firing a
/// rotation dial there would pin a `+1` endpoint at a gateway that never moved
/// off base, breaking five green one-sided netns tests and the working
/// rotations they describe. So the new path must be a literal no-op in that
/// world **by construction, not by argument** — that is what this `None` is.
///
/// **Unequal** means our own Role-A cutover has run, so the two devices hold
/// different keys and only the active tun matches the peer's key set. This is
/// the IN-STEP case (both gateways rotating off the controller's one timer),
/// where the base-port endpoint is NEVER correct: the peer's epoch-1 key is on
/// its reserved own-tun port, our collapse gate waits for a session on the
/// active tun it therefore cannot address, and the peer's retire is gated on
/// that same session. Circular — see
/// `docs/research/in-step-rotation-rebaselined.md`.
///
/// # Only the INEQUALITY is read — never the order, never the distance
///
/// This is deliberately the exact complement of [`route_owner`]'s
/// discriminator (`built_at_own_epoch == own_active_epoch`, "the overlap still
/// runs the key our peer's roster advertises for us"). The two must stay
/// complements, or there is a state where the routes sit on the active tun
/// with no endpoint that can reach the peer — the deadlock, reopened one
/// branch over.
///
/// Writing it as `built_at < active`, or as `active - built_at == 1`, would be
/// epoch arithmetic, which is exactly the class of assumption that produced
/// bug 5 and would read green against every ordinary case.
/// `tests/collapse_dial.rs`'s
/// `only_the_inequality_is_read_never_the_order_or_the_distance` pins this.
///
/// The endpoint itself is not derived here: it IS
/// [`crate::reconcile::own_tun_endpoint`]'s answer, the same one
/// [`crate::reconcile::pending_peer_configs`] builds the overlap with. One
/// authority, two readers.
pub fn collapse_dial(
    own_active_epoch: u32,
    built_at_own_epoch: u32,
    peer_candidate: &str,
) -> Option<String> {
    if built_at_own_epoch == own_active_epoch {
        return None;
    }
    crate::reconcile::own_tun_endpoint(peer_candidate)
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

    // `#[cfg(test)] mod tests`, after `session_corroboration_is_idempotent_after_cutover`.

    // --- B2: the abort edge (design §3.2 Piece 1, §9) ------------------------

    #[test]
    fn on_failed_from_overlapping_aborts_to_idle() {
        let mut r = Rotation::new();
        r.on_directive(7);
        assert_eq!(r.phase, RotationPhase::Overlapping { new_epoch: 7 });

        let action = r.on_failed();
        assert_eq!(
            action,
            Some(RotationAction::Abort { epoch: 7 }),
            "an aborted setup must name the epoch it was building (7) so the caller's unwind \
             tears down THAT epoch's tun/enforcer/mint and not a live one"
        );
        assert_eq!(
            r.phase,
            RotationPhase::Idle,
            "Overlapping is the setup-re-entrancy phase; a rotation that failed during setup has \
             nothing in flight, so the machine must be back at Idle"
        );
    }

    #[test]
    fn on_failed_from_cutover_is_a_no_op() {
        let mut r = Rotation::new();
        r.on_directive(1);
        r.on_new_epoch_session(true);
        assert_eq!(r.phase, RotationPhase::CutOver { new_epoch: 1 });

        let action = r.on_failed();
        assert_eq!(
            action, None,
            "MAKE-BEFORE-BREAK: `CutOver` means routes have ALREADY flipped onto the new epoch \
             and the old epoch is only being kept alive for peers that have not caught up. An \
             abort edge out of `CutOver` would tear the old epoch down after the flip and \
             collapse make-before-break — that is RETIRE_GRACE-collapse route #5, and four \
             independent routes to the same collapse are already recorded in docs/BACKLOG.md \
             (\"Recurring traps\"), each of which looked like a simplification. `on_failed` is \
             an abort of SETUP only. See design §3.5 and the `evict_decision` precedent, whose \
             None-means-keep is pinned by unit tests for exactly this reason."
        );
        assert_eq!(
            r.phase,
            RotationPhase::CutOver { new_epoch: 1 },
            "a refused abort must not move the phase either — a `CutOver` that silently became \
             `Idle` would drop the retire debt and leak the old epoch's Device and private key"
        );
    }

    #[test]
    fn on_failed_from_idle_is_a_no_op() {
        let mut r = Rotation::new();
        assert_eq!(r.phase, RotationPhase::Idle);

        let action = r.on_failed();
        assert_eq!(
            action, None,
            "there is no rotation to abort from Idle; emitting an Abort here would hand the \
             caller an epoch number to tear down that nothing had built"
        );
        assert_eq!(r.phase, RotationPhase::Idle);
    }

    #[test]
    fn directive_is_honoured_immediately_after_on_failed() {
        let mut r = Rotation::new();
        r.on_directive(1);
        r.on_failed();

        let action = r.on_directive(2);
        assert_eq!(
            action,
            Some(RotationAction::MintBringUpSubmit { epoch: 2 }),
            "THE WEDGE (docs/BACKLOG.md item 9): before B2 a rotation that failed part-way left \
             the phase parked off Idle, and `on_directive` is honoured ONLY from Idle — so that \
             gateway silently ignored every later directive until the process restarted. \
             Nothing retries a RotateDirective (design C1: `broker.rs::send_rotate_if_pending` \
             fires once), so the next directive is the only chance there is. It must be taken \
             here, in the same breath as the failure — with no tick, no reconnect and no \
             restart in between."
        );
        assert_eq!(r.phase, RotationPhase::Overlapping { new_epoch: 2 });
    }

    #[test]
    fn late_session_observation_after_abort_does_not_flip_routes() {
        let mut r = Rotation::new();
        r.on_directive(1);
        r.on_failed();
        assert_eq!(r.phase, RotationPhase::Idle);

        let action = r.on_new_epoch_session(true);
        assert_eq!(
            action, None,
            "the unwind has already torn down epoch 1's Device; a liveness observation that \
             raced it must not flip routes onto a tun that no longer exists (the tick reads \
             liveness by UAPI off the run task, so a stale reading IS reachable). Routes \
             pointing at a torn-down device is a data-plane outage, not a degraded rotation."
        );
        assert_eq!(r.phase, RotationPhase::Idle);
    }
}
