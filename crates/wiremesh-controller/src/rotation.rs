//! Key-rotation Task 3: pure ack-driven promote/retire/abort decision logic.
//!
//! This module is deliberately free of any DB/async/tonic dependency: every
//! field [`RotationState`] needs is gathered by the caller (the async driver
//! in `crate::services::sync`), and [`decide`] is a plain, injectable-time
//! function so the whole promote/retire/abort state machine is exhaustively
//! unit-testable without a controller, a DB, or real wall-clock waits (see
//! the `#[cfg(test)] mod tests` below). See `.superpowers/sdd/task-3-brief.md`
//! for the full design rationale.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

/// Promote a real-keyed pending epoch this long after rotation start even
/// without a full peer-ack set (the gateway won't route-flip until its own
/// handshake is live — make-before-break is enforced gateway-side — so this
/// only advances controller bookkeeping).
pub const GRACE_PROMOTE: Duration = Duration::from_secs(90);
/// Retire (delete) the prior active epoch this long after promotion.
pub const RETIRE_GRACE: Duration = Duration::from_secs(30);
/// Abort a rotation whose gateway never submitted a real epoch key within
/// this window (non-destructive: drop the pending epoch, keep old active).
pub const ABORT_AFTER: Duration = Duration::from_secs(300);

/// What the driver (`crate::services::sync::SyncSvc::drive_rotation`) should
/// do next for one gateway's in-flight rotation, per [`decide`]'s rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationDecision {
    Wait,
    Promote { epoch: u32 },
    Retire { epoch: u32 }, // the OLD (prior-active) epoch to delete
    // Rule 1 with nothing to retire: rotation complete, drop the tracker with
    // NO DB call. A variant of its own rather than a `Wait` deliberately —
    // `Wait` leaves the tracker in place forever, which is the bug (item 5).
    Finished,
    Abort { epoch: u32, reason: String }, // the pending epoch to drop
}

/// Immutable snapshot of one gateway's in-flight rotation — everything
/// [`decide`] needs, gathered fresh by the caller on every call (this type
/// itself holds no DB handle and does no I/O).
pub struct RotationState {
    pub pending_epoch: u32,
    pub pending_has_real_key: bool, // pubkey != "awaiting-submission"
    /// The epoch that was `active` when this rotation's tracker was seeded, or
    /// `None` if that key snapshot held no `active` row at all (the legacy/gap
    /// row set `crate::db::Db::rotate_key` deliberately tolerates). `None`
    /// means "there is no prior epoch" — never "unknown", and never "epoch 0".
    /// Coercing it to 0 is BACKLOG item 5, the `Retire{0}` wedge.
    pub prior_active_epoch: Option<u32>,
    pub started_at: Instant,
    pub promoted_at: Option<Instant>,  // Some once promote executed
    pub expected_peers: BTreeSet<u64>, // currently-connected peers that must ack
    pub live_acks: BTreeSet<u64>,      // peers that have acked pending_epoch live
}

/// The pure ack-driven promote/retire/abort decision, evaluated against
/// injectable `now` (never `Instant::now()` internally) so every case below
/// is exercised deterministically without a real sleep. Rule order matters —
/// see each numbered comment, and `.superpowers/sdd/task-3-brief.md` for the
/// rationale behind the ordering (in particular: rule 2's real-key gate is
/// checked BEFORE any ack-based promotion logic, so a sentinel-keyed pending
/// epoch can never promote no matter what acks have landed).
pub fn decide(s: &RotationState, now: Instant) -> RotationDecision {
    // Rule 1: already promoted — only remaining question is whether the
    // prior active epoch's retire grace has elapsed.
    if let Some(promoted_at) = s.promoted_at {
        // (S3, BACKLOG item 5) Nothing to retire -> the rotation is complete.
        // This yields `Finished` REGARDLESS OF ELAPSED TIME, deliberately:
        // `RETIRE_GRACE` buys make-before-break time for peers still finishing
        // a handshake on the PRIOR key, and when there is no prior key there is
        // no such peer and nothing for a grace to protect. Do not "restore" a
        // grace here, and do not fall through to `Wait` — waiting leaves the
        // tracker in place forever, which IS the bug item 5 describes.
        let Some(prior_active_epoch) = s.prior_active_epoch else {
            return RotationDecision::Finished;
        };
        return if now.saturating_duration_since(promoted_at) >= RETIRE_GRACE {
            RotationDecision::Retire {
                epoch: prior_active_epoch,
            }
        } else {
            RotationDecision::Wait
        };
    }

    // Rule 2: not promoted yet. A pending epoch that still holds the
    // sentinel pubkey (no real key submitted) must NEVER promote — not even
    // if every expected peer has (somehow) already acked it live. It can
    // only ever Wait or, past the abort deadline, Abort.
    if !s.pending_has_real_key {
        return if now.saturating_duration_since(s.started_at) >= ABORT_AFTER {
            RotationDecision::Abort {
                epoch: s.pending_epoch,
                reason: "no epoch key submitted before abort deadline".to_string(),
            }
        } else {
            RotationDecision::Wait
        };
    }

    // Rule 3: real key present. Promote immediately once every currently
    // expected peer has acked the new epoch live.
    let all_acked =
        !s.expected_peers.is_empty() && s.expected_peers.iter().all(|p| s.live_acks.contains(p));
    if all_acked {
        return RotationDecision::Promote {
            epoch: s.pending_epoch,
        };
    }

    // Rule 4: otherwise, promote on the grace timeout regardless of ack
    // state (GRACE_PROMOTE < ABORT_AFTER, so a real-keyed rotation always
    // promotes by 90s — abort is only reachable via rule 2's no-real-key
    // branch).
    //
    // KNOWN HAZARD (recorded, not fixed — see
    // `docs/research/key-rotation-teardown-notes.md` §E): because this
    // promotes with ZERO acks, the ack signal is an accelerator and never a
    // veto. A real key the gateway is not actually serving on that epoch's
    // tun can therefore never be acked by anyone, yet is promoted to
    // `active` here at the deadline — the rotation "succeeds" onto a key
    // that cannot carry traffic instead of aborting. Do not "simplify" this
    // rule without reading §E; the fix is a threshold decision, because rule
    // 4 legitimately exists so an offline peer cannot block a rotation
    // forever.
    if now.saturating_duration_since(s.started_at) >= GRACE_PROMOTE {
        return RotationDecision::Promote {
            epoch: s.pending_epoch,
        };
    }

    // Rule 5: nothing has triggered yet.
    RotationDecision::Wait
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::time::{Duration, Instant};

    /// Default `RotationState` with a real key already submitted, no acks
    /// yet, and no promotion/retirement in flight. Override individual
    /// fields per case with struct-update syntax to keep each test focused
    /// on the one thing it's checking.
    ///
    /// (S3) `prior_active_epoch` is `Some(3)` — the ORDINARY case, a rotation
    /// that has a real prior epoch to retire. The `None` case is not a
    /// variation on a normal rotation, it is the absence the whole of item 5
    /// is about, so every test that wants it says so explicitly rather than
    /// inheriting it here.
    fn base_state(t0: Instant) -> RotationState {
        RotationState {
            pending_epoch: 7,
            pending_has_real_key: true,
            prior_active_epoch: Some(3),
            started_at: t0,
            promoted_at: None,
            expected_peers: BTreeSet::new(),
            live_acks: BTreeSet::new(),
        }
    }

    #[test]
    fn promote_when_all_expected_peers_acked() {
        let t0 = Instant::now();
        let s = RotationState {
            expected_peers: BTreeSet::from([2, 3]),
            live_acks: BTreeSet::from([2, 3]),
            ..base_state(t0)
        };
        assert_eq!(
            decide(&s, t0 + Duration::from_secs(10)),
            RotationDecision::Promote {
                epoch: s.pending_epoch
            },
            "all expected peers have acked the real-keyed pending epoch — must promote \
             immediately, well before the 90s grace deadline"
        );
    }

    #[test]
    fn wait_when_not_all_peers_acked_before_grace() {
        let t0 = Instant::now();
        let s = RotationState {
            expected_peers: BTreeSet::from([2, 3]),
            live_acks: BTreeSet::from([2]),
            ..base_state(t0)
        };
        assert_eq!(
            decide(&s, t0 + Duration::from_secs(10)),
            RotationDecision::Wait,
            "only one of two expected peers has acked, and we're well inside the 90s \
             grace window — must not promote yet"
        );
    }

    #[test]
    fn grace_promotes_after_90s_without_full_acks() {
        let t0 = Instant::now();
        let s = RotationState {
            expected_peers: BTreeSet::from([2]),
            live_acks: BTreeSet::new(),
            ..base_state(t0)
        };
        assert_eq!(
            decide(&s, t0 + Duration::from_secs(91)),
            RotationDecision::Promote {
                epoch: s.pending_epoch
            },
            "no peer has acked at all, but GRACE_PROMOTE (90s) has elapsed since \
             started_at — the real-keyed pending epoch must promote on the grace \
             timeout regardless of ack state"
        );
    }

    #[test]
    fn no_promote_without_real_key_even_with_acks() {
        let t0 = Instant::now();
        let s = RotationState {
            pending_has_real_key: false,
            expected_peers: BTreeSet::from([2]),
            live_acks: BTreeSet::from([2]),
            ..base_state(t0)
        };
        assert_eq!(
            decide(&s, t0 + Duration::from_secs(10)),
            RotationDecision::Wait,
            "key safety case: the pending epoch still holds the sentinel pubkey (no \
             real key submitted), so it must NEVER promote — not even when every \
             expected peer has (somehow) already acked it live"
        );
    }

    #[test]
    fn abort_when_no_key_submitted_by_deadline() {
        let t0 = Instant::now();
        let s = RotationState {
            pending_has_real_key: false,
            ..base_state(t0)
        };
        match decide(&s, t0 + Duration::from_secs(301)) {
            RotationDecision::Abort { epoch, .. } => assert_eq!(
                epoch, s.pending_epoch,
                "Abort must target the pending epoch that never got a real key"
            ),
            other => panic!(
                "expected RotationDecision::Abort {{ epoch: {}, .. }} once ABORT_AFTER \
                 (300s) has elapsed with no real key submitted, got: {other:?}",
                s.pending_epoch
            ),
        }
    }

    #[test]
    fn wait_before_abort_deadline_without_key() {
        let t0 = Instant::now();
        let s = RotationState {
            pending_has_real_key: false,
            ..base_state(t0)
        };
        assert_eq!(
            decide(&s, t0 + Duration::from_secs(10)),
            RotationDecision::Wait,
            "no real key yet, but well inside the 300s abort deadline — must not \
             abort prematurely"
        );
    }

    #[test]
    fn retire_prior_active_after_promote_grace() {
        let t0 = Instant::now();
        let s = RotationState {
            promoted_at: Some(t0),
            prior_active_epoch: Some(3),
            ..base_state(t0)
        };
        assert_eq!(
            decide(&s, t0 + Duration::from_secs(31)),
            RotationDecision::Retire { epoch: 3 },
            "RETIRE_GRACE (30s) has elapsed since promotion and there IS a prior active \
             epoch (Some(3)) — it must now be retired. (S3: the expected epoch is written \
             literally rather than read back off `s.prior_active_epoch`, because that field \
             is now an `Option<u32>` and unwrapping it in the assertion would let a \
             `None`-coerced-to-`Some(0)` regression pick its own expected value and pass.)"
        );
    }

    #[test]
    fn wait_after_promote_before_retire_grace() {
        let t0 = Instant::now();
        let s = RotationState {
            promoted_at: Some(t0),
            ..base_state(t0)
        };
        assert_eq!(
            decide(&s, t0 + Duration::from_secs(5)),
            RotationDecision::Wait,
            "only 5s since promotion — well inside the 30s retire grace — must not \
             retire the prior active epoch yet"
        );
    }

    // =======================================================================
    // S3 — `prior_active_epoch: Option<u32>` (BACKLOG item 5, design §4).
    //
    // The bug: a tracker seeded from a key snapshot with NO `active` row used
    // to get `prior_active_epoch = 0` via `.unwrap_or(0)` at three seed sites
    // in `services::sync`. Once promoted, rule 1 below yields
    // `Retire { epoch: 0 }` on every tick; `Db::retire_epoch` CASes on
    // `state = 'retiring'`, matches nothing, and `drive_rotation_for`'s
    // `Retire`/`CasOutcome::NoMatch` arm DELIBERATELY keeps the tracker (see
    // that arm's comment — removing it hands a live `retiring` row to
    // `sweep_rotations`' grace-free step-3 orphan path, collapsing
    // `RETIRE_GRACE`). So the tracker is wedged forever and eats the next
    // rotation's one and only ack.
    //
    // The fix is a TYPE change, not a guard: absence is carried as `None`
    // instead of being coerced to a number that means something else. These
    // tests pin the two halves of that — what `None` must do, and what it must
    // NOT do — plus the over-correction, plus the rules that must not move.
    //
    // Reachability (design §1.2 C3): this state is NOT reachable from any
    // current mutation path — `promote_epoch` verifies a real-keyed `pending`
    // row before demoting the active row, and `enroll_gateway` always inserts
    // an epoch-0 `active` row. It is reachable only for a legacy/gap key-row
    // set, which `Db::rotate_key` deliberately tolerates. S3 is hardening. It
    // is still worth pinning precisely BECAUSE `Retire{0}` is
    // indistinguishable from a legitimate first rotation's retire, so any
    // future change that makes the state reachable would wedge silently.
    // =======================================================================

    /// Rule 1's absent-prior-epoch leg: a promoted rotation with nothing to
    /// retire is COMPLETE, and says so with its own decision.
    ///
    /// `Finished` rather than `Wait` is the whole point (design §4.2 step 2):
    /// `Wait` would leave the tracker in the map forever, which is the bug
    /// wearing a different mask.
    #[test]
    fn promoted_with_no_prior_active_epoch_is_finished() {
        let t0 = Instant::now();
        let s = RotationState {
            promoted_at: Some(t0),
            prior_active_epoch: None,
            ..base_state(t0)
        };
        assert_eq!(
            decide(&s, t0 + Duration::from_secs(31)),
            RotationDecision::Finished,
            "this rotation promoted and there was NO prior active epoch to retire \
             (`prior_active_epoch == None`), so the rotation is over and `decide` must \
             say `Finished` — the decision `drive_rotation_for` maps to \
             `TrackerEffect::Finished` with no DB call, which is what finally clears the \
             tracker. Returning `Wait` here instead would leave the tracker in the map \
             forever, which is BACKLOG item 5's bug in a different shape"
        );
    }

    /// `None` short-circuits rule 1 BEFORE the `RETIRE_GRACE` comparison, so
    /// elapsed time cannot change the answer.
    ///
    /// Separate from the test above on purpose: that one pins the decision at
    /// one instant; this one pins that the decision does not depend on the
    /// clock at all. A fix that wrote `if elapsed >= RETIRE_GRACE { match
    /// prior { Some(e) => Retire{e}, None => Finished } } else { Wait }` would
    /// pass the test above and fail this one — and it would be a real defect,
    /// because it parks a finished rotation's tracker in `Wait` for 30s for no
    /// reason.
    #[test]
    fn finished_regardless_of_elapsed_time_when_there_is_no_prior_active_epoch() {
        let t0 = Instant::now();
        let s = RotationState {
            promoted_at: Some(t0),
            prior_active_epoch: None,
            ..base_state(t0)
        };
        for secs in [0u64, 1, 29, 30, 31, 3600] {
            assert_eq!(
                decide(&s, t0 + Duration::from_secs(secs)),
                RotationDecision::Finished,
                "at {secs}s after promotion with `prior_active_epoch == None`: there is \
                 nothing to retire, so `RETIRE_GRACE` has nothing to protect and must not \
                 be consulted at all. `Finished` is the answer at EVERY instant — a \
                 `Wait` before 30s would park a finished rotation's tracker for half a \
                 minute for no reason"
            );
        }
    }

    /// THE TRAP (design §4.3, §10 R5). `None` must never be coerced to `0`.
    ///
    /// This is deliberately a NEGATIVE assertion rather than a restatement of
    /// the two positive tests above, because the thing that must never happen
    /// is what the failure message has to explain, and because the failure
    /// mode it guards is silent by construction: `Retire { epoch: 0 }` is a
    /// perfectly legitimate decision for a gateway rotating off its epoch-0
    /// enrollment key, so nothing downstream can tell the two apart. The type
    /// is the only place the distinction survives.
    #[test]
    fn none_prior_active_epoch_is_never_coerced_to_retire_zero() {
        let t0 = Instant::now();
        let s = RotationState {
            promoted_at: Some(t0),
            prior_active_epoch: None,
            ..base_state(t0)
        };
        for secs in [0u64, 29, 30, 31, 3600] {
            let d = decide(&s, t0 + Duration::from_secs(secs));
            assert!(
                !matches!(d, RotationDecision::Retire { .. }),
                "at {secs}s after promotion, `decide` produced {d:?} for a rotation with \
                 `prior_active_epoch == None`. `Retire{{0}}` is indistinguishable from a \
                 legitimate first rotation's retire; `None` must never be coerced to 0. \
                 Downstream, `Db::retire_epoch` CASes on `state = 'retiring'` and matches \
                 nothing, `drive_rotation_for`'s `NoMatch` arm deliberately KEEPS the \
                 tracker (removing it would hand a live `retiring` row to \
                 `sweep_rotations`' grace-free orphan path and collapse `RETIRE_GRACE`), \
                 and `evict_decision`'s `None`-means-keep leg never clears it — so the \
                 tracker wedges forever and eats the next rotation's one and only ack"
            );
        }
    }

    /// The OVER-CORRECTION guard, and the reason `Option` is the fix rather
    /// than "treat 0 as absent".
    ///
    /// Epoch 0 is a REAL epoch: `enroll_gateway` inserts every gateway's
    /// baseline key at epoch 0, so a gateway's very first rotation genuinely
    /// has `prior_active_epoch == Some(0)` and genuinely must retire it. A
    /// fix that spelled this `if prior == 0 { Finished }` would strand that
    /// row on disk — and a stranded `retiring` row excludes its gateway from
    /// `Db::gateways_with_rotation_state`, i.e. from the rotation timer, for
    /// the life of the deployment (the failure `tests/rotation_retire_drive.rs`
    /// exists for). Same class of defect as the bug S3 fixes, opposite sign.
    #[test]
    fn a_genuine_prior_active_epoch_zero_still_retires_zero() {
        let t0 = Instant::now();
        let s = RotationState {
            promoted_at: Some(t0),
            prior_active_epoch: Some(0),
            ..base_state(t0)
        };
        assert_eq!(
            decide(&s, t0 + Duration::from_secs(31)),
            RotationDecision::Retire { epoch: 0 },
            "`Some(0)` is a gateway retiring its epoch-0 ENROLLMENT key — the ordinary \
             first rotation, and a row that really is on disk in state 'retiring'. It \
             must still be retired. The distinction S3 introduces is `Some(0)` (a real \
             epoch numbered zero) versus `None` (no prior epoch at all); a fix that \
             collapses them by testing `prior == 0` strands the row, and a stranded \
             'retiring' row removes its gateway from the rotation timer permanently \
             (`Db::gateways_with_rotation_state`)"
        );
    }

    /// The edges that must not move (design §9): rules 2, 3 and 4 do not read
    /// `prior_active_epoch` at all, and making it an `Option` must not give
    /// them an opinion about it.
    ///
    /// One test, four probes, because the property IS the conjunction: "the
    /// absent prior epoch is invisible to every rule except rule 1". Splitting
    /// it into four would name the same property four times.
    #[test]
    fn rules_2_to_4_are_unaffected_by_an_absent_prior_active_epoch() {
        let t0 = Instant::now();

        // Rule 2, inside the abort window: sentinel key, must Wait.
        let s = RotationState {
            pending_has_real_key: false,
            prior_active_epoch: None,
            ..base_state(t0)
        };
        assert_eq!(
            decide(&s, t0 + Duration::from_secs(10)),
            RotationDecision::Wait,
            "rule 2 (no real key, inside ABORT_AFTER) must be reached and answer `Wait` \
             regardless of `prior_active_epoch`. Rule 1 short-circuits on `promoted_at`, \
             which is `None` here, so an absent prior epoch must not divert this case"
        );

        // Rule 2, past the abort deadline: sentinel key, must Abort the PENDING
        // epoch — never the (absent) prior one.
        let s = RotationState {
            pending_has_real_key: false,
            prior_active_epoch: None,
            ..base_state(t0)
        };
        match decide(&s, t0 + Duration::from_secs(301)) {
            RotationDecision::Abort { epoch, .. } => assert_eq!(
                epoch, 7,
                "rule 2's `Abort` must target the PENDING epoch (7), which is present and \
                 real. An absent `prior_active_epoch` is a different field and must not \
                 leak into this decision"
            ),
            other => panic!(
                "expected `RotationDecision::Abort {{ epoch: 7, .. }}` once ABORT_AFTER \
                 (300s) has elapsed with no real key submitted — `prior_active_epoch == \
                 None` must not change which rule fires — got: {other:?}"
            ),
        }

        // Rule 3: real key + full acks promotes immediately.
        let s = RotationState {
            prior_active_epoch: None,
            expected_peers: BTreeSet::from([2, 3]),
            live_acks: BTreeSet::from([2, 3]),
            ..base_state(t0)
        };
        assert_eq!(
            decide(&s, t0 + Duration::from_secs(10)),
            RotationDecision::Promote { epoch: 7 },
            "rule 3 (real key, every expected peer acked) must promote on acks whether or \
             not there is a prior active epoch to retire afterwards. Having nothing to \
             retire is a fact about the END of the rotation, not about whether it may \
             promote"
        );

        // Rule 4: real key, no acks, past GRACE_PROMOTE.
        let s = RotationState {
            prior_active_epoch: None,
            expected_peers: BTreeSet::from([2]),
            live_acks: BTreeSet::new(),
            ..base_state(t0)
        };
        assert_eq!(
            decide(&s, t0 + Duration::from_secs(91)),
            RotationDecision::Promote { epoch: 7 },
            "rule 4 (real key, GRACE_PROMOTE elapsed, zero acks) must still grace-promote \
             with `prior_active_epoch == None`. This is the recorded KNOWN HAZARD §E path \
             and S3 must not change its threshold or its reachability — design §3.3 and \
             §9 list rule 4 as an edge that must not move"
        );
    }
}
