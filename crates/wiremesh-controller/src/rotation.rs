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
    Retire { epoch: u32 },              // the OLD (prior-active) epoch to delete
    Abort  { epoch: u32, reason: String }, // the pending epoch to drop
}

/// Immutable snapshot of one gateway's in-flight rotation — everything
/// [`decide`] needs, gathered fresh by the caller on every call (this type
/// itself holds no DB handle and does no I/O).
pub struct RotationState {
    pub pending_epoch: u32,
    pub pending_has_real_key: bool,       // pubkey != "awaiting-submission"
    pub prior_active_epoch: u32,
    pub started_at: Instant,
    pub promoted_at: Option<Instant>,     // Some once promote executed
    pub expected_peers: BTreeSet<u64>,    // currently-connected peers that must ack
    pub live_acks: BTreeSet<u64>,         // peers that have acked pending_epoch live
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
        return if now.saturating_duration_since(promoted_at) >= RETIRE_GRACE {
            RotationDecision::Retire { epoch: s.prior_active_epoch }
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
    let all_acked = !s.expected_peers.is_empty()
        && s.expected_peers.iter().all(|p| s.live_acks.contains(p));
    if all_acked {
        return RotationDecision::Promote { epoch: s.pending_epoch };
    }

    // Rule 4: otherwise, promote on the grace timeout regardless of ack
    // state (GRACE_PROMOTE < ABORT_AFTER, so a real-keyed rotation always
    // promotes by 90s — abort is only reachable via rule 2's no-real-key
    // branch).
    if now.saturating_duration_since(s.started_at) >= GRACE_PROMOTE {
        return RotationDecision::Promote { epoch: s.pending_epoch };
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
    fn base_state(t0: Instant) -> RotationState {
        RotationState {
            pending_epoch: 7,
            pending_has_real_key: true,
            prior_active_epoch: 3,
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
            RotationDecision::Promote { epoch: s.pending_epoch },
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
            RotationDecision::Promote { epoch: s.pending_epoch },
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
            ..base_state(t0)
        };
        assert_eq!(
            decide(&s, t0 + Duration::from_secs(31)),
            RotationDecision::Retire { epoch: s.prior_active_epoch },
            "RETIRE_GRACE (30s) has elapsed since promotion — the prior active epoch \
             must now be retired"
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
}
