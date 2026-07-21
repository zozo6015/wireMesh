//! Key-rotation Task 3: pure ack-driven promote/retire/abort decision logic.
//!
//! implementer fills in decide/RotationState/consts above — see
//! `.superpowers/sdd/task-3-brief.md` for the exact API (`GRACE_PROMOTE`,
//! `RETIRE_GRACE`, `ABORT_AFTER`, `RotationDecision`, `RotationState`,
//! `pub fn decide(&RotationState, Instant) -> RotationDecision`) and the
//! exact-order rules `decide` must implement. This file intentionally does
//! NOT compile until that implementation lands above this test module — the
//! resulting compile failure is the expected RED for Task 3's unit-test half
//! (see also `crates/wiremesh-controller/tests/rotation.rs` for the
//! ack-driven integration test, and `.superpowers/sdd/task-3-report.md` for
//! the captured RED output).

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
