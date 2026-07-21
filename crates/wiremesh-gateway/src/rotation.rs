// implementer fills in Rotation above

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
