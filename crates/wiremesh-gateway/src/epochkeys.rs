// implementer fills in EpochKey/EpochKeys/impl above

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_next_produces_valid_keypair_at_next_epoch() {
        let mut keys = EpochKeys::default();

        let k0 = keys.generate_next().unwrap().clone();
        assert_eq!(k0.epoch, 0);
        assert_eq!(k0.state, "pending");
        assert_eq!(
            crate::uapi::base64_pub_from_priv(&k0.private_key_b64).unwrap(),
            k0.pubkey_b64,
            "stored pubkey must be the real derived pubkey"
        );

        let k1 = keys.generate_next().unwrap().clone();
        assert_eq!(k1.epoch, 1);
        assert_eq!(k1.state, "pending");
        assert_ne!(
            k1.private_key_b64, k0.private_key_b64,
            "each generated epoch must have a distinct private key"
        );
    }

    #[test]
    fn from_legacy_creates_active_epoch_zero() {
        // Generate a known-valid 32-byte private key via generate_next, then
        // feed it into from_legacy as if it were the pre-rotation single key.
        let mut seed = EpochKeys::default();
        let known_valid_priv = seed.generate_next().unwrap().private_key_b64.clone();

        let keys = EpochKeys::from_legacy(&known_valid_priv).unwrap();
        assert_eq!(keys.epochs.len(), 1);
        assert_eq!(keys.epochs[0].epoch, 0);
        assert_eq!(keys.epochs[0].state, "active");
        assert_eq!(
            keys.epochs[0].pubkey_b64,
            crate::uapi::base64_pub_from_priv(&known_valid_priv).unwrap()
        );
    }

    #[test]
    fn persist_then_load_round_trips_and_is_0600() {
        use std::os::unix::fs::PermissionsExt;

        let mut keys = EpochKeys::default();
        keys.generate_next().unwrap();
        keys.generate_next().unwrap();
        assert_eq!(keys.epochs.len(), 2);

        let dir = tempfile::tempdir().unwrap();
        keys.persist(dir.path()).unwrap();

        let loaded = EpochKeys::load(dir.path()).unwrap();
        assert_eq!(loaded, Some(keys.clone()));

        let meta = std::fs::metadata(dir.path().join("epoch_keys.json")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn load_absent_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(EpochKeys::load(dir.path()).unwrap(), None);
    }

    #[test]
    fn promote_moves_pending_to_active_and_prior_active_to_retiring() {
        let mut seed = EpochKeys::default();
        let priv0 = seed.generate_next().unwrap().private_key_b64.clone();
        let mut keys = EpochKeys::from_legacy(&priv0).unwrap();

        keys.generate_next().unwrap(); // epoch 1, pending
        keys.promote(1).unwrap();

        assert_eq!(keys.by_epoch(1).unwrap().state, "active");
        assert_eq!(keys.by_epoch(0).unwrap().state, "retiring");
    }

    #[test]
    fn retire_removes_the_retiring_epoch() {
        let mut seed = EpochKeys::default();
        let priv0 = seed.generate_next().unwrap().private_key_b64.clone();
        let mut keys = EpochKeys::from_legacy(&priv0).unwrap();
        keys.generate_next().unwrap(); // epoch 1, pending
        keys.promote(1).unwrap(); // epoch1 active, epoch0 retiring

        keys.retire(0).unwrap();
        assert!(keys.by_epoch(0).is_none(), "retired epoch must be removed");
        assert_eq!(keys.epochs.len(), 1);
        assert_eq!(keys.by_epoch(1).unwrap().state, "active");

        assert!(
            keys.retire(1).is_err(),
            "retiring an active (not retiring) epoch must error"
        );
    }
}
