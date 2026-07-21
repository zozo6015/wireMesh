//! Multi-epoch WireGuard key store (key-rotation Task 5). Mirrors
//! `state.rs`'s fail-static persistence idiom (0600, atomic tmp+rename,
//! fsync file and directory) but for the gateway's own rotating keypairs
//! rather than controller-sourced desired state.
use anyhow::{anyhow, Context};
use rand::{rngs::OsRng, RngCore};
use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// One epoch's keypair plus its position in the promote/retire lifecycle:
/// `"pending"` (generated, not yet advertised as active) -> `"active"`
/// (currently in use) -> `"retiring"` (superseded, kept briefly so in-flight
/// traffic from peers who haven't caught up to the new epoch still
/// decrypts) -> removed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EpochKey {
    pub epoch: u32,
    pub private_key_b64: String,
    pub pubkey_b64: String,
    pub state: String,
}

/// The gateway's full set of epoch keys, ordered by insertion (not
/// necessarily by epoch number, though `generate_next` always appends the
/// newest at the end).
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct EpochKeys {
    pub epochs: Vec<EpochKey>,
}

impl EpochKeys {
    /// Migrate a pre-rotation single static key into a one-epoch store:
    /// epoch 0, state "active". Used on first boot of a rotation-aware
    /// gateway against a `state.json`/config that only ever knew one key.
    pub fn from_legacy(private_key_b64: &str) -> anyhow::Result<Self> {
        let pubkey_b64 = crate::uapi::base64_pub_from_priv(private_key_b64)
            .context("deriving pubkey for legacy epoch-0 key")?;
        Ok(EpochKeys {
            epochs: vec![EpochKey {
                epoch: 0,
                private_key_b64: private_key_b64.to_string(),
                pubkey_b64,
                state: "active".to_string(),
            }],
        })
    }

    /// Generate a fresh keypair at the next epoch number (`max epoch + 1`,
    /// or `0` if the store is empty), append it in state `"pending"`, and
    /// return a reference to it. The private key is 32 raw random bytes —
    /// WireGuard/x25519 clamps on use, so no hand-clamping is needed here
    /// (matches what `wg genkey` effectively produces).
    pub fn generate_next(&mut self) -> anyhow::Result<&EpochKey> {
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        let private_key_b64 = crate::uapi::base64_encode(&raw);
        let pubkey_b64 = crate::uapi::base64_pub_from_priv(&private_key_b64)
            .context("deriving pubkey for newly generated epoch key")?;
        let epoch = self.epochs.iter().map(|k| k.epoch).max().map_or(0, |m| m + 1);
        self.epochs.push(EpochKey {
            epoch,
            private_key_b64,
            pubkey_b64,
            state: "pending".to_string(),
        });
        Ok(self.epochs.last().expect("just pushed"))
    }

    /// Persist to `state_dir/epoch_keys.json`, 0600, atomic tmp+rename +
    /// fsync (file and containing directory) — mirrors `state.rs::save`.
    pub fn persist(&self, state_dir: &Path) -> anyhow::Result<()> {
        fs::create_dir_all(state_dir)?;
        let tmp = state_dir.join("epoch_keys.json.tmp");
        let final_path = state_dir.join("epoch_keys.json");
        {
            use std::io::Write;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .context("opening epoch_keys.json.tmp")?;
            f.write_all(&serde_json::to_vec_pretty(self)?)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &final_path).context("atomically renaming epoch_keys.json")?;
        // See state.rs::save: the rename's directory-entry update isn't
        // itself durable until the directory inode is fsynced.
        fs::File::open(state_dir)
            .and_then(|d| d.sync_all())
            .context("fsyncing state_dir after rename")?;
        Ok(())
    }

    /// Load from `state_dir/epoch_keys.json`. `Ok(None)` iff the file is
    /// simply absent; any other I/O or parse failure is an `Err`.
    pub fn load(state_dir: &Path) -> anyhow::Result<Option<EpochKeys>> {
        let path = state_dir.join("epoch_keys.json");
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(
                serde_json::from_slice(&bytes).context("parsing epoch_keys.json")?,
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).context("reading epoch_keys.json"),
        }
    }

    /// The current active epoch, if any.
    pub fn active(&self) -> Option<&EpochKey> {
        self.epochs.iter().find(|k| k.state == "active")
    }

    /// Look up an epoch by number.
    pub fn by_epoch(&self, epoch: u32) -> Option<&EpochKey> {
        self.epochs.iter().find(|k| k.epoch == epoch)
    }

    /// Promote `epoch` from "pending" to "active", demoting whatever was
    /// previously "active" (if anything) to "retiring". Errors if `epoch`
    /// doesn't exist or isn't currently "pending".
    pub fn promote(&mut self, epoch: u32) -> anyhow::Result<()> {
        if !self
            .epochs
            .iter()
            .any(|k| k.epoch == epoch && k.state == "pending")
        {
            return Err(anyhow!(
                "cannot promote epoch {epoch}: not found or not in \"pending\" state"
            ));
        }
        for k in self.epochs.iter_mut() {
            if k.state == "active" {
                k.state = "retiring".to_string();
            }
        }
        let target = self
            .epochs
            .iter_mut()
            .find(|k| k.epoch == epoch)
            .expect("checked above");
        target.state = "active".to_string();
        Ok(())
    }

    /// Remove `epoch` iff it is currently "retiring". Errors otherwise
    /// (not found, or found but not "retiring").
    pub fn retire(&mut self, epoch: u32) -> anyhow::Result<()> {
        let is_retiring = self
            .epochs
            .iter()
            .any(|k| k.epoch == epoch && k.state == "retiring");
        if !is_retiring {
            return Err(anyhow!(
                "cannot retire epoch {epoch}: not found or not in \"retiring\" state"
            ));
        }
        self.epochs.retain(|k| k.epoch != epoch);
        Ok(())
    }
}

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
