use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Pre-provisioned gateway identity (Cycle 4a assumes enrollment already ran —
/// see spec §7-A). `wg_private_key_b64` is the WireGuard static private key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub cert_pem: String,
    pub key_pem: String,
    pub ca_bundle_pem: String,
    pub gateway_id: u64,
    pub observe_key: String,
    pub wg_private_key_b64: String,
}

fn write_0600(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut opts = fs::OpenOptions::new();
    // `mode(0o600)` only applies the permission bits when the OS creates a *new*
    // file; if `path` already exists (e.g. a state dir left over from before this
    // fix, or created under a looser umask), `create(true).truncate(true)` reuses
    // the existing inode and its existing mode. So we still set it here for the
    // fresh-file fast path, but also explicitly re-apply it below unconditionally.
    opts.write(true).create(true).truncate(true).mode(0o600);
    use std::io::Write;
    let mut f = opts.open(path).with_context(|| format!("opening {}", path.display()))?;
    f.write_all(bytes).with_context(|| format!("writing {}", path.display()))?;
    // Explicitly enforce 0600 regardless of whether the file pre-existed with a
    // looser mode, while we still hold the open file handle.
    use std::os::unix::fs::PermissionsExt;
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", path.display()))?;
    Ok(())
}

impl Identity {
    pub fn store(&self, state_dir: &Path) -> anyhow::Result<()> {
        fs::create_dir_all(state_dir)?;
        write_0600(&state_dir.join("wg_private.key"), self.wg_private_key_b64.as_bytes())?;
        let json = serde_json::to_vec_pretty(self)?;
        write_0600(&state_dir.join("identity.json"), &json)?;
        Ok(())
    }

    pub fn load(state_dir: &Path) -> anyhow::Result<Identity> {
        let json = fs::read(state_dir.join("identity.json"))
            .with_context(|| format!("reading identity.json in {}", state_dir.display()))?;
        let id: Identity = serde_json::from_slice(&json).context("parsing identity.json")?;
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_then_load_round_trips_and_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let id = Identity {
            cert_pem: "CERT".into(),
            key_pem: "KEY".into(),
            ca_bundle_pem: "CA".into(),
            gateway_id: 42,
            observe_key: "deadbeef".into(),
            wg_private_key_b64: "cHJpdmtleQ==".into(),
        };
        id.store(dir.path()).unwrap();
        let meta = std::fs::metadata(dir.path().join("wg_private.key")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let identity_meta = std::fs::metadata(dir.path().join("identity.json")).unwrap();
        assert_eq!(identity_meta.permissions().mode() & 0o777, 0o600);
        let loaded = Identity::load(dir.path()).unwrap();
        assert_eq!(loaded.gateway_id, 42);
        assert_eq!(loaded.observe_key, "deadbeef");
        assert_eq!(loaded.wg_private_key_b64, "cHJpdmtleQ==");
        assert_eq!(loaded.cert_pem, "CERT");
    }

    #[test]
    fn load_errors_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Identity::load(dir.path()).is_err());
    }

    #[test]
    fn store_enforces_0600_even_when_files_preexist_with_looser_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();

        // Pre-create both target files with a looser (world/group-readable) mode,
        // simulating an existing state dir from before this fix (or a misconfigured
        // umask). `write_0600`'s `mode(0o600)` on OpenOptions only takes effect when
        // the OS creates a *new* file, so without an explicit chmod after writing,
        // these pre-existing files would keep their old, looser permissions.
        let key_path = dir.path().join("wg_private.key");
        let identity_path = dir.path().join("identity.json");
        fs::write(&key_path, b"stale").unwrap();
        fs::write(&identity_path, b"stale").unwrap();
        fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(&identity_path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let id = Identity {
            cert_pem: "CERT".into(),
            key_pem: "KEY".into(),
            ca_bundle_pem: "CA".into(),
            gateway_id: 7,
            observe_key: "cafef00d".into(),
            wg_private_key_b64: "cHJpdmtleQ==".into(),
        };
        id.store(dir.path()).unwrap();

        let key_meta = std::fs::metadata(&key_path).unwrap();
        assert_eq!(
            key_meta.permissions().mode() & 0o777,
            0o600,
            "wg_private.key must be 0600 even when it pre-existed with a looser mode"
        );
        let identity_meta = std::fs::metadata(&identity_path).unwrap();
        assert_eq!(
            identity_meta.permissions().mode() & 0o777,
            0o600,
            "identity.json must be 0600 even when it pre-existed with a looser mode"
        );
    }
}
