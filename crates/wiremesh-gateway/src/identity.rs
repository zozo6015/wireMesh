use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

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

/// The sibling temp path (`<name>.tmp`) a write is staged in before it is renamed
/// into place.
fn tmp_sibling(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    path.with_file_name(name)
}

/// Atomically write `bytes` to `path` at mode 0600. The bytes are first written
/// to a sibling temp file (`<name>.tmp`, created 0600), then `rename`d over
/// `path`. Because a same-directory `rename` is atomic, a crash mid-store can
/// only ever leave the temp file — never a half-written `path` that
/// `Identity::load` might parse-accept or that would clobber a previously-valid
/// identity. The rename installs the temp file's *new* inode at `path`, replacing
/// any pre-existing file and its (possibly looser) mode.
fn write_atomic_0600(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let tmp = tmp_sibling(path);
    // Remove any stale temp left by a prior crashed store so the fresh write
    // starts clean (and cannot inherit a looser leftover mode).
    let _ = fs::remove_file(&tmp);

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true).mode(0o600);
    let mut f = opts.open(&tmp).with_context(|| format!("creating temp {}", tmp.display()))?;
    // Enforce 0600 on the temp explicitly (defends the case where it somehow
    // pre-existed under a looser umask) BEFORE it is renamed into place, so the
    // installed file is 0600 the instant it becomes visible at `path`.
    f.set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", tmp.display()))?;
    f.write_all(bytes).with_context(|| format!("writing {}", tmp.display()))?;
    f.sync_all().ok();
    drop(f);

    fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

impl Identity {
    pub fn store(&self, state_dir: &Path) -> anyhow::Result<()> {
        fs::create_dir_all(state_dir)?;
        write_atomic_0600(&state_dir.join("wg_private.key"), self.wg_private_key_b64.as_bytes())?;
        let json = serde_json::to_vec_pretty(self)?;
        write_atomic_0600(&state_dir.join("identity.json"), &json)?;
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
    fn store_replaces_identity_atomically_via_rename_not_in_place_truncate() {
        // CRASH-SAFETY: `store` must write each identity file to a temp path and
        // atomically `rename` it into place, so a crash mid-store never leaves a
        // half-written identity.json at the final path (which `Identity::load`
        // might then accept, or which would clobber a previously-valid identity).
        // Observable proxy for atomicity: a truncate-in-place write reuses the
        // destination inode, whereas a temp-file + rename installs a NEW inode.
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();

        let id1 = Identity {
            cert_pem: "CERT1".into(),
            key_pem: "KEY1".into(),
            ca_bundle_pem: "CA1".into(),
            gateway_id: 1,
            observe_key: "aaaa".into(),
            wg_private_key_b64: "a2V5MQ==".into(),
        };
        id1.store(dir.path()).unwrap();
        let identity_path = dir.path().join("identity.json");
        let ino_before = std::fs::metadata(&identity_path).unwrap().ino();

        let id2 = Identity {
            cert_pem: "CERT2".into(),
            key_pem: "KEY2".into(),
            ca_bundle_pem: "CA2".into(),
            gateway_id: 2,
            observe_key: "bbbb".into(),
            wg_private_key_b64: "a2V5Mg==".into(),
        };
        id2.store(dir.path()).unwrap();
        let ino_after = std::fs::metadata(&identity_path).unwrap().ino();

        assert_ne!(
            ino_before, ino_after,
            "store must replace identity.json via an atomic rename (new inode), \
             not truncate-and-rewrite the live file in place"
        );

        // No temp-file residue left behind after a successful store.
        let residue: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp") || n.ends_with('~'))
            .collect();
        assert!(residue.is_empty(), "store must leave no temp residue, found: {residue:?}");

        // The final file is complete and reflects the latest store.
        let loaded = Identity::load(dir.path()).unwrap();
        assert_eq!(loaded.gateway_id, 2, "final identity.json is the fully-written latest one");
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
