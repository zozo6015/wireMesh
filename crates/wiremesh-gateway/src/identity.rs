use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Process-local monotonic counter making each atomic-store temp path unique
/// (combined with the pid + a nanosecond clock read), so concurrent stores never
/// collide on a shared temp name.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

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

/// A UNIQUE sibling temp path for staging an atomic write — `<name>.tmp.<pid>.<seq>.<nanos>`.
/// Unique (not a fixed `<name>.tmp`) so it can never collide with a leftover
/// object, a symlink-attack plant, or a concurrent store, all of which a fixed
/// name is vulnerable to.
fn unique_tmp_path(path: &Path) -> PathBuf {
    let pid = std::process::id();
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp.{pid}.{seq}.{nanos}"));
    path.with_file_name(name)
}

/// Atomically write `bytes` to `path` at mode 0600. The bytes are first written
/// to a UNIQUE sibling temp file (created EXCLUSIVELY with O_EXCL at 0600), then
/// `rename`d over `path`. Because a same-directory `rename` is atomic, a crash
/// mid-store can only ever leave the temp file — never a half-written `path` that
/// `Identity::load` might parse-accept or that would clobber a previously-valid
/// identity. The rename installs the temp file's *new* inode at `path`, replacing
/// any pre-existing file and its (possibly looser) mode.
fn write_atomic_0600(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let tmp = unique_tmp_path(path);

    // `create_new(true)` => O_EXCL: create a brand-new file or fail. Never open an
    // existing object at the temp path (defends against a symlink/collision). If
    // this open itself fails, no temp exists yet — nothing to clean up.
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true).mode(0o600);
    let mut f = opts
        .open(&tmp)
        .with_context(|| format!("creating temp {}", tmp.display()))?;

    // Once the temp exists, ANY subsequent failure (chmod / write / fsync /
    // rename) must best-effort unlink it so a crash-free error path leaves no
    // residue — while preserving the ORIGINAL error and its context (the cleanup
    // unlink's own result is discarded so it can never mask the real failure). The
    // success path renames the temp away, so there is nothing to remove there.
    let result = (|| {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        // Enforce 0600 on the temp explicitly (defends a looser umask) BEFORE it is
        // renamed into place, so the installed file is 0600 the instant it becomes
        // visible at `path`.
        f.set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {}", tmp.display()))?;
        f.write_all(bytes)
            .with_context(|| format!("writing {}", tmp.display()))?;
        // PROPAGATE fsync failures — swallowing them (`.ok()`) would let a rename
        // publish data the kernel never durably committed.
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp.display()))?;
        drop(f);
        fs::rename(&tmp, path)
            .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))
    })();

    if result.is_err() {
        // Best-effort: the temp may still be at `tmp` (any pre-rename failure) or
        // already renamed away (impossible here — rename is the last step and a
        // failed rename leaves the temp in place). Discard this result to preserve
        // the original error.
        let _ = fs::remove_file(&tmp);
    }
    result
}

impl Identity {
    pub fn store(&self, state_dir: &Path) -> anyhow::Result<()> {
        fs::create_dir_all(state_dir)?;
        write_atomic_0600(
            &state_dir.join("wg_private.key"),
            self.wg_private_key_b64.as_bytes(),
        )?;
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

    /// Three-way classification of the on-disk identity for the idempotent-enroll
    /// guard — distinguishing "genuinely absent" from "present but momentarily
    /// unreadable", which a plain `load().is_ok()` conflates:
    ///   * `Ok(true)`  — a parseable, structurally-complete identity is present
    ///                   (`identity.json` read + JSON-parsed) → skip enroll.
    ///   * `Ok(false)` — the file is absent (`NotFound`) OR present but malformed
    ///                   JSON → fall through and (re)enroll.
    ///   * `Err(_)`    — any OTHER `io::ErrorKind` (EACCES/EIO/EISDIR, …) →
    ///                   PROPAGATE. Enrolling in this case would redeem the
    ///                   single-use token while an identity may in fact exist but
    ///                   be temporarily unreadable, risking clobbering it.
    // The doc comment above column-aligns its continuation lines under the list
    // item they belong to. Clippy wants them at the minimum indent, which
    // ragged-edges a table a human laid out on purpose, so the disagreement is
    // recorded here rather than resolved against the reader.
    #[expect(
        clippy::doc_overindented_list_items,
        reason = "the doc comment aligns its continuation lines on purpose; the lint's fix ragged-edges a hand-aligned table"
    )]
    pub fn probe(state_dir: &Path) -> anyhow::Result<bool> {
        match fs::read(state_dir.join("identity.json")) {
            // Present and parseable → skip. Present but unparseable → treat as
            // absent (re-enroll overwrites the malformed file).
            Ok(bytes) => Ok(serde_json::from_slice::<Identity>(&bytes).is_ok()),
            // Genuinely absent → not present (enroll).
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            // Any other IO failure must propagate, never be read as "absent".
            Err(e) => {
                Err(e).with_context(|| format!("probing identity.json in {}", state_dir.display()))
            }
        }
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
        assert!(
            residue.is_empty(),
            "store must leave no temp residue, found: {residue:?}"
        );

        // The final file is complete and reflects the latest store.
        let loaded = Identity::load(dir.path()).unwrap();
        assert_eq!(
            loaded.gateway_id, 2,
            "final identity.json is the fully-written latest one"
        );
    }

    #[test]
    fn store_uses_a_unique_temp_not_the_fixed_sibling_name() {
        // The atomic-store temp must be UNIQUE per store, NOT a fixed shared
        // `<name>.tmp` sibling — a fixed name is a collision / symlink-attack /
        // concurrent-store hazard (CodeRabbit finding). We simulate the fixed name
        // being OCCUPIED by an object that cannot be opened-as-a-file (a DIRECTORY,
        // which even root cannot open for writing, and which `remove_file` cannot
        // clear), planted at BOTH obvious fixed temp paths. A store that targets a
        // UNIQUE temp name is unaffected and MUST still succeed; a store hard-coded
        // to `<name>.tmp` collides and fails — which is the bug this pins against.
        //
        // Additionally specified for the implementer (NOT unit-injectable while
        // tests run as root in the container, so asserted only via spec):
        //   * create the unique temp with O_EXCL at mode 0600, and
        //   * PROPAGATE `sync_all`/fsync errors — do NOT swallow them with `.ok()`.
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("identity.json.tmp")).unwrap();
        fs::create_dir_all(dir.path().join("wg_private.key.tmp")).unwrap();
        let id = Identity {
            cert_pem: "CERT".into(),
            key_pem: "KEY".into(),
            ca_bundle_pem: "CA".into(),
            gateway_id: 9,
            observe_key: "9999".into(),
            wg_private_key_b64: "a2V5OQ==".into(),
        };
        id.store(dir.path())
            .expect("store must succeed with a unique temp even when the fixed `<name>.tmp` path is occupied");
        let loaded = Identity::load(dir.path()).unwrap();
        assert_eq!(
            loaded.gateway_id, 9,
            "final identity.json is the just-stored one"
        );
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
