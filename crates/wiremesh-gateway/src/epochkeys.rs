//! Multi-epoch WireGuard key store (key-rotation Task 5). Mirrors
//! `state.rs`'s fail-static persistence idiom (0600, atomic tmp+rename,
//! fsync file and directory) but for the gateway's own rotating keypairs
//! rather than controller-sourced desired state.
//!
//! Lifecycle wiring (Backlog 3 Task 1 — durable promote/retire): `promote`
//! is driven by the Role-A FlipRoutes cutover in `main.rs`'s rotation tick
//! (the moment the data plane flips onto the new epoch's tun) and `retire`
//! by `service_retire` (the old Device's teardown) — each followed by a
//! `persist`, so a reboot at any point of a rotation sees the store the data
//! plane actually reached. `retire` REMOVES the epoch's entry outright
//! (`Vec::retain`), so the retired PRIVATE key is scrubbed from the
//! serialized `epoch_keys.json` bytes on the next `persist` — retirement is
//! key destruction in THIS file, not a state flag next to a still-readable
//! key. Boot selects its key via [`EpochKeys::select_boot_key`].
//!
//! SCOPE OF THE SCRUB (known residual): retirement destroys key material in
//! `epoch_keys.json` ONLY. The epoch-0 key remains on disk in
//! `identity.json`/`wg_private.key` (the enrollment identity is never
//! rewritten — follow-up, Tasks 2-4 territory), and `select_boot_key`'s
//! legacy fallback will happily boot it again if `epoch_keys.json` is
//! DELETED (an absent file is the fallback branch by design; a present but
//! corrupt file fails loudly at `load` instead).
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

/// The gateway's full set of epoch keys.
///
/// **At most one entry per epoch**, and that is the invariant every mutation
/// upholds: [`EpochKeys::generate_next_at`] replaces a `"pending"` occupant by
/// REMOVING it before pushing, and [`EpochKeys::retire`] /
/// [`EpochKeys::discard_pending`] remove by epoch.
///
/// **Insertion order carries no meaning and must not be relied on.** The
/// vector may hold holes — a retired epoch is removed outright, never
/// tombstoned — and it need not be ascending, because a mint lands at the
/// epoch the controller's directive named, which is not necessarily the
/// highest one present (B2: the gateway no longer numbers epochs itself; see
/// `generate_next_at`). Every lookup is therefore by **state**
/// ([`EpochKeys::active`]) or by **exact epoch** ([`EpochKeys::by_epoch`],
/// `promote`, `retire`, `discard_pending`); nothing reads position.
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

    /// Generate a fresh keypair AT THE EPOCH THE CONTROLLER NAMED, store it in
    /// state `"pending"`, and return a reference to it. The private key is 32
    /// raw random bytes — WireGuard/x25519 clamps on use, so no hand-clamping
    /// is needed here (matches what `wg genkey` effectively produces).
    ///
    /// # Why the caller supplies the number (B2, design §3.2 Piece 2c)
    ///
    /// This replaced a `generate_next` that numbered epochs itself as local
    /// `max(epoch) + 1`. That was a SECOND, independent counter: the controller
    /// numbers a rotation `MAX(epoch) + 1` over ITS `gateway_key` rows
    /// (`controller/src/db.rs::Db::rotate_key`), and the two agreed only
    /// because nothing ever removed a local entry. Once a failed rotation
    /// scrubs its orphan mint (`discard_pending`, B2's whole point) they
    /// diverge: the controller re-issues epoch *n+1* while this store's max is
    /// back at *n-1*, so the gateway would submit its pubkey under the
    /// directive epoch and store it under a different one. The cutover's
    /// `promote(directive_epoch)` would then miss, nothing would be demoted to
    /// `"retiring"`, and `service_retire`'s `retire` would miss too — leaving
    /// the OLD PRIVATE KEY on disk forever, which is precisely the security
    /// half B2 exists to deliver. The controller is the single authority on
    /// epoch numbering; this function takes its answer.
    ///
    /// # Occupant handling — split by state, deliberately
    ///
    /// * `"pending"` at `epoch` → **replaced**. A crash between the mint's
    ///   persist and the unwind can strand a local `"pending"` row at `n`
    ///   while the controller's abort (`drop_pending_epoch`) DELETEs its own,
    ///   freeing `n` to be re-issued. Refusing here would fail that mint
    ///   forever — a second permanent wedge wearing a safety guard's clothes.
    ///   The stale entry is removed (not flipped, not overwritten in place),
    ///   because only removal takes its private key out of the bytes
    ///   `persist` writes.
    /// * `"active"` / `"retiring"` at `epoch` → **`Err`**, no mutation. Those
    ///   are keys the data plane is using or still owes a grace to.
    ///
    /// # Ordering invariant
    ///
    /// **Nothing mutates `self.epochs` until every fallible step has already
    /// succeeded** — guard, then derive, then replace, then push. Pubkey
    /// derivation can fail, and mutating first would leave the occupant
    /// scrubbed with nothing minted while the caller's `RotationResidue`
    /// still says no mint happened, so the unwind would skip it. This store is
    /// a shared `Arc<Mutex<EpochKeys>>` with three writers (`handle_rotate`,
    /// the tick's cutover promote, `service_retire`), so a partial in-memory
    /// mutation left by one is liable to be persisted by whichever runs next.
    pub fn generate_next_at(&mut self, epoch: u32) -> anyhow::Result<&EpochKey> {
        // 1. GUARD — refuse a live occupant. No mutation on this path.
        if let Some(occupant) = self.epochs.iter().find(|k| k.epoch == epoch) {
            if occupant.state != "pending" {
                return Err(anyhow!(
                    "cannot mint epoch {epoch}: already occupied by a \"{}\" key",
                    occupant.state
                ));
            }
        }
        // 2. DERIVE — the last fallible step, still before any mutation.
        let mut raw = [0u8; 32];
        OsRng.fill_bytes(&mut raw);
        let private_key_b64 = crate::uapi::base64_encode(&raw);
        let pubkey_b64 = crate::uapi::base64_pub_from_priv(&private_key_b64)
            .context("deriving pubkey for newly generated epoch key")?;
        // 3. REPLACE — remove any (necessarily "pending") occupant, so the
        //    stale private key leaves the serialized bytes at the next
        //    `persist`, and so the one-entry-per-epoch invariant holds.
        self.epochs.retain(|k| k.epoch != epoch);
        // 4. PUSH.
        self.epochs.push(EpochKey {
            epoch,
            private_key_b64,
            pubkey_b64,
            state: "pending".to_string(),
        });
        // Looked up by epoch rather than `.last()`: the struct's documented
        // invariant is that position means nothing, and leaving zero
        // order-dependent expressions in this file is what makes that
        // greppable rather than aspirational.
        Ok(self
            .epochs
            .iter()
            .find(|k| k.epoch == epoch)
            .expect("just pushed"))
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
            // `mode(0o600)` above only applies the permission bits when the OS
            // creates a *new* file; if `tmp` already existed (e.g. a leftover
            // from a prior crashed write, or created under a looser umask),
            // `create(true).truncate(true)` reuses the existing inode and its
            // existing mode, which the atomic rename below would then carry
            // onto the final `epoch_keys.json` — which holds raw WireGuard
            // PRIVATE keys. So explicitly enforce 0600 here, unconditionally,
            // while we still hold the open file handle (mirrors
            // identity.rs::write_0600).
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(std::fs::Permissions::from_mode(0o600))
                .context("chmod 0600 epoch_keys.json.tmp")?;
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

    /// Select the keypair the gateway must boot its base tun with:
    /// the persisted store's ACTIVE epoch entry when one exists, else an
    /// epoch-0 "active" entry synthesized from the legacy identity key
    /// (`Identity::wg_private_key_b64`). Pure — no I/O; the caller loads
    /// the store ([`EpochKeys::load`]) and passes it in.
    ///
    /// Fallback ladder:
    ///  1. `store` has an entry in state `"active"` → that entry, verbatim.
    ///     A `"retiring"` entry never shadows it — a crash between the
    ///     LOCAL cutover's persisted promote and the local retire must
    ///     reboot onto the PROMOTED epoch, since that is the only key peers
    ///     advertise once the controller has promoted it.
    ///  2. No store, or a store with NO `"active"` entry → synthesized
    ///     epoch-0 active entry from the legacy key. NB the no-active-entry
    ///     branch has no natural producer in today's lifecycle: a crash
    ///     between `generate_next_at`+persist and the cutover's promote leaves
    ///     epoch 0 STILL `"active"` alongside the `"pending"` mint (branch 1
    ///     correctly selects epoch 0 — no cutover happened). It is
    ///     defensive hardening for a hand-edited/foreign store, pinned by
    ///     `tests/epoch_boot_key.rs`: a pending key must never boot, since
    ///     the local data plane never ran it; the legacy key is the last
    ///     state this gateway's data plane actually used.
    ///
    /// KNOWN RESIDUAL (follow-up, T2 territory): the store only records
    /// LOCAL cutovers. The controller's Rule-4 ack-less grace-promote is NOT
    /// reconciled down into it — a rotation whose new-epoch session never
    /// established locally but that the controller grace-promoted anyway
    /// leaves this store pending-only, so a reboot takes branch 2 and boots
    /// the OLD key, which post-grace-promote no peer advertises. Closing
    /// that corner needs the boot path (or Sync) to reconcile the
    /// controller's promoted epoch into the store.
    pub fn select_boot_key(
        store: Option<&EpochKeys>,
        legacy_priv_b64: &str,
    ) -> anyhow::Result<EpochKey> {
        if let Some(active) = store.and_then(|s| s.active()) {
            return Ok(active.clone());
        }
        let pubkey_b64 = crate::uapi::base64_pub_from_priv(legacy_priv_b64)
            .context("deriving pubkey for legacy boot-key fallback")?;
        Ok(EpochKey {
            epoch: 0,
            private_key_b64: legacy_priv_b64.to_string(),
            pubkey_b64,
            state: "active".to_string(),
        })
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
    /// (not found, or found but not "retiring"). Removal (not a state flip)
    /// is the scrub mechanism: once the caller `persist`s, the retired
    /// PRIVATE key is gone from `epoch_keys.json`'s bytes entirely.
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

    /// Remove `epoch` iff it is currently "pending". Errors otherwise (not
    /// found, or found but not "pending"). The mirror of [`EpochKeys::retire`]
    /// — same guard shape, same removal-is-the-scrub mechanism — for the OTHER
    /// end of an epoch's life: a key that was minted but whose rotation never
    /// reached cutover (B2, BACKLOG item 9).
    ///
    /// Every aborted rotation used to leave its mint behind: `generate_next_at`
    /// appends in state `"pending"`, `promote` is the only thing that moves it
    /// on, and `retire` refuses anything that is not `"retiring"` — so an
    /// orphan `"pending"` PRIVATE KEY had no removal path at all and they
    /// accumulated in `epoch_keys.json` without bound. This is that path.
    ///
    /// The `"pending"`-only guard is not decorative: an over-broad version
    /// would delete the live `"active"` key, or a `"retiring"` one still inside
    /// its grace. Removal (not a state flip) is what takes the key out of the
    /// bytes the caller's `persist` writes — see `retire`.
    ///
    /// Atomic by construction: the guard is followed by a `retain` with no
    /// fallible step between them, so this either removes the entry or leaves
    /// the store untouched (the ordering invariant `generate_next_at`
    /// documents, satisfied trivially here).
    pub fn discard_pending(&mut self, epoch: u32) -> anyhow::Result<()> {
        let is_pending = self
            .epochs
            .iter()
            .any(|k| k.epoch == epoch && k.state == "pending");
        if !is_pending {
            return Err(anyhow!(
                "cannot discard epoch {epoch}: not found or not in \"pending\" state"
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

    #[test]
    fn persist_enforces_0600_even_when_tmp_preexists_with_looser_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::TempDir::new().unwrap();

        // Pre-create the tmp file `persist` writes to, with a looser
        // (world-readable/writable) mode, simulating a leftover from a prior
        // crashed write (or a misconfigured umask). `OpenOptions::mode(0o600)`
        // only takes effect when the OS creates a *new* file — if the tmp
        // file already exists, `create(true).truncate(true)` reuses its
        // existing inode and mode, and the atomic rename below would carry
        // that looser mode onto the final `epoch_keys.json`, which holds raw
        // WireGuard PRIVATE keys.
        let tmp = dir.path().join("epoch_keys.json.tmp");
        std::fs::write(&tmp, b"stale").unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o666)).unwrap();

        let mut keys = EpochKeys::default();
        keys.generate_next().unwrap();
        keys.persist(dir.path()).unwrap();

        let mode = std::fs::metadata(dir.path().join("epoch_keys.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "epoch_keys.json (holds PRIVATE keys) must be 0600 even when the tmp file pre-existed world-readable"
        );
    }
}
