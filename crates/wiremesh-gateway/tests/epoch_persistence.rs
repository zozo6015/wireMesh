//! Backlog 3 Task 1 (durable key promote/retire — SECURITY): the durable
//! persistence contract the fix relies on, pinned through the PUBLIC
//! `EpochKeys` surface only (`epochkeys.rs`'s own `#[cfg(test)]` module
//! belongs to src/ and is off-limits to this test-author).
//!
//! These tests compile and PASS against current code — `promote`/`retire`/
//! `persist`/`load` all already work in isolation. What they pin is the exact
//! cross-process-boundary behavior the implementation MUST route through:
//!
//!   * Role-A FlipRoutes cutover  -> `promote(new)` + `persist`  => a reload
//!     (i.e. a reboot) sees the NEW epoch as active, not epoch 0.
//!   * `service_retire`           -> `retire(old)` + `persist`   => the
//!     retired PRIVATE KEY is gone from `epoch_keys.json`'s raw bytes (not
//!     just from the in-memory store) and from the reloaded store's API.
//!
//! Today `promote`/`retire` have ZERO callers, so nothing ever persists a
//! post-rotation store — rotation + reboot resurrects the retired key. The
//! runtime proof of that bug is `key_rotation.rs`'s
//! `rotation_survives_gateway_restart_on_new_epoch`; this file is the
//! process-boundary contract those wiring sites must satisfy.
//!
//! ./dev.sh run "cargo test -p wiremesh-gateway --test epoch_persistence -- --nocapture"

use wiremesh_gateway::epochkeys::EpochKeys;

/// A known-valid 32-byte base64 private key, minted via the store's own
/// generator (matches what `wg genkey` effectively produces).
fn fresh_priv() -> String {
    let mut seed = EpochKeys::default();
    // Epoch 0 on an empty store: key-bytes harvest only, number arbitrary.
    seed.generate_next_at(0).unwrap().private_key_b64.clone()
}

/// Cutover persistence: promote epoch 1, persist, reload — the reloaded
/// store (what a rebooted gateway would see) reports epoch 1 active and
/// epoch 0 demoted to "retiring". This is the durable half of the Role-A
/// FlipRoutes cutover (`epoch_keys.promote(new)` + `persist`).
#[test]
fn promote_then_reload_reports_new_epoch_active() {
    let priv0 = fresh_priv();
    let mut keys = EpochKeys::from_legacy(&priv0).unwrap();
    keys.generate_next_at(1).unwrap(); // epoch 1, "pending"
    keys.promote(1).unwrap();

    let dir = tempfile::tempdir().unwrap();
    keys.persist(dir.path()).unwrap();

    let reloaded = EpochKeys::load(dir.path())
        .unwrap()
        .expect("epoch_keys.json must exist after persist");
    let active = reloaded
        .active()
        .expect("reloaded store must have an active epoch after a persisted promote");
    assert_eq!(
        active.epoch, 1,
        "a reload after promote+persist must see the NEW epoch active — a rebooted \
         gateway selecting the active entry must come up on the rotated key"
    );
    assert_ne!(
        active.private_key_b64, priv0,
        "the active key after a persisted promote must not be the old epoch-0 key"
    );
    assert_eq!(
        reloaded
            .by_epoch(0)
            .expect("epoch 0 still present pre-retire")
            .state,
        "retiring",
        "promote must durably demote the prior active epoch to \"retiring\""
    );
}

/// Retire persistence — the SECURITY half: after retire(old) + persist, the
/// retired PRIVATE KEY material must be gone from the `epoch_keys.json`
/// bytes on disk (grepping the file for the base64 key must find nothing),
/// and the reloaded store must not expose the retired epoch through any API.
/// This is what `service_retire` must do in addition to tearing the old
/// Device down: a torn-down Device whose private key still sits in a
/// world-of-tomorrow `epoch_keys.json` is not retired, it's dormant.
#[test]
fn retire_then_reload_scrubs_retired_private_key_from_disk() {
    let priv0 = fresh_priv();
    let mut keys = EpochKeys::from_legacy(&priv0).unwrap();
    keys.generate_next_at(1).unwrap(); // epoch 1, "pending"
    let priv1 = keys.by_epoch(1).unwrap().private_key_b64.clone();
    keys.promote(1).unwrap(); // epoch 1 active, epoch 0 retiring
    keys.retire(0).unwrap(); // epoch 0 removed

    let dir = tempfile::tempdir().unwrap();
    keys.persist(dir.path()).unwrap();

    // Raw-bytes check: the retired private key must not appear ANYWHERE in
    // the persisted file — not as an epoch entry, not as a stray field.
    let raw = std::fs::read_to_string(dir.path().join("epoch_keys.json"))
        .expect("reading persisted epoch_keys.json");
    assert!(
        !raw.contains(&priv0),
        "SECURITY: retired epoch-0 PRIVATE key material still present in \
         epoch_keys.json after retire+persist:\n{raw}"
    );
    // Sanity that the grep above is meaningful (the file does carry key
    // material in this exact representation): the LIVE key must be present.
    assert!(
        raw.contains(&priv1),
        "sanity: the active epoch-1 private key should be in epoch_keys.json \
         (otherwise the absence-check above proves nothing):\n{raw}"
    );

    // API check on a fresh reload (the reboot view).
    let reloaded = EpochKeys::load(dir.path()).unwrap().expect("file exists");
    assert!(
        reloaded.by_epoch(0).is_none(),
        "retired epoch 0 must be absent from the reloaded store"
    );
    assert!(
        !reloaded.epochs.iter().any(|k| k.private_key_b64 == priv0),
        "no reloaded entry may carry the retired private key under any epoch number"
    );
    let active = reloaded
        .active()
        .expect("epoch 1 must be active after reload");
    assert_eq!(active.epoch, 1);
    assert_eq!(active.private_key_b64, priv1);
}

/// The two persists compose across process boundaries: promote+persist in
/// "process 1", reload, retire+persist in "process 2", reload again. Pins
/// that the fix's two wiring sites (cutover promotes, service_retire
/// retires) work against a store that has been through a reload in between —
/// i.e. a crash/restart BETWEEN cutover and retire still converges to a
/// clean single-active-epoch store rather than wedging `retire` (the
/// reloaded "retiring" state must still be retirable).
#[test]
fn promote_persist_reload_retire_persist_reload_converges() {
    let priv0 = fresh_priv();
    let dir = tempfile::tempdir().unwrap();

    // "Process 1": mint + promote + persist (the cutover).
    {
        let mut keys = EpochKeys::from_legacy(&priv0).unwrap();
        keys.generate_next_at(1).unwrap();
        keys.promote(1).unwrap();
        keys.persist(dir.path()).unwrap();
    }

    // "Process 2": reload (reboot), then retire + persist (service_retire).
    {
        let mut keys = EpochKeys::load(dir.path())
            .unwrap()
            .expect("store persisted");
        assert_eq!(keys.by_epoch(0).unwrap().state, "retiring");
        keys.retire(0)
            .expect("a reloaded \"retiring\" epoch must still be retirable");
        keys.persist(dir.path()).unwrap();
    }

    // "Process 3": the final reboot view — one epoch, active, and no trace
    // of the retired key.
    let keys = EpochKeys::load(dir.path())
        .unwrap()
        .expect("store persisted");
    assert_eq!(keys.epochs.len(), 1);
    assert_eq!(keys.active().unwrap().epoch, 1);
    let raw = std::fs::read_to_string(dir.path().join("epoch_keys.json")).unwrap();
    assert!(
        !raw.contains(&priv0),
        "retired key must be scrubbed from disk"
    );
}
