//! Backlog 3 Task 1 (durable key promote/retire — SECURITY): the boot-key
//! SELECTION contract. **EXPECTED COMPILE-RED TODAY** — this file pins an API
//! that does not exist yet and that the implementer must add to
//! `crates/wiremesh-gateway/src/epochkeys.rs` with EXACTLY this shape:
//!
//! ```ignore
//! impl EpochKeys {
//!     /// Select the keypair the gateway must boot its base tun with:
//!     /// the persisted store's ACTIVE epoch entry when one exists, else an
//!     /// epoch-0 "active" entry synthesized from the legacy identity key
//!     /// (`Identity::wg_private_key_b64`). Pure — no I/O; the caller loads
//!     /// the store (`EpochKeys::load`) and passes it in.
//!     pub fn select_boot_key(
//!         store: Option<&EpochKeys>,
//!         legacy_priv_b64: &str,
//!     ) -> anyhow::Result<EpochKey>;
//! }
//! ```
//!
//! Why this hook: today `main.rs`'s boot (`run`, ~line 238) unconditionally
//! brings up epoch 0 from `Identity::wg_private_key_b64` and only consults
//! `EpochKeys::load` (~line 463) as a mint base — so a rotation + reboot
//! RESURRECTS the retired key, and a crash-mid-rotation gateway whose epoch
//! was grace-promoted by the controller (Rule 4) reboots onto a key no peer
//! advertises: a fabric-wide black hole. The fix's boot path must be
//! `let boot = EpochKeys::select_boot_key(EpochKeys::load(dir)?.as_ref(),
//! &id.wg_private_key_b64)?` and use `boot.private_key_b64` for
//! `tunnels.bring_up(...)` and the `ActiveTunInfo` seed (still on the BASE
//! tun/port per OD-1 — selection changes the KEY, never the tun/port).
//!
//! The runtime proof lives in `key_rotation.rs`
//! (`rotation_survives_gateway_restart_on_new_epoch`); this file pins the
//! selector's pure semantics so the boot wiring has a precise contract.
//!
//! ./dev.sh run "cargo test -p wiremesh-gateway --test epoch_boot_key -- --nocapture"

use wiremesh_gateway::epochkeys::EpochKeys;
use wiremesh_gateway::uapi::base64_pub_from_priv;

/// A known-valid 32-byte base64 private key, minted via the store's own
/// generator.
fn fresh_priv() -> String {
    let mut seed = EpochKeys::default();
    seed.generate_next().unwrap().private_key_b64.clone()
}

/// The heart of the fix: when the persisted store has an active epoch, the
/// boot key IS that epoch's key — the legacy identity key is ignored. A
/// rebooted post-rotation gateway must come up on the promoted epoch, not
/// resurrect epoch 0.
#[test]
fn store_active_epoch_wins_over_legacy_identity_key() {
    let legacy = fresh_priv();
    // The persisted store of a gateway that completed a rotation: epoch 0
    // (the legacy key) retired away, epoch 1 active.
    let mut store = EpochKeys::from_legacy(&legacy).unwrap();
    store.generate_next().unwrap(); // epoch 1, pending
    store.promote(1).unwrap();
    store.retire(0).unwrap();
    let expect = store.active().unwrap().clone();

    let boot = EpochKeys::select_boot_key(Some(&store), &legacy).unwrap();
    assert_eq!(
        boot, expect,
        "boot must select the store's ACTIVE epoch entry verbatim"
    );
    assert_ne!(
        boot.private_key_b64, legacy,
        "boot must NOT resurrect the legacy (retired epoch-0) identity key when the \
         store has an active epoch"
    );
    assert_eq!(boot.epoch, 1);
}

/// Mid-lifecycle store (promote persisted, retire not yet — e.g. a crash in
/// the retire grace window): epoch 0 is present but "retiring", epoch 1 is
/// active — boot must still pick epoch 1. This is exactly the
/// crash-mid-rotation reboot the controller's Rule-4 grace-promote makes
/// fatal today.
#[test]
fn retiring_entry_does_not_shadow_the_active_epoch() {
    let legacy = fresh_priv();
    let mut store = EpochKeys::from_legacy(&legacy).unwrap();
    store.generate_next().unwrap();
    store.promote(1).unwrap(); // epoch 0 now "retiring", epoch 1 "active"

    let boot = EpochKeys::select_boot_key(Some(&store), &legacy).unwrap();
    assert_eq!(boot.epoch, 1, "the active epoch, not the retiring one, boots");
    assert_ne!(boot.private_key_b64, legacy);
}

/// No store at all (first boot of a rotation-aware gateway, or a wiped state
/// dir): fall back to the legacy identity key as a synthesized epoch-0
/// active entry — byte-identical behavior to today's boot.
#[test]
fn no_store_falls_back_to_legacy_identity_key() {
    let legacy = fresh_priv();

    let boot = EpochKeys::select_boot_key(None, &legacy).unwrap();
    assert_eq!(boot.epoch, 0, "legacy fallback is epoch 0");
    assert_eq!(boot.private_key_b64, legacy);
    assert_eq!(
        boot.pubkey_b64,
        base64_pub_from_priv(&legacy).unwrap(),
        "fallback entry must carry the real derived pubkey"
    );
    assert_eq!(boot.state, "active", "the selected boot key is by definition active");
}

/// A store that exists but has only the migrated epoch 0 (the steady-state
/// file `main.rs` writes at first boot, no rotation ever run): selecting
/// from it must be equivalent to the legacy fallback — same epoch, same key.
/// Pins that adding the selector changes NOTHING for never-rotated gateways.
#[test]
fn epoch0_only_store_is_equivalent_to_legacy_fallback() {
    let legacy = fresh_priv();
    let store = EpochKeys::from_legacy(&legacy).unwrap();

    let from_store = EpochKeys::select_boot_key(Some(&store), &legacy).unwrap();
    let from_legacy = EpochKeys::select_boot_key(None, &legacy).unwrap();
    assert_eq!(
        from_store, from_legacy,
        "an epoch-0-only store must select exactly what the no-store legacy \
         fallback selects"
    );
    assert_eq!(from_store.epoch, 0);
    assert_eq!(from_store.private_key_b64, legacy);
}

/// A store that exists but has NO active entry (e.g. only a "pending" mint —
/// a crash between `generate_next`+persist and the cutover's promote): fall
/// back to the legacy identity key. Per the ratified decision the fallback
/// applies "only when no store/active entry exists" — a pending-only store
/// counts as no active entry, and booting a never-promoted pending key would
/// advertise an identity the controller never activated.
#[test]
fn store_without_active_entry_falls_back_to_legacy() {
    let legacy = fresh_priv();
    let mut store = EpochKeys::default();
    store.generate_next().unwrap(); // a single "pending" entry, nothing active
    assert!(store.active().is_none(), "precondition: no active entry");

    let boot = EpochKeys::select_boot_key(Some(&store), &legacy).unwrap();
    assert_eq!(boot.epoch, 0);
    assert_eq!(
        boot.private_key_b64, legacy,
        "with no ACTIVE entry in the store, boot must fall back to the legacy \
         identity key, never a pending (unpromoted) mint"
    );
}
