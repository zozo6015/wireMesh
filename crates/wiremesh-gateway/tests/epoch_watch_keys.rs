//! F3: `new_epoch_watch_keys` must not fall back to the directive-time snapshot
//! when NO key is selected — that watches a key the device provably does not
//! hold, so `all_live` is false forever and the old epoch never retires.
//!
//! ./dev.sh run "cargo test -p wiremesh-gateway --test epoch_watch_keys"
//!
//! # The defect these tests pin
//!
//! Post-cutover, the new-epoch tun IS the active tun and
//! `reconcile::device_config_pinned` owns its peer set. That writer
//! `filter_map`s a peer AWAY when there is no `wg0_pins` entry and no
//! `active_pubkey_b64` (the `?` on `p.active_pubkey_b64.clone()`), so such a
//! peer is simply not configured on the device.
//!
//! `new_epoch_watch_keys` used to collapse "nothing selected" and "the selected
//! key does not decode" into one `unwrap_or_else(|| snapshot_hex.clone())`. For
//! the first of those it therefore watched a key that is NOT on the device:
//! `read_live_peers` can never report it, `all_live` is false on every tick,
//! `retire_all_live_since` resets forever, and the old epoch's Device +
//! enforcer are never torn down — the retired private key is never actually
//! retired, once per rotation, permanently. That is the exact stall commit
//! `5a5f644` created this function to remove, re-entered one branch over.
//!
//! # What is pinned here
//!
//!  1. Post-cutover, "no pin and `active_pubkey_b64 == None`" is
//!     [`EpochWatch::Gone`], never a snapshot fallback.
//!  2. The surviving fallback: a `Some` key that fails to DECODE still yields
//!     the snapshot hex. That case is defensible (the same undecodable key
//!     makes `encode_set` fail inside `apply_state`, so the device keeps what
//!     the snapshot recorded) and dropping it would let a decode glitch retire
//!     a key a live peer still needs.
//!  3. The general invariant behind (1) and (2): post-cutover, a peer yields
//!     `Key` EXACTLY when `device_config_pinned` puts it on the device, and
//!     `Gone` exactly when it drops it. Asserted against the real
//!     `device_config_pinned`, so the two cannot drift again.
//!  4. Pre-cutover the answer is the snapshot VERBATIM for every peer, whatever
//!     the roster and the pins say. This equivalence is load-bearing rather
//!     than cosmetic: the `any_live` cutover gate in `run_rotation_ticks` is
//!     fed from this same set, and the whole claim that `5a5f644` left the
//!     cutover TIMING untouched rests on the pre-cutover branch being
//!     bit-for-bit the old snapshot.
use std::collections::HashMap;
use wiremesh_gateway::reconcile::device_config_pinned;
use wiremesh_gateway::rotation::{new_epoch_watch_keys, EpochWatch};
use wiremesh_gateway::state::{DesiredState, PeerState};
use wiremesh_gateway::uapi::pubkey_b64_to_hex;

// --- Key fixtures ----------------------------------------------------------

/// Standard-alphabet base64 of a fixed 32-byte key, so every test key is a
/// REAL WireGuard-shaped key that `pubkey_b64_to_hex` accepts. Hand-rolled
/// because the crate's own encoder is `pub(crate)` and invisible from an
/// integration-test crate.
fn key_b64(seed: u8) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let raw = [seed; 32];
    let mut out = String::new();
    for chunk in raw.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// The lowercase-hex UAPI form of [`key_b64`], via the production decoder — so
/// a broken fixture fails as a fixture rather than as a wrong expectation.
fn key_hex(seed: u8) -> String {
    pubkey_b64_to_hex(&key_b64(seed)).expect("test fixture key must be a valid 32-byte WG key")
}

/// Valid base64 that decodes to 3 bytes, not 32 — `pubkey_b64_to_hex` rejects
/// it on LENGTH, which is the realistic "roster carries a truncated key" shape.
const UNDECODABLE_KEY: &str = "AAAA";

/// Base64 with a character outside the alphabet — the other undecodable shape.
const MALFORMED_KEY: &str = "not a wireguard key!!";

// --- Roster fixtures -------------------------------------------------------

fn peer(gateway_id: u64, active_pubkey_b64: Option<&str>) -> PeerState {
    PeerState {
        gateway_id,
        segment_name: format!("seg{gateway_id}"),
        active_pubkey_b64: active_pubkey_b64.map(str::to_string),
        keys: vec![],
        candidates: vec!["10.0.0.1:51820".to_string()],
        allowed_ips: vec![format!("10.{gateway_id}.0.0/16")],
    }
}

fn desired(peers: Vec<PeerState>) -> DesiredState {
    DesiredState {
        revision: 1,
        peers,
        policy_ir: vec![],
        policy_version: 1,
        relays: vec![],
        revoked_serials: vec![],
    }
}

fn pins(entries: &[(u64, String)]) -> HashMap<u64, String> {
    entries.iter().cloned().collect()
}

fn watch_of(out: &[(u64, EpochWatch)], gid: u64) -> &EpochWatch {
    &out.iter()
        .find(|(g, _)| *g == gid)
        .unwrap_or_else(|| panic!("no verdict returned for peer {gid}; output was {out:?}"))
        .1
}

// --- (1) THE CORE DEFECT ---------------------------------------------------

/// **THE F3 CASE.** Post-cutover, peer 7 has no `wg0_pins` entry and the roster
/// gives it no `active_pubkey_b64`. `device_config_pinned` drops it, so it is
/// not on the device and there is no session to watch for.
///
/// The pre-fix code returned `Key(snapshot_hex)` here — the directive-time key,
/// which the device provably no longer holds. `read_live_peers` can never
/// report it, so `all_live` stays false on every tick and the old epoch's
/// Device, enforcer and private key leak forever.
#[test]
fn post_cutover_peer_with_no_selectable_key_is_gone() {
    let snapshot = vec![(7u64, key_hex(0x11))];
    let ds = desired(vec![peer(7, None)]);
    let out = new_epoch_watch_keys(&snapshot, true, Some(&ds), &HashMap::new());

    assert_eq!(out.len(), 1, "one verdict per snapshot entry");
    assert_eq!(
        watch_of(&out, 7),
        &EpochWatch::Gone,
        "no pin and no active_pubkey_b64 means device_config_pinned dropped this peer from the \
         device. Falling back to the directive-time snapshot watches a key the device does not \
         hold, so all_live is false forever and the old epoch NEVER retires — the exact stall \
         5a5f644 exists to fix"
    );
}

/// The same case with several peers, only one of which has lost its key. The
/// healthy peers must still be watched — `Gone` is a per-peer verdict, and a
/// blanket drop would stall the rotation just as thoroughly in the other
/// direction (the watch set would empty and, under F4, the retire is withheld).
#[test]
fn post_cutover_only_the_keyless_peer_is_gone() {
    let snapshot = vec![
        (7u64, key_hex(0x11)),
        (8u64, key_hex(0x22)),
        (9u64, key_hex(0x33)),
    ];
    let ds = desired(vec![
        peer(7, Some(&key_b64(0x11))),
        peer(8, None),
        peer(9, Some(&key_b64(0x33))),
    ]);
    let out = new_epoch_watch_keys(&snapshot, true, Some(&ds), &HashMap::new());

    assert_eq!(watch_of(&out, 7), &EpochWatch::Key(key_hex(0x11)));
    assert_eq!(
        watch_of(&out, 8),
        &EpochWatch::Gone,
        "only the peer the writer dropped is Gone"
    );
    assert_eq!(watch_of(&out, 9), &EpochWatch::Key(key_hex(0x33)));
}

/// A peer with NO roster `active_pubkey_b64` but WITH a `wg0_pins` entry is on
/// the device (the pin is what `device_config_pinned` selects), so it must be
/// watched, not dropped. This is the boundary the fix has to respect: the `Gone`
/// branch keys on "nothing selected", not on "`active_pubkey_b64` is `None`".
#[test]
fn post_cutover_a_pin_rescues_a_peer_with_no_roster_active_key() {
    let snapshot = vec![(7u64, key_hex(0x11))];
    let ds = desired(vec![peer(7, None)]);
    let p = pins(&[(7, key_b64(0x44))]);
    let out = new_epoch_watch_keys(&snapshot, true, Some(&ds), &p);

    assert_eq!(
        watch_of(&out, 7),
        &EpochWatch::Key(key_hex(0x44)),
        "the Role-B pubkey pin is what device_config_pinned wrote to the device, so it is what \
         must be watched — a peer with a pin is NOT Gone even with no roster active key"
    );
}

/// The pin outranks the roster's active key, exactly as `device_config_pinned`
/// does. Watching the roster key while the device holds the pinned one is the
/// same class of drift in miniature.
#[test]
fn post_cutover_pin_outranks_the_roster_active_key() {
    let snapshot = vec![(7u64, key_hex(0x11))];
    let ds = desired(vec![peer(7, Some(&key_b64(0x22)))]);
    let p = pins(&[(7, key_b64(0x44))]);
    let out = new_epoch_watch_keys(&snapshot, true, Some(&ds), &p);

    assert_eq!(watch_of(&out, 7), &EpochWatch::Key(key_hex(0x44)));
}

/// Post-cutover, the roster's CURRENT active key wins over the directive-time
/// snapshot — the original `5a5f644` fix. Kept here because the F3 change edits
/// the very same expression, and a regression that restored the snapshot
/// unconditionally would otherwise be invisible.
#[test]
fn post_cutover_a_rotated_peer_is_watched_on_its_new_key() {
    let snapshot = vec![(7u64, key_hex(0x11))];
    let ds = desired(vec![peer(7, Some(&key_b64(0x22)))]);
    let out = new_epoch_watch_keys(&snapshot, true, Some(&ds), &HashMap::new());

    assert_eq!(
        watch_of(&out, 7),
        &EpochWatch::Key(key_hex(0x22)),
        "the peer rotated: apply_state rebuilt our active tun with its NEW key, so the snapshot \
         key is no longer on the device"
    );
}

/// A peer that left the roster entirely is `Gone`: it is not on the device and
/// a departed peer cannot still depend on our old epoch, so it must not hold
/// the retire grace hostage.
#[test]
fn post_cutover_peer_absent_from_the_roster_is_gone() {
    let snapshot = vec![(7u64, key_hex(0x11)), (8u64, key_hex(0x22))];
    let ds = desired(vec![peer(8, Some(&key_b64(0x22)))]);
    let out = new_epoch_watch_keys(&snapshot, true, Some(&ds), &HashMap::new());

    assert_eq!(watch_of(&out, 7), &EpochWatch::Gone);
    assert_eq!(watch_of(&out, 8), &EpochWatch::Key(key_hex(0x22)));
}

// --- (2) THE SURVIVING FALLBACK -------------------------------------------

/// A selected key that will not DECODE keeps the snapshot fallback. The two
/// undecodable shapes — right alphabet/wrong length, and wrong alphabet — must
/// behave identically, and neither may become `Gone`: `uapi::encode_set` fails
/// on the same key inside `apply_state`, so the device still holds whatever it
/// last held, which is what the snapshot records. Watching a stale key merely
/// delays the retire; dropping the peer would retire a key a live peer needs.
#[test]
fn post_cutover_undecodable_active_key_falls_back_to_the_snapshot() {
    for bad in [UNDECODABLE_KEY, MALFORMED_KEY] {
        let snapshot = vec![(7u64, key_hex(0x11))];
        let ds = desired(vec![peer(7, Some(bad))]);
        let out = new_epoch_watch_keys(&snapshot, true, Some(&ds), &HashMap::new());

        assert_eq!(
            watch_of(&out, 7),
            &EpochWatch::Key(key_hex(0x11)),
            "an undecodable active key {bad:?} must fall back to the directive-time snapshot, not \
             become Gone — the same key makes encode_set fail, so the device still holds the \
             snapshot's key"
        );
    }
}

/// The fallback applies to an undecodable PIN too — the pin is what
/// `device_config_pinned` would have selected, and it fails to encode for the
/// same reason.
#[test]
fn post_cutover_undecodable_pin_falls_back_to_the_snapshot() {
    let snapshot = vec![(7u64, key_hex(0x11))];
    let ds = desired(vec![peer(7, Some(&key_b64(0x22)))]);
    let p = pins(&[(7, UNDECODABLE_KEY.to_string())]);
    let out = new_epoch_watch_keys(&snapshot, true, Some(&ds), &p);

    assert_eq!(watch_of(&out, 7), &EpochWatch::Key(key_hex(0x11)));
}

/// No cached desired state at all (the gateway has not received a `State` yet,
/// or `rot.desired` is `None`): keep watching what we know rather than
/// inventing a verdict. This branch must NOT have been swept into the `Gone`
/// change — turning it into `Gone` would empty the watch set on a cold cache.
#[test]
fn post_cutover_without_desired_state_keeps_the_snapshot() {
    let snapshot = vec![(7u64, key_hex(0x11)), (8u64, key_hex(0x22))];
    let out = new_epoch_watch_keys(&snapshot, true, None, &HashMap::new());

    assert_eq!(watch_of(&out, 7), &EpochWatch::Key(key_hex(0x11)));
    assert_eq!(watch_of(&out, 8), &EpochWatch::Key(key_hex(0x22)));
}

// --- (3) THE INVARIANT, AGAINST THE REAL WRITER ---------------------------

/// **The anti-drift assertion.** Post-cutover, a peer is `Key(..)` EXACTLY when
/// `reconcile::device_config_pinned` — the function that actually writes this
/// device — puts it on the device, and `Gone` exactly when it drops it.
///
/// Asserted against the real writer over a roster that exercises every branch
/// at once, so the two functions cannot drift apart again the way they did.
/// A one-branch regression (the F3 bug) shows up here as a peer that
/// `device_config_pinned` dropped but the watcher still watches.
#[test]
fn post_cutover_key_iff_device_config_pinned_keeps_the_peer() {
    let roster = vec![
        peer(1, Some(&key_b64(0x01))),  // plain active key
        peer(2, None),                  // dropped by the writer -> Gone
        peer(3, Some(UNDECODABLE_KEY)), // kept by the writer -> Key(snapshot)
        peer(4, None),                  // rescued by a pin below
        peer(5, Some(&key_b64(0x05))),  // pin overrides the roster key
    ];
    let ds = desired(roster);
    let p = pins(&[(4, key_b64(0x44)), (5, key_b64(0x55))]);
    let snapshot: Vec<(u64, String)> = (1u64..=6)
        .map(|gid| (gid, key_hex(gid as u8 + 0x60)))
        .collect();

    let out = new_epoch_watch_keys(&snapshot, true, Some(&ds), &p);
    assert_eq!(
        out.len(),
        snapshot.len(),
        "one verdict per snapshot entry, in snapshot order"
    );

    let cfg = device_config_pinned(&ds, &key_b64(0xAA), 51820, &p, &HashMap::new());
    // `device_config_pinned` does not carry gateway ids through, so correlate
    // by the selected pubkey: a peer is on the device iff the key the selection
    // rule picks for it appears in the emitted peer list.
    let on_device: Vec<&str> = cfg
        .peers
        .iter()
        .map(|pc| pc.public_key_b64.as_str())
        .collect();
    let selected_for = |gid: u64| -> Option<String> {
        p.get(&gid).cloned().or_else(|| {
            ds.peers
                .iter()
                .find(|q| q.gateway_id == gid)
                .and_then(|q| q.active_pubkey_b64.clone())
        })
    };

    for (gid, _) in &snapshot {
        let writer_keeps_it = match selected_for(*gid) {
            Some(k) => on_device.contains(&k.as_str()),
            None => false,
        };
        match watch_of(&out, *gid) {
            EpochWatch::Key(_) => assert!(
                writer_keeps_it,
                "peer {gid} is being WATCHED but device_config_pinned did not put it on the \
                 device — the watcher is looking for a session that cannot exist, so all_live is \
                 false forever and the old epoch never retires (F3)"
            ),
            EpochWatch::Gone => assert!(
                !writer_keeps_it,
                "peer {gid} IS on the device but the watcher dropped it — the retire could then \
                 fire while that peer still depends on our old key"
            ),
        }
    }
}

// --- (4) PRE-CUTOVER MUST BE THE SNAPSHOT, VERBATIM -----------------------

/// **The cutover-timing equivalence.** Before the cutover, `handle_rotate` owns
/// the new tun's peer set and nothing re-applies to it, so the device holds
/// exactly the keys the snapshot recorded. The function must therefore return
/// the snapshot verbatim — same peers, same order, same hex — no matter what
/// the roster or the pins say, including for every input shape that becomes
/// `Gone` post-cutover.
///
/// This is what keeps the `any_live` gate in `run_rotation_ticks` bit-for-bit
/// what it was before `5a5f644`, i.e. it is the reason the cutover TIMING is
/// unchanged. A `Gone` leaking into the pre-cutover branch would shrink the
/// gate's input set and change when rotations flip.
#[test]
fn pre_cutover_returns_the_snapshot_verbatim() {
    let snapshot = vec![
        (7u64, key_hex(0x11)),
        (8u64, key_hex(0x22)),
        (9u64, key_hex(0x33)),
        (10u64, key_hex(0x44)),
    ];
    // Every post-cutover branch is represented: rotated key, no key at all,
    // undecodable key, and absent from the roster entirely.
    let ds = desired(vec![
        peer(7, Some(&key_b64(0xAA))),
        peer(8, None),
        peer(9, Some(UNDECODABLE_KEY)),
    ]);
    let p = pins(&[(7, key_b64(0xBB))]);

    let out = new_epoch_watch_keys(&snapshot, false, Some(&ds), &p);

    let expected: Vec<(u64, EpochWatch)> = snapshot
        .iter()
        .map(|(g, h)| (*g, EpochWatch::Key(h.clone())))
        .collect();
    assert_eq!(
        out, expected,
        "pre-cutover the answer is the directive-time snapshot verbatim, in order, for EVERY \
         peer — the any_live cutover gate is fed from this set and its timing must not move"
    );
}

/// The pre-cutover branch must not depend on the desired state or the pins at
/// all: the same snapshot with wildly different roster/pin inputs produces the
/// identical answer.
#[test]
fn pre_cutover_ignores_roster_and_pins_entirely() {
    let snapshot = vec![(7u64, key_hex(0x11)), (8u64, key_hex(0x22))];
    let empty = desired(vec![]);
    let full = desired(vec![
        peer(7, Some(&key_b64(0xAA))),
        peer(8, Some(&key_b64(0xBB))),
    ]);

    let a = new_epoch_watch_keys(&snapshot, false, None, &HashMap::new());
    let b = new_epoch_watch_keys(&snapshot, false, Some(&empty), &HashMap::new());
    let c = new_epoch_watch_keys(&snapshot, false, Some(&full), &pins(&[(7, key_b64(0xCC))]));

    assert_eq!(a, b, "pre-cutover must not consult the desired state");
    assert_eq!(
        b, c,
        "pre-cutover must not consult the roster keys or the pins"
    );
}

/// An empty snapshot yields an empty result on both sides of the cutover —
/// totality, and the base case for the F4 note below.
#[test]
fn empty_snapshot_yields_no_verdicts() {
    let ds = desired(vec![peer(7, Some(&key_b64(0x11)))]);
    assert!(new_epoch_watch_keys(&[], false, Some(&ds), &HashMap::new()).is_empty());
    assert!(new_epoch_watch_keys(&[], true, Some(&ds), &HashMap::new()).is_empty());
}

// --- F4's precondition ------------------------------------------------------

/// F4 (`all_live` must not be vacuously true) is only REACHABLE because the
/// post-cutover watch set can now shrink to nothing. This pins that
/// reachability: every peer of an in-flight rotation leaves the roster, so
/// `run_rotation_ticks`'s `filter_map` over these verdicts yields an EMPTY
/// watch vector — the input on which `.all(..)` would be vacuously true.
///
/// This is deliberately only the precondition. The guard itself (`all_live =
/// !watch.is_empty() && ..`) lives inline in `run_rotation_ticks`'s async loop
/// and is not reachable as a unit; see this file's companion note in the test
/// report.
#[test]
fn post_cutover_watch_set_can_empty_completely() {
    let snapshot = vec![(7u64, key_hex(0x11)), (8u64, key_hex(0x22))];
    // Both peers gone from the roster — a transient truncation of `rot.desired`
    // produces exactly this shape, which is why F4 fails toward NOT retiring.
    let ds = desired(vec![]);
    let out = new_epoch_watch_keys(&snapshot, true, Some(&ds), &HashMap::new());

    assert!(
        out.iter().all(|(_, w)| matches!(w, EpochWatch::Gone)),
        "every peer must be Gone: {out:?}"
    );
    let watch: Vec<&u64> = out
        .iter()
        .filter_map(|(g, w)| matches!(w, EpochWatch::Key(_)).then_some(g))
        .collect();
    assert!(
        watch.is_empty(),
        "the filtered watch set is empty — this is the input on which an unguarded `.all()` is \
         vacuously true and the retire would fire having corroborated nothing (F4)"
    );
}
