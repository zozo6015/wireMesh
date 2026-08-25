//! (Backlog items 23 + 24) `PeerState` cannot hold anything `encode_set`
//! would reject — item 1's invariant, extended from `candidates`
//! (`tests/candidate_ingest_validation.rs`) to the two remaining fatal
//! validators in `uapi::push_peer_block`:
//!
//!   - item 23: `key_b64_to_hex(&p.public_key_b64)?` — errors on non-base64,
//!     or on a decode that isn't exactly 32 bytes.
//!   - item 24: `validate_ipv4_cidr(cidr)?` for each `allowed_ip` — errors on
//!     a non-CIDR / non-IPv4 / prefix>32 entry.
//!
//! Both `?`s land identically to item 1's: `push_peer_block` -> `encode_set`
//! -> `apply_state`'s `?` -> unwinds out of `run()` -> **process exit**, on
//! every peer at once, because the device config is built from all of them
//! together. Fail-static then persists the poison into `state.json`, so it
//! also blocks BOOT with the controller not in the loop.
//!
//! # The same two doors item 1 closed, still open here
//!
//!  1. **Sync ingest** — `PeerState::from_proto` (reached via
//!     `DesiredState::from_snapshot` / `apply_delta`) copies `p.active_pubkey_b64`
//!     and `k.pubkey` straight from the wire, and `allowed_ips:
//!     p.allowed_ips.clone()` with no filter at all.
//!  2. **`state.json`** — `DesiredState::load` is a bare `serde_json::from_slice`.
//!     `allowed_ips` (`state.rs:72` at the time of writing — the backlog's own
//!     `state.rs:66` citation is stale; the struct has grown since) carries no
//!     serde attribute whatsoever, so this door is completely unguarded for
//!     item 24 — worse than item 1/23, which at least start from a `pub`
//!     field with no validation rather than no attribute at all.
//!
//! # Item 23's key-less-peer decision (this suite's answer, not the backlog's)
//!
//! A peer with no *usable* candidate is still a legal, encodable WireGuard
//! peer (item 1's answer: drop the endpoint, keep the peer, its allowed_ips
//! keep routing). A peer with no *usable key* is different: `public_key=` is
//! not optional in a UAPI peer block, and this codebase already has a
//! first-class, pinned precedent for "no active key" —
//! `reconcile::peer_configs`'s `p.active_pubkey_b64.clone()?` silently skips
//! such a peer entirely (`reconcile.rs`'s
//! `peer_configs_skip_peers_without_active_key` test). This suite pins that
//! an UNDECODABLE active key must produce the exact same outcome as a MISSING
//! one: the peer is dropped from the device wholesale (no `public_key=` line,
//! and consequently no `allowed_ip=` lines for it either — losing its routes
//! is the cost of a peer the fabric cannot dial encrypted at all, same as
//! today's no-key case), rather than the peer surviving keyless or the whole
//! encode failing. The alternative (treat a bad key like a bad candidate —
//! drop only the field, keep an endpoint-only-looking peer with no key) isn't
//! expressible: `PeerConfig.public_key_b64` is a `String`, not an `Option`,
//! so there is no "peer with no key" WireGuard set block to emit in the first
//! place.
//!
//! Item 24 gets the OPPOSITE answer, deliberately: `allowed_ips` is a list
//! filtered per-entry exactly like `candidates`, not a single required field
//! like the active pubkey — a peer with zero usable routes is still a legal,
//! dialable peer (it just forwards nothing yet), so filtering costs it only
//! the bad CIDRs, never the peer itself.
//!
//! # What these tests pin, and what they deliberately do not
//!
//! Every assertion is expressed through the PUBLIC behaviour —
//! `reconcile::device_config_pinned`, `reconcile::pending_peer_configs`,
//! `uapi::encode_set`/`encode_add_peers` — never by reading `PeerState`
//! fields directly, so any implementation shape (filtering inside
//! `from_proto`, a `deserialize_with` per field, a validating constructor)
//! passes as long as the observable behaviour matches.
//!
//! Pure tests: no netns, no privileged container, no device.

use std::collections::HashMap;

use wiremesh_gateway::reconcile::{device_config_pinned, pending_peer_configs};
use wiremesh_gateway::state::DesiredState;
use wiremesh_gateway::uapi::{encode_add_peers, encode_set};
use wiremesh_proto::v1::{Delta, Peer, PeerKey, StateSnapshot};

/// base64 of 32 bytes of 0x11 — valid WG key material (`key_b64_to_hex`
/// accepts it), used only as the device's own private key so an `encode_set`
/// failure in these tests is never about the PRIVATE key.
const PRIV_B64: &str = "ERERERERERERERERERERERERERERERERERERERERERE=";
/// base64 of 32 bytes of 0x22 / 0x33 / 0x44 — three distinct valid 32-byte
/// peer keys, for tests that need more than one healthy peer.
const PEER_A_PUB_B64: &str = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=";
const PEER_A_PUB_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const PEER_B_PUB_B64: &str = "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=";
const PEER_B_PUB_HEX: &str = "3333333333333333333333333333333333333333333333333333333333333333";

/// Not base64 at all — the first of `key_b64_to_hex`'s two failure modes.
const BOGUS_KEY_NOT_B64: &str = "!!! not base64 !!!";
/// Valid base64, but decodes to 5 bytes, not 32 — the SECOND failure mode,
/// distinct from the first: a filter that only checks "does this parse as
/// base64" would let this one straight through to `key_b64_to_hex`, which
/// still rejects it on length.
const BOGUS_KEY_WRONG_LEN: &str = "SGVsbG8=";

const VALID_CIDR_A: &str = "10.10.2.0/24";
const VALID_CIDR_B: &str = "10.10.3.0/24";
const VALID_EP: &str = "10.0.0.5:51820";
const VALID_EP_9: &str = "10.0.0.9:51820";

/// Not CIDR shape at all (`validate_ipv4_cidr`'s `split_once('/')` fails).
const BOGUS_CIDR_NOT_CIDR: &str = "not-a-cidr";
/// CIDR-shaped but the prefix exceeds /32 — passes the IPv4-address parse,
/// fails only the prefix-range check, so a filter that stops at "does the
/// address part parse" would miss this one.
const BOGUS_CIDR_PREFIX_TOO_LARGE: &str = "10.0.0.0/33";

fn peer_proto(gateway_id: u64, pubkey: &str, candidates: &[&str], cidrs: &[&str]) -> Peer {
    Peer {
        gateway_id,
        segment_name: format!("s{gateway_id}"),
        keys: vec![PeerKey {
            epoch: 0,
            pubkey: pubkey.to_string(),
            state: "active".into(),
        }],
        candidate_endpoints: candidates.iter().map(|s| s.to_string()).collect(),
        allowed_ips: cidrs.iter().map(|s| s.to_string()).collect(),
    }
}

/// Like [`peer_proto`], but with an explicit pending epoch too, for the
/// `pending_peer_configs`/`keys[]`-door tests.
fn peer_proto_with_pending(
    gateway_id: u64,
    active_pubkey: &str,
    pending_pubkey: &str,
    candidates: &[&str],
    cidrs: &[&str],
) -> Peer {
    Peer {
        gateway_id,
        segment_name: format!("s{gateway_id}"),
        keys: vec![
            PeerKey {
                epoch: 0,
                pubkey: active_pubkey.to_string(),
                state: "active".into(),
            },
            PeerKey {
                epoch: 1,
                pubkey: pending_pubkey.to_string(),
                state: "pending".into(),
            },
        ],
        candidate_endpoints: candidates.iter().map(|s| s.to_string()).collect(),
        allowed_ips: cidrs.iter().map(|s| s.to_string()).collect(),
    }
}

#[allow(deprecated)] // `StateSnapshot::deprecated_relays` — kept only to hold its wire slot.
fn snapshot_with(peers: Vec<Peer>) -> StateSnapshot {
    StateSnapshot {
        revision: 7,
        self_cert_pem: String::new(),
        peers,
        deprecated_relays: vec![],
        policy_ir: vec![],
        policy_version: 0,
        revoked_serials: vec![],
        relay_infos: vec![],
    }
}

/// Builds the device exactly the way `apply_state` does and encodes it. In
/// production the `Err` this can return is not handled — it unwinds to
/// `main` and ends the process.
fn encode(ds: &DesiredState) -> anyhow::Result<String> {
    let dev = device_config_pinned(ds, PRIV_B64, 51820, &HashMap::new(), &HashMap::new());
    encode_set(&dev)
}

// ---------------------------------------------------------------------------
// Item 23, Door B (Sync ingest) — the active pubkey
// ---------------------------------------------------------------------------

#[test]
fn a_snapshot_peer_with_a_non_base64_active_pubkey_is_dropped_not_fatal() {
    let ds = DesiredState::from_snapshot(&snapshot_with(vec![peer_proto(
        2,
        BOGUS_KEY_NOT_B64,
        &[VALID_EP],
        &[VALID_CIDR_A],
    )]));

    let encoded = encode(&ds).expect(
        "a peer whose advertised active pubkey is not even valid base64 must still \
         encode. TODAY `key_b64_to_hex` fails to decode it, `push_peer_block` propagates \
         the Err, and `encode_set`'s Err is exactly what `apply_state` calls with `?` \
         before its incremental match — unwinding out of run() and exiting the process.",
    );
    assert!(
        !encoded.contains(VALID_CIDR_A),
        "the peer must be dropped WHOLESALE, not partially: with no usable key there is \
         no legal `public_key=` block to emit, so its allowed_ips (and the routes they \
         represent) must not appear either. Got:\n{encoded}"
    );
}

#[test]
fn a_snapshot_peer_with_a_wrong_length_active_pubkey_is_dropped_not_fatal() {
    // A DIFFERENT failure mode from the non-base64 case above: this string IS
    // valid base64, so a filter that only asks "does this parse as base64"
    // would wrongly let it through — `key_b64_to_hex` rejects it on the
    // DECODED length (5 bytes, not 32) instead.
    let ds = DesiredState::from_snapshot(&snapshot_with(vec![peer_proto(
        2,
        BOGUS_KEY_WRONG_LEN,
        &[VALID_EP],
        &[VALID_CIDR_A],
    )]));

    let encoded = encode(&ds).expect(
        "a peer whose active pubkey decodes to the wrong length must still encode, not \
         fail the whole device apply.",
    );
    assert!(
        !encoded.contains(VALID_CIDR_A),
        "same drop-the-whole-peer semantics as the non-base64 case. Got:\n{encoded}"
    );
}

#[test]
#[allow(deprecated)] // `Delta::deprecated_relays` — kept only to hold its wire slot.
fn a_delta_upserting_a_peer_with_a_bad_active_pubkey_is_filtered_too() {
    // The live path: apply_delta is what runs while the fabric is up, so a
    // fix that only covered the initial snapshot would leave the
    // overwhelmingly common case — a live rotation/re-advertisement — wide
    // open.
    let mut ds = DesiredState::from_snapshot(&snapshot_with(vec![peer_proto(
        2,
        PEER_A_PUB_B64,
        &[VALID_EP],
        &[VALID_CIDR_A],
    )]));
    encode(&ds).expect("the initial healthy snapshot must encode");

    ds.apply_delta(&Delta {
        revision: 8,
        upserted_peers: vec![peer_proto(
            2,
            BOGUS_KEY_NOT_B64,
            &[VALID_EP],
            &[VALID_CIDR_A],
        )],
        removed_peer_ids: vec![],
        deprecated_relays: vec![],
        policy_ir: vec![],
        policy_version: 0,
        revoked_serials: vec![],
        relay_infos: vec![],
        relays_updated: false,
    });

    let encoded = encode(&ds).expect(
        "a gateway that boots clean and is then handed a bad pubkey by a live delta must \
         not die mid-flight over it.",
    );
    assert!(
        !encoded.contains(VALID_CIDR_A),
        "the delta-upserted peer must be dropped identically to the snapshot case. \
         Got:\n{encoded}"
    );
}

#[test]
fn one_peers_bad_active_pubkey_does_not_cost_a_sibling_peer_its_configuration() {
    // The blast-radius property: `encode_set` is all-or-nothing across ALL
    // peers, so before this fix one bad advertisement about ONE peer
    // terminated the gateway for every peer at once.
    let ds = DesiredState::from_snapshot(&snapshot_with(vec![
        peer_proto(2, BOGUS_KEY_NOT_B64, &[VALID_EP], &[VALID_CIDR_A]),
        peer_proto(3, PEER_B_PUB_B64, &[VALID_EP_9], &[VALID_CIDR_B]),
    ]));

    let encoded = encode(&ds)
        .expect("one peer's unusable key must not fail the whole-device encode for its siblings");
    assert!(
        encoded.contains(&format!("public_key={PEER_B_PUB_HEX}\n")),
        "the healthy sibling peer must keep its key, got:\n{encoded}"
    );
    assert!(
        encoded.contains(&format!("endpoint={VALID_EP_9}\n")),
        "and its endpoint, got:\n{encoded}"
    );
    assert!(
        encoded.contains(VALID_CIDR_B),
        "and its route, got:\n{encoded}"
    );
    assert!(
        !encoded.contains(VALID_CIDR_A),
        "while the bad peer contributes nothing, got:\n{encoded}"
    );
}

// ---------------------------------------------------------------------------
// Item 23, the `keys[]` door — the PENDING epoch's pubkey
// (backlog item 23 names `PeerState::from_proto`'s `k.pubkey.clone()` into
// `PeerKeyInfo.pubkey_b64` explicitly, not just the derived active_pubkey_b64
// field — this is the builder that reads it back out.)
// ---------------------------------------------------------------------------

#[test]
fn a_peer_with_a_bad_pending_key_is_excluded_from_the_role_b_overlap_device_not_fatal() {
    let ds = DesiredState::from_snapshot(&snapshot_with(vec![peer_proto_with_pending(
        2,
        PEER_A_PUB_B64,
        BOGUS_KEY_NOT_B64,
        &[VALID_EP],
        &[VALID_CIDR_A],
    )]));

    let peers = pending_peer_configs(&ds, 3);
    assert!(
        peers.is_empty(),
        "a peer whose PENDING epoch carries an undecodable pubkey must contribute NOTHING \
         to the Role-B overlap device — the exact same outcome the doc comment on \
         `pending_peer_configs` already promises for a peer with no REAL pending key at \
         all (an active-only peer, or one still holding the \
         'awaiting-submission' sentinel). Got: {peers:?}"
    );

    let encoded = encode_add_peers(&peers).expect(
        "encoding zero (or only-healthy) pending peers must succeed — this is the exact \
         call the Role-B overlap apply makes, and TODAY it carries the bad-pubkey entry \
         straight through and fails.",
    );
    assert!(!encoded.contains(&format!("public_key={PEER_A_PUB_HEX}\n")));
}

// ---------------------------------------------------------------------------
// Item 23, Door C (state.json) — the persisted-state escape
// ---------------------------------------------------------------------------

/// Writes a `state.json` by hand — NOT via `DesiredState::save` — because
/// hand-written JSON is exactly the threat `DesiredState::load`'s bare
/// `serde_json::from_slice` exposes: anything on disk becomes a
/// `DesiredState` without ever touching `PeerState::from_proto`.
fn write_state_json_with_pubkey(dir: &std::path::Path, pubkey_b64: &str, cidrs: &[&str]) {
    let doc = serde_json::json!({
        "revision": 7,
        "peers": [{
            "gateway_id": 2,
            "segment_name": "s2",
            "active_pubkey_b64": pubkey_b64,
            "keys": [{ "epoch": 0, "pubkey_b64": pubkey_b64, "state": "active" }],
            "candidates": [VALID_EP],
            "allowed_ips": cidrs,
        }],
        "policy_ir": [],
        "policy_version": 0,
        "relays": [],
        "revoked_serials": [],
    });
    std::fs::write(
        dir.join("state.json"),
        serde_json::to_vec_pretty(&doc).unwrap(),
    )
    .expect("writing the test state.json");
}

#[test]
fn a_persisted_peer_with_an_undecodable_pubkey_does_not_block_the_fail_static_boot() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_state_json_with_pubkey(dir.path(), BOGUS_KEY_NOT_B64, &[VALID_CIDR_A]);

    let ds = DesiredState::load(dir.path())
        .expect("loading state.json must not error")
        .expect("state.json exists, so load must yield Some");

    let encoded = encode(&ds).expect(
        "booting from a state.json containing an undecodable pubkey must produce an \
         encodable device. TODAY `PeerState.active_pubkey_b64`/`keys` are `pub` fields \
         with no validating deserializer, so the bad key reaches `encode_set` unfiltered \
         and the boot-time apply_state(None, ds, ..)? call — the same encode_set — exits \
         the process on every subsequent restart, with the controller not even in the \
         loop.",
    );
    assert!(
        !encoded.contains(VALID_CIDR_A),
        "the peer (and its route) must be dropped, exactly as the Sync-ingest door drops \
         it. Got:\n{encoded}"
    );
}

#[test]
fn a_persisted_state_where_every_peers_pubkey_is_bad_still_boots_with_an_empty_device() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_state_json_with_pubkey(dir.path(), BOGUS_KEY_WRONG_LEN, &[VALID_CIDR_A]);

    let ds = DesiredState::load(dir.path())
        .expect("loading state.json must not error")
        .expect("state.json exists, so load must yield Some");

    let encoded = encode(&ds).expect(
        "the worst case — the only persisted peer's key is bad — must still boot. The \
         gateway comes up with an otherwise-empty device (default-deny already covers \
         traffic to a peer it cannot key) rather than refusing to boot at all.",
    );
    assert!(
        !encoded.contains("public_key="),
        "no peer block may survive, got:\n{encoded}"
    );
}

// ---------------------------------------------------------------------------
// Item 24, Door B (Sync ingest) — allowed_ips, filter-per-entry semantics
// ---------------------------------------------------------------------------

#[test]
fn a_snapshot_peer_with_one_malformed_allowed_ip_keeps_the_peer_and_the_valid_cidr() {
    let ds = DesiredState::from_snapshot(&snapshot_with(vec![peer_proto(
        2,
        PEER_A_PUB_B64,
        &[VALID_EP],
        &[BOGUS_CIDR_NOT_CIDR, VALID_CIDR_A],
    )]));

    let encoded = encode(&ds).expect(
        "a peer advertising one malformed allowed_ip alongside a valid one must still \
         encode. TODAY `validate_ipv4_cidr` rejects the malformed entry INSIDE \
         `push_peer_block`, which validates every field before writing any of them, so the \
         Err propagates through encode_set exactly like a bad key or a bad endpoint would.",
    );
    assert!(
        encoded.contains(&format!("public_key={PEER_A_PUB_HEX}\n")),
        "unlike a bad KEY, a bad allowed_ip must never cost the peer its key/endpoint — \
         allowed_ips is filtered per-entry, not treated as peer-fatal. Got:\n{encoded}"
    );
    assert!(
        encoded.contains(&format!("endpoint={VALID_EP}\n")),
        "got:\n{encoded}"
    );
    assert!(
        !encoded.contains(BOGUS_CIDR_NOT_CIDR),
        "the malformed CIDR must not reach the UAPI wire, got:\n{encoded}"
    );
    assert!(
        encoded.contains(&format!("allowed_ip={VALID_CIDR_A}\n")),
        "the valid sibling CIDR must survive, got:\n{encoded}"
    );
}

#[test]
fn a_snapshot_peer_whose_allowed_ips_are_all_malformed_still_configures_with_no_routes() {
    let ds = DesiredState::from_snapshot(&snapshot_with(vec![peer_proto(
        2,
        PEER_A_PUB_B64,
        &[VALID_EP],
        &[BOGUS_CIDR_NOT_CIDR, BOGUS_CIDR_PREFIX_TOO_LARGE],
    )]));

    let encoded = encode(&ds).expect(
        "a peer whose every allowed_ip is malformed must still encode: unlike a bad KEY, \
         zero usable routes is a legal WireGuard peer (a `replace_allowed_ips=true` block \
         with no `allowed_ip=` lines), not a reason to drop the peer.",
    );
    assert!(
        encoded.contains(&format!("public_key={PEER_A_PUB_HEX}\n")),
        "the peer itself (key + endpoint) must survive even with zero usable routes, \
         got:\n{encoded}"
    );
    assert!(
        !encoded.contains("allowed_ip="),
        "no allowed_ip line may be emitted, got:\n{encoded}"
    );
}

#[test]
#[allow(deprecated)] // `Delta::deprecated_relays` — kept only to hold its wire slot.
fn a_delta_upserting_a_peer_with_a_malformed_allowed_ip_is_filtered_too() {
    let mut ds = DesiredState::from_snapshot(&snapshot_with(vec![peer_proto(
        2,
        PEER_A_PUB_B64,
        &[VALID_EP],
        &[VALID_CIDR_A],
    )]));
    encode(&ds).expect("the initial healthy snapshot must encode");

    ds.apply_delta(&Delta {
        revision: 8,
        upserted_peers: vec![peer_proto(
            2,
            PEER_A_PUB_B64,
            &[VALID_EP],
            &[BOGUS_CIDR_NOT_CIDR, VALID_CIDR_A],
        )],
        removed_peer_ids: vec![],
        deprecated_relays: vec![],
        policy_ir: vec![],
        policy_version: 0,
        revoked_serials: vec![],
        relay_infos: vec![],
        relays_updated: false,
    });

    let encoded = encode(&ds)
        .expect("a live delta introducing a bad allowed_ip must not kill the steady-state apply");
    assert!(!encoded.contains(BOGUS_CIDR_NOT_CIDR), "got:\n{encoded}");
    assert!(
        encoded.contains(&format!("allowed_ip={VALID_CIDR_A}\n")),
        "got:\n{encoded}"
    );
}

#[test]
fn one_peers_malformed_allowed_ip_does_not_cost_a_sibling_peer_its_routes() {
    let ds = DesiredState::from_snapshot(&snapshot_with(vec![
        peer_proto(2, PEER_A_PUB_B64, &[VALID_EP], &[BOGUS_CIDR_NOT_CIDR]),
        peer_proto(3, PEER_B_PUB_B64, &[VALID_EP_9], &[VALID_CIDR_B]),
    ]));

    let encoded = encode(&ds).expect(
        "one peer's malformed allowed_ip must not fail the whole-device encode for its \
         siblings — `encode_set` builds every peer's block together, so before a fix this \
         is the same all-peers-die blast radius item 1 fixed for endpoints.",
    );
    assert!(
        encoded.contains(&format!("public_key={PEER_B_PUB_HEX}\n")),
        "got:\n{encoded}"
    );
    assert!(
        encoded.contains(&format!("allowed_ip={VALID_CIDR_B}\n")),
        "the healthy sibling's route must survive, got:\n{encoded}"
    );
}

// ---------------------------------------------------------------------------
// Item 24, Door C (state.json) — completely unguarded today (no serde
// attribute at all on `PeerState::allowed_ips`)
// ---------------------------------------------------------------------------

fn write_state_json_with_cidrs(dir: &std::path::Path, cidrs: &[&str]) {
    let doc = serde_json::json!({
        "revision": 7,
        "peers": [{
            "gateway_id": 2,
            "segment_name": "s2",
            "active_pubkey_b64": PEER_A_PUB_B64,
            "keys": [{ "epoch": 0, "pubkey_b64": PEER_A_PUB_B64, "state": "active" }],
            "candidates": [VALID_EP],
            "allowed_ips": cidrs,
        }],
        "policy_ir": [],
        "policy_version": 0,
        "relays": [],
        "revoked_serials": [],
    });
    std::fs::write(
        dir.join("state.json"),
        serde_json::to_vec_pretty(&doc).unwrap(),
    )
    .expect("writing the test state.json");
}

#[test]
fn a_persisted_malformed_allowed_ip_does_not_block_the_fail_static_boot() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_state_json_with_cidrs(dir.path(), &[BOGUS_CIDR_NOT_CIDR, VALID_CIDR_A]);

    let ds = DesiredState::load(dir.path())
        .expect("loading state.json must not error")
        .expect("state.json exists, so load must yield Some");

    let encoded = encode(&ds).expect(
        "booting from a state.json carrying a malformed allowed_ip must produce an \
         encodable device. `allowed_ips` carries NO serde attribute at all today — worse \
         than `candidates`, which at least had a plain `pub` field before item 1's fix — \
         so this door is currently open by construction, not merely unfiltered.",
    );
    assert!(!encoded.contains(BOGUS_CIDR_NOT_CIDR), "got:\n{encoded}");
    assert!(
        encoded.contains(&format!("allowed_ip={VALID_CIDR_A}\n")),
        "got:\n{encoded}"
    );
    assert!(
        encoded.contains(&format!("public_key={PEER_A_PUB_HEX}\n")),
        "the peer's key/endpoint must be unaffected by an allowed_ip problem, got:\n{encoded}"
    );
}

#[test]
fn a_persisted_state_whose_allowed_ips_are_all_malformed_still_boots_with_no_routes() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_state_json_with_cidrs(
        dir.path(),
        &[BOGUS_CIDR_NOT_CIDR, BOGUS_CIDR_PREFIX_TOO_LARGE],
    );

    let ds = DesiredState::load(dir.path())
        .expect("loading state.json must not error")
        .expect("state.json exists, so load must yield Some");

    let encoded = encode(&ds).expect(
        "the worst persisted case — every allowed_ip malformed — must still boot with the \
         peer configured and zero routes, not refuse to boot.",
    );
    assert!(
        encoded.contains(&format!("public_key={PEER_A_PUB_HEX}\n")),
        "got:\n{encoded}"
    );
    assert!(!encoded.contains("allowed_ip="), "got:\n{encoded}");
}
