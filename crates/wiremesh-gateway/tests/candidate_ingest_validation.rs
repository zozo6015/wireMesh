//! (Backlog item 1, gateway half) A candidate endpoint that cannot be written
//! to the WireGuard UAPI must never reach `DesiredState`, by ANY route.
//!
//! # The failure this prevents
//!
//! `uapi::push_peer_block` validates every peer endpoint with
//! `validate_ipv4_endpoint(ep)?`. `encode_set` propagates that `Err`;
//! `apply_state` calls `uapi::encode_set(&dev).context(..)?` BEFORE its
//! incremental `match delta`, so no path avoids it; the `?` unwinds out of
//! `async fn run(cfg)` past both loops, and `main` ends in
//! `rt.block_on(run(cfg))`. **The gateway process exits non-zero** — for every
//! peer at once, because the device config is built from all of them
//! together.
//!
//! Defense in depth is REQUIRED here, and this file is the reason why. The
//! controller-side filter (`wiremesh-controller/tests/report_local_endpoints_validation.rs`)
//! closes the wire, but there are two more doors into `PeerState.candidates`:
//!
//!  1. **Sync ingest** — `DesiredState::from_snapshot` / `apply_delta` build
//!     peers via `PeerState::from_proto`, which today does
//!     `candidates: p.candidate_endpoints.clone()` with no inspection at all.
//!     A gateway must survive a controller (or a man-in-the-middle inside a
//!     compromised control plane, or simply an older/newer controller build)
//!     that advertises something it cannot use.
//!
//!  2. **`state.json`** — and this is the one that turns a bad apply into a
//!     gateway that CANNOT BOOT. `DesiredState::load` is a bare
//!     `serde_json::from_slice`, and `PeerState.candidates` is a `pub` field
//!     with `#[serde(default)]`, so deserialization rebuilds the candidate
//!     list WITHOUT passing through `from_proto`. The fail-static boot path
//!     is `apply_state(None, ds, ..).await?` — the same `encode_set` call.
//!     So a malformed candidate persisted once kills the process on every
//!     subsequent start, with the controller not even in the loop: the
//!     fail-static mechanism, whose entire purpose is to survive the
//!     controller being unreachable, becomes the thing that prevents boot.
//!
//! # What these tests pin, and what they deliberately do not
//!
//! Every assertion below is expressed through the PUBLIC behaviour —
//! `primary_endpoint()`, `reconcile::device_config_pinned`, `uapi::encode_set`
//! — never by reading `PeerState.candidates` directly. That is deliberate:
//! the implementer may fix this by filtering inside
//! `from_proto`/`from_snapshot`/`apply_delta`/`load`, or by making
//! `candidates` private behind a validating constructor. Both are legitimate
//! and these tests pass under either.
//!
//! Pure tests: no netns, no privileged container, no device.

use std::collections::HashMap;

use wiremesh_gateway::reconcile::device_config_pinned;
use wiremesh_gateway::state::DesiredState;
use wiremesh_gateway::uapi::encode_set;
use wiremesh_proto::v1::{Delta, Peer, PeerKey, StateSnapshot};

/// base64 of 32 bytes of 0x11 / 0x22 / 0x33 — valid WireGuard key material as
/// far as `uapi::key_b64_to_hex` is concerned (exactly 32 decoded bytes), so
/// an `encode_set` failure in these tests can only ever be about the
/// ENDPOINT, never about a key.
const PRIV_B64: &str = "ERERERERERERERERERERERERERERERERERERERERERE=";
const PEER_A_PUB_B64: &str = "IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI=";
const PEER_B_PUB_B64: &str = "MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM=";
const PEER_A_PUB_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";

/// A malformed candidate chosen to sort BEFORE any dotted-quad address, so if
/// nothing filters it, it wins `candidates.first()` on its own — no ordering
/// luck required. `Db::set_local_candidates` sorts, which is how this shape
/// reaches index 0 in production too.
const BOGUS_FIRST: &str = "!!! not an endpoint";

/// The subtle one: `abc:123` passes `reconcile::pending_peer_configs`' own
/// `rsplit_once(':')` + `u16::parse` half-check, so it is not caught by the
/// one place on the gateway that already looks at endpoint shape — it dies
/// later, inside `validate_ipv4_endpoint`, where the error is fatal.
const BOGUS_DNS: &str = "abc:123";

const VALID: &str = "10.0.0.5:51820";

fn peer_proto(gateway_id: u64, pubkey: &str, candidates: &[&str], cidr: &str) -> Peer {
    Peer {
        gateway_id,
        segment_name: format!("s{gateway_id}"),
        keys: vec![PeerKey { epoch: 0, pubkey: pubkey.to_string(), state: "active".into() }],
        candidate_endpoints: candidates.iter().map(|s| s.to_string()).collect(),
        allowed_ips: vec![cidr.to_string()],
    }
}

// `deprecated_relays` is a deliberately-deprecated proto field kept only to
// hold its wire slot (see `sync.proto`); every struct literal here must still
// name it, so the lint is silenced at the two construction sites rather than
// left as permanent build noise.
#[allow(deprecated)]
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

/// The whole point of the exercise: build the device exactly the way
/// `apply_state` does and encode it. In production the `Err` this can return
/// is not handled — it unwinds to `main` and ends the process.
fn encode(ds: &DesiredState) -> anyhow::Result<String> {
    let dev = device_config_pinned(ds, PRIV_B64, 51820, &HashMap::new(), &HashMap::new());
    encode_set(&dev)
}

// ---------------------------------------------------------------------------
// B. Sync ingest — `from_snapshot` / `apply_delta` (both go via `from_proto`)
// ---------------------------------------------------------------------------

#[test]
fn a_snapshot_peer_with_a_malformed_candidate_first_does_not_dial_it() {
    let ds = DesiredState::from_snapshot(&snapshot_with(vec![peer_proto(
        2,
        PEER_A_PUB_B64,
        &[BOGUS_FIRST, VALID],
        "10.10.2.0/24",
    )]));

    let peer = &ds.peers[0];
    assert_eq!(
        peer.primary_endpoint().map(String::as_str),
        Some(VALID),
        "a peer advertising [{BOGUS_FIRST:?}, {VALID:?}] must resolve to {VALID:?}. \
         `primary_endpoint()` is `candidates.first()` and `Db::set_local_candidates` \
         SORTS, so an unparseable string that sorts low takes index 0 for free. \
         Whatever `primary_endpoint()` returns is written to the UAPI as `endpoint=` \
         and validated by `validate_ipv4_endpoint`, whose `Err` unwinds out of \
         `apply_state` -> `run` -> `main` and EXITS THE PROCESS — so an unusable \
         candidate must be dropped at ingest, not merely deprioritized."
    );

    let encoded = encode(&ds).expect(
        "encoding the device for a peer whose advertised candidate list contained a \
         malformed entry must SUCCEED. This is the exact call `apply_state` makes before \
         its `match delta`, and its `Err` is fatal to the process.",
    );
    assert!(
        !encoded.contains(BOGUS_FIRST),
        "the malformed candidate must not appear anywhere in the UAPI `set` body, got:\n{encoded}"
    );
    assert!(
        encoded.contains(&format!("endpoint={VALID}\n")),
        "the surviving valid candidate must still be dialled — filtering must cost the \
         peer only the unusable entries, never its working path. Got:\n{encoded}"
    );
}

#[test]
fn a_snapshot_peer_whose_candidates_are_all_malformed_yields_no_endpoint() {
    let ds = DesiredState::from_snapshot(&snapshot_with(vec![peer_proto(
        2,
        PEER_A_PUB_B64,
        &[BOGUS_FIRST, BOGUS_DNS, "[::1]:51820"],
        "10.10.2.0/24",
    )]));

    // This case is what proves the entries were DROPPED rather than merely
    // reordered: with nothing valid left there is nothing to promote.
    assert_eq!(
        ds.peers[0].primary_endpoint(),
        None,
        "when every advertised candidate is unusable the peer must end up with NO \
         endpoint, not with the least-bad one. `{BOGUS_DNS}` is the trap here: it \
         survives `reconcile::pending_peer_configs`' `rsplit_once(':')` + port parse, so \
         shape-checking alone does not catch it — it dies later in \
         `validate_ipv4_endpoint`, where the error is fatal."
    );

    let encoded = encode(&ds).expect(
        "a peer with no usable candidate must still encode: WireGuard peers without an \
         `endpoint=` line are legal (the peer is configured and can be reached once it \
         speaks first, or once the controller advertises a real candidate). Failing the \
         encode here would exit the process over a peer the gateway simply cannot dial \
         yet.",
    );
    assert!(
        encoded.contains(&format!("public_key={PEER_A_PUB_HEX}\n")),
        "the PEER itself must survive — dropping the peer would also drop its \
         allowed_ips, tearing down routing for that whole segment. Only the unusable \
         endpoints are filtered. Got:\n{encoded}"
    );
    assert!(
        !encoded.contains("endpoint="),
        "no `endpoint=` line may be emitted when there is no usable candidate, got:\n{encoded}"
    );
}

#[test]
#[allow(deprecated)] // `Delta::deprecated_relays` — see `snapshot_with`.
fn a_delta_upserting_a_peer_with_a_malformed_candidate_is_filtered_too() {
    // The live path. `apply_delta` is what runs while the fabric is up, so a
    // fix that only covered the initial snapshot would leave the steady state
    // — the overwhelmingly common case — wide open.
    let mut ds = DesiredState::from_snapshot(&snapshot_with(vec![peer_proto(
        2,
        PEER_A_PUB_B64,
        &[VALID],
        "10.10.2.0/24",
    )]));

    ds.apply_delta(&Delta {
        revision: 8,
        upserted_peers: vec![peer_proto(2, PEER_A_PUB_B64, &[BOGUS_FIRST, VALID], "10.10.2.0/24")],
        removed_peer_ids: vec![],
        deprecated_relays: vec![],
        policy_ir: vec![],
        policy_version: 0,
        revoked_serials: vec![],
        relay_infos: vec![],
        relays_updated: false,
    });

    assert_eq!(
        ds.peers[0].primary_endpoint().map(String::as_str),
        Some(VALID),
        "`apply_delta` upserts through the same `PeerState::from_proto` and must filter \
         identically. A gateway that boots clean and is then handed a malformed candidate \
         by a live delta dies exactly the same way — mid-flight, with traffic on it."
    );
    encode(&ds).expect("the post-delta device must still encode");
}

#[test]
fn one_peers_malformed_candidate_does_not_cost_another_peer_its_endpoint() {
    // The blast-radius property. The device config is built from ALL peers
    // together, so before this fix a single bad advertisement took down the
    // apply for every peer at once.
    let ds = DesiredState::from_snapshot(&snapshot_with(vec![
        peer_proto(2, PEER_A_PUB_B64, &[BOGUS_FIRST], "10.10.2.0/24"),
        peer_proto(3, PEER_B_PUB_B64, &["10.0.0.9:51820"], "10.10.3.0/24"),
    ]));

    let encoded = encode(&ds).expect(
        "one peer's unusable candidate must not fail the whole-device encode. \
         `encode_set` is all-or-nothing by construction and `apply_state` treats its Err \
         as fatal, so before the ingest filter a single malformed advertisement about ONE \
         peer terminated the gateway for ALL of them.",
    );
    assert!(
        encoded.contains("endpoint=10.0.0.9:51820\n"),
        "the healthy peer must keep its endpoint, got:\n{encoded}"
    );
}

// ---------------------------------------------------------------------------
// C. The persisted-state escape — `DesiredState::load` bypasses `from_proto`
// ---------------------------------------------------------------------------

/// Writes a `state.json` by hand — NOT via `DesiredState::save` — because
/// hand-written JSON is exactly the threat: `load` is a bare
/// `serde_json::from_slice`, so anything on disk becomes a `DesiredState`
/// without ever touching `PeerState::from_proto`. The file may have been
/// written by an earlier build of this binary (before the ingest filter
/// existed), by a version-skewed one, or by anything with write access to
/// `/var/lib/wiremesh`.
fn write_state_json(dir: &std::path::Path, candidates: &[&str]) {
    let doc = serde_json::json!({
        "revision": 7,
        "peers": [{
            "gateway_id": 2,
            "segment_name": "s2",
            "active_pubkey_b64": PEER_A_PUB_B64,
            "keys": [{ "epoch": 0, "pubkey_b64": PEER_A_PUB_B64, "state": "active" }],
            "candidates": candidates,
            "allowed_ips": ["10.10.2.0/24"],
        }],
        "policy_ir": [],
        "policy_version": 0,
        "relays": [],
        "revoked_serials": [],
    });
    std::fs::write(dir.join("state.json"), serde_json::to_vec_pretty(&doc).unwrap())
        .expect("writing the test state.json");
}

#[test]
fn a_persisted_malformed_candidate_does_not_block_the_fail_static_boot() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_state_json(dir.path(), &[BOGUS_FIRST, VALID]);

    let ds = DesiredState::load(dir.path())
        .expect("loading state.json must not error")
        .expect("state.json exists, so load must yield Some");

    assert_eq!(
        ds.peers[0].primary_endpoint().map(String::as_str),
        Some(VALID),
        "`DesiredState::load` is `serde_json::from_slice` and `PeerState.candidates` is a \
         `pub` field with `#[serde(default)]`, so deserialization rebuilds the candidate \
         list WITHOUT passing through `PeerState::from_proto` — the ingest filter alone \
         does not cover this door. The boot path is \
         `apply_state(None, ds, ..).await?`, the same `encode_set` whose `Err` exits the \
         process, so a candidate that got persisted once would kill EVERY subsequent \
         start with the controller not even in the loop. That inverts fail-static: the \
         mechanism whose entire purpose is surviving an unreachable controller becomes \
         the reason the gateway cannot come up."
    );

    let encoded = encode(&ds).expect(
        "booting from a state.json containing a malformed candidate must produce an \
         encodable device — this is a crash-loop, not a degradation, and no operator \
         action short of hand-editing /var/lib/wiremesh/state.json recovers it.",
    );
    assert!(
        !encoded.contains(BOGUS_FIRST),
        "the persisted malformed candidate must not reach the UAPI wire, got:\n{encoded}"
    );
    assert!(
        encoded.contains(&format!("endpoint={VALID}\n")),
        "the persisted VALID candidate must still be used — fail-static boot has to bring \
         the working path back up. Got:\n{encoded}"
    );
}

#[test]
fn a_persisted_state_of_only_malformed_candidates_still_boots() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_state_json(dir.path(), &[BOGUS_DNS, "[2001:db8::1]:51820", ""]);

    let ds = DesiredState::load(dir.path())
        .expect("loading state.json must not error")
        .expect("state.json exists, so load must yield Some");

    let encoded = encode(&ds).expect(
        "the worst persisted case — every candidate unusable — must still boot. The \
         gateway comes up with no endpoint for that peer and recovers as soon as the \
         controller advertises a real one; refusing to boot instead leaves the segment \
         dark and unrecoverable without manual file surgery.",
    );
    assert!(
        encoded.contains(&format!("public_key={PEER_A_PUB_HEX}\n")),
        "the peer must still be configured (its allowed_ips carry the segment routes), \
         got:\n{encoded}"
    );
    assert!(
        !encoded.contains("endpoint="),
        "no endpoint may be emitted when every persisted candidate was unusable, \
         got:\n{encoded}"
    );
}

#[test]
fn a_backward_compatible_state_json_without_candidates_still_loads() {
    // Regression guard for the property `PeerState.candidates`'
    // `#[serde(default)]` exists to provide: a pre-4b `state.json` (singular
    // `candidate_endpoint`, now an unknown field) must still deserialize
    // rather than failing the boot-from-persisted-state path. Whatever the
    // implementer does about validation — filter in `load`, or privatize the
    // field behind a validating constructor with a custom `Deserialize` — it
    // must not turn a missing/legacy field into a boot failure.
    let dir = tempfile::tempdir().expect("tempdir");
    let doc = serde_json::json!({
        "revision": 3,
        "peers": [{
            "gateway_id": 2,
            "segment_name": "s2",
            "active_pubkey_b64": PEER_A_PUB_B64,
            "candidate_endpoint": "10.0.0.5:51820",
            "allowed_ips": ["10.10.2.0/24"],
        }],
        "policy_ir": [],
        "policy_version": 0,
        "revoked_serials": [],
    });
    std::fs::write(dir.path().join("state.json"), serde_json::to_vec_pretty(&doc).unwrap())
        .expect("writing the legacy state.json");

    let ds = DesiredState::load(dir.path())
        .expect(
            "a legacy state.json (pre-4b singular `candidate_endpoint`, no `keys`, no \
             `relays`) must still load — that is what the `#[serde(default)]` attributes \
             on `keys`/`candidates`/`relays` are for, and fail-static boot depends on it",
        )
        .expect("state.json exists, so load must yield Some");

    assert_eq!(
        ds.peers[0].primary_endpoint(),
        None,
        "the legacy singular key is an unknown field and is ignored, leaving an empty \
         candidate list — the next controller reconcile repopulates it"
    );
    encode(&ds).expect("a legacy-state boot must encode");
}
