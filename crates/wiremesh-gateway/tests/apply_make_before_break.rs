//! T4 pin — make-before-break peer-set application (mesh-convergence fix
//! cycle, plan `docs/superpowers/plans/2026-07-28-mesh-convergence-fixes.md`,
//! evidence `docs/research/ops-finding-multi-gateway-convergence.md` §2:
//! enrolling the third gateway (px) re-applied the peer set and reset FI's
//! ESTABLISHED `home` endpoint back to the static candidate
//! `79.119.133.77:51820` — then-undialable — breaking a WORKING pair that
//! never re-formed on its own).
//!
//! Where the pin is lost today (bug locus, for the implementer):
//!  - `set_peer_endpoint` (main.rs, "Point peer gid's WG endpoint ...")
//!    applies a punched/roamed endpoint by promoting it to the front of the
//!    candidates of a local CLONE of the desired state — the reorder is
//!    never persisted anywhere (`ctx.desired` keeps the controller's
//!    pristine candidate order).
//!  - The next `apply_state` (any Sync `State` event — e.g. a NEW gateway
//!    enrolling) therefore rebuilds the device via
//!    `reconcile::device_config_pinned` from the pristine candidates, and
//!    every peer's endpoint reverts to `primary_endpoint()` = the static
//!    candidate. The existing `wg0_pins` map pins PUBKEYS only (rotation
//!    Role B); there is NO endpoint pin.
//!
//! TDD: this file is authored AHEAD of the implementation and is EXPECTED
//! to fail to compile until T4 lands. Target surface — the smallest natural
//! extension of the existing builder both apply paths already route through
//! (extending it, rather than adding a sibling builder, means NO call site
//! can rebuild the steady-state device without deciding about live
//! endpoints — the same "no call site can drift" rationale as T1):
//!
//!     pub fn device_config_pinned(
//!         ds: &DesiredState,
//!         private_key_b64: &str,
//!         listen_port: u16,
//!         pinned_pubkeys: &HashMap<u64, String>,   // rotation Role B (unchanged)
//!         live_endpoints: &HashMap<u64, String>,   // NEW: gateway_id -> "ip:port"
//!     ) -> DeviceConfig
//!
//! Normative semantics (plan T4):
//!  - `live_endpoints` holds, for every peer whose tunnel is currently LIVE
//!    (the post-T2 rx-corroborated notion — `Direct`, or `Relayed` pointing
//!    at the relay-transport local socket), the endpoint that tunnel is
//!    actually using. For any peer present in the map, the emitted
//!    `PeerConfig.endpoint` is `Some(<pinned value>)` — NEVER
//!    `primary_endpoint()`'s static candidate.
//!  - A peer ABSENT from the map (a NEW peer, or an existing peer with no
//!    live tunnel) gets `primary_endpoint()` exactly as today — that IS the
//!    recovery path and must keep working.
//!  - Everything else is unchanged: peers absent from `ds.peers` are not
//!    emitted (a stale pin must not resurrect a removed peer), `allowed_ips`
//!    always come from `ds`, the pubkey-pin logic and the always-on
//!    `PERSISTENT_KEEPALIVE_SECS` (T1) are untouched, and the two pin maps
//!    compose independently.
//!
//! Driver contract (implementer notes, not directly pinned here):
//!  - `PathCtx` grows a shared `live_endpoints: Arc<Mutex<HashMap<u64,
//!    String>>>`; `set_peer_endpoint` WRITES the pin (that is where a
//!    punched/relay endpoint is known) instead of relying on the lost
//!    candidate reorder; `run_path_ticks` CLEARS a peer's pin when its path
//!    leaves the live states (e.g. lands `Disconnected`), which is what
//!    re-enables the case-(d) recovery re-point; `apply_state` passes the
//!    map through to this builder.
//!  - CAUTION (reviewer + T8): these pure tests cannot catch a driver that
//!    passes an EMPTY map at the real `apply_state` call site — that wiring
//!    is exactly the incident bug and is covered end-to-end by plan T8's
//!    netns assertion (3) ("enrolling C does not break an established A<->B
//!    pair"). Review the call sites, not just this suite.
//!  - Mechanical churn expected: the 4-arg callers (`main.rs`
//!    `apply_state`/`set_peer_endpoint`, `reconcile.rs` unit tests,
//!    `tests/keepalive_emission.rs`) gain the new argument; only the two
//!    `main.rs` call sites may pass the REAL map, everything steady-state at
//!    boot (fail-static, before any liveness exists) passes an empty map.

use std::collections::HashMap;

use wiremesh_gateway::reconcile::device_config_pinned;
use wiremesh_gateway::state::{DesiredState, PeerState};
use wiremesh_gateway::uapi::{DeviceConfig, PeerConfig, PERSISTENT_KEEPALIVE_SECS};

fn peer(id: u64, key: &str, candidate: &str, cidr: &str) -> PeerState {
    PeerState {
        gateway_id: id,
        segment_name: format!("s{id}"),
        active_pubkey_b64: Some(key.to_string()),
        keys: vec![],
        candidates: vec![candidate.to_string()],
        allowed_ips: vec![cidr.into()],
    }
}

fn ds_with(peers: Vec<PeerState>) -> DesiredState {
    DesiredState { peers, ..Default::default() }
}

fn find<'a>(dev: &'a DeviceConfig, key: &str) -> &'a PeerConfig {
    dev.peers
        .iter()
        .find(|p| p.public_key_b64 == key)
        .unwrap_or_else(|| panic!("peer {key} missing from built device"))
}

const NO_KEY_PINS: fn() -> HashMap<u64, String> = HashMap::new;

/// The incident's endpoint shapes: peer 2 ("home") has the static candidate
/// the controller advertises, but its LIVE tunnel roamed to a punched
/// mapping.
const HOME_STATIC: &str = "79.119.133.77:51820";
const HOME_LIVE: &str = "203.0.113.9:40044";

/// T4(a) — the incident regression, exactly: peers 2+3 are an established
/// pair (peer 2 LIVE on a roamed endpoint); a NEWCOMER (peer 4) enrolls and
/// the desired state is re-applied. The rebuilt config must PRESERVE peer
/// 2's live endpoint — not clobber it back to the static candidate (finding
/// §2: that reset broke a working pair).
#[test]
fn t4_reapply_with_newcomer_preserves_live_peers_endpoint() {
    let ds = ds_with(vec![
        peer(2, "K2", HOME_STATIC, "10.10.2.0/24"),
        peer(3, "K3", "198.51.100.3:51820", "10.10.3.0/24"),
        peer(4, "K4-new", "198.51.100.4:51820", "10.10.4.0/24"), // px, the newcomer
    ]);
    let live = HashMap::from([(2u64, HOME_LIVE.to_string())]);

    let dev = device_config_pinned(&ds, "PRIV", 51820, &NO_KEY_PINS(), &live);

    let p2 = find(&dev, "K2");
    assert_eq!(
        p2.endpoint.as_deref(),
        Some(HOME_LIVE),
        "a LIVE peer's endpoint must survive a peer-set re-apply"
    );
    assert_ne!(
        p2.endpoint.as_deref(),
        Some(HOME_STATIC),
        "the live endpoint must not revert to the static candidate (finding §2)"
    );
}

/// T4(b) — the newcomer itself gets its static candidate endpoint (it has
/// no live tunnel yet) and the T1 always-on keepalive.
#[test]
fn t4_new_peer_gets_candidate_endpoint_and_keepalive() {
    let ds = ds_with(vec![
        peer(2, "K2", HOME_STATIC, "10.10.2.0/24"),
        peer(4, "K4-new", "198.51.100.4:51820", "10.10.4.0/24"),
    ]);
    let live = HashMap::from([(2u64, HOME_LIVE.to_string())]);

    let dev = device_config_pinned(&ds, "PRIV", 51820, &NO_KEY_PINS(), &live);

    let p4 = find(&dev, "K4-new");
    assert_eq!(
        p4.endpoint.as_deref(),
        Some("198.51.100.4:51820"),
        "a peer with no live tunnel dials its candidate"
    );
    assert_eq!(
        p4.keepalive_secs, PERSISTENT_KEEPALIVE_SECS,
        "the newcomer carries the T1 keepalive like every peer"
    );
}

/// T4(c) — a peer REMOVED from desired state disappears from the built
/// config even if a stale live-endpoint pin for it lingers: a pin must
/// never resurrect a deprovisioned peer.
#[test]
fn t4_removed_peer_disappears_despite_stale_pin() {
    let ds = ds_with(vec![peer(2, "K2", HOME_STATIC, "10.10.2.0/24")]); // peer 3 removed
    let live = HashMap::from([
        (2u64, HOME_LIVE.to_string()),
        (3u64, "198.51.100.3:44444".to_string()), // stale — peer 3 is gone
    ]);

    let dev = device_config_pinned(&ds, "PRIV", 51820, &NO_KEY_PINS(), &live);

    assert_eq!(dev.peers.len(), 1, "only desired-state peers may be emitted");
    assert_eq!(dev.peers[0].public_key_b64, "K2");
}

/// T4(d) — the recovery path: a NON-live existing peer (no established
/// tunnel, so absent from the live map) IS re-pointed at its fresh
/// candidate when the controller advertises a new one. Make-before-break
/// protects live tunnels only; a dead pair must keep chasing new
/// candidates.
#[test]
fn t4_non_live_peer_is_repointed_to_fresh_candidate() {
    // Controller learned a new observed mapping for (non-live) peer 3.
    let ds = ds_with(vec![
        peer(2, "K2", HOME_STATIC, "10.10.2.0/24"),
        peer(3, "K3", "198.51.100.7:41000", "10.10.3.0/24"), // fresh candidate
    ]);
    let live = HashMap::from([(2u64, HOME_LIVE.to_string())]); // 3 is NOT live

    let dev = device_config_pinned(&ds, "PRIV", 51820, &NO_KEY_PINS(), &live);

    assert_eq!(
        find(&dev, "K3").endpoint.as_deref(),
        Some("198.51.100.7:41000"),
        "a non-live peer must follow fresh candidates (recovery path)"
    );
}

/// T4(e) — an allowed-ips/CIDR change for a LIVE peer applies WITHOUT
/// touching its endpoint: the new CIDRs are emitted (policy/routing must
/// converge) while the endpoint stays pinned (the tunnel must not be
/// re-pointed).
#[test]
fn t4_allowed_ips_update_applies_without_touching_live_endpoint() {
    let mut p2 = peer(2, "K2", HOME_STATIC, "10.10.2.0/24");
    p2.allowed_ips = vec!["10.10.2.0/24".to_string(), "10.10.22.0/24".to_string()];
    let ds = ds_with(vec![p2]);
    let live = HashMap::from([(2u64, HOME_LIVE.to_string())]);

    let dev = device_config_pinned(&ds, "PRIV", 51820, &NO_KEY_PINS(), &live);

    let p2 = find(&dev, "K2");
    assert_eq!(
        p2.allowed_ips,
        vec!["10.10.2.0/24".to_string(), "10.10.22.0/24".to_string()],
        "the CIDR update must apply"
    );
    assert_eq!(
        p2.endpoint.as_deref(),
        Some(HOME_LIVE),
        "the CIDR update must not re-point a live peer's endpoint"
    );
}

/// The two pin maps compose: a peer that is BOTH rotation-pinned (Role B
/// old-epoch pubkey) and endpoint-pinned (live tunnel) keeps both pins —
/// a rotation overlap during an established session must not become an
/// endpoint reset, nor vice versa.
#[test]
fn t4_endpoint_pin_composes_with_rotation_pubkey_pin() {
    let ds = ds_with(vec![peer(2, "K2-promoted", HOME_STATIC, "10.10.2.0/24")]);
    let key_pins = HashMap::from([(2u64, "K2-old-epoch".to_string())]);
    let live = HashMap::from([(2u64, HOME_LIVE.to_string())]);

    let dev = device_config_pinned(&ds, "PRIV", 51820, &key_pins, &live);

    let p2 = find(&dev, "K2-old-epoch");
    assert_eq!(
        p2.endpoint.as_deref(),
        Some(HOME_LIVE),
        "endpoint pin must hold alongside the Role-B pubkey pin"
    );
    assert_eq!(dev.peers.len(), 1);
}
