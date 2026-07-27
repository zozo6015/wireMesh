//! T1 pin — WireGuard persistent keepalive (mesh-convergence fix cycle,
//! plan `docs/superpowers/plans/2026-07-28-mesh-convergence-fixes.md`,
//! evidence `docs/research/ops-finding-multi-gateway-convergence.md` §5:
//! a NAT-ed peer's mapping expires on idle → the observed sawtooth).
//!
//! TDD: this file is authored AHEAD of the implementation and is EXPECTED
//! to fail to compile until T1 lands. Target API for the implementer:
//!
//!  1. `wiremesh_gateway::uapi::PERSISTENT_KEEPALIVE_SECS: u16 = 25` — a
//!     new public constant on the UAPI device-config writer module; the
//!     single source of the steady-state keepalive (always-on, no config
//!     knob in v1 per the plan). `main.rs`'s private `KEEPALIVE: u16 = 15`
//!     goes away in favor of it.
//!
//!  2. The STEADY-STATE reconcile builders stop taking a caller-supplied
//!     `keepalive_secs` parameter (so no call site can configure a peer
//!     without the keepalive, and the value cannot drift per-caller):
//!       - `reconcile::peer_configs(ds: &DesiredState) -> Vec<PeerConfig>`
//!       - `reconcile::device_config(ds, private_key_b64, listen_port) -> DeviceConfig`
//!       - `reconcile::device_config_pinned(ds, private_key_b64, listen_port, pinned_pubkeys) -> DeviceConfig`
//!     Each emits `keepalive_secs = uapi::PERSISTENT_KEEPALIVE_SECS` on
//!     EVERY peer it builds. NOTE: the rotation-scoped builders
//!     (`pending_peer_configs`, `device_config_at_port`) deliberately KEEP
//!     their explicit parameter — `ROTATION_KEEPALIVE = 3` on transient
//!     overlap devices is a documented design choice (main.rs) and 3s ≤ 25s
//!     keeps NAT mappings at least as warm, so it satisfies T1's intent.
//!
//! Why this covers "peers added later, not just at device creation"
//! (T1(b)): every UAPI apply in this gateway is a full `replace_peers=true`
//! set built by these builders — `apply_state` and `set_peer_endpoint`
//! (the punch-success / relay re-point path, i.e. exactly how a peer's
//! entry is (re)written AFTER boot) both route through
//! `device_config_pinned`. There is no incremental single-peer UAPI write
//! path. Pinning the builders therefore pins every later apply too.
//!
//! Existing tests that will need a mechanical update when the signatures
//! change (implementer's job, expected churn):
//!  - `src/reconcile.rs::tests::peer_configs_skip_peers_without_active_key`
//!    (calls `peer_configs(&ds, 15)` and asserts `keepalive_secs == 15`).
//!  - `src/tunnel.rs` / `src/tunnelset.rs` `reconcile(..., keepalive_secs)`
//!    pass-through parameters, and `main.rs` call sites.

use std::collections::HashMap;

use wiremesh_gateway::reconcile::{device_config, device_config_pinned, peer_configs};
use wiremesh_gateway::state::{DesiredState, PeerState};
use wiremesh_gateway::uapi::{encode_set, DeviceConfig, PeerConfig, PERSISTENT_KEEPALIVE_SECS};

/// Minimal local base64 (the crate's own encoder is `pub(crate)`); only
/// used to mint valid 32-byte WG keys for `encode_set`, which rejects
/// anything else.
fn b64(bytes: &[u8; 32]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { T[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    out
}

fn peer(id: u64, key: Option<&str>, cidr: &str) -> PeerState {
    PeerState {
        gateway_id: id,
        segment_name: format!("s{id}"),
        active_pubkey_b64: key.map(String::from),
        keys: vec![],
        candidates: vec![format!("10.9.0.{id}:51820")],
        allowed_ips: vec![cidr.into()],
    }
}

fn ds_with(peers: Vec<PeerState>) -> DesiredState {
    DesiredState { peers, ..Default::default() }
}

/// T1: the steady-state keepalive is 25 seconds, exposed as a lib constant
/// (so it is unit-assertable, unlike the old `main.rs`-private value) —
/// the standard WG answer to NAT mapping expiry (finding §5).
#[test]
fn t1_steady_state_keepalive_constant_is_25_seconds() {
    assert_eq!(
        PERSISTENT_KEEPALIVE_SECS, 25,
        "plan T1: persistent_keepalive_interval must be 25s on every peer"
    );
}

/// T1(a): the UAPI `set` emission carries `persistent_keepalive_interval=25`
/// for EVERY peer block — including a peer with no endpoint yet (the
/// "added later, not yet punched" shape), which must not silently drop the
/// keepalive line.
#[test]
fn t1_encode_set_emits_keepalive_25_for_every_peer() {
    let cfg = DeviceConfig {
        private_key_b64: b64(&[0x11u8; 32]),
        listen_port: 51820,
        peers: vec![
            PeerConfig {
                public_key_b64: b64(&[0x22u8; 32]),
                endpoint: Some("203.0.113.5:51820".into()),
                allowed_ips: vec!["10.10.2.0/24".into()],
                keepalive_secs: PERSISTENT_KEEPALIVE_SECS,
            },
            // No endpoint: a peer whose candidates aren't dialable yet still
            // needs the keepalive so the session stays warm once it forms.
            PeerConfig {
                public_key_b64: b64(&[0x33u8; 32]),
                endpoint: None,
                allowed_ips: vec!["10.10.3.0/24".into()],
                keepalive_secs: PERSISTENT_KEEPALIVE_SECS,
            },
        ],
    };
    let out = encode_set(&cfg).unwrap();
    let hits = out.matches("persistent_keepalive_interval=25\n").count();
    assert_eq!(
        hits, 2,
        "every peer block must carry persistent_keepalive_interval=25; body:\n{out}"
    );
    assert!(
        !out.contains("persistent_keepalive_interval=0"),
        "no peer may be written with keepalive disabled; body:\n{out}"
    );
}

/// T1(a): the steady-state peer builder produces 25s keepalive on every
/// peer WITHOUT the caller supplying a value — the keepalive is always-on
/// and not a per-call-site choice (target signature: `peer_configs(&ds)`).
#[test]
fn t1_peer_configs_always_carry_25s_keepalive() {
    let ds = ds_with(vec![peer(2, Some("K2"), "10.10.2.0/24"), peer(3, Some("K3"), "10.10.3.0/24")]);
    let cfgs = peer_configs(&ds);
    assert_eq!(cfgs.len(), 2);
    for cfg in &cfgs {
        assert_eq!(
            cfg.keepalive_secs, PERSISTENT_KEEPALIVE_SECS,
            "peer {} must carry the 25s keepalive",
            cfg.public_key_b64
        );
    }
}

/// T1(a): same pin for the full device build used at device creation
/// (target signature: `device_config(&ds, priv, port)`).
#[test]
fn t1_device_config_carries_25s_keepalive() {
    let ds = ds_with(vec![peer(2, Some("K2"), "10.10.2.0/24")]);
    let dev = device_config(&ds, "PRIV", 51820);
    assert_eq!(dev.peers.len(), 1);
    assert_eq!(dev.peers[0].keepalive_secs, PERSISTENT_KEEPALIVE_SECS);
}

/// T1(b): peers (re)applied AFTER device creation get the keepalive too.
/// `set_peer_endpoint` — the path that rewrites a peer's entry on punch
/// success or a relay re-point, i.e. how a later-enrolled peer's endpoint
/// actually lands in WireGuard — builds via `device_config_pinned`, so this
/// builder is the "later" surface (target signature:
/// `device_config_pinned(&ds, priv, port, &pins)`). A NEWLY-ADDED peer
/// (id 4, present in desired state but not pinned) and a pinned existing
/// peer must BOTH carry 25.
#[test]
fn t1_device_config_pinned_carries_25s_keepalive_for_new_and_pinned_peers() {
    let ds = ds_with(vec![
        peer(2, Some("K2"), "10.10.2.0/24"),
        peer(4, Some("K4-new"), "10.10.4.0/24"), // the newcomer (finding §2 shape)
    ]);
    let pins: HashMap<u64, String> = HashMap::from([(2u64, "K2-pinned-old-epoch".to_string())]);
    let dev = device_config_pinned(&ds, "PRIV", 51820, &pins);
    assert_eq!(dev.peers.len(), 2);
    for p in &dev.peers {
        assert_eq!(
            p.keepalive_secs, PERSISTENT_KEEPALIVE_SECS,
            "peer {} (pinned or newly added) must carry the 25s keepalive",
            p.public_key_b64
        );
    }
}
