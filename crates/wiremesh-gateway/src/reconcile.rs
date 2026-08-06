//! Pure reconciliation: turn desired state into a WG device config and a route
//! add/remove diff, and decide when the enforcer needs re-`apply` (spec §5.2).
use crate::state::DesiredState;
use crate::tunnelset::OWN_TUN_PORT_OFFSET;
use crate::uapi::{DeviceConfig, PeerConfig, PERSISTENT_KEEPALIVE_SECS};

/// Steady-state peer builder. Every peer it emits carries
/// [`PERSISTENT_KEEPALIVE_SECS`] unconditionally — deliberately NOT a caller
/// parameter (mesh-convergence fix T1): the incident deployment shipped with
/// no persistent keepalive at all, so NAT-ed peers' UDP mappings expired on
/// idle and working paths sawtoothed
/// (`docs/research/ops-finding-multi-gateway-convergence.md` §5). Baking the
/// keepalive into the builder means no call site can configure a peer
/// without it, and the value cannot drift per-caller. The rotation-scoped
/// builders ([`pending_peer_configs`], [`device_config_at_port`]) keep their
/// explicit parameter — their transient overlap devices use a deliberately
/// tighter cadence (see `main.rs`'s `ROTATION_KEEPALIVE`).
pub fn peer_configs(ds: &DesiredState) -> Vec<PeerConfig> {
    ds.peers
        .iter()
        .filter_map(|p| {
            let public_key_b64 = p.active_pubkey_b64.clone()?;
            Some(PeerConfig {
                public_key_b64,
                endpoint: p.primary_endpoint().cloned(),
                allowed_ips: p.allowed_ips.clone(),
                keepalive_secs: PERSISTENT_KEEPALIVE_SECS,
            })
        })
        .collect()
}

/// Peer-configs targeting each peer's real-keyed PENDING epoch — the peer set
/// of a Role-B overlap Device. The pending endpoint reuses the peer's
/// advertised candidate IP with the UDP port at
/// [`OWN_TUN_PORT_OFFSET`] above the candidate's own port. A peer with no real
/// pending key (active-only, or a sentinel pending) contributes nothing.
///
/// # Why `candidate_port + 1`, and why there is no epoch arithmetic left here
///
/// This used to compute `active_port + (pending_epoch - active_epoch)` on the
/// theory that both gateways placed epoch `n`'s Device at `base_wg_port + n`.
/// Nothing has placed a Device that way since T3 made the listen port an
/// ALLOCATION (`tunnelset::plan_port`), and the formula survived only because
/// its answer coincides with the allocator's on rotation 0 -> 1. On any later
/// rotation the two diverged and the peer dialled a port the rotating gateway
/// was not on — bug 5, i.e. "the second rotation of any gateway cannot
/// complete" (`docs/research/port-authority-verification-the-shape-was-wrong.md`).
///
/// The formula is deleted rather than kept as a fallback, because a fallback
/// would be an alternative answer to a question that admits exactly one:
///
///  - piece 2 puts the rotating gateway's ACTIVE key back on its base port at
///    every retire, so the candidate this endpoint is derived from is the port
///    the peer's active key is really on, at every rotation and not just the
///    first; and
///  - piece 3 RESERVES [`OWN_TUN_PORT_OFFSET`] for a gateway's own new-epoch
///    tun, so its in-flight new epoch is at `base + 1` regardless of the epoch
///    NUMBER and regardless of how many overlaps that gateway is carrying.
///
/// So the target is `candidate_port + OWN_TUN_PORT_OFFSET`, and the constant is
/// imported from the allocator that enforces it rather than restated here:
/// one definition, two readers, nothing to drift.
pub fn pending_peer_configs(ds: &DesiredState, keepalive_secs: u16) -> Vec<PeerConfig> {
    ds.peers
        .iter()
        .filter_map(|p| {
            // Required but unused: a peer mid-make-before-break advertises BOTH
            // rows, and `main.rs`'s `role_b_decisions` — the only consumer of
            // this builder — demands both too. Keeping the guard keeps the two
            // peer sets identical, so a malformed pending-without-active roster
            // entry can never produce an overlap here that the decision layer
            // would refuse to stand up.
            p.active_key()?;
            let pending = p.pending_key()?;
            let endpoint = p.primary_endpoint()?;
            let (ip, port_str) = endpoint.rsplit_once(':')?;
            let candidate_port: u16 = port_str.parse().ok()?;
            let pending_port = candidate_port.checked_add(OWN_TUN_PORT_OFFSET)?;
            Some(PeerConfig {
                public_key_b64: pending.pubkey_b64.clone(),
                endpoint: Some(format!("{ip}:{pending_port}")),
                allowed_ips: p.allowed_ips.clone(),
                keepalive_secs,
            })
        })
        .collect()
}

/// Steady-state full-device builder — peers via [`peer_configs`], which
/// emits the always-on [`PERSISTENT_KEEPALIVE_SECS`] on every peer (fix T1;
/// see [`peer_configs`] for the rationale and the finding citation).
pub fn device_config(ds: &DesiredState, private_key_b64: &str, listen_port: u16) -> DeviceConfig {
    DeviceConfig {
        private_key_b64: private_key_b64.to_string(),
        listen_port,
        peers: peer_configs(ds),
    }
}

/// Like [`device_config`], but for any peer whose `gateway_id` appears in
/// `pinned_pubkeys`, use that pinned base64 pubkey instead of the peer's
/// current `active_pubkey_b64` (key-rotation Task 9, Role B make-before-break).
///
/// While this gateway is overlapping a rotating peer — carrying the peer's NEW
/// epoch on a transient `wg0o<slot>` overlap Device — its base `wg0` Device must keep the
/// peer's OLD-epoch session alive so traffic the peer is still sending on its
/// old key (until it cuts over) keeps decrypting. But a `replace_peers` apply
/// driven by the peer's promote delta (which flips the peer's advertised
/// `active` key to the new epoch) would otherwise rekey the `wg0` peer entry to
/// the new key, tearing that old session down mid-flight. Pinning the `wg0`
/// entry to the epoch this gateway originally brought `wg0` up against holds
/// the old receive path open across the peer's promote — the "break" never
/// happens on the base tun.
///
/// Steady-state surface too (fix T1): `apply_state` AND `set_peer_endpoint`
/// (the punch-success / relay re-point path — i.e. exactly how a
/// later-enrolled peer's entry is (re)written after boot) both build through
/// here, so like [`peer_configs`] it emits [`PERSISTENT_KEEPALIVE_SECS`] on
/// every peer unconditionally rather than taking a caller value (finding §5:
/// idle NAT mappings expired because no keepalive was ever set).
///
/// Make-before-break peer application (mesh-convergence fix T4):
/// `live_endpoints` holds, for every peer whose tunnel currently shows
/// liveness (the post-T2 rx-corroborated notion — `Direct`, or `Relayed`
/// pointing at the relay-transport local socket), the endpoint that tunnel
/// is actually using (`gateway_id -> "ip:port"`). A peer present in the map
/// is emitted with EXACTLY that endpoint — never `primary_endpoint()`'s
/// static candidate. Rationale
/// (`docs/research/ops-finding-multi-gateway-convergence.md` §2): in the
/// 2026-07-27 incident, enrolling a third gateway re-applied the peer set
/// and reset FI's ESTABLISHED `home` endpoint back to the static candidate
/// `79.119.133.77:51820` — then-undialable — breaking a WORKING pair that
/// never re-formed on its own. A newcomer must not break existing tunnels:
/// re-applying desired state may add/remove peers and update
/// keys/allowed-ips, but never rewrite a live tunnel's endpoint. A peer
/// ABSENT from the map (a new peer, or an existing peer with no live
/// tunnel) gets `primary_endpoint()` exactly as before — that IS the
/// recovery path (a dead pair must keep chasing fresh candidates). A stale
/// entry for a peer no longer in `ds.peers` is ignored: pins never
/// resurrect a removed peer. The endpoint pin and the Role-B pubkey pin
/// compose independently. Extending THIS builder (rather than adding a
/// sibling) means no call site can rebuild the steady-state device without
/// deciding about live endpoints — the same "no call site can drift"
/// rationale as T1's keepalive.
pub fn device_config_pinned(
    ds: &DesiredState,
    private_key_b64: &str,
    listen_port: u16,
    pinned_pubkeys: &std::collections::HashMap<u64, String>,
    live_endpoints: &std::collections::HashMap<u64, String>,
) -> DeviceConfig {
    let peers = ds
        .peers
        .iter()
        .filter_map(|p| {
            let public_key_b64 = match pinned_pubkeys.get(&p.gateway_id) {
                Some(pinned) => pinned.clone(),
                None => p.active_pubkey_b64.clone()?,
            };
            let endpoint = match live_endpoints.get(&p.gateway_id) {
                // Live tunnel: keep the endpoint it is actually using
                // (make-before-break, finding §2).
                Some(live) => Some(live.clone()),
                // No live tunnel: dial the advertised candidate (recovery).
                None => p.primary_endpoint().cloned(),
            };
            Some(PeerConfig {
                public_key_b64,
                endpoint,
                allowed_ips: p.allowed_ips.clone(),
                keepalive_secs: PERSISTENT_KEEPALIVE_SECS,
            })
        })
        .collect();
    DeviceConfig { private_key_b64: private_key_b64.to_string(), listen_port, peers }
}

/// A device config for a NEW own-epoch Device (key-rotation Task 9, Role A):
/// the gateway's own rotated private key on `port`, peering the SAME current
/// peers by their ACTIVE keys, **with no endpoint on any peer**. A peer with no
/// active key contributes nothing (it can't be reached on the new epoch yet).
///
/// # This device is a RECEIVER. It is not supposed to dial anyone.
///
/// Until piece 3 this rewrote every peer's endpoint to `ip:port` — our OWN
/// listen port on the peer's address — justified as "the peer's own new-epoch
/// Device listens on the identical offset port". **That premise is false and
/// cannot be made true**, so the rewrite is gone rather than corrected:
///
///  - The peers here are keyed by each peer's **active** public key, and a
///    peer's active key lives on that peer's **active** Device, at its
///    advertised candidate port. Dialling it would reach a Device that has
///    never heard of the brand-new static key this one runs, so its handshake
///    initiation is dropped as an unknown peer.
///  - The only Device in the fabric that CAN answer this one is the peer's
///    Role-B **overlap** toward our pending epoch — which runs the peer's
///    active key (hence the key match) and lives at a port that peer's own
///    `tunnelset::plan_port` allocated from its own free list. That port is
///    genuinely unknowable from here: it depends on how many other peers that
///    gateway is overlapping, and on nothing we are told.
///  - The old rewrite appeared to work only on rotation 0 -> 1, where both
///    sides' free lists happened to hand out `base + 1`. Piece 3's reserved
///    own-epoch slot ends even that coincidence — the peer's overlaps now start
///    at `base + 2` — so an emitted endpoint could not be right even by luck.
///
/// What actually brings this Device live is the peer's overlap initiating (its
/// rotation tick kicks the handshake until the session is up), after which
/// boringtun roams this peer entry onto the authenticated source address. An
/// endpoint-less peer is exactly how WireGuard expresses "wait to be dialled",
/// and it is honest: no value here is ever read back as authority, so there is
/// nothing for a later apply to have to "restore".
///
/// **Known consequence, deliberately accepted:** with no endpoint, this Device
/// emits nothing, so Role A's `kick_overlap` probe is inert for the whole
/// overlap and a NAT in front of this gateway sees no outbound datagram from
/// `port` and opens no mapping for it. Neither is a regression the endpoint
/// could have avoided — a datagram aimed at the peer's active Device punches a
/// hole for an address the peer's overlap does not send from — and rotation
/// behind NAT is separately unsupported anyway: the observe socket is bound to
/// the base port for process life, so an offset port is never observed,
/// reported, or advertised as a candidate.
pub fn device_config_at_port(
    ds: &DesiredState,
    private_key_b64: &str,
    port: u16,
    keepalive_secs: u16,
) -> DeviceConfig {
    let peers = ds
        .peers
        .iter()
        .filter_map(|p| {
            Some(PeerConfig {
                public_key_b64: p.active_pubkey_b64.clone()?,
                // See the doc above: receive-and-roam, never dial.
                endpoint: None,
                allowed_ips: p.allowed_ips.clone(),
                keepalive_secs,
            })
        })
        .collect();
    DeviceConfig { private_key_b64: private_key_b64.to_string(), listen_port: port, peers }
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct RouteDiff {
    pub to_add: Vec<String>,
    pub to_del: Vec<String>,
}

fn all_cidrs(ds: &DesiredState) -> std::collections::BTreeSet<String> {
    ds.peers.iter().flat_map(|p| p.allowed_ips.iter().cloned()).collect()
}

pub fn route_diff(old: &DesiredState, new: &DesiredState) -> RouteDiff {
    let o = all_cidrs(old);
    let n = all_cidrs(new);
    RouteDiff {
        to_add: n.difference(&o).cloned().collect(),
        to_del: o.difference(&n).cloned().collect(),
    }
}

pub fn policy_changed(old: &DesiredState, new: &DesiredState) -> bool {
    old.policy_version != new.policy_version
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{DesiredState, PeerKeyInfo, PeerState};

    fn ds_with(peers: Vec<PeerState>, ver: u64) -> DesiredState {
        DesiredState { peers, policy_version: ver, ..Default::default() }
    }
    fn p(id: u64, key: Option<&str>, cidr: &str) -> PeerState {
        PeerState {
            gateway_id: id, segment_name: format!("s{id}"),
            active_pubkey_b64: key.map(String::from),
            keys: vec![],
            candidates: vec![format!("10.9.0.{id}:51820")],
            allowed_ips: vec![cidr.into()],
        }
    }

    /// Builds a `PeerState` with an explicit `keys` set (active + optionally
    /// pending), for the `pending_peer_configs` tests below. Kept separate
    /// from the shared `p(...)` helper above (which existing tests rely on
    /// and does not carry a `keys` vec) so those tests are left untouched.
    fn peer_full(id: u64, candidate: &str, keys: Vec<PeerKeyInfo>, cidr: &str) -> PeerState {
        let active_pubkey_b64 = keys.iter().find(|k| k.state == "active").map(|k| k.pubkey_b64.clone());
        PeerState {
            gateway_id: id,
            segment_name: format!("s{id}"),
            active_pubkey_b64,
            candidates: vec![candidate.to_string()],
            keys,
            allowed_ips: vec![cidr.into()],
        }
    }

    #[test]
    fn peer_configs_skip_peers_without_active_key() {
        let ds = ds_with(vec![p(2, Some("K2"), "10.10.2.0/24"), p(3, None, "10.10.3.0/24")], 0);
        let cfgs = peer_configs(&ds);
        assert_eq!(cfgs.len(), 1);
        assert_eq!(cfgs[0].public_key_b64, "K2");
        // Plumbing pin only — the 25s value contract itself is pinned by the
        // T1 suite (`tests/keepalive_emission.rs`).
        assert_eq!(cfgs[0].keepalive_secs, PERSISTENT_KEEPALIVE_SECS);
        assert_eq!(cfgs[0].allowed_ips, vec!["10.10.2.0/24".to_string()]);
    }

    #[test]
    fn route_diff_adds_and_removes() {
        let old = ds_with(vec![p(2, Some("K2"), "10.10.2.0/24"), p(3, Some("K3"), "10.10.3.0/24")], 0);
        let new = ds_with(vec![p(2, Some("K2"), "10.10.2.0/24"), p(4, Some("K4"), "10.10.4.0/24")], 0);
        let diff = route_diff(&old, &new);
        assert_eq!(diff.to_add, vec!["10.10.4.0/24".to_string()]);
        assert_eq!(diff.to_del, vec!["10.10.3.0/24".to_string()]);
    }

    #[test]
    fn policy_changed_tracks_version() {
        assert!(policy_changed(&ds_with(vec![], 1), &ds_with(vec![], 2)));
        assert!(!policy_changed(&ds_with(vec![], 2), &ds_with(vec![], 2)));
    }

    #[test]
    fn pending_peer_configs_builds_offset_endpoint() {
        let peer = peer_full(
            2,
            "10.9.0.2:51820",
            vec![
                PeerKeyInfo { epoch: 0, pubkey_b64: "KA".into(), state: "active".into() },
                PeerKeyInfo { epoch: 1, pubkey_b64: "KP".into(), state: "pending".into() },
            ],
            "10.10.2.0/24",
        );
        let ds = ds_with(vec![peer], 0);
        let cfgs = pending_peer_configs(&ds, 25);
        assert_eq!(cfgs.len(), 1);
        assert_eq!(cfgs[0].public_key_b64, "KP");
        assert_eq!(cfgs[0].endpoint.as_deref(), Some("10.9.0.2:51821"));
        assert_eq!(cfgs[0].allowed_ips, vec!["10.10.2.0/24".to_string()]);
        assert_eq!(cfgs[0].keepalive_secs, 25);
    }

    #[test]
    fn pending_peer_configs_skips_active_only() {
        let peer = peer_full(
            3,
            "10.9.0.3:51820",
            vec![PeerKeyInfo { epoch: 0, pubkey_b64: "KA".into(), state: "active".into() }],
            "10.10.3.0/24",
        );
        let ds = ds_with(vec![peer], 0);
        assert!(pending_peer_configs(&ds, 25).is_empty());
    }

    #[test]
    fn pending_peer_configs_skips_sentinel_pending() {
        let peer = peer_full(
            4,
            "10.9.0.4:51820",
            vec![
                PeerKeyInfo { epoch: 0, pubkey_b64: "KA".into(), state: "active".into() },
                PeerKeyInfo { epoch: 1, pubkey_b64: "awaiting-submission".into(), state: "pending".into() },
            ],
            "10.10.4.0/24",
        );
        let ds = ds_with(vec![peer], 0);
        assert!(pending_peer_configs(&ds, 25).is_empty());
    }

    #[test]
    fn pending_peer_configs_offset_survives_nonzero_active_epoch() {
        let peer = peer_full(
            5,
            "10.9.0.2:51822",
            vec![
                PeerKeyInfo { epoch: 2, pubkey_b64: "KA".into(), state: "active".into() },
                PeerKeyInfo { epoch: 3, pubkey_b64: "KP".into(), state: "pending".into() },
            ],
            "10.10.5.0/24",
        );
        let ds = ds_with(vec![peer], 0);
        let cfgs = pending_peer_configs(&ds, 25);
        assert_eq!(cfgs.len(), 1);
        assert_eq!(cfgs[0].endpoint.as_deref(), Some("10.9.0.2:51823"));
    }
}
