//! Pure reconciliation: turn desired state into a WG device config and a route
//! add/remove diff, and decide when the enforcer needs re-`apply` (spec §5.2).
use crate::state::DesiredState;
use crate::uapi::{DeviceConfig, PeerConfig};

pub fn peer_configs(ds: &DesiredState, keepalive_secs: u16) -> Vec<PeerConfig> {
    ds.peers
        .iter()
        .filter_map(|p| {
            let public_key_b64 = p.active_pubkey_b64.clone()?;
            Some(PeerConfig {
                public_key_b64,
                endpoint: p.primary_endpoint().cloned(),
                allowed_ips: p.allowed_ips.clone(),
                keepalive_secs,
            })
        })
        .collect()
}

/// Peer-configs targeting each peer's real-keyed PENDING epoch. The pending
/// endpoint reuses the peer's active-candidate IP with the UDP port offset by
/// `(pending_epoch - active_epoch)`, matching the `base_wg_port + epoch` port
/// convention both gateways use for their per-epoch Devices (key-rotation
/// Task 6). A peer with no real pending key (active-only, or a sentinel
/// pending) contributes nothing.
pub fn pending_peer_configs(ds: &DesiredState, keepalive_secs: u16) -> Vec<PeerConfig> {
    ds.peers
        .iter()
        .filter_map(|p| {
            let active = p.active_key()?;
            let pending = p.pending_key()?;
            let endpoint = p.primary_endpoint()?;
            let (ip, port_str) = endpoint.rsplit_once(':')?;
            let active_port: u16 = port_str.parse().ok()?;
            let offset = pending.epoch.checked_sub(active.epoch)?;
            let offset: u16 = offset.try_into().ok()?;
            let pending_port = active_port.checked_add(offset)?;
            Some(PeerConfig {
                public_key_b64: pending.pubkey_b64.clone(),
                endpoint: Some(format!("{ip}:{pending_port}")),
                allowed_ips: p.allowed_ips.clone(),
                keepalive_secs,
            })
        })
        .collect()
}

pub fn device_config(
    ds: &DesiredState,
    private_key_b64: &str,
    listen_port: u16,
    keepalive_secs: u16,
) -> DeviceConfig {
    DeviceConfig {
        private_key_b64: private_key_b64.to_string(),
        listen_port,
        peers: peer_configs(ds, keepalive_secs),
    }
}

/// Like [`device_config`], but for any peer whose `gateway_id` appears in
/// `pinned_pubkeys`, use that pinned base64 pubkey instead of the peer's
/// current `active_pubkey_b64` (key-rotation Task 9, Role B make-before-break).
///
/// While this gateway is overlapping a rotating peer — carrying the peer's NEW
/// epoch on a transient `wg0e<N>` Device — its base `wg0` Device must keep the
/// peer's OLD-epoch session alive so traffic the peer is still sending on its
/// old key (until it cuts over) keeps decrypting. But a `replace_peers` apply
/// driven by the peer's promote delta (which flips the peer's advertised
/// `active` key to the new epoch) would otherwise rekey the `wg0` peer entry to
/// the new key, tearing that old session down mid-flight. Pinning the `wg0`
/// entry to the epoch this gateway originally brought `wg0` up against holds
/// the old receive path open across the peer's promote — the "break" never
/// happens on the base tun.
pub fn device_config_pinned(
    ds: &DesiredState,
    private_key_b64: &str,
    listen_port: u16,
    keepalive_secs: u16,
    pinned_pubkeys: &std::collections::HashMap<u64, String>,
) -> DeviceConfig {
    let peers = ds
        .peers
        .iter()
        .filter_map(|p| {
            let public_key_b64 = match pinned_pubkeys.get(&p.gateway_id) {
                Some(pinned) => pinned.clone(),
                None => p.active_pubkey_b64.clone()?,
            };
            Some(PeerConfig {
                public_key_b64,
                endpoint: p.primary_endpoint().cloned(),
                allowed_ips: p.allowed_ips.clone(),
                keepalive_secs,
            })
        })
        .collect();
    DeviceConfig { private_key_b64: private_key_b64.to_string(), listen_port, peers }
}

/// Rewrite the UDP port of an `ip:port` endpoint string, preserving the host.
/// `None` for a malformed endpoint (no `:port` suffix). Used by
/// [`device_config_at_port`] to retarget peers at a rotation epoch's offset
/// port (key-rotation Task 9).
fn rewrite_endpoint_port(endpoint: &str, port: u16) -> Option<String> {
    let (ip, _) = endpoint.rsplit_once(':')?;
    Some(format!("{ip}:{port}"))
}

/// A device config for a NEW own-epoch Device (key-rotation Task 9, Role A):
/// the gateway's own rotated private key on `port`, peering the SAME current
/// peers by their ACTIVE keys, but with each peer's endpoint retargeted to
/// `port` — the peer's own new-epoch Device listens on the identical offset
/// port (`base_wg_port + (N - active_epoch)`), so both sides rendezvous on it
/// during the make-before-break overlap while the old epoch keeps carrying
/// traffic on the base port. A peer with no active key or no endpoint
/// contributes nothing (it can't be reached on the new epoch yet).
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
            let public_key_b64 = p.active_pubkey_b64.clone()?;
            let endpoint = p.primary_endpoint().and_then(|ep| rewrite_endpoint_port(ep, port));
            Some(PeerConfig {
                public_key_b64,
                endpoint,
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
        let cfgs = peer_configs(&ds, 15);
        assert_eq!(cfgs.len(), 1);
        assert_eq!(cfgs[0].public_key_b64, "K2");
        assert_eq!(cfgs[0].keepalive_secs, 15);
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
