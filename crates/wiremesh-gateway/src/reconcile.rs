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

/// `ip:(port + OWN_TUN_PORT_OFFSET)` for a peer candidate `ip:port` — the ONE
/// UDP port a gateway's in-flight new epoch can be reached on, by reservation
/// rather than by epoch arithmetic. `None` for anything that is not `ip:port`,
/// and `None` rather than a wrap for a port that cannot be offset inside a
/// u16.
///
/// The overflow case is reachable, not hypothetical: `is_dialable_endpoint`
/// accepts `:65535`, so the ingest filter keeps such a candidate verbatim
/// (`state.rs`'s
/// `partition_dialable_keeps_every_valid_candidate_verbatim_and_in_order`).
/// Wrapping it would produce `:0` — a wildcard that silently reaches nothing
/// while every layer above reports a programmed endpoint — so the add is
/// checked and a peer we cannot derive an endpoint for is DROPPED by its
/// caller instead of emitted half-built.
///
/// # The single authority, and its two readers
///
/// This is a derivation, not a validator, and it exists as one function
/// because the question it answers — *which UDP port is a rotating gateway's
/// in-flight new epoch on?* — must have exactly one answer:
///
///  - [`pending_peer_configs`] asks it while building a Role-B overlap
///    Device's peer set, i.e. while the peer's new epoch is still `pending`;
///  - [`crate::rotation::collapse_dial`] asks it at the Role-B collapse arm,
///    i.e. after the peer has PROMOTED that epoch, to dial the same device
///    from our own new-epoch tun in the in-step case
///    (`docs/research/in-step-rotation-rebaselined.md`).
///
/// Same question on either side of the peer's promote, and the answer must not
/// change across it, because the peer's device did not move. `tests/collapse_dial.rs`
/// compares the two produced strings so neither reader can drift from the other.
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
/// imported from the allocator that enforces it rather than restated here.
/// **Nothing in this derivation reads an epoch NUMBER**, and nothing may start
/// to: that is precisely what bug 5 was.
///
/// # Why this is a socket-address parse, and why the answer is REBUILT
///
/// What this returns is written to the WireGuard UAPI as an `endpoint=` line
/// (via [`pending_peer_configs`] -> the overlap `DeviceConfig`, and via
/// [`crate::rotation::collapse_dial`] -> the collapse arm's pinned endpoint),
/// and the UAPI wire format is newline-delimited `key=value`. So this is a
/// UAPI-injection boundary, and it used to be a `rsplit_once(':')` + port
/// parse — which splits at the LAST colon and hands everything before it back
/// verbatim. `"10.9.0.2:51820\nendpoint=203.0.113.1:9"` therefore came out as
/// `"10.9.0.2:51820\nendpoint=203.0.113.1:10"`: a second `endpoint=` directive
/// of the sender's choosing, smuggled through the derivation.
/// `tests/collapse_dial.rs`'s
/// `an_unparseable_candidate_yields_no_dial_instead_of_a_panic` found it.
///
/// The candidate is therefore parsed as a `SocketAddrV4` — the SAME notion of
/// "is this dialable at all" the rest of the fabric uses, reached through
/// [`crate::uapi::is_dialable_endpoint`] rather than restated here, so this
/// cannot become a third opinion about endpoint shape (see that function, and
/// `tests/predicate_equality.rs`, for why a looser one is a crash-loop path).
/// `uapi::validate_ipv4_endpoint` rejects an embedded newline for exactly this
/// reason, and `tests/uapi_endpoint_validation.rs` pins the same payload shape
/// as rejected at that door.
///
/// The returned string is then REBUILT from the parsed parts — the parsed
/// `Ipv4Addr` and the `checked_add`ed port — never spliced out of the input.
/// That is the half that matters: a filter can be reasoned around, but a
/// result assembled only from a `Ipv4Addr` and a `u16` cannot represent a
/// newline, a second directive, or anything else that is not a canonical
/// `a.b.c.d:port`. Malformed output is unrepresentable rather than screened.
pub fn own_tun_endpoint(candidate: &str) -> Option<String> {
    // Gate on the shared predicate first, so "which endpoints exist at all"
    // keeps exactly one definition; the parse below is how this function gets
    // the PARTS, not a second opinion about acceptance (`is_dialable_endpoint`
    // accepts a `SocketAddr::V4` and nothing else, so it cannot fail after the
    // gate — `.ok()?` keeps the function total rather than asserting that).
    if !crate::uapi::is_dialable_endpoint(candidate) {
        return None;
    }
    let addr: std::net::SocketAddrV4 = candidate.parse().ok()?;
    let own_tun_port = addr.port().checked_add(OWN_TUN_PORT_OFFSET)?;
    Some(format!("{}:{own_tun_port}", addr.ip()))
}

/// Peer-configs targeting each peer's real-keyed PENDING epoch — the peer set
/// of a Role-B overlap Device. The pending endpoint is
/// [`own_tun_endpoint`] of the peer's advertised candidate: the same IP with
/// the UDP port at [`OWN_TUN_PORT_OFFSET`] above the candidate's own. A peer
/// with no real pending key (active-only, or a sentinel pending) contributes
/// nothing, and so does a peer whose candidate has no derivable own-tun
/// endpoint — see [`own_tun_endpoint`] for why that derivation is a shared
/// function rather than inline arithmetic here.
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
            // (Backlog item 23, the `keys[]` door) `pending_key()` only
            // screens the controller's `"awaiting-submission"` sentinel (see
            // its doc comment) — an advertised REAL pending pubkey that
            // fails to decode reaches here unfiltered. Checked here, not by
            // filtering `PeerState::keys` at ingestion, because
            // `rotation::decide_role_b` needs to tell "unusable pending key"
            // (`RoleBDecision::Unusable`) apart from "no pending key at all"
            // (`Skip`) using this SAME `pubkey_b64_to_hex` check — dropping
            // the entry earlier would collapse that distinction. This
            // builder has no such distinction to preserve: an unusable key
            // drops the peer from the overlap device exactly like a missing
            // one.
            crate::uapi::pubkey_b64_to_hex(&pending.pubkey_b64)?;
            // ONE definition, two readers (`own_tun_endpoint`): its `?` keeps
            // this builder's original drop-the-peer behaviour for a candidate
            // that does not parse or whose port cannot be offset.
            let pending_endpoint = own_tun_endpoint(p.primary_endpoint()?)?;
            Some(PeerConfig {
                public_key_b64: pending.pubkey_b64.clone(),
                endpoint: Some(pending_endpoint),
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

    /// Real WG-shaped key material (base64 of 32 bytes of 0xDD), decodable by
    /// `uapi::pubkey_b64_to_hex` — replaces this suite's old placeholder
    /// PENDING pubkey ("KP"), which `pending_peer_configs`'s backlog-item-23
    /// check now (correctly) rejects: an advertised pending epoch with an
    /// undecodable pubkey has nothing valid to build an overlap Device with,
    /// so the peer contributes nothing (see the check's doc comment above).
    /// These port/endpoint-derivation tests are about the PENDING epoch
    /// existing and being real-keyed, not about key content, so a valid key
    /// is a strictly more realistic fixture — the placeholder was fixture
    /// rot, not evidence the check belongs somewhere else.
    const VALID_PENDING_KEY: &str = "3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d0=";

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

    /// Parse the UDP port out of the single endpoint `pending_peer_configs`
    /// emitted, so a test can compare it against a port the ALLOCATOR produced
    /// rather than against a literal it copied from the same formula it is
    /// trying to check.
    fn dialled_port(cfgs: &[PeerConfig]) -> u16 {
        assert_eq!(cfgs.len(), 1, "expected exactly one pending peer config, got {cfgs:?}");
        let ep = cfgs[0].endpoint.as_deref().expect("a pending peer config carries an endpoint");
        ep.rsplit_once(':').expect("endpoint is ip:port").1.parse().expect("port is a u16")
    }

    /// **Epoch-independence by RESERVATION, not by epoch arithmetic.** The
    /// endpoint a peer dials this gateway's in-flight new epoch at is
    /// `candidate_port + OWN_TUN_PORT_OFFSET` — the same constant the allocator
    /// reserves — for every distance between the peer's active and pending
    /// epoch numbers.
    ///
    /// # Why a table, and why `pending == active + 1` is only one row of it
    ///
    /// The two tests this replaces (`pending_peer_configs_builds_offset_endpoint`
    /// and `pending_peer_configs_offset_survives_nonzero_active_epoch`) both used
    /// `pending == active + 1` — the *one* distance at which the deleted
    /// `active_port + (pending_epoch - active_epoch)` formula and
    /// `candidate_port + OWN_TUN_PORT_OFFSET` return the same number. They
    /// therefore agreed with both models at once, never discriminated between
    /// them, and would still pass today against an implementation with the
    /// epoch-delta formula restored. Worse, `k -> k+1` is precisely the
    /// coincidence that hid bug 5 ("the second rotation of any gateway cannot
    /// complete",
    /// `docs/research/port-authority-verification-the-shape-was-wrong.md`), so
    /// what they pinned was the bug's camouflage.
    ///
    /// Every row below whose distance is not 1 is RED against that
    /// implementation. Independence cannot be expressed by a single sample,
    /// which is the whole reason the old pair could not express it.
    #[test]
    fn pending_endpoint_is_the_reserved_offset_at_every_epoch_distance() {
        // (active epoch, pending epoch, candidate endpoint). Distances 1, 2, 6
        // and 7, from both a zero and a non-zero active epoch, and over two
        // different candidate ports so the answer is visibly derived from the
        // CANDIDATE rather than from a hard-coded base.
        let cases: [(u32, u32, &str); 5] = [
            // Distance 1 kept as ONE row of a discriminating family: it is real
            // coverage (rotation 0 -> 1 is the first rotation a fabric ever
            // does), it just cannot carry the property on its own.
            (0, 1, "10.9.0.2:51820"),
            (2, 3, "10.9.0.2:51822"),
            // The rows that kill the epoch-delta formula.
            (2, 4, "10.9.0.2:51820"),
            (3, 9, "10.9.0.3:40000"),
            (0, 7, "10.9.0.4:1024"),
        ];
        for (active_epoch, pending_epoch, candidate) in cases {
            let peer = peer_full(
                2,
                candidate,
                vec![
                    PeerKeyInfo {
                        epoch: active_epoch,
                        pubkey_b64: "KA".into(),
                        state: "active".into(),
                    },
                    PeerKeyInfo {
                        epoch: pending_epoch,
                        pubkey_b64: VALID_PENDING_KEY.into(),
                        state: "pending".into(),
                    },
                ],
                "10.10.2.0/24",
            );
            let ds = ds_with(vec![peer], 0);
            let cfgs = pending_peer_configs(&ds, 25);
            let candidate_port: u16 =
                candidate.rsplit_once(':').unwrap().1.parse().expect("test candidate port");
            assert_eq!(
                dialled_port(&cfgs),
                candidate_port + OWN_TUN_PORT_OFFSET,
                "active epoch {active_epoch} -> pending epoch {pending_epoch} on candidate \
                 {candidate}: the overlap must dial candidate_port + OWN_TUN_PORT_OFFSET \
                 ({}), NOT candidate_port + (pending - active) ({}). The two agree only at \
                 distance 1; anywhere else the deleted formula sends the overlap to a port \
                 the rotating gateway's new epoch is not on — bug 5.",
                candidate_port + OWN_TUN_PORT_OFFSET,
                candidate_port + (pending_epoch - active_epoch) as u16,
            );
            // Plumbing the old `..._builds_offset_endpoint` also covered, kept
            // here so deleting it costs nothing.
            assert_eq!(cfgs[0].public_key_b64, VALID_PENDING_KEY, "the overlap peers the PENDING key");
            assert_eq!(
                cfgs[0].endpoint.as_deref().unwrap().rsplit_once(':').unwrap().0,
                candidate.rsplit_once(':').unwrap().0,
                "the IP is the peer's advertised candidate IP, unmodified"
            );
            assert_eq!(cfgs[0].allowed_ips, vec!["10.10.2.0/24".to_string()]);
            assert_eq!(cfgs[0].keepalive_secs, 25);
        }
    }

    /// The strongest form of the same property: the epoch NUMBERS are not read
    /// at all. A roster whose pending epoch is *below* its active epoch is
    /// malformed, and the deleted formula's `checked_sub` silently dropped the
    /// peer — so this case cannot even be produced by the old implementation,
    /// let alone produced with the right port. The reservation has no opinion
    /// about epoch ordering because it never looks: the peer has a real pending
    /// key, so it gets an overlap, at the one port that key can be reachable on.
    #[test]
    fn pending_endpoint_does_not_read_the_epoch_numbers_at_all() {
        let peer = peer_full(
            6,
            "10.9.0.6:51820",
            vec![
                PeerKeyInfo { epoch: 9, pubkey_b64: "KA".into(), state: "active".into() },
                PeerKeyInfo { epoch: 4, pubkey_b64: VALID_PENDING_KEY.into(), state: "pending".into() },
            ],
            "10.10.6.0/24",
        );
        let ds = ds_with(vec![peer], 0);
        let cfgs = pending_peer_configs(&ds, 25);
        assert_eq!(
            dialled_port(&cfgs),
            51820 + OWN_TUN_PORT_OFFSET,
            "a descending epoch pair must still dial the reserved offset — the builder derives \
             the port from the candidate and a constant, so there is no subtraction left to \
             underflow and no peer to silently drop"
        );
        assert_eq!(cfgs[0].public_key_b64, VALID_PENDING_KEY);
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

    /// **The `?`-propagation pin, for the extraction of [`own_tun_endpoint`].**
    ///
    /// The endpoint derivation moved out of this builder so the Role-B collapse
    /// arm could read the SAME answer instead of restating it
    /// (`tests/collapse_dial.rs`). The tests above all pin what the builder
    /// EMITS; none pins what it does when the derivation has no answer, and that
    /// is precisely the behaviour an extraction can change without touching a
    /// single emitted string — from "drop the peer" to "emit it with a wrapped
    /// port" or "emit it with no endpoint at all". Either would put a peer on
    /// the overlap Device pointing at nothing.
    ///
    /// Port 65535 is not synthetic: `is_dialable_endpoint` accepts it, so the
    /// ingest filter KEEPS a `:65535` candidate (`state.rs`'s
    /// `partition_dialable_keeps_every_valid_candidate_verbatim_and_in_order`),
    /// and `65535 + OWN_TUN_PORT_OFFSET` does not fit in a u16. The malformed
    /// candidates alongside it are defense-in-depth for a future caller with a
    /// looser source.
    ///
    /// The multi-peer row is the same anti-truncation discipline
    /// `tests/role_b_decisions.rs` applies to the decision layer: one peer the
    /// derivation cannot answer for must not take out the peers around it —
    /// with `initiate_due_rotations` rotating every gateway off one timer, the
    /// first peer in roster order would otherwise starve all the rest.
    #[test]
    fn pending_peer_configs_drops_a_peer_whose_candidate_has_no_own_tun_endpoint() {
        let keys = || {
            vec![
                PeerKeyInfo { epoch: 0, pubkey_b64: "KA".into(), state: "active".into() },
                PeerKeyInfo {
                    epoch: 1,
                    pubkey_b64: VALID_PENDING_KEY.into(),
                    state: "pending".into(),
                },
            ]
        };

        for (candidate, why) in [
            ("10.9.0.2:65535", "65535 + OWN_TUN_PORT_OFFSET overflows a u16"),
            ("10.9.0.2", "no colon"),
            ("10.9.0.2:", "empty port"),
            ("10.9.0.2:abc", "non-numeric port"),
            ("", "empty candidate"),
        ] {
            let ds = ds_with(vec![peer_full(2, candidate, keys(), "10.10.2.0/24")], 0);
            assert!(
                pending_peer_configs(&ds, 25).is_empty(),
                "candidate {candidate:?} ({why}): the peer must be DROPPED from the overlap peer \
                 set. A peer emitted here with a wrapped port dials :0 — a wildcard that reaches \
                 nothing while the device reports a programmed endpoint — and one emitted with no \
                 endpoint sits on the overlap unable to dial at all."
            );
        }

        // And the drop is per-peer, not per-loop.
        let ds = ds_with(
            vec![
                peer_full(2, "10.9.0.2:65535", keys(), "10.10.2.0/24"),
                peer_full(3, "10.9.0.3:51820", keys(), "10.10.3.0/24"),
            ],
            0,
        );
        let cfgs = pending_peer_configs(&ds, 25);
        assert_eq!(cfgs.len(), 1, "peer 3 is well-formed and must survive peer 2, got {cfgs:?}");
        assert_eq!(
            cfgs[0].endpoint.as_deref(),
            Some(format!("10.9.0.3:{}", 51820 + OWN_TUN_PORT_OFFSET).as_str()),
            "the surviving peer keeps the reserved-offset endpoint — one unanswerable candidate \
             must not perturb the peers around it, let alone truncate the set"
        );
    }

    /// **The cross-module pin — the assertion that would have caught bug 5.**
    ///
    /// Bug 5 was never a wrong number in one place. It was two functions in two
    /// modules answering the same question — "which UDP port is a rotating
    /// gateway's in-flight new epoch on?" — with two different derivations that
    /// happened to agree on the first rotation. No test compared them, so
    /// nothing was red until the second rotation of a real gateway.
    ///
    /// This test asks both sides and compares the ANSWERS, so neither side can
    /// move without the other. The right-hand side is not a literal and not a
    /// restatement of the formula: it is whatever `tunnelset::plan_tunnel`
    /// actually hands the rotating gateway's own new-epoch tun, computed under
    /// realistic pressure — the gateway is already carrying three Role-B
    /// overlaps toward other peers, planned FIRST, which under the pre-piece-3
    /// shared free list is exactly what pushed the own tun off `base + 1`.
    ///
    /// The peer's active tun sits at `base_port` by piece 2's renormalization
    /// (the survivor returns to base at every retire), which is what makes the
    /// peer's advertised candidate port and the rotating gateway's base port the
    /// same number at every rotation and not just the first.
    #[test]
    fn the_port_a_peer_dials_is_the_port_the_allocator_reserves() {
        use crate::tunnelset::{plan_tunnel, TunnelId, TunnelPlan};
        const BASE_TUN: &str = "wg0";

        for base_port in [51820u16, 1024, 40000] {
            for (active_epoch, pending_epoch) in [(0u32, 1u32), (1, 2), (2, 4), (5, 11)] {
                // --- Side 1: the rotating gateway G allocates its new epoch. ---
                // G's active key is back on its base port (piece 2).
                let mut live = vec![TunnelPlan {
                    id: TunnelId::Own { epoch: active_epoch },
                    ifname: BASE_TUN.to_string(),
                    listen_port: base_port,
                }];
                // G is also Role-B for three other peers that are rotating too
                // (one global timer => the in-step fabric is the default case).
                // Planned BEFORE its own new tun, which is the ordering that
                // used to steal `base + 1`.
                for gid in [21u64, 22, 23] {
                    let id = TunnelId::Overlap { gateway_id: gid, epoch: pending_epoch };
                    let plan = plan_tunnel(id, BASE_TUN, base_port, &live)
                        .unwrap_or_else(|e| panic!("overlap toward {gid}: {e:#}"));
                    live.push(plan);
                }
                let own_id = TunnelId::Own { epoch: pending_epoch };
                let own = plan_tunnel(own_id, BASE_TUN, base_port, &live)
                    .unwrap_or_else(|e| panic!("G's own new epoch {pending_epoch}: {e:#}"));

                // --- Side 2: peer P decides where to dial G's new epoch. ---
                let peer = peer_full(
                    7,
                    &format!("10.9.0.7:{base_port}"),
                    vec![
                        PeerKeyInfo {
                            epoch: active_epoch,
                            pubkey_b64: "KA".into(),
                            state: "active".into(),
                        },
                        PeerKeyInfo {
                            epoch: pending_epoch,
                            pubkey_b64: VALID_PENDING_KEY.into(),
                            state: "pending".into(),
                        },
                    ],
                    "10.10.7.0/24",
                );
                let cfgs = pending_peer_configs(&ds_with(vec![peer], 0), 25);

                assert_eq!(
                    dialled_port(&cfgs),
                    own.listen_port,
                    "base {base_port}, epoch {active_epoch} -> {pending_epoch}: P dials port \
                     {} but G's new-epoch tun was allocated on {}. These are computed by two \
                     different functions in two different modules and MUST agree at every \
                     rotation; they agreed only at the first one before the own-tun port was \
                     reserved.",
                    dialled_port(&cfgs),
                    own.listen_port,
                );
            }
        }
    }

    /// The reservation itself, from the allocator's side — the half that makes
    /// the agreement above structural rather than lucky.
    ///
    /// An overlap must be **incapable** of standing on `base +
    /// OWN_TUN_PORT_OFFSET`, not merely unlikely to. As one shared free list it
    /// was ordinary: any peer that rotated before we did took `base + 1` first,
    /// and our own new epoch then landed somewhere no peer could compute. So the
    /// test drains the ENTIRE overlap free list and then demands the reserved
    /// port still be there for the own tun — maximum pressure, which is where a
    /// shared list fails on its very first allocation.
    #[test]
    fn the_reserved_own_port_is_never_handed_to_an_overlap() {
        use crate::tunnelset::{plan_tunnel, TunnelId, TunnelPlan};
        const BASE_TUN: &str = "wg0";
        const BASE_PORT: u16 = 51820;
        let reserved_port = BASE_PORT + OWN_TUN_PORT_OFFSET;

        let mut live = vec![TunnelPlan {
            id: TunnelId::Own { epoch: 3 },
            ifname: BASE_TUN.to_string(),
            listen_port: BASE_PORT,
        }];

        // Drain the overlap range dry. Its size is whatever the production
        // window is minus the one reserved slot, so this loop keeps going until
        // the allocator refuses rather than hard-coding a count.
        let mut allocated = 0usize;
        while let Ok(plan) = plan_tunnel(
            TunnelId::Overlap { gateway_id: 100 + allocated as u64, epoch: 4 },
            BASE_TUN,
            BASE_PORT,
            &live,
        ) {
            assert_ne!(
                plan.listen_port, reserved_port,
                "overlap #{allocated} was planned onto {reserved_port} = base + \
                 OWN_TUN_PORT_OFFSET. That is the ONLY port a rotating peer can compute for \
                 this gateway's new epoch (`pending_peer_configs`), so an overlap standing \
                 there makes the next rotation unreachable — bug 5, reintroduced."
            );
            live.push(plan);
            allocated += 1;
            assert!(allocated < 1000, "the overlap range must be bounded");
        }
        assert!(
            allocated > 0,
            "the overlap range must not be empty at a conventional base port"
        );

        // With every overlap port taken, the reserved one is still free —
        // because it was never in the free list to begin with.
        let own = plan_tunnel(TunnelId::Own { epoch: 4 }, BASE_TUN, BASE_PORT, &live)
            .expect("the own-epoch tun must still be plannable with the overlap range exhausted");
        assert_eq!(
            own.listen_port, reserved_port,
            "the own-epoch tun takes the RESERVED base + OWN_TUN_PORT_OFFSET, under any amount \
             of overlap pressure — {allocated} overlaps are live here"
        );
    }
}
