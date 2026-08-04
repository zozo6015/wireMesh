//! Desired state (from Sync) + fail-static persistence (spec §5.3). Persist on
//! every apply; on boot the data plane comes up from this before the controller
//! is reached.
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use wiremesh_policy::PolicyIR;
use wiremesh_proto::v1::{Delta, Peer, RelayInfo, StateSnapshot};

/// One advertised key-epoch entry for a peer, as reported by the controller
/// (`Peer.keys` — key-rotation Task 2/7). A peer rotating its WireGuard key
/// advertises both its current `"active"` epoch and, once rotation begins, a
/// real-keyed `"pending"` epoch (or the controller's `"awaiting-submission"`
/// sentinel until the peer gateway has actually submitted a new pubkey).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerKeyInfo {
    pub epoch: u32,
    pub pubkey_b64: String,
    pub state: String, // "pending" | "active" | "retiring"
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerState {
    pub gateway_id: u64,
    pub segment_name: String,
    pub active_pubkey_b64: Option<String>,
    /// The peer's full advertised key set (all epochs/states), as reported by
    /// the controller (`Peer.keys`). `#[serde(default)]` keeps
    /// `DesiredState::load()` backward-compatible with a pre-Task-7
    /// `state.json` that predates this field.
    #[serde(default)]
    pub keys: Vec<PeerKeyInfo>,
    /// The peer's FULL candidate-endpoint list, as reported by the
    /// controller (`Peer.candidate_endpoints` — cycle4b §5/§6.1: the
    /// controller-observed address plus any locally-reported ones,
    /// deduplicated). Kept as a list (not collapsed to `.first()`) so a
    /// future NAT-traversal puncher (Task 10) can iterate every candidate
    /// rather than only ever trying the first.
    ///
    /// `#[serde(default)]` keeps `DesiredState::load()` backward-compatible:
    /// a pre-4b `state.json` (which had a singular `candidate_endpoint` key,
    /// now ignored as unknown) deserializes with an empty candidate list
    /// rather than failing the boot-from-persisted-state path — the next
    /// controller reconcile repopulates it.
    #[serde(default)]
    pub candidates: Vec<String>,
    pub allowed_ips: Vec<String>,
}

impl PeerState {
    fn from_proto(p: &Peer) -> PeerState {
        let active_pubkey_b64 = p
            .keys
            .iter()
            .find(|k| k.state == "active")
            .map(|k| k.pubkey.clone());
        let keys = p
            .keys
            .iter()
            .map(|k| PeerKeyInfo { epoch: k.epoch, pubkey_b64: k.pubkey.clone(), state: k.state.clone() })
            .collect();
        PeerState {
            gateway_id: p.gateway_id,
            segment_name: p.segment_name.clone(),
            active_pubkey_b64,
            keys,
            candidates: p.candidate_endpoints.clone(),
            allowed_ips: p.allowed_ips.clone(),
        }
    }

    /// The endpoint to hand WireGuard as `endpoint=` right now: the
    /// punch-confirmed candidate if one exists, else the first candidate in
    /// the reported list (bootstrap). There is no punch-confirmation wired
    /// yet (that's Task 10's job), so today this is always just the first
    /// candidate — the list is retained precisely so that wiring has
    /// something to iterate over once it lands.
    pub fn primary_endpoint(&self) -> Option<&String> {
        self.candidates.first()
    }

    /// The peer's current active key-epoch entry, if advertised.
    pub fn active_key(&self) -> Option<&PeerKeyInfo> {
        self.keys.iter().find(|k| k.state == "active")
    }

    /// A real-keyed pending epoch: `state == "pending"` AND the pubkey isn't
    /// the controller's `"awaiting-submission"` sentinel (key-rotation Task
    /// 2) — a pending entry still bearing it has no real WG pubkey yet.
    pub fn pending_key(&self) -> Option<&PeerKeyInfo> {
        self.keys
            .iter()
            .find(|k| k.state == "pending" && k.pubkey_b64 != "awaiting-submission")
    }
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct DesiredState {
    pub revision: u64,
    pub peers: Vec<PeerState>,
    pub policy_ir: Vec<u8>,
    pub policy_version: u64,
    /// (4c review fix) `#[serde(default)]` so a `state.json` written before
    /// this field existed — or one written by a version of this binary that
    /// last saw an empty relay set — still deserializes cleanly on boot
    /// (fail-static: booting from stale/older persisted state must never
    /// fail just because a newer field is missing from the JSON).
    #[serde(default)]
    pub relays: Vec<RelayInfo>,
    pub revoked_serials: Vec<String>,
}

impl DesiredState {
    pub fn from_snapshot(s: &StateSnapshot) -> DesiredState {
        DesiredState {
            revision: s.revision,
            peers: s.peers.iter().map(PeerState::from_proto).collect(),
            policy_ir: s.policy_ir.clone(),
            policy_version: s.policy_version,
            // (4c review fix) Sourced from the proto's `relay_infos` (field
            // 8) — the structured relay data moved there rather than
            // repurposing `deprecated_relays` (field 4, kept at its
            // original `repeated string` type; see `sync.proto`). This
            // domain field keeps its own name (`DesiredState.relays`).
            relays: s.relay_infos.clone(),
            revoked_serials: s.revoked_serials.clone(),
        }
    }

    pub fn apply_delta(&mut self, d: &Delta) {
        self.revision = d.revision;
        for p in &d.upserted_peers {
            let ps = PeerState::from_proto(p);
            match self.peers.iter_mut().find(|x| x.gateway_id == ps.gateway_id) {
                Some(existing) => *existing = ps,
                None => self.peers.push(ps),
            }
        }
        self.peers.retain(|p| !d.removed_peer_ids.contains(&p.gateway_id));
        // Replace whenever the delta signals a relay update — including
        // clearing to empty (last-relay eviction). A sparse (non-relay)
        // delta has `relays_updated: false` and must leave `self.relays`
        // untouched; see `Delta.relays_updated`'s doc comment in
        // `sync.proto` and `projection::delta_for_change`.
        if d.relays_updated {
            self.relays = d.relay_infos.clone();
        }
        // Deltas are sparse: only PolicyUpdated carries policy fields (version >= 1);
        // every other change type sends policy_version=0 / empty IR. Guard so a
        // non-policy delta (e.g. EndpointObserved about a peer) does NOT wipe the
        // applied policy. Verified against controller projection::delta_for_change.
        if d.policy_version != 0 {
            self.policy_ir = d.policy_ir.clone();
            self.policy_version = d.policy_version;
        }
        // revoked_serials in a delta is additive (CertRevoked -> the single new
        // serial), not a full replacement; union into the existing set.
        for s in &d.revoked_serials {
            if !self.revoked_serials.contains(s) {
                self.revoked_serials.push(s.clone());
            }
        }
    }

    pub fn save(&self, state_dir: &Path) -> anyhow::Result<()> {
        fs::create_dir_all(state_dir)?;
        let tmp = state_dir.join("state.json.tmp");
        let final_path = state_dir.join("state.json");
        {
            use std::io::Write;
            let mut f = fs::OpenOptions::new()
                .write(true).create(true).truncate(true).mode(0o600)
                .open(&tmp).context("opening state.json.tmp")?;
            f.write_all(&serde_json::to_vec_pretty(self)?)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &final_path).context("atomically renaming state.json")?;
        // Fsync the containing directory too: on most POSIX filesystems the
        // rename's directory-entry update is not itself durable until the
        // directory inode is fsynced, so a crash right after `rename` could
        // otherwise leave the rename un-persisted despite the file's own
        // content already being synced above.
        fs::File::open(state_dir)
            .and_then(|d| d.sync_all())
            .context("fsyncing state_dir after rename")?;
        Ok(())
    }

    pub fn load(state_dir: &Path) -> anyhow::Result<Option<DesiredState>> {
        let path = state_dir.join("state.json");
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes).context("parsing state.json")?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).context("reading state.json"),
        }
    }
}

/// Is `policy_ir` something THIS build can actually install?
///
/// [`crate::enforce::GatewayEnforcer::apply_if_changed`] is its only
/// production consumer, and it funnels every non-empty `policy_ir` through
/// [`PolicyIR::from_json`], which rejects any `schema` other than 1. An IR
/// that fails there can never be installed by this binary — not on this
/// boot, and not on any future one.
///
/// **Cost, because this runs on every Sync `State` event:** an emptiness
/// test and a 12-byte prefix compare. [`PolicyIR::to_canonical_json`] is
/// plain `serde_json::to_string` over a struct whose first field is
/// `schema` — canonical *by construction*, an invariant `wiremesh-policy`'s
/// `ir.rs` documents and explicitly forbids changing — so every well-formed
/// schema-1 IR begins `{"schema":1,`. The full decode below is reached only
/// by an IR that does NOT look like one, i.e. precisely the broken case (or
/// a hypothetical future change to the canonical form, where it keeps this
/// correct rather than fast). It is never a second decode of a healthy IR
/// on the steady-state path.
pub fn policy_ir_is_decodable(policy_ir: &[u8]) -> bool {
    // "No policy yet" — `apply_if_changed` synthesizes an empty schema-1 IR
    // for this, so there is nothing undecodable to persist.
    if policy_ir.is_empty() {
        return true;
    }
    if policy_ir.starts_with(br#"{"schema":1,"#) {
        return true;
    }
    PolicyIR::from_json(policy_ir).is_ok()
}

/// Persists [`DesiredState`] for fail-static boot, never writing a
/// `policy_ir` this build cannot decode.
///
/// # Why this exists
///
/// The enforcer apply used to run INLINE in the Sync loop, and its `?` fired
/// BEFORE the save — so a snapshot carrying an IR the gateway could not
/// decode killed the process and never reached disk. Backlog item 1 moved
/// that apply into an off-loop worker, which makes the save unconditional.
/// Without this type, a schema-2 (or malformed) `policy_ir` would be
/// persisted and then replayed through the same failing worker on every
/// subsequent fail-static boot: the failure would outlive reboots and
/// outlive a controller rollback, and on a gateway with no prior good policy
/// it would come up with nothing installed — default-deny, so fail-closed,
/// but durable and much quieter than the crash it replaced.
///
/// # What it writes instead
///
/// The peer/device half of the snapshot is persisted EXACTLY as before —
/// fail-static's job is unchanged and a newly enrolled peer must still reach
/// disk. Only the `(policy_version, policy_ir)` pair is substituted, with
/// the newest pair this build could decode, so a boot from this file comes
/// up enforcing the last policy the gateway actually understood. That is
/// what fail-static means. A gateway that has never seen a decodable pair
/// falls back to the "no policy yet" pair (`0` / empty), which
/// `apply_if_changed` turns into an empty schema-1 IR: the same default-deny
/// the datapath already has, reported as `applied_version = 0` — which reads
/// as "no policy" rather than as a version that was never installed.
///
/// # Why substituting the pair desynchronizes nothing
///
/// `revision` and `policy_version` are already independent by design, not by
/// accident. Every sparse (non-policy) delta advances `revision` and leaves
/// the policy pair untouched — see [`DesiredState::apply_delta`]'s
/// `policy_version != 0` guard — so a persisted state whose revision is
/// newer than its policy is the routine shape any `EndpointObserved` delta
/// produces, not a new one invented here. `policy_ir` and `policy_version`
/// are substituted together, so they always describe each other.
#[derive(Debug, Default)]
pub struct FailStaticWriter {
    /// Newest `(policy_version, policy_ir)` this build could decode.
    last_good: Option<(u64, Vec<u8>)>,
    /// `policy_version` of the last undecodable IR warned about, so peer
    /// churn under a broken controller does not re-log once per event.
    warned: Option<u64>,
}

impl FailStaticWriter {
    /// Seed from the state loaded at boot, so the first substitution after a
    /// restart still has a good policy to fall back on rather than dropping
    /// to the empty pair. A `state.json` written by a pre-fix binary can
    /// itself carry an undecodable IR; that seeds `None` — and its own boot
    /// install fails loudly, which is correct.
    pub fn seeded_from(persisted: Option<&DesiredState>) -> FailStaticWriter {
        let last_good = persisted
            .filter(|ds| policy_ir_is_decodable(&ds.policy_ir))
            .map(|ds| (ds.policy_version, ds.policy_ir.clone()));
        FailStaticWriter { last_good, warned: None }
    }

    /// Persist `ds`, substituting its policy pair if the IR is undecodable.
    pub fn save(&mut self, ds: &DesiredState, state_dir: &Path) -> anyhow::Result<()> {
        if policy_ir_is_decodable(&ds.policy_ir) {
            // Remember the pair only when the version actually moves: the
            // clone is the IR itself, and `State` events (peer churn,
            // endpoint observations, reconnect snapshots) are far more
            // frequent than policy updates.
            if self.last_good.as_ref().map(|(v, _)| *v) != Some(ds.policy_version) {
                self.last_good = Some((ds.policy_version, ds.policy_ir.clone()));
            }
            self.warned = None;
            return ds.save(state_dir);
        }

        let mut sanitized = ds.clone();
        let kept = match &self.last_good {
            Some((v, ir)) => {
                sanitized.policy_version = *v;
                sanitized.policy_ir = ir.clone();
                Some(*v)
            }
            None => {
                sanitized.policy_version = 0;
                sanitized.policy_ir = Vec::new();
                None
            }
        };
        if self.warned != Some(ds.policy_version) {
            self.warned = Some(ds.policy_version);
            match kept {
                Some(v) => eprintln!(
                    "wiremesh-gateway: CRITICAL: the controller sent policy version {} in an IR \
                     format this build cannot decode (only schema 1 is supported — is the \
                     controller newer than this gateway?). The datapath keeps the last policy \
                     it understood and state.json is being written with THAT policy (version \
                     {v}) instead, so a restart does not inherit an uninstallable one. Peers \
                     and routes are persisted normally. Upgrade this gateway.",
                    ds.policy_version
                ),
                None => eprintln!(
                    "wiremesh-gateway: CRITICAL: the controller sent policy version {} in an IR \
                     format this build cannot decode (only schema 1 is supported — is the \
                     controller newer than this gateway?), and this gateway has never installed \
                     a policy it could read. NO policy is live: every tun is default-denying and \
                     ALL fabric traffic is being dropped. state.json is being written with no \
                     policy rather than an uninstallable one. Upgrade this gateway.",
                    ds.policy_version
                ),
            }
        }
        sanitized.save(state_dir)
    }
}

#[cfg(test)]
#[allow(deprecated)] // constructing StateSnapshot/Delta requires setting deprecated_relays (field 4)
mod tests {
    use super::*;
    use wiremesh_proto::v1::{Delta, Peer, PeerKey, StateSnapshot};

    fn peer(id: u64, pubkey: &str, ep: &str) -> Peer {
        Peer {
            gateway_id: id,
            segment_name: format!("seg{id}"),
            keys: vec![
                PeerKey { epoch: 1, pubkey: "OLD".into(), state: "retiring".into() },
                PeerKey { epoch: 2, pubkey: pubkey.into(), state: "active".into() },
            ],
            candidate_endpoints: vec![ep.into()],
            allowed_ips: vec![format!("10.10.{id}.0/24")],
        }
    }

    #[test]
    fn from_snapshot_picks_active_key_and_endpoint() {
        let snap = StateSnapshot {
            revision: 5,
            self_cert_pem: "C".into(),
            peers: vec![peer(2, "PUBA", "203.0.113.2:51820")],
            deprecated_relays: vec![],
            relay_infos: vec![],
            policy_ir: b"{\"schema\":1}".to_vec(),
            policy_version: 3,
            revoked_serials: vec![],
        };
        let ds = DesiredState::from_snapshot(&snap);
        assert_eq!(ds.revision, 5);
        assert_eq!(ds.policy_version, 3);
        assert_eq!(ds.peers.len(), 1);
        assert_eq!(ds.peers[0].active_pubkey_b64.as_deref(), Some("PUBA"));
        assert_eq!(ds.peers[0].candidates, vec!["203.0.113.2:51820".to_string()]);
        assert_eq!(ds.peers[0].primary_endpoint().map(String::as_str), Some("203.0.113.2:51820"));
    }

    #[test]
    fn from_proto_keeps_all_candidates_primary_is_first() {
        let p = Peer {
            gateway_id: 9,
            segment_name: "seg9".into(),
            keys: vec![PeerKey { epoch: 1, pubkey: "PUB9".into(), state: "active".into() }],
            candidate_endpoints: vec![
                "198.51.100.9:51820".into(),
                "10.0.0.9:51820".into(),
                "203.0.113.9:51820".into(),
            ],
            allowed_ips: vec!["10.10.9.0/24".into()],
        };
        let ps = PeerState::from_proto(&p);
        assert_eq!(
            ps.candidates,
            vec![
                "198.51.100.9:51820".to_string(),
                "10.0.0.9:51820".to_string(),
                "203.0.113.9:51820".to_string(),
            ],
            "from_proto must keep the FULL candidate list, not just .first()"
        );
        assert_eq!(ps.primary_endpoint().map(String::as_str), Some("198.51.100.9:51820"));
    }

    #[test]
    fn from_proto_retains_full_key_set() {
        let p = Peer {
            gateway_id: 11,
            segment_name: "seg11".into(),
            keys: vec![
                PeerKey { epoch: 0, pubkey: "KA".into(), state: "active".into() },
                PeerKey { epoch: 1, pubkey: "KP".into(), state: "pending".into() },
            ],
            candidate_endpoints: vec!["203.0.113.11:51820".into()],
            allowed_ips: vec!["10.10.11.0/24".into()],
        };
        let ps = PeerState::from_proto(&p);
        assert_eq!(ps.keys.len(), 2);
        let active = ps.active_key().expect("active key present");
        assert_eq!(active.epoch, 0);
        assert_eq!(active.pubkey_b64, "KA");
        let pending = ps.pending_key().expect("pending key present");
        assert_eq!(pending.epoch, 1);
        assert_eq!(pending.pubkey_b64, "KP");
    }

    #[test]
    fn pending_key_ignores_sentinel() {
        let p = Peer {
            gateway_id: 12,
            segment_name: "seg12".into(),
            keys: vec![
                PeerKey { epoch: 0, pubkey: "KA".into(), state: "active".into() },
                PeerKey { epoch: 1, pubkey: "awaiting-submission".into(), state: "pending".into() },
            ],
            candidate_endpoints: vec!["203.0.113.12:51820".into()],
            allowed_ips: vec!["10.10.12.0/24".into()],
        };
        let ps = PeerState::from_proto(&p);
        assert!(ps.pending_key().is_none(), "sentinel pending key must not be reported as a real pending key");
        let active = ps.active_key().expect("active key still present");
        assert_eq!(active.pubkey_b64, "KA");
    }

    #[test]
    fn active_pubkey_b64_still_populated() {
        let p = Peer {
            gateway_id: 13,
            segment_name: "seg13".into(),
            keys: vec![
                PeerKey { epoch: 0, pubkey: "KA".into(), state: "active".into() },
                PeerKey { epoch: 1, pubkey: "KP".into(), state: "pending".into() },
            ],
            candidate_endpoints: vec!["203.0.113.13:51820".into()],
            allowed_ips: vec!["10.10.13.0/24".into()],
        };
        let ps = PeerState::from_proto(&p);
        assert_eq!(ps.active_pubkey_b64.as_deref(), Some("KA"));
        assert_eq!(ps.active_key().map(|k| k.pubkey_b64.as_str()), Some("KA"));
    }

    #[test]
    fn apply_delta_upserts_and_removes() {
        let mut ds = DesiredState::from_snapshot(&StateSnapshot {
            revision: 1, self_cert_pem: "C".into(),
            peers: vec![peer(2, "PUBA", "a:1"), peer(3, "PUBB", "b:2")],
            deprecated_relays: vec![], relay_infos: vec![], policy_ir: vec![], policy_version: 0, revoked_serials: vec![],
        });
        let delta = Delta {
            revision: 2,
            upserted_peers: vec![peer(2, "PUBA2", "a:9")],
            removed_peer_ids: vec![3],
            deprecated_relays: vec![], relay_infos: vec![], relays_updated: false, policy_ir: b"NEW".to_vec(), policy_version: 4, revoked_serials: vec![],
        };
        ds.apply_delta(&delta);
        assert_eq!(ds.revision, 2);
        assert_eq!(ds.peers.len(), 1);
        assert_eq!(ds.peers[0].gateway_id, 2);
        assert_eq!(ds.peers[0].active_pubkey_b64.as_deref(), Some("PUBA2"));
        assert_eq!(ds.policy_version, 4);
        assert_eq!(ds.policy_ir, b"NEW");
    }

    #[test]
    fn save_load_round_trip_atomic_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let ds = DesiredState { revision: 9, ..Default::default() };
        ds.save(dir.path()).unwrap();
        let meta = std::fs::metadata(dir.path().join("state.json")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let back = DesiredState::load(dir.path()).unwrap().unwrap();
        assert_eq!(back.revision, 9);
    }

    #[test]
    fn load_absent_is_none() {
        let dir = tempfile::tempdir().unwrap();
        assert!(DesiredState::load(dir.path()).unwrap().is_none());
    }

    #[test]
    fn sparse_delta_does_not_wipe_policy() {
        let mut ds = DesiredState {
            revision: 1,
            peers: vec![],
            policy_ir: b"IRDATA".to_vec(),
            policy_version: 5,
            relays: vec![],
            revoked_serials: vec![],
        };
        // Mimics an EndpointObserved delta: carries a peer upsert but no
        // policy fields (sparse delta per controller projection).
        let delta = Delta {
            revision: 2,
            upserted_peers: vec![peer(7, "PUBX", "c:3")],
            removed_peer_ids: vec![],
            deprecated_relays: vec![],
            relay_infos: vec![],
            relays_updated: false,
            policy_ir: vec![],
            policy_version: 0,
            revoked_serials: vec![],
        };
        ds.apply_delta(&delta);
        assert_eq!(ds.policy_ir, b"IRDATA");
        assert_eq!(ds.policy_version, 5);
    }

    #[test]
    fn policy_update_delta_applies() {
        let mut ds = DesiredState::default();
        let delta = Delta {
            revision: 2,
            upserted_peers: vec![],
            removed_peer_ids: vec![],
            deprecated_relays: vec![],
            relay_infos: vec![],
            relays_updated: false,
            policy_ir: b"NEW".to_vec(),
            policy_version: 6,
            revoked_serials: vec![],
        };
        ds.apply_delta(&delta);
        assert_eq!(ds.policy_ir, b"NEW");
        assert_eq!(ds.policy_version, 6);
    }

    #[test]
    fn apply_delta_relays_updated_true_replaces_relays() {
        let mut ds = DesiredState {
            relays: vec![RelayInfo { relay_id: 1, endpoint: "9.9.9.9:1".into() }],
            ..Default::default()
        };
        let delta = Delta {
            revision: 2,
            upserted_peers: vec![],
            removed_peer_ids: vec![],
            deprecated_relays: vec![],
            relay_infos: vec![RelayInfo { relay_id: 7, endpoint: "1.2.3.4:4443".into() }],
            relays_updated: true,
            policy_ir: vec![],
            policy_version: 0,
            revoked_serials: vec![],
        };
        ds.apply_delta(&delta);
        assert_eq!(
            ds.relays,
            vec![RelayInfo { relay_id: 7, endpoint: "1.2.3.4:4443".into() }]
        );
    }

    #[test]
    fn apply_delta_relays_updated_true_and_empty_clears_relays() {
        // Starting state HAS a relay: this is the last-relay-eviction case the
        // fix enables. The old `if !d.relay_infos.is_empty()` guard could
        // never clear `self.relays` to empty — this test would fail under it.
        let mut ds = DesiredState {
            relays: vec![RelayInfo { relay_id: 3, endpoint: "5.6.7.8:4443".into() }],
            ..Default::default()
        };
        let delta = Delta {
            revision: 2,
            upserted_peers: vec![],
            removed_peer_ids: vec![],
            deprecated_relays: vec![],
            relay_infos: vec![],
            relays_updated: true,
            policy_ir: vec![],
            policy_version: 0,
            revoked_serials: vec![],
        };
        ds.apply_delta(&delta);
        assert_eq!(ds.relays, Vec::<RelayInfo>::new());
    }

    #[test]
    fn apply_delta_relays_updated_false_leaves_relays_unchanged() {
        // A sparse, non-relay delta (relays_updated: false, empty relay_infos)
        // must not wipe an existing relay set — the reason the old guard
        // existed in the first place.
        let mut ds = DesiredState {
            relays: vec![RelayInfo { relay_id: 4, endpoint: "2.2.2.2:4443".into() }],
            ..Default::default()
        };
        let delta = Delta {
            revision: 2,
            upserted_peers: vec![peer(7, "PUBX", "c:3")],
            removed_peer_ids: vec![],
            deprecated_relays: vec![],
            relay_infos: vec![],
            relays_updated: false,
            policy_ir: vec![],
            policy_version: 0,
            revoked_serials: vec![],
        };
        ds.apply_delta(&delta);
        assert_eq!(
            ds.relays,
            vec![RelayInfo { relay_id: 4, endpoint: "2.2.2.2:4443".into() }]
        );
    }

    #[test]
    fn cert_revoked_delta_unions_serials() {
        let mut ds = DesiredState {
            revoked_serials: vec!["A".into()],
            ..Default::default()
        };
        let delta = Delta {
            revision: 2,
            upserted_peers: vec![],
            removed_peer_ids: vec![],
            deprecated_relays: vec![],
            relay_infos: vec![],
            relays_updated: false,
            policy_ir: vec![],
            policy_version: 0,
            revoked_serials: vec!["B".into()],
        };
        ds.apply_delta(&delta);
        assert_eq!(ds.revoked_serials, vec!["A".to_string(), "B".to_string()]);

        let delta2 = Delta {
            revision: 3,
            upserted_peers: vec![],
            removed_peer_ids: vec![],
            deprecated_relays: vec![],
            relay_infos: vec![],
            relays_updated: false,
            policy_ir: vec![],
            policy_version: 0,
            revoked_serials: vec!["B".into()],
        };
        ds.apply_delta(&delta2);
        assert_eq!(ds.revoked_serials, vec!["A".to_string(), "B".to_string()]);
    }
}
