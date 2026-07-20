//! Desired state (from Sync) + fail-static persistence (spec §5.3). Persist on
//! every apply; on boot the data plane comes up from this before the controller
//! is reached.
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use wiremesh_proto::v1::{Delta, Peer, RelayInfo, StateSnapshot};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerState {
    pub gateway_id: u64,
    pub segment_name: String,
    pub active_pubkey_b64: Option<String>,
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
        PeerState {
            gateway_id: p.gateway_id,
            segment_name: p.segment_name.clone(),
            active_pubkey_b64,
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
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct DesiredState {
    pub revision: u64,
    pub peers: Vec<PeerState>,
    pub policy_ir: Vec<u8>,
    pub policy_version: u64,
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
            relays: s.relays.clone(),
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
        if !d.relays.is_empty() {
            self.relays = d.relays.clone();
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

#[cfg(test)]
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
            relays: vec![],
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
    fn apply_delta_upserts_and_removes() {
        let mut ds = DesiredState::from_snapshot(&StateSnapshot {
            revision: 1, self_cert_pem: "C".into(),
            peers: vec![peer(2, "PUBA", "a:1"), peer(3, "PUBB", "b:2")],
            relays: vec![], policy_ir: vec![], policy_version: 0, revoked_serials: vec![],
        });
        let delta = Delta {
            revision: 2,
            upserted_peers: vec![peer(2, "PUBA2", "a:9")],
            removed_peer_ids: vec![3],
            relays: vec![], policy_ir: b"NEW".to_vec(), policy_version: 4, revoked_serials: vec![],
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
            relays: vec![],
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
            relays: vec![],
            policy_ir: b"NEW".to_vec(),
            policy_version: 6,
            revoked_serials: vec![],
        };
        ds.apply_delta(&delta);
        assert_eq!(ds.policy_ir, b"NEW");
        assert_eq!(ds.policy_version, 6);
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
            relays: vec![],
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
            relays: vec![],
            policy_ir: vec![],
            policy_version: 0,
            revoked_serials: vec!["B".into()],
        };
        ds.apply_delta(&delta2);
        assert_eq!(ds.revoked_serials, vec!["A".to_string(), "B".to_string()]);
    }
}
