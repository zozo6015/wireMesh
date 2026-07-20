//! Desired state (from Sync) + fail-static persistence (spec §5.3). Persist on
//! every apply; on boot the data plane comes up from this before the controller
//! is reached.
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use wiremesh_proto::v1::{Delta, Peer, StateSnapshot};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PeerState {
    pub gateway_id: u64,
    pub segment_name: String,
    pub active_pubkey_b64: Option<String>,
    pub candidate_endpoint: Option<String>,
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
            candidate_endpoint: p.candidate_endpoints.first().cloned(),
            allowed_ips: p.allowed_ips.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct DesiredState {
    pub revision: u64,
    pub peers: Vec<PeerState>,
    pub policy_ir: Vec<u8>,
    pub policy_version: u64,
    pub relays: Vec<String>,
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
        // policy fields always reflect the latest delta
        self.policy_ir = d.policy_ir.clone();
        self.policy_version = d.policy_version;
        if !d.revoked_serials.is_empty() {
            self.revoked_serials = d.revoked_serials.clone();
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
        assert_eq!(ds.peers[0].candidate_endpoint.as_deref(), Some("203.0.113.2:51820"));
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
}
