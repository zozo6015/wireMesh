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
    /// The peer's current active-epoch WireGuard public key, derived from
    /// `keys` (the entry with `state == "active"`).
    ///
    /// **INVARIANT (backlog item 23): `Some` only for a key
    /// [`uapi::pubkey_b64_to_hex`] can decode.** Unlike `allowed_ips` below,
    /// an undecodable active key is PEER-fatal, not per-entry-fatal:
    /// `PeerConfig.public_key_b64` is a `String`, not an `Option`, so there
    /// is no "keyless" WG peer block to emit — filtering to `None` here
    /// reuses the pre-existing "no active key" drop
    /// (`reconcile::peer_configs`'s `p.active_pubkey_b64.clone()?`, pinned
    /// by `peer_configs_skip_peers_without_active_key`) instead of adding a
    /// second one. Enforced at the same two doors as `candidates`/
    /// `allowed_ips`: [`PeerState::from_proto`] for anything the controller
    /// advertises, and `deserialize_with` for anything read back off disk.
    #[serde(default, deserialize_with = "deserialize_valid_active_pubkey")]
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
    ///
    /// **INVARIANT (backlog item 1): every entry is
    /// [`uapi::is_dialable_endpoint`].** An entry that is not kills the
    /// gateway PROCESS — `primary_endpoint()` feeds it to the UAPI as
    /// `endpoint=`, `uapi::encode_set`'s `Err` unwinds out of `apply_state`
    /// past both loops in `run()` and exits from `main`'s `block_on`. It is
    /// enforced at BOTH doors into this field:
    /// [`PeerState::from_proto`] for anything the controller advertises, and
    /// `deserialize_with` for anything read back off disk. The
    /// `deserialize_with` is the load-bearing half and it lives HERE, on the
    /// field, rather than as a pass inside `DesiredState::load`: `load` is a
    /// bare `serde_json::from_slice`, so the field's own `Deserialize` is
    /// the only place that covers every present and future deserialization
    /// route by construction. A `state.json` carrying a bad candidate is the
    /// case that turns one bad apply into a gateway that cannot BOOT, with
    /// the controller not even in the loop — fail-static inverted into the
    /// reason the gateway stays down.
    ///
    /// **(Backlog G3) The list is also BOUNDED — at most
    /// [`MAX_PEER_CANDIDATES`] entries**, enforced at those same two doors.
    /// The invariant above keeps a hostile advertisement from killing the
    /// process; the bound keeps it from growing this struct, and `state.json`
    /// with it, without limit instead.
    #[serde(default, deserialize_with = "deserialize_dialable_candidates")]
    pub candidates: Vec<String>,
    /// The peer's advertised route set (`Peer.allowed_ips`), as reported by
    /// the controller.
    ///
    /// **INVARIANT (backlog item 24): every entry is
    /// [`uapi::is_valid_ipv4_cidr`].** Unlike `active_pubkey_b64` above, an
    /// invalid entry costs only itself, not the whole peer: a peer with zero
    /// usable routes is still a legal, dialable WireGuard peer
    /// (`replace_allowed_ips=true` with no `allowed_ip=` lines), so
    /// filtering is per-ENTRY here — the same shape as `candidates`, not the
    /// peer-fatal shape of `active_pubkey_b64`. Enforced at the same two
    /// doors: [`PeerState::from_proto`] and a field `deserialize_with` for
    /// `state.json` (the latter is load-bearing for the same reason as
    /// `candidates`' — `DesiredState::load` is a bare
    /// `serde_json::from_slice`, and until this fix the field carried no
    /// serde attribute at all).
    #[serde(deserialize_with = "deserialize_valid_cidrs")]
    pub allowed_ips: Vec<String>,
}

/// (Backlog G3) The most candidate endpoints this gateway will keep for one
/// peer, from either door.
///
/// **Why a cap exists at all.** Without one, everything a controller says
/// about a peer is retained verbatim: it grows [`PeerState::candidates`], is
/// written back out to `state.json` on every apply, and is re-parsed on every
/// boot — per peer, forever. `Peer.candidate_endpoints` is an unconstrained
/// `repeated string` on a stream this gateway does not size-limit, so a
/// hostile or buggy control plane picks that number, not us. The rule this
/// file already states for correctness ("a gateway must survive a control
/// plane that does not [filter]") has to hold for VOLUME too, or the filter
/// just moves the damage from a crash into unbounded memory and disk.
///
/// **Why 64.** It is derived from what an HONEST controller can advertise,
/// not guessed. `Db::candidates_for` builds one peer's list as the gateway's
/// single UDP-observed `gateway.candidate_endpoint` slot (0 or 1 entry) plus
/// its deduplicated `source = 'local'` rows, which `Sync.Report` ingest caps
/// at `services::sync::MAX_LOCAL_CANDIDATES = 32`. The true ceiling is
/// therefore 1 + 32 = 33 — and because [`partition_dialable`]'s cap check
/// (`kept.len() == MAX_PEER_CANDIDATES`) fires BEFORE the push, a cap set to
/// exactly 33 would still keep a 33-entry honest advertisement whole;
/// equality never drops anything. Only a cap set strictly BELOW 33 would
/// truncate one. 64 is chosen well clear of that ceiling anyway, so the cap
/// never sits exactly on the honest limit and there's room for the
/// controller's cap to be raised (to anything through 63) before an honest
/// advertisement would ever be truncated here — while still bounding what one
/// peer costs us.
pub(crate) const MAX_PEER_CANDIDATES: usize = 64;

/// How many dropped endpoints are quoted in the filter's log line, and how
/// many bytes of each — the same bounds, for the same reason, as the
/// controller's `services::sync::REJECTED_SAMPLE_{COUNT,BYTES}`. The
/// offending strings are chosen by whoever is misbehaving and can be
/// megabytes long and arbitrarily numerous; quoting them all would relocate
/// the flood into this gateway's stderr instead of preventing it.
const DROPPED_SAMPLE_COUNT: usize = 3;
const DROPPED_SAMPLE_BYTES: usize = 64;

/// Outcome of one filtering pass over a peer's advertised candidates.
///
/// Split out from the logging so the decisions are testable: `eprintln!`
/// output is not captured by `cargo test`, so a filter that both decided and
/// reported inline could only ever be asserted on through what it returned —
/// which is exactly how an unbounded log survives in a green suite.
pub(crate) struct CandidateFilter {
    /// The entries kept, in advertised order, capped at
    /// [`MAX_PEER_CANDIDATES`].
    pub(crate) kept: Vec<String>,
    /// How many entries failed [`uapi::is_dialable_endpoint`].
    pub(crate) dropped: usize,
    /// How many otherwise-usable entries were discarded for exceeding
    /// [`MAX_PEER_CANDIDATES`]. Counted separately from `dropped` because it
    /// says something entirely different to an operator: those entries were
    /// well-formed, and the fabric may genuinely be over the cap.
    pub(crate) over_cap: usize,
    /// Up to [`DROPPED_SAMPLE_COUNT`] of the undialable entries, each
    /// truncated to [`DROPPED_SAMPLE_BYTES`] on a char boundary and already
    /// `{:?}`-quoted.
    pub(crate) samples: Vec<String>,
}

/// Partition a peer's advertised candidates into what this build can write to
/// the WireGuard UAPI and what it cannot, applying [`MAX_PEER_CANDIDATES`]
/// and collecting bounded samples of the rejects. Pure — no I/O, no logging.
///
/// The predicate is [`uapi::is_dialable_endpoint`] — the encoder's own accept
/// test, not a second opinion about it. Dropping is per-ENTRY and never drops
/// the peer: a peer with no usable candidate keeps its `allowed_ips` (and
/// therefore its segment routes) and simply gets no `endpoint=` line, which
/// is a legal, encodable WireGuard peer that recovers the moment a real
/// candidate is advertised.
///
/// Deliberately does NOT deduplicate: the controller dedups on ingest
/// (`usable_local_candidates`) and again in `Db::candidates_for`, and adding
/// a third opinion here would silently reorder/reshape what a well-behaved
/// control plane asked for. The cap alone is what bounds a misbehaving one.
pub(crate) fn partition_dialable(candidates: Vec<String>) -> CandidateFilter {
    let mut f = CandidateFilter {
        kept: Vec::new(),
        dropped: 0,
        over_cap: 0,
        samples: Vec::new(),
    };

    for c in candidates {
        if !crate::uapi::is_dialable_endpoint(&c) {
            f.dropped += 1;
            if f.samples.len() < DROPPED_SAMPLE_COUNT {
                // Back off to a char boundary before slicing: the string is
                // attacker-chosen and may be multi-byte UTF-8, where a blind
                // `&c[..64]` panics — inside a serde `deserialize_with`, that
                // is a boot-time crash caused by the very defense meant to
                // prevent one.
                let mut end = DROPPED_SAMPLE_BYTES.min(c.len());
                while end > 0 && !c.is_char_boundary(end) {
                    end -= 1;
                }
                // `{:?}` deliberately: an endpoint carrying a newline is a
                // UAPI line-injection payload, and it must not be able to
                // inject lines into this log either.
                f.samples.push(format!("{:?}", &c[..end]));
            }
            continue;
        }
        if f.kept.len() == MAX_PEER_CANDIDATES {
            f.over_cap += 1;
            continue;
        }
        f.kept.push(c);
    }

    f
}

/// Render one warning line for a filtering pass, or `None` when it dropped
/// nothing. ONE line per pass (per peer, per advertisement) rather than one
/// per entry: the count is what an operator needs, and a per-entry line hands
/// the volume of this gateway's stderr to whoever is sending the junk.
///
/// `source` names the door the candidates came through, since the two have
/// very different meanings: a controller advertisement means a peer (or the
/// control plane) is compromised or version-skewed, while a `state.json`
/// entry means this gateway persisted one before this filter existed.
pub(crate) fn format_drop_warning(f: &CandidateFilter, source: &str) -> Option<String> {
    if f.dropped == 0 && f.over_cap == 0 {
        return None;
    }

    let mut msg = format!(
        "wiremesh-gateway: filtering peer candidate endpoints from {source} — kept {}",
        f.kept.len()
    );
    if f.dropped > 0 {
        msg.push_str(&format!(
            ", DROPPED {} that are not an IPv4 ip:port (writing one to the WireGuard UAPI \
             would fail the whole device apply and terminate this process); first {}: {}",
            f.dropped,
            f.samples.len(),
            f.samples.join(", ")
        ));
    }
    if f.over_cap > 0 {
        msg.push_str(&format!(
            ", DROPPED {} valid endpoint(s) beyond the {MAX_PEER_CANDIDATES} per-peer cap",
            f.over_cap
        ));
    }
    Some(msg)
}

/// Drop every candidate endpoint this build cannot write to the WireGuard
/// UAPI (and everything past [`MAX_PEER_CANDIDATES`]), warning once about
/// what was dropped. The decisions live in [`partition_dialable`] and the
/// wording in [`format_drop_warning`]; this is only the seam that joins them
/// to stderr.
fn retain_dialable(candidates: Vec<String>, source: &str) -> Vec<String> {
    let f = partition_dialable(candidates);
    if let Some(msg) = format_drop_warning(&f, source) {
        eprintln!("{msg}");
    }
    f.kept
}

/// `#[serde(deserialize_with)]` shim for [`PeerState::candidates`] — see that
/// field's invariant. Filters on the way IN, so no route that produces a
/// `PeerState` by deserialization (today `DesiredState::load`'s
/// `serde_json::from_slice`, and any future one) can reintroduce the hole.
fn deserialize_dialable_candidates<'de, D>(d: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(retain_dialable(
        Vec::<String>::deserialize(d)?,
        "state.json",
    ))
}

/// `#[serde(deserialize_with)]` shim for [`PeerState::active_pubkey_b64`] —
/// see that field's invariant. A persisted active key that fails
/// [`crate::uapi::pubkey_b64_to_hex`] loads as `None` (the existing "no
/// active key" outcome), not straight through to `encode_set` at boot.
fn deserialize_valid_active_pubkey<'de, D>(d: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = Option::<String>::deserialize(d)?;
    Ok(raw.filter(|k| crate::uapi::pubkey_b64_to_hex(k).is_some()))
}

/// Outcome of one filtering pass over a peer's advertised `allowed_ips` —
/// mirrors [`CandidateFilter`] minus the per-peer cap: item 24 has no
/// `MAX_PEER_CANDIDATES`-style bound, because there is no volume concern
/// distinct from `candidates`' unbounded-`repeated string` one (allowed_ips
/// is operator-defined, not gateway-reported — see the backlog item).
pub(crate) struct CidrFilter {
    /// The entries kept, in advertised order.
    pub(crate) kept: Vec<String>,
    /// How many entries failed [`uapi::is_valid_ipv4_cidr`].
    pub(crate) dropped: usize,
    /// Up to [`DROPPED_SAMPLE_COUNT`] of the invalid entries, same
    /// truncation/quoting rule as [`CandidateFilter::samples`].
    pub(crate) samples: Vec<String>,
}

/// Partition a peer's advertised `allowed_ips` into what this build can write
/// to the WireGuard UAPI and what it cannot, collecting bounded samples of
/// the rejects. Pure — no I/O, no logging.
///
/// The predicate is [`uapi::is_valid_ipv4_cidr`] — the encoder's own accept
/// test, not a second opinion about it (same rationale as
/// [`partition_dialable`]). Dropping is per-ENTRY and never drops the peer —
/// see [`PeerState::allowed_ips`]'s invariant.
pub(crate) fn partition_valid_cidrs(cidrs: Vec<String>) -> CidrFilter {
    let mut f = CidrFilter {
        kept: Vec::new(),
        dropped: 0,
        samples: Vec::new(),
    };

    for c in cidrs {
        if !crate::uapi::is_valid_ipv4_cidr(&c) {
            f.dropped += 1;
            if f.samples.len() < DROPPED_SAMPLE_COUNT {
                // Same char-boundary backoff as `partition_dialable` — the
                // string is attacker/operator-chosen and may be multi-byte
                // UTF-8.
                let mut end = DROPPED_SAMPLE_BYTES.min(c.len());
                while end > 0 && !c.is_char_boundary(end) {
                    end -= 1;
                }
                f.samples.push(format!("{:?}", &c[..end]));
            }
            continue;
        }
        f.kept.push(c);
    }

    f
}

/// Render one warning line for an `allowed_ips` filtering pass, or `None`
/// when it dropped nothing — same one-line-per-pass rationale as
/// [`format_drop_warning`].
pub(crate) fn format_cidr_drop_warning(f: &CidrFilter, source: &str) -> Option<String> {
    if f.dropped == 0 {
        return None;
    }
    Some(format!(
        "wiremesh-gateway: filtering peer allowed_ips from {source} — kept {}, DROPPED {} \
         that are not an IPv4 CIDR (writing one to the WireGuard UAPI would fail the whole \
         device apply and terminate this process); first {}: {}",
        f.kept.len(),
        f.dropped,
        f.samples.len(),
        f.samples.join(", ")
    ))
}

/// Drop every `allowed_ips` entry this build cannot write to the WireGuard
/// UAPI, warning once about what was dropped — the `allowed_ips` analogue of
/// [`retain_dialable`].
fn retain_valid_cidrs(cidrs: Vec<String>, source: &str) -> Vec<String> {
    let f = partition_valid_cidrs(cidrs);
    if let Some(msg) = format_cidr_drop_warning(&f, source) {
        eprintln!("{msg}");
    }
    f.kept
}

/// `#[serde(deserialize_with)]` shim for [`PeerState::allowed_ips`] — see
/// that field's invariant. Filters on the way IN, same rationale as
/// [`deserialize_dialable_candidates`].
fn deserialize_valid_cidrs<'de, D>(d: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(retain_valid_cidrs(
        Vec::<String>::deserialize(d)?,
        "state.json",
    ))
}

impl PeerState {
    fn from_proto(p: &Peer) -> PeerState {
        // (Backlog item 23) Same "undecodable == missing" collapse as the
        // `deserialize_with` shim below, at the Sync-ingest door: an active
        // key `uapi::pubkey_b64_to_hex` cannot decode becomes `None`, which
        // every consumer (`reconcile::{peer_configs, device_config_pinned,
        // device_config_at_port}`'s `p.active_pubkey_b64.clone()?`) already
        // treats as "drop this peer" — see `PeerState::active_pubkey_b64`'s
        // doc comment for why that reuse, rather than a second drop path, is
        // the right shape.
        let active_pubkey_b64 = p
            .keys
            .iter()
            .find(|k| k.state == "active")
            .map(|k| k.pubkey.clone())
            .filter(|pubkey| crate::uapi::pubkey_b64_to_hex(pubkey).is_some());
        let keys = p
            .keys
            .iter()
            .map(|k| PeerKeyInfo {
                epoch: k.epoch,
                pubkey_b64: k.pubkey.clone(),
                state: k.state.clone(),
            })
            .collect();
        PeerState {
            gateway_id: p.gateway_id,
            segment_name: p.segment_name.clone(),
            active_pubkey_b64,
            keys,
            // (Backlog item 1) The Sync-ingest door. This ONE site covers
            // `from_snapshot` and `apply_delta`, and through them
            // `reconcile::{peer_configs, device_config_pinned,
            // pending_peer_configs}` — deliberately not per-builder checks,
            // which would be three chances to add a fourth builder without
            // one. The controller filters this too; a gateway must survive a
            // control plane that does not.
            candidates: retain_dialable(
                p.candidate_endpoints.clone(),
                "a controller advertisement",
            ),
            // (Backlog item 24) The Sync-ingest door for allowed_ips — same
            // per-entry filter as `candidates`, mirrored at `state.json` via
            // `PeerState::allowed_ips`'s `deserialize_with`.
            allowed_ips: retain_valid_cidrs(p.allowed_ips.clone(), "a controller advertisement"),
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
            match self
                .peers
                .iter_mut()
                .find(|x| x.gateway_id == ps.gateway_id)
            {
                Some(existing) => *existing = ps,
                None => self.peers.push(ps),
            }
        }
        self.peers
            .retain(|p| !d.removed_peer_ids.contains(&p.gateway_id));
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
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .context("opening state.json.tmp")?;
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
            Ok(bytes) => Ok(Some(
                serde_json::from_slice(&bytes).context("parsing state.json")?,
            )),
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
/// This asks the real decoder, with no heuristic in front of it, because
/// there is no cheap test that is also EXACT. An earlier version returned
/// `true` for anything starting with the canonical `{"schema":1,` prefix on
/// the theory that "doesn't look like a schema-1 IR" and "is broken" are the
/// same set. They are not, in either direction: `{"schema":1,` itself, a
/// document truncated mid-`blocks`, and `{"schema":1,"version":"four",...}`
/// all match the prefix and all fail [`PolicyIR::from_json`] — so exactly
/// the corruption cases this guard exists for (a partial write of the
/// controller's `policy_version.compiled_ir` column, a damaged backup) were
/// waved through and persisted.
///
/// The "have I already decoded these exact bytes" fast path belongs to
/// [`FailStaticWriter`], which keeps the last decodable IR and can answer it
/// with a memcmp — exact rather than approximate, and independent of serde
/// field order. See [`FailStaticWriter::save`].
pub fn policy_ir_is_decodable(policy_ir: &[u8]) -> bool {
    // "No policy yet" — `apply_if_changed` synthesizes an empty schema-1 IR
    // for this, so there is nothing undecodable to persist.
    policy_ir.is_empty() || PolicyIR::from_json(policy_ir).is_ok()
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
        FailStaticWriter {
            last_good,
            warned: None,
        }
    }

    /// `policy_version` of the last undecodable IR this writer warned about,
    /// or `None` if the most recent save was clean. Exposed so the
    /// once-per-distinct-bad-version dedupe is assertable — the warning
    /// itself goes to stderr, which an in-process test cannot capture.
    pub fn warned_version(&self) -> Option<u64> {
        self.warned
    }

    /// Persist `ds`, substituting its policy pair if the IR is undecodable.
    pub fn save(&mut self, ds: &DesiredState, state_dir: &Path) -> anyhow::Result<()> {
        // Fast path: byte-identical to the IR we last decoded successfully,
        // so it is KNOWN decodable — a memcmp, no parse, and exact (unlike
        // any shape heuristic, it cannot be fooled and cannot rot if the
        // canonical JSON form changes). This is the steady-state case: peer
        // churn, endpoint observations and every reconnect snapshot re-send
        // the same policy.
        if self
            .last_good
            .as_ref()
            .is_some_and(|(_, ir)| ir == &ds.policy_ir)
        {
            self.warned = None;
            return ds.save(state_dir);
        }
        // The IR genuinely changed (or this is the first save), so it has to
        // be decoded. That is one parse per policy CHANGE, on the same event
        // where `apply_if_changed` is about to parse it anyway — not one per
        // `State` event.
        if policy_ir_is_decodable(&ds.policy_ir) {
            self.last_good = Some((ds.policy_version, ds.policy_ir.clone()));
            self.warned = None;
            return ds.save(state_dir);
        }

        let mut sanitized = ds.clone();
        let (kept_version, kept_ir) = self.last_good.clone().unwrap_or((0, Vec::new()));
        sanitized.policy_version = kept_version;
        sanitized.policy_ir = kept_ir;
        if self.warned != Some(ds.policy_version) {
            self.warned = Some(ds.policy_version);
            // Keyed on what was actually WRITTEN, not on whether `last_good`
            // was set: a `last_good` of the "no policy yet" pair must produce
            // the blackhole wording, not "keeps the last policy (version 0)".
            if !sanitized.policy_ir.is_empty() {
                eprintln!(
                    "wiremesh-gateway: CRITICAL: the controller sent policy version {} in an IR \
                     format this build cannot decode (only schema 1 is supported — is the \
                     controller newer than this gateway?). The datapath keeps the last policy \
                     it understood and state.json is being written with THAT policy (version \
                     {kept_version}) instead, so a restart does not inherit an uninstallable \
                     one. Peers and routes are persisted normally. Upgrade this gateway.",
                    ds.policy_version
                );
            } else {
                eprintln!(
                    "wiremesh-gateway: CRITICAL: the controller sent policy version {} in an IR \
                     format this build cannot decode (only schema 1 is supported — is the \
                     controller newer than this gateway?), and this gateway has never installed \
                     a policy it could read. NO policy is live: every tun is default-denying and \
                     ALL fabric traffic is being dropped. state.json is being written with no \
                     policy rather than an uninstallable one. Upgrade this gateway.",
                    ds.policy_version
                );
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

    /// Real WG-shaped key material (base64 of 32 bytes of a repeated byte),
    /// decodable by `uapi::pubkey_b64_to_hex` — unlike this suite's old
    /// placeholder active pubkeys ("PUBA"/"KA"/"PUBA2"), which
    /// `PeerState::from_proto`'s backlog-item-23 filter correctly nulls out
    /// (an undecodable ACTIVE key is peer-fatal at the UAPI, so ingest drops
    /// it — see `PeerState::active_pubkey_b64`'s invariant doc). These tests
    /// are about snapshot/delta plumbing, not key content, so a valid key is
    /// a strictly more realistic fixture; the placeholders were fixture rot,
    /// not evidence the filter belongs somewhere else.
    const VALID_KEY_AA: &str = "qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqo=";
    const VALID_KEY_BB: &str = "u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7u7s=";
    const VALID_KEY_CC: &str = "zMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMw=";

    fn peer(id: u64, pubkey: &str, ep: &str) -> Peer {
        Peer {
            gateway_id: id,
            segment_name: format!("seg{id}"),
            keys: vec![
                PeerKey {
                    epoch: 1,
                    pubkey: "OLD".into(),
                    state: "retiring".into(),
                },
                PeerKey {
                    epoch: 2,
                    pubkey: pubkey.into(),
                    state: "active".into(),
                },
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
            peers: vec![peer(2, VALID_KEY_AA, "203.0.113.2:51820")],
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
        assert_eq!(ds.peers[0].active_pubkey_b64.as_deref(), Some(VALID_KEY_AA));
        assert_eq!(
            ds.peers[0].candidates,
            vec!["203.0.113.2:51820".to_string()]
        );
        assert_eq!(
            ds.peers[0].primary_endpoint().map(String::as_str),
            Some("203.0.113.2:51820")
        );
    }

    #[test]
    fn from_proto_keeps_all_candidates_primary_is_first() {
        let p = Peer {
            gateway_id: 9,
            segment_name: "seg9".into(),
            keys: vec![PeerKey {
                epoch: 1,
                pubkey: "PUB9".into(),
                state: "active".into(),
            }],
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
        assert_eq!(
            ps.primary_endpoint().map(String::as_str),
            Some("198.51.100.9:51820")
        );
    }

    #[test]
    fn from_proto_retains_full_key_set() {
        let p = Peer {
            gateway_id: 11,
            segment_name: "seg11".into(),
            keys: vec![
                PeerKey {
                    epoch: 0,
                    pubkey: "KA".into(),
                    state: "active".into(),
                },
                PeerKey {
                    epoch: 1,
                    pubkey: "KP".into(),
                    state: "pending".into(),
                },
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
                PeerKey {
                    epoch: 0,
                    pubkey: "KA".into(),
                    state: "active".into(),
                },
                PeerKey {
                    epoch: 1,
                    pubkey: "awaiting-submission".into(),
                    state: "pending".into(),
                },
            ],
            candidate_endpoints: vec!["203.0.113.12:51820".into()],
            allowed_ips: vec!["10.10.12.0/24".into()],
        };
        let ps = PeerState::from_proto(&p);
        assert!(
            ps.pending_key().is_none(),
            "sentinel pending key must not be reported as a real pending key"
        );
        let active = ps.active_key().expect("active key still present");
        assert_eq!(active.pubkey_b64, "KA");
    }

    #[test]
    fn active_pubkey_b64_still_populated() {
        let p = Peer {
            gateway_id: 13,
            segment_name: "seg13".into(),
            keys: vec![
                PeerKey {
                    epoch: 0,
                    pubkey: VALID_KEY_BB.into(),
                    state: "active".into(),
                },
                PeerKey {
                    epoch: 1,
                    pubkey: "KP".into(),
                    state: "pending".into(),
                },
            ],
            candidate_endpoints: vec!["203.0.113.13:51820".into()],
            allowed_ips: vec!["10.10.13.0/24".into()],
        };
        let ps = PeerState::from_proto(&p);
        assert_eq!(ps.active_pubkey_b64.as_deref(), Some(VALID_KEY_BB));
        assert_eq!(
            ps.active_key().map(|k| k.pubkey_b64.as_str()),
            Some(VALID_KEY_BB)
        );
    }

    #[test]
    fn apply_delta_upserts_and_removes() {
        let mut ds = DesiredState::from_snapshot(&StateSnapshot {
            revision: 1,
            self_cert_pem: "C".into(),
            peers: vec![peer(2, "PUBA", "a:1"), peer(3, "PUBB", "b:2")],
            deprecated_relays: vec![],
            relay_infos: vec![],
            policy_ir: vec![],
            policy_version: 0,
            revoked_serials: vec![],
        });
        let delta = Delta {
            revision: 2,
            upserted_peers: vec![peer(2, VALID_KEY_CC, "a:9")],
            removed_peer_ids: vec![3],
            deprecated_relays: vec![],
            relay_infos: vec![],
            relays_updated: false,
            policy_ir: b"NEW".to_vec(),
            policy_version: 4,
            revoked_serials: vec![],
        };
        ds.apply_delta(&delta);
        assert_eq!(ds.revision, 2);
        assert_eq!(ds.peers.len(), 1);
        assert_eq!(ds.peers[0].gateway_id, 2);
        assert_eq!(ds.peers[0].active_pubkey_b64.as_deref(), Some(VALID_KEY_CC));
        assert_eq!(ds.policy_version, 4);
        assert_eq!(ds.policy_ir, b"NEW");
    }

    #[test]
    fn save_load_round_trip_atomic_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let ds = DesiredState {
            revision: 9,
            ..Default::default()
        };
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
            relays: vec![RelayInfo {
                relay_id: 1,
                endpoint: "9.9.9.9:1".into(),
            }],
            ..Default::default()
        };
        let delta = Delta {
            revision: 2,
            upserted_peers: vec![],
            removed_peer_ids: vec![],
            deprecated_relays: vec![],
            relay_infos: vec![RelayInfo {
                relay_id: 7,
                endpoint: "1.2.3.4:4443".into(),
            }],
            relays_updated: true,
            policy_ir: vec![],
            policy_version: 0,
            revoked_serials: vec![],
        };
        ds.apply_delta(&delta);
        assert_eq!(
            ds.relays,
            vec![RelayInfo {
                relay_id: 7,
                endpoint: "1.2.3.4:4443".into()
            }]
        );
    }

    #[test]
    fn apply_delta_relays_updated_true_and_empty_clears_relays() {
        // Starting state HAS a relay: this is the last-relay-eviction case the
        // fix enables. The old `if !d.relay_infos.is_empty()` guard could
        // never clear `self.relays` to empty — this test would fail under it.
        let mut ds = DesiredState {
            relays: vec![RelayInfo {
                relay_id: 3,
                endpoint: "5.6.7.8:4443".into(),
            }],
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
            relays: vec![RelayInfo {
                relay_id: 4,
                endpoint: "2.2.2.2:4443".into(),
            }],
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
            vec![RelayInfo {
                relay_id: 4,
                endpoint: "2.2.2.2:4443".into()
            }]
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

    // -----------------------------------------------------------------
    // (Backlog G3) The bounded drop log
    // -----------------------------------------------------------------
    //
    // `retain_dialable` logged one `eprintln!` PER dropped candidate. The
    // strings it logs are attacker-chosen: a compromised-but-authenticated
    // gateway (or a version-skewed controller) picks both how many there are
    // and how long each one is, and the whole set is re-evaluated on EVERY
    // snapshot and EVERY delta. So the log an operator relies on to notice
    // the problem is also the flood — the diagnostic and the denial-of-service
    // are the same line.
    //
    // The contract these pin is therefore a set of BOUNDS, not a wording:
    // one message per filtering pass, at most `DROPPED_SAMPLE_COUNT` quoted
    // samples, each cut at `DROPPED_SAMPLE_BYTES` of RAW payload on a char
    // boundary, `{:?}`-escaped, with counts that stay accurate however few
    // were sampled. Every assertion below is a bound, a count, a presence, or
    // an escape — none of them is the message text, which stays free to
    // change.

    /// Distinct valid endpoints, cheap to generate in bulk for the cap tests.
    fn valid_eps(n: usize) -> Vec<String> {
        (0..n)
            .map(|i| format!("10.0.{}.{}:51820", i / 256, i % 256))
            .collect()
    }

    /// Distinct INVALID endpoints, indexed ALPHABETICALLY rather than
    /// numerically for two reasons: they must be distinct (`partition_dialable`
    /// deliberately does not dedup, but a future one must not be able to make
    /// these collide), and they must contain no decimal digits — a test
    /// asserting that a specific COUNT appears in the message must not be able
    /// to match a digit that leaked out of a payload instead.
    fn invalid_eps(n: usize) -> Vec<String> {
        (0..n)
            .map(|i| {
                let (mut suffix, mut k) = (String::new(), i);
                loop {
                    suffix.push((b'a' + (k % 26) as u8) as char);
                    k /= 26;
                    if k == 0 {
                        break;
                    }
                }
                format!("!!!bogus-{suffix}")
            })
            .collect()
    }

    fn warn(candidates: Vec<String>, source: &str) -> Option<String> {
        format_drop_warning(&partition_dialable(candidates), source)
    }

    /// THE core of the fix: N bad candidates produce ONE warning, not N.
    ///
    /// Breaks if: the implementation keeps a per-entry `eprintln!` (or
    /// `format_drop_warning` is called inside the loop), or the message is
    /// rendered across multiple lines — which would restore the per-reconcile
    /// stderr flood a hostile peer chooses the size of.
    #[test]
    fn one_filtering_pass_produces_exactly_one_warning_line_not_one_per_dropped_entry() {
        let f = partition_dialable(invalid_eps(200));
        assert_eq!(
            f.dropped, 200,
            "all 200 unusable candidates must be counted as dropped"
        );

        let msg = format_drop_warning(&f, "state.json")
            .expect("200 dropped candidates must produce a warning");
        assert_eq!(
            msg.lines().count(),
            1,
            "the whole filtering pass must render as ONE line. The pre-G3 code emitted one \
             `eprintln!` per dropped entry, so a peer advertising 200 unusable candidates \
             wrote 200 lines on every snapshot AND every delta — for as long as it kept \
             advertising them. The log an operator watches must not be the thing that \
             buries the log an operator watches. Got {} lines:\n{msg}",
            msg.lines().count()
        );
    }

    /// At most `DROPPED_SAMPLE_COUNT` payloads are quoted, however many were
    /// dropped — and at least one is, so the bound is not satisfied by
    /// quoting nothing.
    ///
    /// Breaks if: the sample cap is removed or raised, or samples are dropped
    /// entirely (which would leave an operator a count with no evidence, and
    /// no way to tell a stale local file from a hostile advertisement).
    #[test]
    fn at_most_the_sample_count_of_payloads_is_quoted_however_many_were_dropped() {
        // Unique, greppable markers so "how many appear in the message" is a
        // question with an exact answer.
        let markers: Vec<String> = (0..10).map(|i| format!("ZQMARK{i}!!!")).collect();
        let msg = warn(markers.clone(), "state.json")
            .expect("10 dropped candidates must produce a warning");

        let quoted: Vec<&String> = markers
            .iter()
            .filter(|m| msg.contains(m.as_str()))
            .collect();
        assert!(
            quoted.len() <= DROPPED_SAMPLE_COUNT,
            "at most {DROPPED_SAMPLE_COUNT} of the offending strings may be quoted; {} \
             appear. The strings are chosen by whoever sent them and there can be \
             thousands, so quoting them all relocates the flood from the line COUNT into \
             the line LENGTH. Quoted: {quoted:?}",
            quoted.len()
        );
        assert!(
            !quoted.is_empty(),
            "at least one offending string must be quoted. A count with no example leaves \
             an operator unable to tell a compromised peer from a stale `state.json` — \
             which is the entire diagnostic value of this log line.\n{msg}"
        );
    }

    /// The sample is bounded by the TRUNCATION, not by the input.
    ///
    /// This is the property the raw 64 exists for, and it is asserted two
    /// ways: the quoted sample must be identical for a 10KB and a 100KB
    /// candidate that share a prefix (so its size cannot track the input at
    /// all), and it must sit under an absolute ceiling.
    ///
    /// The ceiling is `DROPPED_SAMPLE_BYTES * 10 + 2`, not `+ 2` alone,
    /// because the stored sample is the `{:?}`-QUOTED form: two quotes always,
    /// and each escaped character expands (a `\n` to two characters, a control
    /// byte to a `\u{..}` of up to six). The bound that matters is
    /// "independent of input size", not a tight byte count.
    ///
    /// Breaks if: the truncation is removed or the cap is raised — one
    /// candidate is bounded only by the Sync message size, so an untruncated
    /// sample is a multi-megabyte log line, the same flood through the other
    /// dimension.
    #[test]
    fn the_quoted_sample_is_bounded_by_the_truncation_not_by_the_input_size() {
        let ten_k = partition_dialable(vec!["A".repeat(10_000)]);
        let hundred_k = partition_dialable(vec!["A".repeat(100_000)]);

        let a = ten_k
            .samples
            .first()
            .expect("the dropped candidate must be sampled");
        let b = hundred_k
            .samples
            .first()
            .expect("the dropped candidate must be sampled");
        assert_eq!(
            a, b,
            "two candidates sharing their first {DROPPED_SAMPLE_BYTES} bytes must produce \
             the IDENTICAL sample, whether the sender wrote 10KB or 100KB after them. A \
             sample whose size tracks the input is not a sample, and the sender picks the \
             input."
        );
        assert!(
            a.len() <= DROPPED_SAMPLE_BYTES * 10 + 2,
            "the quoted sample is {} bytes, past the ceiling {} bytes of raw payload can \
             expand to under `{{:?}}`. Sample: {a}",
            a.len(),
            DROPPED_SAMPLE_BYTES
        );

        let msg = format_drop_warning(&ten_k, "state.json").expect("one drop must warn");
        assert!(
            msg.contains(&"A".repeat(32)),
            "a prefix of the offending string must survive into the message — truncation \
             must shorten the evidence, not delete it.\n{msg}"
        );
        assert!(
            !msg.contains(&"A".repeat(DROPPED_SAMPLE_BYTES + 1)),
            "more than {DROPPED_SAMPLE_BYTES} consecutive RAW payload bytes reached the \
             message. `A` needs no escaping, so its run length in the rendered line is \
             exactly the number of raw bytes quoted — this is the direct read of the \
             truncation.\n{msg}"
        );
    }

    /// **The highest-value test here.** Truncating a UTF-8 string by BYTE
    /// index panics if the index is not a char boundary (`&s[..64]`), and the
    /// blast radius is worse than a bad log line: `partition_dialable` runs
    /// inside `PeerState::candidates`' `deserialize_with`, so a panic there
    /// fires on the `DesiredState::load` fail-static BOOT path. The defense
    /// added to stop a malformed candidate from preventing boot would itself
    /// prevent boot — over a string a peer chose.
    ///
    /// Breaks if: the implementation slices at a fixed `DROPPED_SAMPLE_BYTES`
    /// without walking back to a char boundary. Each prefix length below
    /// places a multi-byte character ACROSS that byte, so at least one lands
    /// mid-character under any fixed-index slice.
    #[test]
    fn sample_truncation_never_splits_a_multibyte_character() {
        let cut = DROPPED_SAMPLE_BYTES;
        for back in [1usize, 2, 3, 4] {
            // 4-byte char starting `back` bytes before the cut: for back < 4 it
            // straddles the cut, so the naive slice is mid-character.
            let payload = format!("{}{}TAIL", "x".repeat(cut - back), '\u{1F600}');
            let msg = warn(vec![payload], "state.json").unwrap_or_else(|| {
                panic!("back={back}: an unusable candidate must produce a warning")
            });
            assert!(
                !msg.contains("TAIL"),
                "back={back}: bytes past the {cut}-byte sample cap were quoted — the \
                 payload's tail marker appears.\n{msg}"
            );
        }
        // The 3-byte and 2-byte continuation depths, so the back-off is
        // exercised at every width UTF-8 has.
        for c in ['\u{20AC}', '\u{00E9}'] {
            for back in [1usize, 2, 3] {
                let payload = format!("{}{c}TAIL", "x".repeat(cut - back));
                assert!(
                    warn(vec![payload], "state.json").is_some(),
                    "back={back}, char {c:?}: truncating here must not panic. `&s[..{cut}]` \
                     on a non-char-boundary index PANICS, and this code runs inside \
                     `PeerState::candidates`' `deserialize_with` — so a multi-byte \
                     candidate that once got persisted would abort the fail-static boot, \
                     inverting the exact mechanism backlog item 1 exists to protect."
                );
            }
        }
    }

    /// The budget is a BYTE budget, not a character budget.
    ///
    /// Breaks if: the implementation truncates with `.chars().take(64)`, which
    /// looks equivalent, passes every ASCII test above, and quietly permits a
    /// 256-byte sample.
    #[test]
    fn the_sample_budget_is_measured_in_bytes_not_characters() {
        let payload = "\u{1F600}".repeat(200); // 800 bytes, 200 chars
        let msg = warn(vec![payload], "state.json").expect("an unusable candidate warns");
        assert!(
            msg.contains('\u{1F600}'),
            "the sample must still appear — this test is about its LENGTH, not its \
             existence.\n{msg}"
        );
        let over = DROPPED_SAMPLE_BYTES / 4 + 1; // one 4-byte char past the budget
        assert!(
            !msg.contains(&"\u{1F600}".repeat(over)),
            "{over} consecutive 4-byte characters is {} bytes, past the \
             {DROPPED_SAMPLE_BYTES}-byte budget. A character-counted truncation would admit \
             {DROPPED_SAMPLE_BYTES} of them (4x the budget) while looking correct against \
             ASCII input.\n{msg}",
            over * 4
        );
    }

    /// Samples are `{:?}`-quoted, so a newline in the payload is ESCAPED.
    ///
    /// Breaks if: the sample is pushed with `{}` instead of `{:?}`. There are
    /// already-passing tests proving `"10.0.0.5:51820\nendpoint=1.2.3.4:1"` is
    /// REJECTED as a UAPI line-injection payload; emitting it raw here would
    /// reintroduce the same injection one layer over, into the log an operator
    /// (or a log shipper, or an alerting rule) parses by line.
    #[test]
    fn an_injection_payload_is_escaped_in_the_log_not_emitted_raw() {
        let payload = "10.0.0.5:51820\nendpoint=1.2.3.4:1"; // 33 bytes: under the cut, so it
                                                            // is quoted whole
        let msg = warn(vec![payload.to_string()], "state.json")
            .expect("the injection payload is unusable and must warn");

        assert!(
            !msg.contains('\n'),
            "the payload's newline reached the rendered message. The candidate that carries \
             it is rejected precisely BECAUSE the UAPI wire format is newline-delimited \
             `key=value` lines; a log that re-emits it raw lets the sender forge a second \
             log record — and splits this warning into two lines, defeating the one-line \
             bound as well.\n{msg:?}"
        );
        assert!(
            msg.contains("10.0.0.5:51820\\nendpoint=1.2.3.4:1"),
            "the payload must appear in its ESCAPED form (the sample is stored already \
             `{{:?}}`-quoted), so the evidence is preserved without the control character. \
             Got:\n{msg:?}"
        );
    }

    /// The counts describe the whole pass even though only
    /// `DROPPED_SAMPLE_COUNT` are sampled.
    ///
    /// Breaks if: the count is taken from `samples.len()` (a very easy slip
    /// once sampling exists) — which would report "3 dropped" for any flood
    /// and hide its size from exactly the operator trying to measure it.
    #[test]
    fn the_warning_reports_the_true_dropped_count_not_the_sample_count() {
        let mut input = invalid_eps(17);
        input.extend(["10.0.0.5:51820".to_string(), "10.0.0.6:51820".to_string()]);

        let f = partition_dialable(input);
        assert_eq!(f.dropped, 17, "17 unusable candidates were supplied");
        assert_eq!(
            f.kept,
            vec!["10.0.0.5:51820".to_string(), "10.0.0.6:51820".to_string()],
            "filtering is per-ENTRY: the two dialable candidates must survive in order. A \
             peer that got one address wrong must not lose the ones it got right — that \
             would turn a cosmetic bug into a lost direct path."
        );
        assert!(
            f.samples.len() <= DROPPED_SAMPLE_COUNT,
            "17 drops must not store 17 samples: {:?}",
            f.samples
        );

        let msg = format_drop_warning(&f, "state.json").expect("17 drops must warn");
        assert!(
            msg.contains("17"),
            "the true dropped count (17) must appear, even though at most \
             {DROPPED_SAMPLE_COUNT} were quoted. Reporting the sample count instead makes \
             every flood look like three bad entries, which is the one number an operator \
             actually needs.\n{msg}"
        );
    }

    /// Silence on the healthy path.
    ///
    /// Breaks if: the warning is emitted unconditionally (e.g. `Some` with a
    /// "0 dropped" body). This is the overwhelmingly common case — every
    /// snapshot and every delta of a healthy fabric — so any noise here is
    /// noise forever, and it is what teaches operators to ignore the line.
    #[test]
    fn nothing_dropped_means_no_warning_at_all() {
        let f = partition_dialable(valid_eps(4));
        assert_eq!(f.dropped, 0);
        assert_eq!(f.over_cap, 0);
        assert_eq!(f.kept.len(), 4, "every dialable candidate is kept");
        assert_eq!(
            format_drop_warning(&f, "state.json"),
            None,
            "a clean filtering pass must produce NO message. This runs on every snapshot \
             and every delta for every peer; a line here is permanent background noise, \
             and a warning that fires when nothing is wrong is a warning nobody reads when \
             something is."
        );
    }

    /// The cap is a CEILING, not a target.
    ///
    /// Breaks if: the bound is off by one, or an at-limit advertisement is
    /// trimmed. `Db::candidates_for` yields at most 1 observed + 32 local = 33
    /// today, so `MAX_PEER_CANDIDATES` (64) is pure headroom — an honest peer
    /// must never reach it, and must never be trimmed if it does.
    #[test]
    fn a_candidate_list_exactly_at_the_cap_is_kept_whole_and_silent() {
        let at_cap = valid_eps(MAX_PEER_CANDIDATES);
        let f = partition_dialable(at_cap.clone());
        assert_eq!(
            f.kept, at_cap,
            "a peer advertising exactly {MAX_PEER_CANDIDATES} usable candidates must keep \
             every one of them, in order. The cap exists to bound a hostile peer, not to \
             trim an honest one — and `primary_endpoint()` is `candidates.first()`, so \
             trimming or reordering silently re-points which address this gateway dials."
        );
        assert_eq!(f.over_cap, 0, "nothing is over a cap it exactly meets");
        assert_eq!(
            format_drop_warning(&f, "state.json"),
            None,
            "and an at-cap list must not warn — it is a legal advertisement"
        );
    }

    /// The over-cap case and the invalid case are different problems and must
    /// read differently.
    ///
    /// Breaks if: over-cap drops are folded into the `dropped` counter, or
    /// both conditions render the same sentence. They mean opposite things to
    /// an operator: unusable entries mean a peer is compromised or
    /// version-skewed and its addresses are garbage; over-cap means its
    /// addresses were all FINE and this gateway chose not to keep them all.
    #[test]
    fn the_over_cap_case_is_reported_distinctly_from_the_invalid_case() {
        const OVER_BY: usize = 5;
        let capped = partition_dialable(valid_eps(MAX_PEER_CANDIDATES + OVER_BY));
        assert_eq!(
            capped.kept.len(),
            MAX_PEER_CANDIDATES,
            "the kept set must be bounded by MAX_PEER_CANDIDATES. Without the bound a peer \
             chooses how many endpoints every reconcile of every apply carries — the same \
             unbounded work the controller's MAX_LOCAL_CANDIDATES closes on its side, left \
             open on this one."
        );
        assert_eq!(
            capped.over_cap, OVER_BY,
            "the excess is counted, not silently discarded"
        );
        assert_eq!(
            capped.dropped, 0,
            "candidates dropped for the CAP must not be counted as unusable: every one of \
             these parses. Conflating them makes a healthy over-provisioned host look like \
             a compromised peer."
        );

        let invalid = partition_dialable(invalid_eps(OVER_BY));
        assert_eq!(invalid.dropped, OVER_BY);
        assert_eq!(invalid.over_cap, 0);

        let cap_msg = format_drop_warning(&capped, "state.json")
            .expect("dropping over-cap entries must warn");
        let bad_msg = format_drop_warning(&invalid, "state.json")
            .expect("dropping unusable entries must warn");
        assert_ne!(
            cap_msg, bad_msg,
            "with the same number of entries dropped for two DIFFERENT reasons, the two \
             messages are identical — so the log cannot distinguish \"this peer is sending \
             garbage\" from \"this peer has more addresses than we keep\". The first is an \
             incident; the second is a shrug.\ncap: {cap_msg}\nbad: {bad_msg}"
        );
        assert!(
            cap_msg.contains(&OVER_BY.to_string()),
            "the over-cap message must say how many were dropped ({OVER_BY}).\n{cap_msg}"
        );
    }

    /// Both conditions at once still produce ONE line, and both counts.
    ///
    /// Breaks if: the over-cap clause is emitted as a second `eprintln!`, or
    /// either clause suppresses the other. The mixed case is the realistic
    /// hostile shape — a peer that sends both garbage and volume — and it is
    /// where a two-`eprintln!` implementation would quietly reappear.
    #[test]
    fn a_pass_that_both_drops_and_over_caps_still_renders_one_line_with_both_counts() {
        const OVER_BY: usize = 7;
        const BAD: usize = 11;
        let mut input = invalid_eps(BAD);
        input.extend(valid_eps(MAX_PEER_CANDIDATES + OVER_BY));

        let f = partition_dialable(input);
        assert_eq!(
            f.dropped, BAD,
            "the unusable entries are counted as dropped"
        );
        assert_eq!(
            f.over_cap, OVER_BY,
            "the valid excess is counted as over-cap"
        );

        let msg = format_drop_warning(&f, "state.json").expect("both conditions must warn");
        assert_eq!(
            msg.lines().count(),
            1,
            "both clauses must share ONE line. Two `eprintln!`s is how the per-entry flood \
             starts coming back.\n{msg}"
        );
        assert!(
            msg.contains(&BAD.to_string()) && msg.contains(&OVER_BY.to_string()),
            "both counts must appear ({BAD} unusable, {OVER_BY} over cap) — a message that \
             reports only the condition it noticed first leaves the operator debugging half \
             the problem.\n{msg}"
        );
    }

    /// `source` names the door the candidate came through, and must be in the
    /// message.
    ///
    /// Breaks if: the parameter is accepted and ignored. The two doors mean
    /// very different things: a controller advertisement means a peer or the
    /// control plane is compromised or version-skewed (act now); a
    /// `state.json` entry means THIS gateway persisted it before the filter
    /// existed (self-healing, ignore). Without the source an operator cannot
    /// tell which one they are looking at.
    #[test]
    fn the_source_names_the_door_the_bad_candidate_came_through() {
        for source in ["state.json", "controller advertisement"] {
            let msg = warn(invalid_eps(3), source)
                .unwrap_or_else(|| panic!("dropped candidates from {source} must warn"));
            assert!(
                msg.contains(source),
                "the warning must name its source ({source:?}) — a `state.json` entry is \
                 this gateway's own stale file and heals itself, while a controller \
                 advertisement means a live peer is sending things it cannot possibly \
                 produce. Same log line, opposite responses.\n{msg}"
            );
        }
    }

    /// Control: the log bound must not have been bought with the filter's
    /// actual job.
    ///
    /// Breaks if: `partition_dialable` reorders, rewrites, or drops valid
    /// entries. Nothing else in this section would notice — every other test
    /// here inspects the MESSAGE.
    #[test]
    fn partition_dialable_keeps_every_valid_candidate_verbatim_and_in_order() {
        let input = vec![
            "!!!bogus".to_string(),
            "203.0.113.9:51820".to_string(),
            "abc:123".to_string(),
            "10.0.0.5:51820".to_string(),
            "[::1]:51820".to_string(),
            "192.168.1.7:65535".to_string(),
        ];
        let f = partition_dialable(input);
        assert_eq!(
            f.kept,
            vec![
                "203.0.113.9:51820".to_string(),
                "10.0.0.5:51820".to_string(),
                "192.168.1.7:65535".to_string(),
            ],
            "the dialable candidates must survive VERBATIM and in their advertised order. \
             Order is load-bearing: `primary_endpoint()` is `candidates.first()`, so \
             reordering silently re-points which address this gateway dials, and the \
             controller already decided that order (observed candidate first)."
        );
        assert_eq!(
            f.dropped, 3,
            "the three unusable entries are dropped and counted"
        );
        assert_eq!(
            f.over_cap, 0,
            "six candidates is nowhere near MAX_PEER_CANDIDATES"
        );
    }

    /// (CodeRabbit 🟡 Minor, PR #59) A manually-kept-in-sync COPY of
    /// `wiremesh_controller::services::sync::MAX_LOCAL_CANDIDATES` (as of
    /// this writing: 32). Not a live reference — this crate deliberately
    /// does not depend on `wiremesh-controller`, and `MAX_PEER_CANDIDATES`
    /// below is `pub(crate)` (invisible outside this crate regardless), so
    /// no dependency edge would make a live cross-crate assertion possible
    /// anyway. Full reasoning lives in
    /// `crates/wiremesh-controller/tests/candidate_cap_gateway_relation.rs`,
    /// which carries the mirror-image constant (a manually-synced copy of
    /// `MAX_PEER_CANDIDATES`, the counterpart of this one). Keep the two in
    /// sync by hand when either constant moves. That discipline covers any
    /// SINGLE unmirrored edit on either side; it does not cover two
    /// compounding ones made at different times (an unmirrored raise on the
    /// controller side AND a separate unmirrored lower here) — each side's
    /// own pin would independently still read green against its own stale
    /// mirror while the real cross-crate relation had already broken.
    const CONTROLLER_MAX_LOCAL_CANDIDATES_MIRROR: usize = 32;

    /// Closes the direction that `candidate_cap_gateway_relation.rs`'s own
    /// mirror cannot cover: that file's tests catch `MAX_LOCAL_CANDIDATES`
    /// being raised on the controller side without a check here, but go
    /// stale — silently — if `MAX_PEER_CANDIDATES` is instead LOWERED on
    /// this side. This test is the other half of that pair.
    ///
    /// Breaks if: `MAX_PEER_CANDIDATES` drops to 33 or below.
    /// `Db::candidates_for` (`crates/wiremesh-controller/src/db.rs`) yields
    /// at most 1 controller-observed endpoint +
    /// `MAX_LOCAL_CANDIDATES` (32, mirrored above) locally-reported ones =
    /// 33 for an HONEST control plane — that IS the exact honest ceiling,
    /// and a cap of exactly 33 would still fit it whole:
    /// `partition_dialable` only starts dropping once `kept.len()` REACHES
    /// the cap (checked before the push, `state.rs:176`), so equality is
    /// safe and the first entry it would ever drop is the 34th, which an
    /// honest control plane never sends. The assertion below requires `>`,
    /// not `>=`, as deliberate MARGIN — so the cap is never left sitting
    /// exactly on the ceiling, one future `MAX_LOCAL_CANDIDATES` bump away
    /// from actually truncating a real advertisement. Currently green
    /// (64 > 33): this is a tripwire against future drift, not a
    /// reproduction of a live bug.
    #[test]
    fn max_peer_candidates_stays_above_the_honest_controller_ceiling() {
        let honest_ceiling = 1 + CONTROLLER_MAX_LOCAL_CANDIDATES_MIRROR;
        assert!(
            MAX_PEER_CANDIDATES > honest_ceiling,
            "MAX_PEER_CANDIDATES ({MAX_PEER_CANDIDATES}) must stay strictly greater than \
             1 (controller-observed) + MAX_LOCAL_CANDIDATES \
             ({CONTROLLER_MAX_LOCAL_CANDIDATES_MIRROR}) = {honest_ceiling} — the honest \
             ceiling `Db::candidates_for` (crates/wiremesh-controller/src/db.rs) can ever \
             produce for a correctly-behaving control plane. A cap of exactly \
             {honest_ceiling} would still keep that whole advertisement — \
             `partition_dialable` only drops once `kept.len()` reaches the cap, so equality \
             is safe. Requiring strictly-greater here is deliberate MARGIN, so the cap is \
             never left sitting exactly on the ceiling where the next \
             MAX_LOCAL_CANDIDATES increase would truncate a real advertisement. If you \
             lowered MAX_PEER_CANDIDATES on purpose, first confirm \
             `wiremesh-controller/src/services/sync.rs`'s MAX_LOCAL_CANDIDATES (mirrored \
             above) hasn't also moved, then update both mirrors — this one and the one in \
             `crates/wiremesh-controller/tests/candidate_cap_gateway_relation.rs` — to \
             match."
        );
    }
}
