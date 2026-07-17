//! The real eBPF [`crate::Enforcer`] backend — graduated from
//! `spike/enforcer/enforcer/src/main.rs`'s `run()`/`apply_rules()` (Task 7
//! brief). Loads the embedded object built by `build.rs` (from the sibling
//! standalone `wiremesh-enforcer-ebpf` workspace's `program` package),
//! attaches the tc classifier ingress (enforce) + egress (flow-record) on
//! `iface`, then drives [`crate::flatten::flatten`]'s output into the
//! spike's A/B rule tables via an atomic `ACTIVE` flip.

use crate::flatten::{flatten, FlatRule, MAX_RULES};
use crate::{BackendKind, Counters, DenyEvent, Enforcer, EnforcerConfig};
use anyhow::{bail, Context, Result};
use aya::{
    maps::{Array, MapData},
    programs::{tc, SchedClassifier, TcAttachType},
    Ebpf,
};
use wiremesh_enforcer_common::{FlowKey, Rule, ACT_ALLOW, ACT_DENY};
use wiremesh_policy::{IrAction, IrProto, PolicyIR};

const BPFFS_ROOT: &str = "/sys/fs/bpf";
const BPF_FS_MAGIC: u64 = 0xcafe_4a11;

/// The spike's A/B tables are fixed 64-entry `Array<Rule>` maps (this
/// task's scope keeps that mechanism as-is per the brief). Task 8's
/// map-in-map generations lift this cap to [`MAX_RULES`] (256) — until
/// then, [`apply_flat_rules`] bails with a clear error rather than silently
/// truncating if a flattened+exploded policy would overflow this table.
const RULE_TABLE_CAPACITY: usize = 64;

const PINNED_MAPS: [&str; 6] = ["COUNTERS", "ACTIVE", "RULES_A", "RULES_B", "RULE_LEN", "FLOWS"];

/// The live eBPF backend: one loaded+attached [`Ebpf`] instance per
/// `probe()` call, kept alive for the lifetime of the boxed [`Enforcer`].
/// Unlike the spike's separate `enforcer`/`enforcer stats` CLI processes,
/// every [`Enforcer`] method here operates directly on this in-process
/// handle — map pinning (below) is therefore best-effort, for external
/// tooling (a later `fabricctl`/stats path), not required for this type's
/// own correctness.
pub struct EbpfEnforcer {
    ebpf: Ebpf,
    #[allow(dead_code)] // not yet consumed: idle timeouts/rate caps/log
    // sampling aren't wired into the eBPF maps in this task (the spike's
    // FLOWS table is a fixed 65536-entry LruHashMap with no idle-eviction
    // or rate-limiting logic yet) -- kept here so a later task can read it
    // back without changing `probe`'s signature again.
    cfg: EnforcerConfig,
}

impl EbpfEnforcer {
    pub(crate) fn new(iface: &str, cfg: EnforcerConfig) -> Result<Self> {
        let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/wiremesh-enforcer"
        )))
        .context("loading embedded eBPF object")?;

        let _ = tc::qdisc_add_clsact(iface); // idempotent-ish: ignore EEXIST (graduated from spike)
        for (prog, at) in [
            ("aeth_ingress", TcAttachType::Ingress),
            ("aeth_egress", TcAttachType::Egress),
        ] {
            let p: &mut SchedClassifier = ebpf
                .program_mut(prog)
                .with_context(|| format!("no program named {prog} in embedded object"))?
                .try_into()
                .with_context(|| format!("{prog} is not a SchedClassifier"))?;
            p.load().with_context(|| format!("loading {prog}"))?;
            p.attach(iface, at)
                .with_context(|| format!("attaching {prog} on {iface} ({at:?})"))?;
        }

        let pin_dir = pin_dir_for(iface);
        if let Err(e) = pin_maps(&mut ebpf, &pin_dir) {
            // Best-effort (see the struct doc above): a pin failure (no
            // bpffs, a stale pin from a previous run, permissions) must not
            // fail attach+apply, which is everything THIS in-process
            // Enforcer needs.
            eprintln!(
                "wiremesh-enforcer: map pinning at {} skipped: {e:#}",
                pin_dir.display()
            );
        }

        Ok(Self { ebpf, cfg })
    }
}

/// Per-iface pin directory, so concurrent `probe()` calls on different
/// interfaces (e.g. Task 8's two gateways) don't collide on the same pin
/// paths. Not yet configurable (no `pin_dir` field on [`EnforcerConfig`]) —
/// a later task can add one if an operator needs to override it.
fn pin_dir_for(iface: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("{BPFFS_ROOT}/wiremesh-enforcer-{iface}"))
}

/// Make sure `/sys/fs/bpf` is an actual mounted bpf filesystem before we try
/// to create the pin dir / pin maps there. On systemd hosts `sys-fs-bpf.mount`
/// does this at boot, but containers (this dev container included) and other
/// minimal environments frequently leave it as a plain directory under sysfs,
/// where `create_dir_all`/`BPF_OBJ_PIN` fail with ENOENT. A real gateway needs
/// the same guarantee, so it lives here rather than in any test/dev wrapper.
///
/// Graduated verbatim from `spike/enforcer/enforcer/src/main.rs:49` (Task 7
/// brief).
fn ensure_bpffs(pin_dir: &std::path::Path) -> Result<()> {
    if !pin_dir.starts_with(BPFFS_ROOT) {
        // Custom pin location: caller is responsible for it being on a bpffs.
        return Ok(());
    }
    let root = std::ffi::CString::new(BPFFS_ROOT).expect("no NUL in constant");
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(root.as_ptr(), &mut st) } == 0 && st.f_type as u64 == BPF_FS_MAGIC {
        return Ok(()); // already a mounted bpffs
    }
    let fstype = std::ffi::CString::new("bpf").expect("no NUL in constant");
    let rc = unsafe {
        libc::mount(
            fstype.as_ptr(), // source (conventionally "bpf"/"bpffs"; unused by kernel)
            root.as_ptr(),
            fstype.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        bail!(
            "{BPFFS_ROOT} is not a bpf filesystem and mounting one there failed: {} \
             (map pinning requires bpffs; are we missing CAP_SYS_ADMIN?)",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

fn pin_maps(ebpf: &mut Ebpf, pin_dir: &std::path::Path) -> Result<()> {
    ensure_bpffs(pin_dir)?;
    std::fs::create_dir_all(pin_dir)
        .with_context(|| format!("creating pin dir {}", pin_dir.display()))?;
    for m in PINNED_MAPS {
        ebpf.map_mut(m)
            .context(m)?
            .pin(pin_dir.join(m))
            .with_context(|| format!("pinning {m}"))?;
    }
    Ok(())
}

impl Enforcer for EbpfEnforcer {
    fn kind(&self) -> BackendKind {
        BackendKind::Ebpf
    }

    fn apply(&mut self, ir: &PolicyIR) -> Result<()> {
        let flat = flatten(ir)?;
        apply_flat_rules(&mut self.ebpf, &flat)
    }

    /// Minimal-real (Task 7 brief): reads the actual `COUNTERS` map.
    /// `by_rule` stays empty -- the eBPF program only tracks the 4 aggregate
    /// counters graduated from the spike (`CTR_ALLOW`/`CTR_DENY`/
    /// `CTR_FLOW_HIT`/`CTR_ICMP_ERR`), not one counter per `rule_id`; a
    /// per-rule counter map is a later task's addition.
    fn counters(&mut self) -> Result<Counters> {
        let counters: Array<&MapData, u64> =
            Array::try_from(self.ebpf.map("COUNTERS").context("COUNTERS")?)?;
        let default_deny = counters
            .get(&wiremesh_enforcer_common::CTR_DENY, 0)
            .unwrap_or(0);
        Ok(Counters {
            by_rule: std::collections::BTreeMap::new(),
            default_deny,
        })
    }

    /// Minimal-real (Task 7 brief): clears every entry in `FLOWS`, forcing
    /// every subsequent packet to be re-evaluated against the current rule
    /// set rather than fast-pathing on a stale recorded flow.
    fn flush_flows(&mut self) -> Result<()> {
        // `FLOWS` is a `BPF_MAP_TYPE_LRU_HASH` (the eBPF program's
        // `LruHashMap<FlowKey, u64>`); on the userspace side aya represents
        // both plain and LRU hash maps with the same `aya::maps::HashMap`
        // type (`Map::LruHashMap` and `Map::HashMap` both convert into it) —
        // there is no separate `aya::maps::LruHashMap` type to name here.
        let mut flows: aya::maps::HashMap<&mut MapData, FlowKey, u64> =
            aya::maps::HashMap::try_from(self.ebpf.map_mut("FLOWS").context("FLOWS")?)?;
        let keys: Vec<FlowKey> = flows.keys().collect::<Result<_, _>>()?;
        for k in keys {
            let _ = flows.remove(&k);
        }
        Ok(())
    }

    /// Honest stub (Task 7 brief): the eBPF program doesn't yet emit a
    /// deny-event ring/perf buffer -- that's Task 10's addition. Draining
    /// real sampled deny events (design §6) needs that buffer wired up
    /// first.
    fn deny_events(&mut self) -> Result<Vec<DenyEvent>> {
        Ok(Vec::new())
    }
}

/// Explodes each [`FlatRule`]'s (possibly multiple) src/dst CIDR pairs into
/// per-CIDR-pair [`Rule`] entries -- the spike's `Rule` has a single src/dst
/// each, not a list. Consecutive entries share the `FlatRule`'s `action`,
/// preserving first-match semantics (a packet matching any of a
/// `FlatRule`'s CIDR pairs gets that one action either way); counters
/// aggregate by `rule_id` regardless (see [`crate::Counters::by_rule`]),
/// which this exploded per-CIDR-pair table has no notion of at all.
fn explode(flat: &[FlatRule]) -> Vec<Rule> {
    let mut rules = Vec::new();
    for f in flat {
        let action = match f.action {
            IrAction::Allow => ACT_ALLOW,
            IrAction::Deny => ACT_DENY,
        };
        let proto = match f.proto {
            IrProto::Tcp => 6,
            IrProto::Udp => 17,
            IrProto::Icmp => 1,
            IrProto::Any => 0,
        };
        for src in &f.src_cidrs {
            for dst in &f.dst_cidrs {
                rules.push(Rule {
                    src: u32::from(src.addr()).to_be(),
                    src_plen: u32::from(src.prefix_len()),
                    dst: u32::from(dst.addr()).to_be(),
                    dst_plen: u32::from(dst.prefix_len()),
                    proto,
                    port_lo: f.port_lo,
                    port_hi: f.port_hi,
                    action,
                });
            }
        }
    }
    rules
}

/// Writes the exploded `Rule`s into whichever of `RULES_A`/`RULES_B` is
/// currently the *inactive* table, sets that table's `RULE_LEN` entry, then
/// flips `ACTIVE` to point at it. The flip (`active.set(0, target, 0)`) is a
/// single map update — the kernel side (`scan_rules`) reads `ACTIVE` exactly
/// once per packet, so every in-flight packet observes either wholly the old
/// generation or wholly the new one, never a half-written table (graduated
/// from `spike/enforcer/enforcer/src/main.rs`'s `apply_rules`, driven by
/// [`flatten`]'s output instead of a JSON rules file).
fn apply_flat_rules(ebpf: &mut Ebpf, flat: &[FlatRule]) -> Result<()> {
    let rules = explode(flat);

    if rules.len() > RULE_TABLE_CAPACITY {
        bail!(
            "policy explodes to {} per-CIDR-pair rules, exceeding this backend's \
             {RULE_TABLE_CAPACITY}-entry A/B table capacity (Task 8's map-in-map generations \
             lift this to wiremesh_enforcer::flatten::MAX_RULES = {MAX_RULES}); trim the \
             policy's CIDR fan-out or wait for Task 8",
            rules.len(),
        );
    }

    let active_now: u32 = {
        let a: Array<&MapData, u32> = Array::try_from(ebpf.map("ACTIVE").context("ACTIVE")?)?;
        a.get(&0, 0)?
    };
    let target = 1 - active_now; // write the INACTIVE table, then flip onto it
    let table_name = if target == 0 { "RULES_A" } else { "RULES_B" };

    let mut tbl: Array<&mut MapData, Rule> =
        Array::try_from(ebpf.map_mut(table_name).context(table_name)?)?;
    for (i, r) in rules.iter().enumerate() {
        tbl.set(i as u32, *r, 0)?;
    }
    let mut len: Array<&mut MapData, u32> =
        Array::try_from(ebpf.map_mut("RULE_LEN").context("RULE_LEN")?)?;
    len.set(target, rules.len() as u32, 0)?;

    let mut active: Array<&mut MapData, u32> =
        Array::try_from(ebpf.map_mut("ACTIVE").context("ACTIVE")?)?;
    active.set(0, target, 0)?; // ATOMIC FLIP

    Ok(())
}
