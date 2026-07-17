//! The real eBPF [`crate::Enforcer`] backend — graduated from
//! `spike/enforcer/enforcer/src/main.rs`'s `run()`/`apply_rules()` (Task 7
//! brief), then upgraded in Task 8
//! (`.superpowers/sdd/task-8-brief.md`) to LPM-bitset first-match matching
//! + map-in-map atomic generations. Loads the embedded object built by
//! `build.rs` (from the sibling standalone `wiremesh-enforcer-ebpf`
//! workspace's `program` package), attaches the tc classifier ingress
//! (enforce) + egress (flow-record) on `iface`, then drives
//! [`crate::flatten::flatten`]'s output into a FRESH generation's per-CPU
//! map-in-map tables via a single atomic `ACTIVE` flip.

use crate::flatten::{flatten, FlatRule};
use crate::{BackendKind, Counters, DenyEvent, Enforcer, EnforcerConfig};
use anyhow::{bail, Context, Result};
use aya::{
    maps::{
        lpm_trie::{Key as LpmKey, LpmTrie},
        Array, ArrayOfMaps, MapData,
    },
    programs::{tc, SchedClassifier, TcAttachType},
    Ebpf,
};
use ipnet::Ipv4Net;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use wiremesh_enforcer_common::{
    bit_set, FlowKey, RuleBits, RuleMeta, ACT_ALLOW, ACT_DENY, BITSET_WORDS, CTR_DEFAULT_DENY,
    LPM_MAX_ENTRIES, MAX_RULES,
};
use wiremesh_policy::{IrAction, IrProto, PolicyIR};

const BPFFS_ROOT: &str = "/sys/fs/bpf";
const BPF_FS_MAGIC: u64 = 0xcafe_4a11;

/// The kernel rejects LPM trie maps that don't set `BPF_F_NO_PREALLOC` —
/// aya doesn't re-export the raw kernel constant (`1`) for userspace map
/// creation, so it's named here; it must stay in sync with
/// `aya_ebpf::btf_maps::lpm_trie::LpmTrie`'s own default `FLAGS` (which the
/// kernel-declared `SrcTrie`/`DstTrie` types in
/// `wiremesh-enforcer-ebpf/program/src/main.rs` don't override), since every
/// fresh trie this file creates must exactly match what the outer
/// `ArrayOfMaps`'s BTF-derived template expects (`map_meta_equal`, enforced
/// by the kernel on every `ArrayOfMaps::set`).
const BPF_F_NO_PREALLOC: u32 = 1;

/// Minimum time an outer-array slot must sit inactive before a later
/// `apply()` is allowed to overwrite it with a fresh generation (design §6:
/// "grace period: 10s after flip, then the old generation's maps are
/// deleted"). See [`GenerationState::pending_reap`] and
/// [`apply_generation`]'s "reap-on-next-apply" wait below.
const REAP_GRACE: Duration = Duration::from_secs(10);

const PINNED_MAPS: [&str; 7] =
    ["COUNTERS", "ACTIVE", "GEN_SRC", "GEN_DST", "GEN_RULES", "GEN_META", "FLOWS"];

/// The live eBPF backend: one loaded+attached [`Ebpf`] instance per
/// `probe()` call, kept alive for the lifetime of the boxed [`Enforcer`].
/// Unlike the spike's separate `enforcer`/`enforcer stats` CLI processes,
/// every [`Enforcer`] method here operates directly on this in-process
/// handle — map pinning (below) is therefore best-effort, for external
/// tooling (a later `fabricctl`/stats path), not required for this type's
/// own correctness.
///
/// **Verified teardown-on-drop contract** (Task 7 review finding,
/// empirically resolved by
/// `tests/ebpf_backend.rs`'s `dropping_enforcer_detaches_and_allows_reprobe_on_same_iface`):
/// `EbpfEnforcer` has no `Drop` impl of its own and discards the `LinkId`s
/// its two tc-classifier `.attach()` calls return, relying entirely on
/// `aya::Ebpf`'s own `Drop` to tear things down when this struct's `ebpf`
/// field is dropped. On this kernel (6.12.x, TCX `bpf_link` attach
/// semantics — design §6), that locking test confirms dropping an
/// `EbpfEnforcer` DOES cleanly detach both tc classifiers: enforcement
/// observably stops (a previously-blocked ping starts succeeding again)
/// once the value goes out of scope, and a subsequent `probe()` on the
/// SAME still-live iface succeeds and re-enforces from scratch. bpffs map
/// pins (if `pin_maps` succeeded) are NOT torn down by this — they persist
/// independently in the kernel until explicitly unpinned or the bpffs
/// mount goes away, which is exactly why `pin_maps`'s own best-effort/
/// non-fatal framing above already treats pin survival as orthogonal to
/// this type's lifetime. Task 8's reload path (drop the current
/// `Enforcer`, `probe()` again) can rely on plain `Drop`/scope-exit for
/// detach; it does not need an explicit unattach/unload step.
pub struct EbpfEnforcer {
    ebpf: Ebpf,
    #[allow(dead_code)] // not yet consumed: idle timeouts/rate caps/log
    // sampling aren't wired into the eBPF maps in this task (the spike's
    // FLOWS table is a fixed 65536-entry LruHashMap with no idle-eviction
    // or rate-limiting logic yet) -- kept here so a later task can read it
    // back without changing `probe`'s signature again.
    cfg: EnforcerConfig,
    /// Task 8 map-in-map generation bookkeeping (idx→`rule_id` mapping for
    /// `counters()`, and the pending-reap grace-period tracker for
    /// `apply()`) — see [`GenerationState`].
    gen: GenerationState,
}

/// Per-[`EbpfEnforcer`] state that has nothing to do with the loaded
/// [`Ebpf`] object itself: which flattened rule idx maps to which
/// `rule_id` (for [`EbpfEnforcer::counters`]), and whether the OTHER outer-
/// array slot is still within its post-flip reap grace (for
/// [`apply_generation`]).
#[derive(Default)]
struct GenerationState {
    /// `idx_to_rule_id[i]` is the `rule_id` of the flattened rule installed
    /// at `COUNTERS[i]`/`RULES[i]` in the CURRENTLY active generation (as of
    /// the last successful `apply()`). Multiple flattened idxs (one per
    /// port-range explosion) can share the same `rule_id` — see
    /// `flatten.rs`'s doc comment — `counters()` sums across all of them.
    idx_to_rule_id: Vec<String>,
    /// `None` before the first `apply()` — at that point neither outer-
    /// array slot has ever been written by us, so there is nothing to wait
    /// on. `Some` after every subsequent flip.
    pending_reap: Option<PendingReap>,
}

/// The outer-array slot a flip just vacated, and when. `apply()`'s `target`
/// (`1 - active_now`) always equals exactly this slot on the NEXT call — our
/// two slots strictly alternate under our own sole control — so a single
/// `Option<PendingReap>` (not one per map) is enough to gate every
/// subsequent `apply()`.
struct PendingReap {
    slot: u32,
    flipped_at: Instant,
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

        Ok(Self { ebpf, cfg, gen: GenerationState::default() })
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
        apply_generation(&mut self.ebpf, &flat, &mut self.gen)
    }

    /// Real (Task 8): reads the 258-entry `COUNTERS` array. `by_rule`
    /// aggregates `COUNTERS[0..len)` by `rule_id`, using the idx→`rule_id`
    /// mapping retained from the last successful `apply()` — see
    /// [`GenerationState::idx_to_rule_id`]. `default_deny` reads
    /// `COUNTERS[MAX_RULES]` (256).
    fn counters(&mut self) -> Result<Counters> {
        let counters: Array<&MapData, u64> =
            Array::try_from(self.ebpf.map("COUNTERS").context("COUNTERS")?)?;
        let default_deny = counters.get(&CTR_DEFAULT_DENY, 0).unwrap_or(0);
        let mut by_rule: BTreeMap<String, u64> = BTreeMap::new();
        for (idx, rule_id) in self.gen.idx_to_rule_id.iter().enumerate() {
            let c = counters.get(&(idx as u32), 0).unwrap_or(0);
            if c > 0 {
                *by_rule.entry(rule_id.clone()).or_insert(0) += c;
            }
        }
        Ok(Counters { by_rule, default_deny })
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

fn proto_num(p: &IrProto) -> u32 {
    match p {
        IrProto::Tcp => 6,
        IrProto::Udp => 17,
        IrProto::Icmp => 1,
        IrProto::Any => 0,
    }
}

/// Builds this generation's [`RuleMeta`] table (in flattened-idx order) and
/// the parallel idx→`rule_id` mapping [`GenerationState::idx_to_rule_id`]
/// retains for `counters()`. CIDR matching lives entirely in the LPM tries
/// now (see [`build_lpm_entries`]) — a [`RuleMeta`] only needs what's left:
/// action + proto/port.
fn build_rules(flat: &[FlatRule]) -> (Vec<RuleMeta>, Vec<String>) {
    let mut rules = Vec::with_capacity(flat.len());
    let mut ids = Vec::with_capacity(flat.len());
    for f in flat {
        let action = match f.action {
            IrAction::Allow => ACT_ALLOW,
            IrAction::Deny => ACT_DENY,
        };
        rules.push(RuleMeta {
            action,
            proto: proto_num(&f.proto),
            port_lo: f.port_lo,
            port_hi: f.port_hi,
        });
        ids.push(f.rule_id.clone());
    }
    (rules, ids)
}

/// Which side of each [`FlatRule`] to read — parameterizes
/// [`build_lpm_entries`] so it isn't duplicated for src vs. dst.
#[derive(Clone, Copy)]
enum Side {
    Src,
    Dst,
}

fn side_cidrs<'a>(f: &'a FlatRule, side: Side) -> &'a [Ipv4Net] {
    match side {
        Side::Src => &f.src_cidrs,
        Side::Dst => &f.dst_cidrs,
    }
}

/// Builds this side's LPM entries per the Task 8 brief's cumulative-bitset
/// contract: one entry per DISTINCT CIDR appearing across every
/// [`FlatRule`]'s CIDR list on this side; each entry's stored bitset is the
/// UNION of every rule's bit whose OWN CIDR (on this side) covers (⊇) that
/// distinct CIDR — not just the rule(s) inserted at that exact CIDR. This is
/// what lets the kernel's LPM longest-prefix-match lookup still hand back
/// every COVERING rule's bit (not only the narrowest inserted prefix's bit),
/// so a bounded first-match scan over `RULES[0..len)` — not raw LPM
/// longest-prefix-wins — decides the verdict. (The reverse-order
/// discriminator test in `tests/generations.rs`,
/// `lpm_cumulative_bitset_first_match_allows_narrow_host_via_earlier_wide_allow_despite_later_deny_carve_out`,
/// is the canary: a naive non-cumulative implementation would pass the
/// brief's literal (c) test but fail this one.)
///
/// O(distinct * n), both bounded by `MAX_RULES` (256) — fine at this scale
/// per the brief.
fn build_lpm_entries(flat: &[FlatRule], side: Side) -> Vec<(Ipv4Net, RuleBits)> {
    let mut distinct: Vec<Ipv4Net> = Vec::new();
    for f in flat {
        for c in side_cidrs(f, side) {
            if !distinct.contains(c) {
                distinct.push(*c);
            }
        }
    }

    distinct
        .into_iter()
        .map(|p| {
            let mut bits: RuleBits = [0u64; BITSET_WORDS];
            for f in flat {
                if side_cidrs(f, side).iter().any(|c| c.contains(&p)) {
                    bit_set(&mut bits, f.idx);
                }
            }
            (p, bits)
        })
        .collect()
}

/// Creates one FRESH standalone LPM trie (matching the kernel-declared
/// `SrcTrie`/`DstTrie` type's `max_entries`/flags exactly, see
/// [`BPF_F_NO_PREALLOC`]'s doc comment) and inserts `entries` into it. The
/// trie's raw key data is `u64`, not `u32` — see `program/src/main.rs`'s
/// `SrcTrie`/`DstTrie` doc comment for why (kernel LPM alignment
/// constraint: `size_of::<K>()` must be a multiple of `align_of::<RuleBits>()`
/// == 8). The zero-extended `u32` (`u32::from(net.network()).to_be() as
/// u64`) leaves the meaningful 4 bytes as the trie's first 4 data bytes on
/// this little-endian host, which is all LPM prefix matching (never past
/// `prefix_len` <= 32 bits) ever examines.
fn build_trie(entries: &[(Ipv4Net, RuleBits)]) -> Result<LpmTrie<MapData, u64, RuleBits>> {
    let mut trie: LpmTrie<MapData, u64, RuleBits> =
        LpmTrie::create(LPM_MAX_ENTRIES as u32, BPF_F_NO_PREALLOC)
            .context("creating fresh LPM trie")?;
    for (net, bits) in entries {
        let key = LpmKey::new(
            net.prefix_len() as u32,
            u32::from(net.network()).to_be() as u64,
        );
        trie.insert(&key, bits, 0)?;
    }
    Ok(trie)
}

/// Creates this generation's four fresh inner maps and installs them into
/// `target`'s slot on all four outer `GEN_*` arrays (Task 8 brief step 2:
/// "Create fresh inner maps, fill them, install into all 4 outer slots at
/// index `target`"). Does NOT touch `ACTIVE` — the caller flips that
/// separately, as the single atomic step.
fn install_generation(
    ebpf: &mut Ebpf,
    target: u32,
    src_entries: &[(Ipv4Net, RuleBits)],
    dst_entries: &[(Ipv4Net, RuleBits)],
    rules: &[RuleMeta],
) -> Result<()> {
    let src_trie = build_trie(src_entries).context("building fresh SRC LPM trie")?;
    let dst_trie = build_trie(dst_entries).context("building fresh DST LPM trie")?;

    let mut rules_arr: Array<MapData, RuleMeta> =
        Array::create(MAX_RULES as u32, 0).context("creating fresh RULES array")?;
    for (i, r) in rules.iter().enumerate() {
        rules_arr.set(i as u32, r, 0)?;
    }

    let mut meta_arr: Array<MapData, u32> =
        Array::create(1, 0).context("creating fresh META array")?;
    meta_arr.set(0, rules.len() as u32, 0)?;

    {
        let mut outer: ArrayOfMaps<&mut MapData, LpmTrie<MapData, u64, RuleBits>> =
            ebpf.map_mut("GEN_SRC").context("GEN_SRC")?.try_into()?;
        outer.set(target, &src_trie, 0)?;
    }
    {
        let mut outer: ArrayOfMaps<&mut MapData, LpmTrie<MapData, u64, RuleBits>> =
            ebpf.map_mut("GEN_DST").context("GEN_DST")?.try_into()?;
        outer.set(target, &dst_trie, 0)?;
    }
    {
        let mut outer: ArrayOfMaps<&mut MapData, Array<MapData, RuleMeta>> =
            ebpf.map_mut("GEN_RULES").context("GEN_RULES")?.try_into()?;
        outer.set(target, &rules_arr, 0)?;
    }
    {
        let mut outer: ArrayOfMaps<&mut MapData, Array<MapData, u32>> =
            ebpf.map_mut("GEN_META").context("GEN_META")?.try_into()?;
        outer.set(target, &meta_arr, 0)?;
    }

    Ok(())
}

/// Builds a fresh generation from `flat` and installs it via a single
/// atomic `ACTIVE` flip (graduated in spirit from Task 7's
/// `apply_flat_rules`, now driving map-in-map generations instead of a
/// fixed-capacity A/B `Array<Rule>` pair — see this file's module doc and
/// the Task 8 brief).
///
/// Reap-on-next-apply (brief: "reap-on-next-apply + minimum 10s since flip
/// is the implementation: if the next apply comes sooner, it waits out the
/// remainder"): `target` (`1 - active_now`) is always exactly the slot the
/// PREVIOUS `apply()` flipped away from (our two slots strictly alternate
/// under our own sole control, so there's only ever one "pending reap" at a
/// time) — before overwriting it with the new generation's fresh maps, wait
/// out whatever remains of the 10s grace since that flip. In production use
/// (`apply()` calls spaced more than 10s apart) this is a no-op; back-to-back
/// rapid re-applies (exercised deliberately by
/// `tests/generations.rs`'s `atomic_generation_flip_under_continuous_udp_traffic_has_zero_deficit`)
/// serialize on this wait instead of ever installing/flipping to a
/// still-possibly-in-use generation's slot.
fn apply_generation(ebpf: &mut Ebpf, flat: &[FlatRule], gen: &mut GenerationState) -> Result<()> {
    let active_now: u32 = {
        let a: Array<&MapData, u32> = Array::try_from(ebpf.map("ACTIVE").context("ACTIVE")?)?;
        a.get(&0, 0)?
    };
    let target = 1 - active_now;

    if let Some(pending) = &gen.pending_reap {
        debug_assert_eq!(
            pending.slot, target,
            "outer-array slots must strictly alternate under apply()'s own sole control"
        );
        let elapsed = pending.flipped_at.elapsed();
        if elapsed < REAP_GRACE {
            std::thread::sleep(REAP_GRACE - elapsed);
        }
    }

    let (rules, idx_to_rule_id) = build_rules(flat);
    let src_entries = build_lpm_entries(flat, Side::Src);
    let dst_entries = build_lpm_entries(flat, Side::Dst);

    install_generation(ebpf, target, &src_entries, &dst_entries, &rules)?;

    {
        let mut active: Array<&mut MapData, u32> =
            Array::try_from(ebpf.map_mut("ACTIVE").context("ACTIVE")?)?;
        active.set(0, target, 0)?; // ATOMIC FLIP
    }

    gen.pending_reap = Some(PendingReap { slot: active_now, flipped_at: Instant::now() });
    gen.idx_to_rule_id = idx_to_rule_id;

    Ok(())
}
