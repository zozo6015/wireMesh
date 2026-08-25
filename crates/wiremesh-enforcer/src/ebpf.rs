//! The real eBPF [`crate::Enforcer`] backend — graduated from
//! `spike/enforcer/enforcer/src/main.rs`'s `run()`/`apply_rules()` (Task 7
//! brief), then upgraded in Task 8
//! (`.superpowers/sdd/task-8-brief.md`) to LPM-bitset first-match matching +
//! map-in-map atomic generations, then in Task 9
//! (`.superpowers/sdd/task-9-brief.md`) with a real flow-table idle timeout/
//! per-source rate cap, and in Task 10
//! (`.superpowers/sdd/task-10-brief.md`) with real, sampled
//! [`crate::DenyEvent`] draining (`deny_events`, below) off the kernel
//! program's `DENY_RB` ring buffer. Loads the embedded object built by
//! `build.rs` (from the sibling standalone `wiremesh-enforcer-ebpf`
//! workspace's `program` package), attaches the tc classifier ingress
//! (enforce) + egress (flow-record) on `iface`, then drives
//! [`crate::flatten::flatten`]'s output into a FRESH generation's per-CPU
//! map-in-map tables via a single atomic `ACTIVE` flip.

use crate::flatten::{flatten, DistinctSideCidrs, FlatRule};
use crate::{BackendKind, Counters, DenyEvent, Enforcer, EnforcerConfig};
use anyhow::{bail, Context, Result};
use aya::{
    maps::{
        lpm_trie::{Key as LpmKey, LpmTrie},
        Array, ArrayOfMaps, MapData, RingBuf,
    },
    programs::{tc, SchedClassifier, TcAttachType},
    Ebpf, EbpfLoader,
};
use ipnet::Ipv4Net;
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use wiremesh_enforcer_common::{
    bit_set, DenyEventRaw, FlowKey, FlowVal, RuleBits, RuleMeta, ACT_ALLOW, ACT_DENY, BITSET_WORDS,
    CFG_ICMP_NS, CFG_LOG_AGGREGATE, CFG_LOG_PER_RULE, CFG_RATE_CAP, CFG_TCP_NS, CFG_UDP_NS,
    CTR_DEFAULT_DENY, LPM_MAX_ENTRIES, MAX_RULES,
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
pub(crate) const REAP_GRACE: Duration = Duration::from_secs(10);

const PINNED_MAPS: [&str; 12] = [
    "COUNTERS",
    "ACTIVE",
    "GEN_SRC",
    "GEN_DST",
    "GEN_RULES",
    "GEN_META",
    "FLOWS",
    // Task 9 additions: the per-protocol-idle-timeout/rate-cap config map
    // and the per-source rate-cap bookkeeping map.
    "CONFIG",
    "RATE",
    // Task 10 additions: the deny-event ring buffer and its two log
    // sampling token-bucket maps.
    "DENY_RB",
    "LOG_RULE_BUDGET",
    "LOG_AGG_BUDGET",
];

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
    // Most of this is consumed in `new` below from the LOCAL `cfg`
    // parameter, strictly before this struct exists (Task 9: `flow_max`/
    // `tcp_idle_s`/`udp_idle_s`/`icmp_idle_s`/`rate_cap_per_src`; Task 10:
    // `log_per_rule`/`log_aggregate`) — it was retained purely so a later
    // task could read the effective config back off a live `EbpfEnforcer`
    // without another `probe`/`new` signature change. Backlog item 1 is
    // that task: `apply_ready_at` reads `cfg.reap_grace` on every call,
    // since the grace is now published to the caller rather than slept out
    // internally.
    cfg: EnforcerConfig,
    /// Task 8 map-in-map generation bookkeeping (idx→`rule_id` mapping for
    /// `counters()`, and the pending-reap grace-period tracker for
    /// `apply()`) — see [`GenerationState`].
    gen: GenerationState,
}

/// Per-[`EbpfEnforcer`] state that has nothing to do with the loaded
/// [`Ebpf`] object itself: which flattened rule idx maps to which
/// `rule_id` (for [`EbpfEnforcer::counters`]), whether the OTHER outer-
/// array slot is still within its post-flip reap grace (for
/// [`apply_generation`]), and the accumulated by-`rule_id` counter history
/// folded out of earlier generations' now-repurposed idx slots (see
/// [`fold_and_reset_counters`] — this is the fix for the Task 8 review
/// finding: `COUNTERS` is a flat, generation-independent array indexed by
/// POSITION, so without this, inserting a rule ahead of existing ones
/// shifts every later rule's idx and leaves its accumulated history behind
/// at the old idx, now mislabeled under whichever rule the new generation
/// puts there).
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
    /// Per-`rule_id` hit counts folded out of `COUNTERS[0..old_len)` by
    /// [`fold_and_reset_counters`], called immediately before every
    /// `apply()`'s `ACTIVE` flip (using the OLD, about-to-be-superseded
    /// `idx_to_rule_id` mapping), before that idx range gets zeroed and
    /// re-homed to the new generation's rules. `counters()` sums this with
    /// the CURRENT generation's live `COUNTERS` reads so a rule's total
    /// survives being shifted to a new idx by a later `apply()`, keyed by
    /// its stable `rule_id` rather than its position. [`prune_retired_counters`]
    /// removes an entry the moment its rule_id is no longer present in a
    /// new generation — a rule's counter survives being MOVED, not being
    /// DELETED; this map is bounded at ≤ `MAX_RULES` entries as a result.
    counter_accum: BTreeMap<String, u64>,
    /// Same idea as `counter_accum`, for the single default-deny slot
    /// (`COUNTERS[MAX_RULES]`). Default-deny isn't actually subject to the
    /// positional-shift misattribution (slot `MAX_RULES` always means
    /// "default deny", never repurposed for a rule), but folding it through
    /// the same accumulate-then-zero mechanism keeps the "counters survive
    /// policy updates" guarantee uniform and honest for every counter kind.
    default_deny_accum: u64,
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
        // Task 9 brief: "flow_max: set FLOWS max_entries from
        // EnforcerConfig BEFORE load" -- `EbpfLoader::map_max_entries`
        // overrides the kernel-declared map's default `max_entries` before
        // the map is actually created in the kernel, unlike the per-
        // generation LPM/`Array` maps (which are recreated fresh on every
        // `apply()` via standalone `create` calls, not the loader). Plain
        // `Ebpf::load` (Task 7/8) has no way to express this override, hence
        // the switch to the builder API here.
        let mut ebpf = EbpfLoader::new()
            .map_max_entries("FLOWS", cfg.flow_max)
            .load(aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/wiremesh-enforcer"
            )))
            .context("loading embedded eBPF object")?;

        // Task 9 brief: config must be written BEFORE either classifier
        // attaches, so no packet is ever classified against an unwritten
        // (all-zero) `CONFIG` -- see `write_config`'s own doc comment and
        // `wiremesh_enforcer_common::DEFAULT_TCP_NS`'s doc comment for the
        // kernel-side defense-in-depth fallback on top of this ordering.
        write_config(&mut ebpf, &cfg).context("writing CONFIG map")?;

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

        Ok(Self {
            ebpf,
            cfg,
            gen: GenerationState::default(),
        })
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

/// Writes `EnforcerConfig`'s idle-timeout/rate-cap/log-sampling fields into
/// the kernel's `CONFIG: Array<u64>` map (Task 9 brief: indices `CFG_TCP_NS`/
/// `CFG_UDP_NS`/`CFG_ICMP_NS`/`CFG_RATE_CAP`; Task 10 adds `CFG_LOG_PER_RULE`/
/// `CFG_LOG_AGGREGATE`) — the first three seconds converted to nanoseconds
/// (`bpf_ktime_get_ns()`-comparable, matching `FlowVal::last_seen_ns`'s
/// unit); the rate cap and the two log sampling budgets are already plain
/// per-second counts, written as-is. Called from `EbpfEnforcer::new`,
/// strictly BEFORE either tc classifier is attached, so no packet is ever
/// evaluated (or logged) against an unwritten (all-zero) `CONFIG` — this
/// ordering is the primary guard the Task 9 brief's self-review checklist
/// calls for ("config written before attach so no packet sees zero
/// timeouts"), unchanged in Task 10 for the two new slots; the kernel
/// program's own `cfg_or_default` is a secondary, defense-in-depth fallback
/// on top of it, not a substitute for it.
fn write_config(ebpf: &mut Ebpf, cfg: &EnforcerConfig) -> Result<()> {
    let mut config: Array<&mut MapData, u64> =
        Array::try_from(ebpf.map_mut("CONFIG").context("CONFIG")?)?;
    config.set(CFG_TCP_NS, u64::from(cfg.tcp_idle_s) * 1_000_000_000, 0)?;
    config.set(CFG_UDP_NS, u64::from(cfg.udp_idle_s) * 1_000_000_000, 0)?;
    config.set(CFG_ICMP_NS, u64::from(cfg.icmp_idle_s) * 1_000_000_000, 0)?;
    config.set(CFG_RATE_CAP, u64::from(cfg.rate_cap_per_src), 0)?;
    config.set(CFG_LOG_PER_RULE, u64::from(cfg.log_per_rule), 0)?;
    config.set(CFG_LOG_AGGREGATE, u64::from(cfg.log_aggregate), 0)?;
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
        // Pre-flight, BEFORE apply_generation does any kernel work (trie
        // building, map creation): see `check_lpm_capacity`'s doc.
        check_lpm_capacity(&flat)?;
        apply_generation(&mut self.ebpf, &flat, &mut self.gen)
    }

    /// `flip instant + reap_grace` while a generation reap is pending;
    /// `None` before the first `apply` (neither outer-array slot has ever
    /// been written by us, so there is nothing to protect and a boot-time
    /// apply must never be made to wait). Every flip republishes this off
    /// ITS OWN `flipped_at`, so a caller honoring it is serialized at
    /// exactly one grace per generation and can never have a stale,
    /// already-satisfied deadline authorize overwriting a slot vacated
    /// moments ago.
    fn apply_ready_at(&self) -> Option<Instant> {
        self.gen
            .pending_reap
            .as_ref()
            .map(|p| p.flipped_at + self.cfg.reap_grace)
    }

    /// Real (Task 8, fixed post-review): reads the 258-entry `COUNTERS`
    /// array and combines it with [`GenerationState::counter_accum`]/
    /// `default_deny_accum` — the history [`fold_and_reset_counters`]
    /// folded out of EARLIER generations' now-repurposed idx slots, keyed
    /// by the stable `rule_id` those slots used to belong to. `by_rule`
    /// therefore reflects a rule's FULL history across `apply()` calls,
    /// not just whatever raw count currently sits at its (possibly brand
    /// new, possibly reused-from-a-different-rule) current idx.
    ///
    /// **Survival semantics** (re-review finding, coordinator-relayed):
    /// this survival guarantee is for rules PRESENT in the current policy
    /// across an `apply()` — a rule whose idx moves keeps its history. It
    /// is NOT a promise that a REMOVED rule's history is kept forever:
    /// [`prune_retired_counters`] drops a `counter_accum` entry the moment
    /// its `rule_id` no longer appears in the applied policy, so
    /// `by_rule` never reports a stale entry for a rule that's gone —
    /// consistent with nft named-counter semantics, where a counter tied
    /// to a deleted rule doesn't outlive it.
    fn counters(&mut self) -> Result<Counters> {
        let counters: Array<&MapData, u64> =
            Array::try_from(self.ebpf.map("COUNTERS").context("COUNTERS")?)?;
        // (Review finding) Propagate a real map-read error instead of
        // swallowing it as `0` — "counters always count" means a read
        // failure here must surface, not silently under-report.
        let live_default_deny = counters
            .get(&CTR_DEFAULT_DENY, 0)
            .context("reading CTR_DEFAULT_DENY from COUNTERS")?;
        let default_deny = self.gen.default_deny_accum + live_default_deny;

        let mut by_rule: BTreeMap<String, u64> = self.gen.counter_accum.clone();
        for (idx, rule_id) in self.gen.idx_to_rule_id.iter().enumerate() {
            let c = counters
                .get(&(idx as u32), 0)
                .with_context(|| format!("reading COUNTERS[{idx}] for rule {rule_id}"))?;
            if c > 0 {
                *by_rule.entry(rule_id.clone()).or_insert(0) += c;
            }
        }
        Ok(Counters {
            by_rule,
            default_deny,
        })
    }

    /// Minimal-real (Task 7 brief): clears every entry in `FLOWS`, forcing
    /// every subsequent packet to be re-evaluated against the current rule
    /// set rather than fast-pathing on a stale recorded flow.
    fn flush_flows(&mut self) -> Result<()> {
        // `FLOWS` is a `BPF_MAP_TYPE_LRU_HASH` (the eBPF program's
        // `LruHashMap<FlowKey, FlowVal>` as of Task 9 -- was `LruHashMap<
        // FlowKey, u64>` pre-Task-9); on the userspace side aya represents
        // both plain and LRU hash maps with the same `aya::maps::HashMap`
        // type (`Map::LruHashMap` and `Map::HashMap` both convert into it) —
        // there is no separate `aya::maps::LruHashMap` type to name here.
        let mut flows: aya::maps::HashMap<&mut MapData, FlowKey, FlowVal> =
            aya::maps::HashMap::try_from(self.ebpf.map_mut("FLOWS").context("FLOWS")?)?;
        let keys: Vec<FlowKey> = flows.keys().collect::<Result<_, _>>()?;
        for k in keys {
            match flows.remove(&k) {
                Ok(()) => {}
                // Benign: `FLOWS` is `BPF_MAP_TYPE_LRU_HASH`, so the kernel
                // can concurrently evict this exact entry between the
                // `keys()` snapshot above and this `remove` -- that surfaces
                // as `bpf_map_delete_elem` failing ENOENT, not a real flush
                // failure (the entry is gone either way, which is the goal).
                Err(aya::maps::MapError::SyscallError(aya::sys::SyscallError {
                    io_error, ..
                })) if io_error.raw_os_error() == Some(libc::ENOENT) => {}
                Err(e) => {
                    return Err(e).context("removing FLOWS entry during flush_flows");
                }
            }
        }
        Ok(())
    }

    /// Real (Task 10): non-blockingly drains every `DenyEventRaw` currently
    /// sitting in `DENY_RB` (`program/src/main.rs`'s sampled deny-event ring
    /// buffer, populated by `maybe_emit_deny` on the deny verdict path,
    /// AFTER that path's counter bump — design §5.3) into the public
    /// [`DenyEvent`] shape.
    ///
    /// **Generation-boundary rule_id mapping (self-review, documented per
    /// the brief's explicit prompt to pick one):** `rule_idx` -> `rule_id`
    /// is resolved via `self.gen.idx_to_rule_id`, i.e. whatever generation
    /// is CURRENT at the moment `deny_events()` is called — not whatever
    /// generation was active at the moment the event was actually emitted
    /// in the kernel. Unlike `counters()` (which Task 8's post-review fix
    /// makes fold history across `apply()` calls specifically so a rule's
    /// count is never lost or misattributed), a `DenyEvent` is a point-in-
    /// time sample, not an accumulating total, and the design's own
    /// sampling philosophy already accepts dropped/imprecise volume as a
    /// trade-off for bounded cost. So the accepted, documented race here is
    /// narrower and cheaper to reason about than an event-tagging scheme
    /// would be: an event emitted by the OLD generation but drained after a
    /// later `apply()` has already flipped and overwritten
    /// `idx_to_rule_id` can report the WRONG `rule_id` (either `None`, if
    /// the new generation has fewer rules than `rule_idx`, or -- rarely --
    /// a different rule's `id`, if the new generation happens to reuse that
    /// same idx for an unrelated rule) rather than the rule that actually
    /// matched at emission time. This is deliberately not "fixed" the way
    /// `counters()` was: doing so would require either tagging every event
    /// with its own generation number (a `DenyEventRaw` field this task's
    /// binding design doesn't call for) or snapshotting/retaining every past
    /// generation's mapping indefinitely (unbounded memory, the same
    /// problem `prune_retired_counters` exists to avoid for `counter_accum`).
    /// In practice this window is both rare (bounded by how long events can
    /// sit undrained across an `apply()`) and low-stakes (deny events are a
    /// monitoring/alerting aid, not a security-relevant total), so it is
    /// accepted and documented rather than engineered away, consistent with
    /// this design's other small, bounded, well-understood races (e.g.
    /// `fold_and_reset_counters`'s own accepted undercount window).
    fn deny_events(&mut self) -> Result<Vec<DenyEvent>> {
        let mut rb: RingBuf<&mut MapData> =
            RingBuf::try_from(self.ebpf.map_mut("DENY_RB").context("DENY_RB")?)?;

        let mut events = Vec::new();
        while let Some(item) = rb.next() {
            if item.len() != std::mem::size_of::<DenyEventRaw>() {
                // Malformed/mis-sized entry (shouldn't happen -- the kernel
                // program only ever writes exactly-sized `DenyEventRaw`
                // records via `RingBuf::output`) -- skip rather than panic
                // or misinterpret adjacent bytes.
                continue;
            }
            // SAFETY: length checked above; `DenyEventRaw` is `#[repr(C)]`,
            // `Copy`, and has no invalid bit patterns for any of its plain
            // integer fields, so reading an unaligned copy out of the ring
            // buffer's byte slice (which the kernel guarantees contains
            // exactly one `DenyEventRaw`'s worth of bytes, written via
            // `RingBuf::output(&ev, 0)` on the kernel side) is sound.
            let raw: DenyEventRaw =
                unsafe { std::ptr::read_unaligned(item.as_ptr().cast::<DenyEventRaw>()) };

            let rule_id = if raw.rule_idx == CTR_DEFAULT_DENY {
                None
            } else {
                self.gen.idx_to_rule_id.get(raw.rule_idx as usize).cloned()
            };

            events.push(DenyEvent {
                // `raw.src`/`raw.dst` are the same raw, as-loaded
                // representation `FlowKey`'s identically-documented fields
                // use (network byte order, not host-order-correct as a bare
                // integer) -- `u32::from_be` undoes the same transformation
                // `build_trie`'s userspace side already applies in the
                // other direction (`u32::from(net.network()).to_be()`) for
                // this exact raw wire format.
                src: Ipv4Addr::from(u32::from_be(raw.src)),
                dst: Ipv4Addr::from(u32::from_be(raw.dst)),
                proto: raw.proto,
                dport: u16::from_be(raw.dport),
                rule_id,
            });
        }
        Ok(events)
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

/// The DISTINCT CIDRs appearing across every [`FlatRule`]'s CIDR list on
/// `side`, in first-appearance order — exactly the set of LPM-trie entries
/// [`build_lpm_entries`] produces (which delegates its dedup here) and
/// therefore exactly what [`check_lpm_capacity`] must count: the two are
/// factored onto this ONE helper so the pre-check and the trie build can
/// never drift apart (Backlog 10 PR-A Item 1).
fn distinct_side_cidrs(flat: &[FlatRule], side: Side) -> Vec<Ipv4Net> {
    accumulate_side(flat, side).into_vec()
}

/// Folds `flat`'s `side` lists into the shared [`DistinctSideCidrs`]
/// accumulator — the single place this crate decides what "distinct" means,
/// so [`distinct_side_cidrs`] (which produces the real trie keys) and
/// [`check_lpm_capacity`] (which vets them) are the same computation, and
/// `flatten`'s incremental guard is that same computation again.
fn accumulate_side(flat: &[FlatRule], side: Side) -> DistinctSideCidrs {
    let mut acc = DistinctSideCidrs::default();
    for f in flat {
        acc.observe(side_cidrs(f, side));
    }
    acc
}

// The compile-time (wiremesh-policy) and load-time (this crate) halves of
// the LPM-capacity guard must fix the SAME number — the duplicated-constant
// contract `MAX_RULES` already follows (see `wiremesh-policy`'s
// `compile.rs`: that crate cannot depend on the enforcer crates, so the
// constant is duplicated, and parity is asserted where the dependency
// direction allows: here, and in `tests/lpm_capacity.rs`).
const _: () = assert!(
    wiremesh_policy::MAX_LPM_CIDRS_PER_SIDE == LPM_MAX_ENTRIES,
    "wiremesh_policy::MAX_LPM_CIDRS_PER_SIDE must equal wiremesh_enforcer_common::LPM_MAX_ENTRIES"
);

/// Pre-insert LPM-capacity check (Backlog 10 PR-A Item 1, the enforcer's
/// load-time half of `wiremesh_policy::MAX_LPM_CIDRS_PER_SIDE`'s
/// compile-time guard): `Ok(())` iff BOTH sides' distinct-CIDR counts — the
/// exact per-side entry counts [`build_lpm_entries`] would produce, via the
/// shared [`distinct_side_cidrs`] helper — fit in the eBPF trie's
/// `LPM_MAX_ENTRIES` (1024). Consulted by the eBPF `apply()` path BEFORE
/// any trie is built, so an oversized policy fails with a clear, named
/// error instead of the opaque `trie.insert` failure entry #1025 used to
/// hit deep inside `apply_generation`. Pure and unprivileged (like
/// [`crate::flatten`]) — the enforcer consumes IR off the wire and must not
/// trust that whatever compiled it upstream enforced any limit.
pub fn check_lpm_capacity(flat: &[FlatRule]) -> anyhow::Result<()> {
    for (side, name) in [(Side::Src, "src"), (Side::Dst, "dst")] {
        accumulate_side(flat, side).check(name)?;
    }
    Ok(())
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
/// O(distinct * n) for the bitset pass below, with n (flat rules) bounded
/// by `MAX_RULES` (256) and distinct (per-side CIDRs) by `LPM_MAX_ENTRIES`
/// (1024) — `apply()` runs [`check_lpm_capacity`] before this is reached,
/// so an over-capacity wire policy fails the cheap pre-check and never
/// pays (or overflows) this pass. Fine at this scale.
fn build_lpm_entries(flat: &[FlatRule], side: Side) -> Vec<(Ipv4Net, RuleBits)> {
    distinct_side_cidrs(flat, side)
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

/// Folds `COUNTERS[0..reset_len)` (`reset_len = max(old_len, new_len)`,
/// where `old_len`/`new_len` are the CURRENT and NEXT generations'
/// flattened rule counts) into `gen.counter_accum`, keyed by the OLD
/// (about-to-be-superseded) `idx_to_rule_id` mapping, then zeroes each
/// slot — and does the same for the single default-deny slot into
/// `gen.default_deny_accum`. Must run BEFORE `gen.idx_to_rule_id` is
/// overwritten for the new generation.
///
/// This is the fix for a Task 8 review finding: `COUNTERS` is a flat,
/// generation-independent `Array<u64>` indexed by each rule's FLATTENED
/// POSITIONAL idx, and nothing previously reset those slots across
/// `apply()` calls. Inserting a new rule ahead of existing ones shifts
/// every later rule's idx — without this fold, an existing rule's
/// already-accumulated hit count would be left behind at its OLD idx, now
/// silently mislabeled under whichever rule the NEW generation happens to
/// place there (`tests/generations.rs`'s
/// `counters_survive_rule_insertion_keyed_by_rule_id` is the regression
/// test). Folding into an accumulator keyed by the stable `rule_id` (a
/// content hash independent of position, see
/// `wiremesh_policy::compile::rule_id`) instead makes a rule's counter
/// survive being re-homed to a different idx, and guarantees a BRAND NEW
/// rule that happens to land on a busy old idx starts at 0 rather than
/// inheriting that idx's history.
///
/// `reset_len` extends past `old_len` up to `new_len` when the new
/// generation has MORE rules than the old one: any stale, non-zero value
/// sitting at those higher idxs (left over from some even-older, since-
/// shrunk generation, well before `old_len`'s current mapping existed) has
/// no valid `rule_id` in the OLD mapping to attribute to, so it's simply
/// dropped rather than misattributed — this loop zeroes it either way, so
/// it can't leak into whatever new rule the CURRENT `apply()` assigns to
/// that idx.
///
/// **Call-site timing is load-bearing** (re-review finding, coordinator-
/// relayed): this must run AFTER `install_generation` succeeds and
/// IMMEDIATELY before the `ACTIVE` flip — not at the top of `apply()`,
/// before `install_generation` runs. `ACTIVE` still points at the OLD
/// generation for this whole function's duration (the flip hasn't
/// happened yet), so a packet can still match the old generation's rule at
/// idx `i` and increment `COUNTERS[i]` at any point before this function
/// zeroes it. Running this fold BEFORE `install_generation` (the original,
/// since-corrected placement) left that window open for
/// `install_generation`'s ENTIRE duration — standalone LPM trie/`Array`
/// creation and population, which scales with policy size, not a fixed
/// cost — during which any such hit would survive the zeroing (since it
/// happened after) and then, once `gen.idx_to_rule_id` is published to the
/// NEW mapping and the flip completes, get silently MISATTRIBUTED to
/// whatever new rule `counters()` finds at that same idx — worse than a
/// mere undercount. Calling this immediately before the flip instead (with
/// `gen.idx_to_rule_id` only overwritten to the new mapping AFTER the flip,
/// in `apply_generation`) bounds the exposure to this function's OWN
/// O(`reset_len`) duration (a fixed-size loop over map reads/writes, not
/// install cost) plus the single subsequent `ACTIVE` write: for the LAST
/// slot this loop touches, the residual window really is just that one
/// flip write; for earlier slots in the loop, it's that same flip write
/// plus whatever loop iterations remain after them — still bounded and
/// small, never install-cost-sized.
///
/// **Known, accepted, bounded race** (documented per the coordinator's
/// review, now describing the ACTUAL residual window above rather than
/// overstating a single read+write in isolation): a packet landing in that
/// window increments a just-zeroed slot whose OLD meaning has already been
/// folded away; that increment is lost rather than folded — an accepted
/// undercount, not eliminated, matching the design's existing "10s reap
/// grace" tolerance for similarly small in-flight windows elsewhere in
/// this same atomic-flip design. The read-then-immediate-zero-per-slot
/// loop below (rather than reading the whole range then zeroing the whole
/// range) keeps this as tight as the mechanism allows.
fn fold_and_reset_counters(
    ebpf: &mut Ebpf,
    gen: &mut GenerationState,
    new_len: usize,
) -> Result<()> {
    let old_len = gen.idx_to_rule_id.len();
    let reset_len = old_len.max(new_len).min(MAX_RULES);

    let mut counters: Array<&mut MapData, u64> =
        Array::try_from(ebpf.map_mut("COUNTERS").context("COUNTERS")?)?;

    for idx in 0..reset_len {
        let idx_u32 = idx as u32;
        let val = counters.get(&idx_u32, 0).unwrap_or(0);
        if val > 0 {
            counters.set(idx_u32, 0u64, 0)?; // zero immediately: minimize the read-to-zero window
            if idx < old_len {
                *gen.counter_accum
                    .entry(gen.idx_to_rule_id[idx].clone())
                    .or_insert(0) += val;
            }
            // idx >= old_len: stale value from an even-older generation,
            // with no rule_id in the OLD mapping to attribute it to --
            // already zeroed above, intentionally dropped rather than
            // misattributed to whatever new rule lands on this idx.
        }
    }

    let dd = counters.get(&CTR_DEFAULT_DENY, 0).unwrap_or(0);
    if dd > 0 {
        counters.set(CTR_DEFAULT_DENY, 0u64, 0)?;
        gen.default_deny_accum += dd;
    }

    Ok(())
}

/// Drops every `gen.counter_accum` entry whose `rule_id` is NOT present in
/// `new_idx_to_rule_id` (the mapping about to become live) — a rule
/// removed entirely from the policy stops appearing in `counters().by_rule`
/// rather than keeping an ever-stale counter around forever.
///
/// Task 8 re-review finding (coordinator-relayed, RED-locked by
/// `tests/generations.rs`'s `counters_for_removed_rules_are_pruned_at_apply`):
/// [`fold_and_reset_counters`] makes a rule's counter survive being
/// RE-HOMED to a different idx across an `apply()`, but `counter_accum`
/// itself was never pruned, so a rule that's REMOVED entirely kept
/// accumulating a phantom entry forever — unbounded growth over a
/// gateway's whole policy-edit history, and a deleted rule's counter
/// staying visible indefinitely. This is consistent with nft named-counter
/// semantics (a counter tied to a deleted rule doesn't outlive it) and
/// doesn't weaken the survival guarantee: that guarantee only ever covers
/// rules PRESENT in the current policy across an update (their counter
/// must not reset just because their idx moved), never a promise that a
/// deleted rule's history is kept forever. `default_deny_accum` is never
/// pruned — it isn't tied to any specific rule_id, so it's always current
/// by construction.
///
/// Call this AFTER `fold_and_reset_counters` (so a just-removed rule's
/// final pre-removal count is folded in first) and it bounds
/// `counter_accum` at ≤ `MAX_RULES` entries (one per rule_id that could
/// possibly exist in `new_idx_to_rule_id`, which itself never exceeds
/// `MAX_RULES`).
fn prune_retired_counters(gen: &mut GenerationState, new_idx_to_rule_id: &[String]) {
    let live: std::collections::BTreeSet<&str> =
        new_idx_to_rule_id.iter().map(String::as_str).collect();
    gen.counter_accum
        .retain(|rule_id, _| live.contains(rule_id.as_str()));
}

/// Builds a fresh generation from `flat` and installs it via a single
/// atomic `ACTIVE` flip (graduated in spirit from Task 7's
/// `apply_flat_rules`, now driving map-in-map generations instead of a
/// fixed-capacity A/B `Array<Rule>` pair — see this file's module doc and
/// the Task 8 brief).
///
/// Reap-on-next-apply: `target` (`1 - active_now`) is always exactly the
/// slot the PREVIOUS `apply()` flipped away from (our two slots strictly
/// alternate under our own sole control, so there's only ever one "pending
/// reap" at a time), and overwriting it with the new generation's fresh maps
/// is only safe once `reap_grace` has elapsed since that flip.
///
/// **This function no longer WAITS for that (Backlog item 1).** It used to
/// `std::thread::sleep` out the remainder of the grace right here. In the
/// gateway that thread is a tokio runtime thread inside the Sync loop
/// (`main.rs`'s `apply_state` → `GatewayEnforcer::apply_if_changed` → here),
/// so a single policy epoch parked the loop for up to 10s — delaying
/// `PunchDirective` servicing past the Cycle-4b go-skew budget, starving the
/// metrics scrape behind the enforcer-map lock, and costing N × 10s with
/// several live epochs during a rotation overlap. The grace did not
/// disappear, it MOVED: [`EbpfEnforcer::apply_ready_at`] publishes
/// `flipped_at + reap_grace` and the caller waits it out asynchronously
/// (`wiremesh_gateway::policy_apply`). Test callers that flip back-to-back
/// must now honor it themselves — see `wiremesh-testkit`'s
/// `flip_under_traffic_zero_loss`.
fn apply_generation(ebpf: &mut Ebpf, flat: &[FlatRule], gen: &mut GenerationState) -> Result<()> {
    let active_now: u32 = {
        let a: Array<&MapData, u32> = Array::try_from(ebpf.map("ACTIVE").context("ACTIVE")?)?;
        a.get(&0, 0)?
    };
    let target = 1 - active_now;

    if let Some(pending) = &gen.pending_reap {
        // Deliberately NO wait here (Backlog item 1) — see this function's
        // doc comment. The remaining invariant this block still guards is
        // the alternation `apply_ready_at`'s single-`PendingReap` model
        // depends on.
        debug_assert_eq!(
            pending.slot, target,
            "outer-array slots must strictly alternate under apply()'s own sole control"
        );
    }

    let (rules, idx_to_rule_id) = build_rules(flat);
    let src_entries = build_lpm_entries(flat, Side::Src);
    let dst_entries = build_lpm_entries(flat, Side::Dst);

    install_generation(ebpf, target, &src_entries, &dst_entries, &rules)?;

    // Fold the CURRENT (about-to-be-superseded, but STILL ACTIVE until the
    // flip a few lines below) generation's per-idx counters into `gen`'s
    // stable-by-rule_id accumulators, zero those slots, then prune any
    // accumulator entry for a rule_id that isn't in the NEW mapping (a
    // removed rule's history is dropped, not kept forever — see
    // `prune_retired_counters`'s doc comment). Deliberately placed HERE —
    // immediately before the flip, after `install_generation` has already
    // done its (policy-size-dependent, non-trivial) work — rather than at
    // the top of this function: see `fold_and_reset_counters`'s doc comment
    // for why call-site timing is load-bearing (a re-review finding). Both
    // calls use `gen.idx_to_rule_id`, which still holds the OLD mapping —
    // it is deliberately NOT overwritten to `idx_to_rule_id` (the new
    // mapping) until after the flip below.
    fold_and_reset_counters(ebpf, gen, flat.len())?;
    prune_retired_counters(gen, &idx_to_rule_id);

    {
        let mut active: Array<&mut MapData, u32> =
            Array::try_from(ebpf.map_mut("ACTIVE").context("ACTIVE")?)?;
        active.set(0, target, 0)?; // ATOMIC FLIP
    }

    gen.pending_reap = Some(PendingReap {
        slot: active_now,
        flipped_at: Instant::now(),
    });
    gen.idx_to_rule_id = idx_to_rule_id; // published only now, AFTER the flip

    Ok(())
}
