#![no_std]

// Graduated verbatim from `spike/enforcer/enforcer-common/src/lib.rs`
// (Task 7 brief), extended in Task 8
// (`.superpowers/sdd/task-8-brief.md`) for LPM-bitset first-match matching +
// map-in-map atomic generations: `#[repr(C)]` types and constants shared
// between the eBPF `program` crate and `wiremesh-enforcer`'s userspace
// loader (`ebpf.rs`), which enables the `user` feature to get the
// `aya::Pod` impls below. Kept map/field names as-is per the brief where
// unchanged from Task 7.

/// Max flattened rules per policy — mirrors `wiremesh_enforcer::flatten::MAX_RULES`,
/// kept as an independent constant here per the Task 8 brief's exact
/// `common/src/lib.rs` additions snippet (both crates fixing this number at
/// compile time is exactly the "duplicated/cross-referenced" contract
/// `flatten.rs`'s own doc comment already describes for `wiremesh-policy`'s
/// compile-time guard). Also the entry count of each generation's
/// `RULES`/`META` inner `Array`s and the width of the flattened-idx-keyed
/// portion of `COUNTERS`.
pub const MAX_RULES: usize = 256;

/// Words in a [`RuleBits`] bitset — 4 * 64 = 256 bits, one per [`MAX_RULES`]
/// flattened rule index.
pub const BITSET_WORDS: usize = 4;

/// Max entries in each generation's SRC/DST LPM tries (design's "LPM key:
/// prefixlen+be-u32"). One entry per DISTINCT CIDR appearing across all
/// flattened rules on that side, not one per rule, so this is sized with
/// headroom above [`MAX_RULES`] for segments/rules carrying more than one
/// CIDR each. Shared here (rather than a local constant in each crate) so
/// the kernel-declared trie type and userspace's standalone-created
/// replacement tries always agree — the kernel's `map_meta_equal` check
/// (run on every `ArrayOfMaps::set`, i.e. every `apply()`) rejects an
/// inner map whose `max_entries`/key/value size or flags don't exactly
/// match what the outer map's BTF-derived template declared.
pub const LPM_MAX_ENTRIES: usize = 1024;

/// Generations per map-in-map outer array (the `ACTIVE` index is 0|1) —
/// named for readability at every `GEN_SRC`/`GEN_DST`/`GEN_RULES`/
/// `GEN_META` declaration site and in the userspace atomic-flip logic.
pub const GENERATIONS: usize = 2;

/// `COUNTERS[0..MAX_RULES)` is one counter per flattened rule idx, bumped
/// when that rule is the FIRST match (first-match-wins) for a packet —
/// regardless of whether its action is allow or deny. `COUNTERS[MAX_RULES]`
/// (256) is the default-deny fallback (no rule matched at all).
pub const CTR_DEFAULT_DENY: u32 = MAX_RULES as u32;
/// `COUNTERS[MAX_RULES + 1]` (257) is the flow-hit fast path: any of
/// `try_ingress`'s three FLOWS-fast-path continuations (reverse flow,
/// forward flow, or an ICMP error whose embedded original packet matched a
/// recorded flow). Task 7 tracked these as two separate aggregate counters
/// (`CTR_FLOW_HIT`/`CTR_ICMP_ERR`); Task 8's 258-entry `COUNTERS` layout
/// (brief: "0..256 per flattened idx, 256 default-deny, 257 flow-hit") has
/// room for exactly one flow-continuation slot, so all three call sites
/// share it.
pub const CTR_FLOW_HIT: u32 = (MAX_RULES + 1) as u32;
/// Total `COUNTERS` entries: one per flattened rule idx (`0..MAX_RULES`)
/// plus the two aggregate slots above.
pub const COUNTERS_LEN: usize = MAX_RULES + 2;

pub const ACT_DENY: u32 = 0;
pub const ACT_ALLOW: u32 = 1;

/// One flattened rule's match metadata (Task 8: replaces Task 7's `Rule`,
/// which carried its own src/dst CIDR pair directly — CIDR matching moved
/// to the per-generation LPM tries' cumulative bitsets, so this only needs
/// what's left: action + proto/port). `#[repr(C)]`, `Clone, Copy` per the
/// brief's exact snippet.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RuleMeta {
    pub action: u32,
    pub proto: u32,   // 6 tcp, 17 udp, 1 icmp, 0 any
    pub port_lo: u16, // dst port range, host order; (0, 0) means any
    pub port_hi: u16,
}

/// One bit per flattened rule idx (`0..MAX_RULES`) — `SRC_LPM[src] &
/// DST_LPM[dst]` is this design's cumulative-bitset first-match scan input
/// (design §6 / task-8 brief).
pub type RuleBits = [u64; BITSET_WORDS];

/// Reads bit `idx` of `bits`. `idx >= MAX_RULES` (out of range for the
/// bitset's word count) reads as unset rather than panicking/UB — callers
/// (the kernel's bounded `0..MAX_RULES` scan) never pass such an `idx`, but
/// this keeps the helper total or either caller.
#[inline(always)]
pub fn bit_get(bits: &RuleBits, idx: u32) -> bool {
    let w = (idx as usize) / 64;
    if w >= BITSET_WORDS {
        return false;
    }
    (bits[w] >> (idx % 64)) & 1 != 0
}

/// Sets bit `idx` of `bits` (see [`bit_get`]'s out-of-range note — a no-op
/// past the bitset's word count rather than panicking/UB).
#[inline(always)]
pub fn bit_set(bits: &mut RuleBits, idx: u32) {
    let w = (idx as usize) / 64;
    if w < BITSET_WORDS {
        bits[w] |= 1u64 << (idx % 64);
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src: u32, // network byte order
    pub dst: u32,
    pub sport: u16, // network byte order; ICMP echo: identifier in sport, 0 in dport
    pub dport: u16,
    pub proto: u8,
    pub _pad: [u8; 3],
}

/// Added in Task 8 per that brief's exact `common/src/lib.rs` additions
/// snippet; wired into `FLOWS` in Task 9
/// (`.superpowers/sdd/task-9-brief.md`) as that map's actual value type
/// (`LruHashMap<FlowKey, FlowVal>`, replacing the bare `u64` presence
/// marker). `last_seen_ns` is a `bpf_ktime_get_ns()` timestamp, written at
/// creation (egress, and ingress-allow) and refreshed on every ordinary
/// (non-embedded-ICMP-error) hit in BOTH directions — see
/// `program/src/main.rs`'s `flow_hit`. A hit whose `now - last_seen_ns`
/// exceeds that flow's protocol's configured idle timeout (`CONFIG` map,
/// below) is stale: the entry is evicted and the packet falls through to
/// rule evaluation instead of fast-pathing.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowVal {
    pub last_seen_ns: u64,
}

/// Per-source egress new-flow rate-cap state (Task 9 brief: `RATE:
/// LruHashMap<u32 /*src ip*/, RateVal>`) — a rolling 1-second window
/// (`RATE_WINDOW_NS`) of how many NEW `FLOWS` entries this source has been
/// allowed to create. `window_start_ns` is the `bpf_ktime_get_ns()` value
/// when the CURRENT window began; `count` is how many new flows this source
/// has recorded within it. Egress-side only (ingress-allow entry creation is
/// uncapped, per the brief) and never blocks the packet itself — only
/// whether its `FLOWS` insert happens.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RateVal {
    pub window_start_ns: u64,
    pub count: u32,
    /// Explicit trailing pad (repr(C) would insert it implicitly anyway,
    /// given `count`'s `u32` after `window_start_ns`'s 8-byte-aligned
    /// `u64`) — named per this file's `FlowKey::_pad` convention so the
    /// struct's true byte layout is visible at the type definition rather
    /// than left to `repr(C)` inference.
    pub _pad: u32,
}

/// `CONFIG[CFG_TCP_NS]`/`CONFIG[CFG_UDP_NS]`/`CONFIG[CFG_ICMP_NS]`: per-
/// protocol `FlowVal` idle timeouts in nanoseconds; `CONFIG[CFG_RATE_CAP]`:
/// the per-source rate cap (`RateVal::count` ceiling per rolling window,
/// stored as `u64` for uniformity with the other three slots even though
/// it's logically a `u32` count). Written by userspace (`ebpf.rs`'s
/// `write_config`) into the generation-independent `CONFIG: Array<u64>` map
/// BEFORE either tc classifier is attached (Task 9 brief) — see
/// `DEFAULT_*_NS`/`DEFAULT_RATE_CAP` below for the belt-and-suspenders
/// fallback the kernel program itself applies if a slot is ever read as
/// exactly `0` anyway.
pub const CFG_TCP_NS: u32 = 0;
pub const CFG_UDP_NS: u32 = 1;
pub const CFG_ICMP_NS: u32 = 2;
pub const CFG_RATE_CAP: u32 = 3;
/// Total `CONFIG` entries.
pub const CONFIG_LEN: usize = 4;

/// Fallback per-protocol idle timeouts (ns) / rate cap the kernel program
/// uses if `CONFIG[idx]` is ever read as exactly `0` (`program/src/main.rs`'s
/// `cfg_or_default`). The PRIMARY guard against "no packet ever sees a
/// zero timeout" is that `EbpfEnforcer::new` (`ebpf.rs`) writes `CONFIG`
/// immediately after `Ebpf::load` and strictly BEFORE either tc classifier
/// is attached, so in practice no packet is ever classified before real
/// config exists. This fallback is defense-in-depth on top of that
/// ordering guarantee, not a replacement for it: a `0` read (which could
/// otherwise only mean "not yet configured", since a real operator-supplied
/// timeout of exactly zero would immediately expire every flow — clearly
/// never the intent) falls back to these literals rather than treating `0`
/// as a real, instant-expiry timeout. Values mirror
/// `wiremesh_enforcer::EnforcerConfig::default()` exactly (7200s/60s/30s/256).
pub const DEFAULT_TCP_NS: u64 = 7_200 * 1_000_000_000;
pub const DEFAULT_UDP_NS: u64 = 60 * 1_000_000_000;
pub const DEFAULT_ICMP_NS: u64 = 30 * 1_000_000_000;
pub const DEFAULT_RATE_CAP: u64 = 256;

/// The rate cap's rolling window width (Task 9 brief: "per rolling 1s
/// window") — one second, in nanoseconds, `bpf_ktime_get_ns()`-comparable.
pub const RATE_WINDOW_NS: u64 = 1_000_000_000;

#[cfg(feature = "user")]
unsafe impl aya::Pod for RuleMeta {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowVal {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for RateVal {}
