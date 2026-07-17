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

/// Added per the Task 8 brief's exact `common/src/lib.rs` additions
/// snippet. Not yet wired into `FLOWS` (still a plain `LruHashMap<FlowKey,
/// u64>`, generation-independent and unchanged from Task 7 per the brief's
/// map list) — idle-eviction/last-seen tracking is a later task's addition,
/// same "not yet consumed" framing as `EbpfEnforcer::cfg` in `ebpf.rs`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowVal {
    pub last_seen_ns: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for RuleMeta {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowKey {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowVal {}
