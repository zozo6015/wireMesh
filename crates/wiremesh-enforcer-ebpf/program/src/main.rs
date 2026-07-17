#![no_std]
#![no_main]

// Graduated from `spike/enforcer/enforcer-ebpf/src/main.rs` (Task 7 brief),
// rewritten for Task 8 (`.superpowers/sdd/task-8-brief.md`): LPM-bitset
// first-match matching + map-in-map atomic generations. The tc classifier
// shape (ingress enforce + egress flow-record) and the ICMP embedded-error
// lookup are unchanged from Task 7; `scan_rules` (renamed `scan_generation`
// below) and the rule tables themselves are what Task 8 replaces — the
// fixed 64-entry A/B `Array<Rule>` + `ACTIVE`-index flip (Task 7) is gone,
// replaced by four `BPF_MAP_TYPE_ARRAY_OF_MAPS` outers (`GEN_SRC`/
// `GEN_DST`/`GEN_RULES`/`GEN_META`), each with `GENERATIONS` (2) slots,
// still indexed by the same single-read `ACTIVE`. `MAX_RULES` is now 256
// (up from 64), `wiremesh_enforcer_common`'s — the same constant
// `wiremesh-enforcer`'s `flatten()` enforces at the controller/compile-time
// layer (design §6: "the controller rejects at compile time, not the
// gateway at load time").
//
// Task 10 (`.superpowers/sdd/task-10-brief.md`) adds sampled deny-event
// emission on top of the above: `scan_generation`'s two deny verdict sites
// (an explicit `deny` rule match, and the default-deny fallback after the
// bounded scan) each call `maybe_emit_deny` immediately after their existing
// `bump(...)` counter call, subject to the new `LOG_RULE_BUDGET`/
// `LOG_AGG_BUDGET` per-second token-bucket sampling budgets (`CONFIG`
// indices `CFG_LOG_PER_RULE`/`CFG_LOG_AGGREGATE`) -- see `log_allows`/
// `maybe_emit_deny`'s doc comments below.

// Generation-independent maps (`COUNTERS`/`ACTIVE`/`FLOWS`) keep the plain
// `#[map]`/`aya_ebpf::maps` style, unchanged from Task 7 (brief: "unchanged
// from Task 7"). Only the new per-generation maps below need `#[btf_map]`/
// `aya_ebpf::btf_maps` — that's the mechanism this crate version's
// `ArrayOfMaps`/LPM-trie-as-inner-map map-in-map support requires; it isn't
// available via the old `#[map]` API at all. (Mixing the two styles in one
// object was investigated as a possible source of a real Task 8 bug and
// ruled out: an all-`#[btf_map]` object exhibited the identical symptom.
// The actual root cause was unrelated to map declaration style — see this
// task's report.)
use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    btf_maps::{lpm_trie::Key as LpmKey, Array as BtfArray, ArrayOfMaps, LpmTrie},
    helpers::bpf_ktime_get_ns,
    macros::{btf_map, classifier, map},
    maps::{Array, LruHashMap, RingBuf},
    programs::TcContext,
};
use wiremesh_enforcer_common::*;

// --- generation-independent maps (Task 7, unchanged; FLOWS's value type
// and RATE/CONFIG are Task 9 additions) -----------------------------------

#[map]
static COUNTERS: Array<u64> = Array::with_max_entries(COUNTERS_LEN as u32, 0);
#[map]
static ACTIVE: Array<u32> = Array::with_max_entries(1, 0);
/// `65536` here is only this map's OWN declared default — `ebpf.rs`'s
/// `EbpfEnforcer::new` overrides the actual loaded `max_entries` from
/// `EnforcerConfig::flow_max` via `EbpfLoader::map_max_entries("FLOWS", ...)`
/// before the map is ever created in the kernel (Task 9 brief: "flow_max:
/// set FLOWS max_entries from EnforcerConfig BEFORE load").
#[map]
static FLOWS: LruHashMap<FlowKey, FlowVal> = LruHashMap::with_max_entries(65536, 0);
/// Per-source egress rate-cap state (Task 9 brief). Sized independently of
/// `flow_max` — its cardinality is bounded by distinct SOURCE IPs feeding
/// this gateway's egress path, not by distinct flows, and the brief doesn't
/// call for it to be configurable. `4096` is a generous, LRU-backed
/// implementation choice (an eviction here only resets a source's rate
/// bookkeeping to a fresh burst-1 window on its next packet — never
/// incorrect, just momentarily generous), not a hard requirement.
#[map]
static RATE: LruHashMap<u32, RateVal> = LruHashMap::with_max_entries(4096, 0);
/// Per-protocol idle timeouts + the rate cap (Task 9 brief: `CONFIG:
/// Array<u64>`, indices `CFG_TCP_NS`/`CFG_UDP_NS`/`CFG_ICMP_NS`/
/// `CFG_RATE_CAP`). Written by `ebpf.rs`'s `write_config` immediately after
/// load, before either classifier is attached — see `cfg_or_default`'s doc
/// comment for the defense-in-depth fallback if a slot is ever read as `0`
/// anyway.
#[map]
static CONFIG: Array<u64> = Array::with_max_entries(CONFIG_LEN as u32, 0);
/// Deny-event ring buffer (Task 10) — sampled `DenyEventRaw` records,
/// drained non-blockingly by userspace (`ebpf.rs`'s `deny_events`). See
/// `DenyEventRaw`/`DENY_RB_BYTES`'s doc comments (`common/src/lib.rs`) for
/// the wire representation and buffer-size rationale.
#[map]
static DENY_RB: RingBuf = RingBuf::with_byte_size(DENY_RB_BYTES, 0);
/// Per-rule (`0..MAX_RULES`, plus [`CTR_DEFAULT_DENY`] (256) for the
/// default-deny fallback) deny-event log sampling token buckets (Task 10
/// brief: "per-rule Array<{window_start_ns, count}>, size MAX_RULES+1
/// covering default-deny"). Reuses [`RateVal`]'s shape — see that type's
/// doc comment for why a distinct type wasn't introduced.
#[map]
static LOG_RULE_BUDGET: Array<RateVal> = Array::with_max_entries((MAX_RULES + 1) as u32, 0);
/// The single aggregate (across every rule) deny-event log sampling token
/// bucket (Task 10 brief: "+ one aggregate slot").
#[map]
static LOG_AGG_BUDGET: Array<RateVal> = Array::with_max_entries(1, 0);

// --- per-generation maps (Task 8) ----------------------------------------
//
// Each of the four outers below has exactly `GENERATIONS` (2) slots,
// mirrored by the same slot index in every other outer — `ACTIVE` (above)
// selects which slot is live. `scan_generation` reads `ACTIVE` exactly ONCE
// per packet, so a packet's SRC lookup, DST lookup, RULES lookups, and META
// length read all resolve against the SAME generation, never a mix (design
// §6's atomic-flip guarantee: "reads the active generation index exactly
// once per packet, so lookups can never straddle generations").

// The trie's raw key data is `u64`, not `u32`, even though only the low 32
// bits (a zero-extended, big-endian-as-loaded IPv4 address) are ever
// meaningful (`prefix_len` never exceeds 32): the kernel's LPM trie node
// layout places `V`'s bytes immediately after `Key<K>`'s raw `data` bytes
// with no padding, so it requires `size_of::<K>()` to be a multiple of
// `align_of::<V>()`; `V` = `RuleBits` = `[u64; 4]` has `align_of() == 8`,
// which a 4-byte `u32` key can't satisfy but an 8-byte `u64` key does. Zero-
// extending a little-endian-native `u32` (`x as u64`) leaves the meaningful
// 4 bytes in the trie's first 4 data bytes (this container's host and the
// bpfel-unknown-none target are both little-endian) — exactly where LPM
// prefix matching (which only ever examines the first `prefix_len` <= 32
// bits) needs them, with the upper 4 bytes an always-zero, never-examined
// pad. See `ebpf.rs`'s `build_trie`/`LpmKey` construction for the userspace
// side of this same convention.
type SrcTrie = LpmTrie<u64, RuleBits, LPM_MAX_ENTRIES>;
type DstTrie = LpmTrie<u64, RuleBits, LPM_MAX_ENTRIES>;
type RulesArr = BtfArray<RuleMeta, MAX_RULES>;
type MetaArr = BtfArray<u32, 1>;

#[btf_map]
static GEN_SRC: ArrayOfMaps<SrcTrie, GENERATIONS> = ArrayOfMaps::new();
#[btf_map]
static GEN_DST: ArrayOfMaps<DstTrie, GENERATIONS> = ArrayOfMaps::new();
#[btf_map]
static GEN_RULES: ArrayOfMaps<RulesArr, GENERATIONS> = ArrayOfMaps::new();
#[btf_map]
static GEN_META: ArrayOfMaps<MetaArr, GENERATIONS> = ArrayOfMaps::new();

fn bump(idx: u32) {
    if let Some(c) = COUNTERS.get_ptr_mut(idx) {
        unsafe { *c += 1 };
    }
}

/// Reads `CONFIG[idx]`, falling back to `default` if the slot is exactly
/// `0` — see `wiremesh_enforcer_common::DEFAULT_TCP_NS`'s doc comment for
/// why `0` specifically (rather than any other sentinel) means "not yet
/// configured, use a safe default" here: a real operator-supplied idle
/// timeout or rate cap of exactly zero would immediately expire every flow
/// / block every new one, which is never the actual intent, so `0` is safe
/// to reserve as the "unset" sentinel. `ebpf.rs`'s `write_config` is the
/// PRIMARY guard (writes real values before either classifier attaches);
/// this is defense-in-depth on top of that ordering, not instead of it.
#[inline(always)]
fn cfg_or_default(idx: u32, default: u64) -> u64 {
    let v = CONFIG.get(idx).copied().unwrap_or(0);
    if v == 0 {
        default
    } else {
        v
    }
}

/// This flow's protocol's configured idle timeout, in nanoseconds
/// (`bpf_ktime_get_ns()`-comparable). Any protocol other than tcp/udp/icmp
/// never reaches a `FLOWS` hit-path call site in practice (`ipv4_at`/
/// `ports_at` only special-case those three; every other IPv4 protocol gets
/// `(0, 0)` ports and is still recordable/matchable, so this still needs a
/// total answer) — falls back to the udp timeout, this design's shortest
/// non-icmp default, as a conservative (expires sooner rather than later)
/// choice for that unspecified case.
#[inline(always)]
fn timeout_ns(proto: u8) -> u64 {
    match proto {
        6 => cfg_or_default(CFG_TCP_NS, DEFAULT_TCP_NS),
        1 => cfg_or_default(CFG_ICMP_NS, DEFAULT_ICMP_NS),
        _ => cfg_or_default(CFG_UDP_NS, DEFAULT_UDP_NS),
    }
}

fn rate_cap() -> u32 {
    cfg_or_default(CFG_RATE_CAP, DEFAULT_RATE_CAP) as u32
}

/// The shared hit-path check for all three of `try_ingress`'s `FLOWS`
/// lookups (reverse-continuation, forward-continuation, and the ICMP
/// embedded-error match) — Task 9 brief's "Hit path" contract: absent ->
/// miss; present but stale (`now - last_seen_ns > timeout_ns(proto)`) ->
/// evict the entry and miss (falls through to rule evaluation); present and
/// fresh -> hit, and if `refresh` is set, bump `last_seen_ns` to `now` in
/// place (both directions of ordinary traffic refresh the idle timer, spec
/// §5.3).
///
/// `refresh = false` is used ONLY by the ICMP embedded-error lookup: an
/// ICMP error report is not itself forward traffic on the flow it's
/// reporting about, so observing one must not extend that flow's idle
/// timer — but the SAME staleness check still applies, so a stale original
/// flow's embedded-error lookup also correctly misses rather than
/// fast-pathing a packet that has no business bypassing rule evaluation.
///
/// Uses `get_ptr_mut` (like `bump`, above) rather than `get`+`insert`, so a
/// refresh is a single in-place field write, not a full map re-insert.
fn flow_hit(key: &FlowKey, proto: u8, now: u64, refresh: bool) -> bool {
    match FLOWS.get_ptr_mut(key) {
        None => false,
        Some(ptr) => {
            let last_seen = unsafe { (*ptr).last_seen_ns };
            if now.saturating_sub(last_seen) > timeout_ns(proto) {
                let _ = FLOWS.remove(key);
                false
            } else {
                if refresh {
                    unsafe { (*ptr).last_seen_ns = now };
                }
                true
            }
        }
    }
}

/// Per-source (`src`, network-byte-order IPv4) rolling-1s-window new-flow
/// rate cap (Task 9 brief). Returns `true` (and records this attempt
/// against the current window) iff `src` may record ONE more new `FLOWS`
/// entry right now; `false` means this window's cap is already spent — the
/// caller must skip the `FLOWS` insert, but the packet itself is still
/// let through either way (egress never blocks traffic, only bookkeeping).
///
/// Window arithmetic is overflow-safe: `now.saturating_sub(window_start_ns)`
/// (both `u64` nanosecond timestamps from the same monotonic clock, `now`
/// always >= any previously-recorded `window_start_ns`, but saturating
/// regardless) and `count.saturating_add(1)` (bounded by `cap` in practice,
/// since the `count < cap` branch is the only place it grows, but
/// saturating regardless rather than relying on that bound alone).
fn rate_allows(src: u32, now: u64) -> bool {
    let cap = rate_cap();
    match RATE.get_ptr_mut(&src) {
        None => {
            let _ = RATE.insert(&src, &RateVal { window_start_ns: now, count: 1, _pad: 0 }, 0);
            true
        }
        Some(ptr) => {
            let window_start = unsafe { (*ptr).window_start_ns };
            if now.saturating_sub(window_start) > RATE_WINDOW_NS {
                // Rolling window elapsed: start a fresh one at `now`.
                unsafe {
                    (*ptr).window_start_ns = now;
                    (*ptr).count = 1;
                }
                true
            } else {
                let count = unsafe { (*ptr).count };
                if count < cap {
                    unsafe { (*ptr).count = count.saturating_add(1) };
                    true
                } else {
                    false
                }
            }
        }
    }
}

/// The shared token-bucket check behind both deny-event log sampling
/// budgets (`LOG_RULE_BUDGET`/`LOG_AGG_BUDGET`, Task 10) — the exact same
/// rolling-1s-window shape as [`rate_allows`]'s `Some` arm above, generalized
/// over an `Array<RateVal>` keyed by a plain `u32` idx instead of
/// `rate_allows`'s `LruHashMap<u32, RateVal>` keyed by source IP (an `Array`
/// slot always exists once declared with enough entries — there is no
/// `LruHashMap`-style "never seen this key before" case to special-case;
/// a zero-initialized slot's `window_start_ns == 0` already falls into the
/// "window elapsed" branch below on the very first real call, since `now`
/// is always far more than `RATE_WINDOW_NS` past the kernel boot epoch in
/// any test/production scenario this design targets — no separate
/// first-touch branch needed).
///
/// Same non-atomic-RMW caveat as `rate_allows`/`bump`: `get_ptr_mut` +
/// plain reads/writes, not a CAS loop. Two CPUs racing on the SAME idx
/// (same rule denying concurrently on multiple cores) could each observe
/// `count < cap` and both increment, momentarily over-admitting by a small,
/// bounded amount within one window — consistent with this design's
/// existing precedent (`bump`'s counter increments and `rate_allows`'s rate
/// cap are both the same non-atomic shape) and acceptable here for the same
/// reason: sampling is a best-effort volume bound, not a hard security
/// guarantee, so a rare, small over-admission under real concurrency is a
/// documented, accepted trade-off rather than a bug.
///
/// Returns `true` (and records this attempt against the current window)
/// iff `idx`'s budget has room for one more emission right now; `false`
/// means this window's cap for `idx` is already spent. `idx` out of the
/// array's declared range (never expected from this file's own call sites)
/// conservatively returns `false` (skip emission) rather than panicking.
fn budget_allows(arr: &Array<RateVal>, idx: u32, cap: u32, now: u64) -> bool {
    match arr.get_ptr_mut(idx) {
        None => false,
        Some(ptr) => {
            let window_start = unsafe { (*ptr).window_start_ns };
            if now.saturating_sub(window_start) > RATE_WINDOW_NS {
                // Window elapsed (or never started -- a zero-initialized
                // slot's `window_start_ns == 0` takes this same branch on
                // its very first real call): start a fresh one at `now`.
                unsafe {
                    (*ptr).window_start_ns = now;
                    (*ptr).count = 1;
                }
                true
            } else {
                let count = unsafe { (*ptr).count };
                if count < cap {
                    unsafe { (*ptr).count = count.saturating_add(1) };
                    true
                } else {
                    false
                }
            }
        }
    }
}

/// Task 10 brief: deny-event emission is gated by BOTH the per-rule AND the
/// aggregate sampling budget -- an over-budget deny still counts (`bump`
/// already ran in every caller before this is reached), it just doesn't
/// emit. Per-rule is checked first: a rule already over its OWN budget
/// never touches the shared aggregate slot at all, a minor fairness
/// kindness to other rules' aggregate headroom, though not load-bearing for
/// this task's own tests (which only ever exercise a single denying rule at
/// a time).
fn log_allows(rule_idx: u32, now: u64) -> bool {
    let per_rule_cap = cfg_or_default(CFG_LOG_PER_RULE, DEFAULT_LOG_PER_RULE) as u32;
    if !budget_allows(&LOG_RULE_BUDGET, rule_idx, per_rule_cap, now) {
        return false;
    }
    let agg_cap = cfg_or_default(CFG_LOG_AGGREGATE, DEFAULT_LOG_AGGREGATE) as u32;
    budget_allows(&LOG_AGG_BUDGET, 0, agg_cap, now)
}

/// Emits one sampled `DenyEventRaw` into `DENY_RB` for a just-denied packet
/// -- called from `scan_generation` at BOTH deny verdict sites (an explicit
/// `deny` rule match and the default-deny fallback), in both cases strictly
/// AFTER that site's own `bump(...)` call (design §5.3: "counters always
/// count" -- sampling only ever affects whether an EVENT goes out, never
/// whether the counter increments). `ev.rule_idx` is `CTR_DEFAULT_DENY`
/// (256) for the default-deny fallback, exactly the marker
/// `wiremesh_enforcer::ebpf::deny_events` (userspace) checks for to report
/// `rule_id: None`.
///
/// Takes the already-built `&DenyEventRaw` (rather than its five individual
/// fields) purely for the eBPF calling convention: BPF only has 5 argument
/// registers, and `rule_idx`/`src`/`dst`/`proto`/`_pad`/`dport`/`now` as
/// separate scalar params is 6 -- `bpf-linker` rejects that outright
/// ("stack arguments are not supported", no eBPF ISA support for spilling
/// call args to the stack). One pointer + `now` is 2 registers, comfortably
/// under the limit.
///
/// `RingBuf::output`'s `Err` (buffer full) is intentionally ignored: a
/// dropped sample under overflow is an accepted, documented trade-off (see
/// `DENY_RB_BYTES`'s doc comment) -- sampling already bounds steady-state
/// volume well under the buffer's size, so overflow should only ever be a
/// rare burst artifact, never a routine occurrence.
fn maybe_emit_deny(ev: &DenyEventRaw, now: u64) {
    if !log_allows(ev.rule_idx, now) {
        return;
    }
    // Explicit turbofish: `&DenyEventRaw` satisfies both the blanket
    // `impl<T> Borrow<T> for T` (with `T = &DenyEventRaw`) and
    // `impl<T> Borrow<T> for &T` (with `T = DenyEventRaw`) `output` accepts,
    // so the compiler can't infer which `T` (the ring buffer ENTRY type) is
    // intended without help.
    let _ = DENY_RB.output::<DenyEventRaw>(ev, 0);
}

#[classifier]
pub fn aeth_ingress(ctx: TcContext) -> i32 {
    match try_ingress(&ctx) {
        Ok(verdict) => verdict,
        Err(_) => TC_ACT_SHOT, // unparseable => deny (default-deny posture)
    }
}

#[classifier]
pub fn aeth_egress(ctx: TcContext) -> i32 {
    let _ = try_egress(&ctx); // recording only, never blocks
    TC_ACT_PIPE
}

// tun is L3: byte 0 is the IP header. IPv4 only (spec §1).
fn ipv4_at(ctx: &TcContext) -> Result<(u32, u32, u8, usize), ()> {
    let vihl: u8 = ctx.load(0).map_err(|_| ())?;
    if vihl >> 4 != 4 {
        return Err(());
    }
    let ihl = ((vihl & 0x0f) as usize) * 4;
    let proto: u8 = ctx.load(9).map_err(|_| ())?;
    let src: u32 = ctx.load(12).map_err(|_| ())?; // stays big-endian as loaded
    let dst: u32 = ctx.load(16).map_err(|_| ())?;
    Ok((src, dst, proto, ihl))
}

fn ports_at(ctx: &TcContext, off: usize, proto: u8) -> (u16, u16) {
    match proto {
        6 | 17 => (
            ctx.load::<u16>(off).unwrap_or(0),
            ctx.load::<u16>(off + 2).unwrap_or(0),
        ),
        1 => {
            // ICMP echo: type(0)/code(1)/csum(2..4)/identifier(4..6)
            let id: u16 = ctx.load::<u16>(off + 4).unwrap_or(0);
            (id, 0)
        }
        _ => (0, 0),
    }
}

fn try_ingress(ctx: &TcContext) -> Result<i32, ()> {
    let (src, dst, proto, ihl) = ipv4_at(ctx)?;
    let (sport, dport) = ports_at(ctx, ihl, proto);
    let now = unsafe { bpf_ktime_get_ns() };

    // 1) reply of an inside-initiated flow? (egress recorded src=inside)
    let rev = FlowKey { src: dst, dst: src, sport: dport, dport: sport, proto, _pad: [0; 3] };
    if flow_hit(&rev, proto, now, true) {
        bump(CTR_FLOW_HIT);
        return Ok(TC_ACT_PIPE);
    }
    // 2) continuation of an inbound-allowed flow?
    let fwd = FlowKey { src, dst, sport, dport, proto, _pad: [0; 3] };
    if flow_hit(&fwd, proto, now, true) {
        bump(CTR_FLOW_HIT);
        return Ok(TC_ACT_PIPE);
    }
    // 3) ICMP errors: pass iff the EMBEDDED original packet matches a recorded flow.
    // (spec §5.3, Cilium approach) — the ICMP error itself is a fresh inbound
    // packet with no flow of its own; instead we look at the original packet
    // it is reporting on, which (being sent from inside this segment) was
    // recorded as-is at egress. `refresh = false`: an ICMP error is not
    // forward traffic on the original flow (see `flow_hit`'s doc comment) —
    // it still honors that flow's own staleness check (a stale original
    // flow's embedded-error lookup also misses), it just must not extend
    // that flow's idle timer merely because a router somewhere reported an
    // error about it.
    if proto == 1 {
        let itype: u8 = ctx.load(ihl).map_err(|_| ())?;
        if itype == 3 || itype == 11 || itype == 12 {
            // embedded original IP header starts at ihl + 8 (icmp hdr)
            let eoff = ihl + 8;
            let evihl: u8 = ctx.load(eoff).map_err(|_| ())?;
            if evihl >> 4 == 4 {
                let eihl = ((evihl & 0x0f) as usize) * 4;
                let eproto: u8 = ctx.load(eoff + 9).map_err(|_| ())?;
                let esrc: u32 = ctx.load(eoff + 12).map_err(|_| ())?;
                let edst: u32 = ctx.load(eoff + 16).map_err(|_| ())?;
                let esport: u16 = ctx.load(eoff + eihl).unwrap_or(0);
                let edport: u16 = ctx.load(eoff + eihl + 2).unwrap_or(0);
                // original packet was OUTBOUND from this segment => recorded at egress as-is
                let ekey = FlowKey { src: esrc, dst: edst, sport: esport, dport: edport,
                                     proto: eproto, _pad: [0; 3] };
                if flow_hit(&ekey, eproto, now, false) {
                    bump(CTR_FLOW_HIT);
                    return Ok(TC_ACT_PIPE);
                }
            }
        }
    }
    // 4) rules (default deny)
    if scan_generation(src, dst, proto, dport, now) == ACT_ALLOW {
        let _ = FLOWS.insert(&fwd, &FlowVal { last_seen_ns: now }, 0);
        return Ok(TC_ACT_PIPE);
    }
    Ok(TC_ACT_SHOT)
}

/// Records this packet's own 5-tuple in `FLOWS` (egress is recording-only —
/// it never blocks, per `aeth_egress`). Task 9 adds: (a) an EXISTING,
/// still-fresh entry is refreshed in place rather than blindly re-inserted;
/// (b) an existing but STALE entry is evicted and treated exactly like a
/// brand-new one — a 5-tuple reused after its previous instance idled out is
/// a new flow in every sense that matters here, not a continuation, so it's
/// still subject to (c); (c) a genuinely new entry is only recorded if this
/// source's per-source rolling-window rate cap (`rate_allows`) allows it —
/// skipping the insert when capped is the entire enforcement mechanism
/// (Task 9 brief: "egress never blocks packets", only the bookkeeping is
/// capped, so a capped new flow's REPLIES simply fall through to rule
/// evaluation instead of fast-pathing).
fn try_egress(ctx: &TcContext) -> Result<(), ()> {
    let (src, dst, proto, ihl) = ipv4_at(ctx)?;
    let (sport, dport) = ports_at(ctx, ihl, proto);
    let key = FlowKey { src, dst, sport, dport, proto, _pad: [0; 3] };
    let now = unsafe { bpf_ktime_get_ns() };

    match FLOWS.get_ptr_mut(&key) {
        None => {
            if rate_allows(src, now) {
                let _ = FLOWS.insert(&key, &FlowVal { last_seen_ns: now }, 0);
            }
        }
        Some(ptr) => {
            let last_seen = unsafe { (*ptr).last_seen_ns };
            if now.saturating_sub(last_seen) > timeout_ns(proto) {
                let _ = FLOWS.remove(&key);
                if rate_allows(src, now) {
                    let _ = FLOWS.insert(&key, &FlowVal { last_seen_ns: now }, 0);
                }
            } else {
                unsafe { (*ptr).last_seen_ns = now };
            }
        }
    }
    Ok(())
}

// The single generation-read-per-packet verdict path (design §6). `ACTIVE`
// is read exactly ONCE (`slot` below); every subsequent lookup (SRC, DST,
// RULES, META) is keyed by that SAME `slot` — a packet can never straddle
// two generations, even if `apply()` flips `ACTIVE` concurrently on another
// CPU mid-scan. `bits = SRC_LPM[src] & DST_LPM[dst]`: LPM lookups return the
// CUMULATIVE bitset `ebpf.rs`'s userspace `apply()` builds — every prefix's
// stored bits are the union of every covering rule's bit, not just the
// rule(s) inserted at that exact prefix (see that file's `build_lpm_entries`
// doc comment) — so a bounded first-match scan over `RULES[0..len)`, not
// raw LPM longest-prefix-wins, decides the verdict. A missing LPM entry (no
// covering CIDR at all) or a missing/uninstalled generation slot (before
// the first `apply()`) both default to an all-zero bitset via `unwrap_or`,
// which naturally falls through the scan below to the default-deny bump —
// no special-casing needed for either case.
fn scan_generation(src: u32, dst: u32, proto: u8, dport: u16, now: u64) -> u32 {
    let slot = ACTIVE.get(0).copied().unwrap_or(0);

    let src_key = LpmKey::new(32, src as u64);
    let dst_key = LpmKey::new(32, dst as u64);

    let src_bits: RuleBits = GEN_SRC
        .get(slot)
        .and_then(|trie| trie.get(&src_key))
        .copied()
        .unwrap_or([0u64; BITSET_WORDS]);
    let dst_bits: RuleBits = GEN_DST
        .get(slot)
        .and_then(|trie| trie.get(&dst_key))
        .copied()
        .unwrap_or([0u64; BITSET_WORDS]);

    let mut bits: RuleBits = [0u64; BITSET_WORDS];
    let mut w = 0usize;
    while w < BITSET_WORDS {
        bits[w] = src_bits[w] & dst_bits[w];
        w += 1;
    }

    let len = GEN_META
        .get_value(slot, &0u32)
        .copied()
        .unwrap_or(0)
        .min(MAX_RULES as u32);

    // Bounded `for 0..MAX_RULES` (not `while i < len`) so the verifier can
    // see a fixed iteration count at compile time; the `i >= len` break
    // enforces the real (runtime) flattened length.
    for i in 0..MAX_RULES as u32 {
        if i >= len {
            break;
        }
        if !bit_get(&bits, i) {
            continue;
        }
        let meta = match GEN_RULES.get_value(slot, &i) {
            Some(m) => m,
            None => break,
        };
        if meta_matches(meta, proto, dport) {
            bump(i);
            if meta.action == ACT_DENY {
                let ev = DenyEventRaw { src, dst, proto, _pad: [0], dport, rule_idx: i };
                maybe_emit_deny(&ev, now);
            }
            return meta.action;
        }
    }
    bump(CTR_DEFAULT_DENY);
    let ev = DenyEventRaw { src, dst, proto, _pad: [0], dport, rule_idx: CTR_DEFAULT_DENY };
    maybe_emit_deny(&ev, now);
    ACT_DENY
}

fn meta_matches(m: &RuleMeta, proto: u8, dport: u16) -> bool {
    (m.proto == 0 || m.proto == proto as u32)
        && (m.port_hi == 0 || {
            let p = u16::from_be(dport);
            p >= m.port_lo && p <= m.port_hi
        })
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
