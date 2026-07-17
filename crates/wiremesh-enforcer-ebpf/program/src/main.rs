#![no_std]
#![no_main]

// Graduated verbatim (Task 7 brief) from `spike/enforcer/enforcer-ebpf/src/main.rs`
// — the tc classifier: ingress enforce + egress flow-record, ICMP
// embedded-error lookup, A/B rules tables. The spike's A/B mechanism (two
// fixed 64-entry `Array<Rule>` tables + an `ACTIVE` index flipped
// atomically) is kept as-is THIS task; map-in-map generations (lifting the
// 64-entry cap to `wiremesh_enforcer::flatten::MAX_RULES` = 256) are
// Task 8. Map names kept as-is per the brief.

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::{Array, LruHashMap},
    programs::TcContext,
};
use wiremesh_enforcer_common::*;

#[map]
static COUNTERS: Array<u64> = Array::with_max_entries(4, 0);
#[map]
static ACTIVE: Array<u32> = Array::with_max_entries(1, 0);
#[map]
static RULES_A: Array<Rule> = Array::with_max_entries(64, 0);
#[map]
static RULES_B: Array<Rule> = Array::with_max_entries(64, 0);
#[map]
static RULE_LEN: Array<u32> = Array::with_max_entries(2, 0); // len per table
#[map]
static FLOWS: LruHashMap<FlowKey, u64> = LruHashMap::with_max_entries(65536, 0);

fn bump(idx: u32) {
    if let Some(c) = COUNTERS.get_ptr_mut(idx) {
        unsafe { *c += 1 };
    }
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

    // 1) reply of an inside-initiated flow? (egress recorded src=inside)
    let rev = FlowKey { src: dst, dst: src, sport: dport, dport: sport, proto, _pad: [0; 3] };
    if unsafe { FLOWS.get(&rev) }.is_some() {
        bump(CTR_FLOW_HIT);
        return Ok(TC_ACT_PIPE);
    }
    // 2) continuation of an inbound-allowed flow?
    let fwd = FlowKey { src, dst, sport, dport, proto, _pad: [0; 3] };
    if unsafe { FLOWS.get(&fwd) }.is_some() {
        bump(CTR_FLOW_HIT);
        return Ok(TC_ACT_PIPE);
    }
    // 3) ICMP errors: pass iff the EMBEDDED original packet matches a recorded flow.
    // (spec §5.3, Cilium approach) — the ICMP error itself is a fresh inbound
    // packet with no flow of its own; instead we look at the original packet
    // it is reporting on, which (being sent from inside this segment) was
    // recorded as-is at egress.
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
                if unsafe { FLOWS.get(&ekey) }.is_some() {
                    bump(CTR_ICMP_ERR);
                    return Ok(TC_ACT_PIPE);
                }
            }
        }
    }
    // 4) rules (default deny)
    if scan_rules(src, dst, proto, dport) == ACT_ALLOW {
        let _ = FLOWS.insert(&fwd, &1u64, 0);
        bump(CTR_ALLOW);
        return Ok(TC_ACT_PIPE);
    }
    bump(CTR_DENY);
    Ok(TC_ACT_SHOT)
}

fn try_egress(ctx: &TcContext) -> Result<(), ()> {
    let (src, dst, proto, ihl) = ipv4_at(ctx)?;
    let (sport, dport) = ports_at(ctx, ihl, proto);
    let key = FlowKey { src, dst, sport, dport, proto, _pad: [0; 3] };
    let _ = FLOWS.insert(&key, &1u64, 0);
    Ok(())
}

// First-match linear scan over whichever table ACTIVE currently points at.
// ACTIVE is read exactly ONCE per packet (`table` below) — the spec's
// one-generation-read-per-packet rule that the A/B atomic flip depends on:
// every packet must see either wholly the old ruleset or wholly the new one,
// never a mix from re-reading ACTIVE mid-scan.
fn scan_rules(src: u32, dst: u32, proto: u8, dport: u16) -> u32 {
    let table = ACTIVE.get(0).copied().unwrap_or(0);
    let len = RULE_LEN.get(table).copied().unwrap_or(0).min(64);
    // Bounded `for 0..64` (not `while i < len`) so the verifier can see a
    // fixed iteration count at compile time; the `i >= len` break enforces
    // the real (runtime) length.
    for i in 0..64u32 {
        if i >= len {
            break;
        }
        let r = match if table == 0 { RULES_A.get(i) } else { RULES_B.get(i) } {
            Some(r) => r,
            None => break,
        };
        if rule_matches(r, src, dst, proto, dport) {
            return r.action;
        }
    }
    ACT_DENY
}

fn prefix_match(addr: u32, net: u32, plen: u32) -> bool {
    if plen == 0 {
        return true;
    }
    let mask = u32::MAX << (32 - plen);
    (u32::from_be(addr) & mask) == (u32::from_be(net) & mask)
}

fn rule_matches(r: &Rule, src: u32, dst: u32, proto: u8, dport: u16) -> bool {
    prefix_match(src, r.src, r.src_plen)
        && prefix_match(dst, r.dst, r.dst_plen)
        && (r.proto == 0 || r.proto == proto as u32)
        && (r.port_hi == 0 || {
            let p = u16::from_be(dport);
            p >= r.port_lo && p <= r.port_hi
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
