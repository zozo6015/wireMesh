#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_PIPE, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::{Array, LruHashMap},
    programs::TcContext,
};
use enforcer_common::*;

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
    // 3) rules (default deny) — Task 7 fills scan_rules; scaffold denies all
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

fn scan_rules(_src: u32, _dst: u32, _proto: u8, _dport: u16) -> u32 {
    ACT_DENY // scaffold: Task 7 implements first-match scan over active table
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
