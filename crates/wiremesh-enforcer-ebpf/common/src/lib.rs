#![no_std]

// Graduated verbatim from `spike/enforcer/enforcer-common/src/lib.rs`
// (Task 7 brief): `#[repr(C)]` types and count/action constants shared
// between the eBPF `program` crate and `wiremesh-enforcer`'s userspace
// loader (`ebpf.rs`), which enables the `user` feature to get the
// `aya::Pod` impls below. Kept map/field names as-is per the brief.

pub const CTR_ALLOW: u32 = 0;
pub const CTR_DENY: u32 = 1;
pub const CTR_FLOW_HIT: u32 = 2;
pub const CTR_ICMP_ERR: u32 = 3;

pub const ACT_DENY: u32 = 0;
pub const ACT_ALLOW: u32 = 1;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Rule {
    pub src: u32,     // network byte order
    pub src_plen: u32,
    pub dst: u32,
    pub dst_plen: u32,
    pub proto: u32,   // 6 tcp, 17 udp, 1 icmp, 0 any
    pub port_lo: u16, // dst port range, host order; 0..=0 means any
    pub port_hi: u16,
    pub action: u32,
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

#[cfg(feature = "user")]
unsafe impl aya::Pod for Rule {}
#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowKey {}
