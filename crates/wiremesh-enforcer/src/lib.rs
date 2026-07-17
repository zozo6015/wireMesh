//! `wiremesh-enforcer` — graduated Phase 0 eBPF-enforcer spike into a real
//! backend-agnostic library (cycle 3, Task 7; design doc §6,
//! `docs/superpowers/specs/2026-07-17-policy-pipeline-design.md`).
//!
//! Public surface (design D-C3-4 — later tasks and cycle 4 rely on these
//! exact names/signatures, per `.superpowers/sdd/task-7-brief.md`):
//! [`BackendKind`], [`EnforcerConfig`], the [`Enforcer`] trait, [`Counters`],
//! [`DenyEvent`], and [`probe`]. [`flatten`]/[`FlatRule`]/[`MAX_RULES`] (in
//! [`flatten`]) are the pure, shared front half both backends (eBPF now,
//! nftables fallback) drive from.
//!
//! Task 7 Step 3 (implementer): `probe`'s real eBPF-load-and-attach path
//! lives in `src/ebpf.rs`; `flatten`'s real flattening logic lives in
//! `src/flatten.rs`. The nftables fallback (Task 12) is the one piece of
//! `probe`'s documented behavior not yet implemented.

mod ebpf;
mod flatten;

pub use flatten::{flatten, FlatRule, MAX_RULES};

use wiremesh_policy::PolicyIR;

/// Which live backend an [`Enforcer`] instance is actually driving. `probe`
/// tries eBPF first and falls back to nftables (design §6/D-C3-4) — callers
/// (fabricctl, logs, tests) read this back to know which one won.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    Ebpf,
    Nftables,
}

/// Tunable enforcer limits (design §6's "Defaults (all configurable)"
/// list). [`Default`] below pins the literal numbers the design doc and the
/// Task 7 brief both specify — flow table 1_048_576 entries; idle timeouts
/// TCP 7200s / UDP 60s / ICMP 30s; rate cap 256 new flows/s per source IP;
/// deny log sampling 10/s per rule, 100/s aggregate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnforcerConfig {
    pub flow_max: u32,
    pub tcp_idle_s: u32,
    pub udp_idle_s: u32,
    pub icmp_idle_s: u32,
    pub rate_cap_per_src: u32,
    pub log_per_rule: u32,
    pub log_aggregate: u32,
}

impl Default for EnforcerConfig {
    fn default() -> Self {
        Self {
            flow_max: 1_048_576,
            tcp_idle_s: 7200,
            udp_idle_s: 60,
            icmp_idle_s: 30,
            rate_cap_per_src: 256,
            log_per_rule: 10,
            log_aggregate: 100,
        }
    }
}

/// The backend-agnostic enforcement surface. Both the eBPF backend (this
/// task) and the nftables fallback (later task) implement this same trait,
/// so callers (the controller-facing gateway agent, `fabricctl`, tests) never
/// need to know which one is actually loaded.
pub trait Enforcer {
    /// Which backend this instance is actually driving.
    fn kind(&self) -> BackendKind;
    /// Installs `ir` as the live rule set. Atomic: in-flight packets must
    /// never observe a half-applied policy (design §6's atomic generation
    /// flip — Task 8's map-in-map generations in the eBPF backend, `ebpf.rs`).
    fn apply(&mut self, ir: &PolicyIR) -> anyhow::Result<()>;
    /// Reads current per-rule and default-deny counters.
    fn counters(&mut self) -> anyhow::Result<Counters>;
    /// Forces re-evaluation of already-live flows against the current rule
    /// set (e.g. after a policy update that should immediately re-deny a
    /// previously-allowed live flow).
    fn flush_flows(&mut self) -> anyhow::Result<()>;
    /// Drains buffered, sampled deny events since the last call.
    fn deny_events(&mut self) -> anyhow::Result<Vec<DenyEvent>>;
}

/// Per-rule and default-deny packet counters (design §6). `by_rule` is keyed
/// by [`wiremesh_policy::IrRule::rule_id`] — [`flatten`]'s port-exploded
/// [`FlatRule`]s that share a `rule_id` aggregate into the same entry.
#[derive(Debug, Clone, Default)]
pub struct Counters {
    pub by_rule: std::collections::BTreeMap<String, u64>,
    pub default_deny: u64,
}

/// One sampled deny event (design §6's deny log sampling). `rule_id: None`
/// means the packet fell through to the default-deny fallback rather than
/// matching an explicit `deny` rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenyEvent {
    pub src: std::net::Ipv4Addr,
    pub dst: std::net::Ipv4Addr,
    pub proto: u8,
    pub dport: u16,
    pub rule_id: Option<String>,
}

/// Tries to load and attach the eBPF backend on `iface`; on failure, falls
/// back to the nftables backend (design §6/D-C3-4: "Attachment: tc clsact
/// ingress on tun (enforce) + egress on tun (flow recording) ... Mitigation
/// if needed"). Returns whichever one actually succeeded, boxed behind the
/// shared [`Enforcer`] trait.
///
/// Task 7 (this task) implements the eBPF half only (`src/ebpf.rs`) — an
/// eBPF load/attach failure is currently returned as-is (with added
/// context), not silently swallowed into a fallback: the nftables backend
/// doesn't exist yet. The nftables fallback (Task 12) will change this
/// function's `Err` path into a second attempt instead of a final one; the
/// signature (`Result<Box<dyn Enforcer>>`) already accommodates that
/// without another breaking change.
pub fn probe(iface: &str, cfg: EnforcerConfig) -> anyhow::Result<Box<dyn Enforcer>> {
    match ebpf::EbpfEnforcer::new(iface, cfg) {
        Ok(enforcer) => Ok(Box::new(enforcer)),
        Err(e) => Err(e.context(format!(
            "eBPF backend failed to load/attach on {iface}; no nftables fallback available yet \
             (design §6/D-C3-4 — that lands in Task 12)"
        ))),
    }
}
