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
mod nft;

pub use ebpf::check_lpm_capacity;
pub use flatten::{flatten, FlatRule, MAX_RULES};
pub use nft::ruleset;

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
    /// (Review finding) The eBPF backend's "reap-on-next-apply + minimum
    /// N since flip" grace (design §6's "grace period: 10s after flip, then
    /// the old generation's maps are deleted" — see `ebpf::apply_generation`)
    /// as an injectable duration, defaulting to the design's 10s.
    ///
    /// **Backlog item 1 inverted what this knob buys a test.** It used to
    /// shrink an internal `std::thread::sleep` inside `apply()`; `apply()`
    /// no longer waits at all, and this value is now the offset
    /// [`Enforcer::apply_ready_at`] publishes past each flip. So it is what
    /// makes a test's OWN inter-flip spacing a sufficient honoring of the
    /// grace: `tests/generations.rs`'s
    /// `atomic_generation_flip_under_continuous_udp_traffic_has_zero_deficit`
    /// sleeps 175ms between flips, which only clears the grace because this
    /// is shrunk to 50ms; `wiremesh-testkit`'s `flip_under_traffic_zero_loss`
    /// waits out `apply_ready_at()` explicitly. Production callers get the
    /// real 10s via `Default`.
    pub reap_grace: std::time::Duration,
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
            reap_grace: ebpf::REAP_GRACE,
        }
    }
}

/// The backend-agnostic enforcement surface. Both the eBPF backend (this
/// task) and the nftables fallback (later task) implement this same trait,
/// so callers (the controller-facing gateway agent, `fabricctl`, tests) never
/// need to know which one is actually loaded.
///
/// `: Send` (added Cycle 4a Task 11): `wiremesh-gateway` shares a live
/// `Box<dyn Enforcer>` between its sync loop and its metrics-scrape task via
/// `Arc<tokio::sync::Mutex<_>>`, which requires the trait object itself to be
/// `Send`. Both concrete backends (`EbpfEnforcer`'s `aya::Ebpf`, `NftEnforcer`'s
/// plain `String`/config fields) already are, so this is purely additive.
pub trait Enforcer: Send {
    /// Which backend this instance is actually driving.
    fn kind(&self) -> BackendKind;
    /// Installs `ir` as the live rule set. Atomic: in-flight packets must
    /// never observe a half-applied policy (design §6's atomic generation
    /// flip — Task 8's map-in-map generations in the eBPF backend, `ebpf.rs`).
    ///
    /// **Does not wait out the previous flip's reap grace** (Backlog item 1):
    /// honoring [`Enforcer::apply_ready_at`] before calling this is the
    /// CALLER's job now. Calling `apply` early is still unsafe for the same
    /// reason it always was — it overwrites an outer-array slot in-flight
    /// packets may still be reading — the enforcement of that rule simply
    /// moved out of a thread-parking `sleep` and into a published deadline.
    fn apply(&mut self, ir: &PolicyIR) -> anyhow::Result<()>;
    /// The earliest instant at which the next [`Enforcer::apply`] may proceed
    /// without overwriting state that in-flight packets may still be reading.
    /// `None` means "no constraint"; a `Some(t)` already in the past is a
    /// SATISFIED constraint, not a request to wait.
    ///
    /// Cheap and non-blocking by contract: it never sleeps and never does
    /// kernel work. Its whole purpose is to let an async caller
    /// `sleep_until` the deadline WITHOUT occupying a thread — which is why
    /// it hands back a plain `Option<Instant>` rather than any kind of
    /// guard: an adapter that reads this across a live enforcer map is
    /// structurally unable to hold that map's lock across the wait (see
    /// `wiremesh_gateway::policy_apply::PolicyApplyTarget::ready_at`).
    ///
    /// The eBPF backend publishes `flip instant + reap_grace` while a
    /// generation reap is pending (design §6's 10s grace); the nftables
    /// backend always returns `None` — one atomic `nft -f -` transaction
    /// replaces the whole ruleset, so there is no vacated slot to protect.
    fn apply_ready_at(&self) -> Option<std::time::Instant>;
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
/// Task 12: the eBPF `Err` path (which Task 7 originally returned as-is, as
/// a final answer — the nftables backend didn't exist yet) is now a second
/// *attempt* rather than the end of the line: the eBPF failure's context is
/// logged to stderr (so an operator/CI log can see WHY it fell back — a
/// silent, undiagnosable fallback would be worse than the eBPF-only
/// behavior it replaces) and [`probe_with`]'s `Nftables` arm is tried next.
/// If nftables ALSO fails, that (not the original eBPF error) is what's
/// returned — the caller only cares about the last, most-relevant failure
/// once every backend has been tried.
pub fn probe(iface: &str, cfg: EnforcerConfig) -> anyhow::Result<Box<dyn Enforcer>> {
    // Validated here as well as in `probe_with` so an invalid name fails
    // once, cleanly, instead of also emitting the misleading "eBPF failed,
    // falling back to nftables" log line below for a name NO backend could
    // ever accept.
    validate_iface(iface)?;
    match probe_with(BackendKind::Ebpf, iface, cfg) {
        Ok(enforcer) => Ok(enforcer),
        Err(e) => {
            eprintln!(
                "wiremesh-enforcer: eBPF backend failed to load/attach on {iface} ({e:#}); \
                 falling back to the nftables backend (design §6/D-C3-4)"
            );
            probe_with(BackendKind::Nftables, iface, cfg)
        }
    }
}

/// Forced-choice counterpart to [`probe`]: loads exactly the requested
/// backend, with no eBPF-attempt-first fallback logic in the way. `probe`
/// itself is expressed in terms of this function's two arms (see `probe`'s
/// doc comment) — this is the one place either backend's constructor is
/// actually invoked.
///
/// Used directly by `tests/nft_backend.rs` to drive the nftables backend
/// deterministically in the privileged dev container, where a plain
/// `probe()` call would always pick `BackendKind::Ebpf` (eBPF always
/// succeeds there) and never exercise the nftables path at all — per
/// `.superpowers/sdd/task-12-brief.md`'s Interfaces section: "an env/knob-
/// free forced choice for tests: `probe_with(BackendKind, ...)`".
pub fn probe_with(
    kind: BackendKind,
    iface: &str,
    cfg: EnforcerConfig,
) -> anyhow::Result<Box<dyn Enforcer>> {
    // Boundary validation (Backlog 10 PR-A Item 3): both backends'
    // constructors are only ever reached through this function, so this one
    // call guards every constructor path before ANY kernel/filesystem work
    // (eBPF load/attach, bpffs pin paths) is attempted.
    validate_iface(iface)?;
    match kind {
        BackendKind::Ebpf => {
            let enforcer = ebpf::EbpfEnforcer::new(iface, cfg)?;
            Ok(Box::new(enforcer))
        }
        BackendKind::Nftables => {
            let enforcer = nft::NftEnforcer::new(iface, cfg)?;
            Ok(Box::new(enforcer))
        }
    }
}

/// Validates a Linux interface name at this crate's external boundaries
/// (Backlog 10 PR-A Item 3): [`probe`]/[`probe_with`] (the only routes to
/// either backend's constructor) and the pure [`ruleset`] codegen entry
/// point (the other public function that interpolates `iface` — into nft
/// script text). An unvalidated name would otherwise flow verbatim into
/// nft-script codegen (`iifname "<iface>"` — `"`/`}`/`#` are injection
/// vectors), shelled-out `nft`/`conntrack` invocations, and bpffs pin
/// paths (`/`/`..` traverse), and a >15-byte name only surfaces as a late,
/// opaque tc-attach failure (the kernel's IFNAMSIZ is 15 bytes + NUL).
///
/// Accepts: non-empty, at most 15 BYTES, charset `[A-Za-z0-9_.-]`, not
/// starting with `-` (reads as an option flag to every CLI the name
/// reaches) or `.` (hidden/relative path components in pin paths).
/// Rejection messages always contain `"invalid interface name"` — pinned
/// by `tests/iface_validation.rs`.
///
/// **`pub`, not `pub(crate)` (key-rotation T3):** the gateway's
/// `tunnelset::plan_tunnel` derives rotation-tun names and must refuse to
/// emit one this function would later reject. Re-implementing the predicate
/// there would let the two drift, and the drift only surfaces in production
/// as a late, opaque tc-attach failure long after the Device is half-built —
/// so the planner calls THIS, the same check the enforcer will apply.
pub fn validate_iface(iface: &str) -> anyhow::Result<()> {
    let charset_ok = iface
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    if iface.is_empty()
        || iface.len() > 15
        || !charset_ok
        || iface.starts_with('-')
        || iface.starts_with('.')
    {
        anyhow::bail!(
            "invalid interface name {iface:?}: must be 1-15 bytes of [A-Za-z0-9_.-] \
             and must not start with '-' or '.'"
        );
    }
    Ok(())
}
