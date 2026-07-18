//! `nft` — the nftables fallback backend: pure codegen (Task 11,
//! [`ruleset`]) plus the live, privileged [`Enforcer`] impl
//! ([`NftEnforcer`], Task 12; `.superpowers/sdd/task-12-brief.md`).
//!
//! [`NftEnforcer::apply`] pipes [`ruleset`]'s output to `nft -f -` as ONE
//! atomic transaction (design D-C3-6): either the whole replace commits, or
//! `nft` rejects it and the PREVIOUS ruleset stays live untouched (nft's own
//! transactional semantics — there is nothing for this code to roll back).
//!
//! **Empirical correction to the Task 12 brief's counter-reset premise**
//! (recorded in full in `docs/research/cycle3-policy-notes.md`): the brief
//! assumed "named nft counters reset on ruleset replace" and specified a
//! Rust-side offset accumulator to compensate. Verified directly against
//! this kernel/nft version (`nft -j list counters` before/after a `flush
//! table` + identical redeclare): a named counter object is NOT reset by
//! `flush table` — it keeps its handle and its accumulated value as long as
//! the SAME name is redeclared in the new ruleset. This actually makes
//! survival-across-re-apply *automatic* (no accumulator needed at all: two
//! `apply()` calls with the same rule → same `rule_id` → same `counter
//! r_<rule_id> {}` name → same persistent counter object), and reveals a
//! DIFFERENT real problem the brief's design didn't anticipate: `flush
//! table` also does NOT delete a counter object that the new ruleset simply
//! stops redeclaring (a rule that's REMOVED from the policy) — it survives
//! as an orphan, forever, unless explicitly `delete counter`d. Left alone,
//! every rule ever removed from any policy version leaks one counter object
//! per gateway for the rest of that gateway's uptime, and `counters()` would
//! keep reporting a phantom entry for a rule that's long gone. So instead of
//! an accumulator, [`NftEnforcer::apply`] explicitly prunes: after the
//! atomic replace commits (only after — deleting a counter still referenced
//! by a live rule fails with `EBUSY`, verified empirically), any table
//! counter whose `rule_id` is no longer in the newly-applied policy is
//! deleted in a follow-up `nft -f -` call. `counters()` itself is then just
//! a direct, unmodified read of `nft -j list counters` — the nftables
//! backend's counterpart to the eBPF backend's `counter_accum`/
//! `prune_retired_counters` pair, achieved by relying on nft's own object
//! persistence instead of re-implementing it in Rust.

use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;
use std::io::Write as _;
use std::process::{Command, Stdio};

use anyhow::Context;
use ipnet::Ipv4Net;
use wiremesh_policy::{IrAction, IrProto, PolicyIR};

use crate::flatten::{flatten, FlatRule};
use crate::{BackendKind, Counters, DenyEvent, Enforcer, EnforcerConfig};

/// IR → complete `nft -f` script: an atomic replace of the dedicated
/// `table ip wiremesh_<iface>` (design §6/D-C3-6). See
/// `tests/nft_codegen.rs` and `tests/fixtures/*.nft` for the exact,
/// golden-tested shape this must produce.
pub fn ruleset(ir: &PolicyIR, iface: &str) -> anyhow::Result<String> {
    let flat = flatten(ir)?;

    // Distinct rule_ids, first-appearance order over the flattened list
    // (NOT sorted, NOT hash-set dedup order — see the tests report's
    // ordering-determinism note).
    let mut seen = HashSet::new();
    let mut rule_ids = Vec::new();
    for f in &flat {
        if seen.insert(f.rule_id.as_str()) {
            rule_ids.push(f.rule_id.as_str());
        }
    }

    let mut out = String::new();
    let _ = writeln!(out, "table ip wiremesh_{iface}");
    let _ = writeln!(out, "flush table ip wiremesh_{iface}");
    let _ = writeln!(out, "table ip wiremesh_{iface} {{");

    for id in &rule_ids {
        let _ = writeln!(out, "  counter r_{id} {{}}");
    }
    let _ = writeln!(out, "  counter default_deny {{}}");

    let _ = writeln!(out, "  chain from_fabric {{");
    // Statefulness via conntrack. `established,related` — NOT `new` — is
    // deliberate: adding `new` would let every not-yet-established flow bypass
    // rule evaluation, breaking new-connection enforcement across a policy
    // update. The accepted consequence (ratified Cycle 3 conformance finding,
    // owner decision 2026-07-18) is that a purely one-way UDP flow — one whose
    // destination never replies — never leaves conntrack `new`, so unlike the
    // eBPF backend's FLOWS map it does NOT survive a rule-removing update; it
    // is re-evaluated (and dropped) on the next packet. All TCP and all
    // bidirectional flows are unaffected. See docs/research/cycle3-policy-notes.md
    // and the Cycle 3 design §1.
    let _ = writeln!(out, "    ct state established,related counter accept");
    for f in &flat {
        write_rule_lines(&mut out, f);
    }
    let _ = writeln!(out, "    counter name \"default_deny\" drop");
    let _ = writeln!(out, "  }}");

    let _ = writeln!(
        out,
        "  chain input {{ type filter hook input priority 0; policy accept; iifname \"{iface}\" jump from_fabric; }}"
    );
    let _ = writeln!(
        out,
        "  chain forward {{ type filter hook forward priority 0; policy accept; iifname \"{iface}\" jump from_fabric; }}"
    );

    let _ = writeln!(out, "}}");

    Ok(out)
}

/// `{ a, b, c }` — nft anonymous-set syntax, always bracketed regardless of
/// element count (uniform codegen, no cardinality branch; also the form the
/// Task 11 brief's own worked example uses even for a single CIDR).
fn cidr_set(cidrs: &[Ipv4Net]) -> String {
    let parts: Vec<String> = cidrs.iter().map(|c| c.to_string()).collect();
    format!("{{ {} }}", parts.join(", "))
}

/// `accept` / `drop` for allow/deny.
fn verdict(action: &IrAction) -> &'static str {
    match action {
        IrAction::Allow => "accept",
        IrAction::Deny => "drop",
    }
}

/// The protocol/port match clause for one concrete proto (never `Any` —
/// callers resolve `Any` into its three concrete protos before calling
/// this). `icmp` and any `(0, 0)` ("any port") FlatRule use the standalone
/// `meta l4proto <proto>` form (a bare `tcp`/`udp`/`icmp` token is not a
/// valid standalone nft match — verified against the real `nft` binary, see
/// the tests report); a concrete port range uses `<proto> dport { ... }`,
/// collapsing to a single value when `lo == hi`.
fn proto_match(proto_str: &str, port_lo: u16, port_hi: u16) -> String {
    if port_lo == 0 && port_hi == 0 {
        format!("meta l4proto {proto_str}")
    } else if port_lo == port_hi {
        format!("{proto_str} dport {{ {port_lo} }}")
    } else {
        format!("{proto_str} dport {{ {port_lo}-{port_hi} }}")
    }
}

/// Appends one flattened rule's `from_fabric` line(s). `proto: any` explodes
/// into 3 consecutive lines (tcp/udp/icmp, in that fixed order) sharing the
/// rule's one named counter and verdict; every other proto emits exactly one
/// line. Icmp never carries a port range (flatten's contract), so it always
/// takes the `meta l4proto icmp` form.
fn write_rule_lines(out: &mut String, f: &FlatRule) {
    let saddr = cidr_set(&f.src_cidrs);
    let daddr = cidr_set(&f.dst_cidrs);
    let verdict = verdict(&f.action);

    let protos: &[&str] = match f.proto {
        IrProto::Tcp => &["tcp"],
        IrProto::Udp => &["udp"],
        IrProto::Icmp => &["icmp"],
        IrProto::Any => &["tcp", "udp", "icmp"],
    };

    for proto_str in protos {
        let (lo, hi) = if *proto_str == "icmp" {
            (0, 0)
        } else {
            (f.port_lo, f.port_hi)
        };
        let pm = proto_match(proto_str, lo, hi);
        let _ = writeln!(
            out,
            "    ip saddr {saddr} ip daddr {daddr} {pm} counter name \"r_{}\" {verdict}",
            f.rule_id
        );
    }
}

// --- Task 12: the live, privileged nftables `Enforcer` backend -----------

/// The live nftables fallback [`Enforcer`] backend: no persistent kernel
/// handle to hold (unlike [`crate::ebpf::EbpfEnforcer`]'s loaded [`aya::Ebpf`]
/// object) and, per this module's doc comment's empirical finding, no
/// in-memory counter bookkeeping either — every [`Enforcer`] method just
/// shells out to the `nft` binary against this instance's dedicated
/// `table ip wiremesh_<iface>`, which is where ALL of this backend's state
/// (rules, verdicts, counters) actually lives.
pub struct NftEnforcer {
    iface: String,
    #[allow(dead_code)] // EnforcerConfig's flow-table/idle-timeout/rate-cap/
    // log-sampling knobs are all eBPF-map-backed concepts (Task 9/10) with
    // no nftables equivalent this backend implements — kept only so a
    // future task can read the effective config back off a live
    // `NftEnforcer` without another `new` signature change, matching
    // `EbpfEnforcer::cfg`'s identical `#[allow(dead_code)]` rationale.
    cfg: EnforcerConfig,
}

impl NftEnforcer {
    /// Constructs a fresh `NftEnforcer` for `iface`. Does NOT touch the
    /// kernel's nftables state at all — no table is created (and no `nft`
    /// subprocess run) until the first [`Enforcer::apply`] call, mirroring
    /// how [`crate::probe_with`]'s `Nftables` arm is meant to be a cheap,
    /// side-effect-free constructor (the eBPF backend's `new`, by contrast,
    /// genuinely loads+attaches at construction time, since there's no
    /// separate "apply" step that could do it later for THAT backend's
    /// design).
    pub(crate) fn new(iface: &str, cfg: EnforcerConfig) -> anyhow::Result<Self> {
        Ok(Self { iface: iface.to_string(), cfg })
    }
}

/// `table ip <table>`'s name for `iface`, matching [`ruleset`]'s own
/// `table ip wiremesh_<iface>` naming exactly.
fn table_name(iface: &str) -> String {
    format!("wiremesh_{iface}")
}

/// Reads the CURRENT live counters for `iface`'s table via
/// `nft -j list counters table ip <table>`, parsed into the same
/// [`Counters`] shape `Enforcer::counters` returns (raw, unfolded — callers
/// combine this with their own offset accumulator).
///
/// Before the very first `apply()`, `iface`'s table doesn't exist yet — nft
/// exits non-zero with a "No such file or directory" stderr message in that
/// case, which is treated as "no counters yet" (all zero) rather than a real
/// error, exactly like the eBPF backend's `GenerationState` starts empty
/// before its first `apply()`.
fn read_live_counters(iface: &str) -> anyhow::Result<Counters> {
    let table = table_name(iface);
    let out = Command::new("nft")
        .args(["-j", "list", "counters", "table", "ip", &table])
        .output()
        .context("spawning nft -j list counters")?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("No such file or directory") || stderr.contains("does not exist") {
            // No apply() yet -- nothing to read, nothing folded.
            return Ok(Counters::default());
        }
        anyhow::bail!(
            "nft -j list counters table ip {table} failed: {}",
            stderr.trim()
        );
    }

    parse_counters_json(&out.stdout, &table)
}

/// Parses `nft -j list counters`'s JSON shape
/// (`{"nftables": [{"counter": {"name": .., "table": .., "packets": ..}}, ...]}`,
/// plus a leading, irrelevant `{"metainfo": ..}` entry) into a [`Counters`].
/// Every counter [`ruleset`] emits is named either `r_<rule_id>` (stripped
/// back to the bare `rule_id` here, matching `by_rule`'s key convention) or
/// the fixed `default_deny` — anything else (there shouldn't be anything
/// else, but a stray/foreign counter in the same table is skipped rather
/// than mis-parsed) is ignored.
fn parse_counters_json(bytes: &[u8], table: &str) -> anyhow::Result<Counters> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).context("parsing nft -j list counters JSON output")?;

    let mut by_rule = BTreeMap::new();
    let mut default_deny = 0u64;

    let entries = value
        .get("nftables")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    for entry in entries {
        let Some(counter) = entry.get("counter") else {
            continue;
        };
        if counter.get("table").and_then(|v| v.as_str()) != Some(table) {
            continue; // defensive -- `nft ... table ip <table>` already scopes the listing
        }
        let Some(name) = counter.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let packets = counter.get("packets").and_then(|v| v.as_u64()).unwrap_or(0);

        if let Some(rule_id) = name.strip_prefix("r_") {
            by_rule.insert(rule_id.to_string(), packets);
        } else if name == "default_deny" {
            default_deny = packets;
        }
    }

    Ok(Counters { by_rule, default_deny })
}

/// Pipes `script` to `nft -f -` as a single subprocess invocation: the whole
/// script is one atomic transaction (design D-C3-6), so either every
/// statement in it commits or `nft` rejects the entire thing and the
/// PREVIOUS ruleset is left running completely untouched -- nft's own
/// transactional semantics, not something this function implements itself.
/// A non-zero exit surfaces `nft`'s stderr in the returned `Err` so callers
/// (and `Enforcer::apply`'s caller) can see exactly what nft rejected.
fn apply_script(script: &str) -> anyhow::Result<()> {
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawning nft -f -")?;

    child
        .stdin
        .take()
        .expect("just configured with Stdio::piped()")
        .write_all(script.as_bytes())
        .context("writing ruleset script to nft's stdin")?;

    let out = child
        .wait_with_output()
        .context("waiting for nft -f - to exit")?;

    if !out.status.success() {
        anyhow::bail!(
            "nft -f - rejected the ruleset (previous ruleset remains live, per nft's atomic \
             transaction semantics): {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Deletes every counter object in `iface`'s table whose `rule_id` is no
/// longer present in `flat` (the just-applied policy's flattened rule
/// list) — the follow-up half of the pruning this module's doc comment
/// describes. MUST be called only AFTER the replace that stopped
/// referencing those counters has already committed: `nft` rejects
/// (`EBUSY`) an attempt to delete a counter a live rule still points at
/// (verified empirically), so calling this before the replace, or against
/// counters the new policy still uses, would be a correctness bug, not just
/// an ordering nicety.
///
/// **Entirely best-effort, start to finish — including the read.** This is
/// cleanup called AFTER `apply()`'s `apply_script()` has already committed
/// the new ruleset (the part that actually matters for enforcement); by the
/// time this runs, the spec guarantee "a failed apply keeps the previous
/// ruleset" no longer applies, because the apply in question already
/// succeeded. So NEITHER the counter read NOR the delete may propagate an
/// `Err` out of this function — doing so from `apply()`'s caller's point of
/// view would be indistinguishable from "the replace itself failed and the
/// old ruleset is still live," which would be false: the new ruleset IS
/// live, only bookkeeping cleanup didn't complete. (Review finding,
/// coordinator-relayed: the read half of this function originally used `?`
/// and leaked exactly that ambiguity — fixed here to match the delete
/// half's already-correct log-and-swallow shape.) A failure here (e.g. a
/// transient `nft -j` read fault, or a counter deleted by a concurrent
/// caller between the read and the delete — this crate's `Enforcer`s are
/// not documented as safe to drive concurrently from multiple threads
/// against the same `iface`, so that's a defensive fallback, not an
/// expected path) is logged to stderr and otherwise ignored.
fn prune_retired_counters(iface: &str, flat: &[FlatRule]) {
    let live = match read_live_counters(iface) {
        Ok(live) => live,
        Err(e) => {
            eprintln!(
                "wiremesh-enforcer: reading live counters on {iface} to prune retired ones \
                 failed (non-fatal -- the policy replace itself already succeeded): {e:#}"
            );
            return;
        }
    };

    let active: HashSet<&str> = flat.iter().map(|f| f.rule_id.as_str()).collect();
    let stale: Vec<&String> = live
        .by_rule
        .keys()
        .filter(|id| !active.contains(id.as_str()))
        .collect();
    if stale.is_empty() {
        return;
    }

    // Unquoted identifier form -- unlike a `counter r_<id> {}` *declaration*
    // inside a `table { .. }` block (which accepts either form), the
    // standalone `delete counter` command rejects a quoted-string object
    // name outright (`nft --check`-verified: "syntax error, unexpected
    // quoted string, expecting handle or string" -- confusingly, nft's own
    // error names the syntax it wants "string", but only the BARE-identifier
    // form is actually accepted here, not `"..."`).
    let table = table_name(iface);
    let mut script = String::new();
    for id in &stale {
        let _ = writeln!(script, "delete counter ip {table} r_{id}");
    }
    if let Err(e) = apply_script(&script) {
        eprintln!(
            "wiremesh-enforcer: pruning {} retired counter(s) on {iface} failed (non-fatal -- \
             the policy replace itself already succeeded): {e:#}",
            stale.len()
        );
    }
}

impl Enforcer for NftEnforcer {
    fn kind(&self) -> BackendKind {
        BackendKind::Nftables
    }

    /// Replaces the whole ruleset atomically via `nft -f -`, then prunes any
    /// now-orphaned rule counter (this module's doc comment's empirical
    /// finding: nft's own named counters already survive a same-name
    /// re-apply on their own, so there is nothing to fold here — the only
    /// thing THIS code must actively do is clean up counters for rules the
    /// new policy no longer has, which `flush table` alone does not do).
    ///
    /// **Error contract:** once `apply_script` returns `Ok` here, THIS
    /// method returns `Ok` regardless of what `prune_retired_counters` finds
    /// — that call is post-commit cleanup, never a condition on whether the
    /// new ruleset is live. Only `flatten`'s or `apply_script`'s own `Err`
    /// (i.e. a failure BEFORE or DURING the replace, when the previous
    /// ruleset is still guaranteed live per nft's transactional semantics)
    /// propagates out of `apply()`; see `prune_retired_counters`'s doc
    /// comment for why conflating the two would break the "a failed apply
    /// keeps the previous ruleset" contract callers rely on.
    fn apply(&mut self, ir: &PolicyIR) -> anyhow::Result<()> {
        let flat = flatten(ir)?;
        let script = ruleset(ir, &self.iface)?;
        apply_script(&script)?;
        prune_retired_counters(&self.iface, &flat);
        Ok(())
    }

    /// A direct, unmodified read of `nft -j list counters table ip
    /// wiremesh_<iface>` — no accumulator to combine it with. Survival
    /// across a policy re-apply is nft's OWN behavior for a rule that stays
    /// present (same `rule_id` -> same counter name -> same object, per
    /// this module's doc comment), and a rule that's gone has already been
    /// pruned by the most recent `apply()`, so there's nothing stale left to
    /// filter out here either.
    fn counters(&mut self) -> anyhow::Result<Counters> {
        read_live_counters(&self.iface)
    }

    /// Flushes the kernel's conntrack table via `conntrack -F`, forcing
    /// every already-established fabric flow to be re-evaluated from
    /// scratch (as `ct state new`) against the CURRENT ruleset on its next
    /// packet — design §8/the master spec's `FlushFlows` parity promise for
    /// both backends. This was a documented no-op through Task 12
    /// (deferred, since nothing exercised it yet); Task 13's conformance
    /// suite (`flush_flows_forces_reevaluation_of_an_established_flow`)
    /// added the first real caller and found the no-op insufficient — see
    /// `docs/research/cycle3-policy-notes.md`'s Task 13 section for the
    /// full RED-to-GREEN writeup.
    ///
    /// **Known, documented blast-radius limitation — read before assuming
    /// this is fabric-scoped like the eBPF backend's `flush_flows`:** the
    /// eBPF backend clears exactly its own `FLOWS` map (every entry in it
    /// was, by construction, created by THIS fabric's tc-attached `iface`
    /// traffic and nothing else). nftables has no equivalent "just this
    /// table's flows" primitive, and three scoping mechanisms that would
    /// get closer were each ruled out, empirically or by scope:
    ///  - **conntrack zone:** `conntrack -F` (and `-D`) accept a `-w/--zone`
    ///    filter, which WOULD scope this precisely — but only if the
    ///    fabric's own ruleset tags its connections with a dedicated zone
    ///    via `ct zone set <n>` at `apply()` time. [`ruleset`] (Task 11,
    ///    golden-fixture-pinned) doesn't do this, and adding it would
    ///    change every fixture's expected byte-for-byte output — out of
    ///    this fix's scope, left for whoever next revisits `ruleset`'s
    ///    codegen with a real need for conntrack zones.
    ///  - **interface:** verified empirically (`conntrack -L -o extended`)
    ///    that a conntrack entry carries no ingress/egress-interface field
    ///    at all in this tool's output — there is nothing to filter
    ///    `conntrack -D` on by `iface`.
    ///  - **segment CIDRs (`-s`/`-d` + `--mask-src`/`--mask-dst`):** ruled
    ///    out on correctness grounds, not just inconvenience — this exact
    ///    method's own driving scenario re-applies a policy that REMOVES
    ///    every CIDR/rule for the flow that must be flushed (see the
    ///    conformance scenario's `ApplyPolicy { yaml: "policy: []\n" }`
    ///    step), so scoping a delete to "the currently-applied policy's
    ///    CIDRs" would delete NOTHING — it would silently fail to flush
    ///    the exact flow the caller needs flushed. Scoping to the UNION of
    ///    every CIDR ever seen across this `NftEnforcer`'s lifetime would
    ///    dodge that specific failure but adds unbounded per-instance state
    ///    for a narrowing that still isn't truly fabric-scoped (a
    ///    coincidentally-reused address from an unrelated, non-fabric
    ///    connection sharing the same netns would still be swept).
    ///
    /// So this flushes the WHOLE network namespace's conntrack table —
    /// broader than "just this fabric's flows," matching the design's
    /// single-purpose-gateway model (§1: "one gateway per segment," no
    /// other workload traffic expected in that netns) but NOT a guarantee
    /// if a real deployment ever runs other stateful traffic through the
    /// same netns as the gateway process. Acceptable for now per explicit
    /// review sign-off; a future task with a real requirement for narrower
    /// scoping should revisit `ruleset`'s codegen to add a conntrack zone.
    ///
    /// **Error contract:** unlike `prune_retired_counters` (best-effort
    /// cleanup after an already-committed `apply()`), a `flush_flows()`
    /// call is itself the caller's explicit, entire request — there is no
    /// "the important part already succeeded" to fall back on if
    /// `conntrack -F` fails, so a failure here surfaces as `Err`, not a
    /// logged-and-swallowed no-op.
    fn flush_flows(&mut self) -> anyhow::Result<()> {
        let out = Command::new("conntrack")
            .args(["-F"])
            .output()
            .context("spawning conntrack -F")?;
        if !out.status.success() {
            anyhow::bail!(
                "conntrack -F failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    /// Documented empty (brief's explicit allowance): the nftables backend
    /// has no ring-buffer-equivalent deny-event channel the way the eBPF
    /// backend's `DENY_RB` does (`ebpf.rs`'s `deny_events`) -- nft's deny
    /// path is just a `drop` verdict plus a counter bump, with no per-packet
    /// sample ever leaving the kernel. None of Task 12's tests call this
    /// method either. Deny-event *logging* parity between the two backends
    /// is explicitly out of this task's scope per the brief.
    fn deny_events(&mut self) -> anyhow::Result<Vec<DenyEvent>> {
        Ok(Vec::new())
    }
}
