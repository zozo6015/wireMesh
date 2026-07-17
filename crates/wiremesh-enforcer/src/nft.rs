//! `nft` — the nftables fallback backend's pure codegen half (design §6/
//! D-C3-6; cycle 3, Task 11; `.superpowers/sdd/task-11-brief.md`).
//!
//! Task 11 Step 1 (test author): only the signature stub below exists so far
//! — [`ruleset`] is `todo!()`. The golden tests in
//! `tests/nft_codegen.rs` pin the exact generated-script shape (table/flush/
//! counters/`from_fabric` chain/base chains) that Task 11 Step 3
//! (implementer) must produce byte-for-byte against
//! `tests/fixtures/*.nft`.
//!
//! The counter-offset accumulator (`offsets: BTreeMap<String, u64>`,
//! folding live nft counters across a `flush`-and-replace `apply`) described
//! in the brief is NOT part of this pure function — it belongs to the
//! `Enforcer` trait impl (Task 12's privileged nftables backend, which
//! actually shells out to `nft -f` and reads counters back). This module's
//! only job right now is turning a [`PolicyIR`] into ruleset text.

use std::collections::HashSet;
use std::fmt::Write as _;

use ipnet::Ipv4Net;
use wiremesh_policy::{IrAction, IrProto, PolicyIR};

use crate::flatten::{flatten, FlatRule};

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
