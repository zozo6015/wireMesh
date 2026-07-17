//! DSL → IR compilation (design §5.2/§4): resolves segment names to
//! concrete CIDRs, assigns content-hash `rule_id`s, and preserves the
//! deterministic source order the DSL already guarantees.
//!
//! `compile` consumes an already-validated [`PolicySource`] (Task 1's
//! `parse_policy` did parse + all validation against `segments`) and may
//! assume it is valid — this is resolution + ordering + hashing only, not
//! re-validation.

use crate::dsl::PortSpec;
use crate::ir::{hex_encode, IrAction, IrBlock, IrProto, IrRule, PolicyIR};
use crate::{CompileError, PolicySource, SegmentDef};
use ipnet::Ipv4Net;
use sha2::{Digest, Sha256};

/// The max-rules-per-policy limit (design §6: "the controller rejects at
/// compile time what the gateway would reject at eBPF-load time"). Must be
/// kept numerically equal to `wiremesh_enforcer::flatten::MAX_RULES` — that
/// crate cannot be depended on here (it depends on `wiremesh-policy`, not
/// the other way around), so the constant is duplicated rather than shared;
/// this is the compile-time half of the check, `flatten`'s is the
/// (redundant, defense-in-depth) load-time half a gateway would hit if this
/// guard were ever bypassed.
const MAX_RULES: usize = 256;

/// Compiles `src` (already validated against `segments` by
/// [`crate::parse_policy`]) into a [`PolicyIR`] tagged with `version`.
/// Design §4's determinism guarantee: two calls with the same `src` and
/// `segments` produce byte-identical `to_canonical_json()` output,
/// regardless of `version`.
///
/// This function trusts [`crate::parse_policy`]'s validation completely
/// (unknown segments, non-subset CIDRs, malformed ports/CIDRs, missing
/// action, `ports` without `proto: tcp|udp` are all Task 1's job and
/// cannot occur here) — it only resolves, normalizes, orders, and hashes.
pub fn compile(
    src: &PolicySource,
    segments: &[SegmentDef],
    version: u64,
) -> Result<PolicyIR, Vec<CompileError>> {
    let mut blocks = Vec::with_capacity(src.0.policy.len());

    for block in &src.0.policy {
        // `parse_policy` already guarantees both names resolve.
        let from_seg = segments
            .iter()
            .find(|s| s.name == block.from)
            .expect("compile() requires an already-validated PolicySource: unknown `from` segment");
        let to_seg = segments
            .iter()
            .find(|s| s.name == block.to)
            .expect("compile() requires an already-validated PolicySource: unknown `to` segment");

        let src_cidrs = sorted_cidr_strings(&from_seg.cidrs);
        let dst_cidrs = sorted_cidr_strings(&to_seg.cidrs);

        let mut rules = Vec::with_capacity(block.rules.len());
        for rule in &block.rules {
            // Exactly-one-of-allow/deny is Task 1's job; `parse_policy`
            // never returns a valid `PolicySource` otherwise.
            let (action, body) = match (&rule.allow, &rule.deny) {
                (Some(body), None) => (IrAction::Allow, body),
                (None, Some(body)) => (IrAction::Deny, body),
                _ => unreachable!(
                    "compile() requires an already-validated PolicySource: rule needs exactly one of allow/deny"
                ),
            };

            let proto = match body.proto.as_deref() {
                None => IrProto::Any,
                Some("tcp") => IrProto::Tcp,
                Some("udp") => IrProto::Udp,
                Some("icmp") => IrProto::Icmp,
                Some("any") => IrProto::Any,
                Some(other) => unreachable!(
                    "compile() requires an already-validated PolicySource: unrecognized proto '{other}'"
                ),
            };

            let src_ips = normalized_cidr_strings(&body.src);
            let dst_ips = normalized_cidr_strings(&body.dst);
            let ports = body.ports.iter().map(normalize_port).collect::<Vec<_>>();

            let mut ir_rule = IrRule {
                rule_id: String::new(),
                action,
                proto,
                src: src_ips,
                dst: dst_ips,
                ports,
            };
            ir_rule.rule_id = rule_id(&block.from, &block.to, &ir_rule);
            rules.push(ir_rule);
        }

        blocks.push(IrBlock {
            from: block.from.clone(),
            to: block.to.clone(),
            src_cidrs,
            dst_cidrs,
            rules,
        });
    }

    // Flattened-rule-count guard (design §6): a rule with no `ports` becomes
    // exactly one eBPF-table entry ("(0,0) = any", the same convention
    // `wiremesh_enforcer::flatten` uses); a rule with k port ranges explodes
    // into k entries sharing one `rule_id`. Reject here — at compile time —
    // whatever total would blow the eBPF table's MAX_RULES budget at load
    // time, so a bad policy never even reaches a gateway.
    let flattened_count: usize = blocks
        .iter()
        .flat_map(|b| &b.rules)
        .map(|r| r.ports.len().max(1))
        .sum();
    if flattened_count > MAX_RULES {
        return Err(vec![CompileError {
            block: None,
            rule: None,
            msg: format!(
                "policy flattens to {flattened_count} rules, exceeding the \
                 {MAX_RULES}-rule limit (MAX_RULES; see wiremesh_enforcer::flatten::MAX_RULES)"
            ),
        }]);
    }

    Ok(PolicyIR {
        schema: 1,
        version,
        blocks,
    })
}

/// Sorts a segment's CIDRs lexically by `(addr, prefix)` (design §4/
/// D-C3-1) and renders each via `Ipv4Net`'s `Display` (e.g. `10.0.0.1/32`).
fn sorted_cidr_strings(cidrs: &[Ipv4Net]) -> Vec<String> {
    let mut sorted: Vec<&Ipv4Net> = cidrs.iter().collect();
    sorted.sort_by_key(|c| (c.addr(), c.prefix_len()));
    sorted.iter().map(|c| c.to_string()).collect()
}

/// Normalizes a rule's own `src`/`dst` CIDR strings via `Ipv4Net`'s
/// `Display`, keeping written order (design §4/D-C3-1) — no sorting.
/// `parse_policy` already guarantees every entry parses as `Ipv4Net`.
fn normalized_cidr_strings(raw: &[String]) -> Vec<String> {
    raw.iter()
        .map(|s| {
            s.parse::<Ipv4Net>()
                .unwrap_or_else(|_| {
                    unreachable!(
                        "compile() requires an already-validated PolicySource: invalid CIDR '{s}'"
                    )
                })
                .to_string()
        })
        .collect()
}

/// A bare DSL port `p` becomes `(p, p)`; a `"lo-hi"` range becomes
/// `(lo, hi)`. `parse_policy` already guarantees both forms are
/// well-formed and in `1..=65535`.
fn normalize_port(spec: &PortSpec) -> (u16, u16) {
    match spec {
        PortSpec::Single(n) => {
            let p = *n as u16;
            (p, p)
        }
        PortSpec::Range(s) => {
            let (lo, hi) = s
                .split_once('-')
                .unwrap_or_else(|| unreachable!("compile() requires an already-validated PolicySource: malformed port range '{s}'"));
            (
                lo.trim().parse().unwrap_or_else(|_| unreachable!("invalid port '{lo}'")),
                hi.trim().parse().unwrap_or_else(|_| unreachable!("invalid port '{hi}'")),
            )
        }
    }
}

/// Content-hash rule id (design D-C3-3): first 8 bytes of
/// `sha256("{from}|{to}|{action}|{proto}|src={src.join(\",\")}|dst={dst.join(\",\")}|ports={lo}-{hi},...")`,
/// hex-encoded (16 hex chars), computed over the rule's *normalized*
/// fields (post CIDR normalization, post single-port-to-range expansion).
/// Depends only on `from`/`to`/the rule's own fields — not on sibling
/// rules in the same block, and not on `version`.
pub fn rule_id(from: &str, to: &str, rule: &IrRule) -> String {
    let action = match rule.action {
        IrAction::Allow => "allow",
        IrAction::Deny => "deny",
    };
    let proto = match rule.proto {
        IrProto::Tcp => "tcp",
        IrProto::Udp => "udp",
        IrProto::Icmp => "icmp",
        IrProto::Any => "any",
    };
    let src = rule.src.join(",");
    let dst = rule.dst.join(",");
    let ports = rule
        .ports
        .iter()
        .map(|(lo, hi)| format!("{lo}-{hi}"))
        .collect::<Vec<_>>()
        .join(",");

    let preimage = format!("{from}|{to}|{action}|{proto}|src={src}|dst={dst}|ports={ports}");
    let digest = Sha256::digest(preimage.as_bytes());
    hex_encode(&digest[..8])
}
