//! Validation for the parsed policy DSL (design §4).
//!
//! `validate` walks the parsed [`PolicyDoc`] in source order (design §4's
//! determinism guarantee) and collects *every* independent error it finds
//! — it never stops at the first one. Each error is a located
//! [`CompileError`] naming the block (and rule, where applicable) it came
//! from.

use crate::dsl::{PolicyDoc, PortSpec, RuleBody, RuleSrc};
use crate::{CompileError, SegmentDef};
use ipnet::{IpNet, Ipv4Net};
use std::collections::HashSet;

/// Validates `doc` against `segments`, returning every compile error found
/// (empty if the document is valid).
pub fn validate(doc: &PolicyDoc, segments: &[SegmentDef]) -> Vec<CompileError> {
    let mut errors = Vec::new();
    let mut seen_pairs: HashSet<(&str, &str)> = HashSet::new();

    for (block_idx, block) in doc.policy.iter().enumerate() {
        let ctx = format!("({}\u{2192}{})", block.from, block.to);

        let from_seg = segments.iter().find(|s| s.name == block.from);
        if from_seg.is_none() {
            errors.push(CompileError {
                block: Some(block_idx),
                rule: None,
                msg: format!("{ctx} unknown segment '{}' in from", block.from),
            });
        }
        let to_seg = segments.iter().find(|s| s.name == block.to);
        if to_seg.is_none() {
            errors.push(CompileError {
                block: Some(block_idx),
                rule: None,
                msg: format!("{ctx} unknown segment '{}' in to", block.to),
            });
        }

        if !seen_pairs.insert((block.from.as_str(), block.to.as_str())) {
            errors.push(CompileError {
                block: Some(block_idx),
                rule: None,
                msg: format!(
                    "{ctx} duplicate block for ordered (from, to) pair '{}' \u{2192} '{}'",
                    block.from, block.to
                ),
            });
        }

        for (rule_idx, rule) in block.rules.iter().enumerate() {
            validate_rule(block_idx, rule_idx, &ctx, from_seg, to_seg, rule, &mut errors);
        }
    }

    errors
}

fn validate_rule(
    block_idx: usize,
    rule_idx: usize,
    ctx: &str,
    from_seg: Option<&SegmentDef>,
    to_seg: Option<&SegmentDef>,
    rule: &RuleSrc,
    errors: &mut Vec<CompileError>,
) {
    let body = match (&rule.allow, &rule.deny) {
        (Some(body), None) | (None, Some(body)) => body,
        (None, None) => {
            errors.push(CompileError {
                block: Some(block_idx),
                rule: Some(rule_idx),
                msg: format!("{ctx} rule needs exactly one of allow/deny"),
            });
            return;
        }
        (Some(_), Some(_)) => {
            errors.push(CompileError {
                block: Some(block_idx),
                rule: Some(rule_idx),
                msg: format!("{ctx} rule needs exactly one of allow/deny (both present)"),
            });
            return;
        }
    };

    validate_cidrs(block_idx, rule_idx, ctx, "src", &body.src, from_seg, errors);
    validate_cidrs(block_idx, rule_idx, ctx, "dst", &body.dst, to_seg, errors);
    validate_ports(block_idx, rule_idx, ctx, body, errors);
}

/// Checks every CIDR string in `field` (`src`/`dst`) is a well-formed IPv4
/// CIDR and a subset of at least one of `segment`'s CIDRs. Skips the
/// subset half of the check when `segment` is `None` — the unknown-segment
/// error for that block already covers it, and there is no CIDR list to
/// compare against.
fn validate_cidrs(
    block_idx: usize,
    rule_idx: usize,
    ctx: &str,
    field: &str,
    values: &[String],
    segment: Option<&SegmentDef>,
    errors: &mut Vec<CompileError>,
) {
    for raw in values {
        let v4 = match raw.parse::<Ipv4Net>() {
            Ok(v4) => v4,
            Err(_) => {
                // Not a valid IPv4 CIDR. Distinguish "syntactically valid
                // but IPv6" (non-IPv4, v1 is IPv4-only) from genuinely
                // malformed, so the two error classes get distinct
                // messages (design §4).
                match raw.parse::<IpNet>() {
                    Ok(IpNet::V6(_)) => {
                        errors.push(CompileError {
                            block: Some(block_idx),
                            rule: Some(rule_idx),
                            msg: format!(
                                "{ctx} {field} '{raw}' is not IPv4 (v1 is IPv4-only)"
                            ),
                        });
                    }
                    _ => {
                        errors.push(CompileError {
                            block: Some(block_idx),
                            rule: Some(rule_idx),
                            msg: format!("{ctx} {field} '{raw}': invalid CIDR"),
                        });
                    }
                }
                continue;
            }
        };

        if let Some(seg) = segment {
            let subset = seg.cidrs.iter().any(|seg_cidr| seg_cidr.contains(&v4));
            if !subset {
                errors.push(CompileError {
                    block: Some(block_idx),
                    rule: Some(rule_idx),
                    msg: format!(
                        "{ctx} {field} '{raw}' is not a subset of segment's CIDRs"
                    ),
                });
            }
        }
    }
}

/// Checks `ports`/`proto` on one rule body: `ports` requires an explicit
/// `proto: tcp|udp` (design §4 — omitted proto defaults to tcp+udp+icmp,
/// and icmp has no ports); each port/range must be in `1..=65535` with
/// `lo <= hi`.
fn validate_ports(
    block_idx: usize,
    rule_idx: usize,
    ctx: &str,
    body: &RuleBody,
    errors: &mut Vec<CompileError>,
) {
    if body.ports.is_empty() {
        return;
    }

    match body.proto.as_deref() {
        Some("tcp") | Some("udp") => {}
        _ => {
            errors.push(CompileError {
                block: Some(block_idx),
                rule: Some(rule_idx),
                msg: format!("{ctx} ports require proto tcp|udp"),
            });
            return;
        }
    }

    for port in &body.ports {
        match port {
            PortSpec::Single(n) => {
                check_port_value(block_idx, rule_idx, ctx, *n, errors);
            }
            PortSpec::Range(s) => match parse_range(s) {
                Some((lo, hi)) => {
                    if check_port_value(block_idx, rule_idx, ctx, lo, errors)
                        && check_port_value(block_idx, rule_idx, ctx, hi, errors)
                        && lo > hi
                    {
                        errors.push(CompileError {
                            block: Some(block_idx),
                            rule: Some(rule_idx),
                            msg: format!(
                                "{ctx} port range '{s}' invalid: lo > hi ({lo} > {hi})"
                            ),
                        });
                    }
                }
                None => {
                    errors.push(CompileError {
                        block: Some(block_idx),
                        rule: Some(rule_idx),
                        msg: format!("{ctx} port range '{s}' is malformed (expected \"lo-hi\")"),
                    });
                }
            },
        }
    }
}

/// Parses a `"lo-hi"` range string into its two endpoints. `None` if the
/// string isn't exactly two `-`-separated integers.
fn parse_range(s: &str) -> Option<(i64, i64)> {
    let (lo, hi) = s.split_once('-')?;
    Some((lo.trim().parse().ok()?, hi.trim().parse().ok()?))
}

/// Validates a single port value is in `1..=65535`. Returns `true` if it
/// was in range (so range-inversion checks only run on two otherwise-valid
/// endpoints).
fn check_port_value(
    block_idx: usize,
    rule_idx: usize,
    ctx: &str,
    n: i64,
    errors: &mut Vec<CompileError>,
) -> bool {
    if n == 0 {
        errors.push(CompileError {
            block: Some(block_idx),
            rule: Some(rule_idx),
            msg: format!("{ctx} port 0 is not valid (ports are 1-65535)"),
        });
        false
    } else if !(1..=65535).contains(&n) {
        errors.push(CompileError {
            block: Some(block_idx),
            rule: Some(rule_idx),
            msg: format!("{ctx} port {n} is out of range (ports are 1-65535)"),
        });
        false
    } else {
        true
    }
}
