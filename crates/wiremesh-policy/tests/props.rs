//! Property tests over generated policies (Task 3, design §4/§5 invariants).
//!
//! Strategy (per the brief): 1-4 segments, each with 1-3 pairwise-disjoint
//! CIDRs; 0-4 blocks over distinct ordered `(from, to)` pairs; 0-6 rules per
//! block, each valid-by-construction (proto/ports/src/dst combinations that
//! `validate.rs` is known to accept). Rather than generating raw YAML text
//! or arbitrary strings, we generate a small structured `GenPolicy` and
//! render it to YAML — this keeps every generated case guaranteed
//! parseable and (mostly) guaranteed valid, so `parse_policy` failures are
//! themselves informative (see `valid_by_construction_always_compiles_ok`).
//!
//! CIDR assignment is deterministic, not randomly generated: segment `i`'s
//! CIDRs are carved out of successive `/24`s under `10.0.0.0/16`
//! (`10.0.0.0/24`, `10.0.1.0/24`, ...), assigned by a running counter across
//! *all* segments. This guarantees every segment's CIDR set is disjoint
//! from every other segment's — not just "1-3 disjoint CIDRs" within one
//! segment — which property (g) (an out-of-segment CIDR must be rejected)
//! depends on: any CIDR borrowed from a different segment is guaranteed to
//! fail the subset check, never accidentally contained by coincidence.
//!
//! Per-block rule dedup: `rule_id` is a pure content hash (design D-C3-3),
//! so two structurally-identical rules within the *same* block would
//! legitimately hash to the same id — that's correct behavior, not a bug,
//! so generating such a pair would make property (d) ("every rule_id is
//! unique") fail for a reason that isn't a real defect. We dedupe
//! generated rules within each block by their normalized content signature
//! before rendering, so (d)'s uniqueness assumption is meaningful: any
//! collision it finds is a genuine `rule_id` bug, not a generator artifact.
//! (Cross-block collisions aren't a concern: every block has a distinct
//! `(from, to)` pair by construction, and that pair is part of the hash
//! preimage.)

use proptest::prelude::*;
use std::collections::HashSet;
use wiremesh_policy::{compile, parse_policy, SegmentDef};

// ---------------------------------------------------------------------------
// Generated policy model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct GenSegment {
    name: String,
    cidrs: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum PortLit {
    Single(u16),
    Range(u16, u16),
}

#[derive(Debug, Clone)]
struct GenRule {
    action: &'static str,        // "allow" | "deny"
    proto: Option<&'static str>, // None | "tcp" | "udp" | "icmp"
    src: Vec<String>,
    dst: Vec<String>,
    ports: Vec<PortLit>,
}

#[derive(Debug, Clone)]
struct GenBlock {
    from_idx: usize,
    to_idx: usize,
    rules: Vec<GenRule>,
}

#[derive(Debug, Clone)]
struct GenPolicy {
    segments: Vec<GenSegment>,
    blocks: Vec<GenBlock>,
}

// ---------------------------------------------------------------------------
// Rendering: GenPolicy -> (YAML text, Vec<SegmentDef>)
// ---------------------------------------------------------------------------

fn render_ports(ports: &[PortLit]) -> String {
    ports
        .iter()
        .map(|p| match p {
            PortLit::Single(n) => n.to_string(),
            // Quoted, matching the master spec §5.1 example's "lo-hi" style
            // (an unquoted `8000-8080` is a fine YAML plain scalar too, but
            // quoting removes any doubt).
            PortLit::Range(lo, hi) => format!("\"{lo}-{hi}\""),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_rule(rule: &GenRule) -> String {
    let mut fields = Vec::new();
    if !rule.src.is_empty() {
        fields.push(format!("src: [{}]", rule.src.join(", ")));
    }
    if !rule.dst.is_empty() {
        fields.push(format!("dst: [{}]", rule.dst.join(", ")));
    }
    if let Some(p) = rule.proto {
        fields.push(format!("proto: {p}"));
    }
    if !rule.ports.is_empty() {
        fields.push(format!("ports: [{}]", render_ports(&rule.ports)));
    }
    let body = if fields.is_empty() {
        "{}".to_string()
    } else {
        format!("{{ {} }}", fields.join(", "))
    };
    format!("      - {}: {}", rule.action, body)
}

fn render_yaml(policy: &GenPolicy) -> String {
    let mut out = String::from("policy:\n");
    for block in &policy.blocks {
        let from = &policy.segments[block.from_idx].name;
        let to = &policy.segments[block.to_idx].name;
        out.push_str(&format!("  - from: {from}\n    to: {to}\n"));
        if block.rules.is_empty() {
            out.push_str("    rules: []\n");
        } else {
            out.push_str("    rules:\n");
            for rule in &block.rules {
                out.push_str(&render_rule(rule));
                out.push('\n');
            }
        }
    }
    out
}

fn segment_defs(policy: &GenPolicy) -> Vec<SegmentDef> {
    policy
        .segments
        .iter()
        .map(|s| SegmentDef {
            name: s.name.clone(),
            cidrs: s.cidrs.iter().map(|c| c.parse().unwrap()).collect(),
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

/// Builds segments from a per-segment CIDR-count list (`cidr_counts.len()`
/// segments, named `seg0`, `seg1`, ...), assigning globally disjoint `/24`s
/// via a running counter (see module doc comment).
fn build_segments(cidr_counts: &[usize]) -> Vec<GenSegment> {
    let mut k: u32 = 0;
    cidr_counts
        .iter()
        .enumerate()
        .map(|(i, &count)| {
            let cidrs = (0..count)
                .map(|_| {
                    let c = format!("10.0.{k}.0/24");
                    k += 1;
                    c
                })
                .collect();
            GenSegment {
                name: format!("seg{i}"),
                cidrs,
            }
        })
        .collect()
}

fn port_lit_strategy() -> impl Strategy<Value = PortLit> {
    prop_oneof![
        (1u32..=65535).prop_map(|p| PortLit::Single(p as u16)),
        (1u32..=65535, 1u32..=65535).prop_map(|(a, b)| {
            let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
            PortLit::Range(lo as u16, hi as u16)
        }),
    ]
}

/// One rule, valid-by-construction: `src`/`dst` are raw slot indices
/// (0..3) resolved against the block's actual from/to segment CIDR counts
/// later (a segment may have fewer than 3 CIDRs); `ports` is forced empty
/// unless `proto` ended up `tcp`/`udp` (design §4: `ports` requires an
/// explicit `proto: tcp|udp`).
#[derive(Debug, Clone)]
struct RawRule {
    action: &'static str,
    proto: Option<&'static str>,
    src_idx: Vec<usize>,
    dst_idx: Vec<usize>,
    ports: Vec<PortLit>,
}

fn raw_rule_strategy() -> impl Strategy<Value = RawRule> {
    (
        any::<bool>(),
        0usize..4,
        proptest::collection::vec(0usize..3, 0..=2),
        proptest::collection::vec(0usize..3, 0..=2),
        proptest::collection::vec(port_lit_strategy(), 0..=3),
    )
        .prop_map(|(is_allow, proto_idx, src_idx, dst_idx, ports)| {
            let action = if is_allow { "allow" } else { "deny" };
            let proto = match proto_idx {
                0 => None,
                1 => Some("tcp"),
                2 => Some("udp"),
                _ => Some("icmp"),
            };
            let ports = if matches!(proto, Some("tcp") | Some("udp")) {
                ports
            } else {
                Vec::new()
            };
            RawRule {
                action,
                proto,
                src_idx,
                dst_idx,
                ports,
            }
        })
}

/// Resolves raw slot indices against a segment's actual CIDR list (modulo
/// its length, since indices are sampled from a fixed `0..3` range but
/// segments may have as few as 1 CIDR), deduping to a set of distinct
/// CIDRs in first-seen (written) order.
fn resolve_indices(idxs: &[usize], cidrs: &[String]) -> Vec<String> {
    let len = cidrs.len();
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for &i in idxs {
        let real = i % len;
        if seen.insert(real) {
            out.push(cidrs[real].clone());
        }
    }
    out
}

/// Normalized content signature used to dedupe rules within a block (see
/// module doc comment) — deliberately mirrors `compile.rs::rule_id`'s
/// preimage shape (minus `from`/`to`, which are already fixed per block).
fn rule_signature(
    action: &str,
    proto: Option<&str>,
    src: &[String],
    dst: &[String],
    ports: &[PortLit],
) -> String {
    let proto = proto.unwrap_or("any");
    let ports = ports
        .iter()
        .map(|p| match p {
            PortLit::Single(n) => format!("{n}-{n}"),
            PortLit::Range(lo, hi) => format!("{lo}-{hi}"),
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{action}|{proto}|{}|{}|{ports}",
        src.join(","),
        dst.join(",")
    )
}

/// One `(from, to)` block plus its resolved, deduped rules.
fn block_strategy(n: usize) -> impl Strategy<Value = (usize, usize, Vec<RawRule>)> {
    (
        0..n,
        0..n,
        proptest::collection::vec(raw_rule_strategy(), 0..=6),
    )
}

fn blocks_strategy(n: usize) -> impl Strategy<Value = Vec<(usize, usize, Vec<RawRule>)>> {
    proptest::collection::vec(block_strategy(n), 0..=4).prop_map(|blocks| {
        let mut seen = HashSet::new();
        blocks
            .into_iter()
            .filter(|(from_idx, to_idx, _)| seen.insert((*from_idx, *to_idx)))
            .collect()
    })
}

/// Top-level strategy: 1-4 segments (1-3 CIDRs each), 0-4 blocks over
/// distinct ordered pairs, 0-6 valid-by-construction (and, within a block,
/// content-distinct) rules each.
fn gen_policy_strategy() -> impl Strategy<Value = GenPolicy> {
    proptest::collection::vec(1usize..=3, 1usize..=4).prop_flat_map(|cidr_counts| {
        let segments = build_segments(&cidr_counts);
        let n = segments.len();
        blocks_strategy(n).prop_map(move |raw_blocks| {
            let blocks = raw_blocks
                .into_iter()
                .map(|(from_idx, to_idx, raw_rules)| {
                    let from_cidrs = &segments[from_idx].cidrs;
                    let to_cidrs = &segments[to_idx].cidrs;

                    let mut seen_signatures = HashSet::new();
                    let rules = raw_rules
                        .into_iter()
                        .filter_map(|r| {
                            let src = resolve_indices(&r.src_idx, from_cidrs);
                            let dst = resolve_indices(&r.dst_idx, to_cidrs);
                            let signature = rule_signature(r.action, r.proto, &src, &dst, &r.ports);
                            if seen_signatures.insert(signature) {
                                Some(GenRule {
                                    action: r.action,
                                    proto: r.proto,
                                    src,
                                    dst,
                                    ports: r.ports,
                                })
                            } else {
                                None
                            }
                        })
                        .collect();

                    GenBlock {
                        from_idx,
                        to_idx,
                        rules,
                    }
                })
                .collect();

            GenPolicy {
                segments: segments.clone(),
                blocks,
            }
        })
    })
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

proptest! {
    // Moderate case count so the suite stays fast in the container (brief:
    // "default 256 or lower with an explicit config comment"); the
    // generator's nested `prop_flat_map` (segments -> blocks -> rules) is
    // more expensive per case than a flat strategy, so 128 keeps total
    // runtime well under a second while still exercising the space.
    #![proptest_config(ProptestConfig { cases: 128, .. ProptestConfig::default() })]

    /// (a) `compile()` never panics on a `PolicySource` that `parse_policy`
    /// accepted. (Generation failures, if any, are `valid_by_construction_
    /// always_compiles_ok`'s concern, not this property's — this one is
    /// purely "no panic given valid input.")
    #[test]
    fn compile_never_panics(policy in gen_policy_strategy(), version in 0u64..1000) {
        let segments = segment_defs(&policy);
        let yaml = render_yaml(&policy);
        if let Ok(src) = parse_policy(&yaml, &segments) {
            let _ = compile(&src, &segments, version);
        }
    }

    /// (b) Every valid-by-construction generated policy parses and
    /// compiles `Ok` — i.e. the generator's notion of "valid" actually
    /// matches `validate.rs`'s.
    #[test]
    fn valid_by_construction_always_compiles_ok(policy in gen_policy_strategy(), version in 0u64..1000) {
        let segments = segment_defs(&policy);
        let yaml = render_yaml(&policy);

        let parse_result = parse_policy(&yaml, &segments);
        prop_assert!(
            parse_result.is_ok(),
            "valid-by-construction policy failed to parse: {:?}\nyaml:\n{yaml}",
            parse_result.err()
        );
        let src = parse_result.unwrap();

        let compile_result = compile(&src, &segments, version);
        prop_assert!(
            compile_result.is_ok(),
            "valid-by-construction policy failed to compile: {:?}",
            compile_result.err()
        );
    }

    /// (c) Determinism: compiling the same source against the same segment
    /// table twice produces byte-identical canonical JSON (design §4).
    #[test]
    fn compiling_twice_is_byte_identical(policy in gen_policy_strategy(), version in 0u64..1000) {
        let segments = segment_defs(&policy);
        let yaml = render_yaml(&policy);

        let src1 = parse_policy(&yaml, &segments).expect("valid-by-construction policy must parse");
        let src2 = parse_policy(&yaml, &segments).expect("valid-by-construction policy must parse");
        let ir1 = compile(&src1, &segments, version).expect("valid-by-construction policy must compile");
        let ir2 = compile(&src2, &segments, version).expect("valid-by-construction policy must compile");

        prop_assert_eq!(ir1.to_canonical_json(), ir2.to_canonical_json());
    }

    /// (d) Every `rule_id` in the compiled output is unique across the
    /// whole document (not just within its own block) and is exactly 16
    /// lowercase hex characters.
    #[test]
    fn rule_ids_are_unique_and_well_formed(policy in gen_policy_strategy(), version in 0u64..1000) {
        let segments = segment_defs(&policy);
        let yaml = render_yaml(&policy);
        let src = parse_policy(&yaml, &segments).expect("valid-by-construction policy must parse");
        let ir = compile(&src, &segments, version).expect("valid-by-construction policy must compile");

        let mut seen = HashSet::new();
        for block in &ir.blocks {
            for rule in &block.rules {
                prop_assert_eq!(rule.rule_id.len(), 16, "rule_id '{}' is not 16 chars", rule.rule_id);
                prop_assert!(
                    rule.rule_id.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
                    "rule_id '{}' is not lowercase hex",
                    rule.rule_id
                );
                prop_assert!(
                    seen.insert(rule.rule_id.clone()),
                    "duplicate rule_id '{}' across the document",
                    rule.rule_id
                );
            }
        }
    }

    /// (e) Mutating one rule's `ports` (to a different, still-valid value)
    /// changes only that rule's `rule_id` — every other rule's `rule_id`,
    /// anywhere in the document, is unaffected (design D-C3-3).
    #[test]
    fn mutating_one_rules_ports_only_changes_that_rules_id(policy in gen_policy_strategy(), version in 0u64..1000) {
        let target = policy.blocks.iter().enumerate().find_map(|(bi, b)| {
            b.rules
                .iter()
                .position(|r| matches!(r.proto, Some("tcp") | Some("udp")))
                .map(|ri| (bi, ri))
        });
        prop_assume!(target.is_some());
        let (target_block, target_rule) = target.unwrap();

        let segments = segment_defs(&policy);
        let yaml_before = render_yaml(&policy);
        let src_before = parse_policy(&yaml_before, &segments).expect("valid-by-construction policy must parse");
        let ir_before = compile(&src_before, &segments, version).expect("valid-by-construction policy must compile");

        let mut mutated = policy.clone();
        let old_ports = mutated.blocks[target_block].rules[target_rule].ports.clone();
        // (Review finding) Comparing raw `PortLit` values (as the previous
        // `old_ports == candidate` check did) isn't enough: a different
        // `PortLit` representation can normalize to the SAME range (e.g.
        // `Range(12345, 12345)` vs `Single(12345)` both normalize to
        // `(12345, 12345)`) -- picking a "new" port that merely LOOKS
        // different but normalizes identically leaves `rule_id` unchanged,
        // spuriously failing this property. Normalize the old rule's ports
        // first (mirroring `compile.rs::normalize_port`) and pick a single
        // port whose own normalized range isn't already present in that
        // list, guaranteeing the compiled rule's normalized range actually
        // changes.
        let old_normalized: Vec<(u16, u16)> = old_ports
            .iter()
            .map(|p| match p {
                PortLit::Single(n) => (*n, *n),
                PortLit::Range(lo, hi) => (*lo, *hi),
            })
            .collect();
        let candidate_port = 12345u16;
        let new_port = if old_normalized.contains(&(candidate_port, candidate_port)) {
            54321u16
        } else {
            candidate_port
        };
        prop_assert!(
            !old_normalized.contains(&(new_port, new_port)),
            "12345 and 54321 can't both already be a degenerate single-port range in old_ports: {:?}",
            old_normalized
        );
        mutated.blocks[target_block].rules[target_rule].ports = vec![PortLit::Single(new_port)];

        let yaml_after = render_yaml(&mutated);
        let src_after = parse_policy(&yaml_after, &segments)
            .expect("mutated ports (proto tcp/udp, in-range single port) must still be valid");
        let ir_after = compile(&src_after, &segments, version).expect("mutated policy must still compile");

        prop_assert_eq!(ir_before.blocks.len(), ir_after.blocks.len());
        for (block_i, (b_before, b_after)) in ir_before.blocks.iter().zip(ir_after.blocks.iter()).enumerate() {
            prop_assert_eq!(b_before.rules.len(), b_after.rules.len());
            for (rule_i, (r_before, r_after)) in b_before.rules.iter().zip(b_after.rules.iter()).enumerate() {
                if block_i == target_block && rule_i == target_rule {
                    prop_assert_ne!(
                        &r_before.rule_id, &r_after.rule_id,
                        "the mutated rule's own rule_id should have changed"
                    );
                } else {
                    prop_assert_eq!(
                        &r_before.rule_id, &r_after.rule_id,
                        "unrelated rule_id changed at block {} rule {}", block_i, rule_i
                    );
                }
            }
        }
    }

    /// (f) Injecting a duplicate ordered `(from, to)` pair (a copy of an
    /// existing block, appended at the end) always yields **exactly one**
    /// `CompileError` for the duplicate occurrence, whose message both
    /// says "duplicate" and names the *original* occurrence's block index
    /// as the substring `"block {original_idx}"` (e.g. "first defined at
    /// block 0"). This is the controller's binding-contract ruling on the
    /// original FINDING below: the plan's "mentioning both block indices"
    /// means one error mentioning both — `block == Some(duplicate_idx)`
    /// plus the original index in text — not two separate `CompileError`s
    /// (one per occurrence). The Task 1 golden test
    /// (`duplicate_ordered_from_to_pair_is_a_compile_error`, `errors.len()
    /// == 1`, `block == Some(1)`) is unaffected and stays green under this
    /// contract.
    #[test]
    fn duplicate_ordered_pair_is_always_a_compile_error(policy in gen_policy_strategy()) {
        prop_assume!(!policy.blocks.is_empty());

        let original_idx = 0usize;
        let mut mutated = policy.clone();
        let original = mutated.blocks[original_idx].clone();
        let duplicate_idx = mutated.blocks.len();
        mutated.blocks.push(GenBlock {
            from_idx: original.from_idx,
            to_idx: original.to_idx,
            rules: Vec::new(),
        });

        let segments = segment_defs(&mutated);
        let yaml = render_yaml(&mutated);
        let result = parse_policy(&yaml, &segments);
        prop_assert!(
            result.is_err(),
            "expected a duplicate ordered pair to be a compile error, got Ok. yaml:\n{yaml}"
        );
        // `.unwrap_err()` would require `PolicySource: Debug`, which it
        // isn't (deliberately opaque, see lib.rs) — match instead.
        let errors = match result {
            Err(e) => e,
            Ok(_) => unreachable!("checked is_err() above"),
        };

        prop_assert_eq!(
            errors.len(), 1,
            "expected exactly one CompileError for the duplicate pair occurrence, got: {:?}", errors
        );
        prop_assert_eq!(errors[0].block, Some(duplicate_idx));
        prop_assert_eq!(errors[0].rule, None);
        prop_assert!(
            errors[0].msg.to_lowercase().contains("duplicate"),
            "msg should contain 'duplicate', got: {}", errors[0].msg
        );
        let original_marker = format!("block {original_idx}");
        prop_assert!(
            errors[0].msg.contains(&original_marker),
            "msg should name the original occurrence as '{}', got: {}",
            original_marker, errors[0].msg
        );
    }

    /// (g) Injecting a `src` CIDR that belongs to a *different* segment
    /// than the block's `from` segment always yields a `CompileError`
    /// (the subset check). The injected CIDR is guaranteed foreign — not
    /// merely different-looking — because segment CIDR pools are globally
    /// disjoint by construction (module doc comment).
    #[test]
    fn out_of_segment_src_cidr_is_always_a_compile_error(policy in gen_policy_strategy()) {
        prop_assume!(policy.segments.len() >= 2 && !policy.blocks.is_empty());

        let mut mutated = policy.clone();
        let block_idx = 0usize;
        let from_idx = mutated.blocks[block_idx].from_idx;
        let foreign_idx = (0..mutated.segments.len())
            .find(|&i| i != from_idx)
            .expect("segments.len() >= 2 guarantees a segment other than from_idx exists");
        let foreign_cidr = mutated.segments[foreign_idx].cidrs[0].clone();

        mutated.blocks[block_idx].rules.push(GenRule {
            action: "allow",
            proto: None,
            src: vec![foreign_cidr],
            dst: Vec::new(),
            ports: Vec::new(),
        });

        let segments = segment_defs(&mutated);
        let yaml = render_yaml(&mutated);
        let result = parse_policy(&yaml, &segments);
        prop_assert!(
            result.is_err(),
            "expected an out-of-segment src CIDR to be a compile error, got Ok. yaml:\n{yaml}"
        );
        let errors = match result {
            Err(e) => e,
            Ok(_) => unreachable!("checked is_err() above"),
        };
        prop_assert!(
            errors.iter().any(|e| e.msg.to_lowercase().contains("subset")),
            "expected an error mentioning 'subset', got: {errors:?}"
        );
    }
}
