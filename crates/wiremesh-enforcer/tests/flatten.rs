//! Task 7, Step 1 (test author): failing unit tests for `flatten` (pure, no
//! privilege needed) — the shared front half both enforcer backends drive
//! from (design §6; `.superpowers/sdd/task-7-brief.md`'s `Interfaces`
//! snippet). Inputs are built via `wiremesh_policy`'s public API
//! (`parse_policy` + `compile`), the same pattern
//! `wiremesh-policy/tests/golden.rs` already establishes — no local
//! `PolicyIR` literal construction, so these tests exercise the real DSL →
//! IR → flatten pipeline end to end.
//!
//! RED evidence (current skeleton): every test below calls `flatten()`,
//! whose body is `todo!()` (Task 7 Step 1's skeleton, `src/flatten.rs`) — all
//! panic with that `todo!()` message until Step 3 (implementer) fills it in.

use ipnet::Ipv4Net;
use wiremesh_enforcer::flatten;
use wiremesh_policy::{compile, parse_policy, PolicyIR, SegmentDef};

/// Two non-overlapping /16s, named so `from`/`to` read naturally — mirrors
/// `wiremesh-policy/tests/golden.rs`'s `segments()` convention (this crate's
/// own fixture table, distinct from that file's).
fn segments() -> Vec<SegmentDef> {
    vec![
        SegmentDef {
            name: "seg-a".into(),
            cidrs: vec!["10.0.0.0/16".parse().unwrap()],
        },
        SegmentDef {
            name: "seg-b".into(),
            cidrs: vec!["10.1.0.0/16".parse().unwrap()],
        },
    ]
}

/// Parses + compiles `yaml` against [`segments`], panicking with full detail
/// on either failure — every fixture used below is expected to be valid, so
/// a failure here is a test bug, never an expected-error case (mirrors
/// `wiremesh-policy/tests/golden.rs`'s `compile_ok`).
fn compile_ok(yaml: &str, version: u64) -> PolicyIR {
    let src = parse_policy(yaml, &segments())
        .unwrap_or_else(|errors| panic!("expected valid policy, got errors: {errors:?}"));
    compile(&src, &segments(), version)
        .unwrap_or_else(|errors| panic!("expected compile to succeed, got errors: {errors:?}"))
}

fn cidr(s: &str) -> Ipv4Net {
    s.parse().unwrap()
}

/// Builds a single-block policy with `n` rules, each `deny: { proto: tcp,
/// ports: [p] }` for a distinct single port `p` in `1..=n` — used by the
/// `MAX_RULES` tests below to generate an oversized (or exactly-boundary)
/// policy programmatically rather than via a giant fixture file (per the
/// Task 7 brief).
fn policy_yaml_with_n_single_port_rules(n: u16) -> String {
    let mut yaml = String::from("policy:\n  - from: seg-a\n    to: seg-b\n    rules:\n");
    for p in 1..=n {
        yaml.push_str(&format!("      - deny: {{ proto: tcp, ports: [{p}] }}\n"));
    }
    yaml
}

/// Blocks (and each block's rules) flatten in `(block_ord, rule_ord)` source
/// order (design §4's determinism guarantee, carried through by `flatten`
/// per the brief). Also exercises the "no `ports:` at all" case: each rule
/// here has no `ports:`, so each must produce exactly one `FlatRule` with
/// `(port_lo, port_hi) == (0, 0)` ("any").
#[test]
fn flatten_orders_flat_rules_in_block_then_rule_source_order() {
    let yaml = "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - deny:
          proto: icmp
  - from: seg-b
    to: seg-a
    rules:
      - allow:
          proto: icmp
";
    let ir = compile_ok(yaml, 1);
    let flat = flatten(&ir).expect("flatten should succeed for 2 single-rule blocks");

    assert_eq!(flat.len(), 2, "one FlatRule per rule, no explosion (no ports)");
    assert_eq!(flat[0].idx, 0);
    assert_eq!(flat[1].idx, 1);
    assert_eq!(
        flat[0].rule_id, ir.blocks[0].rules[0].rule_id,
        "block 0's rule must come first"
    );
    assert_eq!(
        flat[1].rule_id, ir.blocks[1].rules[0].rule_id,
        "block 1's rule must come second"
    );
    assert_eq!(flat[0].port_lo, 0);
    assert_eq!(flat[0].port_hi, 0);
    assert_eq!(flat[1].port_lo, 0);
    assert_eq!(flat[1].port_hi, 0);
}

/// A rule's empty `src`/`dst` falls back to its block's `src_cidrs`/
/// `dst_cidrs`; a rule that specifies its own `src`/`dst` uses those
/// instead, not the block's (both halves of the contract in one test, so a
/// regression that always returns the block's CIDRs — ignoring a rule's own
/// — would still be caught).
#[test]
fn flatten_falls_back_to_block_cidrs_only_when_rule_src_dst_are_empty() {
    let yaml = "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - deny:
          proto: icmp
      - allow:
          src: [\"10.0.5.0/24\"]
          dst: [\"10.1.9.0/24\"]
          proto: tcp
          ports: [80]
";
    let ir = compile_ok(yaml, 1);
    let flat = flatten(&ir).expect("flatten should succeed for one block, two rules");

    assert_eq!(flat.len(), 2);
    // Rule 0: no src/dst -> block's own src_cidrs/dst_cidrs (seg-a's /
    // seg-b's whole segment CIDRs).
    assert_eq!(flat[0].src_cidrs, vec![cidr("10.0.0.0/16")]);
    assert_eq!(flat[0].dst_cidrs, vec![cidr("10.1.0.0/16")]);
    // Rule 1: explicit src/dst -> its own, NOT the block's.
    assert_eq!(flat[1].src_cidrs, vec![cidr("10.0.5.0/24")]);
    assert_eq!(flat[1].dst_cidrs, vec![cidr("10.1.9.0/24")]);
}

/// A rule with `k` port ranges explodes into `k` consecutive `FlatRule`s
/// sharing the same `rule_id` (design §6 / the Task 7 brief). All other
/// fields (action, proto, src_cidrs, dst_cidrs) are identical across the
/// exploded set — only `idx` and `(port_lo, port_hi)` vary.
#[test]
fn flatten_explodes_multiple_port_ranges_into_consecutive_flat_rules_sharing_rule_id() {
    let yaml = "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow:
          proto: tcp
          ports: [80, 443, \"9000-9100\"]
";
    let ir = compile_ok(yaml, 1);
    let flat = flatten(&ir).expect("flatten should succeed for one 3-port-range rule");

    assert_eq!(flat.len(), 3, "3 port ranges -> 3 exploded FlatRules");
    let expected_rule_id = &ir.blocks[0].rules[0].rule_id;

    assert_eq!(flat[0].idx, 0);
    assert_eq!(flat[1].idx, 1);
    assert_eq!(flat[2].idx, 2);

    for f in &flat {
        assert_eq!(&f.rule_id, expected_rule_id, "all 3 must share the one rule_id");
        assert_eq!(f.action, ir.blocks[0].rules[0].action);
        assert_eq!(f.proto, ir.blocks[0].rules[0].proto);
        assert_eq!(f.src_cidrs, vec![cidr("10.0.0.0/16")]); // block fallback (rule omits src)
        assert_eq!(f.dst_cidrs, vec![cidr("10.1.0.0/16")]); // block fallback (rule omits dst)
    }
    assert_eq!((flat[0].port_lo, flat[0].port_hi), (80, 80));
    assert_eq!((flat[1].port_lo, flat[1].port_hi), (443, 443));
    assert_eq!((flat[2].port_lo, flat[2].port_hi), (9000, 9100));
}

/// A flattened rule count of exactly [`wiremesh_enforcer::MAX_RULES`] (256)
/// is the boundary — still `Ok`. Paired with the overflow test below so a
/// regression that rejects at 256 (off-by-one) is caught too.
#[test]
fn flatten_succeeds_at_exactly_max_rules_boundary() {
    let yaml = policy_yaml_with_n_single_port_rules(wiremesh_enforcer::MAX_RULES as u16);
    let ir = compile_ok(&yaml, 1);
    let flat = flatten(&ir).expect("exactly MAX_RULES (256) flattened rules must be Ok");
    assert_eq!(flat.len(), wiremesh_enforcer::MAX_RULES);
}

/// One more flattened rule than [`wiremesh_enforcer::MAX_RULES`] (257) is an
/// `Err` naming the limit (design §6: the eBPF verifier-budget mitigation's
/// "documented max-rules-per-block constant").
#[test]
fn flatten_errs_when_flattened_count_exceeds_max_rules() {
    let n = wiremesh_enforcer::MAX_RULES as u16 + 1;
    let yaml = policy_yaml_with_n_single_port_rules(n);
    let ir = compile_ok(&yaml, 1);
    let err = flatten(&ir).expect_err("257 flattened rules (MAX_RULES=256) must be Err");
    let msg = err.to_string();
    assert!(
        msg.contains("256"),
        "error should name the MAX_RULES limit (256), got: {msg}"
    );
}
