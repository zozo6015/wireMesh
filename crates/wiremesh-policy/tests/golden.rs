//! Golden tests — Task 1 Step 1 (error-class half; the DSL→IR JSON golden
//! fixtures are a separate, later task per design §8).
//!
//! One YAML fixture per compile-error class named in design §4 / the
//! Task 1 brief, plus the multi-error-collection case and the
//! empty-`rules:`-block valid case. Every fixture lives under
//! `tests/fixtures/` and is loaded with `include_str!` so a missing file
//! fails at compile time, not at test time.
//!
//! Indices asserted below are exact (block/rule are `Option<usize>`,
//! 0-based, source order per design §4's determinism guarantee). Messages
//! are asserted as substrings only — the exact wording is the
//! implementer's (Task 1 Step 3) to choose, as long as it says what these
//! substrings say it must.

use wiremesh_policy::{
    compile, parse_policy, rule_id, CompileError, IrAction, IrProto, IrRule, PolicyIR, SegmentDef,
};

/// The fixed segment table every fixture in this file is validated
/// against: three non-overlapping /16s plus one wider /12, named so
/// `from`/`to` in the fixtures read naturally. `seg-wide` exists so the
/// positive subset-containment fixtures have a segment CIDR block visibly
/// larger than the rule CIDR nested inside it (per review finding: every
/// other fixture's `src`/`dst` is either omitted or a negative case, so the
/// containment check's true-path never ran).
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
        SegmentDef {
            name: "seg-c".into(),
            cidrs: vec!["10.2.0.0/16".parse().unwrap()],
        },
        SegmentDef {
            name: "seg-wide".into(),
            cidrs: vec!["172.16.0.0/12".parse().unwrap()],
        },
    ]
}

/// Runs `parse_policy` against `yaml` and the standard [`segments`] table,
/// asserting it fails and returning the collected errors.
fn expect_errors(yaml: &str) -> Vec<CompileError> {
    match parse_policy(yaml, &segments()) {
        Ok(_) => panic!("expected compile errors, got Ok"),
        Err(errors) => errors,
    }
}

#[test]
fn unknown_segment_name_is_a_compile_error() {
    let errors = expect_errors(include_str!("fixtures/unknown_segment.yaml"));
    assert_eq!(errors.len(), 1, "errors: {errors:?}");
    assert_eq!(errors[0].block, Some(0));
    assert_eq!(errors[0].rule, None);
    assert!(
        errors[0].msg.contains("unknown segment"),
        "msg: {}",
        errors[0].msg
    );
}

#[test]
fn duplicate_ordered_from_to_pair_is_a_compile_error() {
    let errors = expect_errors(include_str!("fixtures/duplicate_block_pair.yaml"));
    assert_eq!(errors.len(), 1, "errors: {errors:?}");
    // The error names the second (duplicate) occurrence.
    assert_eq!(errors[0].block, Some(1));
    assert_eq!(errors[0].rule, None);
    assert!(
        errors[0].msg.contains("duplicate"),
        "msg: {}",
        errors[0].msg
    );
}

#[test]
fn src_not_subset_of_from_segment_cidrs_is_a_compile_error() {
    let errors = expect_errors(include_str!("fixtures/src_not_subset.yaml"));
    assert_eq!(errors.len(), 1, "errors: {errors:?}");
    assert_eq!(errors[0].block, Some(0));
    assert_eq!(errors[0].rule, Some(0));
    assert!(errors[0].msg.contains("src"), "msg: {}", errors[0].msg);
    assert!(
        errors[0].msg.contains("subset"),
        "msg: {}",
        errors[0].msg
    );
}

#[test]
fn dst_not_subset_of_to_segment_cidrs_is_a_compile_error() {
    let errors = expect_errors(include_str!("fixtures/dst_not_subset.yaml"));
    assert_eq!(errors.len(), 1, "errors: {errors:?}");
    assert_eq!(errors[0].block, Some(0));
    assert_eq!(errors[0].rule, Some(0));
    assert!(errors[0].msg.contains("dst"), "msg: {}", errors[0].msg);
    assert!(
        errors[0].msg.contains("subset"),
        "msg: {}",
        errors[0].msg
    );
}

#[test]
fn ports_with_proto_icmp_is_a_compile_error() {
    let errors = expect_errors(include_str!("fixtures/ports_proto_icmp.yaml"));
    assert_eq!(errors.len(), 1, "errors: {errors:?}");
    assert_eq!(errors[0].block, Some(0));
    assert_eq!(errors[0].rule, Some(0));
    assert!(
        errors[0].msg.contains("ports require proto tcp|udp"),
        "msg: {}",
        errors[0].msg
    );
}

#[test]
fn ports_with_proto_omitted_is_a_compile_error() {
    let errors = expect_errors(include_str!("fixtures/ports_proto_omitted.yaml"));
    assert_eq!(errors.len(), 1, "errors: {errors:?}");
    assert_eq!(errors[0].block, Some(0));
    assert_eq!(errors[0].rule, Some(0));
    assert!(
        errors[0].msg.contains("ports require proto tcp|udp"),
        "msg: {}",
        errors[0].msg
    );
}

#[test]
fn invalid_proto_without_ports_is_a_compile_error() {
    // Follow-up finding from the Task 2 implementer: `proto: sctp` (or any
    // value other than tcp|udp|icmp|absent) with NO `ports:` was passing
    // `parse_policy` — `validate_ports` only checked `proto` inside its
    // ports-present branch — and then panicking `compile()`'s
    // `unreachable!()`. Decided behavior: invalid `proto` is a
    // `CompileError` from `parse_policy` unconditionally, so `compile()`
    // may keep assuming validity.
    let errors = expect_errors(include_str!("fixtures/invalid_proto_no_ports.yaml"));
    assert_eq!(errors.len(), 1, "errors: {errors:?}");
    assert_eq!(errors[0].block, Some(0));
    assert_eq!(errors[0].rule, Some(0));
    assert!(
        errors[0].msg.to_lowercase().contains("proto"),
        "msg: {}",
        errors[0].msg
    );
}

#[test]
fn valid_proto_values_without_ports_still_parse_ok() {
    // Companion to the test above: tcp/udp/icmp/omitted must still parse
    // fine with no `ports:` present — the fix for the invalid-proto gap
    // must not overcorrect into rejecting these too.
    let yaml = include_str!("fixtures/valid_proto_no_ports.yaml");
    let result = parse_policy(yaml, &segments());
    assert!(
        result.is_ok(),
        "tcp/udp/icmp/omitted proto with no ports should still parse, got {:?}",
        result.err()
    );
}

#[test]
fn malformed_cidr_is_a_compile_error() {
    let errors = expect_errors(include_str!("fixtures/malformed_cidr.yaml"));
    assert_eq!(errors.len(), 1, "errors: {errors:?}");
    assert_eq!(errors[0].block, Some(0));
    assert_eq!(errors[0].rule, Some(0));
    assert!(
        errors[0].msg.contains("invalid CIDR"),
        "msg: {}",
        errors[0].msg
    );
}

#[test]
fn port_zero_is_a_compile_error() {
    let errors = expect_errors(include_str!("fixtures/port_zero.yaml"));
    assert_eq!(errors.len(), 1, "errors: {errors:?}");
    assert_eq!(errors[0].block, Some(0));
    assert_eq!(errors[0].rule, Some(0));
    assert!(
        errors[0].msg.contains("port 0"),
        "msg: {}",
        errors[0].msg
    );
}

#[test]
fn port_above_65535_is_a_compile_error() {
    let errors = expect_errors(include_str!("fixtures/port_too_high.yaml"));
    assert_eq!(errors.len(), 1, "errors: {errors:?}");
    assert_eq!(errors[0].block, Some(0));
    assert_eq!(errors[0].rule, Some(0));
    assert!(
        errors[0].msg.contains("65535"),
        "msg: {}",
        errors[0].msg
    );
}

#[test]
fn port_range_lo_greater_than_hi_is_a_compile_error() {
    let errors = expect_errors(include_str!("fixtures/port_range_inverted.yaml"));
    assert_eq!(errors.len(), 1, "errors: {errors:?}");
    assert_eq!(errors[0].block, Some(0));
    assert_eq!(errors[0].rule, Some(0));
    assert!(
        errors[0].msg.contains("lo > hi"),
        "msg: {}",
        errors[0].msg
    );
}

#[test]
fn rule_missing_allow_or_deny_is_a_compile_error() {
    let errors = expect_errors(include_str!("fixtures/rule_missing_action.yaml"));
    assert_eq!(errors.len(), 1, "errors: {errors:?}");
    assert_eq!(errors[0].block, Some(0));
    assert_eq!(errors[0].rule, Some(0));
    assert!(
        errors[0].msg.contains("exactly one of"),
        "msg: {}",
        errors[0].msg
    );
}

#[test]
fn rule_with_both_allow_and_deny_is_a_compile_error() {
    let errors = expect_errors(include_str!("fixtures/rule_both_actions.yaml"));
    assert_eq!(errors.len(), 1, "errors: {errors:?}");
    assert_eq!(errors[0].block, Some(0));
    assert_eq!(errors[0].rule, Some(0));
    assert!(
        errors[0].msg.contains("exactly one of"),
        "msg: {}",
        errors[0].msg
    );
}

#[test]
fn non_ipv4_cidr_is_a_compile_error() {
    let errors = expect_errors(include_str!("fixtures/non_ipv4_cidr.yaml"));
    assert_eq!(errors.len(), 1, "errors: {errors:?}");
    assert_eq!(errors[0].block, Some(0));
    assert_eq!(errors[0].rule, Some(0));
    assert!(
        errors[0].msg.contains("IPv4"),
        "msg: {}",
        errors[0].msg
    );
}

#[test]
fn empty_rules_block_parses_ok() {
    let yaml = include_str!("fixtures/empty_rules_block.yaml");
    let result = parse_policy(yaml, &segments());
    assert!(
        result.is_ok(),
        "empty rules: [] block should parse (default-deny that pair), got {:?}",
        result.err()
    );
}

#[test]
fn src_and_dst_strictly_inside_segment_cidrs_parses_ok() {
    // Review finding (Important): every other fixture's src/dst is either
    // omitted or a negative case, so the subset-containment check's
    // true-path (a CIDR that legitimately IS contained) never ran. A
    // regression that always returns "not a subset", or that swaps the
    // `contains` call direction to accept supersets instead of subsets,
    // would still pass all the other tests. This fixture's src (10.0.5.0/24
    // inside seg-a's 10.0.0.0/16) and dst (172.16.1.50/32 inside
    // seg-wide's 172.16.0.0/12) are both strictly-contained, list-form
    // CIDRs that must validate successfully.
    let yaml = include_str!("fixtures/positive_subset_containment.yaml");
    let result = parse_policy(yaml, &segments());
    assert!(
        result.is_ok(),
        "src/dst strictly inside their segment's CIDRs should parse, got {:?}",
        result.err()
    );
}

#[test]
fn bare_string_src_and_dst_parses_ok() {
    // Review finding (Minor): RuleBody::src/dst accept a bare YAML string
    // as well as a list (dsl.rs's `string_or_seq`), but no fixture exercised
    // the bare-string form. Same CIDRs as
    // `src_and_dst_strictly_inside_segment_cidrs_parses_ok` above, but
    // written as `src: "..."` / `dst: "..."` instead of `src: ["..."]`.
    let yaml = include_str!("fixtures/bare_string_src_dst.yaml");
    let result = parse_policy(yaml, &segments());
    assert!(
        result.is_ok(),
        "bare-string src/dst should parse the same as list-form, got {:?}",
        result.err()
    );
}

#[test]
fn multiple_independent_errors_are_all_collected() {
    let errors = expect_errors(include_str!("fixtures/multi_error.yaml"));
    assert_eq!(
        errors.len(),
        3,
        "expected all 3 independent errors back, got {errors:?}"
    );

    // Deterministic source order (design §4): block 0, then block 1, then
    // block 2.
    assert_eq!(errors[0].block, Some(0));
    assert_eq!(errors[0].rule, None);
    assert!(
        errors[0].msg.contains("unknown segment"),
        "msg: {}",
        errors[0].msg
    );

    assert_eq!(errors[1].block, Some(1));
    assert_eq!(errors[1].rule, Some(0));
    assert!(
        errors[1].msg.contains("port 0"),
        "msg: {}",
        errors[1].msg
    );

    assert_eq!(errors[2].block, Some(2));
    assert_eq!(errors[2].rule, Some(0));
    assert!(
        errors[2].msg.contains("ports require proto tcp|udp"),
        "msg: {}",
        errors[2].msg
    );
}

// ---------------------------------------------------------------------------
// Task 2 — IR types, canonical JSON, `rule_id`, `compile()` (design §5 /
// D-C3-1 / D-C3-3). Segment table below is distinct from `segments()`
// above: names/CIDRs match the master spec §5.1 worked example and the
// policy-pipeline design doc's §5 "concretized" IR example
// (proxmox-lab -> aws-prod), not Task 1's seg-a/b/c error-class fixtures.
// ---------------------------------------------------------------------------

/// The segment table the design-§5 example (and its rule_id-stability
/// variants) validate against: `proxmox-lab` / `aws-prod`, CIDRs taken
/// directly from the design doc's §5 concretized IR example so this
/// fixture's expected `src_cidrs`/`dst_cidrs` match it exactly.
fn ir_segments() -> Vec<SegmentDef> {
    vec![
        SegmentDef {
            name: "proxmox-lab".into(),
            cidrs: vec!["10.10.0.0/16".parse().unwrap()],
        },
        SegmentDef {
            name: "aws-prod".into(),
            cidrs: vec!["172.16.0.0/12".parse().unwrap()],
        },
    ]
}

/// Parses `yaml` against [`ir_segments`] and compiles it at `version`,
/// panicking with full detail on either failure. Every fixture used in
/// this section is expected to be valid — Task 1's `golden.rs` tests above
/// already cover the error paths, so failures here are unconditionally a
/// test bug or a real regression, never an expected-error case.
fn compile_ok(yaml: &str, version: u64) -> PolicyIR {
    let src = parse_policy(yaml, &ir_segments())
        .unwrap_or_else(|errors| panic!("expected valid policy, got errors: {errors:?}"));
    compile(&src, &ir_segments(), version)
        .unwrap_or_else(|errors| panic!("expected compile to succeed, got errors: {errors:?}"))
}

/// (a) The design-§5 example DSL compiles to the exact expected IR JSON,
/// byte-compared against `to_canonical_json()`. The fixture's `rule_id`
/// values were hand-derived per the brief's exact hash recipe (first 8
/// bytes of sha256 of the normalized-field preimage string, hex) — see
/// `task-2-tests-report.md` for the literal preimage strings hashed. This
/// is the one test in this file that pins those literal hex values; every
/// other rule_id-related test below is a relative (equal/not-equal)
/// comparison instead.
#[test]
fn design_s5_example_compiles_to_exact_canonical_json() {
    let yaml = include_str!("fixtures/design_s5_example.yaml");
    let ir = compile_ok(yaml, 42);
    let expected = include_str!("fixtures/design_s5_example.ir.json");
    assert_eq!(ir.to_canonical_json(), expected);
}

/// (b) Compiling the same source against the same segment table twice
/// produces byte-identical canonical JSON (design §4's determinism
/// guarantee: "two compiles of the same source produce byte-identical
/// JSON").
#[test]
fn compiling_twice_is_byte_identical() {
    let yaml = include_str!("fixtures/design_s5_example.yaml");
    let first = compile_ok(yaml, 42).to_canonical_json();
    let second = compile_ok(yaml, 42).to_canonical_json();
    assert_eq!(first, second);
}

/// (c) part 1: `rule_id` is stable under an edit to an *unrelated* rule in
/// the same block (design D-C3-3: "stable across versions when the rule
/// text is unchanged"). `rule_id_stable_changed.yaml` edits only the
/// second rule's port (5432 -> 5433); the first rule's id must be
/// unaffected, and the edited rule's own id must change.
#[test]
fn rule_id_stable_when_unrelated_rule_in_same_block_changes() {
    let base = compile_ok(include_str!("fixtures/rule_id_stable_base.yaml"), 1);
    let changed = compile_ok(include_str!("fixtures/rule_id_stable_changed.yaml"), 1);

    assert_eq!(
        base.blocks[0].rules[0].rule_id, changed.blocks[0].rules[0].rule_id,
        "unrelated edit to rule 1 must not change rule 0's rule_id"
    );
    assert_ne!(
        base.blocks[0].rules[1].rule_id, changed.blocks[0].rules[1].rule_id,
        "the edited rule's own rule_id must change"
    );
}

/// (c) part 2: the identical rule body placed in a different (from, to)
/// block pair gets a different `rule_id` — the hash preimage includes
/// `from`/`to` (design D-C3-3's recipe), so `rule_id` is not just a hash
/// of the rule body in isolation. Calls `rule_id` directly (no `compile`
/// needed) since it depends only on its three arguments.
#[test]
fn rule_id_differs_across_block_pairs_for_the_same_rule_body() {
    let rule = IrRule {
        rule_id: String::new(), // not read by rule_id() — it computes fresh
        action: IrAction::Deny,
        proto: IrProto::Tcp,
        src: vec![],
        dst: vec![],
        ports: vec![(22, 22)],
    };

    let forward = rule_id("proxmox-lab", "aws-prod", &rule);
    let reversed = rule_id("aws-prod", "proxmox-lab", &rule);
    assert_ne!(
        forward, reversed,
        "the same rule body in a different (from, to) pair must hash differently"
    );
}

/// (d) `from_json` rejects a document declaring an unsupported `schema`
/// (this crate currently only produces/accepts `1`).
#[test]
fn from_json_rejects_unsupported_schema() {
    let bytes = br#"{"schema":2,"version":1,"blocks":[]}"#;
    let result = PolicyIR::from_json(bytes);
    assert!(
        result.is_err(),
        "schema: 2 must be rejected, got {result:?}"
    );
}

/// (e) Omitted `src`/`dst` serialize as `[]` (not omitted, not `null`);
/// a single DSL port `22` becomes the pair `[22,22]` (not a bare `22`).
#[test]
fn omitted_src_dst_and_single_port_serialize_as_expected() {
    let ir = compile_ok(include_str!("fixtures/design_s5_example.yaml"), 42);
    let json = ir.to_canonical_json();
    assert!(
        json.contains(r#""src":[],"dst":[],"ports":[[22,22]]"#),
        "expected omitted src/dst as [] and single port 22 as [[22,22]], got: {json}"
    );
}

/// (f) `blocks_fingerprint` is the version-independent equality key
/// (design D-C3-8): equal across two compiles that differ only in
/// `version`, and different when a rule actually changes.
#[test]
fn blocks_fingerprint_ignores_version_but_reflects_rule_changes() {
    let yaml = include_str!("fixtures/design_s5_example.yaml");
    let v1 = compile_ok(yaml, 1);
    let v2 = compile_ok(yaml, 999);
    assert_eq!(
        v1.blocks_fingerprint(),
        v2.blocks_fingerprint(),
        "fingerprint must not depend on `version`"
    );

    let base = compile_ok(include_str!("fixtures/rule_id_stable_base.yaml"), 1);
    let changed = compile_ok(include_str!("fixtures/rule_id_stable_changed.yaml"), 1);
    assert_ne!(
        base.blocks_fingerprint(),
        changed.blocks_fingerprint(),
        "fingerprint must change when a rule changes"
    );
}

// ---------------------------------------------------------------------------
// Task 7 (test author) — the compiler-side `MAX_RULES` guard (design §6:
// "Mitigation if needed: bounded-loop rule evaluation with a documented
// max-rules-per-block constant (compile error above it) -- the constant, if
// introduced, is surfaced in `wiremesh-policy` validation so the controller
// rejects at compile time, not the gateway at load time"). The limit (256)
// is the same `wiremesh_enforcer::flatten::MAX_RULES` the enforcer crate
// duplicates/cross-references (see `crates/wiremesh-enforcer/src/flatten.rs`)
// -- `wiremesh-policy` cannot depend on `wiremesh-enforcer` (leaf crate, see
// this crate's module doc), so the number is a deliberate duplication, not a
// shared constant.
//
// RED (no guard exists yet, Task 7 Step 1): today NEITHER `parse_policy` NOR
// `compile` reject an oversized policy at all -- `expect_flatten_guard_error`
// below (which tries `parse_policy` then `compile`, and panics with "got Ok"
// if BOTH succeed) currently panics on the 257-rule case, since compiling
// 257 trivially-valid single-port rules succeeds today. Step 3 (implementer)
// adds the guard (either in `validate.rs` or `compile.rs` -- this test
// doesn't care which, only that ONE of `parse_policy`/`compile` returns a
// `CompileError` naming "256").
// ---------------------------------------------------------------------------

/// One block, `n` single-port `deny: { proto: tcp, ports: [p] }` rules for
/// `p` in `1..=n` -- generated programmatically (per the Task 7 brief)
/// rather than as a giant fixture file. Each rule has exactly one port
/// range, so this policy's FLATTENED rule count (post port-explosion, see
/// `wiremesh-enforcer`'s `flatten`) equals `n` exactly.
fn policy_yaml_with_n_single_port_rules(n: u16) -> String {
    let mut yaml = String::from("policy:\n  - from: proxmox-lab\n    to: aws-prod\n    rules:\n");
    for p in 1..=n {
        yaml.push_str(&format!("      - deny: {{ proto: tcp, ports: [{p}] }}\n"));
    }
    yaml
}

/// Runs `parse_policy` then (if that succeeds) `compile` against
/// [`ir_segments`], returning whichever step's errors first reject `yaml`.
/// Panics if BOTH succeed -- every caller of this helper expects a rejection.
fn expect_flatten_guard_error(yaml: &str) -> Vec<CompileError> {
    match parse_policy(yaml, &ir_segments()) {
        Err(errors) => errors,
        Ok(src) => match compile(&src, &ir_segments(), 1) {
            Err(errors) => errors,
            Ok(ir) => panic!(
                "expected a compile error for a >256 flattened-rule policy, \
                 got Ok IR with {} block(s)",
                ir.blocks.len()
            ),
        },
    }
}

/// The guard itself: 257 flattened rules (256 is the limit) must be
/// rejected, and the error must name the limit (256) so a developer reading
/// it knows exactly what to trim.
#[test]
fn more_than_max_rules_flattened_is_a_compile_error() {
    let yaml = policy_yaml_with_n_single_port_rules(257);
    let errors = expect_flatten_guard_error(&yaml);
    assert!(!errors.is_empty(), "expected at least one CompileError");
    assert!(
        errors.iter().any(|e| e.msg.contains("256")),
        "expected an error naming the 256 limit, got: {errors:?}"
    );
}

/// Boundary companion (already green today, since no guard exists yet to
/// reject it -- this pins the *other* side of the fencepost so a Step 3
/// implementation that's off-by-one in the wrong direction, and starts
/// rejecting at exactly 256, is caught too): exactly 256 flattened rules
/// must still compile successfully.
#[test]
fn exactly_max_rules_flattened_still_compiles_ok() {
    let yaml = policy_yaml_with_n_single_port_rules(256);
    let src = parse_policy(&yaml, &ir_segments())
        .unwrap_or_else(|errors| panic!("expected valid policy, got errors: {errors:?}"));
    let ir = compile(&src, &ir_segments(), 1)
        .unwrap_or_else(|errors| panic!("expected compile to succeed, got errors: {errors:?}"));
    assert_eq!(ir.blocks[0].rules.len(), 256);
}
