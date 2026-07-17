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

use wiremesh_policy::{parse_policy, CompileError, SegmentDef};

/// The fixed segment table every fixture in this file is validated
/// against: three non-overlapping /16s, named so `from`/`to` in the
/// fixtures read naturally.
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
