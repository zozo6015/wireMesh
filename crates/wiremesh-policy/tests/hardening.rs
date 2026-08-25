//! Backlog 10 PR-A (Cycle-3 hardening trio), test author — RED tests for
//! two audited `wiremesh-policy` gaps:
//!
//! **Item 1 — LPM capacity compile guard.** `compile.rs`'s only size guard
//! is `MAX_RULES = 256` over the FLATTENED rule count. Nothing bounds the
//! number of DISTINCT CIDRs a policy can put on one side (src or dst), but
//! the eBPF backend's per-side LPM tries are capped at
//! `wiremesh_enforcer_common::LPM_MAX_ENTRIES = 1024`
//! (`crates/wiremesh-enforcer-ebpf/common/src/lib.rs:36`) — entry #1025
//! today fails deep inside the gateway's `apply()` with an opaque
//! trie-insert error, on the gateway, at load time. Design §6's own rule
//! ("the controller rejects at compile time what the gateway would reject
//! at eBPF-load time") says this belongs here, as a `CompileError` naming
//! the limit. Expected constant: `MAX_LPM_CIDRS_PER_SIDE: usize = 1024` in
//! `compile.rs`, computed PRE-flatten per side as the distinct union of
//! each rule's own `src` (if non-empty) else its block's `src_cidrs` —
//! same for `dst` — i.e. exactly the distinct-CIDR count
//! `wiremesh-enforcer`'s `build_lpm_entries` will later produce.
//!
//! **Item 2a — empty-CIDR segment.** A referenced `SegmentDef { cidrs: [] }`
//! sails through `parse_policy` + `compile` today (verified: `validate.rs`
//! has no empty-cidrs check; `compile.rs` just copies the empty list into
//! `src_cidrs`/`dst_cidrs`), producing an IR block whose side matches
//! nothing (eBPF: no LPM entries — a silently dead rule) or, worse, an
//! nftables ruleset with malformed `{ }` set syntax (`nft.rs`'s
//! `cidr_set`). The pipeline must reject it with a `CompileError` instead.
//!
//! RED status (runtime-red — this file compiles against today's public
//! API; no new symbols referenced):
//!  - `compile_errs_at_1025_distinct_src_cidrs_on_one_rule_naming_the_limit` — RED
//!  - `compile_errs_at_1025_distinct_dst_cidrs_on_one_rule_naming_the_limit` — RED
//!  - `compile_errs_when_segment_fallback_side_carries_1025_distinct_cidrs` — RED
//!  - `referenced_segment_with_no_cidrs_is_a_compile_error` — RED
//!  - `compile_ok_at_exactly_1024_distinct_cidrs_on_one_rule_side` — green
//!    today, stays green (the off-by-one boundary pin)
//!  - `distinct_cidr_count_is_a_union_not_a_sum_across_rules` — green
//!    today, stays green (pins the "distinct union" semantics so a naive
//!    per-rule-sum implementation of the new guard is caught)

use wiremesh_policy::{compile, parse_policy, CompileError, PolicyIR, SegmentDef};

/// The eBPF LPM trie's per-side capacity
/// (`wiremesh_enforcer_common::LPM_MAX_ENTRIES`). Duplicated here as a
/// literal, the same way `wiremesh-enforcer/tests/flatten.rs` pins
/// `MAX_RULES`'s 256 numerically — the compile-time half and the load-time
/// half of the guard each fix the number independently (this crate cannot
/// depend on the enforcer crates; the dependency runs the other way). The
/// enforcer-side parity test (`wiremesh-enforcer/tests/lpm_capacity.rs`)
/// asserts the two crates' CONSTANTS agree; this literal asserts neither
/// side drifted from the audited 1024.
const LPM_CAP: usize = 1024;

/// `seg-a` (10.0.0.0/16) → `seg-b` (10.1.0.0/16): wide enough for >1024
/// distinct /32s per side. Mirrors `tests/golden.rs`'s `segments()`
/// convention.
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

/// The full parse+compile pipeline, version pinned to 1. Item 2a's guard
/// may legitimately land in either stage (`parse_policy`'s validation or
/// `compile`) — both return `Vec<CompileError>`, and callers (the
/// controller's `apply::compile_policy`) run both stages back-to-back, so
/// "the pipeline rejects it" is the stable behavioral pin, not which stage
/// fired.
fn compile_pipeline(yaml: &str, segments: &[SegmentDef]) -> Result<PolicyIR, Vec<CompileError>> {
    let src = parse_policy(yaml, segments)?;
    compile(&src, segments, 1)
}

/// `n` distinct quoted /32 CIDRs inside `base` (a /16 given as "10.0" or
/// "10.1"), rendered for a YAML flow sequence. `n` ≤ 65536.
fn quoted_slash32s(base: &str, n: usize) -> String {
    assert!(n <= 65_536);
    (0..n)
        .map(|i| format!("\"{base}.{}.{}/32\"", i / 256, i % 256))
        .collect::<Vec<_>>()
        .join(", ")
}

/// One block, one `allow` rule whose OWN `src` list is `list`.
fn yaml_with_rule_src(list: &str) -> String {
    format!(
        "policy:\n  - from: seg-a\n    to: seg-b\n    rules:\n      - allow: {{ proto: tcp, src: [{list}] }}\n"
    )
}

/// One block, one `allow` rule whose OWN `dst` list is `list`.
fn yaml_with_rule_dst(list: &str) -> String {
    format!(
        "policy:\n  - from: seg-a\n    to: seg-b\n    rules:\n      - allow: {{ proto: tcp, dst: [{list}] }}\n"
    )
}

/// Asserts `errors` contains at least one message naming BOTH the numeric
/// limit (1024) and the LPM-capacity nature of the failure, plus the
/// offending side — an operator staring at a 1025-CIDR policy needs to
/// know which side to shrink, and design §4/§7's convention is errors that
/// name their location.
fn assert_names_lpm_limit(errors: &[CompileError], side: &str) {
    let rendered: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
    assert!(
        rendered.iter().any(|m| {
            let lower = m.to_lowercase();
            m.contains("1024") && lower.contains("lpm") && lower.contains(side)
        }),
        "expected a CompileError naming the 1024 LPM-capacity limit and the \
         '{side}' side, got: {rendered:?}"
    );
}

/// Item 1 boundary (green today, must STAY green after the fix): exactly
/// 1024 distinct src /32s on one rule is exactly at the eBPF trie's
/// capacity — `Ok`, no error. Paired with the 1025 test below so an
/// off-by-one guard (`>= 1024` instead of `> 1024`) is caught.
#[test]
fn compile_ok_at_exactly_1024_distinct_cidrs_on_one_rule_side() {
    let yaml = yaml_with_rule_src(&quoted_slash32s("10.0", LPM_CAP));
    let ir = compile_pipeline(&yaml, &segments()).unwrap_or_else(|e| {
        panic!("exactly {LPM_CAP} distinct src CIDRs must compile Ok, got: {e:?}")
    });
    assert_eq!(ir.blocks[0].rules[0].src.len(), LPM_CAP);
}

/// Item 1 (RED today): 1025 distinct /32s in one rule's `src` compiles
/// `Ok` right now — the resulting IR only fails at gateway `apply()` time,
/// as an opaque LPM-trie insert error on entry #1025. Expected: a
/// `CompileError` naming the 1024 limit, at compile time, on the
/// controller (design §6's compile-time-rejection rule).
#[test]
fn compile_errs_at_1025_distinct_src_cidrs_on_one_rule_naming_the_limit() {
    let yaml = yaml_with_rule_src(&quoted_slash32s("10.0", LPM_CAP + 1));
    let errors = compile_pipeline(&yaml, &segments()).expect_err(
        "1025 distinct src CIDRs exceed the eBPF LPM trie's 1024-entry capacity \
         and must be a compile-time error, not a gateway apply()-time one",
    );
    assert_names_lpm_limit(&errors, "src");
}

/// Item 1, dst-side twin (RED today): the guard is per SIDE — a dst list
/// of 1025 distinct CIDRs overflows the DST trie just the same.
#[test]
fn compile_errs_at_1025_distinct_dst_cidrs_on_one_rule_naming_the_limit() {
    let yaml = yaml_with_rule_dst(&quoted_slash32s("10.1", LPM_CAP + 1));
    let errors = compile_pipeline(&yaml, &segments()).expect_err(
        "1025 distinct dst CIDRs exceed the eBPF LPM trie's 1024-entry capacity \
         and must be a compile-time error",
    );
    assert_names_lpm_limit(&errors, "dst");
}

/// Item 1, block-fallback half (RED today): a rule with EMPTY `src` uses
/// its block's `src_cidrs` — the `from`-segment's whole CIDR list
/// (`flatten`'s documented fallback, mirrored by `build_lpm_entries`). So
/// a 1025-CIDR SEGMENT referenced by a src-less rule overflows the trie
/// exactly like a 1025-CIDR rule list does, and the guard must count the
/// fallback ("distinct union of rule.src if non-empty else block
/// src_cidrs"), not just literal rule lists.
#[test]
fn compile_errs_when_segment_fallback_side_carries_1025_distinct_cidrs() {
    let big_cidrs: Vec<ipnet::Ipv4Net> = (0..LPM_CAP + 1)
        .map(|i| format!("10.0.{}.{}/32", i / 256, i % 256).parse().unwrap())
        .collect();
    let segments = vec![
        SegmentDef {
            name: "seg-big".into(),
            cidrs: big_cidrs,
        },
        SegmentDef {
            name: "seg-b".into(),
            cidrs: vec!["10.1.0.0/16".parse().unwrap()],
        },
    ];
    let yaml =
        "policy:\n  - from: seg-big\n    to: seg-b\n    rules:\n      - allow: { proto: tcp }\n";
    let errors = compile_pipeline(yaml, &segments).expect_err(
        "a src-less rule falls back to its 1025-CIDR from-segment, overflowing \
         the 1024-entry LPM trie — must be a compile-time error",
    );
    assert_names_lpm_limit(&errors, "src");
}

/// Item 1 semantics pin (green today, must STAY green): the per-side count
/// is the DISTINCT UNION across rules, not the sum of per-rule list
/// lengths — two rules sharing one 513-CIDR src list contribute 513
/// distinct CIDRs (513 trie entries in `build_lpm_entries`, which dedups),
/// not 1026. A guard implemented as a naive sum would wrongly reject this
/// valid policy; this test catches that implementation.
#[test]
fn distinct_cidr_count_is_a_union_not_a_sum_across_rules() {
    let list = quoted_slash32s("10.0", 513);
    let yaml = format!(
        "policy:\n  - from: seg-a\n    to: seg-b\n    rules:\n      \
         - allow: {{ proto: tcp, ports: [80], src: [{list}] }}\n      \
         - allow: {{ proto: tcp, ports: [443], src: [{list}] }}\n"
    );
    compile_pipeline(&yaml, &segments()).unwrap_or_else(|e| {
        panic!(
            "two rules sharing the same 513 src CIDRs are 513 DISTINCT CIDRs \
             (well under 1024), not 1026 — must compile Ok, got: {e:?}"
        )
    });
}

/// Item 2a (RED today): a policy referencing a segment declared with NO
/// CIDRs parses and compiles `Ok` right now (verified: `validate.rs` never
/// checks `SegmentDef::cidrs` for emptiness, and `compile()` just copies
/// the empty list into the block's `src_cidrs`). The result is an IR block
/// whose src side matches nothing — a silently dead rule on the eBPF
/// backend, and malformed `{ }` set syntax in the nftables codegen
/// (`nft.rs`'s `cidr_set`). The pipeline must instead reject it with a
/// `CompileError` naming the offending segment and its missing CIDRs
/// (contrast: the controller's enrollment path already rejects empty
/// `cidrs` at its own boundary, `enrollment.rs` — "cidrs must not be
/// empty").
#[test]
fn referenced_segment_with_no_cidrs_is_a_compile_error() {
    let segments = vec![
        SegmentDef {
            name: "empty-seg".into(),
            cidrs: vec![],
        },
        SegmentDef {
            name: "seg-b".into(),
            cidrs: vec!["10.1.0.0/16".parse().unwrap()],
        },
    ];
    let yaml =
        "policy:\n  - from: empty-seg\n    to: seg-b\n    rules:\n      - allow: { proto: icmp }\n";
    let errors = compile_pipeline(yaml, &segments).expect_err(
        "a policy referencing a zero-CIDR segment must fail compilation, not \
         produce an IR block whose side matches nothing",
    );
    let rendered: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
    assert!(
        rendered
            .iter()
            .any(|m| m.to_lowercase().contains("cidr") && m.contains("empty-seg")),
        "expected a CompileError naming segment 'empty-seg' and its missing \
         CIDRs, got: {rendered:?}"
    );
}
