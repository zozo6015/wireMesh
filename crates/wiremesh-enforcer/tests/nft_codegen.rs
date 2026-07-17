//! Task 11, Step 1 (test author): failing golden tests for
//! `wiremesh_enforcer::ruleset` — the pure IR -> nftables ruleset codegen
//! (design §6/D-C3-6; `.superpowers/sdd/task-11-brief.md`). Pure, no
//! privilege/netns needed (unlike `tests/ebpf_backend.rs`).
//!
//! RED evidence (current skeleton): `ruleset`'s body is `todo!()`
//! (`src/nft.rs`, Task 11 Step 1) — every test below panics with that
//! message until Step 3 (implementer) fills it in.
//!
//! Fixture provenance: every `tests/fixtures/*.nft` file was hand-derived
//! from the brief's generated-shape spec, then round-tripped through the
//! real `nft` binary inside the dev container
//! (`./dev.sh run "nft --check -f <file>"` for syntax, and a full
//! `nft -f <file>` + `nft list table ...` + `nft delete table ...` load/
//! apply/teardown cycle for semantics) to confirm every fixture is not just
//! plausible but literally loadable nftables — see
//! `.superpowers/sdd/task-11-tests-report.md` for the full transcript and
//! per-fixture rule_id/ordering derivation.
//!
//! Codegen shape pinned by these fixtures (implementer must match
//! byte-for-byte):
//!  - Header: `table ip wiremesh_<iface>`, `flush table ip wiremesh_<iface>`,
//!    then the table block.
//!  - Table body: one `counter r_<rule_id> {}` per DISTINCT `rule_id`, in
//!    first-appearance order over the flattened rule list (reused from
//!    `flatten`'s `(block_ord, rule_ord, port_ord)` order) — NOT sorted, NOT
//!    deduplicated-by-hash-value order. Then `counter default_deny {}`.
//!  - `chain from_fabric { ... }`: `ct state established,related counter
//!    accept` first; then one line per flattened rule, IN FLATTENED ORDER
//!    (first-match-wins is a textual property of this chain, not enforced
//!    by any nft feature); then `counter name "default_deny" drop` last.
//!  - Per-flattened-rule line:
//!    `ip saddr { <src cidrs, comma-joined> } ip daddr { <dst cidrs> }`
//!    ALWAYS wrapped in `{ }` regardless of how many CIDRs (nft's anonymous-
//!    set syntax accepts one element same as many), followed by:
//!      - `(0,0)` ports (design/`flatten`'s "any port" sentinel) -> NO port
//!        match at all. If `proto` is `tcp`/`udp`, that also means no
//!        protocol keyword is needed to express "any port on this proto" in
//!        a way nft accepts as a standalone match — `nft --check` rejects a
//!        bare `tcp`/`udp`/`icmp` token with no following statement (verified
//!        by hand), so this codegen must use `meta l4proto <proto>` whenever
//!        there is no dport clause (icmp always takes this form; tcp/udp take
//!        it only when the FlatRule's ports are `(0,0)`).
//!      - a concrete `(lo, hi)` -> `tcp dport { <lo> }` when `lo == hi`, else
//!        `tcp dport { <lo>-<hi> }` (never applies to icmp; `wiremesh-policy`
//!        never emits ports on an icmp rule).
//!    then `counter name "r_<rule_id>"` and the verdict (`accept`/`drop` for
//!    allow/deny) — EVERY flattened rule gets a named-counter reference, not
//!    just deny ones (the brief's "one [counter] per distinct rule_id"
//!    applies regardless of action).
//!  - `proto: any` (no explicit proto in the DSL) explodes into exactly 3
//!    consecutive lines — `meta l4proto tcp`, then `udp`, then `icmp` — all
//!    three sharing the ONE `r_<rule_id>` counter and the rule's verdict,
//!    consecutive and in that fixed tcp/udp/icmp order (first-match
//!    semantics for the rule as a whole are unaffected: whichever concrete
//!    proto a packet actually is matches its one line).
//!  - Base chains: `chain input { type filter hook input priority 0; policy
//!    accept; iifname "<iface>" jump from_fabric; }` and the same shape for
//!    `forward` (note: base chain policy stays `accept` — default-deny is
//!    scoped to tun-originated traffic only, via the `iifname` jump, per the
//!    brief; a gateway host's other interfaces are untouched).
//!  - Empty policy (no blocks at all): the table still gets `default_deny`'s
//!    counter and both base chains; `chain from_fabric` contains only the
//!    `ct state ...` line and the final `counter name "default_deny" drop`
//!    line, with no rule lines and no `r_*` counters in between.

use wiremesh_policy::{
    compile, parse_policy, IrAction, IrBlock, IrProto, IrRule, PolicyIR, SegmentDef,
};

/// design §5's worked example (the same YAML as
/// `wiremesh-policy/tests/fixtures/design_s5_example.yaml`, inlined here so
/// this crate's tests don't reach across crate boundaries into another
/// crate's `tests/fixtures/`): proxmox-lab (10.10.0.0/16) -> aws-prod
/// (172.16.0.0/12), a deny carve-out ahead of two allow rules
/// (first-match-wins). `version: 42` matches that sibling crate's
/// `design_s5_example.ir.json` fixture exactly, so the three `rule_id`s
/// hardcoded in `tests/fixtures/design_s5_example.nft` below
/// (`a6332aaa2e0af7cb` / `12703e46657fa6f4` / `4c673459e3261fa2`) are the
/// same real content-hash values already proven correct by that crate's own
/// golden test — not freshly invented ones.
const DESIGN_S5_YAML: &str = "
policy:
  - from: proxmox-lab
    to: aws-prod
    rules:
      - deny:  { ports: [22], proto: tcp }
      - allow: { dst: 172.16.1.50/32, ports: [5432], proto: tcp }
      - allow: { dst: 172.16.2.0/24, ports: [443, \"8000-8080\"], proto: tcp }
";

fn design_s5_segments() -> Vec<SegmentDef> {
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

/// Parses + compiles `yaml` against `segments`, panicking with full detail
/// on failure (mirrors `wiremesh-policy/tests/golden.rs`'s and
/// `wiremesh-enforcer/tests/flatten.rs`'s `compile_ok` convention) — every
/// input used below is expected to be valid, so a failure here is a test
/// bug, never an expected-error case.
fn compile_ok(yaml: &str, segments: &[SegmentDef], version: u64) -> PolicyIR {
    let src = parse_policy(yaml, segments)
        .unwrap_or_else(|errors| panic!("expected valid policy, got errors: {errors:?}"));
    compile(&src, segments, version)
        .unwrap_or_else(|errors| panic!("expected compile to succeed, got errors: {errors:?}"))
}

/// design §5's worked example, compiled with `version: 42` to match the
/// sibling crate's `design_s5_example.ir.json` fixture's rule_ids exactly.
fn design_s5_ir() -> PolicyIR {
    compile_ok(DESIGN_S5_YAML, &design_s5_segments(), 42)
}

/// (a) design-§5 example IR -> exact fixture script (`iface = "wg0"`,
/// matching the brief's own worked example table name
/// `wiremesh_wg0`). Exercises: block src/dst CIDR fallback (rule 0 has no
/// explicit src/dst), an explicit-dst rule (rule 1), and a rule that
/// explodes into 2 port-range FlatRules sharing one `rule_id` (rule 2) — the
/// 3 distinct `rule_id`s -> 3 distinct named counters, 4 flattened rule
/// lines total.
#[test]
fn ruleset_matches_design_s5_example_golden_fixture() {
    let ir = design_s5_ir();
    let script = wiremesh_enforcer::ruleset(&ir, "wg0")
        .expect("ruleset() should succeed for a valid, in-budget PolicyIR");
    let expected = include_str!("fixtures/design_s5_example.nft");
    assert_eq!(script, expected, "generated script must match the golden fixture byte-for-byte");
}

/// (b) `proto: any` (no explicit `proto:` in the DSL) explodes into 3
/// consecutive lines (tcp/udp/icmp) sharing the ONE named counter for that
/// rule's `rule_id` — built via direct `PolicyIR` construction (an edge
/// shape, not one of design §5's examples) per the Task 11 brief's allowance.
#[test]
fn ruleset_explodes_proto_any_into_per_proto_lines_sharing_one_counter() {
    let ir = PolicyIR {
        schema: 1,
        version: 1,
        blocks: vec![IrBlock {
            from: "seg-a".into(),
            to: "seg-b".into(),
            src_cidrs: vec!["10.0.0.0/16".into()],
            dst_cidrs: vec!["10.1.0.0/16".into()],
            rules: vec![IrRule {
                rule_id: "any1".into(),
                action: IrAction::Allow,
                proto: IrProto::Any,
                src: vec![],
                dst: vec![],
                ports: vec![],
            }],
        }],
    };

    let script = wiremesh_enforcer::ruleset(&ir, "wg0")
        .expect("ruleset() should succeed for a single proto:any rule");
    let expected = include_str!("fixtures/proto_any_explosion.nft");
    assert_eq!(script, expected, "generated script must match the golden fixture byte-for-byte");
}

/// (c) carve-out ordering preserved: an explicit `deny` ahead of a broader
/// `allow` (first-match-wins) must stay in that exact textual order in the
/// generated `from_fabric` chain — a codegen bug that grouped/sorted lines
/// by action (e.g. all denies before/after all allows) rather than
/// preserving flattened source order would silently break first-match
/// semantics and must fail this test. Built via direct `PolicyIR`
/// construction (edge shape) with hand-chosen `rule_id`s, independent of the
/// design-§5 fixture above so a fixture-copy-paste bug in (a) can't mask an
/// ordering regression here.
#[test]
fn ruleset_preserves_carve_out_ordering() {
    let ir = PolicyIR {
        schema: 1,
        version: 1,
        blocks: vec![IrBlock {
            from: "internal".into(),
            to: "external".into(),
            src_cidrs: vec!["10.5.0.0/16".into()],
            dst_cidrs: vec!["203.0.113.0/24".into()],
            rules: vec![
                IrRule {
                    rule_id: "carve_deny".into(),
                    action: IrAction::Deny,
                    proto: IrProto::Tcp,
                    src: vec![],
                    dst: vec!["203.0.113.5/32".into()],
                    ports: vec![(3389, 3389)],
                },
                IrRule {
                    rule_id: "carve_allow".into(),
                    action: IrAction::Allow,
                    proto: IrProto::Tcp,
                    src: vec![],
                    dst: vec![],
                    ports: vec![],
                },
            ],
        }],
    };

    let script = wiremesh_enforcer::ruleset(&ir, "wg0")
        .expect("ruleset() should succeed for a 2-rule carve-out policy");
    let expected = include_str!("fixtures/carve_out_ordering.nft");
    assert_eq!(script, expected, "generated script must match the golden fixture byte-for-byte");
}

/// (d) empty policy (no blocks at all) -> just the `ct` line + default-deny:
/// `chain from_fabric` must contain no rule lines and no `r_*` counters, only
/// `ct state established,related counter accept` followed immediately by
/// `counter name "default_deny" drop`. `iface = "eth1"` here (rather than
/// "wg0", reused by every other test above) to prove the iface substitution
/// is a genuine parameter, not a hardcoded string.
#[test]
fn ruleset_for_empty_policy_is_just_ct_line_and_default_deny() {
    let ir = PolicyIR {
        schema: 1,
        version: 1,
        blocks: vec![],
    };

    let script = wiremesh_enforcer::ruleset(&ir, "eth1")
        .expect("ruleset() should succeed for an empty (zero-block) PolicyIR");
    let expected = include_str!("fixtures/empty_policy.nft");
    assert_eq!(script, expected, "generated script must match the golden fixture byte-for-byte");
}
