//! Backlog 10 PR-A (Cycle-3 hardening trio), test author — Item 2c, the
//! enforcer-side belt for empty-CIDR segments: `flatten()` on an IR whose
//! block has an empty side (and whose rule doesn't override it) must be
//! `Err`, so BOTH backends fail identically and loudly instead of each
//! degrading in its own way:
//!
//!  - eBPF: `build_lpm_entries` produces zero entries for that rule's side
//!    → the rule can never match → a silently dead rule (and, for `allow`,
//!    silently dropped traffic that policy says should flow);
//!  - nftables: `nft.rs`'s `cidr_set` (`nft.rs:113-116`) renders the empty
//!    list as `{  }` — malformed anonymous-set syntax `nft -f` rejects at
//!    apply time, i.e. an opaque runtime failure on the gateway.
//!
//! **Why the pin is a flatten-level `Err` (the choice the audit asked to be
//! justified):** both backends' `apply()` — and the nft codegen entry point
//! `ruleset()` — call `flatten()` FIRST, so one guard there is a single
//! choke point that makes eBPF and nftables behaviorally identical (the
//! Cycle-3 conformance suite's core invariant) instead of "dead rule" vs
//! "nft syntax error". Pinning nft's textual output ("no `{  }` rendered")
//! would cover only one backend, would go stale on any codegen reshuffle,
//! and would still leave the eBPF dead-rule half unpinned. The
//! `ruleset()`-propagation test below is kept as the cheap cross-check
//! that the nft entry point actually inherits the guard (it must, since
//! its first line is `flatten(ir)?`).
//!
//! Like `tests/flatten.rs`'s `oversized_ir`, the malformed `PolicyIR`s are
//! built as struct literals: `wiremesh-policy`'s OWN fix for this audit
//! item (Item 2a) will make such IR uncompilable via `parse_policy` +
//! `compile`, but the enforcer consumes IR straight off the wire (design
//! §5's canonical JSON) and must not trust the upstream compiler —
//! defense in depth, the exact rationale `oversized_ir` already documents.
//!
//! RED status (runtime-red — this file compiles against today's public
//! API): all three tests fail today (`flatten` returns `Ok` and `ruleset`
//! happily renders `{  }`).

use wiremesh_enforcer::{flatten, ruleset};
use wiremesh_policy::{IrAction, IrBlock, IrProto, IrRule, PolicyIR};

/// One block, one port-80 allow rule with empty rule-level `src`/`dst`
/// (i.e. both sides fall back to the block's CIDR lists), with the given
/// block-level sides.
fn ir_with_block_sides(src_cidrs: Vec<String>, dst_cidrs: Vec<String>) -> PolicyIR {
    PolicyIR {
        schema: 1,
        version: 1,
        blocks: vec![IrBlock {
            from: "seg-a".into(),
            to: "seg-b".into(),
            src_cidrs,
            dst_cidrs,
            rules: vec![IrRule {
                rule_id: "deadbeef00000000".into(),
                action: IrAction::Allow,
                proto: IrProto::Tcp,
                src: vec![],
                dst: vec![],
                ports: vec![(80, 80)],
            }],
        }],
    }
}

/// Asserts `err`'s message names the offending side and its emptiness, so
/// a gateway log line is actionable ("which side of which policy is
/// empty"), not just a generic failure.
fn assert_names_empty_side(err: &anyhow::Error, side: &str) {
    let msg = format!("{err:#}").to_lowercase();
    assert!(
        msg.contains(side) && msg.contains("cidr"),
        "error must name the empty '{side}' side's missing CIDRs, got: {msg}"
    );
}

/// RED today: `flatten()` currently returns `Ok` for a block whose
/// `src_cidrs` is empty and whose rule declares no `src` of its own — the
/// documented empty-side fallback clones the block's EMPTY list into
/// `FlatRule::src_cidrs`, producing a rule that can never match anything.
/// Expected: `Err` naming the empty src side.
#[test]
fn flatten_errs_when_block_src_side_is_empty_and_rule_does_not_override() {
    let ir = ir_with_block_sides(vec![], vec!["10.1.0.0/16".into()]);
    let err = flatten(&ir).expect_err(
        "an IR block with an empty src side (and no rule-level src) must be \
         rejected by flatten, not become a never-matching FlatRule",
    );
    assert_names_empty_side(&err, "src");
}

/// RED today: the dst-side twin of the test above.
#[test]
fn flatten_errs_when_block_dst_side_is_empty_and_rule_does_not_override() {
    let ir = ir_with_block_sides(vec!["10.0.0.0/16".into()], vec![]);
    let err = flatten(&ir).expect_err(
        "an IR block with an empty dst side (and no rule-level dst) must be \
         rejected by flatten, not become a never-matching FlatRule",
    );
    assert_names_empty_side(&err, "dst");
}

/// RED today: `ruleset()` (the nftables codegen entry point) currently
/// renders the empty side as literal `{  }` — malformed nft anonymous-set
/// syntax that `nft -f` would reject at gateway apply() time. Once
/// `flatten` rejects empty-side IR, `ruleset` inherits the `Err` through
/// its leading `flatten(ir)?` — this test pins that propagation, so the
/// nftables backend can never again emit a ruleset containing `{  }` for
/// such input.
#[test]
fn nft_ruleset_refuses_empty_side_ir_instead_of_emitting_malformed_empty_set() {
    let ir = ir_with_block_sides(vec![], vec!["10.1.0.0/16".into()]);
    match ruleset(&ir, "wg0") {
        Err(_) => {} // expected: the flatten-level guard propagates
        Ok(script) => panic!(
            "ruleset() must refuse empty-side IR (today it renders malformed \
             nft set syntax); got Ok with script:\n{script}"
        ),
    }
}
