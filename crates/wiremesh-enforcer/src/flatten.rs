//! `flatten` — the pure, shared front half of both enforcer backends (design
//! §6; Task 7 brief's `Interfaces` snippet). Turns a [`PolicyIR`] into a flat
//! list of [`FlatRule`]s in the exact order both backends' first-match rule
//! loop must scan them.
//!
//! Contract (from the brief, tested in `tests/flatten.rs` and this crate's
//! own compiler-side guard test in `wiremesh-policy/tests/golden.rs`):
//!  - Blocks flatten in `(block_ord, rule_ord)` order — i.e. source order,
//!    the same order [`PolicyIR::blocks`] and each block's `rules` already
//!    carry (design §4's determinism guarantee).
//!  - A rule's empty `src`/`dst` (design §4: "empty means the whole
//!    segment") falls back to its *block's* `src_cidrs`/`dst_cidrs` — not an
//!    empty CIDR list.
//!  - `Err` if a rule's EFFECTIVE side (its own list, or the block fallback
//!    when that list is empty) ends up with zero CIDRs (Backlog 10 PR-A
//!    Item 2c, `tests/hardening.rs`): such a rule could never match on the
//!    eBPF backend (zero LPM entries — a silently dead rule) and renders as
//!    malformed `{ }` anonymous-set syntax in the nftables codegen.
//!    `wiremesh-policy` now rejects the zero-CIDR segment at compile time
//!    (Item 2a), but this crate consumes IR straight off the wire (design
//!    §5's canonical JSON) and must not trust the upstream compiler — the
//!    same defense-in-depth rationale as the [`MAX_RULES`] re-check below.
//!    Both backends call `flatten` first, so this one guard keeps them
//!    behaviorally identical (Cycle-3 conformance's core invariant).
//!  - A rule with `k` port ranges explodes into `k` consecutive `FlatRule`s
//!    sharing the same `rule_id` (same action ⇒ first-match semantics are
//!    preserved either way; counters aggregate by `rule_id` anyway, see
//!    [`crate::Counters::by_rule`]). A rule with NO ports (proto `icmp`/`any`
//!    with nothing in `ports`) explodes into exactly one `FlatRule` with
//!    `port_lo == port_hi == 0` ("(0,0) = any", per the brief).
//!  - `Err` if the total flattened count (after port explosion, across every
//!    block) exceeds [`MAX_RULES`] — the same 256 limit
//!    `wiremesh-policy`'s compile-time guard duplicates/cross-references
//!    (design §6: "the controller rejects at compile time, not the gateway
//!    at load time").
//!
//! Task 7 Step 3 (implementer): implemented below.

use ipnet::Ipv4Net;
use std::collections::HashSet;
use wiremesh_enforcer_common::LPM_MAX_ENTRIES;
use wiremesh_policy::{IrAction, IrProto, PolicyIR};

/// The max-rules-per-policy constant (design §6's "documented max-rules-
/// per-block constant"; applied here across the WHOLE flattened policy, not
/// per block — see the brief and the cross-referencing comment on
/// `wiremesh-policy`'s own compile-time guard, which duplicates this exact
/// number so the controller rejects at compile time what the gateway would
/// otherwise reject at eBPF-load time).
pub const MAX_RULES: usize = 256;

/// The ONE implementation of "how many DISTINCT CIDRs does a side carry",
/// shared by every site that needs that number so they can never drift
/// (the standing review requirement on this pair): [`flatten`]'s incremental
/// bound below, [`crate::ebpf`]'s `distinct_side_cidrs` (which feeds
/// `build_lpm_entries`' actual trie keys), and [`crate::check_lpm_capacity`].
/// Distinctness is `Ipv4Net` equality — host bits significant, no masking —
/// matching `wiremesh_policy::MAX_LPM_CIDRS_PER_SIDE`'s compile-time
/// counting exactly (see that constant's doc for why masking is off the
/// table: `rule_id` content-hashes the unmasked strings).
#[derive(Default)]
pub(crate) struct DistinctSideCidrs {
    seen: HashSet<Ipv4Net>,
    /// First-appearance order, which is the order `build_lpm_entries`
    /// inserts trie keys in. Trie contents don't depend on it, but keeping
    /// it deterministic makes that output stable for debugging.
    order: Vec<Ipv4Net>,
}

impl DistinctSideCidrs {
    /// Folds one side list into the running distinct set.
    pub(crate) fn observe(&mut self, cidrs: &[Ipv4Net]) {
        for c in cidrs {
            if self.seen.insert(*c) {
                self.order.push(*c);
            }
        }
    }

    pub(crate) fn into_vec(self) -> Vec<Ipv4Net> {
        self.order
    }

    /// `Err` once this side has passed the eBPF per-side LPM trie's
    /// capacity. `side` is `"src"`/`"dst"` — named in the message so an
    /// operator knows which side to shrink.
    pub(crate) fn check(&self, side: &str) -> anyhow::Result<()> {
        if self.order.len() > LPM_MAX_ENTRIES {
            anyhow::bail!(
                "policy's {side} side carries {} distinct CIDRs, exceeding the \
                 {LPM_MAX_ENTRIES}-entry per-side eBPF LPM trie capacity \
                 (wiremesh_enforcer_common::LPM_MAX_ENTRIES)",
                self.order.len()
            );
        }
        Ok(())
    }
}

/// One fully-resolved, backend-agnostic rule, post block-CIDR-fallback and
/// post port-explosion. `idx` is this `FlatRule`'s position in the flattened
/// list (its scan order); `(port_lo, port_hi) == (0, 0)` means "any port".
#[derive(Debug, Clone, PartialEq)]
pub struct FlatRule {
    pub idx: u32,
    pub rule_id: String,
    pub action: IrAction,
    pub proto: IrProto,
    pub src_cidrs: Vec<Ipv4Net>,
    pub dst_cidrs: Vec<Ipv4Net>,
    pub port_lo: u16,
    pub port_hi: u16,
}

/// Parses a slice of normalized CIDR strings (as [`wiremesh_policy::IrBlock`]/
/// [`wiremesh_policy::IrRule`] carry them) into [`Ipv4Net`]s. `wiremesh-policy`
/// guarantees every entry it hands out already parsed successfully once (at
/// `parse_policy`/`compile` time) — a failure here would mean `wiremesh-policy`
/// handed out a malformed string, which is a bug in that crate, not a normal
/// `flatten` error path.
fn parse_cidrs(raw: &[String]) -> anyhow::Result<Vec<Ipv4Net>> {
    raw.iter()
        .map(|s| {
            s.parse::<Ipv4Net>().map_err(|e| {
                anyhow::anyhow!("wiremesh-policy handed flatten an invalid CIDR '{s}': {e}")
            })
        })
        .collect()
}

/// Flattens `ir` per the module-level contract above. `Err` if the resulting
/// list would exceed [`MAX_RULES`] entries.
pub fn flatten(ir: &PolicyIR) -> anyhow::Result<Vec<FlatRule>> {
    // (CodeRabbit finding) Bound the work BEFORE doing it. The flattened
    // count is pure arithmetic over the IR — exactly the same
    // `ports.len().max(1)` sum the post-expansion check used to compute —
    // so hoisting it here changes no verdict and no message, it just means
    // a hostile/corrupt IR (which a gateway genuinely can be handed: this
    // crate parses IR straight off Sync and does not trust its compiler)
    // can no longer make us allocate and clone millions of expanded
    // `FlatRule`s first and only then discover they were over budget.
    let expanded: usize = ir
        .blocks
        .iter()
        .flat_map(|b| &b.rules)
        .map(|r| r.ports.len().max(1))
        .sum();
    if expanded > MAX_RULES {
        anyhow::bail!(
            "policy flattens to {expanded} rules, exceeding the {MAX_RULES}-rule limit \
             (MAX_RULES)"
        );
    }

    let mut flat = Vec::new();
    // Running per-side distinct-CIDR counts, checked as we go for the same
    // bound-the-work-first reason: with the rule count already capped at
    // MAX_RULES above, the remaining amplification is each rule's CIDR-list
    // CLONE, so the side capacity must be enforced before those clones pile
    // up rather than after. Both counters use the shared
    // [`DistinctSideCidrs`], so this incremental guard and
    // [`crate::check_lpm_capacity`] cannot diverge in what they count.
    let mut src_distinct = DistinctSideCidrs::default();
    let mut dst_distinct = DistinctSideCidrs::default();

    for block in &ir.blocks {
        let block_src_cidrs = parse_cidrs(&block.src_cidrs)?;
        let block_dst_cidrs = parse_cidrs(&block.dst_cidrs)?;

        for rule in &block.rules {
            let src_cidrs = if rule.src.is_empty() {
                block_src_cidrs.clone()
            } else {
                parse_cidrs(&rule.src)?
            };
            let dst_cidrs = if rule.dst.is_empty() {
                block_dst_cidrs.clone()
            } else {
                parse_cidrs(&rule.dst)?
            };

            // Empty-side guard (module-doc contract, Backlog 10 PR-A Item
            // 2c): an effective side with zero CIDRs is rejected loudly and
            // identically for BOTH backends, instead of an eBPF dead rule
            // vs. an nft `{  }` syntax error at apply time.
            for (side, cidrs) in [("src", &src_cidrs), ("dst", &dst_cidrs)] {
                if cidrs.is_empty() {
                    anyhow::bail!(
                        "block '{}' \u{2192} '{}' rule {}: {side} side has no CIDRs \
                         (the rule declares no {side} of its own and the block's \
                         {side} CIDR list is empty) — such a rule could never match",
                        block.from,
                        block.to,
                        rule.rule_id
                    );
                }
            }

            // Per-side LPM capacity, folded in BEFORE this rule's lists are
            // cloned into its (possibly many, port-exploded) FlatRules.
            // Observing once per RULE — not once per expanded FlatRule — is
            // equivalent by construction: a port explosion clones the SAME
            // two CIDR lists into every FlatRule it produces, so the distinct
            // sets are identical either way.
            src_distinct.observe(&src_cidrs);
            src_distinct.check("src")?;
            dst_distinct.observe(&dst_cidrs);
            dst_distinct.check("dst")?;

            // No `ports:` at all -> exactly one FlatRule, "(0,0) = any"
            // (module doc / brief). Otherwise one FlatRule per port range,
            // all sharing this rule's `rule_id`.
            if rule.ports.is_empty() {
                flat.push(FlatRule {
                    idx: 0, // fixed up below, once the final length is known
                    rule_id: rule.rule_id.clone(),
                    action: rule.action.clone(),
                    proto: rule.proto.clone(),
                    src_cidrs: src_cidrs.clone(),
                    dst_cidrs: dst_cidrs.clone(),
                    port_lo: 0,
                    port_hi: 0,
                });
            } else {
                for &(port_lo, port_hi) in &rule.ports {
                    flat.push(FlatRule {
                        idx: 0,
                        rule_id: rule.rule_id.clone(),
                        action: rule.action.clone(),
                        proto: rule.proto.clone(),
                        src_cidrs: src_cidrs.clone(),
                        dst_cidrs: dst_cidrs.clone(),
                        port_lo,
                        port_hi,
                    });
                }
            }
        }
    }

    // The pre-expansion bound above is arithmetically the count produced
    // here, so this can only ever hold — kept as a debug-only cross-check
    // that the two stay in step rather than a second live guard.
    debug_assert_eq!(
        flat.len(),
        expanded,
        "the pre-expansion flattened-count bound must equal what expansion actually produced"
    );

    for (i, f) in flat.iter_mut().enumerate() {
        f.idx = i as u32;
    }

    Ok(flat)
}
