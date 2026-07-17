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
use wiremesh_policy::{IrAction, IrProto, PolicyIR};

/// The max-rules-per-policy constant (design §6's "documented max-rules-
/// per-block constant"; applied here across the WHOLE flattened policy, not
/// per block — see the brief and the cross-referencing comment on
/// `wiremesh-policy`'s own compile-time guard, which duplicates this exact
/// number so the controller rejects at compile time what the gateway would
/// otherwise reject at eBPF-load time).
pub const MAX_RULES: usize = 256;

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
            s.parse::<Ipv4Net>()
                .map_err(|e| anyhow::anyhow!("wiremesh-policy handed flatten an invalid CIDR '{s}': {e}"))
        })
        .collect()
}

/// Flattens `ir` per the module-level contract above. `Err` if the resulting
/// list would exceed [`MAX_RULES`] entries.
pub fn flatten(ir: &PolicyIR) -> anyhow::Result<Vec<FlatRule>> {
    let mut flat = Vec::new();

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

    if flat.len() > MAX_RULES {
        anyhow::bail!(
            "policy flattens to {} rules, exceeding the {MAX_RULES}-rule limit \
             (MAX_RULES)",
            flat.len()
        );
    }

    for (i, f) in flat.iter_mut().enumerate() {
        f.idx = i as u32;
    }

    Ok(flat)
}
