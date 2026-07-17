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
//! Task 7 Step 1 (test author) skeleton: `flatten`'s body is `todo!()` — no
//! real logic. Step 3 (implementer) fills it in.

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

/// Flattens `ir` per the module-level contract above. `Err` if the resulting
/// list would exceed [`MAX_RULES`] entries.
pub fn flatten(ir: &PolicyIR) -> anyhow::Result<Vec<FlatRule>> {
    let _ = ir;
    todo!(
        "Task 7 Step 3: flatten PolicyIR into Vec<FlatRule> — block order, \
         block-CIDR fallback for empty rule src/dst, port explosion sharing \
         rule_id, Err if > MAX_RULES ({MAX_RULES})"
    )
}
