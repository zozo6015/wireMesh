//! DSL → IR compilation (design §5.2/§4): resolves segment names to
//! concrete CIDRs, assigns content-hash `rule_id`s, and preserves the
//! deterministic source order the DSL already guarantees. Task 2 Step 1
//! (test author): signatures only, `todo!()` bodies — Task 2 Step 3
//! (implementer) fills these in.
//!
//! `compile` consumes an already-validated [`PolicySource`] (Task 1's
//! `parse_policy` did parse + all validation against `segments`) and may
//! assume it is valid — this is resolution + ordering + hashing only, not
//! re-validation.

use crate::ir::{IrRule, PolicyIR};
use crate::{CompileError, PolicySource, SegmentDef};

/// Compiles `src` (already validated against `segments` by
/// [`crate::parse_policy`]) into a [`PolicyIR`] tagged with `version`.
/// Design §4's determinism guarantee: two calls with the same `src` and
/// `segments` produce byte-identical `to_canonical_json()` output,
/// regardless of `version`.
pub fn compile(
    src: &PolicySource,
    segments: &[SegmentDef],
    version: u64,
) -> Result<PolicyIR, Vec<CompileError>> {
    let _ = (src, segments, version);
    todo!("Task 2 Step 3: resolve segment names to sorted CIDRs, normalize rule src/dst/ports, assign rule_id, preserve source order")
}

/// Content-hash rule id (design D-C3-3): first 8 bytes of
/// `sha256("{from}|{to}|{action}|{proto}|src={src.join(\",\")}|dst={dst.join(\",\")}|ports={lo}-{hi},...")`,
/// hex-encoded (16 hex chars), computed over the rule's *normalized*
/// fields (post CIDR normalization, post single-port-to-range expansion).
/// Depends only on `from`/`to`/the rule's own fields — not on sibling
/// rules in the same block, and not on `version`.
pub fn rule_id(from: &str, to: &str, rule: &IrRule) -> String {
    let _ = (from, to, rule);
    todo!("Task 2 Step 3: sha256 over the exact preimage string above, first 8 bytes hex")
}
