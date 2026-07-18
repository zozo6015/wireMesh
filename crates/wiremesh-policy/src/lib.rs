//! `wiremesh-policy` — DSL parser and validator for the WireMesh policy
//! compiler (cycle 3; design doc §4/§5,
//! `docs/superpowers/specs/2026-07-17-policy-pipeline-design.md`).
//!
//! Pure leaf crate: consumes nothing else in the workspace. Produces the
//! [`SegmentDef`] / [`PolicySource`] / [`parse_policy`] / [`CompileError`]
//! surface that later cycle-3 tasks (IR codegen, controller integration —
//! design §7's `apply::compile_policy`) depend on by these exact names.
//!
//! Deviation from the Task 1 brief's literal `Interfaces` snippet, accepted
//! by the controller (see `.superpowers/sdd/task-1-tests-report.md` for the
//! full note): the brief shows `parse_policy(yaml: &str)` with no segment
//! table, but design §4's subset/unknown-segment checks and §7's "invoked
//! with the current segment table" both require one. `parse_policy` below
//! therefore takes `segments: &[SegmentDef]` as a second argument, and does
//! parsing (`dsl.rs`) and validation (`validate.rs`) in one pure call.

mod compile;
mod dsl;
mod ir;
mod validate;

pub use compile::{compile, rule_id};
pub use ir::{IrAction, IrBlock, IrProto, IrRule, PolicyIR};

use std::fmt;

/// A segment's name and its CIDR blocks, as known to the controller's
/// segment table. Segment names in the DSL's `from`/`to` fields resolve
/// against this list (design §4). v1 is IPv4-only, hence `Ipv4Net`.
#[derive(Debug, Clone)]
pub struct SegmentDef {
    pub name: String,
    pub cidrs: Vec<ipnet::Ipv4Net>,
}

/// An opaque, successfully parsed-and-validated policy document. A later
/// cycle-3 task turns this into the compiled IR (design §5); Task 1 only
/// proves the source parses and validates against a segment table.
pub struct PolicySource(#[allow(dead_code)] dsl::PolicyDoc);

/// Parses `yaml` as a WireMesh policy DSL document (design §4) and
/// validates it against `segments` — the controller's current segment
/// table. Enforces, as compile errors that name their location: unknown
/// segment names in `from`/`to`; more than one block per ordered
/// `(from, to)` pair; `src` not a subset of the `from`-segment's CIDRs (and
/// likewise `dst`/`to`); `ports` without an explicit `proto: tcp|udp`;
/// malformed CIDRs/ports/ranges (`lo > hi`, port 0, port > 65535); non-IPv4
/// CIDRs. All independent errors are collected and returned together —
/// never just the first one found.
pub fn parse_policy(
    yaml: &str,
    segments: &[SegmentDef],
) -> Result<PolicySource, Vec<CompileError>> {
    let doc: dsl::PolicyDoc = serde_yaml::from_str(yaml).map_err(|e| {
        vec![CompileError {
            block: None,
            rule: None,
            msg: format!("YAML parse error: {e}"),
        }]
    })?;

    let errors = validate::validate(&doc, segments);
    if errors.is_empty() {
        Ok(PolicySource(doc))
    } else {
        Err(errors)
    }
}

/// A single compile error, named by its location. `block` is the
/// source-order index into the top-level `policy:` block list; `rule` is
/// the index into that block's `rules:` list, or `None` for block-level
/// errors (an unknown segment name, a duplicate `(from, to)` pair) that
/// aren't about any one rule.
#[derive(Debug, Clone)]
pub struct CompileError {
    pub block: Option<usize>,
    pub rule: Option<usize>,
    pub msg: String,
}

impl fmt::Display for CompileError {
    /// Renders as `"block {n} rule {n}: {msg}"`, degrading gracefully when
    /// `block`/`rule` are `None` (a document-level error has neither; a
    /// block-level error has no `rule`). The brief's example format also
    /// shows a `({from}→{to})` segment-pair parenthetical, but this type
    /// intentionally carries only `block`/`rule`/`msg` (the exact fields
    /// later cycle-3 tasks depend on) — `validate.rs` bakes the `(from→to)`
    /// context directly into `msg` instead of adding fields here.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.block, self.rule) {
            (Some(b), Some(r)) => write!(f, "block {b} rule {r}: {}", self.msg),
            (Some(b), None) => write!(f, "block {b}: {}", self.msg),
            (None, _) => write!(f, "{}", self.msg),
        }
    }
}
