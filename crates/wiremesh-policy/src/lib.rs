//! `wiremesh-policy` — DSL parser and validator for the WireMesh policy
//! compiler (cycle 3; design doc §4/§5,
//! `docs/superpowers/specs/2026-07-17-policy-pipeline-design.md`).
//!
//! Pure leaf crate: consumes nothing else in the workspace. Produces the
//! [`SegmentDef`] / [`PolicySource`] / [`parse_policy`] / [`CompileError`]
//! surface that later cycle-3 tasks (IR codegen, controller integration —
//! design §7's `apply::compile_policy`) depend on by these exact names.
//!
//! Task 1 Step 1 (this commit): signatures only, `todo!()`/`unimplemented!()`
//! bodies — the RED half of the golden tests in `tests/golden.rs`. The real
//! DSL model (`dsl.rs`) and validation (`validate.rs`) land in Step 3.
//!
//! Deviation from the Task 1 brief's literal `Interfaces` snippet, resolved
//! here (see `.superpowers/sdd/task-1-tests-report.md` for the full note):
//! the brief shows `parse_policy(yaml: &str)` with no segment table, but
//! design §4's subset/unknown-segment checks and §7's "invoked with the
//! current segment table" both require one. `parse_policy` below therefore
//! takes `segments: &[SegmentDef]` as a second argument.

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
pub struct PolicySource(#[allow(dead_code)] ());

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
    let _ = (yaml, segments);
    todo!("Task 1 Step 3: DSL parse (dsl.rs) + validation (validate.rs)")
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
    /// Renders as `"block {n} ({from}→{to}) rule {n}: {msg}"`, degrading
    /// gracefully when `block`/`rule` are `None`. Task 1 Step 3 fills this
    /// in; block-level errors need the `from`/`to` segment names, which
    /// this type doesn't carry today, so the real implementation may need
    /// to thread that through some other way (see Step 3 implementer).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = f;
        todo!("Task 1 Step 3: \"block {{n}} ({{from}}\u{2192}{{to}}) rule {{n}}: {{msg}}\" rendering")
    }
}
