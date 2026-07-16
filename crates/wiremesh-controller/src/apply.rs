//! Declarative `fabricctl apply -f fabric.yaml` (Task 14): the YAML shape
//! and the STUBBED policy compiler. The actual diff/mutation logic lives in
//! [`crate::db::Db::apply_fabric`] (it needs a single transaction against
//! live DB state, so it isn't a pure function of this module's parsed
//! types) — this module is just "parse the document" + "the compile seam".
//!
//! ```yaml
//! segments:
//!   - name: aws
//!     cidrs: ["10.0.0.0/16"]
//! relays:
//!   - name: r1
//!     endpoint: "1.2.3.4:4443"
//! policy:
//!   ... (opaque cycle-3 DSL; STUBBED here — see `compile_policy`)
//! ```

use serde::Deserialize;

/// One `segments:` entry.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SegmentSpec {
    pub name: String,
    #[serde(default)]
    pub cidrs: Vec<String>,
}

/// One `relays:` entry. Accepted/parsed for the seam the brief calls out,
/// but NOT yet diffed/applied by [`crate::db::Db::apply_fabric`] — see that
/// method's doc comment and the task report's "partial" note.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelaySpec {
    pub name: String,
    pub endpoint: String,
}

/// A parsed `fabric.yaml` document. `relays` defaults to empty and `policy`
/// defaults to absent so a fabric with only `segments:` (the shape
/// `tests/apply.rs` exercises) parses without any other stanza present.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FabricSpec {
    #[serde(default)]
    pub segments: Vec<SegmentSpec>,
    #[serde(default)]
    pub relays: Vec<RelaySpec>,
    /// Kept as an opaque `serde_yaml::Value` (rather than a typed policy
    /// DSL struct) because the DSL itself doesn't exist yet — cycle-3's
    /// scope. This task's contract is only: accept whatever is under
    /// `policy:`, round-trip it back to YAML text as `source_yaml`, and
    /// compile it via the [`compile_policy`] stub.
    #[serde(default)]
    pub policy: Option<serde_yaml::Value>,
}

/// Parses a `fabric.yaml` document's text into a [`FabricSpec`].
pub fn parse_fabric(yaml: &str) -> Result<FabricSpec, serde_yaml::Error> {
    serde_yaml::from_str(yaml)
}

/// Re-serializes a parsed `policy:` block back to YAML text, for storage as
/// `policy_version.source_yaml` — this is the byte-for-byte-ish source the
/// idempotence check (`Db::apply_fabric`) compares against the
/// previously-stored source to decide whether the policy actually changed.
pub fn policy_source_yaml(policy: &serde_yaml::Value) -> String {
    serde_yaml::to_string(policy).unwrap_or_default()
}

/// **STUB** DSL→IR compiler (real one is cycle-3's scope — see the
/// controller-core design spec and this task's brief). Always compiles any
/// policy source to an empty IR v0: `compiled_ir` is just `"[]"` (a JSON
/// array with no rules), regardless of `source_yaml`'s content. What DOES
/// matter for this task is the call-site discipline in
/// [`crate::db::Db::apply_fabric`]: the stored `policy_version.version` is
/// only bumped when `source_yaml` actually changed from what's already
/// stored, never on every apply — so a real (non-stub) compiler can drop in
/// later without changing that idempotence contract.
pub fn compile_policy(_source_yaml: &str) -> String {
    "[]".to_string()
}
