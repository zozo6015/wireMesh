//! Declarative `fabricctl apply -f fabric.yaml` (Task 14): the YAML shape.
//! The actual diff/mutation logic — including, since cycle-3 Task 4, real
//! DSL→IR compilation via `wiremesh_policy::{parse_policy, compile}` — lives
//! in [`crate::db::Db::apply_fabric`] (it needs a single transaction against
//! live DB state, so it isn't a pure function of this module's parsed
//! types, and the policy compiler needs the segment table as of THAT
//! transaction, not this module's parsed-but-not-yet-applied `segments:`
//! list) — this module is just "parse the document".
//!
//! ```yaml
//! segments:
//!   - name: aws
//!     cidrs: ["10.0.0.0/16"]
//! relays:
//!   - name: r1
//!     endpoint: "1.2.3.4:4443"
//! policy:
//!   - from: aws
//!     to: aws
//!     rules:
//!       - allow: { ports: [443], proto: tcp }
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
    /// Kept as an opaque `serde_yaml::Value` (rather than a typed policy DSL
    /// struct — that struct, `wiremesh_policy::dsl::PolicyDoc`, lives in the
    /// leaf `wiremesh-policy` crate, not here) because this module's only
    /// job is "parse the `fabric.yaml` envelope"; the real DSL grammar is
    /// `wiremesh_policy::parse_policy`'s concern, invoked by
    /// [`crate::db::Db::apply_fabric`] against the re-wrapped text
    /// [`policy_source_yaml`] below produces.
    #[serde(default)]
    pub policy: Option<serde_yaml::Value>,
}

/// Parses a `fabric.yaml` document's text into a [`FabricSpec`].
pub fn parse_fabric(yaml: &str) -> Result<FabricSpec, serde_yaml::Error> {
    serde_yaml::from_str(yaml)
}

/// Re-wraps a parsed `policy:` block's value back into a standalone
/// `policy: ...` YAML document — the exact shape
/// `wiremesh_policy::parse_policy` expects (its `PolicyDoc` deserializes a
/// top-level `{ policy: [...] }` mapping, not a bare sequence) — for storage
/// as `policy_version.source_yaml` and for feeding straight into
/// `wiremesh_policy::parse_policy` inside [`crate::db::Db::apply_fabric`]'s
/// transaction. `FabricSpec::policy` itself holds only the VALUE under the
/// `policy:` key (a `serde_yaml::Value` sequence), since `serde` already
/// stripped that key off during `parse_fabric` — this function puts it back.
pub fn policy_source_yaml(policy: &serde_yaml::Value) -> String {
    let mut doc = serde_yaml::Mapping::new();
    doc.insert(
        serde_yaml::Value::String("policy".to_string()),
        policy.clone(),
    );
    serde_yaml::to_string(&serde_yaml::Value::Mapping(doc)).unwrap_or_default()
}
