//! Serde model for the WireMesh policy DSL (design §4).
//!
//! Mirrors the on-disk YAML shape 1:1: `PolicyDoc` → `policy: [BlockSrc]`,
//! each block a `(from, to)` segment pair plus its ordered `rules:` list,
//! each rule exactly one of `allow`/`deny` (enforced in `validate.rs`, not
//! here, since serde has no clean "exactly one of these two optional keys"
//! primitive and the brief wants that reported as a located
//! [`crate::CompileError`], not a raw serde error).
//!
//! Deliberately permissive at the parse layer: anything that *can* be
//! deserialized (unknown segment names, out-of-range ports, non-IPv4
//! CIDRs, inverted ranges, `ports` without `proto`) is deserialized as-is
//! and left for `validate.rs` to reject with a located, readable error.
//! `deny_unknown_fields` is the one exception — a typo'd key name is a
//! structural mistake the DSL author needs to see immediately, not a
//! semantic question needing segment context.

use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::Deserialize;
use std::fmt;

/// Top-level document: `policy: [BlockSrc, ...]`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDoc {
    pub policy: Vec<BlockSrc>,
}

/// One `(from, to)` block: a segment pair and its ordered rule list.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockSrc {
    pub from: String,
    pub to: String,
    pub rules: Vec<RuleSrc>,
}

/// One rule. Exactly one of `allow`/`deny` should be present — `validate.rs`
/// enforces that as a located `CompileError`; both fields are `Option` here
/// so `{}` (neither) and both-present both deserialize successfully and
/// reach validation.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSrc {
    #[serde(default)]
    pub allow: Option<RuleBody>,
    #[serde(default)]
    pub deny: Option<RuleBody>,
}

/// The body of an `allow:`/`deny:` action. `src`/`dst` accept either a
/// single string or a list of strings on the wire (`string_or_seq`); both
/// default to empty (design §4: omitted `src`/`dst` = the whole segment).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleBody {
    #[serde(default, deserialize_with = "string_or_seq")]
    pub src: Vec<String>,
    #[serde(default, deserialize_with = "string_or_seq")]
    pub dst: Vec<String>,
    #[serde(default)]
    pub ports: Vec<PortSpec>,
    #[serde(default)]
    pub proto: Option<String>,
}

/// A single port (`443`) or an inclusive `"lo-hi"` range (`"8000-8080"`).
/// Kept as raw numbers/strings here (not `u16`/parsed range) so
/// out-of-range values (`0`, `70000`, inverted `lo > hi`) deserialize
/// successfully and `validate.rs` can report them as located compile
/// errors instead of opaque serde errors.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum PortSpec {
    Single(i64),
    Range(String),
}

/// Accepts either a single YAML string or a sequence of strings, always
/// producing a `Vec<String>`.
fn string_or_seq<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringOrSeq;

    impl<'de> Visitor<'de> for StringOrSeq {
        type Value = Vec<String>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a string or a list of strings")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(vec![v.to_string()])
        }

        fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(vec![v])
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut out = Vec::new();
            while let Some(v) = seq.next_element::<String>()? {
                out.push(v);
            }
            Ok(out)
        }
    }

    deserializer.deserialize_any(StringOrSeq)
}
