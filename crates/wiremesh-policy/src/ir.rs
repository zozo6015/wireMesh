//! Policy IR types, canonical JSON, and content-hash rule ids (design §5 /
//! D-C3-1, D-C3-3). Task 2 Step 1 (test author): types + signatures only —
//! bodies are `todo!()`, filled in by Task 2 Step 3 (implementer). The
//! struct/enum shapes and `#[serde(rename_all = "lowercase")]` tags below
//! are the wire contract itself (design §5.2's exact JSON), not
//! implementation, so they're real, not stubbed.

use serde::{Deserialize, Serialize};

/// The compiled policy: `schema` is a format tag (`from_json` rejects
/// anything but `1`); `version` mirrors `POLICY_VERSION.version` (design
/// §7); `blocks` are in source order (design §4's determinism guarantee).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct PolicyIR {
    pub schema: u32,
    pub version: u64,
    pub blocks: Vec<IrBlock>,
}

/// One `(from, to)` segment pair: its resolved segment CIDR lists and its
/// ordered rules (design §5.2). `src_cidrs`/`dst_cidrs` here are the
/// *segment's* CIDRs (sorted lexically by `(addr, prefix)`, design
/// §4/D-C3-1) — not to be confused with a rule's own `src`/`dst` below.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct IrBlock {
    pub from: String,
    pub to: String,
    pub src_cidrs: Vec<String>,
    pub dst_cidrs: Vec<String>,
    pub rules: Vec<IrRule>,
}

/// One resolved rule (first-match-wins order preserved from the DSL). `src`
/// and `dst` are the rule's *own* CIDRs — empty means "the whole segment"
/// — normalized via `Ipv4Net` display and kept in written order (design
/// §4/D-C3-1). `ports` is `[(lo, hi), ..]`; a bare DSL port `p` becomes
/// `(p, p)`. `rule_id` is the content hash from [`crate::rule_id`].
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct IrRule {
    pub rule_id: String,
    pub action: IrAction,
    pub proto: IrProto,
    pub src: Vec<String>,
    pub dst: Vec<String>,
    pub ports: Vec<(u16, u16)>,
}

/// Serializes as `"allow"` / `"deny"` (design §5.2).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum IrAction {
    Allow,
    Deny,
}

/// Serializes as `"tcp"` / `"udp"` / `"icmp"` / `"any"` (design §5.2). A
/// DSL rule with `proto` omitted compiles to `Any` (design §4).
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum IrProto {
    Tcp,
    Udp,
    Icmp,
    Any,
}

impl PolicyIR {
    /// The canonical wire form: plain `serde_json::to_string`. This is the
    /// canonical form *by construction*, not by extra sorting work — these
    /// types contain no maps and no floats, and serde's derived
    /// `Serialize` preserves each struct's declared field order. That
    /// invariant (no `serde_json::Value`, no `HashMap`, no post-hoc
    /// re-sorting) is what makes two compiles of the same source and
    /// segment table byte-identical (design §4). Do not turn this into a
    /// canonicalization pass — keep it exactly `serde_json::to_string`.
    pub fn to_canonical_json(&self) -> String {
        todo!("Task 2 Step 3: serde_json::to_string(self) — see doc comment invariant")
    }

    /// Parses `bytes` as a [`PolicyIR`], rejecting any `schema` other than
    /// the one this crate currently produces (`1`) with an error (not a
    /// panic).
    pub fn from_json(bytes: &[u8]) -> anyhow::Result<PolicyIR> {
        let _ = bytes;
        todo!("Task 2 Step 3: deserialize then check schema == 1")
    }

    /// sha256 hex of the `blocks`-only JSON — the version-independent
    /// equality key (design D-C3-8): two [`PolicyIR`]s with identical
    /// `blocks` but different `version` must produce the same fingerprint,
    /// and any rule/block change must change it.
    pub fn blocks_fingerprint(&self) -> String {
        todo!("Task 2 Step 3: sha256 hex over `self.blocks` only, excluding schema/version")
    }
}
