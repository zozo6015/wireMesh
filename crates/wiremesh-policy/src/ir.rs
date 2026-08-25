//! Policy IR types, canonical JSON, and content-hash rule ids (design §5 /
//! D-C3-1, D-C3-3). The struct/enum shapes and `#[serde(rename_all =
//! "lowercase")]` tags below are the wire contract itself (design §5.2's
//! exact JSON) — the type of a field, once declared, must not be reordered
//! without also updating every golden fixture in `tests/fixtures/` (see
//! `to_canonical_json`'s invariant below).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
        serde_json::to_string(self)
            .expect("PolicyIR contains only strings/numbers/vecs — serialization is infallible")
    }

    /// Parses `bytes` as a [`PolicyIR`], rejecting any `schema` other than
    /// the one this crate currently produces (`1`) with an error (not a
    /// panic).
    pub fn from_json(bytes: &[u8]) -> anyhow::Result<PolicyIR> {
        let ir: PolicyIR = serde_json::from_slice(bytes)?;
        if ir.schema != 1 {
            anyhow::bail!(
                "unsupported policy IR schema {} (this build only produces/accepts schema 1)",
                ir.schema
            );
        }
        Ok(ir)
    }

    /// sha256 hex of the `blocks`-only JSON — the version-independent
    /// equality key (design D-C3-8): two [`PolicyIR`]s with identical
    /// `blocks` but different `version` must produce the same fingerprint,
    /// and any rule/block change must change it.
    ///
    /// Recipe (implementer's choice, per the brief — only relative
    /// equal/not-equal properties are contractual): sha256 hex of
    /// `serde_json::to_string(&self.blocks)` alone (never `schema`/
    /// `version`), using the same field-order-is-canonical invariant as
    /// [`Self::to_canonical_json`].
    pub fn blocks_fingerprint(&self) -> String {
        let blocks_json = serde_json::to_string(&self.blocks).expect(
            "Vec<IrBlock> contains only strings/numbers/vecs — serialization is infallible",
        );
        hex_encode(&Sha256::digest(blocks_json.as_bytes()))
    }
}

/// Lowercase-hex encoding, matching the convention already used elsewhere
/// in the workspace (e.g. `wiremesh-controller`'s `hex_encode` helpers).
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
