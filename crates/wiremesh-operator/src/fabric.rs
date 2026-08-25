//! Pure aggregation of `WiremeshSegment` + `WiremeshPolicy` CRDs into the
//! `fabric.yaml` envelope the controller's `Apply` RPC consumes.
//!
//! The envelope shape and the policy DSL grammar are fixed by the controller:
//! `crates/wiremesh-controller/src/apply.rs` (`FabricSpec`: `segments:` +
//! optional `policy:`, both `deny_unknown_fields`) and
//! `crates/wiremesh-policy/src/dsl.rs` (`policy:` is a sequence of
//! `{from, to, rules: [{allow|deny: {proto, ports, src, dst}}]}` blocks). We
//! emit only `allow` rules over whole segments (no `src`/`dst`), which is the
//! surface the `WiremeshPolicy` CRD exposes. Keys are plain snake_case here
//! (NOT the CRDs' camelCase) — so these are dedicated serialize structs, not
//! the CRD spec types.

use crate::crd::{WiremeshPolicySpec, WiremeshSegmentSpec};
use serde::Serialize;

#[derive(Serialize)]
struct FabricDoc {
    segments: Vec<SegmentOut>,
    /// Omitted entirely when there are no policies, matching `apply.rs`'s
    /// `policy: Option<...>` (a fabric with only `segments:` is valid).
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<Vec<BlockOut>>,
}

#[derive(Serialize)]
struct SegmentOut {
    name: String,
    cidrs: Vec<String>,
}

#[derive(Serialize)]
struct BlockOut {
    from: String,
    to: String,
    rules: Vec<RuleOut>,
}

#[derive(Serialize)]
struct RuleOut {
    allow: AllowOut,
}

#[derive(Serialize)]
struct AllowOut {
    proto: String,
    /// Omitted when empty so a proto-only rule (e.g. `proto: icmp`) doesn't
    /// emit an empty `ports: []` (the DSL treats absent ports as "all ports").
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ports: Vec<u16>,
}

/// Render the fabric envelope. `segments` become `segments:` entries;
/// `policies` become `policy:` blocks. When `policies` is empty the `policy:`
/// key is omitted entirely.
pub fn render_fabric_yaml(
    segments: &[WiremeshSegmentSpec],
    policies: &[WiremeshPolicySpec],
) -> String {
    let segments_out = segments
        .iter()
        .map(|s| SegmentOut {
            name: s.segment_name.clone(),
            cidrs: s.cidrs.clone(),
        })
        .collect();

    let policy = if policies.is_empty() {
        None
    } else {
        Some(
            policies
                .iter()
                .map(|p| BlockOut {
                    from: p.from.clone(),
                    to: p.to.clone(),
                    rules: p
                        .rules
                        .iter()
                        .map(|r| RuleOut {
                            allow: AllowOut {
                                proto: r.allow.proto.clone(),
                                ports: r.allow.ports.clone(),
                            },
                        })
                        .collect(),
                })
                .collect(),
        )
    };

    serde_yaml::to_string(&FabricDoc {
        segments: segments_out,
        policy,
    })
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{AllowRule, PolicyRule};

    fn seg(name: &str, cidrs: &[&str]) -> WiremeshSegmentSpec {
        WiremeshSegmentSpec {
            segment_name: name.to_string(),
            cidrs: cidrs.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn renders_segments_and_policy() {
        let segments = vec![
            seg("aws", &["10.10.1.0/24"]),
            seg("proxmox", &["10.20.0.0/16"]),
        ];
        let policies = vec![WiremeshPolicySpec {
            from: "proxmox".to_string(),
            to: "aws".to_string(),
            rules: vec![PolicyRule {
                allow: AllowRule {
                    proto: "tcp".to_string(),
                    ports: vec![443],
                },
            }],
        }];
        let yaml = render_fabric_yaml(&segments, &policies);

        // Parses as YAML.
        let v: serde_yaml::Value = serde_yaml::from_str(&yaml).expect("valid yaml");
        // Both segment names present.
        assert!(yaml.contains("aws"), "segment aws:\n{yaml}");
        assert!(yaml.contains("proxmox"), "segment proxmox:\n{yaml}");
        // Policy block with the allow rule present.
        let policy = v.get("policy").expect("policy key present");
        let block = &policy.as_sequence().expect("policy is a seq")[0];
        assert_eq!(block.get("from").unwrap().as_str(), Some("proxmox"));
        assert_eq!(block.get("to").unwrap().as_str(), Some("aws"));
        let allow = block.get("rules").unwrap().as_sequence().unwrap()[0]
            .get("allow")
            .expect("allow rule");
        assert_eq!(allow.get("proto").unwrap().as_str(), Some("tcp"));
        assert_eq!(
            allow.get("ports").unwrap().as_sequence().unwrap()[0].as_u64(),
            Some(443)
        );
    }

    #[test]
    fn renders_segments_only_when_no_policy() {
        let segments = vec![seg("aws", &["10.10.1.0/24"])];
        let yaml = render_fabric_yaml(&segments, &[]);
        let v: serde_yaml::Value = serde_yaml::from_str(&yaml).expect("valid yaml");
        assert!(v.get("segments").is_some(), "segments present:\n{yaml}");
        assert!(
            v.get("policy").is_none(),
            "policy key omitted when empty:\n{yaml}"
        );
    }
}
