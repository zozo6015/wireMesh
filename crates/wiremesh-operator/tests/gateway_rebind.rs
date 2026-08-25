//! FAILING tests (test-author, operator hardening round, Backlog 4) — Fix 6b:
//! segment CIDR change → REBIND token + Secret refresh. **compile-RED** until
//! the pinned surfaces exist.
//!
//! # The gap
//!
//! Today only the not-enrolled path mints (gateway.rs:55-57 via
//! `should_mint_token`): once a gateway is enrolled and its identity persisted,
//! editing the WiremeshSegment's CIDRs changes what the fabric routes but the
//! gateway's enrollment (and any future re-enroll) stays bound to the OLD
//! CIDRs — the token Secret is never refreshed, and no rebind is ever issued.
//!
//! # Pinned implementer surfaces (all in `controllers::gateway`)
//!
//! ```ignore
//! /// The rebind decision: compare the CIDRs the CURRENT token Secret was
//! /// minted against with the segment's CURRENT CIDRs, as SETS.
//! ///   None       → no recorded binding (legacy Secret) → false (no churn;
//! ///                the not-enrolled mint path owns first-mint).
//! ///   Some(set-equal, any order) → false.
//! ///   Some(differs)              → true → mint a REBIND token + refresh Secret.
//! pub fn needs_rebind(bound_cidrs: Option<&[String]>, segment_cidrs: &[String]) -> bool
//!
//! /// The token Secret builder, extracted from the inline construction at
//! /// gateway.rs:329-342 and extended to RECORD the bound CIDRs so the next
//! /// reconcile can read them back (representation free — data key or
//! /// annotation — the `bound_cidrs_of` roundtrip below is the contract).
//! /// Namespace/ownerRefs stay stamped by the reconciler as today.
//! pub fn token_secret_body(gateway_name: &str, token: &str, bound_cidrs: &[String]) -> Secret
//!
//! /// Reader half of the roundtrip: None for a legacy Secret with no record.
//! pub fn bound_cidrs_of(secret: &Secret) -> Option<Vec<String>>
//! ```
//!
//! # Wiring (integration-level, documented — NOT unit-testable here)
//!
//! * The mint transport: `MintTokenRequest` ALREADY carries
//!   `rebind_segment_id` — the operator just hardcodes 0 everywhere
//!   (admin.rs:83, operator_admin.rs:84). The rebind mint must pass the real
//!   segment id through `AdminExec` (+ the `operator-admin mint-token` CLI,
//!   e.g. a `--rebind-segment-id` flag) on BOTH transports.
//! * On `needs_rebind` → mint rebind token → FORCE-apply the refreshed Secret
//!   via `token_secret_body` (SSA replaces the stale token; the existing apply
//!   already force-owns). The enroll init-container picks it up on the next
//!   pod recreation — triggering that recreation (or not) is an implementer/
//!   owner call, review-verified.
//! * The reconciler feeds `bound_cidrs_of(existing_secret)` and the freshly
//!   resolved segment CIDRs into `needs_rebind`; the steady-state no-mint
//!   behavior (`should_mint_token`) is unchanged when it returns false.

use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::ByteString;
use std::collections::BTreeMap;
use wiremesh_operator::controllers::gateway::{
    bound_cidrs_of, needs_rebind, token_secret_body, token_secret_name,
};

fn v(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}

#[test]
fn identical_cidrs_need_no_rebind() {
    let bound = v(&["10.0.125.0/24", "10.10.0.0/16"]);
    assert!(
        !needs_rebind(Some(&bound), &v(&["10.0.125.0/24", "10.10.0.0/16"])),
        "same CIDRs, same order → no rebind"
    );
}

#[test]
fn order_is_irrelevant_set_semantics() {
    // A reordered list is the SAME binding — rebinding on order churn would
    // re-mint (and eventually re-enroll) on every cosmetic CR edit.
    let bound = v(&["10.10.0.0/16", "10.0.125.0/24"]);
    assert!(
        !needs_rebind(Some(&bound), &v(&["10.0.125.0/24", "10.10.0.0/16"])),
        "same CIDR SET in a different order → no rebind (set comparison, not Vec ==)"
    );
}

#[test]
fn added_cidr_needs_rebind() {
    let bound = v(&["10.0.125.0/24"]);
    assert!(
        needs_rebind(Some(&bound), &v(&["10.0.125.0/24", "10.99.0.0/16"])),
        "a CIDR added to the segment → rebind"
    );
}

#[test]
fn removed_cidr_needs_rebind() {
    let bound = v(&["10.0.125.0/24", "10.99.0.0/16"]);
    assert!(
        needs_rebind(Some(&bound), &v(&["10.0.125.0/24"])),
        "a CIDR removed from the segment → rebind"
    );
}

#[test]
fn unknown_binding_never_rebinds() {
    // Legacy Secret (pre-fix, no recorded CIDRs) → we cannot know what the
    // token was bound to; churning a rebind on every reconcile would be worse
    // than waiting for the record to appear at the next legitimate mint.
    assert!(
        !needs_rebind(None, &v(&["10.0.125.0/24"])),
        "no recorded binding (legacy Secret) → no rebind"
    );
}

#[test]
fn empty_bound_set_differs_from_populated_segment() {
    // Some(&[]) is a RECORDED-empty binding (distinct from None/unknown) — a
    // populated segment then differs as a set → rebind.
    let empty: Vec<String> = vec![];
    assert!(needs_rebind(Some(&empty), &v(&["10.0.125.0/24"])));
    // ... and two empties are equal.
    assert!(!needs_rebind(Some(&empty), &[]));
}

#[test]
fn token_secret_body_records_token_and_bound_cidrs() {
    let cidrs = v(&["10.0.125.0/24", "10.10.0.0/16"]);
    let sec = token_secret_body("gw-home", "wiremesh://tok-abc", &cidrs);

    assert_eq!(
        sec.metadata.name.as_deref(),
        Some(token_secret_name("gw-home").as_str()),
        "builder must name the Secret via token_secret_name (wiremesh-gw-<name>-token)"
    );
    assert_eq!(sec.type_.as_deref(), Some("Opaque"));
    let data = sec.data.as_ref().expect("Secret data");
    assert_eq!(
        data.get("token"),
        Some(&ByteString(b"wiremesh://tok-abc".to_vec())),
        "the token key keeps its existing shape (the enroll init mounts it as-is)"
    );

    // The roundtrip contract: the reconciler can read back EXACTLY the CIDR set
    // this Secret's token was minted against. Representation (extra data key vs
    // annotation) is the implementer's choice — only the roundtrip is pinned.
    assert_eq!(
        bound_cidrs_of(&sec),
        Some(cidrs),
        "bound CIDRs recorded at mint time must be recoverable for the rebind decision"
    );
}

#[test]
fn legacy_secret_without_record_reads_as_unknown() {
    // A pre-fix Secret (only the token key) → None, which `needs_rebind` maps
    // to "no rebind" — legacy fabrics do not start churning after the upgrade.
    let mut data = BTreeMap::new();
    data.insert(
        "token".to_string(),
        ByteString(b"wiremesh://legacy".to_vec()),
    );
    let legacy = Secret {
        data: Some(data),
        ..Default::default()
    };
    assert_eq!(
        bound_cidrs_of(&legacy),
        None,
        "a Secret with no recorded CIDRs is an UNKNOWN binding, not an empty one"
    );
}
