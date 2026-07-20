//! Declarative `apply -f` (Task 14): a `fabric.yaml` describing segments is
//! diffed against current controller state and applied in one transaction.
//! Idempotence is the core contract: re-applying the *same* fabric a second
//! time must be a true no-op — an empty diff, zero mutations, and therefore
//! zero new audit rows (audit rows track mutations, so "no mutation" must
//! mean "no audit").
const FABRIC: &str = r#"
segments:
  - name: aws
    cidrs: ["10.0.0.0/16"]
  - name: gcp
    cidrs: ["10.1.0.0/16"]
"#;

/// (Issue #9) Same 2 segments as [`FABRIC`], but `aws`'s declared CIDR set
/// has genuinely CHANGED (grown to add a second range).
const FABRIC_AWS_CIDR_CHANGED: &str = r#"
segments:
  - name: aws
    cidrs: ["10.0.0.0/16", "10.2.0.0/16"]
  - name: gcp
    cidrs: ["10.1.0.0/16"]
"#;

#[tokio::test]
async fn apply_is_idempotent() {
    let h = wiremesh_testkit::TestController::start().await;

    // First apply against empty state creates both declared segments.
    let d1 = h.apply(FABRIC).await;
    assert_eq!(
        d1.created_segments, 2,
        "first apply of a 2-segment fabric must create exactly 2 segments, got diff: {:?}",
        d1
    );

    let audits_after_first = h.count_audit().await;

    // Re-applying the identical fabric must be a pure no-op: nothing left
    // to create, update, or delete.
    let d2 = h.apply(FABRIC).await;
    assert_eq!(
        d2.created_segments, 0,
        "second identical apply must create 0 segments, got diff: {:?}",
        d2
    );
    assert!(
        d2.is_empty(),
        "second identical apply must yield an empty diff, got: {:?}",
        d2
    );

    // Idempotence means zero mutations occurred, so the audit log must be
    // untouched by the no-op apply.
    assert_eq!(
        h.count_audit().await,
        audits_after_first,
        "an empty (no-op) apply must not add any audit rows"
    );
}

/// (Issue #9) `Db::apply_fabric` used to silently `continue` past any
/// declared segment whose name already existed — dropping a genuine CIDR
/// change on the floor with no error, no audit row, and `updated_segments`
/// staying 0, indistinguishable from a true no-op re-apply. That was fixed
/// (cycle-3 Task 5, commit b6d7ef9) by replacing the silent skip with a
/// real diff: an existing segment's declared CIDR set is compared against
/// what's stored, and a genuine difference REPLACES the stored CIDRs,
/// counts into `updated_segments`, and writes an audit row — loudly, not
/// silently. This test is a regression guard for that fix, exercised
/// through `apply.rs`'s own plain (no-policy) fixtures rather than
/// `policy_pipeline.rs`'s policy-recompile-focused coverage of the same
/// mechanism.
///
/// Proves the change actually lands (not just that `updated_segments`
/// claims it did) by re-applying the CHANGED fabric a second time: that
/// third apply can only be a true no-op if the second apply's CIDR change
/// was genuinely persisted to the `cidr` table.
#[tokio::test]
async fn apply_applies_not_silently_drops_an_existing_segments_cidr_change() {
    let h = wiremesh_testkit::TestController::start().await;

    let d1 = h.apply(FABRIC).await;
    assert_eq!(
        d1.created_segments, 2,
        "first apply of a 2-segment fabric must create exactly 2 segments, got diff: {:?}",
        d1
    );
    let audits_after_first = h.count_audit().await;

    // Second apply changes `aws`'s declared CIDR set. This must be a real,
    // loud update — NOT a silent no-op.
    let d2 = h.apply(FABRIC_AWS_CIDR_CHANGED).await;
    assert_eq!(
        d2.created_segments, 0,
        "no NEW segment is declared here, got diff: {:?}",
        d2
    );
    assert_eq!(
        d2.updated_segments, 1,
        "changing an existing segment's declared CIDR set must be counted as an update, \
         not silently dropped (issue #9), got diff: {:?}",
        d2
    );
    assert!(
        !d2.is_empty(),
        "a genuine CIDR change must not report an empty diff, got: {:?}",
        d2
    );
    assert!(
        h.count_audit().await > audits_after_first,
        "a genuine CIDR change must append at least one audit row, not silently skip \
         auditing"
    );

    // Third apply re-declares the SAME (already-changed) fabric. This can
    // only be a true no-op if the second apply's CIDR change was actually
    // persisted — if it had been silently dropped, `aws` would still be
    // seen as needing this same "change" and `updated_segments` would be 1
    // again here instead of 0.
    let d3 = h.apply(FABRIC_AWS_CIDR_CHANGED).await;
    assert_eq!(
        d3.updated_segments, 0,
        "re-applying the already-changed fabric must be a true no-op, proving the previous \
         apply's CIDR change was actually persisted (not silently dropped), got diff: {:?}",
        d3
    );
    assert!(
        d3.is_empty(),
        "re-applying the already-changed fabric must yield an empty diff, got: {:?}",
        d3
    );
}

/// A typo'd key (`cidr:` instead of `cidrs:`) must be rejected at parse time
/// rather than silently accepted as an empty `cidrs: []`, which would apply a
/// segment with no CIDRs and mask the typo.
#[test]
fn misspelled_segment_key_is_rejected() {
    const TYPO_FABRIC: &str = r#"
segments:
  - name: aws
    cidr: ["10.0.0.0/16"]
"#;
    let err = wiremesh_controller::apply::parse_fabric(TYPO_FABRIC)
        .expect_err("a misspelled `cidr:` key must fail to parse, not silently be dropped");
    assert!(
        err.to_string().contains("cidr"),
        "parse error should mention the unknown field, got: {err}"
    );
}

/// Same contract for `relays:` and the top-level document: unknown keys must
/// be rejected rather than ignored.
#[test]
fn misspelled_relay_and_top_level_keys_are_rejected() {
    const TYPO_RELAY: &str = r#"
relays:
  - name: r1
    endpont: "1.2.3.4:4443"
"#;
    assert!(
        wiremesh_controller::apply::parse_fabric(TYPO_RELAY).is_err(),
        "a misspelled `endpont:` key on a relay must fail to parse"
    );

    const TYPO_TOP_LEVEL: &str = r#"
segmentz:
  - name: aws
    cidrs: ["10.0.0.0/16"]
"#;
    assert!(
        wiremesh_controller::apply::parse_fabric(TYPO_TOP_LEVEL).is_err(),
        "a misspelled top-level `segmentz:` key must fail to parse"
    );
}
