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
