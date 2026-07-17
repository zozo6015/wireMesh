//! Task 4 (cycle 3): failing integration tests proving the REAL policy
//! compiler is wired end-to-end behind `Db::apply_fabric`'s D-C2-5 seam — the
//! master-spec §5.1 / policy-pipeline-design §5.1 worked example
//! (`proxmox-lab` -> `aws-prod`, a deny carve-out ahead of two allow rules,
//! first-match-wins) must actually get validated, compiled, versioned, and
//! broadcast over Sync — replacing cycle-2's `compile_policy` stub (always
//! `"[]"`, no `policy_rule` rows). See `.superpowers/sdd/task-4-brief.md` for
//! the full contract. The fixture text below is the exact same worked
//! example already golden-tested in
//! `crates/wiremesh-policy/tests/fixtures/design_s5_example.yaml`, just
//! embedded under a `fabric.yaml`'s top-level `policy:` stanza alongside a
//! `segments:` list (see `crates/wiremesh-controller/src/apply.rs`'s
//! `FabricSpec`).
//!
//! Harness: `wiremesh_testkit::TestController` + `StubGateway`, the same
//! pieces `tests/apply.rs` (Admin.Apply idempotence) and
//! `tests/sync_snapshot.rs` / `tests/sync_delta.rs` (stub-gateway Sync.Watch
//! fan-out) already use — this file is the first to combine both in one
//! test: it drives `Admin.Apply` AND a live `Sync.Watch` stream together.
//! `policy_version`/`policy_rule` row assertions go straight at the
//! controller's on-disk SQLite file via a raw second `rusqlite::Connection`
//! (the exact "open a second connection to the same file" pattern
//! `wiremesh_testkit::TestController::count_audit`/`gateway_exists` already
//! use internally, just inlined here instead of adding new `Db`
//! introspection methods) — this task's Step 1 is tests-only, no `src/`
//! changes.
//!
//! RED (current cycle-2 stub) evidence, one line per test:
//!  (a) `PolicyIR::from_json` fails to parse the always-empty stub IR bytes.
//!  (b) same: the delta's `policy_ir` never parses/il never carries a real
//!      compiled version (stub never populates `policy_rule`, and the
//!      stub's `policy_version` is compared by RAW SOURCE TEXT, not
//!      structural equality, but the delta path itself doesn't yet exist
//!      wired to `PolicyUpdated` broadcasting in cycle 2 — the assertion on
//!      `delta.policy_version == 1` fails since no such event exists yet).
//!  (c) the `policy_rule` row-count assertion fails: the stub never inserts
//!      any `policy_rule` rows at all (always 0, never 3).
//!  (d) the stub compares raw `source_yaml` TEXT, not a structural
//!      fingerprint, so reordering keys (a different string) makes the stub
//!      treat it as a real change: `policy_updated` comes back `true`
//!      instead of the expected `false`.
//!  (e) the stub compiler never validates segment names at all, so an
//!      apply referencing an undeclared segment currently SUCCEEDS instead
//!      of returning an error.
//!  (f) same as (c): the stub never populates `policy_rule` at all.

use std::path::PathBuf;
use std::time::Duration;

use tokio_stream::StreamExt;
use wiremesh_policy::PolicyIR;
use wiremesh_proto::v1::{sync_message, ApplyRequest, MintTokenRequest};
use wiremesh_testkit::{StubGateway, TestController};

/// Bounds every wait on a `Sync.Watch` message so a regression (no
/// snapshot/delta ever pushed) fails the test fast instead of hanging the
/// whole suite — same constant/rationale as `tests/sync_snapshot.rs` /
/// `tests/sync_delta.rs`.
const WATCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Two segments, no `policy:` stanza — the "before" half of tests that add
/// a policy on a SECOND apply (so a gateway can be enrolled and its
/// `Sync.Watch` stream already open before the policy-adding mutation
/// happens).
const FABRIC_SEGMENTS_ONLY: &str = r#"
segments:
  - name: proxmox-lab
    cidrs: ["10.10.0.0/16"]
  - name: aws-prod
    cidrs: ["172.16.0.0/12"]
"#;

/// The master-spec §5.1 / policy-pipeline-design §5.1 worked example,
/// verbatim from `crates/wiremesh-policy/tests/fixtures/design_s5_example.yaml`,
/// embedded under a `fabric.yaml` declaring both segments the DSL's
/// `from`/`to` names resolve against. One block, 3 first-match-wins rules
/// (deny carve-out on ssh, then two allows).
const FABRIC_WITH_POLICY: &str = r#"
segments:
  - name: proxmox-lab
    cidrs: ["10.10.0.0/16"]
  - name: aws-prod
    cidrs: ["172.16.0.0/12"]
policy:
  - from: proxmox-lab
    to: aws-prod
    rules:
      - deny:  { ports: [22], proto: tcp }
      - allow: { dst: 172.16.1.50/32, ports: [5432], proto: tcp }
      - allow: { dst: 172.16.2.0/24, ports: [443, "8000-8080"], proto: tcp }
"#;

/// Semantically IDENTICAL to [`FABRIC_WITH_POLICY`] — every block/rule stays
/// in the same SEQUENCE position (reordering those would be a real semantic
/// change), only the KEYS within each rule's mapping are reordered
/// (`proto`/`ports`/`dst` swapped around). A byte-for-byte source-text
/// comparison sees a different string; a `blocks_fingerprint()`-based
/// comparison must not (design D-C3-8).
const FABRIC_WITH_POLICY_REORDERED_KEYS: &str = r#"
segments:
  - name: proxmox-lab
    cidrs: ["10.10.0.0/16"]
  - name: aws-prod
    cidrs: ["172.16.0.0/12"]
policy:
  - from: proxmox-lab
    to: aws-prod
    rules:
      - deny:  { proto: tcp, ports: [22] }
      - allow: { proto: tcp, ports: [5432], dst: 172.16.1.50/32 }
      - allow: { ports: [443, "8000-8080"], proto: tcp, dst: 172.16.2.0/24 }
"#;

/// Declares both real segments but points the policy block's `to` at a
/// THIRD, never-declared segment name (`prod-db`) — must be rejected as a
/// compile error naming that segment, not silently accepted.
const FABRIC_UNKNOWN_SEGMENT: &str = r#"
segments:
  - name: proxmox-lab
    cidrs: ["10.10.0.0/16"]
  - name: aws-prod
    cidrs: ["172.16.0.0/12"]
policy:
  - from: proxmox-lab
    to: prod-db
    rules:
      - allow: { ports: [443], proto: tcp }
"#;

/// The controller's on-disk SQLite file path — same file
/// `wiremesh_testkit::TestController::count_audit`/`gateway_exists` open a
/// second connection to.
fn db_path(h: &TestController) -> PathBuf {
    h.data_dir().join("controller.db")
}

/// Total number of `policy_version` rows, read via a fresh `rusqlite`
/// connection to the controller's on-disk DB (same pattern as
/// `TestController::count_audit`, inlined here rather than adding a new
/// `Db` introspection method — this task's Step 1 is tests-only).
async fn count_policy_versions(h: &TestController) -> i64 {
    let path = db_path(h);
    tokio::task::spawn_blocking(move || {
        let conn = rusqlite::Connection::open(&path)
            .expect("opening controller DB for count_policy_versions");
        conn.busy_timeout(Duration::from_secs(5))
            .expect("setting busy_timeout on count_policy_versions connection");
        conn.query_row("SELECT COUNT(*) FROM policy_version", [], |row| row.get(0))
            .expect("counting policy_version rows")
    })
    .await
    .expect("count_policy_versions blocking task panicked")
}

/// Every `policy_rule` row for `version`, as
/// `(block_ord, rule_ord, action, src, dst, proto, ports)`, ordered by
/// `(block_ord, rule_ord)` — the exact column set the brief calls out.
#[allow(clippy::type_complexity)]
async fn policy_rule_rows(
    h: &TestController,
    version: i64,
) -> Vec<(i64, i64, String, String, String, String, Option<String>)> {
    let path = db_path(h);
    tokio::task::spawn_blocking(move || {
        let conn = rusqlite::Connection::open(&path)
            .expect("opening controller DB for policy_rule_rows");
        conn.busy_timeout(Duration::from_secs(5))
            .expect("setting busy_timeout on policy_rule_rows connection");
        let mut stmt = conn
            .prepare(
                "SELECT block_ord, rule_ord, action, src, dst, proto, ports \
                 FROM policy_rule WHERE version = ?1 ORDER BY block_ord, rule_ord",
            )
            .expect("preparing policy_rule query");
        let rows = stmt
            .query_map([version], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            })
            .expect("querying policy_rule rows");
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .expect("collecting policy_rule rows")
    })
    .await
    .expect("policy_rule_rows blocking task panicked")
}

/// Mints a `gateway` token bound to `cidr` and redeems it, WITHOUT calling
/// `CreateSegment` first — unlike `wiremesh_testkit::enroll_one` (which
/// always creates a brand-new segment), this is for enrolling into a
/// segment a prior `Admin.Apply` already created, matching enrollment's
/// requirement that the declared `cidrs` exactly match an already-registered
/// `cidr` row.
async fn enroll_on_existing_segment(h: &TestController, cidr: &str) -> StubGateway {
    let token = h
        .admin_client()
        .await
        .mint_token(MintTokenRequest {
            kind: "gateway".to_string(),
            bound_cidrs: vec![cidr.to_string()],
            rebind_segment_id: 0,
        })
        .await
        .expect("minting gateway token for enroll_on_existing_segment")
        .into_inner()
        .token;

    StubGateway::enroll(h, &token, &[cidr])
        .await
        .expect("enrolling stub gateway onto an already-applied segment")
}

/// Calls `Admin.Apply` over the raw `AdminClient` (unlike
/// `TestController::apply`, which `.expect()`s success) so a compile-error
/// apply's `Err` surfaces as a clean assertion failure rather than a panic
/// buried inside unrelated harness code.
async fn try_apply(
    h: &TestController,
    fabric_yaml: &str,
) -> Result<wiremesh_proto::v1::ApplyDiff, tonic::Status> {
    h.admin_client()
        .await
        .apply(ApplyRequest {
            fabric_yaml: fabric_yaml.to_string(),
        })
        .await
        .map(|r| r.into_inner())
}

/// (a) `apply -f` of a fabric declaring 2 segments AND a policy in one call
/// must compile the real DSL (not the stub) — `ApplyDiff.policy_updated`
/// comes back `true`, and a gateway enrolled and connected AFTER the apply
/// must receive that real compiled IR as part of its very first
/// `Sync.Watch` snapshot: non-empty `policy_ir` bytes that
/// `PolicyIR::from_json` actually parses, `version == 1`, and exactly the
/// design-§5 example's 3 rules (all in the one `proxmox-lab -> aws-prod`
/// block).
#[tokio::test]
async fn apply_compiles_real_policy_and_snapshot_carries_it() {
    let h = TestController::start().await;

    let diff = h.apply(FABRIC_WITH_POLICY).await;
    assert!(
        diff.policy_updated,
        "first apply of a fabric with a `policy:` stanza must set policy_updated, got diff: {:?}",
        diff
    );

    let gw = enroll_on_existing_segment(&h, "10.10.0.0/16").await;
    let mut stream = gw.open_sync().await;
    let msg = tokio::time::timeout(WATCH_TIMEOUT, stream.next())
        .await
        .expect("timed out waiting for the initial Sync.Watch snapshot")
        .expect("Sync.Watch stream ended before delivering a message")
        .expect("Sync.Watch stream yielded an error instead of a message");

    let snap = match msg.body {
        Some(sync_message::Body::Snapshot(s)) => s,
        other => panic!("expected the first Sync.Watch message to be a StateSnapshot, got: {other:?}"),
    };

    assert_eq!(
        snap.policy_version, 1,
        "the first-ever compiled policy must be version 1, got {}",
        snap.policy_version
    );
    assert!(
        !snap.policy_ir.is_empty(),
        "snapshot policy_ir must be non-empty once a real policy has been applied \
         (cycle-2's stub always leaves it empty)"
    );

    let ir = PolicyIR::from_json(&snap.policy_ir).expect(
        "snapshot policy_ir must parse as a real PolicyIR — the cycle-2 stub's \"[]\" bytes \
         fail to parse here, which is the RED signal for this test",
    );
    assert_eq!(
        ir.version, 1,
        "parsed IR version must match the snapshot's policy_version"
    );
    let total_rules: usize = ir.blocks.iter().map(|b| b.rules.len()).sum();
    assert_eq!(
        total_rules, 3,
        "the design-§5 example compiles to exactly 3 rules in a single block, got blocks: {:?}",
        ir.blocks
    );
}

/// (b) A gateway that is ALREADY connected (its `Sync.Watch` stream already
/// open, having already consumed its initial snapshot) must receive a live
/// `Delta` carrying `policy_version == 1` when a SUBSEQUENT apply adds the
/// policy for the first time — the same live fan-out contract
/// `tests/sync_delta.rs` proves for peer enrollment, now for policy
/// (`ChangeEvent::PolicyUpdated`, `subject_gateway_id() == 0`: every
/// connected gateway gets it).
#[tokio::test]
async fn already_connected_gateway_receives_policy_delta_on_live_apply() {
    let h = TestController::start().await;

    // Segments only — no policy yet — so a gateway can be enrolled and
    // connected before the policy-adding mutation happens.
    let d0 = h.apply(FABRIC_SEGMENTS_ONLY).await;
    assert_eq!(
        d0.created_segments, 2,
        "expected both segments created by the segments-only apply, got diff: {:?}",
        d0
    );

    let gw = enroll_on_existing_segment(&h, "10.10.0.0/16").await;
    let mut stream = gw.open_sync().await;

    // Consume the initial snapshot (no policy applied yet at this point).
    let snap_msg = tokio::time::timeout(WATCH_TIMEOUT, stream.next())
        .await
        .expect("timed out waiting for the initial Sync.Watch snapshot")
        .expect("Sync.Watch stream ended before delivering the initial snapshot")
        .expect("Sync.Watch stream yielded an error instead of the initial snapshot");
    match snap_msg.body {
        Some(sync_message::Body::Snapshot(_)) => {}
        other => panic!("expected the first Sync.Watch message to be a StateSnapshot, got: {other:?}"),
    }

    // Same 2 segments (a no-op) PLUS the policy stanza, for the first time —
    // a live, projection-affecting mutation that must fan out to the
    // already-open stream above.
    let d1 = h.apply(FABRIC_WITH_POLICY).await;
    assert!(
        d1.policy_updated,
        "adding a `policy:` stanza on a live apply must set policy_updated, got: {:?}",
        d1
    );

    let msg = tokio::time::timeout(WATCH_TIMEOUT, stream.next())
        .await
        .expect("timed out waiting for the live policy delta")
        .expect("Sync.Watch stream ended before delivering the policy delta")
        .expect("Sync.Watch stream yielded an error instead of the policy delta");

    let delta = match msg.body {
        Some(sync_message::Body::Delta(d)) => d,
        other => panic!("expected a Delta after a live policy apply, got: {other:?}"),
    };
    assert_eq!(
        delta.policy_version, 1,
        "the live delta must carry the freshly compiled policy_version, got {}",
        delta.policy_version
    );
    assert!(
        !delta.policy_ir.is_empty(),
        "the live delta's policy_ir must be non-empty"
    );
}

/// (c) Re-applying the byte-for-byte identical fabric a second time must be
/// a true no-op for the policy pipeline: `policy_updated == false`, zero
/// new audit rows (mirrors `tests/apply.rs`'s segments-only idempotence
/// contract) — AND, since this task actually populates `policy_rule` rows,
/// the redundant re-apply must not have duplicated them: still exactly the
/// 3 rows version 1 compiled to, still exactly 1 `policy_version` row.
#[tokio::test]
async fn reapplying_identical_policy_is_a_true_no_op() {
    let h = TestController::start().await;

    let d1 = h.apply(FABRIC_WITH_POLICY).await;
    assert!(
        d1.policy_updated,
        "first apply must compile and store the policy, got: {:?}",
        d1
    );

    let audits_after_first = h.count_audit().await;

    let d2 = h.apply(FABRIC_WITH_POLICY).await;
    assert!(
        !d2.policy_updated,
        "re-applying the byte-identical fabric must not create a new policy version, got: {:?}",
        d2
    );
    assert_eq!(
        h.count_audit().await,
        audits_after_first,
        "an idempotent re-apply must not add any audit rows"
    );

    let rows = policy_rule_rows(&h, 1).await;
    assert_eq!(
        rows.len(),
        3,
        "expected exactly 3 policy_rule rows for version 1 with no duplication from the \
         no-op re-apply, got: {:?}",
        rows
    );
    assert_eq!(
        count_policy_versions(&h).await,
        1,
        "a no-op re-apply must not create a second policy_version row"
    );
}

/// (d) A semantically identical policy whose YAML differs only in the
/// ORDER of keys within a rule's mapping (never in block/rule SEQUENCE
/// order, which would be a real semantic change) must still be treated as
/// unchanged: fingerprint-based equality (design D-C3-8), not raw source
/// text comparison.
#[tokio::test]
async fn reordering_rule_keys_does_not_create_a_new_version() {
    let h = TestController::start().await;

    let d1 = h.apply(FABRIC_WITH_POLICY).await;
    assert!(
        d1.policy_updated,
        "first apply must compile the policy, got: {:?}",
        d1
    );

    let d2 = h.apply(FABRIC_WITH_POLICY_REORDERED_KEYS).await;
    assert!(
        !d2.policy_updated,
        "reordering keys WITHIN a rule mapping is not a semantic change — fingerprint-based \
         idempotence must treat it as identical to the previous version, got: {:?}",
        d2
    );
    assert_eq!(
        count_policy_versions(&h).await,
        1,
        "a reordered-but-equivalent policy source must not create a second policy_version row"
    );
}

/// (e) A policy block referencing an undeclared segment must be rejected:
/// the whole `Admin.Apply` call fails with an error status naming the
/// unknown segment, and the `policy_version` table is left completely
/// untouched (nothing stored on a compile error).
#[tokio::test]
async fn policy_referencing_unknown_segment_is_rejected_and_stores_nothing() {
    let h = TestController::start().await;

    let err = try_apply(&h, FABRIC_UNKNOWN_SEGMENT)
        .await
        .expect_err(
            "applying a policy block that references an undeclared segment ('prod-db') must fail",
        );
    assert!(
        err.message().contains("prod-db"),
        "the compile-error status must name the unknown segment 'prod-db', got: {}",
        err.message()
    );
    assert_eq!(
        count_policy_versions(&h).await,
        0,
        "a failed compile must leave the policy_version table untouched"
    );
}

/// (f) `policy_rule` rows are populated with the correct
/// `(block_ord, rule_ord)` ordinals and per-rule fields for the design-§5
/// example's single block / 3 rules: a deny carve-out on port 22 ahead of
/// two allows (Postgres to a single host, then HTTP(S)-ish ports to a
/// /24), all `proto: tcp`, first-match-wins written order preserved.
#[tokio::test]
async fn policy_rule_rows_are_populated_with_correct_ordinals() {
    let h = TestController::start().await;

    let d1 = h.apply(FABRIC_WITH_POLICY).await;
    assert!(
        d1.policy_updated,
        "apply must compile the policy, got: {:?}",
        d1
    );

    let rows = policy_rule_rows(&h, 1).await;
    assert_eq!(
        rows.len(),
        3,
        "expected 3 policy_rule rows for the design-§5 example's single block, got: {:?}",
        rows
    );

    // Row 0: `deny: { ports: [22], proto: tcp }` — the ssh carve-out, first
    // in written order.
    let (block0, rule0, action0, _src0, _dst0, proto0, ports0) = &rows[0];
    assert_eq!(*block0, 0, "row 0 must belong to the only (and first) block");
    assert_eq!(*rule0, 0, "row 0 must be the first rule in its block");
    assert_eq!(action0, "deny", "row 0 is the deny carve-out");
    assert_eq!(proto0, "tcp");
    assert!(
        ports0.as_deref().unwrap_or_default().contains("22"),
        "row 0's ports must mention port 22, got: {:?}",
        ports0
    );

    // Row 1: `allow: { dst: 172.16.1.50/32, ports: [5432], proto: tcp }` —
    // Postgres.
    let (block1, rule1, action1, _src1, dst1, proto1, ports1) = &rows[1];
    assert_eq!(*block1, 0);
    assert_eq!(*rule1, 1, "row 1 must be the second rule in its block");
    assert_eq!(action1, "allow");
    assert_eq!(proto1, "tcp");
    assert!(
        dst1.contains("172.16.1.50/32"),
        "row 1's dst must mention 172.16.1.50/32, got: {:?}",
        dst1
    );
    assert!(
        ports1.as_deref().unwrap_or_default().contains("5432"),
        "row 1's ports must mention port 5432, got: {:?}",
        ports1
    );

    // Row 2: `allow: { dst: 172.16.2.0/24, ports: [443, "8000-8080"], proto: tcp }`.
    let (block2, rule2, action2, _src2, dst2, proto2, ports2) = &rows[2];
    assert_eq!(*block2, 0);
    assert_eq!(*rule2, 2, "row 2 must be the third rule in its block");
    assert_eq!(action2, "allow");
    assert_eq!(proto2, "tcp");
    assert!(
        dst2.contains("172.16.2.0/24"),
        "row 2's dst must mention 172.16.2.0/24, got: {:?}",
        dst2
    );
    let ports2_str = ports2.as_deref().unwrap_or_default();
    assert!(
        ports2_str.contains("443"),
        "row 2's ports must mention port 443, got: {:?}",
        ports2
    );
    assert!(
        ports2_str.contains("8000"),
        "row 2's ports must mention the 8000-8080 range, got: {:?}",
        ports2
    );
}
