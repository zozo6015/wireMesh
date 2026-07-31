//! Backlog 12 Task 1: regression proof for audit-actor attribution.
//!
//! The bug being pinned down (fixed in commit 8ddb579): mutations arriving
//! over the TCP Admin listener with a bearer token were mis-recorded in the
//! audit log with the UDS-only `"unix-socket"` placeholder actor, instead of
//! the authenticated token's name. The fix threads the `Principal` the
//! bearer-auth middleware stamps into the request extensions
//! (`wiremesh_controller::auth`) through `actor_of` in
//! `src/services/admin.rs`, which every mutating Admin RPC now calls before
//! `request.into_inner()` drops the extensions. Until this file existed, no
//! test asserted the TCP-side actor at all — `tests/admin_auth.rs` covers
//! role gating only, and the sole prior actor assertion
//! (`tests/get_policy.rs`) is UDS-side (`"unix-socket"` / merely non-empty).
//!
//! Three assertions:
//!
//!   1. A mutation (`CreateSegment`) performed over TCP with a bearer token
//!      minted under the name `"alice"` must be audited with
//!      `actor == "alice"` — the regression case: before 8ddb579 this row
//!      said `"unix-socket"`.
//!   2. The same mutation performed over the implicit-admin UDS client must
//!      still be audited with `actor == "unix-socket"` — proving the fix
//!      didn't break the legitimate UDS fallback attribution.
//!   3. A clearly read-only RPC (`ListSegments`, over both transports) must
//!      append NO audit row at all — asserted by comparing the full audit
//!      entry-id set before and after the reads, so the check is scoped to
//!      this test's own query window and stable against unrelated rows
//!      written earlier in the same test.
//!
//! Audit rows are located via `Admin.AuditQuery` filtered to
//! `action == "create"` and then matched on `entity == "segment/<name>"`
//! (the exact row `Db::create_segment_audited` writes), so other audited
//! operations in the same test (e.g. `MintApiToken`'s own audit row) can
//! never satisfy — or pollute — the assertion by accident.
use wiremesh_proto::v1::{
    AuditQueryRequest, CreateSegmentRequest, ListSegmentsRequest, MintApiTokenRequest,
};

/// Finds the single `action == "create"` audit row for `segment/<name>` and
/// returns its `actor`. Panics (failing the test loudly) if the row is
/// missing or duplicated — either would itself be an audit-pipeline bug.
async fn create_audit_actor_for(h: &wiremesh_testkit::TestController, seg_name: &str) -> String {
    let audit = h
        .admin_client()
        .await
        .audit_query(AuditQueryRequest {
            action: "create".into(),
            limit: 0,
        })
        .await
        .expect("Admin.AuditQuery(action = \"create\") must succeed")
        .into_inner();

    let entity = format!("segment/{seg_name}");
    let matching: Vec<_> = audit
        .entries
        .iter()
        .filter(|e| e.entity == entity)
        .collect();

    assert_eq!(
        matching.len(),
        1,
        "expected exactly one action == \"create\" audit row for {entity}, got {} — entries: {:?}",
        matching.len(),
        audit.entries
    );
    matching[0].actor.clone()
}

/// Regression case for commit 8ddb579: a mutation over the TCP Admin
/// listener with a bearer token must be audited under the TOKEN'S NAME, not
/// the UDS placeholder. The token is minted with the explicit name
/// `"alice"` (via the implicit-admin UDS mint path, so the credential's own
/// provenance can't contaminate the assertion), then `CreateSegment` is
/// called over TCP+bearer, and the resulting audit row's `actor` must be
/// exactly `"alice"` — with a belt-and-braces check that it is NOT
/// `"unix-socket"`, the precise wrong value the bug produced.
#[tokio::test]
async fn tcp_bearer_mutation_audits_the_token_name() {
    let h = wiremesh_testkit::TestController::start().await;

    // Mint an admin-role token with a KNOWN name — the testkit's
    // `mint_api_token` helper deliberately randomizes names, and this test
    // needs to assert the exact actor string, so it mints directly.
    let token = h
        .admin_client()
        .await
        .mint_api_token(MintApiTokenRequest {
            name: "alice".into(),
            role: "admin".into(),
        })
        .await
        .expect("Admin.MintApiToken(name = \"alice\", role = \"admin\") must succeed")
        .into_inner()
        .token;

    let mut tcp_admin = h.admin_client_with_bearer(&token).await;
    tcp_admin
        .create_segment(CreateSegmentRequest {
            name: "tcp-seg".into(),
            cidrs: vec!["10.20.0.0/24".into()],
        })
        .await
        .expect("CreateSegment over TCP with an admin bearer token must succeed");

    let actor = create_audit_actor_for(&h, "tcp-seg").await;
    assert_ne!(
        actor, "unix-socket",
        "REGRESSION (pre-8ddb579 bug): a TCP-bearer mutation was audited with the \
         UDS-only \"unix-socket\" placeholder actor instead of the token name"
    );
    assert_eq!(
        actor, "alice",
        "a TCP-bearer mutation must be audited under the bearer token's name \
         (\"alice\"), got actor: {actor:?}"
    );
}

/// The other half of the attribution contract: a mutation over the
/// implicit-admin UDS client (no bearer middleware, so no `Principal`
/// extension) must still fall back to `actor == "unix-socket"` — proving
/// the Principal-threading fix didn't over-correct and break the
/// legitimate UDS attribution.
#[tokio::test]
async fn uds_mutation_audits_unix_socket() {
    let h = wiremesh_testkit::TestController::start().await;

    h.admin_client()
        .await
        .create_segment(CreateSegmentRequest {
            name: "uds-seg".into(),
            cidrs: vec!["10.21.0.0/24".into()],
        })
        .await
        .expect("CreateSegment over the implicit-admin UDS client must succeed");

    let actor = create_audit_actor_for(&h, "uds-seg").await;
    assert_eq!(
        actor, "unix-socket",
        "a UDS mutation must be audited with the implicit-admin \"unix-socket\" \
         actor, got: {actor:?}"
    );
}

/// A clearly read-only RPC must not be audited at all. `ListSegments` is
/// exercised over BOTH transports (UDS implicit-admin and TCP with a
/// read-only bearer token — the latter also passes through the bearer
/// middleware and gets a `Principal` stamped, so it would be the likelier
/// transport for an accidental audit write). The assertion compares the
/// full audit entry-id set before and after the reads: one real mutation is
/// performed FIRST so the log is non-empty (a no-op-audit bug can't hide
/// behind an always-empty log), and comparing exact id sets scopes the
/// check to this test's own window regardless of what earlier rows exist.
#[tokio::test]
async fn read_only_rpc_does_not_audit() {
    let h = wiremesh_testkit::TestController::start().await;

    // Baseline mutation so the audit log is non-empty and id comparison is
    // meaningful.
    h.admin_client()
        .await
        .create_segment(CreateSegmentRequest {
            name: "baseline-seg".into(),
            cidrs: vec!["10.22.0.0/24".into()],
        })
        .await
        .expect("baseline CreateSegment over UDS must succeed");

    // Mint the read-only token BEFORE the baseline audit query — MintApiToken
    // is itself an audited mutation, so minting inside the measured window
    // would add a legitimate row and muddy the "no new rows" assertion.
    let ro_token = h.mint_api_token("read-only").await;

    let audit_ids = |entries: Vec<wiremesh_proto::v1::AuditEntry>| -> Vec<u64> {
        let mut ids: Vec<u64> = entries.into_iter().map(|e| e.id).collect();
        ids.sort_unstable();
        ids
    };

    let before = audit_ids(
        h.admin_client()
            .await
            .audit_query(AuditQueryRequest {
                action: "".into(),
                limit: 1000,
            })
            .await
            .expect("Admin.AuditQuery (unfiltered, before the reads) must succeed")
            .into_inner()
            .entries,
    );
    assert!(
        !before.is_empty(),
        "the baseline mutation must have produced at least one audit row — an \
         empty log here would make the no-new-rows assertion vacuous"
    );

    // Read-only RPC over the implicit-admin UDS transport.
    h.admin_client()
        .await
        .list_segments(ListSegmentsRequest {})
        .await
        .expect("ListSegments over UDS must succeed");

    // Read-only RPC over TCP with a read-only bearer token — the transport
    // where the bearer middleware stamps a Principal, i.e. where an
    // accidental "audit every principal-bearing request" bug would surface.
    h.admin_client_with_bearer(&ro_token)
        .await
        .list_segments(ListSegmentsRequest {})
        .await
        .expect("ListSegments over TCP with a read-only bearer token must succeed");

    let after = audit_ids(
        h.admin_client()
            .await
            .audit_query(AuditQueryRequest {
                action: "".into(),
                limit: 1000,
            })
            .await
            .expect("Admin.AuditQuery (unfiltered, after the reads) must succeed")
            .into_inner()
            .entries,
    );

    // Every audited mutation (the CreateSegment baseline and the token
    // mint) happened BEFORE the first query, so the measured window contains
    // only the two ListSegments reads and the audit queries themselves —
    // none of which may append a row. The id sets must be identical.
    assert_eq!(
        before, after,
        "the audit entry-id set changed across two read-only RPCs \
         (ListSegments over UDS and over TCP+bearer) — a read-only RPC must \
         never append an audit row"
    );
}
