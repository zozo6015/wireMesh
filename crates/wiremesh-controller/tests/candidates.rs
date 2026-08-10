//! Cycle-4b Task 3: the controller's multi-candidate DB model (spec §6.1) —
//! `Db::candidates_for` merges a gateway's controller-OBSERVED endpoint
//! (`gateway.candidate_endpoint`, unchanged since cycle-2) with its
//! locally-reported candidates (the new `gateway_candidate` table,
//! `source = 'local'`, cycle-4b Task 3's `Db::set_local_candidates`).
//!
//! These are direct `Db`-level unit tests (not full `wiremesh-testkit`
//! integration tests): nothing yet wires a gateway-reported local-candidate
//! set through any RPC (that's a later cycle-4b task), so the accessors are
//! exercised straight against the DB layer, the same way `tests/db.rs`
//! exercises `insert_segment`/`current_revision` directly.

use ipnet::Ipv4Net;
use rusqlite::Connection;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;
use wiremesh_controller::db::Db;

/// Enrolls one active gateway named `name` bound to `cidr` and returns its
/// `gateway_id`. Mirrors the token-mint-then-enroll flow `Db::enroll_gateway`
/// requires (see its doc comment): a `segment` + matching `cidr` row, a
/// single-use `gateway`-kind `enrollment_token` bound to that exact CIDR set,
/// then `enroll_gateway` redeeming it. `token_id`/`secret_hash`/`cert_serial`
/// are caller-supplied so a test enrolling more than one gateway can give
/// each a distinct set without colliding on the `enrollment_token`/
/// `certificate` primary keys.
fn enroll_test_gateway(
    db: &Db,
    segment_name: &str,
    cidr: &str,
    token_id: &str,
    cert_serial: &str,
) -> i64 {
    let net = Ipv4Net::from_str(cidr).unwrap();
    db.insert_segment(segment_name, &[net]).unwrap();
    db.insert_enrollment_token(
        token_id,
        &format!("secret-hash-{token_id}"),
        "gateway",
        cidr,
        None,
        "2999-01-01T00:00:00Z",
        "test",
        "2020-01-01T00:00:00Z",
    )
    .unwrap();
    let outcome = db
        .enroll_gateway(
            &format!("secret-hash-{token_id}"),
            &[net],
            segment_name,
            "",
            cert_serial,
            "issuer",
            "2999-01-01T00:00:00Z",
            "2020-01-01T00:00:00Z",
        )
        .unwrap();
    outcome.gateway_id
}

#[test]
fn candidates_for_returns_observed_and_locals_deduped_observed_first() {
    let db = Db::open_memory().unwrap();
    let gw = enroll_test_gateway(&db, "aws", "10.0.0.0/16", "tok-1", "serial-1");

    db.set_candidate_endpoint(gw, "1.2.3.4:5").unwrap();
    // One local candidate is a genuinely new address; the other duplicates
    // the observed value and must not appear twice in the merged set.
    db.set_local_candidates(
        gw,
        &["10.0.0.5:9000".to_string(), "1.2.3.4:5".to_string()],
    )
    .unwrap();

    let candidates = db.candidates_for(gw).unwrap();
    assert_eq!(
        candidates,
        vec!["1.2.3.4:5".to_string(), "10.0.0.5:9000".to_string()],
        "expected the observed value first, then the deduplicated local \
         value, got: {candidates:?}"
    );
}

/// (Backlog item 1) This test's fixtures used to be the bare strings `"a"`
/// and `"b"`, which are not endpoints at all. That was harmless while
/// `local_endpoints` went unvalidated end to end, but item 1 makes an
/// unparseable candidate something the fabric must never store — a stored
/// non-`SocketAddrV4` string is re-advertised to every other gateway, where
/// `uapi::validate_ipv4_endpoint` rejects it and the resulting `Err` unwinds
/// out of `apply_state` and EXITS the peer gateway process. The fixtures are
/// therefore real `ip:port` endpoints now. Nothing this test asserts changed:
/// it is about `set_local_candidates`' REPLACE semantics and its
/// bump-only-on-change discipline, and the two endpoints below sort in the
/// same order `"a"`/`"b"` did.
#[test]
fn set_local_candidates_replaces_set_and_bumps_revision_only_on_change() {
    let db = Db::open_memory().unwrap();
    let gw = enroll_test_gateway(&db, "aws", "10.0.0.0/16", "tok-1", "serial-1");

    const A: &str = "10.0.0.1:51820";
    const B: &str = "10.0.0.2:51820";

    let r0 = db.current_revision().unwrap();

    let r1 = db
        .set_local_candidates(gw, &[A.to_string(), B.to_string()])
        .unwrap()
        .expect("a genuinely new local set must bump the revision");
    assert!(r1 > r0, "r1={r1} must be > r0={r0}");
    assert_eq!(db.candidates_for(gw).unwrap(), vec![A.to_string(), B.to_string()]);

    // Re-supplying the SAME set, just reordered, must be a no-op: no write,
    // no revision bump — mirrors `set_candidate_endpoint`'s change-detection
    // discipline (see its doc comment).
    let unchanged = db
        .set_local_candidates(gw, &[B.to_string(), A.to_string()])
        .unwrap();
    assert_eq!(
        unchanged, None,
        "re-supplying an unchanged (just reordered) local set must return None"
    );
    assert_eq!(db.current_revision().unwrap(), r1, "revision must not have moved");

    // A genuinely different set (shrunk to one endpoint) must bump again.
    let r2 = db
        .set_local_candidates(gw, &[A.to_string()])
        .unwrap()
        .expect("a genuinely changed local set must bump the revision");
    assert!(r2 > r1, "r2={r2} must be > r1={r1}");
    assert_eq!(db.candidates_for(gw).unwrap(), vec![A.to_string()]);
}

/// The load-bearing regression guard: a gateway that has only ever had its
/// controller-observed endpoint recorded (no local candidates at all) must
/// still yield exactly the single-element list cycle-2/3 always produced —
/// `Db::candidates_for` must not silently change behavior for every gateway
/// that doesn't participate in the new local-candidate mechanism yet.
#[test]
fn observed_only_gateway_yields_single_element_list_back_compat() {
    let db = Db::open_memory().unwrap();
    let gw = enroll_test_gateway(&db, "aws", "10.0.0.0/16", "tok-1", "serial-1");

    // No observed value yet, no locals: empty.
    assert_eq!(db.candidates_for(gw).unwrap(), Vec::<String>::new());

    db.set_candidate_endpoint(gw, "9.9.9.9:1").unwrap();
    assert_eq!(
        db.candidates_for(gw).unwrap(),
        vec!["9.9.9.9:1".to_string()],
        "an observed-only gateway must yield exactly [observed], matching the \
         pre-Task-3 `p.candidate_endpoint.into_iter().collect()` behavior"
    );
}

// ---------------------------------------------------------------------------
// (CodeRabbit finding on PR #59, 🟠 Major) `Db::candidates_for` has NO
// read-side validation. This PR adds `SyncSvc::usable_local_candidates` to
// filter `Sync.Report`'s `local_endpoints` on the way IN
// (`tests/report_local_endpoints_validation.rs` pins that half), but a
// `gateway_candidate` row that was already sitting in `controller.db` before
// that filter existed — written by a pre-fix controller binary, or by any
// future write path that doesn't route through `set_local_candidates` — is
// read back by `candidates_for` completely unvalidated and re-advertised to
// EVERY other gateway as `Peer.candidate_endpoints`, and separately fed into
// `PunchDirective.candidates` via `broker.rs`.
//
// These tests bypass `Db::set_local_candidates` entirely and INSERT directly
// into `gateway_candidate` over a raw second `rusqlite::Connection` onto the
// same on-disk file — the pattern `tests/enroll_token_kind.rs` established —
// because that is the only way to genuinely reproduce a row the ingest
// filter never got a chance to clean: calling `set_local_candidates` itself
// would just get filtered by this PR's own fix.
//
// The production change these tests are written against: adding the same
// validity predicate `SyncSvc::usable_local_candidates` applies on write
// (parses as `SocketAddr::V4`) as a read-side filter inside
// `Db::candidates_for`, over both the `gateway_candidate` loop and (per the
// finding write-up) the observed `candidate_endpoint` column.
// ---------------------------------------------------------------------------

/// Opens a raw second connection onto `db_path`, for writing rows that
/// bypass every validating `Db` write path — the only way to simulate state
/// a pre-fix controller binary left behind. Mirrors
/// `tests/enroll_token_kind.rs`'s `open_db` helper, including the
/// busy-timeout rationale: nothing here writes concurrently with the `Db`
/// handle under test, but a 5s timeout is free insurance against exactly
/// that flake class.
fn raw_conn(db_path: &Path) -> Connection {
    let conn = Connection::open(db_path)
        .unwrap_or_else(|e| panic!("opening {} for raw insert: {e}", db_path.display()));
    conn.busy_timeout(Duration::from_secs(5))
        .expect("setting busy_timeout on the raw inspection/write connection");
    conn
}

/// Inserts one `gateway_candidate` row with `source = 'local'` directly,
/// bypassing `Db::set_local_candidates` (and therefore bypassing
/// `SyncSvc::usable_local_candidates`, the new ingest-side filter this
/// finding is about) — exactly the shape a pre-filter write path would have
/// left in place.
fn insert_raw_local_candidate(db_path: &Path, gateway_id: i64, endpoint: &str) {
    raw_conn(db_path)
        .execute(
            "INSERT INTO gateway_candidate (gateway_id, endpoint, source, observed_at) \
             VALUES (?1, ?2, 'local', '2020-01-01T00:00:00Z')",
            rusqlite::params![gateway_id, endpoint],
        )
        .unwrap_or_else(|e| panic!("inserting raw local candidate {endpoint:?}: {e}"));
}

/// Every non-`SocketAddrV4` shape used across this branch's validation
/// suites (`tests/report_local_endpoints_validation.rs`'s `REJECTED`), kept
/// to the subset the finding write-up called out so the corpus here stays
/// recognizably the same trap set rather than drifting into a parallel list.
const HOSTILE_LOCAL_ENDPOINTS: &[(&str, &str)] = &[
    (
        "abc:123",
        "a DNS-name-with-port: survives `reconcile::pending_peer_configs`'s own \
         `rsplit_once(':')` half-check and only dies inside \
         `uapi::validate_ipv4_endpoint` on the RECEIVING gateway — THE trap this whole \
         validation effort exists for",
    ),
    ("not-an-endpoint", "unstructured garbage: the base case"),
    ("10.0.0.5", "an IPv4 address with no port: WireGuard's UAPI endpoint= needs ip:port"),
    (
        "[::1]:51820",
        "a bracketed IPv6 literal: parses as `SocketAddr::V6` and is a hard error in \
         `validate_ipv4_endpoint` — v1 is IPv4-only end to end",
    ),
    (
        "10.0.0.5:51820\nendpoint=1.2.3.4:1",
        "the explicit UAPI line-injection payload: the wire protocol is newline-delimited \
         key=value lines, so a stored endpoint carrying one is an injection vector into \
         boringtun's `set` message on every peer it's advertised to, not merely a parse \
         failure",
    ),
    ("", "an empty string parses as nothing and sorts before every real address, so it \
          would take candidates[0] for free"),
];

/// (Item 1) A `gateway_candidate` row with `source = 'local'` holding a
/// non-`SocketAddrV4` value — the shape a pre-fix controller binary left on
/// disk before `SyncSvc::usable_local_candidates` existed — must not survive
/// a `candidates_for` read. One fresh gateway per hostile value so each is
/// isolated: if any one of them came back, that specific string would show
/// up in the assertion failure.
///
/// Expected to FAIL now: `candidates_for` (db.rs:3048) has no predicate on
/// the `gateway_candidate` loop at all — it collects every `source = 'local'`
/// row unconditionally, so each of these comes straight back out.
#[test]
fn a_persisted_pre_filter_local_row_with_a_non_ipv4_endpoint_is_not_returned() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("controller.db");
    let db = Db::open(&db_path).unwrap();

    for (i, (bad, why)) in HOSTILE_LOCAL_ENDPOINTS.iter().enumerate() {
        let gw = enroll_test_gateway(
            &db,
            &format!("seg{i}"),
            &format!("10.{i}.0.0/24"),
            &format!("tok-{i}"),
            &format!("serial-{i}"),
        );
        insert_raw_local_candidate(&db_path, gw, bad);

        assert_eq!(
            db.candidates_for(gw).unwrap(),
            Vec::<String>::new(),
            "a persisted `gateway_candidate` row holding {bad:?} must NOT be returned by \
             candidates_for — why it matters: {why}. What happens if it is returned: it is \
             re-advertised to every other gateway as `Peer.candidate_endpoints` and fed \
             into `PunchDirective.candidates` (broker.rs), verbatim, with no read-side \
             check at all."
        );
    }
}

/// (Item 2) Filtering a gateway's local candidate set must drop only the bad
/// entries, never the whole list — a good sibling stored alongside garbage
/// must still come back. This is the finding's other half: a read-side fix
/// that hard-rejects the whole row set the moment one entry is unparseable
/// would cost a gateway its entire local candidate set (and with it its
/// direct path) over one bad string, exactly the outage `SyncSvc::report`'s
/// own filter-with-a-log posture was written to avoid on the write side.
///
/// Expected to FAIL now for the wrong reason it should pass for: today ALL
/// three rows come back (no filtering happens at all), so the equality
/// against just the two valid endpoints fails because the actual vector
/// additionally contains `"abc:123"`.
#[test]
fn valid_sibling_local_rows_survive_when_a_bad_row_is_also_present() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("controller.db");
    let db = Db::open(&db_path).unwrap();
    let gw = enroll_test_gateway(&db, "aws", "10.0.0.0/16", "tok-1", "serial-1");

    insert_raw_local_candidate(&db_path, gw, "10.0.0.5:51820");
    insert_raw_local_candidate(&db_path, gw, "abc:123");
    insert_raw_local_candidate(&db_path, gw, "10.0.0.6:51820");

    assert_eq!(
        db.candidates_for(gw).unwrap(),
        vec!["10.0.0.5:51820".to_string(), "10.0.0.6:51820".to_string()],
        "the two valid IPv4 endpoints must survive even though a malformed sibling row \
         (\"abc:123\") is present in the same gateway's local set — a read-side fix must \
         drop bad ELEMENTS, not the whole row set, or one stale bad row silently strips a \
         gateway of every direct-path candidate it legitimately has."
    );
}

/// (Item 4) A gateway whose entire persisted local set is invalid must yield
/// an empty `Vec`, not an `Err` — the query itself must keep succeeding once
/// every row is filtered away, the same way `SyncSvc::report`'s ingest-side
/// filter keeps the RPC at `Ok` when every reported endpoint is garbage
/// (`report_local_endpoints_validation.rs`'s
/// `a_report_of_only_invalid_endpoints_succeeds_and_clears_the_set`). This is
/// distinct from item 1's per-value isolation above: here MULTIPLE bad rows
/// are filtered away from ONE gateway at once, proving the whole set
/// collapses to empty rather than to a partial or an error.
///
/// Expected to FAIL now: with no read-side filter, both bad rows come back
/// unchanged, so the result is a 2-element vector, not empty — `.unwrap()`
/// itself would already succeed today (there's no error path to hit), so
/// this pins the VALUE, not merely that the call doesn't error.
#[test]
fn a_gateway_whose_local_rows_are_all_invalid_yields_an_empty_list_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("controller.db");
    let db = Db::open(&db_path).unwrap();
    let gw = enroll_test_gateway(&db, "aws", "10.0.0.0/16", "tok-1", "serial-1");

    insert_raw_local_candidate(&db_path, gw, "not-an-endpoint");
    insert_raw_local_candidate(&db_path, gw, "10.0.0.5");

    let result = db.candidates_for(gw);
    assert!(
        result.is_ok(),
        "candidates_for must keep succeeding even when every persisted local row is \
         invalid — a read-side filter that errors instead of filtering would turn one \
         stale bad row into a hard failure for every caller of candidates_for (the Sync \
         snapshot/delta projection and broker.rs's punch-directive path both call it), \
         got: {result:?}"
    );
    assert_eq!(
        result.unwrap(),
        Vec::<String>::new(),
        "with no observed endpoint and every local row invalid, the merged candidate list \
         must be empty — not the raw garbage rows, and not a partial list"
    );
}
