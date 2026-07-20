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
use std::str::FromStr;
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

#[test]
fn set_local_candidates_replaces_set_and_bumps_revision_only_on_change() {
    let db = Db::open_memory().unwrap();
    let gw = enroll_test_gateway(&db, "aws", "10.0.0.0/16", "tok-1", "serial-1");

    let r0 = db.current_revision().unwrap();

    let r1 = db
        .set_local_candidates(gw, &["a".to_string(), "b".to_string()])
        .unwrap()
        .expect("a genuinely new local set must bump the revision");
    assert!(r1 > r0, "r1={r1} must be > r0={r0}");
    assert_eq!(db.candidates_for(gw).unwrap(), vec!["a".to_string(), "b".to_string()]);

    // Re-supplying the SAME set, just reordered, must be a no-op: no write,
    // no revision bump — mirrors `set_candidate_endpoint`'s change-detection
    // discipline (see its doc comment).
    let unchanged = db
        .set_local_candidates(gw, &["b".to_string(), "a".to_string()])
        .unwrap();
    assert_eq!(
        unchanged, None,
        "re-supplying an unchanged (just reordered) local set must return None"
    );
    assert_eq!(db.current_revision().unwrap(), r1, "revision must not have moved");

    // A genuinely different set (shrunk to one endpoint) must bump again.
    let r2 = db
        .set_local_candidates(gw, &["a".to_string()])
        .unwrap()
        .expect("a genuinely changed local set must bump the revision");
    assert!(r2 > r1, "r2={r2} must be > r1={r1}");
    assert_eq!(db.candidates_for(gw).unwrap(), vec!["a".to_string()]);
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
