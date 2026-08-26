use ipnet::Ipv4Net;
use std::str::FromStr;
use wiremesh_controller::db::{Db, OverlapError};

#[test]
fn migration_is_idempotent_and_sets_user_version() {
    let db = Db::open_memory().unwrap();
    // Cycle-3 Task 4 adds migration v2 (`policy_version.fingerprint`);
    // cycle-4b Task 3 adds migration v3 (`gateway_candidate`); Phase-B B10
    // adds migration v4 (`gateway.version`, `gateway.max_ir_schema`,
    // `relay.version`) — each via the same `PRAGMA user_version` mechanism as
    // v1. `open_memory` runs every migration up to the latest, so a fresh DB
    // lands on 4, not 1.
    //
    // THIS NUMBER TRACKS THE SCHEMA. Bumping it here is what the test is for:
    // the assertion pins that a fresh DB reaches the CURRENT top and that a
    // second `run_migrations` is a no-op, so it must move with every added
    // migration. It is not a tolerance being widened.
    //
    // (`Db::open` does NOT migrate — only `open_memory` does. The asymmetry is
    // real; see `tests/migration` coverage in `db.rs`'s in-module block, whose
    // V3 fixture calls `run_migrations` explicitly for exactly that reason.)
    assert_eq!(db.user_version().unwrap(), 4);
    db.run_migrations().unwrap(); // second run is a no-op
    assert_eq!(db.user_version().unwrap(), 4);
}

#[test]
fn overlapping_cidr_is_rejected_naming_the_conflict() {
    let db = Db::open_memory().unwrap();
    db.insert_segment("aws", &[Ipv4Net::from_str("10.0.0.0/16").unwrap()])
        .unwrap();
    let err = db
        .insert_segment("gcp", &[Ipv4Net::from_str("10.0.5.0/24").unwrap()])
        .unwrap_err();
    let overlap = err.downcast::<OverlapError>().unwrap();
    assert_eq!(overlap.conflicting_segment, "aws");
    // non-overlapping is accepted
    db.insert_segment("lab", &[Ipv4Net::from_str("192.168.0.0/24").unwrap()])
        .unwrap();
}

#[test]
fn same_call_overlapping_cidrs_are_rejected() {
    // The two CIDRs in a SINGLE declaration nest (10.0.0.0/16 contains 10.0.1.0/24),
    // so the call must be rejected as a self-overlap within the incoming set.
    let db = Db::open_memory().unwrap();
    let err = db
        .insert_segment(
            "x",
            &[
                Ipv4Net::from_str("10.0.0.0/16").unwrap(),
                Ipv4Net::from_str("10.0.1.0/24").unwrap(),
            ],
        )
        .unwrap_err();
    assert!(
        err.downcast::<OverlapError>().is_ok(),
        "expected OverlapError for self-overlapping CIDRs in the same insert call",
    );
}

#[test]
fn audit_row_is_appended() {
    let db = Db::open_memory().unwrap();
    db.audit("token:ci", "create", "segment/aws", r#"{"name":"aws"}"#)
        .unwrap();
    assert_eq!(db.count_audit().unwrap(), 1);
}

/// The Sync snapshot's `revision` must be a PERSISTED, monotonically
/// non-decreasing counter — not an in-process `AtomicU64` that resets to 1
/// on restart. A reset would be a landmine for T8 (delta comparison against
/// a stale baseline) and T9 (fail-static resync: a gateway that last saw
/// revision N, reconnecting to a restarted controller now advertising
/// revision 1, could conclude nothing changed and skip a needed resync).
/// So `current_revision()` must (a) bump on every projection-affecting
/// mutation and (b) survive a `Db::open` of the same on-disk file — hence a
/// real file path here, not `open_memory()`, so the state actually persists
/// across the reopen.
#[test]
fn revision_is_persistent_and_monotonic_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("controller.db");

    let db = Db::open(&db_path).unwrap();
    let r0 = db.current_revision().unwrap();

    // A projection-affecting mutation must advance the revision.
    db.insert_segment("aws", &[Ipv4Net::from_str("10.0.0.0/16").unwrap()])
        .unwrap();
    let r1 = db.current_revision().unwrap();
    assert!(
        r1 > r0,
        "insert_segment must bump the revision: r1={r1} r0={r0}"
    );

    // Reopen the SAME file: the revision must have persisted (non-decreasing).
    drop(db);
    let db2 = Db::open(&db_path).unwrap();
    assert!(
        db2.current_revision().unwrap() >= r1,
        "revision must persist across reopen (>= {r1}), got {}",
        db2.current_revision().unwrap()
    );

    // And it must keep incrementing after the reopen, not restart from a base.
    db2.insert_segment("gcp", &[Ipv4Net::from_str("10.1.0.0/16").unwrap()])
        .unwrap();
    assert!(
        db2.current_revision().unwrap() > r1,
        "mutation after reopen must bump the revision above {r1}, got {}",
        db2.current_revision().unwrap()
    );
}
