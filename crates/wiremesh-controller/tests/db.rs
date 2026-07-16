use wiremesh_controller::db::{Db, OverlapError};
use ipnet::Ipv4Net; use std::str::FromStr;

#[test]
fn migration_is_idempotent_and_sets_user_version() {
    let db = Db::open_memory().unwrap();
    assert_eq!(db.user_version().unwrap(), 1);
    db.run_migrations().unwrap(); // second run is a no-op
    assert_eq!(db.user_version().unwrap(), 1);
}

#[test]
fn overlapping_cidr_is_rejected_naming_the_conflict() {
    let db = Db::open_memory().unwrap();
    db.insert_segment("aws", &[Ipv4Net::from_str("10.0.0.0/16").unwrap()]).unwrap();
    let err = db.insert_segment("gcp", &[Ipv4Net::from_str("10.0.5.0/24").unwrap()]).unwrap_err();
    let overlap = err.downcast::<OverlapError>().unwrap();
    assert_eq!(overlap.conflicting_segment, "aws");
    // non-overlapping is accepted
    db.insert_segment("lab", &[Ipv4Net::from_str("192.168.0.0/24").unwrap()]).unwrap();
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
    db.audit("token:ci", "create", "segment/aws", r#"{"name":"aws"}"#).unwrap();
    assert_eq!(db.count_audit().unwrap(), 1);
}
