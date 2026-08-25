//! (Cycle-4b Task 5, spec §4) The Sync **broker**: when both gateways of a
//! cross-segment pair are connected on `Sync.Watch` and each has a candidate
//! set, the controller emits a `PunchDirective` to BOTH members — each
//! carrying the OTHER's candidates, both stamped with a COMMON `go_unix_ms`
//! fire instant, both sent back-to-back in one critical section (the go-skew
//! guarantee, Phase-0 Finding 2).
//!
//! Unlike a `Delta` (which self-excludes the subject gateway), a
//! `PunchDirective` must reach both pair members explicitly — that dual
//! delivery is the central behavior these tests pin.

use std::time::Duration;

use wiremesh_testkit::{enroll_one, next_punch, TestController};

/// A generous ceiling for a punch that SHOULD arrive (candidate report →
/// broadcast → broker → per-connection channel → stream), roomy for a slow
/// container.
const PUNCH_TIMEOUT: Duration = Duration::from_secs(10);

/// A short ceiling for the NEGATIVE cases where NO punch must ever arrive —
/// long enough that a punch, if the broker wrongly emitted one, would have
/// landed well within it.
const NO_PUNCH_TIMEOUT: Duration = Duration::from_secs(2);

/// Happy path: two gateways in different segments both connect and both report
/// a local candidate. BOTH must receive a `PunchDirective` naming the OTHER as
/// `peer_gateway_id`, carrying the other's candidate, and the two directives
/// must share ONE `go_unix_ms` (proving a single common-instant critical
/// section rather than two independently-timed sends).
#[tokio::test]
async fn both_pair_members_receive_a_punch_with_a_common_go() {
    let h = TestController::start().await;
    let a = enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = enroll_one(&h, "gcp", "10.1.0.0/16").await;

    // Both open Watch (registering their punch channels), THEN both report a
    // local candidate. The punch fires once the SECOND report gives the pair
    // mutual candidates.
    let mut a_stream = a.open_sync().await;
    let mut b_stream = b.open_sync().await;

    let a_endpoint = "10.0.0.1:51820";
    let b_endpoint = "10.1.0.1:51820";
    a.report(0, &[a_endpoint])
        .await
        .expect("A reports candidate");
    b.report(0, &[b_endpoint])
        .await
        .expect("B reports candidate");

    let a_punch = next_punch(&mut a_stream, PUNCH_TIMEOUT)
        .await
        .expect("A must receive a PunchDirective");
    let b_punch = next_punch(&mut b_stream, PUNCH_TIMEOUT)
        .await
        .expect("B must receive a PunchDirective");

    // Each directive points at the OTHER gateway and carries the other's
    // candidate.
    assert_eq!(
        a_punch.peer_gateway_id,
        b.id(),
        "A's punch must target B, got peer_gateway_id={}",
        a_punch.peer_gateway_id
    );
    assert!(
        a_punch.candidates.iter().any(|c| c == b_endpoint),
        "A's punch must carry B's candidate {b_endpoint}, got: {:?}",
        a_punch.candidates
    );
    assert_eq!(
        b_punch.peer_gateway_id,
        a.id(),
        "B's punch must target A, got peer_gateway_id={}",
        b_punch.peer_gateway_id
    );
    assert!(
        b_punch.candidates.iter().any(|c| c == a_endpoint),
        "B's punch must carry A's candidate {a_endpoint}, got: {:?}",
        b_punch.candidates
    );

    // The go-skew guarantee: both directives were stamped in the SAME critical
    // section with one common fire instant.
    assert_eq!(
        a_punch.go_unix_ms, b_punch.go_unix_ms,
        "the paired directives must share one common go_unix_ms (proving a single \
         back-to-back critical section), got A={} B={}",
        a_punch.go_unix_ms, b_punch.go_unix_ms
    );
    assert!(
        a_punch.go_unix_ms > 0,
        "go_unix_ms must be a real future wall-clock instant, got {}",
        a_punch.go_unix_ms
    );
}

/// Negative: only ONE member of the pair is connected on Watch. Even though
/// BOTH report a candidate, no `PunchDirective` may be emitted — a punch needs
/// both members reachable on their Watch streams.
#[tokio::test]
async fn no_punch_when_only_one_member_is_connected() {
    let h = TestController::start().await;
    let a = enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = enroll_one(&h, "gcp", "10.1.0.0/16").await;

    // A connects; B never opens Watch (but still reports a candidate).
    let mut a_stream = a.open_sync().await;

    a.report(0, &["10.0.0.1:51820"])
        .await
        .expect("A reports candidate");
    b.report(0, &["10.1.0.1:51820"])
        .await
        .expect("B reports candidate");

    let result = next_punch(&mut a_stream, NO_PUNCH_TIMEOUT).await;
    assert!(
        result.is_err(),
        "no punch may be emitted while B is not connected on Watch, but A received: {result:?}"
    );
}

/// Negative: both members are connected, but only ONE has reported a
/// candidate. No `PunchDirective` may be emitted for a pair where either
/// member has an empty candidate set — so NEITHER stream receives a punch.
#[tokio::test]
async fn no_punch_when_a_member_has_no_candidate() {
    let h = TestController::start().await;
    let a = enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = enroll_one(&h, "gcp", "10.1.0.0/16").await;

    let mut a_stream = a.open_sync().await;
    let mut b_stream = b.open_sync().await;

    // Only A reports a candidate; B never does.
    a.report(0, &["10.0.0.1:51820"])
        .await
        .expect("A reports candidate");

    let a_result = next_punch(&mut a_stream, NO_PUNCH_TIMEOUT).await;
    assert!(
        a_result.is_err(),
        "no punch may be emitted while B has no candidate, but A received: {a_result:?}"
    );
    let b_result = next_punch(&mut b_stream, NO_PUNCH_TIMEOUT).await;
    assert!(
        b_result.is_err(),
        "no punch may be emitted while B has no candidate, but B received: {b_result:?}"
    );
}
