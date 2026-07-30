//! Path-state-aware broker skip (directive-storm fix, FIX A).
//!
//! v0.2.4 stopped tick-driven `ProbeDirect` punch spawns, but production
//! logs showed the "deferring direct punch" line still burst-firing —
//! driven by controller `PunchDirective`s: the broker re-brokers pairs on
//! its 5s/5-attempt periodic budget, and that budget resets on ANY
//! candidate change or reconnect, with no knowledge of the pair's actual
//! data-plane path state. A pair that is already settled (`direct` or
//! `relayed` on both ends) kept getting re-punched forever.
//!
//! TDD: this file is authored AHEAD of the implementation and is EXPECTED
//! to fail to compile until FIX A lands. Target surface:
//!
//! - proto: `ReportRequest` gains additive `repeated PeerPath peer_paths
//!   = 5;` with `message PeerPath { uint64 peer_gateway_id = 1; string
//!   state = 2; }` — `state` is the gateway's lowercase path-state string
//!   ("connecting"/"direct"/"degraded"/"relayed"/"disconnected").
//! - controller: `Sync.Report` forwards the reporter's `peer_paths` to the
//!   broker (`Broker::on_report(gateway_id: i64, peer_paths: ...)`), which
//!   stores the latest state per (reporter, peer) and CLEARS a reporter's
//!   entries when it RECONNECTS (`Broker::on_gateway_connected`, alongside
//!   the existing pair-budget reset — observably equivalent, for these
//!   tests, to clearing on disconnect).
//! - skip semantics: `emit_pair`/`emit_pair_periodic` skip — emit nothing,
//!   consume no budget — iff BOTH members' latest stored reports mark the
//!   OTHER member as "direct" OR "relayed". Anything one-sided, absent, or
//!   in any other state emits exactly as today (fail-open toward
//!   punching; empty `peer_paths` = old client = today's behavior). A
//!   candidate change must NOT override the both-settled skip.
//! - testkit: `StubGateway::report_with_peer_paths(&self, applied_version:
//!   u64, local_endpoints: &[&str], peer_paths: &[(u64, &str)]) ->
//!   anyhow::Result<()>` — additive counterpart to `report`, mirroring
//!   `report_with_relay_health` exactly (each `(peer_gateway_id, state)`
//!   pair mapped to a `wiremesh_proto::v1::PeerPath`).
//!
//! CodeRabbit follow-up (snapshot semantics): a NEW gateway whose
//! steady-state report legitimately carries an EMPTY (or peer-dropping)
//! `peer_paths` — it pruned the peer from its roster, or tracks no paths —
//! is indistinguishable on the wire from an old client, so the broker's
//! stored settled states would go stale until the reporter reconnects.
//! Additional target surface:
//!
//! - proto: `ReportRequest` gains `bool peer_paths_snapshot = 6;`. New
//!   clients set it true on EVERY steady-state report (the gateway sync
//!   loop already serializes its complete `paths` map — a genuine
//!   snapshot, including empty); the rotation-tick unary epoch-ack report
//!   (`send_epoch_ack`) keeps it false — it is not a path snapshot and
//!   must NOT wipe stored states.
//! - broker `on_report`: snapshot=true REPLACES the reporter's stored map
//!   with the report's content (empty snapshot ⇒ clear all of that
//!   reporter's entries); snapshot=false keeps the upsert-only,
//!   empty-is-no-op behavior (old client / epoch-ack shape).
//! - testkit expectation for the implementer: `report_with_peer_paths`
//!   sets `peer_paths_snapshot: true` (it models a new steady-state
//!   client); the plain `report` helper keeps the old-client shape (empty
//!   `peer_paths`, snapshot=false).

use std::time::Duration;

use wiremesh_proto::v1::SyncMessage;
use wiremesh_testkit::{enroll_one, next_punch, TestController};

/// A generous ceiling for a punch that SHOULD arrive (report → broadcast →
/// broker → per-connection channel → stream), roomy for a slow container.
const PUNCH_TIMEOUT: Duration = Duration::from_secs(10);

/// A short ceiling for NEGATIVE cases where NO punch must arrive — long
/// enough that a wrongly-emitted punch would have landed well within it.
const NO_PUNCH_TIMEOUT: Duration = Duration::from_secs(2);

/// Long enough to cover AT LEAST one periodic broker sweep (the broker's
/// retry interval is 5s), so silence over this window proves the periodic
/// path skipped, not merely that no ad-hoc trigger fired.
const SETTLED_SILENCE: Duration = Duration::from_secs(8);

/// Drains any punches already emitted/en-route on `stream` until it has
/// been quiet for [`NO_PUNCH_TIMEOUT`] — used to consume the legitimate
/// pre-settlement punches (initial candidate reports, one-sided-settled
/// windows) before asserting the both-settled silence.
async fn drain_punches(stream: &mut tonic::Streaming<SyncMessage>) {
    while next_punch(stream, NO_PUNCH_TIMEOUT).await.is_ok() {}
}

/// (a) The core skip: once BOTH members' latest reports mark the OTHER as
/// "direct", the pair is settled — the periodic sweep must emit NOTHING
/// (silence across a full sweep interval) and a subsequent candidate
/// change must NOT override the skip (today it resets the budget AND
/// re-emits; settled pairs are exactly the case that made that a storm).
#[tokio::test]
async fn both_settled_pair_skips_periodic_and_candidate_change_repunch() {
    let h = TestController::start().await;
    let a = enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = enroll_one(&h, "gcp", "10.1.0.0/16").await;

    let mut a_stream = a.open_sync().await;
    let mut b_stream = b.open_sync().await;

    let a_endpoint = "10.0.0.1:51820";
    let b_endpoint = "10.1.0.1:51820";
    a.report(0, &[a_endpoint]).await.expect("A reports candidate");
    b.report(0, &[b_endpoint]).await.expect("B reports candidate");

    // The pre-settlement punch pair is legitimate and expected.
    next_punch(&mut a_stream, PUNCH_TIMEOUT)
        .await
        .expect("A must receive the initial pre-settlement punch");
    next_punch(&mut b_stream, PUNCH_TIMEOUT)
        .await
        .expect("B must receive the initial pre-settlement punch");

    // Both sides now report the pair settled: each marks the OTHER "direct".
    // (Same candidate endpoints re-reported so neither side's candidate set
    // empties — local_endpoints has empty-list-clears semantics.)
    a.report_with_peer_paths(0, &[a_endpoint], &[(b.id(), "direct")])
        .await
        .expect("A reports peer_paths direct");
    b.report_with_peer_paths(0, &[b_endpoint], &[(a.id(), "direct")])
        .await
        .expect("B reports peer_paths direct");

    // Consume anything emitted before the SECOND settled report landed
    // (the one-sided window still emits, by design).
    drain_punches(&mut a_stream).await;
    drain_punches(&mut b_stream).await;

    // Settled silence: no punch on EITHER stream across a window covering
    // at least one full periodic sweep.
    let (a_quiet, b_quiet) = tokio::join!(
        next_punch(&mut a_stream, SETTLED_SILENCE),
        next_punch(&mut b_stream, SETTLED_SILENCE),
    );
    assert!(
        a_quiet.is_err(),
        "settled pair: the periodic sweep must not re-punch, but A received: {a_quiet:?}"
    );
    assert!(
        b_quiet.is_err(),
        "settled pair: the periodic sweep must not re-punch, but B received: {b_quiet:?}"
    );

    // A genuine candidate CHANGE (a brand-new local endpoint) must not
    // override the both-settled skip either — this is precisely the reset
    // path that kept the storm alive.
    a.report_with_peer_paths(0, &[a_endpoint, "10.0.0.99:51820"], &[(b.id(), "direct")])
        .await
        .expect("A reports a changed candidate set while settled");
    let (a_after, b_after) = tokio::join!(
        next_punch(&mut a_stream, NO_PUNCH_TIMEOUT),
        next_punch(&mut b_stream, NO_PUNCH_TIMEOUT),
    );
    assert!(
        a_after.is_err(),
        "settled pair: a candidate change must not re-punch, but A received: {a_after:?}"
    );
    assert!(
        b_after.is_err(),
        "settled pair: a candidate change must not re-punch, but B received: {b_after:?}"
    );
}

/// (a, OR-semantics) "Settled" means direct OR relayed on each side — a
/// mixed pair (one side relayed toward the other, the other direct) is
/// just as settled: a candidate change must still emit nothing.
#[tokio::test]
async fn mixed_direct_and_relayed_still_counts_as_settled() {
    let h = TestController::start().await;
    let a = enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = enroll_one(&h, "gcp", "10.1.0.0/16").await;

    let mut a_stream = a.open_sync().await;
    let mut b_stream = b.open_sync().await;

    let a_endpoint = "10.0.0.1:51820";
    let b_endpoint = "10.1.0.1:51820";
    a.report(0, &[a_endpoint]).await.expect("A reports candidate");
    b.report(0, &[b_endpoint]).await.expect("B reports candidate");
    next_punch(&mut a_stream, PUNCH_TIMEOUT)
        .await
        .expect("A must receive the initial pre-settlement punch");
    next_punch(&mut b_stream, PUNCH_TIMEOUT)
        .await
        .expect("B must receive the initial pre-settlement punch");

    a.report_with_peer_paths(0, &[a_endpoint], &[(b.id(), "relayed")])
        .await
        .expect("A reports peer_paths relayed");
    b.report_with_peer_paths(0, &[b_endpoint], &[(a.id(), "direct")])
        .await
        .expect("B reports peer_paths direct");

    drain_punches(&mut a_stream).await;
    drain_punches(&mut b_stream).await;

    // A candidate change while relayed+direct settled: still no punch.
    b.report_with_peer_paths(0, &[b_endpoint, "10.1.0.99:51820"], &[(a.id(), "direct")])
        .await
        .expect("B reports a changed candidate set while settled");
    let (a_after, b_after) = tokio::join!(
        next_punch(&mut a_stream, NO_PUNCH_TIMEOUT),
        next_punch(&mut b_stream, NO_PUNCH_TIMEOUT),
    );
    assert!(
        a_after.is_err(),
        "relayed+direct is settled: candidate change must not re-punch, A got: {a_after:?}"
    );
    assert!(
        b_after.is_err(),
        "relayed+direct is settled: candidate change must not re-punch, B got: {b_after:?}"
    );
}

/// (b) One-sided settlement is NOT settlement: A marks B "direct" but B has
/// never reported any peer_paths — the broker must fail open and emit
/// exactly as today (B may be a freshly-restarted gateway that genuinely
/// needs the punch).
#[tokio::test]
async fn one_sided_settled_report_still_emits() {
    let h = TestController::start().await;
    let a = enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = enroll_one(&h, "gcp", "10.1.0.0/16").await;

    let mut a_stream = a.open_sync().await;
    let mut b_stream = b.open_sync().await;

    // A settles its view of B in the SAME report that carries its
    // candidate; B reports a candidate only (no peer_paths at all).
    a.report_with_peer_paths(0, &["10.0.0.1:51820"], &[(b.id(), "direct")])
        .await
        .expect("A reports candidate + settled peer_path");
    b.report(0, &["10.1.0.1:51820"]).await.expect("B reports candidate");

    let a_punch = next_punch(&mut a_stream, PUNCH_TIMEOUT)
        .await
        .expect("one-sided settlement must still punch: A received nothing");
    let b_punch = next_punch(&mut b_stream, PUNCH_TIMEOUT)
        .await
        .expect("one-sided settlement must still punch: B received nothing");
    assert_eq!(a_punch.peer_gateway_id, b.id(), "A's punch must target B");
    assert_eq!(b_punch.peer_gateway_id, a.id(), "B's punch must target A");
}

/// (c) A non-settled state on either side keeps the pair punchable: A says
/// "direct" but B's latest report marks A "connecting" — emit as today.
#[tokio::test]
async fn connecting_peer_state_still_emits() {
    let h = TestController::start().await;
    let a = enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = enroll_one(&h, "gcp", "10.1.0.0/16").await;

    let mut a_stream = a.open_sync().await;
    let mut b_stream = b.open_sync().await;

    a.report_with_peer_paths(0, &["10.0.0.1:51820"], &[(b.id(), "direct")])
        .await
        .expect("A reports candidate + direct peer_path");
    b.report_with_peer_paths(0, &["10.1.0.1:51820"], &[(a.id(), "connecting")])
        .await
        .expect("B reports candidate + connecting peer_path");

    let a_punch = next_punch(&mut a_stream, PUNCH_TIMEOUT)
        .await
        .expect("a connecting side must keep the pair punchable: A received nothing");
    let b_punch = next_punch(&mut b_stream, PUNCH_TIMEOUT)
        .await
        .expect("a connecting side must keep the pair punchable: B received nothing");
    assert_eq!(a_punch.peer_gateway_id, b.id(), "A's punch must target B");
    assert_eq!(b_punch.peer_gateway_id, a.id(), "B's punch must target A");
}

/// (d) A reporter's stored path states must be CLEARED when it disconnects:
/// a settled pair whose member B drops and reconnects is punchable again —
/// B's process may have restarted with no tunnel at all, and its stale
/// "direct" report must not keep suppressing the punch it now needs.
#[tokio::test]
async fn reporter_disconnect_clears_stored_states_and_pair_repunches() {
    let h = TestController::start().await;
    let a = enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = enroll_one(&h, "gcp", "10.1.0.0/16").await;

    let mut a_stream = a.open_sync().await;
    let mut b_stream = b.open_sync().await;

    let a_endpoint = "10.0.0.1:51820";
    let b_endpoint = "10.1.0.1:51820";
    a.report(0, &[a_endpoint]).await.expect("A reports candidate");
    b.report(0, &[b_endpoint]).await.expect("B reports candidate");
    next_punch(&mut a_stream, PUNCH_TIMEOUT)
        .await
        .expect("A must receive the initial pre-settlement punch");
    next_punch(&mut b_stream, PUNCH_TIMEOUT)
        .await
        .expect("B must receive the initial pre-settlement punch");

    // Settle both sides, then prove the pair actually went quiet (so the
    // punch asserted after the reconnect is attributable to the reconnect,
    // not a straggler).
    a.report_with_peer_paths(0, &[a_endpoint], &[(b.id(), "direct")])
        .await
        .expect("A reports peer_paths direct");
    b.report_with_peer_paths(0, &[b_endpoint], &[(a.id(), "direct")])
        .await
        .expect("B reports peer_paths direct");
    drain_punches(&mut a_stream).await;
    drain_punches(&mut b_stream).await;

    // B disconnects (its Watch stream drops)...
    drop(b_stream);
    // ...give the server a beat to observe the stream teardown...
    tokio::time::sleep(Duration::from_secs(1)).await;
    // ...and reconnects. Its stored "A is direct" entries are gone, so the
    // pair is one-sided at best — punchable again. (The reconnect trigger
    // itself, or at latest the next periodic sweep, must emit; both are
    // comfortably inside PUNCH_TIMEOUT.)
    let mut b_stream2 = b.open_sync().await;

    let a_punch = next_punch(&mut a_stream, PUNCH_TIMEOUT)
        .await
        .expect("after B's disconnect+reconnect the pair must be re-punched: A got nothing");
    let b_punch = next_punch(&mut b_stream2, PUNCH_TIMEOUT)
        .await
        .expect("after B's disconnect+reconnect the pair must be re-punched: B got nothing");
    assert_eq!(a_punch.peer_gateway_id, b.id(), "A's punch must target B");
    assert_eq!(b_punch.peer_gateway_id, a.id(), "B's punch must target A");
}

/// (e) Old-client behavior is unchanged: gateways that NEVER send
/// peer_paths (plain `report`) keep today's semantics — the initial punch
/// fires AND the periodic sweep keeps re-punching within its budget (the
/// second punch below is the first periodic re-punch, due within one 5s
/// sweep interval).
#[tokio::test]
async fn no_peer_paths_old_client_keeps_todays_periodic_repunch() {
    let h = TestController::start().await;
    let a = enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = enroll_one(&h, "gcp", "10.1.0.0/16").await;

    let mut a_stream = a.open_sync().await;
    let mut b_stream = b.open_sync().await;

    a.report(0, &["10.0.0.1:51820"]).await.expect("A reports candidate");
    b.report(0, &["10.1.0.1:51820"]).await.expect("B reports candidate");

    next_punch(&mut a_stream, PUNCH_TIMEOUT)
        .await
        .expect("old clients: A must receive the initial punch");
    next_punch(&mut b_stream, PUNCH_TIMEOUT)
        .await
        .expect("old clients: B must receive the initial punch");

    // With no peer_paths ever reported, the broker cannot consider the pair
    // settled — the periodic sweep must keep re-punching exactly as today.
    next_punch(&mut a_stream, PUNCH_TIMEOUT)
        .await
        .expect("old clients: the periodic sweep must re-punch A within one interval");
    next_punch(&mut b_stream, PUNCH_TIMEOUT)
        .await
        .expect("old clients: the periodic sweep must re-punch B within one interval");
}

/// (snapshot, a) A settled pair whose member then sends a SNAPSHOT report
/// WITHOUT the peer (here: an empty snapshot — the reporter tracks no
/// paths at all, e.g. it pruned the peer from its roster) must become
/// punchable again: the snapshot REPLACES the reporter's stored map, so
/// the pair is at best one-sided and the broker fails open. Without
/// replace-semantics the stale "direct" entry survives until the reporter
/// reconnects — exactly the CodeRabbit gap.
#[tokio::test]
async fn snapshot_report_dropping_the_peer_reopens_the_pair() {
    let h = TestController::start().await;
    let a = enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = enroll_one(&h, "gcp", "10.1.0.0/16").await;

    let mut a_stream = a.open_sync().await;
    let mut b_stream = b.open_sync().await;

    let a_endpoint = "10.0.0.1:51820";
    let b_endpoint = "10.1.0.1:51820";
    a.report(0, &[a_endpoint]).await.expect("A reports candidate");
    b.report(0, &[b_endpoint]).await.expect("B reports candidate");
    next_punch(&mut a_stream, PUNCH_TIMEOUT)
        .await
        .expect("A must receive the initial pre-settlement punch");
    next_punch(&mut b_stream, PUNCH_TIMEOUT)
        .await
        .expect("B must receive the initial pre-settlement punch");

    // Settle both sides (snapshot reports each carrying the other peer as
    // "direct"), then drain to quiet.
    a.report_with_peer_paths(0, &[a_endpoint], &[(b.id(), "direct")])
        .await
        .expect("A reports peer_paths direct");
    b.report_with_peer_paths(0, &[b_endpoint], &[(a.id(), "direct")])
        .await
        .expect("B reports peer_paths direct");
    drain_punches(&mut a_stream).await;
    drain_punches(&mut b_stream).await;

    // A's next snapshot no longer contains the peer at all (empty snapshot;
    // `report_with_peer_paths` sends peer_paths_snapshot=true — it models a
    // new steady-state client, whose report is always its COMPLETE path
    // map). This must CLEAR A's stored entries: the pair is no longer
    // both-settled, so it must be re-punched — by the candidate-report
    // trigger or at latest the next periodic sweep, both well inside the
    // ceiling. (A keeps its candidate endpoint: local_endpoints has
    // empty-list-clears semantics and an empty candidate set would suppress
    // the punch for an unrelated reason.)
    a.report_with_peer_paths(0, &[a_endpoint], &[])
        .await
        .expect("A reports an empty peer_paths snapshot");

    let a_punch = next_punch(&mut a_stream, PUNCH_TIMEOUT)
        .await
        .expect("an empty snapshot must reopen the pair: A got no punch");
    let b_punch = next_punch(&mut b_stream, PUNCH_TIMEOUT)
        .await
        .expect("an empty snapshot must reopen the pair: B got no punch");
    assert_eq!(a_punch.peer_gateway_id, b.id(), "A's punch must target B");
    assert_eq!(b_punch.peer_gateway_id, a.id(), "B's punch must target A");
}

/// (snapshot, b) A NON-snapshot empty report — the old-client shape, and
/// the shape of the rotation-tick unary epoch-ack report — must stay a
/// no-op on the stored states: after settlement it must NOT wipe the
/// reporter's entries, so the both-settled skip keeps holding (silence
/// across a full periodic sweep, even though the report re-announced a
/// candidate). This pins that snapshot=false keeps today's upsert-only,
/// empty-is-no-op behavior — an epoch ack mid-rotation must never make
/// the broker start re-punching a settled pair.
#[tokio::test]
async fn non_snapshot_empty_report_keeps_settled_skip() {
    let h = TestController::start().await;
    let a = enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = enroll_one(&h, "gcp", "10.1.0.0/16").await;

    let mut a_stream = a.open_sync().await;
    let mut b_stream = b.open_sync().await;

    let a_endpoint = "10.0.0.1:51820";
    let b_endpoint = "10.1.0.1:51820";
    a.report(0, &[a_endpoint]).await.expect("A reports candidate");
    b.report(0, &[b_endpoint]).await.expect("B reports candidate");
    next_punch(&mut a_stream, PUNCH_TIMEOUT)
        .await
        .expect("A must receive the initial pre-settlement punch");
    next_punch(&mut b_stream, PUNCH_TIMEOUT)
        .await
        .expect("B must receive the initial pre-settlement punch");

    a.report_with_peer_paths(0, &[a_endpoint], &[(b.id(), "direct")])
        .await
        .expect("A reports peer_paths direct");
    b.report_with_peer_paths(0, &[b_endpoint], &[(a.id(), "direct")])
        .await
        .expect("B reports peer_paths direct");
    drain_punches(&mut a_stream).await;
    drain_punches(&mut b_stream).await;

    // A now sends a plain (non-snapshot) report with empty peer_paths —
    // the exact wire shape of an old client's steady-state report AND of
    // the rotation-tick epoch-ack unary report (peer_paths_snapshot=false).
    // It must not disturb the stored settled states. The same candidate is
    // re-reported so the only thing that could suppress a punch is the
    // preserved skip, not an emptied candidate set.
    a.report(0, &[a_endpoint])
        .await
        .expect("A sends a non-snapshot empty-peer_paths report");

    let (a_after, b_after) = tokio::join!(
        next_punch(&mut a_stream, SETTLED_SILENCE),
        next_punch(&mut b_stream, SETTLED_SILENCE),
    );
    assert!(
        a_after.is_err(),
        "a non-snapshot empty report must not wipe settled states, but A received: {a_after:?}"
    );
    assert!(
        b_after.is_err(),
        "a non-snapshot empty report must not wipe settled states, but B received: {b_after:?}"
    );
}
