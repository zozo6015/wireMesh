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
//!
//! Round 4 (relay-wedge follow-up — see the "Round 4" test block at the
//! bottom): `Broker::on_report` must additionally detect the pair-level
//! settled -> UNSETTLED edge (its stored states said both members settled;
//! this report's content makes that no longer true) and, on that edge
//! only, reset the pair's periodic budget AND trigger an immediate
//! synchronized emit for the pair. No new wire surface — the two RED tests
//! compile against today's proto/testkit and fail at runtime until the
//! broker change lands; the third (no-storm guard) must be green before
//! and after.
//!
//! Sync session generation (see the block at the very bottom of this file):
//! the settled-skip above is what makes the stale pre-restart `Report` race
//! an availability bug rather than a cosmetic one, so its regression tests
//! live here with it — same harness, same both-settled/reconnect vocabulary.

use std::time::Duration;

use wiremesh_proto::v1::{ListGatewaysRequest, PeerPath, ReportRequest, SyncMessage};
use wiremesh_testkit::{enroll_one, next_punch, StubGateway, TestController};

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

/// Drains `stream` until it has been quiet for a FULL periodic sweep
/// interval plus margin ([`SETTLED_SILENCE`] > the broker's 5s
/// `RETRY_INTERVAL`). For an UNSETTLED pair with unchanged candidates, that
/// silence can only mean the pair's periodic budget
/// (`MAX_PERIODIC_ATTEMPTS` = 5) is EXHAUSTED — an un-exhausted budget
/// would have re-punched within one 5s sweep. This is the round-4 tests'
/// budget-exhaustion technique: consume the initial trigger punches plus
/// all 5 periodic re-punches (worst case ~5 x 5s + the final quiet window,
/// so callers must budget ~35s of wall time for it).
async fn drain_periodic_budget(stream: &mut tonic::Streaming<SyncMessage>) {
    while next_punch(stream, SETTLED_SILENCE).await.is_ok() {}
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
    a.report(0, &[a_endpoint])
        .await
        .expect("A reports candidate");
    b.report(0, &[b_endpoint])
        .await
        .expect("B reports candidate");

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
    a.report(0, &[a_endpoint])
        .await
        .expect("A reports candidate");
    b.report(0, &[b_endpoint])
        .await
        .expect("B reports candidate");
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
    b.report(0, &["10.1.0.1:51820"])
        .await
        .expect("B reports candidate");

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
    a.report(0, &[a_endpoint])
        .await
        .expect("A reports candidate");
    b.report(0, &[b_endpoint])
        .await
        .expect("B reports candidate");
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

    a.report(0, &["10.0.0.1:51820"])
        .await
        .expect("A reports candidate");
    b.report(0, &["10.1.0.1:51820"])
        .await
        .expect("B reports candidate");

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
    a.report(0, &[a_endpoint])
        .await
        .expect("A reports candidate");
    b.report(0, &[b_endpoint])
        .await
        .expect("B reports candidate");
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
    a.report(0, &[a_endpoint])
        .await
        .expect("A reports candidate");
    b.report(0, &[b_endpoint])
        .await
        .expect("B reports candidate");
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

// --- Round 4: re-brokering on the settled -> unsettled EDGE ----------------
//
// The authoritative case-4 (relay-wedge) run exposed the remaining gap: a
// pair that SETTLES (both relayed) and later falls off the relay needs the
// broker to re-synchronize its direct punches — but by then the pair's
// periodic budget was exhausted during establishment and nothing ever
// resets it (candidate sets are unchanged, no reconnect happens). The
// broker knows the pair fell off settled the moment a member's snapshot
// report flips its stored peer state out of {direct, relayed} — that EDGE
// must (i) reset the pair's periodic budget and (ii) trigger an immediate
// synchronized emit for the pair. Crucially, ONLY the edge: a report that
// merely keeps an already-unsettled pair unsettled grants nothing (else
// every steady-state snapshot from a struggling pair would become a
// re-broker storm — the very thing the settled-skip fix ended).
//
// These three tests are authored ahead of the implementation: the first two
// are EXPECTED-RED at runtime against the current broker (they compile —
// no new API surface is needed at the wire level), the third pins the
// no-storm guard that must stay green before and after.

/// (round 4, a — RED) A settled pair with an EXHAUSTED periodic budget must
/// be re-punched on BOTH streams as soon as one member's snapshot report
/// unsettles it. Today: the budget is empty, the candidates are unchanged,
/// no reconnect happened — so nothing emits, ever, and the two gateways
/// are left punching on unsynchronized self-timers (the case-4 red).
#[tokio::test]
async fn unsettle_report_rebrokes_pair_despite_exhausted_budget() {
    let h = TestController::start().await;
    let a = enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = enroll_one(&h, "gcp", "10.1.0.0/16").await;

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

    // Exhaust the pair's periodic budget while it is still unsettled: the
    // sweep re-punches every 5s until MAX_PERIODIC_ATTEMPTS (5) is spent,
    // after which a full sweep interval of silence proves exhaustion.
    tokio::join!(
        drain_periodic_budget(&mut a_stream),
        drain_periodic_budget(&mut b_stream)
    );

    // NOW settle both sides (each marks the other "relayed" — the case-4
    // establishment shape). Settling consumes no budget and emits nothing.
    a.report_with_peer_paths(0, &[a_endpoint], &[(b.id(), "relayed")])
        .await
        .expect("A reports peer_paths relayed");
    b.report_with_peer_paths(0, &[b_endpoint], &[(a.id(), "relayed")])
        .await
        .expect("B reports peer_paths relayed");
    drain_punches(&mut a_stream).await;
    drain_punches(&mut b_stream).await;

    // The pair falls off the relay: B's next snapshot flips its stored peer
    // state to "disconnected" (same candidates — no candidate-change reset
    // can mask the edge trigger). settled -> unsettled: the broker must
    // reset the pair's budget AND emit a synchronized punch pair promptly.
    b.report_with_peer_paths(0, &[b_endpoint], &[(a.id(), "disconnected")])
        .await
        .expect("B reports the unsettling snapshot");

    let a_punch = next_punch(&mut a_stream, PUNCH_TIMEOUT)
        .await
        .expect("unsettle edge must re-broker the pair despite an exhausted budget: A got nothing");
    let b_punch = next_punch(&mut b_stream, PUNCH_TIMEOUT)
        .await
        .expect("unsettle edge must re-broker the pair despite an exhausted budget: B got nothing");
    assert_eq!(a_punch.peer_gateway_id, b.id(), "A's punch must target B");
    assert_eq!(b_punch.peer_gateway_id, a.id(), "B's punch must target A");
}

/// (round 4, b — RED) The unsettle edge must RESET the periodic budget, not
/// just fire a one-shot emit: after the edge, the still-unsettled pair gets
/// periodic re-punches again (each due within one 5s sweep). Distinct from
/// the test above because a one-shot-emit-only implementation would pass it
/// while leaving the pair with zero retry budget — one missed simultaneous
/// window (the norm under NAT jitter) and the pair is stranded again.
#[tokio::test]
async fn unsettle_edge_resets_periodic_budget_for_further_sweeps() {
    let h = TestController::start().await;
    let a = enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = enroll_one(&h, "gcp", "10.1.0.0/16").await;

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
    tokio::join!(
        drain_periodic_budget(&mut a_stream),
        drain_periodic_budget(&mut b_stream)
    );

    a.report_with_peer_paths(0, &[a_endpoint], &[(b.id(), "relayed")])
        .await
        .expect("A reports peer_paths relayed");
    b.report_with_peer_paths(0, &[b_endpoint], &[(a.id(), "relayed")])
        .await
        .expect("B reports peer_paths relayed");
    drain_punches(&mut a_stream).await;
    drain_punches(&mut b_stream).await;

    b.report_with_peer_paths(0, &[b_endpoint], &[(a.id(), "disconnected")])
        .await
        .expect("B reports the unsettling snapshot");

    // The edge-triggered emit itself...
    next_punch(&mut a_stream, PUNCH_TIMEOUT)
        .await
        .expect("edge-triggered punch missing on A");
    next_punch(&mut b_stream, PUNCH_TIMEOUT)
        .await
        .expect("edge-triggered punch missing on B");

    // ...and then the REFRESHED periodic budget: with the pair still
    // unsettled and candidates unchanged, at least two further periodic
    // re-punches must arrive on each stream (sweeps run every 5s; each is
    // comfortably inside PUNCH_TIMEOUT). Before the fix there is no budget
    // left, so this is where a one-shot implementation — and the current
    // broker — go red.
    for round in 1..=2 {
        next_punch(&mut a_stream, PUNCH_TIMEOUT)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "post-edge periodic re-punch #{round} missing on A (budget not reset?): {e:?}"
                )
            });
        next_punch(&mut b_stream, PUNCH_TIMEOUT)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "post-edge periodic re-punch #{round} missing on B (budget not reset?): {e:?}"
                )
            });
    }
}

/// (round 4, c — GREEN guard, must stay green) ONLY the settled->unsettled
/// EDGE re-brokers. A snapshot report that keeps an already-unsettled pair
/// unsettled — even one that CHANGES the stored state (connecting ->
/// disconnected, both outside {direct, relayed}) — must grant no fresh
/// budget and trigger no emit once the periodic budget is exhausted.
/// Otherwise every steady-state snapshot from a pair that is struggling to
/// connect would re-arm the punch storm the settled-skip fix ended.
#[tokio::test]
async fn report_keeping_pair_unsettled_grants_no_fresh_budget() {
    let h = TestController::start().await;
    let a = enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = enroll_one(&h, "gcp", "10.1.0.0/16").await;

    let mut a_stream = a.open_sync().await;
    let mut b_stream = b.open_sync().await;

    let a_endpoint = "10.0.0.1:51820";
    let b_endpoint = "10.1.0.1:51820";
    // Stored states are unsettled from the very first report — the pair
    // NEVER passes through settled, so no edge can ever legitimately fire.
    a.report_with_peer_paths(0, &[a_endpoint], &[(b.id(), "connecting")])
        .await
        .expect("A reports candidate + connecting peer state");
    b.report_with_peer_paths(0, &[b_endpoint], &[(a.id(), "connecting")])
        .await
        .expect("B reports candidate + connecting peer state");

    // Exhaust the periodic budget (the unsettled pair is re-punched by the
    // sweep until the 5 attempts are spent).
    tokio::join!(
        drain_periodic_budget(&mut a_stream),
        drain_periodic_budget(&mut b_stream)
    );

    // B's stored peer state CHANGES, but stays outside {direct, relayed}:
    // unsettled -> unsettled is not an edge. Same candidates, so no
    // candidate-change reset applies either. Nothing may emit across a full
    // sweep window on either stream.
    b.report_with_peer_paths(0, &[b_endpoint], &[(a.id(), "disconnected")])
        .await
        .expect("B reports a still-unsettled snapshot");

    let (a_after, b_after) = tokio::join!(
        next_punch(&mut a_stream, SETTLED_SILENCE),
        next_punch(&mut b_stream, SETTLED_SILENCE),
    );
    assert!(
        a_after.is_err(),
        "an unsettled->unsettled report must not re-arm the punch budget, but A received: \
         {a_after:?}"
    );
    assert!(
        b_after.is_err(),
        "an unsettled->unsettled report must not re-arm the punch budget, but B received: \
         {b_after:?}"
    );
}

// --- Sync session generation: rejecting a delayed pre-restart Report -------
//
// The race these six tests pin (see `Broker::on_report` and
// `SyncSvc::sessions`): `Broker::on_gateway_connected` CLEARS a reconnecting
// gateway's stored `peer_paths`, because a restarted gateway may have no
// tunnel at all and its stale "direct" claims must not suppress the punches
// it now needs. But a `Sync.Report` issued by that gateway's PREVIOUS process
// and delayed on the network can land AFTER the clear and — being a snapshot
// — REPLACE the fresh empty state with the pre-restart claims. The pair then
// looks settled to `emit_pair`, the synchronized punch is skipped, and
// nothing re-arms: the two gateways are left punching on unsynchronized
// self-timers, which a port-restricted pair never lands.
//
// The fix: the gateway stamps a per-BOOT nonce on `WatchRequest` AND every
// `ReportRequest`; `SyncSvc::watch_gateway` records it as its first statement
// (before the `on_gateway_connected` spawn that clears), and `SyncSvc::report`
// rejects a conflicting Report with `FAILED_PRECONDITION` before the broker
// ever sees it.
//
// The predicate is deliberately NOT "the values differ":
//
//     reject iff stored != 0 && req != 0 && stored != req
//
// Both zero-legs are load-bearing, and each has its own test below:
//
//   stored == 0  ->  report_before_any_watch_is_accepted_so_a_controller_
//                    restart_cannot_stall_the_fabric   (the fabric-wide one)
//   req    == 0  ->  legacy_zero_generation_client_behaves_exactly_as_today
//                    (all-zeros flow) plus
//                    nonzero_watch_followed_by_zero_generation_report_is_
//                    accepted (the mixed shape, which is the one a naive
//                    `stored != req` actually breaks)

/// `StubGateway::report_raw`'s error, recovered as the gRPC `Status` it
/// actually was. Fails loudly (rather than defaulting) when the failure was a
/// transport/dial error instead — that would mean the request never reached
/// the handler, so any conclusion about the handler's decision would be
/// unfounded.
fn status_of(err: &anyhow::Error) -> &tonic::Status {
    err.downcast_ref::<tonic::Status>().unwrap_or_else(|| {
        panic!(
            "Sync.Report must have failed with a gRPC Status (the controller's decision), but \
             the request failed before reaching the handler: {err:#}"
        )
    })
}

/// The `applied_version` the controller currently holds for `gateway_id`,
/// read back through the real `Admin.ListGateways` surface (`GatewayInfo`).
async fn applied_version_of(h: &TestController, gateway_id: u64) -> u64 {
    let roster = h
        .admin_client()
        .await
        .list_gateways(ListGatewaysRequest {})
        .await
        .expect("Admin.ListGateways")
        .into_inner()
        .gateways;
    roster
        .iter()
        .find(|g| g.id == gateway_id)
        .unwrap_or_else(|| panic!("gateway {gateway_id} missing from the roster: {roster:?}"))
        .applied_version
}

/// Drives `a` and `b` (already watching, on `a_stream`/`b_stream`) to the
/// both-settled state the stale-report race attacks: each reports its
/// candidate, the legitimate pre-settlement punch pair is consumed, each then
/// reports the OTHER as "direct", and the streams are drained to quiet.
/// `applied_version` is what both sides report, so a caller can later assert
/// it was NOT overwritten by a rejected report.
async fn settle_pair(
    a: &StubGateway,
    b: &StubGateway,
    a_stream: &mut tonic::Streaming<SyncMessage>,
    b_stream: &mut tonic::Streaming<SyncMessage>,
    a_endpoint: &str,
    b_endpoint: &str,
    applied_version: u64,
) {
    a.report(applied_version, &[a_endpoint])
        .await
        .expect("A reports candidate");
    b.report(applied_version, &[b_endpoint])
        .await
        .expect("B reports candidate");
    next_punch(a_stream, PUNCH_TIMEOUT)
        .await
        .expect("A must receive the initial pre-settlement punch");
    next_punch(b_stream, PUNCH_TIMEOUT)
        .await
        .expect("B must receive the initial pre-settlement punch");

    a.report_with_peer_paths(applied_version, &[a_endpoint], &[(b.id(), "direct")])
        .await
        .expect("A reports peer_paths direct");
    b.report_with_peer_paths(applied_version, &[b_endpoint], &[(a.id(), "direct")])
        .await
        .expect("B reports peer_paths direct");
    drain_punches(a_stream).await;
    drain_punches(b_stream).await;
}

/// (1 — THE REGRESSION TEST) A `Sync.Report` carrying the generation of a
/// gateway's PREVIOUS process must be rejected with `FAILED_PRECONDITION`,
/// and must not resettle the pair the restart just reopened.
///
/// The wire sequence is exactly the production race, with the network delay
/// collapsed to "sent after the reconnect" (which is all the race needs):
/// A+B settle direct/direct → B's Watch drops → B's process restarts (new
/// nonce) and re-watches, whose `clear_reported_states` reopens the pair →
/// B's pre-restart Report finally arrives, claiming `(A, direct)` as a
/// snapshot.
///
/// Note A never reconnects, so A's stored "B is direct" survives throughout:
/// the pair is one-sided (punchable) after the clear, and the stale report is
/// the ONE thing that could make it look both-settled again. That is why the
/// punch assertion at the end is not incidental — with the report accepted,
/// `emit_pair`'s settled skip suppresses every punch, periodic sweeps
/// included, and the pair is stranded.
#[tokio::test]
async fn stale_generation_report_cannot_resettle_a_restarted_gateways_pair() {
    let h = TestController::start().await;
    let a = enroll_one(&h, "aws", "10.0.0.0/16").await;
    let mut b = enroll_one(&h, "gcp", "10.1.0.0/16").await;

    let mut a_stream = a.open_sync().await;
    let mut b_stream = b.open_sync().await;

    let a_endpoint = "10.0.0.1:51820";
    let b_endpoint = "10.1.0.1:51820";
    settle_pair(
        &a,
        &b,
        &mut a_stream,
        &mut b_stream,
        a_endpoint,
        b_endpoint,
        0,
    )
    .await;

    // B's PREVIOUS process's nonce — captured BEFORE the restart, because
    // that is the value the delayed report carries.
    let stale_generation = b.session_generation();
    assert_ne!(
        stale_generation, 0,
        "the stub must send a NONZERO generation like a real gateway — a 0 would make the \
         controller's gate inert and this test vacuous"
    );

    // B's process dies (its Watch stream drops)...
    drop(b_stream);
    tokio::time::sleep(Duration::from_secs(1)).await;
    // ...and a NEW process comes up with a fresh nonce and re-watches. That
    // Watch open both records the new generation and clears B's stored path
    // states, so the pair is punchable again.
    b.set_session_generation(stale_generation.checked_add(1).unwrap_or(1));
    let mut b_stream2 = b.open_sync().await;

    // Consume the reconnect-triggered punches, so what we assert afterwards
    // is attributable to the state AFTER the stale report, not to stragglers.
    drain_punches(&mut a_stream).await;
    drain_punches(&mut b_stream2).await;

    // The delayed pre-restart report finally lands. Same shape B's old
    // process was sending: a full path snapshot claiming the pair is direct.
    let err = b
        .report_raw(ReportRequest {
            applied_version: 0,
            local_endpoints: vec![b_endpoint.to_string()],
            relay_health: vec![],
            epoch_acks: vec![],
            peer_paths: vec![PeerPath {
                peer_gateway_id: a.id(),
                state: "direct".into(),
            }],
            peer_paths_snapshot: true,
            session_generation: stale_generation,
        })
        .await
        .expect_err(
            "a Report carrying the PREVIOUS process's session_generation must be REJECTED — \
             accepting it re-installs the stale peer_paths that B's reconnect just cleared",
        );
    assert_eq!(
        status_of(&err).code(),
        tonic::Code::FailedPrecondition,
        "a stale-generation Report must be rejected with FAILED_PRECONDITION (the whole \
         handler is gated, before Broker::on_report), got: {err:#}"
    );

    // ...and the pair is still punchable: the clear STUCK.
    let a_punch = next_punch(&mut a_stream, PUNCH_TIMEOUT).await.expect(
        "after B's restart the pair must keep being punched — a rejected stale report must \
         not have resettled it: A got nothing",
    );
    let b_punch = next_punch(&mut b_stream2, PUNCH_TIMEOUT).await.expect(
        "after B's restart the pair must keep being punched — a rejected stale report must \
         not have resettled it: B got nothing",
    );
    assert_eq!(a_punch.peer_gateway_id, b.id(), "A's punch must target B");
    assert_eq!(b_punch.peer_gateway_id, a.id(), "B's punch must target A");
}

/// (2 — POSITIVE CONTROL) A Report whose generation MATCHES the one recorded
/// at the gateway's live Watch is accepted and takes full effect.
///
/// Without this, a gate that rejected everything (or a `record_session_
/// generation` that never ran) would still pass test (1) — silence and
/// rejection look identical from the "no stale resettle" side. Here the
/// accepted report must actually SETTLE the pair, i.e. reach
/// `Broker::on_report` and be stored.
#[tokio::test]
async fn matching_generation_report_is_accepted_and_settles() {
    let h = TestController::start().await;
    let a = enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = enroll_one(&h, "gcp", "10.1.0.0/16").await;

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
    next_punch(&mut a_stream, PUNCH_TIMEOUT)
        .await
        .expect("A must receive the initial pre-settlement punch");
    next_punch(&mut b_stream, PUNCH_TIMEOUT)
        .await
        .expect("B must receive the initial pre-settlement punch");

    // B settles via `report_raw` with its CURRENT generation spelled out
    // explicitly — the same value its live Watch recorded.
    b.report_raw(ReportRequest {
        applied_version: 0,
        local_endpoints: vec![b_endpoint.to_string()],
        relay_health: vec![],
        epoch_acks: vec![],
        peer_paths: vec![PeerPath {
            peer_gateway_id: a.id(),
            state: "direct".into(),
        }],
        peer_paths_snapshot: true,
        session_generation: b.session_generation(),
    })
    .await
    .expect(
        "a Report whose session_generation matches the generation recorded at this gateway's \
         LIVE Watch must be accepted — rejecting it would stop candidate publication and path \
         reporting for every healthy gateway",
    );
    a.report_with_peer_paths(0, &[a_endpoint], &[(b.id(), "direct")])
        .await
        .expect("A reports peer_paths direct");

    drain_punches(&mut a_stream).await;
    drain_punches(&mut b_stream).await;

    // The accepted report reached the broker: the pair is settled, so a full
    // periodic sweep window passes in silence.
    let (a_quiet, b_quiet) = tokio::join!(
        next_punch(&mut a_stream, SETTLED_SILENCE),
        next_punch(&mut b_stream, SETTLED_SILENCE),
    );
    assert!(
        a_quiet.is_err(),
        "the matching-generation report must have been APPLIED (settling the pair), but A was \
         re-punched: {a_quiet:?}"
    );
    assert!(
        b_quiet.is_err(),
        "the matching-generation report must have been APPLIED (settling the pair), but B was \
         re-punched: {b_quiet:?}"
    );
}

/// (3 — LEGACY LEG of the predicate) A client that implements NONE of the
/// scheme — 0 on its `WatchRequest` and 0 on every `ReportRequest` — behaves
/// exactly as it did before the gate existed.
///
/// HONEST LIMIT of this test: 0 == 0, so a naive `stored != req` predicate
/// would also pass it. What it guards is the coarser regression — a "reject
/// anything that is not the recorded nonzero generation" tightening, which
/// would lock every legacy gateway out of `Sync.Report` on upgrade. The
/// `req != 0` conjunct itself is pinned by
/// `nonzero_watch_followed_by_zero_generation_report_is_accepted`, where the
/// two sides genuinely differ.
#[tokio::test]
async fn legacy_zero_generation_client_behaves_exactly_as_today() {
    let h = TestController::start().await;
    let mut a = enroll_one(&h, "aws", "10.0.0.0/16").await;
    let mut b = enroll_one(&h, "gcp", "10.1.0.0/16").await;

    // 0 = the wire's legacy/unknown sentinel, on BOTH the Watch (set before
    // `open_sync`, which is what records it) and every Report.
    a.set_session_generation(0);
    b.set_session_generation(0);

    let mut a_stream = a.open_sync().await;
    let mut b_stream = b.open_sync().await;

    let a_endpoint = "10.0.0.1:51820";
    let b_endpoint = "10.1.0.1:51820";
    // Every step below is byte-for-byte what
    // `both_settled_pair_skips_periodic_and_candidate_change_repunch` does —
    // the point is that a zero-generation client's flow is unchanged.
    settle_pair(
        &a,
        &b,
        &mut a_stream,
        &mut b_stream,
        a_endpoint,
        b_endpoint,
        0,
    )
    .await;

    let (a_quiet, b_quiet) = tokio::join!(
        next_punch(&mut a_stream, SETTLED_SILENCE),
        next_punch(&mut b_stream, SETTLED_SILENCE),
    );
    assert!(
        a_quiet.is_err(),
        "a legacy (generation-0) client's settled pair must skip the periodic sweep exactly as \
         before the gate existed, but A received: {a_quiet:?}"
    );
    assert!(
        b_quiet.is_err(),
        "a legacy (generation-0) client's settled pair must skip the periodic sweep exactly as \
         before the gate existed, but B received: {b_quiet:?}"
    );
}

/// (4 — THE UNKNOWN/CONTROLLER-RESTART LEG: the highest-consequence line in
/// the whole item) A Report from a gateway the controller has NO recorded
/// generation for must be ACCEPTED, even though the report's own generation
/// is nonzero and therefore "differs" from the stored 0.
///
/// `SyncSvc::sessions` is IN-MEMORY and deliberately not persisted, so a
/// CONTROLLER restart empties it while every gateway's Watch is still
/// reconnecting. "No recorded generation" is that window. A predicate of
/// plain `stored != req` would reject EVERY Report from EVERY gateway in it:
/// candidate publication stops, the broker stops learning path states,
/// punches stop, and the whole fabric degrades — a broad availability outage
/// traded for a narrow correctness race. Unknown must fail OPEN.
///
/// Reporting before ever opening a Watch is the cheapest faithful proxy for
/// that window: from `SyncSvc::report`'s point of view the two are the same
/// state — `recorded_session_generation` returns 0 — and it is the ONLY
/// input the predicate has. The report's CONTENT is checked too (via
/// `Admin.ListGateways`), so a gate that "accepted" by silently discarding
/// the request could not pass.
#[tokio::test]
async fn report_before_any_watch_is_accepted_so_a_controller_restart_cannot_stall_the_fabric() {
    let h = TestController::start().await;
    let gw = enroll_one(&h, "aws", "10.0.0.0/16").await;

    // Deliberately NO `open_sync()`: nothing has ever recorded a generation
    // for this gateway, exactly as after a controller restart.
    let generation = gw.session_generation();
    assert_ne!(
        generation, 0,
        "the request side must be NONZERO or this test proves nothing"
    );

    gw.report_raw(ReportRequest {
        applied_version: 42,
        local_endpoints: vec!["10.0.0.1:51820".to_string()],
        relay_health: vec![],
        epoch_acks: vec![],
        peer_paths: vec![],
        peer_paths_snapshot: false,
        session_generation: generation,
    })
    .await
    .unwrap_or_else(|e| {
        panic!(
            "a Report must be ACCEPTED when the controller has no recorded generation for the \
             gateway (stored == 0). This is the controller-restart window: rejecting here \
             stops candidate publication, path reporting and punching for the ENTIRE fabric \
             until every gateway's Watch reconnects. Unknown must fail OPEN. Got: {e:#}"
        )
    });

    assert_eq!(
        applied_version_of(&h, gw.id()).await,
        42,
        "the accepted report must have been APPLIED, not merely not-rejected — the \
         controller-restart window needs reports to keep WORKING, not to be silently dropped"
    );
}

/// (5 — WHOLE-HANDLER GATING) A rejected report must touch NOTHING: the gate
/// sits ahead of `Broker::on_report`, `set_applied_version` AND
/// `set_local_candidates`.
///
/// This matters because `local_endpoints` is the ORIGINAL instance of this
/// stale-report race (it predates `peer_paths` entirely), and it is the field
/// with the nastiest failure mode: it has full-REPLACE semantics and its new
/// value is PUBLISHED to peers as punch candidates. A partially-gated handler
/// that rejected only the path states would still let a dead process's
/// address become the address every peer punches toward.
///
/// Same restart sequence as test (1); the stale report additionally claims a
/// bumped `applied_version` and a bogus candidate address. Both must be
/// invisible afterwards: through `Admin.ListGateways` for the version, and
/// through the peer's next `PunchDirective.candidates` for the endpoint (the
/// broker reads B's candidates straight out of the DB when building A's
/// directive, so this is the real consumer, not a proxy for it).
#[tokio::test]
async fn a_rejected_report_touches_no_other_state() {
    let h = TestController::start().await;
    let a = enroll_one(&h, "aws", "10.0.0.0/16").await;
    let mut b = enroll_one(&h, "gcp", "10.1.0.0/16").await;

    let mut a_stream = a.open_sync().await;
    let mut b_stream = b.open_sync().await;

    let a_endpoint = "10.0.0.1:51820";
    let b_endpoint = "10.1.0.1:51820";
    // A distinctive non-default applied_version, so "unchanged" is
    // distinguishable from "reset to 0" as well as from "overwritten by 99".
    const SETTLED_VERSION: u64 = 7;
    // Never reported by anyone honest — if this reaches a PunchDirective it
    // can only have come from the rejected report.
    const BOGUS_ENDPOINT: &str = "203.0.113.9:51820";
    settle_pair(
        &a,
        &b,
        &mut a_stream,
        &mut b_stream,
        a_endpoint,
        b_endpoint,
        SETTLED_VERSION,
    )
    .await;

    let stale_generation = b.session_generation();
    drop(b_stream);
    tokio::time::sleep(Duration::from_secs(1)).await;
    b.set_session_generation(stale_generation.checked_add(1).unwrap_or(1));
    let mut b_stream2 = b.open_sync().await;
    drain_punches(&mut a_stream).await;
    drain_punches(&mut b_stream2).await;

    // B never reports again after the restart, so anything observed below
    // that differs from the settled state can only have come from the stale
    // report.
    let err = b
        .report_raw(ReportRequest {
            applied_version: 99,
            local_endpoints: vec![BOGUS_ENDPOINT.to_string()],
            relay_health: vec![],
            epoch_acks: vec![],
            peer_paths: vec![PeerPath {
                peer_gateway_id: a.id(),
                state: "direct".into(),
            }],
            peer_paths_snapshot: true,
            session_generation: stale_generation,
        })
        .await
        .expect_err("the stale-generation report must be rejected");
    assert_eq!(
        status_of(&err).code(),
        tonic::Code::FailedPrecondition,
        "expected FAILED_PRECONDITION, got: {err:#}"
    );

    assert_eq!(
        applied_version_of(&h, b.id()).await,
        SETTLED_VERSION,
        "a rejected report must not reach `set_applied_version` — the gate covers the WHOLE \
         handler, not just the broker call"
    );

    // The candidate leg: A's next directive carries B's candidates, read from
    // the DB at emit time. The bogus address must be nowhere in it.
    let a_punch = next_punch(&mut a_stream, PUNCH_TIMEOUT).await.expect(
        "the pair must still be punched after the rejected report (see \
         stale_generation_report_cannot_resettle_a_restarted_gateways_pair): A got nothing",
    );
    assert_eq!(a_punch.peer_gateway_id, b.id(), "A's punch must target B");
    assert!(
        !a_punch
            .candidates
            .iter()
            .any(|c| c.as_str() == BOGUS_ENDPOINT),
        "a rejected report must not reach `set_local_candidates`: the dead process's address \
         {BOGUS_ENDPOINT} was published to B's peer as a punch candidate ({:?})",
        a_punch.candidates
    );
    assert!(
        a_punch.candidates.iter().any(|c| c.as_str() == b_endpoint),
        "B's genuine candidate {b_endpoint} must survive the rejection untouched (a rejected \
         report must not CLEAR the candidate set either — local_endpoints has full-REPLACE, \
         empty-clears semantics); got: {:?}",
        a_punch.candidates
    );
}

/// (6 — the OTHER half of the legacy leg, and the one that can actually go
/// RED) A gateway whose Watch recorded a NONZERO generation may still send a
/// Report carrying 0, and it must be accepted.
///
/// Test (3) pins the all-zeros flow, but two zeros compare EQUAL, so a naive
/// `stored != req` predicate passes it. This mixed shape is where the
/// `req != 0` conjunct is genuinely load-bearing: `stored` is nonzero,
/// `req` is 0, and they differ — a naive predicate rejects.
///
/// It is not hypothetical. `wiremesh-testkit/tests/end_to_end_policy.rs`'s
/// `full_pipeline_apply_sync_enforce_report` produces exactly this shape
/// today: it calls `gw.open_sync()` (nonzero nonce recorded) and later drives
/// its own hand-rolled raw `Sync.Report` client — one that predates
/// `StubGateway::report` and sends 0. (`fabricctl/tests/cli.rs` keeps the
/// same hand-rolled client but never opens a Watch, so it exercises the
/// `stored == 0` leg instead.) In production this is the shape of a
/// partially-upgraded gateway, or any third-party client built against the
/// pre-scheme proto.
#[tokio::test]
async fn nonzero_watch_followed_by_zero_generation_report_is_accepted() {
    let h = TestController::start().await;
    let gw = enroll_one(&h, "aws", "10.0.0.0/16").await;

    // The Watch records this gateway's nonzero nonce controller-side.
    let _stream = gw.open_sync().await;
    assert_ne!(
        gw.session_generation(),
        0,
        "the WATCH side must be nonzero or this test degenerates into test (3)"
    );

    gw.report_raw(ReportRequest {
        applied_version: 5,
        local_endpoints: vec!["10.0.0.1:51820".to_string()],
        relay_health: vec![],
        epoch_acks: vec![],
        peer_paths: vec![],
        peer_paths_snapshot: false,
        // The legacy/unknown sentinel, against a NONZERO recorded generation.
        session_generation: 0,
    })
    .await
    .unwrap_or_else(|e| {
        panic!(
            "a Report carrying the 0 legacy sentinel must be ACCEPTED even when the gateway's \
             Watch recorded a nonzero generation — 0 means 'no opinion', not 'conflict'. \
             Rejecting it locks out every client that has not adopted the scheme. Got: {e:#}"
        )
    });

    assert_eq!(
        applied_version_of(&h, gw.id()).await,
        5,
        "the accepted legacy report must have been APPLIED, not silently discarded"
    );
}
