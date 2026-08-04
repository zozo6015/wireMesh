//! Task 2's failing test: `Sync.SubmitEpochKey(epoch, pubkey)` lets a
//! gateway submit the REAL WireGuard public key it generated for a pending
//! rotation epoch, overwriting the `Db::rotate_key`-inserted sentinel
//! (`"awaiting-submission"`) that Task 2 replaces today's fake
//! `placeholder-pubkey-gw{id}-epoch{n}` value with.
//!
//! Exercises the whole real path: `Admin.RotateKey` inserts the pending row
//! (sentinel pubkey), the gateway calls `Sync.SubmitEpochKey` over its own
//! mTLS identity to overwrite the sentinel with its real pubkey, and
//! `Admin.DebugKeyStates` (extended by Task 2 to also carry the pubkey) is
//! used throughout to observe the DB-backed state.
//!
//! This file will not even COMPILE until Task 2 lands:
//!   - `TestController::debug_key_states` must return `Vec<(u32, String,
//!     String)>` = `(epoch, pubkey, state)` (today it returns `Vec<(u32,
//!     String)>` = `(epoch, state)`, with no pubkey);
//!   - `StubGateway::submit_epoch_key(&self, epoch, pubkey)` does not exist
//!     yet (mirrors the existing `StubGateway::report` method: a fresh mTLS
//!     `SyncClient` using the gateway's own identity, calling the
//!     newly-real `Sync.SubmitEpochKey`, which as of Task 1 is stubbed to
//!     `Err(Status::unimplemented(..))`).
//! That compile failure is the expected RED for this task.

use std::time::Duration;

use wiremesh_proto::v1::{sync_message, Delta, RotateKeyRequest, SubmitEpochKeyRequest, SyncMessage};
use wiremesh_testkit::{enroll_one, StubGateway, TestController};

/// A gateway can submit its real pubkey for a pending epoch, and that
/// submission overwrites the `"awaiting-submission"` sentinel WITHOUT
/// promoting the epoch out of `pending` state (promotion is Task 3's job,
/// not this RPC's).
#[tokio::test]
async fn rotate_then_submit_replaces_sentinel_with_real_pubkey() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;

    // Pre-rotation: gateway A already has its epoch-0 baseline key, active.
    let pre_states = h.debug_key_states(a.id()).await;
    assert!(
        pre_states
            .iter()
            .any(|(epoch, _pubkey, state)| *epoch == 0 && state == "active"),
        "expected gateway A to already have an active epoch-0 key before any \
         rotation, got: {pre_states:?}"
    );

    h.admin_client()
        .await
        .rotate_key(RotateKeyRequest {
            gateway_id: a.id(),
        })
        .await
        .expect("Admin.RotateKey(gateway_id = a.id()) must succeed");

    // After rotation: a NEW pending row exists, carrying the sentinel
    // pubkey (not yet a real key — the gateway hasn't submitted one), and
    // the epoch-0 active row is untouched.
    let post_rotate_states = h.debug_key_states(a.id()).await;
    let (pending_epoch, pending_pubkey, pending_state) = post_rotate_states
        .iter()
        .max_by_key(|(epoch, _, _)| *epoch)
        .unwrap_or_else(|| {
            panic!(
                "expected at least one GATEWAY_KEY row for gateway A after rotation, \
                 got: {post_rotate_states:?}"
            )
        });
    assert_eq!(
        pending_state, "pending",
        "expected the highest-epoch row after Admin.RotateKey to be 'pending', got \
         states: {post_rotate_states:?}"
    );
    assert_eq!(
        pending_pubkey, "awaiting-submission",
        "expected Db::rotate_key to insert the 'awaiting-submission' sentinel pubkey \
         for the new pending epoch (not a real key yet, and not the old cycle-2 \
         placeholder-pubkey-gw{{id}}-epoch{{n}} fake), got states: {post_rotate_states:?}"
    );
    let pending_epoch = *pending_epoch;
    assert!(
        post_rotate_states
            .iter()
            .any(|(epoch, _pubkey, state)| *epoch == 0 && state == "active"),
        "expected the pre-rotation active epoch-0 key to remain untouched by \
         Admin.RotateKey, got states: {post_rotate_states:?}"
    );

    // The gateway submits its real pubkey for the pending epoch.
    a.submit_epoch_key(pending_epoch, "REALKEY==")
        .await
        .expect("Sync.SubmitEpochKey must succeed for a genuinely pending, \
                 sentinel-holding epoch");

    // The sentinel must now be overwritten with the real pubkey, and the
    // epoch must STILL be 'pending' — submitting a key is not the same as
    // promoting it (that's Task 3's job).
    let post_submit_states = h.debug_key_states(a.id()).await;
    let (_epoch, submitted_pubkey, submitted_state) = post_submit_states
        .iter()
        .find(|(epoch, _, _)| *epoch == pending_epoch)
        .unwrap_or_else(|| {
            panic!(
                "expected epoch {pending_epoch} to still be present after \
                 Sync.SubmitEpochKey, got states: {post_submit_states:?}"
            )
        });
    assert_eq!(
        submitted_pubkey, "REALKEY==",
        "expected Sync.SubmitEpochKey to overwrite the 'awaiting-submission' sentinel \
         with the gateway-submitted real pubkey, got states: {post_submit_states:?}"
    );
    assert_eq!(
        submitted_state, "pending",
        "submitting an epoch key must NOT promote it out of 'pending' — promotion is \
         Task 3's job, not Sync.SubmitEpochKey's — got states: {post_submit_states:?}"
    );
    assert!(
        post_submit_states
            .iter()
            .any(|(epoch, _pubkey, state)| *epoch == 0 && state == "active"),
        "expected the epoch-0 active key to remain untouched by Sync.SubmitEpochKey, \
         got states: {post_submit_states:?}"
    );
}

/// Submitting a key for an epoch that has no matching pending,
/// sentinel-holding `GATEWAY_KEY` row (here: an epoch that was never
/// created by a rotation at all) must be rejected rather than silently
/// accepted or silently no-op'd.
#[tokio::test]
async fn submit_to_nonexistent_epoch_is_rejected() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;

    let result = a.submit_epoch_key(999, "X==").await;
    assert!(
        result.is_err(),
        "expected Sync.SubmitEpochKey(epoch = 999) to fail for gateway A, which has no \
         pending epoch 999 (no rotation was ever started), got: {result:?}"
    );
}

// --- Sync session generation on Sync.SubmitEpochKey -----------------------
//
// `SubmitEpochKey` was the one mutating gateway->controller RPC the
// session-generation gate did not cover, and the gap is a live rotation
// wedge, not a theoretical one.
//
// `Db::set_epoch_pubkey` is a compare-and-swap: its `WHERE` requires
// `state = 'pending' AND pubkey = 'awaiting-submission'`, so a stale
// submission can never CLOBBER a real key. What it can do is WIN that swap.
// A gateway process that mints its epoch key, persists it, and dies with the
// submission still in flight leaves the pending row holding the sentinel; the
// broker therefore re-issues the `RotateDirective`; the new process mints a
// DIFFERENT key and submits it for the same epoch; and whichever lands first
// takes the row — usually the pre-restart one, because it was sent first.
//
// The controller then advertises a pubkey the live gateway is not serving on
// that epoch's tun. No peer can establish a session with it, so no peer can
// ever ack it — and it does not fail safe: `rotation::decide` rule 4 promotes
// on the 90s grace REGARDLESS of ack state, so the dead key goes `active`
// instead of the rotation aborting (see
// `docs/research/key-rotation-teardown-notes.md` §E).
//
// The gate makes the FRESH submission the winner. These four tests pin the
// rejection, the two fail-open legs, and — the assertion that actually
// matters — that a rejected submission leaves the sentinel UNWRITTEN and
// fans nothing out to peers.

/// The sentinel `Db::rotate_key` parks in a freshly-pending epoch's row until
/// the gateway submits a real key. Duplicated as a literal rather than
/// imported: `db::AWAITING_SUBMISSION_SENTINEL` is `pub(crate)`, and the rest
/// of this file already spells it out the same way.
const SENTINEL: &str = "awaiting-submission";

/// The key A's PREVIOUS process minted and had in flight when it died.
const STALE_KEY: &str = "STALE-PRE-RESTART-KEY==";
/// The key A's CURRENT process minted after coming back up.
const FRESH_KEY: &str = "FRESH-POST-RESTART-KEY==";

/// Long enough that a delta the controller DID publish would have arrived
/// (the publish is synchronous with the RPC, then one broadcast hop).
const DELTA_WINDOW: Duration = Duration::from_secs(2);

/// `submit_epoch_key_raw`'s error, recovered as the gRPC `Status` it actually
/// was. Panics if the call failed before reaching the handler — a transport
/// error would make any claim about the controller's DECISION unfounded.
/// (Local copy: each `tests/*.rs` is its own binary, so this cannot be shared
/// with `broker_pathstate.rs`'s identical helper.)
fn status_of(err: &anyhow::Error) -> &tonic::Status {
    err.downcast_ref::<tonic::Status>().unwrap_or_else(|| {
        panic!(
            "Sync.SubmitEpochKey must have failed with a gRPC Status (the controller's \
             decision), but the request failed before reaching the handler: {err:#}"
        )
    })
}

/// `(pubkey, state)` currently stored for `epoch`, via `Admin.DebugKeyStates`.
async fn epoch_row(h: &TestController, gateway_id: u64, epoch: u32) -> (String, String) {
    let states = h.debug_key_states(gateway_id).await;
    states
        .iter()
        .find(|(e, _, _)| *e == epoch)
        .map(|(_, pubkey, state)| (pubkey.clone(), state.clone()))
        .unwrap_or_else(|| {
            panic!("expected epoch {epoch} to still exist for gateway {gateway_id}: {states:?}")
        })
}

/// Starts a rotation for `gateway_id` and returns the new pending epoch,
/// asserting it holds the sentinel — the exact row state the CAS races over.
async fn rotate_and_pending_epoch(h: &TestController, gateway_id: u64) -> u32 {
    h.admin_client()
        .await
        .rotate_key(RotateKeyRequest { gateway_id })
        .await
        .expect("Admin.RotateKey must succeed");

    let states = h.debug_key_states(gateway_id).await;
    let (epoch, pubkey, state) = states
        .iter()
        .max_by_key(|(epoch, _, _)| *epoch)
        .unwrap_or_else(|| panic!("no GATEWAY_KEY rows after rotation: {states:?}"));
    assert_eq!(state, "pending", "the freshly rotated epoch must be pending: {states:?}");
    assert_eq!(
        pubkey, SENTINEL,
        "the freshly rotated epoch must hold the sentinel — this fixture exists to race the \
         swap ONTO it: {states:?}"
    );
    *epoch
}

/// Reads `stream` until it has been quiet for `quiet`, discarding everything.
/// Breaks on stream end/error too, so a closed stream can never spin.
async fn drain_quiet(stream: &mut tonic::Streaming<SyncMessage>, quiet: Duration) {
    loop {
        match tokio::time::timeout(quiet, stream.message()).await {
            Ok(Ok(Some(_))) => continue,
            _ => break,
        }
    }
}

/// The first `Delta` on `stream` within `window` that upserts `gateway_id` as
/// a peer, or `None`. That delta is `emit_key_rotated`'s observable
/// signature: `ChangeEvent::KeyRotated` projects to exactly one
/// `upserted_peers` entry for the rotating gateway
/// (`projection::delta_for_change`).
async fn next_delta_upserting(
    stream: &mut tonic::Streaming<SyncMessage>,
    gateway_id: u64,
    window: Duration,
) -> Option<Delta> {
    let deadline = tokio::time::Instant::now() + window;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        match tokio::time::timeout(remaining, stream.message()).await {
            Ok(Ok(Some(msg))) => match msg.body {
                Some(sync_message::Body::Delta(d))
                    if d.upserted_peers.iter().any(|p| p.gateway_id == gateway_id) =>
                {
                    return Some(d)
                }
                _ => continue,
            },
            _ => return None,
        }
    }
}

/// The shared fixture: gateway A is mid-rotation (pending epoch holding the
/// sentinel) and has RESTARTED with its submission still in flight, so the
/// stale nonce and the live nonce both exist. Gateway B is a connected peer,
/// drained to quiet, standing in for "does anything get fanned out".
struct RotationAcrossRestart {
    a: StubGateway,
    /// The RESTARTED process's Watch. Held only to keep A registered under
    /// the NEW generation for the life of the test.
    _a_stream: tonic::Streaming<SyncMessage>,
    /// The peer itself, held only so its lifetime outlives `b_stream`'s (its
    /// `Drop` removes an on-disk temp state dir; nothing the open channel
    /// needs, but keeping the pair together avoids relying on that).
    _b: StubGateway,
    /// A peer's Watch, already drained past the rotation's own delta.
    b_stream: tonic::Streaming<SyncMessage>,
    pending_epoch: u32,
    /// What A's PREVIOUS process stamps on its in-flight submission.
    stale_generation: u64,
}

async fn rotation_in_flight_across_a_gateway_restart(h: &TestController) -> RotationAcrossRestart {
    let mut a = enroll_one(h, "aws", "10.0.0.0/16").await;
    let b = enroll_one(h, "gcp", "10.1.0.0/16").await;

    let mut b_stream = b.open_sync().await;
    // A's ORIGINAL process registers its generation.
    let a_stream_before_restart = a.open_sync().await;

    let pending_epoch = rotate_and_pending_epoch(h, a.id()).await;

    // The nonce the in-flight submission carries.
    let stale_generation = a.session_generation();
    assert_ne!(
        stale_generation, 0,
        "the stub must send a NONZERO generation like a real gateway, or the gate is inert \
         and every test built on this fixture is vacuous"
    );

    // A dies with its submission in flight, and a new process comes up: fresh
    // nonce, fresh Watch. The Watch open is what RECORDS the new generation,
    // which is what makes the old one stale.
    drop(a_stream_before_restart);
    tokio::time::sleep(Duration::from_secs(1)).await;
    a.set_session_generation(stale_generation.checked_add(1).unwrap_or(1));
    let a_stream = a.open_sync().await;

    // Consume B's initial snapshot and the delta `Admin.RotateKey` already
    // published, so anything seen later is attributable to the submission.
    drain_quiet(&mut b_stream, DELTA_WINDOW).await;

    RotationAcrossRestart {
        a,
        _a_stream: a_stream,
        _b: b,
        b_stream,
        pending_epoch,
        stale_generation,
    }
}

/// (c — THE ASSERTION THAT MATTERS) A submission carrying the previous
/// process's generation is rejected with `FAILED_PRECONDITION`, and — the
/// part that is not merely restating the RPC's return value — the pending
/// epoch's row is STILL holding the sentinel afterwards. The stale key was
/// never written.
///
/// Checking only that the RPC errored would be near-worthless here:
/// `Db::set_epoch_pubkey` errors with `FailedPrecondition` ("no pending
/// epoch") whenever the row is already claimed, so a test that asserted only
/// the error code would pass for entirely the wrong reason the moment
/// anything else won the swap first.
///
/// The third phase is the anti-vacuity control, and it is what makes the
/// sentinel assertion mean something: A's CURRENT process submits a
/// DIFFERENT key with its matching generation and that submission SUCCEEDS.
/// So the row was genuinely claimable at the instant the stale one was
/// refused — the sentinel survived because the gate refused the write, not
/// because the row was unavailable.
///
/// Sabotage: delete the `check_session_generation` call in
/// `SyncSvc::submit_epoch_key`. The stale submission then wins the swap, the
/// `expect_err` fails immediately, and (had it not) the sentinel assertion
/// would find `STALE_KEY` in the row — and the fresh submission would then
/// fail with "no pending epoch", reddening a third time.
#[tokio::test]
async fn stale_generation_submission_is_rejected_and_the_sentinel_survives() {
    let h = TestController::start().await;
    let f = rotation_in_flight_across_a_gateway_restart(&h).await;

    let err = f
        .a
        .submit_epoch_key_raw(SubmitEpochKeyRequest {
            epoch: f.pending_epoch,
            pubkey: STALE_KEY.to_string(),
            session_generation: f.stale_generation,
        })
        .await
        .expect_err(
            "a SubmitEpochKey carrying the PREVIOUS process's session_generation must be \
             REJECTED — accepting it installs a key the live gateway is not serving, which no \
             peer can ack and which rule 4 promotes anyway on the grace timeout",
        );
    assert_eq!(
        status_of(&err).code(),
        tonic::Code::FailedPrecondition,
        "expected FAILED_PRECONDITION from the session-generation gate, got: {err:#}"
    );

    let (pubkey, state) = epoch_row(&h, f.a.id(), f.pending_epoch).await;
    assert_eq!(
        pubkey, SENTINEL,
        "a rejected submission must not WRITE: the gate sits ahead of `set_epoch_pubkey`, so \
         epoch {} must still hold the sentinel — found {pubkey:?}",
        f.pending_epoch
    );
    assert_eq!(
        state, "pending",
        "a rejected submission must not advance the epoch's state either, got {state:?}"
    );

    // Anti-vacuity: the row was claimable all along.
    f.a.submit_epoch_key(f.pending_epoch, FRESH_KEY).await.expect(
        "the LIVE process's submission (matching generation) must succeed — if this fails, \
         the sentinel assertion above proved nothing, because the row was not claimable at \
         the moment the stale submission was refused",
    );
    let (pubkey, state) = epoch_row(&h, f.a.id(), f.pending_epoch).await;
    assert_eq!(
        pubkey, FRESH_KEY,
        "the live process's key must be the one that wins the swap, got {pubkey:?}"
    );
    assert_eq!(state, "pending", "submitting a key must not promote it, got {state:?}");
}

/// (d) A rejected submission must produce NO rotation side effects — the gate
/// precedes `projection::emit_key_rotated` and `drive_rotation`, not just
/// `set_epoch_pubkey`.
///
/// Seam: a connected PEER's Watch. `emit_key_rotated` publishes
/// `ChangeEvent::KeyRotated`, which `projection::delta_for_change` turns into
/// a `Delta` with exactly one `upserted_peers` entry for the rotating
/// gateway. So "no delta upserting A arrived" is a direct read on "the fan-out
/// did not run". The second phase is the live-seam control: the same
/// submission with a matching generation DOES produce that delta, carrying
/// the fresh key — without it, this test would pass on a stream that simply
/// never delivers anything.
///
/// HONEST LIMIT on the `drive_rotation` half: its own effects (promote /
/// retire) are unreachable in a fast test. `rotation::decide` needs either
/// every connected peer's ack for the epoch or the 90s grace to have elapsed,
/// and neither holds here — so a `drive_rotation` invoked on a rejected
/// submission would be observably a no-op regardless. This test pins the
/// `emit_key_rotated` half directly and the `drive_rotation` half only by the
/// ordering it shares with it (one gate, one early return, both below it). I
/// did not try to fake the grace clock to reach further.
///
/// Sabotage: delete the gate, or move it below `set_epoch_pubkey` — the stale
/// key lands, `emit_key_rotated` fans it out, and B receives a delta
/// advertising a key A is not serving.
#[tokio::test]
async fn a_rejected_submission_publishes_no_key_delta_to_peers() {
    let h = TestController::start().await;
    let mut f = rotation_in_flight_across_a_gateway_restart(&h).await;
    let a_id = f.a.id();

    let err = f
        .a
        .submit_epoch_key_raw(SubmitEpochKeyRequest {
            epoch: f.pending_epoch,
            pubkey: STALE_KEY.to_string(),
            session_generation: f.stale_generation,
        })
        .await
        .expect_err("the stale-generation submission must be rejected");
    assert_eq!(
        status_of(&err).code(),
        tonic::Code::FailedPrecondition,
        "expected FAILED_PRECONDITION, got: {err:#}"
    );

    if let Some(leaked) = next_delta_upserting(&mut f.b_stream, a_id, DELTA_WINDOW).await {
        panic!(
            "a rejected submission must fan NOTHING out: the gate precedes \
             `emit_key_rotated`, yet peer B received a delta re-advertising gateway {a_id}'s \
             keys — {:?}",
            leaked.upserted_peers
        );
    }

    // Live-seam control: the same call with a matching generation DOES reach
    // `emit_key_rotated`, so the silence above was the gate, not a dead seam.
    f.a.submit_epoch_key(f.pending_epoch, FRESH_KEY)
        .await
        .expect("the live process's submission must succeed");
    let published = next_delta_upserting(&mut f.b_stream, a_id, DELTA_WINDOW)
        .await
        .expect(
            "an ACCEPTED submission must reach `emit_key_rotated` and fan the new key out to \
             peers — if nothing arrives here, the negative assertion above was vacuous",
        );
    assert!(
        published
            .upserted_peers
            .iter()
            .filter(|p| p.gateway_id == a_id)
            .any(|p| p.keys.iter().any(|k| k.pubkey == FRESH_KEY)),
        "the fanned-out delta must carry the LIVE process's key, got: {:?}",
        published.upserted_peers
    );
}

/// (LEGACY LEG, `req == 0`) A gateway whose Watch recorded a NONZERO
/// generation may still submit with 0, and it must be accepted and applied.
///
/// This is the leg a naive `stored != req` breaks: the two sides genuinely
/// differ here. A partially-upgraded gateway — new enough to open a Watch
/// with a nonce, old enough that its submit path does not stamp one — would
/// otherwise be unable to complete any rotation it is directed into, and rule
/// 4 would promote the still-sentinel epoch on the grace timeout.
#[tokio::test]
async fn legacy_zero_generation_submission_is_accepted() {
    let h = TestController::start().await;
    let a = enroll_one(&h, "aws", "10.0.0.0/16").await;

    // The Watch records A's nonzero nonce controller-side.
    let _a_stream = a.open_sync().await;
    assert_ne!(
        a.session_generation(),
        0,
        "the WATCH side must be nonzero, or the two sides do not differ and this proves nothing"
    );

    let pending_epoch = rotate_and_pending_epoch(&h, a.id()).await;

    a.submit_epoch_key_raw(SubmitEpochKeyRequest {
        epoch: pending_epoch,
        pubkey: "LEGACY-CLIENT-KEY==".to_string(),
        // The legacy/unknown sentinel, against a nonzero recorded generation.
        session_generation: 0,
    })
    .await
    .unwrap_or_else(|e| {
        panic!(
            "a submission carrying the 0 legacy sentinel must be ACCEPTED even when the \
             gateway's Watch recorded a nonzero generation — 0 means 'no opinion', not \
             'conflict'. Got: {e:#}"
        )
    });

    let (pubkey, _state) = epoch_row(&h, a.id(), pending_epoch).await;
    assert_eq!(
        pubkey, "LEGACY-CLIENT-KEY==",
        "the accepted legacy submission must have been APPLIED, not silently discarded"
    );
}

/// (UNKNOWN LEG, `stored == 0`) A submission from a gateway the controller
/// has no recorded generation for must be accepted and applied.
///
/// `SyncSvc::sessions` is in-memory, so a CONTROLLER restart empties it while
/// every gateway's Watch reconnects. Submitting before ever opening a Watch
/// is the same state from `check_session_generation`'s point of view —
/// `recorded_session_generation` returns 0 — and it is the only input the
/// predicate has. Rejecting here would mean a rotation directed just before a
/// controller restart could never receive its real key at all, leaving the
/// pending epoch on the sentinel until rule 4's grace fires.
///
/// (It is also the shape every pre-existing `submit_epoch_key` caller in this
/// suite already has — `rotation.rs`, `rotation_timer.rs`, `projection_guard.rs`
/// all submit from a gateway that never opened its own Watch — so this names
/// a leg the suite was silently depending on.)
#[tokio::test]
async fn submission_with_no_recorded_watch_generation_is_accepted() {
    let h = TestController::start().await;
    let a = enroll_one(&h, "aws", "10.0.0.0/16").await;

    // Deliberately NO `open_sync()`.
    assert_ne!(
        a.session_generation(),
        0,
        "the request side must be nonzero, or this exercises the legacy leg instead"
    );

    let pending_epoch = rotate_and_pending_epoch(&h, a.id()).await;

    a.submit_epoch_key(pending_epoch, "NO-WATCH-KEY==")
        .await
        .unwrap_or_else(|e| {
            panic!(
                "a submission must be ACCEPTED when the controller has no recorded generation \
                 for the gateway (stored == 0) — this is the controller-restart window, and \
                 unknown must fail OPEN. Got: {e:#}"
            )
        });

    let (pubkey, _state) = epoch_row(&h, a.id(), pending_epoch).await;
    assert_eq!(
        pubkey, "NO-WATCH-KEY==",
        "the accepted submission must have been APPLIED, not silently discarded"
    );
}
