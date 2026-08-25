//! Task 11b's failing test: `EnrollRequest.wg_pubkey` must land as a
//! gateway's real epoch-0 `GATEWAY_KEY.pubkey`, so a peer's `Sync.Watch`
//! snapshot exposes that real WireGuard key instead of the cycle-2
//! `placeholder-pubkey-gw{id}-epoch0` bookkeeping stand-in — this is what
//! unblocks the mesh milestone (Task 12): a peer can't configure a tunnel
//! against a placeholder string.
//!
//! Boots a real controller, enrolls gateway A ("aws") WITH a real base64 WG
//! pubkey, then a peer gateway B ("gcp") WITHOUT one (the existing
//! `enroll_one` back-compat path), then a third gateway C ("azure") that
//! observes both A and B as peers over its own `Sync.Watch` stream:
//!
//!   1. A's peer entry in C's initial snapshot must carry a `PeerKey` with
//!      `pubkey == REAL_WG_PUBKEY` (not a placeholder), `epoch == 0`,
//!      `state == "active"`.
//!   2. Back-compat: B's peer entry (enrolled via the existing, untouched
//!      `enroll_one`, i.e. no `wg_pubkey` on the wire) must still carry the
//!      old placeholder `pubkey == "placeholder-pubkey-gw{b.id()}-epoch0"` —
//!      proving the empty-`wg_pubkey` fallback keeps producing exactly the
//!      pre-Task-11b behavior.
use std::time::Duration;

use tokio_stream::StreamExt;
use wiremesh_proto::v1::sync_message;

/// Bounds the wait for the initial `Sync.Watch` snapshot so a controller
/// that never emits one (a real regression) fails this test fast instead of
/// hanging the whole suite.
const INITIAL_SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(5);

/// A fixed, validly-shaped (32 raw bytes, base64-encoded, 44 chars incl. the
/// trailing `=` — the same shape a real `wg pubkey` output has) stand-in for
/// a gateway-generated WireGuard public key. Its actual bytes don't matter
/// here — this test proves the controller threads whatever string it's
/// given through to peers verbatim, not that it validates WG key shape.
const REAL_WG_PUBKEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

#[tokio::test]
async fn enrollment_wg_pubkey_reaches_peers_and_empty_falls_back_to_placeholder() {
    let h = wiremesh_testkit::TestController::start().await;

    // A enrolls WITH a real WG pubkey.
    let a =
        wiremesh_testkit::enroll_one_with_wg_pubkey(&h, "aws", "10.0.0.0/16", REAL_WG_PUBKEY).await;
    // B enrolls WITHOUT one — the existing, untouched back-compat path.
    let b = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;
    // C observes both A and B as peers over its own Sync.Watch stream.
    let c = wiremesh_testkit::enroll_one(&h, "azure", "10.2.0.0/16").await;

    let mut c_stream = c.open_sync().await;
    let snap_msg = tokio::time::timeout(INITIAL_SNAPSHOT_TIMEOUT, c_stream.next())
        .await
        .expect("timed out waiting for C's initial Sync.Watch snapshot")
        .expect("Sync.Watch stream ended before delivering C's initial snapshot")
        .expect("Sync.Watch stream yielded an error instead of C's initial snapshot");

    let peers = match snap_msg.body {
        Some(sync_message::Body::Snapshot(s)) => s.peers,
        other => {
            panic!("expected the first Sync.Watch message to be a StateSnapshot, got: {other:?}")
        }
    };

    let a_peer = peers
        .iter()
        .find(|p| p.gateway_id == a.id())
        .unwrap_or_else(|| {
            panic!(
                "expected C's snapshot to include A (id = {}) as a peer, got: {peers:?}",
                a.id()
            )
        });
    let a_key = a_peer
        .keys
        .iter()
        .find(|k| k.epoch == 0)
        .unwrap_or_else(|| {
            panic!(
                "expected A's peer entry to carry an epoch-0 key, got: {:?}",
                a_peer.keys
            )
        });
    assert_eq!(
        a_key.pubkey, REAL_WG_PUBKEY,
        "expected A's epoch-0 PeerKey.pubkey to be the real WG pubkey A enrolled with, \
         got: {:?}",
        a_key
    );
    assert_eq!(
        a_key.state, "active",
        "expected A's epoch-0 key to be active, got: {a_key:?}"
    );

    let b_peer = peers
        .iter()
        .find(|p| p.gateway_id == b.id())
        .unwrap_or_else(|| {
            panic!(
                "expected C's snapshot to include B (id = {}) as a peer, got: {peers:?}",
                b.id()
            )
        });
    let b_key = b_peer
        .keys
        .iter()
        .find(|k| k.epoch == 0)
        .unwrap_or_else(|| {
            panic!(
                "expected B's peer entry to carry an epoch-0 key, got: {:?}",
                b_peer.keys
            )
        });
    let expected_placeholder = format!("placeholder-pubkey-gw{}-epoch0", b.id());
    assert_eq!(
        b_key.pubkey, expected_placeholder,
        "back-compat regression: B enrolled with no wg_pubkey (the existing enroll_one \
         path) must still get the cycle-2 placeholder pubkey, got: {:?}",
        b_key
    );
    assert_eq!(
        b_key.state, "active",
        "expected B's epoch-0 key to be active, got: {b_key:?}"
    );
}
