//! Boots a real controller, enrolls two stub gateways (A: "aws",
//! 10.0.0.0/16; B: "gcp", 10.1.0.0/16), then has A send an authenticated UDP
//! observation probe at the controller's UDP observation endpoint. The
//! controller must echo back A's observed source `ip:port` (as seen server
//! side — on loopback this is `127.0.0.1:<ephemeral-port>`), AND record that
//! address as A's candidate endpoint so it shows up in a peer's projection:
//! once B opens a FRESH `Sync.Watch` stream after the probe, its initial
//! `StateSnapshot` must list A as a peer whose `candidate_endpoints` contains
//! the exact echoed address.
//!
//! This is Task 15's Step 1: the failing test for the UDP observation
//! endpoint (`crates/wiremesh-controller/src/observe.rs`, wired up in
//! `main.rs`, surfaced into `src/projection.rs`) — none of that exists yet.
//! `TestController::observe_addr()` and `StubGateway::probe_observe()` are
//! added by the Task 15 implementer alongside the endpoint itself, so today
//! this fails to COMPILE (unresolved `observe_addr`/`probe_observe`), which
//! is the expected RED state for this step.
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio_stream::StreamExt;
use wiremesh_proto::v1::{sync_message, StateSnapshot};

/// Pulls a `StateSnapshot` out of the first message of a freshly opened
/// `Sync.Watch` stream, panicking with a descriptive message on any other
/// outcome (stream ended, stream error, or a `Delta` instead of the expected
/// initial snapshot) — mirrors the inline pattern `tests/sync_snapshot.rs`
/// and `tests/sync_delta.rs` already use for the same unwrap, just factored
/// out since this test needs it for B's snapshot specifically.
fn expect_snapshot(msg: Option<Result<wiremesh_proto::v1::SyncMessage, tonic::Status>>) -> StateSnapshot {
    let msg = msg
        .expect("Sync.Watch stream ended before delivering a message")
        .expect("Sync.Watch stream yielded an error instead of a message");
    match msg.body {
        Some(sync_message::Body::Snapshot(s)) => s,
        other => panic!(
            "expected the first Sync.Watch message to be a StateSnapshot, got: {other:?}"
        ),
    }
}

#[tokio::test]
async fn observation_echoes_source_and_populates_candidate() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    let _b = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;

    // A sends an authenticated observation probe from a UDP socket; the
    // controller must echo back the source address it observed the probe
    // arrive from.
    let observed = a
        .probe_observe(h.observe_addr())
        .await
        .expect("StubGateway::probe_observe");
    assert!(
        observed.starts_with("127.0.0.1:"),
        "observed address must be A's loopback UDP source as seen by the \
         controller, got: {observed}"
    );

    // B's projection must now list A's observed candidate endpoint. Open a
    // FRESH Sync.Watch stream from B (rather than reusing one opened before
    // the probe) so its initial snapshot reflects the post-probe state —
    // per the brief, the candidate may only appear after the probe is fully
    // processed, and re-opening after the probe is the intended way to
    // observe that rather than racing a live delta.
    let mut b_stream = _b.open_sync().await;
    let snap = expect_snapshot(b_stream.next().await);

    let a_peer = snap
        .peers
        .iter()
        .find(|p| p.gateway_id == a.id())
        .unwrap_or_else(|| {
            panic!(
                "B's snapshot must list A (gateway_id {}) as a peer, got: {:?}",
                a.id(),
                snap.peers
            )
        });
    assert!(
        a_peer
            .candidate_endpoints
            .iter()
            .any(|c| c == &observed),
        "A's peer entry in B's snapshot must list the observed address {observed} \
         as a candidate endpoint, got: {:?}",
        a_peer.candidate_endpoints
    );
}

/// Regression guard for the observation endpoint's core security property: a
/// caller who does NOT hold a gateway's `observe_key` cannot get an echo out
/// of the endpoint, nor plant a candidate endpoint on any gateway. The MAC is
/// `sha256(observe_key || "AOBS" || gateway_id_be)` and this test never learns
/// any `observe_key`, so every datagram it sends carries a MAC the controller
/// cannot reproduce (or a magic/gateway_id it rejects before even checking the
/// MAC) — all must be dropped silently. Unlike the happy-path test above, this
/// one must PASS against the current (correct) implementation.
///
/// Builds probes on a raw `UdpSocket` rather than via `StubGateway::probe_observe`
/// precisely because that helper would build a VALID probe — the whole point
/// here is to send authentic-looking-but-unauthenticated garbage.
#[tokio::test]
async fn hostile_probe_is_rejected_no_echo_no_candidate() {
    let h = wiremesh_testkit::TestController::start().await;
    let a = wiremesh_testkit::enroll_one(&h, "aws", "10.0.0.0/16").await;
    let b = wiremesh_testkit::enroll_one(&h, "gcp", "10.1.0.0/16").await;

    let observe_addr = h.observe_addr();

    // Three hostile datagrams, each of which the controller must drop without
    // any reply:
    //   (a) wrong magic ("XXXX") — rejected before any identity/MAC check.
    //   (b) correct magic "AOBS" + A's real gateway_id + a garbage 32-byte
    //       MAC we cannot have computed (we don't hold A's observe_key).
    //   (c) correct magic + an unknown gateway_id (99999) + garbage MAC.
    let mut wrong_magic = Vec::new();
    wrong_magic.extend_from_slice(b"XXXX");
    wrong_magic.extend_from_slice(&a.id().to_be_bytes());
    wrong_magic.extend_from_slice(&[0xAAu8; 32]);

    let mut bad_mac = Vec::new();
    bad_mac.extend_from_slice(b"AOBS");
    bad_mac.extend_from_slice(&a.id().to_be_bytes());
    bad_mac.extend_from_slice(&[0xBBu8; 32]);

    let mut unknown_gw = Vec::new();
    unknown_gw.extend_from_slice(b"AOBS");
    unknown_gw.extend_from_slice(&99999u64.to_be_bytes());
    unknown_gw.extend_from_slice(&[0xCCu8; 32]);

    for hostile in [wrong_magic, bad_mac, unknown_gw] {
        let sock = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("binding a raw UDP socket for the hostile probe");
        sock.send_to(&hostile, observe_addr)
            .await
            .expect("sending the hostile probe datagram");

        // The controller drops bad probes silently, so no reply must arrive.
        // A short timeout on recv_from is what proves "no echo": if the bug
        // regressed and an echo WERE sent, this would receive it well inside
        // the window and fail the assertion below.
        let mut buf = [0u8; 128];
        let recv = tokio::time::timeout(Duration::from_millis(500), sock.recv_from(&mut buf)).await;
        assert!(
            recv.is_err(),
            "hostile probe must draw NO reply from the observation endpoint, \
             but recv_from returned: {recv:?}"
        );
    }

    // And no candidate was planted: A never sent a valid probe, so a FRESH
    // snapshot from B must show A as a peer whose candidate_endpoints is empty.
    let mut b_stream = b.open_sync().await;
    let snap = expect_snapshot(b_stream.next().await);

    let a_peer = snap
        .peers
        .iter()
        .find(|p| p.gateway_id == a.id())
        .unwrap_or_else(|| {
            panic!(
                "B's snapshot must list A (gateway_id {}) as a peer, got: {:?}",
                a.id(),
                snap.peers
            )
        });
    assert!(
        a_peer.candidate_endpoints.is_empty(),
        "no hostile probe may plant a candidate endpoint — A's candidate_endpoints \
         must stay empty, got: {:?}",
        a_peer.candidate_endpoints
    );
}
