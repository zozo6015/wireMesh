//! Gateway relay transport (Cycle 4c Task 7) — loopback, no netns.
//!
//! Graduates `spike/relay/src/bin/udpshim.rs`'s local-UDP <-> relay-QUIC
//! bridge into `wiremesh_gateway::relay::RelayTransport`, driven by an
//! in-process relay server (`wiremesh_relay::spawn_server`) rather than the
//! `relay` binary, so this test needs no `CARGO_BIN_EXE_*` cross-crate
//! lookup and no netns.
//!
//! ./dev.sh run "cargo test -p wiremesh-gateway --test relay_transport -- --nocapture"
//!
//! ## The last-seen socket dance (read before touching the body below)
//!
//! Each `RelayTransport` bridges its LOCAL UDP socket to a fixed relay peer
//! id (mirroring `udpshim`): a datagram arriving on the local socket is
//! forwarded to the peer over the relay, remembering the local sender as
//! `last_seen`; a datagram arriving FROM the relay is delivered to whatever
//! local address was last seen sending — there is no local peer to deliver
//! to until something has sent in.
//!
//! So proving A -> B bridging needs THREE datagrams, not two:
//!   1. `sb` (a throwaway socket standing in for "B's WireGuard") sends a
//!      priming datagram into `b.local_addr()`. This sets B's `last_seen` to
//!      `sb`. (It also gets forwarded on to A over the relay and dropped
//!      there, since A has no `last_seen` yet — that's fine, untested.)
//!   2. `sa` (standing in for "A's WireGuard") sends the real A->B payload
//!      into `a.local_addr()`. That sets A's `last_seen` to `sa`, forwards
//!      over the relay to B, and B's downlink delivers it to B's
//!      `last_seen` (== `sb`, from step 1) — so `sb.recv_from` must see it.
//!   3. Now that A's `last_seen` is `sa` (set in step 2), the reverse
//!      direction is primed for free: `sb` sends a B->A payload into
//!      `b.local_addr()`, which forwards over the relay to A and A's
//!      downlink delivers it to `sa` — so `sa.recv_from` must see it.
//!
//! Both directions are exercised with distinct payloads so a mixup (e.g.
//! delivering to the wrong socket, or truncating/corrupting the header
//! strip) would show up as a wrong-bytes assertion failure, not a hang.
use std::path::PathBuf;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use wiremesh_gateway::relay::RelayTransport;

/// A tmpdir unique to this test process. No `rand`/`Date` dependency
/// available here, so uniqueness is derived from the PID (sufficient: one
/// process runs this test at a time, and repeated local runs each get a
/// fresh PID) — mirrors `wiremesh-relay/tests/bridge.rs`'s `unique_dir`.
fn unique_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "gw-relay-transport-test-{tag}-{}",
        std::process::id()
    ))
}

async fn recv_exact(sock: &UdpSocket, label: &str) -> Vec<u8> {
    let mut buf = [0u8; 2048];
    let (n, _from) = timeout(Duration::from_secs(3), sock.recv_from(&mut buf))
        .await
        .unwrap_or_else(|_| panic!("{label}: recv timed out"))
        .unwrap_or_else(|e| panic!("{label}: recv_from errored: {e}"));
    buf[..n].to_vec()
}

#[tokio::test]
async fn relay_transport_bridges_datagrams_between_two_gateways() {
    let dir = unique_dir("main");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create certdir");

    wiremesh_relay::test_certs(&dir, &["gw-A", "gw-B"]).expect("test_certs must provision ca+gw-A+gw-B");

    let (relay_addr, _relay_handle) = wiremesh_relay::spawn_server("127.0.0.1:0".parse().unwrap(), &dir)
        .await
        .expect("spawn_server must bind and return the actual ephemeral address");

    let ca_pem = std::fs::read_to_string(dir.join("ca.pem")).expect("read ca.pem");
    let gwa_cert = std::fs::read_to_string(dir.join("gw-A.pem")).expect("read gw-A.pem");
    let gwa_key = std::fs::read_to_string(dir.join("gw-A.key")).expect("read gw-A.key");
    let gwb_cert = std::fs::read_to_string(dir.join("gw-B.pem")).expect("read gw-B.pem");
    let gwb_key = std::fs::read_to_string(dir.join("gw-B.key")).expect("read gw-B.key");

    // `None`: this test deliberately exercises the generic learn-from-first-
    // datagram path (throwaway sockets standing in for "unknown ahead of
    // time" local peers) — see `RelayTransport::start`'s doc comment on
    // `local_peer_hint`.
    let a = RelayTransport::start(relay_addr, &gwa_cert, &gwa_key, &ca_pem, "gw-A", "gw-B", None)
        .await
        .expect("gw-A RelayTransport::start (connect+register+pumps)");
    let b = RelayTransport::start(relay_addr, &gwb_cert, &gwb_key, &ca_pem, "gw-B", "gw-A", None)
        .await
        .expect("gw-B RelayTransport::start (connect+register+pumps)");

    // Give both transports' registration + pump tasks a moment to settle
    // before the socket dance below relies on them being live.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Throwaway sockets standing in for each side's local WireGuard peer.
    let sa = UdpSocket::bind("127.0.0.1:0").await.expect("bind sa");
    let sb = UdpSocket::bind("127.0.0.1:0").await.expect("bind sb");

    // Step 1: prime B's last_seen with `sb`. This datagram also travels
    // B -> relay -> A and is dropped there (A has no last_seen yet) — not
    // asserted on.
    sb.send_to(b"prime-b-last-seen", b.local_addr())
        .await
        .expect("sb prime send to b.local_addr()");
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Step 2: the real A -> B payload. Sets A's last_seen to `sa`, and must
    // arrive at `sb` (B's primed last_seen) with the payload intact.
    let a_to_b_payload = b"ping-a-to-b-payload";
    sa.send_to(a_to_b_payload, a.local_addr())
        .await
        .expect("sa send to a.local_addr()");
    let got_at_sb = recv_exact(&sb, "sb (expecting A->B payload)").await;
    assert_eq!(
        got_at_sb, a_to_b_payload,
        "A->B payload must arrive at B's last-seen local peer unmodified"
    );

    // Step 3: the reverse direction, now that A's last_seen is `sa` (set in
    // step 2). Must arrive at `sa` with the payload intact.
    let b_to_a_payload = b"pong-b-to-a-payload";
    sb.send_to(b_to_a_payload, b.local_addr())
        .await
        .expect("sb send to b.local_addr()");
    let got_at_sa = recv_exact(&sa, "sa (expecting B->A payload)").await;
    assert_eq!(
        got_at_sa, b_to_a_payload,
        "B->A payload must arrive at A's last-seen local peer unmodified"
    );

    assert!(a.is_healthy(), "gw-A RelayTransport must report healthy after successful bridging");
    assert!(b.is_healthy(), "gw-B RelayTransport must report healthy after successful bridging");

    let _ = std::fs::remove_dir_all(&dir);
}
