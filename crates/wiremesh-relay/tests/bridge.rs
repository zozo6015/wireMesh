// crates/wiremesh-relay/tests/bridge.rs
//
// Graduated from spike/relay/tests/bridge.rs (Cycle 4c Task 2).
//
// Proves Bet 3's core claims (spec §6.1) for the `wiremesh-relay` crate:
//   1. Bridging: two gateways register with the relay and exchange one
//      datagram end-to-end (dest-id strip on send, src-id prepend on
//      receive both correct).
//   2. Datagram size: the QUIC connection's usable application-datagram
//      payload comfortably exceeds the WG(1280)+overhead(32)+relay-header(8)
//      = 1320-byte floor the tunnel path actually needs.
//   3. Mandatory mutual TLS: a client presenting no certificate at all can
//      never complete the connect+register+bridge flow.
//
// Runs entirely in the root netns on loopback — no natlab::Lab/NAT needed,
// per the task-13 brief ("no NAT needed to prove bridging + auth").
//
// ## Where the cert-rejection error actually surfaces (read before touching
// ## the assertion below)
//
// Per the implementer's report (task-13-report.md, friction item 10): a
// certless client's *raw* `endpoint.connect(...).await` can return `Ok` —
// the client side doesn't wait to hear back that the server rejected the
// handshake for lacking a client certificate; that rejection is a
// server-initiated CONNECTION_CLOSE that lands slightly later. Asserting on
// that raw future directly would be flaky: it could observe `Ok` and pass
// (or transiently fail) for the wrong reason.
//
// `wiremesh_relay::Client::connect_no_cert` does NOT expose that raw future,
// though — `finish_connect` wraps connect + open_bi (the registration
// stream) + write + ack-read into a single `Result`-returning async fn.
// Confirmed by running this test with the error printed (see the
// `eprintln!`s below): the `Err`'s message is
//   "await registration ack: read error: connection lost: connection lost:
//    aborted by peer: the cryptographic handshake failed: error 116: peer
//    sent no certificates"
// i.e. `endpoint.connect(...).await` and `conn.open_bi()`/the id write both
// succeed (the client-side connection object exists before the server's
// CONNECTION_CLOSE lands), and the failure actually surfaces one step
// later, at `recv.read_to_end(1)` while awaiting the relay's registration
// ack — which is exactly when the server's async rejection of the missing
// client cert reaches the client. So `connect_no_cert(...).await.is_err()`
// is reliable *because* it asserts on the whole flow, at whatever step the
// rejection actually manifests (here: the ack read), not on the bypassed
// raw handshake future — exactly the "assert at the point it actually
// manifests" requirement.
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Kills the relay server on drop, including on panic-driven unwind, so a
/// failed assertion never leaks a background process out of the test.
/// Mirrors `KillOnDrop` in spike/punch/tests/punch.rs.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A tmpdir unique to this test process. No `rand`/`Date` dependency
/// available here, so uniqueness is derived from the PID (sufficient: one
/// process runs this test at a time, and repeated local runs each get a
/// fresh PID).
fn unique_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("relay-bridge-test-{tag}-{}", std::process::id()))
}

fn run_ok(bin: &str, args: &[&str]) {
    let status = Command::new(bin)
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("spawn {bin} {args:?}: {e}"));
    assert!(status.success(), "{bin} {args:?} failed: {status:?}");
}

fn spawn_relay(bin: &str, bind: &str, certdir: &Path) -> Child {
    Command::new(bin)
        .args([bind, certdir.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {bin}: {e}"))
}

#[tokio::test]
async fn bridges_datagrams_and_rejects_certless_clients() {
    let dir = unique_dir("main");
    let mkcerts_bin = env!("CARGO_BIN_EXE_mkcerts");
    let relay_bin = env!("CARGO_BIN_EXE_relay");

    run_ok(mkcerts_bin, &[dir.to_str().unwrap()]);

    // Port derived from PID to avoid colliding with a lingering listener
    // from a just-killed prior run still draining its socket.
    let port = 40000 + (std::process::id() % 10000) as u16;
    let bind_addr = format!("127.0.0.1:{port}");
    let relay_child = spawn_relay(relay_bin, &bind_addr, &dir);
    let _relay_guard = KillOnDrop(relay_child);
    // Let the relay finish binding before either client dials in.
    tokio::time::sleep(Duration::from_millis(400)).await;

    let relay_addr: std::net::SocketAddr = bind_addr.parse().unwrap();

    // --- Property 1: bridging ---------------------------------------
    // Each client is peer-bound: gw-A registers (my=gw-A, peer=gw-B); gw-B
    // registers (my=gw-B, peer=gw-A). The relay verifies each `my_identity`
    // against the presented client cert's `gw-<id>` SAN (mkcerts stamps SAN =
    // the id name) and rendezvous the two directional keys.
    let a = wiremesh_relay::Client::connect(relay_addr, &dir, "gw-A", "gw-B")
        .await
        .expect("gw-A connect+register");
    let b = wiremesh_relay::Client::connect(relay_addr, &dir, "gw-B", "gw-A")
        .await
        .expect("gw-B connect+register");

    // `Client::connect` only returns after the relay has acked gw-B's
    // registration (see lib.rs's finish_connect doc comment), so this
    // send cannot race the registry insert.
    a.send(b"hello").await.expect("send to gw-B");
    let (src, data) = tokio::time::timeout(Duration::from_secs(3), b.recv())
        .await
        .expect("recv timed out")
        .expect("recv errored");
    assert_eq!(data, b"hello".to_vec(), "payload must survive the bridge unmodified");
    // The forwarded datagram carries the TRUE sender's registration key
    // (gw-A's own registered id), not the relay's or a spoofable value.
    assert_eq!(
        src,
        wiremesh_relay::registration_key("gw-A", "gw-B"),
        "forwarded datagram must carry the true sender's registration key"
    );

    // --- Property 2: datagram size ------------------------------------
    // spec §6.1 floor: WG tunnel MTU 1280 + WireGuard overhead 32 + this
    // relay's 8-byte dest/src-id header = 1320 bytes of usable payload.
    const REQUIRED: usize = 1312 + 8;
    let max_immediate = a.max_datagram_size().expect("datagrams must be enabled");
    eprintln!("max_datagram_size (gw-A, right after connect) = {max_immediate}");
    tokio::time::sleep(Duration::from_millis(500)).await;
    let max_settled = a.max_datagram_size().expect("datagrams must be enabled");
    eprintln!("max_datagram_size (gw-A, after 500ms settle)  = {max_settled}");
    assert!(
        max_immediate >= REQUIRED,
        "max datagram {max_immediate} too small for tun MTU 1280 (+wg 32 +hdr 8 = {REQUIRED})"
    );
    assert!(
        max_settled >= REQUIRED,
        "max datagram (settled) {max_settled} too small for tun MTU 1280 (+wg 32 +hdr 8 = {REQUIRED})"
    );

    // --- Property 3: mandatory mutual TLS ------------------------------
    // See the module-level doc comment above for exactly where this fails
    // and why asserting on the wrapped `connect_no_cert` result (rather
    // than a raw handshake future) is the reliable place to check it.
    let no_cert_result = wiremesh_relay::Client::connect_no_cert(relay_addr, &dir).await;
    eprintln!("connect_no_cert is_ok = {}", no_cert_result.is_ok());
    match &no_cert_result {
        Err(e) => eprintln!("certless client correctly rejected: {e:#}"),
        Ok(_) => eprintln!("certless client UNEXPECTEDLY bridged — security hole"),
    }
    assert!(
        no_cert_result.is_err(),
        "certless client completed connect+register — mutual TLS not enforced"
    );
}
