// Behavior tests for `Lab::nat_router` / `NatKind`.
//
// Topology (built fresh per test via a dedicated Lab so the two tests don't
// share netns names):
//
//   c (client, 192.168.50.2/24) --veth-- r::in0 (192.168.50.1/24)
//                                        r (nat_router)
//                                        r::out0 (203.0.113.1/24) --veth-- s::eth0 (203.0.113.10/24, .11/24)
//
// One client UDP socket (bound via the `udpsend` example, port 6000) sends
// one datagram to each of the server's two addresses. Two `udpsink` example
// processes, one per server address, each print the peer (src ip:port) of
// the first datagram they receive. Comparing those two observed source
// ports tells us whether the router's NAT mapping is endpoint-independent
// (PortRestricted: same port both times) or endpoint-dependent (Symmetric:
// different port per destination).
//
// Examples aren't reachable via `env!("CARGO_BIN_EXE_...")` for `tests/`
// integration tests (that only works for `[[bin]]` targets), so the run
// command builds them explicitly first (`cargo build --examples`) and this
// file locates them under `target/debug/examples/` relative to the crate's
// manifest dir.

use natlab::{Lab, NatKind};
use std::net::{IpAddr, SocketAddr};
use std::process::{Child, Command, Output};
use std::sync::mpsc;
use std::time::Duration;

/// The router's public (out0) address — what the servers must see as the
/// datagrams' source IP if masquerade actually translated them.
const ROUTER_PUBLIC_IP: &str = "203.0.113.1";
/// The client's private address — what the servers would see if forwarding
/// happened WITHOUT translation (masquerade rule not firing).
const CLIENT_PRIVATE_IP: &str = "192.168.50.2";

fn example_bin(name: &str) -> String {
    format!("{}/target/debug/examples/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// Waits for `child` to exit and returns its captured output. A watcher
/// thread SIGKILLs the child only if it hasn't exited within `timeout`, so
/// a stuck sink (e.g. a datagram that never arrives) can't hang the test
/// suite forever. The watcher blocks on a channel with `recv_timeout` and
/// the main thread signals it as soon as `wait_with_output` returns, so a
/// child that exited normally is never killed — avoiding the PID-reuse
/// hazard of an unconditional delayed `kill -9`.
fn wait_with_timeout(child: Child, timeout: Duration) -> Output {
    let pid = child.id();
    let (exited_tx, exited_rx) = mpsc::channel::<()>();
    let watcher = std::thread::spawn(move || {
        if exited_rx.recv_timeout(timeout).is_err() {
            // Timed out (or main thread panicked): child is presumed stuck.
            let _ = Command::new("kill").arg("-9").arg(pid.to_string()).status();
        }
    });
    let out = child.wait_with_output().expect("wait_with_output");
    let _ = exited_tx.send(());
    let _ = watcher.join();
    out
}

fn parse_peer(out: &Output, who: &str) -> SocketAddr {
    assert!(
        out.status.success(),
        "{who} exited non-zero (status {:?}): stdout={:?} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout.lines().find(|l| l.starts_with("PEER ")).unwrap_or_else(|| {
        panic!(
            "{who}: no PEER line in stdout={stdout:?} stderr={}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    let addr = line.trim_start_matches("PEER ").trim();
    addr.parse()
        .unwrap_or_else(|e| panic!("{who}: malformed peer addr {addr:?}: {e}"))
}

/// Proves masquerade actually translated the source: forwarding alone
/// (ip_forward=1, default-accept) would deliver the datagrams with the
/// client's private IP:6000 intact — ports would compare equal for the
/// wrong reason. The observed peer must be the router's public address,
/// and must not be the client's private one.
fn assert_translated(peer: SocketAddr, who: &str) {
    let router: IpAddr = ROUTER_PUBLIC_IP.parse().unwrap();
    let client: IpAddr = CLIENT_PRIVATE_IP.parse().unwrap();
    assert_ne!(
        peer.ip(),
        client,
        "{who}: observed the client's PRIVATE address {peer} — packets were forwarded untranslated (masquerade did not fire)"
    );
    assert_eq!(
        peer.ip(),
        router,
        "{who}: observed peer {peer} is not the router's public address {router} — source was not masqueraded as expected"
    );
}

/// Builds the client/router/server topology for `kind`, sends one datagram
/// from a single client socket to each of the server's two addresses, and
/// returns the two full source addresses observed at the server side.
fn observed_peers(kind: NatKind) -> (SocketAddr, SocketAddr) {
    let prefix = match kind {
        NatKind::PortRestricted => "npr",
        NatKind::Symmetric => "nsy",
    };
    let mut lab = Lab::new(prefix).unwrap();
    let c = lab.ns("c").unwrap();
    let r = lab.nat_router("r", kind).unwrap();
    let s = lab.ns("s").unwrap();

    lab.veth(
        (&c, "eth0", &format!("{CLIENT_PRIVATE_IP}/24")),
        (&r, "in0", "192.168.50.1/24"),
    )
    .unwrap();
    lab.veth(
        (&r, "out0", &format!("{ROUTER_PUBLIC_IP}/24")),
        (&s, "eth0", "203.0.113.10/24"),
    )
    .unwrap();
    c.exec(&["ip", "route", "add", "default", "via", "192.168.50.1"])
        .unwrap();
    s.exec(&["ip", "addr", "add", "203.0.113.11/24", "dev", "eth0"])
        .unwrap();

    let udpsink = example_bin("udpsink");
    let udpsend = example_bin("udpsend");

    let sink1 = s.spawn(&[&udpsink, "203.0.113.10:7001"]).unwrap();
    let sink2 = s.spawn(&[&udpsink, "203.0.113.11:7002"]).unwrap();
    // Let both sinks finish binding before the client sends, so neither
    // datagram arrives before its listener exists.
    std::thread::sleep(Duration::from_millis(300));

    let send_out = c
        .exec(&[&udpsend, "203.0.113.10:7001", "203.0.113.11:7002"])
        .unwrap();
    assert!(
        send_out.status.success(),
        "udpsend failed: {}",
        String::from_utf8_lossy(&send_out.stderr)
    );

    let out1 = wait_with_timeout(sink1, Duration::from_secs(5));
    let out2 = wait_with_timeout(sink2, Duration::from_secs(5));

    let peer1 = parse_peer(&out1, "sink@203.0.113.10:7001");
    let peer2 = parse_peer(&out2, "sink@203.0.113.11:7002");
    (peer1, peer2)
}

#[test]
fn port_restricted_nat_is_endpoint_independent() {
    let (peer1, peer2) = observed_peers(NatKind::PortRestricted);
    eprintln!("port_restricted observed peers: dst1={peer1} dst2={peer2}");
    // First prove translation actually happened (see assert_translated) —
    // equal ports alone would also be true of untranslated pass-through.
    assert_translated(peer1, "sink@203.0.113.10:7001");
    assert_translated(peer2, "sink@203.0.113.11:7002");
    assert_eq!(
        peer1.port(),
        peer2.port(),
        "plain masquerade should map the same client flow to the same external port regardless of destination (got {peer1} vs {peer2})"
    );
}

#[test]
fn symmetric_nat_maps_per_destination() {
    let (peer1, peer2) = observed_peers(NatKind::Symmetric);
    eprintln!("symmetric observed peers: dst1={peer1} dst2={peer2}");
    assert_translated(peer1, "sink@203.0.113.10:7001");
    assert_translated(peer2, "sink@203.0.113.11:7002");
    assert_ne!(
        peer1.port(),
        peer2.port(),
        "symmetric NAT should map the same client flow to a different external port per destination (both observed as {peer1})"
    );
}
