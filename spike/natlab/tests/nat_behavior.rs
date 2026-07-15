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
use std::process::{Child, Command, Output};
use std::time::Duration;

fn example_bin(name: &str) -> String {
    format!("{}/target/debug/examples/{name}", env!("CARGO_MANIFEST_DIR"))
}

/// Waits for `child` to exit and returns its captured output. If it hasn't
/// exited within `timeout`, a detached watcher thread SIGKILLs it so a
/// stuck sink (e.g. a datagram that never arrives) can't hang the test
/// suite forever; the watcher's kill is a harmless no-op once the process
/// has already exited normally.
fn wait_with_timeout(child: Child, timeout: Duration) -> Output {
    let pid = child.id();
    std::thread::spawn(move || {
        std::thread::sleep(timeout);
        let _ = Command::new("kill").arg("-9").arg(pid.to_string()).status();
    });
    child.wait_with_output().expect("wait_with_output")
}

fn parse_peer_port(out: &Output, who: &str) -> u16 {
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
    addr.rsplit(':')
        .next()
        .unwrap_or_else(|| panic!("{who}: malformed peer addr {addr:?}"))
        .parse()
        .unwrap_or_else(|e| panic!("{who}: bad port in {addr:?}: {e}"))
}

/// Builds the client/router/server topology for `kind`, sends one datagram
/// from a single client socket to each of the server's two addresses, and
/// returns the two source ports observed at the server side.
fn observed_ports(kind: NatKind) -> (u16, u16) {
    let prefix = match kind {
        NatKind::PortRestricted => "npr",
        NatKind::Symmetric => "nsy",
    };
    let mut lab = Lab::new(prefix).unwrap();
    let c = lab.ns("c").unwrap();
    let r = lab.nat_router("r", kind).unwrap();
    let s = lab.ns("s").unwrap();

    lab.veth((&c, "eth0", "192.168.50.2/24"), (&r, "in0", "192.168.50.1/24"))
        .unwrap();
    lab.veth((&r, "out0", "203.0.113.1/24"), (&s, "eth0", "203.0.113.10/24"))
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

    let p1 = parse_peer_port(&out1, "sink@203.0.113.10:7001");
    let p2 = parse_peer_port(&out2, "sink@203.0.113.11:7002");
    (p1, p2)
}

#[test]
fn port_restricted_nat_is_endpoint_independent() {
    let (p1, p2) = observed_ports(NatKind::PortRestricted);
    eprintln!("port_restricted observed ports: dst1={p1} dst2={p2}");
    assert_eq!(
        p1, p2,
        "plain masquerade should map the same client flow to the same external port regardless of destination (got {p1} vs {p2})"
    );
}

#[test]
fn symmetric_nat_maps_per_destination() {
    let (p1, p2) = observed_ports(NatKind::Symmetric);
    eprintln!("symmetric observed ports: dst1={p1} dst2={p2}");
    assert_ne!(
        p1, p2,
        "symmetric NAT should map the same client flow to a different external port per destination (both observed as {p1})"
    );
}
