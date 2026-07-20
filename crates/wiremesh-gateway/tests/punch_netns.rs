//! Same-socket hole puncher, netns-proven (spec §3, Cycle 4b): two gateway
//! netns behind SEPARATE port-restricted NAT routers, each observes its own
//! post-NAT public mapping, then both call `punch::punch_candidates` at the
//! peer's observed candidate; assert BOTH confirm.
//!
//! Topology and MANDATORY `tc netem delay 20ms` mirror the proven de-risk
//! (`spike/natpunch/tests/handshake.rs`) and `docs/research/`'s PUNCH-WORKS
//! report — ported here as the "focused" gateway-crate test (Task 11 covers
//! the full end-to-end path including the real WG handshake):
//!
//!   pa 192.168.70.2/24 --- ra(in0 .1)[NAT] ra(out0 198.51.100.2/25)   --- inet ia 198.51.100.1/25
//!   pb 192.168.71.2/24 --- rb(in0 .1)[NAT] rb(out0 198.51.100.130/25) --- inet ib 198.51.100.129/25
//!
//! `inet` forwards ia<->ib and hosts a plain UDP echo standing in for the
//! controller's authenticated observe endpoint (§5.4) — this test is about
//! the punch, not the observe wire format, which `observe_parity.rs` already
//! proves against a REAL controller.
//!
//! netem is MANDATORY (Phase-0 Finding 2 / spec §7): a zero-latency veth lab
//! lets a peer's inbound PING beat the local side's own outbound packet
//! through its own NAT, poisoning conntrack and producing a FALSE
//! punch-failure. `apply_netem` is applied to the REAL `out0`-facing `ia`/
//! `ib` interfaces (created by `Lab::veth`, NOT `nat_router_delayed`'s dummy
//! placeholder) and `assert_netem_present` checked before punching starts.
//!
//! Sequencing (mirrors `spike/natpunch/src/bin/gateway.rs`, which observes
//! and punches from the SAME socket, sequentially): each side binds ONE
//! `SO_REUSEPORT` socket on the WG port, observes its public mapping with
//! it, then DROPS it before calling `punch::punch_candidates` (which opens
//! its own fresh `SO_REUSEPORT` socket on the same port). Deliberately does
//! NOT hold a second `SO_REUSEPORT` "stand-in" socket open concurrently
//! through the punch: with two live `SO_REUSEPORT` sockets bound to the same
//! port, the kernel can deliver an inbound `PONG` to whichever socket it
//! hashes to, so the punch socket's own confirmation becomes unreliable —
//! the exact hazard that made this test hang/flake before this fix. Proving
//! that a punch socket can confirm side-by-side with boringtun's own
//! concurrently-bound listener is Task 11's job (the full end-to-end path
//! with a real boringtun device), not this unit-level punch test.
//!
//! Every wait in this test is bounded (`recv_timeout`, not `recv`; capped
//! retries in `observe_public_mapping`; a bounded `punch_candidates`
//! `window`) so the test can only ever PASS or FAIL loudly — never hang.
//!
//! ./dev.sh run "cargo test -p wiremesh-gateway --test punch_netns \
//!   --features netns-tests -- --test-threads=1 --nocapture"
#![cfg(feature = "netns-tests")]

use std::net::{SocketAddr, UdpSocket};
use std::os::unix::io::FromRawFd;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use wiremesh_testkit::netns::{apply_netem, assert_netem_present, join_netns, Lab, NatKind};

const WG_PORT: u16 = 51820;
const OBSERVE_ADDR: &str = "198.51.100.1:7777";

/// Upper bound on any single bounded wait (observation reply, peer-candidate
/// handoff). Generous relative to the ~10s observe retry budget and the
/// punch window below so a genuine (non-hang) slow step still passes, while
/// a real stall still fails fast instead of hanging forever.
const STEP_TIMEOUT: Duration = Duration::from_secs(15);

/// How long each side blasts PING/waits for PONG in `punch_candidates`.
const PUNCH_WINDOW: Duration = Duration::from_secs(6);

/// Byte-for-byte the same technique `observe::reuseport_udp` /
/// `punch::punch_candidates` use — duplicated here (not imported) because
/// this test needs its own short-lived observation socket independent of
/// the library's internals. Bound ONLY for the observe phase, then dropped
/// before `punch::punch_candidates` binds its own socket on the same port
/// (see module doc comment).
fn reuseport_udp(port: u16) -> UdpSocket {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        assert!(fd >= 0, "socket(): {}", std::io::Error::last_os_error());
        let one: libc::c_int = 1;
        for opt in [libc::SO_REUSEADDR, libc::SO_REUSEPORT] {
            let rc = libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            assert_eq!(rc, 0, "setsockopt: {}", std::io::Error::last_os_error());
        }
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr { s_addr: libc::INADDR_ANY.to_be() },
            sin_zero: [0; 8],
        };
        let rc = libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        assert_eq!(rc, 0, "bind(:{port}): {}", std::io::Error::last_os_error());
        UdpSocket::from_raw_fd(fd)
    }
}

/// Send a bare probe from `sock` to the echo stand-in and parse back the
/// post-NAT public `ip:port` it saw as our source — our observed candidate.
/// Bounded to at most 5 attempts * 2s read-timeout (~10s worst case) — never
/// an unbounded wait — then panics with a diagnostic rather than hanging.
fn observe_public_mapping(sock: &UdpSocket, server: &str) -> SocketAddr {
    sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut buf = [0u8; 64];
    for attempt in 0..5 {
        sock.send_to(b"AOBS", server).unwrap();
        if let Ok((n, from)) = sock.recv_from(&mut buf) {
            let addr_str = server.parse::<SocketAddr>().unwrap();
            if from == addr_str {
                return String::from_utf8_lossy(&buf[..n])
                    .parse()
                    .expect("observe stand-in echoes a parseable SocketAddr");
            }
            eprintln!("observe attempt {attempt}: reply from unexpected {from}, retrying");
        }
    }
    panic!("no observation reply from {server} after 5 attempts (~10s)");
}

#[test]
fn two_gateways_confirm_punch_through_port_restricted_nat_with_netem() {
    let test_start = Instant::now();
    let mut lab = Lab::new("pnch").expect("lab");
    let inet = lab.ns("inet").expect("ns inet");
    let pa = lab.ns("pa").expect("ns pa");
    let ra = lab.nat_router("ra", NatKind::PortRestricted).expect("nat ra");
    let pb = lab.ns("pb").expect("ns pb");
    let rb = lab.nat_router("rb", NatKind::PortRestricted).expect("nat rb");

    lab.veth((&pa, "eth0", "192.168.70.2/24"), (&ra, "in0", "192.168.70.1/24")).unwrap();
    lab.veth((&ra, "out0", "198.51.100.2/25"), (&inet, "ia", "198.51.100.1/25")).unwrap();
    lab.veth((&pb, "eth0", "192.168.71.2/24"), (&rb, "in0", "192.168.71.1/24")).unwrap();
    lab.veth((&rb, "out0", "198.51.100.130/25"), (&inet, "ib", "198.51.100.129/25")).unwrap();

    inet.exec(&["sysctl", "-w", "net.ipv4.ip_forward=1"]).unwrap();

    // MANDATORY netem (spec §7 / Phase-0 Finding 2), on the REAL out0-facing
    // interfaces `Lab::veth` just wired — applied exactly once per iface.
    apply_netem(&inet, "ia", 20).expect("apply netem ia");
    apply_netem(&inet, "ib", 20).expect("apply netem ib");
    // Honesty gate: fail loud (not a false punch-pass) if netem is missing.
    assert_netem_present(&inet, "ia");
    assert_netem_present(&inet, "ib");

    pa.exec(&["ip", "route", "add", "default", "via", "192.168.70.1"]).unwrap();
    pb.exec(&["ip", "route", "add", "default", "via", "192.168.71.1"]).unwrap();
    ra.exec(&["ip", "route", "add", "default", "via", "198.51.100.1"]).unwrap();
    rb.exec(&["ip", "route", "add", "default", "via", "198.51.100.129"]).unwrap();

    // Plain UDP echo standing in for the controller's observe endpoint. Bound
    // to the SPECIFIC `OBSERVE_ADDR` IP (198.51.100.1, `ia`'s address) rather
    // than `0.0.0.0` — matching `spike/natpunch/src/bin/observe.rs`, which is
    // invoked with that exact bind address (not the default `0.0.0.0:7777`).
    // This is load-bearing, not cosmetic: `inet` is dual-homed (`ia` at
    // 198.51.100.1/25 towards `ra`, `ib` at 198.51.100.129/25 towards `rb`).
    // A socket bound to `0.0.0.0` lets the kernel pick the reply's source IP
    // from the EGRESS route instead: replies to `ra` (reachable via `ia`)
    // happen to get source 198.51.100.1 — matching `OBSERVE_ADDR` purely by
    // coincidence, since `ia` IS 198.51.100.1 — but replies to `rb`
    // (reachable via `ib`) get source 198.51.100.129 (`ib`'s own address),
    // which does NOT match what `rb`'s conntrack expects back for the flow
    // it opened to 198.51.100.1. `rb` then sees the reply as an unrelated
    // new inbound flow (`conntrack -L` shows it `[UNREPLIED]`, wrong source)
    // instead of the SNAT return leg, and drops it — so `pb` never observes.
    // Binding to the fixed address pins the reply's source IP to
    // `OBSERVE_ADDR` regardless of egress interface, exactly like the real
    // controller (a single well-known observe endpoint) would appear to
    // every gateway.
    let observe_bind: SocketAddr = OBSERVE_ADDR.parse().expect("OBSERVE_ADDR parses");
    let inet_ns = inet.clone();
    let echo = std::thread::spawn(move || {
        join_netns(&inet_ns.name).expect("join inet netns");
        let sock = UdpSocket::bind(observe_bind).expect("bind observe stand-in");
        sock.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let mut buf = [0u8; 64];
        let deadline = Instant::now() + Duration::from_secs(40);
        while Instant::now() < deadline {
            if let Ok((_n, from)) = sock.recv_from(&mut buf) {
                let _ = sock.send_to(from.to_string().as_bytes(), from);
            }
        }
    });
    std::thread::sleep(Duration::from_millis(300));

    // Hand each side's observed candidate to the other, back-to-back
    // (mirrors the broker's simultaneous "go", spec §4).
    let (obs_tx, obs_rx) = mpsc::channel::<(&'static str, SocketAddr)>();
    let (go_tx_a, go_rx_a) = mpsc::channel::<SocketAddr>();
    let (go_tx_b, go_rx_b) = mpsc::channel::<SocketAddr>();

    let pa_ns = pa.clone();
    let obs_tx_a = obs_tx.clone();
    let side_a = std::thread::spawn(move || -> Option<SocketAddr> {
        join_netns(&pa_ns.name).expect("join pa netns");
        // Observe on a socket that is DROPPED before the punch (see module
        // doc comment) — no concurrent SO_REUSEPORT listener during punch.
        let observe_sock = reuseport_udp(WG_PORT);
        let observed = observe_public_mapping(&observe_sock, OBSERVE_ADDR);
        drop(observe_sock);
        obs_tx_a.send(("a", observed)).unwrap();
        let peer = go_rx_a
            .recv_timeout(STEP_TIMEOUT)
            .expect("peer candidate for a (timed out waiting for go)");
        wiremesh_gateway::punch::punch_candidates(WG_PORT, &[peer.to_string()], PUNCH_WINDOW)
            .expect("punch_candidates a")
    });

    let pb_ns = pb.clone();
    let obs_tx_b = obs_tx.clone();
    let side_b = std::thread::spawn(move || -> Option<SocketAddr> {
        join_netns(&pb_ns.name).expect("join pb netns");
        let observe_sock = reuseport_udp(WG_PORT);
        let observed = observe_public_mapping(&observe_sock, OBSERVE_ADDR);
        drop(observe_sock);
        obs_tx_b.send(("b", observed)).unwrap();
        let peer = go_rx_b
            .recv_timeout(STEP_TIMEOUT)
            .expect("peer candidate for b (timed out waiting for go)");
        wiremesh_gateway::punch::punch_candidates(WG_PORT, &[peer.to_string()], PUNCH_WINDOW)
            .expect("punch_candidates b")
    });
    drop(obs_tx);

    let mut observed_a: Option<SocketAddr> = None;
    let mut observed_b: Option<SocketAddr> = None;
    for _ in 0..2 {
        match obs_rx.recv_timeout(STEP_TIMEOUT) {
            Ok((who, addr)) => match who {
                "a" => observed_a = Some(addr),
                "b" => observed_b = Some(addr),
                _ => unreachable!(),
            },
            Err(e) => panic!(
                "timed out waiting for observation ({e}); got so far a={observed_a:?} b={observed_b:?} elapsed={:?}",
                test_start.elapsed()
            ),
        }
    }
    let observed_a = observed_a.expect("a observed");
    let observed_b = observed_b.expect("b observed");
    eprintln!("observed a={observed_a} b={observed_b} elapsed={:?}", test_start.elapsed());

    // Back-to-back "go" — each side gets the OTHER's observed candidate.
    go_tx_a.send(observed_b).unwrap();
    go_tx_b.send(observed_a).unwrap();

    // Every wait inside side_a/side_b (observe retries, go_rx recv_timeout,
    // punch_candidates' own deadline) is bounded, so a plain `join()` here
    // cannot hang — worst case it returns once the thread's own bounded
    // steps have all elapsed.
    let result_a = side_a.join().expect("side a thread panicked");
    let result_b = side_b.join().expect("side b thread panicked");
    eprintln!(
        "punch result a={result_a:?} b={result_b:?} elapsed={:?}",
        test_start.elapsed()
    );

    assert_eq!(
        result_a,
        Some(observed_b),
        "a's punch must confirm reachability of b's observed candidate"
    );
    assert_eq!(
        result_b,
        Some(observed_a),
        "b's punch must confirm reachability of a's observed candidate"
    );

    drop(echo); // detached; the lab teardown below removes the netns under it
    drop(lab);
}
