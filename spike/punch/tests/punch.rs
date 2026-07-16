// spike/punch/tests/punch.rs
//
// Proves Bet 4's core claim (spec §6.1): brokered simultaneous UDP hole
// punching (Task 12's broker + puncher) succeeds for endpoint-independent
// (port-restricted) NATs and is expected to FAIL for endpoint-dependent
// (symmetric) NATs. The negative cell is not a bug — it's the exact case
// that justifies the relay's existence (Tasks 13-14): a symmetric NAT opens
// a different, unpredictable external port per destination, so the mapping
// the observe server saw is only valid for packets to the observe server,
// never for packets to the peer.
//
// Topology (fresh Lab per cell so the two tests never share netns/nft
// state; subnets/prefixes are distinct from Task 10's nat_behavior.rs
// (203.0.113.0/24) and Task 11's observe.rs (203.0.114.0/24)):
//
//   pa (192.168.70.2/24) --veth-- ra::in0 (192.168.70.1/24)
//                                 ra = nat_router(kind)
//                                 ra::out0 (198.51.100.2/25) --veth-- inet::ia (198.51.100.1/25)
//
//   pb (192.168.71.2/24) --veth-- rb::in0 (192.168.71.1/24)
//                                 rb = nat_router(kind)
//                                 rb::out0 (198.51.100.130/25) --veth-- inet::ib (198.51.100.129/25)
//
// `ia`/`ib` are two independent point-to-point veth links into the same
// `inet` namespace: the ra side gets the lower /25 (198.51.100.0/25), the
// rb side the upper /25 (198.51.100.128/25). `inet` has `ip_forward=1` and
// is where `observe` and `broker` both listen, giving each punch cell one
// rendezvous point reachable from both NAT'd private namespaces (`pa`,
// `pb`) via their default routes through `ra`/`rb`.
//
// DEVIATION from the task brief's sketch (which put a /24 on ra's side):
// with 198.51.100.2/24 on ra::out0, ra considers rb's public address
// (198.51.100.130) ON-LINK and ARPs for it on the `ia` link, where nothing
// answers (inet has no proxy_arp and .130 lives on its other link) — so
// NEITHER direction of punch traffic can flow (ra's own replies to rb hit
// the same dead ARP). Verified directly with a minimal 3-netns repro:
// `ip neigh` shows `198.51.100.130 dev v0 INCOMPLETE` and 100% loss both
// ways under /24, 0% loss both ways under the /25 split used here. The
// brief's observe/broker traffic (to on-link 198.51.100.1) masked this.

use natlab::{Lab, NatKind};
use std::process::{Child, Command, Output};
use std::sync::mpsc;
use std::time::Duration;

/// Kills a long-running helper (`observe`, `broker`) on drop, including on
/// panic-driven unwind — mirrors observe.rs's `KillOnDrop` so a failed
/// assertion never leaks a background process into the dev container.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Waits for `child` with a hard safety-net timeout, SIGKILLing it if it
/// hasn't exited by then. `puncher` already self-terminates within ~5s
/// (its own PING/PONG deadline), so this is only a backstop against an
/// implementation bug (e.g. broker hanging on a 3rd `accept()`, or a
/// puncher blocked forever in `TcpStream::connect`) turning a single test
/// into a hung suite. Modeled on nat_behavior.rs's `wait_with_timeout`.
fn wait_with_timeout(child: Child, timeout: Duration) -> Output {
    let pid = child.id();
    let (exited_tx, exited_rx) = mpsc::channel::<()>();
    let watcher = std::thread::spawn(move || {
        if exited_rx.recv_timeout(timeout).is_err() {
            let _ = Command::new("kill").arg("-9").arg(pid.to_string()).status();
        }
    });
    let out = child.wait_with_output().expect("wait_with_output");
    let _ = exited_tx.send(());
    let _ = watcher.join();
    out
}

/// One side's punch outcome: whether the puncher exited 0 and what it
/// printed (the `PUNCHED <peer_addr>` line lives in stdout — used by the
/// positive cell's right-reason check).
struct Outcome {
    punched: bool,
    stdout: String,
}

/// Builds the pa--ra--inet--rb--pb topology for `kind`, runs one brokered
/// punch attempt, and returns each side's outcome (A = pa's puncher,
/// B = pb's puncher).
fn punch_cell(kind: NatKind, prefix: &str) -> (Outcome, Outcome) {
    let mut lab = Lab::new(prefix).unwrap();
    let inet = lab.ns("inet").unwrap();
    let pa = lab.ns("pa").unwrap();
    let ra = lab.nat_router("ra", kind).unwrap();
    let pb = lab.ns("pb").unwrap();
    let rb = lab.nat_router("rb", kind).unwrap();

    lab.veth(
        (&pa, "eth0", "192.168.70.2/24"),
        (&ra, "in0", "192.168.70.1/24"),
    )
    .unwrap();
    lab.veth(
        (&ra, "out0", "198.51.100.2/25"),
        (&inet, "ia", "198.51.100.1/25"),
    )
    .unwrap();
    lab.veth(
        (&pb, "eth0", "192.168.71.2/24"),
        (&rb, "in0", "192.168.71.1/24"),
    )
    .unwrap();
    lab.veth(
        (&rb, "out0", "198.51.100.130/25"),
        (&inet, "ib", "198.51.100.129/25"),
    )
    .unwrap();

    // inet forwards between its two links so ra's and rb's public sides
    // can reach each other (and inet's own observe/broker addresses).
    inet.exec(&["sysctl", "-w", "net.ipv4.ip_forward=1"]).unwrap();

    // REQUIRED LAB-FIDELITY FIX (real finding, see phase0-results Bet 4):
    // model internet path latency with 20ms netem on each internet-side
    // link (one-way ra<->rb = 40ms). Without it, the ~50us veth path makes
    // the peer's first PING arrive at the local router BEFORE the local
    // side's own first outbound has crossed it. On Linux masquerade that
    // unsolicited inbound creates a local-stack conntrack entry occupying
    // the reply tuple for port 6100, so the local side's outbound
    // masquerade is forced onto a mutated source port (confirmed in
    // /proc/net/nf_conntrack: A's mapping showed sport 51642 with an
    // [UNREPLIED] .130:6100->.2:6100 entry above it) — after which neither
    // direction can ever match, deterministically, for conntrack's 30s UDP
    // timeout (> the 5s punch window). Simultaneous punch relies on each
    // side's outbound beating the peer's inbound through its own NAT; on
    // the real internet one-way latency (tens of ms) >> broker go-skew
    // (us..ms) guarantees that, and this netem restores the same invariant
    // in the lab. This is NOT masking a flake: without delay the failure
    // is deterministic (0% punch), with it success is deterministic.
    inet.exec(&["tc", "qdisc", "add", "dev", "ia", "root", "netem", "delay", "20ms"])
        .unwrap();
    inet.exec(&["tc", "qdisc", "add", "dev", "ib", "root", "netem", "delay", "20ms"])
        .unwrap();
    pa.exec(&["ip", "route", "add", "default", "via", "192.168.70.1"])
        .unwrap();
    pb.exec(&["ip", "route", "add", "default", "via", "192.168.71.1"])
        .unwrap();
    ra.exec(&["ip", "route", "add", "default", "via", "198.51.100.1"])
        .unwrap();
    rb.exec(&["ip", "route", "add", "default", "via", "198.51.100.129"])
        .unwrap();

    let obs_child = inet
        .spawn(&[env!("CARGO_BIN_EXE_observe"), "198.51.100.1:7777"])
        .unwrap();
    let _obs_guard = KillOnDrop(obs_child);
    let brk_child = inet
        .spawn(&[env!("CARGO_BIN_EXE_broker"), "198.51.100.1:7000"])
        .unwrap();
    let _brk_guard = KillOnDrop(brk_child);
    // Let observe/broker finish binding before either puncher's first probe.
    std::thread::sleep(Duration::from_millis(300));

    let p = env!("CARGO_BIN_EXE_puncher");
    // Spawn BOTH punchers before waiting on either — the broker only sends
    // "go" once both have registered, and once it does, both sides need to
    // be blasting PINGs concurrently for the port-restricted mapping (opened
    // by each side's own first blast) to be up before the peer's packets
    // arrive. Waiting on `ca` before spawning `cb` would serialize them and
    // is not equivalent to this.
    let ca = pa
        .spawn(&[p, "198.51.100.1:7000", "A", "6100", "198.51.100.1:7777"])
        .unwrap();
    let cb = pb
        .spawn(&[p, "198.51.100.1:7000", "B", "6100", "198.51.100.1:7777"])
        .unwrap();

    // Puncher's own deadline is 5s; 15s leaves generous margin for process
    // spawn/schedule jitter in the container before treating it as hung.
    let out_a = wait_with_timeout(ca, Duration::from_secs(15));
    let out_b = wait_with_timeout(cb, Duration::from_secs(15));

    eprintln!(
        "punch_cell({prefix}): A exit={:?} stdout={:?} stderr={}",
        out_a.status.code(),
        String::from_utf8_lossy(&out_a.stdout),
        String::from_utf8_lossy(&out_a.stderr)
    );
    eprintln!(
        "punch_cell({prefix}): B exit={:?} stdout={:?} stderr={}",
        out_b.status.code(),
        String::from_utf8_lossy(&out_b.stdout),
        String::from_utf8_lossy(&out_b.stderr)
    );

    (
        Outcome {
            punched: out_a.status.success(),
            stdout: String::from_utf8_lossy(&out_a.stdout).into_owned(),
        },
        Outcome {
            punched: out_b.status.success(),
            stdout: String::from_utf8_lossy(&out_b.stdout).into_owned(),
        },
    )
}

/// The positive result Bet 4 exists to prove: two peers behind SEPARATE
/// port-restricted (endpoint-independent-mapping) NATs, brokered via a
/// third-party rendezvous, both successfully hole-punch to each other.
#[test]
fn port_restricted_pair_punches() {
    let (a, b) = punch_cell(NatKind::PortRestricted, "ppr");
    assert!(
        a.punched && b.punched,
        "port-restricted pair must punch (a={} b={})",
        a.punched,
        b.punched
    );
    // Right-reason check: each side must have punched to the PEER's real
    // post-NAT public address (the peer router's out0 IP) — never loopback.
    // Guards against any regression of the 0.0.0.0-candidate self-punch bug
    // (sendto to 0.0.0.0 is kernel-rewritten to 127.0.0.1, so a puncher
    // that dials a wildcard candidate PUNCHes itself instantly).
    assert!(
        a.stdout.contains("PUNCHED 198.51.100.130:"),
        "A must punch to B's public NAT addr (rb out0), got stdout={:?}",
        a.stdout
    );
    assert!(
        b.stdout.contains("PUNCHED 198.51.100.2:"),
        "B must punch to A's public NAT addr (ra out0), got stdout={:?}",
        b.stdout
    );
}

/// The negative result that justifies the relay (Tasks 13-14): two peers
/// behind SEPARATE symmetric (endpoint-dependent-mapping) NATs do NOT both
/// punch, because each side's observed mapping is only valid for the
/// observe server, not for the peer's address.
#[test]
fn symmetric_pair_fails_to_punch() {
    let (a, b) = punch_cell(NatKind::Symmetric, "psy");
    assert!(
        !(a.punched && b.punched),
        "symmetric pair punching would be a (welcome) surprise — investigate before changing this test"
    );
}
