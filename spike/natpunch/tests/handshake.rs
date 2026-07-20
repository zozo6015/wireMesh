// spike/natpunch/tests/handshake.rs
//
// Cycle 4b LINCHPIN de-risk (spec 2026-07-20-cycle4b-nat-traversal-design.md §3):
// prove that two boringtun WireGuard gateways behind SEPARATE port-restricted
// NATs complete a REAL WG handshake and pass traffic over a DIRECT tunnel after a
// controller-brokered simultaneous hole punch that uses a TRANSIENT SO_REUSEPORT
// punch socket on the WG listen port (punch to open the mapping, close the punch
// socket, then let boringtun reuse that mapping).
//
// Topology (identical NAT layout to spike/punch/tests/punch.rs — the /25 split on
// the internet segment is load-bearing, see that file's ARP note):
//
//   pa 192.168.70.2/24 --- ra(in0 .1) [NAT] ra(out0 198.51.100.2/25) --- inet ia 198.51.100.1/25
//   pb 192.168.71.2/24 --- rb(in0 .1) [NAT] rb(out0 198.51.100.130/25) - inet ib 198.51.100.129/25
//
//   inet forwards between ia/ib and hosts observe(:7777) + broker(:7000).
//   WG tunnel overlay: 10.20.0.1 (pa) <-> 10.20.0.2 (pb).
//
// MANDATORY (Phase-0 Finding 2, spec §7): `tc netem delay 20ms` on each
// internet-side link (ia, ib) => 40ms one-way ra<->rb. Zero-latency veths give a
// FALSE punch-failure (the peer's inbound beats the local outbound through the
// local NAT and poisons conntrack for ~30s). Without netem this test would be
// meaningless.

use natlab::{Lab, NatKind, Ns};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wg_keypair() -> (String, String) {
    let priv_out = Command::new("wg").arg("genkey").output().unwrap();
    let privkey = String::from_utf8(priv_out.stdout).unwrap().trim().to_string();
    let pub_out = {
        use std::io::Write;
        let mut c = Command::new("wg").arg("pubkey")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn().unwrap();
        c.stdin.as_mut().unwrap().write_all(privkey.as_bytes()).unwrap();
        c.wait_with_output().unwrap()
    };
    (privkey, String::from_utf8(pub_out.stdout).unwrap().trim().to_string())
}

/// Latest-handshake unix timestamp boringtun reports for wg0's single peer, via
/// UAPI (`wg show wg0 latest-handshakes`). 0 == never handshaked.
fn latest_handshake(ns: &Ns) -> u64 {
    let out = match ns.exec(&["wg", "show", "wg0", "latest-handshakes"]) {
        Ok(o) => o,
        Err(_) => return 0,
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_whitespace().last())
        .filter_map(|s| s.parse::<u64>().ok())
        .max()
        .unwrap_or(0)
}

fn wg_show(ns: &Ns) -> String {
    ns.exec(&["wg", "show", "wg0"])
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// Build the NAT lab for `kind`, brokers a punch, brings boringtun up on both
/// gateways, and returns (handshake_completed, ping_ok, evidence-string).
fn run_cell(kind: NatKind, prefix: &str) -> (bool, bool, String) {
    let mut lab = Lab::new(prefix).unwrap();
    let inet = lab.ns("inet").unwrap();
    let pa = lab.ns("pa").unwrap();
    let ra = lab.nat_router("ra", kind).unwrap();
    let pb = lab.ns("pb").unwrap();
    let rb = lab.nat_router("rb", kind).unwrap();

    lab.veth((&pa, "eth0", "192.168.70.2/24"), (&ra, "in0", "192.168.70.1/24")).unwrap();
    lab.veth((&ra, "out0", "198.51.100.2/25"), (&inet, "ia", "198.51.100.1/25")).unwrap();
    lab.veth((&pb, "eth0", "192.168.71.2/24"), (&rb, "in0", "192.168.71.1/24")).unwrap();
    lab.veth((&rb, "out0", "198.51.100.130/25"), (&inet, "ib", "198.51.100.129/25")).unwrap();

    inet.exec(&["sysctl", "-w", "net.ipv4.ip_forward=1"]).unwrap();

    // MANDATORY netem (spec §7 / Phase-0 Finding 2): 20ms each internet-side link.
    inet.exec(&["tc", "qdisc", "add", "dev", "ia", "root", "netem", "delay", "20ms"]).unwrap();
    inet.exec(&["tc", "qdisc", "add", "dev", "ib", "root", "netem", "delay", "20ms"]).unwrap();

    pa.exec(&["ip", "route", "add", "default", "via", "192.168.70.1"]).unwrap();
    pb.exec(&["ip", "route", "add", "default", "via", "192.168.71.1"]).unwrap();
    ra.exec(&["ip", "route", "add", "default", "via", "198.51.100.1"]).unwrap();
    rb.exec(&["ip", "route", "add", "default", "via", "198.51.100.129"]).unwrap();

    // Confirm netem is actually installed (honesty: fail loud if it's missing).
    let netem = inet.exec(&["tc", "qdisc", "show", "dev", "ia"]).unwrap();
    let netem = String::from_utf8_lossy(&netem.stdout).into_owned();
    assert!(netem.contains("netem") && netem.contains("delay 20"), "netem not present: {netem}");

    let obs = KillOnDrop(inet.spawn(&[env!("CARGO_BIN_EXE_observe"), "198.51.100.1:7777"]).unwrap());
    let brk = KillOnDrop(inet.spawn(&[env!("CARGO_BIN_EXE_broker"), "198.51.100.1:7000"]).unwrap());
    std::thread::sleep(Duration::from_millis(300));

    let (apriv, apub) = wg_keypair();
    let (bpriv, bpub) = wg_keypair();
    let akf = format!("/tmp/{prefix}-a.key");
    let bkf = format!("/tmp/{prefix}-b.key");
    std::fs::write(&akf, &apriv).unwrap();
    std::fs::write(&bkf, &bpriv).unwrap();

    let gw = env!("CARGO_BIN_EXE_gateway");
    // Spawn BOTH before waiting — broker fires "go" only once both register, and
    // both must be blasting concurrently for the simultaneous punch to work.
    let ga = KillOnDrop(pa.spawn(&[
        gw, "198.51.100.1:7000", "A", "51820", "198.51.100.1:7777",
        "wg0", &akf, &apub, "10.20.0.1/24",
    ]).unwrap());
    let gb = KillOnDrop(pb.spawn(&[
        gw, "198.51.100.1:7000", "B", "51820", "198.51.100.1:7777",
        "wg0", &bkf, &bpub, "10.20.0.2/24",
    ]).unwrap());

    // Wait for a WG handshake on both sides (spec: ≤30s convergence budget).
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut hs = false;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_secs(1));
        let ha = latest_handshake(&pa);
        let hb = latest_handshake(&pb);
        if ha > 0 && hb > 0 {
            hs = true;
            break;
        }
    }

    // Ping across the WG tunnel (10.20.0.1 -> 10.20.0.2). This traffic is
    // WG-encapsulated UDP that traverses BOTH NAT routers (pa->ra->inet->rb->pb).
    let mut ping_ok = false;
    if hs {
        let ping = pa.exec(&["ping", "-c", "3", "-W", "3", "10.20.0.2"]);
        ping_ok = ping.map(|o| o.status.success()).unwrap_or(false);
    }

    // ---- evidence ----
    let mut ev = String::new();
    ev.push_str(&format!("=== cell {prefix} ({:?}) ===\n", kindname(kind)));
    ev.push_str(&format!("netem(ia): {}", netem));
    ev.push_str(&format!("wg show wg0 @pa:\n{}\n", wg_show(&pa)));
    ev.push_str(&format!("wg show wg0 @pb:\n{}\n", wg_show(&pb)));
    ev.push_str(&format!("latest-handshake pa={} pb={}\n", latest_handshake(&pa), latest_handshake(&pb)));
    if hs {
        let p = pa.exec(&["ping", "-c", "3", "-W", "3", "10.20.0.2"]).unwrap();
        ev.push_str(&format!("ping 10.20.0.1->10.20.0.2:\n{}\n", String::from_utf8_lossy(&p.stdout)));
    }
    // Prove traffic crosses the NATs: conntrack on the routers shows the WG flow.
    for (r, name) in [(&ra, "ra"), (&rb, "rb")] {
        if let Ok(o) = r.exec(&["conntrack", "-L", "-p", "udp"]) {
            let s = String::from_utf8_lossy(&o.stdout);
            let wglines: Vec<&str> = s.lines().filter(|l| l.contains("dport=51820") || l.contains("sport=51820")).collect();
            ev.push_str(&format!("conntrack@{name} (wg 51820 flows):\n{}\n", wglines.join("\n")));
        }
    }
    ev.push_str(&format!("ip -s link wg0 @pa:\n{}\n",
        pa.exec(&["ip", "-s", "link", "show", "wg0"]).map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default()));

    drop((ga, gb, obs, brk));
    (hs, ping_ok, ev)
}

fn kindname(k: NatKind) -> &'static str {
    match k { NatKind::PortRestricted => "PortRestricted", NatKind::Symmetric => "Symmetric" }
}

/// POSITIVE: port-restricted pair must complete a real WG handshake over the
/// brokered punch and ping across the direct tunnel.
#[test]
fn port_restricted_direct_handshake_and_ping() {
    let (hs, ping_ok, ev) = run_cell(NatKind::PortRestricted, "hpr");
    eprintln!("{ev}");
    assert!(hs, "port-restricted pair must complete a REAL WG handshake through the NATs");
    assert!(ping_ok, "port-restricted pair must ping across the direct WG tunnel (0% loss)");
}

/// NEGATIVE CONTROL: symmetric pair must NOT complete a direct handshake (the
/// observed candidate is the wrong per-destination port) — validating that
/// symmetric correctly needs a relay (4c).
#[test]
fn symmetric_pair_fails_direct_handshake() {
    let (hs, _ping, ev) = run_cell(NatKind::Symmetric, "hsy");
    eprintln!("{ev}");
    assert!(!hs, "symmetric pair completing a direct handshake would be a surprise — investigate before changing");
}
