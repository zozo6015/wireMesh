// spike/natpunch2/tests/handshake.rs
//
// Puncher-socket-isolation de-risk (spec 2026-07-28-puncher-socket-isolation-design.md
// "De-risk spike"): prove that a punch driven ENTIRELY by boringtun's own
// endpoint-set handshake — with NO separate SO_REUSEPORT punch socket anywhere —
// reliably opens a port-restricted NAT mapping and completes a real, DIRECT
// WireGuard handshake between two gateways. This gates productionizing approach B.
//
// Contrast spike/natpunch, whose gateway held a transient SO_REUSEPORT punch
// socket blasting PING/PONG at peer candidates to pre-open the mapping. Here the
// ONLY socket that ever sends toward a peer candidate is boringtun's own WG
// socket; the reuseport socket exists solely for the brief public-mapping
// observation and is closed before boringtun starts (see gateway.rs / lib.rs).
//
// Topology (identical NAT layout to spike/natpunch):
//
//   pa 192.168.70.2/24 --- ra(in0 .1) [NAT] ra(out0 198.51.100.2/25) --- inet ia 198.51.100.1/25
//   pb 192.168.71.2/24 --- rb(in0 .1) [NAT] rb(out0 198.51.100.130/25) - inet ib 198.51.100.129/25
//
// MANDATORY (Phase-0 Finding 2): `tc netem delay 20ms` on each internet-side
// link => 40ms one-way ra<->rb. Zero-latency veths give a FALSE punch result.
//
// BAR: port-restricted pair must complete a real rx-corroborated WG handshake
// (BOTH sides: latest_handshake>0 AND received_bytes>0) reliably — 4/4 runs,
// matching natpunch. Also records endpoint-set -> handshake timing per run.

use natlab::{Lab, NatKind, Ns};
use std::io::{BufRead, BufReader};
use std::process::Child;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wg_keypair() -> (String, String) {
    use std::process::Command;
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

/// latest-handshake unix timestamp for wg0's peer (0 == never).
fn latest_handshake(ns: &Ns) -> u64 {
    // `timeout 3` so a stalled boringtun UAPI read (observed: `wg show` wedged in
    // unix_stream_read) can never wedge the poll loop — a hung tick reads 0.
    ns.exec(&["timeout", "3", "wg", "show", "wg0", "latest-handshakes"])
        .map(|o| String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter_map(|l| l.split_whitespace().last().and_then(|s| s.parse::<u64>().ok()))
            .max().unwrap_or(0))
        .unwrap_or(0)
}

/// received bytes for wg0's peer — the rx corroboration (path.rs): a handshake
/// RESPONSE actually came back, real bytes crossed. `wg show wg0 transfer`
/// prints `<pubkey>\t<received>\t<sent>`.
fn received_bytes(ns: &Ns) -> u64 {
    ns.exec(&["timeout", "3", "wg", "show", "wg0", "transfer"])
        .map(|o| String::from_utf8_lossy(&o.stdout)
            .lines()
            .filter_map(|l| { let mut it = l.split_whitespace(); it.next(); it.next().and_then(|s| s.parse::<u64>().ok()) })
            .max().unwrap_or(0))
        .unwrap_or(0)
}

fn wg_show(ns: &Ns) -> String {
    ns.exec(&["timeout", "3", "wg", "show", "wg0"])
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

/// Drain a spawned child's piped stdout into a shared buffer AND tee every line
/// to `logpath`, flushed per line. Two reasons: (1) the pipe would otherwise
/// fill and stall the child; (2) teeing to a FILE means the gateway's
/// ENDPOINT_SET / HANDSHAKE_OK / HANDSHAKE_NONE / GWREADY lines survive even if
/// the run hangs or is killed — the in-memory buffer alone is lost on hang.
fn drain_stdout(child: &mut Child, logpath: &str) -> Arc<Mutex<Vec<String>>> {
    let buf = Arc::new(Mutex::new(Vec::<String>::new()));
    if let Some(out) = child.stdout.take() {
        let b = buf.clone();
        let path = logpath.to_string();
        std::thread::spawn(move || {
            use std::io::Write;
            let mut f = std::fs::File::create(&path).ok();
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                if let Some(f) = f.as_mut() {
                    let _ = writeln!(f, "{line}");
                    let _ = f.flush();
                }
                b.lock().unwrap().push(line);
            }
        });
    }
    // Also tee STDERR (the gateway's "observed"/"go" lines and any anyhow error
    // land here) to `<logpath>.err`, so a gateway that fails BEFORE its first
    // stdout line still leaves a diagnosable trace.
    if let Some(err) = child.stderr.take() {
        let path = format!("{logpath}.err");
        std::thread::spawn(move || {
            use std::io::Write;
            let mut f = std::fs::File::create(&path).ok();
            for line in BufReader::new(err).lines().map_while(Result::ok) {
                if let Some(f) = f.as_mut() {
                    let _ = writeln!(f, "{line}");
                    let _ = f.flush();
                }
            }
        });
    }
    buf
}

/// wg0's tun-interface RX byte counter from `/sys` (kernel counter, read inside
/// the netns) — a boringtun-UAPI-INDEPENDENT liveness signal. It only advances
/// once decrypted inner packets are delivered, i.e. after the WG handshake
/// completed AND real data crossed. Used to corroborate the `wg show` reading,
/// which depends on the flaky userspace UAPI socket.
fn tun_rx_sys(ns: &Ns) -> u64 {
    ns.exec(&["cat", "/sys/class/net/wg0/statistics/rx_bytes"])
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<u64>().unwrap_or(0))
        .unwrap_or(0)
}

fn find_line<'a>(lines: &'a [String], needle: &str) -> Option<&'a String> {
    lines.iter().find(|l| l.contains(needle))
}

struct CellResult {
    /// The run's verdict: handshake definitively completed (wg-show rx OR ping).
    ok: bool,
    /// Pure `wg show` rx-corroborated detection (may go blind if UAPI stalls).
    wgshow_ok: bool,
    /// Ground-truth: ping crossed the tunnel.
    ping_ok: bool,
    ev: String,
}

/// One port-restricted run: brokers a "go", brings boringtun up on both
/// gateways with the peer endpoint set (NO punch socket), and returns whether a
/// real rx-corroborated WG handshake completed BOTH ways within the budget.
fn run_cell(prefix: &str) -> CellResult {
    let kind = NatKind::PortRestricted;
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

    // MANDATORY netem: 20ms each internet-side link.
    inet.exec(&["tc", "qdisc", "add", "dev", "ia", "root", "netem", "delay", "20ms"]).unwrap();
    inet.exec(&["tc", "qdisc", "add", "dev", "ib", "root", "netem", "delay", "20ms"]).unwrap();

    pa.exec(&["ip", "route", "add", "default", "via", "192.168.70.1"]).unwrap();
    pb.exec(&["ip", "route", "add", "default", "via", "192.168.71.1"]).unwrap();
    ra.exec(&["ip", "route", "add", "default", "via", "198.51.100.1"]).unwrap();
    rb.exec(&["ip", "route", "add", "default", "via", "198.51.100.129"]).unwrap();

    // Fail loud if netem is missing on either internet-facing link.
    let mut netem = String::new();
    for dev in ["ia", "ib"] {
        let out = inet.exec(&["tc", "qdisc", "show", "dev", dev]).unwrap();
        let s = String::from_utf8_lossy(&out.stdout).into_owned();
        assert!(s.contains("netem") && s.contains("delay 20"), "netem missing on {dev}: {s}");
        if dev == "ia" { netem = s; }
    }

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
    // Both must be up concurrently so both boringtuns are sending inits at the
    // same time (each side's outbound opens its NAT's filter for the other).
    let mut ga_child = pa.spawn(&[
        gw, "198.51.100.1:7000", "A", "51820", "198.51.100.1:7777",
        "wg0", &akf, &apub, "10.20.0.1/24",
    ]).unwrap();
    let mut gb_child = pb.spawn(&[
        gw, "198.51.100.1:7000", "B", "51820", "198.51.100.1:7777",
        "wg0", &bkf, &bpub, "10.20.0.2/24",
    ]).unwrap();
    let a_logf = format!("/tmp/{prefix}-gwA.log");
    let b_logf = format!("/tmp/{prefix}-gwB.log");
    let a_out = drain_stdout(&mut ga_child, &a_logf);
    let b_out = drain_stdout(&mut gb_child, &b_logf);
    let ga = KillOnDrop(ga_child);
    let gb = KillOnDrop(gb_child);

    // Require a real rx-corroborated handshake on BOTH sides. Wall-clock cap 75s
    // (a run that won't converge FAILS with captured evidence, never hangs).
    // Every probe below is timeout-guarded, so the loop itself can never wedge.
    let deadline = Instant::now() + Duration::from_secs(75);
    let mut ok = false;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1000));
        let a_live = latest_handshake(&pa) > 0 && received_bytes(&pa) > 0;
        let b_live = latest_handshake(&pb) > 0 && received_bytes(&pb) > 0;
        if a_live && b_live { ok = true; break; }
    }

    // Ground-truth corroboration, independent of the boringtun UAPI: an actual
    // ping across the tunnel (WG only passes data AFTER a completed handshake)
    // plus the kernel tun RX counter. If `wg show` went blind (UAPI socket
    // vanished) but the tunnel is really up, THIS catches it — so a broken
    // measurement can't masquerade as a genuine punch failure.
    let ping_out = pa.exec(&["ping", "-c", "3", "-W", "3", "10.20.0.2"]).ok();
    let ping_ok = ping_out.as_ref().map(|o| o.status.success()).unwrap_or(false);
    let ping_text = ping_out
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default();
    let tun_rx_pa = tun_rx_sys(&pa);
    let tun_rx_pb = tun_rx_sys(&pb);
    // The run's verdict: handshake definitively completed if EITHER the
    // rx-corroborated wg-show reading fired OR the ground-truth ping crossed.
    let handshake_up = ok || ping_ok;

    // ---- evidence ----
    let mut ev = String::new();
    ev.push_str(&format!("=== cell {prefix} (PortRestricted, NO punch socket) ===\n"));
    ev.push_str(&format!("netem(ia): {netem}"));
    // Gateway in-process timing lines (endpoint-set -> handshake).
    for (id, out) in [("A", &a_out), ("B", &b_out)] {
        let lines = out.lock().unwrap();
        for needle in ["ENDPOINT_SET", "HANDSHAKE_OK", "HANDSHAKE_NONE"] {
            if let Some(l) = find_line(&lines, needle) {
                ev.push_str(&format!("gw{id}: {l}\n"));
            }
        }
    }
    ev.push_str(&format!("wg show wg0 @pa:\n{}\n", wg_show(&pa)));
    ev.push_str(&format!("wg show wg0 @pb:\n{}\n", wg_show(&pb)));
    ev.push_str(&format!("latest-handshake pa={} pb={} rx pa={} pb={}\n",
        latest_handshake(&pa), latest_handshake(&pb), received_bytes(&pa), received_bytes(&pb)));
    ev.push_str(&format!("tun rx_bytes (kernel /sys, UAPI-independent) pa={tun_rx_pa} pb={tun_rx_pb}\n"));
    ev.push_str(&format!("verdict: wgshow_ok={ok} ping_ok={ping_ok} handshake_up={handshake_up}\n"));
    ev.push_str(&format!("ping 10.20.0.1->10.20.0.2:\n{ping_text}\n"));
    // Mechanism proof: conntrack on the routers shows the WG 51820 flow crossing
    // the NAT — and in THIS spike the only socket that could have opened it is
    // boringtun's own (there is no punch socket).
    for (r, name) in [(&ra, "ra"), (&rb, "rb")] {
        if let Ok(o) = r.exec(&["conntrack", "-L", "-p", "udp"]) {
            let s = String::from_utf8_lossy(&o.stdout);
            let wg: Vec<&str> = s.lines().filter(|l| l.contains("dport=51820") || l.contains("sport=51820")).collect();
            ev.push_str(&format!("conntrack@{name} (wg 51820 flows):\n{}\n", wg.join("\n")));
        }
    }

    ev.push_str(&format!("gwA log: {a_logf}   gwB log: {b_logf}\n"));

    drop((ga, gb, obs, brk));
    CellResult { ok: handshake_up, wgshow_ok: ok, ping_ok, ev }
}

/// POSITIVE, 4/4: port-restricted pair must complete a real rx-corroborated
/// direct WG handshake driven purely by boringtun's endpoint-set init — no
/// punch socket — reliably across 4 independent runs.
#[test]
fn boringtun_endpoint_driven_punch_4_of_4() {
    const RUNS: usize = 4;
    let mut passed = 0usize;
    let mut all_ev = String::new();
    for i in 0..RUNS {
        let prefix = format!("np2r{i}");
        let r = run_cell(&prefix);
        all_ev.push_str(&r.ev);
        all_ev.push_str(&format!(
            ">>> run {i}: handshake_up={} (wgshow_ok={} ping_ok={})\n\n",
            r.ok, r.wgshow_ok, r.ping_ok));
        // Bar: a direct WG handshake definitively completed over the punched NAT
        // with NO punch socket — corroborated by the ground-truth ping and/or the
        // rx-corroborated wg-show reading.
        if r.ok { passed += 1; }
        eprintln!("{}", r.ev);
        eprintln!(">>> run {i}: handshake_up={} (wgshow_ok={} ping_ok={})",
            r.ok, r.wgshow_ok, r.ping_ok);
    }
    eprintln!("\n==== SUMMARY: {passed}/{RUNS} runs achieved a direct handshake (no punch socket) ====");
    assert_eq!(
        passed, RUNS,
        "boringtun-endpoint-driven punch must reach a direct path 4/4 (no punch socket). \
         Evidence:\n{all_ev}"
    );
}
