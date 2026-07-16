// spike/relay/tests/wg_over_relay.rs
//
// Task 14, Step 2 (test author): the single most load-bearing spike test —
// real WireGuard traffic through the authenticated QUIC relay (Task 13's
// `relay`/`relay::Client`) via `udpshim` (Task 14, Step 1), at tun MTU 1280
// (spec §6.1). Proves Bet 3's actual point: the relay isn't just a bare
// datagram bridge (already shown in tests/bridge.rs) — it can carry a real
// WireGuard session end to end when the two gateways have NO other path to
// each other at all.
//
// ## Topology — A and B have NO direct link; R (running the relay) is the
// ## ONLY path between them.
//
//   a::u0  (10.9.3.1/24) --veth-- r::ur0 (10.9.3.2/24)
//   b::u1  (10.9.4.1/24) --veth-- r::ur1 (10.9.4.2/24)
//
// The relay binds on r's A-facing address, 10.9.3.2:4443. That's on a's
// directly-connected subnet, so a needs no extra route. It is NOT on b's
// directly-connected subnet, so b gets an explicit route to it via r
// (10.9.4.2). r additionally gets ip_forward=1 per the brief, though nothing
// here actually transits r — the relay terminates every connection AT r, it
// never forwards IP packets between a and b.
//
// WireGuard (spike-tunnel, built by the implementer, path via
// SPIKE_TUNNEL_BIN — this crate is a standalone workspace, see
// spike/enforcer's tests/common/mod.rs for the same adaptation) runs in a
// and b. Each side's WG peer "endpoint" points at 127.0.0.1:51999 — its OWN
// LOCAL udpshim — never at the other side's underlay address, because none
// exists:
//
//   a: wg0 -> 127.0.0.1:51999 (udpshim, id gw-A, peer gw-B) -> QUIC -> relay@10.9.3.2:4443
//   b: wg0 -> 127.0.0.1:51999 (udpshim, id gw-B, peer gw-A) -> QUIC -> relay@10.9.3.2:4443
//
// Overlay 10.10.0.1 <-> 10.10.0.2, tun MTU 1280 — mirrors the canonical
// wg_lab pattern (spike/tunnel/tests/common/mod.rs) with underlay endpoints
// replaced by the local shim address.
//
// ## The shim peer-learning chicken/egg (why both sides ping in the
// ## background before we ever check for a handshake)
//
// `udpshim`'s downlink only knows where to deliver a datagram arriving from
// the relay by forwarding to whichever *local* address last sent it
// something (see the implementer's task-14-report.md) — there is no local
// peer to deliver to until the local WireGuard instance has sent at least
// one packet through its own shim. If only A pings, A's shim learns A's wg0
// address and forwards the handshake initiation over the relay to B's
// shim — which drops it, because B's wg0 has never sent anything locally
// yet and B's shim has no local peer on record. So BOTH sides must
// independently queue outbound traffic before either side's inbound relayed
// packets have anywhere to go. Running a background ping from both a and b
// concurrently (rather than a persistent-keepalive timer, whose first-fire
// timing isn't specified anywhere in this repo) makes both sides "send
// first" deterministically and quickly, satisfying that requirement without
// depending on undocumented boringtun timer behavior.
use natlab::{Lab, Ns};
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{fs, thread};

/// Kills a background process on drop (including on panic-driven unwind),
/// mirroring `KillOnDrop` in spike/relay/tests/bridge.rs and
/// spike/punch/tests/punch.rs — a failed assertion must never leak a
/// relay/shim/tunnel process out of this test.
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
        let mut c = Command::new("wg")
            .arg("pubkey")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin.as_mut().unwrap().write_all(privkey.as_bytes()).unwrap();
        c.wait_with_output().unwrap()
    };
    (privkey.clone(), String::from_utf8(pub_out.stdout).unwrap().trim().to_string())
}

/// A tmpdir unique to this test process (same convention as
/// tests/bridge.rs's `unique_dir`).
fn unique_dir(tag: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("relay-wg-test-{tag}-{}", std::process::id()))
}

fn run_ok(bin: &str, args: &[&str]) {
    let status = Command::new(bin)
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("spawn {bin} {args:?}: {e}"));
    assert!(status.success(), "{bin} {args:?} failed: {status:?}");
}

/// Spawns a background thread that drains `child`'s stderr into a shared
/// log buffer (echoing each line to this test's own stderr as it arrives),
/// so the relay's registration log can be inspected later without racing a
/// still-running process for its pipe.
fn capture_stderr(child: &mut Child, tag: &'static str) -> Arc<Mutex<Vec<String>>> {
    let log = Arc::new(Mutex::new(Vec::new()));
    let stderr = child.stderr.take().expect("child spawned with piped stderr");
    let log2 = log.clone();
    thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            eprintln!("[{tag}] {line}");
            log2.lock().unwrap().push(line);
        }
    });
    log
}

/// Reads `wg show <iface> latest-handshakes` and returns the peer's
/// handshake epoch (0 if none yet).
fn handshake_epoch(ns: &Ns) -> u64 {
    let out = ns.exec(&["wg", "show", "wg0", "latest-handshakes"]).unwrap();
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .last()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}

fn mbits_per_sec(out: &Output) -> String {
    let txt = String::from_utf8_lossy(&out.stdout);
    txt.lines()
        .filter(|l| l.contains("sender") || l.contains("receiver"))
        .map(|l| l.trim().to_string())
        .collect::<Vec<_>>()
        .join(" | ")
}

#[test]
fn wireguard_handshakes_and_pings_at_mtu_1280_over_relay() {
    let tunnel_bin = std::env::var("SPIKE_TUNNEL_BIN").expect(
        "SPIKE_TUNNEL_BIN must be set to the path of the built spike-tunnel binary \
         (e.g. /work/spike/tunnel/target/release/spike-tunnel) — spike/tunnel is a \
         standalone workspace, see spike/enforcer/enforcer/tests/common/mod.rs for \
         the same adaptation",
    );
    let mkcerts_bin = env!("CARGO_BIN_EXE_mkcerts");
    let relay_bin = env!("CARGO_BIN_EXE_relay");
    let udpshim_bin = env!("CARGO_BIN_EXE_udpshim");

    // --- topology: a--r--b, a and b NOT directly connected -----------------
    let mut lab = Lab::new("wgr").unwrap();
    let r = lab.ns("r").unwrap();
    let a = lab.ns("a").unwrap();
    let b = lab.ns("b").unwrap();

    lab.veth((&a, "u0", "10.9.3.1/24"), (&r, "ur0", "10.9.3.2/24")).unwrap();
    lab.veth((&b, "u1", "10.9.4.1/24"), (&r, "ur1", "10.9.4.2/24")).unwrap();

    r.exec(&["sysctl", "-w", "net.ipv4.ip_forward=1"]).unwrap();
    // b's only route to the relay's bind address (on a's subnet) is via r.
    b.exec(&["ip", "route", "add", "10.9.3.0/24", "via", "10.9.4.2"]).unwrap();

    // --- right-reason sanity: there really is no direct underlay path -----
    // If this ever started passing, a subsequent overlay ping success
    // wouldn't prove the relay carried anything.
    assert!(
        a.exec(&["ping", "-c", "1", "-W", "1", "10.9.4.1"]).is_err(),
        "A must have NO direct underlay route/reachability to B's address — \
         otherwise a passing overlay ping wouldn't prove the relay carried it"
    );

    // --- certs + relay -------------------------------------------------
    let dir = unique_dir("main");
    run_ok(mkcerts_bin, &[dir.to_str().unwrap()]);

    let relay_bind = "10.9.3.2:4443";
    let mut relay_child = r
        .spawn(&[relay_bin, relay_bind, dir.to_str().unwrap()])
        .unwrap();
    let relay_log = capture_stderr(&mut relay_child, "relay");
    let _relay_guard = KillOnDrop(relay_child);
    thread::sleep(Duration::from_millis(400)); // let the relay finish binding

    // --- udpshims: wg's endpoint on each side is its OWN local shim ------
    let shim_a = a
        .spawn(&[
            udpshim_bin,
            "127.0.0.1:51999",
            relay_bind,
            dir.to_str().unwrap(),
            "gw-A",
            "gw-B",
        ])
        .unwrap();
    let _shim_a_guard = KillOnDrop(shim_a);
    let shim_b = b
        .spawn(&[
            udpshim_bin,
            "127.0.0.1:51999",
            relay_bind,
            dir.to_str().unwrap(),
            "gw-B",
            "gw-A",
        ])
        .unwrap();
    let _shim_b_guard = KillOnDrop(shim_b);
    thread::sleep(Duration::from_millis(600)); // shims connect + register with the relay

    // --- WireGuard, endpoints pointed at the LOCAL shim -------------------
    let (apriv, apub) = wg_keypair();
    let (bpriv, bpub) = wg_keypair();

    let ta = a.spawn(&[tunnel_bin.as_str(), "wg0"]).unwrap();
    let _ta_guard = KillOnDrop(ta);
    let tb = b.spawn(&[tunnel_bin.as_str(), "wg0"]).unwrap();
    let _tb_guard = KillOnDrop(tb);
    thread::sleep(Duration::from_millis(800)); // device + UAPI socket up

    for (ns, privkey, peer_pub, my_ip, peer_ip) in [
        (&a, &apriv, &bpub, "10.10.0.1/24", "10.10.0.2"),
        (&b, &bpriv, &apub, "10.10.0.2/24", "10.10.0.1"),
    ] {
        let kf = format!("/tmp/{}.key", ns.name);
        fs::write(&kf, privkey).unwrap();
        ns.exec(&[
            "wg", "set", "wg0",
            "listen-port", "51820",
            "private-key", &kf,
            "peer", peer_pub,
            "allowed-ips", &format!("{peer_ip}/32"),
            "endpoint", "127.0.0.1:51999",
        ])
        .unwrap();
        ns.exec(&["ip", "addr", "add", my_ip, "dev", "wg0"]).unwrap();
        ns.exec(&["ip", "link", "set", "wg0", "up", "mtu", "1280"]).unwrap();
    }

    // --- Property 1: WG handshake completes over the relay ----------------
    // Background pings from BOTH sides — see the module doc comment above
    // for why both must independently send before either shim can deliver
    // an inbound relayed packet anywhere.
    let mut ping_a = a.spawn(&["ping", "-i", "0.3", "-c", "60", "10.10.0.2"]).unwrap();
    let mut ping_b = b.spawn(&["ping", "-i", "0.3", "-c", "60", "10.10.0.1"]).unwrap();

    let handshake_start = Instant::now();
    let mut hs_a = 0u64;
    let mut hs_b = 0u64;
    for _ in 0..30 {
        hs_a = handshake_epoch(&a);
        hs_b = handshake_epoch(&b);
        if hs_a > 0 && hs_b > 0 {
            break;
        }
        thread::sleep(Duration::from_millis(500));
    }
    let handshake_elapsed = handshake_start.elapsed();
    let _ = ping_a.kill();
    let _ = ping_a.wait();
    let _ = ping_b.kill();
    let _ = ping_b.wait();

    eprintln!(
        "wg_over_relay: handshake epochs a={hs_a} b={hs_b}, elapsed={:.2}s",
        handshake_elapsed.as_secs_f64()
    );
    assert!(hs_a > 0, "A-side WG handshake never completed over the relay (latest-handshakes stayed 0)");
    assert!(hs_b > 0, "B-side WG handshake never completed over the relay (latest-handshakes stayed 0)");

    // right-reason sanity: the relay actually registered both ends (not
    // just "some" bridging happened to work by coincidence of the ping
    // trigger above).
    {
        let log = relay_log.lock().unwrap().join("\n");
        assert!(log.contains("\"gw-A\""), "relay never logged gw-A registration:\n{log}");
        assert!(log.contains("\"gw-B\""), "relay never logged gw-B registration:\n{log}");
    }

    // --- Property 2: MTU boundary is real, both directions ----------------
    // 1232 (icmp payload) + 8 (icmp hdr) + 20 (ip hdr) = 1260 <= 1280 (tun MTU) -> must succeed.
    assert!(
        a.exec(&["ping", "-c", "3", "-M", "do", "-s", "1232", "-W", "5", "10.10.0.2"]).is_ok(),
        "ping -M do -s 1232 (1260 on the wire, under the 1280 tun MTU) must succeed through the relay"
    );
    // 1400 + 28 = 1428 > 1280 (tun MTU), DF set -> must fail (proves the MTU
    // boundary is real, not that ping/the path is just broken).
    assert!(
        a.exec(&["ping", "-c", "1", "-M", "do", "-s", "1400", "-W", "3", "10.10.0.2"]).is_err(),
        "ping -M do -s 1400 (1428 on the wire, over the 1280 tun MTU) must FAIL — \
         if it succeeds, the MTU boundary is not being enforced"
    );

    // --- Property 3: iperf3 through the relay ------------------------------
    let iperf_srv = b.spawn(&["iperf3", "-s", "-p", "5201"]).unwrap();
    let _iperf_srv_guard = KillOnDrop(iperf_srv);
    thread::sleep(Duration::from_millis(500));
    let iperf_out = a
        .exec(&["iperf3", "-c", "10.10.0.2", "-p", "5201", "-t", "3"])
        .expect("iperf3 client through the relay must complete");
    let summary = mbits_per_sec(&iperf_out);
    eprintln!("wg_over_relay: iperf3 through relay: {summary}");
    assert!(!summary.is_empty(), "iperf3 produced no sender/receiver summary line");
}
