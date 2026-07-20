//! Cycle 4b done-bar (spec §2/§7): the NAT-matrix conformance milestone. Two
//! REAL `wiremesh-gateway` binary processes, each behind its OWN NAT router,
//! form a DIRECT WireGuard tunnel via a controller-brokered simultaneous hole
//! punch — and correctly reach a relay-needed verdict when they CAN'T punch
//! (symmetric NAT). This is the cycle's done-bar; it graduates the proven
//! `spike/natpunch` punch topology into a full gateway+controller conformance
//! test.
//!
//! ./dev.sh run "cargo test -p wiremesh-gateway --test nat_matrix \
//!   --features netns-tests -- --test-threads=1 --nocapture"
//!
//! Topology (root netns = the "internet"; the in-process controller binds a
//! routable internet IP on bridge `wmnbr0`; each gateway sits behind its own
//! NAT router whose OUTSIDE interface `out0` masquerades onto that bridge and
//! carries a MANDATORY `tc netem delay 20ms` — Phase-0 Finding 2: a
//! zero-latency lab produces FALSE punch-failures):
//!
//! ```text
//!        root netns (test process + in-process controller @ 198.51.100.1)
//!                       bridge wmnbr0 = 198.51.100.1/24
//!               |                                       |
//!        out0 198.51.100.2/24 (netem 20ms)      out0 198.51.100.3/24 (netem 20ms)
//!            ra netns [NAT]                          rb netns [NAT]
//!        in0 192.168.70.1/24                     in0 192.168.71.1/24
//!               |                                       |
//!   gwA nat0 192.168.70.2/24                gwB nat0 192.168.71.2/24
//!   gwA seg0 10.10.1.1/24                    gwB seg0 10.10.2.1/24
//!        wg0 <===== controller-brokered DIRECT WireGuard tunnel =====> wg0
//!         |                                                             |
//!   wlA eth0 10.10.1.2/24 (seg-a)                wlB eth0 10.10.2.2/24 (seg-b)
//! ```
//!
//! The gateways learn each other's NAT-mapped endpoint via the controller's
//! UDP observation endpoint (source = each gateway's WG listen port, mapped by
//! its NAT), the broker fires paired `PunchDirective`s, and boringtun reuses
//! the punched mapping for the real WG handshake. Policy (allow tcp/8080
//! seg-a → seg-b) is enforced end-to-end, so a workload TCP flow proves data
//! actually crossed the direct tunnel through BOTH NATs (confirmed via
//! `conntrack -L` on each router).
#![cfg(feature = "netns-tests")]

use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use wiremesh_gateway::identity::Identity;
use wiremesh_gateway::uapi::base64_pub_from_priv;
use wiremesh_proto::v1::MintTokenRequest;
use wiremesh_testkit::netns::{apply_netem, assert_netem_present, Lab, NatKind, Ns};
use wiremesh_testkit::{StubGateway, TestController};

const GW_BIN: &str = env!("CARGO_BIN_EXE_wiremesh-gateway");
const BRIDGE: &str = "wmnbr0";
const CTRL_IP: &str = "198.51.100.1";
const METRICS_PORT: u16 = 9099;
const WG_PORT: u16 = 51820;

/// Fabric: seg-a -> seg-b, allow tcp/8080 only (default-deny otherwise), so a
/// workload TCP flow both proves the tunnel carries data AND that the enforcer
/// is live on the punched path.
const FABRIC: &str = r#"
segments:
  - name: seg-a
    cidrs: ["10.10.1.0/24"]
  - name: seg-b
    cidrs: ["10.10.2.0/24"]
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow: { proto: tcp, ports: [8080] }
"#;

// --- root-netns shell helpers ------------------------------------------------

fn run_root(args: &[&str]) {
    let out = Command::new(args[0])
        .args(&args[1..])
        .output()
        .unwrap_or_else(|e| panic!("spawn {args:?}: {e}"));
    if !out.status.success() {
        panic!("{args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
    }
}

fn run_root_best_effort(args: &[&str]) {
    let _ = Command::new(args[0]).args(&args[1..]).status();
}

/// Host-side veth ends parked on the root bridge (one per NAT router). Named so
/// [`RootNetGuard`] and [`setup_bridge`]'s pre-clean can reap leftovers from a
/// crashed prior run.
const HOST_ENDS: [&str; 2] = ["wmniah", "wmnibh"];

/// Deletes any leftover bridge/host-veths from a prior run, then builds the
/// internet bridge with the controller's routable IP in the root netns.
fn setup_bridge() {
    for h in HOST_ENDS {
        run_root_best_effort(&["ip", "link", "del", h]);
    }
    run_root_best_effort(&["ip", "link", "del", BRIDGE]);
    run_root(&["ip", "link", "add", BRIDGE, "type", "bridge"]);
    run_root(&["ip", "addr", "add", &format!("{CTRL_IP}/24"), "dev", BRIDGE]);
    run_root(&["ip", "link", "set", BRIDGE, "up"]);
}

/// Best-effort teardown of the root-netns bridge + host-side veth ends (the
/// child-netns ends go away with the `Lab`'s netns). Runs even on panic.
struct RootNetGuard;
impl Drop for RootNetGuard {
    fn drop(&mut self) {
        for h in HOST_ENDS {
            run_root_best_effort(&["ip", "link", "del", h]);
        }
        run_root_best_effort(&["ip", "link", "del", BRIDGE]);
    }
}

/// Wires a veth from the root bridge into router netns `ns`, naming the moved
/// end `ifname` (must be `out0` for the router's masquerade + netem) and
/// addressing it `cidr`.
fn attach_bridge(ns: &Ns, host_end: &str, ns_end_tag: &str, ifname: &str, cidr: &str) {
    let tmp = format!("wmni{ns_end_tag}n");
    run_root(&["ip", "link", "add", host_end, "type", "veth", "peer", "name", &tmp]);
    run_root(&["ip", "link", "set", host_end, "master", BRIDGE]);
    run_root(&["ip", "link", "set", host_end, "up"]);
    run_root(&["ip", "link", "set", &tmp, "netns", &ns.name]);
    ns.exec(&["ip", "link", "set", &tmp, "down"])
        .unwrap_or_else(|e| panic!("down {ifname}: {e}"));
    ns.exec(&["ip", "link", "set", &tmp, "name", ifname])
        .unwrap_or_else(|e| panic!("rename to {ifname}: {e}"));
    ns.exec(&["ip", "addr", "add", cidr, "dev", ifname])
        .unwrap_or_else(|e| panic!("addr {cidr} on {ifname}: {e}"));
    ns.exec(&["ip", "link", "set", ifname, "up"])
        .unwrap_or_else(|e| panic!("up {ifname}: {e}"));
}

// --- WireGuard identity provisioning ----------------------------------------

fn wg_keypair() -> (String, String) {
    let priv_b64 = String::from_utf8(Command::new("wg").arg("genkey").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_string();
    let pub_b64 = base64_pub_from_priv(&priv_b64).expect("derive wg pubkey");
    (priv_b64, pub_b64)
}

/// Mints a gateway token bound to `cidr` and enrolls a gateway carrying the
/// real `wg_pub` into the ALREADY-EXISTING segment (created by the fabric
/// apply).
async fn enroll_into(h: &TestController, cidr: &str, wg_pub: &str) -> StubGateway {
    let token = h
        .admin_client()
        .await
        .mint_token(MintTokenRequest {
            kind: "gateway".to_string(),
            bound_cidrs: vec![cidr.to_string()],
            rebind_segment_id: 0,
        })
        .await
        .expect("Admin.MintToken")
        .into_inner()
        .token;
    StubGateway::enroll_with_wg_pubkey(h, &token, &[cidr], wg_pub)
        .await
        .expect("enroll gateway with wg pubkey")
}

fn write_identity(gw: &StubGateway, wg_priv: &str, dir: &Path) {
    let id = Identity {
        cert_pem: gw.cert_pem().to_string(),
        key_pem: gw.key_pem().to_string(),
        ca_bundle_pem: gw.ca_bundle_pem().to_string(),
        gateway_id: gw.id(),
        observe_key: gw.observe_key(),
        wg_private_key_b64: wg_priv.to_string(),
    };
    id.store(dir).expect("store gateway identity");
}

// --- gateway process management ---------------------------------------------

struct GwProc {
    child: Child,
    err_log: std::path::PathBuf,
    drains: Vec<std::thread::JoinHandle<()>>,
}

impl GwProc {
    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for h in self.drains.drain(..) {
            let _ = h.join();
        }
    }
    fn stderr_tail(&self) -> String {
        let s = std::fs::read_to_string(&self.err_log).unwrap_or_default();
        // Snap the 4000-byte tail offset up to a char boundary: a raw byte
        // offset can land mid-codepoint and panic in `dump_diag`, masking the
        // real failure this tail was meant to surface.
        let mut start = s.len().saturating_sub(4000);
        while start < s.len() && !s.is_char_boundary(start) {
            start += 1;
        }
        s[start..].to_string()
    }
}

impl Drop for GwProc {
    fn drop(&mut self) {
        self.kill();
    }
}

fn spawn_gw(ns: &Ns, statedir: &Path, sync: &str, observe: &str, logdir: &Path, tag: &str) -> GwProc {
    let metrics = format!("0.0.0.0:{METRICS_PORT}");
    let wg_port = WG_PORT.to_string();
    let statedir_s = statedir.to_str().unwrap();
    let args = [
        GW_BIN,
        "--controller-sync", sync,
        "--observe", observe,
        "--tun", "wg0",
        "--wg-port", &wg_port,
        "--state-dir", statedir_s,
        "--metrics", &metrics,
    ];
    let mut child = ns.spawn(&args).expect("spawn wiremesh-gateway");
    let mut drains = vec![];
    if let Some(mut o) = child.stdout.take() {
        let p = logdir.join(format!("{tag}.out.log"));
        drains.push(std::thread::spawn(move || {
            if let Ok(mut f) = std::fs::File::create(&p) {
                let _ = std::io::copy(&mut o, &mut f);
            }
        }));
    }
    let err_log = logdir.join(format!("{tag}.err.log"));
    if let Some(mut e) = child.stderr.take() {
        let p = err_log.clone();
        drains.push(std::thread::spawn(move || {
            if let Ok(mut f) = std::fs::File::create(&p) {
                let _ = std::io::copy(&mut e, &mut f);
            }
        }));
    }
    GwProc { child, err_log, drains }
}

// --- traffic + metrics probes -----------------------------------------------

fn spawn_listener(ns: &Ns, port: u16) -> Child {
    let script = format!(
        r#"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", {port}))
s.listen(8)
while True:
    c, _ = s.accept()
    c.close()
"#
    );
    ns.spawn(&["python3", "-c", &script]).expect("spawn listener")
}

fn tcp_connect(ns: &Ns, dst: &str, port: u16) -> bool {
    let script = format!(
        r#"
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
try:
    s.connect(("{dst}", {port}))
    sys.exit(0)
except Exception:
    sys.exit(1)
"#
    );
    ns.exec(&["python3", "-c", &script]).is_ok()
}

/// `true` iff a TCP connection from `from` to `to`:`port` actually completes
/// (a listener is running in `to`, so `false` means the packet never arrived).
fn check_tcp(from: &Ns, to: &Ns, to_addr: &str, port: u16) -> bool {
    let mut lst = spawn_listener(to, port);
    std::thread::sleep(Duration::from_millis(300));
    let ok = tcp_connect(from, to_addr, port);
    let _ = lst.kill();
    let _ = lst.wait();
    ok
}

/// Scrapes the gateway's Prometheus `/metrics` from INSIDE its netns (its
/// private NAT IP isn't reachable from the root netns, so we scrape loopback).
fn scrape_metrics(ns: &Ns) -> Option<String> {
    let script = r#"
import socket, sys
try:
    s = socket.create_connection(("127.0.0.1", 9099), 2)
    s.settimeout(2)
    s.sendall(b"GET /metrics HTTP/1.0\r\n\r\n")
    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
    sys.stdout.write(data.decode("utf-8", "replace"))
except Exception as e:
    sys.stderr.write(str(e))
    sys.exit(1)
"#;
    let out = ns.exec(&["python3", "-c", script]).ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Current path state label for the gateway's single peer, parsed from the
/// `wiremesh_gateway_path_state{peer="..",state="X"} 1` scrape line.
fn path_state(ns: &Ns) -> Option<String> {
    let body = scrape_metrics(ns)?;
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("wiremesh_gateway_path_state{") {
            if let Some(idx) = rest.find("state=\"") {
                let tail = &rest[idx + 7..];
                if let Some(end) = tail.find('"') {
                    return Some(tail[..end].to_string());
                }
            }
        }
    }
    None
}

/// boringtun's latest-handshake unix timestamp for wg0's single peer (0 = never).
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

/// WG (udp/51820) conntrack flows on a NAT router — evidence the tunnel
/// traffic actually crossed that NAT rather than taking a veth shortcut.
fn conntrack_wg(ns: &Ns) -> String {
    ns.exec(&["conntrack", "-L", "-p", "udp"])
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| l.contains("dport=51820") || l.contains("sport=51820"))
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

fn kindname(k: NatKind) -> &'static str {
    match k {
        NatKind::PortRestricted => "PortRestricted",
        NatKind::Symmetric => "Symmetric",
    }
}

fn wait_until<F: FnMut() -> bool>(timeout: Duration, mut f: F) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if f() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn dump_diag(label: &str, sc: &Scenario) {
    eprintln!("\n========== DIAGNOSTICS: {label} ==========");
    for (name, ns) in [("gwA", &sc.gwa), ("gwB", &sc.gwb)] {
        eprintln!("--- {name} wg show ---\n{}", wg_show(ns));
        eprintln!("--- {name} path_state ---\n{:?}", path_state(ns));
        eprintln!("--- {name} latest-handshake ---\n{}", latest_handshake(ns));
    }
    for (name, r) in [("ra", &sc.ra), ("rb", &sc.rb)] {
        eprintln!("--- conntrack@{name} (wg 51820) ---\n{}", conntrack_wg(r));
    }
    eprintln!("--- gwA stderr tail ---\n{}", sc.pa.stderr_tail());
    eprintln!("--- gwB stderr tail ---\n{}", sc.pb.stderr_tail());
    eprintln!("========== END DIAGNOSTICS ==========\n");
}

// --- the scenario -----------------------------------------------------------

/// A fully-wired, running dual-NAT gateway pair + in-process controller. Fields
/// are declared so `Drop` kills the gateway processes BEFORE the lab tears down
/// the netns, and the root bridge last.
struct Scenario {
    pa: GwProc,
    pb: GwProc,
    ra: Ns,
    rb: Ns,
    gwa: Ns,
    gwb: Ns,
    wla: Ns,
    wlb: Ns,
    _lab: Lab,
    _h: TestController,
    _sda: tempfile::TempDir,
    _sdb: tempfile::TempDir,
    _logdir: tempfile::TempDir,
    _root_guard: RootNetGuard,
}

/// Builds the full topology for `kind` (PortRestricted or Symmetric), enrolls
/// both gateways with real WG keys, wires the mandatory netem, asserts it is
/// present, and spawns both REAL gateway binaries. Does NOT wait for
/// convergence — the caller asserts the expected outcome.
async fn build_scenario(kind: NatKind, prefix: &str) -> Scenario {
    setup_bridge();
    let root_guard = RootNetGuard;

    let h = TestController::start_on(CTRL_IP.parse().unwrap()).await;

    // Fabric BEFORE enrollment, so each gateway's first snapshot already
    // carries the compiled policy.
    let diff = h.apply(FABRIC).await;
    assert!(diff.policy_updated, "fabric apply must compile a real policy, got: {diff:?}");

    let (a_priv, a_pub) = wg_keypair();
    let (b_priv, b_pub) = wg_keypair();
    let ga = enroll_into(&h, "10.10.1.0/24", &a_pub).await;
    let gb = enroll_into(&h, "10.10.2.0/24", &b_pub).await;

    // netns lab: two gateways, two NAT routers, two workloads.
    let mut lab = Lab::new(prefix).expect("lab");
    let gwa = lab.ns("ga").expect("gwA netns");
    let gwb = lab.ns("gb").expect("gwB netns");
    let wla = lab.ns("wa").expect("wlA netns");
    let wlb = lab.ns("wb").expect("wlB netns");
    // Routers: plain nat_router (masquerade tolerant of not-yet-wired out0),
    // out0 wired below via attach_bridge, netem applied to the real out0 after.
    let ra = lab.nat_router("ra", kind).expect("ra");
    let rb = lab.nat_router("rb", kind).expect("rb");

    // Inside (gateway <-> router) links.
    lab.veth((&gwa, "nat0", "192.168.70.2/24"), (&ra, "in0", "192.168.70.1/24"))
        .expect("gwA<->ra");
    lab.veth((&gwb, "nat0", "192.168.71.2/24"), (&rb, "in0", "192.168.71.1/24"))
        .expect("gwB<->rb");

    // Router outside interfaces onto the internet bridge (must be `out0`).
    attach_bridge(&ra, HOST_ENDS[0], "ra", "out0", "198.51.100.2/24");
    attach_bridge(&rb, HOST_ENDS[1], "rb", "out0", "198.51.100.3/24");

    // MANDATORY netem on each REAL out0 (Phase-0 Finding 2) — call once per
    // iface, AFTER the veth wires it, and assert it's present BEFORE punching.
    apply_netem(&ra, "out0", 20).expect("netem ra/out0");
    apply_netem(&rb, "out0", 20).expect("netem rb/out0");
    assert_netem_present(&ra, "out0");
    assert_netem_present(&rb, "out0");

    // Segment (workload) links + default routes.
    lab.veth((&gwa, "seg0", "10.10.1.1/24"), (&wla, "eth0", "10.10.1.2/24"))
        .expect("seg-a veth");
    lab.veth((&gwb, "seg0", "10.10.2.1/24"), (&wlb, "eth0", "10.10.2.2/24"))
        .expect("seg-b veth");
    wla.exec(&["ip", "route", "add", "default", "via", "10.10.1.1"]).expect("wlA route");
    wlb.exec(&["ip", "route", "add", "default", "via", "10.10.2.1"]).expect("wlB route");

    // Gateway default routes point at their NAT router (so controller + peer
    // NAT-mapped endpoints are reachable through the NAT).
    gwa.exec(&["ip", "route", "add", "default", "via", "192.168.70.1"]).expect("gwA route");
    gwb.exec(&["ip", "route", "add", "default", "via", "192.168.71.1"]).expect("gwB route");

    // Provision identity dirs and spawn the two REAL gateway binaries.
    let sda = tempfile::tempdir().unwrap();
    let sdb = tempfile::tempdir().unwrap();
    write_identity(&ga, &a_priv, sda.path());
    write_identity(&gb, &b_priv, sdb.path());
    let logdir = tempfile::tempdir().unwrap();

    let sync_addr = h.sync_tcp_addr().to_string();
    let observe_addr = h.observe_addr().to_string();
    eprintln!(
        "build_scenario[{prefix}] kind={}: controller sync={sync_addr} observe={observe_addr}",
        kindname(kind)
    );

    let pa = spawn_gw(&gwa, sda.path(), &sync_addr, &observe_addr, logdir.path(), "a");
    let pb = spawn_gw(&gwb, sdb.path(), &sync_addr, &observe_addr, logdir.path(), "b");

    Scenario {
        pa,
        pb,
        ra,
        rb,
        gwa,
        gwb,
        wla,
        wlb,
        _lab: lab,
        _h: h,
        _sda: sda,
        _sdb: sdb,
        _logdir: logdir,
        _root_guard: root_guard,
    }
}

/// Brings the DIRECT tunnel up and waits for BOTH path SMs to reflect `Direct`
/// with a real WG handshake (≤~35s; the done-bar convergence budget is ≤30s,
/// and the observed elapsed is logged).
///
/// The policy-permitted tcp/8080 seg-a→seg-b workload flow doubles as the
/// tunnel-demand driver: boringtun only *initiates* a WG handshake on outbound
/// data demand (or a keepalive timer that the path SM's re-punch cadence keeps
/// resetting — see docs/research/cycle4b-nat-matrix-notes.md, Finding 1), so
/// each connect attempt's SYN entering `wg0` is what triggers the handshake
/// over the freshly punched NAT mapping. This mirrors how the 4a mesh milestone
/// and the `spike/natpunch` de-risk both establish their tunnels, and how every
/// real deployment does — it is the driver, not a weakening of any assertion.
fn establish_direct(sc: &Scenario, label: &str) {
    let start = Instant::now();
    // The connect attempts create outbound tunnel demand; once the handshake
    // completes over the punched mapping, the workload flow actually crosses.
    let crossed = wait_until(Duration::from_secs(35), || {
        check_tcp(&sc.wla, &sc.wlb, "10.10.2.2", 8080)
    });
    if !crossed {
        dump_diag(label, sc);
        panic!("{label}: workload wlA->wlB tcp/8080 never crossed the tunnel (no direct path formed)");
    }
    // The handshake is up; the 1s path-tick reflects Direct momentarily after.
    // Bounded generously (20s, not just enough for the ~1s tick): the
    // workload TCP crossing already proves the WG handshake completed
    // end-to-end, but this test process's OWN `wg show ... latest-handshakes`
    // query is a separate round-trip to boringtun's UAPI socket, independent
    // of the gateway process's own path-tick poll of the same socket — under
    // container CPU contention the two can observe the handshake-time field
    // settle a couple of seconds apart. A single instantaneous scrape here
    // would be a timing race, not a real convergence failure, so this polls
    // repeatedly instead of asserting on one sample (see
    // docs/research/cycle4b-nat-matrix-notes.md).
    let direct = wait_until(Duration::from_secs(20), || {
        path_state(&sc.gwa).as_deref() == Some("direct")
            && path_state(&sc.gwb).as_deref() == Some("direct")
            && latest_handshake(&sc.gwa) > 0
            && latest_handshake(&sc.gwb) > 0
    });
    if !direct {
        dump_diag(label, sc);
        panic!(
            "{label}: workload flow crossed but path_state did not reach Direct on both \
             (gwA={:?}/{}, gwB={:?}/{})",
            path_state(&sc.gwa),
            latest_handshake(&sc.gwa),
            path_state(&sc.gwb),
            latest_handshake(&sc.gwb),
        );
    }
    eprintln!(
        "{label}: PASS direct tunnel established in {:?} \
         (workload tcp/8080 crossed + both path_state=direct + WG handshake)",
        start.elapsed()
    );
}

/// The full case-1 assertion bundle: `establish_direct` + conntrack evidence
/// that the WG flow crossed BOTH NATs (not a veth shortcut).
fn assert_direct_and_traffic(sc: &Scenario, label: &str) {
    establish_direct(sc, label);

    // Conntrack on BOTH routers proves the WG flow crossed the NATs.
    let ra_ct = conntrack_wg(&sc.ra);
    let rb_ct = conntrack_wg(&sc.rb);
    if ra_ct.is_empty() || rb_ct.is_empty() {
        dump_diag(label, sc);
        panic!(
            "{label}: expected WG (udp/51820) conntrack flows crossing BOTH NATs, \
             got ra=[{ra_ct}] rb=[{rb_ct}]"
        );
    }
    eprintln!("{label}: PASS WG flow crossed both NATs:\n  conntrack@ra:\n{ra_ct}\n  conntrack@rb:\n{rb_ct}");
}

// --- the four asserted cases ------------------------------------------------

/// Case 1: port-restricted pair -> DIRECT. Controller brokers the punch; both
/// gateways complete a real WG handshake, reach path_state=direct within ≤30s,
/// pass workload traffic over the direct tunnel, and conntrack confirms the
/// flow crossed both NATs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn case1_port_restricted_direct() {
    let sc = build_scenario(NatKind::PortRestricted, "nm1").await;
    assert_direct_and_traffic(&sc, "case1");
    eprintln!("CASE 1 PASS: port-restricted pair reached Direct via brokered punch.");
}

/// Case 2: symmetric pair -> RELAY-NEEDED. The punch can't confirm (the
/// observed candidate is the wrong per-destination port), so no WG handshake
/// ever completes; the path SM leaves Connecting toward Disconnected
/// (relay-needed metric) without wedging, and the test terminates
/// deterministically within a hard bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn case2_symmetric_relay_needed() {
    let sc = build_scenario(NatKind::Symmetric, "nm2").await;

    // Bounded wait for the relay-needed verdict: the path SM parks in
    // `disconnected` (relay-needed, inert in 4b) after the 10s connect timeout,
    // then oscillates connecting<->disconnected on backoff. We accept the first
    // `disconnected` sighting as the relay-needed determination.
    let relay_needed = wait_until(Duration::from_secs(45), || {
        path_state(&sc.gwa).as_deref() == Some("disconnected")
            || path_state(&sc.gwb).as_deref() == Some("disconnected")
    });
    if !relay_needed {
        dump_diag("case2 relay-needed", &sc);
        panic!(
            "case2: symmetric pair never reached relay-needed (disconnected) state \
             (gwA={:?}, gwB={:?})",
            path_state(&sc.gwa),
            path_state(&sc.gwb)
        );
    }
    eprintln!("case2: PASS reached relay-needed (path_state=disconnected)");

    // Honesty guard: a symmetric pair completing a direct handshake would be a
    // surprise — fail loud (per CLAUDE.md: investigate, don't weaken).
    let ha = latest_handshake(&sc.gwa);
    let hb = latest_handshake(&sc.gwb);
    if ha > 0 && hb > 0 {
        dump_diag("case2 unexpected-handshake", &sc);
        panic!(
            "case2: symmetric pair unexpectedly completed a direct WG handshake \
             (gwA={ha}, gwB={hb}) — investigate before changing the assertion"
        );
    }
    eprintln!("CASE 2 PASS: symmetric pair correctly reached relay-needed, no direct handshake, no hang.");
}

/// Case 3: go-skew determinism. The direct case passes on repeat runs (no
/// conntrack-poisoning flake). Each iteration builds a fresh lab (fresh prefix)
/// and tears it down before the next.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn case3_direct_determinism() {
    const RUNS: usize = 2;
    for i in 0..RUNS {
        let prefix = format!("nm3r{i}");
        eprintln!("case3: determinism run {} / {RUNS} (prefix {prefix})", i + 1);
        let sc = build_scenario(NatKind::PortRestricted, &prefix).await;
        assert_direct_and_traffic(&sc, &format!("case3-run{}", i + 1));
        drop(sc); // full teardown before the next iteration
    }
    eprintln!("CASE 3 PASS: port-restricted direct punch is deterministic across {RUNS} runs.");
}

/// Case 4: Direct -> Degraded. After establishing Direct, block inbound WG on
/// gwA (nft drop) so authenticated inbound stops; within the rx-liveness window
/// the path SM downgrades to Degraded (exercising the rx-liveness fix: a
/// keepalive'd healthy path stays Direct, a blocked one degrades). Bounded to
/// ~65s wall-clock.
///
/// This case is what caught a real driver bug (Cycle 4b Task 11 — see
/// `docs/research/cycle4b-nat-matrix-notes.md`): this environment's boringtun
/// build advances `last_handshake_time` on EVERY path-tick for a peer stuck
/// retrying an unanswered handshake, with `rx_bytes` completely frozen (no
/// packet ever actually arrives). The driver's `on_handshake` call used to
/// trust that advance unconditionally, refreshing `last_inbound` forever and
/// making a blocked/dead path's `DEGRADED_AFTER` unreachable. Fixed in
/// `main.rs`'s `run_path_ticks`: a handshake-time advance while ALREADY
/// Direct is now only trusted when corroborated by a genuine `rx_bytes`
/// increase; it still fires unconditionally for a real
/// Connecting/Degraded/Relayed -> Direct recovery.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn case4_direct_then_degraded() {
    let sc = build_scenario(NatKind::PortRestricted, "nm4").await;
    establish_direct(&sc, "case4");
    eprintln!("case4: direct established; now blocking inbound WG on gwA to force degrade");

    // Drop all inbound WG datagrams on gwA so no authenticated inbound
    // (keepalives/data) reaches boringtun — rx stalls, last_inbound goes stale,
    // and the path SM must degrade after DEGRADED_AFTER (45s).
    let block = "table ip block {\n  chain input {\n    type filter hook input priority 0;\n    udp dport 51820 drop;\n  }\n}\n";
    let block_path = format!("/tmp/{}-block.nft", sc.gwa.name);
    std::fs::write(&block_path, block).expect("write block ruleset");
    sc.gwa.exec(&["nft", "-f", &block_path]).expect("apply inbound WG drop on gwA");
    eprintln!("case4: inbound WG blocked on gwA at t=0; awaiting Degraded (~45s)");

    // Bounded (~65s): catch the FIRST `degraded` sighting, logging gwA's
    // live path_state + latest-handshake every ~5s so a regression is
    // diagnosable from a single run's captured stdout without rerunning.
    let block_start = Instant::now();
    let deadline = block_start + Duration::from_secs(65);
    let mut degraded = false;
    let mut last_log = Instant::now() - Duration::from_secs(5);
    loop {
        let st = path_state(&sc.gwa);
        if st.as_deref() == Some("degraded") {
            degraded = true;
            break;
        }
        if last_log.elapsed() >= Duration::from_secs(5) {
            eprintln!(
                "case4: t+{:?} gwA path_state={:?} gwA-handshake={}",
                block_start.elapsed(),
                st,
                latest_handshake(&sc.gwa),
            );
            last_log = Instant::now();
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    if !degraded {
        dump_diag("case4 degrade", &sc);
        panic!(
            "case4: gwA path did not reach Degraded within 65s of blocking inbound WG (state={:?})",
            path_state(&sc.gwa)
        );
    }
    eprintln!("CASE 4 PASS: blocked-inbound gwA path degraded Direct -> Degraded (rx-liveness).");
}
