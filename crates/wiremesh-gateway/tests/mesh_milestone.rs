//! Cycle 4a done bar (spec §2/§8): two REAL `wiremesh-gateway` binary
//! processes, each in its own netns, driven by an in-process controller, form
//! a policy-enforced encrypted direct mesh that survives a controller outage.
//!
//! ./dev.sh run "cargo build -p wiremesh-gateway && cargo test -p wiremesh-gateway \
//!   --test mesh_milestone --features netns-tests -- --test-threads=1 --nocapture"
//!
//! Topology (all built in the container's default/"root" netns + a lab of
//! four child netns):
//!
//! ```text
//!                       root netns (test process + in-process controller)
//!                       bridge wmbr0 = 10.9.0.254/24  (controller binds here)
//!                          |                    |
//!             underlay veth|                    |underlay veth
//!                          |                    |
//!   wlA netns          gwA netns             gwB netns          wlB netns
//!  10.10.1.2/24 ==seg== 10.10.1.1/24        10.10.2.1/24 ==seg== 10.10.2.2/24
//!   (workload)   veth   und 10.9.0.1/24     und 10.9.0.2/24 veth  (workload)
//!                        wg0 <==== direct WireGuard tunnel ====> wg0
//!                        (real wiremesh-gateway binary in each gw netns)
//! ```
//!
//! The controller's four listeners bind the routable underlay IP 10.9.0.254
//! (via the additive `TestController::start_on` / `Config::bind_ip`); the TLS
//! server cert SAN stays `127.0.0.1` and the gateway's mTLS validates it via
//! SNI, so a gateway in a separate netns dials 10.9.0.254 TLS-cleanly. Each
//! gateway is enrolled with a REAL, locally-generated WireGuard public key
//! (via `StubGateway::enroll_with_wg_pubkey`), so peers learn a usable pubkey
//! and the direct tunnel actually forms. Endpoints are discovered by the
//! gateway's own UDP observation loop (source = its WG listen port on its
//! underlay IP), pushed to the peer by the controller, and used to bring up
//! the tunnel — a genuinely controller-brokered direct mesh.
#![cfg(feature = "netns-tests")]

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use wiremesh_gateway::identity::Identity;
use wiremesh_gateway::uapi::base64_pub_from_priv;
use wiremesh_proto::v1::MintTokenRequest;
use wiremesh_testkit::netns::{Lab, Ns};
use wiremesh_testkit::{StubGateway, TestController};

const GW_BIN: &str = env!("CARGO_BIN_EXE_wiremesh-gateway");
const BRIDGE: &str = "wmbr0";
const CTRL_IP: &str = "10.9.0.254";
const METRICS_PORT: u16 = 9099;

/// Fabric v1: seg-a -> seg-b, allow tcp/8080 only.
const FABRIC_V1: &str = r#"
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

/// Fabric v2: same, plus an added allow for tcp/9090 (the policy-update case).
const FABRIC_V2: &str = r#"
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
      - allow: { proto: tcp, ports: [9090] }
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

/// Deletes any leftover bridge from a prior run, then builds `wmbr0` with the
/// controller's routable IP in the root netns.
fn setup_bridge() {
    run_root_best_effort(&["ip", "link", "del", BRIDGE]);
    run_root(&["ip", "link", "add", BRIDGE, "type", "bridge"]);
    run_root(&["ip", "addr", "add", &format!("{CTRL_IP}/24"), "dev", BRIDGE]);
    run_root(&["ip", "link", "set", BRIDGE, "up"]);
}

/// Best-effort teardown of the root-netns bridge + host-side veth ends (the
/// child-netns ends go away with the `Lab`'s netns). Runs even on panic via
/// its `Drop`.
struct RootNetGuard;
impl Drop for RootNetGuard {
    fn drop(&mut self) {
        run_root_best_effort(&["ip", "link", "del", "wmuah"]);
        run_root_best_effort(&["ip", "link", "del", "wmubh"]);
        run_root_best_effort(&["ip", "link", "del", BRIDGE]);
    }
}

/// Wires a veth from the root bridge into gateway netns `ns`, giving that
/// gateway the underlay IP `ip` on `und`.
fn attach_underlay(ns: &Ns, tag: &str, ip: &str) {
    let hostend = format!("wmu{tag}h");
    let nsend = format!("wmu{tag}n");
    run_root(&[
        "ip", "link", "add", &hostend, "type", "veth", "peer", "name", &nsend,
    ]);
    run_root(&["ip", "link", "set", &hostend, "master", BRIDGE]);
    run_root(&["ip", "link", "set", &hostend, "up"]);
    run_root(&["ip", "link", "set", &nsend, "netns", &ns.name]);
    // Rename the moved end to a stable `und` (must be down to rename), then
    // address it and bring it up.
    ns.exec(&["ip", "link", "set", &nsend, "down"])
        .unwrap_or_else(|e| panic!("down {tag} underlay end: {e}"));
    ns.exec(&["ip", "link", "set", &nsend, "name", "und"])
        .unwrap_or_else(|e| panic!("rename {tag} underlay end: {e}"));
    ns.exec(&["ip", "addr", "add", &format!("{ip}/24"), "dev", "und"])
        .unwrap_or_else(|e| panic!("addr on {tag} underlay: {e}"));
    ns.exec(&["ip", "link", "set", "und", "up"])
        .unwrap_or_else(|e| panic!("up {tag} underlay: {e}"));
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
/// apply) — deliberately NOT `enroll_one_with_wg_pubkey`, which would try to
/// re-create the segment.
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
        let start = s.len().saturating_sub(4000);
        s[start..].to_string()
    }
}

impl Drop for GwProc {
    fn drop(&mut self) {
        self.kill();
    }
}

fn spawn_gw(
    ns: &Ns,
    statedir: &Path,
    sync: &str,
    observe: &str,
    logdir: &Path,
    tag: &str,
) -> GwProc {
    let metrics = format!("0.0.0.0:{METRICS_PORT}");
    let statedir_s = statedir.to_str().unwrap();
    let args = [
        GW_BIN,
        "--controller-sync",
        sync,
        "--observe",
        observe,
        "--tun",
        "wg0",
        "--wg-port",
        "51820",
        "--state-dir",
        statedir_s,
        "--metrics",
        &metrics,
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
    GwProc {
        child,
        err_log,
        drains,
    }
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
    ns.spawn(&["python3", "-c", &script])
        .expect("spawn listener")
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
/// (a listener is running in `to`, so `false` means the enforcer dropped the
/// SYN before it reached the listener).
fn check_tcp(from: &Ns, to: &Ns, to_addr: &str, port: u16) -> bool {
    let mut lst = spawn_listener(to, port);
    std::thread::sleep(Duration::from_millis(300));
    let ok = tcp_connect(from, to_addr, port);
    let _ = lst.kill();
    let _ = lst.wait();
    ok
}

/// Scrapes `wiremesh_gateway_default_deny_total` from a gateway's Prometheus
/// endpoint (reachable from the root netns over the underlay bridge).
fn scrape_deny(addr: &str) -> Option<u64> {
    let sa: std::net::SocketAddr = addr.parse().ok()?;
    let mut s = std::net::TcpStream::connect_timeout(&sa, Duration::from_secs(2)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    s.write_all(b"GET /metrics HTTP/1.0\r\n\r\n").ok()?;
    let mut buf = String::new();
    let _ = s.read_to_string(&mut buf);
    for line in buf.lines() {
        if let Some(rest) = line.strip_prefix("wiremesh_gateway_default_deny_total ") {
            return rest.trim().parse().ok();
        }
    }
    None
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

fn dump_diag(label: &str, gws: &[(&str, &Ns)], procs: &[(&str, &GwProc)]) {
    eprintln!("\n========== DIAGNOSTICS: {label} ==========");
    for (name, ns) in gws {
        for cmd in [
            vec!["wg", "show", "wg0"],
            vec!["ip", "-br", "addr"],
            vec!["ip", "route"],
        ] {
            let out = ns.exec(&cmd);
            match out {
                Ok(o) => eprintln!(
                    "--- {name} {:?} ---\n{}",
                    cmd,
                    String::from_utf8_lossy(&o.stdout)
                ),
                Err(e) => eprintln!("--- {name} {:?} ERR: {e} ---", cmd),
            }
        }
    }
    for (name, p) in procs {
        eprintln!("--- {name} stderr tail ---\n{}", p.stderr_tail());
    }
    eprintln!("========== END DIAGNOSTICS ==========\n");
}

// --- the milestone ----------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_mesh_enforces_policy_and_survives_controller_outage() {
    // Underlay bridge in the root netns; controller binds its routable IP.
    setup_bridge();
    let _root_guard = RootNetGuard;

    let h = TestController::start_on(CTRL_IP.parse().unwrap()).await;

    // Fabric v1 (allow tcp/8080 seg-a -> seg-b) BEFORE enrollment, so each
    // gateway's first snapshot already carries the compiled policy.
    let diff = h.apply(FABRIC_V1).await;
    assert!(
        diff.policy_updated,
        "fabric v1 apply must compile a real policy, got: {diff:?}"
    );

    // Real per-gateway WG keypairs; enroll into the existing segments.
    let (a_priv, a_pub) = wg_keypair();
    let (b_priv, b_pub) = wg_keypair();
    let ga = enroll_into(&h, "10.10.1.0/24", &a_pub).await;
    let gb = enroll_into(&h, "10.10.2.0/24", &b_pub).await;

    // netns lab: two gateways, two workloads.
    let mut lab = Lab::new("gwmesh").expect("lab");
    let gwa = lab.ns("a").expect("gwA netns");
    let gwb = lab.ns("b").expect("gwB netns");
    let wla = lab.ns("wa").expect("wlA netns");
    let wlb = lab.ns("wb").expect("wlB netns");

    // Underlay veths from the bridge into each gateway netns.
    attach_underlay(&gwa, "a", "10.9.0.1");
    attach_underlay(&gwb, "b", "10.9.0.2");

    // Segment veths + workload default routes.
    lab.veth(
        (&gwa, "seg0", "10.10.1.1/24"),
        (&wla, "eth0", "10.10.1.2/24"),
    )
    .expect("seg-a veth");
    lab.veth(
        (&gwb, "seg0", "10.10.2.1/24"),
        (&wlb, "eth0", "10.10.2.2/24"),
    )
    .expect("seg-b veth");
    wla.exec(&["ip", "route", "add", "default", "via", "10.10.1.1"])
        .expect("wlA default route");
    wlb.exec(&["ip", "route", "add", "default", "via", "10.10.2.1"])
        .expect("wlB default route");

    // Provision identity dirs and spawn the two REAL gateway binaries.
    let sda = tempfile::tempdir().unwrap();
    let sdb = tempfile::tempdir().unwrap();
    write_identity(&ga, &a_priv, sda.path());
    write_identity(&gb, &b_priv, sdb.path());
    let logdir = tempfile::tempdir().unwrap();

    let sync_addr = h.sync_tcp_addr().to_string();
    let observe_addr = h.observe_addr().to_string();
    let metrics_b = format!("10.9.0.2:{METRICS_PORT}");

    let mut pa = spawn_gw(
        &gwa,
        sda.path(),
        &sync_addr,
        &observe_addr,
        logdir.path(),
        "a",
    );
    let mut pb = spawn_gw(
        &gwb,
        sdb.path(),
        &sync_addr,
        &observe_addr,
        logdir.path(),
        "b",
    );

    // ===== Assertion 1: ALLOWED flow over the encrypted tunnel =====
    let allowed = wait_until(Duration::from_secs(45), || {
        check_tcp(&wla, &wlb, "10.10.2.2", 8080)
    });
    if !allowed {
        dump_diag(
            "assertion-1 allowed-flow",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!("ASSERTION 1 FAILED: workload A -> workload B tcp/8080 (policy-permitted) never passed over the tunnel");
    }
    eprintln!(
        "ASSERTION 1 PASS: tcp/8080 workload A -> workload B delivered over the direct WG tunnel"
    );

    // ===== Assertion 2: DENIED flow + deny counter increments =====
    let deny_before = scrape_deny(&metrics_b).unwrap_or_else(|| {
        dump_diag("assertion-2 metrics", &[("gwB", &gwb)], &[("gwB", &pb)]);
        pa.kill();
        pb.kill();
        panic!("ASSERTION 2 FAILED: could not scrape gwB metrics at {metrics_b}");
    });
    let denied = check_tcp(&wla, &wlb, "10.10.2.2", 9090);
    assert!(
        !denied,
        "ASSERTION 2 FAILED: tcp/9090 (not policy-permitted) was delivered; it must be dropped"
    );
    let deny_after = {
        let deadline = Instant::now() + Duration::from_secs(6);
        loop {
            match scrape_deny(&metrics_b) {
                Some(v) if v > deny_before => break Some(v),
                _ if Instant::now() >= deadline => break scrape_deny(&metrics_b),
                _ => std::thread::sleep(Duration::from_millis(300)),
            }
        }
    };
    let deny_after = deny_after.expect("scrape gwB deny counter after denied attempt");
    assert!(
        deny_after > deny_before,
        "ASSERTION 2 FAILED: gwB wiremesh_gateway_default_deny_total did not increment ({deny_before} -> {deny_after})"
    );
    eprintln!("ASSERTION 2 PASS: tcp/9090 dropped; gwB default_deny {deny_before} -> {deny_after}");

    // ===== Assertion 4: POLICY UPDATE propagates (controller still up) =====
    let diff2 = h.apply(FABRIC_V2).await;
    assert!(
        diff2.policy_updated,
        "fabric v2 apply must update policy, got: {diff2:?}"
    );
    let now_9090 = wait_until(Duration::from_secs(30), || {
        check_tcp(&wla, &wlb, "10.10.2.2", 9090)
    });
    if !now_9090 {
        dump_diag(
            "assertion-4 policy-update",
            &[("gwB", &gwb)],
            &[("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "ASSERTION 4 FAILED: after pushing a policy permitting tcp/9090, it still did not pass"
        );
    }
    eprintln!("ASSERTION 4 PASS: pushed policy permitting tcp/9090; it now passes");

    // ===== Assertion 3: FAIL-STATIC =====
    // (a) Kill the controller; an allowed flow must keep working.
    drop(h);
    let survived = wait_until(Duration::from_secs(15), || {
        check_tcp(&wla, &wlb, "10.10.2.2", 8080)
    });
    if !survived {
        dump_diag(
            "assertion-3a controller-killed",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "ASSERTION 3a FAILED: allowed tcp/8080 flow dropped after the controller was killed"
        );
    }
    eprintln!("ASSERTION 3a PASS: tcp/8080 still works with the controller dead (fail-static)");

    // (b) Kill + restart gwA's process; it must reload state.json and rebuild
    // the mesh WITHOUT the controller present.
    pa.kill();
    // Clear any stale boringtun UAPI socket left by the SIGKILLed process
    // (its private mount-ns tmpfs persists across the restart).
    let _ = gwa.exec(&["rm", "-f", "/var/run/wireguard/wg0.sock"]);
    let mut pa2 = spawn_gw(
        &gwa,
        sda.path(),
        &sync_addr,
        &observe_addr,
        logdir.path(),
        "a2",
    );
    let reformed = wait_until(Duration::from_secs(45), || {
        check_tcp(&wla, &wlb, "10.10.2.2", 8080)
    });
    if !reformed {
        dump_diag(
            "assertion-3b gwA-restarted",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA-restarted", &pa2), ("gwB", &pb)],
        );
        pa2.kill();
        pb.kill();
        panic!("ASSERTION 3b FAILED: mesh did not return after restarting gwA from state.json without the controller");
    }
    eprintln!("ASSERTION 3b PASS: gwA reloaded state.json and the mesh returned with NO controller running");

    // Teardown.
    pa2.kill();
    pb.kill();
    drop(lab);
    eprintln!("\nALL FOUR ASSERTIONS PASSED: policy-enforced, controller-independent direct mesh.");
}
