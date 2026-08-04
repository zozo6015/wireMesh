//! Backlog item 1 (Cycle-3 hardening PR-B — policy-apply worker restructure),
//! end-to-end: a REAL `wiremesh-gateway` binary must stay responsive — and
//! must collapse a burst of policy epochs into ONE reap grace — while a
//! policy apply is pending the eBPF backend's 10s grace.
//!
//! ```text
//! ./dev.sh run "cargo build -p wiremesh-gateway && cargo test -p wiremesh-gateway \
//!   --test policy_apply_liveness --features netns-tests -- --test-threads=1 --nocapture"
//! ```
//!
//! REQUIRES netns + privileges (it spawns the real gateway binary, which
//! loads eBPF on a tun, programs routes and shells out to `ip`/`nft`/`sysctl`).
//! Topology is the single-gateway reduction of `tests/mesh_milestone.rs`:
//!
//! ```text
//!            root netns (test process + in-process controller)
//!            bridge wmbr1 = 10.9.2.254/24  (controller binds here)
//!                       |
//!          underlay veth|
//!                       |
//!                   gw netns          wl netns
//!                10.10.1.1/24 ==seg== 10.10.1.2/24
//!                und 10.9.2.1/24 veth
//!                wg0 (real wiremesh-gateway binary)
//! ```
//!
//! ## Why this test exists on top of the pure suite
//!
//! `tests/policy_apply_worker.rs` pins the worker's semantics against a fake
//! target, but it CANNOT see whether `main.rs` actually uses the worker — the
//! Sync loop lives in the binary and no integration test can import it. A
//! worker that exists but is not wired IS the bug (same caution
//! `tests/apply_make_before_break.rs` documents for its own driver). This
//! file is the wiring guard, and it is the only place the three
//! collaborators — the enforcer's published deadline, the worker's wait, and
//! the real `Arc<Mutex<HashMap<u32, GatewayEnforcer>>>` — are exercised
//! together at the production 10s grace.
//!
//! ## What it asserts, and why each one discriminates
//!
//! Let `t1` be the instant the gateway is first observed to have installed
//! policy v1 (its first apply — no pending reap, so it is immediate). Its
//! flip arms a 10s reap deadline. The test then pushes TWO further policy
//! versions back to back, both landing inside that deadline.
//!
//! **(1) Lock hygiene.** Throughout the ~8s window that follows, every
//! Prometheus scrape must complete within 2s. The scrape path
//! (`main.rs` ~line 424) takes the SAME `enforcers` map lock the apply path
//! takes. On main, `apply_state` holds that lock across
//! `std::thread::sleep(10s)` (`ebpf::apply_generation`), so scrapes issued
//! during the window hang until it frees — every one of them a 2s read
//! timeout here. Under the fix, `PolicyApplyTarget::ready_at` reads the
//! deadlines and DROPS the lock, so the map is free for the whole wait.
//!
//! **(2) Latest-wins + a live Sync loop.** The gateway must reach the FINAL
//! policy version within 15s of `t1`. On main the two applies serialize on
//! two separate grace periods — v2 installs at ~t1+10s and only then does the
//! Sync loop even dequeue v3, which installs at ~t1+20s. Under the fix, v3
//! supersedes v2 in the mailbox and a single wait to ~t1+10s installs it.
//! 15s sits squarely between the two, and a pass ALSO proves the Sync loop
//! kept consuming the Watch stream while the apply was pending (it had to, to
//! have v3 at all) — which is the real reason `PunchDirective` servicing
//! stops being delayed.
//!
//!   Pinned semantics this depends on: `wiremesh_gateway_applied_policy_version`
//!   keeps meaning "the version actually INSTALLED in the datapath", not "the
//!   version accepted into the mailbox". The worker must therefore store it
//!   after a successful install, not at publish time. (Reporting a version as
//!   applied before it is in the datapath would also make the controller's
//!   roster `applied_version` lag signal lie by up to a grace period.)
//!
//! **(3) The failure metric is wired.** The new
//! `wiremesh_gateway_policy_apply_failures_total` counter must appear in the
//! real scrape body — the "rendered but never reached the scrape" failure
//! mode `metrics.rs`'s `serve_metrics_responds_with_rendered_body_over_tcp`
//! was added to guard after it happened to the path-state gauges.
//!
//! ## What it deliberately does NOT assert
//!
//! The reap grace itself (that the gateway waits ~10s rather than applying
//! v3 instantly) is pinned exactly, and without wall-clock flake, at the
//! backend seam in `crates/wiremesh-enforcer/tests/reap_deadline.rs`. Adding
//! a "not yet applied at t1+3s" assertion here would only add timing
//! fragility for a property already covered.
//!
//! ## RED status
//!
//! RUNTIME-red against main: assertion (1) times out its scrapes during the
//! stall, assertion (2) needs ~20s where it allows 15s, and assertion (3)'s
//! metric does not exist yet.
#![cfg(feature = "netns-tests")]

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use wiremesh_gateway::identity::Identity;
use wiremesh_gateway::uapi::base64_pub_from_priv;
use wiremesh_proto::v1::{GetPolicyRequest, MintTokenRequest};
use wiremesh_testkit::netns::{Lab, Ns};
use wiremesh_testkit::{StubGateway, TestController};

const GW_BIN: &str = env!("CARGO_BIN_EXE_wiremesh-gateway");
/// Distinct from `mesh_milestone.rs`'s `wmbr0`/`wmu*` names and its
/// `10.9.0.0/24` underlay, AND from `wiremesh_testkit::netns::wg_lab`'s own
/// `10.9.1.0/24` — so a stray leftover from another netns binary can never
/// collide with this one.
const BRIDGE: &str = "wmbr1";
const CTRL_IP: &str = "10.9.2.254";
const GW_IP: &str = "10.9.2.1";
const METRICS_PORT: u16 = 9098;

/// The production reap grace (`wiremesh_enforcer::EnforcerConfig::default()`),
/// restated here because every budget below is derived from it. The gateway
/// binary always uses the default — there is no CLI knob, deliberately.
const REAP_GRACE: Duration = Duration::from_secs(10);

/// Assertion (2)'s budget: one grace period plus generous slack, and still a
/// full grace period short of main's two-grace serialization.
const FINAL_VERSION_BUDGET: Duration = Duration::from_secs(15);

/// Assertion (1): how long to keep hammering the scrape, and the per-scrape
/// budget. The window must comfortably straddle the grace so that scrapes
/// genuinely land inside it.
const SCRAPE_WINDOW: Duration = Duration::from_secs(8);
const SCRAPE_BUDGET: Duration = Duration::from_secs(2);

fn fabric(extra_ports: &[u16]) -> String {
    let mut rules = String::from("      - allow: { proto: tcp, ports: [8080] }\n");
    for p in extra_ports {
        rules.push_str(&format!("      - allow: {{ proto: tcp, ports: [{p}] }}\n"));
    }
    format!(
        "
segments:
  - name: seg-a
    cidrs: [\"10.10.1.0/24\"]
  - name: seg-b
    cidrs: [\"10.10.2.0/24\"]
policy:
  - from: seg-a
    to: seg-b
    rules:
{rules}"
    )
}

// --- root-netns shell helpers (same shape as mesh_milestone.rs) -------------

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

fn setup_bridge() {
    run_root_best_effort(&["ip", "link", "del", BRIDGE]);
    run_root(&["ip", "link", "add", BRIDGE, "type", "bridge"]);
    run_root(&["ip", "addr", "add", &format!("{CTRL_IP}/24"), "dev", BRIDGE]);
    run_root(&["ip", "link", "set", BRIDGE, "up"]);
}

struct RootNetGuard;
impl Drop for RootNetGuard {
    fn drop(&mut self) {
        run_root_best_effort(&["ip", "link", "del", "wmpah"]);
        run_root_best_effort(&["ip", "link", "del", BRIDGE]);
    }
}

fn attach_underlay(ns: &Ns, ip: &str) {
    let hostend = "wmpah";
    let nsend = "wmpan";
    run_root(&["ip", "link", "add", hostend, "type", "veth", "peer", "name", nsend]);
    run_root(&["ip", "link", "set", hostend, "master", BRIDGE]);
    run_root(&["ip", "link", "set", hostend, "up"]);
    run_root(&["ip", "link", "set", nsend, "netns", &ns.name]);
    ns.exec(&["ip", "link", "set", nsend, "down"]).expect("down underlay end");
    ns.exec(&["ip", "link", "set", nsend, "name", "und"]).expect("rename underlay end");
    ns.exec(&["ip", "addr", "add", &format!("{ip}/24"), "dev", "und"]).expect("addr on underlay");
    ns.exec(&["ip", "link", "set", "und", "up"]).expect("up underlay");
}

// --- gateway provisioning ---------------------------------------------------

fn wg_keypair() -> (String, String) {
    let priv_b64 = String::from_utf8(Command::new("wg").arg("genkey").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_string();
    let pub_b64 = base64_pub_from_priv(&priv_b64).expect("derive wg pubkey");
    (priv_b64, pub_b64)
}

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
    Identity {
        cert_pem: gw.cert_pem().to_string(),
        key_pem: gw.key_pem().to_string(),
        ca_bundle_pem: gw.ca_bundle_pem().to_string(),
        gateway_id: gw.id(),
        observe_key: gw.observe_key(),
        wg_private_key_b64: wg_priv.to_string(),
    }
    .store(dir)
    .expect("store gateway identity");
}

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
        let start = s.len().saturating_sub(6000);
        s[start..].to_string()
    }
}

impl Drop for GwProc {
    fn drop(&mut self) {
        self.kill();
    }
}

fn spawn_gw(ns: &Ns, statedir: &Path, sync: &str, observe: &str, logdir: &Path) -> GwProc {
    let metrics = format!("0.0.0.0:{METRICS_PORT}");
    let statedir_s = statedir.to_str().unwrap();
    let args = [
        GW_BIN,
        "--controller-sync", sync,
        "--observe", observe,
        "--tun", "wg0",
        "--wg-port", "51820",
        "--state-dir", statedir_s,
        "--metrics", &metrics,
    ];
    let mut child = ns.spawn(&args).expect("spawn wiremesh-gateway");
    let mut drains = vec![];
    if let Some(mut o) = child.stdout.take() {
        let p = logdir.join("gw.out.log");
        drains.push(std::thread::spawn(move || {
            if let Ok(mut f) = std::fs::File::create(&p) {
                let _ = std::io::copy(&mut o, &mut f);
            }
        }));
    }
    let err_log = logdir.join("gw.err.log");
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

// --- metrics probe ----------------------------------------------------------

/// One scrape. Returns the body and how long the whole exchange took, or the
/// error/timeout that ended it. `budget` is applied to BOTH connect and read,
/// so a metrics handler blocked on the enforcer-map lock surfaces as an
/// `Err(...)` rather than as an arbitrarily long hang.
fn scrape(addr: &str, budget: Duration) -> Result<(String, Duration), String> {
    let t0 = Instant::now();
    let sa: std::net::SocketAddr = addr.parse().map_err(|e| format!("bad addr: {e}"))?;
    let mut s = std::net::TcpStream::connect_timeout(&sa, budget)
        .map_err(|e| format!("connect after {:?}: {e}", t0.elapsed()))?;
    s.set_read_timeout(Some(budget)).map_err(|e| format!("set_read_timeout: {e}"))?;
    s.write_all(b"GET /metrics HTTP/1.0\r\n\r\n")
        .map_err(|e| format!("write after {:?}: {e}", t0.elapsed()))?;
    let mut buf = String::new();
    s.read_to_string(&mut buf)
        .map_err(|e| format!("read after {:?}: {e}", t0.elapsed()))?;
    Ok((buf, t0.elapsed()))
}

fn applied_version_of(body: &str) -> Option<u64> {
    body.lines()
        .find_map(|l| l.strip_prefix("wiremesh_gateway_applied_policy_version "))
        .and_then(|v| v.trim().parse().ok())
}

/// Latest compiled policy version, straight from the controller — never
/// guessed from "one apply bumps by one".
async fn latest_policy_version(h: &TestController) -> u64 {
    h.admin_client()
        .await
        .get_policy(GetPolicyRequest { version: 0 })
        .await
        .expect("Admin.GetPolicy(latest)")
        .into_inner()
        .version
}

// --- the test ---------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn policy_apply_does_not_stall_the_gateway_and_bursts_collapse_to_one_grace() {
    setup_bridge();
    let _root_guard = RootNetGuard;

    let h = TestController::start_on(CTRL_IP.parse().unwrap()).await;

    // Fabric v1 BEFORE enrollment, so the gateway's very first snapshot
    // already carries a compiled policy and its first apply happens at boot.
    let diff = h.apply(&fabric(&[])).await;
    assert!(diff.policy_updated, "fabric v1 must compile a real policy, got: {diff:?}");
    let v1 = latest_policy_version(&h).await;

    let (gw_priv, gw_pub) = wg_keypair();
    let gw = enroll_into(&h, "10.10.1.0/24", &gw_pub).await;

    let mut lab = Lab::new("gwpal").expect("lab");
    let gwns = lab.ns("g").expect("gateway netns");
    let wlns = lab.ns("w").expect("workload netns");
    attach_underlay(&gwns, GW_IP);
    lab.veth((&gwns, "seg0", "10.10.1.1/24"), (&wlns, "eth0", "10.10.1.2/24"))
        .expect("seg-a veth");

    let statedir = tempfile::tempdir().unwrap();
    write_identity(&gw, &gw_priv, statedir.path());
    let logdir = tempfile::tempdir().unwrap();

    let sync_addr = h.sync_tcp_addr().to_string();
    let observe_addr = h.observe_addr().to_string();
    let metrics_addr = format!("{GW_IP}:{METRICS_PORT}");

    let mut proc = spawn_gw(&gwns, statedir.path(), &sync_addr, &observe_addr, logdir.path());

    // --- wait for the FIRST apply: it flips a generation and arms the 10s
    // --- reap deadline everything below is measured against.
    let boot_deadline = Instant::now() + Duration::from_secs(60);
    let t1 = loop {
        if let Ok((body, _)) = scrape(&metrics_addr, SCRAPE_BUDGET) {
            if applied_version_of(&body) == Some(v1) {
                break Instant::now();
            }
        }
        if Instant::now() >= boot_deadline {
            eprintln!("--- gateway stderr ---\n{}", proc.stderr_tail());
            proc.kill();
            panic!(
                "gateway never reported applied policy version {v1} at {metrics_addr} \
                 within 60s of boot"
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    eprintln!("SETUP: gateway installed policy v{v1}; its reap deadline is ~t1+{REAP_GRACE:?}");

    // --- push TWO more policy versions back to back, both landing well
    // --- inside that deadline.
    let d2 = h.apply(&fabric(&[9090])).await;
    assert!(d2.policy_updated, "fabric v2 must update policy, got: {d2:?}");
    let d3 = h.apply(&fabric(&[9090, 9091])).await;
    assert!(d3.policy_updated, "fabric v3 must update policy, got: {d3:?}");
    let v3 = latest_policy_version(&h).await;
    assert!(v3 > v1, "sanity: two applies must have advanced the policy version past {v1}");
    assert!(
        t1.elapsed() < REAP_GRACE / 2,
        "both applies must be pushed well inside the gateway's 10s reap deadline for \
         this test to mean anything; pushing them took {:?}",
        t1.elapsed()
    );

    // ===== Assertion 1: the enforcer-map lock is NOT held across the grace =====
    // Every scrape in the window must complete inside its budget. On main the
    // apply path holds the map lock across `std::thread::sleep(10s)`, so these
    // hang and the read times out.
    let mut worst = Duration::ZERO;
    let mut scrapes = 0usize;
    let window_end = Instant::now() + SCRAPE_WINDOW;
    while Instant::now() < window_end {
        match scrape(&metrics_addr, SCRAPE_BUDGET) {
            Ok((body, took)) => {
                assert!(
                    applied_version_of(&body).is_some(),
                    "scrape body must carry the applied-version gauge; got:\n{body}"
                );
                worst = worst.max(took);
                scrapes += 1;
            }
            Err(e) => {
                eprintln!("--- gateway stderr ---\n{}", proc.stderr_tail());
                proc.kill();
                panic!(
                    "ASSERTION 1 FAILED: a Prometheus scrape did not complete within \
                     {SCRAPE_BUDGET:?} while a policy apply was pending its reap grace \
                     ({e}). The apply path must not hold the `enforcers` map lock across \
                     the wait — `PolicyApplyTarget::ready_at` reads the deadlines and \
                     drops the lock."
                );
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    assert!(scrapes >= 10, "sanity: expected many scrapes in {SCRAPE_WINDOW:?}, got {scrapes}");
    eprintln!(
        "ASSERTION 1 PASS: {scrapes} scrapes during the grace window, worst {worst:?} \
         (budget {SCRAPE_BUDGET:?})"
    );

    // ===== Assertion 2: the burst collapsed to ONE grace =====
    // v2 must have been superseded in the mailbox by v3, so a single ~10s wait
    // installs v3. On main, v2 costs a grace and v3 costs another (~20s).
    let mut last_seen = None;
    let deadline = t1 + FINAL_VERSION_BUDGET;
    let reached = loop {
        if let Ok((body, _)) = scrape(&metrics_addr, SCRAPE_BUDGET) {
            last_seen = applied_version_of(&body);
            if last_seen == Some(v3) {
                break true;
            }
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    if !reached {
        eprintln!("--- gateway stderr ---\n{}", proc.stderr_tail());
        proc.kill();
        panic!(
            "ASSERTION 2 FAILED: {FINAL_VERSION_BUDGET:?} after its first apply the \
             gateway is still on policy version {last_seen:?}, not the final {v3}. Two \
             back-to-back policy versions must collapse to ONE reap grace \
             (~{REAP_GRACE:?}) in the latest-wins mailbox — serializing them costs two \
             graces, which is the bug."
        );
    }
    eprintln!(
        "ASSERTION 2 PASS: reached policy v{v3} {:?} after the first apply (one grace, \
         not two)",
        t1.elapsed()
    );

    // ===== Assertion 3: the apply-failure counter reaches the scrape body =====
    let (body, _) = scrape(&metrics_addr, SCRAPE_BUDGET).expect("final scrape");
    assert!(
        body.contains("wiremesh_gateway_policy_apply_failures_total"),
        "ASSERTION 3 FAILED: the new apply-failure counter must reach the real scrape \
         body, not just exist as a pure renderer (the wiring failure mode the path-state \
         gauges once had). Body:\n{body}"
    );
    eprintln!("ASSERTION 3 PASS: wiremesh_gateway_policy_apply_failures_total is exported");

    proc.kill();
    drop(lab);
}
