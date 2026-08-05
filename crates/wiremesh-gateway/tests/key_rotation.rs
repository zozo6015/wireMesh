//! Key-rotation Task 10, case 1 (direct-rotation, zero-drop done bar): two
//! REAL `wiremesh-gateway` binary processes, each in its own netns, form a
//! direct WireGuard mesh; while a continuous ICMP flood crosses it, gwA's
//! key is rotated via `Admin.RotateKey`, and the flood must survive the
//! cutover with (at most) one handshake-RTT's worth of drops.
//!
//! ./dev.sh run "cargo build -p wiremesh-gateway && cargo test -p wiremesh-gateway \
//!   --test key_rotation --features netns-tests -- --test-threads=1 --nocapture"
//!
//! Topology: IDENTICAL to `mesh_milestone.rs` (bridge + two gateway netns +
//! two workload netns; see that file's module doc for the ASCII diagram).
//! The bridge/underlay/identity/process-management helpers below are
//! deliberately DUPLICATED from `mesh_milestone.rs` verbatim (per the task
//! brief: the two test files are not currently factored into a shared
//! module) — keep them byte-for-byte identical to that file if you touch
//! them, so the two suites don't silently drift apart.
//!
//! **Policy choice: ICMP, not a UDP flood.** `crates/wiremesh-policy`'s DSL
//! validates `proto` against exactly `tcp`/`udp`/`icmp` (see
//! `wiremesh-policy/src/validate.rs`'s `validate_ports`), and the enforcer
//! already special-cases `icmp` end-to-end (`wiremesh-enforcer/src/nft.rs`,
//! `.../ebpf.rs`'s `CFG_ICMP_NS` idle timeout) — `relay_matrix.rs` already
//! exercises `allow: { proto: icmp }` as its done-bar crossing flow. So ICMP
//! is expressible and proven to work; a real `ping` flood is simpler and
//! more direct evidence of "zero drop" than rolling a custom UDP
//! echo/sequence protocol, so that's what this test uses.
//!
//! **Mandatory netem (per the plan / Phase-0 Finding 2):** each gateway's
//! underlay `und` device gets a real `tc netem delay 20ms` — a zero-latency
//! lab would let the new-epoch handshake complete unrealistically fast and
//! hide any drop the make-before-break cutover would otherwise cause.
#![cfg(feature = "netns-tests")]

use std::collections::BTreeSet;
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use wiremesh_gateway::identity::Identity;
use wiremesh_gateway::uapi::base64_pub_from_priv;
use wiremesh_proto::v1::{MintTokenRequest, RotateKeyRequest};
use wiremesh_testkit::netns::{apply_netem, Lab, Ns};
use wiremesh_testkit::{StubGateway, TestController};

const GW_BIN: &str = env!("CARGO_BIN_EXE_wiremesh-gateway");
const BRIDGE: &str = "wmbr0";
const CTRL_IP: &str = "10.9.0.254";
const METRICS_PORT: u16 = 9099;

/// Fabric: seg-a <-> seg-b, allow ICMP both directions (default-deny
/// otherwise) — both directions are declared explicitly (rather than
/// relying on the enforcer's stateful flow table to auto-permit the echo
/// reply on the reverse leg, the way `relay_matrix.rs`'s one-directional
/// rule does) so the ping flood's traffic pattern is unambiguously
/// policy-permitted in either direction.
const FABRIC_ICMP: &str = r#"
segments:
  - name: seg-a
    cidrs: ["10.10.1.0/24"]
  - name: seg-b
    cidrs: ["10.10.2.0/24"]
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow: { proto: icmp }
  - from: seg-b
    to: seg-a
    rules:
      - allow: { proto: icmp }
"#;

/// Fabric for the enforcer-on-new-tun security regression test: same
/// ICMP-both-ways liveness rules as `FABRIC_ICMP` (so the mesh-up wait and
/// the poll for a working tunnel don't need a TCP-capable listener), PLUS an
/// allow for tcp/8080 seg-a -> seg-b only (mirrors `mesh_milestone.rs`'s
/// `FABRIC_V1`). tcp/9090 is deliberately left un-declared: default-deny
/// must reject it both before AND after a rotation.
const FABRIC_ICMP_AND_TCP8080: &str = r#"
segments:
  - name: seg-a
    cidrs: ["10.10.1.0/24"]
  - name: seg-b
    cidrs: ["10.10.2.0/24"]
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow: { proto: icmp }
      - allow: { proto: tcp, ports: [8080] }
  - from: seg-b
    to: seg-a
    rules:
      - allow: { proto: icmp }
"#;

/// Fabric v2 for the "policy tightening after rotation" test — same
/// ICMP-both-ways liveness rules as `FABRIC_ICMP_AND_TCP8080` (so the
/// post-tighten liveness check keeps working), but the tcp/8080 seg-a ->
/// seg-b allow rule has been REMOVED, so tcp/8080 becomes default-denied.
/// This is the "v2" fabric applied AFTER the rotation completes to prove a
/// policy tightening reaches whichever tun is actually carrying traffic
/// post-cutover, not just `wg0`.
const FABRIC_ICMP_ONLY_V2: &str = r#"
segments:
  - name: seg-a
    cidrs: ["10.10.1.0/24"]
  - name: seg-b
    cidrs: ["10.10.2.0/24"]
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow: { proto: icmp }
  - from: seg-b
    to: seg-a
    rules:
      - allow: { proto: icmp }
"#;

// --- root-netns shell helpers (duplicated from mesh_milestone.rs) -----------

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
    run_root(&["ip", "link", "add", &hostend, "type", "veth", "peer", "name", &nsend]);
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

// --- WireGuard identity provisioning (duplicated from mesh_milestone.rs) ----

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

// --- gateway process management (duplicated from mesh_milestone.rs) --------

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

fn spawn_gw(ns: &Ns, statedir: &Path, sync: &str, observe: &str, logdir: &Path, tag: &str) -> GwProc {
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

// --- traffic probes ----------------------------------------------------------

/// A single ICMP echo, bounded 2s. `true` iff it got a reply — used both to
/// wait for the mesh to come up and to prove it still works post-rotation.
fn ping_ok(ns: &Ns, dst: &str) -> bool {
    ns.exec(&["ping", "-c", "1", "-W", "2", dst]).is_ok()
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

/// Parses a `ping -q` summary block's `"N packets transmitted, M received, ..."`
/// line into `(transmitted, received)`. Panics with the full output if the
/// line can't be found/parsed — that's a harness bug (or a garbled/empty
/// ping run), not a legitimate zero-drop failure, so it should be loud.
fn parse_ping_summary(stdout: &str) -> (u64, u64) {
    for line in stdout.lines() {
        if line.contains("packets transmitted") {
            let parts: Vec<&str> = line.split(',').collect();
            let transmitted: u64 = parts
                .first()
                .and_then(|s| s.trim().split_whitespace().next())
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| panic!("could not parse transmitted count from: {line:?}"));
            let received: u64 = parts
                .get(1)
                .and_then(|s| s.trim().split_whitespace().next())
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| panic!("could not parse received count from: {line:?}"));
            return (transmitted, received);
        }
    }
    panic!("no 'packets transmitted' summary line found in ping output:\n{stdout}");
}

// --- TCP policy-check probes (duplicated from mesh_milestone.rs) -----------

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

/// Polls `h.debug_key_states(gateway_id)` every 500ms (bounded `timeout`)
/// until `epoch 1` shows `state == "active"` AND no `epoch 0` row remains
/// `active` (either retired away entirely, or demoted to `"retiring"`) —
/// the done-bar's definition of "the rotation has completed". Returns the
/// last-observed snapshot either way (pass or timeout) so the caller can
/// include it in a failure message/diagnostics.
async fn poll_rotation_complete(
    h: &TestController,
    gateway_id: u64,
    timeout: Duration,
) -> (bool, Vec<(u32, String, String)>) {
    let deadline = Instant::now() + timeout;
    loop {
        let states = h.debug_key_states(gateway_id).await;
        let epoch1_active = states.iter().any(|(e, _, s)| *e == 1 && s == "active");
        let epoch0_gone_or_retiring = !states.iter().any(|(e, _, s)| *e == 0 && s == "active");
        if epoch1_active && epoch0_gone_or_retiring {
            return (true, states);
        }
        if Instant::now() >= deadline {
            return (false, states);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

fn dump_diag(label: &str, gws: &[(&str, &Ns)], procs: &[(&str, &GwProc)]) {
    eprintln!("\n========== DIAGNOSTICS: {label} ==========");
    for (name, ns) in gws {
        for cmd in [
            vec!["wg", "show", "wg0"],
            vec!["wg", "show", "wg0e1"],
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

// --- the done-bar test --------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn direct_rotation_is_zero_drop() {
    // Underlay bridge in the root netns; controller binds its routable IP.
    setup_bridge();
    let _root_guard = RootNetGuard;

    let h = TestController::start_on(CTRL_IP.parse().unwrap()).await;

    // ICMP-both-ways fabric BEFORE enrollment, so each gateway's first
    // snapshot already carries the compiled policy.
    let diff = h.apply(FABRIC_ICMP).await;
    assert!(
        diff.policy_updated,
        "fabric apply must compile a real policy, got: {diff:?}"
    );

    // Real per-gateway WG keypairs; enroll into the existing segments.
    let (a_priv, a_pub) = wg_keypair();
    let (b_priv, b_pub) = wg_keypair();
    let ga = enroll_into(&h, "10.10.1.0/24", &a_pub).await;
    let gb = enroll_into(&h, "10.10.2.0/24", &b_pub).await;

    // netns lab: two gateways, two workloads.
    let mut lab = Lab::new("gwrot").expect("lab");
    let gwa = lab.ns("a").expect("gwA netns");
    let gwb = lab.ns("b").expect("gwB netns");
    let wla = lab.ns("wa").expect("wlA netns");
    let wlb = lab.ns("wb").expect("wlB netns");

    // Underlay veths from the bridge into each gateway netns.
    attach_underlay(&gwa, "a", "10.9.0.1");
    attach_underlay(&gwb, "b", "10.9.0.2");

    // MANDATORY real one-way latency on both underlays (Phase-0 Finding 2) —
    // must be applied AFTER the underlay `und` device exists.
    apply_netem(&gwa, "und", 20).expect("netem on gwA underlay");
    apply_netem(&gwb, "und", 20).expect("netem on gwB underlay");

    // Segment veths + workload default routes.
    lab.veth((&gwa, "seg0", "10.10.1.1/24"), (&wla, "eth0", "10.10.1.2/24"))
        .expect("seg-a veth");
    lab.veth((&gwb, "seg0", "10.10.2.1/24"), (&wlb, "eth0", "10.10.2.2/24"))
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

    let mut pa = spawn_gw(&gwa, sda.path(), &sync_addr, &observe_addr, logdir.path(), "a");
    let mut pb = spawn_gw(&gwb, sdb.path(), &sync_addr, &observe_addr, logdir.path(), "b");

    // ===== Wait until the mesh is up (an allowed ICMP flow passes) =====
    let up = wait_until(Duration::from_secs(45), || ping_ok(&wla, "10.10.2.2"));
    if !up {
        dump_diag(
            "mesh-not-up",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!("SETUP FAILED: workload A -> workload B ICMP (policy-permitted) never passed over the direct tunnel before rotation");
    }
    eprintln!("SETUP PASS: direct mesh is up (ICMP crosses wlA -> wlB)");

    // ===== Start a continuous ping flood from wlA to wlB =====
    // No `-c` cap: the flood is stopped explicitly (via `pkill -INT`) once
    // this test is done observing the rotation window, rather than being
    // sized to self-terminate — that avoids having to guess how long a real
    // rotation implementation will take under 20ms netem. `-q` means the
    // flood only prints a final summary (transmitted/received/loss%) once
    // it's told to stop, which is exactly the evidence the zero-drop
    // assertion below needs.
    let flood = wla
        .spawn(&["ping", "-i", "0.2", "-q", "10.10.2.2"])
        .expect("spawn ping flood in wlA netns");

    // ===== Rotate gwA's key =====
    h.admin_client()
        .await
        .rotate_key(RotateKeyRequest { gateway_id: ga.id() })
        .await
        .expect("Admin.RotateKey");
    eprintln!("Admin.RotateKey submitted for gwA (epoch 0 -> 1)");

    // ===== Poll until the rotation has actually completed =====
    let (completed, final_states) =
        poll_rotation_complete(&h, ga.id(), Duration::from_secs(90)).await;
    if !completed {
        dump_diag(
            "rotation-timeout",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        let _ = wla.exec(&["pkill", "-INT", "-x", "ping"]);
        let flood_out = flood.wait_with_output();
        if let Ok(o) = flood_out {
            eprintln!(
                "--- ping flood output at rotation-timeout ---\n{}",
                String::from_utf8_lossy(&o.stdout)
            );
        }
        pa.kill();
        pb.kill();
        panic!(
            "ROTATION TIMEOUT: gwA's key rotation (epoch 0 -> 1) did not complete within 90s \
             (epoch 1 active + epoch 0 gone/retiring). Last observed debug_key_states: \
             {final_states:?}"
        );
    }
    eprintln!("ROTATION COMPLETE: {final_states:?}");

    // ===== Stop the flood and read its zero-drop summary =====
    // `pkill -INT` (rather than signalling the `Child`'s own pid) because
    // `Ns::spawn` runs the target through `nsenter -- ip netns exec <ns> ping
    // ...`: `ip netns exec` forks a genuinely separate process to run `ping`
    // itself, so the `Child` handle's pid is NOT ping's pid. `pkill -x ping`
    // matches on the process's own name inside the (shared, network-namespace-
    // only) process table, which reaches the actual `ping` process directly.
    // `ping` treats SIGINT the same as reaching its packet count: it prints
    // its `-q` summary and exits, so `wait_with_output()` afterwards returns
    // that summary rather than hanging.
    let _ = wla.exec(&["pkill", "-INT", "-x", "ping"]);
    let flood_out = flood
        .wait_with_output()
        .expect("wait for ping flood to exit after SIGINT");
    let flood_stdout = String::from_utf8_lossy(&flood_out.stdout).into_owned();
    eprintln!("--- ping flood summary ---\n{flood_stdout}");
    let (transmitted, received) = parse_ping_summary(&flood_stdout);
    eprintln!("ping flood: transmitted={transmitted} received={received}");

    // The zero-drop bar: allow at most ~3 dropped packets (one
    // handshake-RTT's worth of gap while routes flip onto the new epoch's
    // Device), never a real train of loss.
    assert!(
        received + 3 >= transmitted,
        "ZERO-DROP FAILED: ping flood during rotation dropped too many packets \
         (transmitted={transmitted}, received={received}, allowed gap=3)"
    );
    eprintln!(
        "ZERO-DROP PASS: transmitted={transmitted} received={received} (gap {} <= 3)",
        transmitted.saturating_sub(received)
    );

    // ===== The mesh still works post-rotation (new epoch carries traffic) =====
    let still_works = wait_until(Duration::from_secs(15), || ping_ok(&wla, "10.10.2.2"));
    if !still_works {
        dump_diag(
            "post-rotation",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!("POST-ROTATION FAILED: ICMP wlA -> wlB no longer passes after the key rotation completed");
    }
    eprintln!("POST-ROTATION PASS: ICMP still crosses wlA -> wlB on the new epoch");

    // Teardown.
    pa.kill();
    pb.kill();
    drop(lab);
    eprintln!("\nDONE-BAR PASSED: direct rotation completed under a continuous ICMP flood with zero (near-zero) drop, and the mesh still works after.");
}

/// SECURITY REGRESSION: the L4 enforcer must stay attached across a key
/// rotation's tun cutover. Cycle key-rotation introduces a second WireGuard
/// tun device per epoch (`wg0` for epoch 0, `wg0e<N>` for epoch N) as part of
/// the make-before-break cutover; if the enforcer program is only ever
/// attached to `wg0` at boot and never (re-)attached to the new epoch's tun,
/// then after a rotation completes and traffic moves onto `wg0e1`, ALL
/// traffic — including flows the fabric policy denies — ingresses/egresses
/// with no policy hook at all. That is a default-deny bypass: a previously
/// denied flow becomes silently allowed the moment the mesh rotates.
///
/// Same direct-mesh topology as `direct_rotation_is_zero_drop`, but instead
/// of a zero-drop ICMP flood this test asks a policy question before and
/// after the rotation: does tcp/8080 (allowed) keep working, and — the
/// security-critical assertion — does tcp/9090 (never allowed by the fabric)
/// stay denied? gwB's tun is the interesting side here: it is the Role-B
/// receiver of gwA's rotation, so gwB's overlap/new-epoch tun is the
/// critical ingress point for gwA's post-rotation traffic.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn denied_flow_stays_denied_across_rotation() {
    // Underlay bridge in the root netns; controller binds its routable IP.
    setup_bridge();
    let _root_guard = RootNetGuard;

    let h = TestController::start_on(CTRL_IP.parse().unwrap()).await;

    // ICMP-both-ways (for liveness) + tcp/8080 seg-a->seg-b (allowed) fabric,
    // applied BEFORE enrollment so each gateway's first snapshot already
    // carries the compiled policy. tcp/9090 is intentionally NOT in this
    // fabric: default-deny must reject it, both pre- and post-rotation.
    let diff = h.apply(FABRIC_ICMP_AND_TCP8080).await;
    assert!(
        diff.policy_updated,
        "fabric apply must compile a real policy, got: {diff:?}"
    );

    // Real per-gateway WG keypairs; enroll into the existing segments.
    let (a_priv, a_pub) = wg_keypair();
    let (b_priv, b_pub) = wg_keypair();
    let ga = enroll_into(&h, "10.10.1.0/24", &a_pub).await;
    let gb = enroll_into(&h, "10.10.2.0/24", &b_pub).await;

    // netns lab: two gateways, two workloads.
    let mut lab = Lab::new("gwsec").expect("lab");
    let gwa = lab.ns("a").expect("gwA netns");
    let gwb = lab.ns("b").expect("gwB netns");
    let wla = lab.ns("wa").expect("wlA netns");
    let wlb = lab.ns("wb").expect("wlB netns");

    // Underlay veths from the bridge into each gateway netns.
    attach_underlay(&gwa, "a", "10.9.0.1");
    attach_underlay(&gwb, "b", "10.9.0.2");

    // MANDATORY real one-way latency on both underlays (Phase-0 Finding 2) —
    // must be applied AFTER the underlay `und` device exists.
    apply_netem(&gwa, "und", 20).expect("netem on gwA underlay");
    apply_netem(&gwb, "und", 20).expect("netem on gwB underlay");

    // Segment veths + workload default routes.
    lab.veth((&gwa, "seg0", "10.10.1.1/24"), (&wla, "eth0", "10.10.1.2/24"))
        .expect("seg-a veth");
    lab.veth((&gwb, "seg0", "10.10.2.1/24"), (&wlb, "eth0", "10.10.2.2/24"))
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

    let mut pa = spawn_gw(&gwa, sda.path(), &sync_addr, &observe_addr, logdir.path(), "a");
    let mut pb = spawn_gw(&gwb, sdb.path(), &sync_addr, &observe_addr, logdir.path(), "b");

    // ===== Wait until the mesh is up (an allowed ICMP flow passes) =====
    let up = wait_until(Duration::from_secs(45), || ping_ok(&wla, "10.10.2.2"));
    if !up {
        dump_diag(
            "mesh-not-up",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!("SETUP FAILED: workload A -> workload B ICMP (policy-permitted) never passed over the direct tunnel before rotation");
    }
    eprintln!("SETUP PASS: direct mesh is up (ICMP crosses wlA -> wlB)");

    // ===== BASELINE (pre-rotation): tcp/8080 allowed, tcp/9090 denied =====
    let baseline_8080 = check_tcp(&wla, &wlb, "10.10.2.2", 8080);
    assert!(
        baseline_8080,
        "BASELINE FAILED: tcp/8080 (policy-allowed) did not pass before rotation — \
         the test harness itself is broken, not the enforcer"
    );
    let baseline_9090 = check_tcp(&wla, &wlb, "10.10.2.2", 9090);
    assert!(
        !baseline_9090,
        "BASELINE FAILED: tcp/9090 was NOT denied before rotation — the test is \
         meaningless without a working pre-rotation deny to compare against"
    );
    eprintln!("BASELINE PASS: tcp/8080 allowed, tcp/9090 denied (pre-rotation)");

    // ===== Rotate gwA's key =====
    h.admin_client()
        .await
        .rotate_key(RotateKeyRequest { gateway_id: ga.id() })
        .await
        .expect("Admin.RotateKey");
    eprintln!("Admin.RotateKey submitted for gwA (epoch 0 -> 1)");

    // ===== Poll until the rotation has actually completed =====
    let (completed, final_states) =
        poll_rotation_complete(&h, ga.id(), Duration::from_secs(90)).await;
    if !completed {
        dump_diag(
            "rotation-timeout",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "ROTATION TIMEOUT: gwA's key rotation (epoch 0 -> 1) did not complete within 90s \
             (epoch 1 active + epoch 0 gone/retiring). Last observed debug_key_states: \
             {final_states:?}"
        );
    }
    eprintln!("ROTATION COMPLETE: {final_states:?}");

    // ===== THE SECURITY ASSERTIONS (post-rotation) =====
    // tcp/8080 must still work — the new epoch tun must actually carry
    // policy-allowed traffic (a sanity check that the mesh itself, not just
    // the enforcer, survived the cutover).
    let post_8080 = check_tcp(&wla, &wlb, "10.10.2.2", 8080);
    if !post_8080 {
        dump_diag(
            "post-rotation-8080-failed",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
    }
    assert!(
        post_8080,
        "POST-ROTATION FAILED: tcp/8080 (policy-allowed) stopped passing after rotation — \
         the new epoch tun does not carry allowed traffic at all"
    );

    // THE key assertion: tcp/9090 (never allowed by the fabric) must STILL
    // be denied on the new epoch tun. If this fails, the enforcer is not
    // attached to the new epoch tun and default-deny has been bypassed.
    let post_9090 = check_tcp(&wla, &wlb, "10.10.2.2", 9090);
    if post_9090 {
        dump_diag(
            "post-rotation-9090-leaked",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
    }
    assert!(
        !post_9090,
        "SECURITY: tcp/9090 (policy-denied) leaked after rotation — the enforcer is not \
         attached to the new epoch tun (default-deny bypass)"
    );
    eprintln!("POST-ROTATION PASS: tcp/8080 still allowed, tcp/9090 still denied (enforcer follows the new epoch tun)");

    // Teardown.
    pa.kill();
    pb.kill();
    drop(lab);
    eprintln!("\nDONE-BAR PASSED: default-deny holds across a key rotation — the enforcer stays attached to the new epoch tun.");
}

/// STEP 1 (old-epoch-teardown refactor) REGRESSION: a policy TIGHTENING
/// applied AFTER a rotation has completed must reach whichever tun is
/// actually carrying traffic post-cutover, not just `wg0`.
///
/// `denied_flow_stays_denied_across_rotation` (above) already proves that a
/// STABLE policy (tcp/9090 never allowed) keeps being denied across a
/// rotation — that only requires the new epoch's tun to get *an* enforcer
/// attached at bring-up with the then-current policy. It does NOT prove
/// that a policy CHANGE pushed after the cutover reaches that tun. Today,
/// `apply_state` re-applies the (new) policy IR only to `wg0`'s enforcer —
/// rotation tuns (`wg0e<N>`) receive the policy that was current at their
/// bring-up and nothing since. So a tightening applied post-rotation (e.g.
/// an operator revoking a previously-allowed port) would silently NOT take
/// effect on the tun that is actually forwarding traffic — a default-deny
/// bypass under a CHANGING policy.
///
/// Sequence: same direct mesh as the other two tests in this file, fabric
/// v1 = ICMP both ways + tcp/8080 seg-a->seg-b allowed. Rotate gwA; confirm
/// tcp/8080 still passes post-rotation (the new epoch tun works at all).
/// Then push fabric v2 (`FABRIC_ICMP_ONLY_V2`), which drops the tcp/8080
/// allow — seg-a->seg-b tcp/8080 becomes default-denied. Assert (bounded
/// poll) that tcp/8080 stops passing. If it keeps passing, the tightening
/// never reached the active tun's enforcer: the Step-1 gap this test exists
/// to close.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn policy_tighten_after_rotation_reaches_active_tun() {
    // Underlay bridge in the root netns; controller binds its routable IP.
    setup_bridge();
    let _root_guard = RootNetGuard;

    let h = TestController::start_on(CTRL_IP.parse().unwrap()).await;

    // Fabric v1: ICMP both ways (liveness) + tcp/8080 seg-a->seg-b allowed,
    // applied BEFORE enrollment so each gateway's first snapshot already
    // carries the compiled policy.
    let diff = h.apply(FABRIC_ICMP_AND_TCP8080).await;
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
    let mut lab = Lab::new("gwtgt").expect("lab");
    let gwa = lab.ns("a").expect("gwA netns");
    let gwb = lab.ns("b").expect("gwB netns");
    let wla = lab.ns("wa").expect("wlA netns");
    let wlb = lab.ns("wb").expect("wlB netns");

    // Underlay veths from the bridge into each gateway netns.
    attach_underlay(&gwa, "a", "10.9.0.1");
    attach_underlay(&gwb, "b", "10.9.0.2");

    // MANDATORY real one-way latency on both underlays (Phase-0 Finding 2) —
    // must be applied AFTER the underlay `und` device exists.
    apply_netem(&gwa, "und", 20).expect("netem on gwA underlay");
    apply_netem(&gwb, "und", 20).expect("netem on gwB underlay");

    // Segment veths + workload default routes.
    lab.veth((&gwa, "seg0", "10.10.1.1/24"), (&wla, "eth0", "10.10.1.2/24"))
        .expect("seg-a veth");
    lab.veth((&gwb, "seg0", "10.10.2.1/24"), (&wlb, "eth0", "10.10.2.2/24"))
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

    let mut pa = spawn_gw(&gwa, sda.path(), &sync_addr, &observe_addr, logdir.path(), "a");
    let mut pb = spawn_gw(&gwb, sdb.path(), &sync_addr, &observe_addr, logdir.path(), "b");

    // ===== Wait until the mesh is up (an allowed ICMP flow passes) =====
    let up = wait_until(Duration::from_secs(45), || ping_ok(&wla, "10.10.2.2"));
    if !up {
        dump_diag(
            "mesh-not-up",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!("SETUP FAILED: workload A -> workload B ICMP (policy-permitted) never passed over the direct tunnel before rotation");
    }
    eprintln!("SETUP PASS: direct mesh is up (ICMP crosses wlA -> wlB)");

    // ===== BASELINE (pre-rotation): tcp/8080 allowed =====
    let baseline_8080 = check_tcp(&wla, &wlb, "10.10.2.2", 8080);
    assert!(
        baseline_8080,
        "BASELINE FAILED: tcp/8080 (policy-allowed) did not pass before rotation — \
         the test harness itself is broken, not the enforcer"
    );
    eprintln!("BASELINE PASS: tcp/8080 allowed (pre-rotation)");

    // ===== Rotate gwA's key =====
    h.admin_client()
        .await
        .rotate_key(RotateKeyRequest { gateway_id: ga.id() })
        .await
        .expect("Admin.RotateKey");
    eprintln!("Admin.RotateKey submitted for gwA (epoch 0 -> 1)");

    // ===== Poll until the rotation has actually completed =====
    let (completed, final_states) =
        poll_rotation_complete(&h, ga.id(), Duration::from_secs(90)).await;
    if !completed {
        dump_diag(
            "rotation-timeout",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "ROTATION TIMEOUT: gwA's key rotation (epoch 0 -> 1) did not complete within 90s \
             (epoch 1 active + epoch 0 gone/retiring). Last observed debug_key_states: \
             {final_states:?}"
        );
    }
    eprintln!("ROTATION COMPLETE: {final_states:?}");

    // ===== POST-ROTATION, PRE-TIGHTEN: tcp/8080 must still pass =====
    // (traffic now crosses on the new epoch tun; this is the same sanity
    // check `denied_flow_stays_denied_across_rotation` makes, proving the
    // mesh itself survived the cutover before we go test the tightening.)
    let post_rotation_8080 = check_tcp(&wla, &wlb, "10.10.2.2", 8080);
    if !post_rotation_8080 {
        dump_diag(
            "post-rotation-pre-tighten-8080-failed",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
    }
    assert!(
        post_rotation_8080,
        "POST-ROTATION FAILED: tcp/8080 (policy-allowed) stopped passing right after rotation \
         (before any tightening) — the new epoch tun does not carry allowed traffic at all"
    );
    eprintln!("POST-ROTATION PASS: tcp/8080 still allowed on the new epoch tun (pre-tighten)");

    // ===== THE KEY STEP: push fabric v2, which REMOVES the tcp/8080 allow =====
    // ICMP stays allowed both ways so the mesh doesn't go dark; only the
    // tcp/8080 rule is tightened away, so seg-a -> seg-b tcp/8080 becomes
    // default-denied.
    let diff2 = h.apply(FABRIC_ICMP_ONLY_V2).await;
    assert!(
        diff2.policy_updated,
        "fabric v2 (tightening) apply must compile a real policy update, got: {diff2:?}"
    );
    eprintln!("TIGHTENING PUSHED: fabric v2 applied (tcp/8080 allow removed), diff={diff2:?}");

    // ===== THE ASSERTION: tcp/8080 must become DENIED on the active tun =====
    // Bounded retry loop (the delta must propagate over Sync + get applied)
    // rather than a single check, since apply is asynchronous relative to
    // this test.
    let tighten_deadline = Instant::now() + Duration::from_secs(15);
    let mut still_allowed = true;
    while Instant::now() < tighten_deadline {
        if !check_tcp(&wla, &wlb, "10.10.2.2", 8080) {
            still_allowed = false;
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    if still_allowed {
        dump_diag(
            "tighten-did-not-reach-active-tun",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "policy tightening after a rotation did not reach the active epoch tun — \
             post-cutover enforcement gap (Step 1): tcp/8080 was removed from the fabric \
             but is still passing after a 15s bounded wait"
        );
    }
    eprintln!("TIGHTEN PASS: tcp/8080 became denied on the active epoch tun after the post-rotation tightening (Step 1 closed)");

    // Teardown.
    pa.kill();
    pb.kill();
    drop(lab);
    eprintln!("\nDONE-BAR PASSED: a policy tightening pushed after a rotation reaches the tun actually carrying traffic (Step 1: epoch-aware enforcer).");
}

/// STEP 2+3 (old-epoch-teardown refactor) done bar: after a rotation
/// completes and every peer has provably cut over to the new epoch, the OLD
/// epoch's Device (`wg0`) must actually be torn down — `ip link del`'d, its
/// private key gone from any live boringtun Device — while the NEW epoch's
/// tun (`wg0e1`) stays up and continues carrying (and correctly enforcing)
/// traffic. This is the sharpest possible proof that `apply_state`, the
/// punch/relay `set_peer_endpoint`, and `run_path_ticks` all resolve the
/// "active tun" dynamically (Step 2) rather than hardcoding `wg0`: if any of
/// them still targeted `wg0`, then either (a) `wg0` could never safely be
/// torn down (so this test's central assertion — `wg0` gone — would never
/// pass), or (b) tearing it down anyway would break the live mesh/enforcement
/// (so the post-teardown assertions below would fail instead).
///
/// Sequence: same direct-mesh topology as the other three tests in this
/// file, fabric v1 = ICMP both ways + tcp/8080 seg-a->seg-b allowed
/// (`FABRIC_ICMP_AND_TCP8080`). Rotate gwA; wait for the rotation to
/// complete (epoch 1 active, epoch 0 gone/retiring). Then bound-wait for
/// gwA's `wg0` interface to actually disappear (the retire grace is a
/// handful of keepalives, not instant) while `wg0e1` stays present. Once
/// torn down, re-confirm the mesh still works on the new tun (ICMP +
/// tcp/8080), then push fabric v2 (`FABRIC_ICMP_ONLY_V2`, which removes the
/// tcp/8080 allow) and assert the tightening reaches the *live* tun — proof
/// `apply_state` is applying to `wg0e1`, not silently erroring against a
/// Device that no longer exists.
///
/// RED NOW: the gateway never tears down `wg0` after a rotation retires it
/// (assertion 4 below fails — `wg0` stays present forever).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn old_epoch_device_is_torn_down_after_rotation() {
    // Underlay bridge in the root netns; controller binds its routable IP.
    setup_bridge();
    let _root_guard = RootNetGuard;

    let h = TestController::start_on(CTRL_IP.parse().unwrap()).await;

    // Fabric v1: ICMP both ways (liveness) + tcp/8080 seg-a->seg-b allowed,
    // applied BEFORE enrollment so each gateway's first snapshot already
    // carries the compiled policy.
    let diff = h.apply(FABRIC_ICMP_AND_TCP8080).await;
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
    let mut lab = Lab::new("gwtd").expect("lab");
    let gwa = lab.ns("a").expect("gwA netns");
    let gwb = lab.ns("b").expect("gwB netns");
    let wla = lab.ns("wa").expect("wlA netns");
    let wlb = lab.ns("wb").expect("wlB netns");

    // Underlay veths from the bridge into each gateway netns.
    attach_underlay(&gwa, "a", "10.9.0.1");
    attach_underlay(&gwb, "b", "10.9.0.2");

    // MANDATORY real one-way latency on both underlays (Phase-0 Finding 2) —
    // must be applied AFTER the underlay `und` device exists.
    apply_netem(&gwa, "und", 20).expect("netem on gwA underlay");
    apply_netem(&gwb, "und", 20).expect("netem on gwB underlay");

    // Segment veths + workload default routes.
    lab.veth((&gwa, "seg0", "10.10.1.1/24"), (&wla, "eth0", "10.10.1.2/24"))
        .expect("seg-a veth");
    lab.veth((&gwb, "seg0", "10.10.2.1/24"), (&wlb, "eth0", "10.10.2.2/24"))
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

    let mut pa = spawn_gw(&gwa, sda.path(), &sync_addr, &observe_addr, logdir.path(), "a");
    let mut pb = spawn_gw(&gwb, sdb.path(), &sync_addr, &observe_addr, logdir.path(), "b");

    // ===== Wait until the mesh is up (an allowed ICMP flow passes) =====
    let up = wait_until(Duration::from_secs(45), || ping_ok(&wla, "10.10.2.2"));
    if !up {
        dump_diag(
            "mesh-not-up",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!("SETUP FAILED: workload A -> workload B ICMP (policy-permitted) never passed over the direct tunnel before rotation");
    }
    eprintln!("SETUP PASS: direct mesh is up (ICMP crosses wlA -> wlB)");

    // ===== BASELINE (pre-rotation): tcp/8080 allowed =====
    let baseline_8080 = check_tcp(&wla, &wlb, "10.10.2.2", 8080);
    assert!(
        baseline_8080,
        "BASELINE FAILED: tcp/8080 (policy-allowed) did not pass before rotation — \
         the test harness itself is broken, not the enforcer"
    );
    eprintln!("BASELINE PASS: tcp/8080 allowed (pre-rotation)");

    // ===== Rotate gwA's key =====
    h.admin_client()
        .await
        .rotate_key(RotateKeyRequest { gateway_id: ga.id() })
        .await
        .expect("Admin.RotateKey");
    eprintln!("Admin.RotateKey submitted for gwA (epoch 0 -> 1)");

    // ===== Poll until the rotation has actually completed (epoch 1 active,
    // epoch 0 gone/retiring) =====
    let (completed, final_states) =
        poll_rotation_complete(&h, ga.id(), Duration::from_secs(90)).await;
    if !completed {
        dump_diag(
            "rotation-timeout",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "ROTATION TIMEOUT: gwA's key rotation (epoch 0 -> 1) did not complete within 90s \
             (epoch 1 active + epoch 0 gone/retiring). Last observed debug_key_states: \
             {final_states:?}"
        );
    }
    eprintln!("ROTATION COMPLETE: {final_states:?}");

    // ===== THE TEARDOWN ASSERTION =====
    // The retire grace is a handful of keepalives after every peer's session
    // on the new tun is rx-corroborated live, so this is a bounded retry loop
    // (up to ~30s, 1s sleeps) rather than a single check: `wg0` must
    // disappear entirely (the `ip link show wg0` Command must fail/exit
    // non-zero) while `wg0e1` stays present the whole time.
    let teardown_deadline = Instant::now() + Duration::from_secs(30);
    let mut torn_down = false;
    loop {
        let wg0_gone = gwa.exec(&["ip", "link", "show", "wg0"]).is_err();
        let wg0e1_present = gwa.exec(&["ip", "link", "show", "wg0e1"]).is_ok();
        if wg0_gone && wg0e1_present {
            torn_down = true;
            break;
        }
        if Instant::now() >= teardown_deadline {
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    if !torn_down {
        dump_diag(
            "old-epoch-not-torn-down",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "old-epoch Device wg0 was not torn down after the rotation retired epoch 0"
        );
    }
    eprintln!("TEARDOWN PASS: gwA's wg0 (epoch 0) is gone; wg0e1 (epoch 1) is present");

    // ===== POST-TEARDOWN: the mesh still works on the new tun =====
    let still_works = wait_until(Duration::from_secs(15), || ping_ok(&wla, "10.10.2.2"));
    if !still_works {
        dump_diag(
            "post-teardown-icmp-failed",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!("POST-TEARDOWN FAILED: ICMP wlA -> wlB no longer passes after wg0 was torn down");
    }
    let post_teardown_8080 = check_tcp(&wla, &wlb, "10.10.2.2", 8080);
    if !post_teardown_8080 {
        dump_diag(
            "post-teardown-8080-failed",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
    }
    assert!(
        post_teardown_8080,
        "POST-TEARDOWN FAILED: tcp/8080 (policy-allowed) stopped passing after wg0 was torn down \
         — traffic is not actually being carried/enforced on the new tun"
    );
    eprintln!("POST-TEARDOWN PASS: ICMP and tcp/8080 both still work on wg0e1 after wg0 was torn down");

    // ===== POST-TEARDOWN: a policy tightening still reaches the LIVE tun =====
    // Push fabric v2, which removes the tcp/8080 allow. If `apply_state`
    // still targeted the torn-down `wg0`, this would either error/crash the
    // gateway or silently no-op; the gateway staying up AND tcp/8080
    // becoming denied is proof `apply_state` follows the active (live) tun.
    let diff2 = h.apply(FABRIC_ICMP_ONLY_V2).await;
    assert!(
        diff2.policy_updated,
        "fabric v2 (tightening) apply must compile a real policy update, got: {diff2:?}"
    );
    eprintln!("TIGHTENING PUSHED: fabric v2 applied (tcp/8080 allow removed), diff={diff2:?}");

    let tighten_deadline = Instant::now() + Duration::from_secs(15);
    let mut still_allowed = true;
    while Instant::now() < tighten_deadline {
        if !check_tcp(&wla, &wlb, "10.10.2.2", 8080) {
            still_allowed = false;
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    if still_allowed {
        dump_diag(
            "tighten-did-not-reach-live-tun-post-teardown",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "policy tightening after old-epoch teardown did not reach the live epoch tun: \
             tcp/8080 was removed from the fabric but is still passing after a 15s bounded wait"
        );
    }
    eprintln!("TIGHTEN PASS: tcp/8080 became denied on the live tun after teardown (apply_state follows the active tun, not torn-down wg0)");

    // Teardown.
    pa.kill();
    pb.kill();
    drop(lab);
    eprintln!("\nDONE-BAR PASSED: the old epoch's Device (wg0) is torn down after its rotation retires, the mesh keeps working on the new tun, and policy changes keep reaching the live tun (Step 2+3: epoch-aware device unification + retire/teardown).");
}

// --- restart-durability helpers (Backlog 3 Task 1) ---------------------------

/// Minimal base64 decoder for a 32-byte WG key — duplicated from
/// `tunnelset_netns.rs` (`wiremesh_gateway::uapi`'s own decoder is
/// `pub(crate)`-only, invisible to integration tests). Used solely to turn
/// base64 pubkeys into the lowercase hex boringtun's UAPI speaks.
fn base64_decode_32(s: &str) -> [u8; 32] {
    fn val(c: u8) -> u32 {
        match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("invalid base64 char in test pubkey: {:?}", c as char),
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|&c| c != b'=' && !c.is_ascii_whitespace()).collect();
    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c) << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    out.try_into().expect("WG pubkey must decode to exactly 32 bytes")
}

/// Lowercase hex of a base64-encoded 32-byte WG pubkey (the UAPI wire form).
fn base64_pub_to_hex(b64: &str) -> String {
    base64_decode_32(b64).iter().map(|b| format!("{b:02x}")).collect()
}

/// Panics loudly unless `python3` actually RUNS in `ns`. Called before every
/// UAPI probe so an absent/broken interpreter can never be mistaken for a
/// legitimate "socket not up yet" `None` — which would otherwise make the
/// restart case fail with a completely misleading diagnosis (or, anywhere a
/// `None` is tolerated, pass vacuously).
///
/// Probed exactly ONCE per process: a netns isolates only networking, and
/// `Ns::exec`'s `nsenter --mount=<pin>` mount namespace differs from the
/// container root's only in the private `/var/run/wireguard` tmpfs, so
/// `/usr/bin/python3` is the same file in every `Ns` — one probe answers for
/// all of them.
fn require_python3(ns: &Ns) {
    static PROBED: std::sync::Once = std::sync::Once::new();
    PROBED.call_once(|| {
        ns.exec(&["python3", "-c", "pass"]).expect(
            "python3 is REQUIRED by this netns suite (the UAPI probe below, and \
             spawn_listener/tcp_connect) but did not run in the gateway netns. The dev \
             container gets python3 implicitly from the rust:1-bookworm base — \
             dev/Dockerfile does not install it explicitly — so a base-image change can \
             remove it. This is an ENVIRONMENT failure, not a gateway failure",
        );
    });
}

/// Raw `get=1` UAPI response of `ifname`'s Device INSIDE the gateway's
/// namespaces. Unlike `tunnelset_netns.rs`'s in-process probe, this test
/// stays in the root namespaces while each gateway's UAPI socket lives on a
/// PRIVATE `/var/run/wireguard` tmpfs in that gateway `Ns`'s persistent
/// mount namespace (see `wiremesh-testkit/src/netns.rs`'s `MOUNTNS_DIR`), so
/// the probe must be a subprocess run through `Ns::exec` (which
/// `nsenter --mount=<pin>`s first). boringtun 0.6.0 reports the device's own
/// identity as a non-standard `own_public_key=<hex>` line (and omits
/// `private_key=`), which the real `wg` CLI silently ignores — so this talks
/// to the socket directly (Task-6 divergence,
/// `docs/research/keyrot-task6-uapi-pubkey-note.md`). `None` while the
/// Device/socket isn't up (connect refused / no such file) — callers poll.
///
/// **`python3` is a hard requirement of this file's netns suite** (this probe
/// plus `spawn_listener`/`tcp_connect`). The dev container provides it
/// IMPLICITLY — `dev/Dockerfile`'s explicit apt list does not name it; it
/// arrives transitively with the `rust:1-bookworm` base (verified:
/// `/usr/bin/python3`, Python 3.11.2, owned by `python3-minimal`). Because
/// nothing pins that, a base-image bump could silently remove it — hence
/// `require_python3` below: a missing interpreter must NOT masquerade as
/// "the Device's UAPI socket isn't up yet".
fn uapi_get_device(ns: &Ns, ifname: &str) -> Option<String> {
    require_python3(ns);
    let script = format!(
        r#"
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(3)
try:
    s.connect("/var/run/wireguard/{ifname}.sock")
    s.sendall(b"get=1\n\n")
    buf = b""
    while b"\n\n" not in buf:
        d = s.recv(4096)
        if not d:
            break
        buf += d
except Exception as e:
    sys.stderr.write(str(e))
    sys.exit(1)
sys.stdout.write(buf.decode())
"#
    );
    let out = ns.exec(&["python3", "-c", &script]).ok()?;
    let resp = String::from_utf8_lossy(&out.stdout).into_owned();
    if resp.is_empty() {
        None
    } else {
        Some(resp)
    }
}

/// First `key=` value in a UAPI `get=1` response. For the device-level
/// fields this test reads (`own_public_key`, `listen_port`) first-wins is
/// correct: boringtun emits the device header before any peer section.
fn uapi_field(resp: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    resp.lines().find_map(|l| l.strip_prefix(prefix.as_str()).map(str::to_string))
}

/// BACKLOG 3 TASK 1 done bar (SECURITY): a completed rotation must SURVIVE a
/// gateway crash+restart — the promoted epoch is durable and the retired
/// private key is durably GONE.
///
/// Today rotation's promote/retire lifecycle is process-local:
/// `EpochKeys::promote`/`retire` have zero callers, boot unconditionally
/// brings up epoch 0 from the identity key (`main.rs` ~238), and
/// `EpochKeys::load` (~463) is only a mint base. So after the rotation this
/// test completes, SIGKILLing gwA and restarting it from the same state dir
/// resurrects the RETIRED epoch-0 key — while the controller (which
/// promoted epoch 1) has every peer advertising only the new key: the
/// restarted gateway is a fabric-wide black hole, and the "retired" private
/// key was never actually destroyed.
///
/// Choreography: case 1's direct-mesh setup + rotation, then case 4's
/// bounded wait for the retire/teardown to land (wg0 gone, wg0e1 present) so
/// the retire step has provably run before the crash. Then SIGKILL gwA's
/// process (a real crash — no graceful shutdown path) and restart the same
/// binary from the same `--state-dir`. Assertions, in fail-first order:
///
///   (a) the restarted Device's OWN key — read via UAPI `get=1`
///       `own_public_key` — is the NEW epoch's pubkey, never the retired
///       epoch-0 one. **RED TODAY: this fails first** (the reboot comes up
///       on the identity key = epoch 0).
///   (b) `epoch_keys.json` no longer contains the retired private key — by
///       raw byte-grep AND through the reloaded store's API.
///   (c) wlA <-> wlB traffic resumes within 90s (bound derivation below).
///   (d) per OD-1 the reboot RE-NORMALIZES: the new epoch's key runs on the
///       BASE tun `wg0` at the BASE port 51820 (asserted via the UAPI
///       socket probed being wg0's and its `listen_port`), regardless of the
///       pre-reboot state (pre-crash the live device was `wg0e1` at 51821).
///       `wg0e1` must not be resurrected. A reboot tears all sessions
///       anyway, and peers' stored candidates are base-port — so base-port
///       is the only endpoint peers can find the restarted gateway at.
///
/// Recovery bound for (c) — 90s, derived from the harness's existing
/// patterns rather than invented: worst case, gwB only notices its
/// established path to gwA died via the path state machine's
/// Direct -> Degraded transition at 45s of rx-silence (`path.rs`; pinned by
/// `nat_matrix.rs` case 4) before it re-enters the punch/re-establish
/// ladder; from there, re-establishment is bounded by this file's own
/// standard 45s initial mesh-up window (every case here waits 45s for the
/// first handshake under the mandatory 20ms netem). 45 + 45 = 90s — also
/// exactly the bound `poll_rotation_complete` already uses. Typically far
/// faster: the REBOOTED side re-initiates immediately (fail-static apply +
/// punch ladder from boot), it doesn't wait for gwB's silence detection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotation_survives_gateway_restart_on_new_epoch() {
    // Underlay bridge in the root netns; controller binds its routable IP.
    setup_bridge();
    let _root_guard = RootNetGuard;

    let h = TestController::start_on(CTRL_IP.parse().unwrap()).await;

    // ICMP-both-ways fabric BEFORE enrollment (same as case 1).
    let diff = h.apply(FABRIC_ICMP).await;
    assert!(
        diff.policy_updated,
        "fabric apply must compile a real policy, got: {diff:?}"
    );

    // Real per-gateway WG keypairs; enroll into the existing segments.
    // NB: `a_priv` IS epoch 0's private key (the identity key `from_legacy`
    // migrates at first boot) — it is the exact byte string that must be
    // GONE from epoch_keys.json once the rotation's retire has run.
    let (a_priv, a_pub) = wg_keypair();
    let (b_priv, b_pub) = wg_keypair();
    let ga = enroll_into(&h, "10.10.1.0/24", &a_pub).await;
    let gb = enroll_into(&h, "10.10.2.0/24", &b_pub).await;

    // netns lab: two gateways, two workloads.
    let mut lab = Lab::new("gwrst").expect("lab");
    let gwa = lab.ns("a").expect("gwA netns");
    let gwb = lab.ns("b").expect("gwB netns");
    let wla = lab.ns("wa").expect("wlA netns");
    let wlb = lab.ns("wb").expect("wlB netns");

    // Underlay veths from the bridge into each gateway netns.
    attach_underlay(&gwa, "a", "10.9.0.1");
    attach_underlay(&gwb, "b", "10.9.0.2");

    // MANDATORY real one-way latency on both underlays (Phase-0 Finding 2) —
    // must be applied AFTER the underlay `und` device exists.
    apply_netem(&gwa, "und", 20).expect("netem on gwA underlay");
    apply_netem(&gwb, "und", 20).expect("netem on gwB underlay");

    // Segment veths + workload default routes.
    lab.veth((&gwa, "seg0", "10.10.1.1/24"), (&wla, "eth0", "10.10.1.2/24"))
        .expect("seg-a veth");
    lab.veth((&gwb, "seg0", "10.10.2.1/24"), (&wlb, "eth0", "10.10.2.2/24"))
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

    let mut pa = spawn_gw(&gwa, sda.path(), &sync_addr, &observe_addr, logdir.path(), "a");
    let mut pb = spawn_gw(&gwb, sdb.path(), &sync_addr, &observe_addr, logdir.path(), "b");

    // ===== Wait until the mesh is up (an allowed ICMP flow passes) =====
    let up = wait_until(Duration::from_secs(45), || ping_ok(&wla, "10.10.2.2"));
    if !up {
        dump_diag(
            "mesh-not-up",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!("SETUP FAILED: workload A -> workload B ICMP (policy-permitted) never passed over the direct tunnel before rotation");
    }
    eprintln!("SETUP PASS: direct mesh is up (ICMP crosses wlA -> wlB)");

    // ===== Rotate gwA's key (case-1 choreography) =====
    h.admin_client()
        .await
        .rotate_key(RotateKeyRequest { gateway_id: ga.id() })
        .await
        .expect("Admin.RotateKey");
    eprintln!("Admin.RotateKey submitted for gwA (epoch 0 -> 1)");

    let (completed, final_states) =
        poll_rotation_complete(&h, ga.id(), Duration::from_secs(90)).await;
    if !completed {
        dump_diag(
            "rotation-timeout",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "ROTATION TIMEOUT: gwA's key rotation (epoch 0 -> 1) did not complete within 90s \
             (epoch 1 active + epoch 0 gone/retiring). Last observed debug_key_states: \
             {final_states:?}"
        );
    }
    eprintln!("ROTATION COMPLETE: {final_states:?}");

    // ===== Wait for the retire/teardown to land BEFORE crashing =====
    // Same bounded wait as `old_epoch_device_is_torn_down_after_rotation`:
    // the retire grace is a handful of keepalives after every peer stays
    // rx-corroborated live on the new tun. Waiting for gwA's `wg0` to be
    // GONE (and `wg0e1` present) proves `service_retire` has run — so the
    // durable-retire assertion (b) below is judged only after the point the
    // ratified fix says the private key must have been scrubbed from disk.
    let teardown_deadline = Instant::now() + Duration::from_secs(30);
    let mut torn_down = false;
    loop {
        let wg0_gone = gwa.exec(&["ip", "link", "show", "wg0"]).is_err();
        let wg0e1_present = gwa.exec(&["ip", "link", "show", "wg0e1"]).is_ok();
        if wg0_gone && wg0e1_present {
            torn_down = true;
            break;
        }
        if Instant::now() >= teardown_deadline {
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    if !torn_down {
        dump_diag(
            "old-epoch-not-torn-down-pre-crash",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "SETUP FAILED: gwA's epoch-0 retire/teardown (wg0 gone, wg0e1 present) never \
             landed within 30s of the rotation completing — cannot test restart durability \
             of a retire that hasn't happened"
        );
    }
    eprintln!("PRE-CRASH: retire landed (gwA wg0 gone, wg0e1 present, live at offset port)");

    // Capture the NEW epoch's key material from the persisted store while
    // gwA is still up. `handle_rotate` persists the mint, so epoch 1 is in
    // epoch_keys.json today (state "pending" — unpromoted, the bug) and
    // post-fix (state "active"). No state assertions HERE, deliberately:
    // every durable-state judgment happens post-restart so that assertion
    // (a) is the first thing that can fail.
    let pre_crash_store = match wiremesh_gateway::epochkeys::EpochKeys::load(sda.path()) {
        Ok(Some(s)) => s,
        other => {
            pa.kill();
            pb.kill();
            panic!(
                "gwA must have persisted an epoch_keys.json (boot migration + rotation \
                 mint); load returned: {other:?}"
            );
        }
    };
    let Some(new_key) = pre_crash_store.by_epoch(1).cloned() else {
        pa.kill();
        pb.kill();
        panic!(
            "gwA's epoch_keys.json has no epoch-1 entry after a completed rotation; \
             store: {pre_crash_store:?}"
        );
    };
    let new_pub_hex = base64_pub_to_hex(&new_key.pubkey_b64);
    let old_pub_hex = base64_pub_to_hex(&a_pub);
    if new_pub_hex == old_pub_hex {
        pa.kill();
        pb.kill();
        panic!("sanity: rotation minted a distinct key");
    }

    // ===== SIGKILL gwA (a real crash) =====
    // `pkill -KILL -f <state-dir>`: the state-dir path is in gwA's argv and
    // unique to it (a tempdir), so this reaches the actual gateway process
    // (and its nsenter/ip-netns wrapper chain) without touching gwB — the
    // same reach-the-real-process reasoning as case 1's `pkill -INT ping`.
    // SIGKILL specifically: no signal handler, no graceful persist — the
    // durability under test must come from what was ALREADY on disk.
    let sda_str = sda.path().to_str().unwrap().to_string();
    let killed = Command::new("pkill")
        .args(["-KILL", "-f", &sda_str])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !killed {
        // `pkill` exits 1 when NOTHING matched — gwA's process is not where
        // this test thinks it is, so the "restart" would be meaningless.
        pa.kill();
        pb.kill();
        panic!("pkill -KILL -f {sda_str} matched no process — could not crash gwA");
    }
    pa.kill(); // reap the wrapper Child + drain threads
    // The crash must actually take the data plane down (tun devices die with
    // their owning process's fds) before the restart re-creates it.
    let dead = wait_until(Duration::from_secs(10), || {
        gwa.exec(&["ip", "link", "show", "wg0e1"]).is_err()
    });
    if !dead {
        pb.kill();
        panic!(
            "gwA's wg0e1 still present 10s after SIGKILL — the kill did not reach the \
             gateway process; the restart below would not be a real crash-recovery"
        );
    }
    eprintln!("CRASH: gwA SIGKILLed; data plane gone");

    // ===== Restart gwA from the SAME state dir =====
    let mut pa = spawn_gw(&gwa, sda.path(), &sync_addr, &observe_addr, logdir.path(), "a-restart");

    // ===== (a) THE RED ASSERTION: the restarted Device runs the NEW key =====
    // Boot is controller-independent (fail-static), so the base tun must
    // appear well inside 30s (the same bound style as the teardown wait).
    // Poll until wg0's UAPI socket answers at all, THEN judge the key once.
    let mut resp = None;
    let probe_ok = wait_until(Duration::from_secs(30), || {
        resp = uapi_get_device(&gwa, "wg0");
        resp.as_deref().map_or(false, |r| uapi_field(r, "own_public_key").is_some())
    });
    if !probe_ok {
        dump_diag(
            "restart-no-wg0-uapi",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "RESTART FAILED: gwA's wg0 UAPI never answered get=1 within 30s of restart \
             (last resp: {resp:?})"
        );
    }
    let resp = resp.expect("probe_ok implies a response");
    let own_hex = uapi_field(&resp, "own_public_key").expect("checked in probe");
    if own_hex == old_pub_hex {
        pa.kill();
        pb.kill();
        panic!(
            "SECURITY (Backlog 3 Task 1, RED): the restarted gateway RESURRECTED the \
             RETIRED epoch-0 identity key — boot ignored the promoted epoch and came up \
             on `Identity::wg_private_key_b64`. Peers advertise only the new epoch's key \
             (the controller promoted it), so this gateway is now a fabric-wide black \
             hole AND the \"retired\" private key was never destroyed. \
             own_public_key={own_hex} == retired epoch-0 pubkey"
        );
    }
    if own_hex != new_pub_hex {
        dump_diag(
            "restart-unexpected-own-key",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "restarted wg0's own_public_key is neither the retired epoch-0 key nor the \
             promoted epoch-1 key — boot selected some unexpected identity"
        );
    }
    eprintln!("RESTART KEY PASS: wg0 came up with the promoted epoch-1 key");

    // ===== (b) durable retire: the old private key is GONE from disk =====
    // Every failure below kills both gateway processes FIRST (the file-wide
    // convention) so a failing assertion can never leave two real gateway
    // binaries running against the lab's netns.
    let raw = match std::fs::read_to_string(sda.path().join("epoch_keys.json")) {
        Ok(r) => r,
        Err(e) => {
            pa.kill();
            pb.kill();
            panic!("reading gwA epoch_keys.json post-restart: {e}");
        }
    };
    if raw.contains(&a_priv) {
        pa.kill();
        pb.kill();
        panic!(
            "SECURITY: the retired epoch-0 PRIVATE key is still in gwA's epoch_keys.json \
             after retire + restart — retirement never durably destroyed it:\n{raw}"
        );
    }
    let store = match wiremesh_gateway::epochkeys::EpochKeys::load(sda.path()) {
        Ok(Some(s)) => s,
        other => {
            pa.kill();
            pb.kill();
            panic!("re-reading gwA epoch_keys.json (must exist): {other:?}");
        }
    };
    if store.epochs.iter().any(|k| k.private_key_b64 == a_priv) {
        pa.kill();
        pb.kill();
        panic!("no store entry may still carry the retired epoch-0 private key: {store:?}");
    }
    let Some(active) = store.active() else {
        pa.kill();
        pb.kill();
        panic!("post-rotation store must have an ACTIVE epoch for boot to select: {store:?}");
    };
    if active.pubkey_b64 != new_key.pubkey_b64 {
        let got = active.pubkey_b64.clone();
        pa.kill();
        pb.kill();
        panic!(
            "the store's active entry must be the promoted epoch-1 key (got {got}, \
             want {})",
            new_key.pubkey_b64
        );
    }
    eprintln!("DURABLE RETIRE PASS: epoch-0 private key absent from disk; epoch 1 active");

    // ===== (c) traffic resumes within the derived 90s bound =====
    let resumed = wait_until(Duration::from_secs(90), || ping_ok(&wla, "10.10.2.2"));
    if !resumed {
        dump_diag(
            "post-restart-traffic-never-resumed",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "POST-RESTART FAILED: wlA -> wlB ICMP did not resume within 90s of gwA's \
             restart (bound = 45s peer-side Direct->Degraded silence detection + 45s \
             standard mesh-establishment window). Peers hold base-port candidates and \
             the restarted gateway is on the base port, so the normal punch/re-establish \
             ladder should have reconverged"
        );
    }
    eprintln!("RECOVERY PASS: wlA <-> wlB traffic resumed after the restart");

    // ===== (d) OD-1 re-normalization: base tun, base port, no zombie e-tun =====
    // The key already proved to live on wg0 (that's the socket probed in (a));
    // its listen_port must be the BASE port — pre-crash the live device was
    // wg0e1 at 51821, and a reboot must NOT preserve that offset (peers'
    // stored candidates are base-port; sessions were torn by the reboot).
    let Some(port) = uapi_field(&resp, "listen_port") else {
        pa.kill();
        pb.kill();
        panic!("boringtun's get=1 always reports listen_port; response was:\n{resp}");
    };
    if port != "51820" {
        dump_diag(
            "restart-not-on-base-port",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "OD-1: the restarted gateway must re-normalize to the BASE WireGuard port \
             regardless of the pre-reboot epoch offset (was on 51821 pre-crash)"
        );
    }
    if gwa.exec(&["ip", "link", "show", "wg0"]).is_err() {
        dump_diag(
            "restart-no-base-tun",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!("OD-1: the restarted gateway's device must be the base tun wg0");
    }
    if gwa.exec(&["ip", "link", "show", "wg0e1"]).is_ok() {
        dump_diag(
            "restart-resurrected-offset-tun",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "OD-1: the restarted gateway must NOT resurrect the pre-crash epoch-offset tun \
             wg0e1 — the promoted epoch runs on the base tun after a reboot"
        );
    }
    eprintln!("OD-1 PASS: restarted gateway is on wg0 at the base port, no wg0e1");

    // Teardown.
    pa.kill();
    pb.kill();
    drop(lab);
    eprintln!("\nDONE-BAR PASSED: a completed rotation survives a crash+restart — the promoted epoch boots (on wg0/base port per OD-1), the retired private key is durably gone, and traffic reconverges.");
}

// --- in-step (whole-fabric) rotation: T3's done bar --------------------------

/// Every network interface currently present in `ns`, by its LOCAL name.
/// `ip -br link` prints a veth end as `seg0@if7`; only the part before `@` is
/// this namespace's name for it. Interface names are the one thing the kernel
/// itself guarantees unique per namespace, which is what makes counting them a
/// SCHEME-AGNOSTIC probe: the test never has to know what the implementer
/// named the rotation tuns, only that two more devices exist than before.
/// An `ip` failure yields an empty set rather than panicking — this runs
/// inside a sampling loop where a transient miss must not abort the run (the
/// assertion is on the PEAK across all samples, so a dropped sample can only
/// ever make the test harder to pass).
fn link_names(ns: &Ns) -> BTreeSet<String> {
    let Ok(out) = ns.exec(&["ip", "-br", "link"]) else {
        return BTreeSet::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| Some(l.split_whitespace().next()?.split('@').next()?.to_string()))
        .collect()
}

/// The same "the rotation has completed" predicate `poll_rotation_complete`
/// applies — epoch 1 is `active` AND no epoch-0 row is still `active` (either
/// retired away or demoted to `"retiring"`). Factored out here (rather than
/// reusing `poll_rotation_complete`, which polls ONE gateway to its own
/// deadline) because the in-step case has to watch BOTH gateways on a single
/// sampling loop: sampling the transient overlap devices is only possible
/// while at least one rotation is still in flight.
fn rotation_done(states: &[(u32, String, String)]) -> bool {
    states.iter().any(|(e, _, s)| *e == 1 && s == "active")
        && !states.iter().any(|(e, _, s)| *e == 0 && s == "active")
}

/// **T3 DONE BAR — the scenario the shipped outage actually needs.**
///
/// Every other rotation test in this file rotates ONE gateway, so an
/// own-epoch tun and a Role-B overlap tun never carry the same epoch number
/// and the `TunnelSet` collision cannot arise at all. That is not the
/// production case: `initiate_due_rotations`
/// (`controller/services/sync.rs:640-688`) walks **every** active gateway off
/// one global `rotation_interval` with no per-gateway key-age filter, so the
/// whole fabric marches N -> N+1 in the same tick. Both gateways then hit the
/// three-axis collision simultaneously — this gateway's own new epoch 1 vs the
/// overlap toward a peer whose pending epoch is also 1 (see
/// `docs/research/key-rotation-plan-verification.md`, headline + F3/F8).
///
/// # What "in step" means here, and why it is driven explicitly
///
/// Both gateways are rotated by back-to-back `Admin.RotateKey` calls on a
/// single admin client rather than by shrinking the controller's rotation
/// timer. Three reasons, in order of weight:
///
///  1. It is the SAME collision. The hazard is that the two epoch NUMBERS
///     coincide, which they do for any pair rotating 0 -> 1; the timer only
///     decides *when*. Nothing about the defect is timer-specific — indeed the
///     verification's owner-decision D rejects jitter precisely because
///     staggering does not help.
///  2. It is deterministic. A timer-driven variant would make the test's
///     result depend on tick alignment against a 45s mesh-up wait.
///  3. The timer route is not reachable from here without a new harness seam:
///     `TestController::start_with_rotation_intervals` binds
///     `Config::default_bind_ip()`, and this topology needs
///     `start_on(CTRL_IP)` for a routable underlay address. There is no
///     constructor taking both.
///
/// The two RPCs are issued with no wait between them, so gwA is still holding
/// its own epoch-1 tun when gwB's epoch-1 pending key reaches it — which is
/// exactly the window in which the collision fires.
///
/// # The assertion that would have been red before the fix
///
/// Each gateway must, at some instant during the rotation window, have TWO
/// MORE network interfaces than it had at steady state: its own new epoch tun
/// (Role A) *and* an overlap tun toward the rotating peer (Role B). Four
/// rotation devices across the pair, on top of the two base tuns.
///
/// Before the fix, both roles computed the same map key, the same ifname and
/// the same listen port; `TunnelSet::bring_up` bailed on the duplicate and the
/// `?` inside `for peer in &ds.peers` aborted the whole Role-B loop, whose
/// caller only logs. Neither side ever brought an overlap up, so the peak
/// would have been base + 1, not base + 2, on both gateways.
///
/// The probe is deliberately a COUNT of interfaces, not a set of names: the
/// test asks the kernel "how many devices are up", never "is `wg0e1` up", so
/// it holds for any de-collision scheme the implementer picks. Port
/// distinctness is NOT re-probed here — it is already pinned twice, purely in
/// `tests/tunnel_id_decollision.rs` and against real Devices in
/// `tests/tunnelset_same_epoch_netns.rs`. Sampling `wg show` at the peak would
/// add a race to this (serial, flake-sensitive) file for no new information.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_step_rotation_of_both_gateways_stands_up_own_and_overlap_tuns() {
    // Topology: IDENTICAL to `direct_rotation_is_zero_drop` — see that test
    // for the per-step rationale (bridge, netem, veths, identities).
    setup_bridge();
    let _root_guard = RootNetGuard;

    let h = TestController::start_on(CTRL_IP.parse().unwrap()).await;

    let diff = h.apply(FABRIC_ICMP).await;
    assert!(diff.policy_updated, "fabric apply must compile a real policy, got: {diff:?}");

    let (a_priv, a_pub) = wg_keypair();
    let (b_priv, b_pub) = wg_keypair();
    let ga = enroll_into(&h, "10.10.1.0/24", &a_pub).await;
    let gb = enroll_into(&h, "10.10.2.0/24", &b_pub).await;

    let mut lab = Lab::new("gwstep").expect("lab");
    let gwa = lab.ns("a").expect("gwA netns");
    let gwb = lab.ns("b").expect("gwB netns");
    let wla = lab.ns("wa").expect("wlA netns");
    let wlb = lab.ns("wb").expect("wlB netns");

    attach_underlay(&gwa, "a", "10.9.0.1");
    attach_underlay(&gwb, "b", "10.9.0.2");
    apply_netem(&gwa, "und", 20).expect("netem on gwA underlay");
    apply_netem(&gwb, "und", 20).expect("netem on gwB underlay");

    lab.veth((&gwa, "seg0", "10.10.1.1/24"), (&wla, "eth0", "10.10.1.2/24"))
        .expect("seg-a veth");
    lab.veth((&gwb, "seg0", "10.10.2.1/24"), (&wlb, "eth0", "10.10.2.2/24"))
        .expect("seg-b veth");
    wla.exec(&["ip", "route", "add", "default", "via", "10.10.1.1"])
        .expect("wlA default route");
    wlb.exec(&["ip", "route", "add", "default", "via", "10.10.2.1"])
        .expect("wlB default route");

    let sda = tempfile::tempdir().unwrap();
    let sdb = tempfile::tempdir().unwrap();
    write_identity(&ga, &a_priv, sda.path());
    write_identity(&gb, &b_priv, sdb.path());
    let logdir = tempfile::tempdir().unwrap();

    let sync_addr = h.sync_tcp_addr().to_string();
    let observe_addr = h.observe_addr().to_string();
    let mut pa = spawn_gw(&gwa, sda.path(), &sync_addr, &observe_addr, logdir.path(), "a");
    let mut pb = spawn_gw(&gwb, sdb.path(), &sync_addr, &observe_addr, logdir.path(), "b");

    // ===== Wait until the mesh is up (an allowed ICMP flow passes) =====
    let up = wait_until(Duration::from_secs(45), || ping_ok(&wla, "10.10.2.2"));
    if !up {
        dump_diag("mesh-not-up", &[("gwA", &gwa), ("gwB", &gwb)], &[("gwA", &pa), ("gwB", &pb)]);
        pa.kill();
        pb.kill();
        panic!("SETUP FAILED: workload A -> workload B ICMP (policy-permitted) never passed over the direct tunnel before rotation");
    }
    eprintln!("SETUP PASS: direct mesh is up (ICMP crosses wlA -> wlB)");

    // ===== Steady-state interface baseline, per gateway =====
    // Expected: lo, und, seg0, wg0. Captured rather than hard-coded so the
    // assertion is "two MORE than steady state", immune to the harness
    // acquiring another device later.
    let base_a = link_names(&gwa);
    let base_b = link_names(&gwb);
    eprintln!("BASELINE links: gwA={base_a:?} gwB={base_b:?}");
    assert!(
        base_a.contains("wg0") && base_b.contains("wg0"),
        "SETUP FAILED: both gateways must have their base tun wg0 up at steady state; \
         gwA={base_a:?} gwB={base_b:?}"
    );

    // ===== Continuous ICMP flood across the pair, as in case 1 =====
    let flood = wla
        .spawn(&["ping", "-i", "0.2", "-q", "10.10.2.2"])
        .expect("spawn ping flood in wlA netns");

    // ===== Rotate BOTH gateways, back to back on one admin client =====
    // No await between the two beyond each RPC itself: the pending epochs must
    // be in flight simultaneously for the collision window to open.
    let mut admin = h.admin_client().await;
    admin
        .rotate_key(RotateKeyRequest { gateway_id: ga.id() })
        .await
        .expect("Admin.RotateKey for gwA");
    admin
        .rotate_key(RotateKeyRequest { gateway_id: gb.id() })
        .await
        .expect("Admin.RotateKey for gwB");
    eprintln!("Admin.RotateKey submitted for BOTH gwA and gwB (in step, epoch 0 -> 1 each)");

    // ===== Sample interfaces while both rotations run =====
    // One loop does double duty: it drives both gateways to completion AND
    // captures the transient overlap devices, which only exist while the
    // PEER's rotation is in flight. 250ms cadence against a window that lasts
    // seconds gives tens of samples.
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut peak_a = base_a.clone();
    let mut peak_b = base_b.clone();
    let (states_a, states_b) = loop {
        let now_a = link_names(&gwa);
        if now_a.difference(&base_a).count() > peak_a.difference(&base_a).count() {
            peak_a = now_a;
        }
        let now_b = link_names(&gwb);
        if now_b.difference(&base_b).count() > peak_b.difference(&base_b).count() {
            peak_b = now_b;
        }

        let sa = h.debug_key_states(ga.id()).await;
        let sb = h.debug_key_states(gb.id()).await;
        if (rotation_done(&sa) && rotation_done(&sb)) || Instant::now() >= deadline {
            break (sa, sb);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    let done_a = rotation_done(&states_a);
    let done_b = rotation_done(&states_b);

    let new_a: Vec<&String> = peak_a.difference(&base_a).collect();
    let new_b: Vec<&String> = peak_b.difference(&base_b).collect();
    eprintln!(
        "PEAK rotation devices: gwA +{:?} (all {peak_a:?}), gwB +{:?} (all {peak_b:?})",
        new_a, new_b
    );

    if !done_a || !done_b {
        dump_diag(
            "in-step-rotation-timeout",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        let _ = wla.exec(&["pkill", "-INT", "-x", "ping"]);
        if let Ok(o) = flood.wait_with_output() {
            eprintln!("--- ping flood output at timeout ---\n{}", String::from_utf8_lossy(&o.stdout));
        }
        pa.kill();
        pb.kill();
        panic!(
            "IN-STEP ROTATION TIMEOUT after 120s: gwA done={done_a} gwB done={done_b}. \
             Peak extra devices: gwA={new_a:?} gwB={new_b:?}. Last debug_key_states: \
             gwA={states_a:?} gwB={states_b:?}"
        );
    }
    eprintln!("BOTH ROTATIONS COMPLETE: gwA={states_a:?} gwB={states_b:?}");

    // ===== THE T3 ASSERTION: own-epoch tun AND overlap tun, on each side =====
    // Two extra devices per gateway at the peak — Role A's own new epoch tun
    // and Role B's overlap toward the rotating peer, live at the same instant
    // under the same epoch number. Before the fix both roles computed the same
    // ifname/key/port, `bring_up` bailed on the second, and the `?` inside the
    // peer loop discarded every remaining peer: the peak would be +1, not +2.
    for (name, peak, base, new) in [
        ("gwA", &peak_a, &base_a, &new_a),
        ("gwB", &peak_b, &base_b, &new_b),
    ] {
        if new.len() < 2 {
            dump_diag(
                "in-step-missing-rotation-tun",
                &[("gwA", &gwa), ("gwB", &gwb)],
                &[("gwA", &pa), ("gwB", &pb)],
            );
            let _ = wla.exec(&["pkill", "-INT", "-x", "ping"]);
            pa.kill();
            pb.kill();
            panic!(
                "IN-STEP COLLISION: {name} never had BOTH its own new-epoch tun (Role A) and an \
                 overlap tun toward the rotating peer (Role B) up at the same time. Peak extra \
                 devices over the steady-state baseline: {new:?} (peak={peak:?}, base={base:?}). \
                 Exactly one extra device means the two roles collided on the TunnelSet and the \
                 second bring_up bailed — the shipped fabric-wide outage (F3)."
            );
        }
        assert!(
            peak.contains("wg0"),
            "MAKE-BEFORE-BREAK: {name}'s base tun wg0 must still be up while both rotation tuns \
             exist; peak was {peak:?}"
        );
    }
    eprintln!(
        "T3 PASS: both gateways stood up their own new-epoch tun AND an overlap toward the \
         rotating peer at the same epoch number — four rotation devices across the pair, \
         alongside both base tuns."
    );

    // ===== Traffic kept flowing across BOTH cutovers =====
    let _ = wla.exec(&["pkill", "-INT", "-x", "ping"]);
    let flood_out = flood.wait_with_output().expect("wait for ping flood to exit after SIGINT");
    let flood_stdout = String::from_utf8_lossy(&flood_out.stdout).into_owned();
    eprintln!("--- ping flood summary ---\n{flood_stdout}");
    let (transmitted, received) = parse_ping_summary(&flood_stdout);
    // Same PER-ROTATION tolerance as `direct_rotation_is_zero_drop` (3 packets
    // = roughly one handshake RTT at `-i 0.2` under 20ms netem), applied twice
    // because two independent cutovers happen in this window. Deliberately not
    // a looser bar per cutover.
    assert!(
        received + 6 >= transmitted,
        "IN-STEP TRAFFIC FAILED: the ICMP flood lost more than two cutovers' worth of packets \
         (transmitted={transmitted}, received={received}, allowed gap=6 = 2 x the single-rotation \
         allowance)"
    );
    eprintln!(
        "TRAFFIC PASS: transmitted={transmitted} received={received} (gap {} <= 6)",
        transmitted.saturating_sub(received)
    );

    // ===== Both directions still work once both rotations have settled =====
    // Both sides rotated, so both directions are checked: a one-way check
    // could pass on a pair where only one gateway actually cut over.
    for (from, dst, label) in [(&wla, "10.10.2.2", "wlA -> wlB"), (&wlb, "10.10.1.2", "wlB -> wlA")] {
        if !wait_until(Duration::from_secs(20), || ping_ok(from, dst)) {
            dump_diag(
                "post-in-step-rotation",
                &[("gwA", &gwa), ("gwB", &gwb)],
                &[("gwA", &pa), ("gwB", &pb)],
            );
            pa.kill();
            pb.kill();
            panic!("POST-ROTATION FAILED: ICMP {label} no longer passes after BOTH gateways rotated in step");
        }
        eprintln!("POST-ROTATION PASS: ICMP still crosses {label} on the new epochs");
    }

    pa.kill();
    pb.kill();
    drop(lab);
    eprintln!("\nDONE-BAR PASSED: a whole-fabric in-step rotation — both gateways to epoch 1 at once — stands up every own-epoch and overlap tun without collision, and traffic survives both cutovers.");
}
