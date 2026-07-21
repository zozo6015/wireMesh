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
