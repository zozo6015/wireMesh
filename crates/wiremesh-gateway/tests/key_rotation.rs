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

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read as _, Write as _};
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use wiremesh_gateway::identity::Identity;
use wiremesh_gateway::tunnelset::OWN_TUN_PORT_OFFSET;
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
    /// Every stderr line containing `needle`, from the WHOLE log rather than
    /// [`stderr_tail`]'s last 4 KiB.
    ///
    /// The gateway subprocesses' stderr is drained to a file in a tempdir that
    /// dies with the test, so a decision the gateway logged once — early, and
    /// then buried under a rotation's worth of output — is invisible to anyone
    /// reading a run's console, pass or fail. Nothing asserts on the result:
    /// it exists so a GREEN run leaves behind the gateway's own statement of
    /// which branch it took, next to the device-state assertions that prove
    /// the effect.
    fn stderr_grep(&self, needle: &str) -> Vec<String> {
        std::fs::read_to_string(&self.err_log)
            .unwrap_or_default()
            .lines()
            .filter(|l| l.contains(needle))
            .map(str::to_string)
            .collect()
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
                .and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(|| panic!("could not parse transmitted count from: {line:?}"));
            let received: u64 = parts
                .get(1)
                .and_then(|s| s.split_whitespace().next())
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

/// Dumps each gateway's device, routing and socket state (plus its stderr
/// tail) to the test's stderr on a failure path. Purely diagnostic —
/// nothing asserts on any of it; it exists so a red run leaves behind
/// enough independent evidence to diagnose without a re-run.
///
/// `wg show all` rather than a hardcoded device list, because rotation
/// device names are DERIVED, not fixed (`tunnelset::plan_ifname`): an
/// own-epoch tun is `wg0e<epoch>`, unbounded in the epoch number, and an
/// overlap tun takes the first free slot `wg0o<0..MAX_ROTATION_TUNS>`. The
/// list this replaced was `wg0` + `wg0e1` only, which meant **`wg0o0` — the
/// Role-B overlap tun — was never dumped, and that is the device that can
/// hold the live session while the routes point at `wg0e1`** (measured
/// 2026-08-10, `docs/research/in-step-rotation-rebaselined.md`): the one
/// device carrying working traffic was the only one we had no device-level
/// evidence about, known solely from the gateway's own log line. `all`
/// enumerates whatever is actually in the namespace, so a second overlap
/// or a higher epoch cannot go missing the same way.
///
/// The three compact `wg show all <field>` views are one scannable line per
/// peer per device, which the full dump is not once four rotation devices
/// exist. `endpoints` is the field the in-step defect lives in (a peer
/// endpoint programmed to the wrong port, nondeterministically), and
/// `latest-handshakes` next to `transfer` makes a zeroed handshake
/// alongside nonzero counters — the unexplained `wg0` observation in that
/// same note — a two-line comparison instead of an accident. Note
/// `latest-handshakes` prints raw epoch seconds, so a zeroed timestamp
/// reads as a plain `0` rather than `wg show`'s humanized "56 years ago".
///
/// `ip -br link` alongside `-br addr` because a rotation tun can exist
/// without an address, and `ss -4 -lunp` because the port side is ground
/// truth the `wg` view cannot give: it shows which socket actually owns
/// each listen port, including the boringtun listeners known to leak
/// across a rebind (`docs/research/socket-leak-on-rebind.md`). `-4`
/// because v1 is IPv4-only and the unfiltered form prints both a
/// `0.0.0.0:` and a `*:` row per socket, doubling the output and making
/// the per-port counts ambiguous to read.
fn dump_diag(label: &str, gws: &[(&str, &Ns)], procs: &[(&str, &GwProc)]) {
    eprintln!("\n========== DIAGNOSTICS: {label} ==========");
    for (name, ns) in gws {
        for cmd in [
            vec!["wg", "show", "all"],
            vec!["wg", "show", "all", "endpoints"],
            vec!["wg", "show", "all", "latest-handshakes"],
            vec!["wg", "show", "all", "transfer"],
            vec!["ip", "-br", "link"],
            vec!["ip", "-br", "addr"],
            vec!["ip", "route"],
            vec!["ss", "-4", "-lunp"],
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
        .rotate_key(RotateKeyRequest {
            gateway_id: ga.id(),
        })
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
        .rotate_key(RotateKeyRequest {
            gateway_id: ga.id(),
        })
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
        .rotate_key(RotateKeyRequest {
            gateway_id: ga.id(),
        })
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
        .rotate_key(RotateKeyRequest {
            gateway_id: ga.id(),
        })
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
        panic!("old-epoch Device wg0 was not torn down after the rotation retired epoch 0");
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
    eprintln!(
        "POST-TEARDOWN PASS: ICMP and tcp/8080 both still work on wg0e1 after wg0 was torn down"
    );

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
    let bytes: Vec<u8> = s
        .bytes()
        .filter(|&c| c != b'=' && !c.is_ascii_whitespace())
        .collect();
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
    out.try_into()
        .expect("WG pubkey must decode to exactly 32 bytes")
}

/// Lowercase hex of a base64-encoded 32-byte WG pubkey (the UAPI wire form).
fn base64_pub_to_hex(b64: &str) -> String {
    base64_decode_32(b64)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
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
    resp.lines()
        .find_map(|l| l.strip_prefix(prefix.as_str()).map(str::to_string))
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
/// Choreography: case 1's direct-mesh setup + rotation, then TWO bounded
/// waits, because `service_retire`'s data-plane half and its key-scrub half
/// land at different times and only the first is observable as a link —
/// case 4's teardown wait (wg0 gone, wg0e1 present), then a wait until
/// epoch 0 is gone from `epoch_keys.json`, so both halves of the retire have
/// provably run before the crash (see the waits themselves). Then SIGKILL gwA's
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
        .rotate_key(RotateKeyRequest {
            gateway_id: ga.id(),
        })
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

    // ===== Wait for the retire to land BEFORE crashing — BOTH halves =====
    // `service_retire` (`main.rs`) is four ordered steps: (1) tear the old
    // epoch's Device down, (2) evict its enforcer, (3) renormalize the
    // surviving key's listen port, (4) `EpochKeys::retire` + `persist` — the
    // SCRUB, which removes the epoch's row from `epoch_keys.json`. Only step
    // 1 is observable as a link.
    //
    // So the teardown wait below (same bounded wait as
    // `old_epoch_device_is_torn_down_after_rotation`: the retire grace is a
    // handful of keepalives after every peer stays rx-corroborated live on
    // the new tun) proves the DATA-PLANE retire happened and
    // `service_retire` was entered. It does NOT prove the scrub ran — an
    // earlier revision of this comment claimed it did, and the ordering
    // above contradicts it. Step 3 awaits the `ctx.endpoint_commit` lock
    // inside `renormalize_active_listen_port` — a mutex shared with the
    // observe/punch commit path — so the gap between `wg0` disappearing and
    // the key leaving disk is bounded by lock contention, not by CPU. A
    // `pkill -KILL` inside that gap crashes a gateway whose epoch-0 row is
    // still present in state `"retiring"`, and the durable-retire assertion
    // (b) then fails for a reason that has nothing to do with durability.
    // Observed on a loaded CI runner: epoch 0 present, and ZERO
    // `CRITICAL: … retire …` lines — which is what "never ran" looks like,
    // since a scrub that runs and fails logs one. The scrub therefore gets
    // its own gate, immediately below.
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
    eprintln!("PRE-CRASH: teardown landed (gwA wg0 gone, wg0e1 present, live at offset port)");

    // ===== Wait for the KEY SCRUB (step 4) to land BEFORE crashing =====
    // `EpochKeys::retire` REMOVES the row (`epochkeys.rs`: removal, not a
    // state flip, is the scrub mechanism) and `persist` is an atomic
    // tmp+rename, so polling the file reads either the pre-scrub or the
    // post-scrub bytes and never a torn document; anything that is not
    // `Ok(Some(store))` is simply "not yet".
    //
    // 60s rather than the teardown's 30s: what is being waited out is
    // contention on `endpoint_commit`, which no CPU budget bounds — and the
    // wait costs nothing when the scrub is prompt, which it normally is
    // (sub-second after the teardown).
    //
    // The split between this gate and assertion (b), exactly: THIS GATE
    // requires epoch 0 to be scrubbed BEFORE the crash — it fails (as a setup
    // failure, naming step 4) if the scrub has not landed. ASSERTION (b)
    // verifies only that the scrubbed key is not RESURRECTED after the
    // restart, by raw byte-grep and through the reloaded store. Boot's legacy
    // migration re-seeds epoch 0 from `identity.json`/`wg_private.key` — the
    // same path assertion (a) is RED for — so "gone before the crash" and
    // "still gone after the restart" are genuinely different claims. The gate
    // establishes the first; (b) is left with only the second, which is the
    // half that was ever at risk across a crash.
    let mut last_load = String::new();
    let scrubbed = wait_until(Duration::from_secs(60), || {
        let loaded = wiremesh_gateway::epochkeys::EpochKeys::load(sda.path());
        last_load = format!("{loaded:?}");
        matches!(&loaded, Ok(Some(s)) if s.by_epoch(0).is_none())
    });
    if !scrubbed {
        dump_diag(
            "epoch-0-key-not-scrubbed-pre-crash",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "SETUP FAILED: gwA's epoch-0 key SCRUB (`service_retire` step 4 — \
             `EpochKeys::retire` + `persist`) never removed the epoch-0 entry from \
             epoch_keys.json within 60s of the teardown landing. Steps 1-3 ran (wg0 gone, \
             wg0e1 up), so crashing here would test the restart durability of a scrub that \
             never happened. Last load: {last_load}"
        );
    }
    eprintln!("PRE-CRASH: key scrub landed (epoch 0 gone from gwA's epoch_keys.json)");

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
    let mut pa = spawn_gw(
        &gwa,
        sda.path(),
        &sync_addr,
        &observe_addr,
        logdir.path(),
        "a-restart",
    );

    // ===== (a) THE RED ASSERTION: the restarted Device runs the NEW key =====
    // Boot is controller-independent (fail-static), so the base tun must
    // appear well inside 30s (the same bound style as the teardown wait).
    // Poll until wg0's UAPI socket answers at all, THEN judge the key once.
    let mut resp = None;
    let probe_ok = wait_until(Duration::from_secs(30), || {
        resp = uapi_get_device(&gwa, "wg0");
        resp.as_deref()
            .is_some_and(|r| uapi_field(r, "own_public_key").is_some())
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
    // The pre-crash gate REQUIRED epoch 0 to be scrubbed before the crash, so
    // this verifies only the other half: that the scrubbed key is not
    // RESURRECTED by the restart (boot's legacy migration re-seeds epoch 0
    // from `identity.json`/`wg_private.key` when no `active` entry exists).
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

/// Scrape `wiremesh_gateway_live_enforcers` from a gateway's Prometheus
/// endpoint, reachable from the root netns over the underlay bridge (same
/// route `mesh_milestone.rs`'s `scrape_deny` takes). `None` on any transport
/// failure or a missing series.
///
/// The gauge is the ONLY probe that can see a displaced enforcer. Holding a
/// `GatewayEnforcer` in the gateway's map is what keeps that tun's tc-BPF
/// program attached — the eBPF backend's TCX `bpf_link` attach releases on
/// drop, with no explicit unload (`wiremesh-enforcer/src/ebpf.rs:80-96`, pinned
/// by its `dropping_enforcer_detaches_and_allows_reprobe_on_same_iface`). So a
/// `HashMap::insert` that DISPLACES an entry leaves the tun perfectly up, with
/// routes and traffic, enforcing nothing: **fail-open**, and invisible to every
/// tun-shaped observation this file makes. A one-second budget (rather than
/// `scrape_deny`'s two) keeps a stalled endpoint from stretching a 250ms
/// sampling tick; a timed-out tick just yields `None` and the next tick
/// re-probes.
fn scrape_live_enforcers(addr: &str) -> Option<u64> {
    let sa: std::net::SocketAddr = addr.parse().ok()?;
    let mut s = std::net::TcpStream::connect_timeout(&sa, Duration::from_secs(1)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
    s.write_all(b"GET /metrics HTTP/1.0\r\n\r\n").ok()?;
    let mut buf = String::new();
    let _ = s.read_to_string(&mut buf);
    buf.lines()
        .find_map(|l| l.strip_prefix("wiremesh_gateway_live_enforcers "))
        .and_then(|v| v.trim().parse().ok())
}

/// What one gateway's sampling loop accumulates. See [`sample_tick`] for why
/// `paired_peak` is a single field rather than two independent maxima.
#[derive(Default)]
struct RotationObs {
    /// The FIRST tick at which this gateway satisfied BOTH probes *in the same
    /// tick*: two more interfaces than its steady-state baseline, and at least
    /// three live enforcers. This is the only field asserted on.
    paired_peak: Option<(BTreeSet<String>, u64)>,
    /// DIAGNOSTICS ONLY — never asserted on. Independent maxima exist so a
    /// failure can say WHICH axis fell short (no overlap tun at all, versus
    /// two tuns but a displaced enforcer) instead of just "never paired".
    /// Asserting on these would be exactly the mistake `paired_peak` avoids.
    max_extra_links: usize,
    max_enforcers: u64,
    last_links: BTreeSet<String>,
    last_enforcers: Option<u64>,
}

/// One tick's PAIRED observation of a gateway.
///
/// The two probes must be read together and judged together. Read
/// independently, a gateway that briefly had three interfaces and — at some
/// other, unrelated instant — briefly had three enforcers would satisfy both
/// maxima while never once having had a fully-armed overlap. Making
/// `paired_peak` the conjunction *inside a single call* makes that
/// impossible to express: the tuple can only be recorded by one invocation
/// that saw both at once. The two syscalls are still milliseconds apart
/// (an `ip -br link` exec, then a TCP scrape), which is three orders of
/// magnitude inside the seconds-long overlap window — but they are never
/// separately maximised across the run, which is the property that matters.
fn sample_tick(ns: &Ns, metrics_addr: &str, base: &BTreeSet<String>, obs: &mut RotationObs) {
    let links = link_names(ns);
    let enforcers = scrape_live_enforcers(metrics_addr);
    let extra = links.difference(base).count();

    obs.max_extra_links = obs.max_extra_links.max(extra);
    if let Some(n) = enforcers {
        obs.max_enforcers = obs.max_enforcers.max(n);
        // `>= 3` rather than `== 3`: three is the expected peak (base +
        // own-new + overlap) and a DISPLACEMENT shows up as 2, which this
        // catches. A hypothetical fourth entry is caught by the
        // settles-back-to-1 assertion instead, so there is no need to make
        // the peak brittle about an exact count.
        if obs.paired_peak.is_none() && extra >= 2 && n >= 3 {
            obs.paired_peak = Some((links.clone(), n));
        }
    }
    obs.last_links = links;
    obs.last_enforcers = enforcers;
}

/// **T3 DONE BAR — the scenario the shipped outage actually needs.**
///
/// **This is the in-step done bar, and it is GREEN.** It was committed
/// deliberately `#[ignore]`d as red-by-design from 2026-08-05 until
/// 2026-08-11, parked as the acceptance criterion for the endpoint work; that
/// work landed and the `#[ignore]` came off. It is not a smoke test and not
/// redundant with the other rotation cases in this file — read "What the fix
/// was" and "The two assertions that pin WHY it passed" below before changing
/// anything in it.
///
/// **`--features netns-tests` is mandatory.** Without it this whole file
/// compiles to zero tests and `cargo test` prints a green summary that proves
/// nothing. The full invocation is at the bottom of this comment.
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
/// # The T3 assertion, and the collision it would have caught
///
/// Each gateway must, at some instant during the rotation window, have TWO
/// MORE network interfaces than it had at steady state: its own new epoch tun
/// (Role A) *and* an overlap tun toward the rotating peer (Role B). Four
/// rotation devices across the pair, on top of the two base tuns.
///
/// Before the de-collision fix, both roles computed the same map key, the same
/// ifname and the same listen port; `TunnelSet::bring_up` bailed on the
/// duplicate and the `?` inside `for peer in &ds.peers` aborted the whole
/// Role-B loop, whose caller only logs. Neither side ever brought an overlap
/// up, so the peak would have been base + 1, not base + 2, on both gateways.
///
/// The probe is deliberately a COUNT of interfaces, not a set of names: the
/// test asks the kernel "how many devices are up", never "is `wg0e1` up", so
/// it holds for any de-collision scheme the implementer picks. Port
/// distinctness is NOT re-probed here — it is already pinned twice, purely in
/// `tests/tunnel_id_decollision.rs` and against real Devices in
/// `tests/tunnelset_same_epoch_netns.rs`. Sampling `wg show` at the peak would
/// add a race to this (serial, flake-sensitive) file for no new information.
///
/// # What the fix was, and why the red was structural rather than flaky
///
/// Writing this test was the first time anybody exercised an in-step
/// both-gateways rotation — the shape the controller's default 30-day timer
/// produces on every fabric. It found six bugs. Four were fixed as it was
/// written (the `TunnelSet` three-axis collision the T3 assertion above pins,
/// and the arbitration/route defects around it). The fifth — the second
/// rotation of any gateway could not complete, because `device_config_at_port`
/// and `pending_peer_configs` held two incompatible port models — was fixed by
/// v0.7.2's single port authority; its own done bar is
/// `second_rotation_of_same_gateway_keeps_traffic_flowing`, committed and not
/// ignored.
///
/// The sixth kept this test red, and it was a genuine **deadlock, not a timing
/// window**: after the Role-A cutover, nothing durable in the fabric could
/// address the active tun. Every durable endpoint source (observed candidate,
/// reported locals, punch candidates, `live_endpoints`) is base-port by
/// construction, while the freshly cut-over key listens on the reserved
/// own-tun port. One-sided rotation survives that because the base-port dial
/// is EVENTUALLY correct — the peer's retire is gated on *our overlap's*
/// session, which is live, so the peer renormalizes to base and the unchanged
/// dial starts working. In step, the peer's retire is gated on the very
/// epoch1 ↔ epoch1 session we cannot address, so both sides wait on each
/// other: measured at 90s with no recovery, both churning
/// direct/degraded/disconnected/connecting forever.
///
/// The fix (plan `docs/superpowers/plans/2026-08-11-in-step-rotation-fix.md`,
/// rebaselined evidence in `docs/research/in-step-rotation-rebaselined.md`) is
/// two gated additions on the Role-B collapse arm, both discriminated by
/// `built_at_own_epoch != active.epoch` — "our overlap and our active tun run
/// DIFFERENT private keys", which is false by construction in every one-sided
/// case, so neither addition can perturb them:
///
///  - **The rotation dial.** At the same moment the `wg0` pin is dropped, the
///    collapse arm writes the peer's reserved own-tun port (`candidate_port +
///    OWN_TUN_PORT_OFFSET` — where the peer's active key lives between its
///    cutover and its retire) into `live_endpoints`, so the very apply that
///    performs the rekey carries an endpoint that can reach it. All three
///    renderers read that one map, so they agree by construction.
///  - **A handshake kick on the active tun during the collapse.** Our first
///    init after the rekey is dropped if the peer has not rekeyed yet, and
///    boringtun's ~5s `REKEY_TIMEOUT` retry costs ~25 flood packets against a
///    ≤6 allowance. Nothing kicked the active tun during a collapse before, on
///    a rationale ("routes may still point at the overlap") that is false in
///    the in-step case, where our own cutover already won the routes.
///
/// ## What this test covers
///
/// The T3 assertion (four rotation devices across the pair, every one with its
/// enforcer attached — the fail-open displacement probe), the
/// traffic-during-overlap assertion (the ICMP flood loses at most two
/// cutovers' worth of packets), post-rotation reachability, and the two
/// mechanism blocks described next.
///
/// ## The two assertions that pin WHY it passed, not just that it did
///
/// **These two blocks are load-bearing. They read like belt-and-braces on top
/// of the ping and they are not.** Every assertion described above is an
/// OUTCOME — a device count, an enforcer gauge, a packet gap, a ping — and
/// each is satisfiable by a run in which the in-step fix never fired and the
/// pair converged some other way: traffic can cross on the base tun the whole
/// time while the epoch1 ↔ epoch1 session never comes up at all. The plan says
/// so outright: *"A green run still showing `:51820` passed for the wrong
/// reason."* Deleting either block as redundant would leave a test that goes
/// green on the exact deadlock it exists to catch. Neither relaxes anything
/// above them:
///
///  - **The mechanism** (after the traffic check): the Device holding each
///    gateway's own epoch-1 key must be observed DIALING the peer's reserved
///    own-tun port — `base + OWN_TUN_PORT_OFFSET`, derived from the constant,
///    never written out — and must complete a real handshake there. Before the
///    fix the first was measured wrong in every run and the second was `0` on
///    both gateways in every run. Devices are selected by the KEY THEY HOLD,
///    because during the collapse window the peer's epoch-1 pubkey sits on two
///    devices at once and the Role-B overlap's endpoint was ALREADY correct
///    pre-fix.
///  - **Post-settle reachability** (after the enforcer gauge returns to 1):
///    both sides must address each other where they actually listen, and ICMP
///    must still cross, once BOTH have retired epoch 0 and renormalized to the
///    base port. This is the only assertion that can detect the mutual pin the
///    plan names as its sharpest availability risk — both sides left pinned at
///    the other's now-dead reserved port. Its bound is deliberately under
///    `path::DEGRADED_AFTER` so a 45s degrade-and-recover cannot be certified
///    as a steady state.
///
/// ## What this test does NOT cover
///
/// Two honest gaps, both known and both deferred rather than overlooked:
///
///  - **The `replace_peers` cost is invisible here.** The collapse rekey
///    resets every peer's session, so on a fabric with N peers each rotation
///    costs N-1 innocent resets. This topology has exactly one peer, so no
///    assertion in this file can observe it. It is aggravating rather than
///    causal — scoping the rekey turns nothing green on its own — and is
///    deferred as Shape C in the plan, behind a multi-peer test.
///  - **The post-settle check does not FORCE its sharpest case.** The mutual
///    pin it exists to catch is most likely when both sides renormalize
///    near-simultaneously, and nothing in the harness makes that happen; the
///    check observes whatever interleaving the run produces. It asserts the
///    endpoints AND the ping precisely because the timing cannot be pinned.
///
/// ## Nothing here may be relaxed
///
/// This test is the acceptance criterion for the endpoint/port work and the
/// last blocker before the controller's rotation timer can be re-enabled
/// fabric-wide. No widened packet-loss tolerance, no dropped direction in the
/// both-ways reachability loop, no softened failure message, and above all no
/// deletion of the mechanism or post-settle blocks. If a change makes this go
/// red, the change is the suspect — but see the caution in `CLAUDE.md` about
/// this file's host-load sensitivity and run an interleaved A/B against the
/// parent commit before concluding anything from a single red run.
///
/// Run it (the feature flag is not optional):
/// `cargo test -p wiremesh-gateway --test key_rotation --features netns-tests \
///  -- --test-threads=1 --nocapture`
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn in_step_rotation_of_both_gateways_stands_up_own_and_overlap_tuns() {
    // Topology: IDENTICAL to `direct_rotation_is_zero_drop` — see that test
    // for the per-step rationale (bridge, netem, veths, identities).
    setup_bridge();
    let _root_guard = RootNetGuard;

    let h = TestController::start_on(CTRL_IP.parse().unwrap()).await;

    let diff = h.apply(FABRIC_ICMP).await;
    assert!(
        diff.policy_updated,
        "fabric apply must compile a real policy, got: {diff:?}"
    );

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

    let sda = tempfile::tempdir().unwrap();
    let sdb = tempfile::tempdir().unwrap();
    write_identity(&ga, &a_priv, sda.path());
    write_identity(&gb, &b_priv, sdb.path());
    let logdir = tempfile::tempdir().unwrap();

    let sync_addr = h.sync_tcp_addr().to_string();
    let observe_addr = h.observe_addr().to_string();
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

    // Each gateway's Prometheus endpoint, addressed over the underlay bridge
    // from the root netns (the gateways bind `0.0.0.0:METRICS_PORT`) — the
    // same route `mesh_milestone.rs` scrapes `10.9.0.2:9099` by.
    let metrics_a = format!("10.9.0.1:{METRICS_PORT}");
    let metrics_b = format!("10.9.0.2:{METRICS_PORT}");
    let base_enf_a = scrape_live_enforcers(&metrics_a);
    let base_enf_b = scrape_live_enforcers(&metrics_b);
    eprintln!("BASELINE live_enforcers: gwA={base_enf_a:?} gwB={base_enf_b:?}");
    assert!(
        base_enf_a == Some(1) && base_enf_b == Some(1),
        "SETUP FAILED: at steady state each gateway must report exactly one live enforcer (the \
         base tun's); got gwA={base_enf_a:?} gwB={base_enf_b:?}. A `None` means the \
         `wiremesh_gateway_live_enforcers` series never reached the scrape body, which would \
         make every enforcer assertion below vacuous."
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
        .rotate_key(RotateKeyRequest {
            gateway_id: ga.id(),
        })
        .await
        .expect("Admin.RotateKey for gwA");
    admin
        .rotate_key(RotateKeyRequest {
            gateway_id: gb.id(),
        })
        .await
        .expect("Admin.RotateKey for gwB");
    eprintln!("Admin.RotateKey submitted for BOTH gwA and gwB (in step, epoch 0 -> 1 each)");

    // ===== Sample interfaces AND the enforcer gauge while both rotations run =====
    // One loop does triple duty: it drives both gateways to completion, and
    // per tick takes ONE PAIRED reading per gateway (`sample_tick`) of the
    // interfaces present and the live-enforcer gauge. The transient overlap
    // devices only exist while the PEER's rotation is in flight, so this is
    // the only window in which either probe means anything. 250ms cadence
    // against a window that lasts seconds gives tens of samples.
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut obs_a = RotationObs::default();
    let mut obs_b = RotationObs::default();
    let (states_a, states_b) = loop {
        sample_tick(&gwa, &metrics_a, &base_a, &mut obs_a);
        sample_tick(&gwb, &metrics_b, &base_b, &mut obs_b);

        let sa = h.debug_key_states(ga.id()).await;
        let sb = h.debug_key_states(gb.id()).await;
        if (rotation_done(&sa) && rotation_done(&sb)) || Instant::now() >= deadline {
            break (sa, sb);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    let done_a = rotation_done(&states_a);
    let done_b = rotation_done(&states_b);

    eprintln!(
        "SAMPLING SUMMARY: gwA paired_peak={:?} max_extra_links={} max_enforcers={} | \
         gwB paired_peak={:?} max_extra_links={} max_enforcers={}",
        obs_a.paired_peak,
        obs_a.max_extra_links,
        obs_a.max_enforcers,
        obs_b.paired_peak,
        obs_b.max_extra_links,
        obs_b.max_enforcers,
    );

    if !done_a || !done_b {
        dump_diag(
            "in-step-rotation-timeout",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        let _ = wla.exec(&["pkill", "-INT", "-x", "ping"]);
        if let Ok(o) = flood.wait_with_output() {
            eprintln!(
                "--- ping flood output at timeout ---\n{}",
                String::from_utf8_lossy(&o.stdout)
            );
        }
        pa.kill();
        pb.kill();
        panic!(
            "IN-STEP ROTATION TIMEOUT after 120s: gwA done={done_a} gwB done={done_b}. \
             Last debug_key_states: gwA={states_a:?} gwB={states_b:?}"
        );
    }
    eprintln!("BOTH ROTATIONS COMPLETE: gwA={states_a:?} gwB={states_b:?}");

    // ===== THE T3 ASSERTION: own-epoch tun AND overlap tun, BOTH ARMED =====
    // At one instant, each gateway must have had two more devices than its
    // steady-state baseline — Role A's own new epoch tun and Role B's overlap
    // toward the rotating peer, live at the same time under the same epoch
    // number — AND at least three live enforcers, so neither of those tuns is
    // running with its policy hook displaced.
    //
    // Before the de-collision fix both roles computed the same ifname/key/port,
    // `bring_up` bailed on the second, and the `?` inside the peer loop
    // discarded every remaining peer: the peak would be +1 device, not +2.
    // With the tuns de-collided but the enforcer map still keyed by a bare
    // `u32` epoch, the devices would appear but one `HashMap::insert` would
    // displace the other's enforcer — two extra tuns, only two enforcers, one
    // of them carrying traffic with nothing attached.
    for (name, obs, base) in [("gwA", &obs_a, &base_a), ("gwB", &obs_b, &base_b)] {
        let Some((peak_links, peak_enf)) = &obs.paired_peak else {
            dump_diag(
                "in-step-never-fully-armed",
                &[("gwA", &gwa), ("gwB", &gwb)],
                &[("gwA", &pa), ("gwB", &pb)],
            );
            let _ = wla.exec(&["pkill", "-INT", "-x", "ping"]);
            pa.kill();
            pb.kill();
            panic!(
                "IN-STEP COLLISION: {name} never had, AT THE SAME INSTANT, both rotation tuns up \
                 and all three enforcers attached. Best seen independently (diagnostics only, \
                 never paired): max_extra_links={} (need 2 — one short means the two roles \
                 collided on the TunnelSet and the second bring_up bailed, the shipped \
                 fabric-wide outage F3), max_enforcers={} (need 3 — one short with 2 extra links \
                 means an enforcer was DISPLACED out of the map and its tun is running \
                 fail-open). Last links={:?}, last gauge={:?}, baseline={base:?}",
                obs.max_extra_links, obs.max_enforcers, obs.last_links, obs.last_enforcers,
            );
        };
        assert!(
            peak_links.contains("wg0"),
            "MAKE-BEFORE-BREAK: {name}'s base tun wg0 must still be up at the paired peak \
             (links={peak_links:?}, enforcers={peak_enf})"
        );
    }
    eprintln!(
        "T3 PASS: both gateways stood up their own new-epoch tun AND an overlap toward the \
         rotating peer at the same epoch number — four rotation devices across the pair, \
         alongside both base tuns, every one of them with its enforcer still attached."
    );

    // ===== Traffic kept flowing across BOTH cutovers =====
    let _ = wla.exec(&["pkill", "-INT", "-x", "ping"]);
    let flood_out = flood
        .wait_with_output()
        .expect("wait for ping flood to exit after SIGINT");
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

    // ===== THE MECHANISM: an epoch1 <-> epoch1 session, on the device =====
    //
    // Everything above this point is an OUTCOME, and every one of those
    // outcomes is satisfiable by a run in which the in-step fix never fired.
    // The device counts, the enforcer gauge and the packet gap are all
    // measured DURING the rotation, before the Role-B collapse; the pings
    // below are measured after it, by which time a base-port endpoint can have
    // become correct anyway (one gateway retiring moves its active key back to
    // the base port, which is exactly how the one-sided cases converge). So a
    // pair that deadlocked and then got lucky, and a pair that worked for the
    // designed reason, are indistinguishable to every assertion this test had.
    //
    // What is NOT satisfiable any other way is the pair of facts below, and
    // they are the fix stated as device state:
    //
    //  1. our own new-epoch tun DIALED the peer's reserved own-tun port, and
    //  2. a session actually FORMED there.
    //
    // Before the fix (1) was measured wrong in every run — `:51820` twice and
    // `:51822` once, never the correct port — and (2) was `0`, never a
    // handshake, on both gateways in every run
    // (`docs/research/in-step-rotation-rebaselined.md`). The two are asserted
    // separately because they fail for different reasons and mean different
    // things.
    //
    // Sampled across a window rather than read once: the correct endpoint is
    // live from the collapse arm until both sides retire and roam back to the
    // base port, and the retire is gated on this very session having been live
    // for a full `RETIRE_GRACE` (6s), so the window is comfortably wide — but
    // it is a window, and "was it ever right" is the honest question.
    // must match `spawn_gw`'s `--wg-port`
    const BASE_WG_PORT: u16 = 51820;
    // The peer's active key lives at `base + OWN_TUN_PORT_OFFSET` between its
    // cutover and its retire — a RESERVED port, derived from the constant that
    // reserves it rather than written as `51821`, so a change to the
    // reservation moves the test with the code instead of silently past it.
    let own_tun_port = BASE_WG_PORT + OWN_TUN_PORT_OFFSET;

    let a_e1_b64 = poll_epoch_pubkey(&h, ga.id(), 1, Duration::from_secs(10)).await;
    let b_e1_b64 = poll_epoch_pubkey(&h, gb.id(), 1, Duration::from_secs(10)).await;
    let (Some(a_e1_b64), Some(b_e1_b64)) = (a_e1_b64, b_e1_b64) else {
        dump_diag(
            "in-step-epoch1-pubkey-unresolved",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "MECHANISM UNCHECKABLE: both rotations reported complete, yet the controller never \
             produced a real epoch-1 pubkey for one or both gateways (still the \
             `{AWAITING_SUBMISSION}` sentinel, or absent). Every assertion below identifies \
             devices BY KEY, so without both keys the mechanism cannot be read at all — this is \
             a harness/controller failure, not the in-step defect."
        );
    };
    let a_e1_hex = base64_pub_to_hex(&a_e1_b64);
    let b_e1_hex = base64_pub_to_hex(&b_e1_b64);
    // gwA's underlay address is 10.9.0.1 and gwB's is 10.9.0.2 (`attach_underlay`
    // above), so each side's target is the OTHER's IP at the reserved port.
    let want_a = format!("10.9.0.2:{own_tun_port}");
    let want_b = format!("10.9.0.1:{own_tun_port}");

    let mut mech_a = MechObs::default();
    let mut mech_b = MechObs::default();
    let mech_seen = wait_until(Duration::from_secs(45), || {
        sample_mech(&gwa, &a_e1_hex, &b_e1_hex, &b_e1_b64, &mut mech_a);
        sample_mech(&gwb, &b_e1_hex, &a_e1_hex, &a_e1_b64, &mut mech_b);
        mech_a.saw(&want_a) && mech_b.saw(&want_b)
    });
    eprintln!(
        "MECHANISM SAMPLING (both sides satisfied: {mech_seen}):\n  gwA {}\n  gwB {}",
        mech_a.summary(),
        mech_b.summary(),
    );

    // Asserted on BOTH gateways: the mechanism is symmetric, and a one-sided
    // check would pass a half-working fix in which only one side's own-epoch
    // tun ever became addressable — which is precisely the shape that
    // deadlocks, since each side's retire is gated on the OTHER's session.
    for (name, mech, want, peer_name) in [
        ("gwA", &mech_a, &want_a, "gwB"),
        ("gwB", &mech_b, &want_b, "gwA"),
    ] {
        if mech.own_epoch_ifnames.is_empty() {
            dump_diag(
                "in-step-own-epoch-device-not-found",
                &[("gwA", &gwa), ("gwB", &gwb)],
                &[("gwA", &pa), ("gwB", &pb)],
            );
            pa.kill();
            pb.kill();
            panic!(
                "MECHANISM UNCHECKABLE on {name}: no Device holding {name}'s epoch-1 private key \
                 was seen at any point in a 45s window, although the controller reports epoch 1 \
                 active. Every assertion below is about that Device, so this makes them vacuous \
                 rather than green. Either the cutover never created it, or it was torn down \
                 before the window opened.\n{}\nDevices last seen on {name}:\n{}",
                mech.summary(),
                fmt_snaps(&mech.devs),
            );
        }
        if !mech.dialed(want) {
            dump_diag(
                "in-step-collapse-dial-never-fired",
                &[("gwA", &gwa), ("gwB", &gwb)],
                &[("gwA", &pa), ("gwB", &pb)],
            );
            pa.kill();
            pb.kill();
            panic!(
                "COLLAPSE DIAL NEVER FIRED on {name}: its own new-epoch tun was never observed \
                 dialing {peer_name}'s new epoch at {want} — the port {peer_name}'s active key is \
                 RESERVED on (base {BASE_WG_PORT} + OWN_TUN_PORT_OFFSET {OWN_TUN_PORT_OFFSET}) \
                 between its cutover and its retire.\n\
                 WHAT THIS MEANS: an endpoint of `:{BASE_WG_PORT}` (or any other port) is the \
                 pre-fix shape verbatim — the peer-entry rebuild that the Role-B collapse unpin \
                 forces inherited a base-port endpoint from `live_endpoints`/the candidate list, \
                 neither of which can ever produce the reserved port. Nothing else in this test \
                 distinguishes that from a working fix, so if the rest of the run is green it \
                 passed BY LUCK OR TIMING, not because the epoch1 <-> epoch1 session was \
                 addressable. See docs/research/in-step-rotation-rebaselined.md and the tier-3 \
                 note in docs/superpowers/plans/2026-08-11-in-step-rotation-fix.md.\n{}\n\
                 Devices last seen on {name}:\n{}",
                mech.summary(),
                fmt_snaps(&mech.devs),
            );
        }
        if mech.own_epoch_handshake == 0 {
            dump_diag(
                "in-step-own-epoch-tun-never-handshaked",
                &[("gwA", &gwa), ("gwB", &gwb)],
                &[("gwA", &pa), ("gwB", &pb)],
            );
            pa.kill();
            pb.kill();
            panic!(
                "OWN-EPOCH TUN NEVER HANDSHAKED on {name}: its Device for epoch 1 dialed \
                 {peer_name}'s reserved port, but `wg`'s latest-handshake for that peer stayed \
                 0 — a zeroed timestamp, i.e. no session EVER formed there.\n\
                 WHAT THIS MEANS: this is the strongest single signal in the test, and before the \
                 fix it was 0 on both gateways in every measured run. The endpoint being right is \
                 necessary, not sufficient: both the Role-B collapse gate and the peer's Role-A \
                 retire gate wait on an epoch1 <-> epoch1 session, so a zero here means both gates \
                 are still parked and any traffic that passed did so over the BASE tun, which is \
                 about to retire. A green ping alongside this zero is a fabric that is working \
                 only until the grace expires.\n{}\nDevices last seen on {name}:\n{}",
                mech.summary(),
                fmt_snaps(&mech.devs),
            );
        }
    }
    eprintln!(
        "MECHANISM PASS: both gateways' own new-epoch tuns dialed the peer's RESERVED own-tun \
         port {own_tun_port} (base {BASE_WG_PORT} + OWN_TUN_PORT_OFFSET {OWN_TUN_PORT_OFFSET}) \
         and completed a real handshake there — the epoch1 <-> epoch1 session both collapse/retire \
         gates wait on came up, which is the reason this test is allowed to be green."
    );
    // The gateway's own account of the decision, next to the device evidence
    // of its effect: the collapse-dial line logs both predicate inputs
    // (`own_active_epoch`, `built_at_own_epoch`) and the resulting endpoint on
    // BOTH branches. Printed, never asserted — it is what settles open
    // question 2 of the plan (whether the gating predicate actually held in
    // the in-step case) for a human reading a green run.
    for (name, p) in [("gwA", &pa), ("gwB", &pb)] {
        for line in p.stderr_grep("collapse dial") {
            eprintln!("GATEWAY LOG {name}: {line}");
        }
    }

    // ===== Both directions still work once both rotations have settled =====
    // Both sides rotated, so both directions are checked: a one-way check
    // could pass on a pair where only one gateway actually cut over.
    for (from, dst, label) in [
        (&wla, "10.10.2.2", "wlA -> wlB"),
        (&wlb, "10.10.1.2", "wlB -> wlA"),
    ] {
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

    // ===== The gauge must track BACK DOWN to one =====
    // A peak assertion alone is satisfied by a gauge that only ever rises, and
    // "rises and never falls" is precisely the leak shape: an overlap Device,
    // its enforcer entry, its routes and its `wg0_pins` entry surviving the
    // rotation they belonged to (finding F9 — real, and out of scope for T3,
    // which is exactly why it needs a guard rather than an assumption).
    //
    // Once both rotations have fully settled each gateway must be back to a
    // single tun and a single enforcer: the Role-B overlap collapsed after the
    // peer promoted, and the old epoch-0 Device retired.
    //
    // Budget: the gateway's own retire fires `RETIRE_GRACE` — `2 *
    // ROTATION_KEEPALIVE`, i.e. SIX seconds (`main.rs:351`), not the
    // controller's 30s `RETIRE_GRACE` — after its cutover, gated on every peer
    // staying rx-corroborated live on the new tun for that whole grace. The
    // Role-B collapse additionally waits for a live base-tun session toward
    // the peer's new key. `rotation_survives_gateway_restart_on_new_epoch`
    // already waits for exactly this teardown on a 30s bound and is
    // comfortable; 45s adds headroom for the second gateway doing it at the
    // same time.
    let settle_deadline = Instant::now() + Duration::from_secs(45);
    let (settled_a, settled_b) = loop {
        let a = scrape_live_enforcers(&metrics_a);
        let b = scrape_live_enforcers(&metrics_b);
        if (a == Some(1) && b == Some(1)) || Instant::now() >= settle_deadline {
            break (a, b);
        }
        std::thread::sleep(Duration::from_secs(1));
    };
    if settled_a != Some(1) || settled_b != Some(1) {
        // Capture the interface sets BEFORE killing the gateways — the tun
        // devices go away with the processes, so a post-kill sample would
        // report an empty-looking gateway and hide which state leaked.
        let links_a = link_names(&gwa);
        let links_b = link_names(&gwb);
        dump_diag(
            "in-step-enforcers-did-not-settle",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "LEAKED ROTATION STATE: 45s after both in-step rotations completed the live-enforcer \
             gauge has not returned to 1 — gwA={settled_a:?} gwB={settled_b:?} (links: \
             gwA={links_a:?} gwB={links_b:?}). Above 1 means an overlap or old-epoch enforcer \
             outlived the rotation it belonged to (the F9 leak shape); below 1, or absent, means \
             one was displaced or the exporter died."
        );
    }
    eprintln!("SETTLE PASS: both gateways back to exactly one live enforcer after the overlap collapse and the epoch-0 retire");

    // ===== POST-SETTLE REACHABILITY: the steady state, not the transient =====
    //
    // Everything above stops measuring before the last thing that moves. The
    // reachability pings ran BEFORE this settle, i.e. while each side's active
    // key was still on its offset port and each side's endpoint still pointed
    // there. The settle gate that follows them checks an enforcer COUNT — that
    // the transient state was reclaimed — and says nothing about whether the
    // fabric can still carry a packet afterwards.
    //
    // The gap between those two is a real and specific failure, named in the
    // plan's risk section as its sharpest unmeasured claim: after BOTH sides
    // retire, `renormalize_active_listen_port` moves each active key back to
    // the base port, and each side may be left pinned at the OTHER's now-dead
    // reserved port while both listen on base — a mutual black hole. Neither
    // side can correct it, because an endpoint is only corrected by RECEIVING
    // an authenticated packet and neither side can send one. The design's
    // mitigation is that the renormalize pokes every peer, and the first side
    // to renormalize pokes while the other is still on the reserved port; the
    // residual risk is that poke being lost with near-simultaneous
    // renormalizations. This block is the only assertion in the test that can
    // detect any of that — without it the done bar can go green on a fabric
    // that is unreachable in steady state, which is the exact failure the fix
    // exists to prevent, merely relocated past the last assertion.
    //
    // # What is deterministic here and what is not
    //
    // The ENDPOINT assertion is checkable without racing anything: it reads
    // where each side's surviving Device listens and where it dials, and both
    // are settled facts once the retires have run (which the enforcer gate
    // above has already established). It is the part that names the failure.
    //
    // The TIMING is not forced. This test cannot make the two renormalizations
    // near-simultaneous — they are driven by each gateway's own `RETIRE_GRACE`
    // off its own cutover, and there is no seam to align them from here — so
    // whether the dangerous interleaving is exercised at all is left to chance
    // on any given run. What IS pinned is that if it happens, this fails.
    //
    // The bound is therefore load-bearing and deliberately SHORT. Endpoint
    // correction after a landed poke is one round trip; the recovery path if
    // the poke is lost is `path::DEGRADED_AFTER` (45s) followed by a candidate
    // chase. A bound at or above 45s would certify degrade-and-recover as
    // steady state and this assertion would detect nothing. 20s is far past
    // the poke and far short of the degrade.
    const POST_SETTLE_CONVERGE: Duration = Duration::from_secs(20);
    let mut post_a: Vec<DevSnap> = Vec::new();
    let mut post_b: Vec<DevSnap> = Vec::new();
    let want_base_a = format!("10.9.0.2:{BASE_WG_PORT}");
    let want_base_b = format!("10.9.0.1:{BASE_WG_PORT}");
    let converged = wait_until(POST_SETTLE_CONVERGE, || {
        post_a = uapi_dump_all(&gwa);
        post_b = uapi_dump_all(&gwb);
        let (_, la, ea) = settled_view(&post_a, &a_e1_hex, &b_e1_hex);
        let (_, lb, eb) = settled_view(&post_b, &b_e1_hex, &a_e1_hex);
        la == Some(BASE_WG_PORT)
            && lb == Some(BASE_WG_PORT)
            && ea.as_deref() == Some(want_base_a.as_str())
            && eb.as_deref() == Some(want_base_b.as_str())
    });
    let (if_a, listen_a, ep_a) = settled_view(&post_a, &a_e1_hex, &b_e1_hex);
    let (if_b, listen_b, ep_b) = settled_view(&post_b, &b_e1_hex, &a_e1_hex);
    if !converged {
        dump_diag(
            "in-step-post-settle-endpoints-never-converged",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "POST-SETTLE BLACK HOLE: {POST_SETTLE_CONVERGE:?} after both in-step rotations \
             retired, the two gateways do not address each other where they actually listen.\n\
             \x20 gwA: Device {if_a:?} listens on {listen_a:?}, dials gwB's epoch-1 key at \
             {ep_a:?} (required: listens {BASE_WG_PORT}, dials {want_base_a})\n\
             \x20 gwB: Device {if_b:?} listens on {listen_b:?}, dials gwA's epoch-1 key at \
             {ep_b:?} (required: listens {BASE_WG_PORT}, dials {want_base_b})\n\
             WHAT THIS MEANS: both sides renormalized their active key back to the base port, so \
             the reserved port {own_tun_port} is DEAD on both. A side still pinned there is \
             sending into nothing, and cannot be corrected — endpoint roaming needs an inbound \
             authenticated packet and the peer is in the same state. This is the mutual pin the \
             plan names as its sharpest availability risk: the renormalize's poke to the peer was \
             lost, or the two renormalizations landed too close together for either poke to reach \
             a live socket. Recovery, if any, is {:?} of degrade followed by a candidate chase — \
             which is an outage, not a steady state, and is why this bound is deliberately below \
             it.\n\
             gwA devices:\n{}gwB devices:\n{}",
            wiremesh_gateway::path::DEGRADED_AFTER,
            fmt_snaps(&post_a),
            fmt_snaps(&post_b),
        );
    }
    eprintln!(
        "POST-SETTLE ENDPOINTS PASS: gwA {if_a:?} and gwB {if_b:?} both listen on \
         {BASE_WG_PORT} and dial each other there ({ep_a:?} / {ep_b:?}) — the reserved port \
         {own_tun_port} is dead on both sides and neither is still pinned to it."
    );

    // And the packet that proves it, both ways. The endpoints above are the
    // diagnosis; this is the product claim. It is bounded well under
    // `DEGRADED_AFTER` for the same reason, and separately from the endpoint
    // check so that a failure HERE — correct endpoints, no traffic — reads as
    // what it would be: routes, policy or the enforcer, not the rotation
    // endpoint model.
    for (from, dst, label) in [
        (&wla, "10.10.2.2", "wlA -> wlB"),
        (&wlb, "10.10.1.2", "wlB -> wlA"),
    ] {
        if !wait_until(Duration::from_secs(15), || ping_ok(from, dst)) {
            dump_diag(
                "post-settle-unreachable",
                &[("gwA", &gwa), ("gwB", &gwb)],
                &[("gwA", &pa), ("gwB", &pb)],
            );
            pa.kill();
            pb.kill();
            panic!(
                "POST-SETTLE UNREACHABLE: ICMP {label} does not pass in the SETTLED steady state \
                 — after both gateways retired epoch 0 and moved their active keys back to the \
                 base port. The earlier POST-ROTATION check passed, so this is not the cutover: \
                 something the retire/renormalize did took the fabric down after the last \
                 assertion the done bar used to have. Both sides' endpoints checked out \
                 immediately above (gwA {ep_a:?}, gwB {ep_b:?}), so look at routes, policy \
                 reprogramming or the surviving enforcer rather than at the endpoint model."
            );
        }
        eprintln!("POST-SETTLE PASS: ICMP still crosses {label} in the settled steady state");
    }

    pa.kill();
    pb.kill();
    drop(lab);
    eprintln!("\nDONE-BAR PASSED: a whole-fabric in-step rotation — both gateways to epoch 1 at once — stands up every own-epoch and overlap tun without collision, every one of them armed with its own enforcer, traffic survives both cutovers, and all the transient state is reclaimed.");
}

// --- rotate-twice (bug 5): the port-authority probes -------------------------

/// The controller's placeholder pubkey for a freshly-minted epoch, before the
/// gateway has submitted its real one over `Sync.SubmitEpochKey`
/// (`db.rs`'s `AWAITING_SUBMISSION_SENTINEL`, duplicated here because it is
/// `pub(crate)`). Every port probe below keys off the epoch's REAL pubkey, so
/// they must not start looking until the sentinel is gone.
const AWAITING_SUBMISSION: &str = "awaiting-submission";

/// One WireGuard Device's `get=1` state, reduced to exactly what the
/// port-authority question needs: what this Device LISTENS on, whose key it
/// holds, and — per peer — which key that peer entry is for and where it
/// DIALS that peer.
///
/// This is deliberately a *Device*-level view rather than
/// `uapi::parse_get_response`'s peer map: the whole point of the rotate-twice
/// case is that a gateway can hold several Devices at once (base tun, own
/// new-epoch tun, overlap tuns) and the question is which of THOSE the peer's
/// configured endpoint actually points at.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord)]
struct DevSnap {
    ifname: String,
    listen_port: Option<u16>,
    /// boringtun 0.6.0 reports the device's own identity as a non-standard
    /// `own_public_key=<hex>` line (Task-6 divergence, see `uapi_get_device`).
    own_pub_hex: Option<String>,
    /// `(peer public key hex, configured endpoint)` in wire order.
    peers: Vec<(String, Option<String>)>,
}

/// Splits one `get=1` response into a [`DevSnap`]. Device-level fields are the
/// ones that appear BEFORE the first `public_key=` line (boringtun emits the
/// device header first) — the `peers.is_empty()` guards below encode exactly
/// that, so a peer's own `endpoint=`/port fields can never be mistaken for the
/// device's.
fn parse_dev_snap(ifname: &str, resp: &str) -> DevSnap {
    let mut d = DevSnap {
        ifname: ifname.to_string(),
        ..Default::default()
    };
    for line in resp.lines() {
        if let Some(hex) = line.strip_prefix("public_key=") {
            d.peers.push((hex.to_string(), None));
        } else if let Some(v) = line.strip_prefix("endpoint=") {
            if let Some(last) = d.peers.last_mut() {
                last.1 = Some(v.to_string());
            }
        } else if let Some(v) = line.strip_prefix("listen_port=") {
            if d.peers.is_empty() {
                d.listen_port = v.parse().ok();
            }
        } else if let Some(v) = line.strip_prefix("own_public_key=") {
            if d.peers.is_empty() {
                d.own_pub_hex = Some(v.to_string());
            }
        }
    }
    d
}

/// One python3 invocation that `get=1`s EVERY live UAPI socket in `ns`.
///
/// Deliberately not a loop of [`uapi_get_device`] calls: the sampling loop
/// below runs on a 500ms tick against a gateway that can hold four Devices,
/// and one `nsenter` + interpreter start per Device per tick would cost more
/// than the window being sampled. Sockets that refuse a connection (a Device
/// torn down between the glob and the connect) are skipped, not fatal.
const UAPI_DUMP_ALL_PY: &str = r#"
import socket, glob, os, sys
for p in sorted(glob.glob("/var/run/wireguard/*.sock")):
    name = os.path.basename(p)[:-5]
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(p)
        s.sendall(b"get=1\n\n")
        buf = b""
        while b"\n\n" not in buf:
            d = s.recv(4096)
            if not d:
                break
            buf += d
        s.close()
    except Exception:
        continue
    sys.stdout.write("===DEV %s\n" % name)
    sys.stdout.write(buf.decode())
"#;

/// Every WireGuard Device currently answering UAPI in `ns`, sorted by ifname.
/// An empty vec on any harness failure — callers run this inside a sampling
/// loop where a dropped sample must not abort the run (and, as with
/// `link_names`, a dropped sample can only ever make the assertions harder to
/// satisfy, never easier).
fn uapi_dump_all(ns: &Ns) -> Vec<DevSnap> {
    require_python3(ns);
    let Ok(out) = ns.exec(&["python3", "-c", UAPI_DUMP_ALL_PY]) else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut snaps: Vec<DevSnap> = text
        .split("===DEV ")
        .skip(1)
        .filter_map(|chunk| {
            let (name, body) = chunk.split_once('\n')?;
            let name = name.trim();
            if name.is_empty() {
                return None;
            }
            Some(parse_dev_snap(name, body))
        })
        .collect();
    snaps.sort();
    snaps
}

/// First 12 hex chars of a key — enough to identify it in a dump, short enough
/// that a multi-device diagnostic stays readable.
fn short_key(hex: &str) -> String {
    hex.chars().take(12).collect()
}

fn fmt_snaps(snaps: &[DevSnap]) -> String {
    if snaps.is_empty() {
        return "  (no UAPI devices answered)\n".to_string();
    }
    let mut s = String::new();
    for d in snaps {
        s.push_str(&format!(
            "  {} listen_port={} own_pub={}\n",
            d.ifname,
            d.listen_port
                .map(|p| p.to_string())
                .unwrap_or_else(|| "?".into()),
            d.own_pub_hex
                .as_deref()
                .map(short_key)
                .unwrap_or_else(|| "?".into()),
        ));
        for (k, ep) in &d.peers {
            s.push_str(&format!(
                "      peer {} endpoint={}\n",
                short_key(k),
                ep.as_deref().unwrap_or("(none)"),
            ));
        }
    }
    s
}

/// Port half of an `ip:port` UAPI endpoint value.
fn endpoint_port(ep: &str) -> Option<u16> {
    ep.rsplit_once(':').and_then(|(_, p)| p.parse().ok())
}

// --- in-step done bar: WHY it passed, read off the devices --------------------
//
// The helpers below exist for
// `in_step_rotation_of_both_gateways_stands_up_own_and_overlap_tuns` and are
// sited here, after the `DevSnap`/`uapi_dump_all` toolkit, because they are
// extensions of it rather than of anything near that test.
//
// They exist because that test can PASS FOR THE WRONG REASON. Everything it
// asserted before them is an OUTCOME — device counts, an enforcer gauge, a
// packet gap, a ping. Each of those is satisfiable by a run in which the
// collapse dial never fired and the pair converged some other way (or by luck
// of timing), and the plan says so in as many words: *"A green run still
// showing `:51820` passed for the wrong reason."*
// (`docs/superpowers/plans/2026-08-11-in-step-rotation-fix.md`, test strategy
// tier 3.) These read the MECHANISM off the devices instead.

/// `(ifname, peer base64 pubkey) -> latest handshake as raw epoch seconds`,
/// for every device in `ns`, from `wg show all latest-handshakes` — the exact
/// view `dump_diag` already prints, parsed rather than eyeballed.
///
/// `wg` reports a peer that has NEVER handshaked as a zeroed timestamp, so
/// such a peer appears in this map with a `0` rather than being absent from
/// it: `Some(0)` means "the peer entry exists and no session ever formed",
/// which is a different (and much more damning) statement than `None`.
///
/// Empty map on ANY harness failure, and callers fold it across a sampling
/// window keeping the maximum. A dropped sample can therefore only ever make
/// the assertions harder to satisfy, never easier — the same rule
/// `uapi_dump_all` and `link_names` are written to.
fn latest_handshakes(ns: &Ns) -> BTreeMap<(String, String), u64> {
    let Ok(out) = ns.exec(&["wg", "show", "all", "latest-handshakes"]) else {
        return BTreeMap::new();
    };
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let ifname = f.next()?.to_string();
            let peer = f.next()?.to_string();
            let secs: u64 = f.next()?.parse().ok()?;
            Some(((ifname, peer), secs))
        })
        .collect()
}

/// What one gateway's OWN new-epoch tun was observed doing toward its peer's
/// new epoch, accumulated across a sampling window.
///
/// **Sets and a maximum, not last-values** — the same choice, for the same
/// reason, as [`PortObs`]: the state being watched is transient. The collapse
/// dial's endpoint is correct from the collapse arm until both sides retire,
/// after which `renormalize_active_listen_port` moves each active key back to
/// the base port and boringtun legitimately roams the endpoint there. "The
/// endpoint was NEVER the peer's own-tun port at any instant" is the falsifiable
/// claim; "it is not that right now" is not.
#[derive(Default)]
struct MechObs {
    /// `(ifname, endpoint)` of every peer entry seen on the Device holding
    /// THIS gateway's epoch-1 private key, keyed by the PEER's epoch-1 pubkey
    /// — i.e. every place our own new epoch dialed the peer's own new epoch.
    own_epoch_dials: BTreeSet<(String, String)>,
    /// Largest `latest-handshakes` value seen for that peer on that Device.
    /// Stays `0` iff the epoch1 <-> epoch1 session never formed.
    own_epoch_handshake: u64,
    /// Diagnostics: the ifnames seen holding our epoch-1 key. Normally exactly
    /// one (`wg0e1`); empty means the Device was never identified at all,
    /// which makes every other field vacuous and has its own failure message.
    own_epoch_ifnames: BTreeSet<String>,
    /// Diagnostics: the richest device snapshot seen during the window.
    devs: Vec<DevSnap>,
}

impl MechObs {
    /// Both halves of the mechanism: our own-epoch tun dialed the peer at
    /// `want` at some instant, AND a session actually formed there.
    fn saw(&self, want: &str) -> bool {
        self.dialed(want) && self.own_epoch_handshake > 0
    }
    fn dialed(&self, want: &str) -> bool {
        self.own_epoch_dials.iter().any(|(_, ep)| ep == want)
    }
    fn summary(&self) -> String {
        format!(
            "own-epoch Device(s) {:?}; dialed the peer's new epoch at {:?} (ports {:?}); \
             best latest-handshake seen there: {}",
            self.own_epoch_ifnames,
            self.own_epoch_dials,
            self.own_epoch_dials
                .iter()
                .filter_map(|(_, ep)| endpoint_port(ep))
                .collect::<BTreeSet<u16>>(),
            self.own_epoch_handshake,
        )
    }
}

/// One tick: fold this gateway's device state into `obs`.
///
/// The own-epoch Device is identified by the KEY IT HOLDS (`own_pub_hex ==
/// own_epoch_hex`), never by its name, and its peer entry by the key that
/// entry is FOR. That matters more here than it would elsewhere: during the
/// collapse window a gateway holds the peer's epoch-1 pubkey on *two* devices
/// at once — its own new-epoch tun and its Role-B overlap — with different
/// endpoints (measured, `docs/research/in-step-rotation-rebaselined.md`), and
/// the overlap is the one that was ALREADY right before the fix. Selecting on
/// the peer key alone would read the overlap's correct endpoint and report the
/// mechanism as working when it is not. The overlap runs our epoch-0 key, so
/// keying on our own epoch-1 pubkey excludes it by construction.
///
/// The handshake join is by `(ifname, peer base64)` and comes from a second
/// command, so the two halves of a tick are microseconds apart rather than
/// atomic. Harmless by construction: both are folded into a window, and a
/// skewed tick can only lose a sighting.
fn sample_mech(
    ns: &Ns,
    own_epoch_hex: &str,
    peer_epoch_hex: &str,
    peer_epoch_b64: &str,
    obs: &mut MechObs,
) {
    let devs = uapi_dump_all(ns);
    let hs = latest_handshakes(ns);
    for d in devs
        .iter()
        .filter(|d| d.own_pub_hex.as_deref() == Some(own_epoch_hex))
    {
        obs.own_epoch_ifnames.insert(d.ifname.clone());
        for (k, ep) in &d.peers {
            if k == peer_epoch_hex {
                if let Some(ep) = ep {
                    obs.own_epoch_dials.insert((d.ifname.clone(), ep.clone()));
                }
            }
        }
        if let Some(secs) = hs.get(&(d.ifname.clone(), peer_epoch_b64.to_string())) {
            obs.own_epoch_handshake = obs.own_epoch_handshake.max(*secs);
        }
    }
    if devs.len() >= obs.devs.len() {
        obs.devs = devs;
    }
}

/// Where the Device holding `own_hex` currently listens and where it dials
/// `peer_hex`: `(ifname, listen_port, endpoint)`, each `None` if not
/// observable. The post-settle steady-state view — see the tier-4 block in the
/// in-step test for what is required of it and why.
fn settled_view(
    devs: &[DevSnap],
    own_hex: &str,
    peer_hex: &str,
) -> (Option<String>, Option<u16>, Option<String>) {
    let Some(d) = devs
        .iter()
        .find(|d| d.own_pub_hex.as_deref() == Some(own_hex))
    else {
        return (None, None, None);
    };
    let ep = d
        .peers
        .iter()
        .find(|(k, _)| k == peer_hex)
        .and_then(|(_, ep)| ep.clone());
    (Some(d.ifname.clone()), d.listen_port, ep)
}

/// Diagnostics for a gateway that may hold ANY number of rotation Devices —
/// `dump_diag`'s fixed `wg0`/`wg0e1` pair cannot see a second rotation's
/// `wg0e2`, and it is precisely the *set* of devices and their ports that has
/// to be readable here. Enumerates every `wg*` link, prints `wg show` for each
/// (listening port, peer key, endpoint, latest handshake), the parsed UAPI
/// view, `ip route`, `ip -br addr`, and each process's stderr tail.
fn dump_rot_diag(label: &str, gws: &[(&str, &Ns)], procs: &[(&str, &GwProc)]) {
    eprintln!("\n========== DIAGNOSTICS: {label} ==========");
    for (name, ns) in gws {
        let devs: Vec<String> = link_names(ns)
            .into_iter()
            .filter(|n| n.starts_with("wg"))
            .collect();
        eprintln!("--- {name} wireguard devices: {devs:?} ---");
        for d in &devs {
            match ns.exec(&["wg", "show", d]) {
                Ok(o) => eprintln!(
                    "--- {name} wg show {d} ---\n{}",
                    String::from_utf8_lossy(&o.stdout)
                ),
                Err(e) => eprintln!("--- {name} wg show {d} ERR: {e} ---"),
            }
        }
        eprintln!(
            "--- {name} UAPI get=1 (all devices) ---\n{}",
            fmt_snaps(&uapi_dump_all(ns))
        );
        for cmd in [vec!["ip", "route"], vec!["ip", "-br", "addr"]] {
            match ns.exec(&cmd) {
                Ok(o) => eprintln!(
                    "--- {name} {cmd:?} ---\n{}",
                    String::from_utf8_lossy(&o.stdout)
                ),
                Err(e) => eprintln!("--- {name} {cmd:?} ERR: {e} ---"),
            }
        }
    }
    for (name, p) in procs {
        eprintln!("--- {name} stderr tail ---\n{}", p.stderr_tail());
    }
    eprintln!("========== END DIAGNOSTICS ==========\n");
}

/// [`poll_rotation_complete`] generalised to an arbitrary target epoch: the
/// rotation to `epoch` has completed when `epoch` is `active` AND no EARLIER
/// epoch is still `active` (retired away, or demoted to `"retiring"`).
/// A separate function rather than a widened `poll_rotation_complete` so the
/// four green single-rotation cases keep the exact predicate they were written
/// against.
async fn poll_rotation_to_epoch(
    h: &TestController,
    gateway_id: u64,
    epoch: u32,
    timeout: Duration,
) -> (bool, Vec<(u32, String, String)>) {
    let deadline = Instant::now() + timeout;
    loop {
        let states = h.debug_key_states(gateway_id).await;
        let target_active = states.iter().any(|(e, _, s)| *e == epoch && s == "active");
        let earlier_not_active = !states.iter().any(|(e, _, s)| *e < epoch && s == "active");
        if target_active && earlier_not_active {
            return (true, states);
        }
        if Instant::now() >= deadline {
            return (false, states);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// The REAL base64 pubkey the gateway submitted for `epoch`, once the
/// controller's `awaiting-submission` sentinel has been overwritten. `None` on
/// timeout. Every port probe keys off this, so it must be resolved before the
/// sampling loop can recognise anything.
async fn poll_epoch_pubkey(
    h: &TestController,
    gateway_id: u64,
    epoch: u32,
    timeout: Duration,
) -> Option<String> {
    let deadline = Instant::now() + timeout;
    loop {
        let states = h.debug_key_states(gateway_id).await;
        if let Some((_, pk, _)) = states.iter().find(|(e, _, _)| *e == epoch) {
            if pk != AWAITING_SUBMISSION && !pk.is_empty() {
                return Some(pk.clone());
            }
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Everything the rotate-twice sampling loop accumulates about WHERE gwA's
/// epoch-2 identity lives and WHERE gwB thinks it lives.
///
/// Sets, not last-values: both Devices are transient and either side may be
/// re-rendered mid-rotation, so "the port each side chose at some point during
/// the window" is the honest observation. Two disjoint sets is the two port
/// models disagreeing, stated in the smallest possible form.
#[derive(Default)]
struct PortObs {
    /// gwA: `(ifname, listen_port)` of every Device seen holding the epoch-2
    /// private key (i.e. whose `own_public_key` is the epoch-2 pubkey).
    a_listen: BTreeSet<(String, u16)>,
    /// gwB: `(ifname, endpoint)` of every peer entry seen keyed by gwA's
    /// epoch-2 pubkey — i.e. every place gwB DIALS gwA's new epoch.
    b_dial: BTreeSet<(String, String)>,
    /// Diagnostics only: the richest device snapshot seen on each side.
    a_devs: Vec<DevSnap>,
    b_devs: Vec<DevSnap>,
}

impl PortObs {
    fn listen_ports(&self) -> BTreeSet<u16> {
        self.a_listen.iter().map(|(_, p)| *p).collect()
    }
    fn dial_ports(&self) -> BTreeSet<u16> {
        self.b_dial
            .iter()
            .filter_map(|(_, ep)| endpoint_port(ep))
            .collect()
    }
    fn summary(&self) -> String {
        format!(
            "gwA LISTENED for epoch 2 on {:?} (ports {:?})\n\
             gwB DIALED gwA's epoch-2 key at {:?} (ports {:?})",
            self.a_listen,
            self.listen_ports(),
            self.b_dial,
            self.dial_ports(),
        )
    }
}

/// One paired tick: read both gateways' full UAPI device sets and fold in any
/// sighting of gwA's epoch-2 key.
fn sample_ports(gwa: &Ns, gwb: &Ns, epoch2_hex: &str, obs: &mut PortObs) {
    let a = uapi_dump_all(gwa);
    for d in &a {
        if d.own_pub_hex.as_deref() == Some(epoch2_hex) {
            if let Some(port) = d.listen_port {
                obs.a_listen.insert((d.ifname.clone(), port));
            }
        }
    }
    if a.len() >= obs.a_devs.len() {
        obs.a_devs = a;
    }

    let b = uapi_dump_all(gwb);
    for d in &b {
        for (k, ep) in &d.peers {
            if k == epoch2_hex {
                if let Some(ep) = ep {
                    obs.b_dial.insert((d.ifname.clone(), ep.clone()));
                }
            }
        }
    }
    if b.len() >= obs.b_devs.len() {
        obs.b_devs = b;
    }
}

/// **BUG 5 DONE BAR — rotate the SAME gateway TWICE.**
///
/// Every other case in this file rotates a gateway exactly once, 0 -> 1, from
/// a clean tree. Nobody has ever rotated twice, and the verification pass
/// recorded in `docs/research/rotation-endpoint-and-port-model-is-broken.md`
/// (bug 5) predicts that the SECOND rotation of any gateway cannot complete at
/// all. On the controller's 30-day timer that is a fabric-wide outage on the
/// *second* fire, hidden behind — and not fixed by — any fix for the first.
///
/// # The mechanism this test is built to photograph
///
/// A gateway never returns to its base port after a cutover: `rot.base_wg_port`
/// / `rot.base_tun` stay at the CONFIGURED values (`main.rs:854-855`) and only
/// a reboot re-normalizes (OD-1, `main.rs:463-467`). So on rotation 1 -> 2:
///
///  - `plan_tunnel(Own{2}, "wg0", 51820, live)` sees `Own{1}` still live at
///    51821 and `plan_port`'s free-list (`tunnelset.rs:249-254`) hands out the
///    lowest free port, **51822**.
///  - gwA's new tun dials the peer at *its own* port —
///    `device_config_at_port` (`reconcile.rs:166-187`) retargets peers at the
///    port THIS side chose, on the stated assumption that the peer's
///    identically-numbered epoch listens on the identical offset.
///  - gwB's overlap toward gwA dials `base + (2 - 1)` = **51821** —
///    `pending_peer_configs` (`reconcile.rs:44-52`), base plus epoch delta —
///    which is gwA's *retiring* epoch-1 tun, not its epoch-2 one.
///
/// Two mutually incompatible port models, and T3's free-list allocator
/// invalidated both. Unlike rotation 0 -> 1, there is no correctly-dialing
/// side for boringtun to roam from.
///
/// # What is asserted, in order
///
///  1. **Rotation 0 -> 1 genuinely completes and settles.** Not just "epoch 1
///     is active": gwA's epoch-0 Device `wg0` must be torn down (the same
///     bounded wait `old_epoch_device_is_torn_down_after_rotation` uses), gwA's
///     `wiremesh_gateway_live_enforcers` gauge must be back to its
///     steady-state 1, and ICMP must still cross. Anything less and rotation
///     1 -> 2 would be starting from a half-finished rotation 1 and this test
///     would be measuring something else. Every failure here is labelled
///     `PRE-CONDITION` — it is NOT the bug-5 finding.
///  2. **Rotate again, 1 -> 2, sampling both sides' ports throughout.** The
///     epoch-2 Devices are transient, so the ports are sampled on a 500ms tick
///     across the whole window rather than read once at the end.
///  3. **The two sides must agree on a port.** Every port gwB dials gwA's
///     epoch-2 key at must be a port gwA actually listened on for that key.
///     Predicted red: `{51821}` vs `{51822}`, disjoint.
///  4. **Real traffic, both ways, after the second rotation.** ICMP across the
///     fabric — the same bar every other case in this file holds.
///
/// # gwB's enforcer gauge is recorded, not gated on
///
/// The pre-condition gate in (1) is on **gwA**, the rotating side. gwB's gauge
/// is printed but not asserted, deliberately: bug 5's second half (same
/// research doc) is that gwB's Role-B collapse can never complete after ANY
/// Role-A cutover — it waits for an rx-corroborated session on the ACTIVE tun
/// toward the peer's new key, and that tun's peer entry points at the peer's
/// base port, which after gwA's retire is nothing. So gwB is expected to leak
/// its overlap Device permanently (the F9 leak shape) on the CURRENTLY-GREEN
/// one-sided path. Gating on it would make this test die of that already-known
/// defect before it ever reached rotation 2, which is the subject.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn second_rotation_of_same_gateway_keeps_traffic_flowing() {
    // Topology: IDENTICAL to `direct_rotation_is_zero_drop` — see that test
    // for the per-step rationale (bridge, netem, veths, identities).
    setup_bridge();
    let _root_guard = RootNetGuard;

    let h = TestController::start_on(CTRL_IP.parse().unwrap()).await;

    let diff = h.apply(FABRIC_ICMP).await;
    assert!(
        diff.policy_updated,
        "fabric apply must compile a real policy, got: {diff:?}"
    );

    let (a_priv, a_pub) = wg_keypair();
    let (b_priv, b_pub) = wg_keypair();
    let ga = enroll_into(&h, "10.10.1.0/24", &a_pub).await;
    let gb = enroll_into(&h, "10.10.2.0/24", &b_pub).await;

    let mut lab = Lab::new("gwtwice").expect("lab");
    let gwa = lab.ns("a").expect("gwA netns");
    let gwb = lab.ns("b").expect("gwB netns");
    let wla = lab.ns("wa").expect("wlA netns");
    let wlb = lab.ns("wb").expect("wlB netns");

    attach_underlay(&gwa, "a", "10.9.0.1");
    attach_underlay(&gwb, "b", "10.9.0.2");
    apply_netem(&gwa, "und", 20).expect("netem on gwA underlay");
    apply_netem(&gwb, "und", 20).expect("netem on gwB underlay");

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

    let sda = tempfile::tempdir().unwrap();
    let sdb = tempfile::tempdir().unwrap();
    write_identity(&ga, &a_priv, sda.path());
    write_identity(&gb, &b_priv, sdb.path());
    let logdir = tempfile::tempdir().unwrap();

    let sync_addr = h.sync_tcp_addr().to_string();
    let observe_addr = h.observe_addr().to_string();
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

    let metrics_a = format!("10.9.0.1:{METRICS_PORT}");
    let metrics_b = format!("10.9.0.2:{METRICS_PORT}");

    // ===== Wait until the mesh is up (an allowed ICMP flow passes) =====
    let up = wait_until(Duration::from_secs(45), || ping_ok(&wla, "10.10.2.2"));
    if !up {
        dump_rot_diag(
            "mesh-not-up",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!("SETUP FAILED: workload A -> workload B ICMP (policy-permitted) never passed over the direct tunnel before any rotation");
    }
    let base_enf_a = scrape_live_enforcers(&metrics_a);
    assert_eq!(
        base_enf_a,
        Some(1),
        "SETUP FAILED: at steady state gwA must report exactly one live enforcer (the base \
         tun's); got {base_enf_a:?}. A `None` means the `wiremesh_gateway_live_enforcers` \
         series never reached the scrape body, which would make the settle gate below vacuous."
    );
    eprintln!("SETUP PASS: direct mesh is up (ICMP crosses wlA -> wlB), gwA live_enforcers=1");
    eprintln!("SETUP devices:\n{}", fmt_snaps(&uapi_dump_all(&gwa)));

    // =====================================================================
    // ROTATION 1 (epoch 0 -> 1) — the PRE-CONDITION, not the subject.
    // =====================================================================
    h.admin_client()
        .await
        .rotate_key(RotateKeyRequest {
            gateway_id: ga.id(),
        })
        .await
        .expect("Admin.RotateKey #1");
    eprintln!("Admin.RotateKey #1 submitted for gwA (epoch 0 -> 1)");

    let (done1, states1) = poll_rotation_to_epoch(&h, ga.id(), 1, Duration::from_secs(90)).await;
    if !done1 {
        dump_rot_diag(
            "rotation-1-timeout",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "PRE-CONDITION FAILED: gwA's FIRST rotation (epoch 0 -> 1) did not complete within \
             90s. This test needs a genuinely finished first rotation before it can rotate \
             again; a red here is NOT the rotate-twice finding. Last debug_key_states: {states1:?}"
        );
    }
    eprintln!("ROTATION 1 COMPLETE: {states1:?}");

    // The epoch-0 Device must be gone before rotation 2 is issued: with `wg0`
    // still up, `plan_port` would be allocating against a different live set
    // and the second rotation would not be the production shape (which is a
    // fully-retired previous epoch and an active offset tun).
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
        dump_rot_diag(
            "rotation-1-not-retired",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "PRE-CONDITION FAILED: gwA's epoch-0 Device wg0 was not torn down within 30s of the \
             first rotation completing (wg0e1 present). Rotating again from a half-retired first \
             rotation would not be the production shape; a red here is NOT the rotate-twice \
             finding — it is `old_epoch_device_is_torn_down_after_rotation`'s territory"
        );
    }

    // ... and gwA's enforcer gauge must be back to its steady-state 1: exactly
    // one Device, exactly one policy hook. (gwB's is recorded below but not
    // gated on — see this test's doc comment.)
    let settle_deadline = Instant::now() + Duration::from_secs(45);
    let settled_a = loop {
        let v = scrape_live_enforcers(&metrics_a);
        if v == Some(1) || Instant::now() >= settle_deadline {
            break v;
        }
        std::thread::sleep(Duration::from_secs(1));
    };
    let settled_b = scrape_live_enforcers(&metrics_b);
    eprintln!(
        "POST-ROTATION-1 live_enforcers: gwA={settled_a:?} gwB={settled_b:?} (only gwA is gated)"
    );
    if settled_a != Some(1) {
        let links_a = link_names(&gwa);
        dump_rot_diag(
            "rotation-1-enforcers-did-not-settle",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "PRE-CONDITION FAILED: 45s after gwA's FIRST rotation completed its live-enforcer \
             gauge is {settled_a:?}, not 1 (links: {links_a:?}). The first rotation has not fully \
             settled, so rotating again would not be testing the second rotation. NOT the \
             rotate-twice finding."
        );
    }

    // ... and traffic still crosses. If THIS is red the blocker is bug 4 (the
    // post-cutover endpoint), which is a separate, already-documented defect.
    let alive_after_1 = wait_until(Duration::from_secs(20), || ping_ok(&wla, "10.10.2.2"));
    if !alive_after_1 {
        dump_rot_diag(
            "rotation-1-traffic-dead",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "PRE-CONDITION FAILED: ICMP wlA -> wlB stopped passing after the FIRST rotation. \
             That is bug 4 (the Role-A cutover leaves nothing durable able to address the active \
             tun), not the rotate-twice finding this test exists for — see \
             docs/research/rotation-endpoint-and-port-model-is-broken.md"
        );
    }
    let devs_a_after_1 = uapi_dump_all(&gwa);
    let devs_b_after_1 = uapi_dump_all(&gwb);
    eprintln!(
        "PRE-CONDITION PASS: rotation 1 complete, wg0 retired, gwA back to 1 enforcer, ICMP alive.\n\
         gwA devices after rotation 1:\n{}gwB devices after rotation 1:\n{}",
        fmt_snaps(&devs_a_after_1),
        fmt_snaps(&devs_b_after_1),
    );

    // =====================================================================
    // ROTATION 2 (epoch 1 -> 2) — THE SUBJECT.
    // =====================================================================
    h.admin_client()
        .await
        .rotate_key(RotateKeyRequest {
            gateway_id: ga.id(),
        })
        .await
        .expect("Admin.RotateKey #2");
    eprintln!("Admin.RotateKey #2 submitted for gwA (epoch 1 -> 2) — THE SUBJECT OF THIS TEST");

    // The epoch-2 pubkey is the join key for both port probes, so resolve it
    // (past the controller's `awaiting-submission` sentinel) before sampling.
    let Some(epoch2_pub_b64) = poll_epoch_pubkey(&h, ga.id(), 2, Duration::from_secs(30)).await
    else {
        let states = h.debug_key_states(ga.id()).await;
        dump_rot_diag(
            "rotation-2-no-epoch2-pubkey",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "SECOND ROTATION: gwA never submitted a real epoch-2 pubkey within 30s of \
             Admin.RotateKey #2 — the second rotation did not even reach key submission. \
             debug_key_states: {states:?}"
        );
    };
    let epoch2_hex = base64_pub_to_hex(&epoch2_pub_b64);
    eprintln!(
        "epoch-2 pubkey submitted: {epoch2_pub_b64} (hex {})",
        short_key(&epoch2_hex)
    );

    // Sample both sides' ports for the whole rotation-2 window while driving
    // it to completion. 500ms cadence: the epoch-2 own tun and gwB's overlap
    // toward it are transient, so a single end-of-window read could miss both.
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut obs = PortObs::default();
    let states2 = loop {
        sample_ports(&gwa, &gwb, &epoch2_hex, &mut obs);
        let s = h.debug_key_states(ga.id()).await;
        let done = s.iter().any(|(e, _, st)| *e == 2 && st == "active")
            && !s.iter().any(|(e, _, st)| *e < 2 && st == "active");
        if done || Instant::now() >= deadline {
            break s;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    let done2 = states2.iter().any(|(e, _, st)| *e == 2 && st == "active")
        && !states2.iter().any(|(e, _, st)| *e < 2 && st == "active");

    // The port evidence is printed unconditionally: it is most of this test's
    // value, and it must be readable whichever assertion below goes red.
    eprintln!(
        "\n===== ROTATION-2 PORT EVIDENCE =====\n{}\n\
         gwA devices (richest sample seen):\n{}\
         gwB devices (richest sample seen):\n{}\
         ====================================\n",
        obs.summary(),
        fmt_snaps(&obs.a_devs),
        fmt_snaps(&obs.b_devs),
    );

    if !done2 {
        dump_rot_diag(
            "second-rotation-did-not-complete",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "SECOND ROTATION DID NOT COMPLETE within 120s (epoch 2 active, no earlier epoch \
             active). Last debug_key_states: {states2:?}\n{}\n\
             If the two port sets above are disjoint, this is bug 5 exactly as predicted: \
             `device_config_at_port` retargets peers at the port THIS side chose while \
             `pending_peer_configs` computes base + epoch delta, and T3's free-list `plan_port` \
             invalidated both. See docs/research/rotation-endpoint-and-port-model-is-broken.md",
            obs.summary(),
        );
    }
    eprintln!("ROTATION 2 COMPLETE: {states2:?}");

    // ===== THE TRAFFIC BAR: real ICMP across the fabric, both ways =====
    // Asserted BEFORE the port assertion, deliberately: connectivity is the
    // product bar, and if it is dead that is the headline. Both directions,
    // because a one-way check can pass on the residual state of a session that
    // predates the second rotation.
    for (from, dst, label) in [
        (&wla, "10.10.2.2", "wlA -> wlB"),
        (&wlb, "10.10.1.2", "wlB -> wlA"),
    ] {
        if !wait_until(Duration::from_secs(30), || ping_ok(from, dst)) {
            dump_rot_diag(
                "post-second-rotation-traffic-dead",
                &[("gwA", &gwa), ("gwB", &gwb)],
                &[("gwA", &pa), ("gwB", &pb)],
            );
            pa.kill();
            pb.kill();
            panic!(
                "SECOND ROTATION FAILED: ICMP {label} no longer passes after gwA rotated a \
                 SECOND time (epoch 1 -> 2), even though the controller promoted epoch 2.\n{}",
                obs.summary(),
            );
        }
        eprintln!("POST-ROTATION-2 PASS: ICMP still crosses {label} on epoch 2");
    }

    // ===== SETTLE GATE: gwA's retire + renormalization has actually landed ===
    //
    // The port-authority assertion below is a *data-plane* fact about the
    // steady state after rotation 2. The loop that drove rotation 2 broke on a
    // *controller roster* fact (epoch 2 active, nothing earlier active) — i.e.
    // at PROMOTE. Those are different instants, and the data-plane one is
    // strictly later: gwA only tears down its epoch-1 Device and renormalizes
    // the epoch-2 Device's listen port back to the base after `RETIRE_GRACE`
    // (`main.rs`: 2 x ROTATION_KEEPALIVE) of continuous rx-corroborated
    // liveness following the cutover, polled on a 500ms tick — and the first
    // grace attempt is routinely aborted once, so the real distance from
    // promote is ~10s, not 6s. Reading ~1.5-2s after promote evaluates the
    // invariant at an instant that structurally precedes it becoming
    // satisfiable.
    //
    // This gate moves the moment of evaluation — and ONLY the moment — to when
    // the system claims to provide the invariant. It does not relax anything:
    // the port comparison below is unchanged, and the gate is itself an
    // assertion (gwA's epoch-2 Device must end up ON THE BASE PORT, which is
    // the renormalization's whole observable result).
    //
    // # Why the wait is on gwA alone, and why it has a stability window
    //
    // The obvious second clause — "gwB has finished its Role-B collapse, no
    // `wg0o<n>` overlap Device left" — is UNSATISFIABLE and must not be added.
    // gwB's collapse waits for a live session on the ACTIVE tun toward the
    // peer's new key and never gets one, so the overlap Device leaks
    // permanently (the F9 leak shape). This test's doc comment above
    // deliberately declines to gate on it for exactly that reason: gating
    // there kills the test on an already-known defect instead of measuring its
    // subject. Verified empirically on this branch — a gwB clause times out
    // while gwA's retire demonstrably fires.
    //
    // But gwB *is* the source of a real second race, via a different
    // mechanism than device teardown. The leaked overlap's peer entry toward
    // gwA's epoch-2 key initially dials the OFFSET port (51821); it is
    // corrected to the base port only by boringtun's rx-driven endpoint
    // roaming, once gwA's renormalized `wg0e2` sends from 51820 — which the 3s
    // persistent keepalive guarantees, but not instantly. Since gwA's
    // condition flips true the moment renormalization lands, a single-sample
    // gate can return up to ~3s before gwB has roamed.
    //
    // Hence the stability window: gwA must hold the post-retire state across
    // successive samples for `RENORM_STABLE_FOR` — one keepalive round-trip
    // past renormalization. This is OBSERVED, not slept: every intervening
    // sample must also satisfy the condition, so a state that flaps restarts
    // the clock instead of passing. Note this is deliberately NOT "gwB dials a
    // port gwA listens on" — that would be the assertion restating itself as
    // its own precondition, and would be unfalsifiable.
    //
    // A timeout here is its own, LOUDER finding than a port mismatch: it means
    // the retire never fired at all. That failure is currently invisible —
    // nothing else in this test observes it — so it gets its own panic
    // message, deliberately distinct from the port-authority one.
    //
    // 60s: room for one full grace (6s), one aborted-and-restarted grace, and
    // the stability window, with margin — bounded so this fails rather than
    // hangs.
    const BASE_WG_PORT: u16 = 51820; // must match `spawn_gw`'s `--wg-port`
    /// How long gwA's post-retire state must hold CONTINUOUSLY before the port
    /// state is read. One 3s keepalive round-trip past renormalization, plus
    /// margin — see the roaming rationale above.
    const RENORM_STABLE_FOR: Duration = Duration::from_secs(4);

    let mut gate_a: Vec<DevSnap> = Vec::new();
    let mut gate_b: Vec<DevSnap> = Vec::new();
    let mut stable_since: Option<Instant> = None;
    let mut reached_base = false;
    // Set iff `wg0e2` was seen PRESENT on a non-base port *after* having been
    // seen at the base port — renormalization coming undone, a genuine defect
    // that must surface as itself rather than as a timeout.
    //
    // Deliberately not "the condition went false": `uapi_dump_all` returns an
    // empty vec on a dropped sample (documented on that fn), and an absent
    // `wg0e2` is indistinguishable from a dropped sample. A dropped sample
    // therefore only resets the stability clock — it can never manufacture
    // this failure. Only a Device that is *there*, on the *wrong* port, does.
    let mut regressed: Option<(String, Option<u16>)> = None;

    let retire_settled = wait_until(Duration::from_secs(60), || {
        let a = uapi_dump_all(&gwa);
        let b = uapi_dump_all(&gwb);
        // gwA: epoch-1 Device retired, epoch-2 Device present AND renormalized
        // back to the base port. `listen_port == BASE_WG_PORT` is the
        // observable RESULT of the renormalization.
        let a_e1_retired = !a.iter().any(|d| d.ifname == "wg0e1");
        let e2 = a.iter().find(|d| d.ifname == "wg0e2");
        let a_e2_at_base = e2.is_some_and(|d| d.listen_port == Some(BASE_WG_PORT));

        if a_e2_at_base {
            reached_base = true;
        } else if reached_base && regressed.is_none() {
            if let Some(d) = e2 {
                regressed = Some((d.ifname.clone(), d.listen_port));
            }
        }
        // The stability clock: started by the first satisfying sample, kept
        // alive only by every sample after it, cleared by any that isn't.
        if a_e1_retired && a_e2_at_base {
            stable_since.get_or_insert_with(Instant::now);
        } else {
            stable_since = None;
        }

        gate_a = a;
        gate_b = b;
        // Break out immediately on a regression so it panics as a regression
        // rather than idling until the 60s bound and reading as a timeout.
        regressed.is_some() || stable_since.is_some_and(|t| t.elapsed() >= RENORM_STABLE_FOR)
    });

    if let Some((ifname, port)) = regressed {
        dump_rot_diag(
            "second-rotation-renormalization-came-undone",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "SECOND ROTATION: THE RENORMALIZATION CAME UNDONE. gwA's epoch-2 Device reached the \
             base port {BASE_WG_PORT} and then LEFT it — {ifname} was observed listening on \
             {port:?}. This is neither a timeout nor the port-authority failure: the retire ran, \
             put the active key back on its advertised port, and something moved it off again. \
             Every peer's durable endpoint for this gateway points at the base port, so the \
             active key is no longer addressable where the fabric expects it.\n\
             gwA devices:\n{}gwB devices:\n{}\
             Sampled across the whole rotation-2 window:\n{}",
            fmt_snaps(&gate_a),
            fmt_snaps(&gate_b),
            obs.summary(),
        );
    }
    if !retire_settled {
        dump_rot_diag(
            "second-rotation-retire-never-completed",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "SECOND ROTATION: THE RETIRE/RENORMALIZATION NEVER COMPLETED. 60s after the \
             controller promoted epoch 2, gwA never held its post-retire steady state \
             continuously for {RENORM_STABLE_FOR:?}. This is NOT the port-authority failure — \
             the port comparison below was never reached. It means the gateway-side teardown \
             that is supposed to follow every cutover did not fire at all, which leaves the \
             fabric permanently holding rotation scaffolding and the active key parked on an \
             offset port no peer addresses.\n\
             Required, and last observed:\n\
             \x20 gwA wg0e1 retired: {}\n\
             \x20 gwA wg0e2 present and renormalized to base port {BASE_WG_PORT}: {}\n\
             \x20 ... and held continuously for {RENORM_STABLE_FOR:?}: false\n\
             \x20 (gwA reached the base port at least once during the wait: {reached_base})\n\
             gwA devices:\n{}gwB devices:\n{}\
             Sampled across the whole rotation-2 window:\n{}",
            !gate_a.iter().any(|d| d.ifname == "wg0e1"),
            gate_a
                .iter()
                .find(|d| d.ifname == "wg0e2")
                .is_some_and(|d| d.listen_port == Some(BASE_WG_PORT)),
            fmt_snaps(&gate_a),
            fmt_snaps(&gate_b),
            obs.summary(),
        );
    }
    eprintln!(
        "RETIRE SETTLE PASS: gwA retired wg0e1 and renormalized wg0e2 to the base port \
         {BASE_WG_PORT}, and held that state continuously for {RENORM_STABLE_FOR:?}. \
         Reading the settled port state now."
    );

    // ===== THE PORT-AUTHORITY ASSERTION =====
    // Not "did it ping" — WHICH PORT each side settled on. A future reader has
    // to be able to see the two models disagreeing, not just "ping failed".
    //
    // Judged on a FRESH read of both sides *now*, once everything has settled,
    // rather than on the sampled sets above. Make-before-break legitimately
    // re-renders a peer entry mid-rotation, so "no sample in the whole window
    // ever showed a wrong port" would be a stricter bar than the design owes —
    // and one no fix could clear. The sampled sets stay printed above as the
    // evidence of HOW the two models diverged; this is the assertion.
    let final_a = uapi_dump_all(&gwa);
    let final_b = uapi_dump_all(&gwb);
    let settled_listen: BTreeSet<(String, u16)> = final_a
        .iter()
        .filter(|d| d.own_pub_hex.as_deref() == Some(epoch2_hex.as_str()))
        .filter_map(|d| d.listen_port.map(|p| (d.ifname.clone(), p)))
        .collect();
    let mut settled_dial: BTreeSet<(String, String)> = BTreeSet::new();
    for d in &final_b {
        for (k, ep) in &d.peers {
            if k == &epoch2_hex {
                if let Some(ep) = ep {
                    settled_dial.insert((d.ifname.clone(), ep.clone()));
                }
            }
        }
    }
    let listen_ports: BTreeSet<u16> = settled_listen.iter().map(|(_, p)| *p).collect();
    let dial_ports: BTreeSet<u16> = settled_dial
        .iter()
        .filter_map(|(_, ep)| endpoint_port(ep))
        .collect();
    eprintln!(
        "\n===== SETTLED PORT STATE (after rotation 2) =====\n\
         gwA listens for epoch 2 on {settled_listen:?} (ports {listen_ports:?})\n\
         gwB dials gwA's epoch-2 key at {settled_dial:?} (ports {dial_ports:?})\n\
         gwA devices:\n{}gwB devices:\n{}\
         =================================================\n",
        fmt_snaps(&final_a),
        fmt_snaps(&final_b),
    );

    if listen_ports.is_empty() || dial_ports.is_empty() {
        dump_rot_diag(
            "second-rotation-port-evidence-missing",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "SECOND ROTATION: could not observe both sides of the port question once settled — \
             gwA shows no Device holding the epoch-2 key ({listen_ports:?}) and/or gwB shows no \
             peer entry dialing it ({dial_ports:?}). Sampled during the window:\n{}",
            obs.summary(),
        );
    }
    if !dial_ports.is_subset(&listen_ports) {
        dump_rot_diag(
            "second-rotation-port-models-disagree",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "PORT AUTHORITY (bug 5): once gwA's SECOND rotation settled, the two sides still \
             disagree about where gwA's epoch-2 key listens. gwA listens on {listen_ports:?} \
             ({settled_listen:?}); gwB dials that same key at {dial_ports:?} ({settled_dial:?}). \
             Every dialed port must be one gwA is actually listening on for that key.\n\
             Sampled across the whole rotation-2 window:\n{}\n\
             Mechanism: gwA never returned to its base port after rotation 1, so \
             `plan_tunnel(Own{{2}})` allocated the next FREE port above the base (51822, with \
             Own{{1}} still holding 51821), while `pending_peer_configs` computes base + \
             (2 - 1) = 51821 — gwA's RETIRING epoch-1 tun — and `device_config_pinned` can only \
             ever emit the BASE port 51820, where nothing listens at all. Three answers, no \
             authority. See docs/research/rotation-endpoint-and-port-model-is-broken.md",
            obs.summary(),
        );
    }
    eprintln!(
        "PORT PASS: gwA listens for epoch 2 on {listen_ports:?} and gwB dials it at \
         {dial_ports:?} — one port authority."
    );

    pa.kill();
    pb.kill();
    drop(lab);
    eprintln!(
        "\nDONE-BAR PASSED: the same gateway rotated TWICE (0 -> 1 -> 2), the first rotation \
         fully retired and settled before the second was issued, both sides agree on the port \
         the second epoch listens on, and real traffic crosses the fabric in both directions \
         afterwards."
    );
}
