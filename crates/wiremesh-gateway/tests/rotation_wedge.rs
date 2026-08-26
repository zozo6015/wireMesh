//! B2 done-bar (design §3.4, BACKLOG item 9): a rotation that FAILS part-way
//! must not wedge the gateway — the very next directive has to be honoured.
//!
//! Two REAL `wiremesh-gateway` binary processes in their own netns, one real
//! controller. gwA's first rotation is made to fail deterministically through
//! the `netns-tests`-gated fault hook; the test then asserts the unwind ran
//! and — the falsification signal — that the SECOND rotation actually
//! completes.
//!
//! ./dev.sh run "cargo build -p wiremesh-gateway && cargo test -p wiremesh-gateway \
//!   --test rotation_wedge --features netns-tests -- --test-threads=1 --nocapture"
//!
//! Topology: IDENTICAL to `key_rotation.rs` / `mesh_milestone.rs` (bridge +
//! two gateway netns + two workload netns). The bridge/underlay/identity/
//! process helpers below are deliberately DUPLICATED from `key_rotation.rs`
//! verbatim, per that file's own standing note — keep them byte-for-byte
//! identical if you touch them.
//!
//! # THE FALSE-GREEN TRAP THIS FILE IS BUILT AROUND (design Rev 1.4, RS3)
//!
//! The wedge is **silent on the data plane by construction.** After a failed
//! rotation that unwound its resources, the gateway is sitting on its intact
//! OLD key with a working tunnel; traffic keeps flowing indefinitely. What is
//! broken is that `Rotation::on_directive` is honoured only from `Idle`, so a
//! phase parked at `Overlapping` makes the gateway ignore every later
//! directive until the process restarts — and nothing retries a
//! `RotateDirective` (design C1: `broker.rs::send_rotate_if_pending` fires
//! once, driven only by `ChangeEvent::KeyRotated`).
//!
//! So: **step (iv)'s red condition is "the second rotation never happens" —
//! never "traffic stopped".** Liveness IS asserted, as a co-assertion, and it
//! is labelled as such at every site. A step (iv) written as an outage check
//! would pass under sabotage 1 and report a false green.
//!
//! # Interactions worth knowing before reading a red run
//!
//!  * The controller numbers epochs `MAX(epoch)+1` over its OWN rows
//!    (`db.rs::rotate_key`) and the failed rotation's `pending` row is not
//!    deleted by the gateway-side abort — there is no cancel RPC. So the
//!    second directive is epoch **2**, not 1. This test never hardcodes it:
//!    `RotateKeyResponse.epoch` is the authority.
//!    Nothing here asserts on that stranded row, or on a row COUNT: two
//!    non-`active` rows for gwA inside the controller's 300s `ABORT_AFTER`
//!    window is correct and expected (per C1 nothing re-emits `KeyRotated`
//!    for a sentinel row), and pinning its presence would turn a future
//!    clean-up into a red test.
//!  * That stranded epoch-1 row carries the `"awaiting-submission"` sentinel,
//!    which `PeerState::pending_key` filters, so gwB's Role-B overlap still
//!    targets the real epoch-2 key. If that filter ever changes, this test
//!    reds in step (iv) for a reason that is NOT the wedge — check
//!    `state.rs::pending_key` before blaming the unwind.
//!  * `direct_rotation_is_zero_drop` in `key_rotation.rs` reds ~42% under host
//!    load (`docs/research/flake-direct-rotation-zero-drop.md`). This file's
//!    liveness co-assertions are deliberately `wait_until`-shaped rather than
//!    zero-drop-shaped so they do not import that flake.
#![cfg(feature = "netns-tests")]

use std::collections::BTreeSet;
use std::io::{Read as _, Write as _};
use std::path::Path;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use wiremesh_gateway::epochkeys::EpochKeys;
use wiremesh_gateway::identity::Identity;
use wiremesh_gateway::uapi::base64_pub_from_priv;
use wiremesh_proto::v1::{MintTokenRequest, RotateKeyRequest};
use wiremesh_testkit::netns::{apply_netem, Lab, Ns};
use wiremesh_testkit::{StubGateway, TestController};

const GW_BIN: &str = env!("CARGO_BIN_EXE_wiremesh-gateway");
const BRIDGE: &str = "wmbr0";
const CTRL_IP: &str = "10.9.0.254";
const METRICS_PORT: u16 = 9099;

/// The `netns-tests`-gated fault-injection hook (design §3.4, choice (A);
/// grammar confirmed with gateway-dev via `main`). Parsed in the LIBRARY
/// (`gateway/src/config.rs`) with its own unit tests, never inline in
/// `main.rs`, and feature-gated so it cannot reach a release binary (R4).
///
/// Value: one of `after-mint | after-bring-up | after-enforcer-insert`, with
/// an optional `:N` count (default 1) meaning "fail the first N directives,
/// then behave normally". The count is what makes this a ONE-SHOT: step (iv)
/// must issue its directive to the SAME live process, because restarting gwA
/// in between would reset the state machine for free and make sabotage 1
/// unfalsifiable.
///
/// This test drives `after-enforcer-insert`, which fails at `uapi::apply` —
/// design §2.2 step 8, the maximal residue: mint persisted, tun up, enforcer
/// inserted in the shared map, `role_a` still `None`. It is the only value
/// that exercises all four resource steps of `unwind_failed_rotation`, and it
/// is the reason step (iii) can assert on the store, the link set AND the
/// live-enforcer gauge in one run.
const FAIL_ROTATION_ENV: &str = "WIREMESH_TEST_FAIL_ROTATION";
/// Fail exactly the first directive (the `:N` default), at the deepest
/// unwind-reachable step.
const FAIL_ROTATION_VALUE: &str = "after-enforcer-insert";

/// Mirrors `tunnelset::QUARANTINE`, which is private — the same
/// mirror-with-a-comment device `rotation_slot_quarantine.rs` uses for
/// `MAX_ROTATION_TUNS`. If the production constant moves, step (iv)'s wait
/// must move with it; see the comment there for why the wait exists at all.
const TUNNEL_QUARANTINE: Duration = Duration::from_secs(5);

/// Mirrors `main.rs`'s `OVERLAP_STALL_WARN` (a bin const, unreachable from a
/// `tests/*` target, which links the LIB). Only used to decide whether a stall
/// warning would have been LEGITIMATE for the rotation just observed — see the
/// stall-clock assertion in step (iv).
const STALL_WARN_AFTER: Duration = Duration::from_secs(90);

/// Substring identifying the R2 stall warning `run_rotation_ticks` emits once
/// a phase has been `Overlapping` longer than `OVERLAP_STALL_WARN` (emitted at
/// most once per spell, via that function's `warned_overlap_stall` latch).
///
/// PINNED ANCHOR, same class as [`ABORT_ANCHOR`]: the production side has
/// committed to this token. It matters more than a normal grep string because
/// the assertion below is an ABSENCE check — if the wording changes, this
/// matches nothing, the delta is trivially zero and **the assertion passes
/// silently** rather than failing. A stale marker here does not look like a
/// broken test; it looks like a healthy gateway.
const STALL_WARN_MARKER: &str = "ROTATION STALLED";

/// The abort ANCHOR line, emitted by `handle_rotate`'s wrapper on `Err`
/// **before** the unwind runs. Asserted, because it is contract: it survives
/// BOTH sabotages (neither deletes the wrapper's `eprintln!`), so keying step
/// (iii) on it cannot smear either falsification across two probes.
const ABORT_ANCHOR: &str = "ROTATION ABORTED";

/// The step-5 line, emitted only once the state machine has been returned to
/// `Idle`. **Evidence only, never asserted** — sabotage 1 deletes step 5, and
/// keying anything on this line would make that sabotage red here instead of
/// at step (iv), which is the probe the design nominates for the SM reset.
const SM_RESET_MARKER: &str = "state machine returned to Idle";

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

// --- root-netns shell helpers (duplicated from key_rotation.rs) -------------

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

// --- identity provisioning (duplicated from key_rotation.rs) ---------------

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

// --- gateway process management (duplicated from key_rotation.rs) ----------

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
    /// reading a run's console, pass or fail.
    ///
    /// DELIBERATE DIVERGENCE from `key_rotation.rs`'s copy, which ends "Nothing
    /// asserts on the result". Here the ABORT ANCHOR is asserted on (step iii)
    /// while the SM-reset line is evidence only — see `ABORT_ANCHOR` and
    /// `SM_RESET_MARKER`. Stated rather than silently copied, because the
    /// byte-for-byte convention on this helper block exists to stop the two
    /// files drifting UNNOTICED; a documented divergence is the convention
    /// working, not a breach of it.
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

/// `key_rotation.rs::spawn_gw`, plus an `env` prefix so the fault hook can be
/// armed on ONE gateway only. `Ns::spawn` inherits this process's environment,
/// so setting the var on the test process itself would arm BOTH gateways —
/// hence `env K=V <bin>` rather than `Command::env`.
fn spawn_gw(
    ns: &Ns,
    statedir: &Path,
    sync: &str,
    observe: &str,
    logdir: &Path,
    tag: &str,
    env: &[(&str, &str)],
) -> GwProc {
    let metrics = format!("0.0.0.0:{METRICS_PORT}");
    let statedir_s = statedir.to_str().unwrap();
    let assignments: Vec<String> = env.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let mut args: Vec<&str> = vec!["env"];
    args.extend(assignments.iter().map(String::as_str));
    args.extend_from_slice(&[
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
    ]);
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

// --- probes ----------------------------------------------------------------

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

fn link_names(ns: &Ns) -> BTreeSet<String> {
    let Ok(out) = ns.exec(&["ip", "-br", "link"]) else {
        return BTreeSet::new();
    };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| Some(l.split_whitespace().next()?.split('@').next()?.to_string()))
        .collect()
}

/// One scrape of a gateway's Prometheus endpoint over the underlay bridge —
/// the same route `key_rotation.rs::scrape_live_enforcers` takes. `None` on any
/// transport failure.
fn scrape(addr: &str) -> Option<String> {
    let sa: std::net::SocketAddr = addr.parse().ok()?;
    let mut s = std::net::TcpStream::connect_timeout(&sa, Duration::from_secs(1)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
    s.write_all(b"GET /metrics HTTP/1.0\r\n\r\n").ok()?;
    let mut buf = String::new();
    let _ = s.read_to_string(&mut buf);
    Some(buf)
}

/// `wiremesh_gateway_rotation_aborts_total{reason="failed"}`. `None` if the
/// scrape failed OR the series is absent — and "absent" is treated as a hard
/// failure at the precondition gate below, never silently as 0, because a
/// renderer that never reached the `serve_metrics` fetch tuple would otherwise
/// make every assertion here vacuous (design §3.2 Piece 4 item 3).
fn scrape_rotation_aborts(addr: &str) -> Option<u64> {
    scrape(addr)?.lines().find_map(|l| {
        l.strip_prefix("wiremesh_gateway_rotation_aborts_total{reason=\"failed\"}")
            .and_then(|v| v.trim().parse().ok())
    })
}

/// The single phase label the info-gauge is currently reporting.
fn scrape_rotation_phase(addr: &str) -> Option<String> {
    scrape(addr)?.lines().find_map(|l| {
        let rest = l.strip_prefix("wiremesh_gateway_rotation_phase{phase=\"")?;
        let (phase, tail) = rest.split_once('"')?;
        tail.trim_start_matches('}')
            .trim()
            .eq("1")
            .then(|| phase.to_string())
    })
}

fn scrape_live_enforcers(addr: &str) -> Option<u64> {
    scrape(addr)?.lines().find_map(|l| {
        l.strip_prefix("wiremesh_gateway_live_enforcers ")
            .and_then(|v| v.trim().parse().ok())
    })
}

/// gwA's durable key store, read through the library rather than by parsing
/// JSON in the test — the store's shape is `EpochKeys`' business, not ours.
fn load_store(statedir: &Path) -> EpochKeys {
    EpochKeys::load(statedir)
        .expect("reading gwA's epoch_keys.json")
        .expect("gwA must have persisted an epoch_keys.json (boot migration writes one)")
}

fn raw_store(statedir: &Path) -> String {
    std::fs::read_to_string(statedir.join("epoch_keys.json")).unwrap_or_default()
}

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

fn dump_diag(label: &str, gws: &[(&str, &Ns)], procs: &[(&str, &GwProc)]) {
    eprintln!("\n========== DIAGNOSTICS: {label} ==========");
    for (name, ns) in gws {
        for cmd in [
            vec!["wg", "show", "all"],
            vec!["wg", "show", "all", "endpoints"],
            vec!["wg", "show", "all", "latest-handshakes"],
            vec!["wg", "show", "all", "transfer"],
            vec!["ip", "-br", "link"],
            vec!["ip", "route"],
            vec!["ss", "-4", "-lunp"],
        ] {
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

// --- the done-bar test ------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_failed_rotation_does_not_wedge_the_gateway() {
    // ===== (i) topology — identical to key_rotation.rs =====
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

    let mut lab = Lab::new("gwwedge").expect("lab");
    let gwa = lab.ns("a").expect("gwA netns");
    let gwb = lab.ns("b").expect("gwB netns");
    let wla = lab.ns("wa").expect("wlA netns");
    let wlb = lab.ns("wb").expect("wlB netns");

    attach_underlay(&gwa, "a", "10.9.0.1");
    attach_underlay(&gwb, "b", "10.9.0.2");
    // MANDATORY real one-way latency (Phase-0 Finding 2): a zero-latency lab
    // lets the new-epoch handshake complete unrealistically fast.
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
    let metrics_a = format!("10.9.0.1:{METRICS_PORT}");

    // gwA is armed to fail its FIRST rotation and only its first. gwB is not
    // armed at all — it must behave exactly like production throughout, so
    // that whatever gwA does is the only variable.
    let mut pa = spawn_gw(
        &gwa,
        sda.path(),
        &sync_addr,
        &observe_addr,
        logdir.path(),
        "a",
        &[(FAIL_ROTATION_ENV, FAIL_ROTATION_VALUE)],
    );
    let mut pb = spawn_gw(
        &gwb,
        sdb.path(),
        &sync_addr,
        &observe_addr,
        logdir.path(),
        "b",
        &[],
    );

    let up = wait_until(Duration::from_secs(45), || ping_ok(&wla, "10.10.2.2"));
    if !up {
        dump_diag(
            "mesh-not-up",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!("SETUP FAILED: wlA -> wlB ICMP never passed before any rotation");
    }

    let base_links_a = link_names(&gwa);
    let base_store = load_store(sda.path());
    let base_active_epoch = base_store
        .active()
        .expect("gwA must boot with an active epoch")
        .epoch;
    let base_active_priv = base_store.active().unwrap().private_key_b64.clone();

    // PRECONDITION on the observability surface itself. `None` here means the
    // rotation series never reached `serve_metrics`'s fetch tuple, which would
    // make every metric assertion below vacuous — the exact defect
    // `tests/peer_metrics.rs`'s header records and design §3.2 Piece 4 item 3
    // requires wiring end to end.
    let base_aborts = scrape_rotation_aborts(&metrics_a);
    assert_eq!(
        base_aborts,
        Some(0),
        "HARNESS PRECONDITION: `wiremesh_gateway_rotation_aborts_total{{reason=\"failed\"}}` must \
         be present and 0 on a gateway that has never rotated. A missing series means the \
         counter reached the renderer but not the `serve_metrics` fetch tuple, and every \
         assertion in step (iii) would then be vacuous."
    );
    assert_eq!(
        scrape_rotation_phase(&metrics_a).as_deref(),
        Some("idle"),
        "HARNESS PRECONDITION: a gateway with no rotation in flight must report phase=idle"
    );
    eprintln!(
        "SETUP PASS: mesh up, gwA active epoch {base_active_epoch}, links {base_links_a:?}, \
         aborts=0, phase=idle"
    );

    // ===== (ii) first directive — armed to fail =====
    let r1 = h
        .admin_client()
        .await
        .rotate_key(RotateKeyRequest {
            gateway_id: ga.id(),
        })
        .await
        .expect("Admin.RotateKey #1")
        .into_inner();
    eprintln!(
        "Admin.RotateKey #1 -> epoch {} (gwA is armed to fail this one)",
        r1.epoch
    );

    let unwound = wait_until(Duration::from_secs(60), || {
        scrape_rotation_aborts(&metrics_a) == Some(1)
    });
    if !unwound {
        dump_diag(
            "unwind-never-ran",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        let phase = scrape_rotation_phase(&metrics_a);
        pa.kill();
        pb.kill();
        panic!(
            "gwA's armed rotation to epoch {} never produced an abort within 60s \
             (rotation_aborts_total = {:?}, phase = {phase:?}). Either the fault hook did not \
             fire — check that `{FAIL_ROTATION_ENV}` is parsed and that the binary was built \
             `--features netns-tests` — or `unwind_failed_rotation` was never reached from \
             `handle_rotate`'s Err path. Nothing below can be interpreted until this holds.",
            r1.epoch,
            scrape_rotation_aborts(&metrics_a)
        );
    }

    // ===== (iii) the unwind actually unwound =====

    // (iii-a) EVIDENCE ONLY — deliberately NOT an assertion.
    //
    // The phase gauge returning to "idle" and step (iv)'s "the second
    // rotation completes" are the SAME property (the state-machine reset)
    // observed two ways, and design §3.4 nominates step (iv) as its
    // falsification target. Asserting here as well would make sabotage 1
    // (delete `unwind_failed_rotation`'s step 5) red HERE and never reach
    // (iv) — so the run would never demonstrate the thing that actually
    // matters: that a wedged gateway REFUSES the next directive. One
    // property, one probe (project memory: "red-green: verify the reason,
    // not just the failure"). The reading is recorded, and (iv)'s failure
    // message reads the gauge again so a red run still names the cause.
    let phase_after_abort = {
        let settled = wait_until(Duration::from_secs(30), || {
            scrape_rotation_phase(&metrics_a).as_deref() == Some("idle")
        });
        let phase = scrape_rotation_phase(&metrics_a);
        eprintln!(
            "POST-ABORT rotation phase: {phase:?} (settled to idle within 30s: {settled}). \
             Not asserted here — step (iv) is the falsification target for the SM reset."
        );
        phase
    };

    // (iii-b) the half-built epoch's tun is gone. Scheme-agnostic: the test
    // never has to know what the implementer named the rotation tun, only that
    // no device survives that was not there before.
    let links_settled = wait_until(Duration::from_secs(30), || {
        link_names(&gwa).difference(&base_links_a).count() == 0
    });
    if !links_settled {
        let leaked: Vec<String> = link_names(&gwa)
            .difference(&base_links_a)
            .cloned()
            .collect();
        dump_diag(
            "tun-leaked",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "the aborted rotation leaked device(s) {leaked:?}. Design §2.2 records that steps 8 \
             and 9 of `handle_rotate` do NOT unwind the tun on their own — a leaked own-epoch \
             device also holds the RESERVED own-tun port, and `plan_tunnel` errors rather than \
             falling back when that port is held, so the leak makes every FUTURE rotation fail \
             at step 4. That is the wedge with an extra step."
        );
    }
    let enforcers_settled = wait_until(Duration::from_secs(30), || {
        scrape_live_enforcers(&metrics_a) == Some(1)
    });
    assert!(
        enforcers_settled,
        "gwA's live-enforcer gauge did not return to 1 after the abort (got {:?}). A tun can be \
         gone from `ip link` while its `GatewayEnforcer` is still in the shared map — the map \
         entry is what keeps a tc-BPF program attached — so this is the only probe that can see \
         a half-released enforcer (see key_rotation.rs::scrape_live_enforcers).",
        scrape_live_enforcers(&metrics_a)
    );

    // (iii-c) THE SECURITY HALF — the orphan mint is scrubbed. This is
    // sabotage 2's falsification target; it must stand alone, on its own
    // observable, so that removing `unwind_failed_rotation`'s step 4 reds
    // exactly here and nothing else.
    let store_after_abort = load_store(sda.path());
    let pending: Vec<u32> = store_after_abort
        .epochs
        .iter()
        .filter(|k| k.state == "pending")
        .map(|k| k.epoch)
        .collect();
    assert!(
        pending.is_empty(),
        "SECURITY: gwA's epoch_keys.json still holds pending epoch(s) {pending:?} after the \
         rotation aborted. The mint is persisted BEFORE the fallible steps run (design §2.2 \
         step 3) and, before B2, nothing could ever remove a \"pending\" entry — `EpochKeys::retire` \
         accepts only \"retiring\" — so orphan PRIVATE KEYS accumulated in this file without \
         bound, one per failed rotation, for the life of the gateway. Store: {:?}",
        store_after_abort.epochs
    );
    assert_eq!(
        store_after_abort.active().map(|k| k.epoch),
        Some(base_active_epoch),
        "the unwind must leave the epoch the data plane is actually running on untouched — \
         that intact old key is the whole reason an abort is safe. Store: {:?}",
        store_after_abort.epochs
    );
    assert!(
        raw_store(sda.path()).contains(&base_active_priv),
        "the ACTIVE private key must still be in epoch_keys.json — a store that lost it could \
         not boot the data plane back up (`EpochKeys::select_boot_key`)"
    );

    // The gateway's own statement that it took the abort branch. Asserted:
    // the anchor is emitted by the WRAPPER before the unwind, so it survives
    // both sabotages and cannot smear either falsification.
    let anchor_lines = pa.stderr_grep(ABORT_ANCHOR);
    assert!(
        !anchor_lines.is_empty(),
        "gwA never logged the `{ABORT_ANCHOR}` anchor, yet `rotation_aborts_total` reached 1. \
         Those two are wired at the same place (the wrapper's Err path, before the unwind), so \
         a counter without an anchor means one of them has moved and the operator-facing \
         evidence for a failed rotation no longer exists. stderr tail:\n{}",
        pa.stderr_tail()
    );
    eprintln!("gwA abort anchor: {anchor_lines:?}");
    // Evidence ONLY — sabotage 1 deletes the step that emits this, and step
    // (iv) is the nominated probe for the SM reset. Never assert on it.
    eprintln!(
        "gwA SM-reset lines (not asserted): {:?}",
        pa.stderr_grep(SM_RESET_MARKER)
    );
    eprintln!(
        "POST-ABORT: phase=idle, aborts=1, links back to baseline, no pending epoch. \
         Store: {:?}",
        store_after_abort.epochs
    );

    // CO-ASSERTION, NOT THE FALSIFICATION SIGNAL (design Rev 1.4, RS3): after
    // an unwound rotation the gateway is sitting on its intact OLD key, so
    // traffic is EXPECTED to keep flowing — under sabotage 1 it flows too.
    // Asserted because a regression that broke it would matter; never as
    // evidence that the wedge is closed.
    assert!(
        wait_until(Duration::from_secs(20), || ping_ok(&wla, "10.10.2.2")),
        "CO-ASSERTION: ICMP wlA -> wlB stopped passing after gwA's rotation ABORTED. The abort \
         is supposed to be invisible to the data plane — the gateway never left its old key. \
         This is not the wedge; it means the unwind tore down something live."
    );

    // ===== (iv) THE FALSIFICATION SIGNAL: the SECOND rotation completes =====
    //
    // Read this twice before changing it. The red condition is that the epoch
    // NEVER ADVANCES — not that traffic stopped. Under sabotage 1 (delete
    // `unwind_failed_rotation`'s step 5, the `on_failed` call) steps 1-4 still
    // run, the half-built tun is still torn down, the gateway is still on its
    // working old key, and the ping flood below still passes. What fails is
    // that the phase stayed `Overlapping`, `Rotation::on_directive` refuses
    // this second directive, and the epoch never advances. A step (iv) written
    // as an outage check would report a false green.
    // WAIT OUT THE TUNNEL QUARANTINE BEFORE THE SECOND DIRECTIVE. This is
    // required for correctness of the test, not politeness.
    //
    // `TunnelSet::tear_down` puts a torn-down rotation tun's ifname AND listen
    // port into quarantine for `tunnelset::QUARANTINE` (5s), and `plans()`
    // reports quarantined entries as taken so the pure allocator skips them
    // (F6, `tests/rotation_slot_quarantine.rs`). The unwind's step 2 tears down
    // `TunnelId::Own { epoch }`, whose port is the RESERVED
    // `base + OWN_TUN_PORT_OFFSET` — and `plan_tunnel` REFUSES rather than
    // falling back when that reserved port is held, because a rotating peer
    // computes it and cannot be told any other value.
    //
    // `OWN_TUN_PORT_OFFSET`'s own doc names this exact path: "The sole path
    // that can quarantine it is a rotation whose own-epoch tun was brought up
    // and then torn straight back down by `handle_rotate`'s fail-closed
    // unwind; that holds the port for at most QUARANTINE and expires on its
    // own, so a reserved slot and the quarantine cannot wedge each other."
    //
    // True over 5 seconds — but a second directive issued INSIDE the window
    // fails at `plan_tunnel`, and nothing retries a `RotateDirective` (design
    // C1: `broker.rs::send_rotate_if_pending` fires once, driven only by
    // `ChangeEvent::KeyRotated`), so it is lost permanently. The gateway would
    // then sit at `Idle` with the epoch never advancing — which is
    // indistinguishable at step (iv) from the wedge itself, and would be a
    // FALSE RED blamed on B2.
    //
    // Production never hits this: rotations are minutes or days apart. Only a
    // test can issue two directives inside 5s.
    let quarantine_wait = TUNNEL_QUARANTINE + Duration::from_secs(3);
    eprintln!(
        "waiting {}s for the torn-down epoch's RESERVED own-tun port to leave tunnelset \
         quarantine before the second directive (see comment)",
        quarantine_wait.as_secs()
    );
    tokio::time::sleep(quarantine_wait).await;

    // Snapshot the stall-warning count and start the clock BEFORE the second
    // directive, so the assertion after it is a DELTA over this rotation only
    // and cannot be confused by anything the aborted rotation logged.
    let stall_before = pa.stderr_grep(STALL_WARN_MARKER).len();
    let rot2_start = Instant::now();

    // Same device for the mechanism pin below: a DELTA snapshotted here, so the
    // assertion is about what the SECOND directive caused and nothing else.
    // A file-wide count would happen to work today only because
    // `Role A minted epoch … on` is logged AFTER `submit_epoch_key`, which the
    // injected fault precedes — i.e. it would silently stop being
    // anchor-relative the moment the fault point moved later than submit.
    let stale_mints_before = pa
        .stderr_grep(&format!("Role A minted epoch {} on", r1.epoch))
        .len();

    let r2 = h
        .admin_client()
        .await
        .rotate_key(RotateKeyRequest {
            gateway_id: ga.id(),
        })
        .await
        .expect("Admin.RotateKey #2")
        .into_inner();
    eprintln!(
        "Admin.RotateKey #2 -> epoch {} — THE SUBJECT. (Not 1: the controller numbers epochs \
         MAX(epoch)+1 over its own rows and the aborted rotation's pending row survives there.)",
        r2.epoch
    );

    let (done2, states2) =
        poll_rotation_to_epoch(&h, ga.id(), r2.epoch, Duration::from_secs(120)).await;
    if !done2 {
        let phase = scrape_rotation_phase(&metrics_a);
        dump_diag(
            "second-rotation-never-happened",
            &[("gwA", &gwa), ("gwB", &gwb)],
            &[("gwA", &pa), ("gwB", &pb)],
        );
        pa.kill();
        pb.kill();
        panic!(
            "EXPECTED: EPOCH ADVANCED AFTER UNWIND. Got: THE WEDGE (BACKLOG item 9) — gwA's \
             SECOND rotation (to epoch {}) never completed \
             within 120s after its first one aborted. gwA's rotation phase is {phase:?} (it was \
             {phase_after_abort:?} right after the abort) — if it \
             is not \"idle\", `Rotation::on_directive` refused this directive because the failed \
             rotation left the phase parked, which is the bug B2 exists to close. Nothing \
             retries a RotateDirective (design C1: `broker.rs::send_rotate_if_pending` fires \
             once, driven only by `ChangeEvent::KeyRotated`), so a refused directive is a \
             PERMANENT wedge until the process restarts — silent, because the data plane keeps \
             working on the old key the whole time.\n\n\
             NOT to be confused with the tunnelset-quarantine interaction: that one makes the \
             FIRST directive's unwind leave the reserved own-tun port held for 5s, and this \
             test already waits it out before issuing the second directive (see the wait above \
             and `TUNNEL_QUARANTINE`). If the gateway's stderr shows `plan_tunnel` refusing the \
             reserved port, the wait has drifted from `tunnelset::QUARANTINE` and THAT is the \
             cause, not the wedge. debug_key_states: {states2:?}",
            r2.epoch
        );
    }
    eprintln!("SECOND ROTATION COMPLETE: {states2:?}");

    // MECHANISM PIN (architect ruling Rev 1.39/1.40).
    //
    // The headline above says the epoch advanced. This says WHY, so a future
    // regression in the controller's sentinel SELECTION goes red HERE — at the
    // mechanism — instead of three layers downstream as "the second rotation
    // never happened".
    //
    // Asserted on gwA's captured stderr rather than the controller's, because
    // `wiremesh_testkit::TestController` runs IN-PROCESS: its `eprintln!` goes
    // to this test binary's own stderr, and `GwProc::stderr_grep` reads a FILE
    // that a gateway SUBPROCESS's stderr was drained into. There is no
    // equivalent handle for an in-process controller, and redirecting this
    // process's fd 2 would swallow the `--nocapture` diagnostics every other
    // assertion here depends on. The gateway side carries the same
    // discriminating signal and is the stronger pin anyway: it evidences what
    // the gateway DID, not merely what the controller said.
    //
    //   post-fix : abort for r1, then a mint at r2 and none at r1
    //   pre-fix  : abort for r1, then a mint at R1 AGAIN — the stale sentinel
    //              re-directed — and never one at r2
    //
    // The trailing `" on"` is load-bearing: without it "minted epoch 1" also
    // matches "minted epoch 12".
    let aborted_for = format!("ROTATION ABORTED — rotation to epoch {} failed", r1.epoch);
    let minted_target = format!("Role A minted epoch {} on", r2.epoch);
    let minted_stale = format!("Role A minted epoch {} on", r1.epoch);

    assert!(
        !pa.stderr_grep(&aborted_for).is_empty(),
        "gwA never logged an abort for epoch {} — step (ii)'s injected fault did not fire for          the epoch the FIRST RotateKey created, so nothing below is interpretable.          stderr tail:\n{}",
        r1.epoch,
        pa.stderr_tail()
    );
    assert!(
        !pa.stderr_grep(&minted_target).is_empty(),
        "gwA never minted epoch {} — the epoch the SECOND RotateKey created. The rotation that          completed was for some OTHER epoch, so the headline assertion above passed for the          wrong reason.\n\n         THE MECHANISM THIS PINS: `broker.rs::send_rotate_if_pending` selects the epoch to          direct from the gateway's full row set. An aborted rotation leaves its OWN sentinel          `pending` row behind — there is no gateway->controller cancel RPC — so a selection          that does not prefer the NEWEST row re-directs the ABORTED epoch instead of the one          just created. The gateway then rotates to the stale epoch, and the correctly-targeted          directives that follow arrive while it is mid-rotation and are refused as re-entrant          (design C1: nothing retries them). Full derivation, evidence and the (A′) ruling:          docs/research/stale-sentinel-directive-after-abort.md.\n         stderr tail:\n{}",
        r2.epoch,
        pa.stderr_tail()
    );
    let stale_mints_after = pa.stderr_grep(&minted_stale).len();
    assert_eq!(
        stale_mints_after, stale_mints_before,
        "gwA re-minted epoch {} — the epoch whose rotation was deliberately ABORTED — {} more          time(s) after the abort. That is the stale-sentinel defect in its exact signature: the          controller re-directed the orphan instead of the epoch the second RotateKey created.          The pair can look perfectly healthy on the data plane while this happens, which is why          it is asserted on the log and not on traffic. See          docs/research/stale-sentinel-directive-after-abort.md.\n         stderr tail:\n{}",
        r1.epoch,
        // `saturating_sub`: `stderr_grep` yields an empty Vec on a read
        // failure, so `after` could read LOWER than `before`. A bare `-` would
        // then underflow and panic INSIDE the failure message, replacing a
        // clear diagnosis with an arithmetic backtrace.
        stale_mints_after.saturating_sub(stale_mints_before),
        pa.stderr_tail()
    );

    // The epoch advanced on the fabric; now prove the gateway actually moved
    // its data plane onto it rather than merely acknowledging the roster.
    let new_links = link_names(&gwa);
    let appeared: Vec<String> = new_links.difference(&base_links_a).cloned().collect();
    assert_eq!(
        appeared.len(),
        1,
        "after the second rotation gwA must be running exactly one NEW own-epoch device (its \
         boot tun having been retired). Devices now {new_links:?}, baseline {base_links_a:?}. \
         Two would mean the retire never ran; none would mean the cutover never happened and \
         the controller's promote was the ack-less 90s grace promote (recorded hazard §E), \
         i.e. the roster advertises a key this gateway is not serving on — R2."
    );
    let old_tun_gone = wait_until(Duration::from_secs(45), || {
        !link_names(&gwa).contains("wg0")
    });
    assert!(
        old_tun_gone,
        "gwA's boot tun `wg0` (the epoch it rotated AWAY from) was never torn down within 45s of \
         the second rotation completing. Make-before-break ends with the old Device's teardown; \
         leaving it up keeps the retired epoch's key loaded in boringtun and holds its port."
    );

    // CO-ASSERTION again, and again NOT the red condition for (iv).
    assert!(
        wait_until(Duration::from_secs(30), || ping_ok(&wla, "10.10.2.2")),
        "CO-ASSERTION: ICMP wlA -> wlB stopped passing after the second rotation completed. \
         Not the wedge — that is the post-cutover endpoint territory \
         (`docs/research/rotation-endpoint-and-port-model-is-broken.md`)."
    );

    // THE STALL CLOCK MUST HAVE BEEN RESET BY THE ABORTED ROTATION.
    //
    // An `Overlapping` spell begins in `handle_rotate` BEFORE `role_a` is set,
    // and `role_a` is cleared again at the retire signal — so a stall clock
    // tracked INSIDE `run_rotation_ticks`'s `if let Some(a) = role_a` guard is
    // never reset by a rotation that failed before `role_a` was assigned
    // (design §2.2: steps 1-8 all leave `role_a = None`). The next rotation
    // then inherits a stale `Instant` and the 90s stall warning fires
    // immediately on a perfectly healthy rotation — crying wolf about the
    // recorded hazard §E (the controller's ack-less grace promote) precisely
    // when nothing is wrong.
    //
    // This test is the scenario that reproduces it: a healthy rotation
    // IMMEDIATELY FOLLOWING an aborted one. A count DELTA rather than an
    // absolute count, so nothing the first rotation logged can affect it.
    //
    // The `elapsed` half is not a tolerance: past 90s of `Overlapping` the
    // warning is CORRECT, so it is only evidence of the stale-clock bug when
    // the rotation it covers finished inside the window.
    let rot2_elapsed = rot2_start.elapsed();
    let stall_after = pa.stderr_grep(STALL_WARN_MARKER).len();
    eprintln!(
        "rotation 2 completed in {:?}; stall-warning lines before={stall_before} after={stall_after}",
        rot2_elapsed
    );
    assert!(
        stall_after == stall_before || rot2_elapsed >= STALL_WARN_AFTER,
        "gwA emitted {} new stall warning(s) during a rotation that completed in {:?} — inside \
         the {}s threshold, so the warning cannot be legitimate. The stall clock was not reset \
         by the preceding ABORTED rotation: an `Overlapping` spell starts before `role_a` is \
         set and steps 1-8 of `handle_rotate` all fail with `role_a` still `None`, so a clock \
         tracked inside the tick's `if let Some(a) = role_a` guard never sees the reset and the \
         next rotation inherits a stale `Instant`. Track the spell unconditionally, above the \
         guard. New lines:\n{:?}",
        stall_after - stall_before,
        rot2_elapsed,
        STALL_WARN_AFTER.as_secs(),
        pa.stderr_grep(STALL_WARN_MARKER)
    );

    // The durable store must have followed the data plane. This is the half
    // that could not have worked before Piece 2c (Rev 1.7): `EpochKeys` used
    // to mint at its OWN `max+1`, which agreed with the controller only by
    // accident — an aborted rotation's `pending` row survives controller-side
    // while `discard_pending` removes the local one, so after this test's
    // first (failed) rotation the two counters had drifted by one. The
    // cutover's `ek.promote(directive_epoch)` then failed against a store that
    // had filed the key under a different number, epoch 0 was never demoted to
    // `"retiring"`, and `service_retire`'s `retire(0)` failed too — so the
    // RETIRED PRIVATE KEY stayed on disk. Piece 2c mints at the directive
    // epoch, which is what makes the two assertions below reachable at all.
    let store_after_2 = load_store(sda.path());
    assert_eq!(
        store_after_2.active().map(|k| k.epoch),
        Some(r2.epoch),
        "the durable store must record the epoch the data plane actually cut over to. A store \
         that disagrees reboots the gateway onto a key the fabric no longer advertises \
         (`EpochKeys::select_boot_key` branch 1 selects by STATE), and — because `promote` \
         failed — never demotes the old epoch to \"retiring\", which is the only state \
         `retire` will destroy. Store: {:?}",
        store_after_2.epochs
    );
    assert!(
        !raw_store(sda.path()).contains(&base_active_priv),
        "SECURITY: the RETIRED epoch's private key is still in gwA's epoch_keys.json after the \
         second rotation completed. Retirement is key DESTRUCTION in that file, not a state \
         flag next to a still-readable key (epochkeys.rs module docs). This is B2's own \
         acceptance criterion on the one rotation B2 exists to make work — the retry after an \
         abort."
    );
    assert!(
        !store_after_2.epochs.iter().any(|k| k.state == "pending"),
        "no orphan mint may survive the second rotation either: store {:?}",
        store_after_2.epochs
    );

    pa.kill();
    pb.kill();
}
