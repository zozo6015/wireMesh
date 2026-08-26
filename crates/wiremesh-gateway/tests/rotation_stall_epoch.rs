//! PR4b pin: the `ROTATION STALLED` diagnostic must name the DIRECTIVE epoch.
//!
//! ./dev.sh run "cargo build -p wiremesh-gateway && cargo test -p wiremesh-gateway \
//!   --test rotation_stall_epoch --features netns-tests -- --test-threads=1 --nocapture"
//!
//! # The defect
//!
//! `run_rotation_ticks`' stall warning derived its epoch as `a.old_epoch + 1`.
//! That agrees with the truth only while directive epochs are contiguous —
//! and after a B2 abort they are not. The controller allocates
//! `MAX(epoch) + 1` over its OWN rows and the aborted epoch's row survives
//! (there is no gateway->controller cancel RPC), so the sequence runs
//! 0 active, 1 aborted, 2 directed. `old_epoch + 1` then names **1**: an
//! epoch this gateway aborted and does not hold, printed in the one
//! diagnostic an operator reads when a rotation is stuck.
//! See `docs/research/stale-sentinel-directive-after-abort.md`.
//!
//! The buggy line is INTERNALLY INCONSISTENT, which is what makes a red here
//! immediately legible: it names tun `wg0e2` — correct, derived from the
//! directive epoch — and epoch `1` in the same sentence.
//!
//! # Why this file exists rather than an assertion in `rotation_wedge.rs`
//!
//! That file's stall assertion is an ABSENCE check: a healthy rotation must
//! emit no stall warning. It therefore must NEVER set the threshold override —
//! lowering it there would make a correct system red. This file sets the knob
//! and asserts the warning's CONTENT; the two are complementary and neither
//! substitutes for the other.
//!
//! # How the stall is reached without 90s of wall clock
//!
//! Not by waiting, and not by hoping a healthy pre-cutover window is long
//! enough — by an R2 PARK, which makes the `Overlapping` spell UNBOUNDED:
//!
//!   1. rotation 1 is aborted by the fault hook (epoch 1 minted, scrubbed,
//!      active still 0). No stall line can fire during it: the emission sits
//!      inside `if let Some(a) = role_a`, and every fault point fires BEFORE
//!      `role_a` is set. The spell clock resets on any non-`Overlapping`
//!      phase, so the aborted rotation leaves nothing behind.
//!   2. gwB is SIGSTOPped — deliberately not killed, so its Sync stream stays
//!      open and gwA's watch set stays non-empty. This is a genuine R2 ("no
//!      peer ever rx-corroborates"), not an empty-watch-set R3, which is a
//!      different documented park with a different warning.
//!   3. rotation 2 is directed. gwA mints, brings the tun up and submits (the
//!      controller is up), so `role_a` becomes `Some` and the phase is
//!      `Overlapping` — with nothing left alive to corroborate it.
//!   4. The spell therefore never ends, and exactly one `ROTATION STALLED`
//!      line fires once the lowered threshold elapses (`warned_overlap_stall`
//!      is a one-shot latch per spell).
//!
//! Because the window is unbounded, the knob's one-second granularity is
//! sufficient and no measurement of a healthy window is needed.
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

/// The `netns-tests`-gated fault hook, armed on gwA only. Same value
/// `rotation_wedge.rs` uses: the deepest point, leaving the maximal residue.
const FAIL_ROTATION_ENV: &str = "WIREMESH_TEST_FAIL_ROTATION";
const FAIL_ROTATION_VALUE: &str = "after-enforcer-insert";

/// The `netns-tests`-gated stall-threshold override
/// (`config::fault::OVERLAP_STALL_WARN_ENV`), armed on gwA only.
/// `OVERLAP_STALL_WARN` itself stays 90s and remains the production value.
const STALL_WARN_ENV: &str = "WIREMESH_TEST_OVERLAP_STALL_WARN_SECS";
/// Low enough to fire promptly inside an UNBOUNDED park, high enough not to
/// fire on a tick that merely happens to observe `Overlapping` in passing.
const STALL_WARN_SECS: &str = "3";

/// Mirrors `tunnelset::QUARANTINE`, which is private — the same
/// mirror-with-a-comment device `rotation_wedge.rs` and
/// `rotation_slot_quarantine.rs` use. If the production constant moves, the
/// wait before rotation 2 must move with it.
const TUNNEL_QUARANTINE: Duration = Duration::from_secs(5);

/// Token of the line under test. PINNED ANCHOR — `main.rs` carries a matching
/// `TEST ANCHOR` comment. Also greped as an ABSENCE check by
/// `rotation_wedge.rs::STALL_WARN_MARKER`; keep both in step.
const STALL_WARN_MARKER: &str = "ROTATION STALLED";

/// The abort anchor, used to scope this file's stderr search to the
/// post-abort spell.
const ABORT_ANCHOR: &str = "ROTATION ABORTED";

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

// --- root-netns shell helpers (duplicated from rotation_wedge.rs) ----------

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

// --- local additions (NOT part of the block duplicated above) ---------------

impl GwProc {
    /// Freeze the gateway process with SIGSTOP.
    ///
    /// `Ns::spawn` runs `nsenter … -- ip netns exec <ns> <bin>`, and both of
    /// those `exec` into the next rather than forking, so `child.id()` IS the
    /// gateway's own pid — signalling it stops the gateway, not a wrapper.
    ///
    /// SIGSTOP rather than SIGKILL is load-bearing: a stopped gwB keeps its
    /// Sync stream open, so gwA's watch set stays non-empty and the resulting
    /// park is a genuine R2 ("a peer exists and never rx-corroborates"). A
    /// killed gwB would drain the watch set and produce an R3 empty-watch-set
    /// park instead — a different documented case with a different warning.
    fn stop(&self) {
        run_root_best_effort(&["kill", "-STOP", &self.child.id().to_string()]);
    }

    /// Undo [`stop`]. SIGKILL alone would terminate a stopped process, so this
    /// is not strictly required for teardown — it is here so the process is
    /// resumed deliberately rather than by relying on that, and so a stopped
    /// child can never outlive the netns it sits in.
    fn resume(&self) {
        run_root_best_effort(&["kill", "-CONT", &self.child.id().to_string()]);
    }
}

/// Every stderr line after the LAST occurrence of `ABORT_ANCHOR` — i.e. the
/// post-abort spell only.
///
/// Scoping matters and is exact rather than best-effort: the aborted rotation
/// cannot itself emit a stall line (the emission is inside
/// `if let Some(a) = role_a`, and every fault point fires before `role_a` is
/// set), so everything this returns belongs to the park.
fn stderr_after_abort(p: &GwProc) -> String {
    let all = std::fs::read_to_string(&p.err_log).unwrap_or_default();
    match all.rfind(ABORT_ANCHOR) {
        Some(i) => all[i..].to_string(),
        None => String::new(),
    }
}

// --- the pin ----------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stall_warning_names_the_directive_epoch_not_old_plus_one() {
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

    let mut lab = Lab::new("gwstall").expect("lab");
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

    // gwA carries BOTH knobs: fail the first directive, and lower the stall
    // threshold. gwB carries neither — it must behave exactly like production
    // right up until it is frozen.
    let mut pa = spawn_gw(
        &gwa,
        sda.path(),
        &sync_addr,
        &observe_addr,
        logdir.path(),
        "a",
        &[
            (FAIL_ROTATION_ENV, FAIL_ROTATION_VALUE),
            (STALL_WARN_ENV, STALL_WARN_SECS),
        ],
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

    assert!(
        wait_until(Duration::from_secs(45), || ping_ok(&wla, "10.10.2.2")),
        "SETUP FAILED: wlA -> wlB ICMP never passed before any rotation"
    );

    // ===== rotation 1: aborted by the fault hook =====
    let r1 = h
        .admin_client()
        .await
        .rotate_key(RotateKeyRequest {
            gateway_id: ga.id(),
        })
        .await
        .expect("Admin.RotateKey #1")
        .into_inner();
    let aborted = wait_until(Duration::from_secs(60), || {
        !pa.stderr_grep(ABORT_ANCHOR).is_empty()
    });
    if !aborted {
        pa.kill();
        pb.kill();
        panic!(
            "gwA never aborted its rotation to epoch {} — the fault hook did not fire, so the \
             park below cannot be set up. stderr tail:\n{}",
            r1.epoch,
            pa.stderr_tail()
        );
    }
    eprintln!("rotation 1 (epoch {}) aborted as intended", r1.epoch);

    // ===== the R2 park: freeze gwB, then direct rotation 2 =====
    pb.stop();
    eprintln!("gwB SIGSTOPped — nothing can rx-corroborate gwA's next epoch from here");

    // WAIT OUT THE TUNNEL QUARANTINE BEFORE DIRECTING ROTATION 2 — a
    // precondition of the scenario, not a tolerance. `rotation_wedge.rs`
    // already encodes the same wait for the same reason; omitting it here is
    // what made the first version of this test red on its own park guard,
    // never reaching the assertion it exists for.
    //
    // The unwind's tear-down of `TunnelId::Own { epoch }` puts that tun's
    // ifname AND listen port into `TunnelSet`'s quarantine for
    // `tunnelset::QUARANTINE`, and `plans()` reports quarantined entries as
    // taken. An own-epoch tun's port is the RESERVED
    // `base + OWN_TUN_PORT_OFFSET`, and `plan_tunnel` REFUSES rather than
    // falling back when it is held — so a directive issued inside the window
    // dies at plan time ("the reserved own-epoch listen port … is not
    // available"), unwinds, and is LOST, because nothing retries a
    // RotateDirective (design C1). `role_a` is then never set, and the stall
    // emission lives inside `if let Some(a) = role_a`.
    //
    // That lost-directive window is BACKLOG item 34 — a real, 5s-bounded
    // production gap. This test is not asserting on it; it steps over it,
    // which is why the wait is a fixture concern and not a tolerance.
    let quarantine_wait = TUNNEL_QUARANTINE + Duration::from_secs(3);
    eprintln!(
        "waiting {}s for the aborted epoch's RESERVED own-tun port to leave tunnelset \
         quarantine before directing rotation 2 (BACKLOG item 34)",
        quarantine_wait.as_secs()
    );
    tokio::time::sleep(quarantine_wait).await;

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
        "rotation 2 directed at epoch {} (buggy code will name {} instead)",
        r2.epoch, r1.epoch
    );

    // ===== the stall line of the post-abort spell =====
    let stalled = wait_until(Duration::from_secs(90), || {
        stderr_after_abort(&pa).contains(STALL_WARN_MARKER)
    });
    let post_abort = stderr_after_abort(&pa);
    let stall_lines: Vec<&str> = post_abort
        .lines()
        .filter(|l| l.contains(STALL_WARN_MARKER))
        .collect();

    if !stalled {
        pb.resume();
        pa.kill();
        pb.kill();
        panic!(
            "THE PARK FAILED — no `{STALL_WARN_MARKER}` line appeared within 90s of directing \
             rotation {}. This is NOT the epoch-naming defect under test; something upstream of \
             it did not happen. In order of likelihood: gwB was not actually frozen (so a peer \
             corroborated and the rotation cut over, ending the spell); rotation 2 never got \
             past `submit_epoch_key`, so `role_a` was never set and the emission — which sits \
             inside `if let Some(a) = role_a` — is unreachable; the `{STALL_WARN_ENV}` \
             override did not take effect and the real 90s threshold applied; or — the one that \
             actually happened when this test was first written — rotation 2 was directed \
             INSIDE the tunnelset quarantine window and died at `plan_tunnel` with \"the \
             reserved own-epoch listen port … is not available\", so `role_a` was never set \
             (BACKLOG item 34). The wait before rotation 2 exists to prevent exactly that, so \
             if you see that line in the stderr below, check the wait against \
             `tunnelset::QUARANTINE`. gwA stderr since the abort:\n{post_abort}",
            r2.epoch
        );
    }

    assert_eq!(
        stall_lines.len(),
        1,
        "expected exactly ONE stall line for the post-abort spell — `warned_overlap_stall` is a \
         one-shot latch per spell, so more than one means the latch or the spell tracking has \
         regressed, and zero cannot reach here. Lines:\n{stall_lines:#?}"
    );

    let line = stall_lines[0];
    let wanted = format!("advertising epoch {}", r2.epoch);
    let buggy = format!("advertising epoch {}", r1.epoch);
    pb.resume();
    pa.kill();
    pb.kill();

    assert!(
        line.contains(&wanted),
        "the ROTATION STALLED line names the WRONG epoch. It must derive the epoch from the \
         PHASE (`Overlapping {{ new_epoch }}`), never from `old_epoch + 1`: after a B2 abort \
         directive epochs SKIP — 0 active, {} aborted, {} directed — so `old_epoch + 1` names \
         an epoch this gateway aborted and does not hold.\n\n\
         Note the line is INTERNALLY INCONSISTENT, which is the quickest way to see it: it \
         names the tun `wg0e{}` (correct — that IS derived from the directive epoch) beside \
         the epoch it claims. Expected to contain {wanted:?}{}.\n\n\
         Line:\n{line}",
        r1.epoch,
        r2.epoch,
        r2.epoch,
        if line.contains(&buggy) {
            format!(", found {buggy:?} instead")
        } else {
            String::new()
        }
    );
}
