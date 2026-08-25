//! Task 9, Step 1 (test author): failing netns tests for kernel program v3 —
//! flow table v2 (`.superpowers/sdd/task-9-brief.md`): per-protocol idle
//! timeouts, both-directions refresh-on-traffic, a per-source egress
//! new-entry rate cap, and `flush_flows()` forcing full re-evaluation. These
//! drive the real `wiremesh-enforcer` public API (`probe`/`apply`/
//! `flush_flows`) — that API does NOT change in Task 9 (`EnforcerConfig`'s
//! `flow_max`/`*_idle_s`/`rate_cap_per_src` fields already exist, per Task 7,
//! just unconsumed) — only the kernel + `ebpf.rs` internals it drives are
//! new. New file (not appended to `tests/generations.rs`, which is already
//! big and slow) per the coordinator's guidance.
//!
//! Tiny config throughout (`tiny_cfg()` below): `flow_max: 64`,
//! `udp_idle_s: 2`, `rate_cap_per_src: 8` — small enough to exercise
//! idle-expiry and the rate cap in a few seconds of wall time rather than
//! the design's real-world defaults (`udp_idle_s: 60`, `rate_cap_per_src:
//! 256`, etc.).
//!
//! **Current (Task 8) state, and RED-verification results (empirical, not
//! assumed — see `.superpowers/sdd/task-9-tests-report.md`)** (checked
//! against `crates/wiremesh-enforcer-ebpf/common/src/lib.rs` and
//! `crates/wiremesh-enforcer-ebpf/program/src/main.rs` as they stand after
//! Task 8): 3 of the 5 tests below (a, b, d) RED for genuine Task-9-shaped
//! behavioral reasons. The remaining 2 (c, e) are **empirically GREEN
//! today** — `flush_flows()` and `apply()`'s independence from `FLOWS` are
//! pre-existing Task 7/8 behavior, wholly outside Task 9's actual scope (see
//! each test's own doc comment for why manufacturing an artificial RED for
//! them would either test something the brief didn't ask for or confound
//! them with (a)/(b)'s idle-timeout mechanism). Both are kept as one of the
//! five Step 1 tests the brief lists, and are valuable regression guards for
//! the Task 9 refactor (which changes `FLOWS`'s kernel-side value type and
//! adds timestamp bookkeeping to the exact hit paths they exercise).
//!
//! - `FLOWS` is `LruHashMap<FlowKey, u64>` — a bare presence marker, always
//!   `1u64`. `FlowVal { last_seen_ns }` exists in `common/src/lib.rs` but is
//!   not the map's value type yet, and nothing ever reads or writes a
//!   timestamp. `try_ingress`'s hit checks are pure existence checks
//!   (`FLOWS.get(&rev).is_some()`) with **no staleness check at all** — a
//!   `FlowKey` that starts existing today never stops existing (short of the
//!   65536-entry LRU's own capacity-driven eviction), regardless of how much
//!   real time passes. This is (a) and (b)'s RED reason: any assertion of
//!   the shape "denied once idle-expired" currently fails because it is
//!   never denied at all — the stale entry still matches and passes.
//! - There is no `CONFIG` map at all — `EnforcerConfig`'s `flow_max`/
//!   `tcp_idle_s`/`udp_idle_s`/`icmp_idle_s`/`rate_cap_per_src` are stored on
//!   `EbpfEnforcer::cfg` (`#[allow(dead_code)]`, see `ebpf.rs`) and never
//!   read by anything — `FLOWS`'s `max_entries` is the hardcoded literal
//!   `65536` in `program/src/main.rs`, not `cfg.flow_max`.
//! - There is no `RATE` map and no rate-cap logic anywhere — `try_egress`
//!   unconditionally `FLOWS.insert`s every packet's own key, with no notion
//!   of "new" vs. "refresh" and no per-source counting. This is (d)'s RED
//!   reason: a source blasting far more distinct new flows than
//!   `rate_cap_per_src` in under a second gets every single one recorded,
//!   uncapped.
//! - `flush_flows()` (`ebpf.rs`) and the FWD/REV lookup paths
//!   (`program/src/main.rs`'s `try_ingress`) are already fully correct and
//!   unrelated to Task 9's new pieces — `apply()` never touches `FLOWS`, and
//!   `flush_flows()` already deletes every entry. (c) and (e) exercise this
//!   pre-existing, correct machinery too, but each also has its own
//!   idle-timeout-dependent stage (see each test's doc comment) so the test
//!   as a whole is a genuine RED against Task 8's "nothing ever expires"
//!   behavior, not merely a regression guard for already-green code.

// (Task 12) `wg_lab`/`join_netns` graduated into `wiremesh-testkit`'s
// `netns` module -- see that module's doc comments for the full history
// (this file's previous inline `mod lab` + `fn join_netns` copies are now
// that module's single source of truth). `"aeth9"` is this file's distinct
// `wg_lab` prefix, unchanged from its pre-graduation `Lab::new("aeth9")`
// call -- kept so this file's netns/veth names still never collide with
// another test binary's lab running concurrently.
use std::process::Child;
use std::time::Duration;
use wiremesh_enforcer::EnforcerConfig;
use wiremesh_policy::{compile, parse_policy, PolicyIR, SegmentDef};
use wiremesh_testkit::netns::{join_netns, wg_lab, Ns};

/// This task's small config values throughout (brief: "small config values
/// (udp_idle_s: 2, flow_max: 64, rate_cap_per_src: 8)"). Every other field
/// keeps its (huge, real-world) default so nothing else in this file's tests
/// can be accidentally affected by an unrelated tiny timeout.
fn tiny_cfg() -> EnforcerConfig {
    EnforcerConfig {
        flow_max: 64,
        udp_idle_s: 2,
        rate_cap_per_src: 8,
        ..EnforcerConfig::default()
    }
}

/// Same as [`tiny_cfg`] but with a much larger `udp_idle_s` (60s, the
/// design's real default) instead of 2s, so (c) stays about apply()/flush
/// specifically and can never be confounded by (a)/(b)'s idle-timeout
/// mechanism: with `tiny_cfg`'s 2s window, ANY delay between establishing
/// the flow and probing it after the second `apply()` risks aging the entry
/// out on idle grounds alone, before `flush_flows()` is ever called, which
/// would silently turn (c) into an idle-timeout test.
///
/// (Backlog item 1 rewrote this rationale. It used to name a specific
/// delay: the ~10s `apply()` itself blocked on the reap grace before
/// returning. `apply()` no longer sleeps -- it publishes the deadline via
/// `apply_ready_at()` -- so (c)'s second apply now returns immediately and
/// its establish→probe gap is well under a second. That makes the confound
/// far less likely, NOT impossible, so the large window stays: it is cheap
/// insurance, and (c)'s subject has not changed.)
fn flush_test_cfg() -> EnforcerConfig {
    EnforcerConfig {
        flow_max: 64,
        rate_cap_per_src: 8,
        ..EnforcerConfig::default()
    }
}

fn segments_exact() -> Vec<SegmentDef> {
    vec![
        SegmentDef {
            name: "seg-a".into(),
            cidrs: vec!["10.10.0.1/32".parse().unwrap()],
        },
        SegmentDef {
            name: "seg-b".into(),
            cidrs: vec!["10.10.0.2/32".parse().unwrap()],
        },
    ]
}

fn compile_with(yaml: &str, segs: &[SegmentDef], version: u64) -> PolicyIR {
    let src = parse_policy(yaml, segs)
        .unwrap_or_else(|errors| panic!("expected valid policy, got errors: {errors:?}"));
    compile(&src, segs, version)
        .unwrap_or_else(|errors| panic!("expected compile to succeed, got errors: {errors:?}"))
}

fn empty_ir(version: u64) -> PolicyIR {
    PolicyIR {
        schema: 1,
        version,
        blocks: vec![],
    }
}

// --- packet-level helpers (no `nc`/`ncat`/`socat` in this image — python3
// one-shot scripts, same convention as tests/generations.rs) --------------

/// One-shot, blocking: binds a UDP socket to `bind_ip:bind_port` and sends a
/// single datagram to `dst_ip:dst_port`, then exits. Since this always
/// completes in well under a second, callers needing precise before/after
/// timing (idle-expiry / keep-alive tests) can sequence several calls with
/// explicit `sleep`s in between with no race against a lingering process.
fn udp_send_from(ns: &Ns, bind_ip: &str, bind_port: u16, dst_ip: &str, dst_port: u16) {
    let script = format!(
        r#"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("{bind_ip}", {bind_port}))
s.sendto(b"x", ("{dst_ip}", {dst_port}))
"#
    );
    ns.exec(&["python3", "-c", &script])
        .expect("one-shot udp send");
}

/// Spawns a one-shot UDP receiver bound to `0.0.0.0:port`, blocking up to
/// `timeout_s` for a single datagram. Always prints exactly `RECEIVED` or
/// `TIMEOUT` and exits 0 — never a nonzero exit, so `probe_received` alone
/// (reading stdout after `wait_with_output`) tells the whole story.
fn spawn_udp_recv_probe(ns: &Ns, port: u16, timeout_s: f64) -> Child {
    let script = format!(
        r#"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", {port}))
s.settimeout({timeout_s})
try:
    s.recvfrom(64)
    print("RECEIVED")
except socket.timeout:
    print("TIMEOUT")
"#
    );
    ns.spawn(&["python3", "-c", &script])
        .expect("spawn udp recv probe")
}

fn probe_received(child: Child) -> bool {
    let out = child
        .wait_with_output()
        .expect("udp recv probe should exit");
    String::from_utf8_lossy(&out.stdout).trim() == "RECEIVED"
}

// --- (a) idle timeout: passes within the window, denied once it expires --

/// `b` (running the enforcer) initiates one UDP datagram toward `a` — this
/// always passes (`try_egress` never blocks) and unconditionally records a
/// `FLOWS` entry keyed by `b`'s own outbound 5-tuple. The active policy is
/// EMPTY (default-deny for everything) throughout, so the ONLY way any
/// traffic back from `a` can ever pass `b`'s ingress classifier is the
/// flow table's reverse-continuation fast path (`try_ingress`'s check #1:
/// `FLOWS.get(&rev)`) — there is no rule that could independently allow it.
/// This isolates idle-expiry behavior cleanly: if the recorded entry is
/// still fresh, `a`'s reply passes; once `udp_idle_s` (2s, `tiny_cfg`) has
/// elapsed with no further traffic, it must be evicted and the next
/// identically-shaped packet from `a` must be denied outright (falls
/// through to the rule scan, which has nothing to match).
///
/// RED today: `try_ingress`'s hit checks are pure existence checks with no
/// staleness logic at all (see module doc) — the entry recorded at t0 never
/// expires, so `a`'s SECOND reply (sent well past the 2s idle window) is
/// still (incorrectly) received by `b`'s listener.
#[test]
fn udp_flow_passes_within_idle_window_then_is_denied_after_expiry() {
    let (lab, a, b) = wg_lab("aeth9");
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    let mut enforcer = wiremesh_enforcer::probe("wg0", tiny_cfg())
        .expect("probe should load + attach eBPF on wg0");
    enforcer
        .apply(&empty_ir(1))
        .expect("empty (default-deny) policy should apply");

    // b initiates: records FLOWS{src=b,dst=a,sport=6000,dport=7000} at t0.
    udp_send_from(&b, "10.10.0.2", 6000, "10.10.0.1", 7000);

    // Within the idle window: a's reply (the REVERSE of b's key) must pass
    // via the flow table's fast path, despite there being no allow rule at
    // all for this (or any) traffic.
    let probe1 = spawn_udp_recv_probe(&b, 6000, 1.5);
    std::thread::sleep(Duration::from_millis(150));
    udp_send_from(&a, "10.10.0.1", 7000, "10.10.0.2", 6000);
    assert!(
        probe_received(probe1),
        "a's reply, sent well within the 2s udp idle window, should pass via the flow table's \
         reverse-continuation fast path even though no rule allows this traffic"
    );

    // Sleep past the 2s idle window (2.5-3s total since t0, no further
    // traffic in between to refresh it) -- the entry must now be stale.
    std::thread::sleep(Duration::from_millis(2700));

    // Past the idle window: the SAME 5-tuple must now be denied outright --
    // the stale entry is evicted on this very hit and the packet falls
    // through to the rule scan, which (empty policy) denies it.
    let probe2 = spawn_udp_recv_probe(&b, 6000, 1.5);
    std::thread::sleep(Duration::from_millis(50));
    udp_send_from(&a, "10.10.0.1", 7000, "10.10.0.2", 6000);
    assert!(
        !probe_received(probe2),
        "a's reply, sent well past the 2s udp idle window with no refreshing traffic in \
         between, must now be DENIED (the stale flow entry must be evicted, not kept alive \
         forever) -- default-deny has nothing else that could let it through"
    );

    drop(lab);
}

// --- (b) refresh-on-traffic: keep-alives extend the window; stopping ------
// --- them lets normal expiry resume ---------------------------------------

/// Companion to (a): proves BOTH halves of "both directions refresh, spec
/// §5.3" — (i) repeated hits keep a short-idle flow alive far past its own
/// raw timeout, one keep-alive at a time, and (ii) once traffic actually
/// stops, the flow is not immortal -- ordinary idle expiry still applies
/// after the fact. Same default-deny setup as (a): the flow table's reverse
/// path is the ONLY way any of `a`'s replies can ever pass.
///
/// RED today: since nothing ever expires currently (see module doc), the
/// keep-alive portion trivially "passes" today for the wrong reason -- the
/// REAL RED is the final stage: after keep-alives stop and the idle window
/// elapses, the next reply must be denied, and today it is not (still
/// received).
#[test]
fn keepalive_traffic_refreshes_the_idle_timer_but_stopping_lets_it_expire_again() {
    let (lab, a, b) = wg_lab("aeth9");
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    let mut enforcer = wiremesh_enforcer::probe("wg0", tiny_cfg())
        .expect("probe should load + attach eBPF on wg0");
    enforcer
        .apply(&empty_ir(1))
        .expect("empty (default-deny) policy should apply");

    // b initiates: records FLOWS{src=b,dst=a,sport=6050,dport=7050} at t0.
    udp_send_from(&b, "10.10.0.2", 6050, "10.10.0.1", 7050);

    // 6 keep-alives, ~1s apart -- each is a's reply on the SAME 5-tuple
    // (the reverse-continuation fast path), well inside the 2s idle window
    // relative to the PREVIOUS one. If each hit genuinely refreshes
    // last_seen, the flow survives this whole 6s span despite a 2s raw
    // idle timeout; if it didn't, this would already start failing well
    // before iteration 6 (last_seen frozen at t0 would go stale by ~t=3s).
    for i in 1..=6u32 {
        std::thread::sleep(Duration::from_millis(1000));
        let probe = spawn_udp_recv_probe(&b, 6050, 1.2);
        std::thread::sleep(Duration::from_millis(50));
        udp_send_from(&a, "10.10.0.1", 7050, "10.10.0.2", 6050);
        assert!(
            probe_received(probe),
            "keep-alive #{i} (sent ~1s after the previous hit, well inside the 2s idle window) \
             should keep passing -- each hit must refresh the flow's idle timer"
        );
    }

    // Now STOP sending -- sleep past the idle window with no further
    // traffic. The most recent keep-alive was the last refresh; it must not
    // grant the flow immortality.
    std::thread::sleep(Duration::from_millis(2700));
    let probe_final = spawn_udp_recv_probe(&b, 6050, 1.5);
    std::thread::sleep(Duration::from_millis(50));
    udp_send_from(&a, "10.10.0.1", 7050, "10.10.0.2", 6050);
    assert!(
        !probe_received(probe_final),
        "once keep-alives stop and the 2s idle window elapses with no further traffic, the flow \
         must expire like any other -- refresh-on-traffic must not make an entry immortal"
    );

    drop(lab);
}

// --- (c) flush_flows forces re-evaluation after a rule is removed --------

/// `a` establishes a flow legitimately (v1 allows udp/9600), proving the
/// allow-rule path AND the FWD-continuation fast path both work. v2 (empty,
/// no rule at all) is then applied -- per the design, `apply()` must NOT
/// itself disturb `FLOWS`, so the SAME still-recorded flow must keep passing
/// (a subsequent packet on the identical 5-tuple hits the FWD-continuation
/// check, bypassing the rule scan entirely). Only an explicit
/// `flush_flows()` call clears it, forcing the NEXT packet on that same
/// 5-tuple through the rule scan for real -- which (v2 has no rule) denies
/// it.
///
/// **Empirically GREEN today, not RED** (verified as part of this task's
/// RED-verification step, not assumed): `flush_flows()` (`ebpf.rs`) already
/// unconditionally deletes every `FLOWS` entry, and `apply_generation`
/// (also `ebpf.rs`) never touches `FLOWS` at all -- both are pre-existing,
/// correct Task 7/8 behavior, wholly untouched by Task 9's actual scope
/// (idle timeouts, refresh, the rate cap, and wiring `EnforcerConfig` into a
/// new `CONFIG` map). There is no genuine Task-9-shaped RED to manufacture
/// here without either testing something the brief didn't ask for or
/// confounding this test with (a)/(b)'s idle-timeout mechanism (see
/// [`flush_test_cfg`]'s doc comment for the specific confound this test
/// avoids by using a large `udp_idle_s` instead of the tiny 2s one).
/// Kept as one of the five Step 1 tests per the brief's explicit list, and
/// valuable as a regression guard: Task 9's implementer changes `FLOWS`'s
/// kernel-side value type from a bare `u64` to `FlowVal` and adds
/// timestamp bookkeeping to the exact hit paths this test exercises --
/// this test must stay green throughout that refactor.
#[test]
fn flush_flows_forces_reevaluation_of_an_established_flow_after_its_allow_rule_is_removed() {
    let (lab, a, b) = wg_lab("aeth9");
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    let mut enforcer = wiremesh_enforcer::probe("wg0", flush_test_cfg())
        .expect("probe should load + attach eBPF on wg0");

    let segs = segments_exact();
    let v1_yaml = "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow:
          proto: udp
          ports: [9600]
";
    let v1 = compile_with(v1_yaml, &segs, 1);
    enforcer
        .apply(&v1)
        .expect("v1 (single udp/9600 allow rule) must apply");

    // a establishes the flow: matches v1's allow rule at ingress, recording
    // FLOWS{src=a,dst=b,sport=8600,dport=9600}.
    let probe1 = spawn_udp_recv_probe(&b, 9600, 1.5);
    std::thread::sleep(Duration::from_millis(150));
    udp_send_from(&a, "10.10.0.1", 8600, "10.10.0.2", 9600);
    assert!(
        probe_received(probe1),
        "a's first udp/9600 packet should be allowed by v1's rule and establish a flow entry"
    );

    // v2: udp/9600's allow rule is REMOVED entirely (empty policy). This is
    // the SECOND apply(); since Backlog item 1 it returns immediately rather
    // than sleeping out v1's ~10s reap grace, so probe2 below runs a
    // fraction of a second after the flow was established rather than ~10s
    // later. No caller-side wait is added here on purpose: unlike (e),
    // nothing this test ASSERTS ON is in flight across the flip -- probe1's
    // exchange has completed and probe2 has not started. (That is weaker
    // than "the wire is silent": the netns fixtures can still have stray
    // teardown/retransmit segments crossing wg0, which is harmless for these
    // assertions -- do not reuse this reasoning where an in-flight flow IS
    // the subject.) Adding 10s of dead time would only make the suite
    // slower.
    let v2 = empty_ir(2);
    enforcer
        .apply(&v2)
        .expect("v2 (empty policy, udp/9600's allow rule removed) must apply");

    // Pre-flush: the SAME 5-tuple must still pass -- apply() must not have
    // touched FLOWS, so this hits the FWD-continuation fast path, bypassing
    // the (now rule-less) scan entirely.
    let probe2 = spawn_udp_recv_probe(&b, 9600, 1.5);
    std::thread::sleep(Duration::from_millis(150));
    udp_send_from(&a, "10.10.0.1", 8600, "10.10.0.2", 9600);
    assert!(
        probe_received(probe2),
        "the established flow must keep passing immediately after v2's apply() removed its \
         allow rule -- apply() must not itself disturb FLOWS (security-group semantics)"
    );

    // flush_flows(): clears FLOWS outright.
    enforcer
        .flush_flows()
        .expect("flush_flows() should succeed");

    // Post-flush: the SAME 5-tuple must now be denied -- the entry is gone,
    // so this falls through to the rule scan against v2 (no rule), which
    // default-denies it.
    let probe3 = spawn_udp_recv_probe(&b, 9600, 1.5);
    std::thread::sleep(Duration::from_millis(150));
    udp_send_from(&a, "10.10.0.1", 8600, "10.10.0.2", 9600);
    assert!(
        !probe_received(probe3),
        "after flush_flows(), the same 5-tuple must be re-evaluated against v2's rule set (which \
         no longer allows udp/9600) and denied"
    );

    drop(lab);
}

// --- (d) per-source rate cap: anti-churn guarantee ------------------------

/// Two extra IP aliases on `b`'s wg0 stand in for two distinct traffic
/// sources feeding `b`'s own egress path: `alias2` (10.10.0.22) establishes
/// exactly ONE flow, well before any pressure exists. `alias1` (10.10.0.12)
/// then blasts 100 distinct new UDP flows (fresh source ports 6300..6399,
/// same destination port) in a single tight in-process Python loop -- well
/// under 1 second, and far more than both `rate_cap_per_src` (8) and
/// `flow_max` (64, `tiny_cfg`). `try_egress` unconditionally records every
/// packet it sees today (module doc) with no per-source accounting at all,
/// so ALL 100 of `alias1`'s attempts land in the (tiny, 64-entry once wired)
/// `FLOWS` LRU today -- real churn that can evict ANY entry, including
/// `alias2`'s unrelated, already-established one (this is exactly the
/// "anti-churn" problem the cap exists to prevent: one noisy source must
/// not be able to starve another source's legitimate flow via LRU
/// eviction). With the cap correctly wired, `alias1` can only ever succeed
/// at inserting `rate_cap_per_src` (8) new entries per rolling window, so
/// total occupancy never approaches `flow_max` and `alias2`'s entry is
/// never at risk.
///
/// Exact `FLOWS` occupancy is not asserted (fragile, per this task's
/// guidance) -- two purely behavioral checks instead: (i, primary,
/// anti-churn) `alias2`'s pre-established flow must still pass after the
/// blast; (ii, secondary, direct cap effect) the LAST of the 100 blasted
/// flows (id 99, far beyond the cap in send order) must be denied when its
/// own reply is attempted, since its egress-side entry should never have
/// been recorded at all.
///
/// RED today: there is no `RATE` map and no rate-cap logic anywhere (module
/// doc) -- every one of the 100 blasted entries is recorded uncapped, so
/// (ii) fails today (the last blasted flow's reply is unexpectedly
/// received, since its entry does exist). (i) is asserted too as the
/// primary, brief-mandated anti-churn guarantee, though at this small scale
/// (101 total attempts vs. today's real, unwired 65536-entry `FLOWS`) it may
/// already hold trivially before `flow_max` is wired to the small
/// `tiny_cfg` value -- (ii) is what carries this test's genuine RED.
#[test]
fn per_source_rate_cap_prevents_one_blasting_source_from_evicting_another_sources_flow() {
    let (lab, a, b) = wg_lab("aeth9");
    b.exec(&["ip", "addr", "add", "10.10.0.12/32", "dev", "wg0"])
        .expect("add alias1 (the blasting source) on b's wg0");
    b.exec(&["ip", "addr", "add", "10.10.0.22/32", "dev", "wg0"])
        .expect("add alias2 (the innocent established source) on b's wg0");
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    let mut enforcer = wiremesh_enforcer::probe("wg0", tiny_cfg())
        .expect("probe should load + attach eBPF on wg0");
    enforcer.apply(&empty_ir(1)).expect(
        "empty (default-deny) policy should apply -- rate capping is an egress-side \
                 concern, independent of any rule content",
    );

    // alias2 establishes ONE flow, well before the blast:
    // FLOWS{src=10.10.0.22,dst=a,sport=6100,dport=7100}.
    udp_send_from(&b, "10.10.0.22", 6100, "10.10.0.1", 7100);
    let establish_probe = spawn_udp_recv_probe(&b, 6100, 1.5);
    std::thread::sleep(Duration::from_millis(100));
    udp_send_from(&a, "10.10.0.1", 7100, "10.10.0.22", 6100);
    assert!(
        probe_received(establish_probe),
        "alias2's flow must be established (its reply must pass) before the blast even starts"
    );

    // alias1 blasts 100 distinct new flows (sports 6300..6399, same dst
    // port 7300) in one tight in-process loop -- comfortably under 1s.
    let blast_script = r#"
import socket
n = 100
socks = []
for i in range(n):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("10.10.0.12", 6300 + i))
    socks.append(s)
for s in socks:
    s.sendto(b"x", ("10.10.0.1", 7300))
"#;
    b.exec(&["python3", "-c", blast_script])
        .expect("alias1's blast of 100 distinct new udp flows");

    // (i, primary, anti-churn guarantee) alias2's pre-established flow must
    // still pass, untouched by alias1's churn.
    let survive_probe = spawn_udp_recv_probe(&b, 6100, 1.5);
    std::thread::sleep(Duration::from_millis(100));
    udp_send_from(&a, "10.10.0.1", 7100, "10.10.0.22", 6100);
    assert!(
        probe_received(survive_probe),
        "alias2's established flow must still pass after alias1's 100-flow blast -- one noisy \
         source must not be able to evict another source's legitimate flow via LRU churn"
    );

    // (ii, secondary, direct cap effect) the LAST blasted flow (id 99, sport
    // 6399) is far beyond rate_cap_per_src (8) in send order -- its
    // egress-side entry should never have been recorded, so its reply must
    // be denied.
    let last_probe = spawn_udp_recv_probe(&b, 6399, 1.2);
    std::thread::sleep(Duration::from_millis(80));
    udp_send_from(&a, "10.10.0.1", 7300, "10.10.0.12", 6399);
    assert!(
        !probe_received(last_probe),
        "the last (99th, far beyond rate_cap_per_src=8) of alias1's blasted flows should have \
         been skipped at egress (never recorded), so its reply must be denied, not received"
    );

    drop(lab);
}

// --- (e) live-flow survival across apply, until flush (TCP) ---------------

/// TCP variant of (c)'s "apply doesn't disturb FLOWS, flush does" story,
/// using a real persistent connection to make the security-group framing
/// concrete: v1 allows tcp/9500; a client connects, completes one
/// request/ack round trip (r1). v2 (applied while that connection is still
/// open) REMOVES the tcp/9500 allow rule entirely. The SAME still-open
/// socket must still complete a SECOND round trip (r2) -- proving an
/// established connection isn't retroactively broken by a policy change
/// that stops allowing new ones (security-group semantics). Only after an
/// explicit `flush_flows()` does a THIRD round trip (r3) on that same
/// socket fail -- the data segment is silently dropped (no rule allows
/// tcp/9500 in v2, and the flow entry is gone), so the client's `recv()`
/// times out.
///
/// Timing (single long-lived client process, no cross-process signaling):
/// the client sleeps a fixed 10.5s after r1 before attempting r2, then a
/// further fixed 2.5s before attempting r3 -- the coordinating Rust thread
/// mirrors this with its own waits so `flush_flows()` is called strictly
/// between the client's r2 and r3 attempts. Same technique
/// `tests/generations.rs`'s
/// `old_generation_reap_does_not_break_in_flight_allowed_flow_and_new_gen_matches`
/// already uses for its own reap-grace synchronization.
///
/// **The 10.5s is the ~10s reap grace, and the Rust side must now wait it
/// out EXPLICITLY** (Backlog item 1). It used to be implicit: `apply(&v2)`
/// is the second apply, and `apply()` slept out the remainder of v1's grace
/// internally before returning, which is what put the flush after r2 -- the
/// margin was only ~0.7s. `apply()` no longer sleeps (it publishes the
/// deadline via `apply_ready_at()`), so the coordinator honors it before
/// `apply(&v2)`.
///
/// Drop that wait and, with `T` = client spawn (v1's flip at ~T-0.21, so
/// its deadline is ~T+9.79): `apply(&v2)` returns at ~T+0.31 instead of
/// ~T+9.80 and the flush fires at ~T+1.81 instead of ~T+11.30. That is the
/// flush moving **~9.5s earlier** -- and since r2 lands at ~T+10.6, the
/// flush goes from ~0.7s AFTER r2 to **~8.8s BEFORE** it. (Both figures get
/// quoted; they measure different things. ~9.5s is how far the flush moves,
/// ~8.8s is how far in front of r2 it ends up -- the latter is what an
/// observer instrumenting the r2/flush gap sees.) r2 then hits a flushed
/// table under the empty v2, times out, and both the R2 and R3 assertions
/// fail (R3 because the client guards it behind `if r2_ok:`).
///
/// **Empirically GREEN today, not RED** (same finding as (c), verified as
/// part of this task's RED-verification step): the flush/apply-independence
/// machinery this test exercises is already correct pre-Task-9 behavior.
/// `tiny_cfg` is safe to use here unmodified -- unlike (c), this test never
/// overrides `tcp_idle_s` away from its huge (7200s) default, so the ~11s
/// r1->r2 gap is nowhere near enough to risk a future idle-eviction
/// confound once Task 9 lands. Kept as one of the five Step 1 tests per the
/// brief's explicit list and as this task's TCP/security-group-framed
/// regression guard alongside (c)'s UDP variant.
#[test]
// A long-lived netns helper (traffic generator / listener). `wait()`ing on
// it here would block the suite forever, which is exactly what clippy's fix
// does. Teardown is by NAMESPACE DESTRUCTION -- `Lab`'s `Drop` runs
// `ip netns del`, which takes every process in the namespace with it -- so
// there is no orphan to reap and nothing for a `wait()` to accomplish.
#[allow(clippy::zombie_processes)]
fn live_tcp_flow_survives_apply_removing_its_rule_but_not_a_subsequent_flush() {
    let (lab, a, b) = wg_lab("aeth9");
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    let mut enforcer = wiremesh_enforcer::probe("wg0", tiny_cfg())
        .expect("probe should load + attach eBPF on wg0");

    let segs = segments_exact();
    let v1_yaml = "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow:
          proto: tcp
          ports: [9500]
";
    let v1 = compile_with(v1_yaml, &segs, 1);
    enforcer
        .apply(&v1)
        .expect("v1 (single tcp/9500 allow rule) must apply");

    let mut listener = spawn_ack_echo_listener(&b, 9500);
    std::thread::sleep(Duration::from_millis(200));

    let client = spawn_flow_persistence_client(&a, "10.10.0.2", 9500);
    std::thread::sleep(Duration::from_millis(300)); // let r1 land under v1

    // Backlog item 1: this is the SECOND apply(), so it overwrites the
    // outer-array slot v1's flip vacated -- honor v1's reap grace BEFORE it,
    // as every caller must now that `apply()` no longer sleeps it out
    // internally. Doing it here (not after) is both the contract-correct
    // placement and what reproduces this test's original coordinator
    // timeline exactly: the wait lands at ~v1_flip+10s, i.e. where
    // `apply(&v2)` used to RETURN, so `flush_flows()` below stays strictly
    // between the client's r2 (~t+10.6s) and r3 (~t+13.1s) attempts. Without
    // it the flush would jump ~8.8s earlier, to BEFORE r2, and r2 would be
    // denied -- see this test's doc comment.
    if let Some(t) = enforcer.apply_ready_at() {
        let now = std::time::Instant::now();
        if t > now {
            std::thread::sleep(t - now);
        }
    }
    let v2 = empty_ir(2);
    enforcer
        .apply(&v2)
        .expect("v2 (empty policy, tcp/9500's allow rule removed) must apply");

    // Land solidly past the client's r2 attempt (~t=10.5-10.8s from spawn)
    // before flushing -- r2 must observe the still-established flow, not a
    // just-flushed one.
    std::thread::sleep(Duration::from_millis(1500));
    enforcer
        .flush_flows()
        .expect("flush_flows() should succeed");

    let out = client
        .wait_with_output()
        .expect("flow-persistence client should exit");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("R1=OK"),
        "r1 (under v1) should have succeeded: stdout={stdout} stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("R2=OK"),
        "r2 (same socket, after v2's apply() removed the tcp/9500 rule, before flush) must \
         still succeed -- apply() must not disturb FLOWS: stdout={stdout} stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("R3=DENIED"),
        "r3 (same socket, after flush_flows()) must now be denied -- the flow entry is gone and \
         v2 has no rule allowing tcp/9500: stdout={stdout} stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let _ = listener.kill();
    drop(lab);
}

/// Accepts ONE connection and echoes a fixed `b"ack"` reply for every
/// message it receives, indefinitely. Adapted from `tests/generations.rs`'s
/// identical helper (different port parameter, kept local per this crate's
/// per-file self-sufficiency convention).
fn spawn_ack_echo_listener(ns: &Ns, port: u16) -> Child {
    let script = format!(
        r#"
import socket
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", {port}))
srv.listen(1)
conn, _ = srv.accept()
try:
    while True:
        data = conn.recv(64)
        if not data:
            break
        conn.sendall(b"ack")
except Exception:
    pass
"#
    );
    ns.spawn(&["python3", "-c", &script])
        .expect("spawn ack-echo listener")
}

/// Connects to `dst_addr:port` and performs THREE request/ack round trips
/// on the SAME socket, with fixed sleeps between them (see this test's doc
/// comment for the timing rationale): r1 immediately, r2 after a 10.5s
/// sleep (spans the coordinator's explicit `apply_ready_at()` wait for v1's
/// ~10s reap grace plus its v2 `apply()`), r3 after a further 2.5s sleep
/// (spans the coordinator's `flush_flows()` call). Prints exactly one
/// `R1=`/`R2=`/`R3=`
/// line per stage (`OK`/`FAIL` for r1/r2, `DENIED`/`PASSED` for r3) and
/// always exits 0, so the whole story is in stdout regardless of where a
/// stage fails.
fn spawn_flow_persistence_client(ns: &Ns, dst_addr: &str, port: u16) -> Child {
    let script = format!(
        r#"
import socket, time

r1_ok = False
r2_ok = False
r3_denied = False

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
try:
    s.connect(("{dst_addr}", {port}))
    s.sendall(b"r1")
    r1_ok = (s.recv(64) == b"ack")
except Exception:
    r1_ok = False

time.sleep(10.5)

if r1_ok:
    try:
        s.sendall(b"r2")
        r2_ok = (s.recv(64) == b"ack")
    except Exception:
        r2_ok = False

time.sleep(2.5)

if r2_ok:
    try:
        s.settimeout(2)
        s.sendall(b"r3")
        data = s.recv(64)
        r3_denied = (data != b"ack")
    except Exception:
        r3_denied = True

print(f"R1={{'OK' if r1_ok else 'FAIL'}}")
print(f"R2={{'OK' if r2_ok else 'FAIL'}}")
print(f"R3={{'DENIED' if r3_denied else 'PASSED'}}")
"#
    );
    ns.spawn(&["python3", "-c", &script])
        .expect("spawn flow-persistence client")
}
