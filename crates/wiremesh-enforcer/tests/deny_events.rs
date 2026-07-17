//! Task 10, Step 1 (test author): failing tests for the deny-event ring
//! buffer + in-kernel sampling (`.superpowers/sdd/task-10-brief.md`). These
//! drive the real `wiremesh-enforcer` public API (`probe`/`apply`/
//! `counters`/`deny_events`) — that API does NOT change in Task 10
//! (`DenyEvent`/`EnforcerConfig::log_per_rule`/`log_aggregate` already exist,
//! per Task 7/9, just unconsumed) — only the kernel program + `ebpf.rs`
//! internals it drives are new. New file (not appended to
//! `tests/ebpf_backend.rs`, despite the brief's file list, per this task's
//! explicit test-author guidance: keep suites small, one file per task's
//! Step-1 scope, same convention `tests/flow_table.rs` already established
//! over appending to an ever-growing shared file).
//!
//! **Current (Task 9) state**: `EbpfEnforcer::deny_events` (`src/ebpf.rs`) is
//! an honest stub returning `Ok(Vec::new())` unconditionally — there is no
//! `DENY_RB` ring buffer map, no kernel-side event emission, and no in-kernel
//! per-rule/aggregate token-bucket sampling anywhere (`common/src/lib.rs`'s
//! `CONFIG` map only has 4 slots today: `CFG_TCP_NS`/`CFG_UDP_NS`/
//! `CFG_ICMP_NS`/`CFG_RATE_CAP` — the brief's indices 4/5 for per-rule/
//! aggregate sampling rates don't exist yet either). `Counters.by_rule`/
//! `default_deny`, by contrast, are real and correct since Task 8 — every
//! matched/default-denied packet always bumps its counter regardless of
//! whether an event would ever be sampled (design §5.3: "counters always
//! count"). This split is exactly what makes (c) below a clean two-part RED/
//! GREEN split today: its counter assertion already passes, its event-count
//! assertion doesn't.
//!
//! **Single-SYN technique** ((a)/(b)): a plain Python `connect()` with a
//! 0.3s socket timeout. A denied SYN is dropped by the ingress classifier's
//! `TC_ACT_SHOT` before it ever reaches the destination's IP stack, so no
//! RST is ever generated — the client's `connect()` simply times out
//! (`socket.timeout`), same mechanism `tests/generations.rs`'s
//! `tcp_connect_from` already relies on for its 2s-timeout allow/deny
//! signal. 0.3s is comfortably under Linux's ~1s initial SYN retransmission
//! timer (RFC 6298's minimum RTO), so exactly ONE SYN crosses the wire
//! before the client gives up and closes the socket — no second SYN is ever
//! sent for the ring buffer to (correctly) also report.
//!
//! **UDP blast technique** ((c)): a single UDP socket sending 100 datagrams
//! in a tight in-process Python loop — no per-datagram process spawn, no
//! artificial delay — comfortably completes in low milliseconds, i.e. well
//! within the brief's "<1s" window that `log_per_rule`'s per-second budget
//! is defined against.
//!
//! RED evidence for all three (empirically verified — see
//! `.superpowers/sdd/task-10-tests-report.md`): (a)/(b) fail on "expected 1
//! event, got 0" (the stub's always-empty `Vec`); (c)'s counter assertion
//! (by_rule == 100) already passes today, while its event-count assertion
//! (`>= 5`) fails on "got 0 events".

mod lab {
    use natlab::{Lab, Ns};
    use std::io::Write;

    fn wg_keypair() -> (String, String) {
        let priv_out = std::process::Command::new("wg")
            .arg("genkey")
            .output()
            .unwrap();
        let privkey = String::from_utf8(priv_out.stdout).unwrap().trim().to_string();
        let pub_out = {
            let mut c = std::process::Command::new("wg")
                .arg("pubkey")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            c.stdin.as_mut().unwrap().write_all(privkey.as_bytes()).unwrap();
            c.wait_with_output().unwrap()
        };
        (privkey.clone(), String::from_utf8(pub_out.stdout).unwrap().trim().to_string())
    }

    /// Returns a running lab: overlay 10.10.0.1 <-> 10.10.0.2 over underlay
    /// 10.9.1.0/24, `wg0` created via the KERNEL WireGuard implementation
    /// directly inside each namespace. Verbatim copy of
    /// `tests/generations.rs`'s/`tests/flow_table.rs`'s identical helper
    /// (see those files' doc comments for the full rationale) — `#[path]`-
    /// free per this crate's established per-file self-sufficiency
    /// convention. Distinct `Lab::new` prefix (`"aeth10"`) so this file's
    /// netns/veth names never collide with another test binary's lab
    /// running concurrently.
    pub fn wg_lab() -> (Lab, Ns, Ns) {
        let mut lab = Lab::new("aeth10").unwrap();
        let a = lab.ns("a").unwrap();
        let b = lab.ns("b").unwrap();
        lab.veth((&a, "u0", "10.9.1.1/24"), (&b, "u1", "10.9.1.2/24")).unwrap();

        let (apriv, apub) = wg_keypair();
        let (bpriv, bpub) = wg_keypair();

        for (ns, privkey, peer_pub, my_ip, _peer_ip, peer_ep) in [
            (&a, &apriv, &bpub, "10.10.0.1/24", "10.10.0.2", "10.9.1.2:51820"),
            (&b, &bpriv, &apub, "10.10.0.2/24", "10.10.0.1", "10.9.1.1:51820"),
        ] {
            ns.exec(&["ip", "link", "add", "wg0", "type", "wireguard"]).unwrap();
            let kf = format!("/tmp/{}.key", ns.name);
            std::fs::write(&kf, privkey).unwrap();
            ns.exec(&[
                "wg", "set", "wg0", "listen-port", "51820", "private-key", &kf,
                "peer", peer_pub, "allowed-ips", "10.10.0.0/24",
                "endpoint", peer_ep,
            ]).unwrap();
            ns.exec(&["ip", "addr", "add", my_ip, "dev", "wg0"]).unwrap();
            ns.exec(&["ip", "link", "set", "wg0", "up", "mtu", "1280"]).unwrap();
        }

        (lab, a, b)
    }
}

use lab::wg_lab;
use std::net::Ipv4Addr;
use std::time::Duration;
use wiremesh_enforcer::EnforcerConfig;
use wiremesh_policy::{compile, parse_policy, PolicyIR, SegmentDef};

/// See `tests/generations.rs`'s identical helper for the full rationale
/// (safe here for the same reason: libtest gives every `#[test]` fn its own
/// OS thread, and `setns` is scoped to the calling thread alone).
fn join_netns(ns_name: &str) -> anyhow::Result<()> {
    use std::os::unix::io::AsRawFd;
    let path = format!("/var/run/netns/{ns_name}");
    let file = std::fs::File::open(&path)
        .map_err(|e| anyhow::anyhow!("open {path}: {e}"))?;
    let rc = unsafe { libc::setns(file.as_raw_fd(), libc::CLONE_NEWNET) };
    if rc != 0 {
        anyhow::bail!(
            "setns({path}, CLONE_NEWNET) failed: {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

/// Exact per-host /32 segments — same as `tests/generations.rs`'s
/// `segments_exact`, duplicated per this crate's established per-file
/// self-sufficiency convention.
fn segments_exact() -> Vec<SegmentDef> {
    vec![
        SegmentDef { name: "seg-a".into(), cidrs: vec!["10.10.0.1/32".parse().unwrap()] },
        SegmentDef { name: "seg-b".into(), cidrs: vec!["10.10.0.2/32".parse().unwrap()] },
    ]
}

fn compile_with(yaml: &str, segs: &[SegmentDef], version: u64) -> PolicyIR {
    let src = parse_policy(yaml, segs)
        .unwrap_or_else(|errors| panic!("expected valid policy, got errors: {errors:?}"));
    compile(&src, segs, version)
        .unwrap_or_else(|errors| panic!("expected compile to succeed, got errors: {errors:?}"))
}

/// One-shot, blocking: a single TCP `connect()` attempt from `ns` to
/// `dst_ip:port` with a 0.3s socket timeout, always exiting 0 regardless of
/// outcome (we already know it must fail -- see this file's module doc for
/// why 0.3s guarantees exactly one SYN is ever sent). Exists purely to put
/// one denied SYN packet on the wire, not to report success/failure back to
/// the caller.
fn deny_one_syn(ns: &natlab::Ns, dst_ip: &str, port: u16) {
    let script = format!(
        r#"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(0.3)
try:
    s.connect(("{dst_ip}", {port}))
except Exception:
    pass
"#
    );
    ns.exec(&["python3", "-c", &script])
        .expect("one-shot single-SYN connect attempt (script itself always exits 0)");
}

/// Blocking: sends `count` UDP datagrams to `dst_ip:dst_port` from a single
/// socket in one tight in-process Python loop (no per-datagram process
/// spawn) -- comfortably completes in low milliseconds, well inside the
/// brief's "<1s" scenario window for (c)'s sampling test.
fn udp_blast(ns: &natlab::Ns, dst_ip: &str, dst_port: u16, count: u32) {
    let script = format!(
        r#"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range({count}):
    s.sendto(b"x", ("{dst_ip}", {dst_port}))
"#
    );
    ns.exec(&["python3", "-c", &script])
        .unwrap_or_else(|e| panic!("udp blast of {count} datagrams failed: {e:#}"));
}

// --- (a) one denied SYN -> exactly one DenyEvent, matching rule_id ------

/// A single explicit `deny: { proto: tcp, ports: [5222] }` rule (no other
/// rules -- irrelevant to this test, everything else already falls to
/// default-deny). One denied SYN from `a` to `b:5222` must drain to exactly
/// one `DenyEvent` whose `src`/`dst`/`proto`/`dport` match the packet and
/// whose `rule_id` matches the deny rule's own compiled `rule_id` (Some, not
/// None -- an EXPLICIT deny rule matched, not a fallthrough).
///
/// RED today: `deny_events()` is `Ok(Vec::new())` unconditionally (module
/// doc) -- `events.len() == 1` fails with `events.len() == 0`.
#[test]
fn one_denied_syn_yields_exactly_one_deny_event_with_matching_rule_id() {
    let (lab, a, b) = wg_lab();
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    let mut enforcer = wiremesh_enforcer::probe("wg0", EnforcerConfig::default())
        .expect("probe should load + attach eBPF on wg0");

    let segs = segments_exact();
    let yaml = "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - deny:
          proto: tcp
          ports: [5222]
";
    let ir = compile_with(yaml, &segs, 1);
    let deny_rule_id = ir.blocks[0].rules[0].rule_id.clone();

    enforcer.apply(&ir).expect("policy with a single explicit deny rule should apply");

    deny_one_syn(&a, "10.10.0.2", 5222);
    std::thread::sleep(Duration::from_millis(200));

    let events = enforcer.deny_events().expect("deny_events() should succeed");
    assert_eq!(
        events.len(),
        1,
        "expected exactly one DenyEvent for the single denied SYN, got: {events:?}"
    );
    let ev = &events[0];
    assert_eq!(ev.src, "10.10.0.1".parse::<Ipv4Addr>().unwrap(), "unexpected src: {ev:?}");
    assert_eq!(ev.dst, "10.10.0.2".parse::<Ipv4Addr>().unwrap(), "unexpected dst: {ev:?}");
    assert_eq!(ev.proto, 6, "unexpected proto (want tcp/6): {ev:?}");
    assert_eq!(ev.dport, 5222, "unexpected dport: {ev:?}");
    assert_eq!(
        ev.rule_id,
        Some(deny_rule_id),
        "event's rule_id should match the explicit deny rule that matched: {ev:?}"
    );

    drop(lab);
}

// --- (b) default-deny (no rule matched) -> rule_id: None ----------------

/// Empty policy (zero rules -- everything falls to the default-deny
/// fallback, never matching any explicit rule). One denied SYN must drain
/// to exactly one `DenyEvent` whose `rule_id` is `None` -- distinguishing
/// "no rule matched at all" from (a)'s "an explicit deny rule matched".
///
/// RED today: same stub as (a) -- `events.len() == 1` fails with `0`.
#[test]
fn default_deny_yields_deny_event_with_rule_id_none() {
    let (lab, a, b) = wg_lab();
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    let mut enforcer = wiremesh_enforcer::probe("wg0", EnforcerConfig::default())
        .expect("probe should load + attach eBPF on wg0");

    let empty_ir = PolicyIR { schema: 1, version: 0, blocks: vec![] };
    enforcer.apply(&empty_ir).expect("empty (default-deny) policy should apply");

    deny_one_syn(&a, "10.10.0.2", 5333);
    std::thread::sleep(Duration::from_millis(200));

    let events = enforcer.deny_events().expect("deny_events() should succeed");
    assert_eq!(
        events.len(),
        1,
        "expected exactly one DenyEvent for the single default-denied SYN, got: {events:?}"
    );
    let ev = &events[0];
    assert_eq!(ev.src, "10.10.0.1".parse::<Ipv4Addr>().unwrap(), "unexpected src: {ev:?}");
    assert_eq!(ev.dst, "10.10.0.2".parse::<Ipv4Addr>().unwrap(), "unexpected dst: {ev:?}");
    assert_eq!(ev.proto, 6, "unexpected proto (want tcp/6): {ev:?}");
    assert_eq!(ev.dport, 5333, "unexpected dport: {ev:?}");
    assert_eq!(
        ev.rule_id, None,
        "default-deny (no rule matched) must report rule_id: None, got: {ev:?}"
    );

    drop(lab);
}

// --- (c) sampling: bounded events, unbounded counting -------------------

/// A single explicit `deny: { proto: udp, ports: [6000] }` rule, with
/// `log_per_rule` overridden down to 5 (`log_aggregate` stays at its huge
/// default of 100, so only the per-rule budget is in play here -- all 100
/// packets match this ONE rule). 100 denied UDP datagrams, sent from a
/// single socket in one tight loop (`udp_blast`, comfortably <1s), must
/// yield:
///
///  - `counters().by_rule[deny_rule_id] == 100` -- counters always count,
///    independent of sampling (design §5.3), asserted FIRST as the
///    always-true guard: this half is already correct today (Task 8's
///    per-rule counters), so it is not this test's RED driver.
///  - `deny_events()` returns *some* events (the per-rule token-bucket
///    budget lets a handful through before the budget is exhausted) but
///    nowhere near all 100 -- bounded to `>= 5` (the configured budget,
///    with a little slack for timing/token-bucket implementation
///    differences) and `<= 20` (generous headroom above the budget, chosen
///    so an "emit everything" implementation -- which would report 100 --
///    unambiguously fails this ceiling).
///
/// RED today: the counter half already passes (Task 8). The event-count
/// half fails: `deny_events()` is the always-empty stub, so `events.len()
/// >= 5` fails with `0`.
#[test]
fn sampling_bounds_events_while_counter_still_counts_all_100() {
    let (lab, a, b) = wg_lab();
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    let cfg = EnforcerConfig { log_per_rule: 5, ..EnforcerConfig::default() };
    let mut enforcer =
        wiremesh_enforcer::probe("wg0", cfg).expect("probe should load + attach eBPF on wg0");

    let segs = segments_exact();
    let yaml = "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - deny:
          proto: udp
          ports: [6000]
";
    let ir = compile_with(yaml, &segs, 1);
    let deny_rule_id = ir.blocks[0].rules[0].rule_id.clone();

    enforcer
        .apply(&ir)
        .expect("policy with a single explicit deny rule (log_per_rule: 5) should apply");

    udp_blast(&a, "10.10.0.2", 6000, 100);
    std::thread::sleep(Duration::from_millis(200));

    // Always-true guard: counters always count, regardless of sampling.
    let counters = enforcer.counters().expect("counters() should succeed");
    assert_eq!(
        counters.by_rule.get(&deny_rule_id).copied().unwrap_or(0),
        100,
        "the deny rule's own by_rule counter must count all 100 denied datagrams regardless of \
         event sampling: {:?}",
        counters.by_rule
    );

    // This test's actual RED driver: sampled, bounded event emission.
    let events = enforcer.deny_events().expect("deny_events() should succeed");
    assert!(
        events.len() >= 5 && events.len() <= 20,
        "expected a bounded, budget-shaped number of deny events (>=5 for log_per_rule=5, <=20 \
         generous ceiling so 'emit everything' unambiguously fails), got {} events: {events:?}",
        events.len()
    );

    drop(lab);
}
