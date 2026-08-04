//! Task 8, Step 1 (test author): failing netns tests for kernel program v2 —
//! LPM-bitset first-match matching + map-in-map atomic generations
//! (`.superpowers/sdd/task-8-brief.md`). These exercise the five behaviors
//! the brief's Step 1 lists, (a)-(e), against the real `wiremesh-enforcer`
//! public API (`probe`/`apply`/`counters`) — that API does NOT change in
//! Task 8, only the kernel + `ebpf.rs` internals it drives, so these tests
//! drive behavior only: policies compiled via `wiremesh_policy`, packet
//! outcomes over the same kernel-WireGuard netns lab `tests/ebpf_backend.rs`
//! established in Task 7, and `Counters` by `rule_id`.
//!
//! `mod lab` and `join_netns` below are a verbatim copy of
//! `tests/ebpf_backend.rs`'s (see that file's doc comments for the full
//! rationale) — kept `#[path]`-free and duplicated per this crate's
//! established per-file self-sufficiency convention (each integration test
//! binary is its own `cargo test` target with no shared `common` module).
//!
//! RED evidence (current state, Task 7 landed): `crates/wiremesh-enforcer/
//! src/ebpf.rs`'s `apply_flat_rules` keeps the spike's fixed 64-entry A/B
//! `Array<Rule>` tables and bails with an `Err` (not a panic) the moment the
//! exploded rule count exceeds 64 (`RULE_TABLE_CAPACITY`). Every test below
//! pads its policy to 70+ inert rules specifically so it hits that capacity
//! bail via `.expect(...)` — a real, current-behavior RED reason (not a
//! fabricated one), and exactly what Task 8's map-in-map generations (lifting
//! the cap to `MAX_RULES` = 256) are supposed to fix. `counters().by_rule`
//! is also always empty today (Task 7 brief: "`by_rule` stays empty"), a
//! second independent RED reason behind (a)'s counter assertions, reached
//! only once Task 8 lifts the capacity cap.

// (Task 12) `wg_lab`/`join_netns` graduated into `wiremesh-testkit`'s
// `netns` module -- see that module's doc comments for the full history
// (this file's previous inline `mod lab` + `fn join_netns` copies are now
// that module's single source of truth). `"aeth8"` is this file's distinct
// `wg_lab` prefix, unchanged from its pre-graduation `Lab::new("aeth8")`
// call -- kept so this file's netns/veth names still never collide with
// another test binary's lab running concurrently.
use std::process::Child;
use std::time::Duration;
use wiremesh_policy::{compile, parse_policy, PolicyIR, SegmentDef};
use wiremesh_testkit::netns::{join_netns, wg_lab, Ns};

// --- policy fixtures --------------------------------------------------

/// Exact per-host /32 segments, named so `from`/`to` read naturally — used
/// by tests (a), (d), (e), which only care about point-to-point traffic
/// between the lab's two actual hosts, not segment-CIDR-width semantics.
fn segments_exact() -> Vec<SegmentDef> {
    vec![
        SegmentDef { name: "seg-a".into(), cidrs: vec!["10.10.0.1/32".parse().unwrap()] },
        SegmentDef { name: "seg-b".into(), cidrs: vec!["10.10.0.2/32".parse().unwrap()] },
    ]
}

/// Whole-subnet /24 segments (both cover the lab's overlay range) — used by
/// tests (b) and (c), which specifically need a segment CIDR wider than a
/// single host so the "empty src/dst falls back to the *block's* CIDRs" and
/// LPM-prefix-width mechanics are actually exercised, not just point /32s.
fn segments_wide() -> Vec<SegmentDef> {
    vec![
        SegmentDef { name: "seg-a-wide".into(), cidrs: vec!["10.10.0.0/24".parse().unwrap()] },
        SegmentDef { name: "seg-b-wide".into(), cidrs: vec!["10.10.0.0/24".parse().unwrap()] },
    ]
}

/// Parses + compiles `yaml` against `segs`, panicking with full detail on
/// either failure (mirrors `tests/flatten.rs`'s `compile_ok`, generalized to
/// take the segment table as a parameter since different tests here need
/// different segment tables).
fn compile_with(yaml: &str, segs: &[SegmentDef], version: u64) -> PolicyIR {
    let src = parse_policy(yaml, segs)
        .unwrap_or_else(|errors| panic!("expected valid policy, got errors: {errors:?}"));
    compile(&src, segs, version)
        .unwrap_or_else(|errors| panic!("expected compile to succeed, got errors: {errors:?}"))
}

/// `n` inert `deny: { proto: tcp, ports: [p] }` rules on distinct single
/// ports starting at `start_port`, each omitting `src`/`dst` (so they don't
/// multiply CIDR fan-out — one exploded `Rule` per padding `FlatRule`).
/// Never matched by any test's real traffic (distinct port ranges per
/// test); their only job is pushing the flattened+exploded rule count past
/// today's 64-entry A/B table cap so `apply()` bails with a clean,
/// real RED (per the Task 8 brief's guidance), while staying well under
/// `MAX_RULES` (256).
fn pad_rules_yaml(start_port: u16, n: u16) -> String {
    let mut s = String::new();
    for p in start_port..start_port + n {
        s.push_str(&format!("      - deny:\n          proto: tcp\n          ports: [{p}]\n"));
    }
    s
}

// --- packet-level helpers (no `nc`/`ncat`/`socat` in this image — see
// spike/enforcer/enforcer/tests/enforce.rs's identical note — python3 is
// present, so every helper below is a short inline python3 script) --------

/// Accepts connections in a loop, closing each immediately — enough to make
/// a plain TCP `connect()` succeed on an otherwise-empty test port. Used by
/// (a)/(b)/(c), which only care whether `connect()` succeeds or times out.
fn spawn_accept_only_listener(ns: &Ns, port: u16) -> Child {
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
    ns.spawn(&["python3", "-c", &script]).expect("spawn accept-only listener")
}

/// `connect()`s to `dst_addr:port` from local address `bind_addr` (use
/// `"0.0.0.0"` to let the OS pick), with a `timeout_s`-second timeout.
/// Returns whether the connect succeeded — a denied/dropped SYN times out
/// (no RST ever arrives, since `TC_ACT_SHOT` at the enforcer's ingress
/// classifier drops the packet before it reaches the destination's IP
/// stack), so "succeeds fast" vs. "times out" is a clean allow/deny signal
/// as long as a real listener is bound on the port either way (see
/// `spawn_accept_only_listener` above).
fn tcp_connect_from(ns: &Ns, bind_addr: &str, dst_addr: &str, port: u16, timeout_s: u32) -> bool {
    let script = format!(
        r#"
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout({timeout_s})
s.bind(("{bind_addr}", 0))
try:
    s.connect(("{dst_addr}", {port}))
    sys.exit(0)
except Exception:
    sys.exit(1)
"#
    );
    ns.exec(&["python3", "-c", &script]).is_ok()
}

fn tcp_connect(ns: &Ns, dst_addr: &str, port: u16, timeout_s: u32) -> bool {
    tcp_connect_from(ns, "0.0.0.0", dst_addr, port, timeout_s)
}

/// Counts UDP datagrams received on `port` until `idle_timeout_s` elapses
/// with no new packet, then prints the final count and exits. Used by (d)'s
/// continuous-stream-under-flip test.
fn spawn_udp_counting_receiver(ns: &Ns, port: u16, idle_timeout_s: f64) -> Child {
    let script = format!(
        r#"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", {port}))
s.settimeout({idle_timeout_s})
count = 0
try:
    while True:
        s.recvfrom(2048)
        count += 1
except socket.timeout:
    pass
print(count)
"#
    );
    ns.spawn(&["python3", "-c", &script]).expect("spawn udp counting receiver")
}

/// Sends `count` UDP datagrams to `dst_addr:port`, `interval_s` seconds
/// apart, then prints `count` and exits.
fn spawn_udp_sender(ns: &Ns, dst_addr: &str, port: u16, count: u32, interval_s: f64) -> Child {
    let script = format!(
        r#"
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
n = {count}
for i in range(n):
    s.sendto(b"x", ("{dst_addr}", {port}))
    time.sleep({interval_s})
print(n)
"#
    );
    ns.spawn(&["python3", "-c", &script]).expect("spawn udp sender")
}

/// Accepts ONE connection and echoes a fixed `b"ack"` reply for every
/// message it receives, indefinitely — used by (e) to prove an
/// already-established flow survives a later generation flip + reap.
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
    ns.spawn(&["python3", "-c", &script]).expect("spawn ack-echo listener")
}

/// Connects to 10.10.0.2:9100, exchanges one request/ack, sleeps 11s
/// (spanning the caller's v2 apply + the >=10s old-generation reap grace),
/// then exchanges a second request/ack over the SAME still-open socket.
/// Exits 0 iff both round-trips succeeded.
fn spawn_persistent_9100_client(ns: &Ns) -> Child {
    let script = r#"
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(("10.10.0.2", 9100))
s.sendall(b"hello-v1")
first = s.recv(64)
if first != b"ack":
    sys.exit(1)
time.sleep(11)  # spans the v2 apply + the >=10s old-generation reap grace
s.sendall(b"hello-after-grace")
second = s.recv(64)
sys.exit(0 if second == b"ack" else 1)
"#;
    ns.spawn(&["python3", "-c", script]).expect("spawn persistent 9100 client")
}

// --- (a) first-match-wins + per-rule counters --------------------------

/// Deny-22 carve-out placed BEFORE an allow-all-tcp rule (source order):
/// an SSH-port SYN must be dropped (first match wins on the deny), while a
/// port-80 connect falls through to the allow-all-tcp rule and succeeds.
/// `Counters.by_rule` (keyed by each rule's 16-hex `rule_id`) must land the
/// right counts on the right rule.
///
/// RED today: padded to 72 total rules (2 real + 70 inert), exceeding the
/// spike's 64-entry A/B table — `apply()` returns `Err` (`RULE_TABLE_CAPACITY`
/// in `src/ebpf.rs`), so `.expect(...)` panics before any traffic is even
/// sent. `counters().by_rule` being always-empty today is a second,
/// independent RED reason once/if the cap is raised without wiring up
/// per-rule counters.
#[test]
fn first_match_wins_denies_ssh_carve_out_allows_the_rest_with_correct_rule_counters() {
    let (lab, a, b) = wg_lab("aeth8");
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    let mut enforcer = wiremesh_enforcer::probe("wg0", wiremesh_enforcer::EnforcerConfig::default())
        .expect("probe should load + attach eBPF on wg0");

    let segs = segments_exact();
    let mut yaml = String::from(
        "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - deny:
          proto: tcp
          ports: [22]
      - allow:
          proto: tcp
",
    );
    yaml.push_str(&pad_rules_yaml(20001, 70));
    let ir = compile_with(&yaml, &segs, 1);
    let deny_22_rule_id = ir.blocks[0].rules[0].rule_id.clone();
    let allow_all_rule_id = ir.blocks[0].rules[1].rule_id.clone();

    enforcer.apply(&ir).expect(
        "policy (2 real rules + 70 inert pad rules = 72 total, exceeding today's 64-entry A/B \
         cap) must apply once Task 8's map-in-map generations lift the cap to MAX_RULES=256",
    );

    let mut children = vec![
        spawn_accept_only_listener(&b, 22),
        spawn_accept_only_listener(&b, 80),
    ];
    std::thread::sleep(Duration::from_millis(200));

    assert!(
        !tcp_connect(&a, "10.10.0.2", 22, 2),
        "SSH SYN (port 22) should be dropped by the deny-22 carve-out (first match, before the \
         allow-all-tcp rule), but the connect succeeded"
    );
    assert!(
        tcp_connect(&a, "10.10.0.2", 80, 2),
        "port-80 connect should fall through to the allow-all-tcp rule and succeed"
    );

    let counters = enforcer.counters().expect("counters() should succeed");
    assert!(
        counters.by_rule.get(&deny_22_rule_id).copied().unwrap_or(0) > 0,
        "deny-22 rule's own by_rule counter should have incremented for the dropped SYN(s): {:?}",
        counters.by_rule
    );
    assert!(
        counters.by_rule.get(&allow_all_rule_id).copied().unwrap_or(0) > 0,
        "allow-all-tcp rule's own by_rule counter should have incremented for the allowed \
         connection: {:?}",
        counters.by_rule
    );

    for c in &mut children {
        let _ = c.kill();
    }
    drop(lab);
}

// --- (b) whole-segment fallback ----------------------------------------

/// A rule with empty `src`/`dst` falls back to its *block's* CIDRs (design
/// §4) — here the block's CIDRs are the whole /24 overlay subnet (not a
/// single host /32), so this proves the fallback resolves to a real
/// wide-prefix LPM entry that the lab's actual host addresses fall inside,
/// not just a degenerate point match. Deny-8080 (empty src/dst, so it
/// enforces against the block's /24 CIDRs) precedes allow-all-tcp; port
/// 8080 must be denied, another port must fall through to the allow.
///
/// RED today: same capacity-bail mechanism as (a) — padded to 72 total
/// rules.
#[test]
fn whole_segment_fallback_enforces_against_block_cidrs_not_a_bare_host_match() {
    let (lab, a, b) = wg_lab("aeth8");
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    let mut enforcer = wiremesh_enforcer::probe("wg0", wiremesh_enforcer::EnforcerConfig::default())
        .expect("probe should load + attach eBPF on wg0");

    let segs = segments_wide();
    let mut yaml = String::from(
        "
policy:
  - from: seg-a-wide
    to: seg-b-wide
    rules:
      - deny:
          proto: tcp
          ports: [8080]
      - allow:
          proto: tcp
",
    );
    yaml.push_str(&pad_rules_yaml(21001, 70));
    let ir = compile_with(&yaml, &segs, 1);

    enforcer.apply(&ir).expect(
        "policy (2 real rules + 70 inert pad rules = 72 total, exceeding today's 64-entry A/B \
         cap) must apply once Task 8's map-in-map generations lift the cap",
    );

    let mut children = vec![
        spawn_accept_only_listener(&b, 8080),
        spawn_accept_only_listener(&b, 8081),
    ];
    std::thread::sleep(Duration::from_millis(200));

    assert!(
        !tcp_connect(&a, "10.10.0.2", 8080, 2),
        "port 8080 should be denied by the empty-src/dst rule, which must enforce against the \
         block's /24 CIDRs (covering both real hosts here), not silently match nothing"
    );
    assert!(
        tcp_connect(&a, "10.10.0.2", 8081, 2),
        "port 8081 should fall through to the allow-all-tcp rule and succeed"
    );

    for c in &mut children {
        let _ = c.kill();
    }
    drop(lab);
}

// --- (c) LPM correctness: cumulative bitsets, not longest-prefix-wins ---

/// `deny 10.10.0.8/32` precedes `allow 10.10.0.0/24` (source order). A
/// packet from `.8` must be denied (the narrower deny is first-match), a
/// packet from `.9` must be allowed (only the wider allow's CIDR covers
/// it). Design §6's cumulative-bitset build (every prefix's stored bitset
/// is the union of every covering rule's bit, not just the rule inserted at
/// that exact prefix) is what lets a bounded first-match scan over
/// `0..MAX_RULES` — not raw LPM-longest-prefix-wins — decide the verdict.
///
/// Two extra IP aliases (`10.10.0.8/32`, `10.10.0.9/32`) are added to `a`'s
/// `wg0` so the test can actually source packets from those two specific
/// addresses (via `bind()`) while both still route out `wg0`'s existing
/// `10.10.0.0/24`-covering connected route.
///
/// RED today: same capacity-bail mechanism as (a)/(b) — padded to 72 total
/// rules.
#[test]
fn lpm_first_match_denies_narrow_carve_out_allows_the_wider_covering_cidr() {
    let (lab, a, b) = wg_lab("aeth8");
    a.exec(&["ip", "addr", "add", "10.10.0.8/32", "dev", "wg0"])
        .expect("add secondary source address .8 on a's wg0");
    a.exec(&["ip", "addr", "add", "10.10.0.9/32", "dev", "wg0"])
        .expect("add secondary source address .9 on a's wg0");
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    let mut enforcer = wiremesh_enforcer::probe("wg0", wiremesh_enforcer::EnforcerConfig::default())
        .expect("probe should load + attach eBPF on wg0");

    let segs = segments_wide();
    let mut yaml = String::from(
        "
policy:
  - from: seg-a-wide
    to: seg-b-wide
    rules:
      - deny:
          src: [\"10.10.0.8/32\"]
          proto: tcp
          ports: [9090]
      - allow:
          src: [\"10.10.0.0/24\"]
          proto: tcp
          ports: [9090]
",
    );
    yaml.push_str(&pad_rules_yaml(22001, 70));
    let ir = compile_with(&yaml, &segs, 1);

    enforcer.apply(&ir).expect(
        "policy (2 real rules + 70 inert pad rules = 72 total, exceeding today's 64-entry A/B \
         cap) must apply once Task 8's map-in-map generations lift the cap; this padding ALSO \
         forces the map-in-map LPM path to exist at all, exercising cumulative-bitset \
         correctness once implemented",
    );

    let mut children = vec![spawn_accept_only_listener(&b, 9090)];
    std::thread::sleep(Duration::from_millis(200));

    assert!(
        !tcp_connect_from(&a, "10.10.0.8", "10.10.0.2", 9090, 2),
        "a packet sourced from .8 must be denied by the narrower /32 carve-out (first match)"
    );
    assert!(
        tcp_connect_from(&a, "10.10.0.9", "10.10.0.2", 9090, 2),
        "a packet sourced from .9 (not covered by the /32 carve-out) must be allowed by the \
         wider /24 rule -- this only works if that rule's covering bit was folded into every \
         narrower prefix's cumulative bitset, not just its own /24 LPM entry"
    );

    for c in &mut children {
        let _ = c.kill();
    }
    drop(lab);
}

/// Companion discriminator for the test above, added per coordinator review:
/// in the briefed order (deny `/32` first, allow `/24` second), a buggy
/// non-cumulative LPM implementation (a lookup returns only the bits of the
/// rule inserted at that exact longest-matching prefix, no union of every
/// *covering* rule's bits) happens to produce the SAME observable outcome as
/// correct cumulative-bitset first-match — both deny `.8` and allow `.9` —
/// so that test alone cannot tell the two apart.
///
/// This test reverses the order: `allow 10.10.0.0/24` FIRST, `deny
/// 10.10.0.8/32` SECOND. Correct first-match semantics (with cumulative
/// bitsets, so the `.8`-prefix's LPM entry carries the union of the allow
/// rule's bit AND the deny rule's bit, since the allow's `/24` covers `.8`)
/// must let the earlier (idx 0) allow rule win the scan for a packet from
/// `.8` — i.e. `.8` must be ALLOWED here, the opposite of the previous
/// test's outcome, purely because of rule *order*, not prefix length. A
/// buggy non-cumulative/longest-prefix-wins implementation would instead
/// return only the narrower `/32` deny rule's bit for `.8` (since that's
/// the longest prefix with an entry, and no cumulative union folded the
/// wider allow's bit into it) and wrongly deny it. `.9` is allowed either
/// way (only the `/24` rule covers it) — asserted too, so a regression that
/// makes everything permissive can't slip through unnoticed.
///
/// RED today: same capacity-bail mechanism as the test above — padded to 72
/// total rules (2 real + 70 inert), a fresh, distinct pad port range so it
/// can't be confused with the other test's padding.
#[test]
fn lpm_cumulative_bitset_first_match_allows_narrow_host_via_earlier_wide_allow_despite_later_deny_carve_out(
) {
    let (lab, a, b) = wg_lab("aeth8");
    a.exec(&["ip", "addr", "add", "10.10.0.8/32", "dev", "wg0"])
        .expect("add secondary source address .8 on a's wg0");
    a.exec(&["ip", "addr", "add", "10.10.0.9/32", "dev", "wg0"])
        .expect("add secondary source address .9 on a's wg0");
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    let mut enforcer = wiremesh_enforcer::probe("wg0", wiremesh_enforcer::EnforcerConfig::default())
        .expect("probe should load + attach eBPF on wg0");

    let segs = segments_wide();
    let mut yaml = String::from(
        "
policy:
  - from: seg-a-wide
    to: seg-b-wide
    rules:
      - allow:
          src: [\"10.10.0.0/24\"]
          proto: tcp
          ports: [9091]
      - deny:
          src: [\"10.10.0.8/32\"]
          proto: tcp
          ports: [9091]
",
    );
    yaml.push_str(&pad_rules_yaml(22101, 70));
    let ir = compile_with(&yaml, &segs, 1);

    enforcer.apply(&ir).expect(
        "policy (2 real rules + 70 inert pad rules = 72 total, exceeding today's 64-entry A/B \
         cap) must apply once Task 8's map-in-map generations lift the cap; this is the \
         reverse-order discriminator that actually distinguishes cumulative-bitset first-match \
         from non-cumulative longest-prefix-wins",
    );

    let mut children = vec![spawn_accept_only_listener(&b, 9091)];
    std::thread::sleep(Duration::from_millis(200));

    assert!(
        tcp_connect_from(&a, "10.10.0.8", "10.10.0.2", 9091, 2),
        "a packet sourced from .8 must be ALLOWED: the earlier (first-match) allow rule's /24 \
         covers .8, so its bit must be present in .8's cumulative LPM entry and win the scan \
         over the later, narrower deny /32 -- a non-cumulative/longest-prefix-wins \
         implementation would wrongly deny this"
    );
    assert!(
        tcp_connect_from(&a, "10.10.0.9", "10.10.0.2", 9091, 2),
        "a packet sourced from .9 (not covered by the deny /32 either way) must be allowed by \
         the wide /24 rule"
    );

    for c in &mut children {
        let _ = c.kill();
    }
    drop(lab);
}

// --- (d) atomic flip under traffic: zero received-count deficit --------

/// A continuous UDP stream (1 packet/10ms for ~3.5s) allowed by every
/// generation is sent while `apply()` re-applies the (identical) allow
/// policy 20 times, spaced across that same window -- each call rebuilds a
/// fresh generation's inner maps and flips `ACTIVE` to it. Every packet
/// must land: `received == sent`, zero deficit, exactly mirroring the
/// spike's `rule_flip_under_traffic_never_transiently_denies` test's "0%
/// packet loss across N flips" assertion strength (design §6's one-read-
/// of-ACTIVE-per-packet atomicity guarantee), now applied to the map-in-map
/// generation swap instead of the old A/B index flip.
///
/// RED today: the policy is padded to 71 total rules (1 real allow + 70
/// inert), exceeding today's 64-entry cap -- the very first `apply()` call
/// (before the loop even starts) bails with `Err`.
#[test]
fn atomic_generation_flip_under_continuous_udp_traffic_has_zero_deficit() {
    let (lab, a, b) = wg_lab("aeth8");
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    // (Review finding, REWRITTEN for Backlog item 1 -- the reason this
    // override exists inverted, but the override itself is now MORE
    // load-bearing, not less.)
    //
    // `apply()` no longer sleeps out the previous flip's reap grace; it
    // publishes it via `apply_ready_at()` and the CALLER honors it. So this
    // is no longer "shrink an internal block so the loop fits the traffic
    // window" -- it is what makes this test's own 175ms inter-flip sleep
    // (below) a sufficient honoring of the grace. At the default 10s, that
    // 175ms spacing would overwrite each just-vacated outer-array slot far
    // inside its grace, under live traffic, which is exactly the unsafe
    // overwrite the grace exists to prevent; at 50ms, 175ms clears it with
    // room to spare and all 20 flips still land inside the sender's ~3.5s
    // window, matching this test's "under continuous traffic" intent.
    // Do not remove this override without replacing the 175ms sleep with an
    // explicit `apply_ready_at()` wait.
    let cfg = wiremesh_enforcer::EnforcerConfig {
        reap_grace: Duration::from_millis(50),
        ..wiremesh_enforcer::EnforcerConfig::default()
    };
    let mut enforcer =
        wiremesh_enforcer::probe("wg0", cfg).expect("probe should load + attach eBPF on wg0");

    let segs = segments_exact();
    let mut yaml = String::from(
        "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow:
          proto: udp
          ports: [7000]
",
    );
    yaml.push_str(&pad_rules_yaml(23001, 70));
    let ir = compile_with(&yaml, &segs, 1);

    enforcer.apply(&ir).expect(
        "policy (1 real allow rule + 70 inert pad rules = 71 total, exceeding today's 64-entry \
         A/B cap) must apply once Task 8's map-in-map generations lift the cap",
    );

    let receiver = spawn_udp_counting_receiver(&b, 7000, 1.5);
    std::thread::sleep(Duration::from_millis(150));
    let sender = spawn_udp_sender(&a, "10.10.0.2", 7000, 350, 0.01); // ~3.5s total

    // 20 flips of the SAME allow policy, spread across the sender's ~3.5s
    // window (~175ms apart) -- concurrent with the live traffic. The 175ms
    // is now the CALLER-side honoring of the 50ms grace configured above
    // (see that comment), not merely a pacing choice.
    for i in 0..20 {
        enforcer
            .apply(&ir)
            .unwrap_or_else(|e| panic!("flip #{i} (re-applying the same allow policy) failed: {e:#}"));
        std::thread::sleep(Duration::from_millis(175));
    }

    let sender_out = sender.wait_with_output().expect("udp sender should exit");
    assert!(sender_out.status.success(), "udp sender exited non-zero: {sender_out:?}");
    let sent: u64 = String::from_utf8_lossy(&sender_out.stdout)
        .trim()
        .parse()
        .expect("sender should print its packet count");

    let receiver_out = receiver.wait_with_output().expect("udp receiver should exit after its idle timeout");
    assert!(receiver_out.status.success(), "udp receiver exited non-zero: {receiver_out:?}");
    let received: u64 = String::from_utf8_lossy(&receiver_out.stdout)
        .trim()
        .parse()
        .expect("receiver should print its packet count");

    assert_eq!(
        received, sent,
        "zero received-count deficit expected across 20 concurrent generation flips \
         (sent {sent}, received {received})"
    );

    drop(lab);
}

// --- (e) old-generation reap doesn't break an in-flight allowed flow ----

/// v1 allows only tcp/9100; a flow is established under v1 and exchanges
/// one request/ack. v2 (applied while that flow is open) keeps allowing
/// tcp/9100 and ALSO adds tcp/9101 -- proving the generation actually
/// switched, since v1 never allowed 9101. After v2 is applied, the ORIGINAL
/// 9100 flow sleeps past the design's >=10s old-generation reap grace, then
/// exchanges a second request/ack over the SAME still-open socket: this
/// must still succeed -- the reap of v1's now-superseded inner rule maps
/// must not disturb an already-flowing, already-allowed connection. A
/// brand-new connection on 9101 (which only v2 allows) must also succeed,
/// confirming v2 is the live generation.
///
/// RED today: v1 (1 rule, well under the cap) applies fine, and the flow
/// starts; v2 is padded to 72 total rules (2 real + 70 inert), exceeding
/// today's 64-entry cap -- `apply(&v2)` bails with `Err` before any grace
/// period or reap logic (which doesn't exist at all in Task 7's plain A/B
/// flip) is ever reached.
#[test]
fn old_generation_reap_does_not_break_in_flight_allowed_flow_and_new_gen_matches() {
    let (lab, a, b) = wg_lab("aeth8");
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    let mut enforcer = wiremesh_enforcer::probe("wg0", wiremesh_enforcer::EnforcerConfig::default())
        .expect("probe should load + attach eBPF on wg0");

    let segs = segments_exact();
    let v1_yaml = "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow:
          proto: tcp
          ports: [9100]
";
    let v1 = compile_with(v1_yaml, &segs, 1);
    enforcer
        .apply(&v1)
        .expect("v1 (single allow rule, well under the 64-entry cap) must apply");

    let mut children = vec![
        spawn_ack_echo_listener(&b, 9100),
        spawn_ack_echo_listener(&b, 9101),
    ];
    std::thread::sleep(Duration::from_millis(200));

    // Sanity: v1 does NOT allow 9101 yet -- makes the later "new connection
    // matching only v2" assertion meaningful rather than vacuous.
    assert!(
        !tcp_connect(&a, "10.10.0.2", 9101, 1),
        "port 9101 should not be reachable before v2 is applied"
    );

    // Start a flow on 9100 under v1; keep the Child so we can wait for its
    // second (post-grace) round-trip after applying v2.
    let client_9100 = spawn_persistent_9100_client(&a);
    std::thread::sleep(Duration::from_millis(300)); // let connect + first round-trip land under v1

    // v2: same allow:9100 + a new allow:9101 ("the change"), padded past
    // today's 64-entry A/B cap -- Task 7's apply() bails here today (RED).
    let mut v2_yaml = String::from(
        "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow:
          proto: tcp
          ports: [9100]
      - allow:
          proto: tcp
          ports: [9101]
",
    );
    v2_yaml.push_str(&pad_rules_yaml(24001, 70));
    let v2 = compile_with(&v2_yaml, &segs, 2);
    enforcer.apply(&v2).expect(
        "v2 (adds allow:9101 + 70 pad rules, 72 total, exceeding today's 64-entry cap) must \
         apply once Task 8's map-in-map generations lift the cap",
    );

    // The client sleeps 11s inside its own script (past the >=10s reap
    // grace) before its second round-trip -- wait for it rather than
    // sleeping here ourselves.
    let out = client_9100.wait_with_output().expect("persistent 9100 client should exit");
    assert!(
        out.status.success(),
        "in-flight flow established under v1 must still pass traffic after v2's generation \
         flip + reap of the old generation's rule tables: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    // A brand-new connection matching ONLY v2's added rule must now work.
    assert!(
        tcp_connect(&a, "10.10.0.2", 9101, 2),
        "a new connection on port 9101 (allowed only by v2) should succeed once v2 is active"
    );

    for c in &mut children {
        let _ = c.kill();
    }
    drop(lab);
}

// --- counters must survive rule insertion, keyed by rule_id --------------

/// Task 8 review finding (Important, relayed by the coordinator): `COUNTERS`
/// is a flat, generation-independent `Array<u64>` indexed by each rule's
/// FLATTENED POSITIONAL idx, and `apply()` never resets/re-homes those
/// slots. `counters()` aggregates by reading the CURRENT generation's
/// idx->`rule_id` mapping against those same raw (stale) per-idx slots — so
/// inserting a new rule BEFORE an existing one shifts every later rule's
/// idx, and an existing rule's already-accumulated hit count is left behind
/// at its OLD idx, now mislabeled with whichever rule occupies that idx in
/// the new generation. Concretely: v1 = `[allowA (idx0), allowB (idx1)]`; A
/// accrues `k` hits at idx0. v2 = `[allowC (NEW, idx0), allowA (idx1),
/// allowB (idx2)]` — idx0's `k` hits (A's history) get attributed to C,
/// while idx1 (B's old, untouched slot) gets attributed to A, reading 0.
///
/// Decided behavior (design: "per-rule counters survive policy updates",
/// keyed by the content-hash `rule_id` — stable across reorderings since it
/// never depends on position, only on a rule's own `from`/`to`/action/
/// proto/src/dst/ports, see `wiremesh_policy::compile::rule_id`'s doc
/// comment): after v2, A's pre-v2 hits must still be attributed to A's
/// `rule_id`, and C's `rule_id` must read 0 until traffic actually matches
/// it.
///
/// RED today: the misattribution assertions below fail — A's count reads 0
/// (its history was left behind at the old idx1, which is B's fresh,
/// never-hit slot) while C reads `k` (inheriting idx0's stale count, which
/// is really A's history).
#[test]
fn counters_survive_rule_insertion_keyed_by_rule_id() {
    let (lab, a, b) = wg_lab("aeth8");
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    let mut enforcer = wiremesh_enforcer::probe("wg0", wiremesh_enforcer::EnforcerConfig::default())
        .expect("probe should load + attach eBPF on wg0");

    let segs = segments_exact();
    let v1_yaml = "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow:
          proto: tcp
          ports: [9200]
      - allow:
          proto: tcp
          ports: [9201]
";
    let v1 = compile_with(v1_yaml, &segs, 1);
    let rule_a_id = v1.blocks[0].rules[0].rule_id.clone();
    enforcer
        .apply(&v1)
        .expect("v1 (two small allow rules, no padding needed) must apply");

    let mut children = vec![
        spawn_accept_only_listener(&b, 9200),
        spawn_accept_only_listener(&b, 9201),
        spawn_accept_only_listener(&b, 9202),
    ];
    std::thread::sleep(Duration::from_millis(200));

    // k = 3 distinct connections matching rule A -- each is its own fresh
    // flow (distinct ephemeral src port), so each independently hits
    // `scan_rules`/A's own counter rather than short-circuiting via FLOWS.
    let k = 3u64;
    for _ in 0..k {
        assert!(
            tcp_connect(&a, "10.10.0.2", 9200, 2),
            "connection matching rule A (port 9200) should succeed under v1"
        );
    }
    let snapshot = enforcer.counters().expect("counters() should succeed after v1 traffic");
    assert_eq!(
        snapshot.by_rule.get(&rule_a_id).copied().unwrap_or(0),
        k,
        "rule A should show exactly k={k} hits before any v2 apply: {:?}",
        snapshot.by_rule
    );

    // v2: the SAME two rules, PLUS a brand-new rule C inserted BEFORE A --
    // this shifts A from idx0 to idx1, and B from idx1 to idx2.
    let v2_yaml = "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow:
          proto: tcp
          ports: [9202]
      - allow:
          proto: tcp
          ports: [9200]
      - allow:
          proto: tcp
          ports: [9201]
";
    let v2 = compile_with(v2_yaml, &segs, 2);
    let rule_c_id = v2.blocks[0].rules[0].rule_id.clone();
    assert_ne!(rule_c_id, rule_a_id, "C must be a genuinely distinct rule from A");
    assert_eq!(
        v2.blocks[0].rules[1].rule_id, rule_a_id,
        "rule_id is a content hash independent of position -- A's rule_id must be unchanged \
         across v1/v2 despite shifting from idx0 to idx1"
    );

    // apply() may internally block out the remainder of v1's post-flip reap
    // grace (>=10s total since v1's flip) before returning -- acceptable
    // per the coordinator's note; no explicit sleep needed here.
    enforcer.apply(&v2).expect(
        "v2 (the same 2 rules plus 1 new rule inserted before A, 3 total -- no padding needed, \
         small policies apply fast) must apply",
    );

    let after_v2 = enforcer.counters().expect("counters() should succeed after v2 apply");
    assert!(
        after_v2.by_rule.get(&rule_a_id).copied().unwrap_or(0) >= k,
        "rule A's pre-v2 history (k={k} hits) must survive being re-homed to a new idx, keyed \
         by its stable rule_id, not left behind at its old idx: {:?}",
        after_v2.by_rule
    );
    assert_eq!(
        after_v2.by_rule.get(&rule_c_id).copied().unwrap_or(0),
        0,
        "rule C is brand new in v2 and has not matched any traffic yet -- it must read 0, not \
         inherit A's stale idx0 history: {:?}",
        after_v2.by_rule
    );

    // Now actually exercise C and confirm it counts independently, without
    // disturbing A's retained history.
    let k2 = 2u64;
    for _ in 0..k2 {
        assert!(
            tcp_connect(&a, "10.10.0.2", 9202, 2),
            "connection matching rule C (port 9202) should succeed under v2"
        );
    }
    let final_counters = enforcer.counters().expect("counters() should succeed after C's traffic");
    assert_eq!(
        final_counters.by_rule.get(&rule_c_id).copied().unwrap_or(0),
        k2,
        "rule C should now show exactly k2={k2} hits of its own: {:?}",
        final_counters.by_rule
    );
    assert!(
        final_counters.by_rule.get(&rule_a_id).copied().unwrap_or(0) >= k,
        "rule A's retained history must not be clobbered by C's own traffic: {:?}",
        final_counters.by_rule
    );

    for c in &mut children {
        let _ = c.kill();
    }
    drop(lab);
}

// --- counters for retired rules must be pruned at apply -----------------

/// Task 8 re-review finding (relayed by the coordinator): the fix above
/// (`fold_and_reset_counters` folding a superseded generation's per-idx
/// counts into `GenerationState::counter_accum`, keyed by the stable
/// `rule_id`) makes counters SURVIVE a rule's idx changing across policy
/// updates -- but that same `counter_accum` map is never pruned, so a rule
/// that's REMOVED entirely keeps its counter around forever (unbounded
/// growth over a gateway's whole policy-edit history, and a removed rule's
/// counter staying visible in `counters().by_rule` indefinitely).
///
/// Ruling (relayed by the coordinator): at `apply()`, after folding, any
/// `counter_accum` entry whose `rule_id` is NOT present in the NEW
/// generation's idx->rule_id mapping must be pruned. This is consistent
/// with nft named-counter semantics (a counter tied to a deleted rule
/// doesn't outlive it) and doesn't conflict with the design's survival
/// guarantee, which only ever promised counters survive for UNCHANGED
/// rules across an update, not that a deleted rule's history is kept
/// forever.
///
/// RED today: `counter_accum` has no pruning step at all (see
/// `fold_and_reset_counters`'s doc comment above -- it only folds and
/// zeroes `COUNTERS` slots, never removes an accumulator entry), so a
/// retired rule's `rule_id` remains in `counters().by_rule` after the
/// policy that dropped it is applied.
#[test]
fn counters_for_removed_rules_are_pruned_at_apply() {
    let (lab, a, b) = wg_lab("aeth8");
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    let mut enforcer = wiremesh_enforcer::probe("wg0", wiremesh_enforcer::EnforcerConfig::default())
        .expect("probe should load + attach eBPF on wg0");

    let segs = segments_exact();
    let v1_yaml = "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow:
          proto: tcp
          ports: [9300]
      - allow:
          proto: tcp
          ports: [9301]
";
    let v1 = compile_with(v1_yaml, &segs, 1);
    let rule_a_id = v1.blocks[0].rules[0].rule_id.clone();
    let rule_b_id = v1.blocks[0].rules[1].rule_id.clone();
    enforcer
        .apply(&v1)
        .expect("v1 (two small allow rules, no padding needed) must apply");

    let mut children = vec![
        spawn_accept_only_listener(&b, 9300),
        spawn_accept_only_listener(&b, 9301),
    ];
    std::thread::sleep(Duration::from_millis(200));

    // A gets k hits; B gets its own, smaller, distinct m hits -- so B's
    // post-v2 value has a concrete, non-trivial baseline to prove "intact"
    // against, rather than a vacuous "still absent/0" either way.
    let k = 2u64;
    for _ in 0..k {
        assert!(
            tcp_connect(&a, "10.10.0.2", 9300, 2),
            "connection matching rule A (port 9300) should succeed under v1"
        );
    }
    let m = 1u64;
    for _ in 0..m {
        assert!(
            tcp_connect(&a, "10.10.0.2", 9301, 2),
            "connection matching rule B (port 9301) should succeed under v1"
        );
    }
    let snapshot = enforcer.counters().expect("counters() should succeed after v1 traffic");
    assert!(
        snapshot.by_rule.get(&rule_a_id).copied().unwrap_or(0) > 0,
        "rule A should show a nonzero hit count before v2 removes it: {:?}",
        snapshot.by_rule
    );
    assert_eq!(
        snapshot.by_rule.get(&rule_b_id).copied().unwrap_or(0),
        m,
        "rule B should show exactly m={m} hits before v2: {:?}",
        snapshot.by_rule
    );

    // v2: A is REMOVED entirely -- only B remains.
    let v2_yaml = "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow:
          proto: tcp
          ports: [9301]
";
    let v2 = compile_with(v2_yaml, &segs, 2);
    assert_eq!(
        v2.blocks[0].rules[0].rule_id, rule_b_id,
        "rule_id is a content hash independent of position -- B's rule_id must be unchanged \
         across v1/v2 despite shifting from idx1 to idx0"
    );

    // apply() may internally block out the remainder of v1's post-flip reap
    // grace (>=10s total since v1's flip) before returning -- acceptable,
    // no explicit sleep needed here.
    enforcer.apply(&v2).expect(
        "v2 (B only, A removed -- no padding needed, small policies apply fast) must apply",
    );

    let after_v2 = enforcer.counters().expect("counters() should succeed after v2 apply");
    assert!(
        !after_v2.by_rule.contains_key(&rule_a_id),
        "rule A was removed entirely in v2 -- its counter must be pruned from by_rule, not kept \
         around forever: {:?}",
        after_v2.by_rule
    );
    assert_eq!(
        after_v2.by_rule.get(&rule_b_id).copied().unwrap_or(0),
        m,
        "rule B's own counter must be intact (unaffected by A's removal/pruning): {:?}",
        after_v2.by_rule
    );

    for c in &mut children {
        let _ = c.kill();
    }
    drop(lab);
}
