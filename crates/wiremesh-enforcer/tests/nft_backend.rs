//! Task 12, Step 1 (test author): failing netns tests for the live
//! nftables backend + probe fallback (`.superpowers/sdd/task-12-brief.md`).
//! These drive the real `wiremesh-enforcer` public API
//! (`probe_with`/`apply`/`counters`) against the `Nftables` backend
//! specifically -- unlike every other suite in this crate (`ebpf_backend`,
//! `generations`, `flow_table`, `deny_events`), which all drive `probe`
//! (eBPF only, since that's the only backend that exists before this task).
//!
//! **Why `probe_with`, not `probe`:** the privileged dev container this
//! suite always runs in (`CLAUDE.md`'s "Host is macOS ... tun/eBPF/netns/
//! nftables do not work on the host") always has eBPF available, so a plain
//! `probe()` call would deterministically pick `BackendKind::Ebpf` and never
//! exercise the nftables path at all -- there is no env var or knob that
//! makes eBPF "unavailable" here. Per the brief's Interfaces section, the
//! sanctioned mechanism is a forced-choice `probe_with(BackendKind, iface,
//! cfg)`, stubbed as `todo!()` in `src/lib.rs` by this same commit (allowed
//! Step-1 scaffold, not implementation -- Step 3, the implementer, fills it
//! in for real). Every test below calls
//! `wiremesh_enforcer::probe_with(BackendKind::Nftables, "wg0", ..)`.
//!
//! **RED evidence (current state):** `probe_with`'s body is `todo!(..)` --
//! every test below panics with that message the moment it's called,
//! immediately after the lab comes up (before any traffic is sent). This is
//! true for all six tests (a)-(f), matching the brief's "(a)-(e) panic on
//! probe_with's todo!(); (f) likewise."
//!
//! **Why nft has no padding/reap-grace machinery, unlike the eBPF suites:**
//! `NftEnforcer::apply` is specified to pipe the whole ruleset to `nft -f -`
//! as ONE atomic transaction (design D-C3-6/the brief's Interfaces section)
//! -- there is no fixed-size kernel array to overflow (no
//! `RULE_TABLE_CAPACITY`-style cap, so no padding rules needed to reach a
//! RED-worthy rule count) and no old-generation map-in-map slot to reap on a
//! grace timer (so none of `tests/generations.rs`'s `>=10s` sleeps apply
//! here -- test (d) below flips 20 times back-to-back, not once per ~175ms+
//! reap-grace wait).
//!
//! **Why some tests only ever exercise ONE `Ns`'s enforcer (`b`'s), same as
//! every other suite in this crate:** a real deployment loads the identical
//! compiled `PolicyIR` on every gateway, each evaluating only its OWN
//! ingress traffic (design §6/D-C3-6: `ct state established,related accept`
//! plus explicit rules scoped to `iifname wg0`, hooked on `input`+`forward`
//! only -- egress is never filtered, matching the eBPF backend's
//! ingress-enforce/egress-record split). Running a single enforcer on `b`
//! and treating `a` as a bare, unenforced traffic generator (this crate's
//! established convention since Task 7) is therefore sufficient for every
//! test except (b), which specifically needs `b`'s own OUTBOUND traffic
//! (always unfiltered, whatever policy is active) to seed a conntrack entry
//! that the SAME enforcer's ingress side then recognizes on the reply.

use std::process::Child;
use std::time::Duration;
use wiremesh_enforcer::{BackendKind, EnforcerConfig};
use wiremesh_policy::{compile, parse_policy, PolicyIR, SegmentDef};
use wiremesh_testkit::netns::{join_netns, wg_lab, Ns};

/// Exact per-host /32 segments -- same convention as
/// `tests/generations.rs`'s `segments_exact`, duplicated per this crate's
/// established per-file self-sufficiency convention.
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

// --- packet-level helpers (no `nc`/`ncat`/`socat` in this image -- see
// tests/generations.rs's identical note -- python3 is present, so every
// helper below is a short inline python3 script) --------------------------

/// Accepts connections in a loop, closing each immediately -- enough to make
/// a plain TCP `connect()` succeed on an otherwise-empty test port.
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
    ns.spawn(&["python3", "-c", &script])
        .expect("spawn accept-only listener")
}

/// `connect()`s to `dst_addr:port`, `timeout_s`-second timeout. Returns
/// whether it succeeded -- a denied/dropped SYN never gets a RST (nft's
/// `drop` verdict silently discards it), so "succeeds fast" vs. "times out"
/// is a clean allow/deny signal as long as a real listener is bound on the
/// port either way.
fn tcp_connect(ns: &Ns, dst_addr: &str, port: u16, timeout_s: u32) -> bool {
    let script = format!(
        r#"
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout({timeout_s})
try:
    s.connect(("{dst_addr}", {port}))
    sys.exit(0)
except Exception:
    sys.exit(1)
"#
    );
    ns.exec(&["python3", "-c", &script]).is_ok()
}

/// One-shot, blocking: sends a single UDP datagram from `bind_ip:bind_port`
/// to `dst_ip:dst_port`.
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

/// Spawns a background listener on `port` that prints `RECEIVED` and exits
/// the moment ONE datagram arrives, or `TIMEOUT` after `timeout_s` seconds
/// of silence.
fn spawn_udp_recv_probe(ns: &Ns, port: u16, timeout_s: f64) -> Child {
    let script = format!(
        r#"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", {port}))
s.settimeout({timeout_s})
try:
    s.recvfrom(2048)
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
    ns.spawn(&["python3", "-c", &script])
        .expect("spawn udp counting receiver")
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
    ns.spawn(&["python3", "-c", &script])
        .expect("spawn udp sender")
}

/// Spawns a background raw-ICMP listener on `ns` that prints `GOT <type>`
/// for the first ICMPv4 packet of type `want_type` it observes within
/// `timeout_s` seconds, or `TIMEOUT` otherwise. Requires `CAP_NET_RAW`
/// (always available -- this container is privileged root throughout, same
/// as every other netns test in this crate). A raw `SOCK_RAW`/`IPPROTO_ICMP`
/// socket is delivered a packet by the kernel only AFTER netfilter's
/// `input` hook has already let it through -- an nft `drop` verdict at that
/// hook (this backend's `from_fabric` chain, hooked on `input`) means this
/// listener never sees the packet at all, making "received within timeout"
/// a clean accept/deny signal for inbound ICMP, exactly like
/// `spawn_udp_recv_probe` is for UDP.
fn spawn_icmp_type_probe(ns: &Ns, want_type: u8, timeout_s: f64) -> Child {
    let script = format!(
        r#"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
s.settimeout({timeout_s})
deadline_hits = 0
try:
    while True:
        data, _ = s.recvfrom(2048)
        # raw IPPROTO_ICMP sockets on Linux deliver the FULL IP packet
        # (header included); ihl is the low nibble of byte 0, in 32-bit words.
        ihl = (data[0] & 0x0f) * 4
        icmp = data[ihl:]
        if len(icmp) >= 1 and icmp[0] == {want_type}:
            print(f"GOT {{icmp[0]}}")
            break
except socket.timeout:
    print("TIMEOUT")
"#
    );
    ns.spawn(&["python3", "-c", &script])
        .expect("spawn icmp type probe")
}

fn icmp_probe_got(child: Child, want_type: u8) -> bool {
    let out = child.wait_with_output().expect("icmp probe should exit");
    String::from_utf8_lossy(&out.stdout).trim() == format!("GOT {want_type}")
}

/// Sends one crafted ICMPv4 "destination unreachable" message (type 3) from
/// `ns` to `dst_ip`, embedding a fake original IPv4+UDP header whose src/dst/
/// ports are `(esrc_ip, esport)` -> `(edst_ip, edport)` -- the exact shape
/// conntrack's ICMP-error helper parses to classify this packet as
/// `related` to an existing flow (or not, if the embedded tuple matches
/// nothing). `code` distinguishes a genuine PMTUD-style "fragmentation
/// needed" (3, the brief's "PMTUD-style embedded error") from a control
/// packet with a deliberately non-matching embedded tuple ("host
/// unreachable", code 1 -- a different code so the two are trivially
/// distinguishable in a packet capture, though only `want_type` matters to
/// `spawn_icmp_type_probe` above). Adapted from
/// `spike/enforcer/enforcer/src/bin/pktgen.rs`'s Rust `socket2`-based
/// original -- reimplemented here as an inline python3 raw-socket script
/// (this crate's established no-`nc`/no-extra-binary convention) rather
/// than a new `[[bin]]` target.
fn send_icmp_dest_unreachable(
    ns: &Ns,
    dst_ip: &str,
    code: u8,
    esrc_ip: &str,
    edst_ip: &str,
    esport: u16,
    edport: u16,
) {
    let script = format!(
        r#"
import socket, struct

def csum(data):
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff

esrc = socket.inet_aton("{esrc_ip}")
edst = socket.inet_aton("{edst_ip}")

# Minimal embedded original: 20-byte IPv4 header (proto=UDP) + first 8
# bytes of the UDP header (only src/dst ports are load-bearing for
# conntrack's embedded-tuple lookup).
emb = bytearray(28)
emb[0] = 0x45
emb[8] = 64
emb[9] = 17  # udp
emb[12:16] = esrc
emb[16:20] = edst
emb[20:22] = struct.pack("!H", {esport})
emb[22:24] = struct.pack("!H", {edport})
ecs = csum(bytes(emb[0:20]))
emb[10:12] = struct.pack("!H", ecs)

icmp = bytearray(8) + bytes(emb)
icmp[0] = 3       # type: destination unreachable
icmp[1] = {code}  # code
struct.pack_into("!H", icmp, 6, 1000)  # next-hop MTU (frag-needed field)
cs = csum(bytes(icmp))
struct.pack_into("!H", icmp, 2, cs)

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
s.sendto(bytes(icmp), ("{dst_ip}", 0))
"#
    );
    ns.exec(&["python3", "-c", &script])
        .expect("sending crafted ICMP destination-unreachable message");
}

// --- (a) allow/deny/carve-out through the nftables backend --------------

/// First-match-wins deny-22 carve-out before an allow-all-tcp rule -- the
/// same shape as `tests/generations.rs`'s eBPF (a), but driven through
/// `NftEnforcer` via the forced-choice `probe_with`. No padding rules
/// needed (unlike the eBPF suites): nft has no fixed-size rule table to
/// overflow.
#[test]
fn allow_deny_carve_out_behavior_through_the_nftables_backend() {
    let (lab, a, b) = wg_lab("aeth12");
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    let mut enforcer =
        wiremesh_enforcer::probe_with(BackendKind::Nftables, "wg0", EnforcerConfig::default())
            .expect("probe_with(Nftables, ..) should load the nftables backend on wg0");
    assert_eq!(enforcer.kind(), BackendKind::Nftables);

    let segs = segments_exact();
    let yaml = "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - deny:
          proto: tcp
          ports: [22]
      - allow:
          proto: tcp
";
    let ir = compile_with(yaml, &segs, 1);
    let deny_22_rule_id = ir.blocks[0].rules[0].rule_id.clone();
    let allow_all_rule_id = ir.blocks[0].rules[1].rule_id.clone();

    enforcer.apply(&ir).expect("nftables ruleset should apply");

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
        "deny-22 rule's own named nft counter should have incremented for the dropped SYN(s): \
         {:?}",
        counters.by_rule
    );
    assert!(
        counters
            .by_rule
            .get(&allow_all_rule_id)
            .copied()
            .unwrap_or(0)
            > 0,
        "allow-all-tcp rule's own named nft counter should have incremented for the allowed \
         connection: {:?}",
        counters.by_rule
    );

    for c in &mut children {
        let _ = c.kill();
    }
    drop(lab);
}

// --- (b) conntrack statefulness -------------------------------------------

/// `b`'s enforcer runs an EMPTY (default-deny-everything) policy throughout
/// -- there is no explicit rule, in either direction, for anything in this
/// test. `b` initiates one UDP datagram toward `a` (always unfiltered:
/// nft's `from_fabric` chain is hooked on `input`/`forward` for `iifname
/// wg0`, i.e. INGRESS only -- `b`'s own egress is never filtered, matching
/// the eBPF backend's ingress-enforce/egress-record split). That outbound
/// packet is enough for the kernel's conntrack to open a NEW entry for the
/// `(b,a,sport,dport)` tuple, regardless of any nft rule ever having
/// referenced it. `a`'s reply on the exact reverse tuple must then pass `b`'s
/// ingress via `ct state established,related accept` -- the FIRST line of
/// every `from_fabric` chain, evaluated before any explicit rule -- even
/// though the active policy contains no rule for this (or any) traffic.
///
/// Negative control: a UDP datagram from `a` to `b` on a DIFFERENT port,
/// never preceded by any outbound traffic from `b` on that tuple, must
/// still be denied -- proving the reply above passed specifically because
/// of the established conntrack entry, not because this default-deny
/// policy secretly allows everything.
#[test]
fn established_conntrack_lets_a_reply_pass_with_no_rule_for_that_direction() {
    let (lab, a, b) = wg_lab("aeth12");
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    let mut enforcer =
        wiremesh_enforcer::probe_with(BackendKind::Nftables, "wg0", EnforcerConfig::default())
            .expect("probe_with(Nftables, ..) should load the nftables backend on wg0");
    enforcer
        .apply(&empty_ir(1))
        .expect("empty (default-deny) policy should apply");

    // b initiates: seeds a conntrack entry for (b=10.10.0.2:6000 -> a=10.10.0.1:7000).
    udp_send_from(&b, "10.10.0.2", 6000, "10.10.0.1", 7000);
    std::thread::sleep(Duration::from_millis(100));

    // a's reply on the exact reverse tuple must pass via `established`,
    // despite there being no rule anywhere in this (empty) policy.
    let probe = spawn_udp_recv_probe(&b, 6000, 2.0);
    std::thread::sleep(Duration::from_millis(100));
    udp_send_from(&a, "10.10.0.1", 7000, "10.10.0.2", 6000);
    assert!(
        probe_received(probe),
        "a's reply on the established (b,a,6000,7000) tuple should pass via `ct state \
         established,related accept`, even though the active policy has no rule allowing it"
    );

    // Negative control: an unrelated, never-preceded UDP datagram on a
    // different port must still be denied -- default-deny is genuinely
    // still in effect for anything that ISN'T an established/related reply.
    let control_probe = spawn_udp_recv_probe(&b, 6001, 1.5);
    std::thread::sleep(Duration::from_millis(100));
    udp_send_from(&a, "10.10.0.1", 7001, "10.10.0.2", 6001);
    assert!(
        !probe_received(control_probe),
        "an unrelated UDP datagram, never preceded by any outbound traffic from b on that \
         tuple, must still be denied by the empty (default-deny) policy"
    );

    drop(lab);
}

// --- (c) ICMP echo (explicit rule) + PMTUD-style embedded error (related) -

/// Two-part test, run sequentially against the SAME lab (separate
/// `apply()` calls keep the two mechanisms from confounding each other):
///
///  1. **Explicit rule:** policy allows icmp (only rule) -- a plain ping
///     from `a` to `b` must succeed. This is ordinary first-match rule
///     evaluation, no conntrack `related` involved (the echo REQUEST is
///     conntrack-`NEW`, not `established`/`related`, so it needs -- and
///     gets -- its own explicit rule).
///  2. **`related`, zero icmp rules:** re-`apply()` a DIFFERENT policy with
///     NO icmp rule at all (an unrelated allow-tcp rule is present just to
///     prove the policy isn't accidentally empty/default-permissive). `b`
///     sends one real UDP datagram to `a` (always-unfiltered egress) to
///     seed a genuine conntrack entry. A crafted ICMPv4 "fragmentation
///     needed" (type 3, code 4) message, embedding THAT exact UDP flow's
///     tuple, is sent from `a` to `b` and must be delivered to a raw-socket
///     listener in `b`'s netns -- i.e. it passed netfilter's `input` hook
///     via `related`, despite the current policy having zero icmp rules.
///     A second, control message embeds a bogus tuple that was never a
///     real flow and must be denied.
#[test]
fn icmp_echo_via_explicit_rule_and_pmtud_style_embedded_error_via_related() {
    let (lab, a, b) = wg_lab("aeth12");
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    let mut enforcer =
        wiremesh_enforcer::probe_with(BackendKind::Nftables, "wg0", EnforcerConfig::default())
            .expect("probe_with(Nftables, ..) should load the nftables backend on wg0");

    let segs = segments_exact();

    // --- Part 1: explicit icmp-allow rule -> plain ping succeeds. ---
    let icmp_yaml = "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow:
          proto: icmp
";
    let icmp_ir = compile_with(icmp_yaml, &segs, 1);
    enforcer
        .apply(&icmp_ir)
        .expect("explicit icmp-allow policy should apply");

    assert!(
        a.exec(&["ping", "-c", "1", "-W", "3", "10.10.0.2"]).is_ok(),
        "ping should succeed under a policy with an explicit icmp-allow rule"
    );

    // --- Part 2: re-apply with ZERO icmp rules; embedded-error via `related`. ---
    let no_icmp_yaml = "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow:
          proto: tcp
          ports: [9443]
";
    let no_icmp_ir = compile_with(no_icmp_yaml, &segs, 2);
    enforcer
        .apply(&no_icmp_ir)
        .expect("re-applying a policy with zero icmp rules should succeed");

    // Sanity: plain ping now denied -- proves the re-apply genuinely
    // removed the icmp-allow rule (not just a no-op), so Part 2's
    // eventual PASS below is attributable only to `related`.
    assert!(
        a.exec(&["ping", "-c", "1", "-W", "2", "10.10.0.2"])
            .is_err(),
        "ping should now be denied -- the re-applied policy has no icmp rule at all"
    );

    // b originates a real UDP flow to a (unfiltered egress) -- conntrack
    // now has a genuine entry for (b=10.10.0.2:6100 -> a=10.10.0.1:7100).
    udp_send_from(&b, "10.10.0.2", 6100, "10.10.0.1", 7100);
    std::thread::sleep(Duration::from_millis(100));

    // Matching embedded tuple: must pass via `related`.
    let related_probe = spawn_icmp_type_probe(&b, 3, 2.0);
    std::thread::sleep(Duration::from_millis(100));
    send_icmp_dest_unreachable(&a, "10.10.0.2", 4, "10.10.0.2", "10.10.0.1", 6100, 7100);
    assert!(
        icmp_probe_got(related_probe, 3),
        "a PMTUD-style ICMP error embedding the real, established (b,a,6100,7100) UDP flow's \
         tuple should pass via `ct state established,related accept`, despite zero icmp rules \
         being active"
    );

    // Control: bogus embedded tuple (never a real flow) must be denied.
    let control_probe = spawn_icmp_type_probe(&b, 3, 1.5);
    std::thread::sleep(Duration::from_millis(100));
    send_icmp_dest_unreachable(&a, "10.10.0.2", 1, "10.10.0.2", "10.10.0.1", 6101, 7101);
    assert!(
        !icmp_probe_got(control_probe, 3),
        "an ICMP error embedding a tuple that was never a real, established flow must be \
         denied -- default-deny is genuinely still in effect for anything not `related`"
    );

    drop(lab);
}

// --- (d) atomic replace under continuous traffic: zero drops over 20 flips

/// Continuous UDP stream while the SAME allow policy is re-`apply()`-ed 20
/// times back-to-back: zero received-count deficit expected. Unlike
/// `tests/generations.rs`'s eBPF counterpart, there is no 10s reap grace to
/// pace the flips against (`nft -f -` is one atomic transaction, no
/// generation to reap) -- the 20 flips are issued as fast as the `nft`
/// subprocess completes, not spread across seconds of deliberate sleeping.
#[test]
fn atomic_replace_under_continuous_traffic_has_zero_drops_across_20_applies() {
    let (lab, a, b) = wg_lab("aeth12");
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    let mut enforcer =
        wiremesh_enforcer::probe_with(BackendKind::Nftables, "wg0", EnforcerConfig::default())
            .expect("probe_with(Nftables, ..) should load the nftables backend on wg0");

    let segs = segments_exact();
    let yaml = "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow:
          proto: udp
          ports: [7500]
";
    let ir = compile_with(yaml, &segs, 1);
    enforcer.apply(&ir).expect("allow-udp policy should apply");

    let receiver = spawn_udp_counting_receiver(&b, 7500, 1.5);
    std::thread::sleep(Duration::from_millis(100));
    let sender = spawn_udp_sender(&a, "10.10.0.2", 7500, 350, 0.01); // ~3.5s total

    // 20 flips of the SAME allow policy, back-to-back (no reap grace to
    // pace against), concurrent with the live traffic.
    for i in 0..20 {
        enforcer.apply(&ir).unwrap_or_else(|e| {
            panic!("flip #{i} (re-applying the same allow policy) failed: {e:#}")
        });
    }

    let sender_out = sender.wait_with_output().expect("udp sender should exit");
    assert!(
        sender_out.status.success(),
        "udp sender exited non-zero: {sender_out:?}"
    );
    let sent: u64 = String::from_utf8_lossy(&sender_out.stdout)
        .trim()
        .parse()
        .expect("sender should print its packet count");

    let receiver_out = receiver
        .wait_with_output()
        .expect("udp receiver should exit after its idle timeout");
    assert!(
        receiver_out.status.success(),
        "udp receiver exited non-zero: {receiver_out:?}"
    );
    let received: u64 = String::from_utf8_lossy(&receiver_out.stdout)
        .trim()
        .parse()
        .expect("receiver should print its packet count");

    assert_eq!(
        received, sent,
        "zero received-count deficit expected across 20 back-to-back atomic replaces \
         (sent {sent}, received {received})"
    );

    drop(lab);
}

// --- (e) counters survive re-apply (offset accumulator) ------------------

/// `nft`'s atomic replace (`flush table` + recreate, per the ruleset text
/// `nft.rs::ruleset` already generates) resets each named counter object's
/// OWN raw value back to zero on every `apply()` -- `NftEnforcer` must fold
/// each rule's pre-replace reading into a persistent, `rule_id`-keyed
/// offset accumulator (the brief's Interfaces section: "the counter-offset
/// accumulator ... belongs to the `Enforcer` trait impl") so
/// `counters().by_rule` keeps counting across re-applies of the same
/// policy, exactly like the eBPF backend's counters survive a generation
/// flip (`tests/generations.rs`'s `counters_survive_rule_insertion_keyed_by_rule_id`).
///
/// Each TCP `connect()` here is a genuinely new handshake -- ONE SYN, i.e.
/// one hit against the explicit `allow tcp dport {port}` rule's named
/// counter (every subsequent packet of that same now-established
/// connection instead matches the earlier, unnamed `ct state
/// established,related` line, so it does NOT re-increment the named
/// counter) -- so `by_rule[id]` is an EXACT count of connections made, not
/// just "> 0".
#[test]
// The spawned child is a long-lived netns helper (traffic generator /
// listener) that this harness kills at teardown; `wait()`ing on it here
// would block the test forever, which is what clippy's fix would do.
#[allow(clippy::zombie_processes)]
fn counters_survive_a_policy_reapply_via_the_offset_accumulator() {
    let (lab, a, b) = wg_lab("aeth12");
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    let mut enforcer =
        wiremesh_enforcer::probe_with(BackendKind::Nftables, "wg0", EnforcerConfig::default())
            .expect("probe_with(Nftables, ..) should load the nftables backend on wg0");

    let segs = segments_exact();
    let yaml = "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow:
          proto: tcp
          ports: [9600]
";
    let ir = compile_with(yaml, &segs, 1);
    let rule_id = ir.blocks[0].rules[0].rule_id.clone();

    enforcer.apply(&ir).expect("allow-tcp policy should apply");

    let mut listener = spawn_accept_only_listener(&b, 9600);
    std::thread::sleep(Duration::from_millis(150));

    let k1 = 3;
    for _ in 0..k1 {
        assert!(
            tcp_connect(&a, "10.10.0.2", 9600, 2),
            "connect should succeed under the allow rule"
        );
    }
    let counters1 = enforcer.counters().expect("counters() should succeed");
    assert_eq!(
        counters1.by_rule.get(&rule_id).copied().unwrap_or(0),
        k1,
        "rule's counter should read exactly k1={k1} new connections before any re-apply: {:?}",
        counters1.by_rule
    );

    // Re-apply the IDENTICAL policy: nft's atomic flush+recreate resets the
    // underlying named counter object's raw value to 0.
    enforcer
        .apply(&ir)
        .expect("re-applying the identical allow-tcp policy should succeed");

    let k2 = 2;
    for _ in 0..k2 {
        assert!(
            tcp_connect(&a, "10.10.0.2", 9600, 2),
            "connect should still succeed after the re-apply (same allow rule)"
        );
    }
    let counters2 = enforcer.counters().expect("counters() should succeed");
    assert_eq!(
        counters2.by_rule.get(&rule_id).copied().unwrap_or(0),
        k1 + k2,
        "rule's counter must reflect k1+k2={} total connections -- the pre-reapply reading \
         (k1={k1}) must survive nft's raw counter reset via the offset accumulator, not just \
         show k2={k2}: {:?}",
        k1 + k2,
        counters2.by_rule
    );

    let _ = listener.kill();
    drop(lab);
}

// --- (f) probe fallback: the forced-choice mechanism itself --------------

/// `probe_with(BackendKind::Nftables, ..)` must return a genuinely
/// FUNCTIONAL nftables backend (not just report the right `kind()`) --
/// applies a deny-all-tcp policy and confirms a connect is actually denied.
///
/// **Honest limitation (documented per the brief's explicit allowance):**
/// this test exercises the forced-choice mechanism (`probe_with`), NOT
/// `probe`'s real auto-detect "eBPF attempt, then nftables fallback"
/// branching. The privileged dev container this suite always runs in
/// always has a genuinely working eBPF attach path (every other suite in
/// this crate depends on that), so there is no env-var-free, honest way
/// found here to make eBPF ACTUALLY fail inside this container and observe
/// `probe()` (not `probe_with`) fall back on its own -- doing so would need
/// e.g. a kernel without BTF/tc-BPF support, or dropping `CAP_BPF`/
/// `CAP_SYS_ADMIN` from the test process, neither of which is available
/// from a plain `cargo test` in this image. TODO(implementer/reviewer): if
/// a clean way to force a genuine eBPF failure in-container turns up during
/// Step 3, add a companion test driving bare `probe()` through it; until
/// then, `probe`'s real fallback branch (the `Err` arm calling into
/// `NftEnforcer` instead of returning early, per this same commit's
/// `src/lib.rs` doc comment on `probe_with`) is implementer-verified by
/// code inspection/the task report, not by an automated test here.
#[test]
// The spawned child is a long-lived netns helper (traffic generator /
// listener) that this harness kills at teardown; `wait()`ing on it here
// would block the test forever, which is what clippy's fix would do.
#[allow(clippy::zombie_processes)]
fn probe_with_nftables_returns_a_functional_nftables_backend() {
    let (lab, a, b) = wg_lab("aeth12");
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    let mut enforcer =
        wiremesh_enforcer::probe_with(BackendKind::Nftables, "wg0", EnforcerConfig::default())
            .expect("probe_with(Nftables, ..) should return a working nftables backend");
    assert_eq!(
        enforcer.kind(),
        BackendKind::Nftables,
        "probe_with(Nftables, ..) must report BackendKind::Nftables, not silently pick eBPF"
    );

    enforcer
        .apply(&empty_ir(1))
        .expect("empty (default-deny) policy should apply against the forced nftables backend");

    let mut listener = spawn_accept_only_listener(&b, 9700);
    std::thread::sleep(Duration::from_millis(150));
    assert!(
        !tcp_connect(&a, "10.10.0.2", 9700, 2),
        "a default-deny policy applied through the forced-choice nftables backend must actually \
         deny traffic, not just report the right BackendKind"
    );

    let _ = listener.kill();
    drop(lab);
}
