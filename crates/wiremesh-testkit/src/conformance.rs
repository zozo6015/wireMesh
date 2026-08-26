//! Backend-parity conformance suite (Task 13; design §8/D-C3-7):
//! `Scenario`/`Step`/`run_scenario` drive ONE scenario table — a sequence of
//! packets-in and expected verdicts, expressed against the compiled
//! `PolicyIR` and the `wiremesh_enforcer::Enforcer` trait — against EITHER
//! backend (`BackendKind::{Ebpf,Nftables}`) in an identical netns topology.
//! `crates/wiremesh-testkit/tests/conformance.rs` iterates `[Ebpf,
//! Nftables] × SCENARIOS`; per D-C3-7 a scenario passes only if it passes
//! on BOTH backends — with exactly ONE ratified, documented exception:
//! [`Step::SendExpectByBackend`] (see that variant's own doc comment and
//! `docs/research/cycle3-policy-notes.md`'s "Task 13" section). Every other
//! `Step` in every other scenario asserts a single [`Expect`] both backends
//! must satisfy identically — a scenario reaching for
//! `SendExpectByBackend` a second time, without an equally traced and
//! equally ratified `docs/research/` writeup, is doing it wrong.
//!
//! **Fixed two-node topology, matching every prior enforcer test suite's
//! convention** (`tests/{ebpf_backend,generations,flow_table,deny_events,
//! nft_backend}.rs`): [`netns::wg_lab`] always creates exactly two peers,
//! `a` (`10.10.0.1`) and `b` (`10.10.0.2`), and the `Enforcer` instance
//! under test is always loaded on `b`'s `wg0` (`join_netns(&b.name)` then
//! `probe_with(kind, "wg0", ..)`) — `a` never runs an enforcer at all, it's
//! a bare, unenforced traffic generator/receiver. Consequently only
//! ingress to `b` (`from: Node::A, to: Node::B`) is ever actually policed;
//! `Node::B -> Node::A` sends always succeed (matching the design's
//! ingress-enforce/egress-record split, §6) and are used by several
//! scenarios purely to seed conntrack/`FLOWS` state for a later reply.
//! [`Endpoint`]/[`Node`] name which of these two fixed peers a `Step::Send`
//! addresses, not an arbitrary host.
//!
//! **`FlushFlows` (read before writing a FlushFlows-adjacent scenario) —
//! design-promised parity, met on both backends, NOT a
//! `SendExpectByBackend` case:** design §8 and the master spec both
//! promise "`FlushFlows` forces re-evaluation" as a capability of BOTH
//! backends. `EbpfEnforcer::flush_flows` (Task 9/`flow_table.rs`'s own
//! dedicated, eBPF-only test) genuinely clears the `FLOWS` fast-path map;
//! `NftEnforcer::flush_flows` (`wiremesh-enforcer/src/nft.rs`) runs
//! `conntrack -F`, forcing every established fabric flow back to `ct
//! state new` so it's re-evaluated against the live ruleset on its next
//! packet — the same "forces re-evaluation" contract, reached by each
//! backend's own native mechanism. (This closed a brief Task 12 deferral:
//! `NftEnforcer::flush_flows` started life as a no-op, which Task 13's
//! conformance suite caught as a real, deliberate red-first finding — see
//! `docs/research/cycle3-policy-notes.md`'s "Task 13" section for that
//! history — NOT the ratified one-way-UDP divergence documented on
//! [`Step::SendExpectByBackend`], which remains the suite's only
//! sanctioned per-backend exception.)
//! [`SCENARIOS`]'s `flush_forces_reevaluation_scenario` asserts this
//! design-promised behavior identically for both backends: a
//! bidirectional/conntrack-trackable flow survives the policy update until
//! `FlushFlows` runs, then is denied on its very next packet, on EITHER
//! backend. See `docs/research/cycle3-policy-notes.md`'s "Task 13" section
//! for why that scenario deliberately uses a bidirectional flow, unlike
//! the ratified one-way-UDP scenario.

use crate::netns::{join_netns, wg_lab, Ns};
use anyhow::{ensure, Context};
use std::process::Child;
use std::time::Duration;
use wiremesh_enforcer::{BackendKind, EnforcerConfig};
use wiremesh_policy::{compile, parse_policy, PolicyIR, SegmentDef};

/// One of the two fixed `wg_lab` peers. See this module's doc comment for
/// the "only `b` runs an enforcer" convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Node {
    A,
    B,
}

/// A traffic endpoint: which fixed lab peer, and which port. For TCP,
/// `from.port` is never read (the client always uses an ephemeral source
/// port) — set it to `0` by convention. For ICMP echo, both `from.port`/
/// `to.port` are ignored. For UDP and [`L4::IcmpFragNeeded`], `from.port`/
/// `to.port` are load-bearing: they're the exact 4-tuple that identifies
/// "the same flow" across multiple [`Step::Send`] entries in one scenario
/// (there is no persistent socket/child-process threaded between steps —
/// reusing the identical `(from, to, ports)` quadruple across steps is
/// itself what makes the kernel's conntrack/`FLOWS` treat them as the same
/// flow, exactly as a real gateway's packets would).
#[derive(Debug, Clone, Copy)]
pub struct Endpoint {
    pub node: Node,
    pub port: u16,
}

/// Convenience constructor, mostly so `SCENARIOS` tables read as
/// `ep(Node::A, 8000)` rather than a bare struct literal at every call site.
pub const fn ep(node: Node, port: u16) -> Endpoint {
    Endpoint { node, port }
}

/// Which protocol/verdict-path a [`Step::Send`] exercises.
#[derive(Debug, Clone, Copy)]
pub enum L4 {
    Tcp,
    Udp,
    /// Plain ICMP echo request (`ping`) — ordinary first-match rule
    /// evaluation (an echo request is conntrack-`NEW`, not
    /// `established`/`related`, so it needs its own explicit `icmp` rule to
    /// be allowed).
    Icmp,
    /// A crafted ICMPv4 "destination unreachable / fragmentation needed"
    /// (type 3, code 4) message, embedding a fake original UDP header —
    /// design §6's PMTUD-style embedded-error handling, which both
    /// backends pass via `related`/the eBPF backend's explicit embedded-
    /// tuple lookup, REGARDLESS of whether the current policy has any icmp
    /// rule at all, as long as the embedded tuple matches a real,
    /// previously-recorded flow.
    ///
    /// The outer message is always sent `from` -> `to` (matching every
    /// other `Step::Send` convention: `to` is where the enforcer's ingress
    /// hook is exercised). The embedded (fake original) header's tuple is
    /// derived as `esrc_ip = addr(to)`, `edst_ip = addr(from)` — i.e. it
    /// claims to be part of a flow that ran in the OPPOSITE direction of
    /// this Send (`to` was the original sender, `from` the original
    /// destination), matching how a real ICMP error is addressed back
    /// toward the original packet's source. `embedded_src_port`/
    /// `embedded_dst_port` must be passed as the exact ports an earlier
    /// `Step::Send{proto: L4::Udp, from: <to-of-this-step>, to:
    /// <from-of-this-step>, ..}` step in the same scenario already used, to
    /// genuinely match a real recorded flow (or deliberately not, for a
    /// negative control).
    IcmpFragNeeded {
        embedded_src_port: u16,
        embedded_dst_port: u16,
    },
    /// A bare IPv4 packet carrying an arbitrary, non-{tcp,udp,icmp} IP
    /// protocol number (e.g. `47` = GRE) with a minimal/empty payload — no
    /// L4 semantics at all, just the IP header's protocol field set to
    /// `proto_num`. Exists to distinguish a proto-`any` DSL rule (design
    /// §4: "tcp+udp+icmp", NOT "every IP protocol") from a truly
    /// protocol-unrestricted allow: a proto-any rule must still DENY this,
    /// falling through to default-deny. `port`/direction conventions are
    /// the same as every other `L4` variant (`to` is where the enforcer's
    /// ingress hook is exercised); `Endpoint::port` is ignored (raw IP has
    /// no port concept).
    RawIpProto(u8),
}

/// A `Step::Send`'s expected outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    Delivered,
    Dropped,
}

/// One step in a [`Scenario`]. See each variant's doc comment; the overall
/// shape matches `.superpowers/sdd/task-13-brief.md`'s `Interfaces` section.
#[derive(Debug, Clone, Copy)]
pub enum Step {
    /// Sends one packet (or a short crafted sequence, for
    /// [`L4::IcmpFragNeeded`]) from `from` to `to` and asserts whether it
    /// was delivered.
    Send {
        from: Endpoint,
        to: Endpoint,
        proto: L4,
        expect: Expect,
    },
    /// **The single sanctioned per-backend exception to "one Step, one
    /// Expect, both backends must agree."** Identical to [`Step::Send`]
    /// except the expected outcome is chosen by `kind` at run time
    /// (`ebpf` on [`BackendKind::Ebpf`], `nftables` on
    /// [`BackendKind::Nftables`]) rather than being one shared [`Expect`].
    ///
    /// Exists for exactly one ratified, documented divergence (owner
    /// decision: ACCEPT & DOCUMENT — see
    /// `docs/research/cycle3-policy-notes.md`'s "Task 13" section): a
    /// one-way (never-replied) UDP flow survives a policy update that
    /// removes its allow rule on eBPF (the `FLOWS` fast-path map records
    /// any previously-allowed packet, direction-agnostic, and `apply()`
    /// never touches it) but NOT on nftables (`ct state
    /// established,related` requires conntrack to have seen a REPLY in
    /// the reverse direction before it calls a UDP flow `established`; a
    /// purely one-way flow stays `new` forever and is re-evaluated
    /// against the live rule set on every packet). This is a real,
    /// bounded, understood boundary of the nftables fallback backend, not
    /// a bug — do not add another `SendExpectByBackend` without an
    /// equally traced, equally ratified finding recorded in
    /// `docs/research/`; every other scenario/step in this suite must
    /// keep asserting ONE `Expect` that both backends satisfy identically.
    SendExpectByBackend {
        from: Endpoint,
        to: Endpoint,
        proto: L4,
        ebpf: Expect,
        nftables: Expect,
    },
    /// Recompiles `yaml` against the scenario's `segments` (a fresh
    /// `wiremesh_policy::compile` call, incrementing the running policy
    /// version) and `Enforcer::apply`s it — a mid-scenario policy update.
    ApplyPolicy {
        yaml: &'static str,
    },
    /// Calls `Enforcer::flush_flows`. See this module's doc comment for
    /// what "forces re-evaluation" means (and does not mean) identically
    /// across both backends.
    FlushFlows,
    Sleep {
        ms: u64,
    },
    /// Asserts `enforcer.counters().by_rule[rule_id] >= min`, where
    /// `rule_id` is looked up from the MOST RECENTLY applied `PolicyIR`
    /// (the scenario's initial `policy_yaml`, or the yaml of the last
    /// `ApplyPolicy` step seen so far) as `ir.blocks[block][rule]`.
    /// `pair` is a `"{from}->{to}"` sanity label checked against that
    /// block's own `from`/`to` fields — a documentation aid + a guard
    /// against a scenario author pointing `block` at the wrong index after
    /// an edit, not itself part of the lookup key.
    ExpectCounter {
        rule_id_of: (&'static str, usize, usize),
        min: u64,
    },
}

/// One scenario: a policy, the segment table to compile it against, and a
/// sequence of steps to drive through it. `run_scenario` builds a fresh
/// `wg_lab` per call, so scenarios never share state with each other.
#[derive(Debug, Clone, Copy)]
pub struct Scenario {
    pub name: &'static str,
    pub policy_yaml: &'static str,
    pub segments: &'static [(&'static str, &'static [&'static str])],
    pub steps: &'static [Step],
}

fn addr_of(node: Node) -> &'static str {
    match node {
        Node::A => "10.10.0.1",
        Node::B => "10.10.0.2",
    }
}

fn ns_of<'a>(a: &'a Ns, b: &'a Ns, node: Node) -> &'a Ns {
    match node {
        Node::A => a,
        Node::B => b,
    }
}

/// Parses+validates+compiles `yaml` against `segs` at `version` — the SAME
/// two-call `wiremesh_policy` path the controller uses (design §7's
/// `apply::compile_policy`), just invoked directly rather than through a
/// running controller.
fn compile_yaml(yaml: &str, segs: &[SegmentDef], version: u64) -> anyhow::Result<PolicyIR> {
    let src = parse_policy(yaml, segs)
        .map_err(|errors| anyhow::anyhow!("policy parse/validate errors: {errors:?}"))?;
    compile(&src, segs, version)
        .map_err(|errors| anyhow::anyhow!("policy compile errors: {errors:?}"))
}

/// Builds the `wg_lab`, compiles `s.policy_yaml`, loads `kind`'s `Enforcer`
/// on `b`'s `wg0`, and drives `s.steps` in order. Returns `Err` (with
/// context naming the scenario and step index) on the first expectation
/// mismatch or operational failure.
pub fn run_scenario(s: &Scenario, kind: BackendKind) -> anyhow::Result<()> {
    let (lab, a, b) = wg_lab("aeth13");
    join_netns(&b.name).context("join b's netns before probing wg0 in-process")?;

    let mut enforcer = wiremesh_enforcer::probe_with(kind, "wg0", EnforcerConfig::default())
        .with_context(|| format!("scenario {:?}: probe_with({kind:?}, wg0, ..)", s.name))?;
    ensure!(
        enforcer.kind() == kind,
        "scenario {:?}: probe_with({kind:?}, ..) reported kind()={:?}",
        s.name,
        enforcer.kind()
    );

    let segs: Vec<SegmentDef> = s
        .segments
        .iter()
        .map(|(name, cidrs)| SegmentDef {
            name: (*name).to_string(),
            cidrs: cidrs
                .iter()
                .map(|c| {
                    c.parse().unwrap_or_else(|e| {
                        panic!("scenario {:?}: bad segment CIDR {c:?}: {e}", s.name)
                    })
                })
                .collect(),
        })
        .collect();

    let mut version = 1u64;
    let mut current_ir = compile_yaml(s.policy_yaml, &segs, version)
        .with_context(|| format!("scenario {:?}: compiling initial policy_yaml", s.name))?;
    enforcer
        .apply(&current_ir)
        .with_context(|| format!("scenario {:?}: initial apply", s.name))?;

    for (i, step) in s.steps.iter().enumerate() {
        match step {
            Step::Send {
                from,
                to,
                proto,
                expect,
            } => {
                let delivered = send_and_observe(&a, &b, *from, *to, *proto);
                let want = *expect == Expect::Delivered;
                ensure!(
                    delivered == want,
                    "scenario {:?} step {i} (Send {:?} {:?}->{:?}): expected {:?}, got {}",
                    s.name,
                    proto,
                    from,
                    to,
                    expect,
                    if delivered { "Delivered" } else { "Dropped" }
                );
            }
            Step::SendExpectByBackend {
                from,
                to,
                proto,
                ebpf,
                nftables,
            } => {
                let delivered = send_and_observe(&a, &b, *from, *to, *proto);
                let expect = match kind {
                    BackendKind::Ebpf => *ebpf,
                    BackendKind::Nftables => *nftables,
                };
                let want = expect == Expect::Delivered;
                ensure!(
                    delivered == want,
                    "scenario {:?} step {i} (SendExpectByBackend {:?} {:?}->{:?}, kind={kind:?}): \
                     expected {:?} (the ratified per-backend expectation for this kind), got {}",
                    s.name,
                    proto,
                    from,
                    to,
                    expect,
                    if delivered { "Delivered" } else { "Dropped" }
                );
            }
            Step::ApplyPolicy { yaml } => {
                version += 1;
                current_ir = compile_yaml(yaml, &segs, version).with_context(|| {
                    format!("scenario {:?} step {i}: compiling ApplyPolicy yaml", s.name)
                })?;
                enforcer.apply(&current_ir).with_context(|| {
                    format!("scenario {:?} step {i}: ApplyPolicy apply()", s.name)
                })?;
            }
            Step::FlushFlows => {
                enforcer
                    .flush_flows()
                    .with_context(|| format!("scenario {:?} step {i}: flush_flows()", s.name))?;
            }
            Step::Sleep { ms } => {
                std::thread::sleep(Duration::from_millis(*ms));
            }
            Step::ExpectCounter { rule_id_of, min } => {
                let (pair, block_idx, rule_idx) = *rule_id_of;
                let block = current_ir.blocks.get(block_idx).ok_or_else(|| {
                    anyhow::anyhow!(
                        "scenario {:?} step {i}: ExpectCounter block index {block_idx} out of \
                         range (current IR has {} block(s))",
                        s.name,
                        current_ir.blocks.len()
                    )
                })?;
                let actual_pair = format!("{}->{}", block.from, block.to);
                ensure!(
                    actual_pair == pair,
                    "scenario {:?} step {i}: ExpectCounter's pair label {pair:?} doesn't match \
                     block {block_idx}'s actual (from,to) {actual_pair:?} — likely a stale index \
                     after a scenario edit",
                    s.name
                );
                let rule = block.rules.get(rule_idx).ok_or_else(|| {
                    anyhow::anyhow!(
                        "scenario {:?} step {i}: ExpectCounter rule index {rule_idx} out of \
                         range (block {block_idx} has {} rule(s))",
                        s.name,
                        block.rules.len()
                    )
                })?;
                let counters = enforcer
                    .counters()
                    .with_context(|| format!("scenario {:?} step {i}: counters()", s.name))?;
                let got = counters.by_rule.get(&rule.rule_id).copied().unwrap_or(0);
                ensure!(
                    got >= *min,
                    "scenario {:?} step {i}: ExpectCounter rule_id {} (block {block_idx} rule \
                     {rule_idx}) got {got}, want >= {min}: full by_rule={:?}",
                    s.name,
                    rule.rule_id,
                    counters.by_rule
                );
            }
        }
    }

    drop(lab);
    Ok(())
}

/// Dispatches one `Step::Send` to the right proto-specific driver and
/// returns whether the packet was observed as delivered.
fn send_and_observe(a: &Ns, b: &Ns, from: Endpoint, to: Endpoint, proto: L4) -> bool {
    let from_ns = ns_of(a, b, from.node);
    let to_ns = ns_of(a, b, to.node);
    let to_addr = addr_of(to.node);
    match proto {
        L4::Tcp => check_tcp(from_ns, to_ns, to_addr, to.port),
        L4::Udp => check_udp(
            from_ns,
            to_ns,
            addr_of(from.node),
            from.port,
            to_addr,
            to.port,
        ),
        L4::Icmp => check_icmp_echo(from_ns, to_addr),
        L4::IcmpFragNeeded {
            embedded_src_port,
            embedded_dst_port,
        } => check_icmp_frag_needed(
            from_ns,
            to_ns,
            addr_of(from.node),
            to_addr,
            embedded_src_port,
            embedded_dst_port,
        ),
        L4::RawIpProto(proto_num) => check_raw_ip_proto(from_ns, to_ns, to_addr, proto_num),
    }
}

// --- packet-level helpers -- adapted from `tests/nft_backend.rs`'s
// established inline-python3 convention (no `nc`/`ncat`/`socat` in this
// image), generalized to take addr/port arguments instead of being baked
// into one specific test's script. ---------------------------------------

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

fn check_tcp(from_ns: &Ns, to_ns: &Ns, to_addr: &str, dst_port: u16) -> bool {
    let mut listener = spawn_accept_only_listener(to_ns, dst_port);
    std::thread::sleep(Duration::from_millis(200));
    let ok = tcp_connect(from_ns, to_addr, dst_port, 2);
    let _ = listener.kill();
    // Reap it. `Ns::spawn` runs `nsenter -- ip netns exec <ns> <cmd>`, and
    // both `nsenter` (no PID namespace here) and `ip netns exec` EXEC rather
    // than fork, so the direct child IS the helper: after SIGKILL this
    // returns immediately and cannot block.
    let _ = listener.wait();
    ok
}

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

fn check_udp(
    from_ns: &Ns,
    to_ns: &Ns,
    from_addr: &str,
    src_port: u16,
    to_addr: &str,
    dst_port: u16,
) -> bool {
    let probe = spawn_udp_recv_probe(to_ns, dst_port, 2.0);
    std::thread::sleep(Duration::from_millis(150));
    udp_send_from(from_ns, from_addr, src_port, to_addr, dst_port);
    probe_received(probe)
}

fn check_icmp_echo(from_ns: &Ns, to_addr: &str) -> bool {
    from_ns
        .exec(&["ping", "-c", "1", "-W", "3", to_addr])
        .is_ok()
}

/// Raw ICMPv4 type probe -- graduated from `tests/nft_backend.rs`'s
/// `spawn_icmp_type_probe`/`icmp_probe_got`/`send_icmp_dest_unreachable`.
fn spawn_icmp_type_probe(ns: &Ns, want_type: u8, timeout_s: f64) -> Child {
    let script = format!(
        r#"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
s.settimeout({timeout_s})
try:
    while True:
        data, _ = s.recvfrom(2048)
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

/// See [`L4::IcmpFragNeeded`]'s doc comment for the outer-vs-embedded
/// addressing convention this implements.
fn check_icmp_frag_needed(
    from_ns: &Ns,
    to_ns: &Ns,
    from_addr: &str,
    to_addr: &str,
    embedded_src_port: u16,
    embedded_dst_port: u16,
) -> bool {
    let probe = spawn_icmp_type_probe(to_ns, 3, 2.0);
    std::thread::sleep(Duration::from_millis(150));
    send_icmp_dest_unreachable(
        from_ns,
        to_addr,
        4,         // code 4: fragmentation needed (PMTUD)
        to_addr,   // embedded esrc_ip = the original sender = `to` of this Send
        from_addr, // embedded edst_ip = the original destination = `from` of this Send
        embedded_src_port,
        embedded_dst_port,
    );
    icmp_probe_got(probe, 3)
}

/// Spawns a background raw-IP listener bound to protocol `proto_num` on
/// `ns` -- a `SOCK_RAW` socket created with a NON-zero protocol number is
/// only delivered packets whose IP header's protocol field matches it
/// (the kernel's own raw-socket protocol hash), so this is already
/// filtered to exactly `proto_num`, unlike [`spawn_icmp_type_probe`] (all
/// ICMP, further filtered by hand on `icmp[0]`). Same
/// after-netfilter-input-hook delivery property as every other raw-socket
/// probe in this module: a `drop` verdict at the enforcer's ingress hook
/// means this listener never sees the packet at all.
fn spawn_raw_ip_proto_probe(ns: &Ns, proto_num: u8, timeout_s: f64) -> Child {
    let script = format!(
        r#"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, {proto_num})
s.settimeout({timeout_s})
try:
    s.recvfrom(2048)
    print("RECEIVED")
except socket.timeout:
    print("TIMEOUT")
"#
    );
    ns.spawn(&["python3", "-c", &script])
        .expect("spawn raw ip proto probe")
}

fn raw_probe_received(child: Child) -> bool {
    let out = child
        .wait_with_output()
        .expect("raw ip proto probe should exit");
    String::from_utf8_lossy(&out.stdout).trim() == "RECEIVED"
}

/// Sends one bare IPv4 packet from `ns` to `dst_ip` with its protocol
/// field set to `proto_num` and a minimal, semantically-empty payload --
/// no L4 header of any kind, just enough bytes to be a non-empty packet.
/// No `IP_HDRINCL`: the kernel builds the IP header itself (protocol =
/// `proto_num`, source = whatever route/interface selection picks, which
/// for an overlay-addressed `dst_ip` is `wg0`) -- the same
/// kernel-builds-the-IP-header pattern [`send_icmp_dest_unreachable`]
/// already relies on for crafted ICMP.
fn send_raw_ip_proto_packet(ns: &Ns, dst_ip: &str, proto_num: u8) {
    let script = format!(
        r#"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, {proto_num})
s.sendto(b"\x00" * 8, ("{dst_ip}", 0))
"#
    );
    ns.exec(&["python3", "-c", &script])
        .expect("sending raw ip proto packet");
}

/// See [`L4::RawIpProto`]'s doc comment: proves a proto-`any` DSL rule
/// (design §4: "tcp+udp+icmp") does NOT accidentally allow every IP
/// protocol -- `proto_num` (e.g. `47` = GRE) must fall through to
/// default-deny even under a proto-any allow rule covering the same
/// CIDRs.
fn check_raw_ip_proto(from_ns: &Ns, to_ns: &Ns, to_addr: &str, proto_num: u8) -> bool {
    let probe = spawn_raw_ip_proto_probe(to_ns, proto_num, 2.0);
    std::thread::sleep(Duration::from_millis(150));
    send_raw_ip_proto_packet(from_ns, to_addr, proto_num);
    raw_probe_received(probe)
}

/// Standalone continuous-traffic conformance check (design §8/D-C3-7's
/// "flip-under-traffic zero-loss" item): NOT expressed as a [`Scenario`] —
/// the `Step`/`Send` model is packet-in/verdict-out, and this scenario is
/// instead a wall-clock measurement (zero UDP receive-count deficit across
/// N back-to-back re-`apply()`s of the SAME allow policy, concurrent with a
/// continuous stream) — the Task 8(d)/Task 12(d) pattern from
/// `tests/generations.rs`/`tests/nft_backend.rs`, graduated here so it runs
/// against BOTH backends from the same call site rather than being
/// duplicated per-backend. Callers (this crate's `tests/conformance.rs`)
/// call this once per `BackendKind`, alongside the `SCENARIOS` table.
// Both children ARE reaped, by `wait_with_output()` below. The lint fires on
// the EARLY-RETURN paths: this function is `-> anyhow::Result<_>` and several
// `?`/`with_context` arms return before those calls, leaving the children
// unreaped on a failure path. Reaping them there would mean restructuring the
// whole body around a guard type purely to satisfy a lint, on a path that only
// runs when the test is already failing and whose namespace `Lab`'s `Drop`
// tears down regardless.
#[expect(
    clippy::zombie_processes,
    reason = "children are reaped by `wait_with_output()` on the success path; the lint is about `?` early-return arms, where `Lab`'s Drop destroys the namespace anyway"
)]
pub fn flip_under_traffic_zero_loss(kind: BackendKind) -> anyhow::Result<()> {
    let (lab, a, b) = wg_lab("aeth13");
    join_netns(&b.name).context("join b's netns before probing wg0 in-process")?;

    // (Review finding, revised by Backlog item 1) The reap grace is the
    // minimum spacing between generation flips: overwriting an outer-array
    // slot sooner can pull the maps out from under packets still reading
    // them, which is precisely the deficit this scenario measures. With the
    // default 10s, 20 correctly-spaced flips would take ~190s and run long
    // after the ~3.5s sender / 1.5s receiver-idle traffic window has closed,
    // defeating the "concurrent with live traffic" point. Shrink it so all
    // 20 flips genuinely complete while traffic is still flowing.
    //
    // The grace is now HONORED BY THIS CALLER (see the flip loop below)
    // rather than slept out inside `apply()`.
    let cfg = EnforcerConfig {
        reap_grace: Duration::from_millis(50),
        ..EnforcerConfig::default()
    };
    let mut enforcer = wiremesh_enforcer::probe_with(kind, "wg0", cfg)
        .with_context(|| format!("flip_under_traffic_zero_loss({kind:?}): probe_with"))?;

    let segs = vec![
        SegmentDef {
            name: "seg-a".into(),
            cidrs: vec!["10.10.0.1/32".parse().unwrap()],
        },
        SegmentDef {
            name: "seg-b".into(),
            cidrs: vec!["10.10.0.2/32".parse().unwrap()],
        },
    ];
    let yaml = "
policy:
  - from: seg-a
    to: seg-b
    rules:
      - allow:
          proto: udp
          ports: [7600]
";
    let ir = compile_yaml(yaml, &segs, 1).with_context(|| {
        format!("flip_under_traffic_zero_loss({kind:?}): compiling allow-udp policy")
    })?;
    enforcer
        .apply(&ir)
        .with_context(|| format!("flip_under_traffic_zero_loss({kind:?}): initial apply"))?;

    let receiver = spawn_udp_counting_receiver(&b, 7600, 1.5);
    std::thread::sleep(Duration::from_millis(150));
    let sender = spawn_udp_sender(&a, "10.10.0.2", 7600, 350, 0.01); // ~3.5s total

    // 20 flips of the SAME allow policy, concurrent with the live traffic.
    //
    // The explicit wait is REQUIRED (Backlog item 1): `apply()` used to sleep
    // out the remainder of the prior flip's reap grace itself, which
    // incidentally spaced this loop out; it no longer does, so 20 flips would
    // otherwise land within milliseconds of each other and genuinely violate
    // the grace under live traffic -- a real deficit, not a flaky assertion.
    // Honoring `apply_ready_at()` is exactly what the production caller
    // (`wiremesh_gateway::policy_apply`) does, just synchronously here. The
    // nft backend publishes no deadline (one atomic `nft -f -` transaction,
    // nothing to protect), so this is a no-op on that backend and the loop
    // stays back-to-back there, as before. Cost on eBPF: 20 x the 50ms grace
    // configured above = ~1s, well inside the traffic window.
    for i in 0..20 {
        if let Some(t) = enforcer.apply_ready_at() {
            let now = std::time::Instant::now();
            if t > now {
                std::thread::sleep(t - now);
            }
        }
        enforcer
            .apply(&ir)
            .with_context(|| format!("flip_under_traffic_zero_loss({kind:?}): flip #{i}"))?;
    }

    let sender_out = sender
        .wait_with_output()
        .context("udp sender should exit")?;
    ensure!(
        sender_out.status.success(),
        "udp sender exited non-zero: {sender_out:?}"
    );
    let sent: u64 = String::from_utf8_lossy(&sender_out.stdout)
        .trim()
        .parse()
        .context("udp sender should print its packet count")?;

    let receiver_out = receiver
        .wait_with_output()
        .context("udp receiver should exit after its idle timeout")?;
    ensure!(
        receiver_out.status.success(),
        "udp receiver exited non-zero: {receiver_out:?}"
    );
    let received: u64 = String::from_utf8_lossy(&receiver_out.stdout)
        .trim()
        .parse()
        .context("udp receiver should print its packet count")?;

    ensure!(
        received == sent,
        "flip_under_traffic_zero_loss({kind:?}): zero received-count deficit expected across 20 \
         back-to-back applies of the same allow policy (sent {sent}, received {received})"
    );

    drop(lab);
    Ok(())
}

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
