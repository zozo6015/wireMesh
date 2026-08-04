//! Task 14 Step 1 (cycle 3): the capstone end-to-end test — design §1's done
//! bar in one test (`.superpowers/sdd/task-14-brief.md`). Ties together
//! every piece cycle 3 built separately:
//!
//!  1. A real controller (`wiremesh_testkit::TestController`) compiles the
//!     master-spec §5.1 / policy-pipeline-design §5.1 worked example
//!     (`proxmox-lab` 10.10.0.0/16 -> `aws-prod` 172.16.0.0/12, a deny
//!     carve-out ahead of two allows) via `Admin.Apply` — the same fabric
//!     literal already exercised in `wiremesh-controller/tests/{policy_pipeline,
//!     get_policy}.rs` and `fabricctl/tests/cli.rs`, duplicated here for the
//!     same reason those files each duplicate it: every `tests/*.rs` file is
//!     its own independent compiled binary, with no shared module to pull a
//!     constant from.
//!  2. A stub gateway enrolled AFTER that apply receives the compiled
//!     `policy_ir` bytes + `policy_version` as part of its very first
//!     `Sync.Watch` `StateSnapshot` (mirrors
//!     `policy_pipeline.rs::apply_compiles_real_policy_and_snapshot_carries_it`).
//!  3. Those EXACT bytes are parsed with `wiremesh_policy::PolicyIR::from_json`
//!     — proving the wire bytes a real gateway would receive are genuinely
//!     parseable, not re-derived from the source YAML a second time.
//!  4. That SAME parsed `PolicyIR` is fed into a REAL `wiremesh-enforcer`
//!     backend, loaded on `wg0` inside a privileged netns lab, and a real
//!     TCP SYN is sent for a packet the policy ALLOWS (tcp/5432 to
//!     `172.16.1.50`, the exact host the design example's second rule
//!     names) and one it DENIES (tcp/22 to the same host, caught by the
//!     first rule's carve-out ahead of any allow) — proving the verdict the
//!     wire bytes describe is what a real backend actually enforces, not
//!     just what the struct fields say.
//!  5. The stub gateway then calls `Sync.Report{applied_version: 1}` (the
//!     same call `fabricctl/tests/cli.rs::report_applied_version` makes),
//!     and `Admin.ListGateways` — the data `fabricctl policy status`
//!     renders (`crates/fabricctl/src/main.rs`'s `policy status` subcommand)
//!     — must show that gateway's `applied_version == 1`.
//!
//! **Why a custom netns lab instead of `wiremesh_testkit::netns::wg_lab` /
//! `conformance.rs`'s fixed topology:** `wg_lab` hardcodes both peers onto
//! the SAME `10.10.0.0/24` overlay (so `conformance.rs` always compiles its
//! OWN synthetic segments — `10.10.0.1/32` / `10.10.0.2/32` — to match).
//! This test instead needs the enforcer to evaluate the REAL IR the
//! controller compiled for the REAL `proxmox-lab`/`aws-prod` CIDRs (design
//! §1's whole point is proving the bytes that cross the wire are what gets
//! enforced) — so [`design_lab`] below builds a two-node kernel-WireGuard
//! lab addressed directly inside those two CIDRs instead: `a` at
//! `10.10.9.9` (proxmox-lab), `b` at `172.16.1.50` (aws-prod — the exact
//! host the design example's port-5432 allow rule names), with explicit
//! cross-CIDR routes over `wg0` (unlike `wg_lab`'s single on-link `/24`,
//! these two addresses sit in genuinely disjoint ranges). Everything else
//! (kernel WireGuard via `ip link add wg0 type wireguard`, `join_netns` +
//! `probe_with` + `apply`, and the `python3`-socket TCP check) mirrors
//! `wiremesh_testkit::netns::wg_lab` / `conformance.rs`'s already-graduated
//! patterns — duplicated here (not exported as new pub API) since this is
//! this file's own one-off topology, not a third reusable convention.
//!
//! Only `BackendKind::Ebpf` is required to satisfy design §1's done bar
//! (per the Task 14 brief); `BackendKind::Nftables` is exercised too since
//! `probe_with` and the lab setup are identical either way and the marginal
//! cost of a second pass is small.
//!
//! Run (privileged Linux dev container only — see `CLAUDE.md`'s "Host is
//! macOS" execution rule): `./dev.sh run "cargo test -p wiremesh-testkit \
//! --features netns --test end_to_end_policy -- --test-threads=1 --nocapture"`.
// Compiles to an empty test binary unless `netns` is on: this file needs the
// privileged netns lab plus `wiremesh_policy`/`wiremesh_enforcer`, all of
// which only exist behind that feature, so without this gate a plain
// `cargo build -p wiremesh-testkit` fails to resolve them. Same pattern as
// `tests/netem.rs`.
#![cfg(feature = "netns")]

use std::io::Write;
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use tokio_stream::StreamExt;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use wiremesh_enforcer::{BackendKind, EnforcerConfig};
use wiremesh_policy::{IrAction, IrProto, PolicyIR};
use wiremesh_proto::v1::sync_client::SyncClient;
use wiremesh_proto::v1::{sync_message, ListGatewaysRequest, MintTokenRequest, ReportRequest};
use wiremesh_testkit::netns::{join_netns, Lab, Ns};
use wiremesh_testkit::{StubGateway, TestController};

/// Bounds the wait for the initial `Sync.Watch` snapshot — same
/// constant/rationale as `wiremesh-controller/tests/{policy_pipeline,
/// sync_snapshot}.rs`.
const WATCH_TIMEOUT: Duration = Duration::from_secs(5);

/// The master-spec §5.1 / policy-pipeline-design §5.1 worked example,
/// verbatim from `crates/wiremesh-policy/tests/fixtures/design_s5_example.yaml`
/// (also duplicated in `wiremesh-controller/tests/{policy_pipeline,
/// get_policy}.rs` and `fabricctl/tests/cli.rs` — see this file's module
/// doc comment for why). One block, 3 first-match-wins rules: a deny
/// carve-out on ssh, then two allows.
const FABRIC_WITH_POLICY: &str = r#"
segments:
  - name: proxmox-lab
    cidrs: ["10.10.0.0/16"]
  - name: aws-prod
    cidrs: ["172.16.0.0/12"]
policy:
  - from: proxmox-lab
    to: aws-prod
    rules:
      - deny:  { ports: [22], proto: tcp }
      - allow: { dst: 172.16.1.50/32, ports: [5432], proto: tcp }
      - allow: { dst: 172.16.2.0/24, ports: [443, "8000-8080"], proto: tcp }
"#;

/// Dials a fresh mTLS `Sync` channel presenting `gw`'s already-enrolled
/// identity and calls `Sync.Report{applied_version: version}` — the exact
/// recipe `fabricctl/tests/cli.rs::report_applied_version` uses (not itself
/// exposed as public `StubGateway` API, since it needs a plain unary
/// `Report` call rather than a `Watch` stream), duplicated here for the same
/// "each `tests/*.rs` file is its own binary" reason as `FABRIC_WITH_POLICY`
/// above.
async fn report_applied_version(gw: &StubGateway, sync_addr: SocketAddr, version: u64) {
    let uri = format!("https://{sync_addr}");
    let tls = ClientTlsConfig::new()
        .identity(Identity::from_pem(gw.cert_pem(), gw.key_pem()))
        .ca_certificate(Certificate::from_pem(gw.ca_bundle_pem()))
        .domain_name("127.0.0.1");
    let channel = Channel::from_shared(uri)
        .expect("controller Sync TCP addr must form a valid URI")
        .tls_config(tls)
        .expect("configuring StubGateway mTLS for Sync.Report")
        .connect()
        .await
        .expect("connecting to the controller's Sync (mTLS) TCP port for Sync.Report");

    SyncClient::new(channel)
        .report(ReportRequest {
            applied_version: version,
            local_endpoints: vec![],
            relay_health: vec![],
            epoch_acks: vec![],
            peer_paths: vec![],
            peer_paths_snapshot: false,
            // (Sync session generation) 0 = the wire's legacy/unknown
            // sentinel. This local helper dials its own channel and never
            // opens a `Sync.Watch`, so there is no recorded generation to
            // match; sending 0 keeps the controller's gate inert, which is
            // the documented legacy-client contract (a 0 on EITHER side is
            // accepted). Deliberately NOT `gw.session_generation()` — this
            // helper predates `StubGateway::report`/`report_raw` and is kept
            // hand-rolled precisely to exercise a raw, non-testkit client.
            session_generation: 0,
        })
        .await
        .expect("Sync.Report");
}

/// Generates a fresh WireGuard keypair (private, public) via the `wg` CLI —
/// duplicated from `wiremesh_testkit::netns`'s private `wg_keypair` (not
/// exported; see that module's `wg_lab` for the original).
fn wg_keypair() -> (String, String) {
    let priv_out = Command::new("wg").arg("genkey").output().expect("wg genkey");
    let privkey = String::from_utf8(priv_out.stdout)
        .expect("wg genkey stdout must be utf8")
        .trim()
        .to_string();
    let pub_out = {
        let mut c = Command::new("wg")
            .arg("pubkey")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn wg pubkey");
        c.stdin
            .as_mut()
            .expect("wg pubkey child must have stdin")
            .write_all(privkey.as_bytes())
            .expect("write private key to wg pubkey stdin");
        c.wait_with_output().expect("wg pubkey wait")
    };
    (
        privkey,
        String::from_utf8(pub_out.stdout)
            .expect("wg pubkey stdout must be utf8")
            .trim()
            .to_string(),
    )
}

/// Builds a two-node kernel-WireGuard lab addressed DIRECTLY inside the
/// design-§5 example's two real segment CIDRs — see this file's module doc
/// comment for why this differs from `wiremesh_testkit::netns::wg_lab`'s
/// fixed single-`/24` overlay. `a` (proxmox-lab, `10.10.9.9`) never runs an
/// enforcer (bare traffic generator, matching every other netns test suite's
/// "only the ingress side is policed" convention); `b` (aws-prod,
/// `172.16.1.50` — the exact host the design example's port-5432 allow rule
/// names) is where the caller subsequently `join_netns`s + `probe_with`s.
fn design_lab(prefix: &str) -> (Lab, Ns, Ns) {
    let mut lab = Lab::new(prefix).expect("Lab::new for design_lab");
    let a = lab.ns("a").expect("create netns a (proxmox-lab side)");
    let b = lab.ns("b").expect("create netns b (aws-prod side)");
    lab.veth((&a, "u0", "10.9.20.1/24"), (&b, "u1", "10.9.20.2/24"))
        .expect("veth between a and b");

    let (apriv, apub) = wg_keypair();
    let (bpriv, bpub) = wg_keypair();

    for (ns, privkey, peer_pub, my_addr, peer_allowed_ips, peer_ep) in [
        (&a, &apriv, &bpub, "10.10.9.9/16", "172.16.0.0/12", "10.9.20.2:51820"),
        (&b, &bpriv, &apub, "172.16.1.50/12", "10.10.0.0/16", "10.9.20.1:51820"),
    ] {
        ns.exec(&["ip", "link", "add", "wg0", "type", "wireguard"])
            .expect("ip link add wg0");
        // (Review finding) A WireGuard private key is sensitive: write it to
        // a unique, non-predictable path with 0600 perms (not
        // `std::fs::write`'s default umask-derived, world-readable mode) and
        // delete it as soon as `wg set` has consumed it, rather than leaving
        // it sitting in `/tmp` under a name any other local user could guess
        // (`<ns.name>.key`) for the rest of the test run.
        let kf = std::env::temp_dir().join(format!(
            "wiremesh-e2e-{}-{}-{}.key",
            ns.name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock before UNIX_EPOCH")
                .as_nanos()
        ));
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&kf)
                .expect("create wg private key file with 0600 perms");
            f.write_all(privkey.as_bytes()).expect("write wg private key");
        }
        ns.exec(&[
            "wg",
            "set",
            "wg0",
            "listen-port",
            "51820",
            "private-key",
            kf.to_str().expect("temp key path must be valid UTF-8"),
            "peer",
            peer_pub,
            "allowed-ips",
            peer_allowed_ips,
            "endpoint",
            peer_ep,
        ])
        .expect("wg set wg0");
        let _ = std::fs::remove_file(&kf);
        ns.exec(&["ip", "addr", "add", my_addr, "dev", "wg0"])
            .expect("ip addr add on wg0");
        ns.exec(&["ip", "link", "set", "wg0", "up", "mtu", "1280"])
            .expect("ip link set wg0 up");
    }

    // Unlike `wg_lab` (both peers on-link within the same fixed `/24`), `a`
    // and `b` here sit in two genuinely disjoint CIDRs (proxmox-lab vs.
    // aws-prod), so each side needs an explicit route to the OTHER's range
    // over `wg0`.
    a.exec(&["ip", "route", "add", "172.16.0.0/12", "dev", "wg0"])
        .expect("route to aws-prod via wg0 on a");
    b.exec(&["ip", "route", "add", "10.10.0.0/16", "dev", "wg0"])
        .expect("route to proxmox-lab via wg0 on b");

    (lab, a, b)
}

/// `python3`-socket TCP accept-only listener — graduated verbatim (as a
/// duplicate, not a shared export) from `wiremesh_testkit::conformance`'s
/// private `spawn_accept_only_listener` (no `nc`/`ncat`/`socat` in this
/// image).
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

/// `true` iff a TCP SYN from `from_ns` to `to_ns:dst_port` is actually
/// delivered (the listener accepts the connection) — `false` means the
/// enforcer dropped it before it ever reached the listener.
fn check_tcp(from_ns: &Ns, to_ns: &Ns, to_addr: &str, dst_port: u16) -> bool {
    let mut listener = spawn_accept_only_listener(to_ns, dst_port);
    std::thread::sleep(Duration::from_millis(200));
    let ok = tcp_connect(from_ns, to_addr, dst_port, 2);
    let _ = listener.kill();
    ok
}

/// Loads `kind`'s real `Enforcer` on `b`'s `wg0` inside a fresh
/// [`design_lab`], applies `ir` (the EXACT `PolicyIR` parsed from the
/// controller's `Sync.Watch` snapshot bytes), and returns whether a real TCP
/// SYN to the design example's allowed port (5432) and denied port (22) —
/// both addressed at `172.16.1.50`, the exact host the compiled rules name —
/// were actually delivered.
fn enforce_and_probe(ir: &PolicyIR, kind: BackendKind, lab_prefix: &str) -> (bool, bool) {
    let (lab, a, b) = design_lab(lab_prefix);
    join_netns(&b.name).expect("join b's netns before probing wg0 in-process");

    let mut enforcer = wiremesh_enforcer::probe_with(kind, "wg0", EnforcerConfig::default())
        .unwrap_or_else(|e| panic!("probe_with({kind:?}, wg0, ..) failed: {e:#}"));
    enforcer
        .apply(ir)
        .unwrap_or_else(|e| panic!("enforcer.apply(ir) failed for {kind:?}: {e:#}"));

    let delivered_5432 = check_tcp(&a, &b, "172.16.1.50", 5432);
    let delivered_22 = check_tcp(&a, &b, "172.16.1.50", 22);

    drop(lab);
    (delivered_5432, delivered_22)
}

/// The full pipeline in one test (design §1's done bar): `Admin.Apply` ->
/// `Sync.Watch` snapshot carries the compiled IR -> `PolicyIR::from_json`
/// parses those exact bytes -> a real `Enforcer` in a netns lab enforces
/// them (one allowed packet, one denied packet) -> `Sync.Report` -> `Admin.
/// ListGateways` reflects the acked version.
#[tokio::test]
async fn full_pipeline_apply_sync_enforce_report() {
    let h = TestController::start().await;

    // 1. `apply -f` the 2-segment fabric + design-§5 example policy.
    let diff = h.apply(FABRIC_WITH_POLICY).await;
    assert!(
        diff.policy_updated,
        "apply of the design-§5 example fabric must compile a real policy, got diff: {:?}",
        diff
    );

    // Enroll AFTER the apply, so the gateway's very first Sync.Watch message
    // is a StateSnapshot already carrying the freshly compiled policy (same
    // ordering as policy_pipeline.rs's
    // apply_compiles_real_policy_and_snapshot_carries_it).
    let token = h
        .admin_client()
        .await
        .mint_token(MintTokenRequest {
            kind: "gateway".to_string(),
            bound_cidrs: vec!["10.10.0.0/16".to_string()],
            rebind_segment_id: 0,
        })
        .await
        .expect("Admin.MintToken for the stub gateway")
        .into_inner()
        .token;
    let gw = StubGateway::enroll(&h, &token, &["10.10.0.0/16"])
        .await
        .expect("enrolling the stub gateway onto proxmox-lab");

    // 2. The stub gateway receives policy_ir bytes + version over Sync
    //    (StateSnapshot).
    let mut stream = gw.open_sync().await;
    let msg = tokio::time::timeout(WATCH_TIMEOUT, stream.next())
        .await
        .expect("timed out waiting for the initial Sync.Watch snapshot")
        .expect("Sync.Watch stream ended before delivering a message")
        .expect("Sync.Watch stream yielded an error instead of a message");
    let snap = match msg.body {
        Some(sync_message::Body::Snapshot(s)) => s,
        other => panic!("expected the first Sync.Watch message to be a StateSnapshot, got: {other:?}"),
    };
    assert_eq!(
        snap.policy_version, 1,
        "the first-ever compiled policy must be version 1, got {}",
        snap.policy_version
    );
    assert!(
        !snap.policy_ir.is_empty(),
        "snapshot policy_ir must be non-empty once a real policy has been applied"
    );

    // 3. Parse those EXACT bytes with PolicyIR::from_json.
    let ir = PolicyIR::from_json(&snap.policy_ir)
        .expect("snapshot policy_ir must parse as a real PolicyIR");
    assert_eq!(ir.version, 1, "parsed IR version must match the snapshot's policy_version");
    assert_eq!(
        ir.blocks.len(),
        1,
        "the design-§5 example compiles to exactly one proxmox-lab -> aws-prod block, got: {:?}",
        ir.blocks
    );
    let block = &ir.blocks[0];
    assert_eq!(block.from, "proxmox-lab");
    assert_eq!(block.to, "aws-prod");
    assert_eq!(
        block.dst_cidrs,
        vec!["172.16.0.0/12".to_string()],
        "the block's resolved dst_cidrs must be aws-prod's declared CIDR"
    );
    assert_eq!(
        block.rules.len(),
        3,
        "expected the design-§5 example's 3 first-match-wins rules, got: {:?}",
        block.rules
    );
    assert_eq!(block.rules[0].action, IrAction::Deny, "rule 0 is the ssh carve-out");
    assert_eq!(block.rules[0].proto, IrProto::Tcp);
    assert!(block.rules[0].ports.contains(&(22, 22)), "rule 0 must be scoped to port 22, got: {:?}", block.rules[0].ports);
    assert_eq!(block.rules[1].action, IrAction::Allow, "rule 1 is the postgres allow");
    assert_eq!(
        block.rules[1].dst,
        vec!["172.16.1.50/32".to_string()],
        "rule 1's dst must be the single postgres host"
    );
    assert!(block.rules[1].ports.contains(&(5432, 5432)), "rule 1 must be scoped to port 5432, got: {:?}", block.rules[1].ports);

    // 4. Feed that SAME PolicyIR into a real enforcer in a netns lab; send
    //    one packet the policy ALLOWS (tcp/5432 to 172.16.1.50, rule 1) and
    //    one it DENIES (tcp/22 to the same host, caught by rule 0's
    //    carve-out ahead of any allow); assert the verdicts match the
    //    policy. Run on eBPF (required by design §1's done bar) and
    //    nftables (cheap to also exercise, same lab/apply/probe machinery).
    for (kind, prefix) in [(BackendKind::Ebpf, "aeth14e"), (BackendKind::Nftables, "aeth14n")] {
        let ir_for_backend = ir.clone();
        // (Review finding) `enforce_and_probe` -> `join_netns` calls
        // `setns(2)`, which mutates the CALLING OS thread's network
        // namespace for the rest of that thread's lifetime.
        // `tokio::task::spawn_blocking` runs closures on a SHARED blocking-
        // pool thread that tokio reuses for later, unrelated blocking work
        // -- that would leak this test's netns onto whatever runs next on
        // the same pool thread. Do the actual `setns`/enforce/probe work on
        // a dedicated `std::thread` instead (never returned to any pool,
        // torn down after `.join()`), and only bridge the blocking
        // `.join()` call itself onto `spawn_blocking` -- joining a thread
        // doesn't touch namespaces, so that part is safe to share.
        let handle =
            std::thread::spawn(move || enforce_and_probe(&ir_for_backend, kind, prefix));
        let (delivered_5432, delivered_22) = tokio::task::spawn_blocking(move || handle.join())
            .await
            .unwrap_or_else(|e| panic!("{kind:?} enforcement join-bridging task panicked: {e}"))
            .unwrap_or_else(|e| std::panic::resume_unwind(e));

        assert!(
            delivered_5432,
            "{kind:?}: a tcp/5432 packet to 172.16.1.50 (allowed by the design example's rule 1) \
             must be DELIVERED by the real enforcer applying the exact IR parsed from the \
             controller's Sync.Watch snapshot"
        );
        assert!(
            !delivered_22,
            "{kind:?}: a tcp/22 packet to 172.16.1.50 (denied by the design example's rule 0 \
             carve-out) must be DROPPED by the real enforcer applying the exact IR parsed from \
             the controller's Sync.Watch snapshot"
        );
    }

    // 5. The stub gateway Reports applied_version=1; Admin.ListGateways (the
    //    data `fabricctl policy status` renders) must show it applied.
    report_applied_version(&gw, h.sync_tcp_addr(), 1).await;

    let gateways = h
        .admin_client()
        .await
        .list_gateways(ListGatewaysRequest {})
        .await
        .expect("Admin.ListGateways")
        .into_inner()
        .gateways;
    let gw_info = gateways
        .into_iter()
        .find(|g| g.id == gw.id())
        .unwrap_or_else(|| panic!("expected the enrolled gateway (id={}) in ListGateways", gw.id()));
    assert_eq!(
        gw_info.applied_version, 1,
        "ListGateways must reflect the stub gateway's Sync.Report-acked applied_version, got: {:?}",
        gw_info
    );
}
