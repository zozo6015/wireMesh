//! Task 13's failing test: drives the BUILT `fabricctl` binary (not a library
//! call) against a `TestController`'s Unix socket end-to-end — `segment
//! create` followed by `segment list` must round-trip through the real CLI
//! process, its arg parsing, its UDS transport, and the controller's Admin
//! service.
//!
//! `env!("CARGO_BIN_EXE_fabricctl")` resolves to the path of this crate's own
//! `fabricctl` binary target once one exists — Cargo sets that env var for
//! every integration test in a crate that has a matching `[[bin]]` (here,
//! the auto-discovered `src/main.rs`). Today there is no `src/main.rs` (only
//! an empty `src/lib.rs`), so this crate produces no `fabricctl` binary at
//! all and `CARGO_BIN_EXE_fabricctl` is never set — that makes `env!` fail
//! AT COMPILE TIME with "environment variable not defined", so this file does
//! not even COMPILE yet. That's the expected RED state for this step. The
//! implementer adds `crates/fabricctl/src/main.rs` (clap, `segment
//! {create,list,rm}` / `gateway {list,drain}` / `relay {register,list}` /
//! `token {mint,revoke}` / `audit query` / `status` subcommands, `--socket`
//! UDS transport, `--token` TCP+bearer transport) to turn this green.
use std::net::SocketAddr;
use std::process::{Command, Output};

use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use wiremesh_proto::v1::sync_client::SyncClient;
use wiremesh_proto::v1::{ListGatewaysRequest, MintTokenRequest, ReportRequest};
use wiremesh_testkit::StubGateway;

/// Runs the built `fabricctl` binary with `args`, returning its captured
/// output (status/stdout/stderr) — a thin `std::process::Command` wrapper,
/// not an async call: the binary itself does whatever async work it needs
/// internally and exits, so the test only needs to wait on the child
/// process, not drive an executor.
fn run_fabricctl(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fabricctl"))
        .args(args)
        .output()
        .expect("spawning the built fabricctl binary")
}

/// Task 6 (cycle 3): the master-spec §5.1 worked example fabric, same
/// literal as `wiremesh-controller/tests/policy_pipeline.rs`'s
/// `FABRIC_WITH_POLICY` / `wiremesh-controller/tests/get_policy.rs`'s copy
/// of it — duplicated here (each `tests/*.rs` file is its own binary) so
/// `fabricctl policy show`/`status` have a real compiled policy (not the
/// cycle-2 stub) to read back.
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
/// identity and calls `Sync.Report{applied_version: version}` — rebuilds
/// `wiremesh_testkit::StubGateway`'s internal `dial_sync_with` recipe (not
/// itself exposed publicly, since it's private plumbing behind
/// `open_sync`/`reconnect`) from `StubGateway`'s public
/// `cert_pem()`/`key_pem()`/`ca_bundle_pem()` accessors, because this test
/// needs a plain unary `Report` call rather than a `Watch` stream. This is
/// the "stub gateway acks a policy version" step `fabricctl policy status`
/// (test 5) needs: `Admin.ListGateways`' `applied_version` column is NULL
/// until some gateway actually calls `Sync.Report`.
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
            // sentinel; see the identical note in
            // `wiremesh-testkit/tests/end_to_end_policy.rs`. A 0 on either
            // side is accepted, so this hand-rolled raw client keeps its
            // pre-scheme behaviour whether or not the stub ever watched.
            session_generation: 0,
        })
        .await
        .expect("Sync.Report");
}

#[tokio::test]
async fn fabricctl_creates_and_lists_segments_over_uds() {
    let h = wiremesh_testkit::TestController::start().await;
    let socket = h
        .socket_path()
        .to_str()
        .expect("TestController socket path must be valid UTF-8")
        .to_string();

    let create = run_fabricctl(&[
        "--socket",
        &socket,
        "segment",
        "create",
        "aws",
        "--cidr",
        "10.0.0.0/16",
    ]);
    assert!(
        create.status.success(),
        "fabricctl segment create must succeed, stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&create.stdout),
        String::from_utf8_lossy(&create.stderr)
    );

    let list = run_fabricctl(&["--socket", &socket, "segment", "list"]);
    assert!(
        list.status.success(),
        "fabricctl segment list must succeed, stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&list.stdout),
        String::from_utf8_lossy(&list.stderr)
    );
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(
        stdout.contains("aws"),
        "expected fabricctl segment list's stdout to contain the created segment \"aws\", got: {stdout}"
    );
}

/// (Task 6, test 4) `fabricctl policy show` must print BOTH the applied
/// policy's raw source YAML and its pretty-printed compiled IR. Asserts
/// stable substrings rather than an exact format: a segment name that only
/// appears in the source/IR once a real policy has been applied
/// (`proxmox-lab`), the IR's `schema` tag, and a `version` field reading
/// `1` — not the cycle-2 stub's always-empty IR, and not any other
/// version. Today there is no `policy` subcommand at all, so `fabricctl`
/// (clap) rejects this invocation outright — that unrecognized-subcommand
/// failure is this test's RED signal.
#[tokio::test]
async fn fabricctl_policy_show_prints_source_and_ir() {
    let h = wiremesh_testkit::TestController::start().await;
    let socket = h
        .socket_path()
        .to_str()
        .expect("TestController socket path must be valid UTF-8")
        .to_string();

    let diff = h.apply(FABRIC_WITH_POLICY).await;
    assert!(
        diff.policy_updated,
        "baseline apply must compile a policy before `policy show` has anything to read, \
         got diff: {:?}",
        diff
    );

    let show = run_fabricctl(&["--socket", &socket, "policy", "show"]);
    assert!(
        show.status.success(),
        "fabricctl policy show must succeed, stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&show.stdout),
        String::from_utf8_lossy(&show.stderr)
    );
    let stdout = String::from_utf8_lossy(&show.stdout);

    assert!(
        stdout.contains("proxmox-lab"),
        "expected fabricctl policy show's stdout to contain the applied policy's segment name \
         \"proxmox-lab\" (from the printed source and/or IR), got: {stdout}"
    );
    assert!(
        stdout.contains("schema"),
        "expected fabricctl policy show's stdout to contain the IR's \"schema\" field, got: {stdout}"
    );
    assert!(
        stdout.contains("\"version\": 1") || stdout.contains("\"version\":1"),
        "expected fabricctl policy show's stdout to contain the IR's version field reading 1 \
         (compact or pretty-printed), got: {stdout}"
    );
}

/// (Task 6, test 5) `fabricctl policy status` must print, per gateway, its
/// name and its last-`Sync.Report`-acked applied policy version — here,
/// after a stub gateway enrolls onto `proxmox-lab` and Reports
/// `applied_version: 1`, the CLI output must contain a line naming that
/// gateway which also shows `1`. Chose the CLI-level test (rather than the
/// brief's allowed controller-side fallback) because `Admin.ListGateways`
/// already carries `applied_version` end-to-end (Task 8), so driving this
/// through the real `fabricctl` binary is no heavier than the fallback and
/// actually exercises the new `policy status` subcommand's rendering, which
/// a controller-only assertion would not. Today `policy status` doesn't
/// exist as a subcommand at all, so this RIGHT NOW fails the same way
/// `fabricctl_policy_show_prints_source_and_ir` does: clap rejects the
/// unrecognized subcommand.
#[tokio::test]
async fn fabricctl_policy_status_prints_gateway_and_applied_version() {
    let h = wiremesh_testkit::TestController::start().await;
    let socket = h
        .socket_path()
        .to_str()
        .expect("TestController socket path must be valid UTF-8")
        .to_string();

    let diff = h.apply(FABRIC_WITH_POLICY).await;
    assert!(
        diff.policy_updated,
        "baseline apply must compile a policy, got diff: {:?}",
        diff
    );

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

    let status = run_fabricctl(&["--socket", &socket, "policy", "status"]);
    assert!(
        status.status.success(),
        "fabricctl policy status must succeed, stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );
    let stdout = String::from_utf8_lossy(&status.stdout);

    let gw_line = stdout.lines().find(|l| l.contains(&gw_info.name)).unwrap_or_else(|| {
        panic!(
            "expected a line in fabricctl policy status's output naming gateway {:?}, got: {stdout}",
            gw_info.name
        )
    });
    assert!(
        gw_line.contains('1'),
        "expected gateway {:?}'s line to show its Report-acked applied_version 1, got line: {gw_line:?}",
        gw_info.name
    );
}
