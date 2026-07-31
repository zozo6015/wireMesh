//! Backlog 2 (Sync keepalive mirrors), relay half — DDNS/hostname dial
//! targets for the relay's Sync client (`wiremesh_relay::run_sync`).
//!
//! TDD: authored AHEAD of the implementation and EXPECTED to fail to
//! COMPILE until the mirror lands (same convention as
//! `wiremesh-gateway/tests/keepalive_emission.rs` and this crate's own
//! `denylist_tests`). Ops finding: a half-open relay Sync stream keeps
//! accepting REVOKED certificates until restart
//! (`docs/research/ops-finding-sync-half-open-stream.md`) — the fix mirrors
//! the gateway's landed Sync-client shape (PR #28,
//! `crates/wiremesh-gateway/src/sync.rs`; this file mirrors its
//! `tests/hostname_resolve.rs`).
//!
//! Target API for the implementer (exact, pinned here):
//!
//!  1. `wiremesh_relay::run_sync` changes its first parameter from
//!     `SocketAddr` to `&str` — a `host:port` dial target (DNS hostname or
//!     IPv4 literal), resolved INSIDE every `run_sync` call so the relay
//!     binary's reconnect loop re-resolves DNS per dial (the gateway's
//!     per-reconnect re-resolution semantics; the rest of the signature —
//!     `certdir, relay_id, denylist, persist_path` — is unchanged).
//!  2. `wiremesh_relay::resolve_host_port(s: &str) -> anyhow::Result<SocketAddr>`
//!     (async) and `wiremesh_relay::prefer_ipv4(addrs: &[SocketAddr]) ->
//!     Option<SocketAddr>` — same semantics as
//!     `wiremesh_gateway::sync::{resolve_host_port, prefer_ipv4}` (first
//!     IPv4 wins, NO cross-family fallback, v6-only is an error naming the
//!     input, bounded resolve). The gateway's helpers are currently
//!     gateway-local; if the implementer extracts them into a shared crate,
//!     re-exporting them from `wiremesh_relay`'s root keeps these pins
//!     stable either way.
//!
//! `localhost`/`.invalid` lookups are local-resolver-safe (same rationale as
//! the gateway test file): `localhost` comes from /etc/hosts and `.invalid`
//! is RFC-2606-reserved to never resolve.
//! ./dev.sh run "cargo test -p wiremesh-relay --test sync_hostname -- --test-threads=1 --nocapture"
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use wiremesh_proto::v1::{EnrollRequest, MintTokenRequest, RevokeCertRequest};
use wiremesh_relay::Denylist;
use wiremesh_testkit::{enroll_one, TestController};

/// Bound on every wait for a denylist fold so a regression fails fast
/// instead of hanging the suite (same rationale as
/// `wiremesh-controller/tests/relay_sync_watch.rs`'s SYNC_TIMEOUT, wider
/// here because a full mTLS connect + snapshot fold is in the loop).
const FOLD_TIMEOUT: Duration = Duration::from_secs(10);

/// An IP-literal `host:port` passes through resolution unchanged — no DNS
/// involved, so IP-configured relays (and every existing netns/loopback
/// test topology) never depend on a resolver.
#[tokio::test]
async fn resolve_ip_literal_passes_through_unchanged() {
    let addr = wiremesh_relay::resolve_host_port("127.0.0.1:7000")
        .await
        .expect("IP literal resolves");
    assert_eq!(addr, "127.0.0.1:7000".parse::<SocketAddr>().unwrap());
}

/// The pure selection policy, pinned against synthetic candidate lists so
/// the preference order is deterministic — no resolver (whose result order
/// varies by host) in the loop. Mirrors the gateway pin exactly.
#[test]
fn prefer_ipv4_picks_first_ipv4_from_mixed_list() {
    let addrs: Vec<SocketAddr> = vec![
        "[2001:db8::1]:9500".parse().unwrap(), // v6 FIRST: position must not win
        "192.0.2.10:9500".parse().unwrap(),
        "198.51.100.7:9500".parse().unwrap(), // later IPv4: first IPv4 wins, not last
        "[2001:db8::2]:9500".parse().unwrap(),
    ];
    assert_eq!(
        wiremesh_relay::prefer_ipv4(&addrs),
        Some("192.0.2.10:9500".parse::<SocketAddr>().unwrap()),
        "first IPv4 entry must win over an earlier IPv6 entry"
    );
}

/// v1 is IPv4-only end to end, so there is NO cross-family fallback: a list
/// with no IPv4 entry selects nothing.
#[test]
fn prefer_ipv4_returns_none_for_v6_only_list() {
    let addrs: Vec<SocketAddr> = vec![
        "[2001:db8::1]:9500".parse().unwrap(),
        "[2001:db8::2]:9500".parse().unwrap(),
    ];
    assert_eq!(
        wiremesh_relay::prefer_ipv4(&addrs),
        None,
        "a v6-only list must select NOTHING — no cross-family fallback in v1"
    );
}

#[test]
fn prefer_ipv4_empty_list_yields_none() {
    assert_eq!(wiremesh_relay::prefer_ipv4(&[]), None);
}

/// Integration smoke through a real resolver: `localhost` commonly maps to
/// both `127.0.0.1` and `::1`; the IPv4 result must win.
#[tokio::test]
async fn resolve_localhost_prefers_ipv4() {
    let addr = wiremesh_relay::resolve_host_port("localhost:9500")
        .await
        .expect("localhost resolves");
    assert_eq!(addr, "127.0.0.1:9500".parse::<SocketAddr>().unwrap());
}

/// The v6-only resolution error, pinned deterministically WITHOUT a
/// resolver: an IPv6 literal passes through `lookup_host` untouched,
/// yielding exactly one v6 candidate, so resolution must ERROR — naming the
/// input and saying no IPv4 addresses — rather than hand back an address a
/// v1 (IPv4-only) controller can never be reached at.
#[tokio::test]
async fn resolve_v6_only_target_errors_with_no_ipv4_message() {
    let err = wiremesh_relay::resolve_host_port("[::1]:9500")
        .await
        .expect_err("a target with only IPv6 candidates must error, not fall back");
    let chain = format!("{err:#}");
    assert!(chain.contains("[::1]:9500"), "error must name the input, got: {chain}");
    assert!(chain.contains("no IPv4 addresses"), "error must say no IPv4 addresses, got: {chain}");
}

/// An unresolvable name errors, and the error carries the input so a relay
/// operator's log line names the bad dial target.
#[tokio::test]
async fn resolve_unresolvable_name_errors_with_input_in_context() {
    let err = wiremesh_relay::resolve_host_port("nonexistent.invalid:1")
        .await
        .expect_err(".invalid is RFC-reserved and must never resolve");
    let chain = format!("{err:#}");
    assert!(
        chain.contains("nonexistent.invalid:1"),
        "error must name the input dial target, got: {chain}"
    );
}

/// `run_sync` toward an IPv6 literal must be rejected at resolution (boot of
/// the sync task), with the same no-IPv4 error — never a dial attempt toward
/// an address a v1 controller can't be reached at. The certdir is real
/// (`test_certs`) so the failure under test is unambiguously the resolver's,
/// not a missing-PEM read error.
#[tokio::test]
async fn run_sync_rejects_ipv6_literal_target() {
    let dir = tempfile::tempdir().expect("tempdir");
    wiremesh_relay::test_certs(dir.path(), &[]).expect("writing test certs");

    let err = tokio::time::timeout(
        FOLD_TIMEOUT,
        wiremesh_relay::run_sync(
            "[::1]:9500",
            dir.path(),
            "relay",
            Denylist::new(),
            dir.path().join("denylist.json"),
        ),
    )
    .await
    .expect("an IPv6-literal target must be rejected promptly at resolution, not dialed/hung")
    .expect_err("run_sync toward an IPv6 literal must error (v1 is IPv4-only)");
    let chain = format!("{err:#}");
    assert!(
        chain.contains("no IPv4 addresses"),
        "run_sync's IPv6-literal rejection must surface the resolver's no-IPv4 error, got: {chain}"
    );
}

/// `run_sync` toward an unresolvable hostname fails fast with an error that
/// names the dial target — the relay binary's reconnect loop logs exactly
/// this chain, so a mistyped/stale DDNS name must be diagnosable from the
/// log line alone.
#[tokio::test]
async fn run_sync_unresolvable_hostname_errors_naming_target() {
    let dir = tempfile::tempdir().expect("tempdir");
    wiremesh_relay::test_certs(dir.path(), &[]).expect("writing test certs");

    let err = tokio::time::timeout(
        FOLD_TIMEOUT + Duration::from_secs(5),
        wiremesh_relay::run_sync(
            "nonexistent.invalid:9500",
            dir.path(),
            "relay",
            Denylist::new(),
            dir.path().join("denylist.json"),
        ),
    )
    .await
    .expect("an unresolvable name must fail the (bounded) resolve, not hang the sync task")
    .expect_err("run_sync toward an unresolvable hostname must error");
    let chain = format!("{err:#}");
    assert!(
        chain.contains("nonexistent.invalid"),
        "run_sync's resolution error must name the dial target, got: {chain}"
    );
}

/// An enrolled relay's full client identity — what
/// `wiremesh_testkit::enroll_relay` returns PLUS the private key it discards
/// (which `run_sync`'s mTLS dial needs). Mirrors
/// `wiremesh-controller/tests/relay_sync_watch.rs`'s local helper of the
/// same shape.
struct RelayIdentity {
    cert_pem: String,
    key_pem: String,
    ca_bundle_pem: String,
}

/// Mint a `relay`-kind token and redeem it via `Enrollment.Enroll`
/// (endpoint-routed relay path), KEEPING the generated private key.
async fn enroll_relay_with_key(h: &TestController, endpoint: &str) -> RelayIdentity {
    let token = h
        .admin_client()
        .await
        .mint_token(MintTokenRequest {
            kind: "relay".to_string(),
            bound_cidrs: vec![],
            rebind_segment_id: 0,
        })
        .await
        .expect("minting relay token")
        .into_inner()
        .token;

    let (csr_pem, key_pair) = wiremesh_testkit::gen_csr("stub-relay");
    let key_pem = key_pair.serialize_pem();

    let resp = h
        .enrollment_client()
        .await
        .enroll(EnrollRequest {
            token,
            csr_pem,
            cidrs: vec![],
            wg_pubkey: String::new(),
            endpoint: endpoint.to_string(),
        })
        .await
        .expect("Enrollment.Enroll (relay path) failed")
        .into_inner();

    RelayIdentity {
        cert_pem: resp.cert_pem,
        key_pem,
        ca_bundle_pem: resp.ca_bundle_pem,
    }
}

/// Write an enrolled relay identity into a certdir with the exact filenames
/// `run_sync` reads (`relay.pem`/`relay.key`/`ca.pem`).
fn write_certdir(dir: &Path, id: &RelayIdentity) {
    std::fs::write(dir.join("relay.pem"), &id.cert_pem).expect("writing relay.pem");
    std::fs::write(dir.join("relay.key"), &id.key_pem).expect("writing relay.key");
    std::fs::write(dir.join("ca.pem"), &id.ca_bundle_pem).expect("writing ca.pem");
}

/// Poll (bounded) until `denylist` contains `serial`, panicking with `what`
/// on timeout.
async fn await_fold(denylist: &Denylist, serial: &str, what: &str) {
    let deadline = tokio::time::Instant::now() + FOLD_TIMEOUT;
    loop {
        if denylist.contains(serial) {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "timed out waiting for {what}: serial {serial} never folded into the \
                 denylist; current snapshot: {:?}",
                denylist.snapshot()
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The contract's headline (mirrors the gateway's
/// `connect_via_hostname_yields_working_mtls_sync`): `run_sync` dialed by
/// HOSTNAME — the DDNS-name shape, `localhost:<sync port>` — must resolve
/// via DNS inside the call and produce a working end-to-end mTLS Sync
/// stream: a serial revoked BEFORE the dial arrives via the snapshot
/// (`replace_all` path), a serial revoked WHILE the stream is open arrives
/// via a delta (`union` path), and both are persisted to `denylist.json` so
/// an offline restart still enforces them. Resolution living INSIDE
/// `run_sync` is also the per-dial re-resolution seam: the relay binary's
/// reconnect loop calls `run_sync` afresh each retry, so a rotated DDNS A
/// record heals without a relay restart (same shape as the gateway's
/// per-reconnect `connect`).
#[tokio::test]
async fn run_sync_via_hostname_folds_and_persists_revocations() {
    let h = TestController::start().await;

    // A victim revoked BEFORE the relay's sync task dials: must arrive in
    // the opening snapshot.
    let victim_pre = enroll_one(&h, "seg-a", "10.10.1.0/24").await;
    let pre_serial = victim_pre.cert_serial().expect("pre victim serial");
    h.admin_client()
        .await
        .revoke_cert(RevokeCertRequest { serial: pre_serial.clone() })
        .await
        .expect("Admin.RevokeCert (pre-dial victim)");

    // A second victim to revoke while the stream is open.
    let victim_live = enroll_one(&h, "seg-b", "10.10.2.0/24").await;
    let live_serial = victim_live.cert_serial().expect("live victim serial");

    let relay = enroll_relay_with_key(&h, "203.0.113.9:4443").await;
    let dir = tempfile::tempdir().expect("tempdir");
    write_certdir(dir.path(), &relay);

    let denylist = Denylist::new();
    let persist_path = dir.path().join("denylist.json");

    // Deliberately NOT the IP-literal `h.sync_tcp_addr().to_string()`: the
    // hostname dial path is the thing under test.
    let hostname_addr = format!("localhost:{}", h.sync_tcp_addr().port());
    let task = {
        let denylist = denylist.clone();
        let certdir = dir.path().to_path_buf();
        let persist_path = persist_path.clone();
        tokio::spawn(async move {
            let result = wiremesh_relay::run_sync(
                &hostname_addr,
                &certdir,
                "relay",
                denylist,
                persist_path,
            )
            .await;
            eprintln!("run_sync ended: {result:?}");
        })
    };

    // Snapshot path (replace_all) over the hostname-dialed channel.
    await_fold(&denylist, &pre_serial, "the opening snapshot's revoked serial").await;

    // Delta path (union) — the stream must stay live past the snapshot.
    h.admin_client()
        .await
        .revoke_cert(RevokeCertRequest { serial: live_serial.clone() })
        .await
        .expect("Admin.RevokeCert (live victim)");
    await_fold(&denylist, &live_serial, "the live revocation delta").await;

    // Both folds must have been persisted (0600, atomic) so an offline
    // restart still enforces them — the finding's whole point.
    let persisted = Denylist::load(&persist_path).expect("loading persisted denylist.json");
    assert!(
        persisted.contains(&pre_serial) && persisted.contains(&live_serial),
        "denylist.json must carry both revoked serials after the folds, got: {:?}",
        persisted.snapshot()
    );

    task.abort();
}
