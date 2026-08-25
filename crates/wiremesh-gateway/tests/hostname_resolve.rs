//! DDNS support: `host:port` dial targets resolve at dial time.
//!
//! Covers `sync::resolve_host_port` (IP passthrough, IPv4 preference,
//! unresolvable-name error) and the end-to-end contract that `sync::connect`
//! given a HOSTNAME (not an IP literal) produces a working mTLS Sync
//! connection against the real in-process controller (no netns needed).
//! `localhost` / `.invalid` lookups are local-resolver-safe: `localhost`
//! comes from /etc/hosts and `.invalid` is RFC-2606-reserved to never
//! resolve, so neither depends on internet access.
//! ./dev.sh run "cargo test -p wiremesh-gateway --test hostname_resolve -- --test-threads=1 --nocapture"
use std::net::SocketAddr;
use wiremesh_gateway::identity::Identity;
use wiremesh_gateway::sync;
use wiremesh_testkit::{enroll_one, StubGateway, TestController};

/// An IP-literal `host:port` passes through resolution unchanged — no DNS
/// involved, so IP-configured deployments (and netns tests) never depend on
/// a resolver.
#[tokio::test]
async fn resolve_ip_literal_passes_through_unchanged() {
    let addr = sync::resolve_host_port("127.0.0.1:6000")
        .await
        .expect("IP literal resolves");
    assert_eq!(addr, "127.0.0.1:6000".parse::<SocketAddr>().unwrap());
}

/// The pure selection policy behind `resolve_host_port`, pinned against
/// synthetic candidate lists so the preference order is deterministic — no
/// resolver (whose result order varies by host) in the loop.
#[test]
fn prefer_ipv4_picks_first_ipv4_from_mixed_list() {
    let addrs: Vec<SocketAddr> = vec![
        "[2001:db8::1]:9500".parse().unwrap(), // v6 FIRST: position must not win
        "192.0.2.10:9500".parse().unwrap(),
        "198.51.100.7:9500".parse().unwrap(), // later IPv4: first IPv4 wins, not last
        "[2001:db8::2]:9500".parse().unwrap(),
    ];
    assert_eq!(
        sync::prefer_ipv4(&addrs),
        Some("192.0.2.10:9500".parse::<SocketAddr>().unwrap()),
        "first IPv4 entry must win over an earlier IPv6 entry"
    );
}

/// v1 is IPv4-only end to end, so there is NO cross-family fallback: a list
/// with no IPv4 entry selects nothing (the caller turns this into a clear
/// resolution error instead of an unreachable-dial loop).
#[test]
fn prefer_ipv4_returns_none_for_v6_only_list() {
    let addrs: Vec<SocketAddr> = vec![
        "[2001:db8::1]:9500".parse().unwrap(),
        "[2001:db8::2]:9500".parse().unwrap(),
    ];
    assert_eq!(
        sync::prefer_ipv4(&addrs),
        None,
        "a v6-only list must select NOTHING — no cross-family fallback in v1"
    );
}

/// The v6-only resolution error, pinned deterministically WITHOUT a resolver:
/// an IPv6 literal passes through `lookup_host` untouched (no DNS), yielding
/// exactly one v6 candidate, so `resolve_host_port` must error — naming the
/// input and saying no IPv4 addresses — rather than hand back an address a
/// v1 (IPv4-only) controller can never be reached at.
#[tokio::test]
async fn resolve_v6_only_target_errors_with_no_ipv4_message() {
    let err = sync::resolve_host_port("[::1]:9500")
        .await
        .expect_err("a target with only IPv6 candidates must error, not fall back");
    let chain = format!("{err:#}");
    assert!(
        chain.contains("[::1]:9500"),
        "error must name the input, got: {chain}"
    );
    assert!(
        chain.contains("no IPv4 addresses"),
        "error must say no IPv4 addresses, got: {chain}"
    );
}

#[test]
fn prefer_ipv4_empty_list_yields_none() {
    assert_eq!(sync::prefer_ipv4(&[]), None);
}

/// Integration smoke for the same policy through a real resolver:
/// `localhost` commonly maps to both `127.0.0.1` and `::1`; v1 is IPv4-only,
/// so the IPv4 result must win when a name resolves to mixed families.
/// (The deterministic order pins live in the `prefer_ipv4_*` tests above —
/// resolver result order varies by host, so this only smokes the wiring.)
#[tokio::test]
async fn resolve_localhost_prefers_ipv4() {
    let addr = sync::resolve_host_port("localhost:9500")
        .await
        .expect("localhost resolves");
    assert_eq!(addr, "127.0.0.1:9500".parse::<SocketAddr>().unwrap());
}

/// An unresolvable name errors, and the error carries the input so an
/// operator's log line names the bad dial target.
#[tokio::test]
async fn resolve_unresolvable_name_errors_with_input_in_context() {
    let err = sync::resolve_host_port("nonexistent.invalid:1")
        .await
        .expect_err(".invalid is RFC-reserved and must never resolve");
    let chain = format!("{err:#}");
    assert!(
        chain.contains("nonexistent.invalid:1"),
        "error must name the input dial target, got: {chain}"
    );
}

/// Build a gateway `Identity` from an enrolled `StubGateway`'s material.
/// `sync::connect` only reads the cert/key/CA fields, so `observe_key` and
/// `wg_private_key_b64` (never touched on this path) get placeholders —
/// same adaptation as `tests/sync_client.rs`.
fn identity_of(g: &StubGateway) -> Identity {
    Identity {
        cert_pem: g.cert_pem().to_string(),
        key_pem: g.key_pem().to_string(),
        ca_bundle_pem: g.ca_bundle_pem().to_string(),
        gateway_id: g.id(),
        observe_key: String::new(),
        wg_private_key_b64: String::new(),
    }
}

/// The contract's headline: dialing the Sync endpoint by HOSTNAME — the
/// DDNS-name shape, `localhost:<port>` here — must resolve via DNS inside
/// `connect` and produce a working end-to-end mTLS Sync connection: watch
/// stream up, first message a snapshot listing the peer, report accepted.
#[tokio::test]
async fn connect_via_hostname_yields_working_mtls_sync() {
    let h = TestController::start().await;
    let g1 = enroll_one(&h, "seg-a", "10.10.1.0/24").await;
    let _g2 = enroll_one(&h, "seg-b", "10.10.2.0/24").await;
    let id = identity_of(&g1);

    // Deliberately NOT the IP-literal string `h.sync_tcp_addr().to_string()`:
    // the hostname path is the thing under test.
    let hostname_addr = format!("localhost:{}", h.sync_tcp_addr().port());
    let mut client = sync::connect(&hostname_addr, &id)
        .await
        .expect("hostname dial resolves and completes the mTLS connect");

    let mut stream = sync::watch(&mut client)
        .await
        .expect("watch over hostname-dialed channel");
    let mut cur = None;
    let ds = match sync::next_event(&mut stream, &mut cur)
        .await
        .expect("first msg")
        .expect("stream open")
    {
        sync::SyncEvent::State(ds) => ds,
        other => panic!("first Sync message must be a snapshot, got {other:?}"),
    };
    assert!(
        ds.peers
            .iter()
            .any(|p| p.allowed_ips.contains(&"10.10.2.0/24".to_string())),
        "snapshot over the hostname-dialed channel lists peer B's segment: {:?}",
        ds.peers
    );
    sync::report(&mut client, ds.policy_version, vec![], vec![], vec![], None)
        .await
        .expect("report over hostname-dialed channel");
}

/// `connect` toward an unresolvable hostname fails with an error rather than
/// hanging: resolution happens FIRST inside `connect` and its failure
/// surfaces immediately, before any TCP/TLS dialing begins (the 10s connect
/// timeout bounds only that later dial phase, which this test never
/// reaches), so a plain `.await` is safe here.
#[tokio::test]
async fn connect_unresolvable_hostname_errors() {
    let h = TestController::start().await;
    let g = enroll_one(&h, "seg-a", "10.10.1.0/24").await;
    let id = identity_of(&g);

    let err = sync::connect("nonexistent.invalid:9500", &id)
        .await
        .expect_err("dialing an unresolvable hostname must fail");
    let chain = format!("{err:#}");
    assert!(
        chain.contains("nonexistent.invalid"),
        "connect error must name the unresolvable dial target, got: {chain}"
    );
}
