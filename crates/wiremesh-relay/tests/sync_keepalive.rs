//! Backlog 2 (Sync keepalive mirrors), relay half — the keepalive/timeout
//! channel construction on `wiremesh_relay::run_sync`'s dial.
//!
//! TDD: authored AHEAD of the implementation and EXPECTED to fail to
//! COMPILE until the mirror lands. Ops finding
//! (`docs/research/ops-finding-sync-half-open-stream.md`): the relay's Sync
//! Watch stream carries `revoked_serials`, so a silently half-open stream is
//! a SECURITY failure — the relay keeps accepting certificates revoked
//! after the stream died, until restart. The gateway's landed fix
//! (`crates/wiremesh-gateway/src/sync.rs`) keeps its constants PRIVATE
//! (its tests never needed to inspect them because the netns suites observe
//! reconnects behaviorally); the relay has no equivalent observable, so the
//! smallest testability hook is pinned here instead:
//!
//! Target API for the implementer (exact):
//!
//!   pub const wiremesh_relay::SYNC_KEEPALIVE_INTERVAL: Duration  // 15s
//!   pub const wiremesh_relay::SYNC_KEEPALIVE_TIMEOUT:  Duration  // 10s
//!   pub const wiremesh_relay::SYNC_CONNECT_TIMEOUT:    Duration  // 10s
//!
//! applied on `run_sync`'s channel exactly as the gateway's `connect` does:
//! `.connect_timeout(SYNC_CONNECT_TIMEOUT)
//!  .http2_keep_alive_interval(SYNC_KEEPALIVE_INTERVAL)
//!  .keep_alive_timeout(SYNC_KEEPALIVE_TIMEOUT)
//!  .keep_alive_while_idle(true)` — while-idle is load-bearing: the relay's
//! Watch stream IS the idle case (it receives nothing between revocations).
//! ./dev.sh run "cargo test -p wiremesh-relay --test sync_keepalive -- --test-threads=1 --nocapture"
use std::time::Duration;

use wiremesh_relay::{
    Denylist, SYNC_CONNECT_TIMEOUT, SYNC_KEEPALIVE_INTERVAL, SYNC_KEEPALIVE_TIMEOUT,
};

/// The relay's channel constants must mirror the gateway's landed values
/// verbatim (ops-finding "Suggested fix": 15s interval / 10s timeout / 10s
/// connect timeout — a dead link surfaces as a stream error within ~25s
/// worst case, comfortably inside home-router NAT idle windows).
#[test]
fn relay_sync_keepalive_constants_mirror_gateway() {
    assert_eq!(
        SYNC_KEEPALIVE_INTERVAL,
        Duration::from_secs(15),
        "HTTP/2 PING cadence must be 15s (the gateway's landed value)"
    );
    assert_eq!(
        SYNC_KEEPALIVE_TIMEOUT,
        Duration::from_secs(10),
        "unacked-PING declare-dead timeout must be 10s (the gateway's landed value)"
    );
    assert_eq!(
        SYNC_CONNECT_TIMEOUT,
        Duration::from_secs(10),
        "TCP/TLS dial bound must be 10s (the gateway's landed value)"
    );
    assert!(
        SYNC_KEEPALIVE_TIMEOUT < SYNC_KEEPALIVE_INTERVAL,
        "the PING timeout must expire before the next PING is due, so at most one \
         keepalive is ever outstanding"
    );
}

/// The dial itself must be BOUNDED: `run_sync` toward a blackholed address
/// (10.255.255.1 — RFC1918 space that is unrouted from the dev container;
/// SYNs are dropped, no RST comes back) must surface an error within the
/// connect timeout's order of magnitude, never hang the relay binary's
/// reconnect loop on the OS's multi-minute SYN retry schedule. Today
/// `run_sync` builds its channel with NO `connect_timeout`, so this dial
/// blocks far past the 30s bound below.
///
/// The 30s outer bound is deliberately 3x `SYNC_CONNECT_TIMEOUT`: tight
/// enough to prove the dial is bounded, loose enough not to flake on a slow
/// container. (An environment that fast-fails the dial instead — e.g. an
/// immediate ICMP unreachable — still passes: "errors promptly" is the
/// contract; the exact 10s figure is pinned by the constants test above.)
#[tokio::test]
async fn run_sync_connect_timeout_bounds_blackholed_dial() {
    let dir = tempfile::tempdir().expect("tempdir");
    wiremesh_relay::test_certs(dir.path(), &[]).expect("writing test certs");

    let result = tokio::time::timeout(
        Duration::from_secs(30),
        wiremesh_relay::run_sync(
            "10.255.255.1:9500",
            dir.path(),
            "relay",
            Denylist::new(),
            dir.path().join("denylist.json"),
        ),
    )
    .await
    .expect(
        "run_sync toward a blackholed address must ERROR within the bounded connect \
         timeout (~10s), not hang the reconnect loop on OS SYN retries",
    );
    assert!(
        result.is_err(),
        "a blackholed dial can never yield a working Sync stream — run_sync must \
         return Err, got Ok"
    );
}
