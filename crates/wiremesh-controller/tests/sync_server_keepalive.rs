//! Backlog 2 (Sync keepalive mirrors), controller half — server-side HTTP/2
//! keepalive on the Sync listener.
//!
//! TDD: authored AHEAD of the implementation and EXPECTED to fail to
//! COMPILE until the mirror lands. Ops finding
//! (`docs/research/ops-finding-sync-half-open-stream.md`, "Still open"):
//! the gateway-side keepalive (PR #28) lets the CLIENT detect a dead link,
//! but the controller currently holds a half-open client's Watch stream —
//! and its stale roster entry — until the next Report that never comes.
//! With server-side keepalive the controller ALSO detects dead clients and
//! reaps their streams (freeing the broker/roster state hanging off them).
//!
//! tonic's server knobs (`Server::http2_keepalive_interval(Option<Duration>)`
//! / `Server::http2_keepalive_timeout(Option<Duration>)`) leave no
//! inspectable surface on a built server, so — same approach as the relay's
//! `tests/sync_keepalive.rs` — the smallest testability hook is a pair of
//! pub consts the `serve()` builder must consume.
//!
//! Target API for the implementer (exact):
//!
//!   pub const wiremesh_controller::SYNC_HTTP2_KEEPALIVE_INTERVAL: Duration  // 15s
//!   pub const wiremesh_controller::SYNC_HTTP2_KEEPALIVE_TIMEOUT:  Duration  // 10s
//!
//! applied in `lib.rs::serve()` on the SYNC listener's builder (the one
//! wrapping `SyncServer::new(sync_svc)`):
//!
//!   Server::builder()
//!       .http2_keepalive_interval(Some(SYNC_HTTP2_KEEPALIVE_INTERVAL))
//!       .http2_keepalive_timeout(Some(SYNC_HTTP2_KEEPALIVE_TIMEOUT))
//!       .tls_config(sync_tls_config)...
//!
//! The values mirror the gateway/relay client constants (the ops doc
//! recommends no distinct server-side figures, so the same 15s/10s applies):
//! long-lived server-streaming Watch responses are exactly the
//! idle-on-the-wire case the PING must cover from BOTH ends.
//!
//! A full behavioral half-open-stream reproduction (TCP pathology) is
//! deliberately NOT attempted — the gateway PR pinned construction the same
//! way. Existing suites (`sync_snapshot.rs`, `relay_sync_watch.rs`, …)
//! remain the regression guard that healthy idle streams survive.
//! ./dev.sh run "cargo test -p wiremesh-controller --test sync_server_keepalive -- --test-threads=1 --nocapture"
use std::time::Duration;

use wiremesh_controller::{SYNC_HTTP2_KEEPALIVE_INTERVAL, SYNC_HTTP2_KEEPALIVE_TIMEOUT};

/// The controller's Sync-server keepalive constants must mirror the client
/// side's landed values (15s interval / 10s timeout), so both ends of a
/// dead link detect it on the same ~25s worst-case horizon.
#[test]
fn sync_server_http2_keepalive_constants_mirror_client_side() {
    assert_eq!(
        SYNC_HTTP2_KEEPALIVE_INTERVAL,
        Duration::from_secs(15),
        "server-side HTTP/2 PING cadence must be 15s (mirror of the gateway/relay clients)"
    );
    assert_eq!(
        SYNC_HTTP2_KEEPALIVE_TIMEOUT,
        Duration::from_secs(10),
        "server-side unacked-PING declare-dead timeout must be 10s (mirror of the clients)"
    );
    assert!(
        SYNC_HTTP2_KEEPALIVE_TIMEOUT < SYNC_HTTP2_KEEPALIVE_INTERVAL,
        "the PING timeout must expire before the next PING is due, so at most one \
         keepalive is ever outstanding per stream"
    );
}
