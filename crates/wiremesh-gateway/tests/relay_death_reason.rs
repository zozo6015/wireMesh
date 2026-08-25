//! `RelayTransport` death-reason classification (aether-prod-fi-01 relay-
//! wedge fix, follow-up round) — loopback, no netns.
//!
//! ## Why the death REASON matters
//!
//! The `PathAction::RelayDied` driver handling must branch on WHY the
//! transport died (runner-verified against the netns done-bars):
//!
//! - **`Closed`** — the relay gracefully closed the QUIC connection under us
//!   (a controller-driven eviction: `quinn::Endpoint::close` sends every
//!   client a real CONNECTION_CLOSE, the exact severance `relay_matrix.rs`
//!   case 3 drives). The driver must clear the pin, tear down, and spawn
//!   `ensure_relay_transport` IMMEDIATELY — restoring the pre-fix eviction
//!   re-path timing (case 3's ≤30s budget), because a peer evicted alongside
//!   us is re-pathing to the surviving relay too, so a direct punch window
//!   first would just burn ~12s for a pairing that may not even punch.
//! - **`TimedOut`** — the leg died of SILENCE (QUIC idle timeout; the
//!   production wedge: the peer left the relay, nothing ever arrived again).
//!   The driver keeps the punch-window semantics `relay_matrix.rs` case 4
//!   pins: clear the pin, tear down, do NOT immediately re-relay.
//!
//! Both netns cases stay untouched as the behavioral pins for the two
//! branches; this file pins the CLASSIFICATION layer they both depend on.
//!
//! ## Pinned API (compile-RED until the fix lands — deliberate)
//!
//! In `wiremesh_gateway::relay`:
//!
//! ```ignore
//! #[derive(Debug, Clone, Copy, PartialEq, Eq)]
//! pub enum RelayDeathReason { Closed, TimedOut, Other }
//!
//! impl RelayTransport {
//!     /// `None` while the transport is alive; once a pump observes the
//!     /// connection dead, the recorded classification of how it died.
//!     pub fn death_reason(&self) -> Option<RelayDeathReason>;
//! }
//! ```
//!
//! Semantics pinned by the tests below:
//! - `death_reason()` is `None` while `is_healthy()` is true;
//! - a graceful relay-side close (eviction) yields `Some(Closed)`;
//! - pure silence until QUIC's idle timeout yields `Some(TimedOut)`;
//! - once `is_healthy()` is false, `death_reason()` is `Some(..)` (a dead
//!   transport with no recorded reason would send the driver down an
//!   arbitrary branch).
//!
//! Deliberately NOT pinned: the reason after a locally-initiated
//! `RelayTransport::close`/`Drop` (the driver reads `death_reason()` only
//! for transports that died on their own, BEFORE tearing them down), and
//! the exact mapping of exotic `quinn::ConnectionError` variants (`Reset`,
//! `TransportError`, ...) — those may land in `Other`, whose driver branch
//! is the conservative punch-window path.
//!
//! ## Feasibility note (for the implementer; wiremesh-relay src is off-limits
//! to this test author)
//!
//! `wiremesh_relay::Client::recv` is `self.conn.read_datagram().await?` into
//! `anyhow::Result`, so the underlying `quinn::ConnectionError` survives in
//! the error chain and is recoverable with
//! `err.downcast_ref::<quinn::ConnectionError>()`:
//! `ApplicationClosed`/`ConnectionClosed` (and `LocallyClosed`) ⇒ `Closed`,
//! `TimedOut` ⇒ `TimedOut`, anything else ⇒ `Other`. That downcast needs
//! `quinn` as a REGULAR dependency of `wiremesh-gateway` (today it is
//! dev-only, used by `relay_matrix.rs`'s killable relay) — either promote it
//! (same unpinned `quinn = "0.11"` the dev-dep already documents must match
//! `wiremesh-relay`'s), or have `wiremesh-relay` expose a minimal
//! classifier for its own error surface (e.g.
//! `pub fn recv_error_was_peer_close(&anyhow::Error) -> Option<bool>` or an
//! equivalent small enum). These tests are agnostic to which option is
//! chosen: they only exercise the gateway-side `death_reason()` behavior.
//!
//! ./dev.sh run "cargo test -p wiremesh-gateway --test relay_death_reason -- --nocapture"
//!
//! (`idle_silence_classifies_as_timed_out` takes ~30-35s wall time by
//! construction — see its doc comment.)

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;

use wiremesh_gateway::relay::{RelayDeathReason, RelayTransport};

/// A tmpdir unique to this test process — same PID-based convention as
/// `tests/relay_transport.rs` / `wiremesh-relay/tests/bridge.rs`.
fn unique_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("gw-relay-death-test-{tag}-{}", std::process::id()))
}

struct Pems {
    ca: String,
    cert: String,
    key: String,
}

/// Provisions `ca.pem` + a `gw-A` identity via `wiremesh_relay::test_certs`
/// (the same helper `tests/relay_transport.rs` uses) and reads them back as
/// in-memory PEMs for `RelayTransport::start`.
fn provision(dir: &PathBuf) -> Pems {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).expect("create certdir");
    wiremesh_relay::test_certs(dir, &["gw-A"]).expect("test_certs must provision ca+gw-A");
    Pems {
        ca: std::fs::read_to_string(dir.join("ca.pem")).expect("read ca.pem"),
        cert: std::fs::read_to_string(dir.join("gw-A.pem")).expect("read gw-A.pem"),
        key: std::fs::read_to_string(dir.join("gw-A.key")).expect("read gw-A.key"),
    }
}

/// Starts a REAL in-process relay whose `quinn::Endpoint` the test keeps —
/// the same "killable relay" construction `tests/relay_matrix.rs`'s
/// `enroll_and_spawn_killable_relay` documents: `spawn_server`'s returned
/// handle covers only the accept loop, so only `Endpoint::close` delivers
/// the genuine CONNECTION_CLOSE severance an eviction consists of.
async fn spawn_killable_relay(dir: &PathBuf) -> (SocketAddr, quinn::Endpoint) {
    let cfg = wiremesh_relay::server_config(dir).expect("relay server_config");
    let endpoint = quinn::Endpoint::server(cfg, "127.0.0.1:0".parse().unwrap())
        .expect("bind in-process relay endpoint");
    let addr = endpoint.local_addr().expect("read relay endpoint addr");
    tokio::spawn(wiremesh_relay::serve(endpoint.clone()));
    (addr, endpoint)
}

/// Polls until `t.is_healthy()` flips false, bounded by `budget`.
async fn wait_dead(t: &RelayTransport, budget: Duration, label: &str) {
    let deadline = Instant::now() + budget;
    while t.is_healthy() {
        if Instant::now() >= deadline {
            panic!("{label}: transport still healthy after {budget:?}");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Compile-level pin of the enum's shape and derives: three variants
/// (`Closed`, `TimedOut`, `Other`), `Copy`+`PartialEq`+`Debug` — what the
/// driver's branch (and these tests' `assert_eq!`s) require. `Other` has no
/// behavioral test of its own by design (see the module doc's "deliberately
/// NOT pinned"), but it must exist as the conservative catch-all.
#[test]
fn death_reason_enum_shape() {
    let all = [
        RelayDeathReason::Closed,
        RelayDeathReason::TimedOut,
        RelayDeathReason::Other,
    ];
    for (i, a) in all.iter().enumerate() {
        let copied = *a; // Copy
        assert_eq!(copied, *a, "{copied:?} must equal itself"); // PartialEq + Debug
        for b in &all[i + 1..] {
            assert_ne!(
                copied, *b,
                "variants must be distinct ({copied:?} vs {b:?})"
            );
        }
    }
}

/// The EVICTION branch's input: the relay gracefully closes the QUIC
/// connection out from under a live transport (`quinn::Endpoint::close` —
/// exactly what `relay_matrix.rs` case 3's `RelayHandle::evict` does). The
/// transport must go unhealthy and record `Some(Closed)` — the reason the
/// driver maps to "clear pin + teardown + reconnect a relay IMMEDIATELY"
/// (the ≤30s eviction re-path budget case 3 keeps pinning end-to-end).
#[tokio::test]
async fn graceful_relay_close_classifies_as_closed() {
    let dir = unique_dir("closed");
    let pems = provision(&dir);
    let (relay_addr, endpoint) = spawn_killable_relay(&dir).await;

    let t = RelayTransport::start(
        relay_addr, &pems.cert, &pems.key, &pems.ca, "gw-A", "gw-B", None,
    )
    .await
    .expect("RelayTransport::start against the in-process relay");

    // Alive: healthy, and NO death reason yet — a live transport reporting a
    // reason would let the driver act on a death that hasn't happened.
    assert!(t.is_healthy(), "fresh transport must be healthy");
    assert_eq!(
        t.death_reason(),
        None,
        "death_reason() must be None while the transport is alive"
    );

    // The eviction severance: every connection on the relay's endpoint gets
    // a real CONNECTION_CLOSE.
    endpoint.close(0u32.into(), b"test: evicting relay");

    wait_dead(&t, Duration::from_secs(10), "graceful close").await;
    assert_eq!(
        t.death_reason(),
        Some(RelayDeathReason::Closed),
        "a relay-side graceful QUIC close (eviction) must classify as Closed — the driver \
         branch that reconnects a surviving relay immediately instead of burning a direct \
         punch window (relay_matrix case 3's re-path budget)"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The WEDGE branch's input: the leg dies of pure SILENCE — no close frame
/// ever arrives, QUIC's idle timeout expires (the production shape: the
/// peer left the relay and the stuck side's leg starved). Reproduced
/// deterministically by connecting the transport THROUGH a single-client
/// UDP proxy and then dropping the proxy: neither side's packets cross
/// anymore, no CONNECTION_CLOSE can possibly be delivered, and the client's
/// idle timer expires. The transport must record `Some(TimedOut)` — the
/// reason the driver maps to the punch-window semantics `relay_matrix.rs`
/// case 4 pins (no immediate re-relay).
///
/// Duration: `wiremesh_relay::transport_config` fixes a 30s
/// `max_idle_timeout` on BOTH sides and exposes no tuning knob (checked —
/// it is a private fn applied inside `Client::connect_with_pems`; making it
/// tunable just for tests would fork the very constant this classification
/// exists to interpret). So this test legitimately runs ~30-35s and is
/// bounded at 60s. Neither side sends keep-alives (`keep_alive_interval` is
/// unset) and the transport's uplink only forwards local-socket traffic
/// (none here), so the silence is total and the expiry deterministic.
#[tokio::test]
async fn idle_silence_classifies_as_timed_out() {
    let dir = unique_dir("timedout");
    let pems = provision(&dir);
    let (relay_addr, _endpoint) = spawn_killable_relay(&dir).await;

    // Single-client UDP proxy: front (what the transport dials) <-> back
    // (connected to the real relay). Learns the client's address from its
    // first datagram. 64KiB buffers so DPLPMTUD probes on loopback are
    // forwarded rather than truncated.
    let front = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind proxy front");
    let back = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind proxy back");
    back.connect(relay_addr)
        .await
        .expect("connect proxy back to relay");
    let proxy_addr = front.local_addr().expect("proxy front addr");
    let proxy = tokio::spawn(async move {
        let mut client: Option<SocketAddr> = None;
        let mut fbuf = vec![0u8; 65536];
        let mut bbuf = vec![0u8; 65536];
        loop {
            tokio::select! {
                r = front.recv_from(&mut fbuf) => {
                    let Ok((n, from)) = r else { break };
                    client = Some(from);
                    let _ = back.send(&fbuf[..n]).await;
                }
                r = back.recv(&mut bbuf) => {
                    let Ok(n) = r else { break };
                    if let Some(c) = client {
                        let _ = front.send_to(&bbuf[..n], c).await;
                    }
                }
            }
        }
    });

    let t = RelayTransport::start(
        proxy_addr, &pems.cert, &pems.key, &pems.ca, "gw-A", "gw-B", None,
    )
    .await
    .expect("RelayTransport::start through the proxy (connect+register must succeed)");
    assert!(
        t.is_healthy(),
        "transport must be healthy while the proxy forwards"
    );
    assert_eq!(t.death_reason(), None, "no death reason while alive");

    // Kill the lane: from here on, total silence in both directions — the
    // relay cannot deliver a close even if it wanted to.
    proxy.abort();
    let _ = proxy.await;

    let silenced_at = Instant::now();
    wait_dead(&t, Duration::from_secs(60), "idle silence").await;
    let took = silenced_at.elapsed();
    eprintln!("idle_silence: transport died after {took:?} of silence");

    assert_eq!(
        t.death_reason(),
        Some(RelayDeathReason::TimedOut),
        "a leg that died of pure silence (QUIC idle timeout, the production wedge shape) \
         must classify as TimedOut — the driver branch that grants a clean direct punch \
         window instead of immediately re-relaying (relay_matrix case 4)"
    );

    // Sanity on the mechanism: death must have come from the ~30s idle
    // timer, not something instant (which would mean a close slipped
    // through — i.e. this test stopped exercising the silence path at all).
    assert!(
        took >= Duration::from_secs(10),
        "transport died only {took:?} after the proxy dropped — too fast for an idle \
         timeout; the severance was not silence, so the TimedOut classification above \
         proved nothing. Investigate the harness before trusting this test"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A dead transport must always carry SOME reason: the driver branches on
/// `death_reason()` after observing `is_healthy() == false`, and a
/// `None` there would fall through to an arbitrary default. (Behaviorally
/// covered by re-checking after the Closed-path death; kept as its own
/// test so the invariant is named, not incidental.)
#[tokio::test]
async fn dead_transport_always_has_a_reason() {
    let dir = unique_dir("always-reason");
    let pems = provision(&dir);
    let (relay_addr, endpoint) = spawn_killable_relay(&dir).await;

    let t = RelayTransport::start(
        relay_addr, &pems.cert, &pems.key, &pems.ca, "gw-A", "gw-B", None,
    )
    .await
    .expect("RelayTransport::start against the in-process relay");
    endpoint.close(0u32.into(), b"test: severing");
    wait_dead(&t, Duration::from_secs(10), "severance").await;

    assert!(
        t.death_reason().is_some(),
        "an unhealthy transport must have recorded a death reason — the RelayDied driver \
         branch has no meaningful behavior for a dead-but-reasonless transport"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
