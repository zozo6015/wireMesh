//! Gateway relay transport (Cycle 4c Task 7) — local UDP <-> QUIC relay.
//!
//! Graduates `spike/relay/src/bin/udpshim.rs`'s local-UDP <-> relay-QUIC
//! bridge into a `RelayTransport` the gateway can hold in-process: WireGuard's
//! peer endpoint gets pointed at `local_addr()` (Task 8, NOT here), and this
//! transport bridges that local socket to a fixed relay peer id over a
//! `wiremesh_relay::Client` connection.
//!
//! Two independent pump loops share the local `UdpSocket` (via `Arc`, so both
//! halves can be used concurrently without a lock on the socket itself) and a
//! `last_seen` peer address (via `Arc<Mutex<..>>`, since both loops touch
//! it) — exactly mirroring udpshim:
//!   - local socket -> relay (uplink): read a datagram from the local UDP
//!     socket, remember its source as `last_seen`, forward the payload to
//!     the fixed `peer_id` over the relay.
//!   - relay -> local socket (downlink): read a datagram from the relay and
//!     forward its payload to whichever local address was last seen sending.
//!
//! Scope (Cycle 4c Task 7): just the transport mechanism + the loopback test
//! in `tests/relay_transport.rs`. NOT here: pointing boringtun's peer
//! endpoint at `local_addr()`, the path state machine, make-before-break, or
//! `RelayHealth` reporting (all Task 8).
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use wiremesh_relay::Client;

/// WHY a [`RelayTransport`]'s QUIC leg died — the classification the
/// `PathAction::RelayDied` driver branch dispatches on (aether-prod-fi-01
/// relay-wedge fix, follow-up round; API and semantics pinned by
/// `tests/relay_death_reason.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayDeathReason {
    /// The connection died via a real close frame — the relay gracefully
    /// closed it under us (`quinn::Endpoint::close`, the controller-eviction
    /// severance `relay_matrix.rs` case 3 drives), or the close was local.
    /// Driver: clear the pin, tear down, and reconnect a relay IMMEDIATELY —
    /// a peer evicted alongside us is re-pathing to the surviving relay too,
    /// so a direct punch window first would just burn ~12s for a pairing
    /// that may not even punch.
    Closed,
    /// The leg died of pure SILENCE (QUIC idle timeout — the production
    /// wedge shape: the peer left the relay and nothing ever arrived again).
    /// Driver: punch-window semantics (clear the pin, tear down, do NOT
    /// immediately re-relay — `relay_matrix.rs` case 4).
    TimedOut,
    /// Any other connection error (`Reset`, `TransportError`, ...). The
    /// driver maps this conservatively to the punch-window path.
    Other,
}

/// Maps quinn's connection-level error onto the driver's three-way
/// classification. `LocallyClosed` counts as `Closed` deliberately: the
/// driver only reads `death_reason()` for transports that died on their own
/// (BEFORE tearing them down), so the local-close reading is unpinned by the
/// tests — see `tests/relay_death_reason.rs`'s "deliberately NOT pinned".
fn classify(err: &quinn::ConnectionError) -> RelayDeathReason {
    match err {
        quinn::ConnectionError::ApplicationClosed(_)
        | quinn::ConnectionError::ConnectionClosed(_)
        | quinn::ConnectionError::LocallyClosed => RelayDeathReason::Closed,
        quinn::ConnectionError::TimedOut => RelayDeathReason::TimedOut,
        _ => RelayDeathReason::Other,
    }
}

/// A local-UDP <-> relay-QUIC bridge for one gateway-to-gateway relay path.
/// Binds an ephemeral local UDP socket, connects to (and registers with) the
/// relay, and runs the uplink/downlink pumps for the lifetime of this value.
/// Dropping it aborts both pump tasks.
pub struct RelayTransport {
    local_addr: SocketAddr,
    client: Client,
    uplink: JoinHandle<()>,
    downlink: JoinHandle<()>,
    /// First connection-death classification either pump observed (write-once;
    /// shared with both pump tasks). [`Self::death_reason`] prefers this but
    /// does not depend on it — see that method's fallback.
    death_reason: Arc<OnceLock<RelayDeathReason>>,
}

impl RelayTransport {
    /// Binds a local UDP socket on `127.0.0.1:0`, connects to the relay at
    /// `relay_addr` with the given mTLS identity (registering as `my_id`),
    /// and spawns the uplink/downlink pumps bridging that local socket to
    /// `peer_id` over the relay.
    ///
    /// `local_peer_hint`, if given, seeds the downlink's `last_seen` address
    /// UP FRONT instead of learning it from the first datagram the local
    /// socket happens to receive (Cycle 4c Task 9 fix — see the module doc's
    /// "last-seen socket dance" and `tests/relay_transport.rs`'s doc comment
    /// for the generic udpshim-style chicken/egg this normally requires: a
    /// relayed inbound datagram is dropped, silently, until the local peer
    /// has sent at least one datagram of its own). The gateway's caller
    /// (`main.rs::ensure_relay_transport`) always knows this in advance —
    /// its own boringtun WG process is the only thing that will ever talk to
    /// this local socket, always from its fixed, already-known
    /// `127.0.0.1:<wg_listen_port>` — so there is no need to wait and learn
    /// it: seeding it removes an otherwise-real risk that BOTH sides' very
    /// first relayed handshake packets get silently dropped (each side's
    /// `last_seen` still empty because neither had yet sent anything of its
    /// own through its OWN transport), stalling the initial handshake until
    /// boringtun's own retry timer eventually resolves it out-of-band —
    /// slow enough to threaten a bounded conformance budget. `None` preserves
    /// the original learn-from-first-datagram behavior (used by
    /// `tests/relay_transport.rs`, which deliberately exercises that generic
    /// path with throwaway sockets standing in for "unknown ahead of time"
    /// peers).
    pub async fn start(
        relay_addr: SocketAddr,
        cert_pem: &str,
        key_pem: &str,
        ca_pem: &str,
        my_identity: &str,
        peer_identity: &str,
        local_peer_hint: Option<SocketAddr>,
    ) -> Result<RelayTransport> {
        let sock = Arc::new(
            UdpSocket::bind("127.0.0.1:0")
                .await
                .context("bind local UDP socket for relay transport")?,
        );
        let local_addr = sock.local_addr().context("read bound local UDP addr")?;

        // SECURITY (Cycle 4c): `my_identity`/`peer_identity` are the gateways'
        // cert-embedded `gw-<id>` identities. The relay REQUIRES `my_identity`
        // to match this connection's client cert (see
        // `wiremesh_relay::identity_from_client_cert`) and derives the 8-byte
        // registry key from the pair itself — a gateway can no longer register
        // under an id it doesn't own.
        let client =
            Client::connect_with_pems(relay_addr, cert_pem, key_pem, ca_pem, my_identity, peer_identity)
                .await
                .with_context(|| {
                    format!("connect+register {my_identity:?}->{peer_identity:?} with relay {relay_addr}")
                })?;

        let last_seen: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(local_peer_hint));
        let death_reason: Arc<OnceLock<RelayDeathReason>> = Arc::new(OnceLock::new());

        // local socket -> relay
        let uplink = {
            let sock = sock.clone();
            let last_seen = last_seen.clone();
            let client = client.clone();
            let death = death_reason.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                loop {
                    let (n, from) = match sock.recv_from(&mut buf).await {
                        Ok(pair) => pair,
                        Err(e) => {
                            eprintln!("relay transport: local recv_from failed: {e}");
                            break;
                        }
                    };
                    *last_seen.lock().await = Some(from);
                    // The `Client` is bound to this peer; `send` addresses the
                    // datagram at the id the peer registered under.
                    if let Err(e) = client.send(&buf[..n]).await {
                        eprintln!("relay transport: relay send failed: {e}");
                        // Death classification (aether-prod-fi-01 fix): a
                        // send error that carries a connection-level cause
                        // means the QUIC leg is dead — record why. `Client::
                        // send` fails with `quinn::SendDatagramError`
                        // (`ConnectionLost` wraps the `ConnectionError`);
                        // a bare `ConnectionError` is checked too for
                        // robustness against wiremesh-relay refactors.
                        // Non-connection send errors (e.g. datagram too
                        // large) record nothing — the connection is alive.
                        let ce = e.downcast_ref::<quinn::ConnectionError>().cloned().or_else(
                            || match e.downcast_ref::<quinn::SendDatagramError>() {
                                Some(quinn::SendDatagramError::ConnectionLost(ce)) => {
                                    Some(ce.clone())
                                }
                                _ => None,
                            },
                        );
                        if let Some(ce) = ce {
                            let _ = death.set(classify(&ce));
                        }
                    }
                }
            })
        };

        // relay -> local socket
        let downlink = {
            let client = client.clone();
            let death = death_reason.clone();
            tokio::spawn(async move {
                loop {
                    let (_src, data) = match client.recv().await {
                        Ok(pair) => pair,
                        Err(e) => {
                            eprintln!("relay transport: relay recv failed: {e}");
                            // Death classification (aether-prod-fi-01 fix):
                            // `Client::recv` is `conn.read_datagram().await?`,
                            // so a connection death surfaces here with the
                            // `quinn::ConnectionError` intact in the anyhow
                            // chain. A non-connection recv error (the
                            // short-datagram bail) records nothing — the
                            // connection itself is still alive.
                            if let Some(ce) = e.downcast_ref::<quinn::ConnectionError>() {
                                let _ = death.set(classify(ce));
                            }
                            break;
                        }
                    };
                    let dest = *last_seen.lock().await;
                    match dest {
                        Some(peer) => {
                            if let Err(e) = sock.send_to(&data, peer).await {
                                eprintln!("relay transport: local send_to {peer} failed: {e}");
                            }
                        }
                        None => {
                            // No local peer has sent anything yet, so
                            // there's nowhere to deliver this datagram; drop
                            // it (UDP semantics) — mirrors udpshim.
                            eprintln!(
                                "relay transport: dropping relay datagram, no local peer seen yet"
                            );
                        }
                    }
                }
            })
        };

        Ok(RelayTransport { local_addr, client, uplink, downlink, death_reason })
    }

    /// The bound local UDP address. WireGuard's peer endpoint gets pointed
    /// at this address (Task 8) so that traffic WireGuard sends to this peer
    /// flows into the uplink pump above.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Whether the underlying relay `Client`'s QUIC connection is still
    /// alive. See `wiremesh_relay::Client::is_alive`.
    pub fn is_healthy(&self) -> bool {
        self.client.is_alive()
    }

    /// `None` while the transport is alive; once the QUIC leg is dead, the
    /// classification of HOW it died (see [`RelayDeathReason`]) — what the
    /// `PathAction::RelayDied` driver branch dispatches on: `Closed` (a
    /// relay-side graceful close, i.e. an eviction) reconnects a relay
    /// immediately, `TimedOut`/`Other` keep the punch-window semantics.
    ///
    /// INVARIANT (pinned by `tests/relay_death_reason.rs`): `is_healthy() ==
    /// false` implies `Some(..)`. This does NOT depend on pump-task
    /// scheduling: a pump-recorded classification is preferred, but the
    /// fallback derives the reason from `Client::close_reason()` — the very
    /// connection state `is_healthy`/`is_alive` reads
    /// (`close_reason().is_none()`) — so the reason is available the instant
    /// liveness flips false, even if the downlink pump's broken `recv` has
    /// not been scheduled to record it yet.
    pub fn death_reason(&self) -> Option<RelayDeathReason> {
        if let Some(r) = self.death_reason.get() {
            return Some(*r);
        }
        self.client.close_reason().map(|e| classify(&e))
    }

    /// Explicitly close the relay QUIC connection (Task 7 carry: `Client` is
    /// a `Clone`-able handle onto a refcounted `quinn::Connection`, so a bare
    /// `Drop` of this `RelayTransport` — which only aborts the two pump
    /// tasks below — does not itself tell the relay the session is over; the
    /// pumps' own clones of `client` would otherwise leave the connection
    /// open until QUIC's idle timeout). Callers tearing a transport down on
    /// purpose (relay-to-direct cutover, relay-to-relay re-path) should call
    /// this before/while dropping the `RelayTransport` so the relay frees
    /// its registry entry promptly; see `main.rs`'s teardown call site.
    pub fn close(&self) {
        self.client.close();
    }
}

impl Drop for RelayTransport {
    fn drop(&mut self) {
        self.client.close();
        self.uplink.abort();
        self.downlink.abort();
    }
}

// The per-(gateway,peer) relay registration id derivation moved to
// `wiremesh_relay::registration_key` (Cycle 4c security fix): it is now keyed
// on the gateways' cert-embedded `gw-<id>` IDENTITY strings (not raw numeric
// gateway_ids), because the relay derives the same key from the authenticated
// client cert to bind a registration to its owner. `main.rs` passes the
// identity strings (`gw-<gateway_id>`) to `RelayTransport::start`, which hands
// them to `wiremesh_relay::Client`; the directionality/distinctness/bounded
// properties are now proven by that crate's `registration_key` unit test.
