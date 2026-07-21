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
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use wiremesh_relay::Client;

/// A local-UDP <-> relay-QUIC bridge for one gateway-to-gateway relay path.
/// Binds an ephemeral local UDP socket, connects to (and registers with) the
/// relay, and runs the uplink/downlink pumps for the lifetime of this value.
/// Dropping it aborts both pump tasks.
pub struct RelayTransport {
    local_addr: SocketAddr,
    client: Client,
    uplink: JoinHandle<()>,
    downlink: JoinHandle<()>,
}

impl RelayTransport {
    /// Binds a local UDP socket on `127.0.0.1:0`, connects to the relay at
    /// `relay_addr` with the given mTLS identity (registering as `my_id`),
    /// and spawns the uplink/downlink pumps bridging that local socket to
    /// `peer_id` over the relay.
    pub async fn start(
        relay_addr: SocketAddr,
        cert_pem: &str,
        key_pem: &str,
        ca_pem: &str,
        my_id: &str,
        peer_id: &str,
    ) -> Result<RelayTransport> {
        let sock = Arc::new(
            UdpSocket::bind("127.0.0.1:0")
                .await
                .context("bind local UDP socket for relay transport")?,
        );
        let local_addr = sock.local_addr().context("read bound local UDP addr")?;

        let client = Client::connect_with_pems(relay_addr, cert_pem, key_pem, ca_pem, my_id)
            .await
            .with_context(|| format!("connect+register {my_id:?} with relay {relay_addr}"))?;

        let last_seen: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

        // local socket -> relay
        let uplink = {
            let sock = sock.clone();
            let last_seen = last_seen.clone();
            let client = client.clone();
            let peer_id = peer_id.to_string();
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
                    if let Err(e) = client.send_to(&peer_id, &buf[..n]).await {
                        eprintln!("relay transport: relay send_to {peer_id:?} failed: {e}");
                    }
                }
            })
        };

        // relay -> local socket
        let downlink = {
            let client = client.clone();
            tokio::spawn(async move {
                loop {
                    let (_src, data) = match client.recv().await {
                        Ok(pair) => pair,
                        Err(e) => {
                            eprintln!("relay transport: relay recv failed: {e}");
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

        Ok(RelayTransport { local_addr, client, uplink, downlink })
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
}

impl Drop for RelayTransport {
    fn drop(&mut self) {
        self.uplink.abort();
        self.downlink.abort();
    }
}
