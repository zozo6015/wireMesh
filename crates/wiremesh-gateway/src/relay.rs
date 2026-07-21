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

/// Directional, deterministic per-(gateway,peer) relay registration id.
///
/// Review fix (4c Task 8, CRITICAL): every peer's `RelayTransport` used to
/// register at the relay under this gateway's raw `gateway_id`, so a gateway
/// relaying 2+ peers through one relay collided in the relay's
/// `HashMap<[u8; 8], Connection>` registry and one peer's downlink silently
/// died. Hashing `(my_gateway_id, peer_gateway_id)` in that order gives each
/// ordered pair its own id, so gateway A's transport-for-B and A's
/// transport-for-C never collide, while A's transport-for-B and B's
/// transport-for-A still rendezvous at the relay by design (main.rs calls
/// this with the arguments swapped on each side).
///
/// 32-bit id space (first 4 bytes of a SHA-256 digest, hex-encoded to 8 ASCII
/// bytes to fit the relay's 8-byte truncated registration id): collision-safe
/// at v1's ≤50-segment/~1225-pair scale; a wider raw-`[u8; 8]` id or a single
/// per-(gateway,relay) multiplexed connection is a documented fast-follow.
pub fn relay_pair_id(my_gateway_id: u64, peer_gateway_id: u64) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(my_gateway_id.to_be_bytes());
    hasher.update(peer_gateway_id.to_be_bytes());
    let digest = hasher.finalize();
    digest[..4].iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review fix (4c Task 8, CRITICAL): every peer's `RelayTransport` used
    /// to register at the relay under the same `gateway_id`, so a gateway
    /// relaying 2+ peers through one relay would collide in the relay's
    /// registry and one peer's downlink would go dark. `relay_pair_id` must
    /// give each ordered (my, peer) pair its own id, deterministically, and
    /// fit within the relay's 8-byte truncated registration id.
    #[test]
    fn relay_pair_id_is_directional_distinct_and_bounded() {
        // Directional: A's registration id (for the A->B pair) must differ
        // from B's registration id (for the B->A pair), or the two peers'
        // registrations collide at the relay.
        assert_ne!(relay_pair_id(1, 2), relay_pair_id(2, 1));

        // Distinct per peer: one gateway's ids for two different peers must
        // never collide — this is the whole point of the fix.
        assert_ne!(relay_pair_id(1, 2), relay_pair_id(1, 3));

        // Deterministic: same inputs, same id, every time.
        assert_eq!(relay_pair_id(1, 2), relay_pair_id(1, 2));

        // Bounded: must fit the relay's 8-byte truncated registration id,
        // even for large gateway ids.
        assert!(relay_pair_id(1, 2).len() <= 8, "must fit the relay's 8-byte id");
        assert!(
            relay_pair_id(u64::MAX, u64::MAX - 1).len() <= 8,
            "must fit the relay's 8-byte id even for large ids"
        );

        // ASCII: must survive the relay's byte-truncation as a valid string.
        assert!(relay_pair_id(1, 2).is_ascii());
    }
}
