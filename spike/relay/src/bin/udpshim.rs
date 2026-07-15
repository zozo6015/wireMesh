// udpshim <local_udp_bind> <relay_addr> <certdir> <my_id> <peer_id> — bridges
// a local UDP socket to the relay. This is the spike stand-in for the
// gateway's integrated relay transport: WireGuard's endpoint is pointed at
// this shim's local bind, so packets flow
//   wg -> shim local socket -> relay -> peer shim -> peer wg
// Two independent pump loops share the local `UdpSocket` (via `Arc`, so both
// halves can be used concurrently without a lock on the socket itself) and a
// `last_seen` peer address (via `Arc<Mutex<..>>`, since both loops touch it):
//   - local socket -> relay: read a datagram from the local UDP socket,
//     remember its source as `last_seen`, and forward the payload to the
//     fixed `peer_id` over the relay.
//   - relay -> local socket: read a datagram from the relay and forward its
//     payload to whichever local address was last seen sending.
use anyhow::{Context, Result};
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

#[derive(Parser)]
struct Args {
    /// Local UDP address to bind, e.g. 127.0.0.1:51999. WireGuard's peer
    /// endpoint is pointed at this address.
    bind: SocketAddr,
    /// Relay's UDP/QUIC address, e.g. 10.9.3.2:4443.
    relay_addr: SocketAddr,
    /// Directory containing ca.pem + this shim's gw-<my_id>.pem/key (mkcerts).
    certdir: PathBuf,
    /// This shim's own relay registration id, e.g. "gw-A".
    my_id: String,
    /// The peer shim's relay id to send datagrams to, e.g. "gw-B".
    peer_id: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let sock = Arc::new(
        UdpSocket::bind(args.bind)
            .await
            .with_context(|| format!("bind local UDP socket {}", args.bind))?,
    );
    let client = relay::Client::connect(args.relay_addr, &args.certdir, &args.my_id)
        .await
        .with_context(|| format!("connect to relay {}", args.relay_addr))?;
    eprintln!(
        "udpshim: {} registered as {:?}, bridging {} <-> relay peer {:?}",
        args.relay_addr, args.my_id, args.bind, args.peer_id
    );

    let last_seen: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    // local socket -> relay
    let uplink = {
        let sock = sock.clone();
        let last_seen = last_seen.clone();
        let client = client.clone();
        let peer_id = args.peer_id.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let (n, from) = match sock.recv_from(&mut buf).await {
                    Ok(pair) => pair,
                    Err(e) => {
                        eprintln!("udpshim: local recv_from failed: {e}");
                        break;
                    }
                };
                *last_seen.lock().await = Some(from);
                if let Err(e) = client.send_to(&peer_id, &buf[..n]).await {
                    eprintln!("udpshim: relay send_to {peer_id:?} failed: {e}");
                }
            }
        })
    };

    // relay -> local socket
    let downlink = tokio::spawn(async move {
        loop {
            let (_src, data) = match client.recv().await {
                Ok(pair) => pair,
                Err(e) => {
                    eprintln!("udpshim: relay recv failed: {e}");
                    break;
                }
            };
            let dest = *last_seen.lock().await;
            match dest {
                Some(peer) => {
                    if let Err(e) = sock.send_to(&data, peer).await {
                        eprintln!("udpshim: local send_to {peer} failed: {e}");
                    }
                }
                None => {
                    // No local peer has sent anything yet, so there's nowhere
                    // to deliver this datagram; drop it (UDP semantics).
                    eprintln!("udpshim: dropping relay datagram, no local peer seen yet");
                }
            }
        }
    });

    tokio::select! {
        res = uplink => res.context("uplink task panicked")?,
        res = downlink => res.context("downlink task panicked")?,
    }
    Ok(())
}
