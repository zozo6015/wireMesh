// relay <bind_udp> <certdir> — QUIC datagram forwarder with mandatory mutual
// TLS. Every accepted connection MUST present a client certificate chaining
// to certdir/ca.pem (enforced in relay::server_config via
// WebPkiClientVerifier); connections that don't fail the handshake and never
// reach the registration/forwarding loop below at all.
use anyhow::Result;
use clap::Parser;
use quinn::Endpoint;
use relay::Registry;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Parser)]
struct Args {
    /// UDP address to bind the QUIC endpoint on, e.g. 127.0.0.1:4443.
    bind: SocketAddr,
    /// Directory containing ca.pem + relay.pem/key (from mkcerts).
    certdir: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let server_config = relay::server_config(&args.certdir)?;
    let endpoint = Endpoint::server(server_config, args.bind)?;
    eprintln!("relay: listening on {}", args.bind);

    let registry: Registry = Arc::new(Mutex::new(HashMap::new()));

    while let Some(incoming) = endpoint.accept().await {
        let registry = registry.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(conn) => conn,
                Err(e) => {
                    // Mandatory client-cert handshake failures land here —
                    // e.g. a certless client (Client::connect_no_cert).
                    eprintln!("relay: handshake failed: {e}");
                    return;
                }
            };

            let (ack_stream, id) = match relay::read_registration_id(&conn).await {
                Ok(pair) => pair,
                Err(e) => {
                    eprintln!("relay: registration failed: {e}");
                    return;
                }
            };
            // Insert into the registry *before* acking: the client blocks on
            // the ack before it does anything else, so this ordering is what
            // guarantees a subsequent send_to from a peer can already find
            // this connection registered.
            registry.lock().await.insert(id, conn.clone());
            if let Err(e) = relay::ack_registration(ack_stream).await {
                eprintln!("relay: registration ack failed: {e}");
                registry.lock().await.remove(&id);
                return;
            }
            eprintln!(
                "relay: registered {:?} from {}",
                String::from_utf8_lossy(&id).trim_end_matches('\0'),
                conn.remote_address()
            );

            loop {
                let dgram = match conn.read_datagram().await {
                    Ok(dgram) => dgram,
                    Err(e) => {
                        eprintln!("relay: connection {:?} closed: {e}", String::from_utf8_lossy(&id));
                        break;
                    }
                };
                if dgram.len() < 8 {
                    continue;
                }
                let mut dest = [0u8; 8];
                dest.copy_from_slice(&dgram[..8]);

                let peer = registry.lock().await.get(&dest).cloned();
                if let Some(peer) = peer {
                    let mut fwd = Vec::with_capacity(dgram.len());
                    fwd.extend_from_slice(&id); // src id header
                    fwd.extend_from_slice(&dgram[8..]);
                    if let Err(e) = peer.send_datagram(fwd.into()) {
                        eprintln!("relay: forward to {:?} failed: {e}", String::from_utf8_lossy(&dest));
                    }
                } else {
                    eprintln!("relay: unknown dest {:?}", String::from_utf8_lossy(&dest));
                }
            }

            registry.lock().await.remove(&id);
        });
    }
    Ok(())
}
