// relay <bind_udp> [certdir] — QUIC datagram forwarder with mandatory mutual
// TLS. Every accepted connection MUST present a client certificate chaining
// to certdir/ca.pem (enforced in wiremesh_relay::server_config_with_denylist
// via WebPkiClientVerifier, PLUS a rejection for any serial on the loaded
// denylist); connections that don't fail the handshake and never reach the
// registration/forwarding loop below at all.
//
// `certdir` defaults to `/var/lib/wiremesh` (spec §3 identity/state store
// location): the real relay identity (cert/key/ca) is written there, mode
// 0600, by fabric-CA enrollment (Cycle 4c Task 4) — this binary only READS
// it, never writes it. `<certdir>/denylist.json` is loaded fail-static at
// startup (Cycle 4c Task 3): present or not, the relay always starts and
// serves — a missing file just means "nothing revoked yet".
use anyhow::Result;
use clap::Parser;
use quinn::Endpoint;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use wiremesh_relay::Registry;

#[derive(Parser)]
struct Args {
    /// UDP address to bind the QUIC endpoint on, e.g. 127.0.0.1:4443.
    bind: SocketAddr,
    /// Directory containing ca.pem + relay.pem/key (from mkcerts, or written
    /// by fabric-CA enrollment in production — see module doc comment).
    #[arg(default_value = "/var/lib/wiremesh")]
    certdir: PathBuf,
    /// Controller Sync address (mTLS), e.g. 127.0.0.1:7000. When given, the
    /// relay runs a background Sync client (`wiremesh_relay::run_sync`) that
    /// folds the controller's `revoked_serials` into the live denylist and
    /// persists it to `<certdir>/denylist.json`. When absent (as in the
    /// offline denylist test), the relay serves using only whatever denylist
    /// was already on disk at startup — no controller involved at all.
    #[arg(long)]
    controller: Option<SocketAddr>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let denylist_path = args.certdir.join("denylist.json");
    let denylist = wiremesh_relay::Denylist::load(&denylist_path)?;
    eprintln!(
        "relay: loaded denylist ({} revoked serial(s)) from {}",
        denylist.snapshot().len(),
        denylist_path.display()
    );

    if let Some(sync_addr) = args.controller {
        let denylist = denylist.clone();
        let certdir = args.certdir.clone();
        let persist_path = denylist_path.clone();
        tokio::spawn(async move {
            // Simple reconnect-with-backoff loop: a controller outage must
            // never take the relay's datagram-forwarding path down with it
            // (fail-static — see module doc comment). Each disconnect just
            // means the relay keeps enforcing whatever denylist it last
            // persisted until the controller comes back.
            loop {
                let result = wiremesh_relay::run_sync(
                    sync_addr,
                    &certdir,
                    "relay",
                    denylist.clone(),
                    persist_path.clone(),
                )
                .await;
                if let Err(e) = result {
                    eprintln!("relay: sync client error (will retry): {e:#}");
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
    }

    let server_config = wiremesh_relay::server_config_with_denylist(&args.certdir, denylist)?;
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

            let (ack_stream, id) = match wiremesh_relay::read_registration_id(&conn).await {
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
            if let Err(e) = wiremesh_relay::ack_registration(ack_stream).await {
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
