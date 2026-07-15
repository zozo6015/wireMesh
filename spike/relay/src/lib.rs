// relay client lib + TLS plumbing shared with the `relay` server binary.
//
// Wire format:
//   - Registration: each client's first (and only) unidirectional stream
//     carries its 8-byte, NUL-padded id.
//   - Datagrams sent to the relay: `[8B dest_id][payload]`.
//   - Datagrams the relay forwards to the destination: `[8B src_id][payload]`.
use anyhow::{bail, Context, Result};
use quinn::{
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    ClientConfig as QuinnClientConfig, Connection, Endpoint, MtuDiscoveryConfig,
    ServerConfig as QuinnServerConfig, TransportConfig,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};

/// SNI / certificate-verification name used for every relay connection.
/// mkcerts bakes this in as a SAN on `relay.pem`, so it is stable regardless
/// of what IP address the relay is actually reachable at.
const RELAY_SERVER_NAME: &str = "relay";

fn pad_id(id: &str) -> [u8; 8] {
    let mut buf = [0u8; 8];
    let bytes = id.as_bytes();
    let n = bytes.len().min(8);
    buf[..n].copy_from_slice(&bytes[..n]);
    buf
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut data.as_slice()).collect();
    let certs = certs.with_context(|| format!("parse cert PEM {}", path.display()))?;
    if certs.is_empty() {
        bail!("no certificates found in {}", path.display());
    }
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    rustls_pemfile::private_key(&mut data.as_slice())
        .with_context(|| format!("parse key PEM {}", path.display()))?
        .with_context(|| format!("no private key found in {}", path.display()))
}

/// Ensure a default `rustls` CryptoProvider is installed. Idempotent: quinn
/// pulls in both the `ring` and (transitively, via some feature paths)
/// `aws-lc-rs` backends, and `rustls::ServerConfig::builder()` /
/// `ClientConfig::builder()` panic if the process default is ambiguous and
/// nothing has been installed yet. Installing more than once returns an
/// `Err` we deliberately ignore.
fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Transport settings shared by server and client: 30s idle timeout, default
/// (enabled) DPLPMTUD, and application datagrams turned on with a 1MiB
/// receive buffer. This must be applied on *both* sides — an endpoint with
/// datagrams disabled locally reports `max_datagram_size() == None` even if
/// the peer has them enabled.
fn transport_config() -> Arc<TransportConfig> {
    let mut cfg = TransportConfig::default();
    cfg.max_idle_timeout(Some(
        Duration::from_secs(30)
            .try_into()
            .expect("30s fits in IdleTimeout"),
    ));
    cfg.mtu_discovery_config(Some(MtuDiscoveryConfig::default()));
    cfg.datagram_receive_buffer_size(Some(1 << 20));
    Arc::new(cfg)
}

/// Build the relay server's quinn `ServerConfig`: relay cert/key for the
/// handshake, and a `WebPkiClientVerifier` over `ca.pem` that makes client
/// certificates REQUIRED (not merely optional) — a certless client must fail
/// the handshake outright.
pub fn server_config(certdir: &Path) -> Result<QuinnServerConfig> {
    ensure_crypto_provider();

    let relay_certs = load_certs(&certdir.join("relay.pem"))?;
    let relay_key = load_key(&certdir.join("relay.key"))?;

    let mut roots = RootCertStore::empty();
    for ca_cert in load_certs(&certdir.join("ca.pem"))? {
        roots.add(ca_cert)?;
    }
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build()?;

    let mut tls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(relay_certs, relay_key)?;
    tls.alpn_protocols = vec![b"aetherlink-relay/0".to_vec()];

    let quic_crypto = QuicServerConfig::try_from(tls)?;
    let mut server_config = QuinnServerConfig::with_crypto(Arc::new(quic_crypto));
    server_config.transport_config(transport_config());
    Ok(server_config)
}

fn client_endpoint(certdir: &Path, my_id: Option<&str>) -> Result<Endpoint> {
    ensure_crypto_provider();

    let mut roots = RootCertStore::empty();
    for ca_cert in load_certs(&certdir.join("ca.pem"))? {
        roots.add(ca_cert)?;
    }

    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    let mut tls = match my_id {
        Some(id) => {
            let certs = load_certs(&certdir.join(format!("{id}.pem")))?;
            let key = load_key(&certdir.join(format!("{id}.key")))?;
            builder.with_client_auth_cert(certs, key)?
        }
        None => builder.with_no_client_auth(),
    };
    tls.alpn_protocols = vec![b"aetherlink-relay/0".to_vec()];

    let quic_crypto = QuicClientConfig::try_from(tls)?;
    let mut client_config = QuinnClientConfig::new(Arc::new(quic_crypto));
    client_config.transport_config(transport_config());

    let mut endpoint = Endpoint::client((std::net::Ipv4Addr::UNSPECIFIED, 0).into())?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// A connected, authenticated relay client. Cheap to clone: `quinn::Connection`
/// is itself an internally-refcounted handle, so `Client` just wraps one.
#[derive(Clone)]
pub struct Client {
    conn: Connection,
}

impl Client {
    /// Connect to the relay with mutual TLS: root = ca.pem, client cert =
    /// `gw-<my_id>.pem/key`. Registers `my_id` with the relay over the
    /// connection's first uni stream before returning.
    pub async fn connect(relay_addr: SocketAddr, certdir: &Path, my_id: &str) -> Result<Client> {
        let endpoint = client_endpoint(certdir, Some(my_id))?;
        Self::finish_connect(endpoint, relay_addr, my_id).await
    }

    /// Same as `connect`, but presents no client certificate at all. Used to
    /// prove the relay actually enforces mutual TLS: this must fail.
    pub async fn connect_no_cert(relay_addr: SocketAddr, certdir: &Path) -> Result<Client> {
        let endpoint = client_endpoint(certdir, None)?;
        // A certless connection has nothing to register as, but we still
        // need *some* id to open the registration stream with; the handshake
        // itself is expected to fail before this matters.
        Self::finish_connect(endpoint, relay_addr, "").await
    }

    async fn finish_connect(endpoint: Endpoint, relay_addr: SocketAddr, my_id: &str) -> Result<Client> {
        let conn = endpoint
            .connect(relay_addr, RELAY_SERVER_NAME)?
            .await
            .context("QUIC handshake failed")?;

        // Registration uses a *bidirectional* stream, not a bare uni stream:
        // `send.finish()` only flushes locally and returns as soon as the
        // client's send buffer is handed off, well before the relay has
        // necessarily called `accept_uni`/read the id/inserted it into its
        // registry. Without a round trip here, `Client::connect` can return
        // before the peer is actually registered, so a `send_to` issued
        // immediately afterwards (as the bridge test does, with no extra
        // delay) can race the relay's registry insert and silently drop as
        // "unknown dest". Reading a 1-byte ack back forces this function to
        // wait until the relay has processed the registration.
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .context("open registration stream")?;
        send.write_all(&pad_id(my_id))
            .await
            .context("write registration id")?;
        send.finish().context("finish registration stream")?;
        recv.read_to_end(1)
            .await
            .context("await registration ack")?;

        Ok(Client { conn })
    }

    /// Send `data` to `dest` (an id, NUL-padded/truncated to 8 bytes) as one
    /// QUIC datagram: `[8B dest_id][data]`.
    pub async fn send_to(&self, dest: &str, data: &[u8]) -> Result<()> {
        let mut buf = Vec::with_capacity(8 + data.len());
        buf.extend_from_slice(&pad_id(dest));
        buf.extend_from_slice(data);
        self.conn.send_datagram(buf.into())?;
        Ok(())
    }

    /// Receive the next forwarded datagram, returning `(src_id, payload)`
    /// with the 8-byte source-id header stripped. `src_id` has trailing NUL
    /// padding trimmed.
    pub async fn recv(&self) -> Result<(String, Vec<u8>)> {
        let dgram = self.conn.read_datagram().await?;
        if dgram.len() < 8 {
            bail!("datagram too short: {} bytes", dgram.len());
        }
        let src = String::from_utf8_lossy(&dgram[..8])
            .trim_end_matches('\0')
            .to_string();
        Ok((src, dgram[8..].to_vec()))
    }

    /// Max application-datagram payload this connection currently supports,
    /// or `None` if datagrams are disabled/unsupported. Varies with the live
    /// DPLPMTUD estimate.
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.conn.max_datagram_size()
    }
}

/// In-memory registry the relay binary uses to map a registered id to its
/// live connection. Exposed here so `src/bin/relay.rs` shares the type
/// instead of redeclaring it.
pub type Registry = Arc<tokio::sync::Mutex<std::collections::HashMap<[u8; 8], Connection>>>;

/// Read exactly one registration id (8 bytes) off a freshly-accepted
/// connection's first bidirectional stream. Returns the id plus the send
/// half of that stream so the caller can insert the id into its registry
/// *before* calling [`ack_registration`] — sending the ack any earlier would
/// reopen the race `ack_registration`'s doc comment describes, just shifted
/// to the server side (client would proceed on ack before the registry
/// insert actually happened).
pub async fn read_registration_id(conn: &Connection) -> Result<(quinn::SendStream, [u8; 8])> {
    let (send, mut recv) = conn.accept_bi().await.context("accept registration stream")?;
    let buf = recv.read_to_end(8).await.context("read registration id")?;
    let mut id = [0u8; 8];
    let n = buf.len().min(8);
    id[..n].copy_from_slice(&buf[..n]);
    Ok((send, id))
}

/// Write back the registration ack. Call only after the id has been inserted
/// into the registry — see [`read_registration_id`] and the comment on
/// `Client::finish_connect` for why the ack ordering matters.
pub async fn ack_registration(mut send: quinn::SendStream) -> Result<()> {
    send.write_all(&[1]).await.context("write registration ack")?;
    send.finish().context("finish registration ack stream")?;
    Ok(())
}
