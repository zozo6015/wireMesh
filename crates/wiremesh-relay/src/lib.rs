// relay client lib + TLS plumbing shared with the `relay` server binary.
//
// Wire format:
//   - Registration: each client's first (and only) bidirectional stream
//     carries `[2B my_len][my_identity][peer_identity]` (both UTF-8). The
//     relay derives the client's TRUE identity from its authenticated client
//     certificate (a `gw-<id>` SAN), REQUIRES the self-asserted `my_identity`
//     to equal it (else it closes the connection), and keys the registry by
//     `registration_key(my_identity, peer_identity)` — an 8-byte id nobody
//     but the cert holder can register under. It replies with a 1-byte ack
//     once the entry is in its registry.
//   - Datagrams sent to the relay: `[8B dest_key][payload]`.
//   - Datagrams the relay forwards to the destination: `[8B src_key][payload]`.
//
// SECURITY (Cycle 4c): the registration id used to be an opaque, self-asserted
// 8-byte value — any enrolled gateway could register under (and thereby
// intercept datagrams for, or evict) ANOTHER pair's slot. It is now bound to
// the authenticated client certificate: a gateway can only ever register a
// key whose `my_identity` half equals its own cert-embedded `gw-<id>`, and a
// slot already held by a DIFFERENT cert is never blind-overwritten. See
// `serve`, `identity_from_client_cert`, and `registration_key`.
use anyhow::{anyhow, bail, Context, Result};
use quinn::{
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    ClientConfig as QuinnClientConfig, Connection, Endpoint, MtuDiscoveryConfig,
    ServerConfig as QuinnServerConfig, TransportConfig,
};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SerialNumber};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use std::{
    collections::HashSet,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Duration,
};

/// SNI / certificate-verification name used for every relay connection.
/// mkcerts bakes this in as a SAN on `relay.pem`, so it is stable regardless
/// of what IP address the relay is actually reachable at.
const RELAY_SERVER_NAME: &str = "relay";

/// Upper bound on a registration payload we will read off the wire. Identity
/// strings are short (`gw-<id>`), so this generous cap simply stops a
/// misbehaving/hostile peer from streaming an unbounded registration.
const MAX_REGISTRATION_BYTES: usize = 1024;

/// Deterministic 8-byte relay-registry id for the ordered
/// `(my_identity, peer_identity)` pair. This is the ONE derivation shared by
/// both sides: the relay keys its registry with `registration_key(my, peer)`
/// (my taken from the authenticated cert), and the addressing peer targets a
/// datagram at `registration_key(peer, my)` — i.e. the id the OTHER side
/// registered under — so the two ends rendezvous.
///
/// The identity strings are length-prefixed before hashing so that
/// `("gwa","b")` and `("gw","ab")` can never collide by concatenation. Only
/// the first 4 SHA-256 bytes are used, hex-encoded to 8 ASCII bytes to fit the
/// relay's fixed 8-byte key/datagram-header width — a 32-bit id space,
/// collision-safe at v1's ≤50-segment scale (a wider raw `[u8;8]` id is a
/// documented fast-follow, unchanged from the previous `relay_pair_id`).
pub mod enroll;

pub fn registration_key(my_identity: &str, peer_identity: &str) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update((my_identity.len() as u64).to_be_bytes());
    hasher.update(my_identity.as_bytes());
    hasher.update(peer_identity.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    for (i, b) in digest[..4].iter().enumerate() {
        let hex = [HEX[(b >> 4) as usize], HEX[(b & 0x0f) as usize]];
        out[i * 2] = hex[0];
        out[i * 2 + 1] = hex[1];
    }
    out
}

const HEX: [u8; 16] = *b"0123456789abcdef";

/// Encodes a registration payload: `[2B my_len BE][my_identity][peer_identity]`.
fn encode_registration(my_identity: &str, peer_identity: &str) -> Vec<u8> {
    let my = my_identity.as_bytes();
    let mut buf = Vec::with_capacity(2 + my.len() + peer_identity.len());
    buf.extend_from_slice(&(my.len() as u16).to_be_bytes());
    buf.extend_from_slice(my);
    buf.extend_from_slice(peer_identity.as_bytes());
    buf
}

/// Decodes a registration payload written by [`encode_registration`].
/// Fail-closed: any framing/UTF-8/empty-identity error is an `Err` the caller
/// turns into a connection close, never a permissive default.
fn decode_registration(buf: &[u8]) -> Result<(String, String)> {
    if buf.len() < 2 {
        bail!("registration payload too short: {} bytes", buf.len());
    }
    let my_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + my_len {
        bail!("registration payload truncated: my_len={my_len}, have {} bytes", buf.len() - 2);
    }
    let my = std::str::from_utf8(&buf[2..2 + my_len])
        .context("registration my_identity is not valid UTF-8")?
        .to_string();
    let peer = std::str::from_utf8(&buf[2 + my_len..])
        .context("registration peer_identity is not valid UTF-8")?
        .to_string();
    if my.is_empty() || peer.is_empty() {
        bail!("registration identities must both be non-empty (my={my:?}, peer={peer:?})");
    }
    Ok((my, peer))
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

/// Same as [`load_certs`], but parses an in-memory PEM string instead of
/// reading a file — used by [`Client::connect_with_pems`], whose caller (the
/// gateway) holds its cert/key/ca as PEM strings in `Identity`, not as files
/// in a certdir.
fn parse_certs_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut pem.as_bytes()).collect();
    let certs = certs.context("parse cert PEM string")?;
    if certs.is_empty() {
        bail!("no certificates found in PEM string");
    }
    Ok(certs)
}

/// Same as [`load_key`], but parses an in-memory PEM string instead of
/// reading a file.
fn parse_key_pem(pem: &str) -> Result<PrivateKeyDer<'static>> {
    rustls_pemfile::private_key(&mut pem.as_bytes())
        .context("parse key PEM string")?
        .context("no private key found in PEM string")
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
    tls.alpn_protocols = vec![b"wiremesh-relay/0".to_vec()];

    let quic_crypto = QuicServerConfig::try_from(tls)?;
    let mut server_config = QuinnServerConfig::with_crypto(Arc::new(quic_crypto));
    server_config.transport_config(transport_config());
    Ok(server_config)
}

/// Shared by the file-based (`client_endpoint`) and in-memory-PEM-based
/// (`client_endpoint_from_pems`) endpoint builders: given already-loaded
/// trust roots and an optional (cert chain, key) pair for mTLS client auth,
/// build the quinn client `Endpoint` with this crate's fixed transport
/// settings and ALPN.
fn build_client_endpoint(
    roots: RootCertStore,
    client_auth: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> Result<Endpoint> {
    ensure_crypto_provider();

    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    let mut tls = match client_auth {
        Some((certs, key)) => builder.with_client_auth_cert(certs, key)?,
        None => builder.with_no_client_auth(),
    };
    tls.alpn_protocols = vec![b"wiremesh-relay/0".to_vec()];

    let quic_crypto = QuicClientConfig::try_from(tls)?;
    let mut client_config = QuinnClientConfig::new(Arc::new(quic_crypto));
    client_config.transport_config(transport_config());

    let mut endpoint = Endpoint::client((std::net::Ipv4Addr::UNSPECIFIED, 0).into())?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

fn client_endpoint(certdir: &Path, my_id: Option<&str>) -> Result<Endpoint> {
    let mut roots = RootCertStore::empty();
    for ca_cert in load_certs(&certdir.join("ca.pem"))? {
        roots.add(ca_cert)?;
    }

    let client_auth = match my_id {
        Some(id) => {
            let certs = load_certs(&certdir.join(format!("{id}.pem")))?;
            let key = load_key(&certdir.join(format!("{id}.key")))?;
            Some((certs, key))
        }
        None => None,
    };
    build_client_endpoint(roots, client_auth)
}

fn client_endpoint_from_pems(cert_pem: &str, key_pem: &str, ca_pem: &str) -> Result<Endpoint> {
    let mut roots = RootCertStore::empty();
    for ca_cert in parse_certs_pem(ca_pem)? {
        roots.add(ca_cert)?;
    }

    let certs = parse_certs_pem(cert_pem)?;
    let key = parse_key_pem(key_pem)?;
    build_client_endpoint(roots, Some((certs, key)))
}

/// A connected, authenticated relay client, bound to ONE peer. Cheap to
/// clone: `quinn::Connection` is itself an internally-refcounted handle, so
/// `Client` just wraps one plus the precomputed 8-byte key its datagrams are
/// addressed to (the id its peer registered under).
#[derive(Clone)]
pub struct Client {
    conn: Connection,
    /// The registry id this client's datagrams are addressed to:
    /// `registration_key(peer_identity, my_identity)` — i.e. exactly the id
    /// the peer registered its own side under.
    dest_key: [u8; 8],
}

impl Client {
    /// Connect to the relay with mutual TLS: root = ca.pem, client cert =
    /// `<my_identity>.pem/key`. Registers the `(my_identity, peer_identity)`
    /// pair with the relay over the connection's first bidirectional stream
    /// (and waits for the relay's registration ack) before returning. The
    /// relay REQUIRES `my_identity` to equal the identity in this client's
    /// certificate (a `gw-<id>` SAN); a mismatch closes the connection and
    /// this call returns `Err`.
    pub async fn connect(
        relay_addr: SocketAddr,
        certdir: &Path,
        my_identity: &str,
        peer_identity: &str,
    ) -> Result<Client> {
        let endpoint = client_endpoint(certdir, Some(my_identity))?;
        Self::finish_connect(endpoint, relay_addr, my_identity, peer_identity).await
    }

    /// Same as `connect`, but presents no client certificate at all. Used to
    /// prove the relay actually enforces mutual TLS: this must fail. The
    /// identities are placeholders — the handshake fails before they matter.
    pub async fn connect_no_cert(relay_addr: SocketAddr, certdir: &Path) -> Result<Client> {
        let endpoint = client_endpoint(certdir, None)?;
        Self::finish_connect(endpoint, relay_addr, "gw-nocert", "gw-nocert").await
    }

    /// Same as `connect`, but takes cert/key/ca as in-memory PEM strings
    /// instead of a certdir — for a caller (the gateway) that holds its
    /// identity as PEM strings (`wiremesh_gateway::identity::Identity`), not
    /// as files on disk. `server_name` is always [`RELAY_SERVER_NAME`], same
    /// as the file-based `connect`.
    pub async fn connect_with_pems(
        relay_addr: SocketAddr,
        cert_pem: &str,
        key_pem: &str,
        ca_pem: &str,
        my_identity: &str,
        peer_identity: &str,
    ) -> Result<Client> {
        let endpoint = client_endpoint_from_pems(cert_pem, key_pem, ca_pem)?;
        Self::finish_connect(endpoint, relay_addr, my_identity, peer_identity).await
    }

    async fn finish_connect(
        endpoint: Endpoint,
        relay_addr: SocketAddr,
        my_identity: &str,
        peer_identity: &str,
    ) -> Result<Client> {
        let conn = endpoint
            .connect(relay_addr, RELAY_SERVER_NAME)?
            .await
            .context("QUIC handshake failed")?;

        // Registration uses a *bidirectional* stream, not a bare uni stream:
        // `send.finish()` only flushes locally and returns as soon as the
        // client's send buffer is handed off, well before the relay has
        // necessarily accepted the stream/read the id/inserted it into its
        // registry. Without a round trip here, `Client::connect` can return
        // before the peer is actually registered, so a `send` issued
        // immediately afterwards (as the bridge test does, with no extra
        // delay) can race the relay's registry insert and silently drop as
        // "unknown dest". Reading a 1-byte ack back forces this function to
        // wait until the relay has processed (and ACCEPTED) the registration
        // — an identity-mismatch/duplicate rejection instead closes the
        // connection, surfacing here as an `Err` on the ack read.
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .context("open registration stream")?;
        send.write_all(&encode_registration(my_identity, peer_identity))
            .await
            .context("write registration")?;
        send.finish().context("finish registration stream")?;
        recv.read_to_end(1)
            .await
            .context("await registration ack")?;

        Ok(Client {
            conn,
            dest_key: registration_key(peer_identity, my_identity),
        })
    }

    /// Send `data` to this client's bound peer as one QUIC datagram:
    /// `[8B dest_key][data]`, where `dest_key` is the id the peer registered
    /// under.
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        let mut buf = Vec::with_capacity(8 + data.len());
        buf.extend_from_slice(&self.dest_key);
        buf.extend_from_slice(data);
        self.conn.send_datagram(buf.into())?;
        Ok(())
    }

    /// Receive the next forwarded datagram, returning `(src_key, payload)`
    /// with the 8-byte source-key header stripped. `src_key` is the sender's
    /// registration id (the gateway's downlink ignores it — see
    /// `RelayTransport`).
    pub async fn recv(&self) -> Result<([u8; 8], Vec<u8>)> {
        let dgram = self.conn.read_datagram().await?;
        if dgram.len() < 8 {
            bail!("datagram too short: {} bytes", dgram.len());
        }
        let mut src = [0u8; 8];
        src.copy_from_slice(&dgram[..8]);
        Ok((src, dgram[8..].to_vec()))
    }

    /// Max application-datagram payload this connection currently supports,
    /// or `None` if datagrams are disabled/unsupported. Varies with the live
    /// DPLPMTUD estimate.
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.conn.max_datagram_size()
    }

    /// Whether the underlying QUIC connection is still open (no
    /// `CONNECTION_CLOSE` sent or received yet). The minimal liveness signal:
    /// a closed connection can never again forward datagrams, so `false`
    /// here means this `Client` is dead and must be replaced, not just
    /// degraded.
    pub fn is_alive(&self) -> bool {
        self.conn.close_reason().is_none()
    }

    /// Why the underlying QUIC connection closed, if it has ([`is_alive`]
    /// is exactly `close_reason().is_none()`, so this is `Some` iff the
    /// client is dead). Exposes quinn's own `Connection::close_reason` so a
    /// caller — the gateway's `RelayTransport` death-reason classification
    /// (aether-prod-fi-01 relay-wedge fix) — can tell a graceful relay-side
    /// close (eviction) from an idle timeout (peer left the relay) without
    /// racing its own pump tasks' error observation: the value is derived
    /// from the same connection state `is_alive` reads, so it is present
    /// the instant liveness flips false.
    pub fn close_reason(&self) -> Option<quinn::ConnectionError> {
        self.conn.close_reason()
    }

    /// Explicitly close the underlying QUIC connection (error code 0, no
    /// reason text). `Client` is `Clone` (a refcounted handle onto the same
    /// `quinn::Connection`), so simply dropping one clone does NOT close the
    /// connection — only this (or the last handle's drop, which quinn treats
    /// as an implicit abrupt close with a generic reason) actually tells the
    /// peer/relay the session is over. A caller tearing down a
    /// `RelayTransport` it no longer needs (e.g. the gateway's
    /// make-before-break relay-to-direct cutover, cycle4c Task 8) should call
    /// this explicitly rather than relying on `Drop`, so the relay frees the
    /// registry entry and any buffered state promptly instead of waiting on
    /// QUIC's idle timeout.
    pub fn close(&self) {
        self.conn.close(0u32.into(), b"");
    }
}

/// One registry slot: the live connection plus the cert-bound identity that
/// owns it. `owner` is what makes duplicate registrations safe — a second
/// registration for the same key is only allowed to REPLACE the slot when it
/// comes from the SAME cert identity (a reconnect), never a different one (an
/// eviction/redirection attempt).
#[derive(Clone)]
struct RegEntry {
    conn: Connection,
    owner: String,
}

/// In-memory registry mapping a registration key to its owning connection.
type Registry = Arc<tokio::sync::Mutex<std::collections::HashMap<[u8; 8], RegEntry>>>;

/// Extracts the registering gateway's TRUE identity from its authenticated
/// client certificate: the `gw-<id>` DNS SAN the CA stamps onto every gateway
/// leaf (see `services::enrollment`). This — not anything the client asserts
/// on the wire — is the unforgeable anchor the relay binds a registration to.
///
/// Fail-closed: no client identity, a non-cert identity, an unparseable cert,
/// or the absence of a `gw-*` SAN all return `Err`, which the caller turns
/// into a connection close. There is no permissive fallthrough.
fn identity_from_client_cert(conn: &Connection) -> Result<String> {
    let identity = conn
        .peer_identity()
        .context("no client identity (mandatory mutual TLS should have supplied one)")?;
    let certs = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| anyhow!("client identity was not an X.509 certificate chain"))?;
    let end_entity = certs
        .first()
        .context("client certificate chain was empty")?;
    let (_, cert) = x509_parser::parse_x509_certificate(end_entity.as_ref())
        .map_err(|e| anyhow!("parsing client cert DER: {e}"))?;
    let san = cert
        .subject_alternative_name()
        .map_err(|e| anyhow!("reading client cert SAN extension: {e}"))?
        .context("client cert has no SAN extension (no gw-<id> to bind to)")?;
    for gn in &san.value.general_names {
        if let x509_parser::extensions::GeneralName::DNSName(name) = gn {
            if name.strip_prefix("gw-").is_some_and(|rest| !rest.is_empty()) {
                return Ok((*name).to_string());
            }
        }
    }
    bail!("client cert has no gw-<id> DNS SAN to bind the registration to")
}

/// Read one registration payload (`[2B my_len][my_identity][peer_identity]`)
/// off a freshly-accepted connection's first bidirectional stream. Returns
/// the two identities plus the send half of that stream so the caller can
/// insert the entry into its registry *before* calling [`ack_registration`]
/// — sending the ack any earlier would reopen the race `ack_registration`'s
/// doc comment describes (client proceeds on ack before the registry insert
/// actually happened).
async fn read_registration(
    conn: &Connection,
) -> Result<(quinn::SendStream, String, String)> {
    let (send, mut recv) = conn.accept_bi().await.context("accept registration stream")?;
    let buf = recv
        .read_to_end(MAX_REGISTRATION_BYTES)
        .await
        .context("read registration payload")?;
    let (my_identity, peer_identity) = decode_registration(&buf)?;
    Ok((send, my_identity, peer_identity))
}

/// Write back the registration ack. Call only after the entry has been
/// inserted into the registry — see [`read_registration`] and the comment on
/// `Client::finish_connect` for why the ack ordering matters.
pub async fn ack_registration(mut send: quinn::SendStream) -> Result<()> {
    send.write_all(&[1]).await.context("write registration ack")?;
    send.finish().context("finish registration ack stream")?;
    Ok(())
}

/// Removes `key` from the registry ONLY if it is still owned by `conn`. A
/// connection that was already REPLACED by a same-owner reconnect must not,
/// on its own later teardown, evict the reconnect's live entry — so compare
/// quinn's stable connection id before removing.
async fn remove_if_owner(registry: &Registry, key: &[u8; 8], conn: &Connection) {
    let mut reg = registry.lock().await;
    if reg
        .get(key)
        .is_some_and(|e| e.conn.stable_id() == conn.stable_id())
    {
        reg.remove(key);
    }
}

/// The relay's accept -> handshake -> register -> datagram-forward loop
/// (embeddable via [`spawn_server`], used by the gateway's loopback relay
/// tests, and driven by the standalone `relay` binary). Runs until
/// `endpoint.accept()` returns `None` (the endpoint was closed) — it never
/// returns otherwise.
///
/// SECURITY (Cycle 4c): every registration is bound to the authenticated
/// client certificate. The self-asserted `my_identity` must equal the cert's
/// `gw-<id>` SAN, and a key already held by a different cert is never
/// blind-overwritten — both rejections close the connection (fail-closed).
pub async fn serve(endpoint: Endpoint) {
    let registry: Registry = Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

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

            // The unforgeable identity: read straight off the authenticated
            // client certificate, never from the wire.
            let cert_identity = match identity_from_client_cert(&conn) {
                Ok(id) => id,
                Err(e) => {
                    eprintln!("relay: rejecting connection, no bindable cert identity: {e}");
                    conn.close(1u32.into(), b"no cert identity");
                    return;
                }
            };

            let (ack_stream, my_identity, peer_identity) = match read_registration(&conn).await {
                Ok(t) => t,
                Err(e) => {
                    eprintln!("relay: registration read failed: {e}");
                    conn.close(1u32.into(), b"bad registration");
                    return;
                }
            };

            // SECURITY: the client-asserted `my_identity` MUST match the
            // identity bound into its cert. Otherwise a gateway could register
            // under (and receive datagrams destined for) another pair's slot.
            if my_identity != cert_identity {
                eprintln!(
                    "relay: rejecting registration: asserted my_identity {my_identity:?} \
                     != cert identity {cert_identity:?}"
                );
                conn.close(2u32.into(), b"identity mismatch");
                return;
            }

            let key = registration_key(&my_identity, &peer_identity);

            // SECURITY: never blind-overwrite a slot owned by a DIFFERENT cert
            // (that was the eviction/redirection DoS). A same-owner reconnect
            // is fine — it replaces its own slot.
            {
                let mut reg = registry.lock().await;
                if let Some(existing) = reg.get(&key) {
                    if existing.owner != cert_identity {
                        eprintln!(
                            "relay: rejecting registration for key {:?}: already held by {:?}, \
                             refusing overwrite by {:?}",
                            String::from_utf8_lossy(&key),
                            existing.owner,
                            cert_identity
                        );
                        drop(reg);
                        conn.close(3u32.into(), b"registration id in use");
                        return;
                    }
                }
                // Insert *before* acking: the client blocks on the ack before
                // it does anything else, so this ordering guarantees a
                // subsequent datagram from a peer can already find this entry.
                reg.insert(
                    key,
                    RegEntry {
                        conn: conn.clone(),
                        owner: cert_identity.clone(),
                    },
                );
            }

            if let Err(e) = ack_registration(ack_stream).await {
                eprintln!("relay: registration ack failed: {e}");
                remove_if_owner(&registry, &key, &conn).await;
                return;
            }
            eprintln!(
                "relay: registered key={:?} owner={cert_identity:?} peer={peer_identity:?} from {}",
                String::from_utf8_lossy(&key),
                conn.remote_address()
            );

            loop {
                let dgram = match conn.read_datagram().await {
                    Ok(dgram) => dgram,
                    Err(e) => {
                        eprintln!(
                            "relay: connection for key {:?} closed: {e}",
                            String::from_utf8_lossy(&key)
                        );
                        break;
                    }
                };
                if dgram.len() < 8 {
                    continue;
                }
                let mut dest = [0u8; 8];
                dest.copy_from_slice(&dgram[..8]);

                let peer = registry.lock().await.get(&dest).map(|e| e.conn.clone());
                if let Some(peer) = peer {
                    let mut fwd = Vec::with_capacity(dgram.len());
                    fwd.extend_from_slice(&key); // src key header
                    fwd.extend_from_slice(&dgram[8..]);
                    if let Err(e) = peer.send_datagram(fwd.into()) {
                        eprintln!("relay: forward to {:?} failed: {e}", String::from_utf8_lossy(&dest));
                    }
                } else {
                    eprintln!("relay: unknown dest {:?}", String::from_utf8_lossy(&dest));
                }
            }

            remove_if_owner(&registry, &key, &conn).await;
        });
    }
}

/// Test/embed convenience: builds a PLAIN (no-denylist) server config from
/// `certdir` (see [`server_config`]), binds it on `bind`, and spawns
/// [`serve`] on it in the background. Returns the actual bound address (so
/// callers can pass `bind = 0.0.0.0:0`/`127.0.0.1:0` and learn the ephemeral
/// port) plus the serve task's `JoinHandle`, so a test can hold the handle
/// (dropping it does not stop the task — it keeps running detached, which is
/// what a test wants for the lifetime of a single test function) or abort it
/// explicitly for cleanup.
///
/// This is deliberately the no-denylist config: production and the
/// standalone `relay` binary always go through
/// [`server_config_with_denylist`] instead. A caller that needs denylist
/// enforcement for an embedded relay should build its own
/// `server_config_with_denylist` + `Endpoint::server` and call [`serve`]
/// directly, mirroring what this function does.
pub async fn spawn_server(
    bind: SocketAddr,
    certdir: &Path,
) -> Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let cfg = server_config(certdir)?;
    let endpoint = Endpoint::server(cfg, bind).with_context(|| format!("binding relay endpoint on {bind}"))?;
    let local_addr = endpoint.local_addr().context("reading bound relay endpoint address")?;
    let handle = tokio::spawn(serve(endpoint));
    Ok((local_addr, handle))
}

/// A fresh, random 16-byte serial for [`test_certs`] — same width as
/// `wiremesh-trust::random_serial`. Not cryptographically tied to that
/// function (this is test tooling, not the real CA), but deliberately the
/// same byte length so serial encoding/normalization behaves identically.
fn test_cert_random_serial() -> [u8; 16] {
    use std::time::{SystemTime, UNIX_EPOCH};
    // No `rand` dependency in this crate; a simple splitmix64-style mix
    // seeded from wall-clock time plus PID is more than sufficient entropy
    // for test-only, non-security-sensitive serial uniqueness.
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
        ^ (std::process::id() as u128) << 64;
    let mut state = seed as u64 ^ 0x9E3779B97F4A7C15;
    let mut bytes = [0u8; 16];
    for chunk in bytes.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
    }
    bytes
}

/// Test/embed-convenience certificate generation, graduated (Cycle 4c Task
/// 7) from `src/bin/mkcerts.rs`'s `main`: writes a self-signed CA plus leaf
/// certs for the relay and every given gateway id into `dir` — `ca.pem`,
/// `relay.pem`/`relay.key` (SAN "relay"), and per id a
/// `gw-<id>.pem`/`gw-<id>.key` (+ `<id>.serial`, the lowercase-hex serial in
/// `wiremesh-trust::hex_encode`'s encoding, so a test can put it on a
/// [`Denylist`]). Every leaf gets an explicit 16-byte serial (rather than
/// rcgen's own random default) for exactly that reason.
///
/// `bin/mkcerts.rs` is refactored to call this; its CLI behavior (defaulting
/// to `gw-A`/`gw-B` when no ids are given) is unchanged, and lives in the
/// bin, not here — this function always generates leaves for exactly the
/// `gateway_ids` given.
pub fn test_certs(dir: &Path, gateway_ids: &[&str]) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;

    let ca_key = KeyPair::generate().context("generating CA key")?;
    let mut ca_params = CertificateParams::new(vec![]).context("building CA cert params")?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).context("self-signing CA cert")?;
    std::fs::write(dir.join("ca.pem"), ca_cert.pem()).context("writing ca.pem")?;

    // SANs include the loopback-adjacent test addresses used by natlab labs
    // (203.0.113.1 / 198.51.100.1, TEST-NET-3/TEST-NET-2) so the same certs
    // work whether a test dials 127.0.0.1 (server_name = the leaf's CN, e.g.
    // "relay") or a future netns-based test dials one of these IPs directly.
    let mut names: Vec<String> = vec!["relay".to_string()];
    names.extend(gateway_ids.iter().map(|s| s.to_string()));
    for name in &names {
        let key = KeyPair::generate().with_context(|| format!("generating key for {name}"))?;
        let mut params = CertificateParams::new(vec![
            name.to_string(),
            "203.0.113.1".to_string(),
            "198.51.100.1".to_string(),
        ])
        .with_context(|| format!("building cert params for {name}"))?;
        params.distinguished_name.push(DnType::CommonName, name.as_str());
        let serial = test_cert_random_serial();
        params.serial_number = Some(SerialNumber::from_slice(&serial));
        let cert = params
            .signed_by(&key, &ca_cert, &ca_key)
            .with_context(|| format!("signing cert for {name}"))?;
        std::fs::write(dir.join(format!("{name}.pem")), cert.pem())
            .with_context(|| format!("writing {name}.pem"))?;
        std::fs::write(dir.join(format!("{name}.key")), key.serialize_pem())
            .with_context(|| format!("writing {name}.key"))?;
        let serial_hex: String = serial.iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(dir.join(format!("{name}.serial")), &serial_hex)
            .with_context(|| format!("writing {name}.serial"))?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Cycle 4c Task 3: offline certificate-revocation denylist.
//
// A `Denylist` is an in-memory set of lowercase-hex cert serials (same
// format as `wiremesh-trust`'s `{b:02x}`-per-byte encoding of a 16-byte
// random serial), persisted to a JSON array file (0600, atomic rename —
// mirrors `wiremesh-gateway::state::DesiredState::save`). It is read
// fail-static at relay startup (a missing file is an empty set, not an
// error) so a relay that has never talked to a controller still enforces
// "nothing revoked", and a relay whose controller is currently unreachable
// still enforces the last snapshot it persisted.
#[derive(Debug, Clone)]
pub struct Denylist {
    inner: Arc<RwLock<HashSet<String>>>,
}

impl Default for Denylist {
    fn default() -> Self {
        Self::new()
    }
}

impl Denylist {
    pub fn new() -> Denylist {
        Denylist { inner: Arc::new(RwLock::new(HashSet::new())) }
    }

    /// Loads a denylist from `path` (a JSON array of lowercase-hex serial
    /// strings). A MISSING file is fail-static: it yields an empty denylist,
    /// not an error — a relay that has never received a Sync snapshot (or
    /// booted before any cert was ever revoked) must still start and serve.
    pub fn load(path: &Path) -> Result<Denylist> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let items: Vec<String> = serde_json::from_slice(&bytes)
                    .with_context(|| format!("parsing {}", path.display()))?;
                let dl = Denylist::new();
                dl.replace_all(items);
                Ok(dl)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Denylist::new()),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn contains(&self, serial_hex: &str) -> bool {
        self.inner
            .read()
            .expect("denylist RwLock poisoned")
            .contains(serial_hex)
    }

    /// Snapshot (full-replace) semantics: the controller's `StateSnapshot`
    /// carries the COMPLETE current `revoked_serials` set, so applying one
    /// must discard anything not in it (e.g. a serial un-revoked, or a
    /// stale entry from a prior persisted file).
    pub fn replace_all(&self, serials: impl IntoIterator<Item = String>) {
        let mut set = self.inner.write().expect("denylist RwLock poisoned");
        *set = serials.into_iter().collect();
    }

    /// Delta semantics: a `Delta.revoked_serials` is additive-only (mirrors
    /// `wiremesh-gateway::state::DesiredState::apply_delta`'s treatment of
    /// the same field) — a delta only ever announces newly revoked serials,
    /// never un-revokes one, so entries already present must never be
    /// dropped.
    pub fn union(&self, serials: impl IntoIterator<Item = String>) {
        let mut set = self.inner.write().expect("denylist RwLock poisoned");
        for s in serials {
            set.insert(s);
        }
    }

    pub fn snapshot(&self) -> HashSet<String> {
        self.inner.read().expect("denylist RwLock poisoned").clone()
    }

    /// Atomically persists the current denylist to `path` as a JSON array,
    /// mode 0600 from the moment the file is created — mirrors
    /// `wiremesh-gateway::state::DesiredState::save`'s write-tmp +
    /// fsync + rename + fsync-parent-dir sequence, so a crash never leaves
    /// a partially-written or loosely-permissioned denylist.json on disk.
    pub fn persist(&self, path: &Path) -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt;

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
        }

        let items: Vec<String> = {
            let set = self.inner.read().expect("denylist RwLock poisoned");
            set.iter().cloned().collect()
        };

        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .with_context(|| format!("opening {}", tmp.display()))?;
            f.write_all(&serde_json::to_vec_pretty(&items)?)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)
            .with_context(|| format!("atomically renaming {}", tmp.display()))?;
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::File::open(parent)
                .and_then(|d| d.sync_all())
                .with_context(|| format!("fsyncing {} after rename", parent.display()))?;
        }
        Ok(())
    }
}

/// Extracts a client cert's serial number as the lowercase-hex string
/// `wiremesh-trust` would have produced when it issued that cert (see
/// `wiremesh_trust::hex_encode`/`random_serial`).
///
/// `x509-parser`'s `raw_serial()` returns the DER INTEGER *content* bytes.
/// DER minimal-integer encoding does TWO things to the original 16-byte
/// serial: it (1) strips ALL leading `0x00` bytes, then (2) re-adds exactly
/// one `0x00` sign-pad iff the resulting first byte's high bit is set (so the
/// value isn't misread as negative). So `raw_serial()` can be SHORTER than 16
/// bytes (original had genuine leading zeros) OR 17 bytes (sign-pad case) —
/// it is NOT simply "16 bytes with maybe one extra leading 0x00".
///
/// `wiremesh-trust`'s `IssuedCert.serial` is the hex of the ORIGINAL 16 bytes
/// (leading zeros included), so we RECONSTRUCT that fixed width: undo the
/// sign-pad (drop one leading `0x00` only when the content is 17 bytes), then
/// LEFT-PAD the remainder back to 16 bytes. SECURITY-CRITICAL: do NOT
/// "simplify" this to a single-`0x00`-strip + hex of the variable-length
/// remainder — that silently corrupts the hex for any serial beginning with
/// `0x00` (~0.4% of random serials), so a correctly-revoked cert would never
/// match the denylist and would be ADMITTED. Regression guard:
/// `denylist_tests::extract_serial_hex_reconstructs_full_16_byte_serial`.
fn extract_serial_hex(end_entity: &CertificateDer<'_>) -> Result<String> {
    let (_, cert) = x509_parser::parse_x509_certificate(end_entity.as_ref())
        .map_err(|e| anyhow::anyhow!("parsing end-entity cert DER for serial: {e}"))?;
    let raw = cert.raw_serial();
    // raw_serial() is the DER INTEGER content: leading zeros stripped, with at most
    // one 0x00 pad re-added when the high bit is set. Undo the pad, then left-pad
    // back to the original fixed 16-byte width so the hex matches wiremesh-trust's
    // IssuedCert.serial (hex_encode of the raw 16 bytes, leading zeros included).
    let content: &[u8] = if raw.len() == 17 && raw[0] == 0x00 { &raw[1..] } else { raw };
    if content.len() > 16 {
        anyhow::bail!("cert serial DER content longer than 16 bytes: {}", content.len());
    }
    let mut serial16 = [0u8; 16];
    serial16[16 - content.len()..].copy_from_slice(content);
    Ok(serial16.iter().map(|b| format!("{b:02x}")).collect())
}

/// A `ClientCertVerifier` that delegates chain validation to an inner
/// `WebPkiClientVerifier` and, ONLY after that chain validation succeeds,
/// additionally rejects the connection if the end-entity cert's serial is on
/// a (live, mutably-updatable) denylist. Ordering matters: an untrusted or
/// malformed cert must still fail for the chain reason, not be silently
/// waved through because it happens not to be on the denylist.
#[derive(Debug)]
struct DenyingVerifier {
    inner: Arc<dyn rustls::server::danger::ClientCertVerifier>,
    denylist: Denylist,
}

impl rustls::server::danger::ClientCertVerifier for DenyingVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        // Chain validation FIRST: an untrusted/malformed/expired cert must
        // fail for that reason, never be shadowed by the denylist check.
        let verified = self.inner.verify_client_cert(end_entity, intermediates, now)?;

        let serial_hex = extract_serial_hex(end_entity).map_err(|e| {
            rustls::Error::General(format!("denylist: could not read client cert serial: {e}"))
        })?;
        if self.denylist.contains(&serial_hex) {
            return Err(rustls::Error::InvalidCertificate(rustls::CertificateError::Revoked));
        }
        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Identical to [`server_config`] except the client-cert verifier ALSO
/// rejects any client whose cert serial is present in `denylist` (checked
/// after webpki chain validation succeeds — see [`DenyingVerifier`]). The
/// plain `server_config` remains available for callers that want no
/// denylist at all; the `relay` binary always uses THIS function instead.
/// Task-2 bridge-test parity is preserved via the fail-static empty-denylist
/// path: when no `denylist.json` is present, the denylist is simply empty,
/// so no client is ever rejected on that basis.
pub fn server_config_with_denylist(certdir: &Path, denylist: Denylist) -> Result<QuinnServerConfig> {
    ensure_crypto_provider();

    let relay_certs = load_certs(&certdir.join("relay.pem"))?;
    let relay_key = load_key(&certdir.join("relay.key"))?;

    let mut roots = RootCertStore::empty();
    for ca_cert in load_certs(&certdir.join("ca.pem"))? {
        roots.add(ca_cert)?;
    }
    let inner_verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
    let client_verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> =
        Arc::new(DenyingVerifier { inner: inner_verifier, denylist });

    let mut tls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(relay_certs, relay_key)?;
    tls.alpn_protocols = vec![b"wiremesh-relay/0".to_vec()];

    let quic_crypto = QuicServerConfig::try_from(tls)?;
    let mut server_config = QuinnServerConfig::with_crypto(Arc::new(quic_crypto));
    server_config.transport_config(transport_config());
    Ok(server_config)
}

/// The shared `host:port` dial-target pieces (`wiremesh-enroll`) behind
/// [`run_sync`]'s dial — re-exported here so the relay's DDNS dial contract
/// (first-IPv4-wins, no cross-family fallback, bounded lookup; pinned by
/// `tests/sync_hostname.rs`) is addressable from this crate's root, exactly
/// mirroring `wiremesh_gateway::sync::{resolve_host_port, prefer_ipv4}`.
/// `validate_host_port` is the gateway's boot-time syntax check
/// (`wiremesh_gateway::config`'s original), applied by the `relay` bin's
/// `--controller` value parser so a misconfigured target exits non-zero at
/// boot instead of the sync task logging resolution failures forever.
pub use wiremesh_enroll::{prefer_ipv4, resolve_host_port, validate_host_port};

/// HTTP/2 PING cadence on the relay's Sync channel, sent even while the
/// channel is otherwise idle (`keep_alive_while_idle`) — and the relay's
/// `Sync.Watch` stream IS the idle case: it receives nothing between
/// revocations, so without a keepalive it is completely silent on the wire.
/// A NAT/conntrack entry that times out on that silence leaves the stream
/// half-open — the FIN/RST never reaches the relay, whose blocked stream
/// read waits forever. For the relay that silence is a SECURITY failure, not
/// just staleness: the Watch stream carries `revoked_serials`, so a half-open
/// relay keeps ACCEPTING certificates revoked after the stream died, until
/// restart (the offline-persisted denylist only covers what arrived before
/// the stream went dead). Same live-found failure class — and the same
/// landed values — as the gateway's Sync channel (PR #28,
/// `docs/research/ops-finding-sync-half-open-stream.md`); with
/// [`SYNC_KEEPALIVE_TIMEOUT`] a dead link surfaces as a stream error within
/// ~25s worst case, which the `relay` bin's reconnect loop already handles
/// (re-resolving DNS via [`resolve_host_port`], so a rotated DDNS address
/// heals too). The VALUE is the canonical
/// `wiremesh_enroll::SYNC_KEEPALIVE_INTERVAL`, shared with the gateway
/// client and the controller's server-side mirror so the figures can't
/// drift apart; `pub` here because `tests/sync_keepalive.rs` pins the
/// channel construction through this crate's root.
pub const SYNC_KEEPALIVE_INTERVAL: Duration = wiremesh_enroll::SYNC_KEEPALIVE_INTERVAL;

/// How long an unanswered keepalive PING may go unacknowledged before the
/// channel is declared dead and the error is surfaced to the reconnect loop.
/// See [`SYNC_KEEPALIVE_INTERVAL`] for the half-open-stream rationale (and
/// for why the value comes from `wiremesh-enroll`).
pub const SYNC_KEEPALIVE_TIMEOUT: Duration = wiremesh_enroll::SYNC_KEEPALIVE_TIMEOUT;

/// Bound on the TCP/TLS dial itself. Without one, a dial toward a stale DDNS
/// address that blackholes (no RST) can hang the reconnect loop far longer
/// than the DNS record's own churn; a bounded dial keeps the
/// resolve-dial-retry cycle turning so the next attempt picks up the fresh
/// A record. Value shared via `wiremesh-enroll`, as above.
pub const SYNC_CONNECT_TIMEOUT: Duration = wiremesh_enroll::SYNC_CONNECT_TIMEOUT;

/// Relay Sync client (mirrors `wiremesh-gateway::sync::connect`+`watch`):
/// mTLS-dials the controller with the relay's own cert (`<certdir>/relay.pem`
/// / `.key`, root `<certdir>/ca.pem`), then folds every `revoked_serials`
/// list it receives into `denylist`, persisting to `persist_path` (0600,
/// atomic) after each update so a subsequent restart — even fully offline —
/// still enforces the last-known revocation set.
///
/// `sync_addr` is a `host:port` dial target — a DNS hostname (DDNS
/// controllers) or an IPv4 literal — resolved via [`resolve_host_port`]
/// INSIDE every call, so the `relay` bin's reconnect loop re-resolves DNS on
/// each retry and a rotated DDNS A record heals without a relay restart
/// (the gateway's per-reconnect semantics). An IPv6 literal is rejected at
/// resolution, before any dial: v1 is IPv4-only end to end.
///
/// Snapshot is a full replace (the controller's complete current set);
/// Delta is additive-only, matching
/// `wiremesh-gateway::state::DesiredState::apply_delta`'s treatment of the
/// same field. Returns (with an error) when the Watch stream ends or errors;
/// the caller (the `relay` bin) decides whether/how to retry.
pub async fn run_sync(
    sync_addr: &str,
    certdir: &Path,
    relay_id: &str,
    denylist: Denylist,
    persist_path: PathBuf,
) -> Result<()> {
    use tokio_stream::StreamExt;
    use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity as TlsIdentity};
    use wiremesh_proto::v1::sync_client::SyncClient;
    use wiremesh_proto::v1::{sync_message::Body, WatchRequest};

    // Resolution happens FIRST, inside every call — the per-dial
    // re-resolution seam (see the doc comment above), and the point where an
    // IPv6-only target fails fast instead of ever being dialed.
    let resolved = resolve_host_port(sync_addr).await?;

    let cert_pem = std::fs::read_to_string(certdir.join("relay.pem")).context("reading relay.pem")?;
    let key_pem = std::fs::read_to_string(certdir.join("relay.key")).context("reading relay.key")?;
    let ca_pem = std::fs::read_to_string(certdir.join("ca.pem")).context("reading ca.pem")?;

    let uri = format!("https://{resolved}");
    let tls = ClientTlsConfig::new()
        .identity(TlsIdentity::from_pem(&cert_pem, &key_pem))
        .ca_certificate(Certificate::from_pem(&ca_pem))
        .domain_name("127.0.0.1");
    // Keepalive/timeout mirror of `wiremesh-gateway::sync::connect`'s channel
    // (same builder order): `keep_alive_while_idle(true)` is load-bearing —
    // the Watch stream receives nothing between revocations, and without an
    // idle-time PING a silently dead link would keep this relay enforcing a
    // stale denylist (accepting revoked certs) until restart. See
    // [`SYNC_KEEPALIVE_INTERVAL`].
    let channel = Channel::from_shared(uri)
        .context("controller Sync addr must form a valid URI")?
        .tls_config(tls)
        .context("configuring relay mTLS")?
        .connect_timeout(SYNC_CONNECT_TIMEOUT)
        .http2_keep_alive_interval(SYNC_KEEPALIVE_INTERVAL)
        .keep_alive_timeout(SYNC_KEEPALIVE_TIMEOUT)
        .keep_alive_while_idle(true)
        .connect()
        .await
        .context("connecting to controller Sync (mTLS)")?;
    let mut client = SyncClient::new(channel);
    eprintln!("relay: sync[{relay_id}] connected to controller at {sync_addr} ({resolved})");

    let mut stream = client
        .watch(WatchRequest {})
        .await
        .map_err(|s| anyhow::anyhow!("Sync.Watch failed: {s}"))?
        .into_inner();

    while let Some(msg) = stream.next().await {
        let msg = msg.map_err(|s| anyhow::anyhow!("Sync stream error: {s}"))?;
        match msg.body {
            Some(Body::Snapshot(s)) => {
                let n = s.revoked_serials.len();
                denylist.replace_all(s.revoked_serials);
                if let Err(e) = denylist.persist(&persist_path) {
                    eprintln!("relay: denylist persist failed (continuing with in-memory update): {e}");
                }
                eprintln!("relay: sync[{relay_id}] snapshot: {n} revoked serial(s)");
            }
            Some(Body::Delta(d)) => {
                if !d.revoked_serials.is_empty() {
                    let n = d.revoked_serials.len();
                    denylist.union(d.revoked_serials);
                    if let Err(e) = denylist.persist(&persist_path) {
                        eprintln!("relay: denylist persist failed (continuing with in-memory update): {e}");
                    }
                    eprintln!("relay: sync[{relay_id}] delta: +{n} revoked serial(s)");
                }
            }
            _ => {}
        }
    }
    bail!("relay: sync[{relay_id}] Watch stream ended")
}

// ---------------------------------------------------------------------------
// Cycle 4c Task 3: offline certificate-revocation denylist.
//
// `Denylist` (an `Arc<RwLock<HashSet<String>>>` of lowercase-hex cert
// serials — same format as `wiremesh-trust`'s `{b:02x}`-per-byte encoding of
// a 16-byte random serial) and `server_config_with_denylist` do not exist
// yet as of this commit; a separate implementer task adds them. These tests
// are written against the shared API contract for that task (see the Task 3
// brief) and are expected to fail to COMPILE until that code lands — that is
// the intended RED state, not a mistake.
#[cfg(test)]
mod denylist_tests {
    use super::{extract_serial_hex, Denylist};
    use std::collections::HashSet;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    /// A tmp file path unique to this test process, distinguished by `tag`
    /// so tests that run concurrently in the same test binary (same PID)
    /// never collide on the same path. No `rand`/`Date` dependency
    /// available here — same PID-derived-uniqueness pattern documented in
    /// `tests/bridge.rs`'s `unique_dir`.
    fn unique_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "wiremesh-relay-denylist-unit-{tag}-{}.json",
            std::process::id()
        ))
    }

    fn set(items: &[&str]) -> HashSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn replace_all_implements_snapshot_semantics() {
        let dl = Denylist::new();
        dl.replace_all(["aa".to_string(), "bb".to_string()]);
        assert_eq!(dl.snapshot(), set(&["aa", "bb"]));

        // A second `replace_all` must fully replace the set — "aa"/"bb"
        // must be gone, not merged with "cc".
        dl.replace_all(["cc".to_string()]);
        assert_eq!(
            dl.snapshot(),
            set(&["cc"]),
            "replace_all must implement snapshot (full-replace) semantics"
        );
    }

    #[test]
    fn union_implements_delta_semantics() {
        let dl = Denylist::new();
        dl.replace_all(["aa".to_string()]);
        dl.union(["bb".to_string(), "aa".to_string()]);
        assert_eq!(
            dl.snapshot(),
            set(&["aa", "bb"]),
            "union must be additive/deduped and must never remove an existing entry"
        );
    }

    #[test]
    fn contains_reflects_current_membership() {
        let dl = Denylist::new();
        assert!(!dl.contains("aa"), "empty denylist must not contain anything");
        dl.replace_all(["aa".to_string()]);
        assert!(dl.contains("aa"));
        assert!(!dl.contains("bb"));
    }

    #[test]
    fn persist_then_load_round_trips_and_writes_mode_0600() {
        let path = unique_path("roundtrip");
        let _ = std::fs::remove_file(&path);

        let dl = Denylist::new();
        dl.replace_all(["aa".to_string(), "bb".to_string()]);
        dl.persist(&path).expect("persist must succeed");

        let meta = std::fs::metadata(&path).expect("persisted file must exist");
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o600,
            "denylist.json must be persisted with mode 0600, like wiremesh-gateway's state.json"
        );

        let loaded = Denylist::load(&path).expect("load must succeed for an existing file");
        assert_eq!(loaded.snapshot(), set(&["aa", "bb"]));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_of_missing_file_is_empty_not_an_error() {
        let path = unique_path("missing");
        let _ = std::fs::remove_file(&path);
        assert!(!path.exists(), "precondition: path must not exist");

        let dl = Denylist::load(&path)
            .expect("a MISSING denylist file must be fail-static (empty), not an Err");
        assert!(dl.snapshot().is_empty());
    }

    /// Mints a self-signed leaf cert whose serial number is pinned to the
    /// given 16 raw bytes (mirroring how `wiremesh-trust`/`mkcerts` set
    /// `rcgen::SerialNumber::from_slice` on issuance) and returns its DER
    /// encoding, i.e. exactly what `verify_client_cert` would hand
    /// `extract_serial_hex` for a live connection's end-entity cert.
    fn cert_der_with_serial(serial: &[u8; 16]) -> rustls::pki_types::CertificateDer<'static> {
        let mut params = rcgen::CertificateParams::new(vec!["serialtest".to_string()])
            .expect("building cert params");
        params.serial_number = Some(rcgen::SerialNumber::from_slice(serial));
        let key = rcgen::KeyPair::generate().expect("generating key pair");
        let cert = params.self_signed(&key).expect("self-signing cert");
        cert.der().clone()
    }

    /// Regression test for a revocation-bypass bug: `extract_serial_hex`
    /// must reconstruct the cert's ORIGINAL 16-byte serial as 32 lowercase
    /// hex chars — matching `wiremesh-trust`'s `IssuedCert.serial` — even
    /// when that serial's raw bytes begin with `0x00`. x509-parser's
    /// `raw_serial()` returns the DER INTEGER content, from which the DER
    /// writer has stripped ALL leading `0x00` bytes (re-adding at most one
    /// as a sign pad when the high bit is set). Stripping only a single
    /// leading `0x00` and hex-encoding the remainder — the current
    /// implementation — silently shortens/corrupts the hex for any serial
    /// with more than one leading zero byte, so a revoked cert with such a
    /// serial would never match the denylist.
    #[test]
    fn extract_serial_hex_reconstructs_full_16_byte_serial() {
        let cases: [[u8; 16]; 3] = [
            // Case 1 (THE bug): two leading 0x00 bytes. The DER writer
            // strips both (an all-zero-byte prefix isn't needed to keep the
            // DER INTEGER non-negative), leaving a 14-byte content field;
            // naive single-strip-and-hex yields a 28-char string that has
            // silently lost the two zero bytes wiremesh-trust's hex still
            // has.
            [
                0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44,
                0x55, 0x66,
            ],
            // Case 2: high first byte (>= 0x80) means the DER writer
            // PREPENDS one 0x00 sign-pad byte, so raw_serial() is 17 bytes
            // and exactly one leading 0x00 must be stripped to recover the
            // original 16.
            [
                0x80, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ],
            // Case 3: no leading zero byte and no sign pad needed —
            // raw_serial() is already exactly the original 16 bytes.
            [
                0x7f, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ],
        ];

        for serial in cases {
            let expected: String = serial.iter().map(|b| format!("{b:02x}")).collect();
            let der = cert_der_with_serial(&serial);
            let got = extract_serial_hex(&der).unwrap_or_else(|e| {
                panic!("extract_serial_hex failed for serial {expected}: {e}")
            });
            assert_eq!(
                got, expected,
                "extract_serial_hex must reconstruct the full original 16-byte serial \
                 (including any leading 0x00 bytes), case serial={expected}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Cycle 4c: registration-key derivation + registration framing (the shared
// wire contract the cert-binding security fix rests on).
#[cfg(test)]
mod registration_tests {
    use super::{decode_registration, encode_registration, registration_key};

    /// The registry key must be directional, distinct per (my, peer), stable,
    /// ASCII, and exactly 8 bytes — the same properties the previous
    /// `relay_pair_id` guaranteed, now keyed on identity strings.
    #[test]
    fn registration_key_is_directional_distinct_stable_and_8_bytes() {
        // Directional: A's id (A->B) must differ from B's id (B->A), or the
        // two peers' registrations would collide at the relay.
        assert_ne!(
            registration_key("gw-1", "gw-2"),
            registration_key("gw-2", "gw-1")
        );
        // Distinct per peer: one gateway's ids for two different peers must
        // never collide.
        assert_ne!(
            registration_key("gw-1", "gw-2"),
            registration_key("gw-1", "gw-3")
        );
        // Length-prefix hygiene: concatenation-ambiguous inputs must not
        // collide.
        assert_ne!(
            registration_key("gwa", "b"),
            registration_key("gw", "ab")
        );
        // Deterministic.
        assert_eq!(
            registration_key("gw-1", "gw-2"),
            registration_key("gw-1", "gw-2")
        );
        // Always 8 ASCII hex bytes.
        let k = registration_key("gw-123456789", "gw-987654321");
        assert_eq!(k.len(), 8);
        assert!(k.iter().all(|b| b.is_ascii_hexdigit()));
    }

    /// The rendezvous invariant the whole relay path depends on: the key A
    /// registers under for peer B equals the key B ADDRESSES A with.
    #[test]
    fn registration_key_rendezvous() {
        // A registers (my=gw-A, peer=gw-B) -> registration_key("gw-A","gw-B").
        // B addresses A via registration_key(peer=gw-A, my=gw-B) -- i.e. with
        // (my_for_the_key, peer_for_the_key) = ("gw-A","gw-B"). Same bytes.
        let a_registers = registration_key("gw-A", "gw-B");
        let b_addresses_a = registration_key("gw-A", "gw-B");
        assert_eq!(a_registers, b_addresses_a);
    }

    #[test]
    fn registration_framing_round_trips() {
        let (my, peer) = decode_registration(&encode_registration("gw-42", "gw-7")).unwrap();
        assert_eq!(my, "gw-42");
        assert_eq!(peer, "gw-7");
    }

    #[test]
    fn registration_decode_rejects_malformed() {
        // Too short.
        assert!(decode_registration(&[0x00]).is_err());
        // my_len overruns the buffer.
        assert!(decode_registration(&[0x00, 0xff, b'x']).is_err());
        // Empty identities.
        assert!(decode_registration(&encode_registration("", "gw-1")).is_err());
        assert!(decode_registration(&encode_registration("gw-1", "")).is_err());
    }
}
