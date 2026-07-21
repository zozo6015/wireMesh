// relay client lib + TLS plumbing shared with the `relay` server binary.
//
// Wire format:
//   - Registration: each client's first (and only) bidirectional stream
//     carries its 8-byte, NUL-padded id; the relay replies with a 1-byte
//     ack once the id is in its registry.
//   - Datagrams sent to the relay: `[8B dest_id][payload]`.
//   - Datagrams the relay forwards to the destination: `[8B src_id][payload]`.
use anyhow::{bail, Context, Result};
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

/// A connected, authenticated relay client. Cheap to clone: `quinn::Connection`
/// is itself an internally-refcounted handle, so `Client` just wraps one.
#[derive(Clone)]
pub struct Client {
    conn: Connection,
}

impl Client {
    /// Connect to the relay with mutual TLS: root = ca.pem, client cert =
    /// `gw-<my_id>.pem/key`. Registers `my_id` with the relay over the
    /// connection's first bidirectional stream (and waits for the relay's
    /// registration ack) before returning.
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
        my_id: &str,
    ) -> Result<Client> {
        let endpoint = client_endpoint_from_pems(cert_pem, key_pem, ca_pem)?;
        Self::finish_connect(endpoint, relay_addr, my_id).await
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

    /// Whether the underlying QUIC connection is still open (no
    /// `CONNECTION_CLOSE` sent or received yet). The minimal liveness signal:
    /// a closed connection can never again forward datagrams, so `false`
    /// here means this `Client` is dead and must be replaced, not just
    /// degraded.
    pub fn is_alive(&self) -> bool {
        self.conn.close_reason().is_none()
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

/// The relay's accept -> handshake -> register -> datagram-forward loop,
/// graduated verbatim (Cycle 4c Task 7) from `src/bin/relay.rs`'s `main` so
/// it can be driven either by the standalone `relay` binary or embedded
/// in-process (see [`spawn_server`], used by the gateway's loopback relay
/// tests and any future in-process relay embedding). Runs until
/// `endpoint.accept()` returns `None` (the endpoint was closed) — it never
/// returns otherwise.
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

            let (ack_stream, id) = match read_registration_id(&conn).await {
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
            if let Err(e) = ack_registration(ack_stream).await {
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
/// `x509-parser`'s `raw_serial()` returns the DER INTEGER content bytes,
/// which per the DER positive-integer encoding rule get a leading `0x00`
/// prepended whenever the serial's high bit is set (otherwise the value
/// would be misread as negative). `rcgen::SerialNumber::from_slice` is given
/// the original 16 raw bytes and does not itself add that padding — it is
/// `rcgen`'s DER writer, applying the same encoding rule, that introduces
/// the extra leading byte on the wire for exactly the serials whose first
/// byte is >= 0x80. `wiremesh-trust`'s `IssuedCert.serial` is the hex of the
/// original 16 bytes, with no such padding. So a single leading `0x00`, and
/// ONLY a single leading `0x00`, must be stripped here before hex-encoding —
/// otherwise every serial with a high first bit (roughly half of all random
/// serials) would silently fail to match the denylist.
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

/// Relay Sync client (mirrors `wiremesh-gateway::sync::connect`+`watch`):
/// mTLS-dials the controller with the relay's own cert (`<certdir>/relay.pem`
/// / `.key`, root `<certdir>/ca.pem`), then folds every `revoked_serials`
/// list it receives into `denylist`, persisting to `persist_path` (0600,
/// atomic) after each update so a subsequent restart — even fully offline —
/// still enforces the last-known revocation set.
///
/// Snapshot is a full replace (the controller's complete current set);
/// Delta is additive-only, matching
/// `wiremesh-gateway::state::DesiredState::apply_delta`'s treatment of the
/// same field. Returns (with an error) when the Watch stream ends or errors;
/// the caller (the `relay` bin) decides whether/how to retry.
pub async fn run_sync(
    sync_addr: SocketAddr,
    certdir: &Path,
    relay_id: &str,
    denylist: Denylist,
    persist_path: PathBuf,
) -> Result<()> {
    use tokio_stream::StreamExt;
    use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity as TlsIdentity};
    use wiremesh_proto::v1::sync_client::SyncClient;
    use wiremesh_proto::v1::{sync_message::Body, WatchRequest};

    let cert_pem = std::fs::read_to_string(certdir.join("relay.pem")).context("reading relay.pem")?;
    let key_pem = std::fs::read_to_string(certdir.join("relay.key")).context("reading relay.key")?;
    let ca_pem = std::fs::read_to_string(certdir.join("ca.pem")).context("reading ca.pem")?;

    let uri = format!("https://{sync_addr}");
    let tls = ClientTlsConfig::new()
        .identity(TlsIdentity::from_pem(&cert_pem, &key_pem))
        .ca_certificate(Certificate::from_pem(&ca_pem))
        .domain_name("127.0.0.1");
    let channel = Channel::from_shared(uri)
        .context("controller Sync addr must form a valid URI")?
        .tls_config(tls)
        .context("configuring relay mTLS")?
        .connect()
        .await
        .context("connecting to controller Sync (mTLS)")?;
    let mut client = SyncClient::new(channel);
    eprintln!("relay: sync[{relay_id}] connected to controller at {sync_addr}");

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
