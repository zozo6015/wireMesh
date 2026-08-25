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
//   - Datagrams sent to the relay: `[8B dest_key][payload]`. `dest_key` is
//     PINNED: the only value the relay will forward is
//     `registration_key(peer_identity, my_identity)` for the pair THIS
//     connection registered. Anything else is dropped (see `serve`).
//   - Datagrams the relay forwards to the destination: `[8B src_key][payload]`.
//
// SECURITY (Cycle 4c): the registration id used to be an opaque, self-asserted
// 8-byte value — any enrolled gateway could register under (and thereby
// intercept datagrams for, or evict) ANOTHER pair's slot. It is now bound to
// the authenticated client certificate: a gateway can only ever register a
// key whose `my_identity` half equals its own cert-embedded `gw-<id>`, and a
// slot already held by a DIFFERENT cert is never blind-overwritten. See
// `serve`, `identity_from_client_cert`, and `registration_key`.
//
// SECURITY (item 3a): that bound the RECEIVE side only — the send side still
// forwarded to any `dest` on the wire, so any enrolled gateway could inject
// into any pair's slot. `serve` now pins `dest` to the sending connection's
// own registered pair. Two related holes closed with it: the key is now 8 RAW
// digest bytes rather than 4 hex-expanded ones (a 32-bit space is
// brute-forceable to a chosen pair's slot, because `peer_identity` is NOT
// cert-bound), and a same-owner registration for a DIFFERENT pair is rejected
// instead of silently replacing the incumbent (`register_decision`).
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

/// The v1.0 relay wire protocol, negotiated via ALPN.
///
/// This is the ONE definition. It used to be four hand-copied
/// `b"wiremesh-relay/0"` literals — both server builders, the client endpoint
/// builder, and `tests/dest_pinning.rs`'s hand-rolled replica — so a protocol
/// change meant finding all four.
pub const ALPN_V0: &[u8] = b"wiremesh-relay/0";

/// Every ALPN protocol this build speaks, for BOTH the relay's accept list and
/// the client's offer list. **v1.0 has exactly one member, and that is a
/// deliberate owner ruling (2026-08-25), not an oversight.**
///
/// `wiremesh-relay/1` — the mux wire (`[8B dest_gid][2B channel]`, MTU floor
/// 1322, `docs/research/backlog-program-notes.md`) — is **neither offered nor
/// accepted**, for two reasons that are the same defect with the roles
/// reversed:
///
///   * **Accept side.** `/1`'s framing is not a defined wire: owner decisions
///     **F** (channel semantics) and **G** (the relay→gateway return header,
///     recorded *"OPEN — load-bearing"*) are both still open in
///     `docs/research/relay-mux-design-verification.md`. Accepting a protocol
///     whose framing two open decisions have not fixed would break every
///     future mux client that negotiates it.
///   * **Offer side.** A client that offers a protocol must be able to speak
///     it. A v1.0 client cannot speak `/1`, so against a *future* mux relay a
///     dual-offer would negotiate `/1` and then speak `/0` framing.
///
/// It stays a **list** with one member precisely so adding `/1` later is a
/// one-line change at this one site rather than an archaeology exercise. The
/// relay's accept path is already tolerant of a *superset* offer — a client
/// offering `["/1", "/0"]` negotiates `/0` — which is the forward-compatibility
/// property `tests/alpn.rs` pins with a TEST client (never the shipped one).
pub const ALPN_SUPPORTED: &[&[u8]] = &[ALPN_V0];

/// `ALPN_SUPPORTED` in the `Vec<Vec<u8>>` shape rustls wants.
fn alpn_protocols() -> Vec<Vec<u8>> {
    ALPN_SUPPORTED.iter().map(|p| p.to_vec()).collect()
}

/// TLS alert 120, `no_application_protocol` (RFC 8446 §6.2) — what a server
/// sends when it shares no ALPN protocol with the client.
///
/// A named `const` **on purpose**: in PATTERN position a lowercase identifier
/// is a fresh irrefutable BINDING rather than a reference to this value, so a
/// lowercase spelling would match every alert and classify every credentials
/// rejection as [`RelayConnectFailure::AlpnMismatch`] — while reading exactly
/// as intended. (The nested match in [`classify_transport_code`] means such a
/// slip also makes the following arm `unreachable_pattern`, so it fails to
/// compile under `-D warnings` too. Belt and braces: both are cheap.)
const ALERT_NO_APPLICATION_PROTOCOL: u8 = 120;

/// Why a relay connection attempt failed, in the four terms an operator can
/// act on differently.
///
/// This exists because every cause used to surface identically: one
/// `eprintln!` reading `connecting relay=… failed: …`, repeated per tick
/// forever with nothing to tell a version-skewed relay from a revoked cert,
/// a CA mismatch, or a relay that is simply down.
///
/// Attached to the returned [`anyhow::Error`] as the chain **root**
/// (`anyhow::Error::new(failure).context(…)`), so a caller recovers it with
/// `err.downcast_ref::<RelayConnectFailure>()`. Building it the other way
/// round — `Err(quinn_err).context(…)` with the classification computed
/// separately — would leave the quinn error as the root and the downcast
/// would return `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayConnectFailure {
    /// No shared ALPN protocol: the relay speaks a protocol set disjoint from
    /// this build's [`ALPN_SUPPORTED`]. In practice a version skew.
    AlpnMismatch,
    /// The relay rejected our credentials during the TLS handshake, carrying
    /// the TLS alert it sent: revoked (44), unknown CA (48), access denied
    /// (49), bad certificate (42), certificate required (116), ...
    ///
    /// Match the VARIANT, not the payload — which alert arrives depends on the
    /// cause and on the rustls version.
    PeerRejectedCredentials(u8),
    /// Nothing answered: timeout, reset, or no mutually supported QUIC
    /// version. The relay is down, unreachable, or behind a black hole.
    Unreachable,
    /// Anything else. Reachable and NOT a dead end: the relay's own
    /// application-level registration rejections (identity mismatch,
    /// registration id in use, id collision) close the connection AFTER a
    /// successful TLS handshake, so they land here rather than in any of the
    /// three named variants. The underlying error is preserved in the
    /// `anyhow` context chain — which is why the caller must log `{err:#}`
    /// and not `{err}`, or this becomes an empty bucket.
    Other,
}

impl std::fmt::Display for RelayConnectFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlpnMismatch => {
                f.write_str("relay rejected our ALPN offer (no shared application protocol)")
            }
            Self::PeerRejectedCredentials(alert) => {
                write!(f, "relay rejected our credentials (TLS alert {alert})")
            }
            Self::Unreachable => f.write_str("relay unreachable (no response before timeout)"),
            Self::Other => f.write_str(
                "relay connect failed for an unclassified reason \
                 (see the preceding context for the underlying error)",
            ),
        }
    }
}

impl std::error::Error for RelayConnectFailure {}

/// Classifies a QUIC transport error code. Pure — no I/O, no connection
/// state — so it is directly unit-testable with bare codes.
fn classify_transport_code(code: quinn::TransportErrorCode) -> RelayConnectFailure {
    let raw = u64::from(code);
    match raw {
        // The CRYPTO_ERROR range and the ALPN alert OVERLAP: a TLS alert `n`
        // is encoded as `0x100 | n`, so `crypto(120)` == 0x178 sits INSIDE
        // 0x100..0x200. The two are nested rather than written as sequential
        // sibling arms so that no reordering can silently reclassify an ALPN
        // mismatch as a credentials rejection — there are no sibling arms to
        // reorder, and the inner match is over disjoint `u8` values the
        // compiler checks for reachability.
        r if (0x100..0x200).contains(&r) => match (r & 0xFF) as u8 {
            ALERT_NO_APPLICATION_PROTOCOL => RelayConnectFailure::AlpnMismatch,
            alert => RelayConnectFailure::PeerRejectedCredentials(alert),
        },
        _ => RelayConnectFailure::Other,
    }
}

/// Classifies a connection-level error. Thin wrapper over
/// [`classify_transport_code`] — everything that needs deciding lives there.
fn classify_connection_error(err: &quinn::ConnectionError) -> RelayConnectFailure {
    match err {
        quinn::ConnectionError::ConnectionClosed(close) => {
            classify_transport_code(close.error_code)
        }
        quinn::ConnectionError::TimedOut
        | quinn::ConnectionError::Reset
        | quinn::ConnectionError::VersionMismatch => RelayConnectFailure::Unreachable,
        // `ApplicationClosed` lands here on purpose: the relay's own
        // registration rejections are application closes AFTER a successful
        // handshake. See `RelayConnectFailure::Other`.
        _ => RelayConnectFailure::Other,
    }
}

/// Reads the ALPN protocol negotiated on an established connection off the
/// completed TLS handshake. Used by both sides — the client records it on
/// [`Client`], the relay logs and counts it per session.
///
/// `handshake_data()` is `Some` on an established connection and downcasts to
/// rustls' [`quinn::crypto::rustls::HandshakeData`], whose `protocol` is
/// documented as set whenever a nonempty ALPN list was configured. Both sides
/// always configure [`ALPN_SUPPORTED`], so this is `Some` in practice; it
/// still returns `Option` rather than unwrapping.
fn negotiated_alpn(conn: &Connection) -> Option<Vec<u8>> {
    conn.handshake_data()?
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .ok()?
        .protocol
}

/// Renders a negotiated ALPN for a log line, or `unknown` if none was
/// negotiated. Quoted like the `owner=`/`peer=` tokens beside it.
fn alpn_label(alpn: Option<&[u8]>) -> String {
    match alpn {
        Some(p) => format!("{:?}", String::from_utf8_lossy(p)),
        None => "unknown".to_string(),
    }
}

/// Per-ALPN cumulative session counter for one [`serve`] loop.
///
/// This is decision **H**'s deprecation-horizon anchor
/// (`docs/research/relay-mux-design-verification.md`): `/0` cannot be retired
/// until the fleet can show zero `/0` sessions, and that measurement has to
/// exist in the shipped 1.0 relay or it cannot start until 1.1.
///
/// A counter plus a log line, deliberately **not** a metrics endpoint — the
/// relay has no metrics surface at all, and building one is a separate item
/// (S4). Recorded counter-argument: a per-relay count is necessary but not
/// fleet-complete, because `relay_next_idx` round-robins, so a pair that only
/// ever uses R1 is invisible to R2.
///
/// Counts **accepted registrations** — the increment sits at the registration
/// log line, so a connection rejected for a bad cert, an identity mismatch or
/// a key collision never reaches it. Re-registrations (`ReplaceOwnSlot`) do
/// count, so this is "sessions", not "unique peers". Never decremented.
#[derive(Clone, Default)]
struct AlpnSessionCounts(Arc<std::sync::Mutex<std::collections::HashMap<Vec<u8>, u64>>>);

impl AlpnSessionCounts {
    /// Records one accepted session for `alpn` and returns the new cumulative
    /// count for that protocol.
    fn record(&self, alpn: Option<&[u8]>) -> u64 {
        let key = alpn.unwrap_or(b"unknown").to_vec();
        let mut map = self.0.lock().expect("alpn session counter poisoned");
        let n = map.entry(key).or_insert(0);
        *n += 1;
        *n
    }
}

/// Builds the error for a failed [`Client::finish_connect`] step: `failure`
/// becomes the chain ROOT (so `downcast_ref::<RelayConnectFailure>()`
/// resolves) and the raw error's `Display` is embedded in the context (so
/// even an unclassified `Other` still shows the operator what happened).
fn connect_step_error(
    failure: RelayConnectFailure,
    step: &'static str,
    raw: impl std::fmt::Display,
) -> anyhow::Error {
    anyhow::Error::new(failure).context(format!("{step}: {raw}"))
}

/// Minimum spacing between repeated log lines of ONE kind from ONE connection
/// in `serve`'s datagram loop (see [`DatagramDropLog`]). Every event is
/// counted, but at most one line per kind per connection per interval is
/// emitted, and it carries the running count.
///
/// This is a hard requirement, not tidiness: every branch in that loop runs
/// once per received datagram, and an attacker holding any valid gateway cert
/// controls how fast datagrams arrive. An unbounded `eprintln!` on any of
/// those branches lets it amplify a few bytes of work into unbounded stderr
/// I/O on the relay — a cheaper DoS than the one dest-pinning closes.
const DATAGRAM_LOG_INTERVAL: Duration = Duration::from_secs(10);

/// Per-connection, per-branch rate limiter for `serve`'s datagram loop.
///
/// Deliberately ONE INSTANCE PER BRANCH rather than one shared limiter for
/// the whole loop. A shared limiter is simpler, but the branches have
/// different audiences and one can drown out another: a cross-pair injector
/// sending at line rate would hold the shared token permanently and suppress
/// the `unknown dest` line — which is exactly the line an operator greps for
/// during the [`registration_key`] lockstep upgrade, when a version-skewed
/// pair's only symptom is that it never rendezvouses. Each kind is therefore
/// guaranteed to surface within one interval no matter how loud the others
/// are; three counters and three `Instant`s per connection is nothing.
struct DatagramDropLog {
    /// Total events of this kind on this connection, including suppressed
    /// ones — reported in every emitted line so a suppressed burst is still
    /// visible as a number.
    count: u64,
    last_logged: Option<std::time::Instant>,
}

impl DatagramDropLog {
    fn new() -> DatagramDropLog {
        DatagramDropLog {
            count: 0,
            last_logged: None,
        }
    }

    /// Records one event. Returns `Some(total_so_far)` when a line is due
    /// (first event, or [`DATAGRAM_LOG_INTERVAL`] since the last emitted
    /// one), `None` when it must be suppressed. Counting happens either way.
    fn record(&mut self) -> Option<u64> {
        self.count += 1;
        let now = std::time::Instant::now();
        let due = match self.last_logged {
            None => true,
            Some(t) => now.duration_since(t) >= DATAGRAM_LOG_INTERVAL,
        };
        if due {
            self.last_logged = Some(now);
            Some(self.count)
        } else {
            None
        }
    }
}

pub mod enroll;

/// Deterministic 8-byte relay-registry id for the ordered
/// `(my_identity, peer_identity)` pair. This is the ONE derivation shared by
/// both sides: the relay keys its registry with `registration_key(my, peer)`
/// (my taken from the authenticated cert), and the addressing peer targets a
/// datagram at `registration_key(peer, my)` — i.e. the id the OTHER side
/// registered under — so the two ends rendezvous.
///
/// The identity strings are length-prefixed before hashing so that
/// `("gwa","b")` and `("gw","ab")` can never collide by concatenation.
///
/// # Width: the first 8 RAW digest bytes (item 3a)
///
/// This used to take only the first **4** digest bytes and hex-expand them
/// into the 8 header bytes — 8 ASCII characters carrying **32 bits**. The
/// header width never changed; the entropy in it was simply thrown away. Two
/// consequences, one of which is a security bug:
///
///   * *Accidental* collisions were a probabilistic, self-healing
///     mutual-exclusion fault between two pairs registered on the SAME relay
///     process at the same time (~0.07% at v1's ≤50-segment scale) — plus a
///     silent same-owner variant, see [`register_decision`]. That is the part
///     the old comment here called "collision-safe at v1's ≤50-segment
///     scale", and for accidents at that scale it was true.
///   * *Adversarial* collisions were cheap, and the scale argument says
///     nothing about them. `peer_identity` is NOT cert-bound (only
///     `my_identity` is — see `serve`), so the holder of ANY valid gateway
///     cert can pick peer strings freely and brute-force a P with
///     `registration_key("gw-C", P) == registration_key("gw-A", "gw-B")`. At
///     32 bits that is a ~4.3e9-single-block-SHA-256 target preimage —
///     minutes on a laptop — after which gw-C occupies gw-A's slot: gw-A's
///     own registration is rejected for as long as gw-C holds it, and gw-B's
///     datagrams for that slot are delivered to gw-C. WireGuard's E2E
///     encryption still holds, so it is targeted DoS plus interception of a
///     chosen pair's relay leg, not a confidentiality break. At 64 bits the
///     same preimage search is ~1.8e19 hashes.
///
/// **This is a LOCKSTEP change.** The relay recomputes the key itself from
/// the authenticated cert (`serve`) and each gateway computes its own dest in
/// [`Client::finish_connect`]; all three must agree byte-for-byte or a pair
/// silently never rendezvouses (`unknown dest` on the relay, nothing at all
/// on the gateway). A relay and a gateway on different sides of this change
/// cannot bridge. Nothing else on the wire moves — same 8-byte header, same
/// framing, same MTU — so the upgrade is coordinated but not staged.
pub fn registration_key(my_identity: &str, peer_identity: &str) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update((my_identity.len() as u64).to_be_bytes());
    hasher.update(my_identity.as_bytes());
    hasher.update(peer_identity.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

/// Renders a registration key for a log line. The key used to be 8 ASCII hex
/// characters, so the logs printed it with `String::from_utf8_lossy`; it is
/// now 8 RAW digest bytes, which lossy-decode to replacement-character
/// mojibake. Hex-encode explicitly so operator-facing lines (and the
/// `unknown dest` / cross-pair-drop diagnostics an operator greps for) stay
/// readable and greppable.
fn key_hex(key: &[u8; 8]) -> String {
    const HEX: [u8; 16] = *b"0123456789abcdef";
    let mut s = String::with_capacity(16);
    for b in key {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

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
        bail!(
            "registration payload truncated: my_len={my_len}, have {} bytes",
            buf.len() - 2
        );
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
    tls.alpn_protocols = alpn_protocols();

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
    tls.alpn_protocols = alpn_protocols();

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
    /// The ALPN protocol actually negotiated, read back off the handshake.
    /// See [`Client::negotiated_alpn`].
    negotiated_alpn: Option<Vec<u8>>,
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
        // Every fallible step below is classified on its RAW error, before
        // `.context()` erases the type. This is deliberate and it is not
        // over-engineering: the rejection does NOT reliably surface at the
        // handshake step. `tests/bridge.rs`'s module header records, from a
        // live run, that a certless client's `endpoint.connect(...).await`
        // returns **Ok** — the server's rejection is a CONNECTION_CLOSE that
        // lands later, and the failure actually manifests at the ack read
        // ("...the cryptographic handshake failed: error 116: peer sent no
        // certificates"). Classifying only at the connect step would file
        // every credentials rejection under `Other`.
        //
        // Steps 1 and 5 map to `Other` explicitly rather than by fallthrough:
        // `ConnectError` is entirely local/config (`EndpointStopping`,
        // `InvalidServerName`, ...) and `ClosedStream` is a unit struct, so
        // neither can carry a peer-attributable cause. That is a property of
        // those types, not an omission here.
        let conn = endpoint
            // Step 1: `ConnectError` — local/config only, never a peer cause.
            .connect(relay_addr, RELAY_SERVER_NAME)
            .map_err(|e| connect_step_error(RelayConnectFailure::Other, "QUIC connect", e))?
            .await
            // Step 2: `ConnectionError` — where an ALPN mismatch lands.
            .map_err(|e| {
                connect_step_error(classify_connection_error(&e), "QUIC handshake failed", e)
            })?;

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
        // Step 3: `ConnectionError`.
        let (mut send, mut recv) = conn.open_bi().await.map_err(|e| {
            connect_step_error(classify_connection_error(&e), "open registration stream", e)
        })?;
        // Step 4: `WriteError` — one unwrap to reach the connection cause.
        send.write_all(&encode_registration(my_identity, peer_identity))
            .await
            .map_err(|e| {
                let failure = match &e {
                    quinn::WriteError::ConnectionLost(ce) => classify_connection_error(ce),
                    _ => RelayConnectFailure::Other,
                };
                connect_step_error(failure, "write registration", e)
            })?;
        // Step 5: `ClosedStream` — a unit struct; carries no peer cause.
        send.finish().map_err(|e| {
            connect_step_error(RelayConnectFailure::Other, "finish registration stream", e)
        })?;
        // Step 6: `ReadToEndError` — TWO unwraps to reach the connection
        // cause, and the step where a credentials rejection actually lands
        // (see the note above `endpoint.connect`).
        recv.read_to_end(1).await.map_err(|e| {
            let failure = match &e {
                quinn::ReadToEndError::Read(quinn::ReadError::ConnectionLost(ce)) => {
                    classify_connection_error(ce)
                }
                _ => RelayConnectFailure::Other,
            };
            connect_step_error(failure, "await registration ack", e)
        })?;

        // Guaranteed `Some` whenever a nonempty ALPN list was configured, and
        // `build_client_endpoint` always configures `ALPN_SUPPORTED` — but
        // read defensively rather than unwrapping.
        let negotiated_alpn = negotiated_alpn(&conn);

        Ok(Client {
            conn,
            dest_key: registration_key(peer_identity, my_identity),
            negotiated_alpn,
        })
    }

    /// The ALPN protocol this connection negotiated, as read back off the
    /// completed TLS handshake — not what we offered. `None` only if the peer
    /// negotiated no protocol at all.
    pub fn negotiated_alpn(&self) -> Option<&[u8]> {
        self.negotiated_alpn.as_deref()
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

/// One registry slot: the live connection plus the (owner, peer) pair that
/// occupies it. `owner` is the cert-bound identity — it is what makes
/// duplicate registrations safe, since a second registration for the same key
/// may only REPLACE the slot when it comes from the SAME cert identity.
///
/// `peer` is recorded for exactly one reason: without it the relay cannot
/// tell a same-owner RECONNECT (same pair, must replace) from a same-owner
/// KEY COLLISION (a different pair that hashed onto this slot, must be
/// rejected — replacing it would silently cross-wire two of one gateway's
/// legs, because the receiving gateway discards the forwarded src header).
/// See [`register_decision`], which is the whole rule as a pure function.
#[derive(Clone)]
struct RegEntry {
    conn: Connection,
    owner: String,
    peer: String,
}

/// What [`register_decision`] says to do with an incoming registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterDecision {
    /// The slot is free. Insert.
    Accept,
    /// Same owner, same peer: an honest reconnect after a stale/half-open
    /// connection taking its own slot back. Insert over the incumbent.
    /// (`remove_if_owner` is what stops the stale connection's later teardown
    /// from evicting this replacement.)
    ReplaceOwnSlot,
    /// The slot is held by a DIFFERENT cert identity. Reject — this is the
    /// eviction/redirection attempt `tests/impersonation.rs` pins.
    RejectOwnedByOther,
    /// Same owner, DIFFERENT peer: two of this gateway's own pairs hashed
    /// onto one slot. Reject rather than replace.
    RejectKeyCollision,
}

/// The relay's duplicate-registration rule, extracted as a pure function so
/// the full 2x2 (same/different owner × same/different peer) is decidable and
/// testable without a real key collision and without a relay process — the
/// repo's `mint_action` / `relay_identity_persisted` pattern.
///
/// `existing` is the incumbent slot's `(owner, peer)`, or `None` if the key is
/// free. `cert_identity` is the CERT-bound identity of the registering
/// connection (never the self-asserted one); `peer_identity` is the peer half
/// it registered.
///
/// Ownership is checked FIRST and unconditionally: a different owner is
/// rejected whatever the peer half says, because the peer half is
/// attacker-chosen (it is not cert-bound) and must never be able to upgrade a
/// rejection into a replace.
///
/// The `RejectKeyCollision` arm is the one that used to fall through to a
/// silent `reg.insert`: the old check compared only `existing.owner`, so a
/// same-owner different-pair collision replaced the incumbent with no log and
/// no error, and the first pair's datagrams then landed on the second pair's
/// local socket (the gateway's downlink drops the src header, so boringtun
/// roams the endpoint onto the wrong leg). With the widened
/// [`registration_key`] that arm should now be unreachable in practice; it is
/// kept — and fails CLOSED — because "should be unreachable" is not a
/// guarantee, and a silent cross-wire is a far worse outcome than a rejected
/// registration the gateway retries.
pub fn register_decision(
    existing: Option<(&str, &str)>,
    cert_identity: &str,
    peer_identity: &str,
) -> RegisterDecision {
    match existing {
        None => RegisterDecision::Accept,
        Some((owner, _)) if owner != cert_identity => RegisterDecision::RejectOwnedByOther,
        Some((_, peer)) if peer == peer_identity => RegisterDecision::ReplaceOwnSlot,
        Some(_) => RegisterDecision::RejectKeyCollision,
    }
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
            if name
                .strip_prefix("gw-")
                .is_some_and(|rest| !rest.is_empty())
            {
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
async fn read_registration(conn: &Connection) -> Result<(quinn::SendStream, String, String)> {
    let (send, mut recv) = conn
        .accept_bi()
        .await
        .context("accept registration stream")?;
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
    send.write_all(&[1])
        .await
        .context("write registration ack")?;
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
    // Cumulative per-ALPN session counts for THIS serve loop. The relay
    // binary calls `serve` exactly once, so for it this is per-process; two
    // embedded relays in one test process get independent counters.
    let alpn_counts = AlpnSessionCounts::default();

    while let Some(incoming) = endpoint.accept().await {
        let registry = registry.clone();
        let alpn_counts = alpn_counts.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(conn) => conn,
                Err(e) => {
                    // Mandatory client-cert handshake failures land here —
                    // e.g. a certless client (Client::connect_no_cert). An
                    // ALPN mismatch also fails here, before any session
                    // exists to count.
                    eprintln!("relay: handshake failed: {e}");
                    return;
                }
            };

            // Read back what THIS session negotiated, off the completed
            // handshake — not what we advertised.
            let session_alpn = negotiated_alpn(&conn);

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
            // (that was the eviction/redirection DoS), and never silently
            // replace a same-owner slot that belongs to a DIFFERENT pair (that
            // was the silent cross-wire). The whole rule is
            // `register_decision`; this block only executes it.
            {
                let mut reg = registry.lock().await;
                let decision = register_decision(
                    reg.get(&key).map(|e| (e.owner.as_str(), e.peer.as_str())),
                    &cert_identity,
                    &peer_identity,
                );
                match decision {
                    RegisterDecision::RejectOwnedByOther => {
                        let owner = reg.get(&key).map(|e| e.owner.clone()).unwrap_or_default();
                        eprintln!(
                            "relay: rejecting registration for key {}: already held by {:?}, \
                             refusing overwrite by {:?}",
                            key_hex(&key),
                            owner,
                            cert_identity
                        );
                        drop(reg);
                        conn.close(3u32.into(), b"registration id in use");
                        return;
                    }
                    RegisterDecision::RejectKeyCollision => {
                        let held_peer = reg.get(&key).map(|e| e.peer.clone()).unwrap_or_default();
                        eprintln!(
                            "relay: rejecting registration for key {}: {:?} already holds this \
                             slot for peer {:?}, refusing to replace it with a DIFFERENT pair \
                             (peer {:?}) — this is a registration-key COLLISION, not a reconnect",
                            key_hex(&key),
                            cert_identity,
                            held_peer,
                            peer_identity
                        );
                        drop(reg);
                        conn.close(4u32.into(), b"registration id collision");
                        return;
                    }
                    RegisterDecision::Accept | RegisterDecision::ReplaceOwnSlot => {}
                }
                // Insert *before* acking: the client blocks on the ack before
                // it does anything else, so this ordering guarantees a
                // subsequent datagram from a peer can already find this entry.
                reg.insert(
                    key,
                    RegEntry {
                        conn: conn.clone(),
                        owner: cert_identity.clone(),
                        peer: peer_identity.clone(),
                    },
                );
            }

            if let Err(e) = ack_registration(ack_stream).await {
                eprintln!("relay: registration ack failed: {e}");
                remove_if_owner(&registry, &key, &conn).await;
                return;
            }
            eprintln!(
                "relay: registered key={} owner={cert_identity:?} peer={peer_identity:?} \
                 from {} alpn={} alpn_sessions={}",
                key_hex(&key),
                conn.remote_address(),
                alpn_label(session_alpn.as_deref()),
                alpn_counts.record(session_alpn.as_deref())
            );

            // SECURITY (item 3a): the ONE destination this connection is
            // allowed to address. Registration binds the RECEIVE side to the
            // client certificate (`my_identity == cert_identity` above), but
            // until now the SEND side was unbound: `serve` forwarded to
            // whatever `dest` was on the wire, so any enrolled, non-revoked
            // gateway could enumerate the trivially-guessable `gw-<rowid>`
            // identities, compute another pair's key and inject into its relay
            // slot. WireGuard E2E means that is a routing/DoS problem rather
            // than a confidentiality one, but it was live on every deployed
            // fabric.
            //
            // This connection registered the pair (my_identity,
            // peer_identity), so the only slot it has any business addressing
            // is its peer's half — byte-for-byte what `Client::finish_connect`
            // computes as its own `dest_key`. Computed once, outside the loop:
            // the per-datagram cost is an 8-byte compare.
            let allowed_dest = registration_key(&peer_identity, &my_identity);

            // Rate-limiting state, one limiter per log-emitting branch of the
            // loop below. EVERY branch there is per-datagram and therefore
            // attacker-paced, so none of them may log unconditionally — see
            // [`DatagramDropLog`] for why the limiters are per-branch and not
            // shared. (`unknown dest` is reachable by the same actor that
            // dest-pinning stops: register `(gw-C, P)` for a peer `P` that
            // never connects, then flood your OWN legal dest — the pin passes
            // and the registry lookup misses on every datagram.)
            let mut runt_log = DatagramDropLog::new();
            let mut cross_pair_log = DatagramDropLog::new();
            let mut unknown_dest_log = DatagramDropLog::new();
            let mut forward_failed_log = DatagramDropLog::new();

            loop {
                let dgram = match conn.read_datagram().await {
                    Ok(dgram) => dgram,
                    Err(e) => {
                        eprintln!("relay: connection for key {} closed: {e}", key_hex(&key));
                        break;
                    }
                };
                if dgram.len() < 8 {
                    // A datagram too short to even carry the dest header.
                    // This was the loop's one SILENT drop — no amplification
                    // risk (it logged nothing at all), but no diagnostic
                    // either. Counted and bounded like the rest so the loop
                    // has exactly one shape: every drop is counted, every log
                    // is rate-limited.
                    if let Some(n) = runt_log.record() {
                        eprintln!(
                            "relay: dropping runt datagram ({} bytes, need >= 8 for the dest \
                             header) from {:?} on key {} ({n} so far on this connection)",
                            dgram.len(),
                            cert_identity,
                            key_hex(&key)
                        );
                    }
                    continue;
                }
                let mut dest = [0u8; 8];
                dest.copy_from_slice(&dgram[..8]);

                if dest != allowed_dest {
                    // DROP, do not close. Closing the offender's connection is
                    // tempting (it is fail-closed, and it cannot hurt the
                    // victim — whose slot and connection must both survive)
                    // but it is the worse choice on both axes:
                    //   * Against an attacker it buys nothing. The injector
                    //     holds a valid cert, so it just reconnects — and a
                    //     QUIC handshake plus registration costs the RELAY far
                    //     more than the 8-byte compare that dropped the
                    //     datagram, so close-on-violation is an amplification
                    //     the attacker would choose deliberately.
                    //   * Against a bug it is actively harmful. A gateway
                    //     whose key derivation diverges from ours (the lockstep
                    //     upgrade on `registration_key`, or a future wire
                    //     revision) addresses a dest we compute differently;
                    //     dropping leaves that as a static, greppable "this
                    //     pair never rendezvouses" failure, whereas closing
                    //     turns it into a reconnect storm across the fleet.
                    // The log below is the alerting seam: sustained cross-pair
                    // dests from one connection is the signature of the
                    // injection attempt, not of a misconfiguration.
                    if let Some(n) = cross_pair_log.record() {
                        eprintln!(
                            "relay: DROPPING datagram from {:?} (key {}) addressed to {} — \
                             outside its own registered pair (peer {:?}, only legal dest {}); \
                             {n} violation(s) on this connection so far",
                            cert_identity,
                            key_hex(&key),
                            key_hex(&dest),
                            peer_identity,
                            key_hex(&allowed_dest)
                        );
                    }
                    continue;
                }

                let peer = registry.lock().await.get(&dest).map(|e| e.conn.clone());
                if let Some(peer) = peer {
                    let mut fwd = Vec::with_capacity(dgram.len());
                    fwd.extend_from_slice(&key); // src key header
                    fwd.extend_from_slice(&dgram[8..]);
                    if let Err(e) = peer.send_datagram(fwd.into()) {
                        // Forwarding failure is per-datagram too, and it is
                        // not necessarily rare: a peer whose datagram queue is
                        // full or whose connection is closing errors on every
                        // send until it drains or dies.
                        if let Some(n) = forward_failed_log.record() {
                            eprintln!(
                                "relay: forward to {} failed: {e} ({n} failure(s) on this \
                                 connection so far)",
                                key_hex(&dest)
                            );
                        }
                    }
                } else {
                    // The peer half of this pair is not (or no longer)
                    // registered. Benign and expected while the far side is
                    // still connecting or has just left the relay — and it is
                    // THE line to grep for during a `registration_key`
                    // lockstep upgrade, which is why this limiter is its own
                    // and cannot be starved by a noisy cross-pair injector.
                    if let Some(n) = unknown_dest_log.record() {
                        eprintln!(
                            "relay: unknown dest {} ({n} datagram(s) undeliverable on this \
                             connection so far)",
                            key_hex(&dest)
                        );
                    }
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
    let endpoint =
        Endpoint::server(cfg, bind).with_context(|| format!("binding relay endpoint on {bind}"))?;
    let local_addr = endpoint
        .local_addr()
        .context("reading bound relay endpoint address")?;
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
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .context("self-signing CA cert")?;
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
        params
            .distinguished_name
            .push(DnType::CommonName, name.as_str());
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
        Denylist {
            inner: Arc::new(RwLock::new(HashSet::new())),
        }
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
    let content: &[u8] = if raw.len() == 17 && raw[0] == 0x00 {
        &raw[1..]
    } else {
        raw
    };
    if content.len() > 16 {
        anyhow::bail!(
            "cert serial DER content longer than 16 bytes: {}",
            content.len()
        );
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
        let verified = self
            .inner
            .verify_client_cert(end_entity, intermediates, now)?;

        let serial_hex = extract_serial_hex(end_entity).map_err(|e| {
            rustls::Error::General(format!("denylist: could not read client cert serial: {e}"))
        })?;
        if self.denylist.contains(&serial_hex) {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::Revoked,
            ));
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
pub fn server_config_with_denylist(
    certdir: &Path,
    denylist: Denylist,
) -> Result<QuinnServerConfig> {
    ensure_crypto_provider();

    let relay_certs = load_certs(&certdir.join("relay.pem"))?;
    let relay_key = load_key(&certdir.join("relay.key"))?;

    let mut roots = RootCertStore::empty();
    for ca_cert in load_certs(&certdir.join("ca.pem"))? {
        roots.add(ca_cert)?;
    }
    let inner_verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
    let client_verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> =
        Arc::new(DenyingVerifier {
            inner: inner_verifier,
            denylist,
        });

    let mut tls = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(relay_certs, relay_key)?;
    tls.alpn_protocols = alpn_protocols();

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

    let cert_pem =
        std::fs::read_to_string(certdir.join("relay.pem")).context("reading relay.pem")?;
    let key_pem =
        std::fs::read_to_string(certdir.join("relay.key")).context("reading relay.key")?;
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

    // `session_generation: 0` deliberately. The Sync session-generation
    // scheme exists to reject a delayed pre-restart `Sync.Report` that would
    // otherwise restore stale per-gateway state (peer paths, local
    // candidates, relay health) over the fresh state a reconnect just
    // cleared. A relay NEVER calls `Sync.Report` — its Watch is
    // revocation-scoped only (`SyncSvc::watch_relay`), it registers nothing
    // in the broker, and there is no relay-side state a stale report could
    // corrupt. Relays are therefore outside the scheme, and `watch_relay`
    // ignores this field entirely (only `watch_gateway` records it). 0 is the
    // wire's legacy/unknown sentinel — see `sync.proto`.
    let mut stream = client
        .watch(WatchRequest {
            session_generation: 0,
        })
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
                    eprintln!(
                        "relay: denylist persist failed (continuing with in-memory update): {e}"
                    );
                }
                eprintln!("relay: sync[{relay_id}] snapshot: {n} revoked serial(s)");
            }
            Some(Body::Delta(d)) if !d.revoked_serials.is_empty() => {
                let n = d.revoked_serials.len();
                denylist.union(d.revoked_serials);
                if let Err(e) = denylist.persist(&persist_path) {
                    eprintln!(
                        "relay: denylist persist failed (continuing with in-memory update): {e}"
                    );
                }
                eprintln!("relay: sync[{relay_id}] delta: +{n} revoked serial(s)");
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
        assert!(
            !dl.contains("aa"),
            "empty denylist must not contain anything"
        );
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
            let got = extract_serial_hex(&der)
                .unwrap_or_else(|e| panic!("extract_serial_hex failed for serial {expected}: {e}"));
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
        assert_ne!(registration_key("gwa", "b"), registration_key("gw", "ab"));
        // Deterministic.
        assert_eq!(
            registration_key("gw-1", "gw-2"),
            registration_key("gw-1", "gw-2")
        );
        // Always 8 bytes wide. This assertion used to also require every byte
        // to be an ASCII hex digit — a characterisation of the 4-byte digest
        // prefix hex-expanded into the header, i.e. of the 32-bit width bug
        // item 3a removes. The header is now the first 8 RAW digest bytes, so
        // "all ASCII hex" is exactly what must NO LONGER hold; the replacement
        // property (no byte position confined to a 16-value alphabet, and no
        // collision findable in a 400k budget) is pinned in
        // `tests/pair_id_width.rs`.
        let k = registration_key("gw-123456789", "gw-987654321");
        assert_eq!(k.len(), 8);
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

/// [`DatagramDropLog`] — the per-connection, per-branch rate limiter every
/// branch of `serve`'s datagram loop logs through.
///
/// This is a DoS mitigation, not tidiness: each branch runs once per received
/// datagram and an attacker holding any valid gateway cert controls the
/// arrival rate, so an unbounded `eprintln!` on any of them amplifies a few
/// bytes of work into unbounded stderr I/O. If the limiting silently stops
/// working the only symptom is an operator's disk — which is exactly the kind
/// of regression that needs a test rather than a review.
///
/// `dest_pinning.rs` exercises only the cross-pair branch; the runt,
/// `unknown dest` and forward-failure branches have no behavioural coverage,
/// and none of them can observe the *limiting* itself from outside the
/// process anyway. Hence unit tests, in-crate because the type is private.
///
/// # How the interval boundary is reached without sleeping
///
/// `record` reads `Instant::now()` internally, so the elapse boundary is not
/// reachable through the public behaviour of the type in under
/// [`DATAGRAM_LOG_INTERVAL`] (10s). It IS reachable from in-crate tests by
/// backdating the private `last_logged` stamp, which is what
/// [`set_last_logged_ago`] does — no sleeping, no injectable clock, and no
/// change to the type. The cost is that these tests are coupled to the
/// field's representation: a future rewrite of `DatagramDropLog`'s internals
/// must update `set_last_logged_ago` with them. That is a deliberate trade —
/// the alternative was leaving the whole re-arm contract unpinned.
///
/// The one hairline this cannot resolve is `>=` versus `>` at exactly the
/// interval: real time advances between backdating and the `Instant::now()`
/// inside `record`, so the elapsed span is always a few nanos PAST the
/// interval. Distinguishing those two would need a frozen clock, and the
/// difference is not operationally meaningful.
#[cfg(test)]
mod datagram_drop_log_tests {
    use super::{DatagramDropLog, DATAGRAM_LOG_INTERVAL};
    use std::time::{Duration, Instant};

    /// Rewinds a limiter's last-emitted stamp to `ago` in the past, so the
    /// next `record()` sees that much time as having elapsed.
    fn set_last_logged_ago(log: &mut DatagramDropLog, ago: Duration) {
        let t = Instant::now().checked_sub(ago).expect(
            "cannot rewind the monotonic clock by the test interval — the clock origin is \
             less than the interval in the past (a machine/container booted seconds ago). \
             This is a test-environment limitation, not a failure of the limiter.",
        );
        log.last_logged = Some(t);
    }

    #[test]
    fn the_first_event_on_a_fresh_limiter_always_emits() {
        // The worst possible failure mode is a SILENT first drop: the
        // diagnostic never appears at all and the operator has no signal that
        // anything is being dropped. A fresh limiter must always let the
        // first event through.
        let mut log = DatagramDropLog::new();
        assert_eq!(
            log.record(),
            Some(1),
            "the first event on a fresh limiter must emit, carrying a total of 1"
        );
    }

    #[test]
    fn subsequent_events_within_the_interval_are_suppressed() {
        let mut log = DatagramDropLog::new();
        assert_eq!(log.record(), Some(1), "first event emits");
        for i in 2..=1000u64 {
            assert_eq!(
                log.record(),
                None,
                "event {i} arrived within the interval and must be suppressed — this is the \
                 whole DoS mitigation; emitting here means per-datagram logging is unbounded"
            );
        }
    }

    #[test]
    fn suppressed_events_are_still_counted_and_surface_in_the_next_emitted_line() {
        // Counting ALWAYS happens, even when the line is suppressed, so an
        // eventually-emitted line reports every event rather than only the
        // logged ones — a suppressed burst stays visible as a number.
        let mut log = DatagramDropLog::new();
        assert_eq!(log.record(), Some(1));
        for _ in 0..499 {
            assert_eq!(log.record(), None);
        }

        set_last_logged_ago(&mut log, DATAGRAM_LOG_INTERVAL);
        assert_eq!(
            log.record(),
            Some(501),
            "the next emitted line must carry the total of ALL 501 events, not just the 2 that \
             were logged — otherwise a suppressed burst is invisible"
        );
    }

    #[test]
    fn a_line_becomes_due_again_once_the_interval_has_elapsed() {
        let mut log = DatagramDropLog::new();
        assert_eq!(log.record(), Some(1));
        assert_eq!(log.record(), None, "still inside the interval");

        set_last_logged_ago(&mut log, DATAGRAM_LOG_INTERVAL);
        assert_eq!(
            log.record(),
            Some(3),
            "once the interval has elapsed the next event must emit again — a limiter that \
             latches shut after its first line loses the diagnostic entirely"
        );

        // And emitting must RE-ARM the limiter: if the emit path failed to
        // refresh `last_logged`, every subsequent event would emit forever
        // after, which is the unbounded-logging DoS the type exists to stop.
        assert_eq!(
            log.record(),
            None,
            "emitting must reset the interval, not leave the limiter permanently open"
        );
    }

    #[test]
    fn an_event_well_inside_the_interval_stays_suppressed() {
        // Brackets the boundary from below: half an interval is not enough.
        let mut log = DatagramDropLog::new();
        assert_eq!(log.record(), Some(1));
        set_last_logged_ago(&mut log, DATAGRAM_LOG_INTERVAL / 2);
        assert_eq!(
            log.record(),
            None,
            "half the interval has elapsed — the line is not due yet"
        );
    }

    #[test]
    fn the_running_total_is_cumulative_across_emitted_lines() {
        // The count is the connection's lifetime total for this branch, not a
        // per-interval tally: it must never reset when a line is emitted.
        let mut log = DatagramDropLog::new();
        assert_eq!(log.record(), Some(1));
        set_last_logged_ago(&mut log, DATAGRAM_LOG_INTERVAL);
        assert_eq!(log.record(), Some(2));
        set_last_logged_ago(&mut log, DATAGRAM_LOG_INTERVAL);
        assert_eq!(
            log.record(),
            Some(3),
            "the total must accumulate over the connection's life, not restart each interval"
        );
    }

    #[test]
    fn each_limiter_is_independent_so_a_loud_branch_cannot_silence_a_quiet_one() {
        // The stated reason there are FOUR limiters in `serve` rather than
        // one: a cross-pair injector sending at line rate would hold a shared
        // token permanently and suppress the `unknown dest` line — the exact
        // line an operator greps for during a `registration_key` lockstep
        // upgrade, when a version-skewed pair's only symptom is that it never
        // rendezvouses. Each kind must surface within one interval no matter
        // how loud the others are.
        let mut loud = DatagramDropLog::new();
        let mut quiet = DatagramDropLog::new();

        assert_eq!(loud.record(), Some(1));
        for _ in 0..10_000 {
            let _ = loud.record();
        }

        assert_eq!(
            quiet.record(),
            Some(1),
            "a quiet branch's FIRST event must emit even after another branch has recorded \
             10,000 — the limiters must not share state"
        );

        // Their totals are independent too.
        set_last_logged_ago(&mut loud, DATAGRAM_LOG_INTERVAL);
        set_last_logged_ago(&mut quiet, DATAGRAM_LOG_INTERVAL);
        assert_eq!(
            loud.record(),
            Some(10_002),
            "loud branch's own running total"
        );
        assert_eq!(quiet.record(), Some(2), "quiet branch's own running total");
    }

    #[test]
    fn the_log_interval_is_the_documented_ten_seconds() {
        // Deliberately a restatement of the constant. It exists because the
        // interval is a production tuning value that a later test-author
        // might be tempted to shorten in order to test the elapse boundary by
        // sleeping. Backdating (see this module's doc comment) is how that
        // boundary is reached instead; this assertion makes the shortcut fail
        // loudly if anyone takes it.
        assert_eq!(DATAGRAM_LOG_INTERVAL, Duration::from_secs(10));
    }
}

// ---------------------------------------------------------------------------
// D2: connect-failure classification. The mapping from a QUIC transport error
// code to the operator-facing reason.
#[cfg(test)]
mod classifier_tests {
    use super::{classify_connection_error, classify_transport_code, RelayConnectFailure};

    /// The transport code a peer's CONNECTION_CLOSE carries for TLS alert
    /// `alert`. A one-liner, named so the two cases below read as "alert 120"
    /// and "alert 116" rather than as quinn plumbing.
    fn alert(code: u8) -> quinn::TransportErrorCode {
        quinn::TransportErrorCode::crypto(code)
    }

    /// TLS alert 120 (`no_application_protocol`) is the ALPN mismatch, and the
    /// ONLY alert that is.
    #[test]
    fn alert_120_classifies_as_an_alpn_mismatch() {
        assert_eq!(
            classify_transport_code(alert(120)),
            RelayConnectFailure::AlpnMismatch,
            "TLS alert 120 is `no_application_protocol` — the wire signal for \"no protocol \
             in common\". It is what makes a version-skewed relay distinguishable from a \
             revoked cert, a CA mismatch or a dead one, and §11 B' requires that \
             distinction"
        );
    }

    /// THE HAZARD THIS FILE EXISTS FOR — and it is a Rust footgun, not a
    /// logic slip.
    ///
    /// If `ALERT_NO_APPLICATION_PROTOCOL` ever stops being a `const` and
    /// becomes a plain binding — renamed to lowercase, moved into a `let`,
    /// shadowed by a function parameter — then `match code { ALERT_... => }`
    /// silently changes meaning. It stops being a comparison against 120 and
    /// becomes an IRREFUTABLE BINDING that matches every value, so **every**
    /// connect failure classifies as `AlpnMismatch`. The code still compiles,
    /// the 120 test above still passes, and the classification silently
    /// becomes a constant function.
    ///
    /// That is why this case is not redundant with the one above: 116 is the
    /// probe that can tell a comparison from a binding, and only a non-120
    /// input can.
    #[test]
    fn a_non_alpn_alert_does_not_classify_as_an_alpn_mismatch() {
        let classified = classify_transport_code(alert(116));
        assert_eq!(
            classified,
            RelayConnectFailure::PeerRejectedCredentials(116),
            "TLS alert 116 (`certificate_required` — \"peer sent no certificates\", the alert \
             `tests/bridge.rs` records for a certless client) must classify as \
             `PeerRejectedCredentials(116)`, carrying the code through. Getting \
             `AlpnMismatch` here is the const-pattern hazard: if \
             `ALERT_NO_APPLICATION_PROTOCOL` degraded from a `const` to a binding, the match \
             arm became irrefutable and EVERY alert now classifies as an ALPN mismatch — the \
             120 case would still be green and every operator-facing reason would be a lie. \
             Classified as {classified:?}"
        );
    }

    /// The WRAPPER's own dispatch — the third case, and the only one that
    /// exercises a `ConnectionError` variant carrying no transport code at
    /// all.
    ///
    /// `TimedOut` never reaches `classify_transport_code`, so neither case
    /// above can say anything about it. It guards a different degradation from
    /// the const-pattern hazard: a wrapper that funnelled every variant through
    /// a single "extract a code, or fall back" path would classify a silent
    /// network as whatever that fallback is — and if the fallback were
    /// `Other`, an operator chasing a dead relay would be told the failure is
    /// unclassified rather than told it is unreachable.
    ///
    /// This matters more than it looks: `main.rs::ensure_relay_transport`'s
    /// error arm retries indefinitely with no backoff, so "the relay is
    /// unreachable" is precisely the case an operator most needs named.
    #[test]
    fn a_timeout_classifies_as_unreachable() {
        let classified = classify_connection_error(&quinn::ConnectionError::TimedOut);
        assert_eq!(
            classified,
            RelayConnectFailure::Unreachable,
            "a QUIC handshake that times out means nothing answered — the relay is down, \
             filtered, or the address is wrong. It must classify as `Unreachable`, not as \
             `Other` and certainly not as `AlpnMismatch`. This is the one case that reaches \
             the wrapper's own dispatch rather than the code→variant table, so it is the \
             only guard against a wrapper that funnels every variant through a single \
             extract-a-code path. Classified as {classified:?}"
        );
    }
}
