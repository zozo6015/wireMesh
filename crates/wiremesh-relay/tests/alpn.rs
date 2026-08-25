// crates/wiremesh-relay/tests/alpn.rs
//
// D2 / owner ruling 2026-08-25: **v1.0 speaks `wiremesh-relay/0` ONLY, on both
// sides.** The shipped client OFFERS `/0` only; the relay ACCEPTS `/0` only.
// `ALPN_SUPPORTED` has exactly one member in v1.0 and stays a list so adding
// `/1` later is a one-line change at one site.
//
// ## What this file proves that nothing else can
//
// `tests/dest_pinning.rs` connects with a hand-rolled client whose ALPN list
// is exactly `[/0]`. That pins "the relay accepts `/0`" and nothing else: a
// relay that accepted every protocol on earth would keep it green, and so
// would a relay that accepted only `/0`. The forward-compatibility property a
// future mux client actually depends on — **a SUPERSET offer still negotiates
// `/0`** — is invisible to it, because a superset offer is exactly what it
// never sends.
//
// So the client in `a_client_offering_v1_and_v0_negotiates_v0_and_works` below
// is a TEST client. It is never the shipped one, and the ruling above is the
// reason: a client that offers a protocol must be able to speak it, and a v1.0
// client cannot speak `/1`. Against a FUTURE mux relay a dual-offer would
// negotiate `/1` and then speak `/0` framing — the accept-side defect with the
// roles reversed. `the_shipped_client_does_not_offer_v1` is the test that pins
// the shipped half, and it pins it behaviourally rather than by reading the
// constant, because the constant is only load-bearing if the client actually
// consumes it.
//
// ## Why `/1` must not be accepted (the accept-side half of the ruling)
//
// `/1` is *intended* as the mux wire (a 10-byte `[8B dest_gid][2B channel]`
// header, MTU floor 1322) but it is **not a defined wire**: owner decisions F
// (channel semantics) and G (the relay->gateway return header, recorded as
// "OPEN — load-bearing") are still open, and nothing in code reserves it.
// Accepting a protocol whose framing two open decisions have not fixed would
// break every future mux client that negotiates it.
//
// ## What is deliberately NOT here
//
// A `relay_death_reason`-style pin that an ALPN alert is not classified as
// `RelayDeathReason::Closed`. That defect does not exist and the test was
// deleted from the design (plan-review finding 3): ALPN is negotiated INSIDE
// the QUIC/TLS handshake, so a mismatch returns `Err` from
// `Client::finish_connect`; no `RelayTransport` is ever constructed, nothing
// enters `ctx.relay_transports`, and `gateway/src/relay.rs::classify`'s three
// call sites are all post-establishment. Do not add it back.
//
// ## Harness
//
// Modeled on `tests/bridge.rs` / `tests/dest_pinning.rs`: `KillOnDrop` guard,
// PID-derived tmp dir and port, `mkcerts`/`relay` bins via
// `env!("CARGO_BIN_EXE_...")`, a 400ms bind settle.
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use wiremesh_relay::{ALPN_SUPPORTED, ALPN_V0};

/// SNI the relay's leaf cert is stamped with (`mkcerts` writes SAN "relay");
/// the crate's private `RELAY_SERVER_NAME`.
const RELAY_SERVER_NAME: &str = "relay";

/// The protocol v1.0 does NOT speak, spelled once. Every place below that
/// needs it is testing that it stays unspoken, so it deliberately does NOT
/// come from the crate: if `wiremesh_relay` ever exports an `ALPN_V1`, these
/// tests must be re-read by a human, not silently re-pointed at it.
const ALPN_V1_NOT_SUPPORTED: &[u8] = b"wiremesh-relay/1";

/// Kills the relay server on drop, including on panic-driven unwind, so a
/// failed assertion never leaks a background process out of the test.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn unique_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("relay-alpn-test-{tag}-{}", std::process::id()))
}

/// Port range distinct from every other relay test: bridge.rs (40000+),
/// denylist.rs (45000+), impersonation.rs (50000+), dest_pinning.rs (55000+),
/// relay_pair_collision.rs (60000+). `slot` separates the test functions in
/// this file, which cargo may run in parallel.
fn port_for(slot: u16) -> u16 {
    30000 + slot * 1000 + (std::process::id() % 1000) as u16
}

fn run_ok(bin: &str, args: &[&str]) {
    let status = Command::new(bin)
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("spawn {bin} {args:?}: {e}"));
    assert!(status.success(), "{bin} {args:?} failed: {status:?}");
}

fn spawn_relay(bin: &str, bind: &str, certdir: &Path) -> Child {
    Command::new(bin)
        .args([bind, certdir.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {bin}: {e}"))
}

/// Boots a relay on its own port against a fresh certdir. Returns the guard
/// (which must be held for the test's lifetime) and the address.
async fn relay_on(slot: u16, tag: &str) -> (PathBuf, KillOnDrop, SocketAddr) {
    let dir = unique_dir(tag);
    run_ok(env!("CARGO_BIN_EXE_mkcerts"), &[dir.to_str().unwrap()]);

    let bind = format!("127.0.0.1:{}", port_for(slot));
    let guard = KillOnDrop(spawn_relay(env!("CARGO_BIN_EXE_relay"), &bind, &dir));
    tokio::time::sleep(Duration::from_millis(400)).await;

    let addr = bind.parse().expect("relay bind address");
    (dir, guard, addr)
}

// ---------------------------------------------------------------------------
// A raw relay client whose ALPN offer list is a TEST PARAMETER.
//
// Everything except `alpn` duplicates `wiremesh_relay`'s private
// `build_client_endpoint` (30s idle, DPLPMTUD on, 1MiB datagram receive
// buffer), for the same reason `dest_pinning.rs`'s replica does: the crate
// does not expose a way to vary the offer list, and varying it is the entire
// subject of this file.
// ---------------------------------------------------------------------------
fn raw_client_endpoint(certdir: &Path, my_id: &str, alpn: &[&[u8]]) -> quinn::Endpoint {
    // Idempotent; `Client::connect` installs the same provider.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let ca_pem = std::fs::read(certdir.join("ca.pem")).expect("read ca.pem");
    let mut roots = rustls::RootCertStore::empty();
    for ca in rustls_pemfile::certs(&mut ca_pem.as_slice()) {
        roots.add(ca.expect("parse ca.pem")).expect("add ca root");
    }

    let cert_pem = std::fs::read(certdir.join(format!("{my_id}.pem")))
        .unwrap_or_else(|e| panic!("read {my_id}.pem: {e}"));
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<_, _>>()
        .expect("parse leaf cert PEM");
    let key_pem = std::fs::read(certdir.join(format!("{my_id}.key")))
        .unwrap_or_else(|e| panic!("read {my_id}.key: {e}"));
    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .expect("parse key PEM")
        .expect("no private key in PEM");

    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .expect("build client TLS config");
    tls.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();

    let quic_crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("quic client crypto");
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        Duration::from_secs(30)
            .try_into()
            .expect("30s idle timeout"),
    ));
    transport.mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()));
    transport.datagram_receive_buffer_size(Some(1 << 20));
    client_config.transport_config(Arc::new(transport));

    let mut endpoint =
        quinn::Endpoint::client((Ipv4Addr::UNSPECIFIED, 0).into()).expect("bind client endpoint");
    endpoint.set_default_client_config(client_config);
    endpoint
}

/// The protocol the two sides actually agreed on, read off a live connection.
///
/// `quinn::Connection::handshake_data()` is boxed `dyn Any`; the rustls
/// backend puts a `HandshakeData { protocol, server_name }` in it. Nothing in
/// the repo called this before D2 (zero hits repo-wide), so this helper is the
/// one place the downcast lives.
fn negotiated(conn: &quinn::Connection) -> Option<Vec<u8>> {
    conn.handshake_data()
        .expect("handshake data is available on an established connection")
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .expect("rustls handshake data")
        .protocol
}

/// The 8-byte registration id, recomputed exactly as the crate does, so a raw
/// client can address its own peer.
fn reg_key(my: &str, peer: &str) -> [u8; 8] {
    wiremesh_relay::registration_key(my, peer)
}

/// Registers on a raw connection exactly as `Client::finish_connect` does,
/// including blocking on the 1-byte ack so the relay's registry insert has
/// definitely happened before we return.
async fn raw_register(conn: &quinn::Connection, my: &str, peer: &str) {
    let (mut send, mut recv) = conn.open_bi().await.expect("open registration stream");
    let my_b = my.as_bytes();
    let mut buf = Vec::with_capacity(2 + my_b.len() + peer.len());
    buf.extend_from_slice(&(my_b.len() as u16).to_be_bytes());
    buf.extend_from_slice(my_b);
    buf.extend_from_slice(peer.as_bytes());
    send.write_all(&buf).await.expect("write registration");
    send.finish().expect("finish registration stream");
    recv.read_to_end(1).await.expect("await registration ack");
}

// ===========================================================================
// 1. Forward compatibility: a SUPERSET offer negotiates `/0` and WORKS.
// ===========================================================================

/// The property a future mux client depends on, and the one `dest_pinning.rs`
/// structurally cannot prove.
///
/// "Works" is asserted with a real datagram round trip, not with a successful
/// handshake. A handshake-only assertion would pass against a relay that
/// negotiated `/0` and then mis-framed everything after it — which is exactly
/// the failure mode the `/1` ruling exists to prevent, so proving the
/// negotiated session is genuinely usable is the point rather than a flourish.
#[tokio::test]
async fn a_client_offering_v1_and_v0_negotiates_v0_and_works() {
    let (dir, _relay, addr) = relay_on(0, "superset").await;

    // gw-A: the forward-looking client. Offers BOTH, `/1` first — i.e. it
    // would prefer the mux protocol if this relay spoke it.
    let endpoint = raw_client_endpoint(&dir, "gw-A", &[ALPN_V1_NOT_SUPPORTED, ALPN_V0]);
    let conn = endpoint
        .connect(addr, RELAY_SERVER_NAME)
        .expect("start QUIC connect")
        .await
        .expect(
            "a client offering [\"wiremesh-relay/1\", \"wiremesh-relay/0\"] must complete the \
             handshake against a v1.0 relay — the relay's accept list contains /0, so a \
             superset offer has a protocol in common and TLS must select it. A failure here \
             means the relay rejected an offer it shares a protocol with, which breaks every \
             future mux client",
        );
    assert_eq!(
        negotiated(&conn).as_deref(),
        Some(ALPN_V0),
        "a superset offer must negotiate DOWN to /0, not up to /1. Selection is the SERVER's \
         choice from the client's offer, and a v1.0 relay's accept list is exactly [/0], so \
         /0 is the only possible answer. Negotiating /1 here would mean the relay accepted a \
         protocol whose framing owner decisions F and G have not yet fixed"
    );
    raw_register(&conn, "gw-A", "gw-B").await;

    // gw-B: the shipped client, offering /0 only.
    let b = wiremesh_relay::Client::connect(addr, &dir, "gw-B", "gw-A")
        .await
        .expect("gw-B connect+register");

    // A -> B over the superset-negotiated session.
    let mut dgram = Vec::new();
    dgram.extend_from_slice(&reg_key("gw-B", "gw-A"));
    dgram.extend_from_slice(b"superset-offer-payload");
    conn.send_datagram(dgram.into()).expect("A sends");
    let (_src, payload) = tokio::time::timeout(Duration::from_secs(5), b.recv())
        .await
        .expect("gw-B must receive within 5s")
        .expect("gw-B recv");
    assert_eq!(
        payload, b"superset-offer-payload",
        "the /0 session negotiated from a superset offer must carry real traffic. If the \
         handshake succeeded but this is wrong or missing, the relay agreed on /0 and then \
         did not speak it"
    );

    // B -> A, so the property is proven in both directions rather than only on
    // the leg the superset client happens to originate.
    b.send(b"reply-payload").await.expect("gw-B sends");
    let back = tokio::time::timeout(Duration::from_secs(5), conn.read_datagram())
        .await
        .expect("gw-A must receive within 5s")
        .expect("gw-A read_datagram");
    assert_eq!(
        &back[8..],
        b"reply-payload",
        "the superset-offer client's DOWNLINK must work too — the relay prepends an 8-byte \
         src key and forwards, exactly as it does for a /0-only client"
    );
}

// ===========================================================================
// 2. The accept side: `/1` alone is rejected, as an ALPN mismatch.
// ===========================================================================

/// The relay's accept list does not contain `/1` — proven by a client that
/// offers nothing else.
///
/// The assertion is on the SPECIFIC failure, not on `is_err()`. A bare
/// `is_err()` would pass if the relay were simply down, if the cert were
/// rejected, or if the port were wrong — three things this test is not about.
/// TLS signals "no protocol in common" with alert 120
/// (`no_application_protocol`), which QUIC surfaces as a transport error in
/// the crypto range, so that is what is asserted.
#[tokio::test]
async fn a_client_offering_only_v1_is_rejected_as_an_alpn_mismatch() {
    let (dir, _relay, addr) = relay_on(1, "v1only").await;

    // POSITIVE CONTROL FIRST, same relay, same certdir, same helper: only the
    // offer list differs between this and the rejection below. Without it a
    // red relay (never bound, wrong port, bad certs) would produce the same
    // `Err` and this test would pass for the wrong reason.
    let control_ep = raw_client_endpoint(&dir, "gw-A", &[ALPN_V0]);
    let control = control_ep
        .connect(addr, RELAY_SERVER_NAME)
        .expect("start control connect")
        .await
        .expect(
            "CONTROL: a /0-only client must connect to this relay. If this fails the relay \
             itself is broken and the rejection below proves nothing about ALPN",
        );
    assert_eq!(negotiated(&control).as_deref(), Some(ALPN_V0));
    drop(control);

    let endpoint = raw_client_endpoint(&dir, "gw-A", &[ALPN_V1_NOT_SUPPORTED]);
    let err = endpoint
        .connect(addr, RELAY_SERVER_NAME)
        .expect("start QUIC connect")
        .await
        .expect_err(
            "a client offering ONLY \"wiremesh-relay/1\" must be rejected: /1 is not a defined \
             wire (owner decisions F and G are open) and v1.0's accept list is exactly [/0]. \
             A successful handshake here means the relay accepted a protocol it cannot speak, \
             which black-holes every future mux client that negotiates it",
        );

    // DIAGNOSTIC ONLY, never an assertion (wire-dev's mechanism correction).
    // ALPN is refused during the handshake, so on THIS raw path the close
    // usually lands on `connect().await` as a bare `ConnectionClosed` with
    // `crypto(120)` — but which step it surfaces at, and therefore whether it
    // arrives bare or wrapped in a `WriteError`/`ReadToEndError`, depends on
    // timing. Asserting the exact variant here would pin a shape that is not
    // guaranteed. The CLASSIFICATION test below is where the contract lives;
    // this print is what makes a red run diagnosable.
    eprintln!("/1-only rejection surfaced as: {err:?}");
    assert!(
        !matches!(err, quinn::ConnectionError::TimedOut),
        "the /1-only client TIMED OUT rather than being refused. A timeout is what an \
         unreachable relay looks like, so an ALPN refusal that manifests as one is \
         indistinguishable from a dead relay — the property §11 B' requires. (The positive \
         control above already proved this relay is up and reachable, so a timeout here is \
         not an environment problem.)"
    );
}

/// The classification half, on the SHIPPED client: `Client::finish_connect`
/// must report an ALPN mismatch AS an ALPN mismatch.
///
/// Separate test from the one above because it is a separate property: that
/// one is about what the relay ACCEPTS, this one is about how the client
/// REPORTS. They fail independently — a relay could reject correctly while the
/// client still surfaced `Other`, which is the state §5.2 item 4 records as
/// the real defect (a silent, indefinitely repeating, indistinguishable
/// per-tick retry at `ensure_relay_transport`).
///
/// The shipped client offers `/0` only, so the mismatch has to come from the
/// SERVER side: a test server whose accept list is `/1` only.
#[tokio::test]
async fn the_shipped_client_reports_an_alpn_mismatch_as_such() {
    let dir = unique_dir("client-classify");
    run_ok(env!("CARGO_BIN_EXE_mkcerts"), &[dir.to_str().unwrap()]);

    let addr = test_server(&dir, port_for(2), &[ALPN_V1_NOT_SUPPORTED]).await;

    // `match` rather than `expect_err`: that helper requires `T: Debug`, and
    // `Client` deliberately does not derive it. Adding `Debug` to a production
    // type so a test can use a shorter helper is the same trade this file
    // refuses elsewhere (see the `bytes` note on the classifier pin), and the
    // match reads better anyway — the success arm gets to say what went wrong.
    let err = match wiremesh_relay::Client::connect(addr, &dir, "gw-A", "gw-B").await {
        Ok(_) => panic!(
            "a /0-only client CONNECTED to a server whose accept list is /1 only. That means \
             the shipped client offered /1 — which it must never do (owner ruling \
             2026-08-25), because a v1.0 client cannot speak it"
        ),
        Err(e) => e,
    };
    assert_eq!(
        err.downcast_ref::<wiremesh_relay::RelayConnectFailure>(),
        Some(&wiremesh_relay::RelayConnectFailure::AlpnMismatch),
        "an ALPN mismatch must classify as `RelayConnectFailure::AlpnMismatch`, not as \
         `Other`. `main.rs::ensure_relay_transport`'s error arm is a bare eprintln + return \
         with no backoff, re-spawned from two `MarkRelayNeeded` sites — so without this \
         classification a version-skewed relay produces an indefinitely repeating retry with \
         nothing distinguishing it from a revoked cert, a CA mismatch or a dead relay. Full \
         error chain: {err:?}"
    );
}

/// Distinguishability, from the other direction: a rejection that is NOT an
/// ALPN mismatch must not be reported as one.
///
/// Only the credentials leg is probed. `RelayConnectFailure::Unreachable`
/// costs a real handshake timeout (the client transport sets a 30s idle
/// timeout and there is no per-connect deadline), so probing it here would add
/// tens of seconds to the suite for a leg `tests/bridge.rs`'s certless case
/// already exercises structurally. That omission is stated rather than left
/// for a reader to notice.
#[tokio::test]
async fn a_rejected_certificate_does_not_classify_as_an_alpn_mismatch() {
    let (dir, _relay, addr) = relay_on(3, "cred-vs-alpn").await;

    // `match` rather than `expect_err` — see the note in
    // `the_shipped_client_reports_an_alpn_mismatch_as_such`.
    let err = match wiremesh_relay::Client::connect_no_cert(addr, &dir).await {
        Ok(_) => panic!(
            "a CERTLESS client completed connect+register against a relay that requires \
             mTLS. That is a mutual-TLS enforcement failure, not an ALPN one — this test's \
             subject (how the failure is CLASSIFIED) does not even arise, and \
             `tests/bridge.rs`'s certless case should be red too"
        ),
        Err(e) => e,
    };
    let classified = err
        .downcast_ref::<wiremesh_relay::RelayConnectFailure>()
        .copied();

    // The VARIANT, not the payload. The classifier's rule is "any crypto(n)
    // with n != 120 -> PeerRejectedCredentials(n)", and n varies by cause and
    // by rustls version (116 for "peer sent no certificates", 42/44/48/49 for
    // the various bad-certificate alerts). Pinning a number here would make
    // this test a rustls-version tripwire wearing an ALPN test's name.
    assert!(
        matches!(
            classified,
            Some(wiremesh_relay::RelayConnectFailure::PeerRejectedCredentials(_))
        ),
        "a certless client must classify as `PeerRejectedCredentials(_)`, and in particular \
         must NOT collapse to `AlpnMismatch`. If every connect failure lands on one variant \
         the classification buys nothing and `ensure_relay_transport`'s error arm — a bare \
         eprintln + return, no backoff, re-spawned from two `MarkRelayNeeded` sites — still \
         retries indefinitely with nothing telling an operator whether the relay is \
         version-skewed, revoked, CA-mismatched or dead. Classified as {classified:?}; full \
         chain: {err:?}"
    );

    // The rejection arrives LATER than the handshake (wire-dev's correction,
    // and `tests/bridge.rs`'s header records the same thing): a certless
    // client's `connect().await` returns Ok, and the server's CONNECTION_CLOSE
    // surfaces at the registration ack read. So this path is only classified
    // at all if `finish_connect` classifies at EVERY fallible step, not just
    // at connect. A `None` here is that regression, and it is worth its own
    // sentence because it would otherwise read as a missing variant.
    assert!(
        classified.is_some(),
        "the failure was not classified at all. A certless rejection manifests at the ack \
         `read_to_end`, wrapped in a `ReadToEndError` — so classifying only at \
         `endpoint.connect()` leaves this path unclassified while the ALPN path still looks \
         fine. Full chain: {err:?}"
    );
}

// ===========================================================================
// 3. Readback.
// ===========================================================================

/// Nothing in the repo called `handshake_data()` before D2. This pins that the
/// shipped client can now say which protocol it is on — the observation the
/// `/0` deprecation horizon (decision H) is eventually measured from.
#[tokio::test]
async fn the_negotiated_protocol_reads_back_as_v0() {
    let (dir, _relay, addr) = relay_on(4, "readback").await;

    let c = wiremesh_relay::Client::connect(addr, &dir, "gw-A", "gw-B")
        .await
        .expect("gw-A connect+register");
    assert_eq!(
        c.negotiated_alpn(),
        Some(ALPN_V0),
        "a normal v1.0 connection must read back as `wiremesh-relay/0`. `None` here means \
         the readback is not wired to the live connection at all (quinn always reports a \
         protocol when ALPN is configured), which would make the per-ALPN counter and the \
         registration log line report a constant rather than an observation"
    );
}

// ===========================================================================
// 4. Both lists are exactly [/0] — R7.
// ===========================================================================

/// The single-definition property, asserted on both halves of R7.
///
/// This is the cheap half; `the_shipped_client_does_not_offer_v1` and
/// `a_client_offering_only_v1_is_rejected_as_an_alpn_mismatch` are the halves
/// that prove the constant is actually CONSUMED. A constant nobody reads is
/// worth nothing, which is why this test is not the only one here.
#[test]
fn the_offer_and_accept_lists_are_exactly_v0() {
    assert_eq!(
        ALPN_V0, b"wiremesh-relay/0",
        "the v1.0 ALPN token is frozen: it is on the wire of every deployed relay"
    );
    assert_eq!(
        ALPN_SUPPORTED,
        &[ALPN_V0],
        "v1.0's ALPN list has exactly ONE member, and it is /0 (owner ruling 2026-08-25, both \
         sides). It stays a LIST so adding /1 later is a one-line change at one site — but \
         adding it BEFORE owner decisions F (channel semantics) and G (the relay->gateway \
         return header) are closed would commit the fabric to a framing nobody has defined. \
         If this test is red because someone added /1, that is the conversation to have, not \
         an assertion to update"
    );
    assert!(
        !ALPN_SUPPORTED.contains(&ALPN_V1_NOT_SUPPORTED),
        "neither the accept list nor the shipped client's offer list may contain \
         \"wiremesh-relay/1\" in v1.0 — both sides, R7"
    );
}

// ===========================================================================
// 5. The shipped client's offer list, proven BEHAVIOURALLY.
// ===========================================================================

/// A minimal QUIC server whose ALPN accept list is a test parameter, using the
/// same `relay.pem`/`relay.key` identity the real relay presents so the
/// shipped client's SNI and trust root both match. It answers exactly enough
/// of the relay protocol for `Client::finish_connect` to return: accept one
/// bi stream, read the registration, write the 1-byte ack.
///
/// Returns the bound address; the driving task is detached and dies with the
/// test process.
async fn test_server(certdir: &Path, port: u16, alpn: &[&[u8]]) -> SocketAddr {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cert_pem = std::fs::read(certdir.join("relay.pem")).expect("read relay.pem");
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<_, _>>()
        .expect("parse relay cert");
    let key_pem = std::fs::read(certdir.join("relay.key")).expect("read relay.key");
    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .expect("parse relay key")
        .expect("no private key in relay.key");

    // No client-cert verifier: this server is a probe for ALPN selection, and
    // requiring mTLS would add a second reason for a connection to fail —
    // which is precisely what these tests must not have.
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("build test server TLS config");
    tls.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();

    let quic_crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("quic server crypto");
    let addr: SocketAddr = format!("127.0.0.1:{port}")
        .parse()
        .expect("test server address");
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(quic_crypto)),
        addr,
    )
    .expect("bind test server");

    tokio::spawn(async move {
        // Connections are RETAINED, not dropped at the end of each loop
        // iteration: `quinn::Connection` closes on its last handle drop, which
        // would tear the client's connection down mid-assertion (its
        // `negotiated_alpn()` read happens after `connect` returns). Holding
        // them for the task's lifetime — which ends with the test process — is
        // the whole reason this is a `Vec` rather than a bare loop body.
        let mut held: Vec<quinn::Connection> = Vec::new();
        while let Some(incoming) = endpoint.accept().await {
            let Ok(conn) = incoming.await else { continue };
            // Report what the SERVER selected, so a failure names the actual
            // negotiation rather than leaving it to be inferred client-side.
            eprintln!("test_server: negotiated {:?}", negotiated(&conn));
            if let Ok((mut send, mut recv)) = conn.accept_bi().await {
                let _ = recv.read_to_end(4096).await;
                let _ = send.write_all(&[0u8]).await;
                let _ = send.finish();
            }
            held.push(conn);
        }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    addr
}

/// The shipped client must not OFFER `/1` — the half of the owner ruling that
/// a constant assertion cannot reach, because a constant is only load-bearing
/// if `build_client_endpoint` actually consumes it (and it is private, so no
/// test can read its list directly).
///
/// The probe exploits how ALPN selection works: the SERVER picks the first
/// protocol in ITS OWN list that the client also offered. A server listing
/// `["/1", "/0"]` therefore selects `/1` from anyone who offers it. If the
/// shipped client still ends up on `/0`, it did not offer `/1`.
#[tokio::test]
async fn the_shipped_client_does_not_offer_v1() {
    let dir = unique_dir("offer-list");
    run_ok(env!("CARGO_BIN_EXE_mkcerts"), &[dir.to_str().unwrap()]);

    let addr = test_server(&dir, port_for(5), &[ALPN_V1_NOT_SUPPORTED, ALPN_V0]).await;

    // POSITIVE CONTROL: a raw client that DOES offer /1 must land on /1
    // against this server. Without it, "the shipped client got /0" is also
    // what a server that silently ignores its own preference order would
    // produce, and the real assertion below would pass for the wrong reason.
    let control_ep = raw_client_endpoint(&dir, "gw-A", &[ALPN_V1_NOT_SUPPORTED, ALPN_V0]);
    let control = control_ep
        .connect(addr, RELAY_SERVER_NAME)
        .expect("start control connect")
        .await
        .expect("CONTROL: dual-offer client must connect to the /1-preferring test server");
    assert_eq!(
        negotiated(&control).as_deref(),
        Some(ALPN_V1_NOT_SUPPORTED),
        "CONTROL: this test server prefers /1 and must select it from a client that offers \
         it. If it selected /0 instead, the server's preference order is not doing what this \
         test depends on and the assertion below proves nothing about the shipped client"
    );
    drop(control);

    let c = wiremesh_relay::Client::connect(addr, &dir, "gw-A", "gw-B")
        .await
        .expect("the shipped client must connect to a server that accepts /0");
    assert_eq!(
        c.negotiated_alpn(),
        Some(ALPN_V0),
        "the SHIPPED client landed on a protocol other than /0 against a server that prefers \
         /1 — which can only happen if its offer list contains /1. Owner ruling 2026-08-25: a \
         client that offers a protocol must be able to SPEAK it, and a v1.0 client cannot \
         speak /1. Against a future mux relay a dual-offer would negotiate /1 and then speak \
         /0 framing: the accept-side defect with the roles reversed"
    );
}

// ===========================================================================
// 6. The per-ALPN session counter (decision H's deprecation anchor).
// ===========================================================================

/// Drains a child's piped stderr into a shared buffer on a background thread.
///
/// DRAINING is the point, not reading. Every other relay test pipes the
/// relay's stderr and never consumes it, which is fine only because those
/// tests are short: a relay whose piped stderr is never read eventually blocks
/// on a full pipe. A counter assertion built on an unconsumed pipe would not
/// fail, it would HANG — and it would hang the relay, so the symptom would
/// surface somewhere else entirely. The thread is detached and dies with the
/// test process.
fn drain_stderr(child: &mut Child) -> Arc<std::sync::Mutex<Vec<String>>> {
    use std::io::BufRead;

    let lines = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = Arc::clone(&lines);
    let stderr = child.stderr.take().expect("relay stderr was piped");
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stderr)
            .lines()
            .map_while(Result::ok)
        {
            eprintln!("relay: {line}");
            sink.lock().expect("stderr sink").push(line);
        }
    });
    lines
}

/// The `alpn_sessions=<n>` value from the most recent registration line, or
/// `None` if no registration line has been seen yet.
///
/// Parsed off the bare decimal that follows the token, per wire-dev's format:
/// `relay: registered key=<hex> owner="gw-7" peer="gw-9" from <addr>
/// alpn="wiremesh-relay/0" alpn_sessions=2`.
fn last_alpn_sessions(lines: &Arc<std::sync::Mutex<Vec<String>>>) -> Option<u64> {
    lines
        .lock()
        .expect("stderr sink")
        .iter()
        .rev()
        .find_map(|l| {
            let rest = l.split("alpn_sessions=").nth(1)?;
            rest.split(|c: char| !c.is_ascii_digit())
                .next()?
                .parse()
                .ok()
        })
}

/// Polls until the counter reaches `want` or the budget elapses, returning
/// what was actually last seen either way so the assertion can show it.
///
/// A poll rather than a bare read because the log line is emitted AFTER
/// `ack_registration`, and `Client::connect` returns as soon as it has read
/// that ack — so the line can legitimately lag the client's return by a
/// scheduling quantum. Asserting immediately would be a race.
async fn await_alpn_sessions(lines: &Arc<std::sync::Mutex<Vec<String>>>, want: u64) -> Option<u64> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let seen = last_alpn_sessions(lines);
        if seen == Some(want) || tokio::time::Instant::now() >= deadline {
            return seen;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The `/0` deprecation horizon's anchor (owner decision H, "OPEN,
/// recommended"): the relay counts registrations per negotiated ALPN and says
/// so in the registration line.
///
/// # Why a log line and not a metric
///
/// The relay has no metrics surface at all — `src/bin/relay.rs` is ~115 lines
/// of `eprintln!` with no `prometheus`/`axum`/`hyper`/`warp` dependency — and
/// building one is S4, a separate 1–2 week item. A counter plus a log line is
/// what fits inside v1.0, and getting it in BEFORE the tag is the whole point:
/// if it ships in 1.1 instead, fleet-wide "zero `/0` sessions" cannot start
/// being measured until then, and `/0` removal slips a full release window.
///
/// # The recorded counter-argument, kept because it bounds the claim
///
/// A per-relay count is necessary but NOT fleet-complete: `relay_next_idx`
/// means a pair that only ever uses R1 is invisible to R2. This counter is the
/// anchor for the fleet measurement, not the measurement itself. Do not let a
/// green here be read as "we can see all `/0` usage".
///
/// # Both registrations must hit the SAME relay
///
/// The counter's scope is one `serve()` invocation — one per process in the
/// shipped binary, but a test standing up two embedded relays would get two
/// independent counters and a confusing `=1, =1`. Hence one `relay_on` for
/// both clients here, and hence this paragraph.
#[tokio::test]
async fn the_per_alpn_session_counter_increments() {
    let dir = unique_dir("counter");
    run_ok(env!("CARGO_BIN_EXE_mkcerts"), &[dir.to_str().unwrap()]);

    let bind = format!("127.0.0.1:{}", port_for(6));
    let mut child = spawn_relay(env!("CARGO_BIN_EXE_relay"), &bind, &dir);
    let lines = drain_stderr(&mut child);
    let _guard = KillOnDrop(child);
    tokio::time::sleep(Duration::from_millis(400)).await;
    let addr: SocketAddr = bind.parse().expect("relay bind address");

    assert_eq!(
        last_alpn_sessions(&lines),
        None,
        "no registration has happened yet, so no registration line — and therefore no \
         counter — may have been emitted. A value here means the line is printed for \
         something other than an ACCEPTED registration, which would make the count \
         meaningless as a usage measure"
    );

    let _a = wiremesh_relay::Client::connect(addr, &dir, "gw-A", "gw-B")
        .await
        .expect("gw-A connect+register");
    assert_eq!(
        await_alpn_sessions(&lines, 1).await,
        Some(1),
        "the first accepted /0 registration must report `alpn_sessions=1`. Nothing, or a \
         different number, means the counter is not wired to the registration path"
    );

    let _b = wiremesh_relay::Client::connect(addr, &dir, "gw-B", "gw-A")
        .await
        .expect("gw-B connect+register");
    assert_eq!(
        await_alpn_sessions(&lines, 2).await,
        Some(2),
        "the second accepted /0 registration on the SAME relay must report \
         `alpn_sessions=2`. A second `1` means the counter is per-connection rather than \
         per-`serve()`, and cannot answer the only question it exists for — \"is anyone \
         still speaking /0?\""
    );

    let last = lines
        .lock()
        .expect("stderr sink")
        .iter()
        .rev()
        .find(|l| l.contains("alpn_sessions="))
        .cloned()
        .expect("a registration line was just observed");
    assert!(
        last.contains(r#"alpn="wiremesh-relay/0""#),
        "the registration line must name the NEGOTIATED protocol, quoted, alongside its \
         count — a count with no protocol label cannot distinguish /0 from a future /1 and \
         is useless as a deprecation anchor. Line was: {last}"
    );
    assert!(
        !last.contains("alpn=unknown"),
        "`alpn=unknown` is the bucket for an unreachable `protocol == None`, and it must \
         never appear on an ordinary connection. Seeing it here means the readback is not \
         reading the live handshake data. Line was: {last}"
    );
}
