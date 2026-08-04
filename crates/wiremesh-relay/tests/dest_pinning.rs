// crates/wiremesh-relay/tests/dest_pinning.rs
//
// SECURITY (item 3a) — proves the relay only forwards a datagram to the ONE
// destination key that belongs to the sending connection's own registered
// pair.
//
// ## The hole this pins
//
// `serve`'s datagram loop (`src/lib.rs`, the `read_datagram` loop) reads an
// 8-byte `dest` straight off the wire and looks it up in the shared registry
// with NO check that `dest` belongs to the sender's pair. Only the RECEIVE
// side is bound to the client certificate: a slot `K(A,B)` can only be
// *created* by the holder of the `gw-A` cert (`identity_from_client_cert` +
// the `my_identity != cert_identity` rejection). The SEND side is unenforced.
//
// Gateway identities are `gw-<rowid>` (`services::enrollment`) — sequential
// and trivially enumerable — so ANY enrolled, non-revoked gateway can compute
// `registration_key(victim, victim_peer)` and inject datagrams into that
// pair's relay slot.
//
// This is a ROUTING/reachability property, not a secrecy one: WireGuard's
// end-to-end encryption still holds, so an injected datagram is garbage to
// the victim's boringtun. What it buys an attacker is DoS and endpoint
// confusion (the gateway's downlink discards the src header — `relay.rs`'s
// `let (_src, data)` — so injected bytes are indistinguishable from the real
// peer's at the socket layer). The assertion below is therefore about WHERE
// the datagram goes, never about what is in it.
//
// The fix (per `docs/research/relay-mux-design-verification.md` §2): the
// relay already holds this connection's cert-bound `my_identity` and its
// registered `peer_identity`, so the only legal `dest` is
// `registration_key(peer_identity, my_identity)` — byte-for-byte what
// `Client::finish_connect` computes for its own `dest_key`. Anything else is
// rejected.
//
// ## Why this test cannot be written with `Client` alone
//
// `Client::send` always prefixes `self.dest_key`, which `finish_connect`
// pins to `registration_key(peer_identity, my_identity)` — the public API
// deliberately cannot address an arbitrary slot. And no choice of
// (my, peer) lets gw-C's cert produce `K(gw-A, gw-B)`: the derivation
// length-prefixes `my`, so reproducing `K("gw-A","gw-B")` requires
// `peer == "gw-A"` and `my == "gw-B"`, and `my` is cert-bound to `gw-C`.
//
// So the attacker below is a RAW quinn client: it speaks the documented wire
// format directly (`[2B my_len][my][peer]` registration on the first bi
// stream, then `[8B dest][payload]` datagrams). It presents a real,
// validly-chained `gw-C` certificate and registers a real pair — it is a
// fully legitimate relay client in every respect except the `dest` it
// addresses. That is exactly the threat model: an *enrolled* gateway, not an
// outsider.
//
// ## Guard against passing for the wrong reason
//
// A "victim received nothing" assertion is worthless if the attacker's
// datagram was malformed, or its connection was never really registered, or
// the relay was simply idle. Three structural guards:
//
//   1. POSITIVE CONTROL, same connection, same framing: before injecting,
//      gw-C sends a datagram to its OWN legal peer gw-D and gw-D receives it,
//      with the correct src header. Both sends go through the same
//      `raw_send_datagram` helper; the ONLY difference between the control
//      and the attack is the 8 dest bytes.
//   2. BARRIER + LIVE VICTIM: after the injection, the legitimate holder of
//      the other half of the victim pair (gw-B) sends to the very same slot
//      `K(A,B)`, and gw-A must receive THAT — proving gw-A's downlink is
//      alive, the slot is intact, and the fix rejects on pair membership
//      rather than by breaking the slot.
//   3. DRAIN: after the legitimate datagram lands, a further read on gw-A
//      must time out — catching the case where the injected datagram merely
//      arrived out of order rather than not at all.
//
// Modeled on `tests/bridge.rs` / `tests/impersonation.rs` (KillOnDrop guard,
// PID-derived tmp dir + port, `mkcerts`/`relay` bins via
// `env!("CARGO_BIN_EXE_...")`, a 400ms bind settle).
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

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
    std::env::temp_dir().join(format!("relay-destpin-test-{tag}-{}", std::process::id()))
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

// ---------------------------------------------------------------------------
// A raw relay client: the crate's documented wire format, spoken directly.
//
// This duplicates the transport/TLS settings of `wiremesh_relay`'s private
// `build_client_endpoint` (ALPN `wiremesh-relay/0`, 30s idle, DPLPMTUD on,
// 1MiB datagram receive buffer). It must stay in sync with them — if the
// crate ever changes ALPN or disables datagrams, this endpoint stops
// connecting and the test fails loudly rather than silently passing.
// ---------------------------------------------------------------------------

/// SNI the relay's leaf cert is stamped with (`test_certs` writes SAN
/// "relay"); the crate's private `RELAY_SERVER_NAME`.
const RELAY_SERVER_NAME: &str = "relay";

fn raw_client_endpoint(certdir: &Path, my_id: &str) -> quinn::Endpoint {
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
    tls.alpn_protocols = vec![b"wiremesh-relay/0".to_vec()];

    let quic_crypto =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).expect("quic client crypto");
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        Duration::from_secs(30).try_into().expect("30s idle timeout"),
    ));
    transport.mtu_discovery_config(Some(quinn::MtuDiscoveryConfig::default()));
    transport.datagram_receive_buffer_size(Some(1 << 20));
    client_config.transport_config(Arc::new(transport));

    let mut endpoint =
        quinn::Endpoint::client((Ipv4Addr::UNSPECIFIED, 0).into()).expect("bind client endpoint");
    endpoint.set_default_client_config(client_config);
    endpoint
}

/// Connect + register exactly as `Client::finish_connect` does — including
/// blocking on the 1-byte registration ack, so the relay's registry insert
/// has definitely happened before we return.
///
/// Returns the `Endpoint` alongside the `Connection`: the caller must keep it
/// alive for the connection's lifetime (an endpoint whose last handle is
/// dropped stops driving its socket, which would make this test pass for the
/// wrong reason).
async fn raw_connect_and_register(
    certdir: &Path,
    relay_addr: SocketAddr,
    my_identity: &str,
    peer_identity: &str,
) -> (quinn::Endpoint, quinn::Connection) {
    let endpoint = raw_client_endpoint(certdir, my_identity);
    let conn = endpoint
        .connect(relay_addr, RELAY_SERVER_NAME)
        .expect("start QUIC connect")
        .await
        .expect("QUIC handshake");

    let (mut send, mut recv) = conn.open_bi().await.expect("open registration stream");
    let my = my_identity.as_bytes();
    let mut buf = Vec::with_capacity(2 + my.len() + peer_identity.len());
    buf.extend_from_slice(&(my.len() as u16).to_be_bytes());
    buf.extend_from_slice(my);
    buf.extend_from_slice(peer_identity.as_bytes());
    send.write_all(&buf).await.expect("write registration");
    send.finish().expect("finish registration stream");
    recv.read_to_end(1).await.expect("await registration ack");

    (endpoint, conn)
}

/// The ONE datagram-emitting helper. Both the positive control and the
/// injection go through it, so the only thing that differs between them is
/// the 8 `dest` bytes — a malformed-attacker false pass is impossible.
fn raw_send_datagram(conn: &quinn::Connection, dest: [u8; 8], payload: &[u8]) {
    let mut buf = Vec::with_capacity(8 + payload.len());
    buf.extend_from_slice(&dest);
    buf.extend_from_slice(payload);
    conn.send_datagram(buf.into()).expect("send raw datagram");
}

#[tokio::test]
async fn relay_must_not_forward_a_datagram_addressed_outside_the_senders_own_pair() {
    let dir = unique_dir("main");
    let mkcerts_bin = env!("CARGO_BIN_EXE_mkcerts");
    let relay_bin = env!("CARGO_BIN_EXE_relay");

    // Four validly-enrolled identities, all chaining to the same CA:
    //   gw-A / gw-B — the victim pair.
    //   gw-C / gw-D — the attacker and its own legitimate peer (the positive
    //                 control, so "C's datagrams work at all" is proven on
    //                 the same connection before the attack).
    run_ok(
        mkcerts_bin,
        &[dir.to_str().unwrap(), "gw-A", "gw-B", "gw-C", "gw-D"],
    );

    // Port range distinct from bridge.rs (40000+), denylist.rs (45000+) and
    // impersonation.rs (50000+).
    let port = 55000 + (std::process::id() % 5000) as u16;
    let bind_addr = format!("127.0.0.1:{port}");
    let relay_child = spawn_relay(relay_bin, &bind_addr, &dir);
    let _relay_guard = KillOnDrop(relay_child);
    tokio::time::sleep(Duration::from_millis(400)).await;

    let relay_addr: SocketAddr = bind_addr.parse().unwrap();

    // --- the victim pair, both halves registered honestly -----------------
    // gw-A holds slot K(A,B); gw-B holds slot K(B,A) and addresses K(A,B).
    let victim_a = wiremesh_relay::Client::connect(relay_addr, &dir, "gw-A", "gw-B")
        .await
        .expect("gw-A must register under its own cert identity");
    let victim_b = wiremesh_relay::Client::connect(relay_addr, &dir, "gw-B", "gw-A")
        .await
        .expect("gw-B must register under its own cert identity");

    // --- the attacker's own honest pair -----------------------------------
    // gw-D is an ordinary `Client`; gw-C is raw only because it needs to
    // address a `dest` the public API cannot express.
    let peer_d = wiremesh_relay::Client::connect(relay_addr, &dir, "gw-D", "gw-C")
        .await
        .expect("gw-D must register under its own cert identity");
    let (_attacker_endpoint, attacker_c) =
        raw_connect_and_register(&dir, relay_addr, "gw-C", "gw-D").await;

    // --- GUARD 1: positive control ----------------------------------------
    // gw-C's raw connection is fully functional: a datagram to its OWN legal
    // dest — registration_key(peer="gw-D", my="gw-C"), exactly what
    // `Client::finish_connect` would compute for it — is forwarded to gw-D
    // with the correct src header. Awaited BEFORE the injection so the two
    // sends are strictly sequential.
    let legal_dest = wiremesh_relay::registration_key("gw-D", "gw-C");
    raw_send_datagram(&attacker_c, legal_dest, b"control-c-to-d");
    let (ctl_src, ctl_data) = tokio::time::timeout(Duration::from_secs(3), peer_d.recv())
        .await
        .expect("positive control timed out — the raw gw-C client cannot bridge at all, so a \
                 'victim received nothing' result below would prove nothing")
        .expect("positive control recv errored");
    assert_eq!(
        ctl_data,
        b"control-c-to-d".to_vec(),
        "the raw attacker client's own legitimate traffic must bridge normally"
    );
    assert_eq!(
        ctl_src,
        wiremesh_relay::registration_key("gw-C", "gw-D"),
        "positive-control datagram must carry gw-C's real registration key"
    );

    // --- THE ATTACK -------------------------------------------------------
    // Same connection, same helper, same framing — only the dest differs.
    // gw-C addresses the victim pair's slot K(A,B), which it has no business
    // sending to: gw-C's registered pair is (gw-C, gw-D).
    let victim_slot = wiremesh_relay::registration_key("gw-A", "gw-B");
    assert_ne!(
        victim_slot, legal_dest,
        "test setup error: the victim slot must differ from gw-C's legal dest"
    );
    raw_send_datagram(&attacker_c, victim_slot, b"INJECTED-BY-GW-C");

    // Give the relay time to have processed the injection (and, if the hole
    // is open, to have put it on the wire to gw-A) before the legitimate
    // datagram is sent, so the barrier below is a real ordering barrier.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // --- GUARD 2: barrier + live victim -----------------------------------
    // The legitimate holder of the other half of the pair sends to the very
    // same slot. gw-A must receive THIS — not the injection.
    victim_b
        .send(b"legit-b-to-a")
        .await
        .expect("gw-B must still be able to send to its own peer");
    let (src, data) = tokio::time::timeout(Duration::from_secs(3), victim_a.recv())
        .await
        .expect("gw-A received nothing at all — its slot or downlink is broken, which is a \
                 different failure from the injection this test is about")
        .expect("gw-A recv errored");
    assert_eq!(
        data,
        b"legit-b-to-a".to_vec(),
        "gw-A's FIRST datagram must be gw-B's legitimate one; receiving the injected payload \
         here means the relay forwarded a datagram addressed outside the sender's own pair \
         (any enrolled gateway can enumerate gw-<rowid> and inject into any pair's slot)"
    );
    assert_eq!(
        src,
        wiremesh_relay::registration_key("gw-B", "gw-A"),
        "the datagram gw-A received must carry gw-B's registration key as src"
    );

    // --- GUARD 3: drain ---------------------------------------------------
    // Nothing else may arrive: the injected datagram must not merely have
    // been reordered behind the legitimate one.
    let leftover = tokio::time::timeout(Duration::from_millis(1500), victim_a.recv()).await;
    assert!(
        leftover.is_err(),
        "gw-A received a SECOND datagram after gw-B's legitimate one: {:?} — the relay \
         forwarded gw-C's cross-pair injection into slot K(gw-A, gw-B)",
        // The src key is a raw 8-byte digest prefix, NOT printable ASCII —
        // rendering it lossily would print mojibake at exactly the moment
        // someone is reading this failure. Hex matches the relay's own
        // `key=<16 hex chars>` stderr format, so a failure here can be
        // correlated against the relay's log. The payload stays lossy: it is
        // the ASCII marker `INJECTED-BY-GW-C`, and reading it is the point.
        leftover.map(|r| r.map(|(s, d)| (
            s.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            String::from_utf8_lossy(&d).to_string(),
        )))
    );

    // The victim pair must still be usable afterwards: rejecting a cross-pair
    // dest must not tear down anybody's connection.
    assert!(victim_a.is_alive(), "gw-A's relay connection must survive the injection attempt");
    assert!(victim_b.is_alive(), "gw-B's relay connection must survive the injection attempt");
}
