// crates/wiremesh-relay/tests/impersonation.rs
//
// SECURITY (Cycle 4c) — proves the relay binds every registration to the
// authenticated client certificate, so an enrolled gateway can NO LONGER
// register (and thereby intercept/evict) under an id bound to a DIFFERENT
// gateway's identity.
//
// Before the fix, the registration id was a self-asserted 8-byte value the
// relay took verbatim into its registry, blind-overwriting any duplicate —
// so any valid, non-revoked gateway could register under another pair's
// `relay_pair_id(A,B)` (computable from small gateway ids) and redirect that
// pair's relayed datagrams and/or evict its entry.
//
// The fix: the relay reads the registering gateway's TRUE identity from its
// mTLS client cert (a `gw-<id>` SAN) and REQUIRES the self-asserted
// `my_identity` to equal it; a mismatch closes the connection. A key already
// held by a different cert is never overwritten.
//
// Modeled on `tests/bridge.rs`/`tests/denylist.rs` (KillOnDrop guard,
// PID-derived tmp dir + port, `mkcerts`/`relay` bins via
// `env!("CARGO_BIN_EXE_...")`, a 400ms bind settle).
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Kills the relay server on drop, including on panic-driven unwind.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn unique_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("relay-impersonation-test-{tag}-{}", std::process::id()))
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

#[tokio::test]
async fn relay_rejects_registration_under_another_gateways_identity() {
    let dir = unique_dir("main");
    let mkcerts_bin = env!("CARGO_BIN_EXE_mkcerts");
    let relay_bin = env!("CARGO_BIN_EXE_relay");

    // Two validly-enrolled gateway identities, both chaining to the same CA.
    // Their leaf certs carry SAN gw-A / gw-B respectively (mkcerts stamps
    // SAN = the id name; real enrollment stamps SAN = `gw-<gateway_id>`).
    run_ok(mkcerts_bin, &[dir.to_str().unwrap(), "gw-A", "gw-B"]);

    // Port range distinct from bridge.rs (40000+) and denylist.rs (45000+)
    // so the three relay test binaries never pick the same port.
    let port = 50000 + (std::process::id() % 5000) as u16;
    let bind_addr = format!("127.0.0.1:{port}");
    let relay_child = spawn_relay(relay_bin, &bind_addr, &dir);
    let _relay_guard = KillOnDrop(relay_child);
    tokio::time::sleep(Duration::from_millis(400)).await;

    let relay_addr: std::net::SocketAddr = bind_addr.parse().unwrap();

    // Read the two identities' cert/key PEMs + the CA (for connect_with_pems,
    // which lets us present ONE identity's cert while asserting ANOTHER's id).
    let ca_pem = std::fs::read_to_string(dir.join("ca.pem")).expect("read ca.pem");
    let gwa_cert = std::fs::read_to_string(dir.join("gw-A.pem")).expect("read gw-A.pem");
    let gwa_key = std::fs::read_to_string(dir.join("gw-A.key")).expect("read gw-A.key");

    // --- (1) the legitimate holder of gw-B registers, as itself ------------
    // gw-B registers (my=gw-B, peer=gw-A) under registration_key("gw-B","gw-A").
    let victim = wiremesh_relay::Client::connect(relay_addr, &dir, "gw-B", "gw-A")
        .await
        .expect("gw-B must be able to register under its OWN cert identity");

    // --- (2) THE ATTACK: gw-A's cert, but asserting my_identity = gw-B ------
    // A holder of gw-A's cert/key tries to register under gw-B's identity
    // (e.g. to hijack gw-B's relayed datagrams, or evict its registry slot).
    // The relay reads the cert's SAN (gw-A), sees the asserted my_identity
    // (gw-B) does not match, and CLOSES the connection — so connect+register
    // fails (the failure surfaces at the registration-ack read inside
    // finish_connect, same as the certless/denylist rejections in the sibling
    // tests).
    let impostor = wiremesh_relay::Client::connect_with_pems(
        relay_addr,
        &gwa_cert,
        &gwa_key,
        &ca_pem,
        "gw-B", // asserting SOMEONE ELSE's identity
        "gw-A",
    )
    .await;
    match &impostor {
        Err(e) => eprintln!("impersonation correctly rejected: {e:#}"),
        Ok(_) => eprintln!("impersonation UNEXPECTEDLY accepted — cert binding not enforced"),
    }
    assert!(
        impostor.is_err(),
        "a gw-A cert MUST NOT be able to register under gw-B's cert-bound identity — \
         the relay must reject the registration (impersonation / traffic-redirection)"
    );

    // --- (3) the victim's slot was NOT hijacked or evicted -----------------
    // gw-A, registering honestly as ITSELF (my=gw-A, peer=gw-B), addresses
    // datagrams at registration_key("gw-B","gw-A") — exactly the id the victim
    // registered under. If the impostor had hijacked/evicted that slot, this
    // datagram would go elsewhere (or nowhere). It reaches the victim, proving
    // the slot survived intact.
    let sender = wiremesh_relay::Client::connect(relay_addr, &dir, "gw-A", "gw-B")
        .await
        .expect("gw-A must register under its OWN identity");
    sender.send(b"still-yours").await.expect("send to gw-B");
    let (src, data) = tokio::time::timeout(Duration::from_secs(3), victim.recv())
        .await
        .expect("recv timed out — victim's slot may have been hijacked/evicted")
        .expect("recv errored");
    assert_eq!(
        data,
        b"still-yours".to_vec(),
        "the legitimate gw-B registration must still receive its datagrams"
    );
    assert_eq!(
        src,
        wiremesh_relay::registration_key("gw-A", "gw-B"),
        "datagram must carry gw-A's real registration key"
    );
}
