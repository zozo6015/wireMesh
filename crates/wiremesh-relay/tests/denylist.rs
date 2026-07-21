// crates/wiremesh-relay/tests/denylist.rs
//
// Cycle 4c Task 3: offline certificate-revocation denylist.
//
// Proves the relay's `ClientCertVerifier` does webpki chain validation FIRST
// and then ALSO rejects a client whose cert serial is on a persisted,
// pre-seeded denylist — with no controller involved at all (fully offline:
// `denylist.json` is written to disk before the relay ever starts, and the
// relay bin is spawned with no `--controller` flag).
//
// Modeled directly on `tests/bridge.rs` (KillOnDrop guard, PID-derived
// tmp dir + port, mkcerts/relay bins located via
// `env!("CARGO_BIN_EXE_mkcerts")` / `env!("CARGO_BIN_EXE_relay")`, a 400ms
// sleep to let the relay finish binding before any client dials in).
//
// ## Assumption about mkcerts's CLI (read before touching call sites below)
//
// As of this commit, `src/bin/mkcerts.rs` takes a single `dir` positional
// and hardcodes `for name in ["relay", "gw-A", "gw-B"]`. Task 3 needs two
// gateway identities named `gw-good` / `gw-bad` (so the *meaning* of "bad"
// is "revoked", not "malformed cert") plus a `<id>.serial` sidecar file next
// to every leaf cert. This test assumes the implementer generalizes the
// hardcoded gw-id list into trailing positional CLI args, i.e.
// `mkcerts <dir> gw-good gw-bad`, and writes a `<id>.serial` file (lowercase
// hex, matching wiremesh-trust's `{b:02x}`-per-byte encoding) next to each
// generated leaf cert. If the implementer instead keeps the id list fixed
// in the binary and just renames `gw-A`/`gw-B` to `gw-good`/`gw-bad`, only
// `run_mkcerts`'s call site below needs to change (drop the extra args) —
// nothing else in this test depends on which approach was taken.
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

/// Kills the relay server on drop, including on panic-driven unwind, so a
/// failed assertion never leaks a background process out of the test.
/// Mirrors `KillOnDrop` in `tests/bridge.rs`.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A tmpdir unique to this test process. No `rand`/`Date` dependency
/// available here, so uniqueness is derived from the PID (sufficient: one
/// process runs this test at a time, and repeated local runs each get a
/// fresh PID). Tagged separately from `tests/bridge.rs`'s `unique_dir` so
/// the two test binaries never collide on the same path even if they
/// happen to share a PID across separate `cargo test` invocations.
fn unique_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("relay-denylist-test-{tag}-{}", std::process::id()))
}

fn run_ok(bin: &str, args: &[&str]) {
    let status = Command::new(bin)
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("spawn {bin} {args:?}: {e}"));
    assert!(status.success(), "{bin} {args:?} failed: {status:?}");
}

/// Runs mkcerts with the gw ids this test needs. See the module-level
/// "Assumption about mkcerts's CLI" comment above for why these are passed
/// as trailing positional args.
fn run_mkcerts(bin: &str, dir: &Path, gw_ids: &[&str]) {
    let mut args: Vec<&str> = vec![dir.to_str().unwrap()];
    args.extend_from_slice(gw_ids);
    run_ok(bin, &args);
}

fn spawn_relay(bin: &str, bind: &str, certdir: &Path) -> Child {
    // Deliberately NO `--controller` flag: this test is fully offline. The
    // relay bin is expected to load `<certdir>/denylist.json` at startup
    // unconditionally (via `wiremesh_relay::Denylist::load`, which is
    // fail-static on a missing file) and build its server config with
    // `wiremesh_relay::server_config_with_denylist`.
    Command::new(bin)
        .args([bind, certdir.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {bin}: {e}"))
}

/// Writes `<certdir>/denylist.json` as a JSON array of lowercase-hex serial
/// strings, mode 0600 — the exact on-disk schema `Denylist::load` /
/// `Denylist::persist` use. Hand-built rather than going through
/// `wiremesh_relay::Denylist` itself, so this test seeds the file the way
/// an out-of-band operator (or a prior controller sync) would: as a bare
/// JSON file already on disk before the relay process starts.
fn write_denylist(certdir: &Path, revoked_serials_hex: &[&str]) {
    let items: Vec<String> = revoked_serials_hex
        .iter()
        .map(|s| format!("\"{s}\""))
        .collect();
    let json = format!("[{}]", items.join(","));
    let path = certdir.join("denylist.json");
    std::fs::write(&path, json).expect("write denylist.json");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path).expect("stat denylist.json").permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&path, perms).expect("chmod denylist.json 0600");
    }
}

#[tokio::test]
async fn offline_denylist_rejects_revoked_serial_but_keeps_mutual_tls_and_good_clients_working() {
    let dir = unique_dir("main");
    let mkcerts_bin = env!("CARGO_BIN_EXE_mkcerts");
    let relay_bin = env!("CARGO_BIN_EXE_relay");

    run_mkcerts(mkcerts_bin, &dir, &["gw-good", "gw-bad"]);

    // `gw-bad`'s cert chains validly to the same CA as `gw-good` — mkcerts
    // signs both leaves identically. Only the denylist distinguishes them.
    let bad_serial = std::fs::read_to_string(dir.join("gw-bad.serial"))
        .expect("mkcerts must write gw-bad.serial (lowercase-hex serial) next to gw-bad.pem")
        .trim()
        .to_string();
    assert!(
        !bad_serial.is_empty(),
        "gw-bad.serial must contain a non-empty lowercase-hex serial"
    );

    // Seed the denylist BEFORE the relay ever starts: fully offline, no
    // controller/Sync client involved anywhere in this test.
    write_denylist(&dir, &[&bad_serial]);

    // Port derived from PID to avoid colliding with a lingering listener
    // from a just-killed prior run still draining its socket. Offset from
    // `tests/bridge.rs`'s range (40000+) so the two test binaries can never
    // pick the same port even if they happen to run with close PIDs.
    let port = 45000 + (std::process::id() % 5000) as u16;
    let bind_addr = format!("127.0.0.1:{port}");
    let relay_child = spawn_relay(relay_bin, &bind_addr, &dir);
    let _relay_guard = KillOnDrop(relay_child);
    // Let the relay finish binding before any client dials in.
    tokio::time::sleep(Duration::from_millis(400)).await;

    let relay_addr: std::net::SocketAddr = bind_addr.parse().unwrap();

    // --- (a) a non-revoked, validly-chained client still works ---------
    // Two separate connections both register under the SAME id "gw-good":
    // per relay.rs's registry, the second `insert` overwrites the first, so
    // sending to "gw-good" after both are up routes to the second
    // connection. This lets us bridge a datagram end-to-end using only the
    // one non-revoked identity mkcerts produced for this test, mirroring
    // `tests/bridge.rs`'s Property 1 without needing a third gw id.
    // Both connections register the SAME (my=gw-good, peer=gw-good) pair with
    // the SAME cert — so the second is a same-owner reconnect that REPLACES
    // the first in the registry (allowed; the cert-binding fix only rejects a
    // duplicate from a DIFFERENT cert). `good_a`'s uplink still works, and its
    // datagram to the shared key is delivered to the current holder (good_b).
    let good_a = wiremesh_relay::Client::connect(relay_addr, &dir, "gw-good", "gw-good")
        .await
        .expect("gw-good (1st connection) must connect: valid chain, not on the denylist");
    let good_b = wiremesh_relay::Client::connect(relay_addr, &dir, "gw-good", "gw-good")
        .await
        .expect("gw-good (2nd connection) must also connect: same non-revoked identity");

    good_a
        .send(b"still-good")
        .await
        .expect("send to gw-good");
    let (src, data) = tokio::time::timeout(Duration::from_secs(3), good_b.recv())
        .await
        .expect("recv timed out")
        .expect("recv errored");
    assert_eq!(
        data,
        b"still-good".to_vec(),
        "a non-revoked client's traffic must still bridge unmodified"
    );
    assert_eq!(src, wiremesh_relay::registration_key("gw-good", "gw-good"));

    // --- (b) the revoked serial is rejected, for the RIGHT reason -------
    // gw-bad has a chain that validates cleanly against ca.pem (mkcerts
    // signs gw-bad exactly like gw-good) — if this connect failed, it must
    // be because `server_config_with_denylist`'s verifier checked the
    // serial against the denylist AFTER chain validation passed, not
    // because of a chain/handshake problem. Per `tests/bridge.rs`'s module
    // doc comment on where a server-side TLS rejection actually surfaces
    // (not the raw `endpoint.connect(...).await`, but one step later, while
    // `Client::connect`'s `finish_connect` awaits the registration ack),
    // the same applies here: a denylist rejection is also a server-initiated
    // CONNECTION_CLOSE, so it too is expected to surface at the
    // registration-ack read inside `Client::connect`, which is exactly why
    // asserting on the whole wrapped `Client::connect(..., "gw-bad")` future
    // (not a bypassed raw handshake future) is the reliable place to check
    // this — same reasoning as the certless-client property below.
    let bad_result = wiremesh_relay::Client::connect(relay_addr, &dir, "gw-bad", "gw-good").await;
    eprintln!("gw-bad connect is_ok = {}", bad_result.is_ok());
    match &bad_result {
        Err(e) => eprintln!("revoked client correctly rejected: {e:#}"),
        Ok(_) => eprintln!("revoked client UNEXPECTEDLY connected — denylist not enforced"),
    }
    assert!(
        bad_result.is_err(),
        "gw-bad's serial is on the denylist and must be rejected even though its cert chains \
         validly to the CA — a validating chain must not be enough on its own"
    );

    // --- (c) mandatory mutual TLS must not have been loosened -----------
    // Adding denylist enforcement must be purely additive: a certless
    // client must still fail exactly as it does in `tests/bridge.rs`'s
    // Property 3.
    let no_cert_result = wiremesh_relay::Client::connect_no_cert(relay_addr, &dir).await;
    eprintln!("connect_no_cert is_ok = {}", no_cert_result.is_ok());
    assert!(
        no_cert_result.is_err(),
        "certless client completed connect+register — mutual TLS enforcement regressed"
    );
}
