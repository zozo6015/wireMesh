// crates/wiremesh-relay/tests/relay_pair_collision.rs
//
// Item 3a — the relay's duplicate-registration decision, and the SILENT
// same-owner branch of it.
//
// ## The gap this pins
//
// `serve` rejects a duplicate registration for an already-held key ONLY when
// `existing.owner != cert_identity` (the impersonation/eviction case, pinned
// by `tests/impersonation.rs`). A SAME-owner duplicate falls straight through
// to `reg.insert` and silently REPLACES the incumbent — no log line, no
// error, no ack failure.
//
// For the intended case (a gateway reconnecting for the SAME pair) that
// fallthrough is correct and deliberate: the reconnect must take over its own
// slot. `RegEntry`'s doc comment says so, and `remove_if_owner` exists
// precisely so the stale connection's later teardown does not evict the
// reconnect.
//
// But `RegEntry` records only the OWNER, never the PEER. So the relay cannot
// tell that reconnect apart from a same-owner *different-pair* collision —
// `K(A,B)` and `K(A,D)` landing on the same 32-bit key. In that case the
// silent replace is total cross-wiring: because the gateway's downlink throws
// the src header away (`wiremesh-gateway`'s `relay.rs`: `let (_src, data)`),
// B's datagrams get written to D's local socket and boringtun roams B's
// endpoint onto D's leg. `docs/research/relay-mux-design-verification.md` §1
// calls this "~1/(n-1) of the collision mass, but the only silent branch".
//
// ## Reachability, honestly stated
//
// There is no production seam that lets a test construct colliding registry
// state directly: `Registry`/`RegEntry` are private and `serve` takes only an
// `Endpoint`. The only way in is a REAL key collision.
//
// That is reachable today — but only today. `peer_identity` is NOT cert-bound
// (only `my_identity` is), so one `gw-A` certificate can register any number
// of (gw-A, peer) pairs, and a birthday search over ~2^16 peer strings finds
// a 32-bit collision in milliseconds. After the width fix the same search
// over a 64-bit space finds nothing, and the silent branch stops being
// reachable at all — which IS the fix.
//
// So `same_owner_colliding_registration_must_not_silently_replace` below
// searches for a collision within the shared budget and asserts on BOTH
// outcomes, with no vacuous branch:
//
//   * collision FOUND (today)      -> the second, different-pair registration
//                                     must be REJECTED, not silently swapped
//                                     in over the incumbent.
//   * collision NOT FOUND (fixed)  -> the id space is wide enough that the
//                                     branch is unreachable, AND two ordinary
//                                     different-pair registrations from the
//                                     same owner must both be accepted (the
//                                     fix must not have been implemented by
//                                     banning same-owner duplicates wholesale).
//
// `same_owner_same_pair_reconnect_is_accepted_and_replaces` guards the other
// direction: whatever the implementer does about the collision branch, an
// honest reconnect for the SAME pair must keep working.
//
// Modeled on `tests/bridge.rs` / `tests/impersonation.rs`.
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use wiremesh_relay::registration_key;

/// Kills the relay server on drop, including on panic-driven unwind.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn unique_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "relay-paircollision-test-{tag}-{}",
        std::process::id()
    ))
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

/// Port range distinct from bridge.rs (40000+), denylist.rs (45000+),
/// impersonation.rs (50000+) and dest_pinning.rs (55000+). `slot` separates
/// the test functions in this file, which cargo may run in parallel.
fn port_for(slot: u16) -> u16 {
    60000 + slot * 1200 + (std::process::id() % 1000) as u16
}

/// Same budget and same search as `tests/pair_id_width.rs`'s
/// `find_same_owner_collision` — duplicated because integration test files
/// are separate crates. See that file for the birthday arithmetic: ~18.6
/// expected collisions in a 2^32 space (P(none) ~ 8e-9), ~1e-8 expected in a
/// 2^64 space.
const COLLISION_SEARCH_BUDGET: usize = 400_000;

fn find_same_owner_collision(my_identity: &str, budget: usize) -> Option<(String, String)> {
    let mut seen: HashMap<[u8; 8], String> = HashMap::with_capacity(budget);
    for i in 0..budget {
        let peer = format!("gw-p{i}");
        let key = registration_key(my_identity, &peer);
        if let Some(prev) = seen.insert(key, peer.clone()) {
            return Some((prev, peer));
        }
    }
    None
}

#[tokio::test]
async fn same_owner_colliding_registration_must_not_silently_replace() {
    let dir = unique_dir("collide");
    let mkcerts_bin = env!("CARGO_BIN_EXE_mkcerts");
    let relay_bin = env!("CARGO_BIN_EXE_relay");

    run_ok(mkcerts_bin, &[dir.to_str().unwrap(), "gw-A"]);

    let bind_addr = format!("127.0.0.1:{}", port_for(0));
    let relay_child = spawn_relay(relay_bin, &bind_addr, &dir);
    let _relay_guard = KillOnDrop(relay_child);
    tokio::time::sleep(Duration::from_millis(400)).await;
    let relay_addr: std::net::SocketAddr = bind_addr.parse().unwrap();

    match find_same_owner_collision("gw-A", COLLISION_SEARCH_BUDGET) {
        // ---------------------------------------------------------------
        // The id space is narrow enough that one certificate can drive two
        // DIFFERENT pairs onto the same registry slot. Reaching the silent
        // branch requires exactly this, and here it is.
        // ---------------------------------------------------------------
        Some((peer1, peer2)) => {
            let key = registration_key("gw-A", &peer1);
            assert_eq!(
                key,
                registration_key("gw-A", &peer2),
                "search invariant: the two peers must actually collide"
            );
            assert_ne!(
                peer1, peer2,
                "search invariant: the two peers must be distinct"
            );
            // The key is a raw 8-byte digest prefix, NOT printable ASCII, so
            // it is rendered as hex — the relay's own `key=<16 hex chars>`
            // stderr format, so this line can be correlated against the relay
            // log. This branch is dead in practice now that the key is 64
            // bits wide, which is precisely why the rendering matters: if the
            // derivation ever regresses, this is the line someone reads.
            let key_hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
            eprintln!(
                "found a same-owner collision: K(gw-A, {peer1:?}) == K(gw-A, {peer2:?}) == {key_hex}"
            );

            // The incumbent: gw-A registers its pair with peer1.
            let incumbent = wiremesh_relay::Client::connect(relay_addr, &dir, "gw-A", &peer1)
                .await
                .expect("gw-A must be able to register its first pair");

            // A SECOND, DIFFERENT pair from the SAME certificate that happens
            // to derive the same key. `existing.owner == cert_identity`, so
            // the duplicate check does not fire and `reg.insert` replaces the
            // incumbent's slot with no log and no error — the connect below
            // succeeds and peer1's traffic starts landing on this connection.
            let colliding = wiremesh_relay::Client::connect(relay_addr, &dir, "gw-A", &peer2).await;
            match &colliding {
                Err(e) => eprintln!("colliding registration correctly rejected: {e:#}"),
                Ok(_) => eprintln!(
                    "colliding registration UNEXPECTEDLY accepted — the incumbent's slot was \
                     silently replaced"
                ),
            }
            assert!(
                colliding.is_err(),
                "a registration for a DIFFERENT pair ({peer2:?}) that collides with an existing \
                 slot ({peer1:?}) from the SAME owner must be rejected, not silently swapped in. \
                 The relay's duplicate check only compares `existing.owner`, so this branch \
                 falls through to `reg.insert` with no log and no error — and because the \
                 gateway discards the forwarded src header, the first pair's datagrams then \
                 land on the second pair's local socket and boringtun roams the endpoint onto \
                 the wrong leg."
            );

            // Rejecting the newcomer must not collaterally kill the incumbent.
            assert!(
                incumbent.is_alive(),
                "the incumbent registration's connection must survive a rejected colliding \
                 registration"
            );
        }

        // ---------------------------------------------------------------
        // No collision findable in budget: the id space is wide (the width
        // fix landed). Assert the positive counterpart — the relay must
        // still accept two ordinary different-pair registrations from the
        // same owner, i.e. the collision was not "fixed" by banning
        // same-owner duplicates outright.
        // ---------------------------------------------------------------
        None => {
            eprintln!(
                "no same-owner collision findable within {COLLISION_SEARCH_BUDGET} pairs — the \
                 silent-replace branch is unreachable by construction"
            );
            let first = wiremesh_relay::Client::connect(relay_addr, &dir, "gw-A", "gw-peer-1")
                .await
                .expect("gw-A must be able to register a pair with gw-peer-1");
            let second = wiremesh_relay::Client::connect(relay_addr, &dir, "gw-A", "gw-peer-2")
                .await
                .expect(
                    "gw-A must be able to register a SECOND, different pair — distinct pairs \
                     from one owner occupy distinct slots and must both be accepted",
                );
            assert_ne!(
                registration_key("gw-A", "gw-peer-1"),
                registration_key("gw-A", "gw-peer-2"),
                "two different pairs from the same owner must occupy different slots"
            );
            assert!(first.is_alive(), "the first pair's connection must stay up");
            assert!(
                second.is_alive(),
                "the second pair's connection must stay up"
            );
        }
    }
}

#[tokio::test]
async fn same_owner_same_pair_reconnect_is_accepted_and_replaces() {
    // The deliberate fallthrough that must SURVIVE whatever is done about the
    // collision branch above: a gateway that reconnects for the same pair
    // (its previous connection is stale/half-open) must be able to take its
    // own slot back, and the traffic must follow the new connection.
    let dir = unique_dir("reconnect");
    let mkcerts_bin = env!("CARGO_BIN_EXE_mkcerts");
    let relay_bin = env!("CARGO_BIN_EXE_relay");

    run_ok(mkcerts_bin, &[dir.to_str().unwrap(), "gw-A", "gw-B"]);

    let bind_addr = format!("127.0.0.1:{}", port_for(1));
    let relay_child = spawn_relay(relay_bin, &bind_addr, &dir);
    let _relay_guard = KillOnDrop(relay_child);
    tokio::time::sleep(Duration::from_millis(400)).await;
    let relay_addr: std::net::SocketAddr = bind_addr.parse().unwrap();

    let _stale = wiremesh_relay::Client::connect(relay_addr, &dir, "gw-B", "gw-A")
        .await
        .expect("gw-B's first registration must be accepted");
    let reconnect = wiremesh_relay::Client::connect(relay_addr, &dir, "gw-B", "gw-A")
        .await
        .expect(
            "gw-B must be able to RE-register the SAME pair from the same cert — a reconnect \
             after a stale/half-open connection is the intended same-owner replace, and \
             rejecting it would strand the gateway until QUIC's idle timeout",
        );

    // The slot follows the reconnect: gw-A's datagrams to K(B,A) reach it.
    let sender = wiremesh_relay::Client::connect(relay_addr, &dir, "gw-A", "gw-B")
        .await
        .expect("gw-A must register under its own identity");
    sender.send(b"after-reconnect").await.expect("send to gw-B");

    let (src, data) = tokio::time::timeout(Duration::from_secs(3), reconnect.recv())
        .await
        .expect(
            "the reconnected registration received nothing — the same-owner replace did not \
                 take effect",
        )
        .expect("recv errored");
    assert_eq!(
        data,
        b"after-reconnect".to_vec(),
        "traffic for the pair must follow the reconnected connection"
    );
    assert_eq!(
        src,
        registration_key("gw-A", "gw-B"),
        "forwarded datagram must carry the sender's real registration key"
    );
}

#[tokio::test]
async fn relay_and_client_agree_on_the_key_derivation_for_asymmetric_length_identities() {
    // The relay derives the registry key itself, from the CERT identity:
    // `registration_key(my_identity, peer_identity)`. The sending client
    // derives its dest independently, in `finish_connect`, as
    // `registration_key(peer_identity, my_identity)`. Those two computations
    // must agree byte-for-byte or the pair silently never rendezvouses
    // ("unknown dest" on the relay, nothing at all on the gateway).
    //
    // Only one function exists today, so the risk this pins is a fix that
    // changes the width/shape on one side (or introduces a second
    // derivation) — which is exactly the change item 3a is about. The
    // identities deliberately have DIFFERENT lengths so that a mishandled
    // length prefix diverges between the two directions instead of
    // cancelling out.
    const SHORT: &str = "gw-A";
    const LONG: &str = "gw-1234567890123456";
    assert_ne!(SHORT.len(), LONG.len(), "identities must differ in length");

    let dir = unique_dir("agree");
    let mkcerts_bin = env!("CARGO_BIN_EXE_mkcerts");
    let relay_bin = env!("CARGO_BIN_EXE_relay");

    run_ok(mkcerts_bin, &[dir.to_str().unwrap(), SHORT, LONG]);

    let bind_addr = format!("127.0.0.1:{}", port_for(2));
    let relay_child = spawn_relay(relay_bin, &bind_addr, &dir);
    let _relay_guard = KillOnDrop(relay_child);
    tokio::time::sleep(Duration::from_millis(400)).await;
    let relay_addr: std::net::SocketAddr = bind_addr.parse().unwrap();

    let short = wiremesh_relay::Client::connect(relay_addr, &dir, SHORT, LONG)
        .await
        .expect("short identity must register");
    let long = wiremesh_relay::Client::connect(relay_addr, &dir, LONG, SHORT)
        .await
        .expect("long identity must register");

    // short -> long: the relay must have keyed `long`'s slot with exactly the
    // dest `short` addresses.
    short
        .send(b"short-to-long")
        .await
        .expect("send short->long");
    let (src, data) = tokio::time::timeout(Duration::from_secs(3), long.recv())
        .await
        .expect(
            "nothing arrived: the relay's server-side key derivation and the client's \
             finish_connect dest derivation disagree for asymmetric-length identities",
        )
        .expect("recv errored");
    assert_eq!(data, b"short-to-long".to_vec());
    assert_eq!(
        src,
        registration_key(SHORT, LONG),
        "the relay must stamp the src header with the SENDER's own registry key"
    );

    // long -> short: the reverse direction must rendezvous too, with the
    // reversed key. (A derivation that ignored the length prefix would make
    // these two directions collide instead of being distinct slots.)
    long.send(b"long-to-short").await.expect("send long->short");
    let (src, data) = tokio::time::timeout(Duration::from_secs(3), short.recv())
        .await
        .expect("nothing arrived on the reverse direction")
        .expect("recv errored");
    assert_eq!(data, b"long-to-short".to_vec());
    assert_eq!(
        src,
        registration_key(LONG, SHORT),
        "the reverse direction's src header must be the reversed key"
    );
    assert_ne!(
        registration_key(SHORT, LONG),
        registration_key(LONG, SHORT),
        "the two directions must be distinct slots"
    );
}
