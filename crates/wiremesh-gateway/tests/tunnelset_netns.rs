//! Two simultaneous boringtun Devices (two epochs) coexisting in one netns,
//! each with a distinct ifname/UAPI socket/listen-port/keypair, then tearing
//! one down without disturbing the other.
//! ./dev.sh run "cargo test -p wiremesh-gateway --test tunnelset_netns \
//!   --features netns-tests -- --test-threads=1 --nocapture"
//!
//! Model: `tunnel_netns.rs` (join_netns_and_mountns + wg genkey via
//! base64_pub_from_priv). Only one netns is needed here (unlike
//! tunnel_netns's two-namespace veth setup) because the property under test
//! is "two Devices in the SAME namespace don't collide" — distinct ifnames
//! give distinct `/var/run/wireguard/<ifname>.sock` UAPI sockets, so no
//! mount-namespace juggling across two peers is required.
#![cfg(feature = "netns-tests")]
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::Command;
use wiremesh_gateway::routes;
use wiremesh_gateway::tunnelset::{TunnelId, TunnelSet};
use wiremesh_gateway::uapi::base64_pub_from_priv;
use wiremesh_testkit::netns::{join_netns_and_mountns, Lab};

fn gen_keypair() -> (String, String) {
    // wg genkey / pubkey via the tool present in the container.
    let priv_b64 = String::from_utf8(
        std::process::Command::new("wg")
            .arg("genkey")
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_string();
    let pub_b64 = base64_pub_from_priv(&priv_b64).unwrap();
    (priv_b64, pub_b64)
}

/// Minimal base64 decoder for a 32-byte WG key. `wiremesh_gateway::uapi`'s
/// own decoder is `pub(crate)`-only, and this test crate can't see it (it's
/// a separate compilation unit linking only the library's `pub` surface),
/// so this is a small standalone decoder used solely to turn the test's
/// expected base64 pubkeys into lowercase hex for comparison against the
/// UAPI wire format below.
fn base64_decode_32(s: &str) -> [u8; 32] {
    fn val(c: u8) -> u32 {
        match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => panic!("invalid base64 char in test pubkey: {:?}", c as char),
        }
    }
    let bytes: Vec<u8> = s
        .bytes()
        .filter(|&c| c != b'=' && !c.is_ascii_whitespace())
        .collect();
    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c) << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    out.try_into()
        .expect("WG pubkey must decode to exactly 32 bytes")
}

/// Lowercase hex of a base64-encoded 32-byte WG pubkey, matching the wire
/// format boringtun's UAPI uses for `own_public_key=`/`public_key=`.
fn base64_pub_to_hex(b64: &str) -> String {
    base64_decode_32(b64)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Read a device's own public key directly off its UAPI `get=1` response.
///
/// boringtun 0.6.0 does not follow the WireGuard cross-platform UAPI spec
/// for the device's own identity: the spec has `get=1` report
/// `private_key=<hex>` and leaves it to the client to derive the public key,
/// but boringtun instead emits a non-standard `own_public_key=<hex>` line
/// (already the public key, hex-encoded) and omits `private_key=` entirely.
/// The real `wg` CLI's vocabulary is exactly `private_key`/`public_key` — it
/// has never heard of `own_public_key` and silently ignores it — so `wg show`
/// can never print a boringtun device's own public key. See
/// `docs/research/keyrot-task6-uapi-pubkey-note.md`. This bypasses `wg`
/// entirely and talks to boringtun's UAPI socket directly, exactly as
/// `wiremesh_gateway::uapi::get_latest_handshakes` does for peer state.
fn own_pubkey_hex_via_uapi(ifname: &str) -> Option<String> {
    let path = format!("/var/run/wireguard/{ifname}.sock");
    let mut stream = UnixStream::connect(&path)
        .unwrap_or_else(|e| panic!("connecting to UAPI socket {path}: {e}"));
    stream
        .write_all(b"get=1\n\n")
        .expect("writing UAPI get request");
    let mut resp = String::new();
    stream
        .read_to_string(&mut resp)
        .expect("reading UAPI get response");
    eprintln!("raw UAPI get=1 response for {ifname}:\n{resp}");
    resp.lines()
        .find_map(|l| l.strip_prefix("own_public_key="))
        .map(|s| s.to_string())
}

#[test]
fn two_epoch_tunnels_coexist_and_tear_down() {
    let mut lab = Lab::new("tunset").unwrap();
    let a = lab.ns("a").unwrap();
    join_netns_and_mountns(&a).unwrap();

    let (k0_priv, k0_pub) = gen_keypair();
    let (k1_priv, k1_pub) = gen_keypair();

    // (T3) `TunnelSet` is keyed by `TunnelId`, not a bare epoch — these two
    // are this gateway's OWN epochs 0 and 1, so both are `Own`. Mechanical
    // update: no assertion below changes meaning.
    let e0 = TunnelId::Own { epoch: 0 };
    let e1 = TunnelId::Own { epoch: 1 };
    let mut set = TunnelSet::new();
    set.bring_up(e0, "wge0", &k0_priv, 51820, 1280).unwrap();
    set.bring_up(e1, "wge1", &k1_priv, 51821, 1280).unwrap();

    assert_eq!(set.ids(), vec![e0, e1]);

    let show0 = Command::new("wg").args(["show", "wge0"]).output().unwrap();
    assert!(
        show0.status.success(),
        "wg show wge0 failed: {}",
        String::from_utf8_lossy(&show0.stderr)
    );
    let show0_text = String::from_utf8_lossy(&show0.stdout);
    assert!(
        show0_text.contains("listening port: 51820"),
        "wge0 output missing expected port: {show0_text}"
    );

    let show1 = Command::new("wg").args(["show", "wge1"]).output().unwrap();
    assert!(
        show1.status.success(),
        "wg show wge1 failed: {}",
        String::from_utf8_lossy(&show1.stderr)
    );
    let show1_text = String::from_utf8_lossy(&show1.stdout);
    assert!(
        show1_text.contains("listening port: 51821"),
        "wge1 output missing expected port: {show1_text}"
    );

    // Self-pubkey identity check, via raw UAPI rather than `wg show`: real
    // `wg` can't see a boringtun device's own public key at all (it emits a
    // non-standard `own_public_key=` field `wg` doesn't parse — see
    // `docs/research/keyrot-task6-uapi-pubkey-note.md`), so this reads each
    // epoch's Device directly and confirms it holds the correct, distinct
    // identity derived from the private key `bring_up` was given.
    let k0_pub_hex = base64_pub_to_hex(&k0_pub);
    let k1_pub_hex = base64_pub_to_hex(&k1_pub);
    let own0_hex =
        own_pubkey_hex_via_uapi("wge0").expect("wge0 must report own_public_key via UAPI get=1");
    let own1_hex =
        own_pubkey_hex_via_uapi("wge1").expect("wge1 must report own_public_key via UAPI get=1");
    assert_eq!(
        own0_hex.len(),
        64,
        "own_public_key must be 64 hex chars: {own0_hex}"
    );
    assert_eq!(
        own1_hex.len(),
        64,
        "own_public_key must be 64 hex chars: {own1_hex}"
    );
    assert_eq!(
        own0_hex, k0_pub_hex,
        "wge0's UAPI own_public_key doesn't match the pubkey derived from its private key"
    );
    assert_eq!(
        own1_hex, k1_pub_hex,
        "wge1's UAPI own_public_key doesn't match the pubkey derived from its private key"
    );
    assert_ne!(
        own0_hex, own1_hex,
        "the two epochs' Devices must hold distinct own keys"
    );

    routes::add_route("10.30.0.0/24", "wge0").unwrap();
    routes::add_route("10.31.0.0/24", "wge1").unwrap();

    set.tear_down(e1).unwrap();
    assert_eq!(set.ids(), vec![e0]);
    assert!(
        !Command::new("ip")
            .args(["link", "show", "wge1"])
            .status()
            .unwrap()
            .success(),
        "wge1 should no longer exist after tear_down"
    );

    let show0_after = Command::new("wg").args(["show", "wge0"]).output().unwrap();
    assert!(
        show0_after.status.success(),
        "wge0 should still be live after tearing down wge1"
    );

    drop(lab);
}
