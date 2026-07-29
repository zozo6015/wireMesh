//! Behavioral pin for the gateway's SCOPED single-peer endpoint update
//! (`uapi::set_one_peer` / `uapi::encode_set_one_peer`) — the make-before-break
//! re-point used by NAT-punch and relay-endpoint install.
//!
//! CONTRACT UNDER TEST: the gateway must change ONE peer's WireGuard endpoint
//! WITHOUT disturbing any OTHER peer's session or config. boringtun 0.6.0
//! panics on an in-place modify of an existing peer, so the scoped update is a
//! remove+re-add of ONLY the target peer, applied with NO `replace_peers`
//! header (which would `clear_peers()` and reset EVERY peer). A prior bug
//! removed the target peer and then failed to re-add it, so `wg show` reported
//! no peers and endpoints read `None`. This test catches exactly that
//! regression.
//!
//! TEST LEVEL — DEVICE level, deliberately. This is a BEHAVIORAL pin against a
//! REAL embedded boringtun device, NOT a byte/encoder assertion:
//!
//!   - It stands one device up via the crate's own public constructor
//!     `tunnel::Tunnel::up` (the same `DeviceHandle::new` path production uses
//!     — the test cannot name `boringtun` directly because it's a normal
//!     dependency, not a dev-dependency, and this file must not touch
//!     Cargo.toml).
//!   - It configures two peers B and C through `uapi::apply`, performs the
//!     scoped update on C via `uapi::set_one_peer`, and reads the live device
//!     state straight back over the UAPI `get=1` socket.
//!
//! Why the device level and not the encoder: the scoped re-point's real
//! subtlety is that the remove and the re-add MUST be TWO SEPARATE `set=1`
//! messages — boringtun does NOT re-create a peer from a re-add block that
//! follows a `remove=true` of the same key in the SAME message (the remove
//! wins and the peer VANISHES). That is precisely the "peer vanished /
//! endpoint None" bug, and it is only observable by inspecting boringtun's
//! real peer table after a real `set_one_peer`. The encoder-level structure
//! (two ops, remove-then-add, no `replace_peers`) is already pinned by the
//! `uapi` mod's own unit test, so this file does not duplicate it.
//!
//! It needs a privileged host (tun + `ip link set up`) but NOT netns — the dev
//! container is privileged, so it runs there. Per the project's execution
//! rule, all code/tests run inside `./dev.sh`.
//!
//! Targeted surface (stable public API of `src/uapi.rs`):
//!   pub fn set_one_peer(ifname: &str, peer: &PeerConfig) -> anyhow::Result<()>;
//!   pub fn apply(ifname: &str, cfg: &DeviceConfig) -> anyhow::Result<()>;
//!   pub struct PeerConfig { public_key_b64, endpoint: Option<String>,
//!                           allowed_ips: Vec<String>, keepalive_secs: u16 }
//!
//! Serial-safe: uses a single fixed interface name and is the only test in
//! this file; the suite runs with `--test-threads=1`.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use wiremesh_gateway::tunnel::Tunnel;
use wiremesh_gateway::uapi::{
    apply, set_one_peer, DeviceConfig, PeerConfig, PERSISTENT_KEEPALIVE_SECS,
};

// --- fixed fixtures (all TEST-NET IPv4; v1 is IPv4-only) --------------------

const IFNAME: &str = "wgscoped0";

// Raw 32-byte key material. Distinct byte fills give distinct, easily matched
// hex forms in the `get=1` response; the device key differs from both peers so
// boringtun won't reject a peer whose key equals the device's own.
const DEV_PRIV: [u8; 32] = [0x01; 32];
const B_PUB: [u8; 32] = [0xBB; 32];
const C_PUB: [u8; 32] = [0xCC; 32];

const LISTEN_PORT: u16 = 51820;

const B_ENDPOINT: &str = "192.0.2.11:51820";
const B_CIDR: &str = "10.20.2.0/24";

const C_ENDPOINT_ORIG: &str = "192.0.2.12:51820";
const C_ENDPOINT_NEW: &str = "198.51.100.99:41000"; // the punched/relay re-point
const C_CIDR: &str = "10.20.3.0/24";

// --- tiny local encoders (test-owned; the crate's are pub(crate)) ----------

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_32(bytes: &[u8; 32]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { B64[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[(n & 63) as usize] as char } else { '=' });
    }
    out
}

/// Lowercase hex, as the WG UAPI `public_key=<hex>` line reports it — lets us
/// find a peer's block in the `get=1` response by its known key bytes.
fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn peer(pub_bytes: &[u8; 32], endpoint: &str, cidr: &str) -> PeerConfig {
    PeerConfig {
        public_key_b64: b64_32(pub_bytes),
        endpoint: Some(endpoint.to_string()),
        allowed_ips: vec![cidr.to_string()],
        keepalive_secs: PERSISTENT_KEEPALIVE_SECS,
    }
}

// --- raw UAPI get=1 read side ----------------------------------------------

#[derive(Default, Debug)]
struct GotPeer {
    endpoint: Option<String>,
    allowed_ips: Vec<String>,
}

/// Read the live device state via a raw `get=1` round-trip and index it by
/// pubkey-hex. We parse the endpoint + allowed_ips lines ourselves because the
/// crate's `parse_get_response` is `pub(crate)` (unreachable here) and only
/// extracts handshake/traffic fields, not the endpoint this test asserts on.
fn read_peers(ifname: &str) -> std::collections::HashMap<String, GotPeer> {
    let path = format!("/var/run/wireguard/{ifname}.sock");
    let mut stream = UnixStream::connect(&path)
        .unwrap_or_else(|e| panic!("connecting to WG UAPI socket {path}: {e}"));
    stream.write_all(b"get=1\n\n").expect("writing get=1 request");
    let mut resp = String::new();
    stream.read_to_string(&mut resp).expect("reading get=1 response");

    let mut out: std::collections::HashMap<String, GotPeer> = std::collections::HashMap::new();
    let mut current: Option<String> = None;
    for line in resp.lines() {
        if let Some(hex) = line.strip_prefix("public_key=") {
            current = Some(hex.to_string());
            out.entry(hex.to_string()).or_default();
        } else if let Some(ep) = line.strip_prefix("endpoint=") {
            if let Some(k) = &current {
                out.get_mut(k).unwrap().endpoint = Some(ep.to_string());
            }
        } else if let Some(cidr) = line.strip_prefix("allowed_ip=") {
            if let Some(k) = &current {
                out.get_mut(k).unwrap().allowed_ips.push(cidr.to_string());
            }
        }
    }
    out
}

/// PRIMARY: scoped endpoint update on peer C must re-point C and leave B
/// entirely untouched — proven against a real boringtun device's live peer
/// table (via UAPI `get=1`), not a builder.
#[test]
fn scoped_endpoint_update_touches_only_target_peer() {
    // Real embedded boringtun device (needs a privileged host; NOT netns).
    let tun = Tunnel::up(IFNAME, &b64_32(&DEV_PRIV), LISTEN_PORT, 1280)
        .expect("bringing up embedded boringtun device (needs privileged container)");
    let ifname = tun.ifname.clone();

    // Configure TWO peers, B and C, each with a distinct endpoint/CIDR.
    let cfg = DeviceConfig {
        private_key_b64: b64_32(&DEV_PRIV),
        listen_port: LISTEN_PORT,
        peers: vec![
            peer(&B_PUB, B_ENDPOINT, B_CIDR),
            peer(&C_PUB, C_ENDPOINT_ORIG, C_CIDR),
        ],
    };
    apply(&ifname, &cfg).expect("initial full apply of peers B and C");

    // Sanity precondition: both peers really landed before the scoped update.
    let before = read_peers(&ifname);
    assert_eq!(before.len(), 2, "precondition: both B and C configured: {before:?}");

    // SCOPED update: re-point ONLY peer C to a new endpoint (punch/relay path).
    let c_new = peer(&C_PUB, C_ENDPOINT_NEW, C_CIDR);
    set_one_peer(&ifname, &c_new).expect("scoped single-peer endpoint update on C");

    let after = read_peers(&ifname);
    let b_hex = hex32(&B_PUB);
    let c_hex = hex32(&C_PUB);

    // (1) Target C is PRESENT with the NEW endpoint. Catches the "remove
    //     succeeded but re-add was dropped → peer vanished / endpoint None"
    //     regression the scoped path was written to avoid.
    let c = after
        .get(&c_hex)
        .unwrap_or_else(|| panic!("BUG(re-add dropped): peer C vanished after scoped update: {after:?}"));
    assert_eq!(
        c.endpoint.as_deref(),
        Some(C_ENDPOINT_NEW),
        "BUG: peer C's endpoint must be the new value, not None/stale (re-add dropped): {c:?}"
    );

    // (2) Non-target B is STILL PRESENT with its ORIGINAL endpoint AND CIDR.
    //     Catches the "replace_peers reset every peer" regression.
    let b = after
        .get(&b_hex)
        .unwrap_or_else(|| panic!("BUG(replace_peers): peer B was reset by a scoped update: {after:?}"));
    assert_eq!(
        b.endpoint.as_deref(),
        Some(B_ENDPOINT),
        "BUG: peer B's endpoint must be untouched by a scoped update to C: {b:?}"
    );
    assert_eq!(
        b.allowed_ips,
        vec![B_CIDR.to_string()],
        "BUG: peer B's allowed_ips must be untouched by a scoped update to C: {b:?}"
    );

    // (3) Exactly TWO peers remain — none vanished, none duplicated.
    assert_eq!(
        after.len(),
        2,
        "BUG: peer count must stay 2 after a scoped update (no vanish, no dup): {after:?}"
    );
}
