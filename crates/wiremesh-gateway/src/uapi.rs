//! In-process WireGuard UAPI writer (spec §3, G-1: no `wg` dependency). Renders
//! and applies a full device config to boringtun's unix socket, exactly as
//! `wg syncconf` does: `replace_peers=true` + the complete peer list in one
//! atomic `set` message.
use anyhow::{anyhow, Context};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub public_key_b64: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub keepalive_secs: u16,
}

#[derive(Debug, Clone)]
pub struct DeviceConfig {
    pub private_key_b64: String,
    pub listen_port: u16,
    pub peers: Vec<PeerConfig>,
}

/// Decode a 32-byte WireGuard key from base64 to the lowercase-hex the UAPI
/// wire expects.
fn key_b64_to_hex(b64: &str) -> anyhow::Result<String> {
    let raw = base64_decode(b64).with_context(|| "decoding WG key from base64")?;
    if raw.len() != 32 {
        return Err(anyhow!("WG key must be 32 bytes, got {}", raw.len()));
    }
    Ok(raw.iter().map(|b| format!("{b:02x}")).collect())
}

pub fn encode_set(cfg: &DeviceConfig) -> anyhow::Result<String> {
    let mut s = String::new();
    s.push_str(&format!("private_key={}\n", key_b64_to_hex(&cfg.private_key_b64)?));
    s.push_str(&format!("listen_port={}\n", cfg.listen_port));
    s.push_str("replace_peers=true\n");
    for p in &cfg.peers {
        s.push_str(&format!("public_key={}\n", key_b64_to_hex(&p.public_key_b64)?));
        if let Some(ep) = &p.endpoint {
            s.push_str(&format!("endpoint={ep}\n"));
        }
        s.push_str("replace_allowed_ips=true\n");
        for cidr in &p.allowed_ips {
            s.push_str(&format!("allowed_ip={cidr}\n"));
        }
        s.push_str(&format!("persistent_keepalive_interval={}\n", p.keepalive_secs));
    }
    s.push('\n'); // blank line terminates the request
    Ok(s)
}

/// Derive the base64 WireGuard public key from a base64 private key.
pub fn base64_pub_from_priv(priv_b64: &str) -> anyhow::Result<String> {
    let raw = base64_decode(priv_b64)?;
    let arr: [u8; 32] = raw.as_slice().try_into()
        .map_err(|_| anyhow!("private key must be 32 bytes"))?;
    let secret = boringtun::x25519::StaticSecret::from(arr);
    let public = boringtun::x25519::PublicKey::from(&secret);
    Ok(base64_encode(public.as_bytes()))
}

pub fn apply(ifname: &str, cfg: &DeviceConfig) -> anyhow::Result<()> {
    let path = format!("/var/run/wireguard/{ifname}.sock");
    let mut stream = UnixStream::connect(&path)
        .with_context(|| format!("connecting to WG UAPI socket {path}"))?;
    let req = format!("set=1\n{}", encode_set(cfg)?);
    stream.write_all(req.as_bytes()).context("writing UAPI set request")?;
    let mut resp = String::new();
    stream.read_to_string(&mut resp).context("reading UAPI response")?;
    // Response is `errno=<n>\n\n`.
    let errno = resp
        .lines()
        .find_map(|l| l.strip_prefix("errno="))
        .ok_or_else(|| anyhow!("UAPI response missing errno: {resp:?}"))?;
    if errno != "0" {
        return Err(anyhow!("UAPI set failed: errno={errno}"));
    }
    Ok(())
}

// --- UAPI `get=1` read side (Task 9: path-state driver's handshake feed) ---

/// One peer's parsed state from a `get=1` UAPI response — currently only
/// the fields the path-state driver needs (spec §6.1: "authenticated
/// inbound ≈ latest-handshake advancing OR rx bytes increasing").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct PeerGetInfo {
    pub last_handshake_sec: u64,
    pub last_handshake_nsec: u64,
    pub rx_bytes: u64,
}

/// Parse a `get=1` UAPI response body into `{pubkey_hex -> PeerGetInfo}`.
/// Pure string parsing, no socket I/O, so it's unit-testable against a
/// fixture without a real WG device.
///
/// Wire format (a `public_key=<hex>` line starts each peer block; fields up
/// to the next `public_key=` line or end-of-response belong to that peer):
/// ```text
/// private_key=<hex>
/// listen_port=<n>
/// public_key=<hex>
/// last_handshake_time_sec=<n>
/// last_handshake_time_nsec=<n>
/// rx_bytes=<n>
/// ...
/// errno=0
///
/// ```
pub(crate) fn parse_get_response(resp: &str) -> HashMap<String, PeerGetInfo> {
    let mut out = HashMap::new();
    let mut current: Option<(String, PeerGetInfo)> = None;
    for line in resp.lines() {
        if let Some(hex) = line.strip_prefix("public_key=") {
            if let Some((key, info)) = current.take() {
                out.insert(key, info);
            }
            current = Some((hex.to_string(), PeerGetInfo::default()));
            continue;
        }
        let Some((_, info)) = current.as_mut() else {
            continue; // fields before the first public_key= (device-level) don't belong to any peer
        };
        if let Some(v) = line.strip_prefix("last_handshake_time_sec=") {
            info.last_handshake_sec = v.parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("last_handshake_time_nsec=") {
            info.last_handshake_nsec = v.parse().unwrap_or(0);
        } else if let Some(v) = line.strip_prefix("rx_bytes=") {
            info.rx_bytes = v.parse().unwrap_or(0);
        }
    }
    if let Some((key, info)) = current.take() {
        out.insert(key, info);
    }
    out
}

/// Reduce parsed `get=1` peer info to `{pubkey_hex -> SystemTime}` for
/// peers that HAVE handshaked at least once. A never-handshaked peer (both
/// `last_handshake_time_{sec,nsec}` are 0, the UAPI's zero-value default)
/// is simply absent from the map, rather than mapping to the Unix epoch —
/// which would be indistinguishable from a genuine handshake at time 0.
pub(crate) fn handshake_times_from(peers: &HashMap<String, PeerGetInfo>) -> HashMap<String, SystemTime> {
    peers
        .iter()
        .filter(|(_, info)| info.last_handshake_sec != 0 || info.last_handshake_nsec != 0)
        .map(|(k, info)| {
            let t = SystemTime::UNIX_EPOCH
                + Duration::from_secs(info.last_handshake_sec)
                + Duration::from_nanos(info.last_handshake_nsec);
            (k.clone(), t)
        })
        .collect()
}

/// Read the WireGuard device's per-peer latest-handshake times via UAPI
/// `get=1` — the read side of [`apply`]'s writer. Returns `{pubkey_hex ->
/// SystemTime}`; see [`handshake_times_from`] for why never-handshaked
/// peers are absent rather than epoch-valued.
pub fn get_latest_handshakes(ifname: &str) -> anyhow::Result<HashMap<String, SystemTime>> {
    let peers = read_get_response(ifname)?;
    Ok(handshake_times_from(&peers))
}

/// Reduce parsed `get=1` peer info to `{pubkey_hex -> (latest_handshake,
/// rx_bytes)}`. `latest_handshake` is `None` for a never-handshaked peer,
/// per [`handshake_times_from`]'s epoch-ambiguity rationale; `rx_bytes` is
/// always present (0 for a peer with no traffic yet).
///
/// `rx_bytes` is the point of this reducer (review finding, Cycle 4b Task
/// 10): the path-state driver's ~1s tick only ever called `on_handshake`,
/// but WG handshakes advance only ~every 120s (rekey) while keepalives (15s)
/// bump `rx_bytes` without touching the handshake time. Watching
/// `rx_bytes` for an increase since the previous tick gives the driver a
/// keepalive-visible liveness signal (`Path::on_authenticated_inbound`), so
/// a healthy `Direct` path no longer oscillates to `Degraded` every ~45s.
/// See `docs/research/cycle4b-path-liveness-note.md`.
pub(crate) fn peer_liveness_from(
    peers: &HashMap<String, PeerGetInfo>,
) -> HashMap<String, (Option<SystemTime>, u64)> {
    let times = handshake_times_from(peers);
    peers
        .iter()
        .map(|(k, info)| (k.clone(), (times.get(k).copied(), info.rx_bytes)))
        .collect()
}

/// Read the WireGuard device's per-peer latest-handshake time AND `rx_bytes`
/// via UAPI `get=1` in a single round-trip — the liveness feed the
/// path-state driver uses (see [`peer_liveness_from`]). Returns
/// `{pubkey_hex -> (latest_handshake, rx_bytes)}`.
pub fn get_peer_liveness(ifname: &str) -> anyhow::Result<HashMap<String, (Option<SystemTime>, u64)>> {
    let peers = read_get_response(ifname)?;
    Ok(peer_liveness_from(&peers))
}

/// Shared UAPI `get=1` round-trip: connect, request, read the full response,
/// and parse it. Both [`get_latest_handshakes`] and [`get_peer_liveness`]
/// build on this so there's exactly one socket dance to get right.
fn read_get_response(ifname: &str) -> anyhow::Result<HashMap<String, PeerGetInfo>> {
    let path = format!("/var/run/wireguard/{ifname}.sock");
    let mut stream = UnixStream::connect(&path)
        .with_context(|| format!("connecting to WG UAPI socket {path}"))?;
    stream.write_all(b"get=1\n\n").context("writing UAPI get request")?;
    let mut resp = String::new();
    stream.read_to_string(&mut resp).context("reading UAPI get response")?;
    Ok(parse_get_response(&resp))
}

// --- minimal base64 (avoid a new workspace dep for two 32-byte keys) ---
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub(crate) fn base64_encode(input: &[u8]) -> String {
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { B64[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[(n & 63) as usize] as char } else { '=' });
    }
    out
}

pub(crate) fn base64_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    fn val(c: u8) -> anyhow::Result<u32> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(anyhow!("invalid base64 char")),
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|&c| c != b'=' && !c.is_ascii_whitespace()).collect();
    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 { out.push((n >> 8) as u8); }
        if chunk.len() > 3 { out.push(n as u8); }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(bytes: &[u8; 32]) -> String {
        // base64 of a fixed key for a stable expectation
        base64_encode(bytes)
    }

    #[test]
    fn encode_set_renders_device_then_peer_blocks() {
        let priv_raw = [0x11u8; 32];
        let pub_raw = [0x22u8; 32];
        let cfg = DeviceConfig {
            private_key_b64: b64(&priv_raw),
            listen_port: 51820,
            peers: vec![PeerConfig {
                public_key_b64: b64(&pub_raw),
                endpoint: Some("203.0.113.5:51820".into()),
                allowed_ips: vec!["10.10.2.0/24".into()],
                keepalive_secs: 15,
            }],
        };
        let out = encode_set(&cfg).unwrap();
        let priv_hex = "11".repeat(32);
        let pub_hex = "22".repeat(32);
        let expected = format!(
            "private_key={priv_hex}\n\
             listen_port=51820\n\
             replace_peers=true\n\
             public_key={pub_hex}\n\
             endpoint=203.0.113.5:51820\n\
             replace_allowed_ips=true\n\
             allowed_ip=10.10.2.0/24\n\
             persistent_keepalive_interval=15\n\
             \n"
        );
        assert_eq!(out, expected);
    }

    #[test]
    fn peer_without_endpoint_omits_endpoint_line() {
        let cfg = DeviceConfig {
            private_key_b64: base64_encode(&[0u8; 32]),
            listen_port: 1,
            peers: vec![PeerConfig {
                public_key_b64: base64_encode(&[1u8; 32]),
                endpoint: None,
                allowed_ips: vec!["10.0.0.0/8".into()],
                keepalive_secs: 15,
            }],
        };
        let out = encode_set(&cfg).unwrap();
        assert!(!out.contains("endpoint="), "no endpoint line when None:\n{out}");
    }

    /// A realistic two-peer `get=1` response: one peer with a recorded
    /// handshake + rx traffic, one that has never handshaked (all-zero
    /// handshake/traffic fields) — the fixture the brief asked for.
    const GET_RESPONSE_FIXTURE: &str = "\
private_key=1111111111111111111111111111111111111111111111111111111111111111\n\
listen_port=51820\n\
public_key=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n\
endpoint=203.0.113.5:51820\n\
last_handshake_time_sec=1700000000\n\
last_handshake_time_nsec=500000000\n\
rx_bytes=12345\n\
tx_bytes=6789\n\
persistent_keepalive_interval=15\n\
allowed_ip=10.10.2.5/32\n\
public_key=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n\
last_handshake_time_sec=0\n\
last_handshake_time_nsec=0\n\
rx_bytes=0\n\
tx_bytes=0\n\
persistent_keepalive_interval=15\n\
allowed_ip=10.10.2.6/32\n\
errno=0\n\
\n";

    #[test]
    fn parse_get_response_extracts_both_peers() {
        let parsed = parse_get_response(GET_RESPONSE_FIXTURE);
        assert_eq!(parsed.len(), 2, "both peers parsed: {parsed:?}");

        let a = parsed
            .get("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .expect("peer a present");
        assert_eq!(a.last_handshake_sec, 1700000000);
        assert_eq!(a.last_handshake_nsec, 500000000);
        assert_eq!(a.rx_bytes, 12345);

        let b = parsed
            .get("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .expect("peer b present");
        assert_eq!(b.last_handshake_sec, 0);
        assert_eq!(b.last_handshake_nsec, 0);
        assert_eq!(b.rx_bytes, 0);
    }

    #[test]
    fn handshake_times_from_omits_never_handshaked_peer() {
        let parsed = parse_get_response(GET_RESPONSE_FIXTURE);
        let times = handshake_times_from(&parsed);

        assert_eq!(times.len(), 1, "only the handshaked peer should appear: {times:?}");
        let a_time = times
            .get("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .expect("handshaked peer present");
        assert_eq!(
            *a_time,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1700000000) + Duration::from_nanos(500000000)
        );
        assert!(
            !times.contains_key("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
            "never-handshaked peer must be absent, not epoch-valued: {times:?}"
        );
    }

    #[test]
    fn peer_liveness_from_preserves_rx_bytes_for_both_peers() {
        let parsed = parse_get_response(GET_RESPONSE_FIXTURE);
        let liveness = peer_liveness_from(&parsed);
        assert_eq!(liveness.len(), 2, "both peers present, unlike handshake_times_from: {liveness:?}");

        let (a_time, a_rx) = liveness
            .get("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .expect("peer a present");
        assert_eq!(
            *a_time,
            Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1700000000) + Duration::from_nanos(500000000))
        );
        assert_eq!(*a_rx, 12345, "handshaked peer's rx_bytes preserved");

        let (b_time, b_rx) = liveness
            .get("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .expect("peer b present even though never handshaked");
        assert_eq!(*b_time, None, "never-handshaked peer still has no handshake time");
        assert_eq!(*b_rx, 0, "never-handshaked peer's rx_bytes preserved (0)");
    }

    #[test]
    fn parse_get_response_ignores_device_level_fields_before_first_peer() {
        // private_key=/listen_port= precede the first public_key= line and
        // must not be misattributed to a peer or panic the parser.
        let resp = "private_key=deadbeef\nlisten_port=51820\nerrno=0\n\n";
        let parsed = parse_get_response(resp);
        assert!(parsed.is_empty(), "no peers in response: {parsed:?}");
    }
}
