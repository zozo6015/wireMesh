//! In-process WireGuard UAPI writer (spec §3, G-1: no `wg` dependency). Renders
//! and applies a full device config to boringtun's unix socket, exactly as
//! `wg syncconf` does: `replace_peers=true` + the complete peer list in one
//! atomic `set` message.
use anyhow::{anyhow, Context};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

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
}
