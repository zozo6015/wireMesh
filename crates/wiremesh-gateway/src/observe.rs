//! Authenticated NAT-observation probe (spec §5.4). Byte-for-byte identical to
//! `wiremesh_controller::observe::{build_probe, compute_mac}`; replicated here
//! (not shared) because the gateway must not depend on the controller crate and
//! 4b replaces this whole scheme with the WG-socket-authenticated probe. The
//! cross-process parity test (tests/observe_parity.rs) proves the controller
//! accepts what this builds.
use anyhow::Context;
use sha2::{Digest, Sha256};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

pub const MAGIC: &[u8; 4] = b"AOBS";
pub const PROBE_LEN: usize = 4 + 8 + 32; // MAGIC + gateway_id(BE u64) + MAC

pub fn compute_mac(observe_key_hex: &str, gateway_id: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(observe_key_hex.as_bytes());
    h.update(MAGIC);
    h.update(gateway_id.to_be_bytes());
    h.finalize().into()
}

pub fn build_probe(observe_key_hex: &str, gateway_id: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(PROBE_LEN);
    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&gateway_id.to_be_bytes());
    buf.extend_from_slice(&compute_mac(observe_key_hex, gateway_id));
    buf
}

/// Send one authenticated probe from `sock` and return the observed public
/// `ip:port` the controller echoed back. Retries a few times (UDP is lossy).
pub fn probe_once(
    sock: &UdpSocket,
    server: SocketAddr,
    observe_key_hex: &str,
    gateway_id: u64,
) -> anyhow::Result<SocketAddr> {
    sock.set_read_timeout(Some(Duration::from_secs(2)))?;
    let probe = build_probe(observe_key_hex, gateway_id);
    for _ in 0..3 {
        sock.send_to(&probe, server)?;
        let mut buf = [0u8; 64];
        if let Ok((n, from)) = sock.recv_from(&mut buf) {
            if from == server {
                return String::from_utf8_lossy(&buf[..n])
                    .parse()
                    .context("parsing observed addr from controller echo");
            }
        }
    }
    anyhow::bail!("no observation reply from {server}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn build_probe_layout_and_mac_match_controller_construction() {
        let key = "00112233445566778899aabbccddeeff";
        let gid: u64 = 7;
        let probe = build_probe(key, gid);
        assert_eq!(probe.len(), PROBE_LEN);
        assert_eq!(&probe[0..4], MAGIC);
        assert_eq!(&probe[4..12], &gid.to_be_bytes());
        // MAC = sha256(observe_key || MAGIC || gateway_id_be)
        let mut h = Sha256::new();
        h.update(key.as_bytes());
        h.update(MAGIC);
        h.update(gid.to_be_bytes());
        let want: [u8; 32] = h.finalize().into();
        assert_eq!(&probe[12..44], &want);
        assert_eq!(compute_mac(key, gid), want);
    }
}
