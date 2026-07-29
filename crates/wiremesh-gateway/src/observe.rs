//! Authenticated NAT-observation probe (spec §5.4). Byte-for-byte identical to
//! `wiremesh_controller::observe::{build_probe, compute_mac}`; replicated here
//! (not shared) because the gateway must not depend on the controller crate and
//! 4b replaces this whole scheme with the WG-socket-authenticated probe. The
//! cross-process parity test (tests/observe_parity.rs) proves the controller
//! accepts what this builds.
use anyhow::Context;
use sha2::{Digest, Sha256};
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::io::FromRawFd;
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

/// Bind a UDP socket to `0.0.0.0:bind_port` with SO_REUSEPORT (shares the WG
/// listen port; spec §5.4 — 4a's routable/full-cone observation) and send one
/// authenticated probe, returning the observed public address.
pub fn report_once(
    bind_port: u16,
    server: SocketAddr,
    observe_key_hex: &str,
    gateway_id: u64,
) -> anyhow::Result<SocketAddr> {
    let sock = reuseport_udp(bind_port)?;
    probe_once(&sock, server, observe_key_hex, gateway_id)
}

/// Bind a UDP socket to `0.0.0.0:port` with `SO_REUSEADDR + SO_REUSEPORT`
/// (spec §5.4: the controller address-echo observation probe presents the
/// *same* source `ip:port` boringtun's own WG socket uses, so the controller
/// echoes back the public mapping the WG data plane will actually use). This
/// is the ONLY remaining `SO_REUSEPORT` socket in the gateway: it is transient
/// (one probe per `OBSERVE_PERIOD`, not the near-continuous §3 punch-socket
/// culprit) and genuinely needs its own socket to receive a non-WG reply —
/// explicitly kept out of scope by the puncher-socket-isolation cycle, which
/// removed the punch's use of it. `pub(crate)` for `report_once` above.
pub(crate) fn reuseport_udp(port: u16) -> anyhow::Result<UdpSocket> {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err(anyhow::anyhow!("socket(): {}", std::io::Error::last_os_error()));
        }
        let one: libc::c_int = 1;
        for opt in [libc::SO_REUSEADDR, libc::SO_REUSEPORT] {
            if libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                opt,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            ) != 0
            {
                libc::close(fd);
                return Err(anyhow::anyhow!("setsockopt: {}", std::io::Error::last_os_error()));
            }
        }
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr { s_addr: libc::INADDR_ANY.to_be() },
            sin_zero: [0; 8],
        };
        if libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        ) != 0
        {
            libc::close(fd);
            return Err(anyhow::anyhow!("bind(:{port}): {}", std::io::Error::last_os_error()));
        }
        Ok(UdpSocket::from_raw_fd(fd))
    }
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
