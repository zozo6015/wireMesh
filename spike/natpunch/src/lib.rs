//! Shared helpers for the Cycle 4b NAT-traversal de-risk (spec §3).
use anyhow::{Context, Result};
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::io::FromRawFd;
use std::time::Duration;

/// Bind a UDP socket to `0.0.0.0:port` with `SO_REUSEADDR + SO_REUSEPORT`, so it
/// presents the *same* source `ip:port` to the NAT as boringtun's WG socket will
/// (spec §3 "the transient punch socket"). Byte-for-byte the same technique 4a's
/// `wiremesh_gateway::observe::reuseport_udp` uses.
pub fn reuseport_udp(port: u16) -> Result<UdpSocket> {
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

/// Send `AOBS` to the observe server from `local` and return the post-NAT
/// public `ip:port` the server saw as our source. Uses the exact socket the
/// punch will run on, so the observed mapping is the one the punch reuses.
pub fn observe(local: &UdpSocket, server: SocketAddr) -> Result<SocketAddr> {
    local.set_read_timeout(Some(Duration::from_secs(2)))?;
    for _ in 0..5 {
        local.send_to(b"AOBS", server)?;
        let mut buf = [0u8; 64];
        if let Ok((n, from)) = local.recv_from(&mut buf) {
            if from == server {
                return String::from_utf8_lossy(&buf[..n])
                    .parse()
                    .context("parse observed addr");
            }
        }
    }
    anyhow::bail!("no observation reply from {server}")
}
