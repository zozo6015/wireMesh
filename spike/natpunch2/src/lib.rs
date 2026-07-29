//! Shared helpers for the puncher-socket-isolation de-risk spike
//! (spec 2026-07-28-puncher-socket-isolation-design.md "De-risk spike").
//!
//! IMPORTANT scope note: the ONLY `SO_REUSEPORT` socket in this whole spike is
//! the BRIEF one below, used purely to learn our post-NAT public mapping from
//! the controller address-echo (the design's `observe.rs` piece — explicitly
//! OUT OF SCOPE of the fix and genuinely needed to receive a non-WG reply). It
//! is opened, used for the echo, and dropped BEFORE boringtun binds the port.
//! There is NO punch socket and NO PING/PONG punch loop anywhere — the whole
//! point of this spike is to prove boringtun's OWN handshake init (from its own
//! socket, the only socket during the punch) opens the mapping. Contrast
//! spike/natpunch, whose gateway held a reuseport punch socket blasting PING at
//! peer candidates.

use anyhow::{Context, Result};
use std::net::{SocketAddr, UdpSocket};
use std::os::unix::io::FromRawFd;
use std::time::Duration;

/// Bind a UDP socket to `0.0.0.0:port` with `SO_REUSEADDR + SO_REUSEPORT` so it
/// presents the SAME source `ip:port` to the NAT as boringtun's WG socket will.
/// Used here ONLY for the transient public-mapping observation (see the module
/// note): endpoint-independent mapping (port-restricted NAT) guarantees the
/// external port this observes equals the one boringtun gets when it later binds
/// the same internal `ip:port`, so the observed candidate is the one boringtun
/// punches toward. Dropped before boringtun starts — never held during the punch.
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

/// Send `AOBS` to the observe server from `local` and return the post-NAT public
/// `ip:port` the server saw as our source.
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
