use anyhow::{Context, Result};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

/// Send the `AOBS` magic to `server` from `local` (an existing, already-bound
/// socket — the "from the WG socket" property a real gateway needs) and
/// return the address the server observed as our source, i.e. our post-NAT
/// public `ip:port`.
///
/// Retries a few times with a read timeout since UDP is unreliable.
pub fn observe(local: &UdpSocket, server: SocketAddr) -> Result<SocketAddr> {
    local.set_read_timeout(Some(Duration::from_secs(2)))?;
    for _ in 0..3 {
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
