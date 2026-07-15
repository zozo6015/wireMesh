//! Spike version of the controller's UDP observation endpoint (spec §6.1).
//!
//! TCP-observed addresses are useless here because NATs map TCP/UDP
//! independently, so this endpoint MUST be UDP and MUST reply with the
//! post-NAT source address it actually sees on the wire.

fn main() -> anyhow::Result<()> {
    let bind = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "0.0.0.0:7777".into());
    let sock = std::net::UdpSocket::bind(&bind)?;
    eprintln!("observe: listening on {bind}");
    let mut buf = [0u8; 16];
    loop {
        let (n, peer) = sock.recv_from(&mut buf)?;
        if n >= 4 && &buf[..4] == b"AOBS" {
            sock.send_to(peer.to_string().as_bytes(), peer)?;
        }
    }
}
