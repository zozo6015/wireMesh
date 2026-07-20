//! Controller-side UDP observation endpoint (spec §5.4 / §3). Echoes back the
//! post-NAT source `ip:port` it sees on the wire — must be UDP (NATs map TCP/UDP
//! independently).
fn main() -> anyhow::Result<()> {
    let bind = std::env::args().nth(1).unwrap_or_else(|| "0.0.0.0:7777".into());
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
