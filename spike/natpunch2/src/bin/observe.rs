//! Controller-side UDP observation endpoint (unchanged from spike/natpunch).
//! Echoes back the post-NAT source `ip:port` it sees on the wire — must be UDP
//! (NATs map TCP/UDP independently).
fn main() -> anyhow::Result<()> {
    let bind = std::env::args().nth(1).unwrap_or_else(|| "0.0.0.0:7777".into());
    let sock = std::net::UdpSocket::bind(&bind)?;
    eprintln!("observe: listening on {bind}");
    let mut buf = [0u8; 16];
    loop {
        // Don't `?`-propagate recv errors: a stray ICMP "port unreachable"
        // surfaces as a recv error on a connectionless UDP socket and would
        // otherwise fatally terminate the observe server. Log and keep serving.
        match sock.recv_from(&mut buf) {
            Ok((n, peer)) => {
                if n >= 4 && &buf[..4] == b"AOBS" {
                    let _ = sock.send_to(peer.to_string().as_bytes(), peer);
                }
            }
            Err(e) => eprintln!("observe recv error: {e}"),
        }
    }
}
