// udpsink <addr:port> — binds the given address, waits for exactly one
// datagram, prints the sender's observed peer address/port, then exits.
// Used by tests/nat_behavior.rs to observe the *external* (post-NAT) source
// port a router maps a client flow to, by running one sink per server-side
// address and comparing what each one saw.
fn main() {
    let bind = std::env::args()
        .nth(1)
        .expect("usage: udpsink <addr:port>");
    let sock = std::net::UdpSocket::bind(&bind)
        .unwrap_or_else(|e| panic!("bind {bind}: {e}"));
    let mut buf = [0u8; 64];
    let (_, peer) = sock.recv_from(&mut buf).expect("recv_from");
    println!("PEER {peer}");
}
