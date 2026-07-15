// udpsend <target...> — binds one client-side UDP socket on port 6000 and
// sends a single datagram to each target address given as an argument,
// 100ms apart. Used by tests/nat_behavior.rs: sending from ONE socket to
// multiple destinations is what makes the test's port comparison meaningful
// (endpoint-independent vs endpoint-dependent NAT mapping is a per-*source*-
// socket property).
fn main() {
    let sock = std::net::UdpSocket::bind("0.0.0.0:6000").expect("bind 0.0.0.0:6000");
    for target in std::env::args().skip(1) {
        sock.send_to(b"x", &target)
            .unwrap_or_else(|e| panic!("send_to {target}: {e}"));
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
