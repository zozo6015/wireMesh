//! Binds a local UDP socket, asks the observe server what our public address
//! looks like from its side, and prints it. Used both as a manual smoke tool
//! and (via CARGO_BIN_EXE_whoami) as the in-namespace client for tests.

fn main() -> anyhow::Result<()> {
    let server: std::net::SocketAddr = std::env::args()
        .nth(1)
        .expect("usage: whoami <server addr> <local port>")
        .parse()?;
    let port: u16 = std::env::args()
        .nth(2)
        .expect("usage: whoami <server addr> <local port>")
        .parse()?;
    let sock = std::net::UdpSocket::bind(("0.0.0.0", port))?;
    print!("{}", punch::observe(&sock, server)?);
    Ok(())
}
