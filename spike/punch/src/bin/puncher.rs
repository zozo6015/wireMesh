//! Spike puncher: observes its own post-NAT mapping (Task 11's
//! `punch::observe`, reusing the *same* local UDP socket the punch itself
//! will run on — the mapping only holds for a real port-restricted NAT if we
//! punch out of the socket we just observed with), registers with the
//! broker, and on "go" blasts `PING <id>` at every candidate the broker
//! handed back while listening for a reply.
//!
//! Port-restricted NATs: both sides open a mapping to (roughly) the peer's
//! address at close to the same time, so each side's PING arrives after the
//! local mapping exists and is accepted. Symmetric NATs: the mapping the
//! observe server saw is *only* valid for packets to the observe server's
//! address — the mapping used against the peer is a different, unpredictable
//! port, so the candidate we registered is simply the wrong port and punching
//! is expected to fail. That negative result is the point of Bet 4: it's
//! exactly the case that needs a relay.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::{Duration, Instant};

#[derive(serde::Deserialize)]
struct Go {
    candidates: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 5 {
        anyhow::bail!("usage: puncher <broker_tcp> <id> <local_udp_port> <observe_server>");
    }
    let broker = &a[1];
    let id = &a[2];
    let port: u16 = a[3].parse()?;
    let obs = a[4].parse()?;

    let sock = UdpSocket::bind(("0.0.0.0", port))?;
    // Observe from the exact socket we're about to punch with, so the
    // mapping the NAT created for the observation is the same mapping (for
    // port-restricted cones) the peer's packets will land on.
    let observed = punch::observe(&sock, obs)?;
    eprintln!("puncher {id}: observed as {observed}");

    // Deviation from the brief's sketch: do NOT advertise a "0.0.0.0:{port}"
    // local candidate. sendto() to 0.0.0.0 is rewritten by the kernel to
    // 127.0.0.1, so a peer that dials it PINGs *itself* over loopback and
    // self-PONGs instantly — a false-positive punch that always beats the
    // real cross-NAT round trip (and falsely "punches" even the symmetric
    // cell). In this lab the observed post-NAT candidate is the only useful
    // one anyway; a real gateway would advertise an actual bound interface
    // address, never the wildcard.
    let mut tcp = TcpStream::connect(broker)?;
    writeln!(tcp, "{{\"id\":\"{id}\",\"candidates\":[\"{observed}\"]}}")?;
    let mut line = String::new();
    BufReader::new(tcp.try_clone()?).read_line(&mut line)?;
    let go: Go = serde_json::from_str(&line)?;
    eprintln!("puncher {id}: go, candidates={:?}", go.candidates);

    sock.set_read_timeout(Some(Duration::from_millis(50)))?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = [0u8; 64];
    while Instant::now() < deadline {
        for c in &go.candidates {
            if let Ok(addr) = c.parse::<std::net::SocketAddr>() {
                // Defensive: never dial wildcard/loopback candidates. The
                // kernel rewrites sendto(0.0.0.0) to 127.0.0.1, so dialing
                // one would make us PING ourselves and self-PONG — a
                // spurious "PUNCHED" that masks real punch failure.
                if addr.ip().is_unspecified() || addr.ip().is_loopback() {
                    continue;
                }
                let _ = sock.send_to(format!("PING {id}").as_bytes(), addr);
            }
        }
        if let Ok((n, from)) = sock.recv_from(&mut buf) {
            let msg = String::from_utf8_lossy(&buf[..n]).to_string();
            if msg.starts_with("PING") {
                let _ = sock.send_to(b"PONG", from);
            }
            if msg.starts_with("PONG") {
                println!("PUNCHED {from}");
                return Ok(());
            }
        }
    }
    eprintln!("puncher {id}: punch failed (timeout)");
    std::process::exit(1);
}
