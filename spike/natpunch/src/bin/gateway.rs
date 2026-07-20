//! Cycle 4b LINCHPIN de-risk gateway (spec §3). One process per gateway,
//! spawned inside its netns. Proves the transient-punch-socket approach:
//!
//!   1. Bind a transient `SO_REUSEPORT` UDP socket on the WG listen port.
//!   2. Observe our post-NAT public mapping from that socket.
//!   3. Register with the broker; on its back-to-back "go", punch (PING/PONG)
//!      at every peer candidate from that same socket for a bounded window,
//!      opening the NAT mapping+filter that boringtun's handshake will reuse.
//!   4. CLOSE the punch socket, leaving the WG port free.
//!   5. Bring boringtun up on that same WG port and set the peer endpoint to
//!      the peer's observed candidate — boringtun's handshake now leaves from
//!      the same source ip:port, so the NAT reuses the mapping the punch opened.
//!
//! Then it blocks (boringtun runs) so the test can observe the WG handshake and
//! ping across the tunnel. It always proceeds to boringtun even if the punch
//! failed, so the symmetric negative-control shows "no handshake", not a crash.

use anyhow::{Context, Result};
use boringtun::device::{DeviceConfig, DeviceHandle};
use std::io::{BufRead, BufReader, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::process::Command;
use std::time::{Duration, Instant};

#[derive(serde::Serialize)]
struct Reg {
    id: String,
    candidates: Vec<String>,
    pubkey: String,
    tun_ip: String,
}

#[derive(serde::Deserialize)]
struct Go {
    id: String,
    candidates: Vec<String>,
    pubkey: String,
    tun_ip: String,
}

fn sh(ns_cmd: &[&str]) -> Result<()> {
    let out = Command::new(ns_cmd[0]).args(&ns_cmd[1..]).output()
        .with_context(|| format!("spawn {ns_cmd:?}"))?;
    if !out.status.success() {
        anyhow::bail!("{ns_cmd:?} failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 9 {
        anyhow::bail!("usage: gateway <broker> <id> <wg_port> <observe> <ifname> <privkey_file> <my_pubkey_b64> <my_tun_cidr>");
    }
    let broker = &a[1];
    let id = &a[2];
    let wg_port: u16 = a[3].parse()?;
    let observe_srv: SocketAddr = a[4].parse()?;
    let ifname = &a[5];
    let privkey_file = &a[6];
    let my_pubkey = &a[7];
    let my_tun_cidr = &a[8];
    let my_tun_ip = my_tun_cidr.split('/').next().unwrap().to_string();

    // --- 1. transient SO_REUSEPORT punch socket on the WG listen port ---
    let punch_sock = natpunch::reuseport_udp(wg_port)?;

    // --- 2. observe our post-NAT public mapping from that same socket ---
    let observed = natpunch::observe(&punch_sock, observe_srv)
        .context("observing public mapping")?;
    eprintln!("gw {id}: observed public mapping = {observed}");

    // --- 3. register + wait for broker "go" ---
    let mut tcp = TcpStream::connect(broker).context("connect broker")?;
    let reg = Reg {
        id: id.clone(),
        candidates: vec![observed.to_string()],
        pubkey: my_pubkey.clone(),
        tun_ip: my_tun_ip.clone(),
    };
    writeln!(tcp, "{}", serde_json::to_string(&reg)?)?;
    let mut line = String::new();
    BufReader::new(tcp.try_clone()?).read_line(&mut line)?;
    let go: Go = serde_json::from_str(&line).context("parse go")?;
    eprintln!("gw {id}: go -> peer {} candidates={:?} tun={}", go.id, go.candidates, go.tun_ip);

    // --- punch: PING/PONG from the punch socket for a bounded window ---
    punch_sock.set_read_timeout(Some(Duration::from_millis(50)))?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut buf = [0u8; 64];
    let mut punched = false;
    let mut punched_from: Option<SocketAddr> = None;
    while Instant::now() < deadline {
        for c in &go.candidates {
            if let Ok(addr) = c.parse::<SocketAddr>() {
                if addr.ip().is_unspecified() || addr.ip().is_loopback() {
                    continue; // never dial wildcard/loopback (self-punch guard)
                }
                let _ = punch_sock.send_to(format!("PING {id}").as_bytes(), addr);
            }
        }
        if let Ok((n, from)) = punch_sock.recv_from(&mut buf) {
            let msg = String::from_utf8_lossy(&buf[..n]).to_string();
            if msg.starts_with("PING") {
                let _ = punch_sock.send_to(b"PONG", from);
            }
            if msg.starts_with("PONG") {
                punched = true;
                punched_from = Some(from);
            }
        }
    }
    eprintln!("gw {id}: punch window done punched={punched} from={punched_from:?}");

    // Endpoint boringtun will dial: the peer's registered (observed) candidate,
    // exactly what a real controller-driven gateway sets. On port-restricted NAT
    // this equals `punched_from`; on symmetric NAT it is knowingly the wrong port.
    let peer_endpoint = go.candidates.first().cloned()
        .context("peer advertised no candidate")?;

    // --- 4. CLOSE the transient punch socket, freeing the WG port ---
    drop(punch_sock);

    // --- 5. boringtun up on the same WG port; reuse the punched mapping ---
    let mut cfg = DeviceConfig::default();
    cfg.n_threads = 2;
    let handle = DeviceHandle::new(ifname, cfg)
        .map_err(|e| anyhow::anyhow!("DeviceHandle::new({ifname}): {e:?}"))?;

    sh(&[
        "wg", "set", ifname,
        "listen-port", &wg_port.to_string(),
        "private-key", privkey_file,
        "peer", &go.pubkey,
        "allowed-ips", &format!("{}/32", go.tun_ip),
        "endpoint", &peer_endpoint,
        "persistent-keepalive", "5",
    ])?;
    sh(&["ip", "addr", "add", my_tun_cidr, "dev", ifname])?;
    sh(&["ip", "link", "set", ifname, "up", "mtu", "1280"])?;

    // Machine-readable readiness line for the harness.
    println!("GWREADY id={id} observed={observed} peer_endpoint={peer_endpoint} punched={punched}");
    std::io::stdout().flush().ok();

    let mut handle = handle;
    handle.wait(); // block; boringtun drives the handshake + keepalives
    Ok(())
}
