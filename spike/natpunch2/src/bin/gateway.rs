//! Puncher-socket-isolation de-risk gateway (spec 2026-07-28 "De-risk spike").
//! One process per gateway, spawned inside its netns. Proves approach B: the
//! punch is driven ENTIRELY by boringtun's own endpoint-set handshake — there is
//! NO separate SO_REUSEPORT punch socket and NO PING/PONG punch loop anywhere.
//!
//!   1. BRIEFLY observe our post-NAT public mapping via a reuseport socket
//!      (the address-echo — the design's out-of-scope-but-needed transient
//!      socket), then DROP it, freeing the WG port.  <-- the only reuseport use
//!   2. Register with the broker; wait for its back-to-back "go".
//!   3. Bring a REAL boringtun device up on the WG port and set the peer
//!      endpoint to the peer's observed candidate via the UAPI writer (`wg set`).
//!      boringtun now emits handshake initiations from :51820 toward that
//!      endpoint — THAT is the punch. No manual probe is sent.
//!   4. Measure how long after endpoint-set a real WG handshake completes WITH
//!      rx corroboration (received bytes > 0 — real bytes crossing, not just a
//!      handshake-time advance; mirrors path.rs's rx-corroborated liveness).
//!
//! It always proceeds to boringtun even if nothing completes, so a NO-GO shows
//! "no handshake", not a crash. Prints machine-readable evidence lines the
//! harness parses:  ENDPOINT_SET, HANDSHAKE_OK / HANDSHAKE_NONE, GWREADY.

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

/// (latest_handshake_unix, received_bytes) for wg0's single peer, via the UAPI
/// (`wg show`). handshake==0 => never handshaked. received>0 corroborates that
/// real bytes crossed (the handshake RESPONSE came back), matching path.rs's
/// rx-corroborated liveness — a handshake-time advance alone is NOT accepted.
fn peer_state(ifname: &str) -> (u64, u64) {
    // `timeout 3` guards every UAPI read: boringtun's userspace `wg` socket can
    // stall (observed: `wg show` wedged in unix_stream_read). On stall the child
    // is killed (exit 124, empty stdout) and this simply reads 0 this tick.
    let hs = Command::new("timeout").args(["3", "wg", "show", ifname, "latest-handshakes"]).output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).lines()
            .filter_map(|l| l.split_whitespace().last().and_then(|s| s.parse::<u64>().ok()))
            .max().unwrap_or(0))
        .unwrap_or(0);
    let rx = Command::new("timeout").args(["3", "wg", "show", ifname, "transfer"]).output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).lines()
            // transfer line: <pubkey>\t<received>\t<sent>
            .filter_map(|l| { let mut it = l.split_whitespace(); it.next(); it.next().and_then(|s| s.parse::<u64>().ok()) })
            .max().unwrap_or(0))
        .unwrap_or(0);
    (hs, rx)
}

fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 9 {
        anyhow::bail!("usage: gateway <broker> <id> <wg_port> <observe> <ifname> <privkey_file> <my_pubkey_b64> <my_tun_cidr> [keepalive_secs]");
    }
    let broker = &a[1];
    let id = &a[2];
    let wg_port: u16 = a[3].parse()?;
    let observe_srv: SocketAddr = a[4].parse()?;
    let ifname = &a[5];
    let privkey_file = &a[6];
    let my_pubkey = &a[7];
    let my_tun_cidr = &a[8];
    // Default 25s = the production PERSISTENT_KEEPALIVE_SECS (reconcile.rs). The
    // handshake-retry cadence that actually re-punches is boringtun's own ~5s
    // REKEY_TIMEOUT, independent of this; keepalive only holds the mapping open
    // once established. Overridable so we can probe whether it matters.
    let keepalive: u16 = a.get(9).and_then(|s| s.parse().ok()).unwrap_or(25);
    let my_tun_ip = my_tun_cidr.split('/').next().unwrap().to_string();

    // --- 1. BRIEF reuseport observe of our public mapping, then DROP it ---
    // This is the ONLY reuseport socket in the spike; it is gone before boringtun
    // binds the port. No punch is sent from it.
    let observed = {
        let obs_sock = natpunch2::reuseport_udp(wg_port)?;
        let o = natpunch2::observe(&obs_sock, observe_srv).context("observing public mapping")?;
        // obs_sock dropped here — WG port is free for boringtun.
        o
    };
    eprintln!("gw {id}: observed public mapping = {observed} (reuseport observe socket now closed)");

    // --- 2. register + wait for broker "go" ---
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

    let peer_endpoint = go.candidates.first().cloned()
        .context("peer advertised no candidate")?;

    // --- 3. REAL boringtun up on the WG port; NO punch socket exists ---
    let mut cfg = DeviceConfig::default();
    cfg.n_threads = 2;
    let mut handle = DeviceHandle::new(ifname, cfg)
        .map_err(|e| anyhow::anyhow!("DeviceHandle::new({ifname}): {e:?}"))?;

    // Device-level config first (listen-port + private key), NO peer yet.
    // NOTE: boringtun 0.6.0 cannot MODIFY an existing peer — a second `wg set`
    // that adds an endpoint to an already-configured peer panics the device
    // thread ("Modifying existing peers is not yet supported. Remove and add
    // again instead.", device/mod.rs:321). So the peer must be created in ONE
    // write with its endpoint already present (below) — never add-then-modify.
    sh(&[
        "timeout", "5",
        "wg", "set", ifname,
        "listen-port", &wg_port.to_string(),
        "private-key", privkey_file,
    ])?;
    sh(&["ip", "addr", "add", my_tun_cidr, "dev", ifname])?;
    sh(&["ip", "link", "set", ifname, "up", "mtu", "1280"])?;

    // THE punch: ADD the peer WITH its endpoint in a single UAPI write. This one
    // add is what makes boringtun start emitting handshake initiations from
    // :51820 toward the peer endpoint — the punch, driven purely by boringtun's
    // own socket (approach B: no separate SO_REUSEPORT punch socket). The clock
    // starts here, measuring peer-add-with-endpoint -> rx-corroborated handshake
    // (this mirrors production, which adds a peer with its endpoint in one go).
    let t0 = Instant::now();
    sh(&[
        "timeout", "5",
        "wg", "set", ifname,
        "peer", &go.pubkey,
        "endpoint", &peer_endpoint,
        "allowed-ips", &format!("{}/32", go.tun_ip),
        "persistent-keepalive", &keepalive.to_string(),
    ])?;
    println!("ENDPOINT_SET id={id} peer_endpoint={peer_endpoint} keepalive={keepalive}");
    std::io::stdout().flush().ok();

    // --- 4. measure endpoint-set -> rx-corroborated handshake ---
    let budget = Duration::from_secs(30);
    let mut done = false;
    let mut first_hs_ms: Option<u128> = None; // first handshake-time advance (may precede rx)
    while t0.elapsed() < budget {
        std::thread::sleep(Duration::from_millis(100));
        let (hs, rx) = peer_state(ifname);
        if hs > 0 && first_hs_ms.is_none() {
            first_hs_ms = Some(t0.elapsed().as_millis());
        }
        if hs > 0 && rx > 0 {
            println!(
                "HANDSHAKE_OK id={id} elapsed_ms={} first_hs_ms={} rx_bytes={}",
                t0.elapsed().as_millis(),
                first_hs_ms.unwrap_or(0),
                rx
            );
            std::io::stdout().flush().ok();
            done = true;
            break;
        }
    }
    if !done {
        let (hs, rx) = peer_state(ifname);
        println!("HANDSHAKE_NONE id={id} last_handshake={hs} rx_bytes={rx} first_hs_ms={first_hs_ms:?}");
        std::io::stdout().flush().ok();
    }

    println!("GWREADY id={id} observed={observed} peer_endpoint={peer_endpoint} done={done}");
    std::io::stdout().flush().ok();

    handle.wait(); // block; boringtun keeps running so the harness can probe wg0
    Ok(())
}
