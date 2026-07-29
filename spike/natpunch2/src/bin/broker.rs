//! Minimal broker for simultaneous hole punching (unchanged from spike/natpunch;
//! the design keeps the controller broker + PunchDirective go-coordination as-is).
//! Accepts exactly two TCP registrations
//! `{"id","candidates":[...],"pubkey":...,"tun_ip":...}`, then relays each peer's
//! candidates+pubkey to the other and fires a near-simultaneous "go" by writing
//! both replies back-to-back on one thread (µs-scale skew).
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

#[derive(serde::Deserialize, serde::Serialize)]
struct Reg {
    id: String,
    candidates: Vec<String>,
    pubkey: String,
    tun_ip: String,
}

fn main() -> anyhow::Result<()> {
    let bind = std::env::args().nth(1).expect("usage: broker <bind_tcp>");
    let l = TcpListener::bind(&bind)?;
    eprintln!("broker: on {bind}");

    let mut conns = vec![];
    for _ in 0..2 {
        let (s, peer) = l.accept()?;
        let mut line = String::new();
        BufReader::new(s.try_clone()?).read_line(&mut line)?;
        let reg: Reg = serde_json::from_str(&line)?;
        eprintln!("broker: registered {} from {peer} candidates={:?}", reg.id, reg.candidates);
        conns.push((s, reg));
    }

    let (mut s0, r0) = conns.remove(0);
    let (mut s1, r1) = conns.remove(0);
    let m0 = serde_json::to_string(&r1)? + "\n";
    let m1 = serde_json::to_string(&r0)? + "\n";
    s0.write_all(m0.as_bytes())?;
    s1.write_all(m1.as_bytes())?;
    eprintln!("broker: go sent to both, exiting");
    Ok(())
}
