//! Spike version of Sync-brokered simultaneous hole punching (spec §6.1).
//!
//! Accepts exactly two TCP registrations, each a single JSON line
//! `{"id":"A","candidates":["ip:port",...]}`, then relays each peer's
//! candidates to the other as a single JSON line
//! `{"peer":"<id>","candidates":[...],"go":true}`, writing both replies back
//! to back on the accepting thread so the two "go" signals leave as close to
//! simultaneously as a single-threaded broker can manage. Exits once both
//! sides have been told to go — this is a one-shot spike broker, not a
//! long-running service.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

#[derive(serde::Deserialize)]
struct Reg {
    id: String,
    candidates: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    let bind = std::env::args()
        .nth(1)
        .expect("usage: broker <bind_tcp>");
    let l = TcpListener::bind(&bind)?;
    eprintln!("broker: on {bind}");

    let mut conns = vec![];
    for _ in 0..2 {
        let (s, peer) = l.accept()?;
        let mut line = String::new();
        BufReader::new(s.try_clone()?).read_line(&mut line)?;
        let reg: Reg = serde_json::from_str(&line)?;
        eprintln!("broker: registered {} from {peer}", reg.id);
        conns.push((s, reg));
    }

    let (mut s0, r0) = conns.remove(0);
    let (mut s1, r1) = conns.remove(0);
    let m0 = format!(
        "{{\"peer\":\"{}\",\"candidates\":{},\"go\":true}}\n",
        r1.id,
        serde_json::to_string(&r1.candidates)?
    );
    let m1 = format!(
        "{{\"peer\":\"{}\",\"candidates\":{},\"go\":true}}\n",
        r0.id,
        serde_json::to_string(&r0.candidates)?
    );
    // Near-simultaneous "go": write both before doing anything else so
    // neither side gets an appreciable head start.
    s0.write_all(m0.as_bytes())?;
    s1.write_all(m1.as_bytes())?;
    eprintln!("broker: go sent to both, exiting");
    Ok(())
}
