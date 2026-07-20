//! Same-socket hole puncher (spec §3, Cycle 4b "Decision — the transient
//! punch socket"). Graduates `spike/natpunch`'s proven punch loop
//! (`docs/research/` de-risk report, PUNCH-WORKS verdict) into the gateway
//! crate.
//!
//! The central trick (spec §3): a `SO_REUSEPORT` socket bound to the SAME
//! `bind_port` boringtun listens on presents the identical source `ip:port`
//! to the NAT, so a punch this socket sends to a peer candidate opens
//! exactly the mapping boringtun's later handshake to that candidate will
//! reuse (conntrack keys on the 4-tuple, not on which local socket sent the
//! packet). In production boringtun is ALREADY bound to `bind_port`
//! continuously; this transient socket binds CONCURRENTLY alongside it via
//! `SO_REUSEPORT`. Inbound datagrams during the punch window may hash to
//! either socket, so this function relies ONLY on its own PING/PONG
//! exchange for confirmation — never assume boringtun's socket "helped" —
//! and it closes (drops) its socket promptly on return so boringtun's
//! socket is the sole listener for the ensuing WG handshake.
use crate::observe::reuseport_udp;
use anyhow::Result;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// How often each candidate is re-blasted with `PING` while the window is
/// open. Short enough to reopen a NAT mapping/filter promptly after the
/// conntrack-poisoning hazard (spec §3/§7), long enough not to flood.
const PING_INTERVAL: Duration = Duration::from_millis(200);

/// `recv_from` timeout used while waiting between cadence ticks — short so a
/// `PONG` (or inbound `PING` to answer) is noticed promptly without
/// busy-spinning the CPU for the whole `window`.
const RECV_POLL: Duration = Duration::from_millis(50);

/// Punch every valid candidate in `candidates` from a transient same-port
/// `SO_REUSEPORT` socket for up to `window`, and return the first candidate
/// confirmed reachable.
///
/// - Skips loopback, unspecified (e.g. `0.0.0.0:...`), and unparseable
///   candidates (the self-punch guard `spike/natpunch` uses).
/// - Sends `PING` to every remaining candidate on a ~200ms cadence for the
///   full `window`, tolerating individual `send_to`/`recv_from` failures
///   (the conntrack-poisoning window a zero-latency link would expose —
///   spec §7 — is exactly why this retries rather than bailing on the first
///   error).
/// - Replies `PONG` to any inbound `PING` (bidirectional: this makes the
///   peer's own `punch_candidates` call confirm too, mirroring
///   `spike/natpunch`'s gateway loop), and treats any inbound `PONG` as
///   confirmation of the address it arrived from.
/// - Returns `Ok(None)` if nothing confirms within `window` (e.g. a
///   symmetric-NAT peer whose registered candidate is the wrong
///   per-destination port — the documented relay-needed case, spec §1/§6).
/// - Drops the transient socket on return (success, timeout, or error) —
///   `bind_port` is free again for boringtun's own listener.
pub fn punch_candidates(
    bind_port: u16,
    candidates: &[String],
    window: Duration,
) -> Result<Option<SocketAddr>> {
    let sock = reuseport_udp(bind_port)?;
    sock.set_read_timeout(Some(RECV_POLL))?;

    let targets: Vec<SocketAddr> = candidates
        .iter()
        .filter_map(|c| c.parse::<SocketAddr>().ok())
        .filter(|addr| !addr.ip().is_unspecified() && !addr.ip().is_loopback())
        .collect();

    let deadline = Instant::now() + window;
    // Fire the first PING immediately rather than waiting a full interval.
    let mut last_ping = Instant::now() - PING_INTERVAL;
    let mut buf = [0u8; 64];
    let mut confirmed: Option<SocketAddr> = None;

    while Instant::now() < deadline {
        if last_ping.elapsed() >= PING_INTERVAL {
            for addr in &targets {
                // Tolerate send failures (e.g. transient ICMP unreachable
                // from the not-yet-open NAT mapping) — keep blasting for the
                // full window rather than aborting on the first one.
                let _ = sock.send_to(b"PING", *addr);
            }
            last_ping = Instant::now();
        }
        match sock.recv_from(&mut buf) {
            Ok((n, from)) => {
                let msg = &buf[..n];
                if msg.starts_with(b"PING") {
                    let _ = sock.send_to(b"PONG", from);
                } else if msg.starts_with(b"PONG") {
                    confirmed = Some(from);
                    break;
                }
            }
            Err(_) => {} // read timeout — loop back, maybe re-blast
        }
    }

    Ok(confirmed)
    // `sock` drops here (RAII) — closing the transient socket frees
    // `bind_port` for boringtun's own bind.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_loopback_unspecified_and_malformed_candidates_and_times_out() {
        // None of these are dialable: malformed, unspecified, loopback. No
        // peer will ever PONG, so this must return None promptly rather than
        // hang for the full window semantics being violated.
        let candidates = vec![
            "not-an-addr".to_string(),
            "0.0.0.0:9999".to_string(),
            "127.0.0.1:9999".to_string(),
        ];
        let start = Instant::now();
        let window = Duration::from_millis(300);
        let result = punch_candidates(0, &candidates, window).unwrap();
        assert!(result.is_none(), "no candidate is dialable, so nothing can confirm");
        assert!(
            start.elapsed() >= window,
            "must wait out the full window before giving up"
        );
    }

    #[test]
    fn empty_candidate_list_times_out_to_none() {
        let result = punch_candidates(0, &[], Duration::from_millis(200)).unwrap();
        assert!(result.is_none());
    }
}
