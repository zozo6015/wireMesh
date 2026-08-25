//! Prometheus text exposition (spec §6 metrics component) + the metrics HTTP
//! listener that scrapes it.
//!
//! The listener is decoupled from the live enforcer: [`serve_metrics`] takes
//! a `fetch` closure that supplies (backend kind, applied policy version,
//! counters) per scrape, rather than reaching into a live
//! `GatewayEnforcer` itself. That keeps the HTTP response path (formatting,
//! framing, connection handling) unit-testable with a stub here in-crate;
//! the enforcer-backed path — `main.rs` wiring `fetch` to a live
//! `Arc<tokio::sync::Mutex<GatewayEnforcer>>` behind a real boringtun/eBPF
//! boot — is proven end-to-end by Task 12's mesh milestone, which spawns the
//! real binary and scrapes this port for real.
use crate::path::PathState;
use std::future::Future;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use wiremesh_enforcer::Counters;

/// Render one Prometheus text-exposition scrape body.
pub fn render(kind: &str, applied_version: u64, counters: &Counters) -> String {
    let mut s = String::new();
    s.push_str("# TYPE wiremesh_gateway_default_deny_total counter\n");
    s.push_str(&format!(
        "wiremesh_gateway_default_deny_total {}\n",
        counters.default_deny
    ));
    s.push_str("# TYPE wiremesh_gateway_rule_hits_total counter\n");
    for (rule_id, hits) in &counters.by_rule {
        s.push_str(&format!(
            "wiremesh_gateway_rule_hits_total{{rule_id=\"{rule_id}\"}} {hits}\n"
        ));
    }
    s.push_str("# TYPE wiremesh_gateway_applied_policy_version gauge\n");
    s.push_str(&format!(
        "wiremesh_gateway_applied_policy_version {applied_version}\n"
    ));
    s.push_str("# TYPE wiremesh_gateway_backend_info gauge\n");
    s.push_str(&format!(
        "wiremesh_gateway_backend_info{{backend=\"{kind}\"}} 1\n"
    ));
    s
}

/// Render current per-peer path-state gauges (spec §6.1) as a single
/// labeled gauge — `wiremesh_gateway_path_state{peer,state} 1` for the
/// peer's CURRENT state only, mirroring the `wiremesh_gateway_backend_info`
/// info-gauge pattern above rather than emitting explicit 0-valued lines
/// for the other four states. Task 10 wires `peer_states` from the live
/// per-peer `Path` table (`main.rs`'s boot loop); this task only needs the
/// pure render.
pub fn render_path_state(peer_states: &[(String, PathState)]) -> String {
    let mut s = String::new();
    s.push_str("# TYPE wiremesh_gateway_path_state gauge\n");
    for (peer, state) in peer_states {
        s.push_str(&format!(
            "wiremesh_gateway_path_state{{peer=\"{peer}\",state=\"{}\"}} 1\n",
            state.as_str()
        ));
    }
    s
}

/// Render path-state transition counters:
/// `wiremesh_gateway_path_transitions_total{from,to} <count>`. Task 10
/// accumulates these counts as `Path::tick`/`on_handshake` change state
/// (comparing state before/after each call — `path.rs` itself doesn't
/// track counts, only the current state); this task only needs the pure
/// render.
pub fn render_path_transitions(counts: &[((PathState, PathState), u64)]) -> String {
    let mut s = String::new();
    s.push_str("# TYPE wiremesh_gateway_path_transitions_total counter\n");
    for ((from, to), count) in counts {
        s.push_str(&format!(
            "wiremesh_gateway_path_transitions_total{{from=\"{}\",to=\"{}\"}} {count}\n",
            from.as_str(),
            to.as_str()
        ));
    }
    s
}

/// One peer's traffic/handshake snapshot for the per-peer observability
/// gauges (mesh-convergence fix T5,
/// `docs/research/ops-finding-multi-gateway-convergence.md` §6: every
/// diagnosis in the 2026-07-27 incident required UAPI spelunking via debug
/// containers because the gateway exposed no per-peer rx/tx/last-handshake
/// metrics — e.g. spotting FI's "handshake 28s ago with rx frozen at 0"
/// false-liveness signature took a shell inside the pod). Sourced from the
/// same UAPI `get=1` snapshot the path state machine diffs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// `None` for a peer that has never handshaked — the age line is then
    /// OMITTED entirely (mirroring `uapi::handshake_times_from`'s
    /// epoch-ambiguity rule: absence, not a bogus huge/zero age — an
    /// explicit 0 would be indistinguishable from "handshaked just now").
    pub last_handshake_age_secs: Option<u64>,
}

/// Render per-peer traffic/handshake gauges, one line per peer, labeled by
/// peer id — the same `peer="<gateway_id>"` label
/// `wiremesh_gateway_path_state` uses, so the metric families join on it.
/// rx/tx are always emitted (0 is the interesting diagnostic value — finding
/// §4's "rx stayed 0"); the handshake-age line is omitted for a
/// never-handshaked peer (see [`PeerStats::last_handshake_age_secs`]).
pub fn render_peer_stats(peers: &[(String, PeerStats)]) -> String {
    let mut s = String::new();
    s.push_str("# TYPE wiremesh_gateway_peer_rx_bytes gauge\n");
    for (peer, stats) in peers {
        s.push_str(&format!(
            "wiremesh_gateway_peer_rx_bytes{{peer=\"{peer}\"}} {}\n",
            stats.rx_bytes
        ));
    }
    s.push_str("# TYPE wiremesh_gateway_peer_tx_bytes gauge\n");
    for (peer, stats) in peers {
        s.push_str(&format!(
            "wiremesh_gateway_peer_tx_bytes{{peer=\"{peer}\"}} {}\n",
            stats.tx_bytes
        ));
    }
    s.push_str("# TYPE wiremesh_gateway_peer_last_handshake_age_seconds gauge\n");
    for (peer, stats) in peers {
        if let Some(age) = stats.last_handshake_age_secs {
            s.push_str(&format!(
                "wiremesh_gateway_peer_last_handshake_age_seconds{{peer=\"{peer}\"}} {age}\n"
            ));
        }
    }
    s
}

/// Render the policy-apply failure counter (Backlog item 1). Sourced from
/// `crate::policy_apply::PolicyApplyHandle::failures`: installs that returned
/// `Err` and were retried instead of killing the process, which is precisely
/// the class of event that used to be invisible because it was fatal.
///
/// Always emitted, including at 0 — an absent series is indistinguishable
/// from a dead exporter, and "policy applies are failing" is an alert an
/// operator must be able to write against an always-present series.
pub fn render_policy_apply_failures(total: u64) -> String {
    let mut s = String::new();
    s.push_str("# TYPE wiremesh_gateway_policy_apply_failures_total counter\n");
    s.push_str(&format!(
        "wiremesh_gateway_policy_apply_failures_total {total}\n"
    ));
    s
}

/// Render the count of LIVE ATTACHED L4 ENFORCERS — entries currently held in
/// the gateway's `enforcers` map (key-rotation T3).
///
/// Deliberately a count of map ENTRIES, not of tuns. Holding a
/// `GatewayEnforcer` in that map is what keeps its tc-BPF/nft program
/// attached: dropping the value detaches it (the eBPF backend's TCX
/// `bpf_link` attach releases on drop with no explicit unload — see
/// `wiremesh-enforcer/src/ebpf.rs` and its
/// `dropping_enforcer_detaches_and_allows_reprobe_on_same_iface` pin). So a
/// tun can stay perfectly up, with routes and traffic, while its enforcer
/// entry is gone and it is enforcing NOTHING — a default-deny bypass that is
/// invisible to every tun-shaped observation. This gauge is the one series
/// that sees it.
///
/// The failure mode it exists to catch is `HashMap::insert` DISPLACING a live
/// entry: two rotation roles that computed the same map key would silently
/// drop one enforcer with no removal call anywhere. That is exactly why the
/// value must be read from the map's own `len()` at scrape time, and never
/// tracked by a counter maintained at the insert/remove sites — such a counter
/// would be incremented by the very insert that destroyed an entry, and would
/// report the healthy number while the datapath was open.
///
/// Always emitted: an absent series is indistinguishable from a dead
/// exporter, and "live enforcers dropped below the number of live tuns" is an
/// alert an operator must be able to write against an always-present series.
pub fn render_live_enforcers(count: u64) -> String {
    let mut s = String::new();
    s.push_str("# TYPE wiremesh_gateway_live_enforcers gauge\n");
    s.push_str(&format!("wiremesh_gateway_live_enforcers {count}\n"));
    s
}

/// Wrap a Prometheus text body in a minimal HTTP/1.1 response.
fn http_response(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

/// Serve one Prometheus scrape per accepted TCP connection on `listener`,
/// forever (until `listener` errors). `fetch` is called once per connection
/// to obtain `(backend_kind, applied_policy_version, counters, peer_states,
/// transition_counts, peer_stats, policy_apply_failures, live_enforcers)`,
/// which is rendered via [`render`] + [`render_path_state`] +
/// [`render_path_transitions`] + [`render_peer_stats`] +
/// [`render_policy_apply_failures`] + [`render_live_enforcers`] and written
/// back verbatim (any HTTP request line the client sent is drained and
/// ignored — this is a scrape-only stub server, not a general HTTP server).
///
/// `peer_stats` (sixth, mesh-convergence fix T5),
/// `policy_apply_failures` (seventh, Backlog item 1) and `live_enforcers`
/// (eighth, key-rotation T3) ride the fetch tuple — rather than being
/// rendered by a caller elsewhere — so they provably reach the real scrape
/// body. That is the same wiring failure mode the path-state gauges once had:
/// rendered, unit-tested, and never actually served.
pub async fn serve_metrics<F, Fut>(listener: TcpListener, fetch: F) -> anyhow::Result<()>
where
    F: Fn() -> Fut + Clone + Send + 'static,
    Fut: Future<
            Output = anyhow::Result<(
                String,
                u64,
                Counters,
                Vec<(String, PathState)>,
                Vec<((PathState, PathState), u64)>,
                Vec<(String, PeerStats)>,
                u64,
                u64,
            )>,
        > + Send
        + 'static,
{
    loop {
        let (mut stream, _) = listener.accept().await?;
        let fetch = fetch.clone();
        tokio::spawn(async move {
            // Best-effort drain of whatever the client sent (we don't parse
            // the request — every connection gets the same scrape body).
            let mut buf = [0u8; 512];
            let _ = stream.read(&mut buf).await;
            let body = match fetch().await {
                Ok((
                    kind,
                    version,
                    counters,
                    peer_states,
                    transitions,
                    peer_stats,
                    policy_apply_failures,
                    live_enforcers,
                )) => {
                    let mut body = render(&kind, version, &counters);
                    body.push_str(&render_path_state(&peer_states));
                    body.push_str(&render_path_transitions(&transitions));
                    body.push_str(&render_peer_stats(&peer_stats));
                    body.push_str(&render_policy_apply_failures(policy_apply_failures));
                    body.push_str(&render_live_enforcers(live_enforcers));
                    body
                }
                Err(e) => format!("# error collecting counters: {e:#}\n"),
            };
            let _ = stream.write_all(http_response(&body).as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn render_emits_prometheus_lines() {
        let c = Counters {
            by_rule: BTreeMap::from([("r1".to_string(), 7u64)]),
            default_deny: 3,
        };
        let out = render("ebpf", 5, &c);
        assert!(out.contains("wiremesh_gateway_default_deny_total 3"));
        assert!(out.contains("wiremesh_gateway_rule_hits_total{rule_id=\"r1\"} 7"));
        assert!(out.contains("wiremesh_gateway_applied_policy_version 5"));
        assert!(out.contains("backend=\"ebpf\""));
    }

    #[test]
    fn render_path_state_emits_current_state_gauge_per_peer() {
        let out = render_path_state(&[
            ("peerA".to_string(), PathState::Direct),
            ("peerB".to_string(), PathState::Degraded),
        ]);
        assert!(out.contains("# TYPE wiremesh_gateway_path_state gauge"));
        assert!(
            out.contains("wiremesh_gateway_path_state{peer=\"peerA\",state=\"direct\"} 1"),
            "body: {out}"
        );
        assert!(
            out.contains("wiremesh_gateway_path_state{peer=\"peerB\",state=\"degraded\"} 1"),
            "body: {out}"
        );
    }

    #[test]
    fn render_path_transitions_emits_from_to_counter() {
        let out = render_path_transitions(&[
            ((PathState::Connecting, PathState::Direct), 3u64),
            ((PathState::Direct, PathState::Degraded), 1u64),
        ]);
        assert!(out.contains("# TYPE wiremesh_gateway_path_transitions_total counter"));
        assert!(
            out.contains(
                "wiremesh_gateway_path_transitions_total{from=\"connecting\",to=\"direct\"} 3"
            ),
            "body: {out}"
        );
        assert!(
            out.contains(
                "wiremesh_gateway_path_transitions_total{from=\"direct\",to=\"degraded\"} 1"
            ),
            "body: {out}"
        );
    }

    #[tokio::test]
    async fn serve_metrics_responds_with_rendered_body_over_tcp() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_metrics(listener, || async {
            let counters = Counters {
                by_rule: BTreeMap::from([("r9".to_string(), 2u64)]),
                default_deny: 1,
            };
            let peer_states = vec![("42".to_string(), PathState::Direct)];
            let transitions = vec![((PathState::Connecting, PathState::Direct), 3u64)];
            // Mechanical +1 tuple element (fix T5); the per-peer-gauge
            // scrape assertions live in `tests/peer_metrics.rs`.
            let peer_stats: Vec<(String, PeerStats)> = vec![];
            // Likewise mechanical (Backlog item 1); the apply-failure
            // scrape assertion lives in `tests/policy_apply_liveness.rs`.
            // And likewise the trailing `1u64` (key-rotation T3): the
            // steady-state live-enforcer count is the lone boot tun's, and
            // the scrape assertion for it lives in the rotation netns suite.
            Ok::<_, anyhow::Error>((
                "ebpf".to_string(),
                9u64,
                counters,
                peer_states,
                transitions,
                peer_stats,
                0u64,
                1u64,
            ))
        }));

        let mut stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connect to metrics listener");
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);
        assert!(
            text.contains("wiremesh_gateway_applied_policy_version 9"),
            "body: {text}"
        );
        assert!(
            text.contains("wiremesh_gateway_default_deny_total 1"),
            "body: {text}"
        );
        assert!(
            text.contains("wiremesh_gateway_rule_hits_total{rule_id=\"r9\"} 2"),
            "body: {text}"
        );
        assert!(text.contains("backend=\"ebpf\""), "body: {text}");
        // The review finding this test now guards: path-state gauge +
        // transition counters must reach the actual HTTP scrape body, not
        // just exist as separately-tested pure renderers.
        assert!(
            text.contains("wiremesh_gateway_path_state{peer=\"42\",state=\"direct\"} 1"),
            "path-state gauge must reach the scrape body: {text}"
        );
        assert!(
            text.contains(
                "wiremesh_gateway_path_transitions_total{from=\"connecting\",to=\"direct\"} 3"
            ),
            "path transitions must reach the scrape body: {text}"
        );
    }
}
