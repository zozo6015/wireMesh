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
    s.push_str(&format!("wiremesh_gateway_default_deny_total {}\n", counters.default_deny));
    s.push_str("# TYPE wiremesh_gateway_rule_hits_total counter\n");
    for (rule_id, hits) in &counters.by_rule {
        s.push_str(&format!("wiremesh_gateway_rule_hits_total{{rule_id=\"{rule_id}\"}} {hits}\n"));
    }
    s.push_str("# TYPE wiremesh_gateway_applied_policy_version gauge\n");
    s.push_str(&format!("wiremesh_gateway_applied_policy_version {applied_version}\n"));
    s.push_str("# TYPE wiremesh_gateway_backend_info gauge\n");
    s.push_str(&format!("wiremesh_gateway_backend_info{{backend=\"{kind}\"}} 1\n"));
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
/// to obtain `(backend_kind, applied_policy_version, counters)`, which is
/// rendered via [`render`] and written back verbatim (any HTTP request line
/// the client sent is drained and ignored — this is a scrape-only stub
/// server, not a general HTTP server).
pub async fn serve_metrics<F, Fut>(listener: TcpListener, fetch: F) -> anyhow::Result<()>
where
    F: Fn() -> Fut + Clone + Send + 'static,
    Fut: Future<Output = anyhow::Result<(String, u64, Counters)>> + Send + 'static,
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
                Ok((kind, version, counters)) => render(&kind, version, &counters),
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
        let c = Counters { by_rule: BTreeMap::from([("r1".to_string(), 7u64)]), default_deny: 3 };
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
            out.contains("wiremesh_gateway_path_transitions_total{from=\"connecting\",to=\"direct\"} 3"),
            "body: {out}"
        );
        assert!(
            out.contains("wiremesh_gateway_path_transitions_total{from=\"direct\",to=\"degraded\"} 1"),
            "body: {out}"
        );
    }

    #[tokio::test]
    async fn serve_metrics_responds_with_rendered_body_over_tcp() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_metrics(listener, || async {
            let counters =
                Counters { by_rule: BTreeMap::from([("r9".to_string(), 2u64)]), default_deny: 1 };
            Ok::<_, anyhow::Error>(("ebpf".to_string(), 9u64, counters))
        }));

        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect to metrics listener");
        stream.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);
        assert!(text.contains("wiremesh_gateway_applied_policy_version 9"), "body: {text}");
        assert!(text.contains("wiremesh_gateway_default_deny_total 1"), "body: {text}");
        assert!(text.contains("wiremesh_gateway_rule_hits_total{rule_id=\"r9\"} 2"), "body: {text}");
        assert!(text.contains("backend=\"ebpf\""), "body: {text}");
    }
}
