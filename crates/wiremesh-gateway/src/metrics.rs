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
