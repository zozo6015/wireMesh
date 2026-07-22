//! `wiremesh-operator` entrypoint. Serves a minimal `/healthz` liveness
//! endpoint and (in later tasks) starts the CRD reconcilers. See the crate
//! lib docs + the operator design spec.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();
    tracing::info!("wiremesh-operator started");

    // Minimal liveness endpoint on :8080. Later tasks start the kube-rs
    // reconcilers alongside this.
    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    tracing::info!("healthz listening on :8080");
    loop {
        let (mut sock, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("healthz accept error: {e}");
                continue;
            }
        };
        tokio::spawn(async move {
            // Drain the request line (best-effort) then answer.
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let (code, body) = wiremesh_operator::healthz();
            let resp = format!(
                "HTTP/1.1 {code} OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = sock.write_all(resp.as_bytes()).await;
        });
    }
}
