//! `wiremesh-operator` entrypoint. Starts the four CRD reconcilers against the
//! in-cluster kube API, alongside a minimal `/healthz` liveness endpoint.

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use wiremesh_operator::admin_exec::AdminExec;
use wiremesh_operator::controllers::{self, Context};

/// The namespace the operator runs in / materializes workloads into. The
/// Downward API sets `POD_NAMESPACE`; fall back to `default` for local runs.
fn operator_namespace() -> String {
    std::env::var("POD_NAMESPACE").unwrap_or_else(|_| "default".to_string())
}

/// Build the admin transport from the environment. In-cluster (default) this is
/// the UDS exec sidecar; a `WIREMESH_ADMIN_ADDR` (+`WIREMESH_ADMIN_TOKEN`) opts
/// into the direct-gRPC transport for local runs against a reachable Admin TCP.
fn admin_from_env(namespace: &str) -> AdminExec {
    if let Ok(addr) = std::env::var("WIREMESH_ADMIN_ADDR") {
        let token = std::env::var("WIREMESH_ADMIN_TOKEN").unwrap_or_default();
        AdminExec::Grpc { addr, token }
    } else {
        AdminExec::Exec {
            namespace: namespace.to_string(),
            pod_label: std::env::var("WIREMESH_CONTROLLER_LABEL")
                .unwrap_or_else(|_| "app.kubernetes.io/instance=wiremesh-controller".to_string()),
            container: "admin-exec".to_string(),
            uds: std::env::var("WIREMESH_SOCKET_PATH")
                .unwrap_or_else(|_| "/run/wiremesh/controller.sock".to_string()),
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    // `operator-admin` / `operator-bootstrap` subcommands run the in-controller-pod
    // admin helper (UDS → Admin gRPC). Any other argv is the reconciler loop.
    let mut args = std::env::args();
    let _argv0 = args.next();
    if matches!(args.next().as_deref(), Some("operator-admin") | Some("operator-bootstrap")) {
        tracing::warn!("operator-admin subcommand is not yet implemented (see admin-channel notes)");
        anyhow::bail!("operator-admin subcommand not yet implemented");
    }

    let namespace = operator_namespace();
    tracing::info!(%namespace, "wiremesh-operator starting");

    let client = kube::Client::try_default().await?;
    let ctx = Arc::new(Context {
        client,
        namespace: namespace.clone(),
        admin: Arc::new(admin_from_env(&namespace)),
    });

    // Liveness endpoint on :8080.
    tokio::spawn(healthz_server());

    // Run all four reconcilers concurrently; if any loop ends, so does the
    // process (Kubernetes restarts it).
    tokio::select! {
        _ = controllers::controller::run(ctx.clone()) => tracing::warn!("controller reconciler ended"),
        _ = controllers::fabric::run(ctx.clone())     => tracing::warn!("fabric reconciler ended"),
        _ = controllers::gateway::run(ctx.clone())    => tracing::warn!("gateway reconciler ended"),
        _ = controllers::relay::run(ctx.clone())      => tracing::warn!("relay reconciler ended"),
    }
    Ok(())
}

async fn healthz_server() {
    let listener = match TcpListener::bind("0.0.0.0:8080").await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("healthz bind failed: {e}");
            return;
        }
    };
    tracing::info!("healthz listening on :8080");
    loop {
        let Ok((mut sock, _)) = listener.accept().await else { continue };
        tokio::spawn(async move {
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
