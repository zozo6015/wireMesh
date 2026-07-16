//! `wiremesh-controller` binary: a thin wrapper that builds a [`Config`] from
//! environment variables (CLI flags are out of this task's scope — real
//! deployments/`fabricctl` wiring lands in later tasks) and hands off to the
//! library entrypoint [`wiremesh_controller::serve`], which does all the
//! actual work. Kept thin on purpose: `wiremesh-testkit::TestController`
//! calls `serve` directly (in-process) for integration tests, so all real
//! boot logic must live in the library, not here.

use std::path::PathBuf;

use anyhow::Result;
use wiremesh_controller::{serve, Config};

#[tokio::main]
async fn main() -> Result<()> {
    let data_dir = std::env::var("WIREMESH_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/wiremesh"));
    let tcp_port: u16 = std::env::var("WIREMESH_TCP_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let sync_tcp_port: u16 = std::env::var("WIREMESH_SYNC_TCP_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let socket_path = std::env::var("WIREMESH_SOCKET_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/run/wiremesh/controller.sock"));
    let admin_tcp_port: u16 = std::env::var("WIREMESH_ADMIN_TCP_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let config = Config {
        data_dir,
        tcp_port,
        sync_tcp_port,
        socket_path,
        admin_tcp_port,
    };

    let running = serve(config).await?;
    eprintln!(
        "wiremesh-controller listening: tcp={} sync_tcp={} uds={} admin_tcp={}",
        running.tcp_addr(),
        running.sync_tcp_addr(),
        running.socket_path().display(),
        running.admin_tcp_addr()
    );

    tokio::signal::ctrl_c().await?;
    eprintln!("wiremesh-controller: shutting down");
    running.shutdown().await;
    Ok(())
}
