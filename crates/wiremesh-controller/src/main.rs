//! `wiremesh-controller` binary: a thin wrapper that builds a [`Config`] from
//! environment variables (CLI flags are out of this task's scope — real
//! deployments/`fabricctl` wiring lands in later tasks) and hands off to the
//! library entrypoint [`wiremesh_controller::serve`], which does all the
//! actual work. Kept thin on purpose: `wiremesh-testkit::TestController`
//! calls `serve` directly (in-process) for integration tests, so all real
//! boot logic must live in the library, not here.

use std::path::PathBuf;

use anyhow::{Context, Result};
use wiremesh_controller::{serve, Config};

/// Reads `var` as a `u16` port: an ABSENT variable falls back to `default`
/// (`0` = OS-assigned, everywhere this is called), but a PRESENT-but-
/// malformed value (e.g. `WIREMESH_ADMIN_TCP_PORT=abc`) is a startup error
/// rather than silently becoming `0` — an operator who mistyped a port
/// number must find out at boot, not discover an unexpected ephemeral
/// listener later.
fn port_env(var: &str, default: u16) -> Result<u16> {
    match std::env::var(var) {
        Ok(v) => v
            .parse::<u16>()
            .with_context(|| format!("{var}={v:?} is not a valid u16 port")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(e) => Err(e).with_context(|| format!("reading {var}")),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let data_dir = std::env::var("WIREMESH_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/wiremesh"));
    let tcp_port = port_env("WIREMESH_TCP_PORT", 0)?;
    let sync_tcp_port = port_env("WIREMESH_SYNC_TCP_PORT", 0)?;
    let socket_path = std::env::var("WIREMESH_SOCKET_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/run/wiremesh/controller.sock"));
    let admin_tcp_port = port_env("WIREMESH_ADMIN_TCP_PORT", 0)?;
    let observe_udp_port = port_env("WIREMESH_OBSERVE_UDP_PORT", 0)?;

    let config = Config {
        data_dir,
        tcp_port,
        sync_tcp_port,
        socket_path,
        admin_tcp_port,
        observe_udp_port,
        bind_ip: Config::default_bind_ip(),
        rotation_interval: Config::default_rotation_interval(),
        rotation_sweep_interval: Config::default_rotation_sweep_interval(),
    };

    let running = serve(config).await?;
    eprintln!(
        "wiremesh-controller listening: tcp={} sync_tcp={} uds={} admin_tcp={} observe_udp={}",
        running.tcp_addr(),
        running.sync_tcp_addr(),
        running.socket_path().display(),
        running.admin_tcp_addr(),
        running.observe_addr()
    );

    tokio::signal::ctrl_c().await?;
    eprintln!("wiremesh-controller: shutting down");
    running.shutdown().await;
    Ok(())
}
