//! wiremesh-gateway boot sequence + supervision (spec §5.1).
use anyhow::Context;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use wiremesh_enforcer::BackendKind;
use wiremesh_gateway::config::GatewayConfig;
use wiremesh_gateway::enforce::GatewayEnforcer;
use wiremesh_gateway::identity::Identity;
use wiremesh_gateway::metrics;
use wiremesh_gateway::state::DesiredState;
use wiremesh_gateway::tunnel::Tunnel;
use wiremesh_gateway::{netif, observe, reconcile, routes, sync, uapi};

const TUN_MTU: u32 = 1280;
const MSS: u16 = 1240;
const KEEPALIVE: u16 = 15;
const OBSERVE_PERIOD: Duration = Duration::from_secs(20);

fn main() -> anyhow::Result<()> {
    let cfg = GatewayConfig::from_env()?;
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run(cfg))
}

async fn run(cfg: GatewayConfig) -> anyhow::Result<()> {
    let id = Identity::load(&cfg.state_dir).context("loading pre-provisioned identity")?;

    // Bring the data plane up (from persisted state if present — fail-static,
    // spec §5.1/§5.3: this happens BEFORE the controller is ever contacted).
    let tunnel = Tunnel::up(&cfg.tun_ifname, &id.wg_private_key_b64, cfg.wg_listen_port, TUN_MTU)?;
    routes::enable_ip_forward()?;
    routes::install_mss_clamp(&cfg.tun_ifname, MSS)?;
    let enforcer = Arc::new(Mutex::new(GatewayEnforcer::attach(&cfg.tun_ifname)?));

    // Last-applied policy version, shared with the metrics task below (it
    // does not hold the enforcer lock just to report this gauge).
    let applied_version = Arc::new(AtomicU64::new(0));

    let mut applied: Option<DesiredState> = DesiredState::load(&cfg.state_dir)?;
    if let Some(ds) = &applied {
        eprintln!("wiremesh-gateway: fail-static boot from state.json rev {}", ds.revision);
        apply_state(&tunnel, &enforcer, &cfg, None, ds).await?;
        applied_version.store(ds.policy_version, Ordering::Relaxed);
    }

    // Observation loop (background). Binds the WG listen port with
    // SO_REUSEPORT alongside boringtun's own live socket on that same port
    // (spec §5.4) — see observe::report_once / observe::reuseport_udp.
    {
        let observe_addr = cfg.observe_addr;
        let key = id.observe_key.clone();
        let gid = id.gateway_id;
        let port = cfg.wg_listen_port;
        tokio::spawn(async move {
            loop {
                let (k, a) = (key.clone(), observe_addr);
                let res = tokio::task::spawn_blocking(move || observe::report_once(port, a, &k, gid)).await;
                match res {
                    Ok(Ok(addr)) => eprintln!("wiremesh-gateway: observed endpoint {addr}"),
                    Ok(Err(e)) => eprintln!("wiremesh-gateway: observe failed: {e}"),
                    Err(e) => eprintln!("wiremesh-gateway: observe task join error: {e}"),
                }
                tokio::time::sleep(OBSERVE_PERIOD).await;
            }
        });
    }

    // Metrics endpoint (Prometheus scrape) on an ephemeral loopback port,
    // sharing `enforcer` with the sync loop below via Arc<Mutex<_>>.
    {
        let metrics_listener =
            TcpListener::bind(cfg.metrics_addr).await.context("binding metrics listener")?;
        eprintln!("wiremesh-gateway: metrics listening on {}", metrics_listener.local_addr()?);
        let enforcer = enforcer.clone();
        let applied_version = applied_version.clone();
        tokio::spawn(async move {
            let fetch = move || {
                let enforcer = enforcer.clone();
                let applied_version = applied_version.clone();
                async move {
                    let mut e = enforcer.lock().await;
                    let counters = e.counters()?;
                    let kind = match e.kind() {
                        BackendKind::Ebpf => "ebpf",
                        BackendKind::Nftables => "nftables",
                    };
                    Ok::<_, anyhow::Error>((kind.to_string(), applied_version.load(Ordering::Relaxed), counters))
                }
            };
            if let Err(e) = metrics::serve_metrics(metrics_listener, fetch).await {
                eprintln!("wiremesh-gateway: metrics listener stopped: {e}");
            }
        });
    }

    // Sync loop with reconnect.
    loop {
        match sync::connect(cfg.controller_sync_addr, &id).await {
            Ok(mut client) => {
                let mut stream = match sync::watch(&mut client).await {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("watch failed: {e}; retrying");
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        continue;
                    }
                };
                let mut current = applied.clone();
                loop {
                    match sync::next_desired(&mut stream, &mut current).await {
                        Ok(Some(ds)) => {
                            apply_state(&tunnel, &enforcer, &cfg, applied.as_ref(), &ds).await?;
                            ds.save(&cfg.state_dir)?;
                            let local_endpoints = netif::local_wg_endpoints(cfg.wg_listen_port);
                            let _ = sync::report(&mut client, ds.policy_version, local_endpoints).await;
                            applied_version.store(ds.policy_version, Ordering::Relaxed);
                            applied = Some(ds);
                        }
                        Ok(None) => {
                            eprintln!("sync stream closed; reconnecting");
                            break;
                        }
                        Err(e) => {
                            eprintln!("sync error: {e}; reconnecting");
                            break;
                        }
                    }
                }
            }
            Err(e) => eprintln!("controller unreachable: {e}; staying fail-static, retrying"),
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// Apply one desired state to the data plane (tunnel peers, enforcer, routes).
async fn apply_state(
    tunnel: &Tunnel,
    enforcer: &Arc<Mutex<GatewayEnforcer>>,
    cfg: &GatewayConfig,
    prev: Option<&DesiredState>,
    ds: &DesiredState,
) -> anyhow::Result<()> {
    // The UAPI apply itself is a blocking UnixStream connect/write/read
    // (`uapi::apply`). Build the (cheap, synchronous) device config from the
    // tunnel's plain fields first, then run ONLY the blocking call inside
    // `spawn_blocking` with owned data — this avoids moving `Tunnel`/
    // `DeviceHandle` (which owns boringtun's non-`Send` internals) into the
    // blocking closure while still keeping the Tokio worker thread free.
    let dev = reconcile::device_config(ds, &tunnel.private_key_b64, tunnel.listen_port, KEEPALIVE);
    let ifname = tunnel.ifname.clone();
    tokio::task::spawn_blocking(move || uapi::apply(&ifname, &dev))
        .await
        .context("tunnel UAPI apply task panicked")??;
    enforcer.lock().await.apply_if_changed(ds)?;
    let empty = DesiredState::default();
    let diff = reconcile::route_diff(prev.unwrap_or(&empty), ds);
    for cidr in &diff.to_add {
        routes::add_route(cidr, &cfg.tun_ifname)?;
    }
    for cidr in &diff.to_del {
        routes::del_route(cidr, &cfg.tun_ifname)?;
    }
    Ok(())
}
