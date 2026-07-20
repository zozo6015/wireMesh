//! wiremesh-gateway boot sequence + supervision (spec §5.1).
use anyhow::Context;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use wiremesh_enforcer::BackendKind;
use wiremesh_gateway::config::GatewayConfig;
use wiremesh_gateway::enforce::GatewayEnforcer;
use wiremesh_gateway::identity::Identity;
use wiremesh_gateway::metrics;
use wiremesh_gateway::path::{Path, PathAction, PathState};
use wiremesh_gateway::state::DesiredState;
use wiremesh_gateway::tunnel::Tunnel;
use wiremesh_gateway::{netif, observe, punch, reconcile, routes, sync, uapi};

const TUN_MTU: u32 = 1280;
const MSS: u16 = 1240;
const KEEPALIVE: u16 = 15;
const OBSERVE_PERIOD: Duration = Duration::from_secs(20);

/// How long each hole-punch session blasts candidates before giving up — the
/// de-risked punch window (spec §3, `punch::punch_candidates`).
const PUNCH_WINDOW: Duration = Duration::from_secs(6);

/// Cap on how long we'll sleep waiting for a `PunchDirective`'s `go_unix_ms`
/// fire instant. The controller broker's back-to-back sends are the primary
/// go-skew guarantee (proto note); `go_unix_ms` is best-effort corroboration,
/// so a wildly-future value (bad clock) must not park a punch task forever.
const MAX_PUNCH_DELAY: Duration = Duration::from_secs(5);

/// Cadence of the path-state driver: poll WG handshakes and `tick` every peer
/// (spec §6.1). ~1s keeps state transitions responsive without hammering the
/// UAPI socket.
const PATH_TICK_PERIOD: Duration = Duration::from_secs(1);

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

    // Per-peer NAT-traversal state, shared between the sync loop (which
    // receives PunchDirectives), the spawned punch tasks, and the periodic
    // path-state driver. See `PathCtx` for why these are std (not tokio)
    // mutexes.
    let ctx = PathCtx {
        wg_port: cfg.wg_listen_port,
        ifname: cfg.tun_ifname.clone(),
        priv_key: tunnel.private_key_b64.clone(),
        desired: Arc::new(std::sync::Mutex::new(applied.clone())),
        paths: Arc::new(std::sync::Mutex::new(HashMap::new())),
        transitions: Arc::new(std::sync::Mutex::new(HashMap::new())),
    };
    tokio::spawn(run_path_ticks(ctx.clone()));

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
                    match sync::next_event(&mut stream, &mut current).await {
                        Ok(Some(sync::SyncEvent::State(ds))) => {
                            apply_state(&tunnel, &enforcer, &cfg, applied.as_ref(), &ds).await?;
                            ds.save(&cfg.state_dir)?;
                            // Publish the latest desired state to the punch /
                            // path-tick tasks (guard dropped before the await
                            // below — never held across it).
                            *ctx.desired.lock().unwrap() = Some(ds.clone());
                            let local_endpoints = netif::local_wg_endpoints(cfg.wg_listen_port);
                            let _ = sync::report(&mut client, ds.policy_version, local_endpoints).await;
                            applied_version.store(ds.policy_version, Ordering::Relaxed);
                            applied = Some(ds);
                        }
                        Ok(Some(sync::SyncEvent::Punch(d))) => {
                            eprintln!(
                                "wiremesh-gateway: punch directive for peer={} ({} candidates, go={}ms)",
                                d.peer_gateway_id,
                                d.candidates.len(),
                                d.go_unix_ms
                            );
                            tokio::spawn(punch_and_apply(
                                ctx.clone(),
                                d.peer_gateway_id,
                                d.candidates,
                                Some(d.go_unix_ms),
                            ));
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

/// Shared handles the punch tasks and the path-state driver need. Cloned into
/// each spawned task; every field is either `Copy`/`String` or an
/// `Arc<std::sync::Mutex<_>>`. The std (not tokio) mutexes are deliberate:
/// their guards are `!Send`, so the compiler itself forbids holding one across
/// an `.await`, mechanically enforcing the gateway's async discipline (no lock
/// held across await; all blocking I/O confined to `spawn_blocking`). Every
/// guard below is taken in a tight scope and dropped before the next await.
#[derive(Clone)]
struct PathCtx {
    wg_port: u16,
    ifname: String,
    priv_key: String,
    /// Latest applied desired state (peers, candidate endpoints), published by
    /// the sync loop so punch/tick tasks can map pubkeys → gateway_ids and
    /// re-reconcile with a confirmed endpoint.
    desired: Arc<std::sync::Mutex<Option<DesiredState>>>,
    /// Per-peer direct-path state machine, keyed by peer `gateway_id`.
    paths: Arc<std::sync::Mutex<HashMap<u64, Path>>>,
    /// Cumulative `{(from,to) -> count}` path-state transition tally — the
    /// bookkeeping behind `metrics::render_path_transitions`.
    transitions: Arc<std::sync::Mutex<HashMap<(PathState, PathState), u64>>>,
}

impl PathCtx {
    /// Record (and log) a single path-state transition for `gid`, feeding the
    /// `wiremesh_gateway_path_transitions_total{from,to}` tally. No-op when the
    /// state didn't actually change.
    fn record_transition(&self, gid: u64, before: PathState, after: PathState) {
        if before == after {
            return;
        }
        *self.transitions.lock().unwrap().entry((before, after)).or_insert(0) += 1;
        eprintln!(
            "wiremesh-gateway: path peer={gid} {} -> {}",
            before.as_str(),
            after.as_str()
        );
    }
}

/// Decode a base64 WireGuard public key into the lowercase-hex form the WG
/// UAPI keys its per-peer state by (`uapi::get_latest_handshakes`), so a
/// controller-provided `active_pubkey_b64` can be correlated with the device's
/// live handshake times. Mirrors `uapi`'s private `key_b64_to_hex` (not part
/// of the library's public surface). Returns `None` for malformed input or a
/// key that isn't exactly 32 bytes.
fn pubkey_b64_to_hex(b64: &str) -> Option<String> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = b64.bytes().filter(|&c| c != b'=' && !c.is_ascii_whitespace()).collect();
    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    if out.len() != 32 {
        return None;
    }
    Some(out.iter().map(|b| format!("{b:02x}")).collect())
}

/// Sleep until `go_unix_ms` (best-effort, clamped to `MAX_PUNCH_DELAY`), run
/// ONE hole-punch to `candidates`, and on a confirmed candidate re-reconcile
/// the WG device with that endpoint preferred for peer `gid`. Records the
/// attempt in the peer's path SM (created `Connecting` if absent). Every
/// blocking call (`punch::punch_candidates`, `uapi::apply`) runs inside
/// `spawn_blocking`; no mutex guard is ever held across an `.await`.
async fn punch_and_apply(ctx: PathCtx, gid: u64, candidates: Vec<String>, go_unix_ms: Option<u64>) {
    if let Some(go) = go_unix_ms {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let delay = Duration::from_millis(go.saturating_sub(now_ms)).min(MAX_PUNCH_DELAY);
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }

    // Record the attempt: a peer we're punching toward is (at least)
    // Connecting. Guard dropped before the first await below.
    {
        let mut paths = ctx.paths.lock().unwrap();
        paths.entry(gid).or_insert_with(|| Path::new(Instant::now()));
    }

    let wg_port = ctx.wg_port;
    let cands = candidates.clone();
    let confirmed = match tokio::task::spawn_blocking(move || {
        punch::punch_candidates(wg_port, &cands, PUNCH_WINDOW)
    })
    .await
    {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => {
            eprintln!("wiremesh-gateway: punch to peer={gid} failed: {e}");
            return;
        }
        Err(e) => {
            eprintln!("wiremesh-gateway: punch task for peer={gid} panicked: {e}");
            return;
        }
    };

    let Some(addr) = confirmed else {
        // Nothing confirmed within the window (e.g. symmetric-NAT peer — the
        // documented relay-needed case). The path SM will drive retry/relay.
        eprintln!("wiremesh-gateway: no candidate confirmed for peer={gid}");
        return;
    };

    // Re-reconcile the FULL device (replace_peers) with the confirmed endpoint
    // moved to the front of this peer's candidate list so `primary_endpoint()`
    // prefers it. Only the `desired` guard is held here — dropped before the
    // blocking apply.
    let dev = {
        let desired = ctx.desired.lock().unwrap();
        let Some(ds) = desired.as_ref() else {
            eprintln!("wiremesh-gateway: no desired state yet; dropping punch result for peer={gid}");
            return;
        };
        let mut ds = ds.clone();
        if let Some(peer) = ds.peers.iter_mut().find(|p| p.gateway_id == gid) {
            let a = addr.to_string();
            peer.candidates.retain(|c| c != &a);
            peer.candidates.insert(0, a);
        }
        reconcile::device_config(&ds, &ctx.priv_key, ctx.wg_port, KEEPALIVE)
    };

    let ifname = ctx.ifname.clone();
    match tokio::task::spawn_blocking(move || uapi::apply(&ifname, &dev)).await {
        Ok(Ok(())) => {
            eprintln!("wiremesh-gateway: punch confirmed peer={gid} endpoint={addr}");
            // The path SM transitions to Direct off the ensuing WG handshake,
            // observed by `run_path_ticks` — not off this punch confirmation.
        }
        Ok(Err(e)) => {
            eprintln!("wiremesh-gateway: applying punched endpoint for peer={gid} failed: {e}")
        }
        Err(e) => eprintln!("wiremesh-gateway: uapi apply task for peer={gid} panicked: {e}"),
    }
}

/// Periodic path-state driver (spec §6.1). Every `PATH_TICK_PERIOD`: read the
/// device's per-peer latest-handshake times, advance each peer's `Path`
/// (handshake → Direct; time-driven degrade/disconnect via `tick`), record
/// transitions, and act on the returned `PathAction` (StartPunch/Retry re-run
/// a bounded punch; MarkRelayNeeded is inert in 4b). `relay_available` is
/// always `false` in 4b — no relay transport exists yet. All blocking I/O runs
/// in `spawn_blocking`; no mutex guard is held across an `.await`.
async fn run_path_ticks(ctx: PathCtx) {
    // Last handshake time we've observed per peer, to detect *advancement*
    // (a repeated identical timestamp must NOT re-fire `on_handshake`).
    let mut last_seen: HashMap<u64, SystemTime> = HashMap::new();
    loop {
        tokio::time::sleep(PATH_TICK_PERIOD).await;

        let ifname = ctx.ifname.clone();
        let handshakes = match tokio::task::spawn_blocking(move || {
            uapi::get_latest_handshakes(&ifname)
        })
        .await
        {
            Ok(Ok(m)) => m,
            Ok(Err(e)) => {
                eprintln!("wiremesh-gateway: path-tick handshake read failed: {e}");
                continue;
            }
            Err(e) => {
                eprintln!("wiremesh-gateway: path-tick handshake task panicked: {e}");
                continue;
            }
        };

        // Snapshot desired state (guard dropped immediately).
        let Some(ds) = ctx.desired.lock().unwrap().clone() else { continue };

        let now = Instant::now();
        let mut to_record: Vec<(u64, PathState, PathState)> = Vec::new();
        let mut to_punch: Vec<(u64, Vec<String>)> = Vec::new();
        {
            let mut paths = ctx.paths.lock().unwrap();
            for peer in &ds.peers {
                let Some(b64) = peer.active_pubkey_b64.as_deref() else { continue };
                let Some(hex) = pubkey_b64_to_hex(b64) else { continue };
                let gid = peer.gateway_id;
                let path = paths.entry(gid).or_insert_with(|| Path::new(now));
                let before = path.state;

                if let Some(&t) = handshakes.get(&hex) {
                    let advanced = last_seen.get(&gid).map_or(true, |prev| t > *prev);
                    if advanced {
                        path.on_handshake(now);
                        last_seen.insert(gid, t);
                    }
                }

                match path.tick(now, false) {
                    Some(PathAction::StartPunch) => to_punch.push((gid, peer.candidates.clone())),
                    Some(PathAction::MarkRelayNeeded) => {
                        eprintln!("wiremesh-gateway: relay-needed for peer={gid} (inert in 4b)")
                    }
                    Some(PathAction::Retry) | None => {}
                }

                if before != path.state {
                    to_record.push((gid, before, path.state));
                }
            }
        } // paths guard dropped before the awaits/spawns below

        for (gid, before, after) in to_record {
            ctx.record_transition(gid, before, after);
        }
        for (gid, candidates) in to_punch {
            // Bounded by the SM's own backoff (StartPunch only fires on
            // Disconnected → Connecting expiry).
            tokio::spawn(punch_and_apply(ctx.clone(), gid, candidates, None));
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pubkey_b64_to_hex_matches_uapi_wire_form() {
        // 32 zero bytes: base64 is 43 'A's + one '=' pad; hex is "00" x32 —
        // the lowercase-hex form `uapi::get_latest_handshakes` keys peers by.
        let b64 = format!("{}=", "A".repeat(43));
        assert_eq!(pubkey_b64_to_hex(&b64), Some("00".repeat(32)));
    }

    #[test]
    fn pubkey_b64_to_hex_rejects_malformed_or_wrong_length() {
        assert_eq!(pubkey_b64_to_hex("not*base64"), None);
        // Well-formed base64 but far too short to be a 32-byte WG key.
        assert_eq!(pubkey_b64_to_hex("AAAA"), None);
    }
}
