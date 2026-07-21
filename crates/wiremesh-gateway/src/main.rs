//! wiremesh-gateway boot sequence + supervision (spec §5.1).
use anyhow::Context;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
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
use wiremesh_gateway::relay::RelayTransport;
use wiremesh_gateway::state::DesiredState;
use wiremesh_gateway::tunnel::Tunnel;
use wiremesh_gateway::{netif, observe, punch, reconcile, routes, sync, uapi};
use wiremesh_proto::v1::RelayHealth;

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

    // Per-peer NAT-traversal state, shared between the sync loop (which
    // receives PunchDirectives), the spawned punch tasks, the periodic
    // path-state driver, AND (below) the metrics scrape. See `PathCtx` for
    // why these are std (not tokio) mutexes.
    let ctx = PathCtx {
        wg_port: cfg.wg_listen_port,
        ifname: cfg.tun_ifname.clone(),
        priv_key: tunnel.private_key_b64.clone(),
        identity: Arc::new(id.clone()),
        desired: Arc::new(std::sync::Mutex::new(applied.clone())),
        paths: Arc::new(std::sync::Mutex::new(HashMap::new())),
        transitions: Arc::new(std::sync::Mutex::new(HashMap::new())),
        punching: Arc::new(std::sync::Mutex::new(HashSet::new())),
        relay_transports: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        relay_connecting: Arc::new(std::sync::Mutex::new(HashSet::new())),
        relay_next_idx: Arc::new(std::sync::Mutex::new(HashMap::new())),
        relay_pointed: Arc::new(std::sync::Mutex::new(HashMap::new())),
    };

    // Metrics endpoint (Prometheus scrape) on an ephemeral loopback port,
    // sharing `enforcer` with the sync loop below via Arc<Mutex<_>>, and
    // `ctx.paths`/`ctx.transitions` with the path-tick driver below so the
    // scrape body carries live path-state gauges + transition counters
    // (review finding: these were rendered/tested in `metrics.rs` but never
    // actually reached the HTTP scrape).
    {
        let metrics_listener =
            TcpListener::bind(cfg.metrics_addr).await.context("binding metrics listener")?;
        eprintln!("wiremesh-gateway: metrics listening on {}", metrics_listener.local_addr()?);
        let enforcer = enforcer.clone();
        let applied_version = applied_version.clone();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let fetch = move || {
                let enforcer = enforcer.clone();
                let applied_version = applied_version.clone();
                let ctx = ctx.clone();
                async move {
                    let mut e = enforcer.lock().await;
                    let counters = e.counters()?;
                    let kind = match e.kind() {
                        BackendKind::Ebpf => "ebpf",
                        BackendKind::Nftables => "nftables",
                    };
                    let peer_states: Vec<(String, PathState)> = ctx
                        .paths
                        .lock()
                        .unwrap()
                        .iter()
                        .map(|(gid, path)| (gid.to_string(), path.state))
                        .collect();
                    let transitions: Vec<((PathState, PathState), u64)> =
                        ctx.transitions.lock().unwrap().iter().map(|(k, v)| (*k, *v)).collect();
                    Ok::<_, anyhow::Error>((
                        kind.to_string(),
                        applied_version.load(Ordering::Relaxed),
                        counters,
                        peer_states,
                        transitions,
                    ))
                }
            };
            if let Err(e) = metrics::serve_metrics(metrics_listener, fetch).await {
                eprintln!("wiremesh-gateway: metrics listener stopped: {e}");
            }
        });
    }

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
                            let relay_health = ctx.relay_health_snapshot().await;
                            let _ = sync::report(
                                &mut client,
                                ds.policy_version,
                                local_endpoints,
                                relay_health,
                            )
                            .await;
                            applied_version.store(ds.policy_version, Ordering::Relaxed);
                            applied = Some(ds);
                        }
                        Ok(Some(sync::SyncEvent::Punch(d))) => {
                            let gid = d.peer_gateway_id;
                            eprintln!(
                                "wiremesh-gateway: punch directive for peer={gid} ({} candidates, go={}ms)",
                                d.candidates.len(),
                                d.go_unix_ms
                            );
                            match ctx.try_start_punch(gid) {
                                Some(guard) => {
                                    tokio::spawn(punch_and_apply(
                                        ctx.clone(),
                                        gid,
                                        d.candidates,
                                        Some(d.go_unix_ms),
                                        guard,
                                    ));
                                }
                                None => eprintln!(
                                    "wiremesh-gateway: punch already in flight for peer={gid}; \
                                     skipping controller directive"
                                ),
                            }
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
    /// This gateway's own identity (mTLS cert/key/CA PEMs + `gateway_id`),
    /// needed to mint a `RelayTransport` connection on this peer's behalf
    /// (Cycle 4c Task 8). `Arc`-wrapped since `Identity` holds several PEM
    /// `String`s and `PathCtx` (and thus this field) is cloned into every
    /// spawned punch/relay-connect task.
    identity: Arc<Identity>,
    /// Latest applied desired state (peers, candidate endpoints), published by
    /// the sync loop so punch/tick tasks can map pubkeys → gateway_ids and
    /// re-reconcile with a confirmed endpoint.
    desired: Arc<std::sync::Mutex<Option<DesiredState>>>,
    /// Per-peer direct-path state machine, keyed by peer `gateway_id`.
    paths: Arc<std::sync::Mutex<HashMap<u64, Path>>>,
    /// Cumulative `{(from,to) -> count}` path-state transition tally — the
    /// bookkeeping behind `metrics::render_path_transitions`.
    transitions: Arc<std::sync::Mutex<HashMap<(PathState, PathState), u64>>>,
    /// Gateway IDs with a `punch_and_apply` task currently in flight (review
    /// finding: a controller `Punch` directive and a tick-driven
    /// `StartPunch` for the SAME peer could otherwise spawn two concurrent
    /// tasks that each `replace_peers`-apply the full device). Claimed via
    /// [`PathCtx::try_start_punch`], released by dropping the returned
    /// [`PunchGuard`].
    punching: Arc<std::sync::Mutex<HashSet<u64>>>,
    /// Live relay transport per peer `gateway_id` currently relying on relay
    /// help — present only while that peer is (or very recently was)
    /// `Relayed`. A `tokio::sync::Mutex` (unlike every other `PathCtx` map)
    /// because establishing/tearing down a transport requires holding the
    /// guard across the `async` `RelayTransport::start` / UAPI-apply calls in
    /// [`ensure_relay_transport`]/[`teardown_relay_transport`] — those
    /// functions are careful never to also hold `paths`/`desired` (the
    /// `std::sync::Mutex`es) across an `.await` at the same time.
    relay_transports: Arc<tokio::sync::Mutex<HashMap<u64, PeerRelay>>>,
    /// Gateway IDs with a relay-connect task (`ensure_relay_transport`)
    /// currently in flight — the relay analogue of `punching`, so a
    /// `MarkRelayNeeded`/re-path firing on two consecutive ticks before the
    /// first `RelayTransport::start` lands doesn't race two connect attempts
    /// for the same peer.
    relay_connecting: Arc<std::sync::Mutex<HashSet<u64>>>,
    /// Round-robin cursor into the advertised-relay list, per peer, so a
    /// relay-to-relay re-path (the peer's current transport died) tries the
    /// NEXT advertised relay rather than immediately reconnecting to the one
    /// that just died.
    relay_next_idx: Arc<std::sync::Mutex<HashMap<u64, usize>>>,
    /// Whether peer `gid`'s WG endpoint is CURRENTLY pointed at a
    /// `RelayTransport`'s local relay socket (`true`) or a real direct
    /// candidate (`false`/absent) — set by every [`set_peer_endpoint`] call
    /// (Cycle 4c Task 9, make-before-break cutover gating). This is the
    /// disambiguator `run_path_ticks` needs: while `Relayed`, a completed WG
    /// handshake carried OVER THE RELAY must NOT be treated as the Direct
    /// cutover (`Path::on_handshake`) — it just means the relay path is
    /// alive, so it feeds `Path::on_authenticated_inbound` instead. Only a
    /// handshake completing AFTER the endpoint has been repointed at a real
    /// direct candidate (`ensure_relay_transport`'s ProbeDirect punch
    /// succeeding) counts as the actual cutover. Absent/`false` is the safe
    /// default for a peer that has never been relayed at all, preserving
    /// every pre-4c-Task-9 direct-only scenario's behavior unchanged.
    relay_pointed: Arc<std::sync::Mutex<HashMap<u64, bool>>>,
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

    /// Try to claim the in-flight-punch slot for peer `gid`. Returns `None`
    /// if a punch for this peer is already running — the caller should skip
    /// spawning another `punch_and_apply` and just log it. Returns
    /// `Some(guard)` otherwise, having marked `gid` as in-flight; the caller
    /// must move the guard into the spawned task (e.g. as an extra
    /// parameter to `punch_and_apply`) so it's held for the task's whole
    /// lifetime and released — fail-static, on success OR error OR panic —
    /// when the guard drops.
    fn try_start_punch(&self, gid: u64) -> Option<PunchGuard> {
        let mut set = self.punching.lock().unwrap();
        if !set.insert(gid) {
            return None;
        }
        Some(PunchGuard { punching: self.punching.clone(), gid })
    }

    /// Try to claim the in-flight-relay-connect slot for peer `gid`. Same
    /// dedup shape as [`try_start_punch`] — see [`RelayConnectGuard`].
    fn try_start_relay_connect(&self, gid: u64) -> Option<RelayConnectGuard> {
        let mut set = self.relay_connecting.lock().unwrap();
        if !set.insert(gid) {
            return None;
        }
        Some(RelayConnectGuard { connecting: self.relay_connecting.clone(), gid })
    }

    /// Snapshot the gateway's current per-relay health for `Sync.Report`
    /// (cycle4c Task 8): one [`RelayHealth`] entry per DISTINCT `relay_id`
    /// this gateway currently has at least one `RelayTransport` open to
    /// (`healthy` true if ANY such transport reports alive — a peer's dead
    /// transport doesn't mark a relay unhealthy if another peer's transport
    /// to the same relay is still fine). A relay this gateway has never
    /// needed to connect to (no peer currently relayed through it) simply
    /// has no entry, mirroring `local_endpoints`' "report only what's true
    /// right now" semantics.
    async fn relay_health_snapshot(&self) -> Vec<RelayHealth> {
        let map = self.relay_transports.lock().await;
        let mut by_relay: HashMap<u64, bool> = HashMap::new();
        for peer_relay in map.values() {
            let healthy = by_relay.entry(peer_relay.relay_id).or_insert(false);
            *healthy = *healthy || peer_relay.transport.is_healthy();
        }
        by_relay.into_iter().map(|(relay_id, healthy)| RelayHealth { relay_id, healthy }).collect()
    }
}

/// RAII release for [`PathCtx::try_start_punch`]'s in-flight-punch slot.
/// Removing `gid` on `Drop` (rather than requiring an explicit call at every
/// `punch_and_apply` return site) means an early `return` on error, or even
/// a task panic unwinding through it, still releases the slot — a punch
/// failure must never permanently wedge future punches for that peer.
struct PunchGuard {
    punching: Arc<std::sync::Mutex<HashSet<u64>>>,
    gid: u64,
}

impl Drop for PunchGuard {
    fn drop(&mut self) {
        self.punching.lock().unwrap().remove(&self.gid);
    }
}

/// RAII release for [`PathCtx::try_start_relay_connect`]'s in-flight-connect
/// slot — the relay analogue of [`PunchGuard`], same fail-static rationale
/// (an error or panic mid-connect must not permanently wedge future relay
/// attempts for that peer).
struct RelayConnectGuard {
    connecting: Arc<std::sync::Mutex<HashSet<u64>>>,
    gid: u64,
}

impl Drop for RelayConnectGuard {
    fn drop(&mut self) {
        self.connecting.lock().unwrap().remove(&self.gid);
    }
}

/// One peer's live relay transport plus which advertised relay it's
/// connected to (`RelayInfo.relay_id`) — the latter isn't recoverable from
/// `RelayTransport` itself, but [`PathCtx::relay_health_snapshot`] needs it
/// to report [`RelayHealth`] keyed by relay, not by peer.
struct PeerRelay {
    transport: RelayTransport,
    relay_id: u64,
}

/// Decode a base64 WireGuard public key into the lowercase-hex form the WG
/// UAPI keys its per-peer state by (`uapi::get_peer_liveness`), so a
/// controller-provided `active_pubkey_b64` can be correlated with the device's
/// live handshake/rx_bytes state. Mirrors `uapi`'s private `key_b64_to_hex`
/// (not part of the library's public surface). Returns `None` for malformed
/// input or a key that isn't exactly 32 bytes.
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
///
/// `_guard` is the in-flight-punch slot from [`PathCtx::try_start_punch`] —
/// unused by name, but its whole purpose is to be HELD for this function's
/// entire lifetime (including every early `return` below) and released via
/// `Drop` when it returns, so at most one `punch_and_apply` runs per peer at
/// a time regardless of whether it was triggered by a controller `Punch`
/// directive or a tick-driven `StartPunch`.
async fn punch_and_apply(
    ctx: PathCtx,
    gid: u64,
    candidates: Vec<String>,
    go_unix_ms: Option<u64>,
    _guard: PunchGuard,
) {
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
    // prefers it — this doubles as the make-before-break direct cutover when
    // `gid` was `Relayed` (the relay transport is torn down separately by
    // `run_path_ticks` once the ensuing handshake actually lands `Direct`).
    match set_peer_endpoint(&ctx, gid, addr, false).await {
        Ok(()) => {
            eprintln!("wiremesh-gateway: punch confirmed peer={gid} endpoint={addr}");
            // The path SM transitions to Direct off the ensuing WG handshake,
            // observed by `run_path_ticks` — not off this punch confirmation.
        }
        Err(e) => {
            eprintln!("wiremesh-gateway: applying punched endpoint for peer={gid} failed: {e}")
        }
    }
}

/// Point peer `gid`'s WG endpoint at `endpoint` and re-apply the full device
/// config. This does NOT re-add the peer or rekey it: WireGuard's UAPI keys
/// a peer's live session by its (unchanged) `public_key=`, so a
/// `replace_peers=true` `set` that repeats the same peers with just a
/// different `endpoint=` for one of them only changes where WireGuard sends
/// its next packet — the running noise session survives untouched. Shared by
/// [`punch_and_apply`] (a hole-punch-confirmed direct candidate,
/// `is_relay=false`) and [`ensure_relay_transport`] (pointing a peer at its
/// `RelayTransport`'s local relay socket, Cycle 4c Task 8, `is_relay=true`).
///
/// `is_relay` records into `ctx.relay_pointed` (Cycle 4c Task 9) whether
/// `endpoint` is the local relay-transport socket or a real direct
/// candidate — the disambiguator `run_path_ticks` needs so a WG handshake
/// completing OVER THE RELAY isn't mistaken for the make-before-break Direct
/// cutover.
async fn set_peer_endpoint(
    ctx: &PathCtx,
    gid: u64,
    endpoint: SocketAddr,
    is_relay: bool,
) -> anyhow::Result<()> {
    let dev = {
        let desired = ctx.desired.lock().unwrap();
        let ds = desired.as_ref().ok_or_else(|| {
            anyhow::anyhow!("no desired state yet; cannot set endpoint for peer={gid}")
        })?;
        let mut ds = ds.clone();
        if let Some(peer) = ds.peers.iter_mut().find(|p| p.gateway_id == gid) {
            let a = endpoint.to_string();
            peer.candidates.retain(|c| c != &a);
            peer.candidates.insert(0, a);
        }
        reconcile::device_config(&ds, &ctx.priv_key, ctx.wg_port, KEEPALIVE)
    };
    let ifname = ctx.ifname.clone();
    tokio::task::spawn_blocking(move || uapi::apply(&ifname, &dev))
        .await
        .context("uapi apply task panicked")??;
    ctx.relay_pointed.lock().unwrap().insert(gid, is_relay);
    Ok(())
}

/// Ensure peer `gid` has a live, healthy [`RelayTransport`] and that its WG
/// endpoint points at it (Cycle 4c Task 8 — the `MarkRelayNeeded` action,
/// both for freshly entering `Relayed` and for a relay-to-relay re-path once
/// the peer's current transport dies). No-op if a healthy transport already
/// exists. `relays` is the controller's currently-advertised relay list
/// (`DesiredState.relays`); a peer's round-robin cursor
/// (`PathCtx::relay_next_idx`) picks which one to (re)connect to, advancing
/// on every attempt so a dead relay isn't retried first. Dedups against a
/// concurrent attempt for the same peer via
/// [`PathCtx::try_start_relay_connect`], mirroring [`punch_and_apply`]'s
/// `punching` guard.
async fn ensure_relay_transport(ctx: PathCtx, gid: u64, relays: Vec<wiremesh_proto::v1::RelayInfo>) {
    if relays.is_empty() {
        return;
    }

    {
        let map = ctx.relay_transports.lock().await;
        if map.get(&gid).is_some_and(|pr| pr.transport.is_healthy()) {
            return; // already covered
        }
    }

    let Some(_guard) = ctx.try_start_relay_connect(gid) else {
        return; // another connect attempt for this peer is already in flight
    };

    // Re-check under the guard: the in-flight attempt that held the slot
    // before us may have just succeeded.
    {
        let map = ctx.relay_transports.lock().await;
        if map.get(&gid).is_some_and(|pr| pr.transport.is_healthy()) {
            return;
        }
    }

    let idx = {
        let mut idxs = ctx.relay_next_idx.lock().unwrap();
        let cursor = idxs.entry(gid).or_insert(0);
        let i = *cursor % relays.len();
        *cursor = cursor.wrapping_add(1);
        i
    };
    let relay_info = &relays[idx];

    let addr: SocketAddr = match relay_info.endpoint.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!(
                "wiremesh-gateway: relay={} endpoint {:?} unparseable for peer={gid}: {e}",
                relay_info.relay_id, relay_info.endpoint
            );
            return;
        }
    };

    let identity = ctx.identity.clone();
    // SECURITY (Cycle 4c): register under this gateway's cert-embedded
    // identity (`gw-<gateway_id>`), which the relay verifies against the
    // authenticated client cert — a gateway can only register a key it owns.
    // `RelayTransport`/`wiremesh_relay::Client` derive the directional 8-byte
    // registry key from the ordered (my_identity, peer_identity) pair, so this
    // gateway's transport-for-`gid` and `gid`'s transport-for-us still
    // rendezvous (each passes the identities swapped).
    let my_identity = format!("gw-{}", identity.gateway_id);
    let peer_identity = format!("gw-{gid}");
    // The only thing that will ever talk to this transport's local socket is
    // THIS gateway's own boringtun process, always from its fixed, already-
    // known listen port — seed the downlink's `last_seen` with it up front
    // (Cycle 4c Task 9 fix) rather than waiting to learn it from the first
    // datagram, which would otherwise silently drop the very first relayed
    // handshake packet on whichever side hasn't sent anything locally yet.
    let local_peer_hint = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, ctx.wg_port));
    let transport = match RelayTransport::start(
        addr,
        &identity.cert_pem,
        &identity.key_pem,
        &identity.ca_bundle_pem,
        &my_identity,
        &peer_identity,
        Some(local_peer_hint),
    )
    .await
    {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "wiremesh-gateway: connecting relay={} for peer={gid} failed: {e}",
                relay_info.relay_id
            );
            return;
        }
    };
    let local_addr = transport.local_addr();
    let relay_id = relay_info.relay_id;

    // Insert (any prior transport for this peer is dropped here, closing its
    // QUIC connection — see `RelayTransport::Drop`).
    {
        let mut map = ctx.relay_transports.lock().await;
        map.insert(gid, PeerRelay { transport, relay_id });
    }

    if let Err(e) = set_peer_endpoint(&ctx, gid, local_addr, true).await {
        eprintln!("wiremesh-gateway: pointing peer={gid} at relay={relay_id} endpoint failed: {e}");
    } else {
        eprintln!("wiremesh-gateway: peer={gid} now relayed via relay={relay_id} ({local_addr})");
    }
}

/// Tear down peer `gid`'s relay transport, if any (Cycle 4c Task 8's
/// make-before-break cutover: called once a peer reaches `Direct`, whether
/// it arrived there from `Relayed` or never needed relay help at all — a
/// no-op in the latter case). Explicitly [`RelayTransport::close`]s the QUIC
/// connection before dropping (see that method's doc: `Client` clones don't
/// close on drop by themselves).
async fn teardown_relay_transport(ctx: &PathCtx, gid: u64) {
    let removed = ctx.relay_transports.lock().await.remove(&gid);
    if let Some(peer_relay) = removed {
        peer_relay.transport.close();
        eprintln!(
            "wiremesh-gateway: peer={gid} reached Direct; tore down relay={} transport",
            peer_relay.relay_id
        );
    }
}

/// Periodic path-state driver (spec §6.1). Every `PATH_TICK_PERIOD`: read the
/// device's per-peer latest-handshake times AND `rx_bytes`
/// (`uapi::get_peer_liveness`), advance each peer's `Path` (handshake →
/// Direct; an `rx_bytes` increase without a handshake advance → refreshed
/// liveness via `on_authenticated_inbound`, so 15s keepalives count as
/// inbound even between ~120s handshake rekeys; time-driven degrade/
/// disconnect via `tick`), record transitions, and act on the returned
/// `PathAction`: `StartPunch`/`Retry`/`ProbeDirect` all re-run a bounded
/// punch (`ProbeDirect`'s make-before-break background probe reuses the same
/// `punching` dedup guard as a fresh `StartPunch`); `MarkRelayNeeded` spawns
/// [`ensure_relay_transport`] (Cycle 4c Task 8 — a no-op if the controller
/// hasn't advertised any relay). `relay_available` is computed per peer as
/// "the controller has advertised ≥1 relay AND this peer already has a live,
/// healthy `RelayTransport`" — so the FIRST time a peer's direct budget is
/// exhausted it still parks `Disconnected` (no transport exists yet) while
/// `ensure_relay_transport` connects one in the background; the peer's next
/// `Connecting` cycle sees `relay_available = true` and lands in `Relayed`.
/// A peer that reaches `Direct` has any relay transport it was using torn
/// down (make-before-break cutover). All blocking I/O runs in
/// `spawn_blocking`; no `std::sync::Mutex` guard is ever held across an
/// `.await` (the `tokio::sync::Mutex` guarding `relay_transports` is the only
/// exception, and is never held at the same time as a `std::sync::Mutex`
/// guard).
///
/// Stability debug note (Cycle 4c Task 9, `relay_matrix.rs` case 1 flake):
/// `Path::tick`'s `Relayed` arm now rate-limits `ProbeDirect` to once per
/// `path::PROBE_DIRECT_INTERVAL` (with a full grace interval before the
/// FIRST probe of a `Relayed` spell), rather than every ~1s tick. Firing
/// every tick stacked back-to-back `punch_and_apply` attempts (the punch
/// window outlives a tick, so the next tick's request was rejected by
/// `try_start_punch` — "punch already in flight; skipping" — and immediately
/// retried the instant the guard released) and kept the driver's transient
/// same-port `SO_REUSEPORT` punch socket (`punch::punch_candidates`) open
/// almost continuously. That socket shares the WG listen port with
/// `RelayTransport`'s local downlink delivery target (`ensure_relay_transport`
/// binds its `local_peer_hint` at `127.0.0.1:<wg_listen_port>`, the very
/// address boringtun's own socket listens on), so the kernel's
/// `SO_REUSEPORT` load-balancing intermittently steered inbound relayed WG
/// datagrams to the punch socket instead of boringtun's — silently starving
/// an otherwise-healthy relay path of traffic, which is what actually broke
/// case 1, not a bad state-machine transition. See
/// docs/research/cycle4c-relay-stability-note.md. Note this only makes the
/// RELAY path stable; a genuine `Relayed -> Direct` cutover for a pair whose
/// NAT kind allows it was already correct (`punch_and_apply` only repoints
/// the WG endpoint on a CONFIRMED candidate — never blindly) and is
/// unaffected. For a symmetric<->symmetric pair specifically (this test's
/// scenario), the punch can never confirm at all (`nat_matrix.rs`'s
/// `case2_symmetric_relay_needed` already proves that for this NAT kind), so
/// a real Direct cutover from `Relayed` for that pairing is out of scope here
/// (Cycle 4c fast-follow, alongside `nat_matrix.rs`'s existing 4b-only
/// direct-cutover coverage) — this fix's job is only to stop that
/// known-futile probe from also breaking the relay path it's running
/// alongside.
async fn run_path_ticks(ctx: PathCtx) {
    // Last handshake time we've observed per peer, to detect *advancement*
    // (a repeated identical timestamp must NOT re-fire `on_handshake`).
    let mut last_seen: HashMap<u64, SystemTime> = HashMap::new();
    // Last rx_bytes we've observed per peer, to detect an *increase* — WG
    // keepalives (every 15s) bump rx_bytes without advancing the handshake
    // time (which only moves on ~120s rekey). Without this, `last_inbound`
    // only ever refreshes off `on_handshake`, so a healthy Direct path goes
    // stale after `DEGRADED_AFTER` (45s) and spuriously degrades + re-punches
    // every ~2 minutes. See docs/research/cycle4b-path-liveness-note.md.
    let mut last_rx: HashMap<u64, u64> = HashMap::new();
    loop {
        tokio::time::sleep(PATH_TICK_PERIOD).await;

        let ifname = ctx.ifname.clone();
        let liveness = match tokio::task::spawn_blocking(move || {
            uapi::get_peer_liveness(&ifname)
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
        let desired_gids: HashSet<u64> = ds.peers.iter().map(|p| p.gateway_id).collect();

        // Review/debug cleanup (Cycle 4c Task 9 minor): a peer dropped from
        // desired state (removed from the fabric, or this segment's gateway
        // deprovisioned) otherwise left its `relay_pointed`/`relay_transports`
        // entries around forever — unbounded growth over the controller's
        // lifetime, and a live `RelayTransport` (QUIC connection + two pump
        // tasks) leaked open for a peer nothing references anymore. Prune
        // both, closing any stale transport exactly like the make-before-break
        // teardown does elsewhere in this function.
        ctx.relay_pointed.lock().unwrap().retain(|gid, _| desired_gids.contains(gid));
        ctx.relay_next_idx.lock().unwrap().retain(|gid, _| desired_gids.contains(gid));

        // Snapshot which peers currently have a healthy relay transport
        // (single `tokio::sync::Mutex` acquisition for the whole tick, ahead
        // of the `std::sync::Mutex` `paths` scope below so the two guards
        // are never held simultaneously). Also prunes/closes any transport
        // for a peer no longer in desired state (same rationale as above).
        let relays_advertised = !ds.relays.is_empty();
        let healthy_relay: HashMap<u64, bool> = {
            let mut map = ctx.relay_transports.lock().await;
            let stale: Vec<u64> =
                map.keys().copied().filter(|gid| !desired_gids.contains(gid)).collect();
            for gid in stale {
                if let Some(peer_relay) = map.remove(&gid) {
                    peer_relay.transport.close();
                    eprintln!(
                        "wiremesh-gateway: peer={gid} no longer in desired state; tore down \
                         relay={} transport",
                        peer_relay.relay_id
                    );
                }
            }
            ds.peers
                .iter()
                .map(|p| {
                    let healthy = map.get(&p.gateway_id).is_some_and(|pr| pr.transport.is_healthy());
                    (p.gateway_id, healthy)
                })
                .collect()
        };

        let now = Instant::now();
        let mut to_record: Vec<(u64, PathState, PathState)> = Vec::new();
        let mut to_punch: Vec<(u64, Vec<String>)> = Vec::new();
        let mut to_relay_needed: Vec<u64> = Vec::new();
        let mut to_teardown_relay: Vec<u64> = Vec::new();
        {
            let mut paths = ctx.paths.lock().unwrap();
            for peer in &ds.peers {
                let Some(b64) = peer.active_pubkey_b64.as_deref() else { continue };
                let Some(hex) = pubkey_b64_to_hex(b64) else { continue };
                let gid = peer.gateway_id;
                let path = paths.entry(gid).or_insert_with(|| Path::new(now));
                let before = path.state;

                if let Some((Some(t), rx)) = liveness.get(&hex).copied() {
                    let advanced = last_seen.get(&gid).map_or(true, |prev| t > *prev);
                    if advanced {
                        last_seen.insert(gid, t);
                    }
                    let rx_increased = last_rx.get(&gid).map_or(false, |&prev| rx > prev);
                    last_rx.insert(gid, rx);

                    // Trust a handshake-time advance unconditionally only for
                    // this peer's FIRST-EVER handshake (`path.last_handshake
                    // == None`), i.e. genuine session bootstrap where no
                    // prior session ever existed to go stale. Once the peer
                    // HAS had a handshake before (Direct at some point, now
                    // Degraded/Relayed/Connecting-again), require corroboration
                    // by an rx_bytes increase this same tick.
                    //
                    // Why the split, not a uniform rx requirement: this
                    // project's boringtun build has been observed (netns
                    // conformance, Cycle 4b Task 11 — see
                    // docs/research/cycle4b-nat-matrix-notes.md) to advance
                    // `last_handshake_time` on EVERY driver tick for a peer
                    // that is repeatedly RETRYING an established-but-now-stale
                    // session with no reply ever arriving (`rx_bytes` frozen)
                    // — i.e. the timestamp climbs in lockstep with wall-clock
                    // time with no corresponding received byte. The PRIOR
                    // version of this code trusted the advance unconditionally
                    // whenever `path.state != Direct`, on the theory that
                    // "advance while not Direct is always a genuine fresh
                    // handshake" -- that theory is exactly what the quirk
                    // contradicts for a Degraded path retrying a dead link:
                    // the timestamp advances every tick there too, bouncing
                    // Degraded back to Direct forever and never escalating to
                    // Disconnected/relay-needed, defeating failover.
                    //
                    // A uniform "always require same-tick rx corroboration"
                    // fix (tried first) is ALSO wrong, though, and for a
                    // different reason: a genuine WireGuard handshake
                    // completion is a control-plane event that does NOT
                    // itself bump `rx_bytes` (only decrypted data-channel
                    // packets, incl. keepalives, do — see the `last_rx`
                    // comment above), and for a brand-new peer's first-ever
                    // handshake, the first corroborating data packet can lag
                    // the handshake advance by an unbounded amount (any fixed
                    // grace window can miss it, e.g. under retry/backoff at
                    // higher layers) -- confirmed empirically: requiring rx
                    // corroboration (same-tick, or within a several-second
                    // grace window) for the FIRST handshake made
                    // `establish_direct` in the netns nat matrix stick in
                    // `Connecting` forever on one side across cases 1/3/4,
                    // because that side's one-shot `advanced` event was never
                    // re-observed once missed. Gating only on "has this peer
                    // ever had a handshake before" avoids that: a first
                    // handshake is trusted immediately (matching every
                    // previously-passing scenario), while a peer that has
                    // already been Direct once — the ONLY case the documented
                    // quirk actually needs guarding, since only an established
                    // session can go stale and enter a retry-with-no-reply
                    // loop — requires corroboration. Net effect:
                    //   - genuine first-time connect (Connecting/Relayed ->
                    //     Direct with no prior handshake) still fires
                    //     immediately, exactly as before;
                    //   - genuine recovery on a peer that's had a handshake
                    //     before (Degraded/Relayed -> Direct on a real
                    //     completed re-handshake) still fires, since
                    //     `advanced && rx_increased` both hold once real data
                    //     resumes;
                    //   - a healthy keepalive'd Direct path stays Direct (rx
                    //     increases every keepalive interval -> falls through
                    //     to on_authenticated_inbound below);
                    //   - a truly DEAD path that had a handshake before
                    //     (spurious timestamp advance, rx frozen) no longer
                    //     gets re-Directed -- it sticks in Degraded and
                    //     correctly escalates to Disconnected/MarkRelayNeeded
                    //     after DEGRADED_DEAD_AFTER.
                    let is_first_handshake = path.last_handshake.is_none();
                    if advanced && (is_first_handshake || rx_increased) {
                        // Cycle 4c Task 9 (make-before-break cutover
                        // gating): a WG handshake CARRIED OVER THE RELAY
                        // (endpoint currently pointed at
                        // `ensure_relay_transport`'s local relay socket,
                        // `ctx.relay_pointed[gid] == true`) is expected
                        // while `Relayed` and must NOT be mistaken for the
                        // Direct cutover — that would falsely flip
                        // `Relayed -> Direct` and tear down a relay path
                        // that's actually the only thing carrying traffic.
                        // It only means the relay path itself is alive, so
                        // treat it as liveness instead. Only once
                        // `punch_and_apply` has repointed the endpoint at a
                        // real direct candidate (`relay_pointed[gid] ==
                        // false`, the ProbeDirect make-before-break probe
                        // having succeeded) does a completed handshake count
                        // as the actual cutover.
                        let relay_pointed =
                            ctx.relay_pointed.lock().unwrap().get(&gid).copied().unwrap_or(false);
                        if relay_pointed {
                            path.on_authenticated_inbound(now);
                        } else {
                            path.on_handshake(now);
                        }
                    } else if rx_increased {
                        // A handshake advance already calls on_handshake or
                        // on_authenticated_inbound above (both refresh
                        // last_inbound); only need this for the
                        // keepalive-only case in between.
                        path.on_authenticated_inbound(now);
                    }
                }

                let relay_available =
                    relays_advertised && *healthy_relay.get(&gid).unwrap_or(&false);
                match path.tick(now, relay_available) {
                    Some(PathAction::StartPunch) | Some(PathAction::ProbeDirect) => {
                        to_punch.push((gid, peer.candidates.clone()))
                    }
                    Some(PathAction::MarkRelayNeeded) => to_relay_needed.push(gid),
                    Some(PathAction::Retry) | None => {}
                }

                if before != path.state {
                    to_record.push((gid, before, path.state));
                    if path.state == PathState::Direct {
                        // Make-before-break cutover: a relay transport (if
                        // any) is no longer needed now that a real WG
                        // handshake has landed.
                        to_teardown_relay.push(gid);
                    }
                }
            }
        } // paths guard dropped before the awaits/spawns below

        for (gid, before, after) in to_record {
            ctx.record_transition(gid, before, after);
        }
        for gid in to_teardown_relay {
            teardown_relay_transport(&ctx, gid).await;
        }
        for gid in to_relay_needed {
            // Spawned rather than awaited inline: a `RelayTransport::start`
            // QUIC handshake can take noticeably longer than one tick
            // period, and must not delay every other peer's tick. Dedup
            // against a concurrent attempt for the same peer is handled
            // inside `ensure_relay_transport` itself (`try_start_relay_connect`).
            tokio::spawn(ensure_relay_transport(ctx.clone(), gid, ds.relays.clone()));
        }
        for (gid, candidates) in to_punch {
            // Bounded by the SM's own backoff (StartPunch only fires on
            // Disconnected → Connecting expiry; ProbeDirect fires on every
            // Relayed tick while the relay stays up). Dedup against a
            // concurrent controller-directed punch — or another
            // StartPunch/ProbeDirect tick — for the same peer (Fix 3).
            match ctx.try_start_punch(gid) {
                Some(guard) => {
                    tokio::spawn(punch_and_apply(ctx.clone(), gid, candidates, None, guard));
                }
                None => eprintln!(
                    "wiremesh-gateway: punch already in flight for peer={gid}; skipping tick-driven StartPunch/ProbeDirect"
                ),
            }
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
        // the lowercase-hex form `uapi::get_peer_liveness` keys peers by.
        let b64 = format!("{}=", "A".repeat(43));
        assert_eq!(pubkey_b64_to_hex(&b64), Some("00".repeat(32)));
    }

    #[test]
    fn pubkey_b64_to_hex_rejects_malformed_or_wrong_length() {
        assert_eq!(pubkey_b64_to_hex("not*base64"), None);
        // Well-formed base64 but far too short to be a 32-byte WG key.
        assert_eq!(pubkey_b64_to_hex("AAAA"), None);
    }

    fn test_ctx() -> PathCtx {
        PathCtx {
            wg_port: 0,
            ifname: String::new(),
            priv_key: String::new(),
            identity: Arc::new(Identity {
                cert_pem: String::new(),
                key_pem: String::new(),
                ca_bundle_pem: String::new(),
                gateway_id: 0,
                observe_key: String::new(),
                wg_private_key_b64: String::new(),
            }),
            desired: Arc::new(std::sync::Mutex::new(None)),
            paths: Arc::new(std::sync::Mutex::new(HashMap::new())),
            transitions: Arc::new(std::sync::Mutex::new(HashMap::new())),
            punching: Arc::new(std::sync::Mutex::new(HashSet::new())),
            relay_transports: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            relay_connecting: Arc::new(std::sync::Mutex::new(HashSet::new())),
            relay_next_idx: Arc::new(std::sync::Mutex::new(HashMap::new())),
            relay_pointed: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    /// Fix 3 (in-flight punch dedup): a second claim for the SAME peer while
    /// the first guard is still held must be rejected (this is what stops a
    /// controller `Punch` and a tick-driven `StartPunch` from both spawning
    /// `punch_and_apply` for one peer); an unrelated peer is unaffected; and
    /// the slot is released — fail-static — once the guard drops.
    #[test]
    fn try_start_punch_dedups_per_peer_and_releases_on_drop() {
        let ctx = test_ctx();
        let guard = ctx.try_start_punch(7).expect("first claim for peer 7 succeeds");
        assert!(
            ctx.try_start_punch(7).is_none(),
            "second concurrent claim for the same peer must be rejected"
        );
        assert!(ctx.try_start_punch(8).is_some(), "a different peer is unaffected by peer 7's guard");
        drop(guard);
        assert!(ctx.try_start_punch(7).is_some(), "slot released once the guard drops");
    }
}
