//! wiremesh-gateway boot sequence + supervision (spec §5.1).
use anyhow::Context;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tonic::transport::Channel;
use wiremesh_enforcer::{BackendKind, Counters};
use wiremesh_gateway::config::GatewayConfig;
use wiremesh_gateway::enforce::GatewayEnforcer;
use wiremesh_gateway::epochkeys::EpochKeys;
use wiremesh_gateway::identity::Identity;
use wiremesh_gateway::metrics;
use wiremesh_gateway::path::{Path, PathAction, PathState};
use wiremesh_gateway::relay::RelayTransport;
use wiremesh_gateway::rotation::{Rotation, RotationAction, RotationPhase};
use wiremesh_gateway::state::DesiredState;
use wiremesh_gateway::tunnelset::TunnelSet;
use wiremesh_gateway::uapi::DeviceConfig;
use wiremesh_gateway::{netif, observe, punch, reconcile, routes, sync, uapi};
use wiremesh_proto::v1::sync_client::SyncClient;
use wiremesh_proto::v1::{EpochAck, RelayHealth};

const TUN_MTU: u32 = 1280;
const MSS: u16 = 1240;
const KEEPALIVE: u16 = 15;

/// Persistent-keepalive for a rotation's transient overlap Devices
/// (`wg0e<N>`), deliberately much shorter than the steady-state
/// [`KEEPALIVE`]. persistent-keepalive is what makes boringtun proactively
/// INITIATE (and retry) a handshake for a peer that has an endpoint but no
/// data yet — a rotation Device carries no traffic until the cutover, so
/// without a tight keepalive its session can take a full 15s (or a missed
/// retry) to come live, stretching the rotation and risking the done-bar's
/// 90s budget. 3s brings the overlap session up promptly and re-tries fast if
/// the first handshake races the peer's Device coming up. Matches the
/// `spike/keyrot` choreography's short keepalive.
const ROTATION_KEEPALIVE: u16 = 3;
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

/// Cadence of the rotation observation driver ([`run_rotation_ticks`]).
/// Deliberately much tighter than [`PATH_TICK_PERIOD`]: the make-before-break
/// cutover's brief asymmetric-forwarding window (one gateway flipped its route
/// onto the new epoch's tun, its peer not yet) lasts at most the SKEW between
/// the two gateways' independent flip ticks, and each dropped datagram in that
/// window is a lost flood packet against the tight zero-drop bar. A 200ms poll
/// caps that skew (and thus the worst-case loss) at ~1 packet's worth of a
/// 0.2s-interval flood, versus ~5 at a 1s poll.
const ROTATION_TICK_PERIOD: Duration = Duration::from_millis(200);

/// How long EVERY peer's session on the new epoch's tun must have stayed
/// rx-corroborated live (continuously) after a Role-A cutover before the OLD
/// epoch's Device is retired/torn down. `2 * ROTATION_KEEPALIVE` guarantees at
/// least a couple of keepalive intervals have elapsed with real inbound on the
/// new tun — i.e. every peer has provably cut over and no peer still depends on
/// the old key — before the old private key is dropped (make-before-break).
const RETIRE_GRACE: Duration = Duration::from_secs(2 * ROTATION_KEEPALIVE as u64);

/// How often the run task wakes to service a pending old-epoch retire even when
/// the controller is quiet (no Sync traffic). The teardown happens in the run
/// task because it owns the non-`Send` `TunnelSet`; the rotation tick only
/// signals readiness via `RotationShared::retire_ready`.
const RETIRE_POLL_PERIOD: Duration = Duration::from_millis(500);

/// The tun this gateway is CURRENTLY applying peers/policy/routes to and
/// watching for liveness. `wg0` (the boot epoch) in steady state; after THIS
/// gateway rotates its own key and cuts over (Role A), the new epoch's
/// `wg0e<N>`. A non-rotating gateway (steady state, or a Role-B peer of a
/// rotating gateway) never flips this off `wg0`, so `apply_state` /
/// `set_peer_endpoint` / `run_path_ticks` all resolve to `wg0` exactly as
/// before — the key non-regression property. Absorbs the old standalone
/// `applied_wg0` change-guard as [`ActiveTunInfo::applied_config`]. Every field
/// is `Send`.
#[derive(Clone)]
struct ActiveTunInfo {
    /// The active tun's interface name (`wg0` or `wg0e<N>`).
    ifname: String,
    /// The active tun's WireGuard private key (epoch 0's identity key, or the
    /// rotated epoch's key after a Role-A cutover).
    priv_key: String,
    /// The active tun's WireGuard listen port (base port, or the rotation
    /// epoch's offset port after a cutover).
    wg_port: u16,
    /// The last device config (encoded UAPI `set` string) actually pushed to
    /// the active tun — the change-guard that keeps a redundant re-apply from
    /// needlessly resetting the live WireGuard session (boringtun rebuilds a
    /// peer's whole session on every `replace_peers` apply). `None` right after
    /// a cutover: the new tun's config was pushed out-of-band by `handle_rotate`
    /// and nothing has been re-applied through the guard yet.
    applied_config: Option<String>,
}

fn main() -> anyhow::Result<()> {
    let cfg = GatewayConfig::from_env()?;
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run(cfg))
}

async fn run(cfg: GatewayConfig) -> anyhow::Result<()> {
    let id = Identity::load(&cfg.state_dir).context("loading pre-provisioned identity")?;

    // Bring the data plane up (from persisted state if present — fail-static,
    // spec §5.1/§5.3: this happens BEFORE the controller is ever contacted).
    routes::enable_ip_forward()?;
    // Loose reverse-path filtering so a make-before-break rotation's brief
    // asymmetric-forwarding window (send route on the new tun, reverse route
    // still on the old) doesn't get its decrypted packets dropped by strict
    // rp_filter — see `routes::set_rp_filter_loose`. Best-effort: a gateway
    // that can't set it still runs (and, absent a rotation, never forwards
    // asymmetrically anyway).
    if let Err(e) = routes::set_rp_filter_loose() {
        eprintln!("wiremesh-gateway: could not set loose rp_filter (continuing): {e}");
    }
    // Bring the boot epoch (0) up INTO the `TunnelSet` rather than as a
    // standalone `Tunnel`, so that once a rotation retires it the old epoch's
    // Device can actually be torn down (its boringtun Device dropped +
    // `ip link del`). `bring_up` creates the boringtun Device, brings the tun
    // link up at `TUN_MTU`, and applies epoch 0's private key + listen port
    // with an EMPTY peer set; `apply_state` (boot fail-static below, and every
    // Sync snapshot) fills in the peers.
    let mut tunnels = TunnelSet::new();
    tunnels.bring_up(0, &cfg.tun_ifname, &id.wg_private_key_b64, cfg.wg_listen_port, TUN_MTU)?;
    routes::install_mss_clamp(&cfg.tun_ifname, MSS)?;
    // All live L4 enforcers, keyed by epoch (0 = boot tun `wg0`; `wg0e<N>` per
    // rotation). `apply_state` applies the current policy to EVERY entry so a
    // policy update reaches every tun that may be carrying traffic during a
    // rotation overlap (not just `wg0`). A `tokio::sync::Mutex` (same as the
    // old single `enforcer`) because `apply_if_changed`/`counters` are held
    // across the metrics task's `.await`. The map only grows in Step 1 — old
    // entries are torn down in a later step.
    let enforcers: Arc<Mutex<HashMap<u32, GatewayEnforcer>>> = Arc::new(Mutex::new({
        let mut m = HashMap::new();
        m.insert(0u32, GatewayEnforcer::attach(&cfg.tun_ifname)?);
        m
    }));

    // Last-applied policy version, shared with the metrics task below (it
    // does not hold the enforcer lock just to report this gauge).
    let applied_version = Arc::new(AtomicU64::new(0));

    // The single shared "active tun" descriptor (ifname + priv key + port +
    // change-guard), seeded to `wg0`'s values. Shared by every site that
    // applies the active tun — `apply_state`, the punch/relay
    // `set_peer_endpoint`, and (read-only) `run_path_ticks` — and flipped to the
    // new epoch's tun by a Role-A cutover. The `applied_config` change-guard
    // absorbs the former standalone `applied_wg0`: boringtun REPLACES a peer's
    // whole session (a fresh `Tunn`, no handshake state) on every
    // `replace_peers` apply — it can't modify a peer in place — so re-pushing a
    // byte-identical config needlessly tears the live WireGuard session down.
    // Skipping an unchanged apply (see `apply_device_if_changed`) is what keeps
    // a continuous flow zero-drop across the make-before-break rotation window.
    let active = Arc::new(std::sync::Mutex::new(ActiveTunInfo {
        ifname: cfg.tun_ifname.clone(),
        priv_key: id.wg_private_key_b64.clone(),
        wg_port: cfg.wg_listen_port,
        applied_config: None,
    }));
    // Rotating peers whose `wg0` entry must stay pinned to their OLD epoch key
    // for the overlap's lifetime (Role B make-before-break) — read by every
    // `wg0` apply site so the peer's promote delta doesn't rekey `wg0`. Empty
    // in steady state.
    let wg0_pins = Arc::new(std::sync::Mutex::new(HashMap::<u64, String>::new()));

    let mut applied: Option<DesiredState> = DesiredState::load(&cfg.state_dir)?;
    if let Some(ds) = &applied {
        eprintln!("wiremesh-gateway: fail-static boot from state.json rev {}", ds.revision);
        apply_state(&enforcers, None, ds, &active, &wg0_pins).await?;
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
        active: active.clone(),
        base_wg_port: cfg.wg_listen_port,
        identity: Arc::new(id.clone()),
        desired: Arc::new(std::sync::Mutex::new(applied.clone())),
        paths: Arc::new(std::sync::Mutex::new(HashMap::new())),
        transitions: Arc::new(std::sync::Mutex::new(HashMap::new())),
        punching: Arc::new(std::sync::Mutex::new(HashSet::new())),
        relay_transports: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        relay_connecting: Arc::new(std::sync::Mutex::new(HashSet::new())),
        relay_next_idx: Arc::new(std::sync::Mutex::new(HashMap::new())),
        relay_pointed: Arc::new(std::sync::Mutex::new(HashMap::new())),
        wg0_pins: wg0_pins.clone(),
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
        let enforcers = enforcers.clone();
        let applied_version = applied_version.clone();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let fetch = move || {
                let enforcers = enforcers.clone();
                let applied_version = applied_version.clone();
                let ctx = ctx.clone();
                async move {
                    // Aggregate deny counters across ALL live enforcers (boot
                    // tun + any rotation tun) so a post-rotation deny on the new
                    // tun is still counted; `kind` is the same backend for every
                    // entry, so any one's is representative. In the no-rotation
                    // case the map has exactly one entry (`wg0`), so the value is
                    // identical to the single-enforcer past behavior.
                    let mut map = enforcers.lock().await;
                    let kind = match map.values().next().map(|e| e.kind()) {
                        Some(BackendKind::Nftables) => "nftables",
                        // eBPF is also the safe default for the (unreachable)
                        // empty map — epoch 0 is always present.
                        Some(BackendKind::Ebpf) | None => "ebpf",
                    };
                    let mut per_tun = Vec::with_capacity(map.len());
                    for e in map.values_mut() {
                        per_tun.push(e.counters()?);
                    }
                    drop(map);
                    let counters = aggregate_counters(per_tun);
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

    // --- Key-rotation wiring (make-before-break) ---------------------------
    // Migrate the pre-rotation single identity key into a one-epoch store
    // (epoch 0, "active") the first time a rotation-aware gateway boots, so
    // `generate_next` has a base to mint from. Steady-state (no rotation)
    // behavior is completely unchanged: epoch 0 already runs on `wg0` at the
    // base port from the boot above; the epoch store is only consulted when a
    // rotation actually starts.
    let mut epoch_keys = match EpochKeys::load(&cfg.state_dir)? {
        Some(k) => k,
        None => {
            let k = EpochKeys::from_legacy(&id.wg_private_key_b64)?;
            k.persist(&cfg.state_dir)?;
            k
        }
    };
    // `tunnels` (created at boot — it owns the boot epoch-0 Device now, and the
    // per-rotation Devices below) stays owned by THIS (`block_on`'d) task,
    // never moved into a spawned task, since boringtun's `DeviceHandle` is not
    // `Send`. The rotation observation tick only ever reads a rotation Device's
    // liveness by ifname (a `String`), so it needs no handle to the Device; the
    // old-epoch teardown after a retire runs here in the run task (which owns
    // `tunnels`), driven by a shared `retire_ready` flag the tick sets.
    //
    // Each transient rotation tun's (`wg0e<N>`) L4 enforcer is inserted into the
    // shared `enforcers` map above, keyed by EPOCH — so `apply_state` reaches
    // it on every policy update AND holding it in the map keeps its tc-BPF/nft
    // program attached for the overlap Device's lifetime (dropping it would
    // detach). Closes the default-deny-bypass-on-new-tun security gap: without
    // this, a rotation's new-epoch tun carries traffic with NO policy hook at
    // all.
    let rot = RotationShared {
        base_wg_port: cfg.wg_listen_port,
        base_tun: cfg.tun_ifname.clone(),
        state_dir: cfg.state_dir.clone(),
        identity: Arc::new(id.clone()),
        controller_sync_addr: cfg.controller_sync_addr,
        rotation: Arc::new(std::sync::Mutex::new(Rotation::new())),
        role_a: Arc::new(std::sync::Mutex::new(None)),
        role_b: Arc::new(std::sync::Mutex::new(HashMap::new())),
        active: active.clone(),
        wg0_pins: wg0_pins.clone(),
        desired: ctx.desired.clone(),
        retire_ready: Arc::new(std::sync::Mutex::new(None)),
    };
    tokio::spawn(run_rotation_ticks(rot.clone()));

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
                    // Service any pending old-epoch retire the rotation tick has
                    // signalled (every peer cut over to the new tun and the
                    // grace elapsed). Done HERE in the run task because it owns
                    // the non-`Send` `tunnels`/`enforcers`.
                    service_retire(&mut tunnels, &enforcers, &rot).await;

                    // Bounded wait so the loop still wakes to service a retire
                    // even while the controller is quiet. `next_event` is
                    // cancel-safe (tonic's `Streaming` keeps its own buffered
                    // state), so dropping it on timeout never loses a message.
                    let ev = match tokio::time::timeout(
                        RETIRE_POLL_PERIOD,
                        sync::next_event(&mut stream, &mut current),
                    )
                    .await
                    {
                        Ok(res) => res,
                        Err(_elapsed) => continue,
                    };
                    match ev {
                        Ok(Some(sync::SyncEvent::State(ds))) => {
                            apply_state(
                                &enforcers,
                                applied.as_ref(),
                                &ds,
                                &rot.active,
                                &wg0_pins,
                            )
                            .await?;
                            ds.save(&cfg.state_dir)?;
                            // (Key-rotation Role B) If desired state now shows a
                            // peer that is rotating (a real-keyed `pending`
                            // epoch advertised alongside its `active` one),
                            // stand up the transient overlap Device toward the
                            // peer's new key so the make-before-break cutover
                            // can happen once that session is live. No-op for
                            // steady state (no rotating peers).
                            if let Err(e) =
                                maybe_start_role_b(&mut tunnels, &enforcers, &rot, &ds).await
                            {
                                eprintln!("wiremesh-gateway: Role B setup failed: {e}");
                            }
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
                                vec![],
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
                        Ok(Some(sync::SyncEvent::Rotate(d))) => {
                            eprintln!(
                                "wiremesh-gateway: RotateDirective received (epoch={})",
                                d.epoch
                            );
                            if let Err(e) = handle_rotate(
                                &mut epoch_keys,
                                &mut tunnels,
                                &enforcers,
                                &rot,
                                d.epoch,
                                applied.as_ref(),
                                &mut client,
                            )
                            .await
                            {
                                eprintln!("wiremesh-gateway: Role A rotation failed: {e}");
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
    /// The shared "active tun" descriptor (ifname + priv key + port +
    /// change-guard) — the SAME `Arc` the sync loop's `apply_state` and the
    /// rotation cutover hold. `set_peer_endpoint` reads it (which tun to point a
    /// punched/relayed endpoint at, and its priv key/port/change-guard) and
    /// `run_path_ticks` reads `.ifname` (which tun to poll for liveness), so
    /// after a Role-A cutover both follow the new epoch's tun rather than the
    /// drained/torn-down `wg0`.
    active: Arc<std::sync::Mutex<ActiveTunInfo>>,
    /// The BASE WireGuard listen port (`wg0`'s), fixed for the process lifetime.
    /// The transient hole-punch socket (`punch::punch_candidates`) binds this —
    /// NOT the active port — because it shares the port via `SO_REUSEPORT` with
    /// boringtun's socket, and post-cutover the live traffic is on the new tun's
    /// offset port: binding the base (now-idle/retired) port keeps a punch from
    /// stealing the new tun's inbound datagrams. In steady state (no rotation)
    /// base == active port, so this is identical to the pre-rotation behavior.
    base_wg_port: u16,
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
    /// Shared Role-B `wg0` pin map (peer `gateway_id` -> old-epoch pubkey) — so
    /// `set_peer_endpoint` builds the same pinned config `apply_state` does and
    /// a punch during a rotation overlap can't rekey `wg0` off the pin.
    wg0_pins: Arc<std::sync::Mutex<HashMap<u64, String>>>,
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

    let wg_port = ctx.base_wg_port;
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
    // Resolve the ACTIVE tun (ifname + priv key + port), captured together so
    // the device we build and the ifname we apply it to are consistent even if
    // a cutover flips `active` concurrently.
    let (ifname, priv_key, wg_port) = {
        let a = ctx.active.lock().unwrap();
        (a.ifname.clone(), a.priv_key.clone(), a.wg_port)
    };
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
        // Honor the same Role-B `wg0` pin `apply_state` uses, so a punch/relay
        // re-point during a rotation overlap can't rekey the active tun off the
        // pinned old-epoch key (make-before-break), and — with the change-guard
        // below — resolving to an already-applied endpoint is a true no-op that
        // never resets the live session.
        let pins = ctx.wg0_pins.lock().unwrap();
        reconcile::device_config_pinned(&ds, &priv_key, wg_port, KEEPALIVE, &pins)
    };
    apply_device_if_changed(&ifname, &dev, &ctx.active).await?;
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
    let local_peer_hint =
        SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, ctx.active.lock().unwrap().wg_port));
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

        let ifname = ctx.active.lock().unwrap().ifname.clone();
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

/// Apply `dev` to `ifname` ONLY if it differs from the last config recorded in
/// the active tun's `applied_config` change-guard (its encoded UAPI `set`
/// string). boringtun rebuilds a peer's entire session on every `replace_peers`
/// apply (see [`ActiveTunInfo::applied_config`]), so re-pushing an identical
/// config would needlessly reset the live WireGuard session and drop in-flight
/// traffic — this is the guard that makes a redundant re-reconcile (a
/// policy-only delta, a punch re-confirm of the same endpoint, a peer's promote
/// under an active Role-B pin) a genuine no-op on the data plane. The blocking
/// `uapi::apply` runs inside `spawn_blocking`.
async fn apply_device_if_changed(
    ifname: &str,
    dev: &DeviceConfig,
    active: &Arc<std::sync::Mutex<ActiveTunInfo>>,
) -> anyhow::Result<()> {
    let encoded = uapi::encode_set(dev).context("encoding active-tun device config")?;
    if active.lock().unwrap().applied_config.as_deref() == Some(encoded.as_str()) {
        return Ok(());
    }
    let ifn = ifname.to_string();
    let dev = dev.clone();
    tokio::task::spawn_blocking(move || uapi::apply(&ifn, &dev))
        .await
        .context("active-tun UAPI apply task panicked")??;
    active.lock().unwrap().applied_config = Some(encoded);
    Ok(())
}

/// Apply one desired state to the data plane (tunnel peers, enforcer, routes).
///
/// The WG device peers, the change-guard, and the peer-segment routes ALL
/// follow the ACTIVE tun (`active`): boot's `wg0` in steady state, and after a
/// Role-A cutover the new epoch's `wg0e<N>` — which is what lets the old epoch's
/// `wg0` be torn down afterward without this ever trying to `uapi::apply` to a
/// Device that no longer exists. The current policy IR is applied to EVERY live
/// enforcer (see below), not just the active tun's.
async fn apply_state(
    enforcers: &Arc<Mutex<HashMap<u32, GatewayEnforcer>>>,
    prev: Option<&DesiredState>,
    ds: &DesiredState,
    active: &Arc<std::sync::Mutex<ActiveTunInfo>>,
    wg0_pins: &Arc<std::sync::Mutex<HashMap<u64, String>>>,
) -> anyhow::Result<()> {
    // Resolve the active tun (ifname + priv key + port), captured together.
    let (ifname, priv_key, wg_port) = {
        let a = active.lock().unwrap();
        (a.ifname.clone(), a.priv_key.clone(), a.wg_port)
    };
    // Build the (cheap, synchronous) active-tun device config, pinning any
    // rotating peer's entry to its old epoch key (Role B make-before-break;
    // empty pin map in steady state = identical to the pre-rotation config),
    // then apply it only if it actually changed.
    let dev = {
        let pins = wg0_pins.lock().unwrap();
        reconcile::device_config_pinned(ds, &priv_key, wg_port, KEEPALIVE, &pins)
    };
    apply_device_if_changed(&ifname, &dev, active).await?;
    // Apply the current policy IR to EVERY live enforcer (boot tun + every
    // rotation tun), not just the active one — a policy TIGHTENING during/after
    // a rotation overlap must reach the tun actually carrying traffic (Role A's
    // new tun; Role B's overlap tun). `apply_if_changed` is idempotent per
    // policy_version, so applying to all entries each time is cheap and correct.
    {
        let mut map = enforcers.lock().await;
        for e in map.values_mut() {
            e.apply_if_changed(ds)?;
        }
    }
    let empty = DesiredState::default();
    let diff = reconcile::route_diff(prev.unwrap_or(&empty), ds);
    for cidr in &diff.to_add {
        routes::add_route(cidr, &ifname)?;
    }
    for cidr in &diff.to_del {
        routes::del_route(cidr, &ifname)?;
    }
    Ok(())
}

/// Service a pending old-epoch retire the rotation tick has signalled via
/// [`RotationShared::retire_ready`]. Runs in the run task, which owns the
/// non-`Send` `tunnels` (and drives the shared `enforcers`). Idempotent and a
/// no-op when nothing is pending: `retire_ready` is consumed (`take`n) and the
/// [`Rotation`] SM only emits `TearDown` from `CutOver`, returning `None` if
/// already `Idle`. Tears the old epoch's Device down (drops the boringtun
/// Device — its private key gone from any live Device — and `ip link del`s the
/// tun) and evicts its enforcer (closing the map's per-epoch entry).
async fn service_retire(
    tunnels: &mut TunnelSet,
    enforcers: &Arc<Mutex<HashMap<u32, GatewayEnforcer>>>,
    rot: &RotationShared,
) {
    let Some(old_epoch) = rot.retire_ready.lock().unwrap().take() else {
        return;
    };
    // Drive the SM (guard: only from CutOver; idempotent). Pass the OLD epoch —
    // the SM doesn't cross-check, so the caller must supply the correct one.
    let action = rot.rotation.lock().unwrap().on_epoch_retired(old_epoch);
    let Some(RotationAction::TearDown { epoch }) = action else {
        eprintln!(
            "wiremesh-gateway: retire signalled for epoch {old_epoch} but rotation SM not in \
             CutOver; ignoring"
        );
        return;
    };
    if let Err(e) = tunnels.tear_down(epoch) {
        eprintln!("wiremesh-gateway: tearing down retired epoch {epoch} Device failed: {e}");
    }
    enforcers.lock().await.remove(&epoch);
    eprintln!(
        "wiremesh-gateway: retired epoch {epoch} — old Device torn down (key gone), enforcer evicted"
    );
}

/// Fold each live enforcer's [`Counters`] into one aggregate for the metrics
/// scrape: sum `default_deny` and merge `by_rule` (summing per-rule hits). In
/// the steady state (no rotation) the map has a single entry, so the aggregate
/// equals that one enforcer's counters — identical to the pre-Step-1 metric.
/// Aggregating (rather than reading only epoch 0) means a deny recorded on a
/// rotation's new-epoch tun is still counted post-cutover.
fn aggregate_counters(all: impl IntoIterator<Item = Counters>) -> Counters {
    let mut agg = Counters { by_rule: std::collections::BTreeMap::new(), default_deny: 0 };
    for c in all {
        agg.default_deny = agg.default_deny.saturating_add(c.default_deny);
        for (rule, hits) in c.by_rule {
            let e = agg.by_rule.entry(rule).or_insert(0);
            *e = e.saturating_add(hits);
        }
    }
    agg
}

// --- Key-rotation make-before-break wiring -----------------------------------

/// Shared, `Send` rotation state — cloned into the observation tick
/// ([`run_rotation_ticks`]) and read/written from the sync loop. Deliberately
/// holds NO boringtun `Device`/`TunnelSet` (those are non-`Send` and stay
/// owned by the `block_on`'d `run` task); the tick only ever needs a rotation
/// Device's ifname (a `String`) to read its liveness by UAPI, never a handle
/// to the Device itself. Every field is `Copy`/`String`/`Arc<_>`, and every
/// `std::sync::Mutex` guard is taken in a tight scope and dropped before any
/// `.await` (same discipline as [`PathCtx`]).
#[derive(Clone)]
struct RotationShared {
    /// Base WireGuard listen port (epoch-0 / `wg0`), the offset anchor for a
    /// rotation Device's port (`base + (N - active_epoch)`).
    base_wg_port: u16,
    /// Boot tun ifname (`wg0`); a rotation Device is `<base_tun>e<N>`.
    base_tun: String,
    state_dir: PathBuf,
    identity: Arc<Identity>,
    controller_sync_addr: SocketAddr,
    /// This gateway's own rotation state machine (Role A). `on_directive`
    /// (sync loop) and `on_new_epoch_session` (tick) both drive it.
    rotation: Arc<std::sync::Mutex<Rotation>>,
    /// Present while THIS gateway is rotating its own key (Role A): what the
    /// tick must watch on the new tun to trigger the route flip.
    role_a: Arc<std::sync::Mutex<Option<RoleA>>>,
    /// Rotating PEERS this gateway is overlapping toward (Role B), keyed by
    /// the rotating peer's `gateway_id`.
    role_b: Arc<std::sync::Mutex<HashMap<u64, RoleB>>>,
    /// The shared "active tun" descriptor (same `Arc` [`PathCtx`] and the sync
    /// loop hold) — `wg0` until THIS gateway's own Role-A cutover flips it to
    /// the new epoch's tun (ifname + priv key + port + reset change-guard).
    active: Arc<std::sync::Mutex<ActiveTunInfo>>,
    /// Shared Role-B `wg0` pin map (same `Arc` [`PathCtx`] holds). Role B adds
    /// an entry when it stands up an overlap so every `wg0` apply keeps that
    /// peer's base-tun session on its old epoch key across the promote.
    wg0_pins: Arc<std::sync::Mutex<HashMap<u64, String>>>,
    /// Latest applied desired state (same `Arc` [`PathCtx`] holds). Read at a
    /// Role-A cutover to SEED the new tun's change-guard with the exact config
    /// `apply_state`/`set_peer_endpoint` will recompute — so those become
    /// no-ops on the new tun and never clobber the correct offset-port session
    /// `handle_rotate` set up out-of-band (make-before-break).
    desired: Arc<std::sync::Mutex<Option<DesiredState>>>,
    /// Signal from the rotation tick to the run task: the OLD epoch to retire
    /// (tear its Device down + evict its enforcer) once every peer has cut over
    /// to the new tun and the retire grace has elapsed. The run task owns the
    /// non-`Send` `tunnels`, so the tick can't tear down directly; it sets this
    /// flag and [`service_retire`] (in the run task) consumes it. `None` when
    /// nothing is pending.
    retire_ready: Arc<std::sync::Mutex<Option<u32>>>,
}

/// Role A (this gateway is rotating its own key): the observation the tick
/// needs to decide the make-before-break flip.
#[derive(Clone)]
struct RoleA {
    /// The new epoch's tun (`wg0e<N>`) — watched for the peer's handshake.
    new_tun: String,
    /// The new epoch's own private key — seeded into `active` at cutover so
    /// `apply_state`/`set_peer_endpoint` reconcile the new tun with the right
    /// key afterward.
    new_priv: String,
    /// The new epoch's WireGuard listen port (the offset port) — likewise
    /// seeded into `active` at cutover.
    new_port: u16,
    /// The OLD (pre-rotation) active epoch number — what gets torn down once
    /// the retire grace passes.
    old_epoch: u32,
    /// `(peer active-key hex, that peer's segment CIDRs)`: the peer talks to
    /// us on `new_tun` with its ACTIVE key; once that session is
    /// rx-corroborated live we flip the peer's CIDR routes onto `new_tun`.
    peers: Vec<(String, Vec<String>)>,
}

/// Role B (a PEER of this gateway is rotating): the transient overlap Device
/// this gateway stood up toward the peer's new key, and what to do once its
/// session is live.
#[derive(Clone)]
struct RoleB {
    pending_epoch: u32,
    new_tun: String,
    /// The rotating peer's PENDING-key hex — the peer entry we watch on
    /// `new_tun` for a live, rx-corroborated session.
    peer_pending_hex: String,
    /// The rotating peer's segment CIDRs, flipped onto `new_tun` at cutover.
    peer_cidrs: Vec<String>,
    /// Set once we've flipped routes AND reported the live epoch ack — a
    /// completed Role-B cutover for this peer, not re-driven.
    done: bool,
}

/// Role A: handle a `RotateDirective`. Mint+persist the new epoch key, bring
/// its Device up alongside `wg0` (the "make"), reconcile it against the
/// current peers at the offset port, submit the real pubkey to the controller,
/// and arm the observation tick to watch for the peer's live session. Idempotent
/// against a re-entrant directive (the SM only honors one from `Idle`).
async fn handle_rotate(
    epoch_keys: &mut EpochKeys,
    tunnels: &mut TunnelSet,
    enforcers: &Arc<Mutex<HashMap<u32, GatewayEnforcer>>>,
    rot: &RotationShared,
    directive_epoch: u32,
    applied: Option<&DesiredState>,
    client: &mut SyncClient<Channel>,
) -> anyhow::Result<()> {
    let action = rot.rotation.lock().unwrap().on_directive(directive_epoch);
    let Some(RotationAction::MintBringUpSubmit { epoch: n }) = action else {
        eprintln!(
            "wiremesh-gateway: ignoring RotateDirective(epoch={directive_epoch}) — a rotation is \
             already in flight"
        );
        return Ok(());
    };
    let ds = applied.ok_or_else(|| {
        anyhow::anyhow!("RotateDirective arrived before any desired state; no peer set to mint against")
    })?;

    let new_key = epoch_keys.generate_next()?.clone();
    epoch_keys.persist(&rot.state_dir)?;
    if new_key.epoch != n {
        eprintln!(
            "wiremesh-gateway: WARNING minted epoch {} != directive epoch {n}; proceeding on the \
             directive epoch for the port/tun convention",
            new_key.epoch
        );
    }

    let active_epoch = epoch_keys.active().map(|k| k.epoch).unwrap_or(0);
    let offset = u16::try_from(n.saturating_sub(active_epoch)).unwrap_or(0);
    let new_port = rot.base_wg_port.saturating_add(offset);
    let new_tun = format!("{}e{}", rot.base_tun, n);

    tunnels.bring_up(n, &new_tun, &new_key.private_key_b64, new_port, TUN_MTU)?;

    // SECURITY (fail-closed): attach the L4 enforcer to the new epoch tun with
    // the current policy BEFORE the device is made session-capable (peer
    // apply, below). `bring_up` only brought the Device up with an EMPTY peer
    // set, so at this point the tun cannot yet form a WG session with anyone —
    // attaching the enforcer here, ahead of the peer-apply, closes the
    // default-deny-bypass-on-new-tun gap with no unfiltered window. If
    // `attach`/`apply_if_changed` errors, tear the half-built tun back down
    // and propagate the error: the device never received peers, so it never
    // became traffic-capable — no fail-open on this path, unlike attaching
    // after the peer-apply (which would leave a session-capable, unenforced
    // tun on an attach failure).
    let mut ke = match GatewayEnforcer::attach(&new_tun) {
        Ok(ke) => ke,
        Err(e) => {
            let _ = tunnels.tear_down(n);
            return Err(e).with_context(|| format!("attaching enforcer to rotation tun {new_tun}"));
        }
    };
    if let Err(e) = ke.apply_if_changed(ds) {
        let _ = tunnels.tear_down(n);
        return Err(e).with_context(|| format!("applying policy to rotation tun {new_tun}"));
    }
    // Insert into the SHARED enforcer map keyed by EPOCH (insert is last on this
    // path, so the fail-closed teardown above never has to remove it), so every
    // later `apply_state` reaches this new tun's enforcer.
    enforcers.lock().await.insert(n, ke);

    let dev =
        reconcile::device_config_at_port(ds, &new_key.private_key_b64, new_port, ROTATION_KEEPALIVE);
    uapi::apply(&new_tun, &dev)?;

    let peers: Vec<(String, Vec<String>)> = ds
        .peers
        .iter()
        .filter_map(|p| {
            let hex = pubkey_b64_to_hex(p.active_pubkey_b64.as_deref()?)?;
            Some((hex, p.allowed_ips.clone()))
        })
        .collect();
    *rot.role_a.lock().unwrap() = Some(RoleA {
        new_tun: new_tun.clone(),
        new_priv: new_key.private_key_b64.clone(),
        new_port,
        old_epoch: active_epoch,
        peers,
    });

    sync::submit_epoch_key(client, n, new_key.pubkey_b64.clone()).await?;
    eprintln!(
        "wiremesh-gateway: Role A minted epoch {n} on {new_tun}:{new_port}, submitted pubkey; \
         awaiting rx-corroborated session to flip routes"
    );
    Ok(())
}

/// Role B: for each peer in `ds` that is rotating (advertises a real-keyed
/// `pending` epoch alongside its `active` one) and isn't already being
/// overlapped, bring up a transient overlap Device toward the peer's pending
/// key (this gateway's OWN active key on the offset port) and arm the tick to
/// flip+ack once that session is live. No-op in steady state.
async fn maybe_start_role_b(
    tunnels: &mut TunnelSet,
    enforcers: &Arc<Mutex<HashMap<u32, GatewayEnforcer>>>,
    rot: &RotationShared,
    ds: &DesiredState,
) -> anyhow::Result<()> {
    for peer in &ds.peers {
        let (Some(active), Some(pending)) = (peer.active_key(), peer.pending_key()) else {
            continue;
        };
        let aid = peer.gateway_id;
        if rot.role_b.lock().unwrap().contains_key(&aid) {
            continue;
        }

        let pending_epoch = pending.epoch;
        let offset = u16::try_from(pending_epoch.saturating_sub(active.epoch)).unwrap_or(0);
        let listen_port = rot.base_wg_port.saturating_add(offset);
        let new_tun = format!("{}e{}", rot.base_tun, pending_epoch);

        // Peer set for the overlap Device: exactly the rotating peer at its
        // pending key + offset endpoint (`pending_peer_configs`, filtered to
        // this peer's pending pubkey so a second rotating peer never lands on
        // this peer's single-purpose Device).
        let peers: Vec<_> = reconcile::pending_peer_configs(ds, ROTATION_KEEPALIVE)
            .into_iter()
            .filter(|pc| pc.public_key_b64 == pending.pubkey_b64)
            .collect();
        if peers.is_empty() {
            continue; // couldn't build the peer's offset endpoint — skip this round
        }

        let own_priv = rot.identity.wg_private_key_b64.clone();
        tunnels.bring_up(pending_epoch, &new_tun, &own_priv, listen_port, TUN_MTU)?;

        // SECURITY (fail-closed): attach the L4 enforcer to this overlap
        // Device with the current policy BEFORE the device is made
        // session-capable (peer apply, below). `bring_up` only brought the
        // Device up with an EMPTY peer set, so at this point the tun cannot
        // yet form a WG session toward the rotating peer — attaching the
        // enforcer here, ahead of the peer-apply, closes the
        // default-deny-bypass-on-new-tun gap with no unfiltered window. If
        // `attach`/`apply_if_changed` errors, tear the half-built tun back
        // down and propagate the error: the device never received peers, so
        // it never became traffic-capable — no fail-open on this path, unlike
        // attaching after the peer-apply (which would leave a
        // session-capable, unenforced tun on an attach failure).
        let mut ke = match GatewayEnforcer::attach(&new_tun) {
            Ok(ke) => ke,
            Err(e) => {
                let _ = tunnels.tear_down(pending_epoch);
                return Err(e).with_context(|| format!("attaching enforcer to rotation tun {new_tun}"));
            }
        };
        if let Err(e) = ke.apply_if_changed(ds) {
            let _ = tunnels.tear_down(pending_epoch);
            return Err(e).with_context(|| format!("applying policy to rotation tun {new_tun}"));
        }
        // Insert into the SHARED enforcer map keyed by EPOCH (insert is last on
        // this path, so the fail-closed teardown above never has to remove it),
        // so every later `apply_state` reaches this overlap tun's enforcer. No
        // `std::sync::Mutex` guard is held across this `.await`.
        enforcers.lock().await.insert(pending_epoch, ke);

        uapi::apply(
            &new_tun,
            &DeviceConfig { private_key_b64: own_priv, listen_port, peers },
        )?;

        let Some(peer_pending_hex) = pubkey_b64_to_hex(&pending.pubkey_b64) else {
            anyhow::bail!("rotating peer {aid} pending pubkey is not valid base64");
        };
        // Pin this peer's `wg0` entry to its CURRENT (old) epoch key for the
        // overlap, so its later promote delta can't rekey `wg0` and reset the
        // still-in-use old session (make-before-break on the base tun).
        rot.wg0_pins.lock().unwrap().insert(aid, active.pubkey_b64.clone());
        rot.role_b.lock().unwrap().insert(
            aid,
            RoleB {
                pending_epoch,
                new_tun: new_tun.clone(),
                peer_pending_hex,
                peer_cidrs: peer.allowed_ips.clone(),
                done: false,
            },
        );
        eprintln!(
            "wiremesh-gateway: Role B overlap Device up on {new_tun}:{listen_port} toward peer \
             {aid} epoch {pending_epoch}"
        );
    }
    Ok(())
}

/// First host address of an `ip/prefix` CIDR (network address + 1), e.g.
/// `10.10.2.0/24` -> `10.10.2.1` — conventionally the peer gateway's own
/// segment address, and always a member of the peer's `allowed_ips`. Used as
/// an out-of-band handshake-probe target. `None` for a malformed CIDR.
fn first_host_of(cidr: &str) -> Option<String> {
    let (ip, prefix) = cidr.split_once('/')?;
    let addr: std::net::Ipv4Addr = ip.parse().ok()?;
    let prefix: u32 = prefix.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let base = u32::from(addr);
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    let network = base & mask;
    Some(std::net::Ipv4Addr::from(network.wrapping_add(1)).to_string())
}

/// Out-of-band handshake kick for a rotation Device (blocking; shells out like
/// the rest of `routes`). boringtun does NOT proactively initiate a WG
/// handshake from persistent-keepalive alone (Cycle-4b/keyrot-spike finding:
/// the `spike/keyrot` choreography had to send a probe to bring the new key's
/// session live) — it only starts one when it has an actual packet to send to
/// the peer. So temporarily route a single ICMP echo at the peer segment's
/// first host THROUGH the new tun (a /32, so the real flood's route is
/// untouched — make-before-break preserved) sourced from a real local address:
/// that gives boringtun a packet whose destination matches the peer's
/// `allowed_ips`, which fires the handshake. The echo itself may be lost (the
/// point is the handshake); the route is removed immediately after. Entirely
/// best-effort — every step is ignore-on-error, since this only needs to
/// SUCCEED often enough that one handshake completes, after which the 3s
/// keepalive keeps the session live.
fn probe_overlap_handshake(new_tun: &str, cidr: &str, src_ip: &str) {
    use std::process::Command;
    let Some(target) = first_host_of(cidr) else { return };
    let route = format!("{target}/32");
    let _ = Command::new("ip").args(["route", "replace", &route, "dev", new_tun]).status();
    let _ = Command::new("ping").args(["-c", "1", "-W", "1", "-I", src_ip, &target]).status();
    let _ = Command::new("ip").args(["route", "del", &route, "dev", new_tun]).status();
}

/// Kick the overlap handshake for `new_tun` toward each of `cidrs`, sourced
/// from this gateway's first routable local address (needed so the probe
/// packet actually has a source and gets sent; the destination — not the
/// source — is what makes boringtun pick the peer and handshake). No-op if the
/// gateway has no routable local address to source from. Runs the blocking
/// shell-outs off the async runtime.
async fn kick_overlap(new_tun: String, cidrs: Vec<String>, base_wg_port: u16) {
    let _ = tokio::task::spawn_blocking(move || {
        let locals = netif::local_wg_endpoints(base_wg_port);
        let Some(src) = locals.first().and_then(|e| e.rsplit_once(':').map(|(ip, _)| ip.to_string()))
        else {
            return;
        };
        for cidr in &cidrs {
            probe_overlap_handshake(&new_tun, cidr, &src);
        }
    })
    .await;
}

/// Read `ifname`'s per-peer liveness and return the subset of `wanted`
/// pubkey-hexes whose session is rx-corroborated live: a completed handshake
/// AND `rx_bytes > 0` (real decrypted inbound, e.g. a keepalive) — the
/// make-before-break gate. `rx > 0` is what distinguishes a genuinely live
/// new-epoch session from boringtun advancing `last_handshake_time` while
/// retrying an unanswered handshake with no reply (Cycle 4b path-liveness
/// finding); we must NEVER flip routes onto the new epoch on a handshake
/// alone. `None` if the Device's UAPI can't be read yet (not up).
async fn read_live_peers(
    ifname: &str,
    wanted: impl Iterator<Item = String>,
) -> Option<HashSet<String>> {
    let wanted: HashSet<String> = wanted.collect();
    let ifn = ifname.to_string();
    let liveness = match tokio::task::spawn_blocking(move || uapi::get_peer_liveness(&ifn)).await {
        Ok(Ok(m)) => m,
        _ => return None,
    };
    let mut live = HashSet::new();
    for w in wanted {
        if let Some((Some(_), rx)) = liveness.get(&w).copied() {
            if rx > 0 {
                live.insert(w);
            }
        }
    }
    Some(live)
}

/// Report a single live epoch ack to the controller over a fresh short-lived
/// mTLS Sync channel (a unary `Report`, like the testkit's helper) — the
/// observation tick has no access to the sync loop's own `client`, and a
/// unary Report neither registers a Watch nor disturbs the open one.
async fn send_epoch_ack(rot: &RotationShared, ack: EpochAck) -> anyhow::Result<()> {
    let mut client: SyncClient<Channel> =
        sync::connect(rot.controller_sync_addr, &rot.identity).await?;
    sync::report(&mut client, 0, vec![], vec![], vec![ack]).await
}

/// The rotation observation driver: every `ROTATION_TICK_PERIOD`, watch any
/// in-flight rotation's new-epoch tun for a live, rx-corroborated session and
/// execute the make-before-break cutover — Role A flips its own peer routes
/// (driven through the `Rotation` SM's `on_new_epoch_session`/`FlipRoutes`) and
/// repoints the shared `active` descriptor at the new tun, Role B flips the
/// rotating peer's routes and reports the live epoch ack that advances the
/// controller's promote SM.
///
/// Old-epoch RETIRE (Role A only): once EVERY peer's session on the new tun has
/// stayed rx-corroborated live continuously for [`RETIRE_GRACE`] after the
/// cutover — so every peer has provably cut over and no peer still needs the
/// old key — this signals the OLD epoch via `retire_ready` for the run task's
/// [`service_retire`] to tear its Device down (dropping the old private key)
/// and evict its enforcer. `retire_all_live_since` (loop-local, like
/// `run_path_ticks`'s `last_seen`) tracks the continuous-liveness grace; it
/// resets if liveness ever lapses before the grace elapses (make-before-break:
/// never retire the old Device while any peer might still depend on it). A
/// non-rotating gateway (no `role_a`) and a Role-B peer never enter this path,
/// so their `wg0` is never torn down — the key non-regression property.
async fn run_rotation_ticks(rot: RotationShared) {
    // Loop-local: when did EVERY Role-A peer first become (and stay)
    // rx-corroborated live on the new tun after cutover. `Some` only while a
    // continuous live spell is in progress; reset to `None` the moment liveness
    // lapses, so the grace only fires after an UNINTERRUPTED window.
    let mut retire_all_live_since: Option<Instant> = None;
    loop {
        tokio::time::sleep(ROTATION_TICK_PERIOD).await;

        // Role A: our own new epoch's Device.
        let role_a = rot.role_a.lock().unwrap().clone();
        if let Some(a) = role_a {
            let hexes = a.peers.iter().map(|(h, _)| h.clone());
            let live = read_live_peers(&a.new_tun, hexes).await;
            let any_live =
                live.as_ref().map_or(false, |l| a.peers.iter().any(|(hex, _)| l.contains(hex)));
            let all_live =
                live.as_ref().map_or(false, |l| a.peers.iter().all(|(hex, _)| l.contains(hex)));
            let phase = rot.rotation.lock().unwrap().phase.clone();
            match phase {
                RotationPhase::Overlapping { .. } => {
                    if any_live {
                        let action = rot.rotation.lock().unwrap().on_new_epoch_session(true);
                        if let Some(RotationAction::FlipRoutes { epoch }) = action {
                            for (_, cidrs) in &a.peers {
                                for cidr in cidrs {
                                    if let Err(e) = routes::add_route(cidr, &a.new_tun) {
                                        eprintln!(
                                            "wiremesh-gateway: Role A route flip {cidr} -> {} failed: {e}",
                                            a.new_tun
                                        );
                                    }
                                }
                            }
                            // SEED the new tun's change-guard with the exact
                            // config `apply_state`/`set_peer_endpoint` will
                            // recompute for it (`device_config_pinned` at the
                            // new key/port). `handle_rotate` already brought the
                            // new tun up with the CORRECT offset-port peer
                            // endpoints out-of-band; a subsequent apply through
                            // the guard would otherwise rebuild it with base-port
                            // endpoints (`primary_endpoint`) and tear the live
                            // session down. Seeding makes those recomputes a
                            // no-op on the data plane while the enforcer-policy
                            // loop (unguarded) still reaches the new tun.
                            let applied_config = {
                                let ds_guard = rot.desired.lock().unwrap();
                                ds_guard.as_ref().and_then(|ds| {
                                    let pins = rot.wg0_pins.lock().unwrap();
                                    let dev = reconcile::device_config_pinned(
                                        ds, &a.new_priv, a.new_port, KEEPALIVE, &pins,
                                    );
                                    uapi::encode_set(&dev).ok()
                                })
                            };
                            // Flip the shared active descriptor onto the new tun:
                            // apply_state/set_peer_endpoint/path-ticks now all
                            // follow it.
                            *rot.active.lock().unwrap() = ActiveTunInfo {
                                ifname: a.new_tun.clone(),
                                priv_key: a.new_priv.clone(),
                                wg_port: a.new_port,
                                applied_config,
                            };
                            eprintln!(
                                "wiremesh-gateway: Role A cutover — routes flipped onto {} (epoch {epoch})",
                                a.new_tun
                            );
                        }
                    } else {
                        // Not live yet: kick the overlap handshake (boringtun
                        // won't initiate from keepalive alone). The `ping -W1`
                        // timeout naturally rate-limits this to ~once/sec while
                        // the peer's Device isn't up yet.
                        let cidrs: Vec<String> = a.peers.iter().flat_map(|(_, c)| c.clone()).collect();
                        kick_overlap(a.new_tun.clone(), cidrs, rot.base_wg_port).await;
                    }
                }
                RotationPhase::CutOver { .. } => {
                    // Post-cutover: retire the OLD epoch once every peer has
                    // stayed live on the new tun for the whole grace.
                    if all_live {
                        let elapsed = retire_all_live_since
                            .get_or_insert_with(Instant::now)
                            .elapsed();
                        if elapsed >= RETIRE_GRACE {
                            *rot.retire_ready.lock().unwrap() = Some(a.old_epoch);
                            // Stop watching (and re-signalling) — the run task
                            // will tear the old Device down and the SM will move
                            // to Idle.
                            *rot.role_a.lock().unwrap() = None;
                            retire_all_live_since = None;
                            eprintln!(
                                "wiremesh-gateway: Role A — every peer live on {} for the grace; \
                                 signalling retire of old epoch {}",
                                a.new_tun, a.old_epoch
                            );
                        }
                    } else {
                        // Liveness lapsed before the grace elapsed: restart it —
                        // never retire the old Device while a peer might still
                        // need the old key (make-before-break).
                        retire_all_live_since = None;
                    }
                }
                RotationPhase::Idle => {}
            }
        }

        // Role B: transient overlap Device(s) toward rotating peer(s).
        let pending_b: Vec<(u64, RoleB)> = rot
            .role_b
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, b)| !b.done)
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        for (aid, b) in pending_b {
            let live =
                read_live_peers(&b.new_tun, std::iter::once(b.peer_pending_hex.clone())).await;
            if !live.map_or(false, |l| l.contains(&b.peer_pending_hex)) {
                // Not live yet: kick the overlap handshake toward the rotating
                // peer (same rationale as Role A above).
                kick_overlap(b.new_tun.clone(), b.peer_cidrs.clone(), rot.base_wg_port).await;
                continue;
            }
            for cidr in &b.peer_cidrs {
                if let Err(e) = routes::add_route(cidr, &b.new_tun) {
                    eprintln!(
                        "wiremesh-gateway: Role B route flip {cidr} -> {} failed: {e}",
                        b.new_tun
                    );
                }
            }
            let ack = EpochAck { peer_gateway_id: aid, epoch: b.pending_epoch, live: true };
            match send_epoch_ack(&rot, ack).await {
                Ok(()) => {
                    if let Some(e) = rot.role_b.lock().unwrap().get_mut(&aid) {
                        e.done = true;
                    }
                    // NB: Role B does NOT flip the shared `active` descriptor.
                    // This gateway isn't rotating its OWN key — its `wg0` device
                    // config stays pinned (old-epoch peer key) and must not be
                    // rebuilt on the overlap tun, and its `wg0` is never torn
                    // down. The peer's return-path routes were already flipped
                    // onto `b.new_tun` directly above; that's all Role B needs.
                    eprintln!(
                        "wiremesh-gateway: Role B cutover — peer {aid} epoch {} live; routes on {}, \
                         epoch ack sent",
                        b.pending_epoch, b.new_tun
                    );
                }
                Err(e) => eprintln!(
                    "wiremesh-gateway: Role B epoch ack for peer {aid} failed (will retry): {e}"
                ),
            }
        }
    }
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
            active: Arc::new(std::sync::Mutex::new(ActiveTunInfo {
                ifname: String::new(),
                priv_key: String::new(),
                wg_port: 0,
                applied_config: None,
            })),
            base_wg_port: 0,
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
            wg0_pins: Arc::new(std::sync::Mutex::new(HashMap::new())),
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
