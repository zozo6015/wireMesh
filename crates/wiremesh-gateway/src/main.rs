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
use wiremesh_gateway::path::{directive_should_punch, Path, PathAction, PathState};
use wiremesh_gateway::punch_backoff::{PunchBackoff, PunchDecision};
use wiremesh_gateway::relay::RelayTransport;
use wiremesh_gateway::rotation::{Rotation, RotationAction, RotationPhase};
use wiremesh_gateway::state::DesiredState;
use wiremesh_gateway::tunnelset::TunnelSet;
use wiremesh_gateway::uapi::DeviceConfig;
use wiremesh_gateway::{netif, observe, punch, reconcile, routes, sync, uapi};
use wiremesh_proto::v1::sync_client::SyncClient;
use wiremesh_proto::v1::{EpochAck, PeerPath, RelayHealth};

const TUN_MTU: u32 = 1280;
const MSS: u16 = 1240;

// The steady-state persistent keepalive is NOT a constant here anymore
// (mesh-convergence fix T1): `uapi::PERSISTENT_KEEPALIVE_SECS` (25s) is baked
// into the steady-state `reconcile` builders themselves, so no call site in
// this file can configure a peer without it — see that constant's doc and
// `docs/research/ops-finding-multi-gateway-convergence.md` §5 (idle NAT
// mappings expired because no keepalive was set, sawtoothing working paths).

/// Persistent-keepalive for a rotation's transient overlap Devices
/// (`wg0e<N>`), deliberately much shorter than the steady-state
/// `uapi::PERSISTENT_KEEPALIVE_SECS`. persistent-keepalive is what makes boringtun proactively
/// INITIATE (and retry) a handshake for a peer that has an endpoint but no
/// data yet — a rotation Device carries no traffic until the cutover, so
/// without a tight keepalive its session can take a full 15s (or a missed
/// retry) to come live, stretching the rotation and risking the done-bar's
/// 90s budget. 3s brings the overlap session up promptly and re-tries fast if
/// the first handshake races the peer's Device coming up. Matches the
/// `spike/keyrot` choreography's short keepalive.
const ROTATION_KEEPALIVE: u16 = 3;
const OBSERVE_PERIOD: Duration = Duration::from_secs(20);

/// How long the endpoint-driven punch waits for ONE candidate's WG handshake to
/// land before advancing to the next (`punch::CandidateTrial`'s per-candidate
/// window). Chosen ≥ boringtun 0.6.0's ~5s handshake-retry cadence (spike
/// finding): a correct candidate, once nudged, completes its handshake within a
/// single RTT — well inside this window — so 5s is the time a WRONG candidate
/// costs before we move on, and one retry cycle is enough to be sure it is
/// wrong. See the reconciliation note on [`punch_and_apply`] for why this is
/// safe against `path::CONNECT_TIMEOUT` (the `Connecting` budget).
const PER_CANDIDATE_PUNCH_TIMEOUT: Duration = Duration::from_secs(5);

/// How often [`punch_and_apply`] re-polls its [`punch::CandidateTrial`] and
/// checks whether the peer's path has reached `Direct` (the rx-corroborated
/// liveness signal published by `run_path_ticks`). Sub-second so a completed
/// handshake is acted on promptly, without busy-spinning.
const PUNCH_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// How often the gateway sends a small VISIBLE overlay data probe to each peer
/// currently in a live state (`Direct`/`Relayed`), so the peer's `rx_bytes`
/// advances and the path SM's rx-corroborated liveness holds.
///
/// REQUIRED because boringtun 0.6.0 does NOT count a bare WireGuard
/// persistent-keepalive in `rx_bytes`: `noise/mod.rs::validate_decapsulated_
/// packet` returns early on a 0-length decrypted packet ("This is keepalive,
/// and not an error") BEFORE `self.rx_bytes += computed_len`. So keepalives
/// keep the NAT mapping warm but are INVISIBLE to `uapi::get_peer_liveness`,
/// and a keepalive-only-idle `Direct` path degrades exactly `DEGRADED_AFTER`
/// (45s) after the last real DATA packet even though the tunnel is perfectly
/// alive (convergence A4: `gwA[peer B]` left `direct` at t+36.9s ≈ 45s − the
/// pre-idle traffic gap). A one-byte overlay datagram decrypts to a NON-empty
/// inner packet, so it DOES bump the receiver's `rx_bytes` (counted before the
/// device's allowed-ips filter, so a dropped inner packet still counts). Every
/// gateway runs this, so each live pair exchanges a visible datagram every
/// interval and BOTH sides corroborate.
///
/// 20s is comfortably under `DEGRADED_AFTER` (45s) — each side refreshes the
/// other within one interval, ≥2 chances before the 45s threshold — and it
/// does NOT mask a genuinely dead peer: the probe only bumps rx on RECEIPT, so
/// a cut-off peer (nat_matrix case4's real silence) still shows flat rx and
/// degrades on schedule. It is also under the routers' 30s conntrack timeout,
/// so like the WG keepalive it keeps the NAT mapping warm.
const LIVENESS_PROBE_INTERVAL: Duration = Duration::from_secs(20);

/// Cap on how long we'll sleep waiting for a `PunchDirective`'s `go_unix_ms`
/// fire instant. The controller broker's back-to-back sends are the primary
/// go-skew guarantee (proto note); `go_unix_ms` is best-effort corroboration,
/// so a wildly-future value (bad clock) must not park a punch task forever.
const MAX_PUNCH_DELAY: Duration = Duration::from_secs(5);

/// Cadence of the path-state driver: poll WG handshakes and `tick` every peer
/// (spec §6.1). ~1s keeps state transitions responsive without hammering the
/// UAPI socket.
const PATH_TICK_PERIOD: Duration = Duration::from_secs(1);

/// How long a remembered-but-uncorroborated handshake-time advance stays
/// eligible for promotion to a real `on_handshake(_, true)` once an
/// `rx_bytes` delta arrives (mesh-convergence fix T2). Plan T2's rule is
/// "an rx delta must accompany the handshake evidence within the liveness
/// window", so this reuses the path SM's liveness window
/// (`path::DEGRADED_AFTER`, 45s) verbatim: a promotion can never certify a
/// handshake older than what the silence rules would already have condemned.
/// In practice corroboration lands far sooner — with
/// `uapi::PERSISTENT_KEEPALIVE_SECS` (25s, fix T1) on every peer, a real
/// completed handshake is followed by authenticated inbound within one
/// keepalive interval — while a boringtun false-advance (finding §4) refreshes
/// its pending entry every tick but never sees rx move, so it can never be
/// promoted no matter the window.
const HANDSHAKE_CORROBORATION_WINDOW: Duration = wiremesh_gateway::path::DEGRADED_AFTER;

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
    /// The peer set of the last config pushed to the active tun — i.e. what
    /// WireGuard currently holds (kept in lockstep with `applied_config`
    /// everywhere it's written). `apply_state` diffs this against the freshly
    /// built desired peers to detect the PURE-ADDITION case (a newcomer
    /// enrolling with every existing peer unchanged), which it then applies
    /// via the incremental, session-preserving [`uapi::add_peers`] instead of
    /// the session-destructive full `replace_peers` apply — the T8 done-bar's
    /// make-before-break requirement (finding §2). Empty whenever
    /// `applied_config` is `None`.
    applied_peers: Vec<uapi::PeerConfig>,
}

fn main() -> anyhow::Result<()> {
    // Live-deployment diagnostics: `-h`/`--help` and `-V`/`--version` are
    // resolved at the VERY TOP of arg handling — before the enroll-vs-run
    // dispatch below and before any required-flag validation — so they work
    // with no other args and never error (see `cli::cli_action`).
    match wiremesh_gateway::cli::cli_action(std::env::args()) {
        wiremesh_gateway::cli::CliAction::Help(m) => {
            print!("{m}");
            return Ok(());
        }
        wiremesh_gateway::cli::CliAction::Version(s) => {
            println!("{s}");
            return Ok(());
        }
        wiremesh_gateway::cli::CliAction::Run => {}
    }

    // `enroll` subcommand: one-shot token->Identity bootstrap, then exit. Any
    // other argv is the normal data-plane path (GatewayConfig::from_env reads
    // std::env::args() itself, so the normal path is unaffected).
    let mut args = std::env::args();
    let _argv0 = args.next();
    if args.next().as_deref() == Some("enroll") {
        let eargs = wiremesh_gateway::enroll::parse_args(args)?;
        let rt = tokio::runtime::Runtime::new()?;
        return rt.block_on(wiremesh_gateway::enroll::run_enroll(eargs));
    }

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
        applied_peers: Vec::new(),
    }));
    // Rotating peers whose `wg0` entry must stay pinned to their OLD epoch key
    // for the overlap's lifetime (Role B make-before-break) — read by every
    // `wg0` apply site so the peer's promote delta doesn't rekey `wg0`. Empty
    // in steady state.
    let wg0_pins = Arc::new(std::sync::Mutex::new(HashMap::<u64, String>::new()));
    // Live-endpoint pins (mesh-convergence fix T4): peer gateway_id -> the
    // "ip:port" its LIVE tunnel is actually using (punched mapping or
    // relay-transport local socket). Written by `set_peer_endpoint`, cleared
    // by `run_path_ticks` when a peer's path leaves the live states, and read
    // by EVERY steady-state device rebuild (`apply_state`,
    // `set_peer_endpoint`, the Role-A cutover guard seed) so a peer-set
    // re-apply — e.g. a NEW gateway enrolling — can never reset an
    // established tunnel's endpoint back to its static candidate (finding §2:
    // exactly that reset broke the working home↔FI pair when px enrolled).
    // Empty at boot: fail-static has no liveness yet, so the boot apply dials
    // candidates as before.
    let live_endpoints = Arc::new(std::sync::Mutex::new(HashMap::<u64, String>::new()));

    let mut applied: Option<DesiredState> = DesiredState::load(&cfg.state_dir)?;
    if let Some(ds) = &applied {
        eprintln!("wiremesh-gateway: fail-static boot from state.json rev {}", ds.revision);
        apply_state(&enforcers, None, ds, &active, &wg0_pins, &live_endpoints).await?;
        applied_version.store(ds.policy_version, Ordering::Relaxed);
    }

    // Observation loop (background). Binds the WG listen port with
    // SO_REUSEPORT alongside boringtun's own live socket on that same port
    // (spec §5.4) — see observe::report_once / observe::reuseport_udp.
    {
        let observe_addr = cfg.observe_addr.clone();
        let key = id.observe_key.clone();
        let gid = id.gateway_id;
        let port = cfg.wg_listen_port;
        tokio::spawn(async move {
            loop {
                // Resolve the observe `host:port` fresh EVERY tick — for a
                // controller behind a DDNS name this per-tick re-resolution
                // is what repoints observation at a rotated public IP without
                // a restart (see `sync::resolve_host_port`). A failed
                // resolution skips the tick; the next one retries.
                let a = match sync::resolve_host_port(&observe_addr).await {
                    Ok(a) => a,
                    // `{e:#}` (whole anyhow chain) because the io cause is
                    // the actionable part for a DDNS operator: NXDOMAIN vs
                    // dead resolver vs timeout. Distinct wording from the
                    // probe's "observe failed:" below so the two failure
                    // stages triage apart in logs.
                    Err(e) => {
                        eprintln!("wiremesh-gateway: observe resolve failed: {e:#}");
                        tokio::time::sleep(OBSERVE_PERIOD).await;
                        continue;
                    }
                };
                let k = key.clone();
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
        identity: Arc::new(id.clone()),
        desired: Arc::new(std::sync::Mutex::new(applied.clone())),
        paths: Arc::new(std::sync::Mutex::new(HashMap::new())),
        transitions: Arc::new(std::sync::Mutex::new(HashMap::new())),
        punching: Arc::new(std::sync::Mutex::new(HashSet::new())),
        relay_transports: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        relay_connecting: Arc::new(std::sync::Mutex::new(HashSet::new())),
        relay_next_idx: Arc::new(std::sync::Mutex::new(HashMap::new())),
        relay_pointed: Arc::new(std::sync::Mutex::new(HashMap::new())),
        endpoint_commit: Arc::new(tokio::sync::Mutex::new(())),
        wg0_pins: wg0_pins.clone(),
        peer_stats: Arc::new(std::sync::Mutex::new(HashMap::new())),
        live_endpoints: live_endpoints.clone(),
        punch_backoff: Arc::new(std::sync::Mutex::new(HashMap::new())),
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
                    // Per-peer rx/tx/handshake-age gauges (fix T5, finding
                    // §6): rendered from the snapshot `run_path_ticks`
                    // published off the SAME UAPI fetch the path SM diffed
                    // (≤1 tick stale). Age is computed at scrape time via
                    // `reported_handshake_age`, which normalizes boringtun
                    // 0.6.0's elapsed-time field semantics (a naive
                    // `now - t` would report ~56 years for a live tunnel —
                    // see that helper's doc); a never-handshaked peer yields
                    // `None`, and the renderer omits its age line — absence,
                    // not a bogus 0, mirroring `uapi::handshake_times_from`.
                    let peer_stats: Vec<(String, metrics::PeerStats)> = ctx
                        .peer_stats
                        .lock()
                        .unwrap()
                        .iter()
                        .map(|(gid, pl)| {
                            let age = pl.latest_handshake.map(|t| {
                                reported_handshake_age(t, SystemTime::now()).as_secs()
                            });
                            (
                                gid.to_string(),
                                metrics::PeerStats {
                                    rx_bytes: pl.rx_bytes,
                                    tx_bytes: pl.tx_bytes,
                                    last_handshake_age_secs: age,
                                },
                            )
                        })
                        .collect();
                    Ok::<_, anyhow::Error>((
                        kind.to_string(),
                        applied_version.load(Ordering::Relaxed),
                        counters,
                        peer_states,
                        transitions,
                        peer_stats,
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
        controller_sync_addr: cfg.controller_sync_addr.clone(),
        rotation: Arc::new(std::sync::Mutex::new(Rotation::new())),
        role_a: Arc::new(std::sync::Mutex::new(None)),
        role_b: Arc::new(std::sync::Mutex::new(HashMap::new())),
        active: active.clone(),
        wg0_pins: wg0_pins.clone(),
        desired: ctx.desired.clone(),
        live_endpoints: live_endpoints.clone(),
        retire_ready: Arc::new(std::sync::Mutex::new(None)),
    };
    tokio::spawn(run_rotation_ticks(rot.clone()));

    // Sync loop with reconnect.
    loop {
        match sync::connect(&cfg.controller_sync_addr, &id).await {
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
                                // The REAL shared live-endpoint map (fix T4)
                                // — passing an empty map here would BE the
                                // finding-§2 bug (a new enrollment's State
                                // event resetting established endpoints).
                                &live_endpoints,
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
                            // (Directive-storm fix) Attach the complete
                            // current per-peer path-state snapshot (every
                            // tracked peer, `PathState::as_str()`'s lowercase
                            // label — the same one the metrics use) so the
                            // controller's broker can skip re-punching pairs
                            // both sides report settled. `Some(..)` = a real
                            // snapshot (sets `peer_paths_snapshot` on the
                            // wire), so an EMPTY map is meaningful too — it
                            // clears this gateway's stored states rather
                            // than reading as an old client. Guard taken in
                            // a tight scope and dropped before the await,
                            // per `PathCtx`'s no-lock-across-await
                            // discipline.
                            let peer_paths: Vec<PeerPath> = ctx
                                .paths
                                .lock()
                                .unwrap()
                                .iter()
                                .map(|(gid, p)| PeerPath {
                                    peer_gateway_id: *gid,
                                    state: p.state.as_str().to_string(),
                                })
                                .collect();
                            let _ = sync::report(
                                &mut client,
                                ds.policy_version,
                                local_endpoints,
                                relay_health,
                                vec![],
                                Some(peer_paths),
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
                            // (Directive-storm fix) BEFORE anything with a
                            // side effect, consult the path-state spawn
                            // precondition (`directive_should_punch` — the
                            // exact condition `punch_and_apply`'s
                            // make-before-break guard accepts: no path entry
                            // yet or `Connecting`, and the WG endpoint not
                            // pointed at a relay socket). A directive failing
                            // it would only reach that guard and yield one
                            // "deferring direct punch" line per directive —
                            // the burst a controller-side directive storm
                            // fires forever — so it is filtered HERE, before
                            // `try_start_punch` (no concurrency-guard churn)
                            // and before `punch_allowed` (no back-off window
                            // consumed). Guards taken in a tight scope,
                            // dropped before anything awaits.
                            //
                            // Fix T3 (finding §3): for a directive that
                            // passes, acquire the CONCURRENCY guard FIRST,
                            // and only then consult the pair's punch
                            // back-off. `punch_allowed` has a side effect —
                            // on an EXPIRED window it clears the back-off and
                            // returns Allow (consuming the window) — so it
                            // must not run when no attempt will actually
                            // start. If the guard is already held (a punch in
                            // flight), we skip WITHOUT touching the back-off.
                            // While backed off — and equally when the
                            // path-state precondition fails — directives are
                            // skipped SILENTLY (the state change was logged
                            // when it happened; the incident's directive
                            // storm re-fired every few seconds, so
                            // once-per-directive would flood the log).
                            let should_punch = {
                                let state =
                                    ctx.paths.lock().unwrap().get(&gid).map(|p| p.state);
                                let pointed = ctx
                                    .relay_pointed
                                    .lock()
                                    .unwrap()
                                    .get(&gid)
                                    .copied()
                                    .unwrap_or(false);
                                directive_should_punch(state, pointed)
                            };
                            if should_punch {
                                match ctx.try_start_punch(gid) {
                                    Some(guard) => {
                                        if ctx.punch_allowed(gid, &d.candidates) {
                                            tokio::spawn(punch_and_apply(
                                                ctx.clone(),
                                                gid,
                                                d.candidates,
                                                Some(d.go_unix_ms),
                                                guard,
                                            ));
                                        }
                                        // else: backed off — drop the guard (it
                                        // releases on scope exit) without spawning.
                                    }
                                    None => eprintln!(
                                        "wiremesh-gateway: punch already in flight for peer={gid}; \
                                         skipping controller directive"
                                    ),
                                }
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
            // `{e:#}`: this line now also carries DNS-resolution failures
            // (`sync::connect` resolves per dial), and the io cause —
            // NXDOMAIN vs dead resolver vs dial timeout — is what a DDNS
            // operator needs to act on.
            Err(e) => eprintln!("controller unreachable: {e:#}; staying fail-static, retrying"),
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
    /// direct candidate (the forced-rehandshake Relayed→Direct cutover — a
    /// documented fast-follow, not yet wired) counts as the actual cutover.
    /// Absent/`false` is the safe
    /// default for a peer that has never been relayed at all, preserving
    /// every pre-4c-Task-9 direct-only scenario's behavior unchanged.
    relay_pointed: Arc<std::sync::Mutex<HashMap<u64, bool>>>,
    /// Serializes the endpoint-commit critical section — the scoped WG
    /// remove+re-add write plus the `relay_pointed` publish — across BOTH the
    /// direct-punch (`punch_and_apply` → `set_peer_endpoint(is_relay=false)`)
    /// and the relay-install (`ensure_relay_transport` →
    /// `set_peer_endpoint(is_relay=true)`) paths (MAJOR-1). Held across the
    /// `spawn_blocking` UAPI write, so it is a `tokio::sync::Mutex`: while it is
    /// held the two paths are mutually exclusive and CANNOT interleave. Under it
    /// the direct path re-checks `path.state == Connecting` (and that no relay
    /// endpoint is already installed) and ABORTS the write rather than clobber a
    /// freshly installed relay socket — the make-before-break race that
    /// otherwise leaves WG pointed at a dead direct candidate with a healthy
    /// relay transport that `ensure_relay_transport` won't re-point (silent dead
    /// relay path). `run_path_ticks` mutates `paths` to leave `Connecting`
    /// BEFORE it spawns `ensure_relay_transport`, so `state != Connecting` is
    /// the earliest signal a relay install is in play.
    endpoint_commit: Arc<tokio::sync::Mutex<()>>,
    /// Shared Role-B `wg0` pin map (peer `gateway_id` -> old-epoch pubkey) — so
    /// `set_peer_endpoint` builds the same pinned config `apply_state` does and
    /// a punch during a rotation overlap can't rekey `wg0` off the pin.
    wg0_pins: Arc<std::sync::Mutex<HashMap<u64, String>>>,
    /// Live-endpoint pins (fix T4): peer `gateway_id` -> the "ip:port" its
    /// LIVE tunnel is actually using — the durable record that replaces
    /// `set_peer_endpoint`'s old candidate-reorder-on-a-clone (which was
    /// never persisted, so the next `apply_state` reverted every endpoint to
    /// the pristine static candidate: the finding-§2 incident bug). Written
    /// by `set_peer_endpoint` (where a punched/relay endpoint is known),
    /// cleared by `run_path_ticks` when the peer's path leaves the live
    /// states (`Direct`/`Relayed`) — which is what re-enables the recovery
    /// re-point at fresh candidates — and passed by every steady-state
    /// device rebuild to `reconcile::device_config_pinned`. The same `Arc`
    /// the boot loop and `RotationShared` hold.
    live_endpoints: Arc<std::sync::Mutex<HashMap<u64, String>>>,
    /// Per-peer punch back-off state (fix T3, finding §3: an undialable
    /// pair's punch directives re-fired every few seconds indefinitely, and
    /// the near-continuously-open transient `SO_REUSEPORT` punch socket then
    /// starved OTHER pairs' inbound WG traffic). Consulted via
    /// [`PathCtx::punch_allowed`] before BOTH spawn sites (controller
    /// `Punch` directives and tick-driven `StartPunch`); fed
    /// by [`PathCtx::record_punch_outcome`] from `punch_and_apply`. Note
    /// `try_start_punch` bounds concurrency; this bounds RATE.
    punch_backoff: Arc<std::sync::Mutex<HashMap<u64, PunchBackoff>>>,
    /// Latest per-peer UAPI liveness snapshot (rx/tx bytes + latest
    /// handshake), keyed by peer `gateway_id` — published by `run_path_ticks`
    /// from the SAME `uapi::get_peer_liveness` fetch that drives the path
    /// state machine, and read by the metrics scrape to render the per-peer
    /// `wiremesh_gateway_peer_{rx,tx}_bytes` /
    /// `..._last_handshake_age_seconds` gauges (mesh-convergence fix T5,
    /// finding §6: every diagnosis in the incident needed UAPI spelunking via
    /// debug containers). Sharing the driver's snapshot — rather than the
    /// scrape doing its own `get=1` — guarantees the metrics describe exactly
    /// the evidence the path SM acted on, at zero extra UAPI traffic.
    peer_stats: Arc<std::sync::Mutex<HashMap<u64, uapi::PeerLiveness>>>,
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

    /// Consult peer `gid`'s punch back-off (fix T3) with the candidate list
    /// of the attempt about to run. `true` = the attempt may proceed (then
    /// still subject to `try_start_punch`'s concurrency guard); `false` =
    /// the pair is inside an open back-off window and the attempt must be
    /// skipped. Deliberately SILENT on skip: plan T3 requires logging once
    /// per state CHANGE (the window opening, logged by
    /// [`record_punch_outcome`]), not once per skipped directive — the
    /// incident's directive storm re-fired every few seconds and would have
    /// flooded the log.
    fn punch_allowed(&self, gid: u64, candidates: &[String]) -> bool {
        let now = Instant::now();
        let mut map = self.punch_backoff.lock().unwrap();
        let backoff = map
            .entry(gid)
            .or_insert_with(|| PunchBackoff::new(punch_jitter_seed(self.identity.gateway_id, gid)));
        matches!(backoff.decide(now, candidates), PunchDecision::Allow)
    }

    /// Feed a finished `punch_and_apply` attempt's outcome into peer `gid`'s
    /// back-off (fix T3): a confirmed candidate resets it immediately; a
    /// failure counts toward (or extends) the back-off. Logs exactly when
    /// the back-off state CHANGES — a new window opening (including each
    /// doubled window after a failed half-open retry) — never per skipped
    /// directive, per plan T3.
    fn record_punch_outcome(&self, gid: u64, success: bool) {
        let mut map = self.punch_backoff.lock().unwrap();
        let Some(backoff) = map.get_mut(&gid) else {
            // No decide ever ran for this peer (shouldn't happen — both
            // spawn sites consult `punch_allowed` first); nothing to feed.
            return;
        };
        if success {
            let was_backed_off = backoff.backoff_until().is_some();
            backoff.record_success();
            if was_backed_off {
                eprintln!(
                    "wiremesh-gateway: peer={gid} punch back-off cleared (punch confirmed)"
                );
            }
        } else {
            let now = Instant::now();
            let before = backoff.backoff_until();
            backoff.record_failure(now);
            let after = backoff.backoff_until();
            if after != before {
                if let Some(until) = after {
                    eprintln!(
                        "wiremesh-gateway: peer={gid} punch back-off engaged for {:?} \
                         (consecutive punch failures; directives skipped until it expires \
                         or candidates change — finding §3 storm guard)",
                        until.saturating_duration_since(now)
                    );
                }
            }
        }
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

/// Normalize a UAPI-reported last-handshake value to the handshake's AGE
/// (time since it completed), robust to BOTH field semantics in the wild
/// (mesh-convergence fix cycle, nat_matrix regression root-cause):
///
/// - The WG UAPI spec defines `last_handshake_time_{sec,nsec}` as the
///   ABSOLUTE unix time of the last handshake — age is `now - reported`.
/// - This project's boringtun (0.6.0) instead fills the fields with
///   `time_since_last_handshake()` — the ELAPSED time since the handshake
///   (`device/api.rs` / `noise/timers.rs`), so the parsed "`SystemTime`" is
///   really `UNIX_EPOCH + <elapsed>` and the age is simply `reported -
///   UNIX_EPOCH`. This is why `wg show` prints "56 years ago" on live
///   tunnels, and it is the true mechanism behind the cycle-4b "handshake
///   time advances every tick with rx flat" quirk: elapsed time grows with
///   the wall clock between handshakes. Fatally for the first T2 driver
///   cut, it also means the epoch-interpreted value DROPS on a genuine new
///   handshake (elapsed resets to ~0), so a `t > prev` "advance" check
///   misses exactly the event it exists to detect — observed as the
///   nat_matrix cases 1/3/4 sticking in `connecting` while real WG traffic
///   flowed.
///
/// The two are disambiguated by magnitude: a real absolute timestamp is ~56
/// years past the epoch, while an elapsed value would need a >20-year-old
/// session to cross the threshold below. In AGE space both semantics behave
/// identically — the age grows between handshakes and drops on each new one
/// — which is what the path-tick driver keys its handshake-event detection
/// on, and what the T5 `last_handshake_age_seconds` gauge reports.
fn reported_handshake_age(reported: SystemTime, now: SystemTime) -> Duration {
    /// Values further than this past the epoch are treated as absolute
    /// timestamps (20 years — no session's elapsed age gets near it, and
    /// any plausible real handshake instant is far beyond it).
    const ABSOLUTE_IF_PAST: Duration = Duration::from_secs(20 * 365 * 86_400);
    let since_epoch = reported.duration_since(UNIX_EPOCH).unwrap_or_default();
    if since_epoch >= ABSOLUTE_IF_PAST {
        // Spec-conforming absolute timestamp; clock skew clamps to 0 rather
        // than erroring (a just-completed handshake must read as age ~0).
        now.duration_since(reported).unwrap_or_default()
    } else {
        // boringtun elapsed semantics: the reported value IS the age.
        since_epoch
    }
}

/// Jitter seed for a peer pair's [`PunchBackoff`] (fix T3). Mixes this
/// gateway's own id with the peer's so (a) the two ENDS of one pair draw
/// different jitter sequences (own/peer are swapped on the other side) and
/// (b) distinct pairs on one gateway decorrelate — the point of the jitter
/// is that backed-off retries across the fabric don't re-synchronize into
/// simultaneous punch storms (finding §3). Deterministic across restarts by
/// design: the back-off module keeps ALL randomness injected/seeded (the
/// `path.rs` testability rule), and reproducible retry timing is a feature
/// when replaying an incident from logs.
fn punch_jitter_seed(own_gateway_id: u64, peer_gateway_id: u64) -> u64 {
    own_gateway_id
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .rotate_left(32)
        ^ peer_gateway_id.wrapping_mul(0xBF58_476D_1CE4_E5B9)
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

/// Production [`punch::NudgeSink`]: sends ONE datagram from a fresh EPHEMERAL
/// UDP socket toward the peer's overlay IP, so the kernel routes it through
/// `wg0` and boringtun (seeing "data to send, no session") initiates its WG
/// handshake immediately rather than waiting ~26s for its persistent-keepalive
/// tick (spike finding 1). The socket binds `0.0.0.0:0` — NOT the WG listen
/// port, NOT `SO_REUSEPORT` — and is dropped at once, so it can never share or
/// steal boringtun's inbound datagrams (the whole point of the §3 fix). The
/// datagram's destination PORT is irrelevant (the packet is tunnelled whole);
/// its destination IP is what selects the peer and fires the handshake.
struct TunNudgeSink;

/// Arbitrary destination port for the nudge datagram. Only the destination IP
/// matters (it routes the packet through `wg0` and selects the peer by
/// allowed-ips longest-prefix match); the port rides inside the tunnelled
/// packet and is never interpreted by anything on the underlay. `9` is the
/// standard discard port.
const NUDGE_DST_PORT: u16 = 9;

impl punch::NudgeSink for TunNudgeSink {
    fn nudge(&self, overlay_ip: std::net::Ipv4Addr) -> anyhow::Result<()> {
        let sock = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0))
            .context("binding ephemeral nudge socket")?;
        let dst = SocketAddr::from((overlay_ip, NUDGE_DST_PORT));
        sock.send_to(&[0u8; 1], dst).with_context(|| format!("sending nudge to {dst}"))?;
        Ok(())
    }
}

/// Send ONE small datagram from an ephemeral socket toward peer `gid`'s overlay
/// IP (a routable host in its allowed-ips), routed through `wg0`. This single
/// primitive serves TWO purposes depending on the peer's session state:
///
///  - **Handshake nudge** (sessionless peer, just (re)pointed): boringtun 0.6.0
///    sees "data to send, no session" → initiates its WG handshake NOW rather
///    than waiting ~26s for its persistent-keepalive tick (spike finding 1).
///    Used by the direct punch ([`punch_and_apply`]) and the relay endpoint
///    install / re-path ([`ensure_relay_transport`]) — after
///    [`set_peer_endpoint`]'s scoped remove+re-add leaves the peer sessionless,
///    without this the relay tunnel flows encrypted data but never completes a
///    handshake (relay_matrix case1: `latest_handshake` stuck at 0).
///
///  - **Liveness probe** (live `Direct`/`Relayed` peer, from `run_path_ticks`
///    every [`LIVENESS_PROBE_INTERVAL`]): the datagram decrypts to a NON-empty
///    inner packet on the peer, so it bumps the peer's `rx_bytes` — unlike a
///    bare WG keepalive, which boringtun does NOT count in `rx_bytes` (see
///    [`LIVENESS_PROBE_INTERVAL`]). Every gateway probes, so each live pair
///    exchanges a visible datagram and BOTH sides' rx-corroborated liveness
///    holds through a keepalive-only idle (convergence A4).
///
/// Best-effort: a failed send just means boringtun falls back to its slower
/// keepalive-tick behavior. The blocking socket I/O runs off the async runtime.
async fn poke_peer_overlay(ctx: &PathCtx, gid: u64) {
    let allowed_ips: Vec<String> = ctx
        .desired
        .lock()
        .unwrap()
        .as_ref()
        .and_then(|ds| ds.peers.iter().find(|p| p.gateway_id == gid).map(|p| p.allowed_ips.clone()))
        .unwrap_or_default();
    match tokio::task::spawn_blocking(move || punch::nudge_peer(&TunNudgeSink, &allowed_ips)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => eprintln!("wiremesh-gateway: overlay poke to peer={gid} failed: {e}"),
        Err(e) => eprintln!("wiremesh-gateway: overlay poke task for peer={gid} panicked: {e}"),
    }
}

/// Sleep until `go_unix_ms` (best-effort, clamped to `MAX_PUNCH_DELAY`), then
/// run ONE endpoint-driven punch trial toward `candidates` for peer `gid`.
///
/// This is the productionized §3 punch (puncher-socket-isolation): there is NO
/// separate `SO_REUSEPORT` punch socket. A [`punch::CandidateTrial`] sequences
/// the candidates one at a time; for each, we
///
///   1. set the peer's WG endpoint via [`set_peer_endpoint`] — a SCOPED
///      remove+re-add of ONLY this peer (leaving every other peer's live
///      session intact), NEVER a boringtun in-place `update_peer` modify (which
///      panics 0.6.0 — spike finding 2) nor a full `replace_peers` (which would
///      reset every other established peer — see `apply_peer_endpoint_scoped`);
///   2. NUDGE boringtun to initiate its handshake NOW via [`punch::nudge_peer`]
///      with the production [`TunNudgeSink`] (one ephemeral-socket datagram
///      toward the peer's overlay IP — spike finding 1); and
///   3. wait up to [`PER_CANDIDATE_PUNCH_TIMEOUT`] for the handshake to land,
///      detected by the peer's path reaching `Direct` (the T2 rx-corroborated
///      liveness `run_path_ticks` publishes — the punch IS boringtun's own
///      authenticated handshake, so its completion is the confirmation).
///
/// On liveness the pair's back-off is reset (fix T3) and we return; on trial
/// exhaustion (every candidate tried, or none dialable) the back-off records a
/// failure and the path SM drives the existing `Relayed` fallback.
///
/// ### Relay-preservation invariant (make-before-break)
///
/// The trial NEVER points WireGuard away from an ACTIVE relay endpoint. A WG
/// peer has one endpoint and, under approach B, the endpoint-set IS the punch —
/// so while the peer is on a relay path (`relay_pointed`, or `path.state ==
/// Relayed` during the install window) the loop YIELDS (returns) instead of
/// setting a direct candidate. Clobbering the relay socket would time out relay
/// recv and sawtooth the path; a corroborated Relayed → Direct cutover needs a
/// forced rehandshake with no second socket and is a documented fast-follow, so
/// a Relayed pair stays relayed until then. See the guard at the loop head.
///
/// ### Reconciliation with `path::CONNECT_TIMEOUT` (the `Connecting` budget)
///
/// `path.rs` gives a `Connecting` peer `CONNECT_TIMEOUT` (10s) before it falls
/// back to `Relayed`/`Disconnected`. A punchable pair almost always has ONE or
/// two candidates (its observed public mapping, plus perhaps a local endpoint),
/// so its trial completes in ≤5–10s — comfortably inside the budget, and the
/// nudge makes the handshake land within ~1 RTT of the first punch, far sooner
/// than the window. A pair with THREE-plus candidates could run a trial longer
/// than `CONNECT_TIMEOUT`; if a relay becomes available meanwhile the path
/// enters `Relayed` and the trial then YIELDS (per the invariant above) — the
/// relay carries traffic and the pair simply stays relayed (the documented
/// fast-follow), rather than the punch fighting the relay for the endpoint. We
/// therefore keep `CONNECT_TIMEOUT` at its spec'd 10s rather than stretching it:
/// the done-bar pairs (nat_matrix, convergence A↔B) each punch a single observed
/// candidate and reach `Direct` well within it.
///
/// `_guard` is the in-flight-punch slot from [`PathCtx::try_start_punch`] —
/// unused by name, but HELD for this function's entire lifetime (including
/// every early `return`) and released via `Drop`, so at most one
/// `punch_and_apply` runs per peer at a time regardless of whether it was
/// triggered by a controller `Punch` directive or a tick-driven `StartPunch`.
/// Every blocking call (`uapi::apply` inside `set_peer_endpoint`,
/// the nudge socket) runs inside `spawn_blocking`; no mutex guard is ever held
/// across an `.await`.
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

    let mut trial = punch::CandidateTrial::new(&candidates, Instant::now());
    let mut last_addr: Option<SocketAddr> = None;
    loop {
        // Make-before-break: NEVER let this endpoint-driven punch clobber an
        // ACTIVE relay endpoint. Under approach B a WireGuard peer has exactly
        // ONE endpoint and the endpoint-set IS the punch, so pointing WG at a
        // direct candidate while the peer is Relayed points it AWAY from the
        // relay socket (`127.0.0.1:<relay port>` that `ensure_relay_transport`
        // installed) — relay recv then times out and the path sawtooths
        // relayed -> disconnected -> connecting -> relayed. A corroborated
        // Relayed -> Direct cutover needs a forced rehandshake and no second
        // socket, which is a DOCUMENTED fast-follow (CLAUDE.md / cycle4c note),
        // so until then a punch trial must YIELD to a live relay path rather
        // than disrupt it. `relay_pointed` is the precise signal ("WG endpoint
        // currently points at a relay socket"); `path.state == Relayed` closes
        // the brief transition window before `ensure_relay_transport` has set
        // `relay_pointed` (Connecting times out -> Relayed, relay endpoint
        // still installing). Checking BOTH covers a mid-trial
        // Connecting -> Relayed transition AND the case3 relay-eviction
        // re-path (Disconnected -> Connecting StartPunch while the endpoint is
        // already re-pointed at the second relay). Controller directives can
        // no longer arrive here while Relayed as a matter of course — the
        // directive arm filters them through `path::directive_should_punch`
        // (the same Connecting-and-not-pointed condition) before spawning —
        // but this guard STAYS as defense-in-depth: the state can change
        // between the arm's check and any later loop iteration of this trial
        // (that race is exactly what a per-iteration guard exists for), and a
        // tick-driven StartPunch spawn consults no such precondition. We
        // return WITHOUT recording
        // a punch outcome: no dialability was actually tested (the trial
        // yielded), so neither success nor failure should feed the pair's
        // back-off. This is the regression fix for the endpoint-driven punch
        // clobbering the relay path (relay_matrix 0/2, convergence A4).
        // MAJOR-1: a StartPunch trial is only meaningful while the path is
        // `Connecting`. The moment it has LEFT `Connecting`, the driver is (or
        // is about to be) establishing a relay path — `run_path_ticks` mutates
        // the `Path` state to `Relayed`/`Disconnected` under `paths` BEFORE it
        // spawns `ensure_relay_transport`, so `state != Connecting` is the
        // earliest signal a relay install is in flight. Yielding here (and,
        // ATOMICALLY, in `set_peer_endpoint`'s commit below) is the
        // make-before-break guard that stops a slow multi-candidate trial from
        // clobbering a freshly installed relay socket (WG left pointed at a dead
        // direct candidate with a healthy relay transport that
        // `ensure_relay_transport` then refuses to re-point → silent dead relay
        // path). This subsumes the old `Relayed || relay_pointed` guard: any
        // trial that finds itself `Relayed` mid-flight (a directive-spawned
        // trial raced a relay install after passing the arm's
        // `directive_should_punch` filter — no tick-driven trial, and no
        // directive spawned against an already-`Relayed` entry, can any
        // longer) still yields (state != Connecting), and
        // the `Disconnected` window this bug drove through is now covered too. A
        // completed direct handshake returns via the `is_direct` check below, so
        // reaching this point in any non-`Connecting` state means yield.
        // DRY note: this shares `directive_should_punch` (the directive
        // arm's spawn precondition — same Connecting-and-not-relay-pointed
        // predicate) with ONE deliberate asymmetry, the `state.is_some()`
        // conjunct: at the ARM, `None` means "unknown peer, punch to create
        // its entry" and must spawn; IN-TRIAL, `None` means the entry this
        // very task created at the top has since been PRUNED (the tick
        // loop's desired-peer `retain` — the peer left the roster
        // mid-trial), and punching a de-rostered peer must yield.
        let connecting = {
            let state = ctx.paths.lock().unwrap().get(&gid).map(|p| p.state);
            let pointed = ctx.relay_pointed.lock().unwrap().get(&gid).copied().unwrap_or(false);
            state.is_some() && directive_should_punch(state, pointed)
        };
        if !connecting {
            // Low-noise, and deliberately NOT worded with any of the four
            // attempt-counting prefixes (`punch to peer=`, `no candidate
            // confirmed`, `punch confirmed`, `punch task for peer=`) — yielding
            // is not a punch attempt, so it must not feed the anti-storm tally.
            // Return WITHOUT recording an outcome: no dialability was tested.
            eprintln!(
                "wiremesh-gateway: peer={gid} path no longer connecting; deferring direct punch \
                 (make-before-break, relay path kept flowing)"
            );
            return;
        }

        match trial.poll(Instant::now(), PER_CANDIDATE_PUNCH_TIMEOUT) {
            punch::TrialStep::Punch(addr) => {
                last_addr = Some(addr);
                // Set the endpoint via the scoped remove+re-add (make-before-
                // break: only THIS peer's session resets, spike finding 2 — no
                // boringtun in-place modify), then nudge it to handshake NOW.
                match set_peer_endpoint(&ctx, gid, addr, false).await {
                    // Committed: nudge boringtun to initiate its handshake NOW
                    // (spike finding 1) — the scoped re-add left the peer
                    // sessionless.
                    Ok(true) => poke_peer_overlay(&ctx, gid).await,
                    // MAJOR-1: the atomic commit guard saw the peer leave
                    // `Connecting` (or a relay endpoint already installed) and
                    // SKIPPED the write, yielding to the relay path. No
                    // dialability was tested, so return WITHOUT recording an
                    // outcome — and do NOT use an attempt-counting prefix.
                    Ok(false) => {
                        eprintln!(
                            "wiremesh-gateway: peer={gid} left connecting during punch commit; \
                             deferring to relay path (make-before-break)"
                        );
                        return;
                    }
                    // NB: deliberately NOT worded with a "punch to peer=" /
                    // "no candidate confirmed" / "punch confirmed" prefix — this
                    // is a mid-trial, per-candidate error, NOT one of the four
                    // TERMINAL outcome lines the convergence anti-storm test
                    // counts as a punch ATTEMPT. Exactly one terminal line is
                    // emitted per `punch_and_apply` (on Exhausted or Direct).
                    Err(e) => eprintln!(
                        "wiremesh-gateway: applying punch endpoint for peer={gid} at {addr} failed: {e}"
                    ),
                }
            }
            punch::TrialStep::Waiting => {}
            punch::TrialStep::Exhausted => {
                // Every candidate tried without a completed handshake (e.g. a
                // symmetric-NAT peer — the documented relay-needed case), or no
                // dialable candidate at all. The path SM drives retry/relay,
                // rate-bounded by the pair's back-off (fix T3).
                eprintln!("wiremesh-gateway: no candidate confirmed for peer={gid}");
                ctx.record_punch_outcome(gid, false);
                return;
            }
        }

        // Sleep, then check for the rx-corroborated liveness signal: the punch
        // IS boringtun's own handshake, so a completed handshake = the peer's
        // path reaching `Direct` (published by `run_path_ticks` off UAPI). That
        // is the confirmation — there is no PING/PONG anymore.
        tokio::time::sleep(PUNCH_POLL_INTERVAL).await;
        let is_direct = ctx
            .paths
            .lock()
            .unwrap()
            .get(&gid)
            .map(|p| p.state == PathState::Direct)
            .unwrap_or(false);
        if is_direct {
            // Fix T3: a landed direct handshake proves the pair dialable, so
            // the pair's back-off clears immediately.
            ctx.record_punch_outcome(gid, true);
            match last_addr {
                Some(addr) => {
                    eprintln!("wiremesh-gateway: punch confirmed peer={gid} endpoint={addr}")
                }
                None => eprintln!("wiremesh-gateway: punch confirmed peer={gid}"),
            }
            return;
        }
    }
}

/// Point peer `gid`'s WG endpoint at `endpoint` via a SCOPED single-peer
/// re-point (guarded: the change-guard makes a re-confirm of an already-applied
/// endpoint a true no-op, so the controller re-brokering punches every few
/// seconds never resets a live session).
///
/// This uses [`apply_peer_endpoint_scoped`] — a `remove=true` + re-add of ONLY
/// this peer ([`uapi::set_one_peer`]) — NOT the full `replace_peers` apply.
/// remove+re-add is the only existing-peer mutation boringtun 0.6.0 supports
/// (its `update_peer` panics on an in-place modify), and scoping it to the
/// target peer leaves every OTHER peer's live boringtun session and keepalive
/// timer intact. That is the finding-§5 session-continuity fix: the former
/// full `replace_peers` apply here was implemented as `clear_peers()`, so a
/// punch/relay re-point against ONE peer rebuilt EVERY peer's `Tunn` — under
/// punch contention against a permanently-blocked peer that reset an
/// established pair's session repeatedly and it degraded (convergence A4). The
/// earlier scoped attempt was reverted because the re-added peer flowed data
/// but never reported a current handshake — resolved here by the caller nudging
/// it to re-handshake promptly (`poke_peer_overlay`, spike finding 1), which
/// makes the scoped path work for BOTH the direct and relay paths. The T4
/// live-endpoint pins are still recorded so any later full `apply_state` rebuild
/// keeps this endpoint. Shared by [`punch_and_apply`] (a hole-punched direct
/// candidate, `is_relay=false`) and [`ensure_relay_transport`] (pointing a peer
/// at its `RelayTransport`'s local relay socket, Cycle 4c Task 8,
/// `is_relay=true`); both nudge after this returns `Ok(true)`.
///
/// Returns `Ok(true)` when the endpoint was committed to the device, and
/// `Ok(false)` when the DIRECT path YIELDED without writing (MAJOR-1): the whole
/// guard+write runs under [`PathCtx::endpoint_commit`] (held across the
/// `spawn_blocking` UAPI write) so the direct-punch and relay-install writes are
/// mutually exclusive; under it the direct path aborts the moment the peer has
/// left `Connecting` or a relay endpoint is already installed, rather than
/// clobber a freshly installed relay socket. The relay path (`is_relay=true`)
/// never yields — it returns `Ok(true)` or an `Err`.
///
/// `is_relay` records into `ctx.relay_pointed` (Cycle 4c Task 9) whether
/// `endpoint` is the local relay-transport socket or a real direct
/// candidate — the disambiguator `run_path_ticks` needs so a WG handshake
/// completing OVER THE RELAY isn't mistaken for the make-before-break Direct
/// cutover.
///
/// Fix T4 (finding §2): the endpoint is recorded as a durable pin in
/// `ctx.live_endpoints` and the device is rebuilt from the PRISTINE desired
/// state plus that pin map. The previous implementation instead reordered
/// the candidates of a LOCAL CLONE of desired state — never persisted — so
/// the very next `apply_state` (any Sync `State` event, e.g. a new gateway
/// enrolling) rebuilt from the pristine candidates and reverted every
/// established endpoint to its static candidate; that reset is exactly what
/// broke the working home↔FI pair when px enrolled in the 2026-07-27
/// incident. `run_path_ticks` clears the pin again when the peer's path
/// leaves the live states, re-enabling candidate-chasing recovery.
async fn set_peer_endpoint(
    ctx: &PathCtx,
    gid: u64,
    endpoint: SocketAddr,
    is_relay: bool,
) -> anyhow::Result<bool> {
    // Resolve the ACTIVE tun (ifname + priv key + port), captured together so
    // the device we build and the ifname we apply it to are consistent even if
    // a cutover flips `active` concurrently.
    let (ifname, priv_key, wg_port) = {
        let a = ctx.active.lock().unwrap();
        (a.ifname.clone(), a.priv_key.clone(), a.wg_port)
    };

    // MAJOR-1: hold the endpoint-commit lock across the ENTIRE guard+write, so
    // the direct-punch and relay-install endpoint writes are mutually exclusive
    // and cannot interleave. A `tokio::sync::Mutex`, so it is safe to hold
    // across the `spawn_blocking` UAPI write inside `apply_peer_endpoint_scoped`.
    let _commit = ctx.endpoint_commit.lock().await;

    // MAJOR-1 atomic guard (DIRECT path only): abort — WITHOUT touching the
    // device or any pin — the moment the peer has left `Connecting` or a relay
    // endpoint is already installed. `run_path_ticks` mutates `paths` out of
    // `Connecting` BEFORE it spawns `ensure_relay_transport`, so this is the
    // earliest signal a relay install is (about to be) in flight; and because
    // the relay install takes the SAME `endpoint_commit` lock for its own
    // commit, one that already ran is visible here (relay endpoint installed +
    // `relay_pointed=true`) and one that hasn't cannot slip between this check
    // and the write below. Yielding here is what stops a slow multi-candidate
    // trial from clobbering a freshly installed relay socket.
    if !is_relay {
        let connecting = ctx
            .paths
            .lock()
            .unwrap()
            .get(&gid)
            .map(|p| p.state == PathState::Connecting)
            .unwrap_or(false);
        let relay_installed =
            ctx.relay_pointed.lock().unwrap().get(&gid).copied().unwrap_or(false);
        if !connecting || relay_installed {
            return Ok(false);
        }
    }

    // Record the live-endpoint pin (fix T4): from here on, every steady-state
    // rebuild — this one and any concurrent/later `apply_state` — emits this
    // endpoint for `gid` instead of the static candidate. (If the apply below
    // fails, the pin still describes where the tunnel SHOULD point; the next
    // apply retries it, and `run_path_ticks` clears the pin if no live path
    // ever materializes.) Deliberately recorded AFTER the MAJOR-1 yield check:
    // a yielded direct punch must NOT leave a stale direct pin behind, or a
    // later `apply_state` rebuild would use it to clobber the relay endpoint.
    ctx.live_endpoints.lock().unwrap().insert(gid, endpoint.to_string());
    // Build the full pinned desired device (for the change-guard and the
    // `applied_peers` bookkeeping `apply_state` diffs against) AND resolve the
    // TARGET peer's pubkey — the one peer whose block the scoped apply pushes.
    let (dev, target_pubkey) = {
        let desired = ctx.desired.lock().unwrap();
        let ds = desired.as_ref().ok_or_else(|| {
            anyhow::anyhow!("no desired state yet; cannot set endpoint for peer={gid}")
        })?;
        // Honor the same Role-B `wg0` pin `apply_state` uses, so a punch/relay
        // re-point during a rotation overlap can't rekey the active tun off the
        // pinned old-epoch key (make-before-break), and — with the change-guard
        // below — resolving to an already-applied endpoint is a true no-op that
        // never resets the live session. The live-endpoint map carries this
        // call's own pin (inserted above) plus every other live peer's, so
        // re-pointing ONE peer can't clobber another's established endpoint.
        let pins = ctx.wg0_pins.lock().unwrap();
        let live = ctx.live_endpoints.lock().unwrap();
        let dev = reconcile::device_config_pinned(ds, &priv_key, wg_port, &pins, &live);
        // The target peer's device pubkey: Role-B pinned if a rotation pin
        // exists for it, else its advertised active key — the SAME resolution
        // `device_config_pinned` used to build the target's block, so it always
        // matches a block in `dev.peers`.
        let target_pubkey = ds
            .peers
            .iter()
            .find(|p| p.gateway_id == gid)
            .and_then(|p| pins.get(&gid).cloned().or_else(|| p.active_pubkey_b64.clone()));
        (dev, target_pubkey)
    };
    // SCOPED apply (session-continuity fix): re-point ONLY this peer via
    // remove+re-add, leaving every OTHER peer's live boringtun session and
    // keepalive timer intact. The old full `replace_peers` apply here rebuilt
    // EVERY peer (`clear_peers()`), so a punch/relay re-point against peer C
    // reset peer B's established session — under punch contention B then went
    // silent and degraded (convergence A4). See `apply_peer_endpoint_scoped`.
    apply_peer_endpoint_scoped(&ifname, &dev, target_pubkey.as_deref(), &ctx.active).await?;
    ctx.relay_pointed.lock().unwrap().insert(gid, is_relay);
    Ok(true)
}

/// Re-point ONE peer's endpoint on `ifname` via a scoped remove+re-add
/// ([`uapi::set_one_peer`]), leaving every OTHER peer's live boringtun session
/// untouched. This replaces [`set_peer_endpoint`]'s former full
/// [`apply_device_if_changed`] (`replace_peers=true` → `clear_peers()`), which
/// rebuilt every peer's `Tunn` — so a punch/relay re-point against one peer
/// reset every OTHER established peer, the finding-§5 session-continuity
/// contention (convergence A4: peerB degraded whenever a permanently-blocked
/// peerC was punched/relayed).
///
/// `dev` is the full pinned desired device; only its `private_key`/`listen_port`
/// (to re-encode the guard's `applied_config`) and the ONE peer block selected
/// by `target_pubkey` are used. The scoped remove+re-add resets only the
/// target's session (boringtun can't modify a peer in place); the caller nudges
/// it to re-handshake promptly (`poke_peer_overlay`).
///
/// CHANGE-GUARD SCOPE (MAJOR-3): this writes ONLY the target peer, so it must
/// only claim the target as applied — never the whole `dev`. The former code
/// set `applied_peers = dev.peers.clone()` and compared `encode_set(full dev)`,
/// which FABRICATED guard state for every unrelated peer: an unrelated peer with
/// a still-un-applied change would be silently recorded as applied, so a later
/// `apply_state` (which diffs `applied_peers`) would skip reconciling it. Here
/// the guard's `applied_peers` is the current set with ONLY the target
/// replaced-or-added, and `applied_config` is re-derived from that set — so
/// `classify_peer_delta` / `apply_device_if_changed` stay consistent for every
/// OTHER peer. When `target_pubkey` is `None` or no matching peer exists, there
/// is nothing to write and the guard is left UNCHANGED (no phantom adoption).
async fn apply_peer_endpoint_scoped(
    ifname: &str,
    dev: &DeviceConfig,
    target_pubkey: Option<&str>,
    active: &Arc<std::sync::Mutex<ActiveTunInfo>>,
) -> anyhow::Result<()> {
    // The single peer whose endpoint we're setting. Absent (target not keyed,
    // or dropped from desired state) → nothing to push to the device, and —
    // unlike the old code — DON'T fabricate guard state for the whole device:
    // leave `applied_config`/`applied_peers` untouched so a later reconcile
    // sees the true drift.
    let Some(peer) = target_pubkey
        .and_then(|pk| dev.peers.iter().find(|p| p.public_key_b64 == pk).cloned())
    else {
        return Ok(());
    };

    // Scoped change-guard, compared to ONLY the target peer: a re-confirm of an
    // already-applied endpoint is a true no-op (the controller re-brokers
    // punches every few seconds; without this it would needlessly reset the
    // target's session on every one). If the exact target block is already in
    // `applied_peers`, the device already holds it — skip the write.
    {
        let a = active.lock().unwrap();
        if a.applied_peers.iter().any(|p| *p == peer) {
            return Ok(());
        }
    }

    let ifn = ifname.to_string();
    let peer_for_write = peer.clone();
    tokio::task::spawn_blocking(move || uapi::set_one_peer(&ifn, &peer_for_write))
        .await
        .context("scoped set-one-peer UAPI task panicked")??;

    // Update the guard to reflect ONLY the target peer just written: replace it
    // in (or add it to) the CURRENT applied peer set — unrelated peers keep
    // their real recorded state — and re-derive `applied_config` from the
    // resulting set (with `dev`'s device header). Recomputed here from the live
    // `applied_peers` (not a snapshot) so a concurrent apply can't be lost.
    // Runs only after a SUCCESSFUL write: on a `set_one_peer` error the `?`
    // above returns first, leaving the guard un-updated (MAJOR-2) so the next
    // `apply_state` reconciles the peer that was left removed.
    {
        let mut a = active.lock().unwrap();
        match a.applied_peers.iter_mut().find(|p| p.public_key_b64 == peer.public_key_b64) {
            Some(existing) => *existing = peer.clone(),
            None => a.applied_peers.push(peer.clone()),
        }
        let device = DeviceConfig {
            private_key_b64: dev.private_key_b64.clone(),
            listen_port: dev.listen_port,
            peers: a.applied_peers.clone(),
        };
        a.applied_config =
            Some(uapi::encode_set(&device).context("re-encoding scoped active-tun device config")?);
    }
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

    // The relay path never yields (is_relay=true → always `Ok(true)` or `Err`).
    if let Err(e) = set_peer_endpoint(&ctx, gid, local_addr, true).await {
        eprintln!("wiremesh-gateway: pointing peer={gid} at relay={relay_id} endpoint failed: {e}");
    } else {
        // NUDGE boringtun to handshake over the relay NOW (spike finding 1):
        // `set_peer_endpoint`'s scoped remove+re-add left the peer sessionless,
        // and boringtun would otherwise not init until its ~26s keepalive tick —
        // so the relay tunnel would flow encrypted data but never complete a
        // handshake (relay_matrix case1: `latest_handshake` stuck at 0 on both
        // sides while data flows). Same tun-nudge the direct punch uses. Fires
        // on a relay-to-relay re-path too (case3), since this runs on every
        // (re)establish.
        poke_peer_overlay(&ctx, gid).await;
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
/// (`uapi::get_peer_liveness`), advance each peer's `Path` (rx-corroborated
/// handshake → Direct, per fix T2 — see the corroboration block below; an
/// `rx_bytes` increase without a handshake advance → refreshed liveness via
/// `on_authenticated_inbound`, so 25s keepalives count as
/// inbound even between ~120s handshake rekeys; time-driven degrade/
/// disconnect via `tick`), record transitions, and act on the returned
/// `PathAction`: `StartPunch` re-runs a bounded punch; `ProbeDirect` is a
/// deliberate driver no-op — any spawned probe would yield instantly to the
/// make-before-break guard (see the tick match arm); `MarkRelayNeeded` spawns
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
/// `Path::tick`'s `Relayed` arm rate-limits `ProbeDirect` to once per
/// `path::PROBE_DIRECT_INTERVAL` (with a full grace interval before the
/// FIRST probe of a `Relayed` spell), rather than every ~1s tick. HISTORICAL
/// root cause (now removed by the puncher-socket-isolation cycle): firing
/// every tick stacked back-to-back `punch_and_apply` attempts, which each
/// opened the driver's transient same-port `SO_REUSEPORT` punch socket
/// (`punch::punch_candidates`) — kept almost continuously open, it shared the
/// WG listen port with `RelayTransport`'s local downlink delivery target
/// (`ensure_relay_transport` binds its `local_peer_hint` at
/// `127.0.0.1:<wg_listen_port>`, the very address boringtun's own socket
/// listens on), so the kernel's `SO_REUSEPORT` load-balancing intermittently
/// steered inbound relayed WG datagrams to the punch socket instead of
/// boringtun's — silently starving an otherwise-healthy relay path of traffic,
/// which is what actually broke case 1, not a bad state-machine transition.
/// See docs/research/cycle4c-relay-stability-note.md. **That punch socket no
/// longer exists** — `punch_and_apply` now drives boringtun's own handshake
/// (endpoint-set + tun nudge, no competing socket), so the starvation
/// mechanism is gone at the source; the SM's `ProbeDirect` rate-limit is
/// retained even though the driver no longer acts on the action (see the
/// tick match arm) — a low bounded probe rate stays the right posture (a
/// full `replace_peers` re-point is not free) for when the forced-rehandshake
/// cutover fast-follow re-wires this seam. Note this only makes the
/// RELAY path stable; with no probe running while `Relayed`, a genuine
/// `Relayed -> Direct` cutover is currently inert for EVERY NAT kind —
/// pending that same forced-rehandshake fast-follow — not just the
/// symmetric pairs that could never punch. For a symmetric<->symmetric pair
/// specifically (this test's
/// scenario), the punch can never confirm at all (`nat_matrix.rs`'s
/// `case2_symmetric_relay_needed` already proves that for this NAT kind), so
/// a real Direct cutover from `Relayed` for that pairing is out of scope here
/// (Cycle 4c fast-follow, alongside `nat_matrix.rs`'s existing 4b-only
/// direct-cutover coverage) — this fix's job is only to stop that
/// known-futile probe from also breaking the relay path it's running
/// alongside.
async fn run_path_ticks(ctx: PathCtx) {
    // Last handshake AGE we've observed per peer (via
    // `reported_handshake_age` — see its doc for the boringtun
    // elapsed-vs-absolute semantics this normalizes). A NEW handshake is an
    // age DECREASE: between handshakes the age only grows (by ~one tick per
    // tick), and each genuine completion resets it to ~0. The previous
    // epoch-space `t > prev` comparison was wrong under boringtun's elapsed
    // semantics — true every tick between handshakes (pure wall-clock noise,
    // the cycle-4b quirk) and FALSE at a genuine new handshake — which is
    // what stuck nat_matrix cases 1/3/4 in `connecting` with live traffic.
    let mut last_hs_age: HashMap<u64, Duration> = HashMap::new();
    // Last rx_bytes we've observed per peer, to detect an *increase* — WG
    // keepalives (every `uapi::PERSISTENT_KEEPALIVE_SECS` = 25s) bump
    // rx_bytes without advancing the handshake time (which only moves on
    // ~120s rekey). Without this, `last_inbound` only ever refreshes off
    // `on_handshake`, so a healthy Direct path goes stale after
    // `DEGRADED_AFTER` (45s) and spuriously degrades + re-punches every ~2
    // minutes. See docs/research/cycle4b-path-liveness-note.md.
    let mut last_rx: HashMap<u64, u64> = HashMap::new();
    // Handshake-time advances observed WITHOUT a same-tick rx delta, awaiting
    // corroboration (mesh-convergence fix T2): {gid -> tick instant of the
    // most recent uncorroborated advance}. An advance with flat rx is fed to
    // the machine as `on_handshake(now, false)` — non-evidence — and
    // remembered here; if rx then moves within
    // `HANDSHAKE_CORROBORATION_WINDOW`, the entry is promoted to a real
    // `on_handshake(now, true)`. This replaces the old "first-ever handshake
    // is trusted unconditionally" exception, which was exactly the hole the
    // 2026-07-27 incident drove through (gw-home reported `direct` on a first
    // session whose peer rx stayed 0 — finding §4). The historical reason for
    // that exception (a genuine first handshake's corroborating data packet
    // could lag unboundedly, sticking `establish_direct` in Connecting in the
    // netns nat matrix, because the one-shot `advanced` event was never
    // re-observed once missed) is addressed by this map plus fix T1: the
    // advance is no longer one-shot — it stays pending — and with a 25s
    // persistent keepalive on every peer, a real completed handshake is
    // followed by authenticated inbound within one keepalive interval, so the
    // promotion fires promptly. A boringtun false-advance (retrying a dead
    // session, timestamp climbing every tick with rx frozen) refreshes its
    // pending entry forever but never sees rx move, so it is never promoted.
    let mut pending_hs: HashMap<u64, Instant> = HashMap::new();
    // Last instant we sent a liveness probe (visible overlay datagram) to each
    // peer, so probes fire at most once per `LIVENESS_PROBE_INTERVAL` rather
    // than every ~1s tick. See `LIVENESS_PROBE_INTERVAL`: this is what makes a
    // keepalive-only-idle `Direct`/`Relayed` path's rx-corroborated liveness
    // hold, since boringtun does not count bare WG keepalives in `rx_bytes`.
    let mut last_probe: HashMap<u64, Instant> = HashMap::new();
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
        // Same rationale for the T4 endpoint pins and T3 back-off state: a
        // peer removed from the fabric must not leave a stale pin (which
        // could otherwise resurface if the id were ever reused) or an
        // orphaned back-off entry behind.
        ctx.live_endpoints.lock().unwrap().retain(|gid, _| desired_gids.contains(gid));
        ctx.punch_backoff.lock().unwrap().retain(|gid, _| desired_gids.contains(gid));
        // Same rationale again for the path map (directive-storm fix
        // review): a peer dropped from the fabric otherwise kept its `Path`
        // entry forever — unbounded growth, AND the sync loop's Report would
        // keep exporting the removed peer's frozen state in `peer_paths`
        // (feeding the controller broker stale settle/unsettle data for a
        // pair that no longer exists). The tick loop below re-creates
        // entries for every desired peer anyway (`paths.entry(..)
        // .or_insert_with`), so pruning here is always safe.
        ctx.paths.lock().unwrap().retain(|gid, _| desired_gids.contains(gid));
        // MINOR-6: this loop's OWN per-peer bookkeeping maps must be pruned on
        // the same desired-peer set too — unlike the `ctx`-level maps above they
        // are task-local, but a peer dropped from the fabric (or a reused gid)
        // would otherwise leave stale entries here forever (unbounded growth
        // under peer churn, and a resurfaced `last_hs_age`/`last_rx` baseline
        // for a reused id).
        last_hs_age.retain(|gid, _| desired_gids.contains(gid));
        last_rx.retain(|gid, _| desired_gids.contains(gid));
        pending_hs.retain(|gid, _| desired_gids.contains(gid));
        last_probe.retain(|gid, _| desired_gids.contains(gid));

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
        // Fresh per-peer stats snapshot for the metrics scrape (fix T5) —
        // rebuilt from scratch each tick so a peer dropped from desired
        // state also drops out of the scrape body.
        let mut stats_snapshot: HashMap<u64, uapi::PeerLiveness> = HashMap::new();
        let mut to_record: Vec<(u64, PathState, PathState)> = Vec::new();
        let mut to_punch: Vec<(u64, Vec<String>)> = Vec::new();
        let mut to_relay_needed: Vec<u64> = Vec::new();
        let mut to_teardown_relay: Vec<u64> = Vec::new();
        // Peers due a liveness probe this tick (keepalive-invisibility fix).
        let mut to_probe: Vec<u64> = Vec::new();
        {
            let mut paths = ctx.paths.lock().unwrap();
            for peer in &ds.peers {
                let Some(b64) = peer.active_pubkey_b64.as_deref() else { continue };
                let Some(hex) = pubkey_b64_to_hex(b64) else { continue };
                let gid = peer.gateway_id;
                let path = paths.entry(gid).or_insert_with(|| Path::new(now));
                let before = path.state;

                if let Some(info) = liveness.get(&hex).copied() {
                    // Publish this peer's snapshot for the metrics scrape
                    // (fix T5) — the SAME fetch the state machine is about
                    // to act on, so the gauges describe exactly the evidence
                    // the SM saw. Recorded even for a never-handshaked peer:
                    // rx=0/tx=0 with the age line omitted is the interesting
                    // diagnostic shape (finding §4's "rx stayed 0").
                    stats_snapshot.insert(gid, info);

                    // rx tracking runs for EVERY peer with a device entry —
                    // seeded from boot, BEFORE the first handshake exists
                    // (nat_matrix regression fix): the tick that first
                    // observes a completed handshake usually also carries the
                    // first data bytes (the handshake was demand-driven), and
                    // with `last_rx` unseeded that tick could never see the
                    // rx delta — the genuine first connect parked as
                    // uncorroborated and the machine (correctly) refused
                    // Direct. Seeding from the 0-rx boot ticks makes the
                    // handshake tick's rx jump visible, so a real first
                    // connect corroborates in the same tick, exactly like the
                    // pre-T2 timing. A never-yet-observed peer's baseline is
                    // 0 BY CONSTRUCTION — boringtun peer objects start their
                    // counters at zero when created (device boot, or a
                    // desired-state apply adding the peer, both of which this
                    // ~1s tick loop observes within a tick or two) — so a
                    // first observation with rx > 0 is itself a genuine
                    // delta; without this, a tick task briefly starved while
                    // the handshake AND first data both landed would miss the
                    // one-shot jump and park a healthy first connect until
                    // the next 25s keepalive (observed as a rare nat_matrix
                    // establishment flake). An rx DECREASE means the peer
                    // object was rebuilt (a `replace_peers` apply resets
                    // counters) — not inbound; it reseeds the baseline so the
                    // NEXT delta is visible instead of hiding behind the old
                    // high-water mark.
                    let rx = info.rx_bytes;
                    let rx_increased = last_rx.get(&gid).map_or(rx > 0, |&prev| rx > prev);
                    last_rx.insert(gid, rx);

                    if let Some(t) = info.latest_handshake {
                        // A NEW handshake is an AGE DECREASE (see
                        // `reported_handshake_age` — this is the semantics-
                        // robust event detector; boringtun 0.6.0 reports
                        // elapsed-since-handshake in the absolute-time
                        // fields, so epoch-space `t > prev` was noise: true
                        // every tick between handshakes and false at the
                        // genuine event).
                        let age = reported_handshake_age(t, SystemTime::now());
                        let new_handshake =
                            last_hs_age.get(&gid).map_or(true, |prev| age < *prev);
                        last_hs_age.insert(gid, age);

                        // Mesh-convergence fix T2: a handshake event is ONLY
                        // trusted with rx corroboration — an rx_bytes
                        // increase this same tick, or (via `pending_hs`)
                        // within `HANDSHAKE_CORROBORATION_WINDOW`. The
                        // 2026-07-27 incident
                        // (docs/research/ops-finding-multi-gateway-convergence.md
                        // §4) showed uncorroborated handshake evidence
                        // claiming `direct` for a dead tunnel (FI: handshakes
                        // "13-70s ago" with rx_bytes=0 sustained) — under the
                        // then-driver's "first-ever handshake is trusted
                        // unconditionally" exception, which is gone. A missed
                        // same-tick delta is not fatal: the event stays in
                        // `pending_hs`, and fix T1's 25s persistent keepalive
                        // guarantees a real handshake is followed by
                        // authenticated inbound within one keepalive
                        // interval, promoting it. The machine itself enforces
                        // the same rule (`Path::on_handshake(_, false)` is
                        // non-evidence), so this driver cannot weaken it — it
                        // only decides WHEN corroboration is established.
                        //
                        // Cycle 4c Task 9 gating is preserved: a corroborated
                        // handshake CARRIED OVER THE RELAY (`relay_pointed`)
                        // must not be mistaken for the make-before-break
                        // Direct cutover — it only proves the relay path is
                        // alive, so it feeds `on_authenticated_inbound`
                        // instead; only a handshake completing after
                        // `punch_and_apply` repointed the endpoint at a real
                        // direct candidate counts as the cutover.
                        if new_handshake && rx_increased {
                            // Corroborated in the same tick — the genuine
                            // completed-handshake case (data resumed with it).
                            pending_hs.remove(&gid);
                            let relay_pointed =
                                ctx.relay_pointed.lock().unwrap().get(&gid).copied().unwrap_or(false);
                            if relay_pointed {
                                path.on_authenticated_inbound(now);
                            } else {
                                path.on_handshake(now, true);
                            }
                        } else if new_handshake {
                            // Handshake event with flat rx: NOT liveness
                            // (finding §4). Remember it for within-window
                            // promotion and tell the machine, which ignores
                            // it by contract.
                            pending_hs.insert(gid, now);
                            path.on_handshake(now, false);
                        } else if rx_increased {
                            // rx moved without a handshake event this tick:
                            // real decrypted inbound. If an uncorroborated
                            // handshake is pending and still inside the
                            // window, this is its corroboration — promote it
                            // to the real handshake event; otherwise it's
                            // keepalive/data liveness as before.
                            let promoted = matches!(
                                pending_hs.remove(&gid),
                                Some(hs_at) if now.saturating_duration_since(hs_at)
                                    <= HANDSHAKE_CORROBORATION_WINDOW
                            );
                            let relay_pointed =
                                ctx.relay_pointed.lock().unwrap().get(&gid).copied().unwrap_or(false);
                            if promoted && !relay_pointed {
                                path.on_handshake(now, true);
                            } else {
                                path.on_authenticated_inbound(now);
                            }
                        }
                    }
                }

                let relay_available =
                    relays_advertised && *healthy_relay.get(&gid).unwrap_or(&false);
                match path.tick(now, relay_available) {
                    Some(PathAction::StartPunch) => {
                        to_punch.push((gid, peer.candidates.clone()))
                    }
                    // Deliberate no-op: `ProbeDirect` only fires while
                    // `Relayed`, and `punch_and_apply`'s MAJOR-1 make-before-
                    // break guard yields the moment the path isn't
                    // `Connecting` — so a spawned probe could never test a
                    // candidate, only burn a `punching` slot and print the
                    // "deferring direct punch" line once per relayed peer per
                    // `PROBE_DIRECT_INTERVAL`, forever. A real Relayed→Direct
                    // cutover needs a forced rehandshake (documented Cycle-4c
                    // fast-follow); the SM's emission and its rate-limit are
                    // the seam that fast-follow re-wires.
                    Some(PathAction::ProbeDirect) => {}
                    Some(PathAction::MarkRelayNeeded) => to_relay_needed.push(gid),
                    Some(PathAction::Retry) | None => {}
                }

                // Liveness probe (keepalive-invisibility fix): a peer in a LIVE
                // state must keep receiving VISIBLE inbound to hold, because
                // boringtun does not count bare WG keepalives in `rx_bytes`
                // (see `LIVENESS_PROBE_INTERVAL`). Send a small overlay datagram
                // toward each live peer every `LIVENESS_PROBE_INTERVAL`; every
                // gateway does this, so each live pair exchanges visible rx and
                // both sides corroborate through a keepalive-only idle
                // (convergence A4). Only `Direct`/`Relayed` — `Connecting` is
                // already nudged by the punch, and a `Degraded`/`Disconnected`
                // peer recovers via the punch/relay path, not a probe.
                if matches!(path.state, PathState::Direct | PathState::Relayed) {
                    let due = last_probe
                        .get(&gid)
                        .map_or(true, |t| now.saturating_duration_since(*t) >= LIVENESS_PROBE_INTERVAL);
                    if due {
                        last_probe.insert(gid, now);
                        to_probe.push(gid);
                    }
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

        // Publish this tick's per-peer stats snapshot for the metrics scrape
        // (fix T5). Whole-map replacement: peers dropped from desired state
        // vanish from the scrape body the same tick.
        *ctx.peer_stats.lock().unwrap() = stats_snapshot;

        // Fire this tick's due liveness probes (keepalive-invisibility fix).
        // Spawned, not awaited, so a slow send never delays the tick loop; the
        // per-peer cadence is already bounded by `last_probe`.
        for gid in to_probe {
            let ctx = ctx.clone();
            tokio::spawn(async move { poke_peer_overlay(&ctx, gid).await });
        }

        for (gid, before, after) in to_record {
            // Fix T4: a path leaving the LIVE states (Direct / Relayed) no
            // longer shows liveness, so its endpoint pin must go — that is
            // precisely what re-enables the recovery re-point: the next
            // device rebuild dials the peer's (possibly fresh) candidates
            // again instead of a dead pinned endpoint. While the pin held
            // (path live), no re-apply could clobber the endpoint (finding
            // §2); once liveness is gone, make-before-break no longer
            // applies and candidate-chasing must resume.
            if !matches!(after, PathState::Direct | PathState::Relayed) {
                ctx.live_endpoints.lock().unwrap().remove(&gid);
            }
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
            // Fix T3 (finding §3): acquire the CONCURRENCY guard FIRST, THEN
            // consult the pair's punch back-off — same ordering as the
            // controller-`Punch` arm. `punch_allowed` consumes an expired
            // back-off window (clears it, returns Allow), so it must only run
            // when an attempt will actually start; if a punch is already in
            // flight, skip without touching the back-off. The path SM's own
            // backoff bounds how often StartPunch fires per DISCONNECT cycle,
            // but an undialable pair re-enters that cycle forever — the
            // indefinite storm this back-off exists to bound.
            // Skips are silent: the state change was logged when the window
            // opened.
            match ctx.try_start_punch(gid) {
                Some(guard) => {
                    if ctx.punch_allowed(gid, &candidates) {
                        tokio::spawn(punch_and_apply(ctx.clone(), gid, candidates, None, guard));
                    }
                    // else: backed off — drop the guard without spawning.
                }
                None => eprintln!(
                    "wiremesh-gateway: punch already in flight for peer={gid}; skipping tick-driven StartPunch"
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
    let peers = dev.peers.clone();
    tokio::task::spawn_blocking(move || uapi::apply(&ifn, &dev))
        .await
        .context("active-tun UAPI apply task panicked")??;
    // Keep both change-guard fields in lockstep: `applied_peers` is the
    // structured mirror of the config just pushed, which `apply_state`'s
    // incremental-add delta diffs against (T8 make-before-break).
    {
        let mut a = active.lock().unwrap();
        a.applied_config = Some(encoded);
        a.applied_peers = peers;
    }
    Ok(())
}

/// How the desired peer set differs from what WireGuard currently holds —
/// the decision `apply_state` makes between the incremental add-only path and
/// the full `replace_peers` apply (T8 make-before-break, finding §2).
enum PeerSetDelta {
    /// The set is identical (order-insensitive) — no UAPI write needed.
    Unchanged,
    /// The only difference is brand-new peers; every peer already on the
    /// device is byte-identical. Safe for the session-preserving
    /// [`uapi::add_peers`]. Carries the peers to add.
    PureAdditions(Vec<uapi::PeerConfig>),
    /// A peer was removed, or an existing peer's endpoint/allowed-ips/keepalive
    /// changed — the full apply is required (and its session reset accepted).
    NeedsFullApply,
}

/// Classify the change from `prev` (peers currently on the device) to `next`
/// (freshly built desired peers). Peers are identified by their WireGuard
/// public key (unique per peer); a same-key peer whose other fields differ is
/// a MODIFICATION (→ [`PeerSetDelta::NeedsFullApply`], since boringtun cannot
/// modify a peer in place — see `uapi::apply`'s caveat). Only when every
/// pre-existing peer is byte-identical AND nothing was removed do added peers
/// yield [`PeerSetDelta::PureAdditions`].
fn classify_peer_delta(prev: &[uapi::PeerConfig], next: &[uapi::PeerConfig]) -> PeerSetDelta {
    use std::collections::HashMap;
    let prev_by_key: HashMap<&str, &uapi::PeerConfig> =
        prev.iter().map(|p| (p.public_key_b64.as_str(), p)).collect();
    let next_keys: std::collections::HashSet<&str> =
        next.iter().map(|p| p.public_key_b64.as_str()).collect();

    // Any peer removed (present before, absent now) forces a full apply.
    if prev.iter().any(|p| !next_keys.contains(p.public_key_b64.as_str())) {
        return PeerSetDelta::NeedsFullApply;
    }

    let mut added = Vec::new();
    for p in next {
        match prev_by_key.get(p.public_key_b64.as_str()) {
            // Pre-existing peer: must be unchanged, else it's a modify.
            Some(existing) => {
                if **existing != *p {
                    return PeerSetDelta::NeedsFullApply;
                }
            }
            None => added.push(p.clone()),
        }
    }

    if added.is_empty() {
        PeerSetDelta::Unchanged
    } else {
        PeerSetDelta::PureAdditions(added)
    }
}

/// The NON-peer device header of an `encode_set` string — everything before
/// the first peer block, i.e. the `private_key=<hex>\nlisten_port=<n>\n
/// replace_peers=true\n` lines. Used to decide whether the incremental
/// add-only fast path is safe: `classify_peer_delta` only inspects the peer
/// SET, so a change to `private_key`/`listen_port` (which `add_peers` does
/// NOT emit) would otherwise be silently skipped. Comparing this prefix
/// against the applied config's makes the header change force a full apply.
fn device_header(encoded: &str) -> &str {
    match encoded.find("public_key=") {
        Some(i) => &encoded[..i],
        None => encoded, // no peers — the whole string is header
    }
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
    live_endpoints: &Arc<std::sync::Mutex<HashMap<u64, String>>>,
) -> anyhow::Result<()> {
    // Resolve the active tun (ifname + priv key + port), captured together.
    let (ifname, priv_key, wg_port) = {
        let a = active.lock().unwrap();
        (a.ifname.clone(), a.priv_key.clone(), a.wg_port)
    };
    // Build the (cheap, synchronous) active-tun device config, pinning any
    // rotating peer's entry to its old epoch key (Role B make-before-break;
    // empty pin map in steady state = identical to the pre-rotation config)
    // AND every live peer's entry to the endpoint its tunnel is actually
    // using (fix T4, finding §2: this apply runs on EVERY Sync `State`
    // event — e.g. a brand-new gateway enrolling — and must never reset an
    // established pair's endpoint back to a static candidate; that reset is
    // what broke the working home↔FI pair when px enrolled). Then apply it
    // only if it actually changed.
    let dev = {
        let pins = wg0_pins.lock().unwrap();
        let live = live_endpoints.lock().unwrap();
        reconcile::device_config_pinned(ds, &priv_key, wg_port, &pins, &live)
    };
    // T8 make-before-break (finding §2): classify the change from what
    // WireGuard currently holds (`applied_peers`) to the freshly built
    // desired peer set. If the ONLY change is added peers — a newcomer
    // enrolling with every existing peer byte-identical, no removals or
    // modifications — apply just the new peers via the incremental,
    // session-preserving `uapi::add_peers` so established pairs keep flowing
    // uninterrupted (the full `replace_peers` apply would clear_peers() and
    // force every pair to re-handshake). Any removal/modification, or the
    // boot/first apply (no prior config, so `private_key`/`listen_port` must
    // be sent), falls through to the full apply.
    // Snapshot BOTH guard fields we classify against, so after the (awaiting)
    // incremental UAPI write we can detect a concurrent `set_peer_endpoint`
    // (spawned punch/relay task) that mutated the guard in between and refuse
    // to clobber it with our now-stale view — a TOCTOU on the `active` mutex,
    // which is deliberately only ever held in tight non-await scopes.
    let snapshot: Option<(String, Vec<uapi::PeerConfig>)> = {
        let a = active.lock().unwrap();
        a.applied_config.clone().map(|cfg| (cfg, a.applied_peers.clone()))
    };
    // Encode the freshly built device up front: needed both for the non-peer
    // header compare below and (on the PureAdditions path) for the guard
    // write-back. `encode_set` is the same renderer `apply_device_if_changed`
    // uses, so a header/byte match here is authoritative.
    let encoded_dev = uapi::encode_set(&dev).context("encoding active-tun device config")?;
    // The incremental fast paths (Unchanged / PureAdditions) only inspect the
    // peer SET; they are trustworthy ONLY when the NON-peer device config
    // (private_key + listen_port) also equals the applied snapshot — else the
    // header change would be silently skipped, since `add_peers` emits no
    // `private_key`/`listen_port` lines. A header mismatch (or no prior
    // config) forces the full replace_peers apply.
    let header_matches = snapshot
        .as_ref()
        .is_some_and(|(cfg, _)| device_header(cfg) == device_header(&encoded_dev));
    let delta = snapshot.as_ref().map(|(_, prev)| classify_peer_delta(prev, &dev.peers));
    match delta {
        Some(PeerSetDelta::Unchanged) if header_matches => {
            // No peer change AND the header (private_key/listen_port) matches —
            // a true no-op. Classifying here also correctly skips a pure
            // REORDER (same set, different order) that the byte-guard would
            // otherwise treat as a change and destructively re-apply.
        }
        Some(PeerSetDelta::PureAdditions(added)) if header_matches => {
            let encoded = encoded_dev;
            let added_n = added.len();
            let ifn = ifname.clone();
            tokio::task::spawn_blocking(move || uapi::add_peers(&ifn, &added))
                .await
                .context("incremental add-peers UAPI task panicked")??;
            // TOCTOU re-check: only write the guard back if it STILL equals the
            // snapshot we classified against. A concurrent `set_peer_endpoint`
            // full apply across the await would otherwise have its guard state
            // clobbered by our stale `encoded`/`dev.peers`. On a mismatch,
            // leave the guard as the concurrent writer set it and let the next
            // reconcile re-derive (our incremental add is already on the
            // device; the byte-guard/classify on the next apply reconciles any
            // drift). The uncontended fast path is unchanged.
            let (snap_cfg, snap_peers) =
                snapshot.as_ref().expect("PureAdditions implies a Some snapshot");
            let mut a = active.lock().unwrap();
            if a.applied_config.as_ref() == Some(snap_cfg) && a.applied_peers == *snap_peers {
                a.applied_config = Some(encoded);
                a.applied_peers = dev.peers.clone();
                drop(a);
                eprintln!(
                    "wiremesh-gateway: incremental add of {added_n} new peer(s) — existing sessions preserved",
                );
            } else {
                drop(a);
                eprintln!(
                    "wiremesh-gateway: guard changed during incremental add of {added_n} peer(s) \
                     (concurrent endpoint re-point); leaving guard for the next reconcile to re-derive",
                );
            }
        }
        // Everything else needs the full replace_peers apply: a peer
        // removal/modification (`NeedsFullApply`), boot/first apply (`None`),
        // OR an Unchanged/PureAdditions peer-set whose NON-peer header
        // (private_key/listen_port) changed (`!header_matches`) — the latter
        // must not take an incremental path that would drop the header change.
        _ => {
            apply_device_if_changed(&ifname, &dev, active).await?;
        }
    }
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
    /// Controller Sync dial target as `host:port` (hostname or IP literal) —
    /// kept unresolved so [`send_epoch_ack`]'s short-lived channel, like the
    /// main sync loop, re-resolves DNS at every dial (`sync::connect`).
    controller_sync_addr: String,
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
    /// Shared live-endpoint pin map (same `Arc` [`PathCtx`] and `apply_state`
    /// use — fix T4). Needed at the Role-A cutover guard seed for the same
    /// reason as `desired`/`wg0_pins`: the seeded config must be EXACTLY what
    /// `apply_state`/`set_peer_endpoint` will recompute (they now build with
    /// this map), or the change-guard would mismatch and the next apply would
    /// needlessly rebuild the new tun's live session.
    live_endpoints: Arc<std::sync::Mutex<HashMap<u64, String>>>,
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
        if let Some(info) = liveness.get(&w) {
            if info.latest_handshake.is_some() && info.rx_bytes > 0 {
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
        sync::connect(&rot.controller_sync_addr, &rot.identity).await?;
    // `peer_paths: None` deliberately — this unary ack is NOT a path
    // snapshot (it carries no `ctx.paths` data), so it must ride the legacy
    // `peer_paths_snapshot=false` shape: a snapshot-flagged empty list would
    // wipe the broker's stored path states for this gateway MID-ROTATION,
    // reopening settled pairs to re-punching for no reason.
    sync::report(&mut client, 0, vec![], vec![], vec![ack], None).await
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
                            let (applied_config, applied_peers) = {
                                let ds_guard = rot.desired.lock().unwrap();
                                ds_guard
                                    .as_ref()
                                    .and_then(|ds| {
                                        let pins = rot.wg0_pins.lock().unwrap();
                                        // Same live-endpoint map the recomputes
                                        // use (fix T4) — seed must match exactly.
                                        let live = rot.live_endpoints.lock().unwrap();
                                        let dev = reconcile::device_config_pinned(
                                            ds, &a.new_priv, a.new_port, &pins, &live,
                                        );
                                        // Seed BOTH guard fields (T8): the
                                        // structured peers keep `apply_state`'s
                                        // incremental-add delta consistent with
                                        // the encoded bytes right after the flip.
                                        uapi::encode_set(&dev).ok().map(|enc| (enc, dev.peers))
                                    })
                                    .map_or((None, Vec::new()), |(enc, peers)| (Some(enc), peers))
                            };
                            // Flip the shared active descriptor onto the new tun:
                            // apply_state/set_peer_endpoint/path-ticks now all
                            // follow it.
                            *rot.active.lock().unwrap() = ActiveTunInfo {
                                ifname: a.new_tun.clone(),
                                priv_key: a.new_priv.clone(),
                                wg_port: a.new_port,
                                applied_config,
                                applied_peers,
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
                applied_peers: Vec::new(),
            })),
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
            endpoint_commit: Arc::new(tokio::sync::Mutex::new(())),
            wg0_pins: Arc::new(std::sync::Mutex::new(HashMap::new())),
            peer_stats: Arc::new(std::sync::Mutex::new(HashMap::new())),
            live_endpoints: Arc::new(std::sync::Mutex::new(HashMap::new())),
            punch_backoff: Arc::new(std::sync::Mutex::new(HashMap::new())),
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
