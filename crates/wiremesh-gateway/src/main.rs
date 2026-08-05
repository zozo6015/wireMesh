//! wiremesh-gateway boot sequence + supervision (spec §5.1).
use anyhow::Context;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
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
use wiremesh_gateway::path::{
    directive_should_punch, transition_crosses_settled_boundary, Path, PathAction, PathState,
};
use wiremesh_gateway::policy_apply::needs_policy_write;
use wiremesh_gateway::punch_backoff::{PunchBackoff, PunchDecision};
use wiremesh_gateway::relay::{RelayDeathReason, RelayTransport};
use wiremesh_gateway::rotation::{
    role_b_decisions, EpochWatch, OverlapClaim, OverlapIdentity, RoleBDecision, Rotation,
    RotationAction, RotationPhase, RouteOwner, WriteBack,
};
use wiremesh_gateway::state::{DesiredState, FailStaticWriter};
use wiremesh_gateway::tunnelset::{plan_tunnel, TunnelId, TunnelSet};
use wiremesh_gateway::uapi::{pubkey_b64_to_hex, DeviceConfig};
use wiremesh_gateway::{netif, observe, punch, reconcile, rotation, routes, sync, uapi};
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

/// Persistent-keepalive for a rotation's transient Devices (our own
/// `wg0e<N>`, a Role-B overlap's `wg0o<slot>`), deliberately much shorter than the steady-state
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

/// The policy-apply worker's FIRST retry pause after an install returns
/// `Err`; consecutive failures double it up to
/// `policy_apply::RETRY_BACKOFF_MAX` (60s), so a permanently unconsumable
/// policy IR degrades to a slow heartbeat rather than a hot loop of failing
/// kernel work. Short enough that a transient failure costs a scrape
/// interval rather than a maintenance window. The pause is INTERRUPTIBLE: a
/// newly published policy wakes the worker immediately, so an operator
/// pushing a corrected policy never waits out a backoff the bad one earned.
const POLICY_APPLY_RETRY: Duration = Duration::from_secs(5);

/// The real [`wiremesh_gateway::policy_apply::PolicyApplyTarget`]: the live
/// per-tun enforcer map, plus the two things that must only move once an
/// install has ACTUALLY landed in the datapath (the `applied_version` gauge
/// and a nudge to re-report it).
struct EnforcerApplyTarget {
    enforcers: Arc<Mutex<HashMap<TunnelId, GatewayEnforcer>>>,
    applied_version: Arc<AtomicU64>,
    report_notify: Arc<tokio::sync::Notify>,
}

impl wiremesh_gateway::policy_apply::PolicyApplyTarget for EnforcerApplyTarget {
    /// The furthest-out deadline across the enforcers this install would
    /// actually WRITE (see [`wiremesh_gateway::policy_apply::needs_policy_write`],
    /// the single shared predicate this and `install` must agree on) — an
    /// entry that will not
    /// be touched has a grace that protects nothing. Without that filter, a
    /// rotation overlap's brand-new enforcer (first apply = a full fresh
    /// grace) would delay a policy TIGHTENING to the boot tun that is
    /// already clear to take it.
    ///
    /// The guard is dropped on return by construction (the signature hands
    /// back a plain `Option<Instant>`), which is what keeps the map
    /// available to the metrics scrape, retire, Role-B collapse and
    /// rotation-insert paths for the whole of the worker's wait.
    fn ready_at(&self, ds: &DesiredState, ds_is_newest: bool) -> Option<Instant> {
        let map = self.enforcers.blocking_lock();
        map.values()
            .filter(|e| needs_policy_write(e.applied_version(), ds.policy_version, ds_is_newest))
            .filter_map(|e| e.apply_ready_at())
            .max()
    }

    /// Apply the current policy IR to EVERY live enforcer (boot tun + every
    /// rotation tun), not just the active one — a policy TIGHTENING during
    /// or after a rotation overlap must reach the tun actually carrying
    /// traffic. `apply_if_changed` is idempotent per policy version, so this
    /// is cheap for entries already on `ds.policy_version` and, crucially,
    /// makes a RETRY after a partial failure re-apply only what is missing.
    ///
    /// **Each entry's deadline is re-checked HERE, under the lock.** The
    /// reading `ready_at` took was made before the lock was dropped, and
    /// `maybe_start_role_a`/`maybe_start_role_b` can insert a brand-new
    /// enforcer — one that flipped moments ago — in between. Today that is
    /// benign only because those handlers apply the same snapshot we hold,
    /// so `apply_if_changed` short-circuits; nothing states or enforces
    /// that, and it is exactly the overwrite the grace exists to prevent.
    /// An entry still inside its grace is left alone and the whole install
    /// reports `Err`, so the worker's retry re-reads the deadline and
    /// completes it once the grace elapses.
    ///
    /// `applied_version` is set from what is OBSERVED LIVE on the enforcers
    /// once the loop is done — the highest version any of them actually
    /// holds — and only on the fully-successful path. So the gauge, and the
    /// roster report derived from it, can neither claim a version the
    /// datapath does not have nor report a regression the datapath did not
    /// suffer, in either the stale-snapshot or the rollback case. See the
    /// store itself for why both halves need saying.
    fn install(&self, ds: &DesiredState, ds_is_newest: bool) -> anyhow::Result<()> {
        // `(tun id, how much of its grace is left)` for every entry this call
        // refused to write. Both halves are in the error text below: the
        // id says WHICH tun is still on the old policy, and the remaining
        // duration says how long the retry will take to finish the job —
        // without them an operator reading a `policy_apply_failures_total`
        // bump has no way to tell a benign rotation race from a real
        // rejection.
        let mut deferred: Vec<(TunnelId, Duration)> = Vec::new();
        let mut installed: Vec<TunnelId> = Vec::new();
        let mut failure: Option<anyhow::Error> = None;
        // "At least one live tun is enforcing SOME policy", evaluated under
        // the same lock as the loop below. This replaces an `ever_installed`
        // flag that was only set after a FULLY successful install: an install
        // that landed on some epochs and then bailed through the deferred
        // path below left the flag false while the datapath genuinely had
        // policy, so a later hard failure printed the CRITICAL blackhole line
        // — the loudest log in the binary — falsely, mid-incident. Reading
        // the enforcers directly cannot drift, and it is also true of policy
        // installed by a path OTHER than this worker (a rotation insert
        // applies inline before inserting).
        let any_policy_live;
        // The highest policy version actually live across the map once this
        // call is done — the gauge is derived from the enforcers themselves
        // rather than inferred from `ds`. See its use below.
        let live_max;
        {
            let mut map = self.enforcers.blocking_lock();
            let now = Instant::now();
            for (id, enforcer) in map.iter_mut() {
                if !needs_policy_write(enforcer.applied_version(), ds.policy_version, ds_is_newest)
                {
                    continue; // nothing would be written; nothing to gate on
                }
                if let Some(left) =
                    enforcer.apply_ready_at().map(|t| t.saturating_duration_since(now))
                {
                    if !left.is_zero() {
                        deferred.push((*id, left));
                        continue;
                    }
                }
                if let Err(err) = enforcer.apply_if_changed(ds) {
                    failure = Some(err.context(format!("applying policy to {id:?}")));
                    break;
                }
                installed.push(*id);
            }
            any_policy_live = map.values().any(|e| e.applied_version().is_some());
            live_max = map.values().filter_map(|e| e.applied_version()).max();
        }
        if let Some(e) = failure {
            if !any_policy_live {
                eprintln!(
                    "wiremesh-gateway: CRITICAL: NO policy is installed on ANY live tun and \
                     policy version {} cannot be applied — every tun is attached and \
                     default-denying, so ALL fabric traffic is being dropped. This is a \
                     blackhole, not fail-static. Push an installable policy from the \
                     controller.",
                    ds.policy_version
                );
            }
            // Name what DID land before the failure, so a partial success
            // followed by a hard failure doesn't read as "nothing worked".
            return Err(if installed.is_empty() {
                e
            } else {
                e.context(format!(
                    "policy version {} had already landed on tun(s) {installed:?}",
                    ds.policy_version
                ))
            });
        }
        if !deferred.is_empty() {
            // Not a policy error — a race with a rotation insert. Reported
            // as `Err` purely so the worker retries; the counter ticking is
            // acceptable and honest ("this apply did not fully land").
            //
            // This message is the ONLY place this condition is ever visible:
            // the worker only sees an opaque `anyhow::Error`, so no test can
            // assert its contents. It must therefore say, on its own, what
            // happened, what is stale right now, and what will fix it.
            let longest = deferred.iter().map(|(_, left)| *left).max().unwrap_or_default();
            let tuns: Vec<String> =
                deferred.iter().map(|(id, left)| format!("{id:?} ({left:?} left)")).collect();
            anyhow::bail!(
                "policy version {} was installed on tun(s) {installed:?} but NOT on {} of \
                 them — tun(s) [{}] are still inside their post-flip reap grace. They were \
                 created after this apply's deadline was read (a key rotation starting \
                 concurrently with a policy update), so writing them now could pull maps out \
                 from under in-flight packets. No policy is lost: the worker retries and the \
                 longest outstanding grace is {longest:?}. Persistent repeats of this for the \
                 SAME tun mean a rotation tun is stuck flipping, not a bad policy.",
                ds.policy_version,
                deferred.len(),
                tuns.join(", "),
            );
        }
        // The gauge is the highest version OBSERVED LIVE on the enforcers,
        // not `ds.policy_version` and not a running maximum. Deriving it
        // from ground truth is what makes it correct in both directions at
        // once, which neither simpler form manages:
        //
        //  - A plain `store(ds.policy_version)` is wrong when an older `ds`
        //    is skipped as stale (`ds_is_newest == false`): every enforcer is
        //    filtered out, nothing is written, and storing would report a
        //    regression the datapath never suffered (the CodeRabbit finding
        //    — invisible before the monotone filter, because back then the
        //    older snapshot was written everywhere instead, keeping gauge and
        //    datapath consistent by downgrading the datapath).
        //  - A `fetch_max(ds.policy_version)` fixes that but is then wrong
        //    for a genuine controller ROLLBACK: those enforcers really were
        //    moved back, and a high-water mark would pin the gauge above the
        //    controller's own latest forever, turning a converged gateway
        //    into a permanent roster mismatch.
        //
        // `live_max` is simply what is installed, so it holds steady in the
        // first case and follows the datapath down in the second. It is
        // monotone in normal operation for free, because `apply_if_changed`
        // only moves an enforcer forward unless a rollback write was
        // authorized, and evicting a retired epoch cannot lower the maximum
        // (the boot tun receives every version too).
        //
        // This matters beyond cosmetics: `applied_version` is what the
        // path-snapshot report carries, and controller-side alerting on
        // roster `applied_version` lag is an outstanding follow-up (see
        // `docs/research/ops-finding-sync-half-open-stream.md`). A phantom
        // regression would page as "gateway falling behind" when it is not;
        // a phantom high-water mark would hide a real rollback convergence.
        //
        // `None` only for an empty map, which cannot happen (the boot epoch
        // is always present) — leave the last value rather than inventing 0.
        if let Some(v) = live_max {
            self.applied_version.store(v, Ordering::Relaxed);
        }
        // Tell the Sync loop to re-report: it already sent its report for
        // this snapshot while the install was still pending, carrying the
        // PREVIOUS applied version. Debounced on the loop side.
        self.report_notify.notify_one();
        Ok(())
    }
}

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
    /// The active tun's WireGuard private key (the boot key selected by
    /// `EpochKeys::select_boot_key` — the store's active epoch, else the
    /// legacy identity key — or the rotated epoch's key after a Role-A
    /// cutover).
    priv_key: String,
    /// The active tun's WireGuard listen port (base port, or the rotation
    /// epoch's offset port after a cutover).
    wg_port: u16,
    /// The active tun's OWN key epoch — the boot epoch, or the rotated epoch
    /// after a Role-A cutover. This is the epoch a peer's roster advertises as
    /// our ACTIVE key, which is what makes it the discriminator
    /// [`rotation::route_owner`] uses: a Role-B overlap built on a different
    /// (now rotated-off) epoch can no longer pair with the peer's device, so it
    /// can never be that peer's settled route home. Kept in lockstep with
    /// `priv_key`/`ifname`/`wg_port` at every write.
    epoch: u32,
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
    // Boot-key selection (Backlog 3 Task 1 — durable promote/retire): the
    // persisted epoch store's ACTIVE entry wins over the legacy identity key,
    // so a rebooted post-rotation gateway comes up on the PROMOTED epoch's
    // key rather than resurrecting the retired epoch-0 key (which no peer
    // advertises once the controller has promoted — the black-hole bug, see
    // docs/research/key-rotation-teardown-notes.md item C). With no store or
    // no active entry this falls back to `Identity::wg_private_key_b64`,
    // byte-identical to the pre-fix boot. Per OD-1 the selection changes the
    // KEY only, never the tun/port: boot is ALWAYS the base tun (`wg0`) at
    // the base listen port regardless of the selected epoch — a reboot tears
    // every WG session anyway, and peers hold base-port candidates for us,
    // so re-normalizing is what lets the punch/re-establish ladder converge.
    let epoch_store = EpochKeys::load(&cfg.state_dir).context("loading epoch key store")?;
    let boot_key = EpochKeys::select_boot_key(epoch_store.as_ref(), &id.wg_private_key_b64)
        .context("selecting boot key")?;
    if boot_key.epoch != 0 {
        eprintln!(
            "wiremesh-gateway: booting on promoted epoch {} key (base tun/port per OD-1)",
            boot_key.epoch
        );
    }
    // Bring the boot epoch up INTO the `TunnelSet` rather than as a
    // standalone `Tunnel`, so that once a rotation retires it the old epoch's
    // Device can actually be torn down (its boringtun Device dropped +
    // `ip link del`). `bring_up` creates the boringtun Device, brings the tun
    // link up at `TUN_MTU`, and applies the boot epoch's private key + listen
    // port with an EMPTY peer set; `apply_state` (boot fail-static below, and
    // every Sync snapshot) fills in the peers. Keyed by `Own { epoch }` for
    // the boot key's epoch, so a later rotation's retire (`old_epoch` = the
    // store's active epoch at mint time) tears down THIS entry — and so a
    // Role-B overlap toward a PEER whose pending epoch happens to carry the
    // same NUMBER can never address it (the T3 de-collision; see
    // `tunnelset::TunnelId`). Not planned via `plan_tunnel`: the boot tun IS
    // the base tun at the base port by definition (OD-1), which is exactly
    // why the planner has to be handed the live set rather than deriving it.
    let boot_tun_id = TunnelId::Own { epoch: boot_key.epoch };
    let mut tunnels = TunnelSet::new();
    tunnels.bring_up(
        boot_tun_id,
        &cfg.tun_ifname,
        &boot_key.private_key_b64,
        cfg.wg_listen_port,
        TUN_MTU,
    )?;
    routes::install_mss_clamp(&cfg.tun_ifname, MSS)?;
    // All live L4 enforcers, keyed by `TunnelId` — the SAME key space as
    // `tunnels`, deliberately (boot tun = `Own { boot epoch }`; one entry per
    // rotation tun). `apply_state` applies the current policy to EVERY entry
    // so a policy update reaches every tun that may be carrying traffic during
    // a rotation overlap (not just `wg0`).
    //
    // SECURITY — why the key type matters here as much as it does in
    // `TunnelSet` (T3): this map used to be keyed by a bare `u32` epoch that
    // meant OUR epoch for Role A and the PEER's pending epoch for Role B. That
    // is the identical collision `TunnelSet` had, one map over — masked only
    // because `bring_up` bailed first. De-colliding the tunnels alone would
    // have converted that loud bail into a silent fail-open: `HashMap::insert`
    // returns and DROPS the displaced `GatewayEnforcer`, and holding it in
    // this map is precisely what keeps its tc-BPF/nft program attached (see
    // the note above `RotationShared`'s construction), so the displaced tun
    // would go on carrying traffic with NO policy hook at all — the very
    // default-deny-bypass gap this map exists to close.
    //
    // A `tokio::sync::Mutex` (same as the old single `enforcer`) because
    // `apply_if_changed`/`counters` are held across the metrics task's
    // `.await`.
    let enforcers: Arc<Mutex<HashMap<TunnelId, GatewayEnforcer>>> = Arc::new(Mutex::new({
        let mut m = HashMap::new();
        m.insert(boot_tun_id, GatewayEnforcer::attach(&cfg.tun_ifname)?);
        m
    }));

    // Last-applied policy version, shared with the metrics task below (it
    // does not hold the enforcer lock just to report this gauge).
    //
    // Written by exactly ONE place now (Backlog item 1):
    // `EnforcerApplyTarget::install`, after a successful install. It keeps
    // meaning "the version actually live in the datapath" — storing it when a
    // snapshot is merely accepted into the worker's mailbox would make both
    // this gauge and the controller's roster `applied_version` lag signal
    // lie by up to a full reap grace.
    let applied_version = Arc::new(AtomicU64::new(0));

    // Signals the Sync loop to send a fresh (debounced) report. Created here
    // rather than inline in `PathCtx` below because the policy-apply worker
    // — which runs the install asynchronously and so learns the new
    // `applied_version` AFTER the Sync loop has already reported — needs to
    // poke it, and the worker is spawned before `ctx` exists. Without this,
    // an install completing during a quiet period would leave the
    // controller's roster stuck on the previous version until the next
    // unrelated event.
    let path_report_notify = Arc::new(tokio::sync::Notify::new());

    // The policy-apply worker (Backlog item 1). From here on the ONLY way
    // policy reaches the enforcers on the steady-state path is
    // `policy_apply.publish(..)` — a non-async, infallible hand-off, so the
    // Sync loop can neither stall on a reap grace nor die on a bad IR. See
    // `wiremesh_gateway::policy_apply` for the full why.
    let policy_apply = wiremesh_gateway::policy_apply::spawn_policy_apply_worker(
        Arc::new(EnforcerApplyTarget {
            enforcers: enforcers.clone(),
            applied_version: applied_version.clone(),
            report_notify: path_report_notify.clone(),
        }),
        POLICY_APPLY_RETRY,
    );

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
        // The SELECTED boot key (store-active epoch, or the legacy identity
        // key fallback) — must match what `bring_up` just applied, or the
        // first `apply_state` would silently rekey the base tun.
        priv_key: boot_key.private_key_b64.clone(),
        wg_port: cfg.wg_listen_port,
        // The SAME epoch the boot tun is keyed by (`boot_tun_id` above) — the
        // store's active epoch, or 0 for the legacy identity-key fallback.
        epoch: boot_key.epoch,
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
    // Every fail-static write goes through this (Backlog item 1 follow-up):
    // the enforcer apply is asynchronous now, so the save below is no longer
    // gated by an IR decode that would have killed the process first. See
    // `FailStaticWriter` for what it refuses to persist and why.
    let mut fail_static = FailStaticWriter::seeded_from(applied.as_ref());
    if let Some(ds) = &applied {
        eprintln!("wiremesh-gateway: fail-static boot from state.json rev {}", ds.revision);
        apply_state(None, ds, &active, &wg0_pins, &live_endpoints).await?;
        // The enforcer half goes through the worker here too, so boot and
        // steady state share one install path. No reap is pending at boot
        // (nothing has flipped yet), so the backend publishes no deadline and
        // the install runs immediately; `applied_version` is stored by the
        // worker once it has.
        policy_apply.publish(ds.clone());
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
        punching: Arc::new(std::sync::Mutex::new(HashMap::new())),
        relay_transports: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        relay_connecting: Arc::new(std::sync::Mutex::new(HashSet::new())),
        relay_next_idx: Arc::new(std::sync::Mutex::new(HashMap::new())),
        relay_pointed: Arc::new(std::sync::Mutex::new(HashMap::new())),
        endpoint_commit: Arc::new(tokio::sync::Mutex::new(())),
        endpoint_commit_gen: Arc::new(AtomicU64::new(0)),
        wg0_pins: wg0_pins.clone(),
        // Shared with the policy-apply worker (created above), which pokes it
        // after a successful install so the loop re-reports the freshly
        // advanced `applied_version`.
        path_report_notify: path_report_notify.clone(),
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
        let policy_apply_metrics = policy_apply.clone();
        tokio::spawn(async move {
            let fetch = move || {
                let enforcers = enforcers.clone();
                let applied_version = applied_version.clone();
                let ctx = ctx.clone();
                let policy_apply = policy_apply_metrics.clone();
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
                        // empty map — the boot epoch is always present.
                        Some(BackendKind::Ebpf) | None => "ebpf",
                    };
                    // The `wiremesh_gateway_live_enforcers` gauge (T3), read
                    // from the map's own `len()` under the SAME acquisition
                    // the counter fold below uses — no second lock, and no
                    // parallel counter.
                    //
                    // Reading `len()` is the entire point. An enforcer entry
                    // is what holds a tun's tc-BPF/nft program attached, and
                    // `HashMap::insert` can DISPLACE one — dropping it, hence
                    // detaching it — with no removal call to hook a counter
                    // onto. A counter maintained at the insert/remove sites
                    // would therefore be incremented by the very insert that
                    // silently disarmed a live tun, and would keep reporting
                    // the healthy number while the datapath ran open. Only
                    // the map itself knows.
                    let live_enforcers = map.len() as u64;
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
                        // Backlog item 1: apply failures are no longer fatal,
                        // so they need a series an operator can alert on —
                        // and it has to ride the fetch tuple to actually
                        // reach the body.
                        policy_apply.failures(),
                        // Key-rotation T3: how many enforcers are actually
                        // ATTACHED right now. Rides the tuple for the same
                        // reason — a gauge that never reaches the scrape body
                        // proves nothing. See `render_live_enforcers`.
                        live_enforcers,
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
    // behavior is completely unchanged: the boot epoch already runs on `wg0`
    // at the base port from the boot above; the epoch store is only consulted
    // when a rotation actually starts. Uses the store loaded at boot-key
    // selection above; an EXISTING store is kept verbatim even when
    // `select_boot_key` fell back to the legacy key (a pending-only store
    // from a crash-mid-mint) — overwriting it with `from_legacy` here would
    // destroy the persisted mint. Shared (`Arc<Mutex<_>>`) because the
    // lifecycle now has three writers: `handle_rotate` (sync loop) mints,
    // the rotation tick's Role-A cutover promotes, and `service_retire`
    // (run task) retires — each persisting its transition (Backlog 3 Task 1).
    let epoch_keys: Arc<std::sync::Mutex<EpochKeys>> =
        Arc::new(std::sync::Mutex::new(match epoch_store {
            Some(k) => k,
            None => {
                let k = EpochKeys::from_legacy(&id.wg_private_key_b64)?;
                k.persist(&cfg.state_dir)?;
                k
            }
        }));
    // `tunnels` (created at boot — it owns the boot epoch-0 Device now, and the
    // per-rotation Devices below) stays owned by THIS (`block_on`'d) task,
    // never moved into a spawned task, since boringtun's `DeviceHandle` is not
    // `Send`. The rotation observation tick only ever reads a rotation Device's
    // liveness by ifname (a `String`), so it needs no handle to the Device; the
    // old-epoch teardown after a retire runs here in the run task (which owns
    // `tunnels`), driven by a shared `retire_ready` flag the tick sets.
    //
    // Each transient rotation tun's (`wg0e<N>` / `wg0o<slot>`) L4 enforcer is
    // inserted into the shared `enforcers` map above, under the SAME
    // `TunnelId` the Device itself is keyed by — so `apply_state` reaches it
    // on every policy update AND holding it in the map keeps its tc-BPF/nft
    // program attached for that Device's lifetime (dropping it would detach).
    // Closes the default-deny-bypass-on-new-tun security gap: without this, a
    // rotation tun carries traffic with NO policy hook at all.
    //
    // The key type is part of that guarantee (T3). Keyed by a bare epoch —
    // which meant OUR epoch for Role A and the PEER's pending epoch for Role
    // B — an insert could displace a DIFFERENT live tun's enforcer, and
    // `HashMap::insert` drops what it displaces. See the map's construction
    // above.
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
        relay_transports: ctx.relay_transports.clone(),
        retire_ready: Arc::new(std::sync::Mutex::new(None)),
        epoch_keys: epoch_keys.clone(),
        applied_version: applied_version.clone(),
        collapse_ready: Arc::new(std::sync::Mutex::new(Vec::new())),
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
                // Prompt-report debounce state (relay-wedge fix round 4),
                // per connection: `pending` is set when the path-tick driver
                // signals a settled-boundary crossing, and flushed at the
                // top of the loop once the debounce window opens — kept as a
                // flag (rather than sleeping on the notify arm) so the Watch
                // stream stays serviced while the window closes; the
                // `RETIRE_POLL_PERIOD` bounded wait guarantees a wakeup
                // within ~500ms of the window opening.
                let mut prompt_report_pending = false;
                let mut last_prompt_report: Option<Instant> = None;
                loop {
                    // Service any pending old-epoch retire the rotation tick has
                    // signalled (every peer cut over to the new tun and the
                    // grace elapsed). Done HERE in the run task because it owns
                    // the non-`Send` `tunnels`/`enforcers`.
                    service_retire(&mut tunnels, &enforcers, &rot, &ctx).await;
                    // Likewise any completed Role-B collapse (a rotated PEER's
                    // overlap Device whose reverse make-before-break finished).
                    service_role_b_collapse(&mut tunnels, &enforcers, &rot).await;

                    // Flush a pending prompt path-snapshot report once its
                    // debounce window opens (≥ PROMPT_REPORT_DEBOUNCE since
                    // the last prompt report — the WHY lives on
                    // `PathCtx::path_report_notify`: the broker needs the
                    // unsettle edge promptly to re-arm + re-synchronize the
                    // pair's punches, the case-4 finding). Failures are
                    // logged and dropped — the next State apply sends the
                    // same snapshot anyway.
                    //
                    // (Backlog item 1) The policy-apply worker also signals
                    // here after a successful install, so a version that
                    // landed during a quiet period still reaches the
                    // controller's roster rather than waiting for an
                    // unrelated event.
                    if prompt_report_pending
                        && last_prompt_report
                            .map_or(true, |t| t.elapsed() >= PROMPT_REPORT_DEBOUNCE)
                    {
                        prompt_report_pending = false;
                        last_prompt_report = Some(Instant::now());
                        // The INSTALLED version (the worker's atomic), not
                        // the newest snapshot's: with the install
                        // asynchronous, `applied.policy_version` is what we
                        // have accepted, which is not yet what the datapath
                        // enforces.
                        let version = applied_version.load(Ordering::Relaxed);
                        if let Err(e) = send_paths_snapshot_report(
                            &mut client,
                            &ctx,
                            cfg.wg_listen_port,
                            version,
                        )
                        .await
                        {
                            eprintln!(
                                "wiremesh-gateway: prompt path-snapshot report failed: {e}"
                            );
                        }
                    }

                    // Bounded wait so the loop still wakes to service a retire
                    // even while the controller is quiet. `next_event` is
                    // cancel-safe (tonic's `Streaming` keeps its own buffered
                    // state), so dropping it on timeout never loses a message —
                    // and `Notify::notified` is likewise cancel-safe here (a
                    // permit delivered while the other branch wins stays
                    // stored, so the signal is picked up on a later wait).
                    let ev = tokio::select! {
                        res = tokio::time::timeout(
                            RETIRE_POLL_PERIOD,
                            sync::next_event(&mut stream, &mut current),
                        ) => match res {
                            Ok(res) => res,
                            Err(_elapsed) => continue,
                        },
                        // Prompt-report signal (round 4): a peer's path
                        // crossed the settled boundary. Just mark pending —
                        // the flush above sends it once the debounce allows,
                        // keeping this wait free to keep draining the stream.
                        _ = ctx.path_report_notify.notified() => {
                            prompt_report_pending = true;
                            continue;
                        }
                    };
                    match ev {
                        Ok(Some(sync::SyncEvent::State(ds))) => {
                            // (Backlog 3 Task 1 slice of T3 — Role-B collapse
                            // trigger) BEFORE apply_state, so that when a
                            // rotating peer's retire delta collapses its key
                            // set back to active-only, the unpin below takes
                            // effect in THIS very apply: `wg0` gets rebuilt
                            // with the peer's NEW active key immediately, and
                            // the tick's reverse make-before-break can start
                            // waiting for that session to go live.
                            maybe_collapse_role_b(&rot, &ds);
                            apply_state(
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
                            // (Backlog item 1) The enforcer half of the apply,
                            // handed to the worker instead of run here. No
                            // `.await` and no `?`: this loop must not park on
                            // a reap grace (it is the same loop that services
                            // `PunchDirective`, whose go-skew budget is
                            // milliseconds) and must not exit the process
                            // because one policy IR was unconsumable.
                            //
                            // The ordering genuinely CHANGED. It used to be
                            // device → policy → routes (the enforcer apply
                            // sat inside `apply_state`, between the UAPI
                            // write and the route diff); it is now device →
                            // routes → policy, with the policy landing
                            // asynchronously later. Two distinct consequences
                            // — do not conflate them:
                            //
                            // 1. The ROUTE-vs-policy reorder is fail-closed.
                            //    A newly enrolled peer's segment CIDRs are
                            //    routed at the tun before the policy
                            //    governing them reaches the datapath, but the
                            //    policy still live there is the previous
                            //    version, which has no rule for that new
                            //    segment and default-denies it. That specific
                            //    window can only deny traffic the new policy
                            //    would allow.
                            //
                            // 2. A policy TIGHTENING is now LATE, and that is
                            //    a genuine (accepted) regression, not covered
                            //    by (1). Removing a rule or narrowing a CIDR
                            //    leaves the looser previous policy live for
                            //    the install latency — a reap grace (≤10s)
                            //    plus, if an attempt failed, up to
                            //    `policy_apply::RETRY_BACKOFF_MAX`. Nothing
                            //    here can shorten that: the grace is the
                            //    safety property (see
                            //    `PolicyApplyTarget::ready_at`'s doc, which
                            //    calls tightenings out by name). The old
                            //    inline apply paid for promptness with a 10s
                            //    stall of the Punch/rotation/scrape paths,
                            //    which is what this item exists to remove.
                            policy_apply.publish(ds.clone());
                            fail_static.save(&ds, &cfg.state_dir)?;
                            // (Key-rotation Role B) If desired state now shows a
                            // peer that is rotating (a real-keyed `pending`
                            // epoch advertised alongside its `active` one),
                            // stand up the transient overlap Device toward the
                            // peer's new key so the make-before-break cutover
                            // can happen once that session is live. No-op for
                            // steady state (no rotating peers).
                            //
                            // Infallible by construction now (T3): every
                            // failure is per-peer, logged there, and does not
                            // stop the remaining peers being attempted. This
                            // used to return `Err` on the FIRST bad peer and
                            // the handling here was exactly this log line —
                            // i.e. every peer behind it was silently skipped,
                            // on every `State` event, forever.
                            maybe_start_role_b(&mut tunnels, &enforcers, &rot, &ds).await;
                            // Publish the latest desired state to the punch /
                            // path-tick tasks (guard dropped before the await
                            // below — never held across it).
                            *ctx.desired.lock().unwrap() = Some(ds.clone());
                            // (Directive-storm fix) The full steady-state
                            // report, including the complete per-peer
                            // path-state snapshot (every tracked peer,
                            // `PathState::as_str()`'s lowercase label) so
                            // the controller's broker can skip re-punching
                            // pairs both sides report settled — see
                            // `send_paths_snapshot_report` (round 4: shared
                            // with the prompt-report path, which is why it
                            // also feeds the prompt debounce below — a State
                            // apply IS a fresh snapshot, so any pending
                            // prompt is satisfied by it).
                            // Logged, not swallowed: a report the controller
                            // REJECTS (e.g. the session-generation gate
                            // returning `FAILED_PRECONDITION`) is otherwise
                            // completely invisible in this gateway's logs,
                            // even though it means the controller's view of
                            // this gateway is frozen. Matches the
                            // prompt-report path above. Non-fatal — the next
                            // event or the reconnect re-reports.
                            if let Err(e) = send_paths_snapshot_report(
                                &mut client,
                                &ctx,
                                cfg.wg_listen_port,
                                // (Backlog item 1) The INSTALLED version, not
                                // `ds.policy_version`: the worker may still be
                                // waiting out a reap grace, and reporting a
                                // version the datapath does not yet enforce
                                // would make the controller's roster-lag
                                // signal lie. The worker signals
                                // `path_report_notify` once the install lands,
                                // so the roster converges within a debounce
                                // window rather than at the next event.
                                applied_version.load(Ordering::Relaxed),
                            )
                            .await
                            {
                                eprintln!(
                                    "wiremesh-gateway: steady-state path-snapshot report failed: {e}"
                                );
                            }
                            prompt_report_pending = false;
                            last_prompt_report = Some(Instant::now());
                            // NB: `applied_version` is deliberately NOT stored
                            // here anymore — see its declaration. `applied`
                            // still tracks the newest ACCEPTED snapshot, which
                            // is what the route diff and the rotation handlers
                            // need (both are applied synchronously above).
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
                            // flight), we don't touch the back-off: a
                            // DIRECTIVE-origin holder is skipped outright,
                            // while a TICK-origin holder is PREEMPTED (round
                            // 5 — see the None arm below).
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
                                match ctx.try_start_punch(gid, PunchOrigin::Directive) {
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
                                    // Round 5 (directive preemption — case-4
                                    // rerun finding): the slot is occupied. A
                                    // TICK-origin holder is a stale self-timer
                                    // trial — by the time it yields on its own
                                    // (deferring when the SM recycles
                                    // Connecting→Disconnected at
                                    // CONNECT_TIMEOUT), this directive's
                                    // synchronized go-time has long passed, so
                                    // every broker-synchronized window was
                                    // being eaten by "punch already in
                                    // flight" skips. Cancel it and hand the
                                    // directive to a small bounded-wait task
                                    // that claims the slot the moment it
                                    // frees (the cancelled trial polls its
                                    // flag every PUNCH_POLL_INTERVAL=500ms).
                                    // A DIRECTIVE-origin holder keeps today's
                                    // skip: two synchronized directives carry
                                    // the same go — racing them buys nothing.
                                    None => {
                                        if ctx.preempt_tick_punch(gid) {
                                            eprintln!(
                                                "wiremesh-gateway: peer={gid} controller directive \
                                                 preempting stale tick-origin punch trial; handing off"
                                            );
                                            tokio::spawn(directive_punch_handoff(
                                                ctx.clone(),
                                                gid,
                                                d.candidates,
                                                d.go_unix_ms,
                                            ));
                                        } else {
                                            eprintln!(
                                                "wiremesh-gateway: punch already in flight for peer={gid}; \
                                                 skipping controller directive"
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        Ok(Some(sync::SyncEvent::Rotate(d))) => {
                            eprintln!(
                                "wiremesh-gateway: RotateDirective received (epoch={})",
                                d.epoch
                            );
                            if let Err(e) = handle_rotate(
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
    /// Per-peer in-flight `punch_and_apply` slot (review finding: a
    /// controller `Punch` directive and a tick-driven `StartPunch` for the
    /// SAME peer could otherwise spawn two concurrent tasks that each
    /// `replace_peers`-apply the full device). Claimed via
    /// [`PathCtx::try_start_punch`], released by dropping the returned
    /// [`PunchGuard`]. Each slot records its [`PunchOrigin`] and carries a
    /// cancellation flag (round 5, directive preemption): a
    /// controller-directive arrival may preempt a stale TICK-origin trial —
    /// the case-4 rerun showed the broker's synchronized directives being
    /// dropped at "punch already in flight" against self-timer tick trials,
    /// eating every synchronized window — whereas a DIRECTIVE-origin
    /// in-flight trial is left alone (two synchronized directives share one
    /// go; racing them buys nothing).
    punching: Arc<std::sync::Mutex<HashMap<u64, PunchSlot>>>,
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
    /// Monotonic counter of [`set_peer_endpoint`] pin mutations, bumped inside
    /// the [`PathCtx::endpoint_commit`] critical section on every
    /// `live_endpoints` write that function performs.
    ///
    /// This is what subordinates the path tick's ENDPOINT READ-THROUGH (the
    /// port-authority fix, piece 1) to the explicit punch/relay writers rather
    /// than letting the two race. The tick reads the device's roamed
    /// `endpoint=` OUTSIDE the commit lock (it is one leg of the same
    /// once-per-second `get_peer_liveness` fetch that drives the state
    /// machine), so without a guard this interleaving reverts a just-installed
    /// endpoint:
    ///
    /// 1. tick reads the device and sees peer `g` at the OLD endpoint `E1`;
    /// 2. `set_peer_endpoint` pins `E2` (punch success, or a relay install)
    ///    and writes it to the device;
    /// 3. the tick's read-through writes `E1` back over the pin — the device
    ///    still holds `E2`, but the next full `apply_state` rebuild renders
    ///    `E1` and clobbers the live path.
    ///
    /// The tick therefore snapshots this counter BEFORE its UAPI read and,
    /// holding `endpoint_commit`, re-reads it before writing: any intervening
    /// commit means the snapshot is stale, and the whole read-through is
    /// skipped for that tick (the next tick's read is fresh, and — since the
    /// device and the pin then agree — resolves to a no-op).
    endpoint_commit_gen: Arc<AtomicU64>,
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
    ///
    /// SECOND WRITER, deliberately subordinate (port-authority fix, piece 1):
    /// `run_path_ticks`'s endpoint READ-THROUGH also refreshes this map, from
    /// the device's own roamed `endpoint=`, for peers it has just judged
    /// `Direct`/`Relayed`. That covers every endpoint boringtun chose for
    /// itself — which `set_peer_endpoint` by construction never sees — so a
    /// full `replace_peers` apply can no longer rewrite a live roamed peer
    /// back to its static base-port candidate and destroy the session. The
    /// two writers are ordered, not racing: the read-through runs under the
    /// same `endpoint_commit` lock and drops its whole batch if
    /// `endpoint_commit_gen` moved during its device read, so an explicit
    /// commit always beats a stale observation.
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
    /// Prompt-report signal (relay-wedge fix round 4): `run_path_ticks`
    /// fires `notify_one` whenever any peer's recorded transition CROSSES
    /// the settled boundary (`path::transition_crosses_settled_boundary` —
    /// membership in `{Direct, Relayed}` changed), and the sync loop
    /// `select!`s on `notified()` alongside its Watch stream to send a full
    /// `peer_paths` snapshot Report promptly (debounced there, ≥2s between
    /// prompt reports across ALL peers). WHY (the authoritative case-4
    /// finding): reports used to ride only `SyncEvent::State` applies, so
    /// when a relayed pair's legs died the controller's stored states said
    /// `relayed`/`relayed` (settled — possibly settled-SKIPPING the pair)
    /// long after the fall, its periodic punch budget stayed exhausted from
    /// establishment, and the two gateways punched on unsynchronized
    /// self-timers (idle-timeout detection + backoff drift) that a
    /// port-restricted pair can never land — the broker needs the unsettle
    /// edge promptly, not at the next roster change. `Notify`'s stored
    /// permit means an edge fired while the sync loop was busy (or
    /// disconnected) is picked up at its next wait, and multiple edges
    /// coalesce — correct, since every prompt report is a complete
    /// snapshot.
    path_report_notify: Arc<tokio::sync::Notify>,
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

    /// Try to claim the in-flight-punch slot for peer `gid`, recording the
    /// attempt's `origin` (round 5: tick-driven vs controller-directive —
    /// see `punching`'s doc for why the distinction matters). Returns `None`
    /// if a punch for this peer is already running — a tick-driven caller
    /// should skip and log; the DIRECTIVE arm instead consults
    /// [`PathCtx::preempt_tick_punch`] to evict a stale tick trial. Returns
    /// `Some(guard)` otherwise, having marked `gid` as in-flight; the caller
    /// must move the guard into the spawned task (e.g. as an extra
    /// parameter to `punch_and_apply`) so it's held for the task's whole
    /// lifetime and released — fail-static, on success OR error OR panic —
    /// when the guard drops. `punch_and_apply` polls the guard's `cancel`
    /// flag each trial iteration and yields promptly once preempted.
    fn try_start_punch(&self, gid: u64, origin: PunchOrigin) -> Option<PunchGuard> {
        let mut slots = self.punching.lock().unwrap();
        if slots.contains_key(&gid) {
            return None;
        }
        let cancel = Arc::new(AtomicBool::new(false));
        slots.insert(gid, PunchSlot { origin, cancel: cancel.clone() });
        Some(PunchGuard { punching: self.punching.clone(), gid, cancel })
    }

    /// (Round 5, directive preemption) If peer `gid`'s in-flight punch slot
    /// is held by a TICK-origin trial, set its cancellation flag and return
    /// `true` — the caller (the controller-directive arm) then spawns
    /// [`directive_punch_handoff`] to claim the slot the moment the
    /// cancelled trial yields it. Returns `false` when the slot is held by a
    /// DIRECTIVE-origin trial (two synchronized directives share one go —
    /// racing them buys nothing; keep today's skip) or is already free (the
    /// caller should simply retry [`PathCtx::try_start_punch`]; the handoff
    /// task's first poll does exactly that, so callers may treat free as
    /// preemptable — this method returns `true` for that case to keep the
    /// arm's logic single-branch). Idempotent: re-flagging an
    /// already-cancelled trial is harmless.
    fn preempt_tick_punch(&self, gid: u64) -> bool {
        let slots = self.punching.lock().unwrap();
        match slots.get(&gid) {
            Some(slot) if slot.origin == PunchOrigin::Tick => {
                slot.cancel.store(true, Ordering::Relaxed);
                true
            }
            Some(_) => false, // directive-origin in flight: leave it be
            None => true,     // freed in the meantime: hand off immediately
        }
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

/// Who started an in-flight punch attempt (round 5, directive preemption):
/// the path SM's self-timer (`StartPunch`, unsynchronized with the peer) or
/// a controller `PunchDirective` (broker-synchronized go on both sides —
/// the only kind that can land a port-restricted pair). A directive arrival
/// preempts a `Tick` holder but never a `Directive` one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PunchOrigin {
    Tick,
    Directive,
}

/// One peer's occupied in-flight-punch slot: its origin plus the
/// cancellation flag `punch_and_apply` polls each trial iteration
/// (dependency-free `Arc<AtomicBool>` — the trial loop already wakes every
/// [`PUNCH_POLL_INTERVAL`] = 500ms, so a set flag is honored well inside
/// the handoff wait budget).
struct PunchSlot {
    origin: PunchOrigin,
    cancel: Arc<AtomicBool>,
}

/// RAII release for [`PathCtx::try_start_punch`]'s in-flight-punch slot.
/// Removing `gid` on `Drop` (rather than requiring an explicit call at every
/// `punch_and_apply` return site) means an early `return` on error, or even
/// a task panic unwinding through it, still releases the slot — a punch
/// failure must never permanently wedge future punches for that peer. Drop
/// removes the entry only if it is still THIS guard's own slot (`Arc::ptr_eq`
/// on the cancel flag — same defensive shape as `RegistrationGuard`'s
/// `same_channel`), so a late drop can never evict a successor's slot.
struct PunchGuard {
    punching: Arc<std::sync::Mutex<HashMap<u64, PunchSlot>>>,
    gid: u64,
    /// This attempt's own cancellation flag — set via
    /// [`PathCtx::preempt_tick_punch`]; polled by `punch_and_apply`.
    cancel: Arc<AtomicBool>,
}

impl PunchGuard {
    /// Whether this attempt has been preempted (round 5) — checked by
    /// `punch_and_apply` at the top of every trial iteration.
    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
}

impl Drop for PunchGuard {
    fn drop(&mut self) {
        let mut slots = self.punching.lock().unwrap();
        let still_ours =
            slots.get(&self.gid).is_some_and(|s| Arc::ptr_eq(&s.cancel, &self.cancel));
        if still_ours {
            slots.remove(&self.gid);
        }
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
/// `guard` is the in-flight-punch slot from [`PathCtx::try_start_punch`] —
/// HELD for this function's entire lifetime (including every early `return`)
/// and released via `Drop`, so at most one `punch_and_apply` runs per peer
/// at a time regardless of whether it was triggered by a controller `Punch`
/// directive or a tick-driven `StartPunch`. The guard also carries this
/// attempt's CANCELLATION flag (round 5, directive preemption): the trial
/// polls it at the top of every loop iteration AND again immediately before
/// each endpoint commit (B1 follow-up — the cheap common-case exit) and,
/// once preempted (a controller directive evicting a stale tick-origin trial
/// — [`PathCtx::preempt_tick_punch`]), returns promptly WITHOUT recording a
/// punch outcome (mirroring the make-before-break yield semantics: no
/// dialability was conclusively tested), freeing the slot for the waiting
/// [`directive_punch_handoff`] — whose [`HANDOFF_WAIT_MAX`] is derived from
/// this loop's worst-case latency to observe the flag.
/// Every blocking call (`uapi::apply` inside `set_peer_endpoint`,
/// the nudge socket) runs inside `spawn_blocking`; no mutex guard is ever held
/// across an `.await`.
async fn punch_and_apply(
    ctx: PathCtx,
    gid: u64,
    candidates: Vec<String>,
    go_unix_ms: Option<u64>,
    guard: PunchGuard,
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
        // Preemption check (round 5): a controller directive has evicted
        // this stale tick-origin trial — yield the slot NOW so the waiting
        // handoff can run the broker-synchronized punch before its go-time
        // rots. Return WITHOUT recording an outcome (no dialability was
        // conclusively tested), exactly like the make-before-break yield.
        if guard.cancelled() {
            eprintln!(
                "wiremesh-gateway: peer={gid} punch trial preempted by controller directive; \
                 yielding slot"
            );
            return;
        }

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
        let (connecting, relay_pointed_now) = {
            let state = ctx.paths.lock().unwrap().get(&gid).map(|p| p.state);
            let pointed = ctx.relay_pointed.lock().unwrap().get(&gid).copied().unwrap_or(false);
            (state.is_some() && directive_should_punch(state, pointed), pointed)
        };
        if !connecting {
            // Low-noise, and deliberately NOT worded with any of the four
            // attempt-counting prefixes (`punch to peer=`, `no candidate
            // confirmed`, `punch confirmed`, `punch task for peer=`) — yielding
            // is not a punch attempt, so it must not feed the anti-storm tally.
            // Return WITHOUT recording an outcome: no dialability was tested.
            // The "deferring direct punch" substring is the counting tests'
            // DEFER_NEEDLE and must stay byte-identical; only the
            // parenthetical varies — the relay clause is only claimed when
            // the WG endpoint really is pointed at a relay socket (round-5
            // wording fix: a post-relay-death yield has no relay flowing).
            let why = if relay_pointed_now {
                "(make-before-break, relay path kept flowing)"
            } else {
                "(make-before-break)"
            };
            eprintln!(
                "wiremesh-gateway: peer={gid} path no longer connecting; deferring direct punch {why}"
            );
            return;
        }

        match trial.poll(Instant::now(), PER_CANDIDATE_PUNCH_TIMEOUT) {
            punch::TrialStep::Punch(addr) => {
                // Second preemption check (B1 review follow-up), immediately
                // BEFORE the iteration's expensive part — the endpoint
                // commit + nudge. Safe by construction: nothing has been
                // written yet (`set_peer_endpoint` performs the whole
                // guard+write atomically under `endpoint_commit`, and this
                // returns before entering it), so there is no half-applied
                // endpoint state — identical to the make-before-break yield,
                // which already returns from this same point. This does not
                // LOWER the worst-case bound (a flag set just after this
                // check still costs apply+nudge+sleep — see
                // `HANDOFF_WAIT_MAX`'s arithmetic, which budgets for exactly
                // that), but it collapses the common case: a directive
                // arriving while the trial is between candidates now yields
                // the slot in ~one poll instead of a full apply cycle.
                if guard.cancelled() {
                    eprintln!(
                        "wiremesh-gateway: peer={gid} punch trial preempted by controller \
                         directive before endpoint commit; yielding slot"
                    );
                    return;
                }
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

/// How often [`directive_punch_handoff`] re-polls the per-peer punch slot
/// while waiting for a preempted tick trial to yield it (round 5).
const HANDOFF_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Bounded allowance for ONE endpoint-apply + nudge inside a punch trial
/// iteration — `set_peer_endpoint`'s [`PathCtx::endpoint_commit`] acquisition
/// plus its `spawn_blocking` UAPI write, plus `poke_peer_overlay`'s own
/// `spawn_blocking` socket send. All are local (UAPI socket / loopback
/// datagram) and typically complete in single-digit ms; 1s is deliberately
/// generous for container CPU contention and for the commit lock briefly
/// being held by a concurrent relay install.
const HANDOFF_ENDPOINT_APPLY_ALLOWANCE: Duration = Duration::from_millis(1000);

/// Upper bound on [`directive_punch_handoff`]'s wait for the slot, DERIVED
/// from the preempted trial's actual worst-case latency to observe its
/// cancel flag rather than guessed (B1 review finding: a flat 1.5s could be
/// shorter than that worst case, dropping the directive after a successful
/// preemption — wasting the very window preemption exists to capture).
///
/// Arithmetic — worst case is the flag being set immediately AFTER the
/// trial's last cancel check in an iteration, so the whole remainder of that
/// iteration runs before the next check:
///
/// * [`HANDOFF_ENDPOINT_APPLY_ALLOWANCE`] (1000ms) — the endpoint write +
///   nudge that iteration may still perform;
/// * [`PUNCH_POLL_INTERVAL`] (500ms) — the trial's per-iteration sleep,
///   always completed before it loops back to the check;
/// * [`HANDOFF_POLL_INTERVAL`] (100ms) — this task observes the freed slot
///   up to one poll late.
///
/// That sums to 1600ms; doubled for headroom = 3200ms. Comfortably under the
/// broker's ~5s periodic re-emit cadence, so a genuinely stuck slot (e.g. a
/// fresh trial re-claimed it first) still falls back to the sweep rather
/// than parking this task indefinitely.
const HANDOFF_WAIT_MAX: Duration = Duration::from_millis(
    2 * (HANDOFF_ENDPOINT_APPLY_ALLOWANCE.as_millis() as u64
        + PUNCH_POLL_INTERVAL.as_millis() as u64
        + HANDOFF_POLL_INTERVAL.as_millis() as u64),
);

/// (Round 5, directive preemption) Bounded wait for a preempted TICK-origin
/// punch trial to release peer `gid`'s slot, then run the controller
/// directive's synchronized punch (`candidates` + shared `go_unix_ms`) in
/// its place. Spawned by the directive arm when `try_start_punch` found the
/// slot held by a tick trial (which it flagged for cancellation via
/// [`PathCtx::preempt_tick_punch`]). Mirrors the arm's own ordering
/// discipline on claim: concurrency guard FIRST, then the
/// `directive_should_punch` precondition re-check (the path may have left
/// `Connecting` during the wait — spawning anyway would only buy a
/// "deferring direct punch" line, silently skip instead, exactly like the
/// arm), then `punch_allowed` (fix T3: never consume a back-off window
/// unless an attempt actually starts). `punch_and_apply`'s go-delay handles
/// an already-past `go_unix_ms` as "start now", so a handoff landing after
/// the go instant still punches immediately — late by ≤~1 trial-poll, still
/// inside the punch probes' overlap window.
async fn directive_punch_handoff(ctx: PathCtx, gid: u64, candidates: Vec<String>, go_unix_ms: u64) {
    let deadline = Instant::now() + HANDOFF_WAIT_MAX;
    loop {
        if let Some(guard) = ctx.try_start_punch(gid, PunchOrigin::Directive) {
            let should_punch = {
                let state = ctx.paths.lock().unwrap().get(&gid).map(|p| p.state);
                let pointed =
                    ctx.relay_pointed.lock().unwrap().get(&gid).copied().unwrap_or(false);
                directive_should_punch(state, pointed)
            };
            if should_punch && ctx.punch_allowed(gid, &candidates) {
                punch_and_apply(ctx.clone(), gid, candidates, Some(go_unix_ms), guard).await;
            }
            // else: precondition lapsed or backed off — drop the guard
            // silently without spawning (same as the directive arm).
            return;
        }
        if Instant::now() >= deadline {
            eprintln!(
                "wiremesh-gateway: peer={gid} directive handoff timed out waiting for the \
                 punch slot; dropping directive (broker re-emits on its sweep)"
            );
            return;
        }
        tokio::time::sleep(HANDOFF_POLL_INTERVAL).await;
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
    // Publish the pin mutation to the path tick's endpoint read-through
    // (port-authority fix, piece 1): bumped HERE — under `endpoint_commit`,
    // immediately after the pin write and BEFORE the device write — so a tick
    // that read the device before this commit can detect that its snapshot is
    // stale and decline to write `E1` back over this `E2`. See
    // `PathCtx::endpoint_commit_gen`. Bumped on the pin write rather than on
    // apply success because the pin is inserted unconditionally above: a
    // failing apply still leaves the pin mutated, and the read-through must
    // not race that either.
    ctx.endpoint_commit_gen.fetch_add(1, Ordering::SeqCst);
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
/// both for freshly entering `Relayed` and for a relay-to-relay re-path
/// after the peer's current transport dies; since the aether-prod-fi-01
/// wedge fix a dead transport first goes through `PathAction::RelayDied` —
/// teardown + pin clear — whose driver branch then either spawns this
/// IMMEDIATELY (a graceful relay-side close, i.e. an eviction: the
/// fast-path preserving the ≤30s re-path budget) or grants one clean
/// direct-punch window first (silence/other), with the re-relay landing
/// here one punch cycle later via the `Connecting`-timeout
/// `MarkRelayNeeded` ladder). No-op if a healthy transport already
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

/// Tear down peer `gid`'s relay transport, if any. Serves BOTH teardown
/// paths: Cycle 4c Task 8's make-before-break cutover (called once a peer
/// reaches `Direct`, whether it arrived there from `Relayed` or never needed
/// relay help at all — a no-op in the latter case), and the relay-death
/// cleanup (`PathAction::RelayDied` — the peer's relay leg died, so the dead
/// transport must go before the next direct-punch window opens). `reason` is
/// interpolated into the teardown log line so the Direct-cutover wording
/// isn't emitted for the death path. Explicitly [`RelayTransport::close`]s
/// the QUIC connection before dropping (see that method's doc: `Client`
/// clones don't close on drop by themselves).
async fn teardown_relay_transport(ctx: &PathCtx, gid: u64, reason: &str) {
    let removed = ctx.relay_transports.lock().await.remove(&gid);
    if let Some(peer_relay) = removed {
        peer_relay.transport.close();
        eprintln!(
            "wiremesh-gateway: peer={gid} {reason}; tore down relay={} transport",
            peer_relay.relay_id
        );
    }
}

/// Builds and sends the gateway's COMPLETE steady-state `Sync.Report`: the
/// full local-endpoint set, the relay-health snapshot, and the per-peer
/// path-state SNAPSHOT (`Some(..)` → `peer_paths_snapshot=true` on the
/// wire). Factored so BOTH report sites emit the identical shape (relay-wedge
/// fix round 4): the `SyncEvent::State` apply path, and the prompt-report
/// path (a settled-boundary transition signalled via
/// `PathCtx::path_report_notify` — the broker needs the unsettle edge
/// promptly, not at the next roster change). The `paths` guard is taken in a
/// tight scope and dropped before any await, per `PathCtx`'s discipline.
async fn send_paths_snapshot_report(
    client: &mut SyncClient<Channel>,
    ctx: &PathCtx,
    wg_listen_port: u16,
    applied_version: u64,
) -> anyhow::Result<()> {
    let local_endpoints = netif::local_wg_endpoints(wg_listen_port);
    let relay_health = ctx.relay_health_snapshot().await;
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
    sync::report(client, applied_version, local_endpoints, relay_health, vec![], Some(peer_paths))
        .await
}

/// Minimum spacing between PROMPT (notify-triggered) path-snapshot reports —
/// a simple across-all-peers debounce so a burst of boundary crossings (e.g.
/// several peers' relay legs dying at once) coalesces into one snapshot
/// rather than one RPC per transition. Each report is a complete snapshot,
/// so coalescing loses nothing.
const PROMPT_REPORT_DEBOUNCE: Duration = Duration::from_secs(2);

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
/// hasn't advertised any relay); `RelayDied` (the `Relayed` arm's relay-death
/// branch, aether-prod-fi-01 wedge fix) tears down the peer's DEAD relay
/// transport, clears its `relay_pointed` pin, and then branches on the
/// death's classification (`RelayTransport::death_reason`): a graceful
/// relay-side close (`Closed` — a controller eviction, which severed the
/// peer's leg too) reconnects a relay IMMEDIATELY, restoring the eviction
/// re-path timing; `TimedOut` (silence — the wedge shape: the peer left the
/// relay entirely) and `Other` do NOT immediately re-relay, so the next
/// `Connecting` spell's punch guard actually opens (a genuinely
/// relay-needing pair re-relays one punch cycle later via the
/// `Connecting`-timeout `MarkRelayNeeded` ladder). A per-tick stale-pin
/// invariant sweep backs all of this up: any `relay_pointed` pin with no
/// healthy transport while the peer is not `Relayed` is a leak (e.g. a
/// late `ensure_relay_transport` re-pinning after a `RelayDied` cleanup,
/// whose transport then dies outside `Relayed` — `RelayDied` can't re-fire
/// there) and is cleared, with the dead map entry torn down — see the sweep
/// collect/act phases in the loop body. Recorded transitions that CROSS the
/// settled boundary (`path::transition_crosses_settled_boundary`) fire
/// `PathCtx::path_report_notify` so the sync loop sends a prompt `peer_paths`
/// snapshot report (round 4 — the broker needs the unsettle edge promptly to
/// re-synchronize a fallen pair's punches; see that field's doc).
/// `relay_available` is computed per peer as
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
        // Snapshot the endpoint-commit generation BEFORE the device read, so
        // the endpoint read-through below can tell whether a punch/relay
        // commit landed while this fetch was in flight (see
        // `PathCtx::endpoint_commit_gen` for the interleaving this closes).
        let commit_gen_at_read = ctx.endpoint_commit_gen.load(Ordering::SeqCst);
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
        // Peers whose relay leg DIED this tick (`PathAction::RelayDied`):
        // dead-transport teardown + relay_pointed clear, NO relay reconnect.
        let mut to_relay_died: Vec<u64> = Vec::new();
        // Stale-pin sweep candidates (round-3 reviewer MAJOR): peers whose
        // `relay_pointed` pin is set with NO healthy transport while not
        // `Relayed` — a leaked pin nothing else would ever clear. See the
        // sweep loop below for the leak path and the race trace.
        let mut to_sweep_pin: Vec<u64> = Vec::new();
        // Peers due a liveness probe this tick (keepalive-invisibility fix).
        let mut to_probe: Vec<u64> = Vec::new();
        // Endpoint read-through candidates (port-authority fix, piece 1):
        // `(gid, the endpoint the DEVICE says it is using)` for every peer
        // this tick judged live. Collected here and reconciled against the
        // pin map after the `paths` guard drops — see the ACT phase.
        let mut to_pin_endpoint: Vec<(u64, SocketAddr)> = Vec::new();
        {
            let mut paths = ctx.paths.lock().unwrap();
            for peer in &ds.peers {
                let Some(b64) = peer.active_pubkey_b64.as_deref() else { continue };
                let Some(hex) = pubkey_b64_to_hex(b64) else { continue };
                let gid = peer.gateway_id;
                let path = paths.entry(gid).or_insert_with(|| Path::new(now));
                let before = path.state;
                // The endpoint the DEVICE is actually using for this peer,
                // taken off the SAME fetch the state machine is about to act
                // on (endpoint read-through, port-authority fix piece 1 — see
                // the COLLECT block further down). Captured up here because
                // `info` is scoped to the liveness block below while the
                // read-through needs the POST-`tick` path state.
                let dev_endpoint = liveness.get(&hex).and_then(|i| i.endpoint);

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
                let action = path.tick(now, relay_available);
                match action {
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
                    // Relay-death (aether-prod-fi-01 wedge fix): the peer's
                    // relay leg died while `Relayed`. Handled after the
                    // `paths` guard drops — tear down the dead transport,
                    // clear the `relay_pointed` pin, then branch on the
                    // death's classification: immediate relay reconnect for
                    // a graceful close (eviction), or a clean direct-punch
                    // window (no reconnect) for silence/other — see the
                    // to_relay_died loop below.
                    Some(PathAction::RelayDied) => to_relay_died.push(gid),
                    Some(PathAction::Retry) | None => {}
                }

                // Stale-pin invariant sweep — COLLECT phase (round-3
                // reviewer MAJOR). Leak path being closed: a late-completing
                // `ensure_relay_transport` (spawned before a `RelayDied`
                // cleanup ran) can re-point + re-pin AFTER that cleanup —
                // its commit has no staleness guard ("the relay path never
                // yields"). If that transport then dies BEFORE the path
                // re-enters `Relayed`, `RelayDied` can never fire again (it
                // is emitted only from the `Relayed` arm), nothing else
                // clears the pin, and every StartPunch defers — the
                // production wedge surviving through a window that was
                // benign pre-fix only because every death immediately
                // re-spawned `ensure`. The invariant enforced here: a pin
                // may only outlive its tick if a healthy transport backs it
                // or the peer is `Relayed` (the legitimate install window —
                // ensure just committed, path about to go Relayed — always
                // HAS a healthy transport in the map, so it is excluded by
                // construction). The same-tick `RelayDied` peer is excluded
                // too: its own cleanup below already tears down + clears.
                // `healthy_relay` here is this tick's earlier snapshot; the
                // ACT phase below re-checks the live map before acting (see
                // its race trace).
                if !matches!(action, Some(PathAction::RelayDied))
                    && path.state != PathState::Relayed
                    && !*healthy_relay.get(&gid).unwrap_or(&false)
                    && ctx.relay_pointed.lock().unwrap().get(&gid).copied().unwrap_or(false)
                {
                    to_sweep_pin.push(gid);
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

                // ENDPOINT READ-THROUGH — COLLECT phase (port-authority fix,
                // piece 1; see
                // docs/research/port-authority-verification-the-shape-was-wrong.md).
                //
                // WHY: `device_config_pinned` PREFERS `live_endpoints` over
                // `primary_endpoint()`, and until now the only writer was
                // `set_peer_endpoint` — so the map only ever learned endpoints
                // this gateway CHOSE (a punch candidate, or a relay socket).
                // Anything boringtun ROAMED to on its own was invisible to
                // every rebuild, and the next full apply (`replace_peers`)
                // rewrote the peer back to its static base-port candidate AND
                // destroyed the session. That is what makes the key-rotation
                // collapse arm destroy a working roamed session: the collapse
                // unpins, the key change forces `NeedsFullApply`, and the
                // roamed endpoint is lost — so `all_live` never holds and
                // `service_retire` never fires.
                //
                // WHAT: for a peer this tick judged LIVE (`Direct`/`Relayed`),
                // adopt the device's own `endpoint=` as the pin. This is a
                // CONTINUOUS read-through, not a one-shot seed at the rotation
                // cutover: the only roamed value available at the cutover is
                // the peer's transient Role-B overlap socket, which is
                // destroyed when that overlap collapses, so seeding from it
                // would durably pin a dead address.
                //
                // The existing semantics are preserved exactly — live peers
                // keep the endpoint their tunnel is really using, dead peers
                // chase candidates (the pin is still cleared the moment the
                // path leaves `Direct`/`Relayed`, in the `to_record` loop
                // below). This does not add a competing writer: it is
                // subordinate to `set_peer_endpoint`, which still decides
                // where a NON-live peer gets pointed, and whose commits win
                // over a stale read via `endpoint_commit_gen`.
                //
                // RELAY: for a `Relayed` peer the device's endpoint IS the
                // loopback relay socket — `RelayTransport` serves both pump
                // directions from the ONE socket it bound at `127.0.0.1:0`,
                // so relayed inbound reaches boringtun sourced from exactly
                // the `local_addr` `set_peer_endpoint` installed, and the
                // read-through resolves to a no-op. (If a relayed peer's
                // device did roam off-loopback, an authenticated datagram
                // genuinely arrived direct and boringtun is ALREADY sending
                // there — the pin then just stops a later rebuild from
                // disagreeing with the device.)
                //
                // Rejected values: a port-0 or unspecified-IP endpoint is
                // undialable, so it must never be made durable — better no
                // pin (chase the candidate) than a black hole. Unparseable
                // endpoints are already dropped in `uapi::parse_get_response`.
                if matches!(path.state, PathState::Direct | PathState::Relayed) {
                    match dev_endpoint {
                        Some(ep) if !ep.ip().is_unspecified() && ep.port() != 0 => {
                            to_pin_endpoint.push((gid, ep));
                        }
                        _ => {}
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

        // ENDPOINT READ-THROUGH — ACT phase (port-authority fix, piece 1; see
        // the COLLECT block above for the full rationale). Two steps, both
        // outside the `paths` guard:
        //
        // 1. Diff against the current pins first, under a short
        //    `live_endpoints` lock with nothing else held. In steady state the
        //    device agrees with the pin, so this is empty and the tick costs
        //    one uncontended lock — no `endpoint_commit` traffic, no log line.
        // 2. Only a REAL change takes `endpoint_commit` and re-checks the
        //    commit generation snapshotted before this tick's device read. A
        //    mismatch means `set_peer_endpoint` committed a newer endpoint
        //    while our read was in flight, so what we observed is stale and
        //    the whole batch is dropped — the explicit writer always wins.
        //    See `PathCtx::endpoint_commit_gen`.
        let endpoint_changes: Vec<(u64, String)> = {
            let live = ctx.live_endpoints.lock().unwrap();
            to_pin_endpoint
                .into_iter()
                .filter_map(|(gid, ep)| {
                    let ep = ep.to_string();
                    (live.get(&gid) != Some(&ep)).then_some((gid, ep))
                })
                .collect()
        };
        if !endpoint_changes.is_empty() {
            let _commit = ctx.endpoint_commit.lock().await;
            if ctx.endpoint_commit_gen.load(Ordering::SeqCst) == commit_gen_at_read {
                let mut live = ctx.live_endpoints.lock().unwrap();
                for (gid, ep) in endpoint_changes {
                    eprintln!(
                        "wiremesh-gateway: peer={gid} endpoint read-through: pinning {ep} \
                         (the endpoint the device is actually using)"
                    );
                    live.insert(gid, ep);
                }
            } else {
                // A punch/relay commit landed mid-read; its endpoint is newer
                // than anything this fetch could have seen. Skip — the next
                // tick reads the post-commit device and agrees with the pin.
                eprintln!(
                    "wiremesh-gateway: endpoint read-through skipped: an endpoint commit \
                     landed during the device read"
                );
            }
        }

        // Fire this tick's due liveness probes (keepalive-invisibility fix).
        // Spawned, not awaited, so a slow send never delays the tick loop; the
        // per-peer cadence is already bounded by `last_probe`.
        for gid in to_probe {
            let ctx = ctx.clone();
            tokio::spawn(async move { poke_peer_overlay(&ctx, gid).await });
        }

        // Prompt-report trigger (relay-wedge fix round 4): any recorded
        // transition that crosses the settled boundary must reach the
        // controller broker PROMPTLY — the case-4 finding: after a relay-leg
        // death the broker's stored states stayed `relayed`/`relayed`
        // (settled-skipping the pair) until the next `SyncEvent::State`,
        // its punch budget stayed exhausted, and the two sides punched on
        // unsynchronized self-timers a port-restricted pair can never land.
        // One `notify_one` per tick at most; the sync loop coalesces +
        // debounces and sends the full snapshot (see
        // `PathCtx::path_report_notify`).
        if to_record
            .iter()
            .any(|(_, before, after)| transition_crosses_settled_boundary(*before, *after))
        {
            ctx.path_report_notify.notify_one();
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
            teardown_relay_transport(&ctx, gid, "reached Direct").await;
        }
        for gid in to_relay_died {
            // Relay-death cleanup (aether-prod-fi-01 wedge fix): drop the
            // DEAD transport, then clear the peer's relay_pointed pin so the
            // upcoming Disconnected -> Connecting StartPunch cycle's guard
            // chain (`directive_should_punch` / `punch_and_apply`'s
            // make-before-break yield) actually opens. Lock ordering: the
            // reason read and the teardown each take the tokio
            // `relay_transports` mutex alone; the std `relay_pointed` lock
            // is only taken after both guards are dropped.
            //
            // Read the death classification BEFORE the teardown removes the
            // transport from the map — it is the branch input below.
            let reason = {
                let map = ctx.relay_transports.lock().await;
                map.get(&gid).and_then(|pr| pr.transport.death_reason())
            };
            teardown_relay_transport(&ctx, gid, "relay leg died").await;
            ctx.relay_pointed.lock().unwrap().remove(&gid);
            // Branch on WHY the leg died (runner-verified against the netns
            // done-bars; classification pinned by tests/relay_death_reason.rs):
            match reason {
                // EVICTION fast-path (relay_matrix case 3): the relay
                // gracefully CLOSED the connection under us — a controller-
                // driven eviction severs every client with a real
                // CONNECTION_CLOSE. Our peer was evicted right alongside us
                // and is re-pathing to the surviving relay too, so burning a
                // direct punch window first (~12s, for a pairing that may
                // not even punch — case 3 is symmetric<->symmetric) would
                // blow the ≤30s re-path budget. Reconnect a relay
                // IMMEDIATELY, restoring the pre-RelayDied eviction timing;
                // the round-robin cursor already points past the dead relay.
                Some(RelayDeathReason::Closed) => {
                    eprintln!(
                        "wiremesh-gateway: peer={gid} relay leg gracefully closed (eviction); \
                         reconnecting a relay immediately"
                    );
                    tokio::spawn(ensure_relay_transport(ctx.clone(), gid, ds.relays.clone()));
                }
                // WEDGE semantics (relay_matrix case 4): the leg died of
                // SILENCE (QUIC idle timeout — the production shape: the
                // peer restarted, punched direct, and LEFT the relay; our
                // leg starved). NO immediate re-relay — the next Connecting
                // spell gets one clean direct-punch window; a genuinely
                // relay-needing pair re-relays one punch cycle later via the
                // Connecting-timeout MarkRelayNeeded ladder. `Other`
                // (exotic quinn errors) and `None` (no transport found —
                // e.g. already pruned) map here too, conservatively: only a
                // positively-identified eviction earns the fast-path.
                Some(RelayDeathReason::TimedOut) | Some(RelayDeathReason::Other) | None => {}
            }
        }
        // Stale-pin invariant sweep — ACT phase (round-3 reviewer MAJOR; see
        // the collect phase above for the leak path). Race trace for why
        // this cannot clear a HEALTHY install's pin:
        // `ensure_relay_transport` commits in a fixed order — it inserts the
        // (healthy, just-connected) transport into `relay_transports` FIRST,
        // and only then runs `set_peer_endpoint(.., is_relay=true)`, which
        // sets the pin. So any pin the collect phase observed implies its
        // transport was ALREADY in the map at that moment; if the collect's
        // `healthy_relay` snapshot said "no healthy transport", either the
        // transport is genuinely dead (the leak this sweep exists for) or
        // the install committed AFTER the snapshot was taken — and the
        // re-check below, against the LIVE map, sees that install's healthy
        // transport and skips. The one residual interleaving (an install's
        // insert lands after this re-check but its pin-set after our clear)
        // leaves a pin with a closed transport for at most one tick — the
        // sweep is a standing per-tick invariant enforcer, so the next tick
        // clears it. Lock ordering: the tokio `relay_transports` guard (the
        // re-check, then the teardown's own) is never held while the std
        // `relay_pointed` lock is taken.
        for gid in to_sweep_pin {
            {
                let map = ctx.relay_transports.lock().await;
                if map.get(&gid).is_some_and(|pr| pr.transport.is_healthy()) {
                    continue; // legitimate install raced the snapshot — leave it
                }
            }
            teardown_relay_transport(&ctx, gid, "stale relay pin swept").await;
            ctx.relay_pointed.lock().unwrap().remove(&gid);
            eprintln!(
                "wiremesh-gateway: peer={gid} relay pin swept (pinned, no healthy transport, \
                 not relayed) — punch guard re-opened"
            );
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
            match ctx.try_start_punch(gid, PunchOrigin::Tick) {
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

/// Apply one desired state to the data plane (tunnel peers, routes).
///
/// The WG device peers, the change-guard, and the peer-segment routes ALL
/// follow the ACTIVE tun (`active`): boot's `wg0` in steady state, and after a
/// Role-A cutover the new epoch's `wg0e<N>` — which is what lets the old epoch's
/// `wg0` be torn down afterward without this ever trying to `uapi::apply` to a
/// Device that no longer exists.
///
/// **The enforcer half is NOT here (Backlog item 1).** It used to be, and it
/// is what made this function — awaited inline by the Sync loop — park a
/// runtime thread for up to a reap grace per epoch while holding the
/// enforcer-map lock. It now goes through
/// `wiremesh_gateway::policy_apply`'s worker; every caller of this function
/// pairs it with a `policy_apply.publish(..)`. What stayed is deliberate:
/// the UAPI device apply and the route diff are fast AND must stay ordered
/// with peer events, so deferring them would trade a stall for a
/// correctness problem.
async fn apply_state(
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

/// Rewrite the `listen_port=` line in an encoded UAPI `set` string's device
/// HEADER, leaving every other byte — the private key, `replace_peers`, and
/// every peer block — byte-identical. `None` if the header carries no
/// `listen_port=` line at all.
///
/// This is how the active tun's change-guard is re-seeded after
/// [`renormalize_active_listen_port`] moves the port (port-authority fix,
/// piece 2). Deliberately a TEXTUAL rewrite of the recorded config rather than
/// a fresh `device_config_pinned` render: `applied_config` means "the last
/// config actually pushed to this device", and the port is the ONLY thing the
/// renormalization pushed. Re-rendering from the current desired state would
/// instead record config that was never applied, silently swallowing any peer
/// delta that accumulated since the last apply.
///
/// Only the header is scanned. `push_peer_block` never emits a `listen_port=`
/// line, so the restriction is belt-and-braces rather than load-bearing — but
/// it means a peer field that ever gained that prefix could not be corrupted
/// by this.
fn rewrite_listen_port(encoded: &str, port: u16) -> Option<String> {
    let split = encoded.find("public_key=").unwrap_or(encoded.len());
    let (header, peers) = encoded.split_at(split);
    let mut out = String::with_capacity(encoded.len() + 8);
    let mut replaced = false;
    for line in header.split_inclusive('\n') {
        if line.starts_with("listen_port=") {
            out.push_str(&format!("listen_port={port}\n"));
            replaced = true;
        } else {
            out.push_str(line);
        }
    }
    if !replaced {
        return None;
    }
    out.push_str(peers);
    Some(out)
}

/// Point every LIVE relay transport's downlink at `127.0.0.1:<wg_port>`.
///
/// `RelayTransport` delivers relayed inbound to the local address it last saw
/// sending — seeded at `start` from the then-current active listen port. Any
/// move of that port (a Role-A cutover, or the retire-time renormalization)
/// therefore leaves every existing transport delivering to a port boringtun no
/// longer listens on, and every relayed peer black-holes until boringtun's next
/// outbound datagram re-teaches the pump. Calling this immediately after the
/// port moves closes that window; see `RelayTransport::set_local_peer`.
///
/// Best-effort and non-destructive by construction: it mutates one address per
/// live transport and touches neither the QUIC connection nor WireGuard, so
/// there is nothing here to fail or to unwind. A gateway with no relayed peers
/// (the common case) does nothing and logs nothing.
async fn retarget_relay_transports(
    relay_transports: &Arc<Mutex<HashMap<u64, PeerRelay>>>,
    wg_port: u16,
    why: &str,
) {
    let local = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, wg_port));
    let map = relay_transports.lock().await;
    for (gid, pr) in map.iter() {
        pr.transport.set_local_peer(local).await;
        eprintln!(
            "wiremesh-gateway: peer={gid} relay={} downlink re-pointed at {local} ({why})",
            pr.relay_id
        );
    }
}

/// Put the surviving active tun back on the BASE WireGuard listen port after a
/// rotation's old epoch has been torn down — the renormalization at the heart
/// of the port-authority fix, piece 2
/// (`docs/research/port-authority-verification-the-shape-was-wrong.md`).
///
/// # The invariant this restores
///
/// A Role-A cutover moves the active key onto a rotation offset port and, until
/// now, NOTHING ever moved it back except a reboot (OD-1, see `run`'s boot
/// comment). Everything durable that addresses this gateway is base-port by
/// construction — the controller-observed candidate (the observe socket is
/// bound to `cfg.wg_listen_port` for process life), reported locals, punch
/// candidates, `live_endpoints` — so after one cutover none of them can reach
/// the active key, and after a SECOND rotation the free-list allocation drifts
/// one port further out with no side able to predict it. Both are the same
/// invariant violated twice, which is why neither is fixable alone.
///
/// # Ordering: this can only run once the old Device is GONE
///
/// The old epoch's Device holds the base port until it is dropped, so this must
/// follow `TunnelSet::tear_down`, never precede it. That is also why this hangs
/// off the retire rather than the cutover: at the cutover the base port is
/// still in use by the very key peers are still talking to.
///
/// # Failure posture
///
/// Everything is ordered so a failure leaves a COHERENT state rather than a
/// half-moved one. The UAPI write + the `TunnelSet` record go first
/// (`TunnelSet::set_listen_port` does both, or neither); only once the device
/// has really moved are `ActiveTunInfo::wg_port` and the change-guard
/// published. A failed move therefore leaves the gateway exactly where it was —
/// on the offset port, i.e. today's behaviour — instead of advertising a port
/// it is not on.
///
/// # Why the change-guard MUST be re-seeded here
///
/// `apply_state` compares the non-peer device header (`private_key` +
/// `listen_port`) of the freshly built config against `applied_config`, and a
/// mismatch forces the full `replace_peers` apply — which with this boringtun
/// is session-destructive for EVERY peer (`uapi::apply`'s caveat). Moving the
/// port without re-seeding the guard would therefore trade the port fix for a
/// torn-down data plane on the very next Sync `State` event. The guard is a
/// textual rewrite of the recorded config (see [`rewrite_listen_port`]), so it
/// keeps describing what was actually pushed; if the rewrite cannot be made,
/// the guard is CLEARED rather than left lying — `None` forces one full apply,
/// which is the same cost as the mismatch but without a stale record.
///
/// The move and the publish (and only those — see the inline lock-order note)
/// run under `PathCtx::endpoint_commit`, the lock a concurrent
/// `set_peer_endpoint` (punch or relay install) already holds across its own
/// guard read-modify-write. Without it the two interleave on `ActiveTunInfo`:
/// `set_peer_endpoint` snapshots `wg_port`, we publish, and it then writes back
/// a guard rendered at the OLD port — reintroducing the very header mismatch
/// this re-seed exists to prevent.
async fn renormalize_active_listen_port(
    tunnels: &mut TunnelSet,
    ctx: &PathCtx,
    base_wg_port: u16,
) {
    let (id, ifname, from) = {
        let a = ctx.active.lock().unwrap();
        (TunnelId::Own { epoch: a.epoch }, a.ifname.clone(), a.wg_port)
    };
    if from == base_wg_port {
        return; // never left the base port (no cutover happened) — nothing to do
    }
    // Serialize the move + publish against `set_peer_endpoint`'s guard
    // read-modify-write; see this function's doc. Scoped to exactly that, and
    // deliberately NOT held across the relay/poke work below: every existing
    // site takes the `relay_transports` mutex ALONE (never while holding
    // `endpoint_commit`), and this must not be the one call that introduces the
    // opposite lock order.
    {
        let _commit = ctx.endpoint_commit.lock().await;
        if let Err(e) = tunnels.set_listen_port(id, base_wg_port) {
            eprintln!(
                "wiremesh-gateway: CRITICAL: could not renormalize {ifname} from listen port \
                 {from} back to the base port {base_wg_port}: {e:#} — the active key stays on \
                 {from}, which NO durable candidate (controller-observed endpoint, reported \
                 locals, punch candidates) advertises, so peers that lose their live pin cannot \
                 re-address this gateway without a restart"
            );
            return;
        }
        // The device really moved: publish it. Both fields under one guard so
        // no reader can observe a port/guard pair that never existed.
        let mut a = ctx.active.lock().unwrap();
        a.wg_port = base_wg_port;
        a.applied_config = match a.applied_config.as_deref() {
            Some(cfg) => match rewrite_listen_port(cfg, base_wg_port) {
                Some(rewritten) => Some(rewritten),
                None => {
                    eprintln!(
                        "wiremesh-gateway: change-guard for {ifname} carried no listen_port line; \
                         clearing it so the next apply rebuilds rather than mismatching"
                    );
                    a.applied_peers.clear();
                    None
                }
            },
            // Nothing has been applied through the guard since the cutover, so
            // there is nothing to correct: the next apply is a full one either
            // way.
            None => None,
        };
    }
    // Relayed peers: the downlink's delivery address is the port we just left.
    retarget_relay_transports(&ctx.relay_transports, base_wg_port, "listen port renormalized")
        .await;
    eprintln!(
        "wiremesh-gateway: renormalized {ifname} from listen port {from} back to the base port \
         {base_wg_port} — the active key is addressable at its advertised port again"
    );
    // Our SOURCE port changed, so every peer's boringtun is still sending to
    // {from} until it authenticates a datagram from {base_wg_port} and roams.
    // It will (the endpoint address we send TO is untouched by the rebind — see
    // `uapi::set_listen_port`), but on nothing faster than the 25s keepalive,
    // which is uncomfortably close to the degrade threshold. Poke each peer so
    // boringtun emits now and the roam happens immediately. Best-effort and
    // spawned: this must not hold the run task.
    let peers: Vec<u64> = ctx
        .desired
        .lock()
        .unwrap()
        .as_ref()
        .map(|ds| ds.peers.iter().map(|p| p.gateway_id).collect())
        .unwrap_or_default();
    for gid in peers {
        let ctx = ctx.clone();
        tokio::spawn(async move { poke_peer_overlay(&ctx, gid).await });
    }
}

/// Service a pending old-epoch retire the rotation tick has signalled via
/// [`RotationShared::retire_ready`]. Runs in the run task, which owns the
/// non-`Send` `tunnels` (and drives the shared `enforcers`). Idempotent and a
/// no-op when nothing is pending: `retire_ready` is consumed (`take`n) and the
/// [`Rotation`] SM only emits `TearDown` from `CutOver`, returning `None` if
/// already `Idle`. Tears the old epoch's Device down (drops the boringtun
/// Device — its private key gone from any live Device — and `ip link del`s the
/// tun) and evicts its enforcer (closing the map's per-epoch entry).
///
/// Then RENORMALIZES the surviving active tun back onto the base WireGuard
/// listen port (port-authority fix, piece 2 — see
/// [`renormalize_active_listen_port`] for the invariant it restores, and for
/// why this is the only place it can happen: the base port is not free until
/// the teardown above drops the old Device).
async fn service_retire(
    tunnels: &mut TunnelSet,
    enforcers: &Arc<Mutex<HashMap<TunnelId, GatewayEnforcer>>>,
    rot: &RotationShared,
    ctx: &PathCtx,
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
    // Always OUR OWN epoch: a retire only ever tears down the epoch this
    // gateway rotated off. A Role-B overlap toward a peer that happens to
    // carry the same epoch NUMBER is a different `TunnelId` and is retired by
    // `service_role_b_collapse`, never here (T3).
    let id = TunnelId::Own { epoch };
    if let Err(e) = tunnels.tear_down(id) {
        eprintln!("wiremesh-gateway: tearing down retired epoch {epoch} Device failed: {e}");
    }
    enforcers.lock().await.remove(&id);
    // The base port is free again as of the teardown above — put the surviving
    // active key back on it (port-authority fix, piece 2). Best-effort and
    // self-contained: it publishes nothing unless the device really moved, so a
    // failure here leaves the pre-existing (offset-port) behaviour and must not
    // hold up the key scrub below, which is the security half of the retire.
    renormalize_active_listen_port(tunnels, ctx, rot.base_wg_port).await;
    // Durable retire (Backlog 3 Task 1 — the SECURITY half): tearing the
    // Device down only destroys the live in-process copy of the old private
    // key; `retire` REMOVES the epoch's store entry and `persist` rewrites
    // `epoch_keys.json` without it — the retired key is scrubbed from
    // epoch_keys.json (ONLY: the epoch-0 key also lives on in
    // identity.json/wg_private.key — see epochkeys.rs's scope-of-the-scrub
    // note), not left dormant next to an "inactive" flag. This persist also
    // re-writes the cutover's promote, so it is the durable backstop if the
    // promote-time persist failed. Failure is logged loudly but doesn't
    // unwind the teardown (the data-plane retire already happened).
    {
        let mut ek = rot.epoch_keys.lock().unwrap();
        match ek.retire(epoch) {
            Ok(()) => {
                if let Err(e) = ek.persist(&rot.state_dir) {
                    eprintln!(
                        "wiremesh-gateway: CRITICAL: persisting retire of epoch {epoch} failed: \
                         {e:#} — the retired PRIVATE key is still on disk in epoch_keys.json"
                    );
                }
            }
            Err(e) => eprintln!(
                "wiremesh-gateway: CRITICAL: retiring epoch {epoch} in the key store failed: \
                 {e:#} — its private key remains in epoch_keys.json"
            ),
        }
    }
    eprintln!(
        "wiremesh-gateway: retired epoch {epoch} — old Device torn down (key gone), enforcer \
         evicted, store entry scrubbed"
    );
}

/// Service completed Role-B collapses the rotation tick has signalled via
/// [`RotationShared::collapse_ready`]: tear each overlap Device down and
/// evict its enforcer. Runs in the run task (owner of the non-`Send`
/// `tunnels`), like [`service_retire`], but deliberately does NOT drive the
/// Role-A [`Rotation`] SM — a Role-B overlap belongs to a PEER's rotation,
/// not ours. By the time an entry lands here the tick has already proven the
/// base tun live toward the peer's new key and flipped the routes back
/// (reverse make-before-break), so tearing the overlap down cannot cut a
/// still-needed path. `tear_down` on an absent epoch is a no-op, so a stale
/// signal is harmless. No epoch-key store involvement: the overlap Device
/// ran this gateway's OWN active key, which stays active.
async fn service_role_b_collapse(
    tunnels: &mut TunnelSet,
    enforcers: &Arc<Mutex<HashMap<TunnelId, GatewayEnforcer>>>,
    rot: &RotationShared,
) {
    let ready: Vec<(u64, u32)> = std::mem::take(&mut *rot.collapse_ready.lock().unwrap());
    for (aid, epoch) in ready {
        // The overlap's id is a pure function of `(peer, its pending epoch)`,
        // so reconstructing it here cannot drift from what `maybe_start_role_b`
        // brought up — and it can never alias our OWN tun at the same epoch
        // number, which is the whole point of `TunnelId` (T3).
        let id = TunnelId::Overlap { gateway_id: aid, epoch };
        if let Err(e) = tunnels.tear_down(id) {
            eprintln!(
                "wiremesh-gateway: tearing down collapsed Role-B overlap epoch {epoch} (peer \
                 {aid}) failed: {e}"
            );
        }
        enforcers.lock().await.remove(&id);
        eprintln!(
            "wiremesh-gateway: Role B overlap for peer {aid} collapsed — epoch-{epoch} Device \
             torn down, enforcer evicted; wg0 is the routed device on the peer's new key"
        );
    }
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
    /// Boot tun ifname (`wg0`); one of OUR epochs is `<base_tun>e<N>` and a
    /// Role-B overlap toward a rotating peer is `<base_tun>o<slot>` — disjoint
    /// namespaces, see [`wiremesh_gateway::tunnelset::plan_tunnel`] (T3).
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
    /// Live relay transports (same `Arc` [`PathCtx`] holds). Needed at the
    /// Role-A cutover for exactly one reason: the cutover MOVES the active
    /// tun's listen port, and a `RelayTransport` delivers relayed inbound to
    /// the local address it last saw sending — seeded from the port the active
    /// tun had when that transport was started. Left alone, every relayed peer
    /// black-holes across the cutover until boringtun's next outbound datagram
    /// re-teaches the pump. See [`retarget_relay_transports`], called from both
    /// port-moving sites: the cutover below and the retire-time
    /// renormalization.
    relay_transports: Arc<Mutex<HashMap<u64, PeerRelay>>>,
    /// Signal from the rotation tick to the run task: the OLD epoch to retire
    /// (tear its Device down + evict its enforcer) once every peer has cut over
    /// to the new tun and the retire grace has elapsed. The run task owns the
    /// non-`Send` `tunnels`, so the tick can't tear down directly; it sets this
    /// flag and [`service_retire`] (in the run task) consumes it. `None` when
    /// nothing is pending.
    retire_ready: Arc<std::sync::Mutex<Option<u32>>>,
    /// The durable epoch-key store (Backlog 3 Task 1) — the SAME handle the
    /// sync loop's `handle_rotate` mints through. The tick's Role-A cutover
    /// drives `promote(new)` + `persist` and `service_retire` drives
    /// `retire(old)` + `persist`, so the on-disk `epoch_keys.json` tracks the
    /// data plane's lifecycle transitions and a reboot at any point selects
    /// the right key (`EpochKeys::select_boot_key`). `persist` (sync file I/O
    /// + fsync) runs under the guard — brief, and serializing writers through
    /// the lock is exactly what keeps two transitions from interleaving their
    /// tmp+rename writes.
    epoch_keys: Arc<std::sync::Mutex<EpochKeys>>,
    /// The live "version actually installed in the datapath" counter — the
    /// SAME `Arc<AtomicU64>` the policy-apply worker writes and the sync
    /// loop's steady-state report reads.
    ///
    /// Needed here because [`send_epoch_ack`] issues a REAL `Sync.Report`
    /// (a unary one, over its own short-lived channel) and the controller
    /// writes `set_applied_version(gw.id, req.applied_version)`
    /// UNCONDITIONALLY. Sending the previous hard-coded `0` therefore ZEROED
    /// this gateway's roster `applied_version` on every rotation epoch ack,
    /// and — because reports are event-driven rather than periodic — it
    /// could stay zeroed until the next unrelated event, poisoning the
    /// roster-lag alerting follow-up in
    /// `docs/research/ops-finding-sync-half-open-stream.md`.
    ///
    /// Fixed on the SENDING side rather than by making the controller
    /// conditional: the controller should be able to trust what a gateway
    /// tells it, and an ack that reports the real installed version is
    /// simply a correct (if partial) report.
    applied_version: Arc<AtomicU64>,
    /// Signal from the rotation tick to the run task: Role-B overlap Devices
    /// whose COLLAPSE completed its reverse make-before-break (base-tun
    /// session live toward the peer's new key, routes flipped back to `wg0`)
    /// and now need their `(peer gateway_id, overlap epoch)` Device torn down
    /// + enforcer evicted. Same owns-the-non-`Send`-`tunnels` split as
    /// `retire_ready`, but a separate channel: consuming it must NOT drive
    /// the Role-A `Rotation` SM (this gateway isn't the one rotating).
    collapse_ready: Arc<std::sync::Mutex<Vec<(u64, u32)>>>,
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
    /// The peers this rotation is watched against — see [`RoleAPeer`].
    peers: Vec<RoleAPeer>,
}

/// One peer of an in-flight Role-A rotation.
#[derive(Clone)]
struct RoleAPeer {
    /// Which peer this is. Carried (rather than the bare key+CIDRs the tuple
    /// form used to hold) because the cutover now has to ask
    /// [`rotation::route_owner`] whether THIS peer's CIDRs belong on the new
    /// epoch tun or on a Role-B overlap we hold toward the very same peer —
    /// which needs a `role_b` lookup, which needs the id.
    gateway_id: u64,
    /// The peer's ACTIVE-key hex AS OF THE DIRECTIVE — i.e. exactly what
    /// `handle_rotate` configured on `new_tun`. It is the watch key until the
    /// cutover (nothing re-applies to `new_tun` before then) and the fallback
    /// after it; from the cutover on, the live watch key is re-derived every
    /// tick from the roster + pins by `rotation::new_epoch_watch_keys`,
    /// because `apply_state` owns the peer set once `new_tun` is the active
    /// tun and a peer that rotates too gets rekeyed out from under this value.
    active_hex: String,
    /// The peer's segment CIDRs.
    cidrs: Vec<String>,
}

/// Role B (a PEER of this gateway is rotating): the transient overlap Device
/// this gateway stood up toward the peer's new key, and what to do once its
/// session is live.
#[derive(Clone)]
struct RoleB {
    pending_epoch: u32,
    new_tun: String,
    /// THIS gateway's own active epoch when the overlap Device was brought up —
    /// i.e. the epoch whose private key the Device runs (`maybe_start_role_b`
    /// always builds on the then-current active key). The route-ownership
    /// discriminator: see [`rotation::route_owner`]. If our own rotation later
    /// moves the active epoch past this, the peer's roster stops advertising
    /// the key this overlap runs, the peer re-applies, and the overlap's
    /// session is dead — so it can no longer own the peer's routes.
    built_at_own_epoch: u32,
    /// The rotating peer's PENDING-key hex — the peer entry we watch on
    /// `new_tun` for a live, rx-corroborated session.
    peer_pending_hex: String,
    /// The rotating peer's segment CIDRs, placed by [`place_peer_routes`] at
    /// cutover (onto `new_tun` or onto the active tun — the overlap no longer
    /// assumes it wins).
    peer_cidrs: Vec<String>,
    /// Set once the overlap's session toward `peer_pending_hex` has been
    /// observed rx-corroborated live. Deliberately SEPARATE from `done`, which
    /// also requires the epoch ack to have landed: route ownership turns on
    /// "is this overlap a proven-live path", and a failed (retried) ack must
    /// not make a live overlap look like one that never came up.
    cut_over: bool,
    /// Set once we've placed routes AND reported the live epoch ack — a
    /// completed Role-B cutover for this peer, not re-driven.
    done: bool,
    /// Set by `maybe_collapse_role_b` when the rotating peer's advertised key
    /// set collapses back to active-only (its rotation completed — the new
    /// key IS `peer_pending_hex`'s key, now active). Arms the reverse
    /// make-before-break in the rotation tick: wait for the peer's session on
    /// the ACTIVE tun (rekeyed to the new key by the unpinned apply) to become
    /// rx-corroborated live, THEN drop this overlap's route claim — which
    /// re-derives the peer's routes onto the active tun — and tear the overlap
    /// Device down. NB *active*, not *base* (F8): after a Role-A cutover the
    /// active tun is `wg0e<N>`, and `wg0` is no longer applied to at all, so
    /// watching the base tun here would wait for a session that can never
    /// appear and strand the peer's routes on a doomed overlap forever.
    /// While armed, the normal cutover arm
    /// skips this entry.
    collapse_armed: bool,
}

impl RoleB {
    /// This overlap as [`rotation::route_owner`] sees it.
    fn claim(&self) -> OverlapClaim {
        OverlapClaim { built_at_own_epoch: self.built_at_own_epoch, cut_over: self.cut_over }
    }

    /// This overlap as [`rotation::overlap_write_back`] sees it — the identity
    /// a deferred write-back must still match before it is applied.
    fn identity(&self) -> OverlapIdentity {
        OverlapIdentity { pending_epoch: self.pending_epoch, new_tun: self.new_tun.clone() }
    }
}

/// Role A: handle a `RotateDirective`. Mint+persist the new epoch key, bring
/// its Device up alongside `wg0` (the "make"), reconcile it against the
/// current peers at the offset port, submit the real pubkey to the controller,
/// and arm the observation tick to watch for the peer's live session. Idempotent
/// against a re-entrant directive (the SM only honors one from `Idle`).
async fn handle_rotate(
    tunnels: &mut TunnelSet,
    enforcers: &Arc<Mutex<HashMap<TunnelId, GatewayEnforcer>>>,
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

    // Mint + persist under one guard (no `.await` in scope) so the persisted
    // store always contains the mint, and compute the CURRENT active epoch
    // from the same snapshot — post-reboot-on-a-promoted-epoch this is the
    // promoted epoch (not 0), which anchors the port offset and, later, which
    // epoch the retire tears down.
    let (new_key, active_epoch) = {
        let mut ek = rot.epoch_keys.lock().unwrap();
        let new_key = ek.generate_next()?.clone();
        ek.persist(&rot.state_dir)?;
        let active_epoch = ek.active().map(|k| k.epoch).unwrap_or(0);
        (new_key, active_epoch)
    };
    if new_key.epoch != n {
        eprintln!(
            "wiremesh-gateway: WARNING minted epoch {} != directive epoch {n}; proceeding on the \
             directive epoch for the port/tun convention",
            new_key.epoch
        );
    }

    // Plan the new tun's ifname + listen port against everything already live
    // (T3). The NAME is unchanged — `{base}e{n}`, exactly as before, since an
    // own-epoch number is unique among our own tuns. The PORT is what moves:
    // the old `base + (n - active_epoch)` was derived from the epoch number
    // alone, and a Role-B overlap toward a peer's identically-numbered pending
    // epoch derived the very same value — guaranteed, not incidental, because
    // the controller rotates the whole fabric off one timer. The planner hands
    // back a port free of the boot tun, of any previous rotation tun, and of
    // every overlap we hold.
    let plan = plan_tunnel(
        TunnelId::Own { epoch: n },
        &rot.base_tun,
        rot.base_wg_port,
        &tunnels.plans(),
    )
    .context("planning this gateway's new epoch tun")?;
    let new_tun = plan.ifname.clone();
    let new_port = plan.listen_port;

    tunnels.bring_up(plan.id, &new_tun, &new_key.private_key_b64, new_port, TUN_MTU)?;

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
            let _ = tunnels.tear_down(plan.id);
            return Err(e).with_context(|| format!("attaching enforcer to rotation tun {new_tun}"));
        }
    };
    if let Err(e) = ke.apply_if_changed(ds) {
        let _ = tunnels.tear_down(plan.id);
        return Err(e).with_context(|| format!("applying policy to rotation tun {new_tun}"));
    }
    // Insert into the SHARED enforcer map under the SAME `TunnelId` the Device
    // is keyed by (insert is last on this path, so the fail-closed teardown
    // above never has to remove it), so every later `apply_state` reaches this
    // new tun's enforcer. Keying by `TunnelId` rather than the bare epoch is
    // load-bearing, not cosmetic: an `insert` colliding with a Role-B overlap
    // at the same epoch number would DROP the displaced enforcer and detach
    // its tc-BPF/nft program from a tun that is still carrying traffic.
    enforcers.lock().await.insert(plan.id, ke);

    let dev =
        reconcile::device_config_at_port(ds, &new_key.private_key_b64, new_port, ROTATION_KEEPALIVE);
    uapi::apply(&new_tun, &dev)?;

    let peers: Vec<RoleAPeer> = ds
        .peers
        .iter()
        .filter_map(|p| {
            let hex = pubkey_b64_to_hex(p.active_pubkey_b64.as_deref()?)?;
            Some(RoleAPeer {
                gateway_id: p.gateway_id,
                active_hex: hex,
                cidrs: p.allowed_ips.clone(),
            })
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
/// `pending` epoch alongside its `active` one) and isn't already overlapped at
/// exactly that epoch, bring up a transient overlap Device toward the peer's
/// pending key (this gateway's OWN active key on a planned free port) and arm
/// the tick to flip+ack once that session is live. No-op in steady state.
///
/// # Structure (T3): decide first, then execute per peer
///
/// The *decision* — one [`RoleBDecision`] per peer, in roster order — is made
/// by the pure [`role_b_decisions`], and this function only executes it. The
/// split is not tidiness; it is the fix for two shipped defects that a single
/// imperative loop kept producing:
///
///  - **Totality.** [`role_b_decisions`] cannot return fewer decisions than
///    there are peers, so "peer 2 is broken" can no longer mean "peers 3..N
///    were never considered".
///  - **Re-rotation.** The old `contains_key(&gid)` guard keyed on the peer id
///    alone; a peer rotating AGAIN while we still held an overlap toward its
///    previous pending epoch was skipped silently and permanently. That is now
///    [`RoleBDecision::Restart`], and this function honours it.
///
/// **This function cannot fail** — hence no `Result`. Every step that used to
/// `?`/`bail!`/`return Err` out of the loop body now logs and `continue`s to
/// the NEXT peer: `bring_up`, the two enforcer steps, the peer `uapi::apply`,
/// and the unusable-pubkey case. One unusable peer must never starve the peers
/// behind it, and the caller only logged the error anyway, so an early return
/// was pure loss.
async fn maybe_start_role_b(
    tunnels: &mut TunnelSet,
    enforcers: &Arc<Mutex<HashMap<TunnelId, GatewayEnforcer>>>,
    rot: &RotationShared,
    ds: &DesiredState,
) {
    // What we currently overlap toward, as `gateway_id -> the pending epoch
    // that overlap Device targets`. The epoch is what makes a re-rotation
    // distinguishable from the steady mid-rotation state.
    let overlapped: BTreeMap<u64, u32> = rot
        .role_b
        .lock()
        .unwrap()
        .iter()
        .map(|(gid, b)| (*gid, b.pending_epoch))
        .collect();

    for (aid, decision) in role_b_decisions(ds, &overlapped) {
        let pending_epoch = match decision {
            RoleBDecision::Skip => continue,
            RoleBDecision::Unusable { pending_epoch } => {
                // Used to be `anyhow::bail!`, which destroyed the whole loop.
                eprintln!(
                    "wiremesh-gateway: Role B — rotating peer {aid}'s pending epoch \
                     {pending_epoch} pubkey is not a valid 32-byte base64 WG key; no overlap \
                     stood up for it (other peers unaffected)"
                );
                continue;
            }
            RoleBDecision::Start { pending_epoch } => pending_epoch,
            RoleBDecision::Restart { stale_epoch, pending_epoch } => {
                // The peer has moved past the epoch we overlapped toward (it
                // re-rotated, or the entry leaked from an aborted rotation).
                // Retire the stale overlap before standing up the new one, so
                // the peer ends up with exactly one overlap Device.
                retire_stale_overlap(tunnels, enforcers, rot, aid, stale_epoch).await;
                pending_epoch
            }
        };

        // Re-find the peer the decision was made about. `role_b_decisions`
        // emits one entry per `ds.peers`, so this always resolves; the three
        // `else continue`s below are unreachable-by-construction restatements
        // of what a `Start`/`Restart` already implies, kept as guards rather
        // than `expect`s because a panic in the sync loop kills the gateway.
        let Some(peer) = ds.peers.iter().find(|p| p.gateway_id == aid) else {
            continue;
        };
        let (Some(active), Some(pending)) = (peer.active_key(), peer.pending_key()) else {
            continue;
        };
        let Some(peer_pending_hex) = pubkey_b64_to_hex(&pending.pubkey_b64) else {
            continue;
        };

        // Peer set for the overlap Device: exactly the rotating peer at its
        // pending key + offset endpoint (`pending_peer_configs`, filtered to
        // this peer's pending pubkey so a second rotating peer never lands on
        // this peer's single-purpose Device).
        let peers: Vec<_> = reconcile::pending_peer_configs(ds, ROTATION_KEEPALIVE)
            .into_iter()
            .filter(|pc| pc.public_key_b64 == pending.pubkey_b64)
            .collect();
        if peers.is_empty() {
            // Transient: the peer has no usable candidate endpoint yet. The
            // next `State` event re-decides, and until then `role_b` holds no
            // entry, so this is a genuine retry rather than a drop.
            eprintln!(
                "wiremesh-gateway: Role B — no offset endpoint could be built for rotating peer \
                 {aid} (epoch {pending_epoch}); skipping this round"
            );
            continue;
        }

        // Plan the overlap's ifname + listen port against everything already
        // live (T3). The old scheme derived both from the peer's pending epoch
        // NUMBER — `{base}e{pending}` at `base + (pending - peer active)` —
        // which is exactly the namespace and formula our OWN tuns used, so an
        // in-step fabric collided on all three axes at once and the first
        // collision aborted the loop. Overlaps now live in their own
        // `{base}o{slot}` namespace, and the planner sees the boot tun, our
        // own rotation tun and every other peer's overlap in
        // `tunnels.plans()`, so the port is free of all of them too.
        let id = TunnelId::Overlap { gateway_id: aid, epoch: pending_epoch };
        let plan = match plan_tunnel(id, &rot.base_tun, rot.base_wg_port, &tunnels.plans()) {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "wiremesh-gateway: Role B — cannot plan an overlap tun for peer {aid} epoch \
                     {pending_epoch}: {e:#}"
                );
                continue;
            }
        };
        let new_tun = plan.ifname.clone();
        let listen_port = plan.listen_port;

        // This gateway's OWN key for the overlap Device: the CURRENT ACTIVE
        // key (what the rotating peer's roster advertises for us), not
        // `identity.wg_private_key_b64` — after our own rotation (and
        // especially after a post-rotation reboot, Backlog 3 Task 1) the
        // identity key is the RETIRED epoch-0 key, and an overlap built on it
        // could never complete the peer's handshake. Pre-rotation the two are
        // identical, so steady-state behavior is unchanged.
        //
        // The EPOCH that key belongs to is read under the same guard and
        // recorded on the `RoleB` entry: it is what later tells
        // `rotation::route_owner` whether this overlap is still keyed on the
        // epoch the peer's roster advertises for us, or has been stranded by
        // our own Role-A cutover.
        let (own_priv, own_epoch) = {
            let a = rot.active.lock().unwrap();
            (a.priv_key.clone(), a.epoch)
        };
        if let Err(e) = tunnels.bring_up(id, &new_tun, &own_priv, listen_port, TUN_MTU) {
            eprintln!(
                "wiremesh-gateway: Role B — bringing up overlap Device {new_tun}:{listen_port} \
                 for peer {aid} epoch {pending_epoch} failed: {e:#}"
            );
            continue;
        }

        // SECURITY (fail-closed): attach the L4 enforcer to this overlap
        // Device with the current policy BEFORE the device is made
        // session-capable (peer apply, below). `bring_up` only brought the
        // Device up with an EMPTY peer set, so at this point the tun cannot
        // yet form a WG session toward the rotating peer — attaching the
        // enforcer here, ahead of the peer-apply, closes the
        // default-deny-bypass-on-new-tun gap with no unfiltered window. If
        // `attach`/`apply_if_changed` errors, tear the half-built tun back
        // down and move on to the next peer: the device never received peers,
        // so it never became traffic-capable — no fail-open on this path,
        // unlike attaching after the peer-apply (which would leave a
        // session-capable, unenforced tun on an attach failure).
        let mut ke = match GatewayEnforcer::attach(&new_tun) {
            Ok(ke) => ke,
            Err(e) => {
                let _ = tunnels.tear_down(id);
                eprintln!(
                    "wiremesh-gateway: Role B — attaching enforcer to overlap tun {new_tun} \
                     (peer {aid}) failed, tun torn back down: {e:#}"
                );
                continue;
            }
        };
        if let Err(e) = ke.apply_if_changed(ds) {
            let _ = tunnels.tear_down(id);
            eprintln!(
                "wiremesh-gateway: Role B — applying policy to overlap tun {new_tun} (peer \
                 {aid}) failed, tun torn back down: {e:#}"
            );
            continue;
        }
        // Insert into the SHARED enforcer map under the SAME `TunnelId` the
        // Device is keyed by, so every later `apply_state` reaches this
        // overlap tun's enforcer. No `std::sync::Mutex` guard is held across
        // this `.await`.
        //
        // SECURITY: the `TunnelId` key is what makes this insert safe. Keyed
        // by the bare pending epoch, it could displace the enforcer of OUR own
        // tun at the same epoch number — `insert` drops the old value, which
        // detaches its tc-BPF/nft program — leaving a live tun with no policy
        // hook. `TunnelId::Overlap` and `TunnelId::Own` are disjoint, so this
        // can only ever replace an entry for this very peer at this very
        // epoch, which `Restart` has already removed.
        enforcers.lock().await.insert(id, ke);

        if let Err(e) = uapi::apply(
            &new_tun,
            &DeviceConfig { private_key_b64: own_priv, listen_port, peers },
        ) {
            // The peer-apply is what makes the Device session-capable, so a
            // failure here leaves a tun that cannot carry traffic. Unwind BOTH
            // resources — the enforcer entry as well as the Device — or the
            // map would retain an attached program for a tun that no longer
            // exists and keep it out of a later slot's reach.
            let _ = tunnels.tear_down(id);
            enforcers.lock().await.remove(&id);
            eprintln!(
                "wiremesh-gateway: Role B — applying the rotating peer's config to overlap tun \
                 {new_tun} (peer {aid}) failed, tun torn back down: {e:#}"
            );
            continue;
        }

        // Pin this peer's `wg0` entry to its CURRENT (old) epoch key for the
        // overlap, so its later promote delta can't rekey `wg0` and reset the
        // still-in-use old session (make-before-break on the base tun).
        rot.wg0_pins.lock().unwrap().insert(aid, active.pubkey_b64.clone());
        rot.role_b.lock().unwrap().insert(
            aid,
            RoleB {
                pending_epoch,
                new_tun: new_tun.clone(),
                built_at_own_epoch: own_epoch,
                peer_pending_hex,
                peer_cidrs: peer.allowed_ips.clone(),
                cut_over: false,
                done: false,
                collapse_armed: false,
            },
        );
        eprintln!(
            "wiremesh-gateway: Role B overlap Device up on {new_tun}:{listen_port} toward peer \
             {aid} epoch {pending_epoch}"
        );
    }
}

/// Program ONE peer's segment CIDRs onto whichever device
/// [`rotation::route_owner`] says owns them, and report which that was.
///
/// THE single writer of a rotating peer's routes. Role A's cutover, Role B's
/// cutover, Role B's collapse and the Role-B restart all call this instead of
/// each programming the device it individually believes in — which is what let
/// whichever of them ran last win, and is the whole of the in-step defect
/// (`docs/research/in-step-rotation-cutover-arbitration.md`).
///
/// The active view and the overlap view are passed EXPLICITLY rather than read
/// off `RotationShared` here, because the Role-A cutover has to decide against
/// the epoch it is cutting over TO — which it has not published to
/// `rot.active` yet at the moment it needs the answer. Every caller therefore
/// states the state it is acting on, and the arbitration itself stays in the
/// pure function.
///
/// `routes::add_route` is `ip route replace`, so writing the device a CIDR is
/// already on is an idempotent no-op — an ownership decision that agrees with
/// the status quo costs nothing, and a decision that disagrees moves the route
/// atomically. Failures are logged per-CIDR and never abort the caller: a
/// half-placed route set is strictly better than a peer loop that stops.
fn place_peer_routes(
    aid: u64,
    cidrs: &[String],
    active_ifname: &str,
    active_epoch: u32,
    overlap: Option<(&str, OverlapClaim)>,
    site: &str,
) -> RouteOwner {
    let owner = rotation::route_owner(active_epoch, overlap.map(|(_, claim)| claim));
    let target = match (owner, overlap) {
        (RouteOwner::OverlapTun, Some((ifname, _))) => ifname,
        // `OverlapTun` without an overlap is unreachable by construction
        // (`route_owner` only returns it for a `Some` claim); fall back to the
        // active tun rather than panicking in the rotation tick.
        _ => active_ifname,
    };
    for cidr in cidrs {
        if let Err(e) = routes::add_route(cidr, target) {
            eprintln!(
                "wiremesh-gateway: {site} — placing peer {aid}'s {cidr} on {target} failed: {e}"
            );
        }
    }
    owner
}

/// Retire the overlap Device we hold toward `aid` at `stale_epoch`, because
/// the peer has moved on to a newer pending epoch ([`RoleBDecision::Restart`]).
/// Best-effort throughout: every step is independently logged and none can
/// abort the caller's peer loop.
///
/// Order matters. The peer's segment routes may already have been placed on
/// the overlap tun by a completed Role-B cutover, so the entry is dropped
/// FIRST and the routes then re-derived with no overlap claim
/// ([`place_peer_routes`]) — which lands them on the ACTIVE tun — before the
/// Device is deleted. Active, not base (F8): after a Role-A cutover the base
/// tun is no longer the tun this gateway applies peers to, so moving routes
/// there would strand them. `routes::add_route` is `ip route replace`, so this
/// is an idempotent no-op when the cutover never happened, and when it did it
/// is what stops those CIDRs from pointing at an interface that is about to
/// disappear. The `wg0` pin is dropped too: it
/// holds the base tun on a key the peer has since rotated past, and the caller
/// re-pins to the peer's CURRENT active key as soon as the replacement overlap
/// is up (and if the replacement fails, no pin at all is the correct state —
/// `wg0` then follows the roster's active key).
async fn retire_stale_overlap(
    tunnels: &mut TunnelSet,
    enforcers: &Arc<Mutex<HashMap<TunnelId, GatewayEnforcer>>>,
    rot: &RotationShared,
    aid: u64,
    stale_epoch: u32,
) {
    // Drop the claim FIRST, then re-derive: with no overlap claim left for
    // this peer `route_owner` yields the active tun, which is exactly where
    // these CIDRs must go before the stale Device disappears.
    let stale = rot.role_b.lock().unwrap().remove(&aid);
    rot.wg0_pins.lock().unwrap().remove(&aid);
    if let Some(b) = &stale {
        let (active_ifname, active_epoch) = {
            let a = rot.active.lock().unwrap();
            (a.ifname.clone(), a.epoch)
        };
        place_peer_routes(
            aid,
            &b.peer_cidrs,
            &active_ifname,
            active_epoch,
            None,
            "Role B restart",
        );
    }
    let id = TunnelId::Overlap { gateway_id: aid, epoch: stale_epoch };
    if let Err(e) = tunnels.tear_down(id) {
        eprintln!(
            "wiremesh-gateway: Role B restart — tearing down peer {aid}'s stale overlap (epoch \
             {stale_epoch}) failed: {e}"
        );
    }
    enforcers.lock().await.remove(&id);
    eprintln!(
        "wiremesh-gateway: Role B restart — peer {aid} has re-rotated past epoch {stale_epoch}; \
         stale overlap retired, standing up a fresh one"
    );
}

/// Role-B collapse trigger (the minimal reverse-make-before-break slice of
/// the ratified plan's Task 3 — see key-rotation-teardown-notes finding D):
/// when a rotating peer's ROSTER key set no longer advertises a real-keyed
/// pending epoch AND its active key is the very key this gateway overlapped
/// toward, start collapsing our overlap state. NB the timing: this fires at
/// the controller's PROMOTE of the peer's new epoch (pending -> active; the
/// roster may still carry the old key as a `"retiring"` row at that point —
/// `pending_key()` is what goes `None`), not at the controller's retire.
/// Rule-4 laggard consequence: on an ack-less grace-promote where the
/// rotating peer never actually established its new key, this still unpins
/// and rekeys `wg0` toward that new key at promote time — dropping any
/// still-working old-key `wg0` session with the peer; the peer is doomed on
/// the old key anyway once promoted roster-wide, but recovery then waits
/// until it genuinely runs the new key (e.g. re-normalizes after a reboot).
/// Sequence:
///
///  (a) HERE (sync, before the caller's `apply_state` for the same delta):
///      unpin `wg0_pins[gid]`, so the apply rebuilds `wg0`'s entry for this
///      peer with its NEW active key (`device_config_pinned` falls back to
///      `active_pubkey_b64` once no pin exists; the key change defeats both
///      the change-guard and the pure-addition incremental path, so a full
///      rebuild is guaranteed by that very apply);
///  (b) arm `collapse_armed` — the rotation tick then waits for the peer's
///      session on the ACTIVE tun to become rx-corroborated live;
///  (c) the tick drops the overlap's route claim (re-deriving the peer's
///      routes onto the active tun) and signals the run task to tear the
///      overlap Device down (`service_role_b_collapse`).
///
/// Deliberately does NOT require `b.done`: the controller's ack-less Rule-4
/// grace-promote can collapse the roster while our cutover never completed —
/// in that case the routes are already on the active tun (the re-derive's `ip
/// route replace` is then an idempotent no-op) and the collapse is exactly the
/// recovery needed. While armed, the tick's normal cutover arm skips the entry.
fn maybe_collapse_role_b(rot: &RotationShared, ds: &DesiredState) {
    let mut role_b = rot.role_b.lock().unwrap();
    for (aid, b) in role_b.iter_mut() {
        if b.collapse_armed {
            continue;
        }
        let Some(peer) = ds.peers.iter().find(|p| p.gateway_id == *aid) else {
            // Peer vanished from the roster entirely (removed, not rotated):
            // out of scope for this slice — see finding D remainders.
            continue;
        };
        if peer.pending_key().is_some() {
            continue; // still mid-rotation
        }
        let new_active_hex = peer
            .active_key()
            .and_then(|k| pubkey_b64_to_hex(&k.pubkey_b64));
        if new_active_hex.as_deref() != Some(b.peer_pending_hex.as_str()) {
            continue; // active key isn't the one we overlapped toward
        }
        rot.wg0_pins.lock().unwrap().remove(aid);
        b.collapse_armed = true;
        eprintln!(
            "wiremesh-gateway: Role B collapse armed for peer {aid} (rotation complete; roster \
             active-only on the new key) — wg0 unpinned, awaiting a live session on the ACTIVE \
             tun before tearing {} down",
            b.new_tun
        );
    }
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
    // WHY EVERY FIELD BELOW IS WHAT IT IS.
    //
    // `ReportRequest` mixes three different update semantics in one message
    // (full-REPLACE snapshots, last-writer-wins scalars, and sparse
    // append-only events), and the controller's `report` handler applies most
    // of them UNCONDITIONALLY. So a partial sender like this one — which only
    // wants to deliver an epoch ack — must reconstruct every replace/LWW
    // field or it silently DESTROYS controller-side state. Two live bugs of
    // exactly that shape were found at this single call site; each field is
    // therefore justified explicitly. See `sync.proto`'s `ReportRequest` for
    // the design finding this pattern motivated.
    //
    // - `applied_version`: DESTRUCTIVE if wrong. The controller calls
    //   `set_applied_version` unconditionally, so the `0` this used to
    //   hard-code silently reset this gateway's roster version on every
    //   rotation ack — and since reports are event-driven, not periodic, it
    //   could stay reset for a long time (poisoning the roster-lag alerting
    //   follow-up). Now the REAL installed version, read from the same
    //   `Arc<AtomicU64>` the policy-apply worker writes and the steady-state
    //   report reads (see `RotationShared::applied_version`).
    // - `local_endpoints`: DESTRUCTIVE if empty. `Db::set_local_candidates`
    //   is a full REPLACE where empty means CLEAR, and the controller calls
    //   it unconditionally — so the `vec![]` this used to pass wiped this
    //   gateway's LAN/hairpin punch candidates and published the shrunk set
    //   to every peer via `EndpointObserved`, mid-rotation, which is exactly
    //   when path disruption is least welcome. Now derived the same way the
    //   steady-state report derives it: `netif::local_wg_endpoints` over the
    //   CONFIGURED listen port. `rot.base_wg_port` IS `cfg.wg_listen_port`
    //   (see its construction), i.e. the identical value
    //   `send_paths_snapshot_report` uses, and the same one `kick_overlap`
    //   already uses from this very rotation path.
    //
    //   NOTE, deliberately NOT settled here: whether a gateway mid-Role-A
    //   rotation should advertise its locals on the base port at all, rather
    //   than on the offset port in `rot.active`, is a PRE-EXISTING open
    //   question — `send_paths_snapshot_report` has always advertised the
    //   base port through a rotation. This change makes the two report paths
    //   agree; it does not answer that question, and must not be read as
    //   having answered it.
    // - `relay_health`: SAFE empty. The controller's relay-health block is
    //   guarded by `if !req.relay_health.is_empty()`, so an empty list is a
    //   genuine no-op — the steady-state report remains the sole owner of
    //   that snapshot.
    // - `epoch_acks`: the actual payload of this call.
    // - `peer_paths: None`: SAFE, and load-bearing. `None` selects the legacy
    //   `peer_paths_snapshot=false` wire shape, and `Broker::on_report`
    //   early-returns on `!snapshot && peer_paths.is_empty()` — a true no-op.
    //   The alternative (`Some(vec![])`) would set `peer_paths_snapshot=true`
    //   and REPLACE the broker's stored path states with nothing, reopening
    //   settled pairs to re-punching mid-rotation. This unary ack carries no
    //   `ctx.paths` data, so it must never claim to be a snapshot.
    // - `session_generation`: stamped inside `sync::report` from the
    //   process-wide `OnceLock`, so this path cannot omit or mismatch it.
    sync::report(
        &mut client,
        rot.applied_version.load(Ordering::Relaxed),
        netif::local_wg_endpoints(rot.base_wg_port),
        vec![],
        vec![ack],
        None,
    )
    .await
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
    // Loop-local, paired with the above: whether the "post-cutover watch set is
    // empty" condition has already been reported for the CURRENT empty spell.
    // The tick runs five times a second, so the warning is emitted on the
    // transition into that state rather than every 200ms.
    let mut warned_empty_watch = false;
    loop {
        tokio::time::sleep(ROTATION_TICK_PERIOD).await;

        // Role A: our own new epoch's Device.
        let role_a = rot.role_a.lock().unwrap().clone();
        if let Some(a) = role_a {
            let phase = rot.rotation.lock().unwrap().phase.clone();
            // WHICH KEY to watch is a judgement over CURRENT roster + pin
            // state, not the directive-time snapshot it used to be: once we
            // have cut over, `apply_state` owns the new tun's peer set and a
            // peer that ALSO rotates has its entry rekeyed out from under a
            // snapshot watcher — which stalled the retire grace forever and so
            // never actually retired the old key. See
            // `rotation::new_epoch_watch_keys`, which derives it from exactly
            // the inputs `device_config_pinned` writes it from.
            //
            // One watch set feeds both arms. Pre-cutover the function returns
            // the snapshot verbatim, so the `any_live` cutover gate below is
            // bit-for-bit what it was; only the post-cutover retire arm sees a
            // refreshed answer.
            let watch: Vec<(u64, String)> = {
                let snapshot: Vec<(u64, String)> =
                    a.peers.iter().map(|p| (p.gateway_id, p.active_hex.clone())).collect();
                let cut_over = matches!(phase, RotationPhase::CutOver { .. });
                let ds = rot.desired.lock().unwrap();
                let pins = rot.wg0_pins.lock().unwrap();
                rotation::new_epoch_watch_keys(&snapshot, cut_over, ds.as_ref(), &pins)
                    .into_iter()
                    .filter_map(|(gid, w)| match w {
                        EpochWatch::Key(hex) => Some((gid, hex)),
                        // A peer that left the roster is not on the device and
                        // cannot need our old epoch — excluded rather than
                        // watched, so it can't hold the retire hostage.
                        EpochWatch::Gone => None,
                    })
                    .collect()
            };
            let live = read_live_peers(&a.new_tun, watch.iter().map(|(_, h)| h.clone())).await;
            let any_live =
                live.as_ref().map_or(false, |l| watch.iter().any(|(_, hex)| l.contains(hex)));
            // An EMPTY watch set is NOT "all live" (F4). `.all()` on an empty
            // iterator is vacuously true, and the watch set can now SHRINK: it
            // starts as the directive-time snapshot and every peer that has
            // since left `rot.desired` — or that the roster no longer gives a
            // usable active key for — is dropped as `EpochWatch::Gone`. Drain
            // it completely and the retire would fire after `RETIRE_GRACE`
            // having corroborated nothing at all.
            //
            // WHICH WAY TO FAIL. The two readings of an emptied watch set are
            // not distinguishable from here: either those peers genuinely left
            // the fabric (retiring is then correct AND harmless — no peer is
            // left to break), or `rot.desired` is transiently truncated and the
            // peers still hold sessions on our old key (retiring then deletes a
            // key live peers depend on, i.e. an outage that only ends when
            // those peers rehandshake on the new epoch, if they can). The
            // asymmetry decides it: a wrong retire is a data-plane outage, a
            // withheld retire is a lingering old private key plus one leaked
            // Device + enforcer. So this fails toward NOT retiring, and says so
            // loudly below — the leak is visible and recoverable (a restart
            // boots on the promoted key via `select_boot_key`), the outage is
            // neither.
            //
            // A rotation whose snapshot was empty from the start cannot reach
            // here: `any_live` over an empty watch set is false, so
            // `Overlapping` never advances to `CutOver`.
            if !watch.is_empty() {
                warned_empty_watch = false;
            }
            let all_live = !watch.is_empty()
                && live.as_ref().map_or(false, |l| watch.iter().all(|(_, hex)| l.contains(hex)));
            match phase {
                RotationPhase::Overlapping { .. } => {
                    if any_live {
                        let action = rot.rotation.lock().unwrap().on_new_epoch_session(true);
                        if let Some(RotationAction::FlipRoutes { epoch }) = action {
                            // Place each peer's CIDRs on the device
                            // `rotation::route_owner` says owns them, decided
                            // against the epoch we are cutting over TO (`epoch`
                            // / `a.new_tun`) — not against `rot.active`, which
                            // this block has not republished yet.
                            //
                            // In practice every peer lands on the new tun here:
                            // an overlap can only out-rank it by having been
                            // built on our CURRENT active epoch, and by
                            // definition every overlap we hold right now was
                            // built before this cutover, i.e. on the epoch we
                            // are rotating OFF. The lookup still runs, because
                            // that reasoning is a property of the rule, not an
                            // assumption this site is entitled to bake in — and
                            // baking exactly this kind of assumption in at three
                            // separate sites is what produced the in-step
                            // clobber.
                            for p in &a.peers {
                                let held = rot
                                    .role_b
                                    .lock()
                                    .unwrap()
                                    .get(&p.gateway_id)
                                    .map(|b| (b.new_tun.clone(), b.claim()));
                                place_peer_routes(
                                    p.gateway_id,
                                    &p.cidrs,
                                    &a.new_tun,
                                    epoch,
                                    held.as_ref().map(|(ifname, claim)| (ifname.as_str(), *claim)),
                                    "Role A cutover",
                                );
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
                                // Publishing the epoch alongside the tun is
                                // what makes every LATER route decision (Role
                                // B's cutover, its collapse, a Role-B restart)
                                // see that any overlap standing on the old
                                // epoch has been rotated out from under.
                                epoch,
                                applied_config,
                                applied_peers,
                            };
                            // Durable promote (Backlog 3 Task 1): the data
                            // plane just cut over to epoch `epoch`, so record
                            // it in the store (new epoch "active", old epoch
                            // "retiring") and persist — a reboot from here on
                            // must select the NEW key (`select_boot_key`), not
                            // resurrect the old one. Failure posture: the
                            // cutover has ALREADY happened on the data plane,
                            // so never unwind it — log loudly and continue.
                            // A failed persist here still gets a durable
                            // second chance: `service_retire`'s retire+persist
                            // (>= RETIRE_GRACE later) re-writes the whole
                            // store, in-memory promote included. A crash
                            // inside that window reboots on the old key;
                            // whether peers still honor it then depends on
                            // the CONTROLLER's roster clock (peers drop their
                            // old-key pins when the controller's promote SM
                            // retires the old epoch roster-side), NOT on our
                            // local RETIRE_GRACE — the two clocks are
                            // unrelated, so this degraded window is best-
                            // effort, not guaranteed reachable. And the
                            // backstop shares the failure domain: a
                            // persistent disk fault fails the retire persist
                            // identically, leaving no durable promote at all.
                            {
                                let mut ek = rot.epoch_keys.lock().unwrap();
                                match ek.promote(epoch) {
                                    Ok(()) => {
                                        if let Err(e) = ek.persist(&rot.state_dir) {
                                            eprintln!(
                                                "wiremesh-gateway: CRITICAL: persisting promoted \
                                                 epoch {epoch} failed: {e:#} — a reboot before the \
                                                 retire persist would resurrect the old key"
                                            );
                                        }
                                    }
                                    Err(e) => eprintln!(
                                        "wiremesh-gateway: CRITICAL: promoting epoch {epoch} in \
                                         the key store failed: {e:#} — store diverges from the \
                                         live data plane"
                                    ),
                                }
                            }
                            // The active tun's listen port just MOVED (base ->
                            // `a.new_port`). Every live relay transport is
                            // still delivering relayed inbound to the port we
                            // left, where the OLD Device — holding the OLD
                            // private key — cannot decrypt what the peer now
                            // sends. Re-teach them before anything else gets a
                            // chance to notice the silence. Pre-existing bug
                            // (every rotation has always black-holed relayed
                            // peers this way); handled here because piece 2
                            // adds a SECOND port move and must not make it more
                            // frequent while leaving it unfixed.
                            retarget_relay_transports(
                                &rot.relay_transports,
                                a.new_port,
                                "Role A cutover",
                            )
                            .await;
                            eprintln!(
                                "wiremesh-gateway: Role A cutover — peer routes re-derived against \
                                 {} (epoch {epoch})",
                                a.new_tun
                            );
                        }
                    } else {
                        // Not live yet: kick the overlap handshake (boringtun
                        // won't initiate from keepalive alone). The `ping -W1`
                        // timeout naturally rate-limits this to ~once/sec while
                        // the peer's Device isn't up yet.
                        let cidrs: Vec<String> =
                            a.peers.iter().flat_map(|p| p.cidrs.clone()).collect();
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
                        if watch.is_empty() && !warned_empty_watch {
                            warned_empty_watch = true;
                            eprintln!(
                                "wiremesh-gateway: ROTATION WEDGED — every peer of the rotation \
                                 to {} has left the watch set (roster no longer lists them, or \
                                 lists no usable active key). The old epoch {} will NOT be \
                                 retired while that holds, because an empty watch set \
                                 corroborates nothing. THIS IS NOT ONLY A LEAK: the rotation \
                                 stays in CutOver, and `Rotation::on_directive` is honored only \
                                 from Idle, so THIS GATEWAY WILL SILENTLY IGNORE EVERY FURTHER \
                                 RotateDirective UNTIL THE PROCESS RESTARTS. `service_retire` \
                                 also never runs, so the old private key is never scrubbed from \
                                 epoch_keys.json — the security half of the rotation does not \
                                 happen. Restart the gateway to clear this",
                                a.new_tun, a.old_epoch
                            );
                        }
                    }
                }
                RotationPhase::Idle => {}
            }
        }

        // Role B: transient overlap Device(s) toward rotating peer(s). A
        // collapse-armed entry is excluded — its rotation already completed
        // roster-side, so driving the (now-moot) cutover/ack arm against it
        // would fight the collapse below.
        //
        // TWO different races run against this snapshot, and only one of them
        // is benign.
        //
        //  - **Arming, benign.** The snapshot is taken before the loop's
        //    awaits while arming happens concurrently in the sync loop, so a
        //    single tick can still drive the cutover arm for an entry armed
        //    just after the snapshot (sending a moot ack). Harmless: the ack
        //    is idempotent controller-side, and the routes are no longer this
        //    arm's to assert — they go wherever `rotation::route_owner` says,
        //    and the collapse arm re-derives them once the active tun is
        //    proven live.
        //
        //  - **Replacement, NOT benign.** `RoleBDecision::Restart` REMOVES a
        //    peer's entry and inserts a new one toward a newer pending epoch,
        //    so the entry behind a given peer id can be a different overlap
        //    entirely by the time `read_live_peers`/`send_epoch_ack` return.
        //    Writing `cut_over`/`done` back by peer id alone would then mark a
        //    never-observed overlap as a proven-live route target and filter
        //    the live rotation out of this very set forever. Every write-back
        //    below therefore states the identity it was computed against and
        //    goes through `rotation::overlap_write_back`; a mismatch leaves
        //    the new entry strictly alone for the next tick to drive from
        //    scratch.
        let pending_b: Vec<(u64, RoleB)> = rot
            .role_b
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, b)| !b.done && !b.collapse_armed)
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        for (aid, b) in pending_b {
            // The overlap this pass is ABOUT. Everything below is only ever
            // written back to an entry that still matches it.
            let taken = b.identity();
            let live =
                read_live_peers(&b.new_tun, std::iter::once(b.peer_pending_hex.clone())).await;
            if !live.map_or(false, |l| l.contains(&b.peer_pending_hex)) {
                // Not live yet: kick the overlap handshake toward the rotating
                // peer (same rationale as Role A above).
                kick_overlap(b.new_tun.clone(), b.peer_cidrs.clone(), rot.base_wg_port).await;
                continue;
            }
            // The overlap is PROVEN LIVE. That is a fact about the overlap, not
            // a licence to claim the peer's routes: this used to flip them onto
            // `b.new_tun` unconditionally, which is precisely what clobbered a
            // Role-A cutover that had already moved the same peer onto our new
            // epoch tun (in-step rotation, where BOTH cutovers run on the same
            // gateway toward the same peer). Record the liveness on the entry,
            // then let `rotation::route_owner` arbitrate.
            //
            // Qualified by the overlap's IDENTITY, not just the peer id: the
            // liveness just proved is a fact about `taken`'s Device. If the
            // peer re-rotated during the read, the entry under the lock is a
            // DIFFERENT, never-observed overlap, and stamping `cut_over` on it
            // would hand `route_owner` a claim of a proven-live path that does
            // not exist — placing the peer's CIDRs on a Device with no session,
            // i.e. make-before-break violated. The whole pass is abandoned in
            // that case, routes and ack included: the ack would report a
            // pending epoch the peer has already moved past.
            let verdict = {
                let mut role_b = rot.role_b.lock().unwrap();
                let current = role_b.get(&aid).map(RoleB::identity);
                let verdict = rotation::overlap_write_back(&taken, current.as_ref());
                if verdict == WriteBack::Apply {
                    if let Some(e) = role_b.get_mut(&aid) {
                        e.cut_over = true;
                    }
                }
                verdict
            };
            if verdict != WriteBack::Apply {
                eprintln!(
                    "wiremesh-gateway: Role B cutover — peer {aid}'s overlap {} (epoch {}) was \
                     {verdict:?} while its liveness was being read; leaving the current entry \
                     alone for the next tick to drive",
                    taken.new_tun, taken.pending_epoch
                );
                continue;
            }
            let (active_ifname, active_epoch) = {
                let a = rot.active.lock().unwrap();
                (a.ifname.clone(), a.epoch)
            };
            let claim =
                OverlapClaim { built_at_own_epoch: b.built_at_own_epoch, cut_over: true };
            let owner = place_peer_routes(
                aid,
                &b.peer_cidrs,
                &active_ifname,
                active_epoch,
                Some((b.new_tun.as_str(), claim)),
                "Role B cutover",
            );
            // The ack is NOT conditional on winning the route: it reports that
            // the peer's new epoch has a live session with us, which the
            // overlap just proved either way, and it is what advances the
            // controller's promote SM.
            let ack = EpochAck { peer_gateway_id: aid, epoch: b.pending_epoch, live: true };
            match send_epoch_ack(&rot, ack).await {
                Ok(()) => {
                    // `send_epoch_ack` opens a fresh mTLS channel, so this is
                    // the LONGEST await in the pass and the likeliest point
                    // for the entry to be replaced under us. Same identity
                    // gate: `done` permanently filters an entry out of
                    // `pending_b`, so setting it on a replacement would strand
                    // the peer's live rotation with no cutover and no ack.
                    // The ack itself is already sent and is correct for the
                    // epoch it names — only the bookkeeping is withheld.
                    let verdict = {
                        let mut role_b = rot.role_b.lock().unwrap();
                        let current = role_b.get(&aid).map(RoleB::identity);
                        let verdict = rotation::overlap_write_back(&taken, current.as_ref());
                        if verdict == WriteBack::Apply {
                            if let Some(e) = role_b.get_mut(&aid) {
                                e.done = true;
                            }
                        }
                        verdict
                    };
                    if verdict != WriteBack::Apply {
                        eprintln!(
                            "wiremesh-gateway: Role B cutover — peer {aid}'s overlap {} (epoch \
                             {}) was {verdict:?} while its epoch ack was in flight; the ack stands \
                             but the entry is left alone for the next tick to drive",
                            taken.new_tun, taken.pending_epoch
                        );
                        continue;
                    }
                    // NB: Role B does NOT flip the shared `active` descriptor.
                    // This gateway isn't rotating its OWN key — its `wg0` device
                    // config stays pinned (old-epoch peer key) and must not be
                    // rebuilt on the overlap tun, and its `wg0` is never torn
                    // down.
                    let target = match owner {
                        RouteOwner::OverlapTun => b.new_tun.as_str(),
                        RouteOwner::ActiveTun => active_ifname.as_str(),
                    };
                    eprintln!(
                        "wiremesh-gateway: Role B cutover — peer {aid} epoch {} live on {}; routes \
                         on {target} ({owner:?}), epoch ack sent",
                        b.pending_epoch, b.new_tun
                    );
                }
                Err(e) => eprintln!(
                    "wiremesh-gateway: Role B epoch ack for peer {aid} failed (will retry): {e}"
                ),
            }
        }

        // Role B COLLAPSE (reverse make-before-break — Backlog 3 Task 1 slice
        // of T3): for each collapse-armed entry, watch the ACTIVE tun for a
        // live, rx-corroborated session toward the peer's NEW active key
        // (== `peer_pending_hex` — the pending key we overlapped toward is
        // the one the roster promoted). Ordering guarantee: the overlap
        // Device `wg0o<slot>` is NEVER torn down — and its route claim never
        // dropped — before the active tun is proven live, mirroring (in
        // reverse) the Role-A cutover's make-before-break. Until then the
        // overlap keeps carrying whatever traffic still flows (steady-state
        // completion), or simply idles (the peer rebooted onto the base
        // port). No handshake kick here: routes may still point at the overlap
        // tun, so a segment-IP ping can't egress the active tun; its
        // persistent keepalive + the punch/path machinery drive that
        // handshake instead.
        //
        // ACTIVE, not BASE (F8). This arm used to watch and flip `rot.base_tun`
        // outright. That is only the same device while THIS gateway isn't
        // rotating: once our own Role-A cutover has moved `active` to
        // `wg0e<N>`, `wg0` is no longer applied to at all, so it never receives
        // the peer's new key, the liveness read can never come true, and the
        // collapse hangs forever with the peer's routes stranded on an overlap
        // that is about to be doomed by our own key change. Read inside the
        // loop, so a cutover landing mid-pass is picked up on the next entry
        // rather than acted on stale.
        let armed_b: Vec<(u64, RoleB)> = rot
            .role_b
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, b)| b.collapse_armed)
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        for (aid, b) in armed_b {
            let taken = b.identity();
            let (active_ifname, active_epoch) = {
                let a = rot.active.lock().unwrap();
                (a.ifname.clone(), a.epoch)
            };
            let live =
                read_live_peers(&active_ifname, std::iter::once(b.peer_pending_hex.clone())).await;
            if !live.map_or(false, |l| l.contains(&b.peer_pending_hex)) {
                continue; // active tun not live yet — keep the overlap intact
            }
            // The active tun is live on the peer's new key. Drop the overlap's
            // route claim FIRST (so a future rotation of this peer can start
            // fresh), then re-derive: with no claim left `route_owner` yields
            // the active tun, and `add_route`'s `ip route replace` moves each
            // CIDR off `wg0o<slot>` atomically — or is a no-op if the claim
            // never won the route in the first place (the in-step case, where
            // our own cutover already owned it).
            //
            // The remove is CONDITIONAL on the entry still being the overlap
            // this pass read liveness for. Unqualified, a peer that re-rotated
            // during the read would have its BRAND-NEW entry removed here while
            // the teardown signalled below names the OLD epoch's Device: the new
            // overlap Device and its enforcer would stay live with no `role_b`
            // entry left to ever collapse them, and every later
            // `maybe_start_role_b` would return `Start` for a `(peer, epoch)`
            // whose `bring_up` bails "already has a tunnel up" forever. Both the
            // route re-derive and the teardown signal are gated on it too —
            // re-deriving with no claim would yank the peer's CIDRs off the
            // replacement overlap that legitimately holds them.
            let verdict = {
                let mut role_b = rot.role_b.lock().unwrap();
                let current = role_b.get(&aid).map(RoleB::identity);
                let verdict = rotation::overlap_write_back(&taken, current.as_ref());
                if verdict == WriteBack::Apply {
                    role_b.remove(&aid);
                }
                verdict
            };
            if verdict != WriteBack::Apply {
                eprintln!(
                    "wiremesh-gateway: Role B collapse — peer {aid}'s overlap {} (epoch {}) was \
                     {verdict:?} while the active tun's liveness was being read; nothing removed \
                     or torn down, leaving the current entry for the next tick to drive",
                    taken.new_tun, taken.pending_epoch
                );
                continue;
            }
            place_peer_routes(
                aid,
                &b.peer_cidrs,
                &active_ifname,
                active_epoch,
                None,
                "Role B collapse",
            );
            // Only now signal the run task to tear the Device down + evict its
            // enforcer (`service_role_b_collapse`; the tick can't touch the
            // non-`Send` `tunnels`). `wg0_pins` was already unpinned at the
            // trigger; the live-endpoint pin is left to the path SM.
            rot.collapse_ready.lock().unwrap().push((aid, b.pending_epoch));
            eprintln!(
                "wiremesh-gateway: Role B collapse — peer {aid} live on {active_ifname} with its \
                 new key; routes re-derived onto it, overlap {} teardown signalled",
                b.new_tun
            );
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
                epoch: 0,
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
            punching: Arc::new(std::sync::Mutex::new(HashMap::new())),
            relay_transports: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            relay_connecting: Arc::new(std::sync::Mutex::new(HashSet::new())),
            relay_next_idx: Arc::new(std::sync::Mutex::new(HashMap::new())),
            relay_pointed: Arc::new(std::sync::Mutex::new(HashMap::new())),
            endpoint_commit: Arc::new(tokio::sync::Mutex::new(())),
            endpoint_commit_gen: Arc::new(AtomicU64::new(0)),
            wg0_pins: Arc::new(std::sync::Mutex::new(HashMap::new())),
            path_report_notify: Arc::new(tokio::sync::Notify::new()),
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
        let guard = ctx
            .try_start_punch(7, PunchOrigin::Tick)
            .expect("first claim for peer 7 succeeds");
        assert!(
            ctx.try_start_punch(7, PunchOrigin::Directive).is_none(),
            "second concurrent claim for the same peer must be rejected"
        );
        assert!(
            ctx.try_start_punch(8, PunchOrigin::Tick).is_some(),
            "a different peer is unaffected by peer 7's guard"
        );
        drop(guard);
        assert!(
            ctx.try_start_punch(7, PunchOrigin::Directive).is_some(),
            "slot released once the guard drops"
        );
    }
}
