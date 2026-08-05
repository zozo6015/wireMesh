//! `wiremesh-controller`: the single-tenant control plane binary's library
//! crate. See [`db`] for the embedded SQLite store (schema, migrations,
//! CIDR-overlap invariant, audit log), [`db_async`] for the blocking-pool
//! async wrapper around it, and [`services`] for the tonic service impls.
//!
//! [`serve`] is the library entrypoint other binaries/tests boot the
//! controller through: `src/main.rs` is a thin wrapper around it, and
//! `wiremesh-testkit::TestController` boots it in-process for integration
//! tests.

pub mod apply;
pub mod auth;
pub mod cli;
pub mod broker;
pub mod db;
pub mod db_async;
pub mod observe;
pub mod projection;
pub mod rotation;
pub mod routes;
pub mod services;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use anyhow::{Context, Result};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::{broadcast, oneshot};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::{TcpListenerStream, UnixListenerStream};
use tonic::transport::{Certificate, Identity, Server, ServerTlsConfig};

use auth::BearerAuthLayer;
use db::Db;
use db_async::DbHandle;
use services::admin::AdminSvc;
use services::enrollment::EnrollmentSvc;
use services::sync::SyncSvc;
use wiremesh_proto::v1::admin_server::AdminServer;
use wiremesh_proto::v1::enrollment_server::EnrollmentServer;
use wiremesh_proto::v1::sync_server::SyncServer;
use wiremesh_trust::{CertificateIssuer, EmbeddedTrust};

/// Lifetime of the controller's own TLS server-identity certificate (issued
/// fresh at every `serve()` call — see [`serve`]'s body). Long enough that a
/// long-running controller process doesn't need in-process cert rotation
/// for cycle-2; a later task can persist/rotate this if the process is
/// expected to run for years uninterrupted.
const SERVER_IDENTITY_TTL: StdDuration = StdDuration::from_secs(365 * 24 * 3600);

/// Server-side HTTP/2 PING cadence on the SYNC listener — the controller's
/// half of the Sync keepalive mirror
/// (`docs/research/ops-finding-sync-half-open-stream.md`). The client-side
/// keepalives (gateway PR #28, relay mirror) let CLIENTS detect a dead link;
/// without a server-side PING the controller keeps holding a half-open
/// client's Watch stream — and the roster/broker state hanging off it —
/// until a Report that never comes. The VALUE is the canonical
/// `wiremesh_enroll::SYNC_KEEPALIVE_INTERVAL` — the exact same constant the
/// gateway/relay clients build their channels from (the ops doc recommends
/// no distinct server-side figure), so client and server figures can't
/// silently drift apart: long-lived server-streaming Watch responses are
/// exactly the idle-on-the-wire case the PING must cover from BOTH ends.
/// `pub` because tonic's built server exposes no inspectable surface, so
/// `tests/sync_server_keepalive.rs` pins construction via these consts.
pub const SYNC_HTTP2_KEEPALIVE_INTERVAL: StdDuration = wiremesh_enroll::SYNC_KEEPALIVE_INTERVAL;

/// How long an unanswered server-side keepalive PING may go unacknowledged
/// before the controller declares the connection dead and reaps its streams.
/// Same shared value as the clients' — see
/// [`SYNC_HTTP2_KEEPALIVE_INTERVAL`].
pub const SYNC_HTTP2_KEEPALIVE_TIMEOUT: StdDuration = wiremesh_enroll::SYNC_KEEPALIVE_TIMEOUT;

/// Capacity of the [`projection::ChangeEvent`] broadcast channel shared by
/// every service that can mutate the projection (currently just
/// `EnrollmentSvc` — see [`services::enrollment`]) and every live
/// `Sync.Watch` connection (`SyncSvc`, [`services::sync`]). A lagging
/// subscriber that falls more than this many events behind gets a
/// `Lagged` error on its next read rather than blocking the sender —
/// `SyncSvc::watch` handles that by logging and relying on the gateway's
/// next reconnect to fully resync (see that module's doc comment). 64 is
/// generous for cycle-2's mutation rate (gateway enrollment is an
/// operator-driven, low-frequency event, not a hot path).
const CHANGE_EVENT_CHANNEL_CAPACITY: usize = 64;

/// How long [`RunningController::shutdown`] waits for a gracefully-signaled
/// server task to finish before force-`abort()`ing it. Short enough that a
/// restart with an open `Sync.Watch` stream completes promptly (the whole
/// point — see `shutdown`'s doc comment), long enough that a task genuinely
/// draining a brief in-flight unary request finishes gracefully first.
const SHUTDOWN_GRACE: StdDuration = StdDuration::from_millis(500);

/// Everything [`serve`] needs to boot a controller instance.
///
/// `tcp_port = 0` asks the OS to pick a free port (used by tests and by the
/// `wiremesh-testkit` harness so parallel test runs never collide).
pub struct Config {
    /// Directory holding the SQLite DB, the embedded CA, and secrets. Created
    /// if absent.
    pub data_dir: PathBuf,
    /// TCP port for the Enrollment service (server-TLS only — no client
    /// cert required, since an unenrolled gateway has none yet). `0` =
    /// OS-assigned.
    pub tcp_port: u16,
    /// TCP port for the Sync service. Deliberately a SEPARATE listener from
    /// `tcp_port`, with its own `ServerTlsConfig` that REQUIRES a client
    /// certificate chaining to the embedded CA (mTLS) — see [`serve`]'s doc
    /// comment for why Enrollment and Sync can't safely share one
    /// TLS-config'd listener. `0` = OS-assigned.
    pub sync_tcp_port: u16,
    /// Unix-domain-socket path the Admin service is served on. Its parent
    /// directory is created (if absent) and forced to mode `0700`.
    pub socket_path: PathBuf,
    /// (Task 13) TCP port for a SECOND Admin listener, behind
    /// [`auth::BearerAuthLayer`] — plaintext gRPC (no TLS; the bearer token
    /// is this listener's security boundary, matching cycle-2 scope: a real
    /// deployment would put this behind a TLS-terminating reverse proxy or
    /// grow its own `ServerTlsConfig` later). The UDS listener above stays
    /// implicit-admin and unauthenticated-by-token; this is what
    /// `fabricctl --token`/`TestController::admin_client_with_bearer` dial.
    /// `0` = OS-assigned.
    pub admin_tcp_port: u16,
    /// (Task 15) UDP port for the observation endpoint (`crate::observe`) —
    /// deliberately UDP, not TCP: NATs map TCP/UDP independently, so a
    /// TCP-observed address would be useless for the UDP data plane this
    /// endpoint exists to help a gateway discover its own reachable address
    /// for. `0` = OS-assigned, same convention as every other port in this
    /// struct.
    pub observe_udp_port: u16,
    /// (Cycle 4a Task 12) IP address every TLS/mTLS/authenticated TCP/UDP
    /// listener above binds to — the Enrollment TCP, Sync TCP, and
    /// observation UDP sockets. Defaults to `127.0.0.1` via
    /// [`Config::default_bind_ip`] for every existing test/dev deployment
    /// (loopback-only, unchanged behavior); the mesh-milestone netns test
    /// overrides it to a routable underlay address so a `wiremesh-gateway`
    /// process in a SEPARATE network namespace can actually reach the
    /// controller. NOTE: this does NOT change the TLS server certificate's
    /// SAN — that stays `127.0.0.1` (the gateway's mTLS dial validates the
    /// cert via SNI `domain_name("127.0.0.1")`, not the dialed IP), so
    /// binding a routable IP here is purely a socket-bind change, not a
    /// certificate change.
    ///
    /// Deliberately EXCLUDED: the Admin TCP listener (`admin_tcp_port`) is
    /// plaintext gRPC with a bearer token as its only security boundary, so
    /// it always binds loopback-only regardless of this field — see the
    /// bind call at the Admin TCP listener's construction site for why
    /// exposing it on a routable interface would make the bearer token
    /// interceptable/replayable on the wire.
    pub bind_ip: std::net::Ipv4Addr,
    /// (Key-rotation Task 4) How often the rotation-initiation background
    /// task fires: on each tick, every `active` gateway whose key set is
    /// single-`active`-only (not already mid-rotation — see
    /// [`services::sync::initiate_due_rotations`]) gets a fresh `rotate_key`
    /// call with no operator action at all. `Some(30 days)`
    /// ([`Config::default_rotation_interval`]) for every real deployment;
    /// tests shrink this to sub-second values via
    /// `wiremesh_testkit::TestController::start_with_rotation_intervals` so
    /// the timer's behavior can be observed without an actual 30-day wait.
    /// `serve()` consumes `tokio::time::interval`'s immediate first tick
    /// before looping (see that call site's comment), so the first real
    /// initiation lands after one full `rotation_interval`, not immediately
    /// at boot.
    ///
    /// `None` DISABLES automatic initiation: [`serve`] spawns no
    /// rotation-initiation task at all (not a very-long interval — there is
    /// no timer). Set from `WIREMESH_ROTATION_INTERVAL=off` via
    /// [`rotation_interval_from_env`]/[`parse_rotation_interval`]. This is the
    /// operator escape hatch for the known-broken automatic-rotation path, and
    /// it is deliberately narrow — it turns off the SCHEDULE only:
    ///
    ///   * the decision sweep ([`Config::rotation_sweep_interval`] /
    ///     [`services::sync::sweep_rotations`]) keeps running, so a rotation
    ///     already in flight still promotes/retires/aborts and a crash-orphaned
    ///     `retiring` row is still recovered. Stranding a half-finished
    ///     rotation would be worse than either rotating or not;
    ///   * `Admin.RotateKey` still works, so an operator can still replace a
    ///     key they believe is compromised, on demand.
    pub rotation_interval: Option<std::time::Duration>,
    /// (Key-rotation Task 4) How often the decision-sweep background task
    /// fires: on each tick, it drives the Task-3 ack-driven promote/retire/
    /// abort decision for every gateway with an in-flight rotation (rebuilding
    /// a lazily-lost `RotationTracker` for a DB `pending` row that has none —
    /// crash recovery), and retires any `retiring` row left ORPHANED by a
    /// crash inside the promote→retire grace window (no in-memory tracker —
    /// see [`services::sync::sweep_rotations`]). Defaults to 5 seconds
    /// ([`Config::default_rotation_sweep_interval`]); shrunk by tests the
    /// same way as `rotation_interval`.
    pub rotation_sweep_interval: std::time::Duration,
    /// Directory the CA re-mint guard probes for a pre-existing WireMesh CA
    /// before it is allowed to mint one into `data_dir` (see
    /// [`wiremesh_trust::EmbeddedTrust::open_with_legacy_dir`] and
    /// [`serve`]).
    ///
    /// `None` — the only value any production deployment should use — means
    /// [`wiremesh_trust::LEGACY_SHARED_DATA_DIR`] (`/var/lib/wiremesh`).
    /// Deliberately NOT wired to an environment variable in `main.rs`: an
    /// operator-settable override would be a one-line bypass of the guard,
    /// and the guard's entire job is to stop a misconfiguration from
    /// rotating the fabric's trust anchor.
    ///
    /// It exists so the guard is TESTABLE. It keys on an absolute production
    /// path, so a controller booted into a tempdir on a machine that happens
    /// to have `/var/lib/wiremesh/ca.key` — a real controller host, or a
    /// developer's own box — refuses to start and fails the suite for a
    /// reason that has nothing to do with the code under test. Every test
    /// that boots [`serve`] should point this at a directory it owns.
    pub legacy_data_dir: Option<PathBuf>,
}

impl Config {
    /// The default bind IP (`127.0.0.1`) — loopback-only, the historical
    /// behavior every caller except the mesh-milestone test wants.
    pub fn default_bind_ip() -> std::net::Ipv4Addr {
        std::net::Ipv4Addr::LOCALHOST
    }

    /// The default rotation-initiation interval: 30 days. See
    /// [`Config::rotation_interval`]'s doc comment.
    pub fn default_rotation_interval() -> std::time::Duration {
        std::time::Duration::from_secs(30 * 24 * 60 * 60)
    }

    /// The default decision-sweep interval: 5 seconds. See
    /// [`Config::rotation_sweep_interval`]'s doc comment.
    pub fn default_rotation_sweep_interval() -> std::time::Duration {
        std::time::Duration::from_secs(5)
    }
}

/// The environment variable `main.rs` reads the rotation-initiation interval
/// from — see [`rotation_interval_from_env`].
pub const ROTATION_INTERVAL_ENV: &str = "WIREMESH_ROTATION_INTERVAL";

/// The one spelling that disables automatic rotation (matched
/// case-insensitively). Named here so the parser and every error message it
/// emits can't drift from each other: a rejected value's only useful hint is
/// the exact word that does what the operator meant.
const ROTATION_DISABLED_LITERAL: &str = "off";

/// Parses an operator-supplied rotation-initiation interval into
/// [`Config::rotation_interval`].
///
/// Accepted forms — nothing else, ever:
///
///   * `<integer><s|m|h|d>` (e.g. `30d`, `12h`, `900s`) → `Ok(Some(duration))`,
///     automatic rotation enabled at exactly that interval;
///   * `off`, in any casing → `Ok(None)`, automatic rotation DISABLED.
///
/// Surrounding whitespace is trimmed (env files and Kubernetes manifests pick
/// up stray spaces and newlines trivially, and a ` off ` that silently fell
/// back to the 30-day timer would reinstate exactly the scheduled fabric-wide
/// outage the operator just tried to switch off). Interior whitespace is not.
///
/// Everything else is an `Err` the caller is expected to turn into a non-zero
/// exit, rather than a fallback to some default:
///
///   * a ZERO interval (`0s`, `0d`, …) — a zero-period ticker would hot-loop
///     [`services::sync::initiate_due_rotations`], rotating every gateway's key
///     as fast as the DB allows. It is also never silently reinterpreted as
///     "disabled": the operator asked for something impossible and is told the
///     word (`off`) that does what they meant;
///   * an UPPERCASE unit suffix (`30D`, `15M`) — owner decision: `M` reads as
///     "months" to many operators, and accepting it buys nothing;
///   * an implausibly LARGE interval — anything above
///     [`MAX_ROTATION_INTERVAL_SECS`] (`3650d`) is a timer that would never
///     fire, i.e. a silent second spelling of "disabled" that bypasses the
///     `off` banner (see that constant). Bounded uniformly across all four
///     units, since `s` alone can express it without overflowing. Nothing
///     wraps or panics on the way there: `30d`-style inputs are multiplied up
///     into seconds with a SATURATING multiply, so an oversized count lands
///     above the cap and is rejected by it, with the cap's own message
///     (`rotation_interval_too_large`) rather than a weaker one that happens
///     to name no bound. A count too large for `u64` to hold at all is the
///     same rejection;
///   * anything else (missing/unknown suffix, empty, negative, fractional,
///     non-numeric, `off`-adjacent-but-not-`off`).
pub fn parse_rotation_interval(s: &str) -> Result<Option<std::time::Duration>> {
    let raw = s.trim();

    if raw.eq_ignore_ascii_case(ROTATION_DISABLED_LITERAL) {
        return Ok(None);
    }

    // Split the trailing unit character off by BYTE INDEX from `char_indices`
    // (never `len() - 1`), so a multi-byte trailing character can't panic on a
    // non-char-boundary slice.
    let (digits, unit) = raw
        .char_indices()
        .next_back()
        .map(|(i, c)| (&raw[..i], c))
        .ok_or_else(|| invalid_rotation_interval(s, "it is empty"))?;

    // Is the part before the suffix a well-formed count? Computed up front
    // because the uppercase-unit message below is only TRUE when casing is the
    // one and only problem: `30D` is a miscased unit, but `abcD` and a bare `D`
    // are not — telling their author to "write `d`, not `D`" would send them
    // back for a second controller restart with a suggestion (`d`, `abcd`) that
    // is itself invalid.
    let digits_ok = !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit());

    // An uppercase spelling of a real unit is rejected outright rather than
    // folded to lowercase (owner decision: `M` reads as "months" to plenty of
    // operators, and there is no upside to guessing) — but it gets its own
    // message, since "not a unit suffix" would be a lie for `30D`. Inputs whose
    // count is ALSO broken fall through to the ordinary unknown-suffix/
    // bad-number rejections below.
    if digits_ok && matches!(unit, 'S' | 'M' | 'H' | 'D') {
        return Err(invalid_rotation_interval(
            s,
            &format!(
                "unit suffixes are lowercase — write `{}`, not `{unit}`",
                unit.to_ascii_lowercase()
            ),
        ));
    }

    let unit_secs: u64 = match unit {
        's' => 1,
        'm' => 60,
        'h' => 60 * 60,
        'd' => 24 * 60 * 60,
        _ => {
            return Err(invalid_rotation_interval(
                s,
                &format!("`{unit}` is not one of the unit suffixes s|m|h|d"),
            ))
        }
    };

    if !digits_ok {
        return Err(invalid_rotation_interval(
            s,
            "the part before the unit suffix must be a non-negative whole number",
        ));
    }

    // `digits_ok` already guarantees a non-empty run of ASCII digits, so the
    // ONLY way this parse fails is a literal too large for `u64` — which is the
    // same operator mistake as tripping the cap below, and gets the same
    // message. A bare "the number is too large" names no bound and never
    // mentions `off`, so its author can only guess downwards, one controller
    // restart per guess.
    let count: u64 = digits.parse().map_err(|_| rotation_interval_too_large(s))?;
    // Saturating, not checked: `unit_secs >= 1`, so an overflow here is
    // unambiguously ABOVE the cap, and clamping to `u64::MAX` lets it fall
    // through to the cap check and pick up the cap's full explanation instead
    // of short-circuiting to a weaker one. Whether the multiply happened to
    // overflow is an implementation detail of the unit the operator chose
    // (`18446744073709551615s` never overflows; the same count with `d` does) —
    // it must not decide how much help they get. Zero cannot saturate, so the
    // zero check below still sees a true zero.
    let secs = count.saturating_mul(unit_secs);

    if secs == 0 {
        return Err(invalid_rotation_interval(
            s,
            "a zero interval would rotate every gateway's key in a hot loop; to turn \
             automatic rotation OFF, set it to `off`",
        ));
    }

    if secs > MAX_ROTATION_INTERVAL_SECS {
        return Err(rotation_interval_too_large(s));
    }

    Ok(Some(std::time::Duration::from_secs(secs)))
}

/// The single "that interval is too big" rejection, shared by EVERY route that
/// reaches it: over the [`MAX_ROTATION_INTERVAL_SECS`] cap, a multiply-up into
/// seconds that saturated, and a count literal too large for `u64`. They are
/// one operator mistake with one fix, so they get one message — the bound they
/// have to come under, and the `off` spelling if what they actually meant was
/// "disabled". Which of the three an input trips is an accident of the unit it
/// used, and the operator's only feedback channel is this string (no metrics
/// surface, one controller restart per retry), so the help must not vary.
fn rotation_interval_too_large(raw: &str) -> anyhow::Error {
    invalid_rotation_interval(
        raw,
        &format!(
            "an interval longer than {MAX_ROTATION_INTERVAL_DISPLAY} is a timer that would \
             never fire, which disables automatic rotation WITHOUT the boot warning that \
             says so; to turn automatic rotation OFF, set it to `off`"
        ),
    )
}

/// The largest accepted rotation interval: 10 years. Anything above it is a
/// timer that will never fire in the life of a controller process — i.e. a
/// SECOND, silent way to disable automatic rotation, reachable without the
/// `off` spelling and therefore without [`warn_automatic_rotation_disabled`]'s
/// boot banner. Since that banner is the only runtime signal this binary has
/// (the controller exposes no metrics endpoint), a silent-disable route defeats
/// the whole safety mechanism, so oversized values are rejected and pointed at
/// `off`. `18446744073709551615s` was the concrete case: unit `s` means the
/// overflow check above can never trip, and tokio's `Interval` saturates to
/// `Instant::far_future()` rather than panicking, so it "worked" — silently.
const MAX_ROTATION_INTERVAL_SECS: u64 = 3650 * 24 * 60 * 60;

/// How [`MAX_ROTATION_INTERVAL_SECS`] is spelled to operators — the same
/// `<integer><unit>` form they would have typed.
const MAX_ROTATION_INTERVAL_DISPLAY: &str = "3650d (10 years)";

/// Builds the one operator-facing rejection message shape used by every
/// [`parse_rotation_interval`] error: what was rejected, why, and — always —
/// the full set of things that would have been accepted, `off` included. A
/// bare "invalid value" would leave an operator with no way to discover the
/// escape hatch.
fn invalid_rotation_interval(raw: &str, why: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "invalid rotation interval {raw:?}: {why}. Expected `<integer><s|m|h|d>` \
         (e.g. `30d`, `12h`, `900s`), or `{ROTATION_DISABLED_LITERAL}` to disable \
         automatic key rotation"
    )
}

/// Resolves [`Config::rotation_interval`] from the environment, using the
/// caller-supplied `lookup` (`main.rs` passes `|k| std::env::var(k)`; the test
/// suite passes a closure, since `main.rs` itself is unreachable from an
/// integration test).
///
/// `lookup` mirrors [`std::env::var`]'s signature ON PURPOSE, rather than the
/// lossy `.ok()` form: `std::env::var` returns `Err(VarError::NotUnicode(..))`
/// for a PRESENT variable whose bytes are not UTF-8, and collapsing that into
/// `None` would make it indistinguishable from ABSENT — i.e. it would arm the
/// 30-day timer, with no banner and no error, for an operator who believes
/// they wrote `off`. Keeping the distinction in the signature also keeps it
/// testable without touching the real process environment.
///
/// ABSENT (`Err(VarError::NotPresent)`) →
/// `Ok(Some(Config::default_rotation_interval()))`, the unchanged 30-day
/// behaviour. NOT UTF-8 → `Err`. PRESENT → whatever [`parse_rotation_interval`]
/// makes of it, INCLUDING an error: a present-but-malformed value is a startup
/// error, not a silent fallback — the same precedent (and the same reasoning)
/// as `main.rs`'s `port_env`. An operator who mistyped `30dd` must find out at
/// boot rather than discover a 30-day timer still running months later, and
/// one who mistyped `of` must not be left believing rotation is off when it is
/// not. (Deliberately NOT the warn-and-fall-back treatment `WIREMESH_BIND_IP`
/// gets: a wrong bind IP fails loudly the moment nothing can connect, whereas
/// a wrong rotation interval is invisible until it fires.)
pub fn rotation_interval_from_env(
    lookup: impl FnOnce(&str) -> std::result::Result<String, std::env::VarError>,
) -> Result<Option<std::time::Duration>> {
    match lookup(ROTATION_INTERVAL_ENV) {
        Err(std::env::VarError::NotPresent) => Ok(Some(Config::default_rotation_interval())),
        Err(std::env::VarError::NotUnicode(_)) => Err(anyhow::anyhow!(
            "{ROTATION_INTERVAL_ENV} is set, but its value is not valid UTF-8. It is being \
             treated as a startup error rather than as unset, because falling back to the \
             {}-day default here would silently arm the automatic key-rotation timer for an \
             operator who believes they disabled it. Set {ROTATION_INTERVAL_ENV} to \
             `<integer><s|m|h|d>` (e.g. `30d`, `12h`, `900s`), or to \
             `{ROTATION_DISABLED_LITERAL}` to disable automatic key rotation",
            Config::default_rotation_interval().as_secs() / (24 * 60 * 60),
        )),
        Ok(raw) => parse_rotation_interval(&raw)
            .with_context(|| format!("reading {ROTATION_INTERVAL_ENV}")),
    }
}

/// The boot-time banner [`serve`] prints when `rotation_interval: None` —
/// automatic key rotation is off, and that is a standing operational risk an
/// operator must not be able to forget they took on. Printed to stderr because
/// that is this binary's only diagnostic surface: the controller exposes no
/// metrics/Prometheus endpoint to also publish it on (unlike the gateway),
/// and inventing one for a single gauge is not in scope for this knob.
fn warn_automatic_rotation_disabled() {
    eprintln!(
        "wiremesh-controller: ############################################################\n\
         wiremesh-controller: ##  WARNING: AUTOMATIC KEY ROTATION IS OFF                ##\n\
         wiremesh-controller: ############################################################\n\
         wiremesh-controller: {ROTATION_INTERVAL_ENV}={ROTATION_DISABLED_LITERAL} — no \
         rotation-initiation timer is running, so NO gateway's WireGuard key will be \
         rotated on a schedule, for as long as this controller runs. Keys will not be \
         rotated until automatic rotation is re-enabled (set {ROTATION_INTERVAL_ENV} to an \
         interval, e.g. 30d, and restart the controller).\n\
         wiremesh-controller: Still working: rotations already in flight complete normally \
         (the decision sweep keeps running), and manual rotation via Admin.RotateKey \
         (fabricctl) is unaffected."
    );
}

/// A live, in-process controller instance. Dropping it stops both servers
/// (best effort — see the `Drop` impl) so tests don't leak listeners/tasks
/// across cases.
pub struct RunningController {
    tcp_addr: std::net::SocketAddr,
    sync_tcp_addr: std::net::SocketAddr,
    admin_tcp_addr: std::net::SocketAddr,
    socket_path: PathBuf,
    data_dir: PathBuf,
    /// PEM trust bundle of the embedded CA — exposed so a TLS client (e.g.
    /// `wiremesh-testkit::TestController::enrollment_client`) can trust the
    /// server-TLS identity presented on `tcp_addr` without needing its own
    /// filesystem access to the controller's data dir. The same bundle is
    /// also what a Sync client must present a client cert chaining to.
    ca_bundle_pem: String,
    observe_addr: std::net::SocketAddr,
    admin_shutdown_tx: Option<oneshot::Sender<()>>,
    admin_join: Option<JoinHandle<()>>,
    admin_tcp_shutdown_tx: Option<oneshot::Sender<()>>,
    admin_tcp_join: Option<JoinHandle<()>>,
    enroll_shutdown_tx: Option<oneshot::Sender<()>>,
    enroll_join: Option<JoinHandle<()>>,
    sync_shutdown_tx: Option<oneshot::Sender<()>>,
    sync_join: Option<JoinHandle<()>>,
    observe_shutdown_tx: Option<oneshot::Sender<()>>,
    observe_join: Option<JoinHandle<()>>,
    /// (Cycle-4b Task 5) The broker's background trigger loop (candidate-change
    /// + periodic-retry punch triggers — see [`broker::Broker::spawn`]), torn
    /// down the same bounded-join-then-abort way as every other server task.
    broker_shutdown_tx: Option<oneshot::Sender<()>>,
    broker_join: Option<JoinHandle<()>>,
    /// (Key-rotation Task 4) The rotation-initiation timer's background task
    /// — see [`Config::rotation_interval`] / [`services::sync::initiate_due_rotations`].
    /// Torn down the same bounded-join-then-abort way as every other server
    /// task. BOTH are `None` when `Config::rotation_interval` is `None`: that
    /// task is then never spawned at all, and shutdown simply has nothing to
    /// signal or join here.
    rotation_timer_shutdown_tx: Option<oneshot::Sender<()>>,
    rotation_timer_join: Option<JoinHandle<()>>,
    /// (Key-rotation Task 4) The decision-sweep's background task — see
    /// [`Config::rotation_sweep_interval`] / [`services::sync::sweep_rotations`].
    rotation_sweep_shutdown_tx: Option<oneshot::Sender<()>>,
    rotation_sweep_join: Option<JoinHandle<()>>,
}

impl RunningController {
    /// The bound TCP address (host+port the OS assigned, if `tcp_port` was 0)
    /// the Enrollment service (server-TLS) listens on.
    pub fn tcp_addr(&self) -> std::net::SocketAddr {
        self.tcp_addr
    }

    /// The bound TCP address (host+port the OS assigned, if `sync_tcp_port`
    /// was 0) the Sync service (mTLS: client cert required) listens on —
    /// deliberately a different listener/port than `tcp_addr` (see [`serve`]).
    pub fn sync_tcp_addr(&self) -> std::net::SocketAddr {
        self.sync_tcp_addr
    }

    /// The Unix-domain-socket path the Admin service listens on.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// (Task 13) The bound TCP address the Admin service's SECOND,
    /// bearer-auth-gated listener listens on — see [`Config::admin_tcp_port`]
    /// and `crate::auth`. A distinct address from `tcp_addr()`/
    /// `sync_tcp_addr()` (Enrollment/Sync's listeners).
    pub fn admin_tcp_addr(&self) -> std::net::SocketAddr {
        self.admin_tcp_addr
    }

    /// (Task 15) The bound UDP address the observation endpoint
    /// (`crate::observe`) listens on — see [`Config::observe_udp_port`].
    pub fn observe_addr(&self) -> std::net::SocketAddr {
        self.observe_addr
    }

    /// The data directory this instance was opened against (DB + CA +
    /// secrets all live under here).
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// PEM trust bundle (one or more root certs) of the embedded CA that
    /// signed this instance's TLS server identity on `tcp_addr`/
    /// `sync_tcp_addr` — a TLS client dialing the Enrollment port trusts the
    /// server by pinning this bundle as its CA root, and a Sync client must
    /// additionally present a client certificate chaining to this same
    /// bundle (it's also the Sync listener's `client_ca_root`).
    pub fn ca_bundle_pem(&self) -> &str {
        &self.ca_bundle_pem
    }

    /// Signals all servers to stop and waits (bounded) for their tasks to
    /// finish, force-aborting any that don't wind down promptly.
    ///
    /// tonic's `serve_with_incoming_shutdown` does a GRACEFUL shutdown: after
    /// the signal fires it waits for every in-flight request to complete
    /// before its `serve` future resolves. That's the right default, but a
    /// `Sync.Watch` connection is a server-streaming RPC that stays in-flight
    /// for as long as the CLIENT holds the stream open — an effectively
    /// infinite request. If a caller (e.g. `TestController::restart`, or a
    /// real operator restarting a controller with gateways still connected)
    /// shuts down while a `Watch` stream is open, a purely graceful
    /// `join.await` would block FOREVER waiting for that stream to end on its
    /// own. So after signaling, each server task is awaited only up to
    /// [`SHUTDOWN_GRACE`]; on timeout it's `abort()`ed, which force-closes the
    /// listener (and thus the lingering stream) so shutdown always completes
    /// in bounded time. The clean case — no open long-lived streams (e.g.
    /// `fail_static.rs`, which drops its stream first) — still finishes
    /// gracefully well within the grace window and is never aborted.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.admin_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.admin_tcp_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.enroll_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.sync_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.observe_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.broker_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.rotation_timer_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.rotation_sweep_shutdown_tx.take() {
            let _ = tx.send(());
        }
        join_bounded(self.admin_join.take()).await;
        join_bounded(self.admin_tcp_join.take()).await;
        join_bounded(self.enroll_join.take()).await;
        join_bounded(self.sync_join.take()).await;
        join_bounded(self.observe_join.take()).await;
        join_bounded(self.broker_join.take()).await;
        join_bounded(self.rotation_timer_join.take()).await;
        join_bounded(self.rotation_sweep_join.take()).await;
    }
}

/// Awaits a server task's `JoinHandle` for at most [`SHUTDOWN_GRACE`], then
/// `abort()`s it if it hasn't finished — see [`RunningController::shutdown`]
/// for why an unbounded await can hang on an open `Sync.Watch` stream.
async fn join_bounded(join: Option<JoinHandle<()>>) {
    let Some(mut join) = join else {
        return;
    };
    // `&mut JoinHandle` is itself a `Future` (JoinHandle: Future + Unpin), so
    // a timeout that elapses leaves the handle intact to `abort()`.
    match tokio::time::timeout(SHUTDOWN_GRACE, &mut join).await {
        Ok(_) => {}
        Err(_) => {
            join.abort();
            // Reap the now-cancelled task so its resources are released
            // before we return (the abort makes this resolve promptly).
            let _ = join.await;
        }
    }
}

impl Drop for RunningController {
    fn drop(&mut self) {
        // Best-effort: if `shutdown()` was never called explicitly, at least
        // signal every server to stop so their tasks don't outlive this
        // handle. We can't `.await` the join handles here (Drop is sync), so
        // we don't try to wait for them — but a graceful shutdown signal
        // alone isn't enough: a `Sync.Watch` server-streaming call stays
        // in-flight for as long as its CLIENT holds the stream open (see
        // `shutdown`'s doc comment), so a signal-only Drop could leave that
        // task running indefinitely after this handle is gone. `abort()` is
        // synchronous and non-blocking (unlike `join_bounded`'s `.await`),
        // so it's safe to call directly here: it forcibly cancels the task
        // (force-closing its listener) regardless of whether the graceful
        // signal above was heeded in time.
        if let Some(tx) = self.admin_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.admin_join.take() {
            join.abort();
        }
        if let Some(tx) = self.admin_tcp_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.admin_tcp_join.take() {
            join.abort();
        }
        if let Some(tx) = self.enroll_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.enroll_join.take() {
            join.abort();
        }
        if let Some(tx) = self.sync_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.sync_join.take() {
            join.abort();
        }
        if let Some(tx) = self.observe_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.observe_join.take() {
            join.abort();
        }
        if let Some(tx) = self.broker_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.broker_join.take() {
            join.abort();
        }
        if let Some(tx) = self.rotation_timer_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.rotation_timer_join.take() {
            join.abort();
        }
        if let Some(tx) = self.rotation_sweep_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.rotation_sweep_join.take() {
            join.abort();
        }
    }
}

/// Boots the controller: opens the SQLite DB and embedded CA under
/// `config.data_dir`, binds the Admin service on `config.socket_path` (a Unix
/// socket, directory forced to `0700`), serves Enrollment on a TCP listener
/// at `config.tcp_port` with server-side TLS only, and serves Sync on a
/// SEPARATE TCP listener at `config.sync_tcp_port` with mTLS — the embedded
/// CA issues the controller its own server identity at startup for both
/// listeners (see [`SERVER_IDENTITY_TTL`]), and Sync's `ServerTlsConfig`
/// additionally sets `client_ca_root` to the same CA's bundle with
/// `client_auth_optional` left at its default `false`, so tonic/rustls
/// refuse the TLS handshake itself for any Sync connection that doesn't
/// present a client certificate chaining to it.
///
/// Enrollment and Sync are two listeners, not one, because they need
/// opposite TLS postures: an unenrolled gateway calling `Enrollment.Enroll`
/// has no client certificate yet (that's the whole point of enrollment), so
/// that listener must accept connections without one, while `Sync.Watch`
/// must reject connections without one (mTLS is how a Sync caller's gateway
/// identity is established — see `services::sync`). tonic's
/// `ServerTlsConfig` is one config per listener with no per-RPC override, so
/// getting both postures right means two listeners.
///
/// Returns once all three services are actually listening.
pub async fn serve(config: Config) -> Result<RunningController> {
    std::fs::create_dir_all(&config.data_dir)
        .with_context(|| format!("creating data dir {}", config.data_dir.display()))?;

    // Trust FIRST, deliberately: `EmbeddedTrust::open` carries the guard that
    // refuses to mint a replacement CA when this data dir has none but the
    // legacy one does (see `wiremesh_trust::load_or_create_ca`), and a guard
    // is only worth having if it runs before anything else writes here.
    // `Db::open` runs migrations, so opening it first left a complete, empty
    // schema in the wrong directory on every refused boot — which is exactly
    // the residue the packaging looks at to decide whether a directory is
    // already in use, so one mis-start used to permanently disable the
    // postinstall's data-dir pin.
    //
    // `open_with_legacy_dir`, not `open`: `open` hardcodes the absolute
    // production path, which would make every test that boots a controller
    // into a tempdir depend on whether the HOST running the suite has a
    // `/var/lib/wiremesh/ca.key` (see `Config::legacy_data_dir`).
    let legacy_data_dir = config
        .legacy_data_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from(wiremesh_trust::LEGACY_SHARED_DATA_DIR));
    let trust = EmbeddedTrust::open_with_legacy_dir(&config.data_dir, &legacy_data_dir)
        .context("opening embedded CA/trust")?;

    let db_path = config.data_dir.join("controller.db");
    let db = Db::open(&db_path).with_context(|| format!("opening db at {}", db_path.display()))?;
    let db_handle = DbHandle::new(db);

    let ca_fingerprint = ca_root_fingerprint_hex(&trust).await?;
    let ca_bundle_pem = trust.trust_bundle().await.context("reading CA trust bundle")?;

    // The controller's own TLS server identity for the Enrollment/Sync TCP
    // port. `127.0.0.1` covers the loopback address every test/dev
    // deployment dials; a real deployment binding a routable address would
    // need its hostname/IP added here too (out of cycle-2 scope).
    let (server_cert_pem, server_key_pem) = trust
        .issue_server_identity(
            "wiremesh-controller",
            vec!["127.0.0.1".to_string()],
            SERVER_IDENTITY_TTL,
        )
        .context("issuing controller TLS server identity")?;
    let tls_identity = Identity::from_pem(server_cert_pem, server_key_pem);

    // `Arc<dyn CertificateIssuer>` so `EnrollmentSvc` can hold/share it
    // without the concrete `EmbeddedTrust` type leaking into `services::*`.
    let trust: Arc<dyn CertificateIssuer> = Arc::new(trust);

    let tcp_listener = TcpListener::bind((config.bind_ip, config.tcp_port))
        .await
        .context("binding controller TCP listener")?;
    let tcp_addr = tcp_listener.local_addr().context("reading bound TCP addr")?;
    let tcp_stream = TcpListenerStream::new(tcp_listener);

    let sync_tcp_listener = TcpListener::bind((config.bind_ip, config.sync_tcp_port))
        .await
        .context("binding controller Sync TCP listener")?;
    let sync_tcp_addr = sync_tcp_listener
        .local_addr()
        .context("reading bound Sync TCP addr")?;
    let sync_tcp_stream = TcpListenerStream::new(sync_tcp_listener);

    // (Task 15) The observation endpoint's UDP socket — bound here (UDP, not
    // one of the TCP/UDS listeners above) since NATs map TCP/UDP
    // independently; see `Config::observe_udp_port`'s doc comment and
    // `crate::observe`'s module doc comment for the full scheme.
    let observe_socket = tokio::net::UdpSocket::bind((config.bind_ip, config.observe_udp_port))
        .await
        .context("binding controller observation UDP socket")?;
    let observe_addr = observe_socket
        .local_addr()
        .context("reading bound observation UDP addr")?;

    bind_uds_dir(&config.socket_path, &config.data_dir)?;
    if config.socket_path.exists() {
        std::fs::remove_file(&config.socket_path).with_context(|| {
            format!("removing stale socket at {}", config.socket_path.display())
        })?;
    }
    let uds = UnixListener::bind(&config.socket_path)
        .with_context(|| format!("binding unix socket at {}", config.socket_path.display()))?;
    // Belt-and-braces: restrict the socket FILE itself to owner-only,
    // regardless of whether `bind_uds_dir` was able to tighten its parent
    // directory (see that function's doc comment for why it deliberately
    // does NOT chmod a directory this process doesn't own). Every
    // filesystem this process can bind a socket into, it can also chmod the
    // socket it just created.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&config.socket_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting 0600 on {}", config.socket_path.display()))?;
    }
    let uds_stream = UnixListenerStream::new(uds);

    // Shared fan-out channel for Task 8's Sync delta stream: every
    // projection-affecting mutation site (`EnrollmentSvc`, and — Task 11 —
    // `AdminSvc::rotate_key`) publishes here; every `SyncSvc::watch`
    // connection subscribes its own receiver. See `projection::ChangeEvent`'s
    // doc comment. Constructed before `AdminSvc`/`EnrollmentSvc` so both can
    // hold a clone of the sender.
    let (change_tx, _) =
        broadcast::channel::<projection::ChangeEvent>(CHANGE_EVENT_CHANNEL_CAPACITY);

    // (Task 15) The observation endpoint's receive loop — spawned like every
    // other server task below, with its own shutdown signal so
    // `RunningController::shutdown`/`Drop` can tear it down the same
    // bounded-join-then-abort way as the TCP/UDS listeners.
    let (observe_shutdown_tx, observe_shutdown_rx) = oneshot::channel::<()>();
    let observe_join = observe::spawn(
        observe_socket,
        db_handle.clone(),
        change_tx.clone(),
        observe_shutdown_rx,
    );

    let admin_svc = AdminSvc::new(
        db_handle.clone(),
        ca_fingerprint,
        tcp_addr.to_string(),
        change_tx.clone(),
    );

    let (admin_shutdown_tx, admin_shutdown_rx) = oneshot::channel::<()>();
    let admin_server = Server::builder()
        .add_service(AdminServer::new(admin_svc.clone()))
        .serve_with_incoming_shutdown(uds_stream, async {
            let _ = admin_shutdown_rx.await;
        });

    let admin_join = tokio::spawn(async move {
        if let Err(e) = admin_server.await {
            eprintln!("wiremesh-controller: admin server error: {e}");
        }
    });

    // (Task 13) A SECOND Admin listener, on TCP, behind `BearerAuthLayer` —
    // see `Config::admin_tcp_port`'s doc comment for the UDS-vs-TCP auth
    // posture split. `.layer(..)` (applied before `.add_service(..)`) wraps
    // the WHOLE `Routes` service the auth module's doc comment explains is
    // necessary for method-path-based classification. Plaintext gRPC (no
    // TLS) — the bearer token is this listener's security boundary in
    // cycle-2.
    //
    // Bound to loopback UNCONDITIONALLY — NOT `config.bind_ip`. The bearer
    // token is this listener's only security boundary; exposing it on a
    // routable interface (as `bind_ip` does for the mesh-milestone netns
    // test) would make the token interceptable/replayable on the wire. The
    // Sync (mTLS), Enrollment (server-TLS), and observe (authenticated MAC)
    // listeners are fine to expose via `bind_ip`; this one is not. See
    // `Config::bind_ip`'s doc comment.
    let admin_tcp_listener =
        TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, config.admin_tcp_port))
            .await
            .context("binding Admin TCP listener")?;
    let admin_tcp_addr = admin_tcp_listener
        .local_addr()
        .context("reading bound Admin TCP addr")?;
    let admin_tcp_stream = TcpListenerStream::new(admin_tcp_listener);

    let (admin_tcp_shutdown_tx, admin_tcp_shutdown_rx) = oneshot::channel::<()>();
    let admin_tcp_server = Server::builder()
        .layer(BearerAuthLayer::new(db_handle.clone()))
        .add_service(AdminServer::new(admin_svc.clone()))
        .serve_with_incoming_shutdown(admin_tcp_stream, async {
            let _ = admin_tcp_shutdown_rx.await;
        });

    let admin_tcp_join = tokio::spawn(async move {
        if let Err(e) = admin_tcp_server.await {
            eprintln!("wiremesh-controller: admin TCP server error: {e}");
        }
    });

    let enrollment_svc = EnrollmentSvc::new(db_handle.clone(), trust, change_tx.clone());
    let enroll_tls_config = ServerTlsConfig::new().identity(tls_identity.clone());

    let (enroll_shutdown_tx, enroll_shutdown_rx) = oneshot::channel::<()>();
    let enroll_server = Server::builder()
        .tls_config(enroll_tls_config)
        .context("configuring Enrollment server TLS")?
        .add_service(EnrollmentServer::new(enrollment_svc))
        .serve_with_incoming_shutdown(tcp_stream, async {
            let _ = enroll_shutdown_rx.await;
        });

    let enroll_join = tokio::spawn(async move {
        if let Err(e) = enroll_server.await {
            eprintln!("wiremesh-controller: enrollment server error: {e}");
        }
    });

    // (Cycle-4b Task 5) The broker + its shared connection registry. Built
    // BEFORE `SyncSvc` (which registers each Watch connection into the same
    // registry clone) and given a `ChangeEvent` subscriber of its own so its
    // background loop re-punches a pair when a candidate changes; the periodic
    // retry sweep lives in the same spawned task. `change_tx.subscribe()` here
    // (before `change_tx` is moved into `SyncSvc` below) hands the broker its
    // own receiver.
    let punch_registry = broker::new_registry();
    let broker = broker::Broker::new(db_handle.clone(), punch_registry.clone());
    let (broker_shutdown_tx, broker_shutdown_rx) = oneshot::channel::<()>();
    let broker_join = broker
        .clone()
        .spawn(change_tx.subscribe(), broker_shutdown_rx);

    // (Key-rotation Task 4) `db_handle`/`change_tx`/`broker` are each cloned
    // here (rather than moved, as before this task) because the
    // rotation-initiation timer and decision-sweep tasks spawned below also
    // need their own handles to the same DB/broadcast-channel/broker.
    let sync_svc = SyncSvc::new(db_handle.clone(), change_tx.clone(), broker.clone());
    // The SAME `rotations` map `SyncSvc` drives ack-triggered promotions
    // against — cloning the `Arc` here (rather than each side building its
    // own) is what lets the sweep task rebuild/observe the exact in-flight
    // trackers `Sync.Report`/`Sync.SubmitEpochKey` create, and vice versa.
    let rotations = sync_svc.rotations_handle();

    // (Key-rotation Task 4) The rotation-initiation timer: fires every
    // `config.rotation_interval` (default 30 days; tests shrink this via
    // `TestController::start_with_rotation_intervals`) and initiates a fresh
    // rotation for every `active` gateway not already mid-rotation. The
    // immediate first tick `tokio::time::interval` fires is deliberately
    // consumed BEFORE the loop starts (mirrors `broker::Broker::spawn`'s
    // identical comment) — without this, a controller boot would
    // immediately rotate every gateway's key rather than waiting a full
    // interval, which is both surprising and (for the 30-day default)
    // irrelevant, but for a shrunk test interval would make "one interval
    // elapsed" tests unable to distinguish "fired at t=0" from "fired after
    // one real interval."
    //
    // `rotation_interval: None` = DISABLED, and it is disabled by NOT SPAWNING
    // THIS TASK AT ALL — deliberately not by substituting a very long interval,
    // which would still be a live timer that eventually fires (and which no
    // in-process test could tell apart from "fell back to the 30-day default").
    // There is no `initiate_due_rotations` call site anywhere else, so with the
    // `None` arm taken nothing in the process can initiate a rotation on its
    // own. The decision sweep below is a SEPARATE task and is spawned
    // unconditionally — see `Config::rotation_interval`'s doc comment for why
    // stranding an in-flight rotation would be worse than either rotating or
    // not.
    let (rotation_timer_shutdown_tx, rotation_timer_join) = match config.rotation_interval {
        Some(rotation_interval) => {
            let (tx, mut rotation_timer_shutdown_rx) = oneshot::channel::<()>();
            let rotation_timer_db = db_handle.clone();
            let rotation_timer_change_tx = change_tx.clone();
            let join = tokio::spawn(async move {
                let mut ticker = tokio::time::interval(rotation_interval);
                ticker.tick().await;
                loop {
                    tokio::select! {
                        _ = &mut rotation_timer_shutdown_rx => break,
                        _ = ticker.tick() => {
                            services::sync::initiate_due_rotations(&rotation_timer_db, &rotation_timer_change_tx)
                                .await;
                        }
                    }
                }
            });
            (Some(tx), Some(join))
        }
        None => {
            warn_automatic_rotation_disabled();
            (None, None)
        }
    };

    // (Key-rotation Task 4) The decision sweep: fires every
    // `config.rotation_sweep_interval` (default 5s) and drives the Task-3
    // ack-driven promote/retire/abort decision for every in-flight rotation
    // — including rebuilding a lazily-lost tracker for a crash-surviving
    // `pending` row, and retiring a `retiring` row orphaned by a crash inside
    // the promote→retire grace window (no in-memory tracker left to drive
    // it via `decide`). Shares the SAME `rotations` Arc as `sync_svc` above.
    let (rotation_sweep_shutdown_tx, mut rotation_sweep_shutdown_rx) = oneshot::channel::<()>();
    let rotation_sweep_db = db_handle.clone();
    let rotation_sweep_change_tx = change_tx.clone();
    let rotation_sweep_broker = broker.clone();
    let rotation_sweep_rotations = rotations.clone();
    let rotation_sweep_interval = config.rotation_sweep_interval;
    let rotation_sweep_join = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(rotation_sweep_interval);
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = &mut rotation_sweep_shutdown_rx => break,
                _ = ticker.tick() => {
                    services::sync::sweep_rotations(
                        &rotation_sweep_db,
                        &rotation_sweep_change_tx,
                        &rotation_sweep_broker,
                        &rotation_sweep_rotations,
                    )
                    .await;
                }
            }
        }
    });

    // `client_auth_optional` defaults to `false` — i.e. REQUIRED — so this
    // is exactly the mTLS posture Sync needs: the Sync listener rejects any
    // TLS handshake that doesn't present a client cert chaining to
    // `client_ca_root`. Same embedded CA/server identity as Enrollment;
    // only the client-cert requirement differs.
    let sync_tls_config = ServerTlsConfig::new()
        .identity(tls_identity)
        .client_ca_root(Certificate::from_pem(&ca_bundle_pem));

    let (sync_shutdown_tx, sync_shutdown_rx) = oneshot::channel::<()>();
    // Server-side keepalive on the SYNC listener ONLY (see
    // [`SYNC_HTTP2_KEEPALIVE_INTERVAL`]): Sync is the one surface with
    // long-lived, idle-on-the-wire Watch streams to clients across
    // NATs/middleboxes. The Admin listeners (UDS + loopback-only TCP) and
    // the Enrollment listener carry short unary RPCs — nothing there can go
    // silently half-open the way a Watch stream can, so they keep tonic's
    // defaults.
    let sync_server = Server::builder()
        .http2_keepalive_interval(Some(SYNC_HTTP2_KEEPALIVE_INTERVAL))
        .http2_keepalive_timeout(Some(SYNC_HTTP2_KEEPALIVE_TIMEOUT))
        .tls_config(sync_tls_config)
        .context("configuring Sync server mTLS")?
        .add_service(SyncServer::new(sync_svc))
        .serve_with_incoming_shutdown(sync_tcp_stream, async {
            let _ = sync_shutdown_rx.await;
        });

    let sync_join = tokio::spawn(async move {
        if let Err(e) = sync_server.await {
            eprintln!("wiremesh-controller: sync server error: {e}");
        }
    });

    Ok(RunningController {
        tcp_addr,
        sync_tcp_addr,
        admin_tcp_addr,
        observe_addr,
        socket_path: config.socket_path,
        data_dir: config.data_dir,
        ca_bundle_pem,
        admin_shutdown_tx: Some(admin_shutdown_tx),
        admin_join: Some(admin_join),
        admin_tcp_shutdown_tx: Some(admin_tcp_shutdown_tx),
        admin_tcp_join: Some(admin_tcp_join),
        enroll_shutdown_tx: Some(enroll_shutdown_tx),
        enroll_join: Some(enroll_join),
        sync_shutdown_tx: Some(sync_shutdown_tx),
        sync_join: Some(sync_join),
        observe_shutdown_tx: Some(observe_shutdown_tx),
        observe_join: Some(observe_join),
        broker_shutdown_tx: Some(broker_shutdown_tx),
        broker_join: Some(broker_join),
        // Already `Option`s: both are `None` when automatic rotation is
        // disabled (no task was spawned), which `shutdown`/`Drop` handle the
        // same way they handle an already-taken handle.
        rotation_timer_shutdown_tx,
        rotation_timer_join,
        rotation_sweep_shutdown_tx: Some(rotation_sweep_shutdown_tx),
        rotation_sweep_join: Some(rotation_sweep_join),
    })
}

/// Creates (if absent) the Unix socket's parent directory and, if that
/// directory is the controller's OWN `data_dir` (or nested under it),
/// tightens it to mode `0700`.
///
/// Deliberately does NOT chmod a parent directory outside `data_dir`: a
/// misconfigured `socket_path` (e.g. `/tmp/wiremesh.sock`) would otherwise
/// have this function force a SHARED system directory like `/tmp` to
/// `0700`, potentially breaking every other tenant of that path — this
/// process has no business re-mode-ing a directory it doesn't own. The
/// bound socket FILE itself is separately restricted to `0600` by
/// [`serve`] right after `bind`, which is safe unconditionally (the
/// process just created that file, so it unambiguously owns it) and is
/// the actual access boundary in that unsafe-parent case.
fn bind_uds_dir(socket_path: &Path, data_dir: &Path) -> Result<()> {
    let Some(parent) = socket_path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(parent)
        .with_context(|| format!("creating unix socket dir {}", parent.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if owns_dir(parent, data_dir) {
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("setting 0700 on {}", parent.display()))?;
        }
    }
    Ok(())
}

/// `true` iff `dir` IS `data_dir`, or is nested under it — the only case
/// where this process can be confident it's safe to chmod `dir`, since
/// `data_dir` itself is exclusively this controller instance's own
/// directory (created, if absent, at the top of [`serve`]). Falls back to
/// the given paths verbatim if `canonicalize` fails (e.g. a path that
/// doesn't exist yet) rather than erroring — worst case this is overly
/// conservative (skips the chmod) rather than chmod-ing the wrong thing.
#[cfg(unix)]
fn owns_dir(dir: &Path, data_dir: &Path) -> bool {
    let dir = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
    let data_dir = data_dir
        .canonicalize()
        .unwrap_or_else(|_| data_dir.to_path_buf());
    dir == data_dir || dir.starts_with(&data_dir)
}

/// sha256 of the CA root certificate's DER bytes (not the PEM text), hex
/// encoded — the fingerprint embedded in minted enrollment tokens so a
/// gateway can pin the controller it expects to enroll against.
async fn ca_root_fingerprint_hex(trust: &EmbeddedTrust) -> Result<String> {
    use sha2::{Digest, Sha256};

    let bundle_pem = trust.trust_bundle().await.context("reading CA trust bundle")?;
    let der = pem_to_der(&bundle_pem).context("decoding CA trust bundle PEM")?;
    let digest = Sha256::digest(&der);
    Ok(hex_encode(&digest))
}

/// Decodes the first PEM block's base64 body to raw DER bytes. Minimal by
/// design: the embedded CA's `trust_bundle()` is always exactly one
/// `CERTIFICATE` block.
fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    let body: String = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .context("base64-decoding PEM body")
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
