//! `wiremesh-testkit`: neutral test infrastructure shared by the controller's
//! integration tests — it is not itself "the code under test" (see
//! `CLAUDE.md`'s agent-workflow rules), just plumbing to boot a real
//! controller in-process and talk to it.
//!
//! [`TestController`] boots the real `wiremesh_controller::serve` entrypoint
//! against a fresh `tempfile::tempdir()` (so every test gets an isolated
//! data-dir/CA/DB, and the dir + everything under it is removed when the
//! `TestController` is dropped). A later task (originally cycle-2 plan Task
//! 6, folded into Task 4's brief) adds `StubGateway` on top of this.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Privileged Linux network-namespace test harness (`Lab`/`Ns`/`wg_lab`/
/// `join_netns`) — graduated (Task 12) from `spike/natlab` and the
/// `wiremesh-enforcer` test suite's duplicated netns lab helpers. Feature-
/// gated (see this crate's `Cargo.toml`) so the userspace `TestController`/
/// `StubGateway` surface above never pulls it in.
#[cfg(feature = "netns")]
pub mod netns;

/// Backend-parity conformance scenario runner (Task 13; design D-C3-7) —
/// `Scenario`/`Step`/`run_scenario` drive ONE scenario table against
/// EITHER backend (`wiremesh_enforcer::BackendKind`) in an identical netns
/// topology built on top of [`netns::wg_lab`]. Feature-gated alongside
/// `netns` (see this crate's `Cargo.toml`) since it's built directly on
/// that module plus `wiremesh-policy`/`wiremesh-enforcer`.
#[cfg(feature = "netns")]
pub mod conformance;

use hyper_util::rt::TokioIo;
use rand::RngCore;
use tempfile::TempDir;
use tokio::net::UnixStream;
use tonic::service::interceptor::InterceptedService;
use tonic::service::Interceptor;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity, Uri};
use tower::service_fn;

use wiremesh_controller::{serve, Config, RunningController};
use wiremesh_proto::v1::admin_client::AdminClient;
use wiremesh_proto::v1::enrollment_client::EnrollmentClient;
use wiremesh_proto::v1::sync_client::SyncClient;
use wiremesh_proto::v1::{
    ApplyDiff, ApplyRequest, CreateSegmentRequest, MintApiTokenRequest, MintTokenRequest,
    ReportRequest, SubmitEpochKeyRequest, SyncMessage, WatchRequest,
};

/// (Task 13) Client-side counterpart to `crate::auth`'s bearer-auth
/// middleware: attaches `authorization: Bearer <token>` metadata to every
/// outgoing request on a `tonic::service::Interceptor`-wrapped channel — see
/// [`TestController::admin_client_with_bearer`].
#[derive(Clone)]
pub struct BearerCredential(String);

impl Interceptor for BearerCredential {
    fn call(
        &mut self,
        mut request: tonic::Request<()>,
    ) -> Result<tonic::Request<()>, tonic::Status> {
        let value = format!("Bearer {}", self.0)
            .parse()
            .map_err(|_| tonic::Status::internal("bearer token is not a valid header value"))?;
        request.metadata_mut().insert("authorization", value);
        Ok(request)
    }
}

/// A real controller, booted in-process against a temporary data directory,
/// for integration tests to drive.
/// The directory a harness-booted controller points its CA re-mint guard at:
/// a path inside the harness's own tempdir that is never created.
///
/// The guard exists to stop a controller minting a replacement CA when one
/// already sits at `/var/lib/wiremesh` (see
/// `wiremesh_controller::Config::legacy_data_dir`). That absolute path is
/// right in production and poison in a test: on any machine that really has
/// `/var/lib/wiremesh/ca.key` — a controller host, or a developer's laptop —
/// every harness boot into a tempdir would refuse to start. Pointing the
/// probe at a guaranteed-absent path makes the harness hermetic: the guard
/// still runs, and still resolves the same way on every machine.
///
/// A test that wants to exercise the guard itself should build its own
/// `Config` (or use `EmbeddedTrust::open_with_legacy_dir` directly) rather
/// than reaching for this.
fn hermetic_legacy_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("no-legacy-ca-here")
}

pub struct TestController {
    // FIELD ORDER matters, but as of Task 13 the ordering between `running`
    // and `_data_dir` is enforced EXPLICITLY in `impl Drop` below (not just
    // by declaration order — see that impl's comment for why a plain
    // `#[derive]`-style reliance on drop order stopped being enough once
    // `server_runtime` entered the picture).
    //
    // `Option` (rather than a bare `RunningController`) so `restart()` can
    // `.take()` the old instance out, `.await` its `shutdown()` (releasing
    // the TCP/UDS listeners and joining every server task) to completion,
    // and only THEN boot a new one against the same `_data_dir` — see
    // `restart()`'s doc comment for why the old instance must be fully torn
    // down first. It's `None` only for the brief instant inside `restart()`;
    // every accessor treats a `None` here as a bug (`running()` panics).
    running: Option<RunningController>,
    // (Task 13) The dedicated background Tokio runtime `start()`/`restart()`
    // actually run the controller's `serve()` (and everything it internally
    // `tokio::spawn`s) on — see `start()`'s doc comment for why this exists:
    // `fabricctl`'s CLI test (`crates/fabricctl/tests/cli.rs`) drives the
    // BUILT binary via a genuinely blocking `std::process::Command::output()`
    // call from inside a plain (current-thread-flavored) `#[tokio::test]`.
    // That call fully monopolizes the test's one worker thread until the
    // child process exits — if the controller's own accept-loop tasks
    // shared that SAME thread (as they would if `serve()` were simply
    // `.await`ed on the test's own ambient runtime, the way every
    // pre-Task-13 test does), the child could never get a response: a real
    // deadlock (the test thread blocked on the child; the child blocked on
    // a server only that SAME blocked thread could service). A dedicated
    // multi-thread `Runtime` has its own OS worker threads that keep
    // polling regardless of what the CALLING test's thread is doing.
    // `Option` so `impl Drop` can `.take()` it and call
    // `shutdown_background()` (the non-blocking teardown — see that impl's
    // comment for why the plain, blocking `Runtime::drop` would itself
    // panic here).
    server_runtime: Option<tokio::runtime::Runtime>,
    socket_path: PathBuf,
    // (Cycle 4a Task 12) The IP every controller listener binds to, captured
    // at `start`/`start_on` so `restart` re-binds the SAME address (the OS
    // still re-assigns the ports). `127.0.0.1` for `start()` (unchanged);
    // a routable underlay IP for the mesh-milestone test's `start_on`.
    bind_ip: std::net::Ipv4Addr,
    // (Key-rotation Task 4) The rotation-initiation-timer/decision-sweep
    // intervals this instance was booted with — captured at
    // `start`/`start_on`/`start_with_rotation_intervals` so `restart` reuses
    // the SAME small intervals a test started with, rather than reverting to
    // `Config`'s 30-day/5s defaults. Without this, a test that shrinks these
    // intervals to observe timer/sweep behavior would silently lose that
    // after a `restart()` — exactly the scenario
    // `sweep_retires_orphaned_retiring_row_after_crash` depends on NOT
    // happening.
    rotation_interval: std::time::Duration,
    rotation_sweep_interval: std::time::Duration,
    // Held only so the directory (and everything the controller wrote under
    // it — DB, CA, secrets, the socket) is cleaned up on drop; never read
    // directly.
    _data_dir: TempDir,
}

impl Drop for TestController {
    /// Explicit teardown order (Task 13): `running` MUST be dropped (firing
    /// `RunningController`'s best-effort shutdown-signal Drop impl) WHILE
    /// `server_runtime`'s worker threads are still alive to receive it —
    /// hence `.take()`ing and dropping `running` FIRST, in this body, rather
    /// than trusting field-declaration order (which only governs drop order
    /// for fields this impl does NOT already handle, like `_data_dir`).
    ///
    /// `server_runtime.shutdown_background()` (NOT plain `drop(server_runtime)`,
    /// which reduces to the same thing once this impl ends anyway) is used
    /// because `Runtime`'s ordinary `Drop` blocks the CURRENT thread joining
    /// every worker thread — and Tokio explicitly PANICS if that runs from
    /// within any async context on this thread (which this always is: a
    /// `TestController` local variable going out of scope at the end of an
    /// `async fn` test IS such a context). `shutdown_background()` is the
    /// Tokio-documented non-blocking alternative for exactly this situation:
    /// it signals shutdown and returns immediately, letting the worker
    /// threads wind down in the background.
    fn drop(&mut self) {
        self.running.take();
        if let Some(rt) = self.server_runtime.take() {
            rt.shutdown_background();
        }
    }
}

impl TestController {
    /// Boots a controller against a fresh temp data-dir: a Unix socket
    /// (`<data-dir>/controller.sock`) and a TCP listener on an OS-assigned
    /// port (unused by any service yet — reserved for Enrollment/Sync in
    /// later tasks).
    ///
    /// (Task 13) `serve()` itself is not `.await`ed directly on whichever
    /// runtime calls `start()` — it's handed to a fresh, dedicated
    /// multi-thread [`tokio::runtime::Runtime`] via [`tokio::runtime::Runtime::spawn`]
    /// (which works from ANY calling context, per its own docs) and only
    /// the resulting `JoinHandle` is awaited here. See the `server_runtime`
    /// field's doc comment for why this decoupling is load-bearing, not
    /// cosmetic.
    pub async fn start() -> TestController {
        Self::start_on(Config::default_bind_ip()).await
    }

    /// (Cycle 4a Task 12) Additive counterpart to [`Self::start`] that binds
    /// every controller listener (Enrollment/Sync/Admin TCP + observation
    /// UDP) to `bind_ip` instead of the default `127.0.0.1`. Used by the
    /// mesh-milestone netns test to bind a routable underlay address a
    /// `wiremesh-gateway` process in a separate network namespace can reach —
    /// `sync_tcp_addr()`/`observe_addr()` then return that routable `IP:port`.
    /// `start()` delegates here with `127.0.0.1`, so every existing caller is
    /// byte-for-byte unchanged. The TLS server cert SAN stays `127.0.0.1`
    /// regardless (see `Config::bind_ip`'s doc comment).
    pub async fn start_on(bind_ip: std::net::Ipv4Addr) -> TestController {
        Self::start_inner(
            bind_ip,
            Config::default_rotation_interval(),
            Config::default_rotation_sweep_interval(),
        )
        .await
    }

    /// (Key-rotation Task 4) Additive counterpart to [`Self::start`]/
    /// [`Self::start_on`] that boots against the DEFAULT `bind_ip` but
    /// caller-supplied `rotation_interval`/`rotation_sweep_interval` — what
    /// every rotation-timer/decision-sweep test uses instead of `start()`'s
    /// 30-day/5s production defaults, so the timer's/sweep's background
    /// cadence can be observed within a test's own bounded budget rather than
    /// requiring an actual 30-day (or even 5s-per-tick) wait. Both intervals
    /// are stored on the returned `TestController` so a later `restart()`
    /// reuses them (see the `rotation_interval`/`rotation_sweep_interval`
    /// fields' doc comment) — a restart must NOT silently revert to
    /// `Config`'s production defaults.
    pub async fn start_with_rotation_intervals(
        rotation_interval: std::time::Duration,
        rotation_sweep_interval: std::time::Duration,
    ) -> TestController {
        Self::start_inner(
            Config::default_bind_ip(),
            rotation_interval,
            rotation_sweep_interval,
        )
        .await
    }

    /// Shared boot logic behind [`Self::start_on`] (defaults) and
    /// [`Self::start_with_rotation_intervals`] (caller-supplied intervals) —
    /// see either method's doc comment for what each is for.
    async fn start_inner(
        bind_ip: std::net::Ipv4Addr,
        rotation_interval: std::time::Duration,
        rotation_sweep_interval: std::time::Duration,
    ) -> TestController {
        let data_dir = tempfile::tempdir().expect("creating temp data dir for TestController");
        let socket_path = data_dir.path().join("controller.sock");

        let config = Config {
            data_dir: data_dir.path().to_path_buf(),
            tcp_port: 0,
            sync_tcp_port: 0,
            socket_path: socket_path.clone(),
            admin_tcp_port: 0,
            observe_udp_port: 0,
            bind_ip,
            rotation_interval,
            rotation_sweep_interval,
            legacy_data_dir: Some(hermetic_legacy_dir(data_dir.path())),
        };

        let server_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("building TestController's background server runtime");

        let running = server_runtime
            .spawn(serve(config))
            .await
            .expect("TestController's background serve() task panicked")
            .expect("controller failed to start in TestController::start");

        TestController {
            _data_dir: data_dir,
            socket_path,
            running: Some(running),
            server_runtime: Some(server_runtime),
            bind_ip,
            rotation_interval,
            rotation_sweep_interval,
        }
    }

    /// Restarts the controller in place: awaits a full, graceful shutdown of
    /// the CURRENT `RunningController` (both TCP listeners closed, every
    /// server task joined — NOT just `Drop`'s best-effort signal-and-abandon,
    /// which doesn't wait for the OS to actually release the ports), then
    /// boots a brand-new one via `serve` against the SAME `_data_dir` — same
    /// SQLite DB file, same embedded CA key, same Unix socket path. This is
    /// what proves C-7 (`fail_static.rs`): the new controller reopens
    /// already-issued gateway certs' trust root and already-recorded
    /// projection state from disk, rather than starting from scratch.
    ///
    /// The old shutdown MUST complete before the new `serve()` call binds —
    /// otherwise the new listeners could collide with sockets the old
    /// process hasn't released yet, or a caller's `reconnect` could race and
    /// hit the dying old controller instead of the new one. Awaiting
    /// `RunningController::shutdown()` (rather than just dropping the old
    /// value) is what guarantees that ordering.
    ///
    /// The new controller's TCP/Sync ports are OS-assigned again (`0`) and
    /// may differ from the old ones, so callers must re-read
    /// `tcp_addr()`/`sync_tcp_addr()` (or, for a `StubGateway`, call
    /// `reconnect(&self)`) after this returns rather than reusing an address
    /// captured before the restart.
    pub async fn restart(&mut self) {
        let old = self
            .running
            .take()
            .expect("TestController::restart called on an already-shut-down controller");
        old.shutdown().await;

        let config = Config {
            data_dir: self._data_dir.path().to_path_buf(),
            tcp_port: 0,
            sync_tcp_port: 0,
            socket_path: self.socket_path.clone(),
            admin_tcp_port: 0,
            observe_udp_port: 0,
            bind_ip: self.bind_ip,
            // (Key-rotation Task 4) Reuse the SAME intervals this instance
            // was started with — NOT `Config`'s 30-day/5s production
            // defaults — so a restart doesn't silently widen a test's
            // shrunk rotation-timer/decision-sweep cadence back out. See the
            // `rotation_interval`/`rotation_sweep_interval` fields' doc
            // comment.
            rotation_interval: self.rotation_interval,
            rotation_sweep_interval: self.rotation_sweep_interval,
            // Same sentinel as the initial boot — a restart must not suddenly
            // start probing the host's real /var/lib/wiremesh.
            legacy_data_dir: Some(hermetic_legacy_dir(self._data_dir.path())),
        };

        // (Task 13) Reuse the SAME `server_runtime` across a restart (rather
        // than building a fresh one) — see `start()`/the `server_runtime`
        // field's doc comments for why `serve()` must run via
        // `Runtime::spawn` rather than a direct `.await` here at all.
        let server_runtime = self
            .server_runtime
            .as_ref()
            .expect("TestController::restart called with no background server runtime installed");
        let running = server_runtime
            .spawn(serve(config))
            .await
            .expect("TestController's background serve() task panicked on restart")
            .expect("controller failed to restart in TestController::restart");
        self.running = Some(running);
    }

    /// The current `RunningController`. Panics if called between `restart()`
    /// taking the old instance and installing the new one — `restart()` is
    /// the only place that window exists, and it never yields to another
    /// caller of `TestController` while `running` is `None`.
    fn running(&self) -> &RunningController {
        self.running
            .as_ref()
            .expect("TestController::running() called with no controller installed")
    }

    /// The Unix-domain-socket path the Admin service is listening on.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// The controller's bound TCP address the Enrollment service (server-TLS
    /// only) listens on.
    pub fn tcp_addr(&self) -> SocketAddr {
        self.running().tcp_addr()
    }

    /// The controller's CA bundle PEM — the trust root an enrolling gateway or
    /// relay pins to verify the controller's TLS server cert. Exposed so
    /// out-of-crate tests (e.g. `wiremesh-enroll`) can drive the real
    /// client-side enrollment flow.
    pub fn ca_bundle_pem(&self) -> &str {
        self.running().ca_bundle_pem()
    }

    /// The controller's bound TCP address the Sync service (mTLS: client
    /// cert required) listens on — a separate listener/port from
    /// `tcp_addr()` (see `wiremesh_controller::serve`'s doc comment for why).
    pub fn sync_tcp_addr(&self) -> SocketAddr {
        self.running().sync_tcp_addr()
    }

    /// (Task 13) The controller's bound TCP address the Admin service's
    /// SECOND, bearer-auth-gated listener listens on — see
    /// `wiremesh_controller::Config::admin_tcp_port` and `crate::auth`
    /// (controller-side) for the UDS-vs-TCP auth posture split this
    /// exercises for the first time.
    pub fn admin_tcp_addr(&self) -> SocketAddr {
        self.running().admin_tcp_addr()
    }

    /// (Task 15) The controller's bound UDP address the observation
    /// endpoint (`wiremesh_controller::observe`) listens on — what
    /// [`StubGateway::probe_observe`] dials.
    pub fn observe_addr(&self) -> SocketAddr {
        self.running().observe_addr()
    }

    /// The temp directory backing this instance's DB/CA/secrets.
    pub fn data_dir(&self) -> &Path {
        self.running().data_dir()
    }

    /// Connects a tonic `AdminClient` over the controller's Unix socket.
    ///
    /// tonic's transport is hyper-1.x-based, so a plain `tokio::net::UnixStream`
    /// doesn't itself implement the `hyper::rt::{Read,Write}` traits the
    /// custom connector needs — it must be wrapped in `hyper_util::rt::TokioIo`.
    /// The `http://[::]:50051` URI is a required-but-unused placeholder:
    /// `connect_with_connector` ignores it and always dials the Unix socket.
    pub async fn admin_client(&self) -> AdminClient<Channel> {
        let path = self.socket_path.clone();
        let channel = Endpoint::try_from("http://[::]:50051")
            .expect("static placeholder URI must parse")
            .connect_with_connector(service_fn(move |_: Uri| {
                let path = path.clone();
                async move {
                    let stream = UnixStream::connect(path).await?;
                    Ok::<_, std::io::Error>(TokioIo::new(stream))
                }
            }))
            .await
            .expect("connecting AdminClient over the controller's unix socket");
        AdminClient::new(channel)
    }

    /// (Task 13) Mints a fresh bearer API token with the given `role`
    /// (`"admin"` or `"read-only"`) via the implicit-admin UDS Admin
    /// client — the SAME trust boundary `admin_client()` already uses, so
    /// minting the credential doesn't itself require one. Returns the raw
    /// bearer secret (`Admin.MintApiToken`'s response), the same string a
    /// caller would hand to [`Self::admin_client_with_bearer`] or
    /// `fabricctl --token`. Each call mints a token under a fresh random
    /// name so a test can call this more than once without an
    /// already-exists collision.
    pub async fn mint_api_token(&self, role: &str) -> String {
        let mut id_bytes = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut id_bytes);
        let suffix: String = id_bytes.iter().map(|b| format!("{b:02x}")).collect();

        self.admin_client()
            .await
            .mint_api_token(MintApiTokenRequest {
                name: format!("test-{role}-{suffix}"),
                role: role.to_string(),
            })
            .await
            .expect("Admin.MintApiToken")
            .into_inner()
            .token
    }

    /// (Task 13) Connects an `AdminClient` to the controller's SECOND,
    /// bearer-auth-gated TCP Admin listener (`admin_tcp_addr()`), attaching
    /// `token` as an `authorization: Bearer <token>` header via
    /// [`BearerCredential`] on every outgoing call — the client-side
    /// counterpart to `wiremesh_controller::auth`'s server-side middleware.
    /// Plaintext gRPC (no TLS), matching that listener's cycle-2 posture
    /// (see `wiremesh_controller::Config::admin_tcp_port`'s doc comment).
    pub async fn admin_client_with_bearer(
        &self,
        token: &str,
    ) -> AdminClient<InterceptedService<Channel, BearerCredential>> {
        let uri = format!("http://{}", self.admin_tcp_addr());
        let channel = Channel::from_shared(uri)
            .expect("controller Admin TCP addr must form a valid URI")
            .connect()
            .await
            .expect("connecting AdminClient over the controller's Admin TCP port");
        AdminClient::with_interceptor(channel, BearerCredential(token.to_string()))
    }

    /// Connects a PLAIN `AdminClient` to the bearer-auth-gated TCP Admin
    /// listener (`admin_tcp_addr()`) with NO `authorization` header attached
    /// at all — unlike [`Self::admin_client_with_bearer`], which always
    /// attaches SOME bearer credential (even an invalid one). This is what
    /// actually exercises the "header entirely absent" branch of
    /// `wiremesh_controller::auth`'s middleware (`extract_bearer` returning
    /// `None`), which an invalid-but-present token never reaches the same
    /// way (`extract_bearer` succeeds either way; only the DB lookup
    /// differs) — both paths currently converge on `Unauthenticated`, but
    /// only this one proves the missing-header case specifically.
    pub async fn admin_client_tcp_no_auth(&self) -> AdminClient<Channel> {
        let uri = format!("http://{}", self.admin_tcp_addr());
        let channel = Channel::from_shared(uri)
            .expect("controller Admin TCP addr must form a valid URI")
            .connect()
            .await
            .expect("connecting AdminClient over the controller's Admin TCP port");
        AdminClient::new(channel)
    }

    /// (Task 11; pubkey added key-rotation Task 2) Debug/test accessor:
    /// every `GATEWAY_KEY` row (any state — `pending`, `active`,
    /// `retiring`) for `gateway_id`, as `(epoch, pubkey, state)` triples —
    /// read via `Admin.DebugKeyStates` over the controller's Unix socket
    /// (not a direct file-level DB read), so it exercises the same
    /// running-controller path a real debug/ops surface would, and works
    /// unchanged after `restart()` swaps in a new `RunningController` over
    /// the same on-disk DB.
    pub async fn debug_key_states(&self, gateway_id: u64) -> Vec<(u32, String, String)> {
        let resp = self
            .admin_client()
            .await
            .debug_key_states(wiremesh_proto::v1::DebugKeyStatesRequest { gateway_id })
            .await
            .expect("Admin.DebugKeyStates")
            .into_inner();
        resp.keys
            .into_iter()
            .map(|k| (k.epoch, k.pubkey, k.state))
            .collect()
    }

    /// (Task 12) `true` iff `gateway_id` is currently an existing, active
    /// gateway — `false` once `Admin.Drain` has removed it. Queries the
    /// controller's on-disk DB directly (`wiremesh_controller::db::Db::open`
    /// against `<data-dir>/controller.db`, the same file `wiremesh_controller::serve`
    /// opens) rather than adding a dedicated debug RPC: `TestController`
    /// already depends on `wiremesh-controller` as a library, and this is
    /// purely a test-harness accessor, not something a real deployment's
    /// wire contract needs. `Db::open` re-enables `foreign_keys` and sets a
    /// 5s `busy_timeout` on every open, so a read here racing the live
    /// controller's own connection (a distinct in-process `Connection` to the
    /// same file) retries instead of failing outright on a transient lock.
    pub async fn gateway_exists(&self, gateway_id: u64) -> bool {
        let db_path = self.data_dir().join("controller.db");
        tokio::task::spawn_blocking(move || {
            let db = wiremesh_controller::db::Db::open(&db_path)
                .expect("opening controller DB for TestController::gateway_exists");
            db.gateway_is_active(gateway_id as i64)
                .expect("querying gateway_is_active in TestController::gateway_exists")
        })
        .await
        .expect("gateway_exists blocking task panicked")
    }

    /// (Task 14) Calls `Admin.Apply` with `fabric_yaml` as the raw `fabric.yaml`
    /// text, over the controller's Unix socket, and returns the resulting
    /// `ApplyDiff` — the wire-level equivalent of running `fabricctl apply -f`.
    /// Used by `tests/apply.rs` to prove the diff engine's idempotence
    /// contract (re-applying the identical fabric yields an empty diff).
    pub async fn apply(&self, fabric_yaml: &str) -> ApplyDiff {
        self.admin_client()
            .await
            .apply(ApplyRequest {
                fabric_yaml: fabric_yaml.to_string(),
            })
            .await
            .expect("Admin.Apply")
            .into_inner()
    }

    /// (Task 14 testkit accessor) Total number of `audit_log` rows, read
    /// straight off the controller's on-disk DB — same
    /// open-a-second-connection-to-the-same-file pattern as
    /// [`Self::gateway_exists`] (see that method's doc comment for why this
    /// is safe: `Db::open` re-enables `foreign_keys` and sets a 5s
    /// `busy_timeout` on every open). Used by `tests/apply.rs` to prove an
    /// empty (no-op) re-apply writes zero new audit rows.
    pub async fn count_audit(&self) -> i64 {
        let db_path = self.data_dir().join("controller.db");
        tokio::task::spawn_blocking(move || {
            let db = wiremesh_controller::db::Db::open(&db_path)
                .expect("opening controller DB for TestController::count_audit");
            db.count_audit()
                .expect("querying count_audit in TestController::count_audit")
        })
        .await
        .expect("count_audit blocking task panicked")
    }

    /// Connects a tonic `EnrollmentClient` over the controller's TCP port.
    ///
    /// Enrollment is server-TLS only (the caller has no client cert yet —
    /// mTLS begins at Sync, Task 7), so this just needs to TRUST the
    /// controller's server identity, not present one of its own. It pins
    /// the controller's own embedded CA (`RunningController::ca_bundle_pem`)
    /// as the sole trust root — deliberately not the system root store, the
    /// same way a real gateway pins the CA fingerprint carried inside its
    /// enrollment token rather than trusting ambient CAs — and verifies the
    /// server cert's `127.0.0.1` SAN, which is the identity
    /// `wiremesh_controller::serve` issues its TLS listener at startup.
    pub async fn enrollment_client(&self) -> EnrollmentClient<Channel> {
        let uri = format!("https://{}", self.tcp_addr());
        let tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(self.running().ca_bundle_pem()))
            .domain_name("127.0.0.1");
        let channel = Channel::from_shared(uri)
            .expect("controller TCP addr must form a valid URI")
            .tls_config(tls)
            .expect("configuring EnrollmentClient TLS trust of the controller's embedded CA")
            .connect()
            .await
            .expect("connecting EnrollmentClient over the controller's TCP port");
        EnrollmentClient::new(channel)
    }
}

/// A non-enforcing test counterpart to a real gateway: it runs the same
/// bootstrap a gateway would (generate a keypair, build a CSR, redeem an
/// enrollment token over `Enrollment.Enroll`) and then just *holds* the
/// resulting identity — no tunnel, no eBPF, no nftables — so controller-side
/// tests (Task 7's Sync stream, Task 9's fail-static reload) have something
/// to drive without a real Linux data plane.
///
/// The identity (leaf cert, private key, CA bundle) is persisted to a
/// per-instance temp directory (`state_dir()`) in addition to being held in
/// memory, so a later test can simulate a gateway restart by reloading from
/// disk instead of from this struct — that's what Task 9's fail-static test
/// exercises. The directory (and everything under it) is removed when the
/// `StubGateway` is dropped.
pub struct StubGateway {
    cert_pem: String,
    key_pem: String,
    ca_bundle_pem: String,
    // (Task 11) The DB row id the controller assigned this gateway at
    // enrollment — `EnrollResponse.gateway_id`, threaded straight through
    // like `cert_pem`/`ca_bundle_pem` (unlike `segment_id`, which
    // `EnrollResponse` never carried and had to be threaded in separately
    // via `enroll_one`/`set_segment_id`).
    gateway_id: i64,
    // (Task 15) The random per-gateway secret the controller generated and
    // returned exactly once, in `EnrollResponse.observe_key` — this stub
    // holds onto it (mirroring how a real gateway would) so
    // `probe_observe` can build an authenticated probe. See
    // `wiremesh_controller::observe`'s module doc comment for the scheme.
    observe_key: String,
    // The controller's Sync (mTLS) TCP endpoint, captured at enroll time so
    // `open_sync` can dial it without the caller having to pass the
    // `TestController` back in — mirrors what a real gateway does (it learns
    // the controller's address once, at enrollment, and dials Sync
    // independently thereafter).
    sync_addr: SocketAddr,
    // Held only for its `Drop` (removes `state_dir` on disk); never read
    // directly — mirrors `TestController::_data_dir`.
    _state_dir: TempDir,
    state_dir_path: PathBuf,
    // (Task 10) The segment id this gateway enrolled into, if the caller
    // told us — `EnrollResponse` doesn't carry a segment id (and the T10
    // brief deliberately doesn't grow the proto just for this test helper),
    // so `enroll()` itself never knows it. `enroll_one` DOES know it (it
    // just read it back from `CreateSegment`'s response) and threads it in
    // via `set_segment_id` right after `enroll()` returns. `None` for a
    // `StubGateway` built directly via `enroll()` (e.g. rebind's
    // replacement gateway in `tests/rebind.rs`, which never calls
    // `segment_id()`).
    segment_id: Option<i64>,
    // (Sync session generation) This stub's per-"process" nonce, sent on
    // BOTH `Sync.Watch` (`dial_sync_with`) and every `Sync.Report` helper —
    // exactly as `wiremesh_gateway::sync::session_generation` does for a
    // real gateway.
    //
    // DELIBERATELY NONZERO BY DEFAULT, and randomised per instance. 0 is the
    // wire's legacy/unknown sentinel, which makes the controller's
    // generation gate inert; a stub that sent 0 would be a stub of something
    // no real gateway is, and the gate would go completely unexercised by
    // the existing stub-driven suites (so a regression that started
    // rejecting ordinary reports — or one that stopped rejecting stale ones
    // — could only ever be caught by the handful of tests written
    // specifically for it). With a nonzero default, every existing
    // watch-then-report sequence in the suite doubles as a live positive
    // control for the gate's ACCEPT path.
    //
    // The scheme is per-PROCESS, not per-connection: `open_sync`/
    // `reconnect`/`reconnect_from_disk` all resend the SAME value, so a
    // reconnect never invalidates this stub's own in-flight reports. A test
    // that wants to model a gateway process RESTART bumps it explicitly via
    // [`StubGateway::set_session_generation`] and then re-opens Sync.
    session_generation: u64,
}

/// (Sync session generation) A uniformly random NONZERO `u64` — the same
/// shape of value `wiremesh_gateway::sync::session_generation` mints for a
/// real gateway process, and generated the same way: retried rather than
/// forced (`| 1`, `saturating_add`) so the distribution stays uniform and the
/// intent — "anything but the 0 legacy/unknown sentinel" — stays obvious.
/// `next_u64` returning 0 is a ~1-in-2^64 event, so this never spins.
fn random_nonzero_u64() -> u64 {
    loop {
        let v = rand::thread_rng().next_u64();
        if v != 0 {
            return v;
        }
    }
}

impl StubGateway {
    /// Enrolls a fresh gateway identity against `controller`: generates a
    /// keypair + CSR (real gateway's CN doesn't matter here — the controller
    /// assigns the identity's real name/serial from the token, not from
    /// whatever CN the CSR asks for), redeems `token` for it over
    /// `Enrollment.Enroll` declaring `cidrs`, and persists the returned cert
    /// + CA bundle alongside the private key to a fresh temp state dir.
    pub async fn enroll(
        controller: &TestController,
        token: &str,
        cidrs: &[&str],
    ) -> anyhow::Result<StubGateway> {
        Self::enroll_inner(controller, token, cidrs, "").await
    }

    /// (Task 11b) Additive counterpart to [`Self::enroll`] that also
    /// declares a real, caller-supplied base64 WireGuard public key on the
    /// `EnrollRequest` — this is what lands as the gateway's epoch-0
    /// baseline `GATEWAY_KEY.pubkey` instead of the cycle-2 placeholder (see
    /// `wiremesh_controller::db::Db::enroll_gateway`). `enroll` itself is
    /// left untouched (it delegates to the same private helper with `""`)
    /// so every existing caller keeps getting the placeholder, unaffected by
    /// this addition.
    pub async fn enroll_with_wg_pubkey(
        controller: &TestController,
        token: &str,
        cidrs: &[&str],
        wg_pubkey: &str,
    ) -> anyhow::Result<StubGateway> {
        Self::enroll_inner(controller, token, cidrs, wg_pubkey).await
    }

    async fn enroll_inner(
        controller: &TestController,
        token: &str,
        cidrs: &[&str],
        wg_pubkey: &str,
    ) -> anyhow::Result<StubGateway> {
        let (csr_pem, key_pair) = gen_csr("stub-gw");
        let key_pem = key_pair.serialize_pem();

        let mut enr = controller.enrollment_client().await;
        let resp = enr
            .enroll(wiremesh_proto::v1::EnrollRequest {
                token: token.to_string(),
                csr_pem,
                cidrs: cidrs.iter().map(|c| c.to_string()).collect(),
                wg_pubkey: wg_pubkey.to_string(),
                endpoint: String::new(),
            })
            .await
            .map_err(|status| anyhow::anyhow!("Enrollment.Enroll failed: {status}"))?
            .into_inner();

        let state_dir = tempfile::tempdir()
            .map_err(|e| anyhow::anyhow!("creating StubGateway state dir: {e}"))?;
        let state_dir_path = state_dir.path().to_path_buf();

        std::fs::write(state_dir_path.join("cert.pem"), &resp.cert_pem)
            .map_err(|e| anyhow::anyhow!("writing cert.pem to state dir: {e}"))?;
        std::fs::write(state_dir_path.join("ca_bundle.pem"), &resp.ca_bundle_pem)
            .map_err(|e| anyhow::anyhow!("writing ca_bundle.pem to state dir: {e}"))?;

        let key_path = state_dir_path.join("key.pem");
        std::fs::write(&key_path, &key_pem)
            .map_err(|e| anyhow::anyhow!("writing key.pem to state dir: {e}"))?;
        // Private key must never be group/other-readable on disk, same
        // posture `wiremesh-trust` holds its own CA key to.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| anyhow::anyhow!("setting key.pem permissions: {e}"))?;
        }

        Ok(StubGateway {
            cert_pem: resp.cert_pem,
            key_pem,
            ca_bundle_pem: resp.ca_bundle_pem,
            gateway_id: resp.gateway_id as i64,
            observe_key: resp.observe_key,
            sync_addr: controller.sync_tcp_addr(),
            _state_dir: state_dir,
            state_dir_path,
            segment_id: None,
            // (Sync session generation) See the field's doc comment for why
            // the default is nonzero.
            session_generation: random_nonzero_u64(),
        })
    }

    /// Opens `Sync.Watch` against the controller's mTLS Sync endpoint,
    /// presenting this gateway's own enrolled client certificate + key —
    /// this is the mTLS handshake the brief calls out: `rustls`/tonic
    /// reject the connection outright if the presented cert doesn't chain
    /// to the controller's embedded CA (`ca_bundle_pem`, pinned here as the
    /// trust root the same way `TestController::enrollment_client` pins it
    /// for verifying the *server*). Returns the raw streaming response —
    /// callers drive it with `tokio_stream::StreamExt::next()`.
    pub async fn open_sync(&self) -> tonic::Streaming<SyncMessage> {
        self.dial_sync(self.sync_addr)
            .await
            .expect("StubGateway::open_sync")
    }

    /// Re-opens `Sync.Watch` after a controller restart, presenting this
    /// gateway's EXISTING (already-enrolled) client certificate + key — it
    /// never re-runs `Enrollment.Enroll`, which is the whole point: this is
    /// what `fail_static.rs` drives to prove C-7 (a restarted controller
    /// still recognizes an already-issued gateway cert and resyncs it,
    /// rather than requiring re-enrollment).
    ///
    /// Unlike `open_sync` (which dials the address captured at enroll time),
    /// this reads `controller`'s CURRENT `sync_tcp_addr()` — after
    /// `TestController::restart`, the new controller instance may be
    /// listening on a new OS-assigned port, so re-dialing the stale
    /// pre-restart address would connect to nothing (or, in the small window
    /// before the OS recycles the port, to the wrong process).
    ///
    /// Returns a `Result` (rather than panicking like `open_sync`) because a
    /// failure here — e.g. the restarted controller rejecting this cert —
    /// would be the actual finding under test, not a harness bug.
    pub async fn reconnect(
        &self,
        controller: &TestController,
    ) -> anyhow::Result<tonic::Streaming<SyncMessage>> {
        self.dial_sync(controller.sync_tcp_addr()).await
    }

    /// Like [`Self::reconnect`], but reads the identity bundle (cert/key/CA
    /// bundle) BACK OFF DISK from [`Self::state_dir`] first, and dials using
    /// ONLY those freshly-read bytes — never touching `self`'s in-memory
    /// `cert_pem`/`key_pem`/`ca_bundle_pem` fields at all. `persist_state`
    /// (or `enroll`, which writes the same files) must have already run.
    ///
    /// This is what actually exercises the fail-static restore PATH:
    /// reusing `self`'s in-memory fields (as a plain `reconnect()` call
    /// would) proves nothing about whether the on-disk persistence format
    /// is genuinely readable/restorable — it would pass even if
    /// `persist_state` wrote garbage, since the in-memory identity used to
    /// reconnect never came from disk at all.
    pub async fn reconnect_from_disk(
        &self,
        controller: &TestController,
    ) -> anyhow::Result<tonic::Streaming<SyncMessage>> {
        let cert_pem = std::fs::read_to_string(self.state_dir_path.join("cert.pem"))
            .map_err(|e| anyhow::anyhow!("reading persisted cert.pem: {e}"))?;
        let key_pem = std::fs::read_to_string(self.state_dir_path.join("key.pem"))
            .map_err(|e| anyhow::anyhow!("reading persisted key.pem: {e}"))?;
        let ca_bundle_pem = std::fs::read_to_string(self.state_dir_path.join("ca_bundle.pem"))
            .map_err(|e| anyhow::anyhow!("reading persisted ca_bundle.pem: {e}"))?;

        Self::dial_sync_with(
            controller.sync_tcp_addr(),
            &cert_pem,
            &key_pem,
            &ca_bundle_pem,
            // (Sync session generation) The identity comes off DISK, but the
            // nonce deliberately does NOT: this models the same process
            // re-dialing after a CONTROLLER restart (what `fail_static.rs`
            // drives), not a gateway restart. A gateway restart is
            // `set_session_generation` + `open_sync`.
            self.session_generation,
        )
        .await
    }

    /// Shared mTLS-dial + `Sync.Watch` logic behind `open_sync`/`reconnect`:
    /// connects to `addr` presenting this gateway's cert/key and trusting the
    /// controller's CA bundle, then opens the `Sync.Watch` stream.
    async fn dial_sync(&self, addr: SocketAddr) -> anyhow::Result<tonic::Streaming<SyncMessage>> {
        Self::dial_sync_with(
            addr,
            &self.cert_pem,
            &self.key_pem,
            &self.ca_bundle_pem,
            self.session_generation,
        )
        .await
    }

    /// Free-function core of [`Self::dial_sync`]: takes the identity PEMs
    /// explicitly (rather than reading `self`) so [`Self::reconnect_from_disk`]
    /// can dial with bytes read fresh off disk instead of `self`'s in-memory
    /// copies.
    ///
    /// `session_generation` is the per-"process" nonce this Watch open
    /// RECORDS against the authenticated gateway id controller-side (see
    /// [`StubGateway::session_generation`]); every subsequent `Sync.Report`
    /// carrying a DIFFERENT nonzero value is rejected with
    /// `FAILED_PRECONDITION`. Taken explicitly rather than read off `self`
    /// because this is the free-function core `reconnect_from_disk` also
    /// calls.
    async fn dial_sync_with(
        addr: SocketAddr,
        cert_pem: &str,
        key_pem: &str,
        ca_bundle_pem: &str,
        session_generation: u64,
    ) -> anyhow::Result<tonic::Streaming<SyncMessage>> {
        let uri = format!("https://{addr}");
        let tls = ClientTlsConfig::new()
            .identity(Identity::from_pem(cert_pem, key_pem))
            .ca_certificate(Certificate::from_pem(ca_bundle_pem))
            .domain_name("127.0.0.1");
        let channel = Channel::from_shared(uri)
            .map_err(|e| anyhow::anyhow!("controller Sync TCP addr must form a valid URI: {e}"))?
            .tls_config(tls)
            .map_err(|e| {
                anyhow::anyhow!(
                    "configuring StubGateway mTLS: presenting its cert + trusting the controller CA: {e}"
                )
            })?
            .connect()
            .await
            .map_err(|e| {
                anyhow::anyhow!("connecting to the controller's Sync (mTLS) TCP port: {e}")
            })?;

        let mut client = SyncClient::new(channel);
        let stream = client
            .watch(WatchRequest { session_generation })
            .await
            .map_err(|status| anyhow::anyhow!("Sync.Watch failed: {status}"))?
            .into_inner();
        Ok(stream)
    }

    /// (Task 15) Sends an authenticated UDP observation probe to the
    /// controller's observation endpoint at `observe_addr`
    /// (`TestController::observe_addr()`) and returns the `ip:port` the
    /// controller echoed back as this gateway's observed source address.
    ///
    /// Builds the probe via `wiremesh_controller::observe::build_probe`
    /// (the SAME function the controller's own verifier's expected-MAC
    /// computation is built from — see that module's doc comment for the
    /// wire format/scheme), using this gateway's `observe_key` learned once
    /// at enrollment. Binds a fresh ephemeral local UDP socket (NOT the
    /// Sync mTLS connection — this is a deliberately separate, unrelated
    /// transport, matching how a real gateway's data-plane WG socket has no
    /// relation to its control-plane TLS connection) so the observed
    /// source address is this call's own, not shared with anything else.
    pub async fn probe_observe(&self, observe_addr: SocketAddr) -> anyhow::Result<String> {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .map_err(|e| anyhow::anyhow!("binding local UDP socket for probe_observe: {e}"))?;

        let probe = wiremesh_controller::observe::build_probe(&self.observe_key, self.id());
        sock.send_to(&probe, observe_addr)
            .await
            .map_err(|e| anyhow::anyhow!("sending observation probe to {observe_addr}: {e}"))?;

        let mut buf = [0u8; 128];
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                anyhow::bail!(
                    "no observation reply from {observe_addr} within the probe_observe timeout"
                );
            }
            match tokio::time::timeout(remaining, sock.recv_from(&mut buf)).await {
                Ok(Ok((n, from))) if from == observe_addr => {
                    return Ok(String::from_utf8_lossy(&buf[..n]).into_owned());
                }
                // A reply from anyone other than the controller itself
                // isn't the answer we're waiting for — keep listening
                // rather than treating it as this probe's result.
                Ok(Ok(_)) => continue,
                Ok(Err(e)) => {
                    anyhow::bail!("receiving observation reply from {observe_addr}: {e}")
                }
                Err(_) => anyhow::bail!(
                    "no observation reply from {observe_addr} within the probe_observe timeout"
                ),
            }
        }
    }

    /// (Sync session generation) The single dial-and-send core behind every
    /// `report*` helper below: opens a FRESH mTLS channel presenting this
    /// gateway's own enrolled identity (the same recipe `open_sync` uses —
    /// modelling the real gateway's rotation tick, which dials its own
    /// short-lived channel per report) and sends `req` VERBATIM.
    ///
    /// Verbatim is the point. The four public helpers all stamp
    /// `self.session_generation` and hard-code most other fields; a test
    /// that needs to send something no honest gateway would — most
    /// importantly a STALE `session_generation`, i.e. one from before a
    /// simulated process restart — has to bypass them.
    ///
    /// Returns the raw `tonic::Response` on success. On an RPC failure the
    /// `tonic::Status` is placed in the `anyhow::Error` UNSTRINGIFIED, so a
    /// caller can recover it and assert on the CODE rather than on message
    /// text:
    ///
    /// ```ignore
    /// let err = gw.report_raw(req).await.expect_err("must be rejected");
    /// let status = err
    ///     .downcast_ref::<tonic::Status>()
    ///     .expect("the failure must be a gRPC Status, not a transport error");
    /// assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    /// ```
    ///
    /// Dial/TLS failures still surface as ordinary `anyhow` errors, so a
    /// `downcast_ref::<tonic::Status>()` returning `None` genuinely means
    /// "the request never reached the handler" — which is why the snippet
    /// above `expect`s rather than defaulting.
    pub async fn report_raw(
        &self,
        req: ReportRequest,
    ) -> anyhow::Result<tonic::Response<wiremesh_proto::v1::ReportResponse>> {
        let uri = format!("https://{}", self.sync_addr);
        let tls = ClientTlsConfig::new()
            .identity(Identity::from_pem(&self.cert_pem, &self.key_pem))
            .ca_certificate(Certificate::from_pem(&self.ca_bundle_pem))
            .domain_name("127.0.0.1");
        let channel = Channel::from_shared(uri)
            .map_err(|e| anyhow::anyhow!("controller Sync TCP addr must form a valid URI: {e}"))?
            .tls_config(tls)
            .map_err(|e| anyhow::anyhow!("configuring StubGateway mTLS for Sync.Report: {e}"))?
            .connect()
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "connecting to the controller's Sync (mTLS) TCP port for Sync.Report: {e}"
                )
            })?;

        // `anyhow::Error::new(status)` — NOT `anyhow!("...: {status}")`.
        // `tonic::Status` implements `std::error::Error`, so wrapping it
        // preserves the concrete type for `downcast_ref`; formatting it into
        // a string would throw the code away and force callers to
        // substring-match the message.
        SyncClient::new(channel)
            .report(req)
            .await
            .map_err(anyhow::Error::new)
    }

    /// (Cycle-4b Task 4) Calls `Sync.Report{applied_version, local_endpoints}`
    /// against the controller, over a FRESH mTLS channel presenting this
    /// gateway's own enrolled identity — the same dial recipe `open_sync`
    /// uses, just a plain unary `Report` call instead of a `Watch` stream
    /// (so it can't reuse `dial_sync`'s streaming return type). Promoted
    /// here from what had been a hand-rolled private helper duplicated in
    /// `wiremesh-testkit/tests/end_to_end_policy.rs` and
    /// `fabricctl/tests/cli.rs` (each predating `local_endpoints`, so each
    /// only ever sent an empty list) — this is the one shared place that
    /// now also exercises reporting a gateway's own local candidate
    /// endpoints (spec §6.1).
    ///
    /// (Sync session generation) Now a thin wrapper over
    /// [`StubGateway::report_raw`] — the four helpers' channel setups were
    /// byte-identical — stamping this stub's own `session_generation`, which
    /// is what a real gateway does and what makes this helper's report
    /// ACCEPTED after an `open_sync()` and REJECTED after a simulated
    /// restart it hasn't re-watched through.
    pub async fn report(
        &self,
        applied_version: u64,
        local_endpoints: &[&str],
    ) -> anyhow::Result<()> {
        self.report_raw(ReportRequest {
            applied_version,
            local_endpoints: local_endpoints.iter().map(|s| s.to_string()).collect(),
            relay_health: vec![],
            epoch_acks: vec![],
            peer_paths: vec![],
            peer_paths_snapshot: false,
            session_generation: self.session_generation,
        })
        .await
        .map_err(|e| anyhow::anyhow!("Sync.Report failed: {e}"))?;
        Ok(())
    }

    /// (Key-rotation Task 2) Submits this gateway's REAL WireGuard public
    /// key for a pending rotation `epoch` via `Sync.SubmitEpochKey`, over a
    /// fresh mTLS channel using this gateway's own identity — mirrors
    /// [`Self::report`]'s connection setup exactly.
    pub async fn submit_epoch_key(&self, epoch: u32, pubkey: &str) -> anyhow::Result<()> {
        let uri = format!("https://{}", self.sync_addr);
        let tls = ClientTlsConfig::new()
            .identity(Identity::from_pem(&self.cert_pem, &self.key_pem))
            .ca_certificate(Certificate::from_pem(&self.ca_bundle_pem))
            .domain_name("127.0.0.1");
        let channel = Channel::from_shared(uri)
            .map_err(|e| anyhow::anyhow!("controller Sync TCP addr must form a valid URI: {e}"))?
            .tls_config(tls)
            .map_err(|e| {
                anyhow::anyhow!("configuring StubGateway mTLS for Sync.SubmitEpochKey: {e}")
            })?
            .connect()
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "connecting to the controller's Sync (mTLS) TCP port for \
                     Sync.SubmitEpochKey: {e}"
                )
            })?;

        SyncClient::new(channel)
            .submit_epoch_key(SubmitEpochKeyRequest {
                epoch,
                pubkey: pubkey.to_string(),
            })
            .await
            .map_err(|status| anyhow::anyhow!("Sync.SubmitEpochKey failed: {status}"))?;
        Ok(())
    }

    /// (Cycle-4c Task 6) Additive counterpart to [`Self::report`] that also
    /// populates `ReportRequest.relay_health` — what a real gateway's own
    /// QUIC-ping health (Task 7/8) will eventually compute, stood in here by
    /// a caller-supplied `(relay_id, healthy)` list so controller-only tests
    /// can exercise the health-aggregation/eviction pipeline without any real
    /// gateway-side relay transport. `relay_id` is `i64` (matching
    /// `enroll_relay`'s return tuple's third element / the DB row id type)
    /// and cast up to the proto's `uint64` here, mirroring how
    /// `tests/sync_relays.rs` casts `relay_id as u64` when comparing against
    /// `RelayInfo.relay_id`. `report` itself is left untouched (it keeps
    /// sending the hardcoded empty `relay_health: vec![]`) so every existing
    /// caller is unaffected by this addition.
    ///
    /// (Sync session generation) Routes through
    /// [`StubGateway::report_raw`], stamping this stub's own nonce — see
    /// [`StubGateway::report`].
    pub async fn report_with_relay_health(
        &self,
        applied_version: u64,
        local_endpoints: &[&str],
        relay_health: &[(i64, bool)],
    ) -> anyhow::Result<()> {
        self.report_raw(ReportRequest {
            applied_version,
            local_endpoints: local_endpoints.iter().map(|s| s.to_string()).collect(),
            relay_health: relay_health
                .iter()
                .map(|(relay_id, healthy)| wiremesh_proto::v1::RelayHealth {
                    relay_id: *relay_id as u64,
                    healthy: *healthy,
                })
                .collect(),
            epoch_acks: vec![],
            peer_paths: vec![],
            peer_paths_snapshot: false,
            session_generation: self.session_generation,
        })
        .await
        .map_err(|e| anyhow::anyhow!("Sync.Report (relay health) failed: {e}"))?;
        Ok(())
    }

    /// (Directive-storm fix) Additive counterpart to [`Self::report`] that
    /// also populates `ReportRequest.peer_paths` — what a real gateway's
    /// steady-state sync loop computes from its own path state machine
    /// (`wiremesh_gateway::path::PathState::as_str()`'s lowercase labels),
    /// stood in here by a caller-supplied `(peer_gateway_id, state)` list so
    /// controller-only tests can exercise the broker's both-settled punch
    /// skip without any real gateway data plane. Sends
    /// `peer_paths_snapshot: true` — it models a NEW steady-state client,
    /// whose report is always its COMPLETE path map, so the broker REPLACES
    /// the stored states with `peer_paths` (an empty list here therefore
    /// CLEARS them; the plain [`Self::report`] keeps the old-client shape:
    /// empty `peer_paths`, snapshot=false, a broker no-op).
    /// `local_endpoints` is taken alongside (unlike
    /// [`Self::report_epoch_acks`]) because `local_endpoints` has
    /// full-REPLACE empty-list-clears semantics — a peer-path report must be
    /// able to re-assert the candidate set it isn't changing. Mirrors
    /// [`Self::report_with_relay_health`]'s connection setup exactly.
    ///
    /// (Sync session generation) Routes through
    /// [`StubGateway::report_raw`], stamping this stub's own nonce — see
    /// [`StubGateway::report`].
    pub async fn report_with_peer_paths(
        &self,
        applied_version: u64,
        local_endpoints: &[&str],
        peer_paths: &[(u64, &str)],
    ) -> anyhow::Result<()> {
        self.report_raw(ReportRequest {
            applied_version,
            local_endpoints: local_endpoints.iter().map(|s| s.to_string()).collect(),
            relay_health: vec![],
            epoch_acks: vec![],
            peer_paths: peer_paths
                .iter()
                .map(|(peer_gateway_id, state)| wiremesh_proto::v1::PeerPath {
                    peer_gateway_id: *peer_gateway_id,
                    state: state.to_string(),
                })
                .collect(),
            peer_paths_snapshot: true,
            session_generation: self.session_generation,
        })
        .await
        .map_err(|e| anyhow::anyhow!("Sync.Report (peer paths) failed: {e}"))?;
        Ok(())
    }

    /// (Key-rotation Task 3) Additive counterpart to [`Self::report`] that
    /// populates `ReportRequest.epoch_acks` instead — what a real gateway's
    /// own WireGuard UAPI-driven liveness check (a later task) will
    /// eventually compute, stood in here by a caller-supplied
    /// `(peer_gateway_id, epoch, live)` list. Per the ack-direction rule
    /// (`.superpowers/sdd/task-3-brief.md`): calling
    /// `b.report_epoch_acks(_, &[(a.id(), n, true)])` means "B has a live
    /// WireGuard session with rotating-gateway A's epoch-n key" — the ack is
    /// recorded against A (the rotating gateway), not B (the reporter).
    /// Mirrors [`Self::report_with_relay_health`]'s connection setup exactly.
    ///
    /// (Sync session generation) Routes through
    /// [`StubGateway::report_raw`], stamping this stub's own nonce — see
    /// [`StubGateway::report`]. This is also the helper that models the real
    /// gateway's rotation-tick unary ack, which is precisely the report the
    /// controller's whole-handler gating can drop if it fires while the
    /// gateway's Watch has been replaced (an accepted residual — see
    /// `SyncSvc::sessions`).
    pub async fn report_epoch_acks(
        &self,
        applied_version: u64,
        acks: &[(u64, u32, bool)],
    ) -> anyhow::Result<()> {
        self.report_raw(ReportRequest {
            applied_version,
            local_endpoints: vec![],
            relay_health: vec![],
            epoch_acks: acks
                .iter()
                .map(|(peer_gateway_id, epoch, live)| wiremesh_proto::v1::EpochAck {
                    peer_gateway_id: *peer_gateway_id,
                    epoch: *epoch,
                    live: *live,
                })
                .collect(),
            peer_paths: vec![],
            peer_paths_snapshot: false,
            session_generation: self.session_generation,
        })
        .await
        .map_err(|e| anyhow::anyhow!("Sync.Report (epoch acks) failed: {e}"))?;
        Ok(())
    }

    /// Ensures this gateway's identity bundle (leaf cert, private key
    /// (`0600`), CA bundle) is durably on disk under `state_dir()` — the
    /// fail-static posture `fail_static.rs` exercises: a gateway must not
    /// depend on the controller (or its own in-memory state) being alive to
    /// still hold a usable identity across a restart. `enroll()` already
    /// writes these same three files at enrollment time, so in the common
    /// case this just re-writes identical bytes (a truthful no-op); it's a
    /// real write, not a check, so it stays correct even if a future change
    /// makes enrollment lazier about persisting to disk.
    pub fn persist_state(&self) {
        std::fs::write(self.state_dir_path.join("cert.pem"), &self.cert_pem)
            .expect("persisting cert.pem in StubGateway::persist_state");
        std::fs::write(self.state_dir_path.join("ca_bundle.pem"), &self.ca_bundle_pem)
            .expect("persisting ca_bundle.pem in StubGateway::persist_state");

        let key_path = self.state_dir_path.join("key.pem");
        std::fs::write(&key_path, &self.key_pem)
            .expect("persisting key.pem in StubGateway::persist_state");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .expect("setting key.pem permissions in StubGateway::persist_state");
        }
    }

    /// This gateway's signed leaf certificate, PEM-encoded.
    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    /// This gateway's private key, PEM-encoded. Held only in-process and on
    /// disk under `state_dir()` (0600) — never sent back to the controller.
    pub fn key_pem(&self) -> &str {
        &self.key_pem
    }

    /// The CA bundle the controller returned alongside the leaf cert —
    /// what this gateway would pin as its trust root for verifying peers.
    pub fn ca_bundle_pem(&self) -> &str {
        &self.ca_bundle_pem
    }

    /// The temp directory this gateway's identity (cert/key/CA bundle) is
    /// persisted under, as `cert.pem` / `key.pem` / `ca_bundle.pem` — a
    /// later fail-static reload test (Task 9) reloads from here rather than
    /// from this struct's in-memory fields, to prove the on-disk state is
    /// what actually survives a restart.
    pub fn state_dir(&self) -> &Path {
        &self.state_dir_path
    }

    /// (Task 10 test-setup plumbing) Records the segment id this gateway
    /// enrolled into, so a later [`StubGateway::segment_id`] call can return
    /// it. `pub(crate)` — only [`enroll_one`] (which already knows the id
    /// from `CreateSegment`'s response) calls this; `enroll()` itself has no
    /// way to learn it (see the `segment_id` field's doc comment).
    pub(crate) fn set_segment_id(&mut self, segment_id: i64) {
        self.segment_id = Some(segment_id);
    }

    /// The segment id this gateway enrolled into. Only set for a
    /// `StubGateway` returned by [`enroll_one`] — panics otherwise, since
    /// nothing else records it (see the `segment_id` field's doc comment).
    pub fn segment_id(&self) -> u64 {
        self.segment_id.expect(
            "StubGateway::segment_id() called on a gateway whose segment id was never \
             recorded — only enroll_one() sets it (enroll() has no way to learn it)",
        ) as u64
    }

    /// This gateway's DB row id, as the controller assigned it at
    /// enrollment (`EnrollResponse.gateway_id`, Task 11) — always available
    /// (unlike `segment_id()`, which only `enroll_one` populates), since
    /// `enroll()` itself reads it straight off the enrollment response.
    pub fn id(&self) -> u64 {
        self.gateway_id as u64
    }

    /// (Sync session generation) The per-"process" nonce this stub currently
    /// stamps on `Sync.Watch` and every `Sync.Report` — see the
    /// `session_generation` field's doc comment. Always NONZERO unless a
    /// test deliberately set it to the legacy sentinel.
    ///
    /// Capture this BEFORE [`StubGateway::set_session_generation`] when
    /// modelling a restart: the captured value is the "previous process's"
    /// generation, i.e. the one a delayed pre-restart report would carry.
    pub fn session_generation(&self) -> u64 {
        self.session_generation
    }

    /// (Sync session generation) Simulates a gateway PROCESS RESTART by
    /// replacing this stub's nonce. Nothing is sent by this call on its own
    /// — the new value only reaches the controller on the NEXT
    /// `open_sync()`/`reconnect()`, which is what records it against this
    /// gateway id and thereby invalidates the previous process's reports.
    ///
    /// The idiomatic restart is therefore:
    ///
    /// ```ignore
    /// let previous = gw.session_generation();
    /// drop(stream);                       // the old process's Watch dies
    /// gw.set_session_generation(previous + 1);
    /// let stream = gw.open_sync().await;  // the new process registers
    /// ```
    ///
    /// after which a `report_raw` carrying `previous` is exactly the
    /// delayed pre-restart report the scheme exists to reject.
    ///
    /// Passing 0 is legal and meaningful: it models a LEGACY client (or one
    /// that does not implement the scheme), for which the controller's gate
    /// must stay inert in both directions.
    pub fn set_session_generation(&mut self, generation: u64) {
        self.session_generation = generation;
    }

    /// (Task 10) This gateway's `observe_key` — the random per-gateway
    /// secret the controller returned exactly once in
    /// `EnrollResponse.observe_key` at enrollment (see the `observe_key`
    /// field's doc comment). `probe_observe` already reaches this field
    /// internally to build its own probe; this accessor exposes the same
    /// value so a caller can build an equivalent probe itself (e.g. the
    /// gateway crate's own `wiremesh_gateway::observe::report_once`, whose
    /// cross-process parity with the controller's verifier is exactly what
    /// `tests/observe_parity.rs` proves).
    pub fn observe_key(&self) -> String {
        self.observe_key.clone()
    }

    /// This gateway's leaf certificate's serial number, as a lowercase hex
    /// string (e.g. `"01a2b3"`), parsed back out of `cert_pem`. Used by
    /// later tasks to correlate "the cert this stub is holding" with "the
    /// serial the controller's admin/audit surface reports" without
    /// re-deriving it from raw DER offsets by hand.
    pub fn cert_serial(&self) -> anyhow::Result<String> {
        let (_, pem) = x509_parser::pem::parse_x509_pem(self.cert_pem.as_bytes())
            .map_err(|e| anyhow::anyhow!("parsing cert_pem as PEM: {e}"))?;
        let cert = pem
            .parse_x509()
            .map_err(|e| anyhow::anyhow!("parsing cert_pem's DER as X.509: {e}"))?;
        // `raw_serial()` returns the *minimal* DER INTEGER contents, which
        // differs from the controller's fixed 16-byte record in BOTH
        // directions, so we width-normalize back to exactly 16 bytes:
        //
        //  - OVER-length: per ASN.1's canonical positive-integer rule, a
        //    leading 0x00 pad byte is prepended whenever the true leading byte
        //    has its MSB set (>= 0x80), else the value would parse as negative
        //    → 17 bytes. Strip that single sign-pad byte.
        //  - UNDER-length: minimal DER also DROPS genuine leading zero bytes,
        //    so e.g. `00 7f..` comes back as 15 bytes and `00 00 03..` as 14.
        //    Left-pad with 0x00 back up to 16.
        //
        // The controller records exactly 16 raw unmasked bytes (wiremesh-trust
        // `random_serial` → `hex_encode([u8;16])`), so after normalization
        // cert_serial() is ALWAYS 32 lowercase-hex chars equal to that record.
        let buf = normalize_serial_to_16_bytes(cert.raw_serial())?;
        Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
    }
}

/// The width-normalization at the core of [`StubGateway::cert_serial`],
/// extracted into a pure function of raw bytes so it can be unit-tested
/// deterministically against CRAFTED over-/under-length inputs — a single
/// randomly generated certificate only exercises the sign-pad-strip branch
/// on the ~50% of runs whose real serial happens to have its top byte
/// `>= 0x80`, and essentially never exercises the leading-zero-restore
/// branch (which needs a serial with 1-2 leading zero bytes — astronomically
/// unlikely for a random 16-byte value). See `tests` below for both cases
/// exercised directly.
fn normalize_serial_to_16_bytes(raw: &[u8]) -> anyhow::Result<[u8; 16]> {
    let stripped: &[u8] = match raw {
        [0x00, rest @ ..] if rest.len() == 16 => rest,
        _ => raw,
    };
    if stripped.len() > 16 {
        anyhow::bail!(
            "cert serial is {} bytes after sign-pad strip, expected <= 16 \
             (controller records a 16-byte serial): {stripped:02x?}",
            stripped.len()
        );
    }
    let mut buf = [0u8; 16];
    buf[16 - stripped.len()..].copy_from_slice(stripped);
    Ok(buf)
}

#[cfg(test)]
mod serial_normalization_tests {
    use super::normalize_serial_to_16_bytes;

    /// Exact 16 bytes: no stripping, no padding — passed through unchanged.
    #[test]
    fn exact_16_bytes_passes_through() {
        let raw: [u8; 16] = [0x7f; 16];
        assert_eq!(normalize_serial_to_16_bytes(&raw).unwrap(), raw);
    }

    /// OVER-length (17 bytes, `0x00` sign-pad prefix): the real 16-byte
    /// serial had its top byte `>= 0x80` (e.g. starting `0xff, 0x01, ..`),
    /// so minimal-DER `raw_serial()` prepends a pad byte to keep the ASN.1
    /// INTEGER non-negative. Must be stripped back to exactly the original
    /// 16 bytes.
    #[test]
    fn over_length_sign_pad_is_stripped() {
        let inner: [u8; 16] = [0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
        let mut raw = vec![0x00u8];
        raw.extend_from_slice(&inner);
        assert_eq!(normalize_serial_to_16_bytes(&raw).unwrap(), inner);
    }

    /// UNDER-length (15 bytes): the real serial's leading byte was itself
    /// `0x00`, which minimal-DER drops entirely (no pad needed — a leading
    /// zero followed by a byte `< 0x80` is still non-negative without one).
    /// Must be restored to 16 bytes via a single left-padding `0x00`.
    #[test]
    fn under_length_by_one_is_left_padded() {
        let raw: [u8; 15] = [0x7f, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e];
        let mut expected = [0u8; 16];
        expected[1..].copy_from_slice(&raw);
        assert_eq!(normalize_serial_to_16_bytes(&raw).unwrap(), expected);
    }

    /// UNDER-length by two (14 bytes): two genuine leading zero bytes were
    /// dropped by minimal DER — must be restored with two left-padding
    /// `0x00` bytes.
    #[test]
    fn under_length_by_two_is_left_padded() {
        let raw: [u8; 14] = [0x03, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d];
        let mut expected = [0u8; 16];
        expected[2..].copy_from_slice(&raw);
        assert_eq!(normalize_serial_to_16_bytes(&raw).unwrap(), expected);
    }

    /// Over-length that is NOT exactly a 16-byte sign-pad (e.g. 18 bytes, or
    /// 17 bytes whose pad byte isn't `0x00`) must be rejected as an
    /// internal inconsistency rather than silently truncated/misread.
    #[test]
    fn implausible_over_length_is_rejected() {
        let raw = [0xAAu8; 18];
        assert!(normalize_serial_to_16_bytes(&raw).is_err());
    }
}

/// Convenience wrapper mirroring the pattern already exercised by
/// `tests/enroll.rs`: creates a fresh segment named `segment_name` bound to
/// `cidr`, mints a single-use `gateway` token scoped to that same `cidr`,
/// and redeems it via [`StubGateway::enroll`]. Panics (via `.expect`) on any
/// failure — this is test-setup plumbing, not something callers need to
/// handle a partial-failure path for.
pub async fn enroll_one(h: &TestController, segment_name: &str, cidr: &str) -> StubGateway {
    let mut admin = h.admin_client().await;

    let segment = admin
        .create_segment(CreateSegmentRequest {
            name: segment_name.to_string(),
            cidrs: vec![cidr.to_string()],
        })
        .await
        .expect("creating segment for enroll_one")
        .into_inner();

    let token = admin
        .mint_token(MintTokenRequest {
            kind: "gateway".to_string(),
            bound_cidrs: vec![cidr.to_string()],
            rebind_segment_id: 0,
        })
        .await
        .expect("minting gateway token for enroll_one")
        .into_inner()
        .token;

    let mut gw = StubGateway::enroll(h, &token, &[cidr])
        .await
        .expect("enrolling stub gateway in enroll_one");
    // (Task 10) Thread the segment id `CreateSegment` handed back into the
    // stub, so a caller can later call `gw.segment_id()` (e.g. to mint a
    // `rebind` token bound to this exact segment) without needing a
    // dedicated lookup RPC.
    gw.set_segment_id(segment.id as i64);
    gw
}

/// (Task 11b) Additive counterpart to [`enroll_one`] that redeems the minted
/// token via [`StubGateway::enroll_with_wg_pubkey`] instead of
/// [`StubGateway::enroll`], so the resulting gateway's epoch-0 baseline key
/// is `wg_pubkey` rather than the cycle-2 placeholder. `enroll_one` itself is
/// untouched — every existing caller is unaffected.
pub async fn enroll_one_with_wg_pubkey(
    h: &TestController,
    segment_name: &str,
    cidr: &str,
    wg_pubkey: &str,
) -> StubGateway {
    let mut admin = h.admin_client().await;

    let segment = admin
        .create_segment(CreateSegmentRequest {
            name: segment_name.to_string(),
            cidrs: vec![cidr.to_string()],
        })
        .await
        .expect("creating segment for enroll_one_with_wg_pubkey")
        .into_inner();

    let token = admin
        .mint_token(MintTokenRequest {
            kind: "gateway".to_string(),
            bound_cidrs: vec![cidr.to_string()],
            rebind_segment_id: 0,
        })
        .await
        .expect("minting gateway token for enroll_one_with_wg_pubkey")
        .into_inner()
        .token;

    let mut gw = StubGateway::enroll_with_wg_pubkey(h, &token, &[cidr], wg_pubkey)
        .await
        .expect("enrolling stub gateway in enroll_one_with_wg_pubkey");
    gw.set_segment_id(segment.id as i64);
    gw
}

/// (Cycle-4c Task 4) Convenience wrapper mirroring `enroll_one`'s pattern for
/// the RELAY enrollment path: mints a single-use `relay`-kind token,
/// generates a keypair + CSR, and redeems it via `Enrollment.Enroll` with
/// `endpoint` set (a relay declares no cidrs/segment — see
/// `EnrollmentSvc::enroll`'s endpoint-routed branch). Returns `(cert_pem,
/// ca_bundle_pem, relay_id)`, mirroring what `StubGateway::enroll` persists,
/// minus the state-dir/key-file bookkeeping a `StubGateway` needs for its
/// later `Sync` dial — no relay-side test yet needs a persisted identity on
/// disk (a later cycle-4c task that does can grow this into a full
/// `StubRelay` then). Panics (via `.expect`) on any failure — this is
/// test-setup plumbing, not something callers need a partial-failure path
/// for.
pub async fn enroll_relay(h: &TestController, endpoint: &str) -> (String, String, i64) {
    let mut admin = h.admin_client().await;

    let token = admin
        .mint_token(MintTokenRequest {
            kind: "relay".to_string(),
            bound_cidrs: vec![],
            rebind_segment_id: 0,
        })
        .await
        .expect("minting relay token for enroll_relay")
        .into_inner()
        .token;

    let (csr_pem, _key_pair) = gen_csr("stub-relay");
    let mut enr = h.enrollment_client().await;
    let resp = enr
        .enroll(wiremesh_proto::v1::EnrollRequest {
            token,
            csr_pem,
            cidrs: vec![],
            wg_pubkey: String::new(),
            endpoint: endpoint.to_string(),
        })
        .await
        .expect("Enrollment.Enroll (relay path) failed in enroll_relay")
        .into_inner();

    (resp.cert_pem, resp.ca_bundle_pem, resp.gateway_id as i64)
}

/// (Cycle-4b Task 5) Reads the next broker `PunchDirective` off a live
/// `Sync.Watch` stream, transparently skipping any `Snapshot`/`Delta` messages
/// that precede it, bounded by `timeout`. Additive test helper for the broker
/// suite: a `Watch` stream always opens with a `Snapshot` and may interleave
/// `Delta`s (e.g. a peer's candidate-report delta) before/around the punch, so
/// a test that wants to assert on the punch specifically needs to filter for
/// it rather than positionally index the stream.
///
/// Returns `Ok(PunchDirective)` on the first `Punch` body seen; `Err` if the
/// stream ends, errors, or no punch arrives within `timeout` (the negative
/// cases — one member not connected, or a member with no candidate — rely on
/// this timing out).
///
/// Uses `tonic::Streaming::message()` (rather than a `StreamExt` combinator)
/// so this lives in the crate's normal (non-dev) surface without pulling
/// `tokio-stream` out of dev-dependencies.
pub async fn next_punch(
    stream: &mut tonic::Streaming<SyncMessage>,
    timeout: std::time::Duration,
) -> anyhow::Result<wiremesh_proto::v1::PunchDirective> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            anyhow::bail!("no PunchDirective arrived on the Sync.Watch stream within the timeout");
        }
        match tokio::time::timeout(remaining, stream.message()).await {
            Ok(Ok(Some(msg))) => match msg.body {
                Some(wiremesh_proto::v1::sync_message::Body::Punch(punch)) => return Ok(punch),
                // A Snapshot or Delta ahead of the punch — skip and keep
                // reading.
                _ => continue,
            },
            Ok(Ok(None)) => anyhow::bail!("Sync.Watch stream ended before any PunchDirective"),
            Ok(Err(status)) => anyhow::bail!("Sync.Watch stream yielded an error: {status}"),
            Err(_) => {
                anyhow::bail!("no PunchDirective arrived on the Sync.Watch stream within the timeout")
            }
        }
    }
}

/// Generates a fresh keypair and a PEM-encoded CSR with common name `cn` —
/// mirrors what a real gateway does before calling `Enrollment.Enroll`
/// (same pattern as Phase 0's `spike/relay/src/bin/mkcerts.rs` and
/// `wiremesh-trust`'s own embedded test). The trust provider never sees the
/// returned `KeyPair`'s private key beyond what's embedded in the CSR's
/// public key — callers keep it only to mirror a gateway holding its own
/// key material (unused by the Task 5 test beyond being generated).
pub fn gen_csr(cn: &str) -> (String, rcgen::KeyPair) {
    let key_pair = rcgen::KeyPair::generate().expect("generating gateway key pair");
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .expect("building CSR params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    let csr_pem = params
        .serialize_request(&key_pair)
        .expect("building CSR")
        .pem()
        .expect("PEM-encoding CSR");
    (csr_pem, key_pair)
}
