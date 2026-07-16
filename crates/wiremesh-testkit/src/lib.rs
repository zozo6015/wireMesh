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
    SyncMessage, WatchRequest,
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
        let data_dir = tempfile::tempdir().expect("creating temp data dir for TestController");
        let socket_path = data_dir.path().join("controller.sock");

        let config = Config {
            data_dir: data_dir.path().to_path_buf(),
            tcp_port: 0,
            sync_tcp_port: 0,
            socket_path: socket_path.clone(),
            admin_tcp_port: 0,
            observe_udp_port: 0,
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

    /// (Task 11) Debug/test accessor: every `GATEWAY_KEY` row (any state —
    /// `pending`, `active`, `retiring`) for `gateway_id`, as `(epoch, state)`
    /// pairs — read via `Admin.DebugKeyStates` over the controller's Unix
    /// socket (not a direct file-level DB read), so it exercises the same
    /// running-controller path a real debug/ops surface would, and works
    /// unchanged after `restart()` swaps in a new `RunningController` over
    /// the same on-disk DB.
    pub async fn debug_key_states(&self, gateway_id: u64) -> Vec<(u32, String)> {
        let resp = self
            .admin_client()
            .await
            .debug_key_states(wiremesh_proto::v1::DebugKeyStatesRequest { gateway_id })
            .await
            .expect("Admin.DebugKeyStates")
            .into_inner();
        resp.keys.into_iter().map(|k| (k.epoch, k.state)).collect()
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
        let (csr_pem, key_pair) = gen_csr("stub-gw");
        let key_pem = key_pair.serialize_pem();

        let mut enr = controller.enrollment_client().await;
        let resp = enr
            .enroll(wiremesh_proto::v1::EnrollRequest {
                token: token.to_string(),
                csr_pem,
                cidrs: cidrs.iter().map(|c| c.to_string()).collect(),
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

    /// Shared mTLS-dial + `Sync.Watch` logic behind `open_sync`/`reconnect`:
    /// connects to `addr` presenting this gateway's cert/key and trusting the
    /// controller's CA bundle, then opens the `Sync.Watch` stream.
    async fn dial_sync(&self, addr: SocketAddr) -> anyhow::Result<tonic::Streaming<SyncMessage>> {
        let uri = format!("https://{addr}");
        let tls = ClientTlsConfig::new()
            .identity(Identity::from_pem(&self.cert_pem, &self.key_pem))
            .ca_certificate(Certificate::from_pem(&self.ca_bundle_pem))
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
            .watch(WatchRequest {})
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
        let raw = cert.raw_serial();
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
        Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
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
