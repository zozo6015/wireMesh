//! `wiremesh-controller`: the single-tenant control plane binary's library
//! crate. See [`db`] for the embedded SQLite store (schema, migrations,
//! CIDR-overlap invariant, audit log), [`db_async`] for the blocking-pool
//! async wrapper around it, and [`services`] for the tonic service impls.
//!
//! [`serve`] is the library entrypoint other binaries/tests boot the
//! controller through: `src/main.rs` is a thin wrapper around it, and
//! `wiremesh-testkit::TestController` boots it in-process for integration
//! tests.

pub mod db;
pub mod db_async;
pub mod projection;
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
}

/// A live, in-process controller instance. Dropping it stops both servers
/// (best effort — see the `Drop` impl) so tests don't leak listeners/tasks
/// across cases.
pub struct RunningController {
    tcp_addr: std::net::SocketAddr,
    sync_tcp_addr: std::net::SocketAddr,
    socket_path: PathBuf,
    data_dir: PathBuf,
    /// PEM trust bundle of the embedded CA — exposed so a TLS client (e.g.
    /// `wiremesh-testkit::TestController::enrollment_client`) can trust the
    /// server-TLS identity presented on `tcp_addr` without needing its own
    /// filesystem access to the controller's data dir. The same bundle is
    /// also what a Sync client must present a client cert chaining to.
    ca_bundle_pem: String,
    admin_shutdown_tx: Option<oneshot::Sender<()>>,
    admin_join: Option<JoinHandle<()>>,
    enroll_shutdown_tx: Option<oneshot::Sender<()>>,
    enroll_join: Option<JoinHandle<()>>,
    sync_shutdown_tx: Option<oneshot::Sender<()>>,
    sync_join: Option<JoinHandle<()>>,
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

    /// Signals all servers to stop and waits for their tasks to finish.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.admin_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.enroll_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.sync_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.admin_join.take() {
            let _ = join.await;
        }
        if let Some(join) = self.enroll_join.take() {
            let _ = join.await;
        }
        if let Some(join) = self.sync_join.take() {
            let _ = join.await;
        }
    }
}

impl Drop for RunningController {
    fn drop(&mut self) {
        // Best-effort: if `shutdown()` was never called explicitly, at least
        // signal every server to stop so their tasks don't outlive this
        // handle. We can't `.await` the join handles here (Drop is sync), so
        // we don't try — they're spawned tokio tasks and quit promptly once
        // their shutdown signal fires.
        if let Some(tx) = self.admin_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.enroll_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.sync_shutdown_tx.take() {
            let _ = tx.send(());
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

    let db_path = config.data_dir.join("controller.db");
    let db = Db::open(&db_path).with_context(|| format!("opening db at {}", db_path.display()))?;
    let db_handle = DbHandle::new(db);

    let trust = EmbeddedTrust::open(&config.data_dir).context("opening embedded CA/trust")?;
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

    let tcp_listener = TcpListener::bind(("127.0.0.1", config.tcp_port))
        .await
        .context("binding controller TCP listener")?;
    let tcp_addr = tcp_listener.local_addr().context("reading bound TCP addr")?;
    let tcp_stream = TcpListenerStream::new(tcp_listener);

    let sync_tcp_listener = TcpListener::bind(("127.0.0.1", config.sync_tcp_port))
        .await
        .context("binding controller Sync TCP listener")?;
    let sync_tcp_addr = sync_tcp_listener
        .local_addr()
        .context("reading bound Sync TCP addr")?;
    let sync_tcp_stream = TcpListenerStream::new(sync_tcp_listener);

    bind_uds_dir(&config.socket_path)?;
    if config.socket_path.exists() {
        std::fs::remove_file(&config.socket_path).with_context(|| {
            format!("removing stale socket at {}", config.socket_path.display())
        })?;
    }
    let uds = UnixListener::bind(&config.socket_path)
        .with_context(|| format!("binding unix socket at {}", config.socket_path.display()))?;
    let uds_stream = UnixListenerStream::new(uds);

    let admin_svc = AdminSvc::new(db_handle.clone(), ca_fingerprint, tcp_addr.to_string());

    let (admin_shutdown_tx, admin_shutdown_rx) = oneshot::channel::<()>();
    let admin_server = Server::builder()
        .add_service(AdminServer::new(admin_svc))
        .serve_with_incoming_shutdown(uds_stream, async {
            let _ = admin_shutdown_rx.await;
        });

    let admin_join = tokio::spawn(async move {
        if let Err(e) = admin_server.await {
            eprintln!("wiremesh-controller: admin server error: {e}");
        }
    });

    // Shared fan-out channel for Task 8's Sync delta stream: `EnrollmentSvc`
    // (the only projection-affecting mutation site today) publishes here;
    // every `SyncSvc::watch` connection subscribes its own receiver. See
    // `projection::ChangeEvent`'s doc comment.
    let (change_tx, _) =
        broadcast::channel::<projection::ChangeEvent>(CHANGE_EVENT_CHANNEL_CAPACITY);

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

    let sync_svc = SyncSvc::new(db_handle, change_tx);
    // `client_auth_optional` defaults to `false` — i.e. REQUIRED — so this
    // is exactly the mTLS posture Sync needs: the Sync listener rejects any
    // TLS handshake that doesn't present a client cert chaining to
    // `client_ca_root`. Same embedded CA/server identity as Enrollment;
    // only the client-cert requirement differs.
    let sync_tls_config = ServerTlsConfig::new()
        .identity(tls_identity)
        .client_ca_root(Certificate::from_pem(&ca_bundle_pem));

    let (sync_shutdown_tx, sync_shutdown_rx) = oneshot::channel::<()>();
    let sync_server = Server::builder()
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
        socket_path: config.socket_path,
        data_dir: config.data_dir,
        ca_bundle_pem,
        admin_shutdown_tx: Some(admin_shutdown_tx),
        admin_join: Some(admin_join),
        enroll_shutdown_tx: Some(enroll_shutdown_tx),
        enroll_join: Some(enroll_join),
        sync_shutdown_tx: Some(sync_shutdown_tx),
        sync_join: Some(sync_join),
    })
}

/// Creates (if absent) the Unix socket's parent directory and forces it to
/// mode `0700` — the socket itself inherits no meaningful permissions of its
/// own on most platforms, so the directory is the actual access boundary.
fn bind_uds_dir(socket_path: &Path) -> Result<()> {
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
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("setting 0700 on {}", parent.display()))?;
    }
    Ok(())
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
