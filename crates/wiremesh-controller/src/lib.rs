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
pub mod services;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use anyhow::{Context, Result};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::{TcpListenerStream, UnixListenerStream};
use tonic::transport::{Identity, Server, ServerTlsConfig};

use db::Db;
use db_async::DbHandle;
use services::admin::AdminSvc;
use services::enrollment::EnrollmentSvc;
use wiremesh_proto::v1::admin_server::AdminServer;
use wiremesh_proto::v1::enrollment_server::EnrollmentServer;
use wiremesh_trust::{CertificateIssuer, EmbeddedTrust};

/// Lifetime of the controller's own TLS server-identity certificate (issued
/// fresh at every `serve()` call — see [`serve`]'s body). Long enough that a
/// long-running controller process doesn't need in-process cert rotation
/// for cycle-2; a later task can persist/rotate this if the process is
/// expected to run for years uninterrupted.
const SERVER_IDENTITY_TTL: StdDuration = StdDuration::from_secs(365 * 24 * 3600);

/// Everything [`serve`] needs to boot a controller instance.
///
/// `tcp_port = 0` asks the OS to pick a free port (used by tests and by the
/// `wiremesh-testkit` harness so parallel test runs never collide).
pub struct Config {
    /// Directory holding the SQLite DB, the embedded CA, and secrets. Created
    /// if absent.
    pub data_dir: PathBuf,
    /// TCP port for the (future) Enrollment/Sync services. `0` = OS-assigned.
    pub tcp_port: u16,
    /// Unix-domain-socket path the Admin service is served on. Its parent
    /// directory is created (if absent) and forced to mode `0700`.
    pub socket_path: PathBuf,
}

/// A live, in-process controller instance. Dropping it stops both servers
/// (best effort — see the `Drop` impl) so tests don't leak listeners/tasks
/// across cases.
pub struct RunningController {
    tcp_addr: std::net::SocketAddr,
    socket_path: PathBuf,
    data_dir: PathBuf,
    /// PEM trust bundle of the embedded CA — exposed so a TLS client (e.g.
    /// `wiremesh-testkit::TestController::enrollment_client`) can trust the
    /// server-TLS identity presented on `tcp_addr` without needing its own
    /// filesystem access to the controller's data dir.
    ca_bundle_pem: String,
    admin_shutdown_tx: Option<oneshot::Sender<()>>,
    admin_join: Option<JoinHandle<()>>,
    enroll_shutdown_tx: Option<oneshot::Sender<()>>,
    enroll_join: Option<JoinHandle<()>>,
}

impl RunningController {
    /// The bound TCP address (host+port the OS assigned, if `tcp_port` was 0)
    /// the Enrollment service (server-TLS) listens on.
    pub fn tcp_addr(&self) -> std::net::SocketAddr {
        self.tcp_addr
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
    /// signed this instance's TLS server identity on `tcp_addr` — a TLS
    /// client dialing the Enrollment/Sync port trusts the server by
    /// pinning this bundle as its CA root.
    pub fn ca_bundle_pem(&self) -> &str {
        &self.ca_bundle_pem
    }

    /// Signals both servers to stop and waits for their tasks to finish.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.admin_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.enroll_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.admin_join.take() {
            let _ = join.await;
        }
        if let Some(join) = self.enroll_join.take() {
            let _ = join.await;
        }
    }
}

impl Drop for RunningController {
    fn drop(&mut self) {
        // Best-effort: if `shutdown()` was never called explicitly, at least
        // signal both servers to stop so their tasks don't outlive this
        // handle. We can't `.await` the join handles here (Drop is sync), so
        // we don't try — they're spawned tokio tasks and quit promptly once
        // their shutdown signal fires.
        if let Some(tx) = self.admin_shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.enroll_shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Boots the controller: opens the SQLite DB and embedded CA under
/// `config.data_dir`, binds the Admin service on `config.socket_path` (a Unix
/// socket, directory forced to `0700`), and serves the Enrollment service on
/// a TCP listener at `config.tcp_port` with server-side TLS (the embedded CA
/// issues the controller its own server identity at startup — see
/// [`SERVER_IDENTITY_TTL`]). Sync (Task 7) adds mTLS/client-cert
/// verification to the same TCP port; Enrollment itself is server-TLS only
/// since the caller has no client cert yet.
///
/// Returns once both services are actually listening.
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

    let enrollment_svc = EnrollmentSvc::new(db_handle, trust);
    let enroll_tls_config = ServerTlsConfig::new().identity(tls_identity);

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

    Ok(RunningController {
        tcp_addr,
        socket_path: config.socket_path,
        data_dir: config.data_dir,
        ca_bundle_pem,
        admin_shutdown_tx: Some(admin_shutdown_tx),
        admin_join: Some(admin_join),
        enroll_shutdown_tx: Some(enroll_shutdown_tx),
        enroll_join: Some(enroll_join),
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
