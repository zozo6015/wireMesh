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

use anyhow::{Context, Result};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;

use db::Db;
use db_async::DbHandle;
use services::admin::AdminSvc;
use wiremesh_proto::v1::admin_server::AdminServer;
use wiremesh_trust::EmbeddedTrust;

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

/// A live, in-process controller instance. Dropping it stops the server (best
/// effort — see the `Drop` impl) so tests don't leak listeners/tasks across
/// cases.
pub struct RunningController {
    tcp_addr: std::net::SocketAddr,
    socket_path: PathBuf,
    data_dir: PathBuf,
    /// Kept alive only to hold the TCP port reserved for later tasks
    /// (Enrollment/Sync aren't served yet in this task) — never accepted on.
    _tcp_listener: TcpListener,
    shutdown_tx: Option<oneshot::Sender<()>>,
    join: Option<JoinHandle<()>>,
}

impl RunningController {
    /// The bound TCP address (host+port the OS assigned, if `tcp_port` was 0).
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

    /// Signals the server to stop and waits for its task to finish.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.await;
        }
    }
}

impl Drop for RunningController {
    fn drop(&mut self) {
        // Best-effort: if `shutdown()` was never called explicitly, at least
        // signal the server to stop so its task doesn't outlive this handle.
        // We can't `.await` the join handle here (Drop is sync), so we don't
        // try — the task is a spawned tokio task and quits promptly once the
        // shutdown signal fires.
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

/// Boots the controller: opens the SQLite DB and embedded CA under
/// `config.data_dir`, binds the Admin service on `config.socket_path` (a Unix
/// socket, directory forced to `0700`), and reserves a TCP listener at
/// `config.tcp_port` for the Enrollment/Sync services later tasks add.
///
/// Returns once the Admin service is actually listening.
pub async fn serve(config: Config) -> Result<RunningController> {
    std::fs::create_dir_all(&config.data_dir)
        .with_context(|| format!("creating data dir {}", config.data_dir.display()))?;

    let db_path = config.data_dir.join("controller.db");
    let db = Db::open(&db_path).with_context(|| format!("opening db at {}", db_path.display()))?;
    let db_handle = DbHandle::new(db);

    let trust = EmbeddedTrust::open(&config.data_dir).context("opening embedded CA/trust")?;
    let ca_fingerprint = ca_root_fingerprint_hex(&trust).await?;

    // Reserve the TCP port now (Enrollment/Sync are wired up on it in later
    // tasks) so `RunningController::tcp_addr()` is a real, stable address for
    // the lifetime of this instance.
    let tcp_listener = TcpListener::bind(("127.0.0.1", config.tcp_port))
        .await
        .context("binding controller TCP listener")?;
    let tcp_addr = tcp_listener.local_addr().context("reading bound TCP addr")?;

    bind_uds_dir(&config.socket_path)?;
    if config.socket_path.exists() {
        std::fs::remove_file(&config.socket_path).with_context(|| {
            format!("removing stale socket at {}", config.socket_path.display())
        })?;
    }
    let uds = UnixListener::bind(&config.socket_path)
        .with_context(|| format!("binding unix socket at {}", config.socket_path.display()))?;
    let uds_stream = UnixListenerStream::new(uds);

    let admin_svc = AdminSvc::new(db_handle, ca_fingerprint, tcp_addr.to_string());

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let server = Server::builder()
        .add_service(AdminServer::new(admin_svc))
        .serve_with_incoming_shutdown(uds_stream, async {
            let _ = shutdown_rx.await;
        });

    let join = tokio::spawn(async move {
        if let Err(e) = server.await {
            eprintln!("wiremesh-controller: admin server error: {e}");
        }
    });

    Ok(RunningController {
        tcp_addr,
        socket_path: config.socket_path,
        data_dir: config.data_dir,
        _tcp_listener: tcp_listener,
        shutdown_tx: Some(shutdown_tx),
        join: Some(join),
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
    use wiremesh_trust::CertificateIssuer;

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
