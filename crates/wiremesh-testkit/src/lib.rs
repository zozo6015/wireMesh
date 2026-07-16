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
use tempfile::TempDir;
use tokio::net::UnixStream;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Uri};
use tower::service_fn;

use wiremesh_controller::{serve, Config, RunningController};
use wiremesh_proto::v1::admin_client::AdminClient;
use wiremesh_proto::v1::enrollment_client::EnrollmentClient;

/// A real controller, booted in-process against a temporary data directory,
/// for integration tests to drive.
pub struct TestController {
    // FIELD ORDER IS LOad-BEARING. Rust drops struct fields in declaration
    // order, so `running` MUST be declared before `_data_dir`: dropping
    // `running` first fires `RunningController`'s shutdown signal, and only
    // then does `_data_dir`'s Drop remove the DB/CA/secrets and unlink the
    // socket. The reverse order would delete the on-disk state (and the UDS)
    // out from under a still-running server task — which later streaming
    // tasks (5/7/8) build on this harness and would stress.
    running: RunningController,
    socket_path: PathBuf,
    // Held only so the directory (and everything the controller wrote under
    // it — DB, CA, secrets, the socket) is cleaned up on drop; never read
    // directly.
    _data_dir: TempDir,
}

impl TestController {
    /// Boots a controller against a fresh temp data-dir: a Unix socket
    /// (`<data-dir>/controller.sock`) and a TCP listener on an OS-assigned
    /// port (unused by any service yet — reserved for Enrollment/Sync in
    /// later tasks).
    pub async fn start() -> TestController {
        let data_dir = tempfile::tempdir().expect("creating temp data dir for TestController");
        let socket_path = data_dir.path().join("controller.sock");

        let config = Config {
            data_dir: data_dir.path().to_path_buf(),
            tcp_port: 0,
            socket_path: socket_path.clone(),
        };

        let running = serve(config)
            .await
            .expect("controller failed to start in TestController::start");

        TestController {
            _data_dir: data_dir,
            socket_path,
            running,
        }
    }

    /// The Unix-domain-socket path the Admin service is listening on.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// The controller's bound TCP address (Enrollment/Sync aren't served on
    /// it yet in this task, but the address is real and stable for the
    /// instance's lifetime).
    pub fn tcp_addr(&self) -> SocketAddr {
        self.running.tcp_addr()
    }

    /// The temp directory backing this instance's DB/CA/secrets.
    pub fn data_dir(&self) -> &Path {
        self.running.data_dir()
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
            .ca_certificate(Certificate::from_pem(self.running.ca_bundle_pem()))
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
    // Held only for its `Drop` (removes `state_dir` on disk); never read
    // directly — mirrors `TestController::_data_dir`.
    _state_dir: TempDir,
    state_dir_path: PathBuf,
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
            _state_dir: state_dir,
            state_dir_path,
        })
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
        Ok(cert
            .raw_serial()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect())
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
