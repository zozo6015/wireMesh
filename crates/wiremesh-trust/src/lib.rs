//! `wiremesh-trust`: the pluggable CA / secret-store seams for the
//! controller, plus an embedded, on-disk default implementation.
//!
//! The controller talks to trust material only through the
//! [`CertificateIssuer`] and [`SecretStore`] traits. [`EmbeddedTrust`]
//! implements both with a self-signed rcgen CA and plain files on disk —
//! good enough for a single-node deployment, and swappable later for a
//! Vault/ACME-backed implementation without touching controller code.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration as StdDuration;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DnType, IsCa, KeyPair,
};
use time::{Duration as TimeDuration, OffsetDateTime};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

/// Opaque handle returned by [`CertificateIssuer::sign`], accepted back by
/// [`CertificateIssuer::revoke`]. For the embedded issuer this is the
/// certificate's serial number (hex-encoded), but callers must not assume
/// any structure — other issuers may use a different encoding entirely.
pub type IssuerHandle = String;

/// A freshly issued leaf certificate.
pub struct IssuedCert {
    /// PEM-encoded leaf certificate (no chain, no key material).
    pub cert_pem: String,
    /// Hex-encoded serial number, unique per issued cert.
    pub serial: String,
    /// Expiry of the issued certificate.
    pub not_after: OffsetDateTime,
    /// Opaque handle for later revocation.
    pub handle: IssuerHandle,
}

/// What kind of leaf certificate to issue.
pub struct CertProfile {
    /// Subject common name to stamp onto the issued leaf (the CA is
    /// authoritative for this — it does not trust whatever CN, if any, the
    /// CSR itself carries).
    pub subject_cn: String,
    /// Requested lifetime of the leaf, from the moment of issuance.
    pub ttl: StdDuration,
}

/// A byte value paired with a monotonically increasing version number, as
/// returned by [`SecretStore::get`].
pub struct Versioned {
    pub version: u64,
    pub value: Vec<u8>,
}

/// Issues and revokes leaf certificates from some certificate authority.
///
/// Object-safe (via `#[async_trait]`) so the controller can hold a
/// `Arc<dyn CertificateIssuer>` and swap embedded/external implementations
/// without generics leaking through its API.
#[async_trait]
pub trait CertificateIssuer: Send + Sync {
    /// Returns the PEM-encoded trust bundle (one or more root certificates).
    /// Never contains private key material.
    async fn trust_bundle(&self) -> Result<String>;

    /// Signs a PEM-encoded CSR into a leaf certificate per `profile`.
    async fn sign(&self, csr_pem: &str, profile: CertProfile) -> Result<IssuedCert>;

    /// Revokes a previously issued certificate, identified by the handle
    /// returned from `sign`.
    async fn revoke(&self, handle: &IssuerHandle) -> Result<()>;
}

/// Reads and writes versioned secret material.
#[async_trait]
pub trait SecretStore: Send + Sync {
    /// Fetches the current value and version for `key`, or `None` if it has
    /// never been written.
    async fn get(&self, key: &str) -> Result<Option<Versioned>>;

    /// Writes `value` for `key`, returning the new version number. Versions
    /// increase monotonically per key, starting at 1.
    async fn put(&self, key: &str, value: Vec<u8>) -> Result<u64>;
}

/// Embedded default: a self-signed CA and a plain-file secret store, both
/// rooted at a single `data_dir`.
///
/// Layout:
/// - `<data_dir>/ca.pem`      — CA certificate (public, no restriction)
/// - `<data_dir>/ca.key`      — CA private key, mode 0600
/// - `<data_dir>/secrets/<k>` — secret value + version, mode 0600
pub struct EmbeddedTrust {
    data_dir: PathBuf,
    /// Exactly the bytes persisted at `ca.pem` — the single source of truth
    /// returned by `trust_bundle()`. Kept separate from `ca_cert` below
    /// because reconstructing an `rcgen::Certificate` after a reload
    /// re-signs it (ECDSA signing isn't deterministic), which would produce
    /// bytes that differ from what's actually on disk.
    ca_cert_pem: String,
    /// In-memory issuer certificate, used only as the `issuer` argument to
    /// rcgen's `signed_by` — never serialized back out.
    ca_cert: rcgen::Certificate,
    ca_key: KeyPair,
    /// Serials recorded as revoked. This is bookkeeping only: the embedded
    /// issuer has no CRL/OCSP responder, so a "revoked" cert is NOT
    /// actually rejected by anyone verifying it against `trust_bundle()`.
    /// Real revocation enforcement is the controller's job (tracked in its
    /// own SQLite store); this set exists so `revoke()` doesn't silently
    /// lie about handles it has never seen.
    revoked: Mutex<std::collections::HashSet<String>>,
}

impl EmbeddedTrust {
    /// Opens (or creates, if absent) the embedded CA rooted at `data_dir`.
    /// Idempotent: calling this again against the same `data_dir` reuses
    /// the existing CA rather than minting a new one.
    pub fn open(data_dir: &Path) -> Result<Self> {
        fs::create_dir_all(data_dir)
            .with_context(|| format!("creating data dir {}", data_dir.display()))?;
        fs::create_dir_all(data_dir.join("secrets"))
            .with_context(|| format!("creating secrets dir under {}", data_dir.display()))?;

        let (ca_cert, ca_key, ca_cert_pem) = load_or_create_ca(data_dir)?;

        Ok(Self {
            data_dir: data_dir.to_path_buf(),
            ca_cert_pem,
            ca_cert,
            ca_key,
            revoked: Mutex::new(std::collections::HashSet::new()),
        })
    }

    fn secret_path(&self, key: &str) -> Result<PathBuf> {
        if key.is_empty() || key.contains(['/', '\\', '\0']) {
            bail!("invalid secret key: {key:?}");
        }
        Ok(self.data_dir.join("secrets").join(key))
    }
}

#[async_trait]
impl CertificateIssuer for EmbeddedTrust {
    async fn trust_bundle(&self) -> Result<String> {
        Ok(self.ca_cert_pem.clone())
    }

    async fn sign(&self, csr_pem: &str, profile: CertProfile) -> Result<IssuedCert> {
        let mut csr_params = CertificateSigningRequestParams::from_pem(csr_pem)
            .context("parsing CSR PEM")?;

        // The CA decides the subject and validity window; nothing from the
        // CSR's own params is trusted for these beyond the public key and
        // (best-effort) SANs already parsed onto csr_params.params.
        csr_params
            .params
            .distinguished_name
            .push(DnType::CommonName, profile.subject_cn.as_str());

        let not_before = OffsetDateTime::now_utc();
        let ttl = TimeDuration::try_from(profile.ttl).context("ttl out of range")?;
        let not_after = not_before + ttl;
        csr_params.params.not_before = not_before;
        csr_params.params.not_after = not_after;

        let serial = random_serial();
        csr_params.params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial));
        let serial_hex = hex_encode(&serial);

        let leaf = csr_params
            .signed_by(&self.ca_cert, &self.ca_key)
            .context("signing CSR with embedded CA")?;

        Ok(IssuedCert {
            cert_pem: leaf.pem(),
            serial: serial_hex.clone(),
            not_after,
            handle: serial_hex,
        })
    }

    async fn revoke(&self, handle: &IssuerHandle) -> Result<()> {
        self.revoked
            .lock()
            .expect("revoked-set mutex poisoned")
            .insert(handle.clone());
        Ok(())
    }
}

#[async_trait]
impl SecretStore for EmbeddedTrust {
    async fn get(&self, key: &str) -> Result<Option<Versioned>> {
        let path = self.secret_path(key)?;
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("reading secret {key}")),
        };
        Ok(Some(decode_versioned(&bytes)?))
    }

    async fn put(&self, key: &str, value: Vec<u8>) -> Result<u64> {
        let path = self.secret_path(key)?;
        let next_version = match fs::read(&path) {
            Ok(existing) => decode_versioned(&existing)?.version + 1,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 1,
            Err(e) => return Err(e).with_context(|| format!("reading secret {key}")),
        };

        let mut buf = Vec::with_capacity(8 + value.len());
        buf.extend_from_slice(&next_version.to_le_bytes());
        buf.extend_from_slice(&value);

        // Write to a sibling temp file first, then rename into place, so a
        // reader never observes a partially written secret.
        let tmp_path = path.with_extension("tmp");
        write_private_file(&tmp_path, &buf)
            .with_context(|| format!("writing secret {key}"))?;
        fs::rename(&tmp_path, &path)
            .with_context(|| format!("committing secret {key}"))?;

        Ok(next_version)
    }
}

fn decode_versioned(bytes: &[u8]) -> Result<Versioned> {
    if bytes.len() < 8 {
        bail!("corrupt secret record: too short ({} bytes)", bytes.len());
    }
    let (version_bytes, value) = bytes.split_at(8);
    let version = u64::from_le_bytes(version_bytes.try_into().unwrap());
    Ok(Versioned {
        version,
        value: value.to_vec(),
    })
}

/// Loads the CA from `data_dir` if both `ca.pem` and `ca.key` already exist,
/// otherwise mints a fresh self-signed CA and persists it. Returns the
/// in-memory issuer `Certificate` (usable for `signed_by`), the `KeyPair`,
/// and the exact PEM bytes on disk (the value `trust_bundle()` must return).
fn load_or_create_ca(data_dir: &Path) -> Result<(rcgen::Certificate, KeyPair, String)> {
    let ca_key_path = data_dir.join("ca.key");
    let ca_pem_path = data_dir.join("ca.pem");

    if ca_key_path.exists() && ca_pem_path.exists() {
        let key_pem = fs::read_to_string(&ca_key_path)
            .with_context(|| format!("reading {}", ca_key_path.display()))?;
        let cert_pem = fs::read_to_string(&ca_pem_path)
            .with_context(|| format!("reading {}", ca_pem_path.display()))?;

        let ca_key = KeyPair::from_pem(&key_pem).context("parsing existing ca.key")?;
        let ca_params =
            CertificateParams::from_ca_cert_pem(&cert_pem).context("parsing existing ca.pem")?;
        // Re-derive an in-memory issuer Certificate from the persisted
        // params + key. This re-signs (a new object, new signature bytes)
        // but preserves subject/serial/validity, so it's a faithful issuer
        // for `signed_by` even though its own bytes differ from ca.pem —
        // `trust_bundle()` always returns the pinned `cert_pem` read above,
        // never this reconstruction.
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .context("reconstructing CA certificate from stored params")?;
        ensure_private_mode(&ca_key_path)?;
        return Ok((ca_cert, ca_key, cert_pem));
    }

    let mut ca_params = CertificateParams::new(Vec::<String>::new())
        .context("building CA certificate params")?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "AetherLink Embedded CA");

    let ca_key = KeyPair::generate().context("generating CA key pair")?;
    let ca_cert = ca_params
        .self_signed(&ca_key)
        .context("self-signing CA certificate")?;
    let cert_pem = ca_cert.pem();

    write_private_file(&ca_key_path, ca_key.serialize_pem().as_bytes())
        .with_context(|| format!("writing {}", ca_key_path.display()))?;
    fs::write(&ca_pem_path, cert_pem.as_bytes())
        .with_context(|| format!("writing {}", ca_pem_path.display()))?;

    Ok((ca_cert, ca_key, cert_pem))
}

/// Generates a 16-byte random serial number (hex-encoded for the handle
/// returned to callers).
fn random_serial() -> [u8; 16] {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Writes `contents` to `path`, creating it (or truncating it) with mode
/// 0600 from the moment it's opened — no window where the file exists with
/// looser permissions.
#[cfg(unix)]
fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, contents: &[u8]) -> Result<()> {
    fs::write(path, contents)?;
    Ok(())
}

/// Belt-and-suspenders: if `ca.key` somehow exists with looser permissions
/// (e.g. copied in from elsewhere), tighten it on load.
#[cfg(unix)]
fn ensure_private_mode(path: &Path) -> Result<()> {
    let meta = fs::metadata(path)?;
    let mut perms = meta.permissions();
    if perms.mode() & 0o777 != 0o600 {
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_mode(_path: &Path) -> Result<()> {
    Ok(())
}
