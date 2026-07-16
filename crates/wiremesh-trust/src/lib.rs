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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration as StdDuration;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName, DnType,
    IsCa, KeyPair,
};
use time::{Duration as TimeDuration, OffsetDateTime};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

/// Minimum leaf TTL the embedded issuer will grant, per the master spec
/// §3.4 (manager-owned rotation: min granted TTL 24h, refused below).
/// [`EmbeddedTrust::sign`] returns `Err` for any `profile.ttl` below this
/// floor rather than silently issuing a shorter-lived leaf.
pub const MIN_TTL: StdDuration = StdDuration::from_secs(24 * 3600);

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
    /// Serializes the read-modify-write-rename in `put` so concurrent writes
    /// (even to the same key) compute strictly-increasing versions instead
    /// of racing on read-existing+1. A store-wide lock is more than enough
    /// for a local-disk embedded default. No `.await` is held across it, so
    /// the guard never crosses a suspend point.
    put_lock: Mutex<()>,
    /// Per-write uniquifier for temp filenames, so two puts (to any keys)
    /// never share a temp path. Combined with the pid this is unique across
    /// processes sharing the dir too.
    tmp_counter: AtomicU64,
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
            put_lock: Mutex::new(()),
            tmp_counter: AtomicU64::new(0),
        })
    }

    fn secret_path(&self, key: &str) -> Result<PathBuf> {
        if key.is_empty() || key.contains(['/', '\\', '\0']) {
            bail!("invalid secret key: {key:?}");
        }
        Ok(self.data_dir.join("secrets").join(key))
    }

    /// Issues a leaf certificate for the controller's OWN TLS-server
    /// identity (used to serve the Enrollment/Sync TCP port), keeping the
    /// caller-supplied subject alternative names.
    ///
    /// This is deliberately a separate, non-trait method from
    /// [`CertificateIssuer::sign`]: `sign()` exists to answer a CSR an
    /// *external* gateway/relay generated, and hardens itself by discarding
    /// every SAN/extension the CSR asked for — the CA alone decides a
    /// gateway's identity. Here there is no external CSR to distrust: the
    /// controller process is asking its own embedded CA to vouch for its own
    /// listening address, so the SANs it requests (e.g. `127.0.0.1`) are
    /// exactly what the resulting server cert must present for TLS
    /// hostname/IP verification to succeed. Returns `(cert_pem, key_pem)`;
    /// the private key is generated fresh here and handed back directly
    /// (not persisted to disk by this method) since the caller needs it
    /// in-hand to configure its TLS listener.
    pub fn issue_server_identity(
        &self,
        common_name: &str,
        subject_alt_names: Vec<String>,
        ttl: StdDuration,
    ) -> Result<(String, String)> {
        let key = KeyPair::generate().context("generating server key pair")?;
        let mut params = CertificateParams::new(subject_alt_names)
            .context("building server cert SAN params")?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, common_name);
        params.distinguished_name = dn;
        params.is_ca = IsCa::NoCa;

        let not_before = OffsetDateTime::now_utc();
        let ttl = TimeDuration::try_from(ttl).context("ttl out of range")?;
        params.not_before = not_before;
        params.not_after = not_before + ttl;
        params.serial_number = Some(rcgen::SerialNumber::from_slice(&random_serial()));

        let cert = params
            .signed_by(&key, &self.ca_cert, &self.ca_key)
            .context("signing server identity cert")?;

        Ok((cert.pem(), key.serialize_pem()))
    }
}

#[async_trait]
impl CertificateIssuer for EmbeddedTrust {
    async fn trust_bundle(&self) -> Result<String> {
        Ok(self.ca_cert_pem.clone())
    }

    async fn sign(&self, csr_pem: &str, profile: CertProfile) -> Result<IssuedCert> {
        // Provider-contract invariant (master spec §3.4, manager-owned
        // rotation): min granted TTL is 24h, refused below. Reject before
        // touching the CSR or minting a serial, so a too-short request never
        // gets partway through issuance.
        if profile.ttl < MIN_TTL {
            bail!(
                "requested TTL below 24h minimum: {:?} < {:?}",
                profile.ttl,
                MIN_TTL
            );
        }

        let csr = CertificateSigningRequestParams::from_pem(csr_pem)
            .context("parsing CSR PEM")?;

        // The CA fully controls leaf identity: take ONLY the subject public
        // key from the CSR and rebuild the leaf's parameters from scratch.
        // Any subject DN entries, SANs, key-usages, or extensions the CSR
        // requested are discarded — a gateway cannot smuggle a CN, SAN, or
        // extension of its choosing into the issued cert.
        let public_key = csr.public_key;
        let mut params = CertificateParams::new(Vec::<String>::new())
            .context("building leaf certificate params")?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, profile.subject_cn.as_str());
        params.distinguished_name = dn;
        params.subject_alt_names.clear();
        params.key_usages.clear();
        params.extended_key_usages.clear();
        params.custom_extensions.clear();
        params.is_ca = IsCa::NoCa;

        let not_before = OffsetDateTime::now_utc();
        let ttl = TimeDuration::try_from(profile.ttl).context("ttl out of range")?;
        let not_after = not_before + ttl;
        params.not_before = not_before;
        params.not_after = not_after;

        let serial = random_serial();
        params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial));
        let serial_hex = hex_encode(&serial);

        let leaf = params
            .signed_by(&public_key, &self.ca_cert, &self.ca_key)
            .context("signing leaf with embedded CA")?;

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

        // Serialize the whole read-modify-write-rename so concurrent puts
        // can't read the same "existing version" and both write version N+1.
        // No `.await` inside this critical section, so the std guard never
        // crosses a suspend point.
        let _guard = self.put_lock.lock().expect("put-lock mutex poisoned");

        let next_version = match fs::read(&path) {
            Ok(existing) => decode_versioned(&existing)?.version + 1,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 1,
            Err(e) => return Err(e).with_context(|| format!("reading secret {key}")),
        };

        let mut buf = Vec::with_capacity(8 + value.len());
        buf.extend_from_slice(&next_version.to_le_bytes());
        buf.extend_from_slice(&value);

        // Write to a temp file, then atomic-rename into place, so a reader
        // never observes a partially written secret. The temp name is unique
        // per write — it appends `.<pid>.<counter>.tmp` to the FULL sanitized
        // filename, so distinct dotted keys (`gw1.wgkey` vs `gw1.token`) get
        // distinct temp paths instead of both collapsing onto `gw1.tmp` the
        // way `Path::with_extension("tmp")` did.
        let uniq = self.tmp_counter.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let leaf_name = path
            .file_name()
            .expect("secret path always has a filename")
            .to_string_lossy();
        let tmp_path = path.with_file_name(format!("{leaf_name}.{pid}.{uniq}.tmp"));

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

    let key_exists = ca_key_path.exists();
    let cert_exists = ca_pem_path.exists();

    if key_exists != cert_exists {
        bail!(
            "incomplete CA state: expected both {} and {} to exist (or neither); \
             found only {}. Refusing to regenerate the CA, which would silently \
             rotate the trust anchor and invalidate all enrolled certificates.",
            ca_key_path.display(),
            ca_pem_path.display(),
            if key_exists {
                ca_key_path.display()
            } else {
                ca_pem_path.display()
            }
        );
    }

    if key_exists && cert_exists {
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
