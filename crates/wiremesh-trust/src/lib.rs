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
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, IsCa, KeyPair,
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
    /// Subject Alternative Names the CA has decided to stamp onto the issued
    /// leaf — e.g. `["relay"]` for a relay's QUIC server cert, so that
    /// rustls hostname verification (`wiremesh_relay::RELAY_SERVER_NAME`)
    /// succeeds against it. **The caller (controller service code), not the
    /// CSR, decides this list** — [`EmbeddedTrust::sign`] never reads SANs
    /// out of the CSR itself (see that method's doc comment); this field is
    /// the one and only source of truth for a leaf's SANs. An ordinary
    /// gateway cert has no need of a SAN (gateways are mTLS *clients*,
    /// verified by chain, not by hostname) and passes an empty `Vec` here.
    pub subject_alt_names: Vec<String>,
    /// A caller-chosen serial number to stamp onto the leaf, or `None` to let
    /// the issuer mint a fresh random one (the default for essentially every
    /// caller).
    ///
    /// This exists for exactly one caller: gateway enrollment
    /// (`services::enrollment`), which must record the cert's serial into its
    /// single-use-token transaction *before* it knows the gateway_id it needs
    /// to embed in the leaf's `gw-<gateway_id>` SAN (the relay's registration
    /// binding — Cycle 4c). Pre-generating the serial (via
    /// [`random_serial`]) lets that transaction commit the certificate row
    /// atomically with the token spend (so the cert stays revocable), and the
    /// SAME serial is then stamped onto the leaf signed afterwards. `None`
    /// preserves the historic behavior for all other callers.
    pub serial: Option<[u8; 16]>,
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
        Self::open_with_legacy_dir(data_dir, Path::new(LEGACY_SHARED_DATA_DIR))
    }

    /// Same as [`EmbeddedTrust::open`], with the directory that the re-mint
    /// guard probes for a pre-existing CA injected rather than hardcoded.
    ///
    /// Exists purely so that guard is testable: it keys on an absolute
    /// production path ([`LEGACY_SHARED_DATA_DIR`]), and a test must be able
    /// to point it at a temp dir instead of depending on — or worse, being
    /// silently disabled by — whatever happens to exist at that path on the
    /// machine running the suite. Injection rather than a `cfg(test)` switch
    /// or an env var: integration tests link this crate built WITHOUT
    /// `cfg(test)`, and a process-global override would race under the
    /// parallel test harness.
    pub fn open_with_legacy_dir(data_dir: &Path, legacy_dir: &Path) -> Result<Self> {
        fs::create_dir_all(data_dir)
            .with_context(|| format!("creating data dir {}", data_dir.display()))?;
        fs::create_dir_all(data_dir.join("secrets"))
            .with_context(|| format!("creating secrets dir under {}", data_dir.display()))?;

        let (ca_cert, ca_key, ca_cert_pem) = load_or_create_ca(data_dir, legacy_dir)?;

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
        let mut params =
            CertificateParams::new(subject_alt_names).context("building server cert SAN params")?;
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

        let csr = CertificateSigningRequestParams::from_pem(csr_pem).context("parsing CSR PEM")?;

        // The CA fully controls leaf identity: take ONLY the subject public
        // key from the CSR and rebuild the leaf's parameters from scratch.
        // Any subject DN entries, SANs, key-usages, or extensions the CSR
        // requested are discarded — a gateway cannot smuggle a CN, SAN, or
        // extension of its choosing into the issued cert. The ONLY SANs that
        // ever land on the leaf are `profile.subject_alt_names` — chosen by
        // the CALLER (controller service code), never read from the CSR
        // itself. This is how a relay's QUIC server cert gets its required
        // `"relay"` SAN (see `services::enrollment`'s relay branch) while an
        // ordinary gateway cert (an mTLS client cert, verified by chain, not
        // hostname) still gets none.
        let public_key = csr.public_key;
        let mut params = CertificateParams::new(profile.subject_alt_names.clone())
            .context("building leaf certificate params")?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, profile.subject_cn.as_str());
        params.distinguished_name = dn;
        params.key_usages.clear();
        params.extended_key_usages.clear();
        params.custom_extensions.clear();
        params.is_ca = IsCa::NoCa;

        let not_before = OffsetDateTime::now_utc();
        let ttl = TimeDuration::try_from(profile.ttl).context("ttl out of range")?;
        let not_after = not_before + ttl;
        params.not_before = not_before;
        params.not_after = not_after;

        // Use the caller-supplied serial when present (gateway enrollment
        // pre-generates it so it can record the cert row atomically with the
        // single-use token spend before the leaf is signed — see
        // `CertProfile::serial`); otherwise mint a fresh random one.
        let serial = profile.serial.unwrap_or_else(random_serial);
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

        write_private_file(&tmp_path, &buf).with_context(|| format!("writing secret {key}"))?;
        fs::rename(&tmp_path, &path).with_context(|| format!("committing secret {key}"))?;

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

/// The pre-split shared state directory that the controller, the relay
/// certdir default, the container image and the operator PVC all used.
///
/// [`load_or_create_ca`] probes it before minting so a packaging or
/// configuration mistake cannot silently rotate the fabric's trust anchor.
pub const LEGACY_SHARED_DATA_DIR: &str = "/var/lib/wiremesh";

/// Loads the CA from `data_dir` if both `ca.pem` and `ca.key` already exist,
/// otherwise mints a fresh self-signed CA and persists it. Returns the
/// in-memory issuer `Certificate` (usable for `signed_by`), the `KeyPair`,
/// and the exact PEM bytes on disk (the value `trust_bundle()` must return).
///
/// `legacy_dir` is the directory checked for a pre-existing CA before
/// minting — [`LEGACY_SHARED_DATA_DIR`] in production, a temp dir under test
/// (see [`EmbeddedTrust::open_with_legacy_dir`]).
fn load_or_create_ca(
    data_dir: &Path,
    legacy_dir: &Path,
) -> Result<(rcgen::Certificate, KeyPair, String)> {
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

    // ---- Everything below this line is the MINT path, and only the mint
    // path. The two branches above are exhaustive over "a CA exists here":
    // unequal existence bailed, both-exist loaded and returned. So the
    // invariant `!key_exists && !cert_exists` holds from here on by control
    // flow, not by a condition anyone has to remember to re-state.
    //
    // That placement is the point, and it is load-bearing: an earlier
    // revision put this probe ABOVE the load branch, where it ran
    // unconditionally, and it bailed on every host that had already been
    // split (own CA present, legacy ca.key still lying around) — turning the
    // guard into the very outage it exists to prevent, and emitting a "no CA
    // in {data_dir}" message that was plainly false. Keep the probe here.
    debug_assert!(
        !key_exists && !cert_exists,
        "the legacy-CA probe must be reachable only when data_dir has no CA of its own"
    );

    // "No CA here" is genuinely ambiguous: it is the normal first boot of a
    // NEW fabric, and it is also exactly what a controller sees when a
    // package upgrade, a unit override or a typo points WIREMESH_DATA_DIR
    // somewhere the state is not. `data_dir` alone cannot tell them apart,
    // and guessing "new fabric" the second way mints a fresh trust anchor and
    // invalidates every enrolled gateway and relay — the outage class that
    // turned one bad `chown` in a postinstall into a fabric-wide incident.
    // Probing the one path WireMesh has historically used disambiguates it.
    // Keyed on `ca.key`, NOT `ca.pem`: a legacy relay identity is ca.pem +
    // relay.pem + relay.key in that same shared directory, so ca.pem alone
    // would false-positive on a relay-only host.
    //
    // The `data_dir != legacy_dir` clause is UNREACHABLE as a decision: we
    // have just proved `data_dir/ca.key` does not exist, so when the two
    // paths denote the same directory the legacy probe IS that same check and
    // cannot succeed. NO TEST CAN DISCRIMINATE IT — forcing the clause to
    // `true` leaves the whole suite green, which has been verified
    // empirically, so do not assume the k8s/Docker fresh-PVC shape (where
    // `data_dir` IS the legacy path and an empty volume must still mint) is
    // protected by this clause; it is protected by that unreachability. The
    // clause is kept as cheap insurance for the day the two probes diverge —
    // point the legacy side at `controller.db` instead, say, and it becomes
    // live and load-bearing — and as documentation of the intent. Plain
    // `Path` comparison is component-wise, so trailing slashes and `.`
    // components already match; deliberately not `canonicalize`, which fails
    // on a non-existent directory (the common case) for no benefit here.
    //
    // The probe is a `metadata` call, NOT `Path::exists()`. `exists()` is
    // `metadata().is_ok()`, so it answers "no CA here" to EVERY error — most
    // importantly `EACCES`, which is what a `User=wiremesh` controller gets
    // for anything inside a root-owned 0700 `/var/lib/wiremesh`. That turned
    // the guard silently off in precisely the situation it was written for:
    // an operator who runs the `chown root:root /var/lib/wiremesh` from
    // docs/install.md while control-plane state is still in there locks the
    // controller out of its own CA, and a guard that reads "locked out" as
    // "absent" would then mint a replacement and invalidate the fabric. A
    // controller that CANNOT TELL must refuse; only a definite `NotFound` is
    // permission to mint.
    if data_dir != legacy_dir {
        let legacy_key = legacy_dir.join("ca.key");
        // Stat the directory first, so the overwhelmingly common "this host
        // never had a shared dir" case is a clean, silent `NotFound` and the
        // stricter file-level probe below only ever runs against a directory
        // that actually exists.
        let legacy_dir_present = match fs::metadata(legacy_dir) {
            Ok(md) => md.is_dir(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => bail!(
                "cannot determine whether a CA exists at {}: {} while reading {}. Refusing to \
                 generate a CA in {} without knowing: if that directory holds a WireMesh CA, \
                 minting here would silently rotate the trust anchor and invalidate every \
                 enrolled certificate. Make {} readable to this process, or point \
                 WIREMESH_DATA_DIR at the data dir that already holds the CA.",
                legacy_dir.display(),
                e,
                legacy_dir.display(),
                data_dir.display(),
                legacy_dir.display()
            ),
        };

        let legacy_key_present = if legacy_dir_present {
            match fs::metadata(&legacy_key) {
                Ok(_) => true,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
                Err(e) => bail!(
                    "cannot determine whether a CA exists at {}: {}. Refusing to generate a CA \
                     in {} without knowing: if {} exists, minting here would silently rotate \
                     the trust anchor and invalidate every enrolled certificate.\n\
                     If {} is a CO-LOCATED GATEWAY's state directory and holds no controller \
                     CA, grant this process search access to it — `sudo chmod o+x {}` is \
                     enough, and leaks nothing: the directory still cannot be listed and its \
                     0600 files still cannot be read.\n\
                     If it does hold your control-plane state, point WIREMESH_DATA_DIR at it \
                     instead of {}.",
                    legacy_key.display(),
                    e,
                    data_dir.display(),
                    legacy_key.display(),
                    legacy_dir.display(),
                    legacy_dir.display(),
                    data_dir.display()
                ),
            }
        } else {
            false
        };

        if legacy_key_present {
            bail!(
                "no CA in {}, but an existing WireMesh CA is present at {}. Refusing to \
                 regenerate the CA, which would silently rotate the trust anchor and \
                 invalidate all enrolled certificates. Either set WIREMESH_DATA_DIR to {}; \
                 or — with the controller STOPPED — move ca.pem, ca.key, controller.db and \
                 secrets/ into {} and start it again; or, if that old fabric is retired and \
                 every gateway and relay will be re-enrolled, delete {} to allow a new CA \
                 to be generated here.",
                data_dir.display(),
                legacy_key.display(),
                legacy_dir.display(),
                data_dir.display(),
                legacy_key.display()
            );
        }
    }

    let mut ca_params =
        CertificateParams::new(Vec::<String>::new()).context("building CA certificate params")?;
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
/// returned to callers). Uses the OS CSPRNG directly (`OsRng`) rather than
/// the thread-local `rand::thread_rng()` — this value ends up in
/// certificate metadata, so it's crypto-adjacent key material (#8).
///
/// Exposed (`pub`) so a caller that needs to pre-commit a certificate's
/// serial before signing the leaf (gateway enrollment — see
/// [`CertProfile::serial`]) generates it with exactly the same CSPRNG and
/// width the issuer would have used, then passes it back in via
/// `CertProfile::serial`.
pub fn random_serial() -> [u8; 16] {
    use rand::{rngs::OsRng, RngCore};
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Validates that `csr_pem` parses as a PEM-encoded PKCS#10 CSR, without
/// signing anything. Gateway enrollment (Cycle 4c) signs the leaf *after* its
/// single-use-token transaction commits — so it calls this up front to reject
/// a malformed CSR (`Err`) *before* the token is spent, preserving the
/// invariant that a bad request never consumes a single-use token (the
/// historic sign-before-commit order gave this for free).
pub fn validate_csr_pem(csr_pem: &str) -> Result<()> {
    CertificateSigningRequestParams::from_pem(csr_pem)
        .map(|_| ())
        .context("parsing CSR PEM")
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
