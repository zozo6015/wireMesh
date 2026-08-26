//! Relay identity bootstrap: redeem a `kind = "relay"` enrollment token and
//! write the `ca.pem` / `relay.pem` / `relay.key` layout the relay server
//! (`server_config`) loads from its `certdir` at boot. Run by the K8s
//! operator's enroll init-container before the relay starts.

use anyhow::{anyhow, Context};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Parsed `enroll` flags.
pub struct EnrollArgs {
    pub token: String,
    /// Controller TCP address (`host:port`) the Enrollment RPC listens on.
    pub controller: String,
    /// Path to the controller CA bundle PEM to trust.
    pub ca_path: PathBuf,
    /// Directory the relay identity is written to (the relay's `certdir`).
    pub certdir: PathBuf,
    /// The relay's publicly-advertised `ip:port` (must be a valid IPv4
    /// endpoint — the controller rejects non-IPv4).
    pub endpoint: String,
}

/// Write `bytes` to `path`, mode 0600 (each identity file individually — the
/// private key, the leaf cert, and the CA must all be 0600, matching the
/// deployment note). Re-applies the mode even if the file pre-existed looser.
fn write_0600(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut opts = fs::OpenOptions::new();
    // Do NOT truncate at open. If `path` pre-exists with loose permissions,
    // truncating + writing before the chmod would leave the new private key
    // world-readable for that window. Instead: open, tighten to 0600 FIRST,
    // THEN truncate and write — so the secret content only ever lands in an
    // already-0600 file. (`mode(0o600)` alone only covers freshly-created
    // files; the explicit chmod covers a reused inode.)
    opts.write(true).create(true).truncate(false).mode(0o600);
    let mut f = opts
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    f.set_permissions(fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", path.display()))?;
    f.set_len(0)
        .with_context(|| format!("truncating {}", path.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Whether `certdir` already holds a COMPLETE relay identity — all three of
/// [`IDENTITY_FILES`] present and non-empty. Mirrors the gateway's
/// `Identity::probe` classification:
///
///   * complete → `Ok(true)`: skip (never redeem the token again).
///   * absent, or PARTIAL / empty (a crash between the three writes) →
///     `Ok(false)`: proceed with the real enrollment, which overwrites.
///   * any other IO failure (EACCES/EIO/EISDIR) → `Err`: PROPAGATE. An
///     unreadable-but-possibly-present identity must never be read as "absent"
///     and clobbered by redeeming the single-use token.
pub fn probe_identity(certdir: &Path) -> anyhow::Result<bool> {
    let mut complete = 0usize;
    for name in IDENTITY_FILES {
        let path = certdir.join(name);
        match fs::metadata(&path) {
            // A zero-length file is a half-written identity, not an identity.
            Ok(m) if m.len() > 0 => complete += 1,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e).with_context(|| format!("probing {}", path.display()));
            }
        }
    }
    Ok(complete == IDENTITY_FILES.len())
}

/// Enroll and persist the relay identity.
///
/// **Idempotent**, exactly like `wiremesh-gateway enroll`: if `--certdir`
/// already holds a complete identity ([`probe_identity`]), this is a no-op — it
/// logs a skip and returns `Ok(())` WITHOUT reading the CA or dialing the
/// controller. This is what makes the operator's PVC-backed relay durable: the
/// enroll init-container runs on EVERY pod start, enrolls once into a fresh
/// PVC, and skips on every later start — so a node reboot/upgrade/eviction no
/// longer re-redeems a SPENT single-use token and wedges the pod in
/// `Init:Error`. (A partial identity still proceeds to a real enrollment.)
pub async fn run_enroll(args: EnrollArgs) -> anyhow::Result<()> {
    // MUST come before the CA read and the controller dial so a re-run never
    // redeems a (now spent) single-use token.
    if probe_identity(&args.certdir)? {
        eprintln!(
            "wiremesh-relay: already enrolled (identity present in {}), skipping",
            args.certdir.display()
        );
        return Ok(());
    }

    let ca_pem = fs::read_to_string(&args.ca_path)
        .with_context(|| format!("reading CA bundle {}", args.ca_path.display()))?;

    let out = wiremesh_enroll::enroll(
        &args.controller,
        &ca_pem,
        &args.token,
        &[],
        "",
        &args.endpoint,
        "relay",
    )
    .await
    .context("enrolling relay with the controller")?;

    fs::create_dir_all(&args.certdir)
        .with_context(|| format!("creating {}", args.certdir.display()))?;
    // Tighten the identity dir itself to 0700 (create_dir_all leaves it at
    // the umask default): the three files inside are each 0600, but a
    // world-traversable directory needlessly leaks their names/existence.
    // Matches the packaged StateDirectoryMode=0700 / postinstall chmod.
    fs::set_permissions(&args.certdir, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", args.certdir.display()))?;
    write_0600(&args.certdir.join("ca.pem"), out.ca_bundle_pem.as_bytes())?;
    write_0600(&args.certdir.join("relay.pem"), out.cert_pem.as_bytes())?;
    write_0600(&args.certdir.join("relay.key"), out.key_pem.as_bytes())?;
    eprintln!(
        "wiremesh-relay: enrolled (identity written to {})",
        args.certdir.display()
    );
    Ok(())
}

/// The unix account the packaged systemd unit runs the relay as
/// (`User=wiremesh` in `deploy/packages/systemd/wiremesh-relay.service`).
pub const SERVICE_USER: &str = "wiremesh";

/// The three identity files [`run_enroll`] generates inside `certdir` — also
/// what [`probe_identity`] requires (all three, non-empty) to call an identity
/// complete.
const IDENTITY_FILES: [&str; 3] = ["ca.pem", "relay.pem", "relay.key"];

/// Best-effort handoff of the enrolled identity to the packaged service user —
/// called by the `wiremesh-relay-enroll` BINARY (not by [`run_enroll`], which
/// stays a pure library step for the K8s operator's init-container and the
/// tests).
///
/// Rationale (ops finding 2026-07-27/28, "Relay Finding A",
/// `docs/research/ops-finding-multi-gateway-convergence.md`):
/// `wiremesh-relay-enroll` is documented as a `sudo` step, so the identity
/// files land root-owned 0600 — unreadable by the packaged unit's
/// `User=wiremesh`, which crash-looped on "Permission denied" until the
/// operator chown'd them by hand. When this process can (it's root and the
/// `wiremesh` account exists — i.e. exactly the packaged bare-metal flow),
/// this completes the handoff automatically; otherwise (unprivileged run, a
/// container image without the account, macOS) it prints the exact command
/// to run instead of failing — enrollment itself already succeeded, and a
/// non-systemd deployment may legitimately run the relay as someone else.
/// Shelling out to `chown` follows the project idiom
/// (`ip`/`nft`/`sysctl`/`conntrack` are shelled elsewhere) and sidesteps a
/// uid lookup: `chown`'s own exit status already answers "am I root AND does
/// the user exist".
///
/// SCOPE: chowns ONLY the directory itself and the three known generated
/// identity files ([`IDENTITY_FILES`]) — NOT `-R`. A recursive chown would
/// re-own any unrelated descendants an operator's `--certdir` might contain
/// (e.g. a shared state dir), which is not this tool's business.
pub fn chown_identity_best_effort(certdir: &Path) {
    let target = format!("{SERVICE_USER}:{SERVICE_USER}");
    // The directory plus each generated file that actually exists — never a
    // recursive descent.
    let mut targets: Vec<std::ffi::OsString> = vec![certdir.as_os_str().to_owned()];
    for name in IDENTITY_FILES {
        let p = certdir.join(name);
        if p.exists() {
            targets.push(p.into_os_string());
        }
    }
    let status = std::process::Command::new("chown")
        .arg(&target)
        .args(&targets)
        .status();
    match status {
        Ok(s) if s.success() => {
            eprintln!(
                "wiremesh-relay: identity chowned to {target} (the packaged systemd unit runs \
                 User={SERVICE_USER})"
            );
        }
        _ => {
            let files = IDENTITY_FILES
                .iter()
                .map(|f| certdir.join(f).display().to_string())
                .collect::<Vec<_>>()
                .join(" ");
            eprintln!(
                "wiremesh-relay: NOTE identity left owned by the invoking user. If the relay \
                 runs as the packaged systemd unit (User={SERVICE_USER}), run: \
                 chown {target} {} {files}",
                certdir.display()
            );
        }
    }
}

/// The binary name reported by `--version` / the usage synopsis. The enroll
/// tool ships as its own binary (`wiremesh-relay-enroll`) even though it lives
/// in the `wiremesh-relay` crate, so its `env!("CARGO_PKG_VERSION")` is the
/// relay crate's version.
const ENROLL_BIN: &str = "wiremesh-relay-enroll";

/// Pre-parse CLI intent for the `wiremesh-relay-enroll` binary — the
/// live-deployment DIAGNOSTICS feature (plan
/// `docs/superpowers/plans/2026-07-28-cli-help-version.md`). Lives beside
/// [`parse_args`] so the bin can intercept `-h`/`--help`/`-V`/`--version`
/// BEFORE `parse_args`' required-flag validation runs. INFALLIBLE by design.
pub enum CliAction {
    /// `-h`/`--help` seen: the fully rendered usage manual.
    Help(String),
    /// `-V`/`--version` seen: the rendered "`<bin> <version>`" line.
    Version(String),
    /// Neither: proceed with the normal `parse_args`/`run_enroll` path.
    Run,
}

/// Decide the [`CliAction`]. Unlike the controller/gateway/operator variants,
/// this receives the args iterator ALREADY positioned at `argv[1..]` — the bin
/// hands it `std::env::args().skip(1)`, matching [`parse_args`] — so it does
/// NOT skip a leading token. Help wins if both flags appear.
pub fn cli_action(args: impl Iterator<Item = String>) -> CliAction {
    let mut help = false;
    let mut version = false;
    for tok in args {
        match tok.as_str() {
            "-h" | "--help" => help = true,
            "-V" | "--version" => version = true,
            _ => {}
        }
    }
    if help {
        CliAction::Help(enroll_manual())
    } else if version {
        CliAction::Version(format!("{ENROLL_BIN} {}", env!("CARGO_PKG_VERSION")))
    } else {
        CliAction::Run
    }
}

/// The full usage manual: synopsis, description, every flag (placeholder +
/// required/optional + default + description), the deployment note, and a
/// concrete example. Descriptions mirror [`EnrollArgs`] / [`parse_args`].
fn enroll_manual() -> String {
    format!(
        "\
{ENROLL_BIN} {version}
Relay identity bootstrap: redeem a kind=relay enrollment token and write the
ca.pem / relay.pem / relay.key layout the relay server loads from its certdir.
Run once (the operator's enroll init-container, or a bare-metal sudo step)
before the relay starts. On the packaged host it best-effort chowns the
identity to the User=wiremesh service account.

USAGE (supply the token inline with --token):
    {ENROLL_BIN} --token <token> --controller <host:port> --ca <path> \\
                         --certdir <path> --endpoint <ip:port>

USAGE (read the token from a file with --token-file):
    {ENROLL_BIN} --token-file <path> --controller <host:port> --ca <path> \\
                         --certdir <path> --endpoint <ip:port>

    {ENROLL_BIN} --help
    {ENROLL_BIN} --version

FLAGS:
    --token <token>          (required*) Enrollment token to redeem. *Exactly
                             one of --token or --token-file.
    --token-file <path>      (required*) Read the token from a file instead
                             (keeps it out of argv; the K8s init-container
                             mounts it).
    --controller <host:port> (required) Controller Enrollment RPC address.
    --ca <path>              (required) Controller CA bundle PEM to trust.
    --certdir <path>         (required) Directory the relay identity
                             (ca.pem/relay.pem/relay.key, each mode 0600) is
                             written to.
    --endpoint <ip:port>     (required) The relay's publicly-advertised IPv4
                             endpoint (the controller rejects non-IPv4).
    -h, --help               Print this manual and exit.
    -V, --version            Print the version and exit.

DEPLOYMENT:
    The packaged systemd flow runs this as a sudo step before starting
    wiremesh-relay; RELAY_ARGS in /etc/wiremesh/relay.env then configures the
    relay service itself. The K8s operator runs it as an enroll init-container.

EXAMPLE:
    {ENROLL_BIN} --token-file /run/token --controller controller.example.com:9400 \\
                         --ca /etc/wiremesh/ca.pem --certdir /var/lib/wiremesh \\
                         --endpoint 203.0.113.7:4443
",
        version = env!("CARGO_PKG_VERSION")
    )
}

/// Parse the `enroll` flags from the args iterator (positioned past argv[0]).
pub fn parse_args(mut it: impl Iterator<Item = String>) -> anyhow::Result<EnrollArgs> {
    let mut token = None;
    let mut token_file = None;
    let mut controller = None;
    let mut ca = None;
    let mut certdir = None;
    let mut endpoint = None;
    while let Some(flag) = it.next() {
        let mut val = || {
            it.next()
                .ok_or_else(|| anyhow!("flag {flag} needs a value"))
        };
        match flag.as_str() {
            "--token" => token = Some(val()?),
            // `--token-file` avoids exposing the token in argv / a shell command
            // substitution (the K8s enroll init-container mounts it as a file).
            "--token-file" => token_file = Some(PathBuf::from(val()?)),
            "--controller" => controller = Some(val()?),
            "--ca" => ca = Some(PathBuf::from(val()?)),
            "--certdir" => certdir = Some(PathBuf::from(val()?)),
            "--endpoint" => endpoint = Some(val()?),
            other => return Err(anyhow!("unknown enroll flag {other}")),
        }
    }
    let token = match (token, token_file) {
        (Some(t), None) => t,
        (None, Some(f)) => std::fs::read_to_string(&f)
            .with_context(|| format!("reading token file {}", f.display()))?
            .trim()
            .to_string(),
        (None, None) => return Err(anyhow!("one of --token or --token-file is required")),
        (Some(_), Some(_)) => {
            return Err(anyhow!("--token and --token-file are mutually exclusive"))
        }
    };
    Ok(EnrollArgs {
        token,
        controller: controller.ok_or_else(|| anyhow!("--controller required"))?,
        ca_path: ca.ok_or_else(|| anyhow!("--ca required"))?,
        certdir: certdir.ok_or_else(|| anyhow!("--certdir required"))?,
        endpoint: endpoint.ok_or_else(|| anyhow!("--endpoint required"))?,
    })
}
