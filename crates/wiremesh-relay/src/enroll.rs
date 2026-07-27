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

/// Enroll and persist the relay identity.
pub async fn run_enroll(args: EnrollArgs) -> anyhow::Result<()> {
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

/// Best-effort handoff of the enrolled identity to the packaged service
/// user — called by the `wiremesh-relay-enroll` BINARY (not by
/// [`run_enroll`], which stays a pure library step for the K8s operator's
/// init-container and the tests).
///
/// Rationale (ops finding 2026-07-27/28, "Relay Finding A",
/// `docs/research/ops-finding-multi-gateway-convergence.md`):
/// `wiremesh-relay-enroll` is documented as a `sudo` step, so the identity
/// files land root-owned 0600 — unreadable by the packaged unit's
/// `User=wiremesh`, which crash-looped on "Permission denied" until the
/// operator chown'd them by hand. When this process can (it's root and the
/// `wiremesh` account exists — i.e. exactly the packaged bare-metal flow),
/// `chown -R wiremesh:wiremesh <certdir>` completes the handoff
/// automatically; otherwise (unprivileged run, a container image without
/// the account, macOS) it prints the exact command to run instead of
/// failing — enrollment itself already succeeded, and a non-systemd
/// deployment may legitimately run the relay as someone else. Shelling out
/// to `chown` follows the project idiom (`ip`/`nft`/`sysctl`/`conntrack`
/// are shelled elsewhere) and sidesteps a uid lookup: `chown`'s own exit
/// status already answers "am I root AND does the user exist".
pub fn chown_identity_best_effort(certdir: &Path) {
    let target = format!("{SERVICE_USER}:{SERVICE_USER}");
    let status = std::process::Command::new("chown")
        .arg("-R")
        .arg(&target)
        .arg(certdir)
        .status();
    match status {
        Ok(s) if s.success() => {
            eprintln!(
                "wiremesh-relay: identity chowned to {target} (the packaged systemd unit runs \
                 User={SERVICE_USER})"
            );
        }
        _ => {
            eprintln!(
                "wiremesh-relay: NOTE identity left owned by the invoking user. If the relay \
                 runs as the packaged systemd unit (User={SERVICE_USER}), run: \
                 chown -R {target} {}",
                certdir.display()
            );
        }
    }
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
        let mut val = || it.next().ok_or_else(|| anyhow!("flag {flag} needs a value"));
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
        (Some(_), Some(_)) => return Err(anyhow!("--token and --token-file are mutually exclusive")),
    };
    Ok(EnrollArgs {
        token,
        controller: controller.ok_or_else(|| anyhow!("--controller required"))?,
        ca_path: ca.ok_or_else(|| anyhow!("--ca required"))?,
        certdir: certdir.ok_or_else(|| anyhow!("--certdir required"))?,
        endpoint: endpoint.ok_or_else(|| anyhow!("--endpoint required"))?,
    })
}
