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
    opts.write(true).create(true).truncate(true).mode(0o600);
    let mut f = opts
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    f.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    f.set_permissions(fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", path.display()))?;
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
    write_0600(&args.certdir.join("ca.pem"), out.ca_bundle_pem.as_bytes())?;
    write_0600(&args.certdir.join("relay.pem"), out.cert_pem.as_bytes())?;
    write_0600(&args.certdir.join("relay.key"), out.key_pem.as_bytes())?;
    eprintln!(
        "wiremesh-relay: enrolled (identity written to {})",
        args.certdir.display()
    );
    Ok(())
}

/// Parse the `enroll` flags from the args iterator (positioned past argv[0]).
pub fn parse_args(mut it: impl Iterator<Item = String>) -> anyhow::Result<EnrollArgs> {
    let mut token = None;
    let mut controller = None;
    let mut ca = None;
    let mut certdir = None;
    let mut endpoint = None;
    while let Some(flag) = it.next() {
        let mut val = || it.next().ok_or_else(|| anyhow!("flag {flag} needs a value"));
        match flag.as_str() {
            "--token" => token = Some(val()?),
            "--controller" => controller = Some(val()?),
            "--ca" => ca = Some(PathBuf::from(val()?)),
            "--certdir" => certdir = Some(PathBuf::from(val()?)),
            "--endpoint" => endpoint = Some(val()?),
            other => return Err(anyhow!("unknown enroll flag {other}")),
        }
    }
    Ok(EnrollArgs {
        token: token.ok_or_else(|| anyhow!("--token required"))?,
        controller: controller.ok_or_else(|| anyhow!("--controller required"))?,
        ca_path: ca.ok_or_else(|| anyhow!("--ca required"))?,
        certdir: certdir.ok_or_else(|| anyhow!("--certdir required"))?,
        endpoint: endpoint.ok_or_else(|| anyhow!("--endpoint required"))?,
    })
}
