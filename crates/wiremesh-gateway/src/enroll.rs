//! `wiremesh-gateway enroll` — one-shot identity bootstrap. Generates the
//! gateway's WireGuard keypair, redeems an enrollment token against the
//! controller (via `wiremesh-enroll`), and persists the resulting `Identity`
//! in the exact on-disk layout `Identity::load` reads at boot. Run by the K8s
//! operator's enroll init-container before the gateway data-plane starts.

use crate::identity::Identity;
use crate::uapi::{base64_encode, base64_pub_from_priv};
use anyhow::{anyhow, Context};
use rand::rngs::OsRng;
use rand::RngCore;
use std::path::PathBuf;

/// Parsed `enroll` flags.
pub struct EnrollArgs {
    pub token: String,
    /// Controller TCP address (`host:port`) the Enrollment RPC listens on.
    pub controller: String,
    /// Path to the controller CA bundle PEM to trust.
    pub ca_path: PathBuf,
    /// Where the `Identity` is written (the gateway's `--state-dir`).
    pub state_dir: PathBuf,
    pub cidrs: Vec<String>,
}
// NOTE: a gateway enrollment carries NO `endpoint`. On the controller
// (`services/enrollment.rs:112`) a non-empty `EnrollRequest.endpoint` selects
// the RELAY enrollment path, so a gateway that sent one would be misrouted and
// rejected (its token is `kind = gateway`, not `relay`). The gateway's own
// reachable endpoint is learned later via the observe channel, never declared
// at enroll time. Hence no `--endpoint` flag here (relays have their own bin).

/// Generate a WG keypair, enroll, and persist the identity.
///
/// **Idempotent** (design 2026-07-28, §2): if a parseable, structurally-complete
/// identity already exists in `--state-dir` (the same `Identity::load` the runtime
/// reads at boot — a structural JSON parse, NOT a crypto/expiry validity check),
/// enroll is a no-op — it logs a skip and returns `Ok(())` WITHOUT generating a
/// keypair, reading the CA, or dialing the controller. This retires the old
/// drain → delete-token → re-mint → new-id re-enroll dance and makes a single
/// `enroll` command safe to run on EVERY boot: the K8s init-container enrolls once
/// into a fresh PVC and skips on every later boot; systemd and manual invocations
/// get the same "enroll once, then no-op" guarantee. Only the "no/unparseable
/// identity" path proceeds to the real enrollment flow below (unchanged).
pub async fn run_enroll(args: EnrollArgs) -> anyhow::Result<()> {
    // Classify the on-disk identity into three outcomes (idempotent enroll). This
    // MUST come before keypair gen / CA read / controller dial so a re-run never
    // redeems a (now spent) single-use token:
    //   * present   → skip (return Ok — never dial the controller)
    //   * absent/malformed → fall through to the real enrollment below
    //   * other IO error (EACCES/EIO/EISDIR) → PROPAGATE (never enroll: an
    //     unreadable-but-possibly-present identity must not be silently clobbered
    //     by redeeming the single-use token).
    if Identity::probe(&args.state_dir)? {
        eprintln!(
            "wiremesh-gateway: already enrolled (identity present in {}), skipping",
            args.state_dir.display()
        );
        return Ok(());
    }

    // Fresh WireGuard static key — same method as `epochkeys::generate_next`
    // (x25519 clamps on use, so raw random bytes are correct).
    let mut raw = [0u8; 32];
    OsRng.fill_bytes(&mut raw);
    let wg_private_key_b64 = base64_encode(&raw);
    let wg_pubkey =
        base64_pub_from_priv(&wg_private_key_b64).context("deriving WG public key")?;

    let ca_pem = std::fs::read_to_string(&args.ca_path)
        .with_context(|| format!("reading CA bundle {}", args.ca_path.display()))?;

    let out = wiremesh_enroll::enroll(
        &args.controller,
        &ca_pem,
        &args.token,
        &args.cidrs,
        &wg_pubkey,
        "", // gateways declare no endpoint at enroll (see EnrollArgs note)
        "gateway",
    )
    .await
    .context("enrolling gateway with the controller")?;

    let id = Identity {
        cert_pem: out.cert_pem,
        key_pem: out.key_pem,
        ca_bundle_pem: out.ca_bundle_pem,
        gateway_id: out.gateway_id,
        observe_key: out.observe_key,
        wg_private_key_b64,
    };
    id.store(&args.state_dir)
        .context("persisting enrolled identity")?;
    eprintln!(
        "wiremesh-gateway: enrolled as gateway_id={} (identity written to {})",
        id.gateway_id,
        args.state_dir.display()
    );
    Ok(())
}

/// Parse the `enroll` flags from the args iterator positioned just past the
/// `enroll` subcommand token.
pub fn parse_args(mut it: impl Iterator<Item = String>) -> anyhow::Result<EnrollArgs> {
    let mut token = None;
    let mut token_file = None;
    let mut controller = None;
    let mut ca = None;
    let mut state_dir = None;
    let mut cidrs = Vec::new();
    while let Some(flag) = it.next() {
        let mut val = || it.next().ok_or_else(|| anyhow!("flag {flag} needs a value"));
        match flag.as_str() {
            "--token" => token = Some(val()?),
            // `--token-file` avoids exposing the token in argv / a shell command
            // substitution (the K8s enroll init-container mounts it as a file).
            "--token-file" => token_file = Some(PathBuf::from(val()?)),
            "--controller" => controller = Some(val()?),
            "--ca" => ca = Some(PathBuf::from(val()?)),
            "--state-dir" => state_dir = Some(PathBuf::from(val()?)),
            "--cidr" => cidrs.push(val()?),
            other => return Err(anyhow!("unknown enroll flag {other}")),
        }
    }
    let token = resolve_token(token, token_file)?;
    Ok(EnrollArgs {
        token,
        controller: controller.ok_or_else(|| anyhow!("--controller required"))?,
        ca_path: ca.ok_or_else(|| anyhow!("--ca required"))?,
        state_dir: state_dir.ok_or_else(|| anyhow!("--state-dir required"))?,
        cidrs,
    })
}

/// Resolve the token from exactly one of `--token` / `--token-file` (the file's
/// contents are trimmed of trailing whitespace/newline).
fn resolve_token(token: Option<String>, token_file: Option<PathBuf>) -> anyhow::Result<String> {
    match (token, token_file) {
        (Some(t), None) => Ok(t),
        (None, Some(f)) => Ok(std::fs::read_to_string(&f)
            .with_context(|| format!("reading token file {}", f.display()))?
            .trim()
            .to_string()),
        (None, None) => Err(anyhow!("one of --token or --token-file is required")),
        (Some(_), Some(_)) => Err(anyhow!("--token and --token-file are mutually exclusive")),
    }
}
