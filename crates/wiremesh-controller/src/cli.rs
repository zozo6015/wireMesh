//! `-h`/`--help` and `-V`/`--version` handling for the `wiremesh-controller`
//! binary — the live-deployment DIAGNOSTICS feature (plan
//! `docs/superpowers/plans/2026-07-28-cli-help-version.md`).
//!
//! The controller takes NO flags: it is configured entirely by `WIREMESH_*`
//! environment variables (see `src/main.rs`). It must still answer help/version
//! so an operator can confirm the deployed version and discover the env-var
//! surface without the source. [`cli_action`] runs at the very top of `main`,
//! BEFORE any `WIREMESH_*` var is read or `serve` is called, and is INFALLIBLE
//! by design.

/// Pre-parse CLI intent. See the module doc.
pub enum CliAction {
    /// `-h`/`--help` seen: the fully rendered usage manual.
    Help(String),
    /// `-V`/`--version` seen: the rendered "`<bin> <version>`" line.
    Version(String),
    /// Neither: proceed with the normal env-driven boot.
    Run,
}

/// The binary name reported by `--version` and shown in the usage synopsis.
const BIN: &str = "wiremesh-controller";

/// Decide the [`CliAction`] for a `std::env::args()`-shaped iterator
/// (INCLUDES `argv[0]`, skipped here). Help wins if both flags appear.
pub fn cli_action(args: impl Iterator<Item = String>) -> CliAction {
    let mut help = false;
    let mut version = false;
    for tok in args.skip(1) {
        match tok.as_str() {
            "-h" | "--help" => help = true,
            "-V" | "--version" => version = true,
            _ => {}
        }
    }
    if help {
        CliAction::Help(manual())
    } else if version {
        CliAction::Version(version_line())
    } else {
        CliAction::Run
    }
}

fn version_line() -> String {
    format!("{BIN} {}", env!("CARGO_PKG_VERSION"))
}

/// The full usage manual. The controller is env-configured, so the "flags"
/// section documents every `WIREMESH_*` variable (placeholder, required/
/// optional, default, one-line description) an operator sets, plus the
/// env-file deployment mechanism and a concrete example. Descriptions mirror
/// `main.rs` / the `Config` doc comments.
fn manual() -> String {
    format!(
        "\
{version}
Single-tenant zero-trust fabric controller: the control plane. Serves
Enrollment (server-TLS), Sync (mTLS), and Admin (Unix socket + bearer-auth TCP)
gRPC, an observation UDP endpoint, and drives policy compilation + key rotation.

USAGE:
    {BIN}                    run the control plane (configured via env, below)
    {BIN} --help | --version

CONFIGURATION (environment variables — this binary takes NO flags):
    WIREMESH_DATA_DIR <path>        (optional, default /var/lib/wiremesh)
                                    Directory holding the SQLite DB, embedded
                                    CA, and secrets. Created if absent.
    WIREMESH_TCP_PORT <u16>         (optional, default 0 = OS-assigned) TCP
                                    port for the Enrollment service (server-TLS
                                    only).
    WIREMESH_SYNC_TCP_PORT <u16>    (optional, default 0 = OS-assigned) TCP
                                    port for the Sync service (mTLS; requires a
                                    client cert chaining to the embedded CA).
    WIREMESH_ADMIN_TCP_PORT <u16>   (optional, default 0 = OS-assigned) TCP
                                    port for the bearer-auth-gated Admin
                                    listener (fabricctl --token/--addr). Always
                                    binds loopback-only.
    WIREMESH_OBSERVE_UDP_PORT <u16> (optional, default 0 = OS-assigned) UDP
                                    port for the observation endpoint.
    WIREMESH_SOCKET_PATH <path>     (optional, default
                                    /run/wiremesh/controller.sock) Unix socket
                                    the implicit-admin Admin service listens on.
    WIREMESH_BIND_IP <ipv4>         (optional, default 127.0.0.1) IPv4 address
                                    the Enrollment/Sync/observe listeners bind
                                    to. Set 0.0.0.0 to expose them (e.g. via a
                                    Kubernetes Service). The Admin TCP listener
                                    stays loopback-only regardless. A malformed
                                    value falls back to the default.
    WIREMESH_ROTATION_INTERVAL <interval|off>
                                    (optional, default 30d) How often every
                                    gateway's WireGuard key is automatically
                                    rotated. <integer><s|m|h|d>, lowercase unit
                                    (30d, 12h, 900s). `off` disables the
                                    automatic SCHEDULE only: in-flight rotations
                                    still complete and manual rotation
                                    (fabricctl / Admin RotateKey) still works,
                                    but no key is rotated on a timer until it is
                                    re-enabled. A zero interval is rejected —
                                    use `off`.

    A malformed port value (e.g. WIREMESH_TCP_PORT=abc), or a malformed
    WIREMESH_ROTATION_INTERVAL, is a startup error, not a silent fallback.

DEPLOYMENT:
    The packaged systemd unit reads these variables from /etc/wiremesh/
    controller.env. The Kubernetes operator sets them on the controller
    Deployment. This binary is Unix-only.

EXAMPLE:
    WIREMESH_DATA_DIR=/var/lib/wiremesh WIREMESH_BIND_IP=0.0.0.0 \\
    WIREMESH_SYNC_TCP_PORT=9500 WIREMESH_TCP_PORT=9400 {BIN}
",
        version = version_line()
    )
}
