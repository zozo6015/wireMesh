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
                                    (optional; UNSET = no timer) Automatic key
                                    rotation is OPT-IN. Leave this unset and no
                                    rotation-initiation timer runs at all: no
                                    gateway's WireGuard key is ever rotated on
                                    a schedule. To arm it, set
                                    <integer><s|m|h|d>, lowercase unit (30d,
                                    12h, 900s) — 30d is the recommended period
                                    if you do. Arming it is an informed choice
                                    against a known-open defect: a rotation
                                    that fails part-way leaves that gateway
                                    ignoring every later rotation directive
                                    until its process is restarted, and never
                                    scrubbing the old key (docs/BACKLOG.md item
                                    9, the rotation wedge). That is why the
                                    schedule is opt-in.
                                    `off` is the explicit spelling of the
                                    unset behaviour, worth writing down to
                                    record the intent. Either way only the
                                    SCHEDULE is off: in-flight rotations still
                                    complete and manual rotation (fabricctl /
                                    Admin RotateKey) still works. A zero
                                    interval is rejected — use `off`. So is
                                    anything above 3650d (10 years): a timer
                                    that never fires is `off` without the boot
                                    warning that says so.

    A malformed port value (e.g. WIREMESH_TCP_PORT=abc), or a malformed
    WIREMESH_ROTATION_INTERVAL, is a startup error, not a silent fallback.

DEPLOYMENT:
    The packaged systemd unit reads these variables from /etc/wiremesh/
    controller.env. The Kubernetes operator sets them on the controller
    Deployment from the WiremeshController CR — including this one:

        spec:
          rotationInterval: 30d      # opt in to the schedule; omit to keep
                                     # rotation off. Read the wedge caveat
                                     # above before arming it.

    Operator v0.8.0 (2026-08-10) and newer always emits
    WIREMESH_ROTATION_INTERVAL, passing that field through verbatim and falling
    back to `off` when it is unset. It owns the key under server-side apply
    with force, so editing the Deployment by hand (kubectl set env) is reverted
    on the next reconcile — set the CR field instead. OLDER operators omitted
    the key entirely: against one of those this controller sees an unset
    variable (so, no timer) and a hand-applied kubectl set env survives every
    reconcile. The controller and the operator are separate images and can run
    at different versions, and this binary cannot detect which operator is
    reconciling it — so check that version rather than trusting this paragraph
    indefinitely. This binary is Unix-only.

EXAMPLE:
    WIREMESH_DATA_DIR=/var/lib/wiremesh WIREMESH_BIND_IP=0.0.0.0 \\
    WIREMESH_SYNC_TCP_PORT=9500 WIREMESH_TCP_PORT=9400 {BIN}
",
        version = version_line()
    )
}
