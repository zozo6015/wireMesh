//! `-h`/`--help` and `-V`/`--version` handling for the `wiremesh-gateway`
//! binary — the live-deployment DIAGNOSTICS feature (plan
//! `docs/superpowers/plans/2026-07-28-cli-help-version.md`).
//!
//! Motivation: an operator on a running host must be able to discover the
//! gateway's flags (`--help`) and confirm the deployed version (`--version`)
//! WITHOUT the source. The gateway keeps its hand-rolled arg parser
//! (`config::GatewayConfig::parse` / `enroll::parse_args`); this module only
//! adds a pre-parse intercept that `main` runs at the very TOP of arg handling,
//! BEFORE the `enroll`-vs-run subcommand dispatch and BEFORE
//! `GatewayConfig::from_env`'s required-flag validation.
//!
//! [`cli_action`] is intentionally INFALLIBLE: help/version detection can never
//! error, which is exactly the "recognized before required-flag validation"
//! guarantee — a bare `wiremesh-gateway --help` (no required flags at all) must
//! print the manual and exit 0, never hit "`--controller-sync` required".
//! [`CliAction::Run`] is returned only when neither flag is present, deferring
//! ALL fallible parsing to the existing parser untouched (the non-regression
//! property the netns milestone depends on).

/// Pre-parse CLI intent, resolved BEFORE any required-flag validation or
/// subcommand dispatch. See the module doc.
pub enum CliAction {
    /// `-h`/`--help` seen: the fully rendered usage manual (print to stdout,
    /// exit 0).
    Help(String),
    /// `-V`/`--version` seen: the rendered "`<bin> <version>`" line (print to
    /// stdout, exit 0).
    Version(String),
    /// Neither: proceed with the normal enroll-vs-run dispatch.
    Run,
}

/// The binary name reported by `--version` and shown in the usage synopsis.
const BIN: &str = "wiremesh-gateway";

/// Decide the [`CliAction`] for a `std::env::args()`-shaped iterator — it
/// INCLUDES `argv[0]`, which this function skips itself, so `main` calls
/// `cli_action(std::env::args())`. Help wins if both `--help` and `--version`
/// appear. Scans ALL tokens (not just the first) so the flags are honored
/// "anywhere" — e.g. after other run flags — matching how `--help` behaves on
/// every other CLI.
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

/// `<bin> <crate-version>` — the compile-time crate version, so a shipped
/// binary reports exactly the release it was built from.
fn version_line() -> String {
    format!("{BIN} {}", env!("CARGO_PKG_VERSION"))
}

/// The full usage manual: synopsis, one-line component description, every
/// run flag (placeholder + required/optional + default + description), the
/// `enroll` subcommand, the env-file / `GATEWAY_ARGS` deployment mechanism,
/// and a concrete example. Flag descriptions mirror `config.rs` /
/// `enroll.rs`'s doc comments.
fn manual() -> String {
    format!(
        "\
{version}
Zero-trust WireGuard fabric gateway: one per network segment. mTLS Sync client
to the controller, in-process boringtun data plane, eBPF/nftables L4 policy
enforcement, NAT-traversal (hole-punch + relay fallback), fail-static boot.

USAGE:
    {BIN} [FLAGS]                 run the data plane (default)
    {BIN} enroll [ENROLL FLAGS]   one-shot identity bootstrap, then exit
    {BIN} --help | --version

RUN FLAGS:
    --controller-sync <host:port>   (required) Controller Sync dial target
                                    (mTLS). A DNS/DDNS name or IPv4 literal;
                                    re-resolved every reconnect (no restart on
                                    a rotated A record). IPv6 is rejected (v1
                                    is IPv4-only).
    --observe <host:port>           (required) Controller observation
                                    (UDP endpoint-discovery) dial target.
                                    Re-resolved every tick, same rules as
                                    --controller-sync.
    --tun <ifname>                  (required) WireGuard tun interface name to
                                    create/drive, e.g. wg0.
    --wg-port <u16>                 (required) WireGuard UDP listen port.
    --state-dir <path>              (required) Directory holding the enrolled
                                    identity and persisted desired state
                                    (state.json) for fail-static boot.
    --metrics <ip:port>             (optional, default 127.0.0.1:0) Bind
                                    address of the Prometheus metrics endpoint;
                                    default is loopback with an OS-assigned
                                    port.
    -h, --help                      Print this manual and exit.
    -V, --version                   Print the version and exit.

ENROLL SUBCOMMAND:
    {BIN} enroll --token <t> --controller <host:port> --ca <path> \\
                          --state-dir <path> [--cidr <cidr>]...
    Generates the gateway's WireGuard keypair, redeems the enrollment token
    against the controller, and writes the Identity into --state-dir. Use
    --token-file <path> instead of --token to avoid the token in argv. Run once
    (the operator's enroll init-container) before the data plane starts.

DEPLOYMENT:
    The packaged systemd unit / container reads run flags from an env file: set
    GATEWAY_ARGS in /etc/wiremesh/gateway.env (the unit passes $GATEWAY_ARGS to
    this binary). The Kubernetes operator sets the same flags on the gateway
    Deployment. This binary shells out to ip/nft/sysctl, so iproute2, nftables,
    and procps must be present on the host.

EXAMPLE:
    {BIN} --controller-sync controller.example.com:9500 \\
                   --observe controller.example.com:9600 \\
                   --tun wg0 --wg-port 51820 --state-dir /var/lib/wiremesh
",
        version = version_line()
    )
}
