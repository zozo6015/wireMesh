//! `-h`/`--help` and `-V`/`--version` handling for the `wiremesh-operator`
//! binary — the live-deployment DIAGNOSTICS feature (plan
//! `docs/superpowers/plans/2026-07-28-cli-help-version.md`).
//!
//! The operator dispatches `operator-admin <op>` and `idle` subcommands off
//! argv before starting the reconciler loop, and is otherwise configured by
//! `WIREMESH_*` / Downward-API environment variables. [`cli_action`] runs at
//! the very top of `main`, BEFORE that subcommand match, and is INFALLIBLE so
//! help/version never error.

/// Pre-parse CLI intent. See the module doc.
pub enum CliAction {
    /// `-h`/`--help` seen: the fully rendered usage manual.
    Help(String),
    /// `-V`/`--version` seen: the rendered "`<bin> <version>`" line.
    Version(String),
    /// Neither: proceed with the normal subcommand/reconciler dispatch.
    Run,
}

/// The binary name reported by `--version` and shown in the usage synopsis.
const BIN: &str = "wiremesh-operator";

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

/// The full usage manual: synopsis, description, the `idle`/`operator-admin`
/// subcommands, the environment-variable configuration surface (the operator
/// takes no flags of its own), and a concrete example. Descriptions mirror
/// `main.rs` / `operator_admin.rs`.
fn manual() -> String {
    format!(
        "\
{version}
WireMesh Kubernetes operator: a declarative front-end over the controller Admin
API. With no subcommand it runs the four CRD reconcilers (controller, fabric,
gateway, relay) plus a /healthz endpoint on :8080.

USAGE:
    {BIN}                          run the reconciler loop (default)
    {BIN} idle                     keep the admin-exec sidecar alive to be
                                   exec'd into (no reconcilers)
    {BIN} operator-admin <op> [FLAGS]
                                   run one in-controller-pod admin op (the
                                   reconciler kube-exec's this; UDS -> Admin
                                   gRPC, JSON out)
    {BIN} --help | --version

operator-admin OPS:
    apply | mint-token | register-relay | delete-segment | segment-id |
    list-gateways | drain
    Flags (per op): --socket <path>, --kind gateway|relay|rebind,
    --cidr <cidr>, --name <s>, --endpoint <ip:port>, --id <n>,
    --rebind-segment-id <n> (required by, and only valid with, --kind rebind;
    a rebind token takes no --cidr — its scope IS the segment id).

CONFIGURATION (environment variables; the operator takes no flags of its own):
    POD_NAMESPACE <ns>             (optional, default \"default\") Namespace to
                                   reconcile into (Downward API).
    WIREMESH_ADMIN_ADDR <host:port>(optional) Direct-gRPC Admin transport for
                                   local runs; when unset the in-cluster UDS
                                   exec sidecar is used instead.
    WIREMESH_ADMIN_TOKEN <token>   (optional) Bearer token for
                                   WIREMESH_ADMIN_ADDR.
    WIREMESH_CONTROLLER_LABEL <sel>(optional) Pod selector for the controller
                                   pod to exec into.
    WIREMESH_ADMIN_CONTAINER <name>(optional, default admin-exec) Container to
                                   exec the admin helper in.
    WIREMESH_SOCKET_PATH <path>    (optional, default
                                   /run/wiremesh/controller.sock) Controller
                                   Admin UDS the exec sidecar dials.

DEPLOYMENT:
    Runs as a Deployment in-cluster; these variables are set on the operator
    pod. This binary is Unix-only.

EXAMPLE:
    {BIN}                          # in-cluster reconciler
    {BIN} operator-admin list-gateways --socket /run/wiremesh/controller.sock
",
        version = version_line()
    )
}
