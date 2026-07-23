//! `fabricctl`: the imperative CLI for WireMesh's Admin service (Task 13).
//!
//! Connects either:
//! - `--socket <path>`: over the controller's Unix socket, implicit-admin
//!   (no token needed — see `wiremesh_controller::serve`'s doc comment for
//!   why the UDS listener trusts anyone who can open the socket at all), or
//! - `--token <bearer> --addr <host:port>`: over the controller's SECOND,
//!   bearer-auth-gated TCP Admin listener (`wiremesh_controller::auth`),
//!   presenting `token` as an `authorization: Bearer <token>` header on
//!   every call.
//!
//! Both paths produce the exact same client type (`AdminClient<InterceptedService<Channel, AuthMode>>`)
//! — `AuthMode::None` on the UDS path is a harmless no-op interceptor (the
//! UDS-side server never reads the header), so every subcommand handler
//! below is written against one client type regardless of which transport
//! the caller chose.
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use tonic::service::interceptor::InterceptedService;
use tonic::service::Interceptor;
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::{Code, Request, Status};
use tower::service_fn;

use wiremesh_proto::v1::admin_client::AdminClient;
use wiremesh_proto::v1::{
    ApplyRequest, AuditQueryRequest, CreateSegmentRequest, DeleteSegmentRequest, DrainRequest,
    GetPolicyRequest, ListGatewaysRequest, ListRelaysRequest, ListSegmentsRequest,
    MintApiTokenRequest, RegisterRelayRequest, RevokeApiTokenRequest,
};

#[derive(Parser)]
#[command(name = "fabricctl", about = "WireMesh controller Admin CLI")]
struct Cli {
    /// Connect over the controller's Unix socket (implicit admin). Mutually
    /// exclusive with `--token`/`--addr`.
    #[arg(long, global = true)]
    socket: Option<PathBuf>,
    /// Bearer API token, presented over `--addr`'s TCP Admin listener.
    /// Requires `--addr`.
    #[arg(long, global = true)]
    token: Option<String>,
    /// The controller's bearer-auth-gated TCP Admin address (`host:port`).
    /// Requires `--token`.
    #[arg(long, global = true)]
    addr: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Segment CRUD.
    Segment {
        #[command(subcommand)]
        cmd: SegmentCmd,
    },
    /// Gateway bookkeeping (read-only list, plus drain).
    Gateway {
        #[command(subcommand)]
        cmd: GatewayCmd,
    },
    /// Relay bookkeeping.
    Relay {
        #[command(subcommand)]
        cmd: RelayCmd,
    },
    /// API bearer token mint/revoke.
    Token {
        #[command(subcommand)]
        cmd: TokenCmd,
    },
    /// Audit log queries.
    Audit {
        #[command(subcommand)]
        cmd: AuditCmd,
    },
    /// (Task 14) Declaratively applies a `fabric.yaml` (segments/relays,
    /// policy stanza stubbed) against the controller — idempotent: re-running
    /// against an unchanged file is a no-op.
    Apply {
        #[arg(short = 'f', long = "file")]
        file: PathBuf,
    },
    /// (Task 6) Compiled-policy inspection: the source/IR of a specific (or
    /// the latest) version, and per-gateway applied-vs-latest status.
    Policy {
        #[command(subcommand)]
        cmd: PolicyCmd,
    },
}

#[derive(Subcommand)]
enum SegmentCmd {
    /// Creates a segment with one or more `--cidr` ranges.
    Create {
        name: String,
        #[arg(long)]
        cidr: Vec<String>,
    },
    /// Lists every registered segment.
    List,
    /// Deletes a segment by id.
    Rm { segment_id: u64 },
}

#[derive(Subcommand)]
enum GatewayCmd {
    /// Lists every gateway (any status), with its last-acked applied policy
    /// version.
    List,
    /// Drains a gateway by id.
    Drain { gateway_id: u64 },
}

#[derive(Subcommand)]
enum RelayCmd {
    /// Registers a relay.
    Register {
        name: String,
        #[arg(long)]
        endpoint: String,
    },
    /// Lists every registered relay.
    List,
}

#[derive(Subcommand)]
enum TokenCmd {
    /// Mints a bearer API token (`role`: `admin` or `read-only`). Prints the
    /// raw bearer secret — this is the only time it is ever shown.
    Mint {
        name: String,
        #[arg(long)]
        role: String,
    },
    /// Revokes a bearer API token by name.
    Revoke { name: String },
}

/// (Task 16) `limit <= 0` (or omitted) falls back to the server-side
/// default — see `Admin.AuditQuery`'s doc comment. `action` is an optional
/// EXACT-match filter; omitted (or passed as an empty string) means "no
/// filter" on that column. (`AuditQueryRequest`'s wire shape is fixed by
/// `tests/revoke_audit.rs` to exactly `{limit, action}` — no `actor`/
/// `entity` filter is wired through the RPC yet; see that message's proto
/// doc comment.)
#[derive(Subcommand)]
enum AuditCmd {
    /// Most-recent-first audit log entries.
    Query {
        #[arg(long, default_value_t = 50)]
        limit: i32,
        /// Exact-match filter on `action` (e.g. "revoke", "create", "mint").
        #[arg(long, default_value_t = String::new())]
        action: String,
    },
    /// (Task 16) Streams every matching audit-log entry to stdout as one
    /// JSON object per line (JSON Lines / ndjson) — a machine-readable
    /// counterpart to `Query`'s tab-separated human output, meant for
    /// piping into `jq`/log-shipping rather than reading directly. With no
    /// filter, exports the whole audit log (up to `--limit`, defaulting to
    /// a large-but-bounded value rather than the server's small
    /// human-oriented default).
    Export {
        #[arg(long, default_value_t = 1_000_000)]
        limit: i32,
        /// Exact-match filter on `action`.
        #[arg(long, default_value_t = String::new())]
        action: String,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Prints a policy version's raw source YAML followed by its
    /// pretty-printed compiled IR (JSON). Omit `--version` (or pass `0`) for
    /// the latest.
    Show {
        #[arg(long, default_value_t = 0)]
        version: u64,
    },
    /// Per-gateway `name / applied_version / latest_version` — `applied_version`
    /// is the last version that gateway's `Sync.Report` acked (`0` if it has
    /// never reported one); `latest_version` is the controller's current
    /// latest compiled policy (`0` if none has ever been applied).
    Status,
}

/// One `audit export` JSON line's shape — field names match `AuditEntry`'s
/// wire fields 1:1 so the export is a direct, lossless JSON rendering of
/// the proto message (not a re-interpreted/renamed view).
#[derive(serde::Serialize)]
struct AuditEntryJson {
    id: u64,
    ts: String,
    actor: String,
    action: String,
    entity: String,
    diff_json: String,
}

/// Client-side counterpart to `wiremesh_controller::auth`'s bearer-auth
/// middleware. `None` (the UDS path) attaches nothing — a harmless no-op,
/// since the UDS listener never reads the header at all.
#[derive(Clone)]
enum AuthMode {
    None,
    Bearer(String),
}

impl Interceptor for AuthMode {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        if let AuthMode::Bearer(token) = self {
            let value = format!("Bearer {token}")
                .parse()
                .map_err(|_| Status::internal("bearer token is not a valid header value"))?;
            request.metadata_mut().insert("authorization", value);
        }
        Ok(request)
    }
}

type AdminAuthClient = AdminClient<InterceptedService<Channel, AuthMode>>;

/// Connects per `cli`'s `--socket` / `--token`+`--addr` flags — see the
/// module doc comment for the transport contract.
async fn connect(cli: &Cli) -> anyhow::Result<AdminAuthClient> {
    match (&cli.socket, &cli.token, &cli.addr) {
        (Some(socket), None, None) => {
            // The UDS admin transport is Unix-only (Windows has no AF_UNIX in
            // tokio); on Windows fabricctl uses the TCP `--addr`+`--token` path.
            #[cfg(unix)]
            {
                let path = socket.clone();
                // The same `tower::service_fn` + `hyper_util::rt::TokioIo` UDS
                // connector pattern as `wiremesh-testkit::TestController::admin_client`.
                // The placeholder URI below is required by the builder but never
                // dialed — `connect_with_connector` always opens the Unix socket —
                // so its exact value is irrelevant.
                let channel = Endpoint::try_from("http://127.0.0.1:50051")?
                    .connect_with_connector(service_fn(move |_: Uri| {
                        let path = path.clone();
                        async move {
                            let stream = tokio::net::UnixStream::connect(path).await?;
                            Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
                        }
                    }))
                    .await?;
                Ok(AdminClient::with_interceptor(channel, AuthMode::None))
            }
            #[cfg(not(unix))]
            {
                let _ = socket;
                anyhow::bail!(
                    "--socket (Unix-domain admin) is only supported on Unix; \
                     on Windows use --addr <host:port> --token <token>"
                )
            }
        }
        (None, Some(token), Some(addr)) => {
            let uri = format!("http://{addr}");
            let channel = Channel::from_shared(uri)?.connect().await?;
            Ok(AdminClient::with_interceptor(
                channel,
                AuthMode::Bearer(token.clone()),
            ))
        }
        (None, None, None) => {
            anyhow::bail!("must pass either --socket <path> or --token <bearer> --addr <host:port>")
        }
        _ => anyhow::bail!(
            "--socket is mutually exclusive with --token/--addr; pass exactly one transport"
        ),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let mut client = connect(&cli).await?;

    match cli.command {
        Command::Segment { cmd } => run_segment(&mut client, cmd).await,
        Command::Gateway { cmd } => run_gateway(&mut client, cmd).await,
        Command::Relay { cmd } => run_relay(&mut client, cmd).await,
        Command::Token { cmd } => run_token(&mut client, cmd).await,
        Command::Audit { cmd } => run_audit(&mut client, cmd).await,
        Command::Apply { file } => run_apply(&mut client, file).await,
        Command::Policy { cmd } => run_policy(&mut client, cmd).await,
    }
}

async fn run_segment(client: &mut AdminAuthClient, cmd: SegmentCmd) -> anyhow::Result<()> {
    match cmd {
        SegmentCmd::Create { name, cidr } => {
            let seg = client
                .create_segment(CreateSegmentRequest {
                    name: name.clone(),
                    cidrs: cidr,
                })
                .await?
                .into_inner();
            println!(
                "created segment id={} name={} cidrs={}",
                seg.id,
                seg.name,
                seg.cidrs.join(",")
            );
        }
        SegmentCmd::List => {
            let resp = client
                .list_segments(ListSegmentsRequest {})
                .await?
                .into_inner();
            for seg in resp.segments {
                println!("{}\t{}\t{}", seg.id, seg.name, seg.cidrs.join(","));
            }
        }
        SegmentCmd::Rm { segment_id } => {
            client
                .delete_segment(DeleteSegmentRequest { segment_id })
                .await?;
            println!("deleted segment id={segment_id}");
        }
    }
    Ok(())
}

async fn run_gateway(client: &mut AdminAuthClient, cmd: GatewayCmd) -> anyhow::Result<()> {
    match cmd {
        GatewayCmd::List => {
            let resp = client
                .list_gateways(ListGatewaysRequest {})
                .await?
                .into_inner();
            for gw in resp.gateways {
                println!(
                    "{}\t{}\t{}\t{}\tapplied_version={}",
                    gw.id, gw.name, gw.segment, gw.status, gw.applied_version
                );
            }
        }
        GatewayCmd::Drain { gateway_id } => {
            client.drain(DrainRequest { gateway_id }).await?;
            println!("drained gateway id={gateway_id}");
        }
    }
    Ok(())
}

async fn run_relay(client: &mut AdminAuthClient, cmd: RelayCmd) -> anyhow::Result<()> {
    match cmd {
        RelayCmd::Register { name, endpoint } => {
            let relay = client
                .register_relay(RegisterRelayRequest {
                    name: name.clone(),
                    endpoint,
                })
                .await?
                .into_inner();
            println!(
                "registered relay id={} name={} endpoint={} status={}",
                relay.id, relay.name, relay.endpoint, relay.status
            );
        }
        RelayCmd::List => {
            let resp = client.list_relays(ListRelaysRequest {}).await?.into_inner();
            for relay in resp.relays {
                println!(
                    "{}\t{}\t{}\t{}",
                    relay.id, relay.name, relay.endpoint, relay.status
                );
            }
        }
    }
    Ok(())
}

async fn run_token(client: &mut AdminAuthClient, cmd: TokenCmd) -> anyhow::Result<()> {
    match cmd {
        TokenCmd::Mint { name, role } => {
            let resp = client
                .mint_api_token(MintApiTokenRequest { name, role })
                .await?
                .into_inner();
            println!("{}", resp.token);
        }
        TokenCmd::Revoke { name } => {
            client
                .revoke_api_token(RevokeApiTokenRequest { name: name.clone() })
                .await?;
            println!("revoked api token name={name}");
        }
    }
    Ok(())
}

/// (Task 14) Reads `file`, calls `Admin.Apply`, and prints the resulting
/// diff's counts — a no-op re-apply prints all zeros/false.
async fn run_apply(client: &mut AdminAuthClient, file: PathBuf) -> anyhow::Result<()> {
    let fabric_yaml = std::fs::read_to_string(&file)
        .map_err(|e| anyhow::anyhow!("reading fabric file {}: {e}", file.display()))?;
    let diff = client
        .apply(ApplyRequest { fabric_yaml })
        .await?
        .into_inner();
    println!(
        "created_segments={} updated_segments={} deleted_segments={} policy_updated={} total_changes={}",
        diff.created_segments,
        diff.updated_segments,
        diff.deleted_segments,
        diff.policy_updated,
        diff.total_changes,
    );
    Ok(())
}

/// (Task 6) `policy show` prints the raw source YAML, then the compiled IR
/// pretty-printed as JSON (parsed from `PolicyVersionMsg.compiled_ir`'s
/// verbatim bytes, then re-serialized with `serde_json::to_string_pretty`
/// for readability — the wire bytes themselves are already valid,
/// canonical-but-compact JSON, see `PolicyIR::from_json`'s doc comment).
/// `policy status` prints, per gateway (off `Admin.ListGateways`), its
/// name, its last-`Sync.Report`-acked `applied_version`, and the
/// controller's current `latest_version` (off `Admin.GetPolicy{version: 0}`
/// — `0` if no policy has ever been applied, rather than failing the whole
/// command).
async fn run_policy(client: &mut AdminAuthClient, cmd: PolicyCmd) -> anyhow::Result<()> {
    match cmd {
        PolicyCmd::Show { version } => {
            let resp = client
                .get_policy(GetPolicyRequest { version })
                .await?
                .into_inner();
            println!("{}", resp.source_yaml);
            let ir: serde_json::Value = serde_json::from_slice(&resp.compiled_ir)
                .map_err(|e| anyhow::anyhow!("parsing compiled_ir as JSON: {e}"))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&ir)
                    .map_err(|e| anyhow::anyhow!("pretty-printing compiled_ir as JSON: {e}"))?
            );
        }
        PolicyCmd::Status => {
            let gateways = client
                .list_gateways(ListGatewaysRequest {})
                .await?
                .into_inner()
                .gateways;
            let latest_version = match client.get_policy(GetPolicyRequest { version: 0 }).await {
                Ok(resp) => resp.into_inner().version,
                Err(status) if status.code() == Code::NotFound => 0,
                Err(status) => return Err(status.into()),
            };
            for gw in gateways {
                println!(
                    "{}\tapplied_version={}\tlatest_version={}",
                    gw.name, gw.applied_version, latest_version
                );
            }
        }
    }
    Ok(())
}

async fn run_audit(client: &mut AdminAuthClient, cmd: AuditCmd) -> anyhow::Result<()> {
    match cmd {
        AuditCmd::Query { limit, action } => {
            let resp = client
                .audit_query(AuditQueryRequest { limit, action })
                .await?
                .into_inner();
            for e in resp.entries {
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}",
                    e.id, e.ts, e.actor, e.action, e.entity, e.diff_json
                );
            }
        }
        // (Task 16) A real client: calls the same `Admin.AuditQuery` RPC as
        // `Query` above, then serializes each returned `AuditEntry` as one
        // JSON object per line to stdout.
        AuditCmd::Export { limit, action } => {
            let resp = client
                .audit_query(AuditQueryRequest { limit, action })
                .await?
                .into_inner();
            for e in resp.entries {
                let line = AuditEntryJson {
                    id: e.id,
                    ts: e.ts,
                    actor: e.actor,
                    action: e.action,
                    entity: e.entity,
                    diff_json: e.diff_json,
                };
                println!(
                    "{}",
                    serde_json::to_string(&line)
                        .map_err(|e| anyhow::anyhow!("serializing audit entry as JSON: {e}"))?
                );
            }
        }
    }
    Ok(())
}
