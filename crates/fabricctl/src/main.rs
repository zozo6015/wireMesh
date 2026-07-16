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
use tonic::{Request, Status};
use tower::service_fn;

use wiremesh_proto::v1::admin_client::AdminClient;
use wiremesh_proto::v1::{
    AuditQueryRequest, CreateSegmentRequest, DeleteSegmentRequest, DrainRequest,
    ListGatewaysRequest, ListRelaysRequest, ListSegmentsRequest, MintApiTokenRequest,
    RegisterRelayRequest, RevokeApiTokenRequest,
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

#[derive(Subcommand)]
enum AuditCmd {
    /// Most-recent-first audit log entries.
    Query {
        #[arg(long, default_value_t = 50)]
        limit: i32,
    },
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
            let path = socket.clone();
            // Same `tower::service_fn` + `hyper_util::rt::TokioIo` UDS
            // connector `wiremesh-testkit::TestController::admin_client`
            // uses — the placeholder URI is required but ignored by
            // `connect_with_connector`, which always dials the Unix socket.
            let channel = Endpoint::try_from("http://[::]:50051")?
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

async fn run_audit(client: &mut AdminAuthClient, cmd: AuditCmd) -> anyhow::Result<()> {
    match cmd {
        AuditCmd::Query { limit } => {
            let resp = client
                .audit_query(AuditQueryRequest { limit })
                .await?
                .into_inner();
            for e in resp.entries {
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}",
                    e.id, e.ts, e.actor, e.action, e.entity, e.diff_json
                );
            }
        }
    }
    Ok(())
}
