//! `wiremesh-operator operator-admin <op> [flags]` — the in-controller-pod admin
//! helper. Runs in the controller pod's `admin-exec` sidecar (which shares the
//! controller's UDS); the operator reconciler `kube exec`s it (see
//! [`crate::admin_exec::AdminExec::Exec`]). It connects the controller's
//! **implicit-admin** Unix socket (no bearer token — that is the whole point of
//! the UDS) and prints one op's result as JSON to stdout.
//!
//! Ops: `apply` (fabric YAML on stdin), `mint-token --kind gateway|relay|rebind
//! [--cidr …] [--rebind-segment-id <n>]`, `register-relay --name --endpoint`,
//! `delete-segment --name`, `segment-id --name` (name → controller segment id,
//! `null` if absent), `list-gateways`, `drain --id`. `--socket` overrides the
//! UDS path.
//!
//! `--kind` is passed to `Admin.MintToken` verbatim — the controller's three
//! kinds are `gateway`, `relay`, and `rebind`. A **rebind** token (the one that
//! may replace a segment's already-active gateway) REQUIRES `--kind rebind`
//! plus a non-zero `--rebind-segment-id`, and carries NO `--cidr`: the
//! controller keys the rebind path off the KIND alone and reads
//! `rebind_segment_id` only inside that arm, so `--kind gateway` with a rebind
//! id would silently take the ordinary path and be rejected on the occupied
//! segment. Both invariants are enforced below rather than minting a token that
//! can only fail at redemption.

use anyhow::{anyhow, Context};
use hyper_util::rt::TokioIo;
use std::io::Read;
use std::path::PathBuf;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;
use wiremesh_proto::v1::admin_client::AdminClient;
use wiremesh_proto::v1::{
    ApplyRequest, DeleteSegmentRequest, DrainRequest, ListGatewaysRequest, ListSegmentsRequest,
    MintTokenRequest, RegisterRelayRequest,
};

/// Default UDS path (matches the controller's `WIREMESH_SOCKET_PATH` default).
pub const DEFAULT_SOCKET: &str = "/run/wiremesh/controller.sock";

async fn connect(socket: &PathBuf) -> anyhow::Result<AdminClient<Channel>> {
    let path = socket.clone();
    // The authority is a required-but-ignored placeholder — the custom
    // connector always dials the Unix socket. (Same pattern as wiremesh-testkit.)
    let channel = Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move { Ok::<_, std::io::Error>(TokioIo::new(UnixStream::connect(path).await?)) }
        }))
        .await
        .with_context(|| format!("connecting Admin over UDS {}", socket.display()))?;
    Ok(AdminClient::new(channel))
}

/// Run one admin op. `args` is positioned at the op token (past
/// `wiremesh-operator operator-admin`).
pub async fn run(args: impl Iterator<Item = String>) -> anyhow::Result<()> {
    let mut args = args;
    let op = args.next().ok_or_else(|| anyhow!("operator-admin: missing <op>"))?;

    let mut socket = PathBuf::from(DEFAULT_SOCKET);
    let mut kind = String::new();
    let mut cidrs: Vec<String> = Vec::new();
    let mut name = String::new();
    let mut endpoint = String::new();
    let mut id: u64 = 0;
    let mut rebind_segment_id: u64 = 0;
    while let Some(f) = args.next() {
        let mut val = || args.next().ok_or_else(|| anyhow!("flag {f} needs a value"));
        match f.as_str() {
            "--socket" => socket = PathBuf::from(val()?),
            "--kind" => kind = val()?,
            "--cidr" => cidrs.push(val()?),
            "--name" => name = val()?,
            "--endpoint" => endpoint = val()?,
            "--id" => id = val()?.parse().context("--id")?,
            // Non-zero → mint a REBIND token scoped to this segment id (0 is
            // the wire encoding for "no rebind" — the controller maps it to
            // NULL).
            "--rebind-segment-id" => {
                rebind_segment_id = val()?.parse().context("--rebind-segment-id")?
            }
            other => return Err(anyhow!("unknown operator-admin flag {other}")),
        }
    }

    let mut client = connect(&socket).await?;
    let out: serde_json::Value = match op.as_str() {
        "apply" => {
            let mut yaml = String::new();
            std::io::stdin().read_to_string(&mut yaml).context("reading fabric YAML from stdin")?;
            let d = client.apply(ApplyRequest { fabric_yaml: yaml }).await?.into_inner();
            // Report the change counts the reconciler surfaces in status.
            serde_json::json!({
                "applied": true,
                "createdSegments": d.created_segments,
                "updatedSegments": d.updated_segments,
                "deletedSegments": d.deleted_segments,
                "policyUpdated": d.policy_updated,
            })
        }
        "mint-token" => {
            // Fail closed on the two rebind mis-encodings that would otherwise
            // mint a token which can only be rejected at redemption. Keyed off
            // the SHARED `REBIND_TOKEN_KIND` (not a local literal) so the kind
            // can never drift from what the transports encode.
            if kind == crate::admin::REBIND_TOKEN_KIND {
                if rebind_segment_id == 0 {
                    return Err(anyhow!(
                        "mint-token --kind rebind requires a non-zero --rebind-segment-id \
                         (the segment id IS a rebind token's authorization scope)"
                    ));
                }
                if !cidrs.is_empty() {
                    return Err(anyhow!(
                        "mint-token --kind rebind takes no --cidr (a rebind token's bound \
                         CIDRs are ignored by the controller; its scope is the segment id)"
                    ));
                }
            } else if rebind_segment_id != 0 {
                return Err(anyhow!(
                    "--rebind-segment-id is only valid with --kind rebind (the controller \
                     reads it only on the rebind path; --kind {kind} would be minted as an \
                     ORDINARY token and rejected on an occupied segment)"
                ));
            }
            let r = client
                .mint_token(MintTokenRequest { kind, bound_cidrs: cidrs, rebind_segment_id })
                .await?
                .into_inner();
            serde_json::json!({ "token": r.token })
        }
        "register-relay" => {
            let r = client
                .register_relay(RegisterRelayRequest { name, endpoint })
                .await?
                .into_inner();
            serde_json::json!({ "id": r.id })
        }
        "delete-segment" => {
            let segs = client.list_segments(ListSegmentsRequest {}).await?.into_inner().segments;
            if let Some(s) = segs.into_iter().find(|s| s.name == name) {
                client.delete_segment(DeleteSegmentRequest { segment_id: s.id }).await?;
            }
            serde_json::json!({ "deleted": name })
        }
        "segment-id" => {
            // Name → controller-side segment id (the rebind mint needs it);
            // `id: null` when the segment isn't registered.
            let segs = client.list_segments(ListSegmentsRequest {}).await?.into_inner().segments;
            let id = segs.into_iter().find(|s| s.name == name).map(|s| s.id);
            serde_json::json!({ "id": id })
        }
        "list-gateways" => {
            let gws = client.list_gateways(ListGatewaysRequest {}).await?.into_inner().gateways;
            serde_json::Value::Array(
                gws.into_iter()
                    .map(|g| {
                        // snake_case keys — must match `admin_exec::GatewayRow`'s
                        // deserialized field names (the exec consumer).
                        serde_json::json!({
                            "id": g.id, "name": g.name, "segment": g.segment,
                            "status": g.status, "applied_version": g.applied_version,
                        })
                    })
                    .collect(),
            )
        }
        "drain" => {
            client.drain(DrainRequest { gateway_id: id }).await?;
            serde_json::json!({ "drained": id })
        }
        other => return Err(anyhow!("unknown operator-admin op {other}")),
    };
    println!("{out}");
    Ok(())
}
