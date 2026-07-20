//! Sync client (spec §2.1). mTLS Watch stream + Report; snapshot/delta folding.
use crate::identity::Identity;
use crate::state::DesiredState;
use anyhow::{anyhow, Context};
use std::net::SocketAddr;
use tokio_stream::StreamExt;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity as TlsIdentity};
use wiremesh_proto::v1::sync_client::SyncClient;
use wiremesh_proto::v1::{sync_message::Body, ReportRequest, SyncMessage, WatchRequest};

pub async fn connect(sync_addr: SocketAddr, id: &Identity) -> anyhow::Result<SyncClient<Channel>> {
    let uri = format!("https://{sync_addr}");
    let tls = ClientTlsConfig::new()
        .identity(TlsIdentity::from_pem(&id.cert_pem, &id.key_pem))
        .ca_certificate(Certificate::from_pem(&id.ca_bundle_pem))
        .domain_name("127.0.0.1");
    let channel = Channel::from_shared(uri)
        .context("controller Sync addr must form a valid URI")?
        .tls_config(tls)
        .context("configuring gateway mTLS")?
        .connect()
        .await
        .context("connecting to controller Sync (mTLS)")?;
    Ok(SyncClient::new(channel))
}

pub async fn watch(client: &mut SyncClient<Channel>) -> anyhow::Result<tonic::Streaming<SyncMessage>> {
    Ok(client.watch(WatchRequest {}).await.map_err(|s| anyhow!("Sync.Watch failed: {s}"))?.into_inner())
}

/// `local_endpoints` (cycle4b §5/§6.1) is the gateway's COMPLETE current
/// routable local-address set (see `netif::local_wg_endpoints`), sent fresh
/// on every `Report` call — there is no per-endpoint add/remove RPC, so an
/// empty list here is a genuine, meaningful "I currently have no routable
/// local addresses" and the controller applies it as a full REPLACE
/// (`Db::set_local_candidates`), clearing any previously reported set.
pub async fn report(
    client: &mut SyncClient<Channel>,
    applied_version: u64,
    local_endpoints: Vec<String>,
) -> anyhow::Result<()> {
    client
        .report(ReportRequest { applied_version, local_endpoints })
        .await
        .map_err(|s| anyhow!("Sync.Report failed: {s}"))?;
    Ok(())
}

/// Pull the next Sync message and fold it into `current`, returning the updated
/// desired state (or None at stream end). First message is always a snapshot.
pub async fn next_desired(
    stream: &mut tonic::Streaming<SyncMessage>,
    current: &mut Option<DesiredState>,
) -> anyhow::Result<Option<DesiredState>> {
    loop {
        let Some(msg) = stream.next().await else { return Ok(None) };
        let msg = msg.map_err(|s| anyhow!("Sync stream error: {s}"))?;
        match msg.body {
            Some(Body::Snapshot(s)) => {
                let ds = DesiredState::from_snapshot(&s);
                *current = Some(ds.clone());
                return Ok(Some(ds));
            }
            Some(Body::Delta(d)) => {
                let cur = current.as_mut().ok_or_else(|| anyhow!("delta before snapshot"))?;
                cur.apply_delta(&d);
                return Ok(Some(cur.clone()));
            }
            Some(Body::Punch(_)) => {
                // NAT-traversal punch directives (cycle4b §4) are not a DesiredState
                // change — they'll be routed to the path/puncher subsystem by a
                // later cycle4b task. Ignore here and wait for the next message.
                continue;
            }
            None => return Err(anyhow!("empty SyncMessage body")),
        }
    }
}
