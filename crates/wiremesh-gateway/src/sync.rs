//! Sync client (spec §2.1). mTLS Watch stream + Report; snapshot/delta folding.
use crate::identity::Identity;
use crate::state::DesiredState;
use anyhow::{anyhow, Context};
use std::net::SocketAddr;
use tokio_stream::StreamExt;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity as TlsIdentity};
use wiremesh_proto::v1::sync_client::SyncClient;
use wiremesh_proto::v1::{
    sync_message::Body, EpochAck, PunchDirective, RelayHealth, ReportRequest, RotateDirective,
    SubmitEpochKeyRequest, SyncMessage, WatchRequest,
};

/// One decoded Sync message, surfaced to the gateway boot loop. `Snapshot`/
/// `Delta` fold into the running [`DesiredState`] and arrive as
/// [`SyncEvent::State`]; a NAT-traversal [`PunchDirective`] (cycle4b §4) is
/// NOT a desired-state change and arrives as [`SyncEvent::Punch`] for the
/// boot loop to route to the hole puncher + path state machine (Task 10); a
/// key-rotation [`RotateDirective`] is likewise not a desired-state change
/// and arrives as [`SyncEvent::Rotate`] for the boot loop to route to the
/// per-gateway [`crate::rotation::Rotation`] state machine (wiring lands in
/// the netns-integration task; this variant only carries the directive).
#[derive(Debug, Clone)]
pub enum SyncEvent {
    State(DesiredState),
    Punch(PunchDirective),
    Rotate(RotateDirective),
}

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
///
/// `relay_health` (cycle4c §8) is likewise the gateway's complete current
/// per-relay health snapshot (one entry per advertised relay this gateway
/// currently has a `RelayTransport` open to — see `main.rs`'s path-tick
/// driver), sent fresh every `Report` call; an empty list is the equally
/// meaningful "no relay transports open right now" (e.g. every peer is
/// `Direct`), not "leave the previous snapshot alone".
///
/// `epoch_acks` (key-rotation Task 1/3) carries this gateway's liveness acks
/// for a rotating PEER's pending epoch: an `EpochAck{peer_gateway_id: A,
/// epoch: N, live: true}` means "I have a live, rx-corroborated WireGuard
/// session with rotating gateway A's epoch-N key" — the signal that drives
/// the controller's promote state machine. The steady-state sync loop sends
/// an empty vec; only the rotation observation tick (Role B) populates it.
pub async fn report(
    client: &mut SyncClient<Channel>,
    applied_version: u64,
    local_endpoints: Vec<String>,
    relay_health: Vec<RelayHealth>,
    epoch_acks: Vec<EpochAck>,
) -> anyhow::Result<()> {
    client
        .report(ReportRequest { applied_version, local_endpoints, relay_health, epoch_acks })
        .await
        .map_err(|s| anyhow!("Sync.Report failed: {s}"))?;
    Ok(())
}

/// Submit this gateway's freshly-minted REAL WireGuard public key for a
/// pending rotation `epoch` (key-rotation Role A) — the private key never
/// leaves the gateway. The controller overwrites the epoch's
/// `awaiting-submission` sentinel with `pubkey`, then fans it out to peers so
/// they can bring up their overlap Device toward the real key.
pub async fn submit_epoch_key(
    client: &mut SyncClient<Channel>,
    epoch: u32,
    pubkey: String,
) -> anyhow::Result<()> {
    client
        .submit_epoch_key(SubmitEpochKeyRequest { epoch, pubkey })
        .await
        .map_err(|s| anyhow!("Sync.SubmitEpochKey failed: {s}"))?;
    Ok(())
}

/// Pull the next Sync message and turn it into a [`SyncEvent`]. Snapshot/Delta
/// are folded into `current` and returned as `State`; a `PunchDirective` is
/// returned verbatim as `Punch` (leaving `current` untouched). Returns
/// `Ok(None)` only at stream end. First message is always a snapshot.
pub async fn next_event(
    stream: &mut tonic::Streaming<SyncMessage>,
    current: &mut Option<DesiredState>,
) -> anyhow::Result<Option<SyncEvent>> {
    let Some(msg) = stream.next().await else { return Ok(None) };
    let msg = msg.map_err(|s| anyhow!("Sync stream error: {s}"))?;
    Ok(Some(classify(msg.body, current)?))
}

/// Pure per-message classification, factored out of [`next_event`] so it's
/// unit-testable without constructing a `tonic::Streaming`. Snapshot seeds/
/// replaces `current`; Delta folds into it (erroring if none exists yet);
/// Punch passes through without disturbing `current`.
fn classify(body: Option<Body>, current: &mut Option<DesiredState>) -> anyhow::Result<SyncEvent> {
    match body {
        Some(Body::Snapshot(s)) => {
            let ds = DesiredState::from_snapshot(&s);
            *current = Some(ds.clone());
            Ok(SyncEvent::State(ds))
        }
        Some(Body::Delta(d)) => {
            let cur = current.as_mut().ok_or_else(|| anyhow!("delta before snapshot"))?;
            cur.apply_delta(&d);
            Ok(SyncEvent::State(cur.clone()))
        }
        Some(Body::Punch(d)) => Ok(SyncEvent::Punch(d)),
        // RotateDirective is surfaced verbatim; the boot loop routes it to
        // the per-gateway Rotation state machine (netns-integration task).
        Some(Body::Rotate(d)) => Ok(SyncEvent::Rotate(d)),
        None => Err(anyhow!("empty SyncMessage body")),
    }
}

#[cfg(test)]
#[allow(deprecated)] // constructing StateSnapshot/Delta requires setting deprecated_relays (field 4)
mod tests {
    use super::*;
    use wiremesh_proto::v1::{Delta, StateSnapshot};

    #[test]
    fn classify_snapshot_yields_state_event() {
        let mut current = None;
        let snap = StateSnapshot {
            revision: 7,
            self_cert_pem: "C".into(),
            peers: vec![],
            deprecated_relays: vec![],
            relay_infos: vec![],
            policy_ir: vec![],
            policy_version: 2,
            revoked_serials: vec![],
        };
        match classify(Some(Body::Snapshot(snap)), &mut current).unwrap() {
            SyncEvent::State(ds) => {
                assert_eq!(ds.revision, 7);
                assert_eq!(ds.policy_version, 2);
            }
            other => panic!("expected State, got {other:?}"),
        }
        assert!(current.is_some(), "snapshot must seed current desired state");
    }

    #[test]
    fn classify_punch_yields_punch_event_and_leaves_current_untouched() {
        let mut current = None;
        let punch = PunchDirective {
            peer_gateway_id: 42,
            candidates: vec!["198.51.100.2:51820".into()],
            go_unix_ms: 123456,
        };
        match classify(Some(Body::Punch(punch.clone())), &mut current).unwrap() {
            SyncEvent::Punch(d) => assert_eq!(d, punch),
            other => panic!("expected Punch, got {other:?}"),
        }
        assert!(current.is_none(), "a punch directive must not fold into desired state");
    }

    #[test]
    fn classify_rotate_yields_rotate_event() {
        let mut current = None;
        let rotate = wiremesh_proto::v1::RotateDirective { epoch: 5 };
        match classify(Some(Body::Rotate(rotate.clone())), &mut current).unwrap() {
            SyncEvent::Rotate(d) => assert_eq!(d.epoch, 5),
            other => panic!("expected Rotate, got {other:?}"),
        }
        assert!(current.is_none(), "a rotate directive must not fold into desired state");
    }

    #[test]
    fn classify_delta_before_snapshot_errors() {
        let mut current = None;
        let d = Delta {
            revision: 1,
            upserted_peers: vec![],
            removed_peer_ids: vec![],
            deprecated_relays: vec![],
            relay_infos: vec![],
            relays_updated: false,
            policy_ir: vec![],
            policy_version: 0,
            revoked_serials: vec![],
        };
        assert!(classify(Some(Body::Delta(d)), &mut current).is_err());
    }

    #[test]
    fn classify_empty_body_errors() {
        let mut current = None;
        assert!(classify(None, &mut current).is_err());
    }
}
