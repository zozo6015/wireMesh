//! Sync client (spec §2.1). mTLS Watch stream + Report; snapshot/delta folding.
use crate::identity::Identity;
use crate::state::DesiredState;
use anyhow::{anyhow, Context};
use std::net::SocketAddr;
use std::time::Duration;
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

/// HTTP/2 PING cadence on the Sync channel, sent even while the channel is
/// otherwise idle (`keep_alive_while_idle`) — and the long-lived `Sync.Watch`
/// stream IS the idle case: it receives nothing between policy pushes, so
/// without a keepalive it is completely silent on the wire. A NAT/conntrack
/// entry that times out on that silence leaves the stream half-open — the
/// FIN/RST never reaches the gateway, whose blocked stream read waits forever
/// while it silently misses every policy update, `PunchDirective`, and
/// `RotateDirective` (observed live for ~3 days on zolab; see
/// `docs/research/ops-finding-sync-half-open-stream.md`). The PING forces
/// periodic traffic both to keep middlebox entries warm and, with
/// [`SYNC_KEEPALIVE_TIMEOUT`], to surface a dead link as a stream error
/// within ~25s worst case — which the reconnect loop in `main.rs` already
/// handles correctly (and re-resolves DNS via [`connect`], so a rotated DDNS
/// address heals too). 15s stays comfortably inside common home-router idle
/// timeouts (minutes for TCP) without meaningful load on the controller.
const SYNC_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// How long an unanswered keepalive PING may go unacknowledged before the
/// channel is declared dead and the error is surfaced to the reconnect loop.
/// See [`SYNC_KEEPALIVE_INTERVAL`] for the half-open-stream rationale.
const SYNC_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Bound on the TCP/TLS dial itself. Without one, a dial toward a stale DDNS
/// address that blackholes (no RST) can hang the reconnect loop far longer
/// than the DNS record's own churn; a bounded dial keeps the
/// resolve-dial-retry cycle turning so the next attempt picks up the fresh
/// A record.
const SYNC_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Bound on the DNS lookup in [`resolve_host_port`]. `getaddrinfo` has no
/// application-level timeout of its own, and [`SYNC_CONNECT_TIMEOUT`] cannot
/// cover the resolve phase because resolution happens BEFORE the dial — so
/// without this bound a hung OS resolver (e.g. the DDNS host's configured
/// nameserver blackholing) would stall the Sync reconnect loop and the
/// observe tick indefinitely: the same silent-hang class the Sync keepalive
/// exists to kill (`docs/research/ops-finding-sync-half-open-stream.md`). On
/// expiry the caller gets an error and retries on its own cadence, each
/// attempt resolving fresh.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);

/// Resolve a `host:port` dial target — a DNS hostname or an IPv4 literal —
/// to one `SocketAddr`: the first IPv4 result ([`prefer_ipv4`]). A name that
/// resolves to only IPv6 is an ERROR, not a fallback — v1 is IPv4-only end
/// to end (spec §1; the controller itself binds an `Ipv4Addr`), so an IPv6
/// address can never reach a v1 controller. Callers resolve fresh at every
/// dial/tick ON PURPOSE: a DDNS name's A record changes when the ISP rotates
/// the controller's public IP, and per-reconnect (Sync) / per-tick (observe)
/// re-resolution is what picks the new address up without a gateway restart
/// (`docs/research/operator-remote-deployment-notes.md` Finding 3). IP
/// literals pass through `lookup_host` without touching DNS, so netns tests
/// and IP-configured deployments never depend on a resolver.
pub async fn resolve_host_port(s: &str) -> anyhow::Result<SocketAddr> {
    let addrs: Vec<SocketAddr> = tokio::time::timeout(RESOLVE_TIMEOUT, tokio::net::lookup_host(s))
        .await
        .map_err(|_| anyhow!("DNS resolution of {s:?} timed out after {RESOLVE_TIMEOUT:?}"))?
        .with_context(|| format!("resolving {s:?}"))?
        .collect();
    prefer_ipv4(&addrs)
        .ok_or_else(|| anyhow!("{s:?} resolved to no IPv4 addresses (v1 is IPv4-only)"))
}

/// The pure address-selection policy behind [`resolve_host_port`]: the first
/// IPv4 result, `None` when the list has none. Deliberately NO cross-family
/// fallback: v1 is IPv4-only end to end (spec §1 — the controller binds an
/// `Ipv4Addr`), so an IPv6 candidate is a dead end and "falling back" to one
/// would only trade a clear resolution error for an unreachable-dial loop.
/// Factored out of the resolver so the selection is checkable against a
/// synthetic candidate list, without a resolver in the loop.
pub fn prefer_ipv4(addrs: &[SocketAddr]) -> Option<SocketAddr> {
    addrs.iter().find(|a| a.is_ipv4()).copied()
}

/// Dial the controller Sync endpoint (`host:port`, hostname or IP literal)
/// over mTLS. DNS resolution happens HERE, inside every call, so the
/// reconnect loop's redial after a keepalive-detected dead link also picks up
/// a rotated DDNS address (see [`resolve_host_port`]). `domain_name` is the
/// constant `127.0.0.1` regardless of what was dialed: the controller's TLS
/// is hostname-agnostic by design — trust is anchored in the pinned private
/// CA + mTLS, not public-PKI hostname validation (see the rationale at
/// `wiremesh-controller/src/lib.rs` on the server leaf's constant SAN).
pub async fn connect(sync_addr: &str, id: &Identity) -> anyhow::Result<SyncClient<Channel>> {
    let resolved = resolve_host_port(sync_addr).await?;
    let uri = format!("https://{resolved}");
    let tls = ClientTlsConfig::new()
        .identity(TlsIdentity::from_pem(&id.cert_pem, &id.key_pem))
        .ca_certificate(Certificate::from_pem(&id.ca_bundle_pem))
        .domain_name("127.0.0.1");
    let channel = Channel::from_shared(uri)
        .context("controller Sync addr must form a valid URI")?
        .tls_config(tls)
        .context("configuring gateway mTLS")?
        .connect_timeout(SYNC_CONNECT_TIMEOUT)
        .http2_keep_alive_interval(SYNC_KEEPALIVE_INTERVAL)
        .keep_alive_timeout(SYNC_KEEPALIVE_TIMEOUT)
        .keep_alive_while_idle(true)
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
