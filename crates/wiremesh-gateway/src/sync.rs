//! Sync client (spec §2.1). mTLS Watch stream + Report; snapshot/delta folding.
use crate::identity::Identity;
use crate::state::DesiredState;
use anyhow::{anyhow, Context};
use std::time::Duration;
use tokio_stream::StreamExt;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity as TlsIdentity};
use wiremesh_proto::v1::sync_client::SyncClient;
use wiremesh_proto::v1::{
    sync_message::Body, EpochAck, PeerPath, PunchDirective, RelayHealth, ReportRequest,
    RotateDirective, SubmitEpochKeyRequest, SyncMessage, WatchRequest,
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
/// The VALUE is the canonical `wiremesh_enroll::SYNC_KEEPALIVE_INTERVAL`
/// (shared with the relay client and the controller's server-side mirror so
/// the figures can't drift apart); this alias just keeps it private here.
const SYNC_KEEPALIVE_INTERVAL: Duration = wiremesh_enroll::SYNC_KEEPALIVE_INTERVAL;

/// How long an unanswered keepalive PING may go unacknowledged before the
/// channel is declared dead and the error is surfaced to the reconnect loop.
/// See [`SYNC_KEEPALIVE_INTERVAL`] for the half-open-stream rationale (and
/// for why the value comes from `wiremesh-enroll`).
const SYNC_KEEPALIVE_TIMEOUT: Duration = wiremesh_enroll::SYNC_KEEPALIVE_TIMEOUT;

/// Bound on the TCP/TLS dial itself. Without one, a dial toward a stale DDNS
/// address that blackholes (no RST) can hang the reconnect loop far longer
/// than the DNS record's own churn; a bounded dial keeps the
/// resolve-dial-retry cycle turning so the next attempt picks up the fresh
/// A record. Value shared via `wiremesh-enroll`, as above.
const SYNC_CONNECT_TIMEOUT: Duration = wiremesh_enroll::SYNC_CONNECT_TIMEOUT;

// The bounded `host:port` resolver behind [`connect`] (and `main.rs`'s
// observe tick) moved to `wiremesh-enroll` when the relay's Sync client
// gained the same DDNS dial semantics (Backlog 2, mirroring this crate's
// PR-#28 fix — see `docs/research/ops-finding-sync-half-open-stream.md`).
// Re-exported under the original paths so every caller — and the pinned
// contract in `tests/hostname_resolve.rs` — is unchanged. Semantics
// (first-IPv4-wins, no cross-family fallback, 10s-bounded lookup, resolved
// fresh at every dial) are documented at the definition.
pub use wiremesh_enroll::{prefer_ipv4, resolve_host_port};

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

/// This process's Sync session generation — a per-BOOT nonce, generated once
/// and then constant for the lifetime of the gateway process.
///
/// # Why it exists
///
/// The controller's broker stores per-gateway reported state (`peer_paths`,
/// `local_endpoints`, `relay_health`). When a gateway reconnects, the
/// controller CLEARS that state (`Broker::on_gateway_connected` ->
/// `clear_reported_states`) because a restarted gateway may have no tunnel at
/// all and its stale "direct" claims must not suppress the punches it now
/// needs. But a `Report` issued by the PREVIOUS process and delayed on the
/// network can land AFTER that clear and — being a snapshot — REPLACE the
/// fresh empty state with pre-restart claims. The controller then believes a
/// pair is settled, skips brokering the synchronized punch, and the pair
/// never lands (unsynchronized self-timers do not work for a port-restricted
/// pair — see `path.rs`'s settled-boundary notes). Tagging every Watch and
/// every Report with this nonce lets the controller reject a report from a
/// generation that is not the one its live Watch registered.
///
/// # Why per-PROCESS and not per-connection
///
/// Two reasons, both load-bearing:
/// - The rotation observation tick's unary epoch-ack Report dials its OWN
///   short-lived channel (`send_epoch_ack`), entirely outside the sync loop's
///   Watch. A per-connection value would make every one of those acks
///   mismatch and be rejected.
/// - Every Sync reconnect would otherwise invalidate reports still in flight
///   from the connection that just dropped, turning ordinary reconnect churn
///   into spurious rejections.
///
/// # Why nonzero
///
/// 0 is the wire's legacy/unknown sentinel: the controller accepts any report
/// where either side's value is 0 (an old client, or a report arriving while
/// the controller's in-memory store is empty after ITS own restart). A
/// gateway that implements the scheme must therefore never send 0, or it
/// silently opts itself out.
pub fn session_generation() -> u64 {
    static SESSION_GENERATION: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *SESSION_GENERATION.get_or_init(|| {
        use rand::RngCore as _;
        // Retry rather than `| 1` / `saturating_add`: biasing the value would
        // be harmless here, but a plain loop keeps the distribution uniform
        // and the intent (nonzero) obvious. `next_u64` returning 0 is a
        // ~1-in-2^64 event, so this never spins in practice.
        loop {
            let v = rand::rngs::OsRng.next_u64();
            if v != 0 {
                return v;
            }
        }
    })
}

/// Opens the desired-state `Sync.Watch` stream.
///
/// Fills [`session_generation`] ITSELF rather than taking it as a parameter:
/// there is exactly one `watch` wrapper and one [`report`] wrapper in this
/// crate, so having each stamp the nonce makes "every place it must be sent"
/// structurally closed — a new call site cannot forget it, because there is
/// no way to construct the request without going through here.
pub async fn watch(
    client: &mut SyncClient<Channel>,
) -> anyhow::Result<tonic::Streaming<SyncMessage>> {
    Ok(client
        .watch(WatchRequest {
            session_generation: session_generation(),
        })
        .await
        .map_err(|s| anyhow!("Sync.Watch failed: {s}"))?
        .into_inner())
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
///
/// `peer_paths` (directive-storm fix + CodeRabbit snapshot follow-up) is
/// this gateway's complete current per-peer path-state SNAPSHOT (one entry
/// per tracked peer in `ctx.paths`, `state` = `PathState::as_str()`'s
/// lowercase label), which the controller's broker uses to stop re-punching
/// a pair BOTH sides report settled ("direct"/"relayed" —
/// make-before-break awareness). The `Option` encodes the wire's
/// `peer_paths_snapshot` flag so the two shapes can't be mixed up:
///
/// - `Some(paths)` — a genuine snapshot (the steady-state sync loop, every
///   `Report` call): sets `peer_paths_snapshot: true`, so the broker
///   REPLACES this gateway's stored states with `paths` — INCLUDING
///   `Some(vec![])`, which clears them (no tracked paths is real
///   information; without the flag an empty list would be
///   indistinguishable from an old client and the broker's stored states
///   would go stale until reconnect — reports are event-driven, sent when
///   a `SyncEvent::State` applies, not periodic, so "the next report fixes
///   it soon" holds no water).
/// - `None` — not a path snapshot (the rotation observation tick's unary
///   epoch-ack report): sends the legacy shape (empty list,
///   `peer_paths_snapshot: false`), a broker NO-OP that must never wipe
///   the states the last real snapshot established mid-rotation.
///
/// `session_generation` is stamped HERE, from the process-wide
/// [`session_generation`] nonce — deliberately not a parameter, for the
/// reason given on [`watch`]. Both report paths (the sync loop's steady-state
/// snapshot report and the rotation tick's unary epoch ack, which dials its
/// own channel) route through this one function, so neither can be missed and
/// neither needed a signature change.
pub async fn report(
    client: &mut SyncClient<Channel>,
    applied_version: u64,
    local_endpoints: Vec<String>,
    relay_health: Vec<RelayHealth>,
    epoch_acks: Vec<EpochAck>,
    peer_paths: Option<Vec<PeerPath>>,
) -> anyhow::Result<()> {
    let (peer_paths, peer_paths_snapshot) = match peer_paths {
        Some(paths) => (paths, true),
        None => (Vec::new(), false),
    };
    client
        .report(ReportRequest {
            applied_version,
            local_endpoints,
            relay_health,
            epoch_acks,
            peer_paths,
            peer_paths_snapshot,
            session_generation: session_generation(),
        })
        .await
        .map_err(|s| anyhow!("Sync.Report failed: {s}"))?;
    Ok(())
}

/// Submit this gateway's freshly-minted REAL WireGuard public key for a
/// pending rotation `epoch` (key-rotation Role A) — the private key never
/// leaves the gateway. The controller overwrites the epoch's
/// `awaiting-submission` sentinel with `pubkey`, then fans it out to peers so
/// they can bring up their overlap Device toward the real key.
///
/// Stamps [`session_generation`] itself, like [`watch`] and [`report`] — this
/// is the crate's only `SubmitEpochKey` call site, so the nonce cannot be
/// forgotten by a future caller. It matters here specifically: the
/// controller's swap onto the sentinel is first-writer-wins, so a submission
/// still in flight from a PREVIOUS process can beat this one and install a
/// key this gateway is not serving (see the field's doc in `sync.proto`).
/// The generation is what makes the live process's submission the winner.
pub async fn submit_epoch_key(
    client: &mut SyncClient<Channel>,
    epoch: u32,
    pubkey: String,
) -> anyhow::Result<()> {
    client
        .submit_epoch_key(SubmitEpochKeyRequest {
            epoch,
            pubkey,
            session_generation: session_generation(),
        })
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
    let Some(msg) = stream.next().await else {
        return Ok(None);
    };
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
            let cur = current
                .as_mut()
                .ok_or_else(|| anyhow!("delta before snapshot"))?;
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
        assert!(
            current.is_some(),
            "snapshot must seed current desired state"
        );
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
        assert!(
            current.is_none(),
            "a punch directive must not fold into desired state"
        );
    }

    #[test]
    fn classify_rotate_yields_rotate_event() {
        let mut current = None;
        let rotate = wiremesh_proto::v1::RotateDirective { epoch: 5 };
        match classify(Some(Body::Rotate(rotate)), &mut current).unwrap() {
            SyncEvent::Rotate(d) => assert_eq!(d.epoch, 5),
            other => panic!("expected Rotate, got {other:?}"),
        }
        assert!(
            current.is_none(),
            "a rotate directive must not fold into desired state"
        );
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
