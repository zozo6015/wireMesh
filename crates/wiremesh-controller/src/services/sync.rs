//! `Sync` service (Task 7): the ONLY mTLS-gated surface in cycle-2. Unlike
//! Enrollment (server-TLS only — the caller has no client cert yet),
//! `serve()` binds this service's TCP listener with a
//! `tonic::transport::ServerTlsConfig` whose `client_ca_root` is the
//! embedded CA's own bundle and `client_auth_optional` left at its default
//! `false` — meaning tonic/rustls REJECT the TLS handshake outright for any
//! connection that doesn't present a client certificate chaining to that CA.
//! A request handler in this file only ever runs once that handshake has
//! already succeeded.
//!
//! Gateway identity is derived ONLY from the peer certificate tonic/rustls
//! already validated (`Request::peer_certs`) — specifically its subject
//! CN, looked up against `gateway.name` (the same value `EnrollmentSvc`
//! derived from the enrollment token and stamped as the issued leaf's
//! subject CN; see `services::enrollment`). Nothing client-supplied (e.g. a
//! field in `WatchRequest`) is trusted as identity — `WatchRequest` is
//! (deliberately) an empty message.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use base64::Engine as _;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::wrappers::{BroadcastStream, ReceiverStream};
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status};

use wiremesh_proto::v1::sync_server::Sync;
use wiremesh_proto::v1::sync_message::Body;
use wiremesh_proto::v1::{ReportRequest, ReportResponse, SyncMessage, WatchRequest};

use crate::broker::{Broker, RegistrationGuard, PUNCH_CHANNEL_CAPACITY};
use crate::db_async::DbHandle;
use crate::projection::{self, ChangeEvent};

pub type WatchStream = Pin<Box<dyn Stream<Item = Result<SyncMessage, Status>> + Send + 'static>>;

pub struct SyncSvc {
    db: DbHandle,
    /// Fan-out source for delta events (Task 8): every projection-affecting
    /// mutation that adds/changes a gateway publishes one
    /// [`ChangeEvent`] here (see `crate::services::enrollment`); every live
    /// `Sync.Watch` connection below subscribes its own receiver and
    /// forwards relevant events as `Delta`s down its still-open stream.
    change_tx: broadcast::Sender<ChangeEvent>,
    /// (Cycle-4b Task 5) The Sync broker. Every `Watch` connection registers
    /// its per-connection punch channel into the broker's shared registry
    /// (keyed by the AUTHENTICATED gateway id) so the broker can push a
    /// `PunchDirective` explicitly to BOTH members of a pair — deliberately
    /// NOT the `subject_gateway_id()` self-skip path the deltas below use.
    broker: Arc<Broker>,
    /// (Cycle-4c Task 6) In-memory relay health votes: `relay_id -> (gw_id ->
    /// healthy)`. Populated exclusively by `report`'s `req.relay_health`
    /// handling below. Deliberately NOT persisted — lost on controller
    /// restart is an accepted tradeoff (see the design notes' "known
    /// limitation" section): a relay defaults back to whatever its DB
    /// `status` already was (unaffected by this map resetting), and any
    /// gateway that still considers a relay live/dead simply re-reports on
    /// its next `Report` call. `Arc` so every `SyncSvc` produced by cloning
    /// (if ever) — and, more immediately, every concurrent `report` call
    /// against the same shared service instance — sees and mutates the SAME
    /// map rather than a private copy. A plain `std::sync::Mutex` is fine:
    /// every critical section below is a short, synchronous map read/write
    /// with no `.await` inside the locked region (the lock is dropped before
    /// any DB call or broadcast send).
    relay_health: Arc<Mutex<HashMap<i64, HashMap<i64, bool>>>>,
}

impl SyncSvc {
    pub fn new(
        db: DbHandle,
        change_tx: broadcast::Sender<ChangeEvent>,
        broker: Arc<Broker>,
    ) -> Self {
        Self {
            db,
            change_tx,
            broker,
            relay_health: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// (Cycle-4c Task 6) Re-reads the current active-relay set + persisted
    /// revision and publishes ONE `ChangeEvent::RelaysChanged` — the shared
    /// tail end of both the enrollment path (`EnrollmentSvc::enroll`'s
    /// relay-enrollment branch) and this file's health-driven eviction/
    /// re-admission path. Active relays are read FIRST, then the revision
    /// LAST (per the Cycle-4c Task 5 review fix): this guarantees the
    /// revision attached to the emitted delta is >= the state the advertised
    /// `relays` reflect, so an open `Sync.Watch` stream never sees the
    /// revision regress relative to the relay set it just applied (see
    /// `projection.rs`). Best-effort: a failure reading either is silently
    /// swallowed (mirrors every other best-effort `change_tx.send` call in
    /// this crate — a transient DB read failure here must never turn an
    /// otherwise-successful `Report`/`Enroll` call into an error response),
    /// and `send` itself only ever errors when there are currently no
    /// `Sync.Watch` subscribers, which is not a failure either.
    async fn emit_relays_changed(&self) {
        if let Ok(active) = self.db.active_relays().await {
            if let Ok(revision) = self.db.current_revision().await {
                let relays = active
                    .into_iter()
                    .map(|(id, endpoint)| wiremesh_proto::v1::RelayInfo {
                        relay_id: id as u64,
                        endpoint,
                    })
                    .collect();
                let _ = self
                    .change_tx
                    .send(ChangeEvent::RelaysChanged { relays, revision });
            }
        }
    }
}

/// Wraps the `Watch` response stream with its [`RegistrationGuard`] so the
/// connection's broker registry entry is removed exactly when the stream is
/// dropped (client disconnect, RPC end, or a dropped `Response`) — the guard
/// is a plain field, so it drops with the struct and no explicit deregister
/// call is needed. Poll is a straight delegation to the inner stream.
struct GuardedWatchStream {
    _guard: RegistrationGuard,
    inner: WatchStream,
}

impl Stream for GuardedWatchStream {
    type Item = Result<SyncMessage, Status>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

#[tonic::async_trait]
impl Sync for SyncSvc {
    type WatchStream = WatchStream;

    async fn watch(
        &self,
        request: Request<WatchRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        let (gateway_name, self_cert_pem) = peer_identity(&request)?;

        let gw = self
            .db
            .find_gateway_by_name(gateway_name)
            .await
            .map_err(|e| Status::internal(format!("looking up gateway by cert CN: {e}")))?
            .ok_or_else(|| {
                Status::permission_denied(
                    "client certificate's CN does not match any enrolled gateway",
                )
            })?;

        // Subscribe BEFORE building the snapshot. `build_snapshot` has
        // internal `await` points (each `DbHandle` call hops onto
        // `spawn_blocking`), so a `ChangeEvent` published in the window
        // between the snapshot's DB read and here would otherwise be LOST:
        // committed too late to appear in the snapshot, yet published before
        // a receiver existed to buffer it — the gateway would silently miss
        // that peer until its next reconnect. Subscribing first closes the
        // window: any event arriving during snapshot-building is buffered in
        // `rx` and delivered as a Delta right after the snapshot. At worst
        // that's a redundant upsert for a peer already in the snapshot
        // (whose Delta `revision` may even equal the snapshot's in the rare
        // overlap) — harmless, since `upserted_peers` is idempotent on the
        // client.
        let self_gateway_id = gw.id;
        let rx = self.change_tx.subscribe();

        // (Cycle-4b Task 5) The per-connection broker punch channel: the broker
        // pushes `SyncMessage{Punch}` here (keyed by this connection's
        // AUTHENTICATED gateway id), merged into the outgoing stream below
        // alongside the broadcast deltas. `guard`'s Drop deregisters this
        // channel when the stream ends (see `GuardedWatchStream`), so a
        // panic/early-return still cleans up the registry entry.
        let (punch_tx, punch_rx) = mpsc::channel::<SyncMessage>(PUNCH_CHANNEL_CAPACITY);
        let guard = self.broker.register(self_gateway_id, punch_tx);

        let snapshot = projection::build_snapshot(&self.db, gw.id, self_cert_pem)
            .await
            .map_err(|e| Status::internal(format!("building Sync snapshot: {e}")))?;

        let snapshot_msg = SyncMessage {
            body: Some(Body::Snapshot(snapshot)),
        };
        // First message on the stream is always the full snapshot (must
        // stay true — `tests/sync_snapshot.rs` asserts it). The stream then
        // stays OPEN: every subsequent projection-affecting mutation
        // published on `change_tx` (currently only gateway enrollment —
        // see `crate::services::enrollment`) is forwarded as a `Delta`,
        // for as long as this gRPC call is alive.
        // `lagged` latches once this connection's receiver falls behind the
        // broadcast channel's ring buffer: from that point on, the
        // gateway's view of the projection is provably INCOMPLETE (deltas
        // it never saw were dropped), so silently continuing (the old
        // behavior) would leave it stale indefinitely with no client-side
        // way to detect the gap. Instead, `map_while` below emits exactly
        // ONE final `Err(Unavailable)` item and then ends the stream (once
        // `lagged` is set, every subsequent poll returns `None`, which
        // `map_while` treats as end-of-stream) — tonic surfaces that `Err`
        // item as the RPC's final status, forcing the gateway to reconnect
        // and re-fetch a fresh, fully-consistent snapshot rather than
        // silently trusting a gapped delta stream.
        let mut lagged = false;
        let delta_stream = BroadcastStream::new(rx)
            .map_while(move |item| {
                if lagged {
                    return None;
                }
                match item {
                    Ok(event) => {
                        // A gateway must never receive a delta
                        // "adding"/"updating" itself as its own peer —
                        // skip it (`Some(None)`), but keep the stream open.
                        if event.subject_gateway_id() == self_gateway_id {
                            Some(None)
                        } else {
                            let delta = projection::delta_for_change(event);
                            Some(Some(Ok(SyncMessage {
                                body: Some(Body::Delta(delta)),
                            })))
                        }
                    }
                    Err(BroadcastStreamRecvError::Lagged(skipped)) => {
                        eprintln!(
                            "wiremesh-controller: Sync.Watch for gateway {self_gateway_id} lagged \
                             behind the change broadcast by {skipped} event(s); terminating the \
                             stream so the gateway reconnects and re-snapshots"
                        );
                        lagged = true;
                        Some(Some(Err(Status::unavailable(format!(
                            "Sync.Watch lagged behind the change broadcast by {skipped} event(s); \
                             reconnect to receive a fresh, consistent snapshot"
                        )))))
                    }
                }
            })
            .filter_map(|opt| opt);

        // (Cycle-4b Task 5) The per-connection punch stream, MERGED with the
        // broadcast deltas. `select!`-style fairness between {broadcast delta,
        // broker punch channel} is exactly what `StreamExt::merge` provides —
        // whichever has an item ready is yielded. The `Snapshot` stays the
        // guaranteed FIRST message (chained ahead of the merge), so existing
        // snapshot/delta/self-skip behavior is unchanged; punches are simply an
        // additional interleaved item type. Unlike deltas, a punch is NOT
        // subject to the `subject_gateway_id()` self-skip — the broker already
        // targeted THIS connection's channel explicitly.
        let punch_stream = ReceiverStream::new(punch_rx).map(Ok::<SyncMessage, Status>);
        let merged = delta_stream.merge(punch_stream);

        let inner: Self::WatchStream =
            Box::pin(tokio_stream::once(Ok(snapshot_msg)).chain(merged));

        // (Cycle-4b Task 5) Trigger (a): now that this connection is registered,
        // give the broker a chance to punch any peer that is already connected
        // with a mutual candidate set. Spawned (not awaited) so building the
        // Watch response doesn't block on peer/candidate DB reads; the registry
        // insert above already happened, so the spawned task sees this
        // connection as present.
        let broker = self.broker.clone();
        tokio::spawn(async move {
            broker.on_gateway_connected(self_gateway_id).await;
        });

        let stream: Self::WatchStream = Box::pin(GuardedWatchStream {
            _guard: guard,
            inner,
        });
        Ok(Response::new(stream))
    }

    async fn report(
        &self,
        request: Request<ReportRequest>,
    ) -> Result<Response<ReportResponse>, Status> {
        let (gateway_name, _self_cert_pem) = peer_identity(&request)?;

        let gw = self
            .db
            .find_gateway_by_name(gateway_name)
            .await
            .map_err(|e| Status::internal(format!("looking up gateway by cert CN: {e}")))?
            .ok_or_else(|| {
                Status::permission_denied(
                    "client certificate's CN does not match any enrolled gateway",
                )
            })?;

        let req = request.into_inner();
        self.db
            .set_applied_version(gw.id, req.applied_version)
            .await
            .map_err(|e| Status::internal(format!("recording applied_version: {e}")))?;

        // (Cycle-4b Task 8, spec §5/§6.1 — supersedes the Task 4 "empty is a
        // no-op" behavior) The gateway now reports its COMPLETE current
        // local-address set on every `Report` call (there is no per-endpoint
        // add/remove RPC — see `wiremesh_gateway::sync::report`'s doc
        // comment). An empty `local_endpoints` is therefore no longer
        // ambiguous ("didn't report" vs. "reported nothing"): it means the
        // gateway genuinely has no routable local address right now, and
        // must REPLACE (clear) any previously-reported set the same way a
        // non-empty report replaces a different non-empty set —
        // `Db::set_local_candidates`'s full-REPLACE contract already handles
        // this uniformly, so the call is no longer conditioned on
        // non-emptiness.
        let revision = self
            .db
            .set_local_candidates(gw.id, req.local_endpoints)
            .await
            .map_err(|e| Status::internal(format!("recording local_endpoints: {e}")))?;

        // `None` means the deduplicated incoming set was IDENTICAL to
        // what's already stored (see `Db::set_local_candidates`'s doc
        // comment) — nothing changed, so there is nothing new for an
        // already-connected peer to learn; skip the publish entirely
        // (mirrors `crate::observe::handle_probe`'s identical early-return
        // on an unchanged observed endpoint).
        if let Some(revision) = revision {
            // Re-reads the gateway's current identity/allowed_ips/keys and
            // its FULL current candidate set (observed + locals) — same
            // "full peer refresh" pattern `crate::observe::handle_probe`
            // already uses for the sibling `EndpointObserved` event, reused
            // as-is here since its `Delta` shape already carries
            // `candidate_endpoints` straight off `Db::candidates_for` (see
            // that event's doc comment).
            if let Ok(Some(identity)) = self.db.gateway_identity_by_id(gw.id).await {
                if let (Ok(allowed_ips), Ok(keys), Ok(candidate_endpoints)) = (
                    self.db.cidrs_for_segment(identity.segment_id).await,
                    self.db.all_keys_for_gateway(gw.id).await,
                    self.db.candidates_for(gw.id).await,
                ) {
                    let _ = self.change_tx.send(ChangeEvent::EndpointObserved {
                        gateway_id: gw.id,
                        segment_name: identity.segment_name,
                        allowed_ips,
                        keys,
                        candidate_endpoints,
                        revision,
                    });
                }
            }
        }

        // (Cycle-4c Task 6, R-3) Relay health pipeline: aggregate this
        // gateway's votes into the shared `relay_id -> (gw_id -> healthy)`
        // map, then for every relay THIS report touched, compare the fresh
        // aggregate (healthy-override: a relay is unhealthy iff it has >=1
        // vote on record and NONE of them is `true`) against its current DB
        // status, flipping + tracking a change where they now differ. This
        // runs synchronously on the `Report` call that tips the aggregate,
        // so eviction/re-admission is trivially inside the 15s R-3 budget.
        if !req.relay_health.is_empty() {
            let touched_aggregates: Vec<(i64, bool)> = {
                // Held only across the map mutation + aggregate computation
                // below — no `.await` inside this block, so the lock is
                // dropped well before the DB reads/broadcast that follow.
                let mut health = self
                    .relay_health
                    .lock()
                    .expect("relay_health mutex poisoned");
                let mut touched = Vec::with_capacity(req.relay_health.len());
                for vote in &req.relay_health {
                    let relay_id = vote.relay_id as i64;
                    health
                        .entry(relay_id)
                        .or_default()
                        .insert(gw.id, vote.healthy);
                    if !touched.contains(&relay_id) {
                        touched.push(relay_id);
                    }
                }
                touched
                    .into_iter()
                    .map(|relay_id| {
                        let votes = health.get(&relay_id).expect(
                            "relay_id just inserted above must have an entry in the map",
                        );
                        let healthy_agg = votes.values().any(|&h| h);
                        (relay_id, healthy_agg)
                    })
                    .collect()
            };

            let mut any_changed = false;
            for (relay_id, healthy_agg) in touched_aggregates {
                let current_status = self
                    .db
                    .relay_status(relay_id)
                    .await
                    .map_err(|e| Status::internal(format!("reading relay status: {e}")))?;
                let Some(current_status) = current_status else {
                    // Unknown relay id (e.g. a stale report about a relay
                    // row that no longer exists) — nothing to flip.
                    continue;
                };
                let desired_status = if healthy_agg { "active" } else { "inactive" };
                if current_status != desired_status {
                    self.db
                        .set_relay_status(relay_id, desired_status.to_string())
                        .await
                        .map_err(|e| Status::internal(format!("flipping relay status: {e}")))?;
                    any_changed = true;
                }
            }

            if any_changed {
                self.emit_relays_changed().await;
            }
        }

        Ok(Response::new(ReportResponse {}))
    }
}

/// Extracts the calling gateway's identity from the mTLS session: the
/// subject CN of the FIRST certificate in the peer's chain (the leaf the
/// gateway presented), plus that same certificate re-PEM-encoded as
/// `self_cert_pem` for the snapshot. This is the security-critical
/// identity-extraction path this task's brief calls out — identity comes
/// exclusively from the certificate rustls/tonic already cryptographically
/// verified chains to the CA (`ServerTlsConfig::client_ca_root`, configured
/// in `serve()`); nothing in `request`'s message body or metadata is
/// consulted.
///
/// `Request::peer_certs()` is documented by tonic as returning `Some` only
/// for TLS-enabled server connections that actually negotiated a client
/// cert — since `serve()` configures Sync's listener with
/// `client_auth_optional` left at its default `false`, tonic/rustls refuse
/// the handshake itself for a certless client, so in practice this is
/// never `None` by the time a request reaches here. It's still handled as a
/// hard authentication failure rather than `.expect()`-ing, in case a
/// future refactor of the TLS config ever loosens that guarantee.
fn peer_identity<T>(request: &Request<T>) -> Result<(String, String), Status> {
    let certs = request.peer_certs().ok_or_else(|| {
        Status::unauthenticated(
            "Sync requires a client certificate chaining to the fabric CA (mTLS handshake \
             did not yield one)",
        )
    })?;
    let leaf = certs.first().ok_or_else(|| {
        Status::unauthenticated("Sync client presented an empty certificate chain")
    })?;

    let (_, cert) = x509_parser::parse_x509_certificate(leaf)
        .map_err(|e| Status::internal(format!("parsing peer certificate: {e}")))?;
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .ok_or_else(|| Status::permission_denied("peer certificate has no subject CN"))?;

    Ok((cn.to_string(), der_to_pem(leaf)))
}

/// Re-encodes raw certificate DER bytes as a PEM `CERTIFICATE` block
/// (RFC 7468: 64-character base64 lines).
fn der_to_pem(der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).expect("base64 output is always ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}
