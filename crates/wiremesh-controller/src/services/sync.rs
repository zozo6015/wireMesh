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

use std::pin::Pin;

use base64::Engine as _;
use tokio::sync::broadcast;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status};

use wiremesh_proto::v1::sync_server::Sync;
use wiremesh_proto::v1::sync_message::Body;
use wiremesh_proto::v1::{ReportRequest, ReportResponse, SyncMessage, WatchRequest};

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
}

impl SyncSvc {
    pub fn new(db: DbHandle, change_tx: broadcast::Sender<ChangeEvent>) -> Self {
        Self { db, change_tx }
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

        let stream: Self::WatchStream =
            Box::pin(tokio_stream::once(Ok(snapshot_msg)).chain(delta_stream));
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

        // (Cycle-4b Task 4, spec §6.1) `local_endpoints` is additive: an
        // empty list (a pre-4b gateway binary, or one that just hasn't
        // enumerated any routable local address this round) must be a
        // no-op — `Db::set_local_candidates` already treats "identical to
        // what's stored" as a no-op (returns `None`, no write, no revision
        // bump), but an explicitly EMPTY report must never be allowed to
        // WIPE an already-recorded local candidate set just because the
        // caller sent nothing this round. Skip the call entirely rather
        // than replacing a non-empty stored set with an empty one.
        if !req.local_endpoints.is_empty() {
            let revision = self
                .db
                .set_local_candidates(gw.id, req.local_endpoints)
                .await
                .map_err(|e| Status::internal(format!("recording local_endpoints: {e}")))?;

            // `None` means the deduplicated incoming set was IDENTICAL to
            // what's already stored (see `Db::set_local_candidates`'s doc
            // comment) — nothing changed, so there is nothing new for an
            // already-connected peer to learn; skip the publish entirely
            // (mirrors `crate::observe::handle_probe`'s identical
            // early-return on an unchanged observed endpoint).
            if let Some(revision) = revision {
                // Re-reads the gateway's current identity/allowed_ips/keys
                // and its FULL current candidate set (observed + locals) —
                // same "full peer refresh" pattern
                // `crate::observe::handle_probe` already uses for the
                // sibling `EndpointObserved` event, reused as-is here since
                // its `Delta` shape already carries `candidate_endpoints`
                // straight off `Db::candidates_for` (see that event's doc
                // comment).
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
