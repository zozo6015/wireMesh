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
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use wiremesh_proto::v1::sync_server::Sync;
use wiremesh_proto::v1::sync_message::Body;
use wiremesh_proto::v1::{ReportRequest, ReportResponse, SyncMessage, WatchRequest};

use crate::db_async::DbHandle;
use crate::projection;

pub type WatchStream = Pin<Box<dyn Stream<Item = Result<SyncMessage, Status>> + Send + 'static>>;

pub struct SyncSvc {
    db: DbHandle,
}

impl SyncSvc {
    pub fn new(db: DbHandle) -> Self {
        Self { db }
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

        let snapshot = projection::build_snapshot(&self.db, gw.id, self_cert_pem)
            .await
            .map_err(|e| Status::internal(format!("building Sync snapshot: {e}")))?;

        let msg = SyncMessage {
            body: Some(Body::Snapshot(snapshot)),
        };
        let stream: Self::WatchStream = Box::pin(tokio_stream::once(Ok(msg)));
        Ok(Response::new(stream))
    }

    async fn report(
        &self,
        _request: Request<ReportRequest>,
    ) -> Result<Response<ReportResponse>, Status> {
        // Policy-ack reporting is out of this task's scope (the policy
        // pipeline that would give `applied_version` any meaning doesn't
        // exist yet) — explicit Unimplemented rather than silently
        // accepting and discarding acks.
        Err(Status::unimplemented("Report is not implemented yet"))
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
