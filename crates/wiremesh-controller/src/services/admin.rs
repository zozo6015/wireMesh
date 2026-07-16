//! `Admin` service (minimal, cycle-2 Task 4 slice): `CreateSegment` and
//! `MintToken`. `ListGateways` is part of the wire contract already (grown
//! further in Task 13) but out of this task's scope — it returns
//! `Unimplemented` rather than silently faking data.

use std::str::FromStr;

use ipnet::Ipv4Net;
use rand::RngCore;
use sha2::{Digest, Sha256};
use time::{Duration as TimeDuration, OffsetDateTime};
use tonic::{Request, Response, Status};

use wiremesh_proto::v1::admin_server::Admin;
use wiremesh_proto::v1::{
    CreateSegmentRequest, ListGatewaysRequest, ListGatewaysResponse, MintTokenRequest,
    MintTokenResponse, Segment,
};

use crate::db_async::DbHandle;

/// A freshly minted enrollment token's raw secret is never persisted —
/// [`enrollment_token.secret_hash`] stores only its sha256. Cycle-2 tokens
/// are valid for this long from mint time (no renewal path yet; a later task
/// can make this configurable).
const TOKEN_TTL: TimeDuration = TimeDuration::hours(24);

/// Minimum accepted secret length, per the task brief ("≥32 bytes").
const SECRET_LEN: usize = 32;

pub struct AdminSvc {
    db: DbHandle,
    /// hex-encoded sha256 of the embedded CA's root certificate DER —
    /// embedded in every minted token so a gateway can pin the controller it
    /// expects to enroll against.
    ca_root_fingerprint_hex: String,
    /// Host (currently the controller's TCP address) stamped into the
    /// `wiremesh://<host>/...` token URL.
    host: String,
}

impl AdminSvc {
    pub fn new(db: DbHandle, ca_root_fingerprint_hex: String, host: String) -> Self {
        Self {
            db,
            ca_root_fingerprint_hex,
            host,
        }
    }
}

#[tonic::async_trait]
impl Admin for AdminSvc {
    async fn create_segment(
        &self,
        request: Request<CreateSegmentRequest>,
    ) -> Result<Response<Segment>, Status> {
        let req = request.into_inner();

        if req.name.is_empty() {
            return Err(Status::invalid_argument("segment name must not be empty"));
        }

        let cidrs: Vec<Ipv4Net> = req
            .cidrs
            .iter()
            .map(|c| {
                Ipv4Net::from_str(c)
                    .map_err(|e| Status::invalid_argument(format!("invalid IPv4 CIDR {c:?}: {e}")))
            })
            .collect::<Result<_, _>>()?;

        let segment_id = self
            .db
            .insert_segment(req.name.clone(), cidrs)
            .await
            .map_err(|e| {
                // `OverlapError` (and any other insert failure) surfaces as
                // `already_exists` — the one condition this op can fail on
                // besides a bad request.
                Status::already_exists(e.to_string())
            })?;

        self.db
            .audit(
                "unix-socket".into(),
                "create".into(),
                format!("segment/{}", req.name),
                format!(r#"{{"name":"{}","cidrs":{:?}}}"#, req.name, req.cidrs),
            )
            .await
            .map_err(|e| Status::internal(format!("audit append failed: {e}")))?;

        Ok(Response::new(Segment {
            id: segment_id as u64,
            name: req.name,
            cidrs: req.cidrs,
        }))
    }

    async fn mint_token(
        &self,
        request: Request<MintTokenRequest>,
    ) -> Result<Response<MintTokenResponse>, Status> {
        let req = request.into_inner();

        if req.kind.is_empty() {
            return Err(Status::invalid_argument("token kind must not be empty"));
        }

        let mut secret = [0u8; SECRET_LEN];
        rand::thread_rng().fill_bytes(&mut secret);
        let secret_hex = hex_encode(&secret);
        let secret_hash_hex = hex_encode(&Sha256::digest(secret));

        let mut id_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut id_bytes);
        let token_id = hex_encode(&id_bytes);

        let rebind_segment_id = if req.rebind_segment_id == 0 {
            None
        } else {
            Some(req.rebind_segment_id as i64)
        };

        let expires_at = (OffsetDateTime::now_utc() + TOKEN_TTL)
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| Status::internal(format!("formatting token expiry: {e}")))?;

        self.db
            .insert_enrollment_token(
                token_id,
                secret_hash_hex,
                req.kind.clone(),
                req.bound_cidrs.join(","),
                rebind_segment_id,
                expires_at,
            )
            .await
            .map_err(|e| Status::internal(format!("storing enrollment token: {e}")))?;

        self.db
            .audit(
                "unix-socket".into(),
                "mint".into(),
                "enrollment_token".into(),
                format!(r#"{{"kind":"{}"}}"#, req.kind),
            )
            .await
            .map_err(|e| Status::internal(format!("audit append failed: {e}")))?;

        let token = format!(
            "wiremesh://{}/#tok_{}@sha256:{}",
            self.host, secret_hex, self.ca_root_fingerprint_hex
        );

        Ok(Response::new(MintTokenResponse { token }))
    }

    async fn list_gateways(
        &self,
        _request: Request<ListGatewaysRequest>,
    ) -> Result<Response<ListGatewaysResponse>, Status> {
        // Out of Task 4's scope (Task 13 grows Admin CRUD). Explicit
        // Unimplemented rather than a silently-empty list, so a caller can't
        // mistake "not built yet" for "no gateways registered".
        Err(Status::unimplemented(
            "ListGateways is not implemented yet",
        ))
    }
}

fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}
