//! `Admin` service (minimal, cycle-2 Task 4 slice): `CreateSegment` and
//! `MintToken`. `ListGateways` is part of the wire contract already (grown
//! further in Task 13) but out of this task's scope — it returns
//! `Unimplemented` rather than silently faking data.

use std::str::FromStr;

use ipnet::Ipv4Net;
use rand::RngCore;
use sha2::{Digest, Sha256};
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::sync::broadcast;
use tonic::{Request, Response, Status};

use wiremesh_proto::v1::admin_server::Admin;
use wiremesh_proto::v1::{
    CreateSegmentRequest, DebugKeyStatesRequest, DebugKeyStatesResponse, DrainRequest,
    DrainResponse, GatewayKeyState, ListGatewaysRequest, ListGatewaysResponse, MintTokenRequest,
    MintTokenResponse, RotateKeyRequest, RotateKeyResponse, Segment,
};

use crate::db_async::DbHandle;
use crate::projection::ChangeEvent;

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
    /// (Task 11) Publishes a [`ChangeEvent::KeyRotated`] after a successful
    /// `RotateKey`, same fan-out channel `EnrollmentSvc` publishes
    /// `GatewayEnrolled` on — see `crate::services::sync` for the
    /// subscriber side.
    change_tx: broadcast::Sender<ChangeEvent>,
}

impl AdminSvc {
    pub fn new(
        db: DbHandle,
        ca_root_fingerprint_hex: String,
        host: String,
        change_tx: broadcast::Sender<ChangeEvent>,
    ) -> Self {
        Self {
            db,
            ca_root_fingerprint_hex,
            host,
            change_tx,
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

        // Validate each bound CIDR as IPv4 up front (mirrors CreateSegment) so
        // a malformed CIDR is rejected at mint time rather than surfacing much
        // later at enrollment.
        for c in &req.bound_cidrs {
            Ipv4Net::from_str(c).map_err(|e| {
                Status::invalid_argument(format!("invalid IPv4 bound_cidr {c:?}: {e}"))
            })?;
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
                encode_bound_cidrs(&req.bound_cidrs),
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

    /// (Task 11) Starts a make-before-break key-epoch rotation: see
    /// [`crate::db::Db::rotate_key`] for the transactional bookkeeping
    /// (new `pending` epoch + audit + revision bump, all atomic). After that
    /// commits, re-reads the gateway's segment identity, `allowed_ips`, and
    /// FULL current key set (including the just-inserted pending row) to
    /// publish a [`ChangeEvent::KeyRotated`] — this is what pushes a `Delta`
    /// down every OTHER already-connected gateway's still-open `Sync.Watch`
    /// stream, same fan-out pattern `EnrollmentSvc::enroll` uses for
    /// `GatewayEnrolled`.
    async fn rotate_key(
        &self,
        request: Request<RotateKeyRequest>,
    ) -> Result<Response<RotateKeyResponse>, Status> {
        let req = request.into_inner();
        let gateway_id = req.gateway_id as i64;

        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| Status::internal(format!("formatting current time: {e}")))?;

        let outcome = self.db.rotate_key(gateway_id, now).await.map_err(|e| {
            let msg = e.to_string();
            if msg.contains("no gateway row") {
                Status::not_found(msg)
            } else {
                Status::internal(format!("rotating key: {e}"))
            }
        })?;

        // Publish so already-connected peers see the new pending key. A
        // missing identity here would mean the gateway vanished between
        // `rotate_key`'s existence check and this re-read — treated as an
        // internal error (shouldn't happen: nothing in cycle-2 deletes
        // gateway rows).
        let identity = self
            .db
            .gateway_identity_by_id(gateway_id)
            .await
            .map_err(|e| Status::internal(format!("re-reading gateway after rotation: {e}")))?
            .ok_or_else(|| {
                Status::internal(format!(
                    "gateway {gateway_id} vanished immediately after RotateKey committed"
                ))
            })?;
        let allowed_ips = self
            .db
            .cidrs_for_segment(identity.segment_id)
            .await
            .map_err(|e| Status::internal(format!("reading segment cidrs after rotation: {e}")))?;
        let keys = self
            .db
            .all_keys_for_gateway(gateway_id)
            .await
            .map_err(|e| Status::internal(format!("reading gateway keys after rotation: {e}")))?;
        let revision = self
            .db
            .current_revision()
            .await
            .map_err(|e| Status::internal(format!("reading revision after rotation: {e}")))?;

        // `send` errors only when there are currently no `Sync.Watch`
        // subscribers — nobody to notify, which is not a failure (mirrors
        // `EnrollmentSvc::enroll`'s identical `let _ =`).
        let _ = self.change_tx.send(ChangeEvent::KeyRotated {
            gateway_id,
            segment_name: identity.segment_name,
            allowed_ips,
            keys,
            revision,
        });

        Ok(Response::new(RotateKeyResponse {
            epoch: outcome.epoch as u32,
            pubkey: outcome.pubkey,
            state: "pending".to_string(),
        }))
    }

    /// (Task 11) Debug/test accessor: every `gateway_key` row (any state)
    /// for a gateway, straight off the DB — not part of the gateway-facing
    /// Sync projection. Backs `wiremesh-testkit::TestController::debug_key_states`,
    /// which `tests/keys.rs` uses to prove the rotation's `pending` epoch
    /// survives a controller restart (i.e. it's DB-backed, not just
    /// in-memory).
    async fn debug_key_states(
        &self,
        request: Request<DebugKeyStatesRequest>,
    ) -> Result<Response<DebugKeyStatesResponse>, Status> {
        let req = request.into_inner();
        let rows = self
            .db
            .all_keys_for_gateway(req.gateway_id as i64)
            .await
            .map_err(|e| Status::internal(format!("reading key states: {e}")))?;
        Ok(Response::new(DebugKeyStatesResponse {
            keys: rows
                .into_iter()
                .map(|(epoch, _pubkey, state)| GatewayKeyState {
                    epoch: epoch as u32,
                    state,
                })
                .collect(),
        }))
    }

    /// (Task 12, G-7) Drains `gateway_id`: [`crate::db_async::DbHandle::drain_gateway`]
    /// atomically revokes its still-unrevoked cert(s), marks its `gateway`
    /// row `status = 'removed'`, appends an audit entry, and bumps the
    /// persisted revision — all BEFORE this handler publishes anything, same
    /// "mutate durably first, then notify" order `RotateKey`/`enroll` use.
    ///
    /// Ack-wait: cycle-2 has no real per-peer ack channel to wait on (the
    /// master-spec's "waits for acks (or 5s)" describes a later cycle's
    /// fully-tracked withdrawal). Rather than block this RPC for a fixed
    /// window that serves no one (the mutation has already committed by the
    /// time any peer could ack it, and no code path reads such an ack), this
    /// returns as soon as the withdrawal `Delta` is published — an immediate,
    /// zero-wait bound that trivially satisfies "at most 5s" without making
    /// every `Drain` call pay a latency tax it can't act on.
    async fn drain(
        &self,
        request: Request<DrainRequest>,
    ) -> Result<Response<DrainResponse>, Status> {
        let req = request.into_inner();
        let gateway_id = req.gateway_id as i64;

        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| Status::internal(format!("formatting current time: {e}")))?;

        let outcome = self.db.drain_gateway(gateway_id, now).await.map_err(|e| {
            let msg = e.to_string();
            if msg.contains("no gateway row") {
                Status::not_found(msg)
            } else {
                Status::internal(format!("draining gateway: {e}"))
            }
        })?;

        let revision = self
            .db
            .current_revision()
            .await
            .map_err(|e| Status::internal(format!("reading revision after drain: {e}")))?;

        // `send` errors only when there are currently no `Sync.Watch`
        // subscribers — nobody to notify, which is not a failure (mirrors
        // `EnrollmentSvc::enroll`/`AdminSvc::rotate_key`'s identical `let _ =`).
        let _ = self.change_tx.send(ChangeEvent::GatewayDrained {
            gateway_id,
            revoked_serials: outcome.revoked_serials,
            revision,
        });

        Ok(Response::new(DrainResponse {}))
    }
}

fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// Encode/decode contract for `enrollment_token.bound_cidrs` (consumed by T5
/// Enrollment + T10 rebind):
///
/// - Storage is a comma-joined string of the CIDR strings.
/// - **An empty set stores the empty string `""`** and MUST decode back to an
///   empty `Vec`, NOT `[""]`. A naive `s.split(',')` yields one empty element
///   for `""`, which would then fail CIDR parsing at enrollment — so decoders
///   MUST short-circuit the empty string to `[]`. [`decode_bound_cidrs`] is
///   the canonical decoder; T5/T10 should call it rather than re-split.
///
/// (Comma-join is safe because every element is a validated IPv4 CIDR — no
/// element can itself contain a comma.)
fn encode_bound_cidrs(cidrs: &[String]) -> String {
    cidrs.join(",")
}

/// Canonical decoder for [`encode_bound_cidrs`] — treats `""` as the empty
/// set (see that function's contract). Kept `pub` so the Enrollment/rebind
/// services parse `bound_cidrs` through exactly this, not an ad-hoc split.
pub fn decode_bound_cidrs(stored: &str) -> Vec<String> {
    if stored.is_empty() {
        return Vec::new();
    }
    stored.split(',').map(|s| s.to_string()).collect()
}
