//! `Admin` service: segment CRUD (`CreateSegment`/`ListSegments`/
//! `DeleteSegment`), gateway bookkeeping (`ListGateways`/`RotateKey`/
//! `DebugKeyStates`/`Drain`), enrollment-token minting (`MintToken`), relay
//! bookkeeping (`RegisterRelay`/`ListRelays`), API-bearer-token minting/
//! revocation (`MintApiToken`/`RevokeApiToken` — the credential
//! `crate::auth`'s TCP bearer-auth middleware checks; distinct from
//! `MintToken`'s gateway/relay enrollment tokens), single-certificate
//! revocation (`RevokeCert` — Task 16; distinct from `Drain`, which revokes a
//! cert as a side effect of removing the whole gateway), and `AuditQuery`
//! (Task 16 adds `action`/`actor`/`entity` filters).

use std::str::FromStr;

use ipnet::Ipv4Net;
use rand::RngCore;
use sha2::{Digest, Sha256};
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::sync::broadcast;
use tonic::{Request, Response, Status};

use wiremesh_proto::v1::admin_server::Admin;
use wiremesh_proto::v1::{
    ApplyDiff, ApplyRequest, AuditEntry, AuditQueryRequest, AuditQueryResponse,
    CreateSegmentRequest, DebugKeyStatesRequest, DebugKeyStatesResponse, DeleteSegmentRequest,
    DeleteSegmentResponse, DrainRequest, DrainResponse, GatewayInfo, GatewayKeyState,
    ListGatewaysRequest, ListGatewaysResponse, ListRelaysRequest, ListRelaysResponse,
    ListSegmentsRequest, ListSegmentsResponse, MintApiTokenRequest, MintApiTokenResponse,
    MintTokenRequest, MintTokenResponse, RegisterRelayRequest, Relay, RevokeApiTokenRequest,
    RevokeApiTokenResponse, RevokeCertRequest, RevokeCertResponse, RotateKeyRequest,
    RotateKeyResponse, Segment,
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

/// Valid `MintApiTokenRequest.role` values — see `crate::auth`'s bearer-auth
/// middleware, which is the actual enforcement point for what each role can
/// do on the Admin TCP listener.
const VALID_API_TOKEN_ROLES: &[&str] = &["admin", "read-only"];

/// Default `AuditQuery` page size when the caller passes `limit <= 0`.
const DEFAULT_AUDIT_LIMIT: i64 = 50;

#[derive(Clone)]
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

    /// (Task 13) Every `gateway` row (any status), with the segment name it
    /// belongs to and its last-`Sync.Report`-acked `applied_version` —
    /// [`crate::db::Db::list_gateways`] does the actual query. This is what
    /// makes T8's applied-version bookkeeping observable from the Admin
    /// surface for the first time.
    async fn list_gateways(
        &self,
        _request: Request<ListGatewaysRequest>,
    ) -> Result<Response<ListGatewaysResponse>, Status> {
        let rows = self
            .db
            .list_gateways()
            .await
            .map_err(|e| Status::internal(format!("listing gateways: {e}")))?;
        Ok(Response::new(ListGatewaysResponse {
            gateways: rows
                .into_iter()
                .map(|(id, name, segment, status, applied_version)| GatewayInfo {
                    id: id as u64,
                    name,
                    segment,
                    status,
                    applied_version: applied_version.unwrap_or(0) as u64,
                })
                .collect(),
        }))
    }

    /// (Task 13) Every registered segment with its CIDRs — backs
    /// `fabricctl segment list`.
    async fn list_segments(
        &self,
        _request: Request<ListSegmentsRequest>,
    ) -> Result<Response<ListSegmentsResponse>, Status> {
        let rows = self
            .db
            .list_segments()
            .await
            .map_err(|e| Status::internal(format!("listing segments: {e}")))?;
        Ok(Response::new(ListSegmentsResponse {
            segments: rows
                .into_iter()
                .map(|(id, name, cidrs)| Segment {
                    id: id as u64,
                    name,
                    cidrs,
                })
                .collect(),
        }))
    }

    /// (Task 13) Deletes a segment — see [`crate::db::Db::delete_segment`]
    /// for the "no associated gateways" precondition this maps to
    /// `FailedPrecondition`.
    async fn delete_segment(
        &self,
        request: Request<DeleteSegmentRequest>,
    ) -> Result<Response<DeleteSegmentResponse>, Status> {
        let req = request.into_inner();
        let segment_id = req.segment_id as i64;

        self.db.delete_segment(segment_id).await.map_err(|e| {
            let msg = e.to_string();
            if msg.contains("no segment row") {
                Status::not_found(msg)
            } else if msg.contains("has associated gateway") {
                Status::failed_precondition(msg)
            } else {
                Status::internal(format!("deleting segment: {e}"))
            }
        })?;

        self.db
            .audit(
                "unix-socket".into(),
                "delete".into(),
                format!("segment/{segment_id}"),
                "{}".into(),
            )
            .await
            .map_err(|e| Status::internal(format!("audit append failed: {e}")))?;

        Ok(Response::new(DeleteSegmentResponse {}))
    }

    /// (Task 13) Registers a relay — cycle-2 bookkeeping only (no real relay
    /// data-plane wiring yet, mirroring `RotateKey`'s placeholder-pubkey
    /// posture).
    async fn register_relay(
        &self,
        request: Request<RegisterRelayRequest>,
    ) -> Result<Response<Relay>, Status> {
        let req = request.into_inner();
        if req.name.is_empty() {
            return Err(Status::invalid_argument("relay name must not be empty"));
        }
        if req.endpoint.is_empty() {
            return Err(Status::invalid_argument("relay endpoint must not be empty"));
        }

        let relay_id = self
            .db
            .insert_relay(req.name.clone(), req.endpoint.clone())
            .await
            .map_err(|e| Status::already_exists(e.to_string()))?;

        self.db
            .audit(
                "unix-socket".into(),
                "create".into(),
                format!("relay/{}", req.name),
                format!(r#"{{"name":"{}","endpoint":"{}"}}"#, req.name, req.endpoint),
            )
            .await
            .map_err(|e| Status::internal(format!("audit append failed: {e}")))?;

        Ok(Response::new(Relay {
            id: relay_id as u64,
            name: req.name,
            endpoint: req.endpoint,
            status: "active".to_string(),
        }))
    }

    /// (Task 13) Every registered relay — backs `fabricctl relay list`.
    async fn list_relays(
        &self,
        _request: Request<ListRelaysRequest>,
    ) -> Result<Response<ListRelaysResponse>, Status> {
        let rows = self
            .db
            .list_relays()
            .await
            .map_err(|e| Status::internal(format!("listing relays: {e}")))?;
        Ok(Response::new(ListRelaysResponse {
            relays: rows
                .into_iter()
                .map(|(id, name, endpoint, status)| Relay {
                    id: id as u64,
                    name,
                    endpoint,
                    status,
                })
                .collect(),
        }))
    }

    /// (Task 13) Mints a bearer API token: an `admin` or `read-only` role
    /// credential for the Admin TCP listener's bearer-auth middleware
    /// (`crate::auth`) — distinct from [`Self::mint_token`]'s enrollment
    /// tokens, which authorize a GATEWAY/RELAY to enroll, not an
    /// operator/CLI to call Admin. Only the sha256 of the random secret is
    /// ever persisted (same discipline as enrollment tokens) — the plaintext
    /// bearer string returned here is the only time the raw secret exists
    /// outside the caller's own hands.
    async fn mint_api_token(
        &self,
        request: Request<MintApiTokenRequest>,
    ) -> Result<Response<MintApiTokenResponse>, Status> {
        let req = request.into_inner();
        if req.name.is_empty() {
            return Err(Status::invalid_argument("token name must not be empty"));
        }
        if !VALID_API_TOKEN_ROLES.contains(&req.role.as_str()) {
            return Err(Status::invalid_argument(format!(
                "role must be one of {VALID_API_TOKEN_ROLES:?}, got {:?}",
                req.role
            )));
        }

        let mut secret = [0u8; SECRET_LEN];
        rand::thread_rng().fill_bytes(&mut secret);
        let secret_hex = hex_encode(&secret);
        let secret_hash_hex = hex_encode(&Sha256::digest(secret));

        let mut id_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut id_bytes);
        let token_id = hex_encode(&id_bytes);

        self.db
            .insert_api_token(token_id, req.name.clone(), req.role.clone(), secret_hash_hex, None)
            .await
            .map_err(|e| Status::already_exists(e.to_string()))?;

        self.db
            .audit(
                "unix-socket".into(),
                "mint".into(),
                format!("api_token/{}", req.name),
                format!(r#"{{"role":"{}"}}"#, req.role),
            )
            .await
            .map_err(|e| Status::internal(format!("audit append failed: {e}")))?;

        Ok(Response::new(MintApiTokenResponse { token: secret_hex }))
    }

    /// (Task 13) Revokes an API token by name — after this, `crate::auth`'s
    /// lookup no longer finds it (its `secret_hash` still matches a row, but
    /// `revoked_at` is now set), so any bearer credential built from it is
    /// rejected `Unauthenticated` on its very next TCP Admin call.
    async fn revoke_api_token(
        &self,
        request: Request<RevokeApiTokenRequest>,
    ) -> Result<Response<RevokeApiTokenResponse>, Status> {
        let req = request.into_inner();

        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| Status::internal(format!("formatting current time: {e}")))?;

        let found = self
            .db
            .revoke_api_token(req.name.clone(), now)
            .await
            .map_err(|e| Status::internal(format!("revoking API token: {e}")))?;
        if !found {
            return Err(Status::not_found(format!(
                "no api_token row named {:?}",
                req.name
            )));
        }

        self.db
            .audit(
                "unix-socket".into(),
                "revoke".into(),
                format!("api_token/{}", req.name),
                "{}".into(),
            )
            .await
            .map_err(|e| Status::internal(format!("audit append failed: {e}")))?;

        Ok(Response::new(RevokeApiTokenResponse {}))
    }

    /// (Task 13; Task 16 adds the `action` filter) Most-recent-first audit
    /// log entries — backs `fabricctl audit query`/`audit export`. Read-only
    /// (listed in `crate::auth::READONLY_METHODS`), so a `read-only`-role
    /// bearer token may call it. An empty `action` means "no filter" (proto3
    /// can't distinguish "unset" from "empty string" for a plain `string`
    /// field, and `action` is always non-empty in practice, so treating
    /// `""` as "don't filter" is unambiguous). `Db::audit_query` also
    /// accepts `actor`/`entity` filters, unused here — see
    /// `AuditQueryRequest`'s doc comment for why the wire contract doesn't
    /// (yet) expose them.
    async fn audit_query(
        &self,
        request: Request<AuditQueryRequest>,
    ) -> Result<Response<AuditQueryResponse>, Status> {
        let req = request.into_inner();
        let limit = if req.limit > 0 {
            req.limit as i64
        } else {
            DEFAULT_AUDIT_LIMIT
        };
        let action = (!req.action.is_empty()).then_some(req.action);

        let rows = self
            .db
            .audit_query(limit, action, None, None)
            .await
            .map_err(|e| Status::internal(format!("querying audit log: {e}")))?;

        Ok(Response::new(AuditQueryResponse {
            entries: rows
                .into_iter()
                .map(|(id, ts, actor, action, entity, diff_json)| AuditEntry {
                    id: id as u64,
                    ts,
                    actor,
                    action,
                    entity,
                    diff_json,
                })
                .collect(),
        }))
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

    /// (Task 16) Revokes a single certificate by serial WITHOUT touching any
    /// gateway row — see [`crate::db::Db::revoke_cert`] for the transactional
    /// "revoke + audit + bump revision" mutation this maps to. `NotFound` if
    /// no `certificate` row has this serial at all; idempotent (no error) if
    /// it's already revoked. Publishes a [`ChangeEvent::CertRevoked`] AFTER
    /// the mutation commits, same "mutate durably first, then notify" order
    /// `RotateKey`/`Drain` use — this is what pushes the serial into every
    /// already-connected gateway's next Delta's `revoked_serials` without
    /// waiting for a reconnect/fresh snapshot.
    async fn revoke_cert(
        &self,
        request: Request<RevokeCertRequest>,
    ) -> Result<Response<RevokeCertResponse>, Status> {
        let req = request.into_inner();
        if req.serial.is_empty() {
            return Err(Status::invalid_argument("serial must not be empty"));
        }

        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| Status::internal(format!("formatting current time: {e}")))?;

        let found = self
            .db
            .revoke_cert(req.serial.clone(), now)
            .await
            .map_err(|e| Status::internal(format!("revoking certificate: {e}")))?;
        if !found {
            return Err(Status::not_found(format!(
                "no certificate row with serial {:?}",
                req.serial
            )));
        }

        let revision = self
            .db
            .current_revision()
            .await
            .map_err(|e| Status::internal(format!("reading revision after revocation: {e}")))?;

        // `send` errors only when there are currently no `Sync.Watch`
        // subscribers — nobody to notify, which is not a failure (mirrors
        // `EnrollmentSvc::enroll`/`AdminSvc::rotate_key`/`AdminSvc::drain`'s
        // identical `let _ =`).
        let _ = self.change_tx.send(ChangeEvent::CertRevoked {
            serial: req.serial,
            revision,
        });

        Ok(Response::new(RevokeCertResponse {}))
    }

    /// (Task 14) Declarative `fabricctl apply -f fabric.yaml`: parses the
    /// YAML (`crate::apply::parse_fabric`), validates every segment's CIDRs
    /// as IPv4 (mirrors `create_segment`), and hands the whole thing to
    /// [`crate::db_async::DbHandle::apply_fabric`] to diff-and-apply in one
    /// transaction. See that method's doc comment for the idempotence
    /// contract this RPC is entirely riding on: a second, identical apply
    /// must come back with every `ApplyDiff` field zero/false.
    async fn apply(&self, request: Request<ApplyRequest>) -> Result<Response<ApplyDiff>, Status> {
        let req = request.into_inner();

        let spec = crate::apply::parse_fabric(&req.fabric_yaml)
            .map_err(|e| Status::invalid_argument(format!("parsing fabric yaml: {e}")))?;

        let mut segments = Vec::with_capacity(spec.segments.len());
        for s in &spec.segments {
            let cidrs: Vec<Ipv4Net> = s
                .cidrs
                .iter()
                .map(|c| {
                    Ipv4Net::from_str(c).map_err(|e| {
                        Status::invalid_argument(format!(
                            "invalid IPv4 CIDR {c:?} in segment {:?}: {e}",
                            s.name
                        ))
                    })
                })
                .collect::<Result<_, _>>()?;
            segments.push((s.name.clone(), cidrs));
        }

        let policy_yaml = spec.policy.as_ref().map(crate::apply::policy_source_yaml);

        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| Status::internal(format!("formatting current time: {e}")))?;

        let outcome = self
            .db
            .apply_fabric(segments, policy_yaml, "unix-socket".to_string(), now)
            .await
            .map_err(|e| Status::internal(format!("applying fabric: {e}")))?;

        let total_changes = outcome.created_segments
            + outcome.updated_segments
            + outcome.deleted_segments
            + u32::from(outcome.policy_updated);

        Ok(Response::new(ApplyDiff {
            created_segments: outcome.created_segments,
            updated_segments: outcome.updated_segments,
            deleted_segments: outcome.deleted_segments,
            policy_updated: outcome.policy_updated,
            total_changes,
        }))
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
