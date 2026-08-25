//! `Enrollment` service (Task 5): a bearer-token, single-use flow that turns
//! a gateway's self-generated CSR into a signed leaf certificate + the CA's
//! trust bundle. Served on the controller's TCP port with server-only TLS —
//! the caller has no client certificate of its own yet at this point (mTLS
//! begins at Sync, Task 7), so authentication here is purely the bearer
//! token embedded in the presented `wiremesh://.../#tok_<secret>@sha256:...`
//! URL.
//!
//! Token validation, cert recording, gateway association, marking the token
//! spent, and the audit entry all happen inside ONE `Db::enroll_gateway`
//! transaction (see that method's doc comment) — that's what makes the
//! token single-use guarantee atomic against a replay.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use base64::Engine as _;
use ipnet::Ipv4Net;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tokio::sync::broadcast;
use tonic::{Request, Response, Status};

use wiremesh_proto::v1::enrollment_server::Enrollment;
use wiremesh_proto::v1::{EnrollRequest, EnrollResponse};
use wiremesh_trust::{CertProfile, CertificateIssuer};

use crate::db_async::{DbHandle, EnrollError};
use crate::projection::ChangeEvent;

/// Cycle-2 leaf certs (gateway enrollment) are valid for 90 days from
/// issuance — no renewal path yet (a later task can make this configurable).
/// A `rebind` token (Task 10) issues a fresh 90-day cert too, exactly like an
/// ordinary `gateway` token — only its authorization scope and the
/// replaced-gateway revocation differ, both handled inside
/// `Db::enroll_gateway`.
const GATEWAY_CERT_TTL: StdDuration = StdDuration::from_secs(90 * 24 * 3600);

pub struct EnrollmentSvc {
    db: DbHandle,
    trust: Arc<dyn CertificateIssuer>,
    /// Publishes a [`ChangeEvent`] after every successful enrollment (Task
    /// 8) — Enrollment and Sync are two separate services/connections
    /// (see `wiremesh_controller::serve`'s doc comment for why), so this is
    /// how a newly enrolled gateway reaches every OTHER already-connected
    /// gateway's still-open `Sync.Watch` stream as an incremental `Delta`
    /// instead of requiring a reconnect. Shared with `SyncSvc` via the same
    /// `broadcast::Sender` constructed once in `serve()`.
    change_tx: broadcast::Sender<ChangeEvent>,
}

impl EnrollmentSvc {
    pub fn new(
        db: DbHandle,
        trust: Arc<dyn CertificateIssuer>,
        change_tx: broadcast::Sender<ChangeEvent>,
    ) -> Self {
        Self {
            db,
            trust,
            change_tx,
        }
    }
}

#[tonic::async_trait]
impl Enrollment for EnrollmentSvc {
    async fn enroll(
        &self,
        request: Request<EnrollRequest>,
    ) -> Result<Response<EnrollResponse>, Status> {
        let req = request.into_inner();

        if req.csr_pem.is_empty() {
            return Err(Status::invalid_argument("csr_pem must not be empty"));
        }

        // A malformed token string is treated exactly like an invalid one
        // (PermissionDenied), not InvalidArgument: distinguishing "wrong
        // shape" from "wrong secret" in the response would hand an attacker
        // a free oracle for probing the token format. The raw secret is
        // NEVER logged anywhere in this path — only its sha256 hash is used
        // past this point.
        let secret_hex = parse_token_secret(&req.token)
            .ok_or_else(|| Status::permission_denied("invalid enrollment token"))?;
        let secret_bytes = hex_decode(&secret_hex)
            .map_err(|_| Status::permission_denied("invalid enrollment token"))?;
        let secret_hash_hex = hex_encode(&Sha256::digest(&secret_bytes));

        let cidrs: Vec<Ipv4Net> = req
            .cidrs
            .iter()
            .map(|c| {
                Ipv4Net::from_str(c)
                    .map_err(|e| Status::invalid_argument(format!("invalid IPv4 CIDR {c:?}: {e}")))
            })
            .collect::<Result<_, _>>()?;

        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| Status::internal(format!("formatting current time: {e}")))?;

        // (Cycle-4c Task 4) A relay has no segment/cidrs to declare — it's
        // routed by request SHAPE instead of an explicit field: a non-empty
        // `endpoint` selects the relay path; an empty one is the ordinary
        // gateway path below, entirely unchanged. The DB remains the
        // kind-authority either way — `Db::enroll_relay` only matches
        // `kind = 'relay'` tokens (a gateway/rebind token here comes back
        // `InvalidToken`, indistinguishable from a bad secret), and
        // `Db::enroll_gateway` below already only matches
        // `kind IN ('gateway', 'rebind')` (a relay token there is likewise
        // `InvalidToken`) — so a mismatched token/path combination is
        // rejected by the same non-disclosure posture as any other invalid
        // token, never a distinct error that would help an attacker probe
        // token kinds.
        if !req.endpoint.is_empty() {
            // (Cycle-4c Task 5) A relay's `endpoint` is what every gateway's
            // relay transport will eventually dial (Task 7) — reject
            // anything that doesn't even parse as `ip:port` up front, before
            // signing or touching the DB, so a malformed value can never be
            // enrolled (and therefore never advertised in a snapshot/delta).
            // `SocketAddrV4` (not `SocketAddr`) enforces the project's
            // IPv4-only v1 invariant (CLAUDE.md), consistent with the
            // `Ipv4Net` CIDR validation on the gateway path.
            if req.endpoint.parse::<std::net::SocketAddrV4>().is_err() {
                return Err(Status::invalid_argument(
                    "relay endpoint must be a valid IPv4 ip:port",
                ));
            }

            let relay_name = format!("relay-{secret_hash_hex}");

            // Signing (pure crypto, no DB dependency) happens before the
            // single-use transaction, same rationale as the gateway path
            // below: an invalid/spent token just means the freshly signed
            // cert is discarded, never recorded or returned.
            let issued = self
                .trust
                .sign(
                    &req.csr_pem,
                    CertProfile {
                        subject_cn: relay_name.clone(),
                        ttl: GATEWAY_CERT_TTL,
                        // The relay's QUIC server cert MUST carry SAN
                        // "relay" — every gateway's relay client dials it
                        // with `wiremesh_relay::RELAY_SERVER_NAME` ("relay")
                        // as both the QUIC SNI and the rustls
                        // hostname-verification target (see
                        // `wiremesh_relay::Client::connect_with_pems`); a
                        // leaf with zero SANs fails that check outright, no
                        // matter what CN it carries. This is CA-decided
                        // (the relay's CSR is never consulted for it), so it
                        // can't be smuggled by a non-relay token that
                        // happens to hit this branch.
                        subject_alt_names: vec!["relay".to_string()],
                        serial: None,
                    },
                )
                .await
                .map_err(|e| Status::invalid_argument(format!("signing CSR failed: {e}")))?;

            let not_after = issued
                .not_after
                .format(&time::format_description::well_known::Rfc3339)
                .map_err(|e| Status::internal(format!("formatting cert not_after: {e}")))?;

            let ca_bundle_pem = self
                .trust
                .trust_bundle()
                .await
                .map_err(|e| Status::internal(format!("reading trust bundle: {e}")))?;

            let relay_id = match self
                .db
                .enroll_relay(
                    secret_hash_hex,
                    relay_name,
                    req.endpoint.clone(),
                    issued.serial.clone(),
                    issued.handle.clone(),
                    not_after,
                    now,
                )
                .await
            {
                Ok(id) => id,
                Err(EnrollError::InvalidToken) => {
                    return Err(Status::permission_denied(
                        "enrollment token is invalid, expired, wrong kind, or already used",
                    ));
                }
                Err(EnrollError::Other(e)) => {
                    return Err(Status::internal(format!("relay enrollment failed: {e}")));
                }
                Err(other) => {
                    return Err(Status::internal(format!(
                        "relay enrollment failed: {other:?}"
                    )));
                }
            };

            // Projection-affecting mutation succeeded (and its transaction
            // already bumped the persisted revision — see
            // `Db::enroll_relay`'s doc comment) and the single-use token is
            // now spent. From here on this is best-effort, same discipline
            // as the gateway path below: a failure re-reading the revision
            // or active-relay set must never turn into an error response —
            // the relay row, cert, and response are already durably
            // committed/ready regardless.
            // (CodeRabbit round 3, Major) Reads the active-relay set AND the
            // revision as ONE atomic pair via `relays_snapshot` (single lock
            // hold) rather than two separate `active_relays()` +
            // `current_revision()` calls — this guarantees the revision
            // attached to this delta is consistent with the advertised
            // `relay_infos`, closing a race where a concurrent relay
            // mutation committing between two separate reads could
            // broadcast a stale relay set tagged with a newer revision (see
            // `Db::relays_snapshot`'s doc comment). An open `Sync.Watch`
            // stream must never see the revision regress relative to the
            // relay set it just applied (see projection.rs).
            if let Ok((active, revision)) = self.db.relays_snapshot().await {
                let relay_infos = active
                    .into_iter()
                    .map(|(id, endpoint)| wiremesh_proto::v1::RelayInfo {
                        relay_id: id as u64,
                        endpoint,
                    })
                    .collect();
                // `send` errors only when there are currently no
                // `Sync.Watch` subscribers — nobody to notify, which is
                // not a failure (mirrors the gateway path's identical
                // rationale below).
                let _ = self.change_tx.send(ChangeEvent::RelaysChanged {
                    relay_infos,
                    revision,
                });
            }

            return Ok(Response::new(EnrollResponse {
                cert_pem: issued.cert_pem,
                ca_bundle_pem,
                // Not a gateway id at all — the field is reused to carry the
                // newly enrolled relay's row id (the "id the controller
                // assigned", same as the gateway path). Documented here since
                // the proto field name doesn't say so itself.
                gateway_id: relay_id as u64,
                observe_key: String::new(),
            }));
        }

        if cidrs.is_empty() {
            return Err(Status::invalid_argument("cidrs must not be empty"));
        }

        // (Backlog item 23, controller half) Reject an unusable `wg_pubkey`
        // up front, before signing or touching the DB — mirrors the relay
        // `endpoint` check above (Cycle-4c Task 5), the precedent this was
        // never applied to. `Db::enroll_gateway` stores whatever is passed
        // here verbatim and every peer advertises it as-is; an undecodable
        // key reaching a peer's `apply_state` fails
        // `wiremesh_gateway::uapi::key_b64_to_hex` and exits that peer's
        // process — for every peer this gateway has, at once (see
        // `crates/wiremesh-gateway/tests/peer_key_and_allowedips_validation.rs`
        // for the gateway-side half, which now survives a bad key it is
        // ADVERTISED; this is the other end, stopping the fabric from ever
        // advertising one). An EMPTY `wg_pubkey` stays legal — it is the
        // pre-Task-11b "no real key yet" caller shape, and `enroll_gateway`
        // below substitutes its own placeholder for it, unchanged.
        // Deliberately does NOT cover `Sync.SubmitEpochKey`
        // (`services/sync.rs`) — an unrelated, owner-deferred door; see
        // `tests/enroll_wg_pubkey_validation.rs`'s module doc for why.
        let wg_pubkey_valid = base64::engine::general_purpose::STANDARD
            .decode(&req.wg_pubkey)
            .is_ok_and(|raw| raw.len() == 32);
        if !req.wg_pubkey.is_empty() && !wg_pubkey_valid {
            return Err(Status::invalid_argument(
                "wg_pubkey must be base64 of exactly 32 bytes",
            ));
        }

        // The gateway's name/CN is derived from the token's secret hash
        // (already computed above) rather than parsed out of the CSR: it is
        // deterministic, unique per distinct token (two different tokens
        // never collide; the SAME token can't reach here twice because it's
        // single-use), and it sidesteps trusting anything the CSR itself
        // claims about its own identity — consistent with
        // `CertificateIssuer::sign` discarding CSR-supplied identity
        // entirely and letting the CA decide the subject CN.
        let gateway_name = format!("gw-{secret_hash_hex}");

        // SECURITY (Cycle 4c relay-registration binding): a gateway's leaf
        // now carries a CA-decided SAN `gw-<gateway_id>` so the relay can
        // bind a relay registration to the authenticated client cert (a
        // gateway can only register/receive relay traffic under an id derived
        // from ITS OWN cert-embedded gateway_id, not another pair's). That
        // creates a chicken/egg: the gateway_id is assigned by
        // `enroll_gateway`'s single-use transaction, but it must be inside the
        // leaf we sign. We resolve it by SIGNING AFTER the transaction, while
        // still recording the certificate row atomically with the token spend
        // (so the cert stays revocable) — by pre-generating the serial here
        // and stamping that SAME serial onto both the DB row and the leaf.
        //
        // `validate_csr_pem` up front preserves the pre-reorder invariant that
        // a MALFORMED CSR is rejected WITHOUT consuming the single-use token
        // (previously free, because signing — which parses the CSR — happened
        // before the transaction). A valid CSR + a pre-generated serial makes
        // the post-commit `sign` below effectively infallible.
        wiremesh_trust::validate_csr_pem(&req.csr_pem)
            .map_err(|e| Status::invalid_argument(format!("signing CSR failed: {e}")))?;

        // Pre-generate the leaf's serial (same CSPRNG/width the issuer uses)
        // so the certificate row can be committed inside the single-use-token
        // transaction below, before the leaf itself is signed. NOTE: the
        // `issuer_handle` recorded alongside it is this same serial hex —
        // correct for the embedded issuer (whose handle IS the serial, see
        // `EmbeddedTrust::sign`); a future non-embedded issuer with opaque
        // post-sign handles would need to revisit this ordering.
        let serial = wiremesh_trust::random_serial();
        let serial_hex = hex_encode(&serial);

        // not_after is computed here (at reserve time) rather than read back
        // from the signed leaf, since we sign after this transaction. The
        // leaf's own not_after (set by the issuer at sign time) differs only
        // by the signing latency — immaterial against a 90-day TTL, and
        // nothing compares the two.
        let not_after_dt = OffsetDateTime::now_utc()
            + time::Duration::try_from(GATEWAY_CERT_TTL)
                .map_err(|e| Status::internal(format!("gateway cert TTL out of range: {e}")))?;
        let not_after = not_after_dt
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| Status::internal(format!("formatting cert not_after: {e}")))?;

        // Fetched BEFORE the single-use token is spent below: this is the
        // one piece of response data (`EnrollResponse.ca_bundle_pem`) that
        // isn't already produced by `enroll_gateway` itself, so it's the
        // only genuinely fallible "response prep" step. Doing it here means
        // a transient failure reading the CA bundle rejects the request
        // (InvalidArgument-adjacent — actually Internal, but pre-commit)
        // WITHOUT ever touching the token, so the caller can simply retry
        // with the same (still-unused) token — see the doc comment below on
        // why everything AFTER the commit must instead be best-effort.
        let ca_bundle_pem = self
            .trust
            .trust_bundle()
            .await
            .map_err(|e| Status::internal(format!("reading trust bundle: {e}")))?;

        let outcome = self
            .db
            .enroll_gateway(
                secret_hash_hex,
                cidrs,
                gateway_name.clone(),
                req.wg_pubkey.clone(),
                serial_hex.clone(),
                serial_hex.clone(),
                not_after,
                now,
            )
            .await;

        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(err) => {
                return Err(match err {
                    EnrollError::InvalidToken => Status::permission_denied(
                        "enrollment token is invalid, expired, wrong kind, or already used",
                    ),
                    EnrollError::NoMatchingSegment => Status::failed_precondition(
                        "no segment is registered for the declared cidrs",
                    ),
                    EnrollError::BoundCidrMismatch => Status::permission_denied(
                        "declared cidrs are outside this token's authorized scope",
                    ),
                    EnrollError::SegmentAlreadyBound => Status::already_exists(
                        "segment already has an active gateway; use a rebind token to replace it",
                    ),
                    EnrollError::Other(e) => Status::internal(format!("enrollment failed: {e}")),
                });
            }
        };

        // The token is now spent and the certificate row is durably
        // committed (with `serial_hex`). Sign the leaf NOW that we know the
        // gateway_id, stamping the pre-generated serial and the CA-decided
        // `gw-<gateway_id>` SAN. With a validated CSR and a fixed serial this
        // is effectively infallible; a failure here means the token is
        // already spent (documented above), so it surfaces as Internal.
        let issued = self
            .trust
            .sign(
                &req.csr_pem,
                CertProfile {
                    subject_cn: gateway_name.clone(),
                    ttl: GATEWAY_CERT_TTL,
                    // SECURITY: the relay-registration identity binding. The
                    // CA (not the CSR) stamps this SAN, so a gateway cannot
                    // choose its own gateway_id — see the relay's
                    // `identity_from_client_cert`.
                    subject_alt_names: vec![format!("gw-{}", outcome.gateway_id)],
                    serial: Some(serial),
                },
            )
            .await
            .map_err(|e| Status::internal(format!("signing gateway leaf failed: {e}")))?;

        // (Task 10) If this was a `rebind`, `Db::enroll_gateway` already
        // committed the replaced gateway's cert(s) as `revoked_at` in the DB
        // — that's the AUTHORITATIVE denylist the Sync projection's
        // `revoked_serials` reads from, and it's already durable by this
        // point regardless of what happens below. This best-effort call to
        // `CertificateIssuer::revoke` is purely so the issuer's own
        // bookkeeping (e.g. `EmbeddedTrust`'s in-memory `revoked` set) stays
        // consistent with the DB; a failure here does NOT undo or fail the
        // enrollment that already succeeded.
        for handle in &outcome.revoked_issuer_handles {
            let _ = self.trust.revoke(handle).await;
        }

        // Projection-affecting mutation succeeded (and its transaction
        // already bumped the persisted revision — see
        // `Db::enroll_gateway`'s doc comment) and the single-use token is
        // now spent. From here on EVERYTHING is best-effort: the gateway
        // row, certificate, and (if a rebind) revocations are already
        // durably committed, so a failure in this section must NEVER turn
        // into an error response — the token can't be retried, and the
        // client's cert (built from `outcome`/`issued`/`ca_bundle_pem`,
        // none of which depend on anything below) is already ready to
        // return regardless of what happens here.
        //
        // Re-reads the just-inserted gateway's identity/cidrs/revision
        // through the same DB handle rather than threading extra return
        // values through `EnrollOutcome`: `find_gateway_by_name` and
        // `cidrs_for_segment` already exist for exactly this shape of
        // lookup (the Sync projection uses them the same way), and the
        // gateway is guaranteed to exist (this same call just created it).
        // Any lookup failure here just means the broadcast is skipped —
        // other already-connected gateways fall back to their next
        // reconnect/resync to see the new peer, same as the "no current
        // subscribers" case below.
        if let Ok(Some(identity)) = self.db.find_gateway_by_name(gateway_name.clone()).await {
            if let Ok(allowed_ips) = self.db.cidrs_for_segment(identity.segment_id).await {
                if let Ok(revision) = self.db.current_revision().await {
                    // `send` errors only when there are currently no
                    // `Sync.Watch` subscribers (e.g. the very first gateway
                    // enrolling into a fresh controller) — nobody to
                    // notify, which is not a failure.
                    let _ = self.change_tx.send(ChangeEvent::GatewayEnrolled {
                        new_gateway_id: identity.id,
                        segment_name: identity.segment_name,
                        allowed_ips,
                        // (Mesh-convergence T6, CodeRabbit) On a `rebind` this
                        // carries the replaced gateway's just-revoked cert
                        // serial(s) (empty for an ordinary enroll) so an
                        // already-open Sync.Watch — gateway AND relay —
                        // denylists them immediately rather than only on its
                        // next reconnect. See `EnrollOutcome::revoked_serials`.
                        revoked_serials: outcome.revoked_serials.clone(),
                        revision,
                    });
                }
            }
        }

        Ok(Response::new(EnrollResponse {
            cert_pem: issued.cert_pem,
            ca_bundle_pem,
            gateway_id: outcome.gateway_id as u64,
            // (Task 15) The only time this gateway's UDP-observation
            // authenticator ever crosses the wire — see `crate::observe`'s
            // module doc comment.
            observe_key: outcome.observe_key,
        }))
    }
}

/// Extracts the `<secret>` hex string from a
/// `wiremesh://<host>/#tok_<secret>@sha256:<fp>` token URL (see
/// `services::admin::mint_token`'s format string). Returns `None` for
/// anything that doesn't match that shape — callers must treat that
/// identically to "no such token" (see the caller's doc comment on why).
fn parse_token_secret(token: &str) -> Option<String> {
    let after_hash = token.split_once('#')?.1;
    let after_tok = after_hash.strip_prefix("tok_")?;
    let secret = after_tok.split_once('@')?.0;
    if secret.is_empty() {
        return None;
    }
    Some(secret.to_string())
}

fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks(2) {
        let hi = (chunk[0] as char).to_digit(16).ok_or(())?;
        let lo = (chunk[1] as char).to_digit(16).ok_or(())?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}
