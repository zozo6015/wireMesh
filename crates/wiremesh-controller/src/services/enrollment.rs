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
        Self { db, trust, change_tx }
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
        if cidrs.is_empty() {
            return Err(Status::invalid_argument("cidrs must not be empty"));
        }

        let now = OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| Status::internal(format!("formatting current time: {e}")))?;

        // The gateway's name/CN is derived from the token's secret hash
        // (already computed above) rather than parsed out of the CSR: it is
        // deterministic, unique per distinct token (two different tokens
        // never collide; the SAME token can't reach here twice because it's
        // single-use), and it sidesteps trusting anything the CSR itself
        // claims about its own identity — consistent with
        // `CertificateIssuer::sign` discarding CSR-supplied identity
        // entirely and letting the CA decide the subject CN.
        let gateway_name = format!("gw-{secret_hash_hex}");

        // Signing is pure crypto with no DB dependency, so it happens
        // BEFORE the single-use transaction below — if the token turns out
        // to be invalid/spent, the freshly signed (but never recorded or
        // returned) cert is simply discarded.
        let issued = self
            .trust
            .sign(
                &req.csr_pem,
                CertProfile {
                    subject_cn: gateway_name.clone(),
                    ttl: GATEWAY_CERT_TTL,
                },
            )
            .await
            .map_err(|e| Status::invalid_argument(format!("signing CSR failed: {e}")))?;

        let not_after = issued
            .not_after
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| Status::internal(format!("formatting cert not_after: {e}")))?;

        let outcome = self
            .db
            .enroll_gateway(
                secret_hash_hex,
                cidrs,
                gateway_name.clone(),
                issued.serial.clone(),
                issued.handle.clone(),
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
        // `Db::enroll_gateway`'s doc comment). Publish a `ChangeEvent` so
        // every OTHER already-connected gateway's open `Sync.Watch` stream
        // learns about this new peer without needing to reconnect.
        //
        // Re-reads the just-inserted gateway's identity/cidrs/revision
        // through the same DB handle rather than threading extra return
        // values through `EnrollOutcome`: `find_gateway_by_name` and
        // `cidrs_for_segment` already exist for exactly this shape of
        // lookup (the Sync projection uses them the same way), and the
        // gateway is guaranteed to exist (this same call just created it).
        let identity = self
            .db
            .find_gateway_by_name(gateway_name.clone())
            .await
            .map_err(|e| Status::internal(format!("re-reading enrolled gateway: {e}")))?
            .ok_or_else(|| {
                Status::internal(format!(
                    "enrolled gateway {gateway_name:?} vanished immediately after enrollment"
                ))
            })?;
        let allowed_ips = self
            .db
            .cidrs_for_segment(identity.segment_id)
            .await
            .map_err(|e| Status::internal(format!("reading enrolled gateway's segment cidrs: {e}")))?;
        let revision = self
            .db
            .current_revision()
            .await
            .map_err(|e| Status::internal(format!("reading revision after enrollment: {e}")))?;
        // `send` errors only when there are currently no `Sync.Watch`
        // subscribers (e.g. the very first gateway enrolling into a fresh
        // controller) — nobody to notify, which is not a failure.
        let _ = self.change_tx.send(ChangeEvent {
            new_gateway_id: identity.id,
            segment_name: identity.segment_name,
            allowed_ips,
            revision,
        });

        let ca_bundle_pem = self
            .trust
            .trust_bundle()
            .await
            .map_err(|e| Status::internal(format!("reading trust bundle: {e}")))?;

        Ok(Response::new(EnrollResponse {
            cert_pem: issued.cert_pem,
            ca_bundle_pem,
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
