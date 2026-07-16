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
use tonic::{Request, Response, Status};

use wiremesh_proto::v1::enrollment_server::Enrollment;
use wiremesh_proto::v1::{EnrollRequest, EnrollResponse};
use wiremesh_trust::{CertProfile, CertificateIssuer};

use crate::db_async::{DbHandle, EnrollError};

/// Cycle-2 leaf certs (gateway enrollment) are valid for 90 days from
/// issuance — no renewal path yet (a later task can make this configurable
/// / add rebind-driven renewal).
const GATEWAY_CERT_TTL: StdDuration = StdDuration::from_secs(90 * 24 * 3600);

/// This task's slice only handles `kind = "gateway"` tokens. `relay` tokens
/// and the `rebind` segment-exemption path are out of scope (Task 10).
const TOKEN_KIND_GATEWAY: &str = "gateway";

pub struct EnrollmentSvc {
    db: DbHandle,
    trust: Arc<dyn CertificateIssuer>,
}

impl EnrollmentSvc {
    pub fn new(db: DbHandle, trust: Arc<dyn CertificateIssuer>) -> Self {
        Self { db, trust }
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
                TOKEN_KIND_GATEWAY.to_string(),
                cidrs,
                gateway_name,
                issued.serial.clone(),
                issued.handle.clone(),
                not_after,
                now,
            )
            .await;

        if let Err(err) = outcome {
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
                EnrollError::Other(e) => Status::internal(format!("enrollment failed: {e}")),
            });
        }

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
