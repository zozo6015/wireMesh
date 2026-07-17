//! (Task 13) Bearer-token auth for the Admin service's TCP listener.
//!
//! The Admin service is served on TWO listeners with deliberately different
//! auth postures:
//!
//! - **UDS** (`config.socket_path`): implicit-admin. A caller that can open
//!   the socket at all (gated by the `0700` directory permission —
//!   `crate::bind_uds_dir`) is trusted as full admin, no bearer token
//!   needed. This is what every pre-Task-13 test still drives via
//!   `TestController::admin_client()`, and what `fabricctl --socket` uses.
//! - **TCP** (`config.admin_tcp_port`, new in Task 13): every request must
//!   carry a valid `API_TOKEN` bearer credential in the `authorization`
//!   metadata header, as `authorization: Bearer <token>` — the same header
//!   HTTP/gRPC callers conventionally use for bearer auth (chosen over a
//!   custom `x-wiremesh-token` header so `fabricctl --token` and any future
//!   HTTP-adjacent tooling need no special-casing). No/invalid/expired/
//!   revoked token -> `Status::unauthenticated`. A valid `read-only`-role
//!   token calling a MUTATING RPC -> `Status::permission_denied`.
//!
//! ## How mutating-vs-read-only is classified
//!
//! [`BearerAuthMiddleware`] is a `tower::Layer`/`Service` wrapped around the
//! WHOLE `tonic::service::Routes` router (via `Server::builder().layer(..)`,
//! applied BEFORE `.add_service(..)`), not a `tonic::service::Interceptor`.
//! That choice is deliberate: `tonic::service::Interceptor::call` only ever
//! sees a bodiless `Request<()>` with the gRPC method's URI already
//! stripped off (see `tonic::service::interceptor::InterceptedService::call`,
//! which extracts `req.uri()` and then discards it before invoking the
//! interceptor) — so a plain `Interceptor` has no reliable way to tell
//! `CreateSegment` apart from `ListSegments`. Sitting one layer further out,
//! at the raw `http::Request<BoxBody>` level, this middleware still has the
//! untouched request URI: every gRPC call's path is
//! `/wiremesh.v1.Admin/<MethodName>` (`tonic-build`'s fixed wire convention
//! — `<package>.<Service>/<Method>`), so `req.uri().path().rsplit('/').next()`
//! reliably recovers the exact RPC name Rust-server-side dispatch itself
//! uses to route the call, with no risk of drifting from what the client
//! actually invoked. [`READONLY_METHODS`] is the single table this
//! classification reads, and it is an ALLOWLIST that fails CLOSED: a request
//! is treated as requiring `admin` (i.e. denied for a `read-only` token)
//! UNLESS its method name is explicitly listed as read-only. Any method NOT
//! in the list — including a future Admin RPC whose author forgets to
//! classify it — defaults to mutating and is denied for `read-only` tokens.
//! This is deliberately the security-safe default for an auth boundary: a
//! misclassification can only ever be too RESTRICTIVE (a genuinely
//! read-only RPC that was forgotten gets rejected, a loud, obvious bug),
//! never too permissive (silently granting a `read-only` token write
//! access). The inverse — a mutating allowlist — would fail OPEN, silently
//! exposing any forgotten-to-be-listed mutation to `read-only` tokens.
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use http::{HeaderMap, Request, Response};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tonic::body::BoxBody;
use tonic::service::Routes;
use tonic::Status;
use tower::{Layer, Service};

use crate::db_async::DbHandle;

/// RPC method names (the segment after the last `/` in
/// `/wiremesh.v1.Admin/<Method>`) that are READ-ONLY — the ONLY Admin RPCs a
/// `read-only`-role token may call. This is the single source of truth for
/// classification and it fails CLOSED: any method NOT listed here is treated
/// as requiring `admin` (denied for `read-only` tokens) — see the module doc
/// comment for why deny-unknown is the security-safe default. A future Admin
/// RPC's author must ADD it here only if it is genuinely non-mutating;
/// forgetting to do so denies `read-only` access (a safe, loud failure),
/// never silently grants it.
const READONLY_METHODS: &[&str] = &[
    "ListSegments",
    "ListGateways",
    "ListRelays",
    "AuditQuery",
    "DebugKeyStates",
    "GetPolicy",
];

/// The authenticated caller's identity, stamped into the request's
/// `http::Extensions` by [`BearerAuthMiddleware`] on every successfully
/// authenticated TCP request — `http::Request`'s extensions survive tonic's
/// decode into a typed `tonic::Request<T>`, so `services::admin::AdminSvc`
/// handlers can read this back out (before calling `.into_inner()`, which
/// discards it) to record the REAL bearer-token identity in an audit row
/// instead of the UDS-only `"unix-socket"` placeholder. Never present on
/// the UDS listener (which has no `BearerAuthLayer`), so `AdminSvc` falls
/// back to `"unix-socket"` whenever this extension is absent.
#[derive(Clone, Debug)]
pub struct Principal(pub String);

/// A `tower::Layer` that wraps the Admin `Routes` service with bearer-token
/// auth — see the module doc comment for why this is a `Layer` around the
/// whole router rather than a `tonic::service::Interceptor`.
#[derive(Clone)]
pub struct BearerAuthLayer {
    db: DbHandle,
}

impl BearerAuthLayer {
    pub fn new(db: DbHandle) -> Self {
        Self { db }
    }
}

impl Layer<Routes> for BearerAuthLayer {
    type Service = BearerAuthMiddleware;

    fn layer(&self, inner: Routes) -> Self::Service {
        BearerAuthMiddleware {
            inner,
            db: self.db.clone(),
        }
    }
}

#[derive(Clone)]
pub struct BearerAuthMiddleware {
    inner: Routes,
    db: DbHandle,
}

impl Service<Request<BoxBody>> for BearerAuthMiddleware {
    type Response = Response<BoxBody>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Service::<Request<BoxBody>>::poll_ready(&mut self.inner, cx)
    }

    fn call(&mut self, req: Request<BoxBody>) -> Self::Future {
        // Standard tower pattern for a middleware that needs to `.await`
        // before delegating: clone `inner` (cheap — `Routes` is an
        // `axum::Router` clone, and `self.inner` stays usable for the NEXT
        // `call` via `poll_ready`'s readiness contract) rather than trying
        // to hold `&mut self` across an await point.
        let mut inner = self.inner.clone();
        let db = self.db.clone();

        Box::pin(async move {
            let mut req = req;
            let method = req
                .uri()
                .path()
                .rsplit('/')
                .next()
                .unwrap_or("")
                .to_string();

            match authorize(&db, req.headers(), &method).await {
                Ok(principal) => {
                    req.extensions_mut().insert(principal);
                    inner.call(req).await
                }
                Err(status) => Ok(status.into_http()),
            }
        })
    }
}

/// Validates the bearer token in `headers` against `api_token` and enforces
/// role vs. `method`'s mutating-ness. See the module doc comment for the
/// header/classification contract. On success, returns the token's `name`
/// as a [`Principal`] — see that type's doc comment for how it reaches
/// `AdminSvc`'s audit rows.
async fn authorize(db: &DbHandle, headers: &HeaderMap, method: &str) -> Result<Principal, Status> {
    let token =
        extract_bearer(headers).ok_or_else(|| Status::unauthenticated("missing bearer token"))?;
    // The bearer token IS the hex-encoded raw secret (`MintApiTokenResponse.token`,
    // straight from `AdminSvc::mint_api_token`'s `hex_encode(&secret)` — no
    // `wiremesh://...` URL wrapping, unlike an enrollment token). Hash the
    // DECODED raw bytes, matching exactly what `AdminSvc::mint_api_token`
    // stored as `secret_hash` (`hex_encode(&Sha256::digest(secret))` over the
    // raw bytes) — hashing the hex STRING's own ASCII bytes instead would
    // never match. Same decode-then-hash discipline
    // `services::enrollment::parse_token_secret`/`hex_decode` use for
    // enrollment tokens.
    let secret_bytes = hex_decode(&token)
        .ok_or_else(|| Status::unauthenticated("invalid, expired, or revoked API token"))?;
    let secret_hash = hex_encode(&Sha256::digest(secret_bytes));
    let now = OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|e| Status::internal(format!("formatting current time: {e}")))?;

    let (name, role) = db
        .find_active_api_token(secret_hash, now)
        .await
        .map_err(|e| Status::internal(format!("looking up API token: {e}")))?
        .ok_or_else(|| Status::unauthenticated("invalid, expired, or revoked API token"))?;

    // Fail closed: an `admin` token may call anything; a `read-only` token
    // may call ONLY methods explicitly listed as read-only. Any method not
    // in the allowlist (including a future, unclassified RPC) is treated as
    // requiring `admin` — see [`READONLY_METHODS`] and the module doc
    // comment.
    if role != "admin" && !READONLY_METHODS.contains(&method) {
        return Err(Status::permission_denied(
            "a read-only API token cannot call this Admin RPC",
        ));
    }
    Ok(Principal(name))
}

/// Pulls the raw token out of an `authorization: Bearer <token>` header —
/// see the module doc comment for why this header (rather than a custom
/// `x-wiremesh-token`) was chosen.
fn extract_bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
    value.strip_prefix("Bearer ").map(|s| s.trim().to_string())
}

fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// Decodes a lowercase-hex string back to raw bytes, `None` on any malformed
/// input (odd length or a non-hex-digit byte) — mirrors
/// `services::enrollment::hex_decode`'s contract exactly.
fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks(2) {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Some(out)
}
