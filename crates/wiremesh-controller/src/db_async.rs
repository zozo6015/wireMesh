//! Async wrapper around [`crate::db::Db`]: every call runs on
//! [`tokio::task::spawn_blocking`] so the synchronous `rusqlite` connection
//! (already serialized behind `Db`'s internal `Mutex`) never blocks the tonic
//! executor. A single connection is fine for cycle-2 volume — see the
//! controller-core design §4/D-C2-2.

use std::sync::Arc;

use anyhow::Result;
use ipnet::Ipv4Net;

use crate::db::Db;
pub use crate::db::{EnrollError, EnrollOutcome, GatewayIdentity, GatewayKeyRow, GatewayRow};

/// Cheaply cloneable async handle to a [`Db`]. `Db` already serializes access
/// internally (a `Mutex<Connection>`), so `Arc<Db>` — rather than a pool — is
/// the "clean one" per the task brief: cloning `DbHandle` just bumps a
/// refcount, and every method spawns the blocking call onto a blocking-pool
/// thread.
#[derive(Clone)]
pub struct DbHandle {
    inner: Arc<Db>,
}

impl DbHandle {
    pub fn new(db: Db) -> Self {
        Self { inner: Arc::new(db) }
    }

    /// See [`Db::insert_segment`]. Returns the new segment's id.
    pub async fn insert_segment(&self, name: String, cidrs: Vec<Ipv4Net>) -> Result<i64> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.insert_segment(&name, &cidrs)).await?
    }

    /// See [`Db::audit`].
    pub async fn audit(
        &self,
        actor: String,
        action: String,
        entity: String,
        diff_json: String,
    ) -> Result<()> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.audit(&actor, &action, &entity, &diff_json)).await?
    }

    /// See [`Db::insert_enrollment_token`].
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_enrollment_token(
        &self,
        id: String,
        secret_hash: String,
        kind: String,
        bound_cidrs: String,
        rebind_segment_id: Option<i64>,
        expires_at: String,
    ) -> Result<()> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            db.insert_enrollment_token(
                &id,
                &secret_hash,
                &kind,
                &bound_cidrs,
                rebind_segment_id,
                &expires_at,
            )
        })
        .await?
    }

    /// See [`Db::enroll_gateway`]. Returns [`EnrollError`] (not
    /// `anyhow::Error`) so the gRPC handler can distinguish "bad token" from
    /// "no matching segment" from "internal error" and map each to the
    /// right `tonic::Status` code.
    #[allow(clippy::too_many_arguments)]
    pub async fn enroll_gateway(
        &self,
        secret_hash: String,
        kind: String,
        cidrs: Vec<Ipv4Net>,
        gateway_name: String,
        cert_serial: String,
        issuer_handle: String,
        cert_not_after: String,
        now: String,
    ) -> Result<EnrollOutcome, EnrollError> {
        let db = self.inner.clone();
        match tokio::task::spawn_blocking(move || {
            db.enroll_gateway(
                &secret_hash,
                &kind,
                &cidrs,
                &gateway_name,
                &cert_serial,
                &issuer_handle,
                &cert_not_after,
                &now,
            )
        })
        .await
        {
            Ok(result) => result,
            Err(join_err) => Err(EnrollError::Other(anyhow::anyhow!(
                "enroll_gateway blocking task panicked: {join_err}"
            ))),
        }
    }

    /// See [`Db::list_other_gateways`].
    pub async fn list_other_gateways(&self, exclude_gateway_id: i64) -> Result<Vec<GatewayRow>> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.list_other_gateways(exclude_gateway_id)).await?
    }

    /// See [`Db::cidrs_for_segment`].
    pub async fn cidrs_for_segment(&self, segment_id: i64) -> Result<Vec<String>> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.cidrs_for_segment(segment_id)).await?
    }

    /// See [`Db::active_keys_for_gateway`].
    pub async fn active_keys_for_gateway(&self, gateway_id: i64) -> Result<Vec<GatewayKeyRow>> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.active_keys_for_gateway(gateway_id)).await?
    }

    /// See [`Db::revoked_serials`].
    pub async fn revoked_serials(&self) -> Result<Vec<String>> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.revoked_serials()).await?
    }

    /// See [`Db::current_revision`].
    pub async fn current_revision(&self) -> Result<u64> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.current_revision()).await?
    }

    /// See [`Db::find_gateway_by_name`].
    pub async fn find_gateway_by_name(&self, name: String) -> Result<Option<GatewayIdentity>> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.find_gateway_by_name(&name)).await?
    }
}
