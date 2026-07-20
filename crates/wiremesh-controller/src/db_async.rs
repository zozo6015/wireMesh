//! Async wrapper around [`crate::db::Db`]: every call runs on
//! [`tokio::task::spawn_blocking`] so the synchronous `rusqlite` connection
//! (already serialized behind `Db`'s internal `Mutex`) never blocks the tonic
//! executor. A single connection is fine for cycle-2 volume — see the
//! controller-core design §4/D-C2-2.

use std::sync::Arc;

use anyhow::Result;
use ipnet::Ipv4Net;

use crate::db::Db;
pub use crate::db::{
    ApplyOutcome, DrainOutcome, EnrollError, EnrollOutcome, GatewayIdentity, GatewayKeyRow,
    GatewayRow, PolicyVersionRow, RotateKeyOutcome,
};

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

    /// See [`Db::create_segment_audited`].
    pub async fn create_segment_audited(
        &self,
        name: String,
        cidrs: Vec<Ipv4Net>,
        actor: String,
        now: String,
    ) -> Result<i64> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.create_segment_audited(&name, &cidrs, &actor, &now))
            .await?
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
        actor: String,
        now: String,
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
                &actor,
                &now,
            )
        })
        .await?
    }

    /// See [`Db::enroll_gateway`]. Returns [`EnrollError`] (not
    /// `anyhow::Error`) so the gRPC handler can distinguish "bad token" from
    /// "no matching segment" from "internal error" and map each to the
    /// right `tonic::Status` code. The token's `kind` (`gateway` vs.
    /// `rebind`) is no longer a caller-supplied parameter (Task 10) — `Db`
    /// reads it off the matched `enrollment_token` row itself, so one call
    /// handles both.
    #[allow(clippy::too_many_arguments)]
    pub async fn enroll_gateway(
        &self,
        secret_hash: String,
        cidrs: Vec<Ipv4Net>,
        gateway_name: String,
        wg_pubkey: String,
        cert_serial: String,
        issuer_handle: String,
        cert_not_after: String,
        now: String,
    ) -> Result<EnrollOutcome, EnrollError> {
        let db = self.inner.clone();
        match tokio::task::spawn_blocking(move || {
            db.enroll_gateway(
                &secret_hash,
                &cidrs,
                &gateway_name,
                &wg_pubkey,
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

    /// See [`Db::active_gateway_for_segment`].
    pub async fn active_gateway_for_segment(&self, segment_id: i64) -> Result<Option<i64>> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.active_gateway_for_segment(segment_id)).await?
    }

    /// See [`Db::active_keys_for_gateway`].
    pub async fn active_keys_for_gateway(&self, gateway_id: i64) -> Result<Vec<GatewayKeyRow>> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.active_keys_for_gateway(gateway_id)).await?
    }

    /// See [`Db::all_keys_for_gateway`].
    pub async fn all_keys_for_gateway(&self, gateway_id: i64) -> Result<Vec<GatewayKeyRow>> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.all_keys_for_gateway(gateway_id)).await?
    }

    /// See [`Db::rotate_key`].
    pub async fn rotate_key(
        &self,
        gateway_id: i64,
        actor: String,
        now: String,
    ) -> Result<RotateKeyOutcome> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.rotate_key(gateway_id, &actor, &now)).await?
    }

    /// See [`Db::gateway_identity_by_id`].
    pub async fn gateway_identity_by_id(&self, gateway_id: i64) -> Result<Option<GatewayIdentity>> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.gateway_identity_by_id(gateway_id)).await?
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

    /// See [`Db::set_applied_version`].
    pub async fn set_applied_version(&self, gateway_id: i64, applied_version: u64) -> Result<()> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.set_applied_version(gateway_id, applied_version))
            .await?
    }

    /// See [`Db::find_gateway_by_name`].
    pub async fn find_gateway_by_name(&self, name: String) -> Result<Option<GatewayIdentity>> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.find_gateway_by_name(&name)).await?
    }

    /// See [`Db::drain_gateway`].
    pub async fn drain_gateway(
        &self,
        gateway_id: i64,
        actor: String,
        now: String,
    ) -> Result<DrainOutcome> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.drain_gateway(gateway_id, &actor, &now)).await?
    }

    /// See [`Db::gateway_is_active`].
    pub async fn gateway_is_active(&self, gateway_id: i64) -> Result<bool> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.gateway_is_active(gateway_id)).await?
    }

    /// See [`Db::list_segments`].
    pub async fn list_segments(&self) -> Result<Vec<(i64, String, Vec<String>)>> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.list_segments()).await?
    }

    /// See [`Db::delete_segment`].
    pub async fn delete_segment(&self, segment_id: i64, actor: String, now: String) -> Result<()> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.delete_segment(segment_id, &actor, &now)).await?
    }

    /// See [`Db::insert_relay`].
    pub async fn insert_relay(
        &self,
        name: String,
        endpoint: String,
        actor: String,
        now: String,
    ) -> Result<i64> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.insert_relay(&name, &endpoint, &actor, &now)).await?
    }

    /// See [`Db::list_relays`].
    pub async fn list_relays(&self) -> Result<Vec<(i64, String, String, String)>> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.list_relays()).await?
    }

    /// See [`Db::insert_api_token`].
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_api_token(
        &self,
        id: String,
        name: String,
        role: String,
        secret_hash: String,
        expires_at: Option<String>,
        actor: String,
        now: String,
    ) -> Result<()> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            db.insert_api_token(
                &id,
                &name,
                &role,
                &secret_hash,
                expires_at.as_deref(),
                &actor,
                &now,
            )
        })
        .await?
    }

    /// See [`Db::revoke_api_token`].
    pub async fn revoke_api_token(&self, name: String, actor: String, now: String) -> Result<bool> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.revoke_api_token(&name, &actor, &now)).await?
    }

    /// See [`Db::find_active_api_token_role`]. Used by
    /// [`crate::auth`]'s bearer-auth middleware on every TCP Admin request.
    pub async fn find_active_api_token_role(
        &self,
        secret_hash: String,
        now: String,
    ) -> Result<Option<String>> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.find_active_api_token_role(&secret_hash, &now)).await?
    }

    /// See [`Db::find_active_api_token`].
    pub async fn find_active_api_token(
        &self,
        secret_hash: String,
        now: String,
    ) -> Result<Option<(String, String)>> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.find_active_api_token(&secret_hash, &now)).await?
    }

    /// See [`Db::audit_query`].
    pub async fn audit_query(
        &self,
        limit: i64,
        action: Option<String>,
        actor: Option<String>,
        entity: Option<String>,
    ) -> Result<Vec<(i64, String, String, String, String, String)>> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            db.audit_query(
                limit,
                action.as_deref(),
                actor.as_deref(),
                entity.as_deref(),
            )
        })
        .await?
    }

    /// See [`Db::revoke_cert`].
    pub async fn revoke_cert(&self, serial: String, actor: String, now: String) -> Result<bool> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.revoke_cert(&serial, &actor, &now)).await?
    }

    /// See [`Db::list_gateways`].
    pub async fn list_gateways(&self) -> Result<Vec<(i64, String, String, String, Option<i64>)>> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.list_gateways()).await?
    }

    /// See [`Db::gateway_observe_key`].
    pub async fn gateway_observe_key(&self, gateway_id: i64) -> Result<Option<String>> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.gateway_observe_key(gateway_id)).await?
    }

    /// See [`Db::candidate_endpoint_for_gateway`].
    pub async fn candidate_endpoint_for_gateway(
        &self,
        gateway_id: i64,
    ) -> Result<Option<String>> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.candidate_endpoint_for_gateway(gateway_id)).await?
    }

    /// See [`Db::set_candidate_endpoint`].
    pub async fn set_candidate_endpoint(
        &self,
        gateway_id: i64,
        addr: String,
    ) -> Result<Option<u64>> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.set_candidate_endpoint(gateway_id, &addr)).await?
    }

    /// See [`Db::candidates_for`].
    pub async fn candidates_for(&self, gateway_id: i64) -> Result<Vec<String>> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.candidates_for(gateway_id)).await?
    }

    /// See [`Db::set_local_candidates`].
    pub async fn set_local_candidates(
        &self,
        gateway_id: i64,
        endpoints: Vec<String>,
    ) -> Result<Option<u64>> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.set_local_candidates(gateway_id, &endpoints)).await?
    }

    /// See [`Db::apply_fabric`]. Backs `Admin.Apply`.
    pub async fn apply_fabric(
        &self,
        segments: Vec<(String, Vec<Ipv4Net>)>,
        policy_yaml: Option<String>,
        actor: String,
        now: String,
    ) -> Result<ApplyOutcome> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            db.apply_fabric(&segments, policy_yaml.as_deref(), &actor, &now)
        })
        .await?
    }

    /// See [`Db::latest_policy`].
    pub async fn latest_policy(&self) -> Result<Option<(u64, String)>> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.latest_policy()).await?
    }

    /// See [`Db::policy_version`]. Backs `Admin.GetPolicy`.
    pub async fn policy_version(&self, version: Option<u64>) -> Result<Option<PolicyVersionRow>> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || db.policy_version(version)).await?
    }
}
