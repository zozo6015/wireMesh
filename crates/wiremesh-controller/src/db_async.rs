//! Async wrapper around [`crate::db::Db`]: every call runs on
//! [`tokio::task::spawn_blocking`] so the synchronous `rusqlite` connection
//! (already serialized behind `Db`'s internal `Mutex`) never blocks the tonic
//! executor. A single connection is fine for cycle-2 volume — see the
//! controller-core design §4/D-C2-2.

use std::sync::Arc;

use anyhow::Result;
use ipnet::Ipv4Net;

use crate::db::Db;

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
}
