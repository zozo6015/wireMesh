//! Embedded SQLite store for the controller: connection management,
//! migrations, schema v1 (master-spec §4.1), the CIDR-overlap invariant
//! (§4.1 note, C-2), and audit-log append (§4.5, C-8).
//!
//! `Db` wraps a single [`rusqlite::Connection`] behind a [`Mutex`] so that
//! `&self` methods (required so callers don't need a `mut` handle threaded
//! everywhere) can still open rusqlite transactions, which need `&mut
//! Connection`. All access is synchronous; a later task wraps `Db` for use
//! from async request handlers (e.g. via `spawn_blocking`).

use std::path::Path;
use std::sync::Mutex;

use anyhow::Result;
use ipnet::Ipv4Net;
use rusqlite::{params, Connection};

/// Full schema for master-spec §4.1. Applied once, in a single transaction,
/// by [`Db::run_migrations`] when `PRAGMA user_version` is `0`. Datetimes are
/// stored as RFC3339 text (SQLite has no native datetime type).
const SCHEMA_V1: &str = r#"
CREATE TABLE segment (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE cidr (
    id         INTEGER PRIMARY KEY,
    segment_id INTEGER NOT NULL REFERENCES segment(id),
    cidr       TEXT NOT NULL UNIQUE
);

CREATE TABLE gateway (
    id         INTEGER PRIMARY KEY,
    segment_id INTEGER NOT NULL REFERENCES segment(id),
    name       TEXT NOT NULL UNIQUE,
    status     TEXT NOT NULL,
    backend    TEXT NOT NULL,
    last_seen  TEXT
);

CREATE TABLE gateway_key (
    gateway_id INTEGER NOT NULL REFERENCES gateway(id),
    epoch      INTEGER NOT NULL,
    pubkey     TEXT NOT NULL,
    state      TEXT NOT NULL CHECK (state IN ('pending', 'active', 'retiring')),
    PRIMARY KEY (gateway_id, epoch)
);

CREATE TABLE tunnel_pair (
    gw_a        INTEGER NOT NULL REFERENCES gateway(id),
    gw_b        INTEGER NOT NULL REFERENCES gateway(id),
    transport   TEXT NOT NULL CHECK (transport IN ('direct', 'relayed')),
    state       TEXT NOT NULL,
    last_change TEXT,
    PRIMARY KEY (gw_a, gw_b),
    CHECK (gw_a < gw_b)
);

CREATE TABLE relay (
    id        INTEGER PRIMARY KEY,
    name      TEXT NOT NULL UNIQUE,
    endpoint  TEXT NOT NULL,
    status    TEXT NOT NULL,
    last_seen TEXT
);

CREATE TABLE certificate (
    serial        TEXT PRIMARY KEY,
    subject_kind  TEXT NOT NULL,
    subject_id    INTEGER NOT NULL,
    issuer_handle TEXT NOT NULL,
    not_after     TEXT NOT NULL,
    revoked_at    TEXT
);

CREATE TABLE enrollment_token (
    id                TEXT PRIMARY KEY,
    secret_hash       TEXT NOT NULL,
    kind              TEXT NOT NULL CHECK (kind IN ('gateway', 'relay', 'rebind')),
    bound_cidrs       TEXT,
    rebind_segment_id INTEGER REFERENCES segment(id),
    expires_at        TEXT NOT NULL,
    used_at           TEXT
);

CREATE TABLE policy_version (
    version      INTEGER PRIMARY KEY,
    source_yaml  TEXT NOT NULL,
    compiled_ir  TEXT NOT NULL,
    created_by   TEXT NOT NULL,
    created_at   TEXT NOT NULL
);

CREATE TABLE policy_rule (
    id        INTEGER PRIMARY KEY,
    version   INTEGER NOT NULL REFERENCES policy_version(version),
    block_ord INTEGER NOT NULL,
    rule_ord  INTEGER NOT NULL,
    action    TEXT NOT NULL,
    src       TEXT NOT NULL,
    dst       TEXT NOT NULL,
    proto     TEXT NOT NULL,
    ports     TEXT
);

CREATE TABLE policy_status (
    gateway_id      INTEGER NOT NULL REFERENCES gateway(id),
    applied_version INTEGER NOT NULL REFERENCES policy_version(version),
    acked_at        TEXT NOT NULL,
    PRIMARY KEY (gateway_id, applied_version)
);

CREATE TABLE api_token (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    role        TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    expires_at  TEXT,
    revoked_at  TEXT
);

CREATE TABLE audit_log (
    id        INTEGER PRIMARY KEY,
    ts        TEXT NOT NULL,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    entity    TEXT NOT NULL,
    diff_json TEXT NOT NULL
);
"#;

/// Returned (wrapped in [`anyhow::Error`]) when [`Db::insert_segment`]'s CIDR
/// overlap check finds a conflicting, already-registered CIDR. Names the
/// existing segment so callers/operators can resolve it (master-spec §4.1,
/// C-2).
#[derive(Debug)]
pub struct OverlapError {
    pub conflicting_segment: String,
}

impl std::fmt::Display for OverlapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CIDR overlaps with an existing CIDR of segment '{}'",
            self.conflicting_segment
        )
    }
}

impl std::error::Error for OverlapError {}

/// The controller's embedded SQLite store.
///
/// The connection is held behind a `Mutex` purely for interior mutability
/// (rusqlite's `Connection::transaction` needs `&mut Connection`); `Db` is
/// not meant to be shared across threads under contention in this task —
/// that's the "later task wraps them for async" seam mentioned in the brief.
pub struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    /// Opens (creating if absent) a SQLite database file at `path` and runs
    /// migrations.
    pub fn open(path: &Path) -> Result<Db> {
        let conn = Connection::open(path)?;
        // FK enforcement is per-connection and defaults OFF in SQLite, so it
        // must be re-enabled on every open (it is not persisted in the file).
        // Without this, all REFERENCES clauses in the schema are decorative.
        conn.pragma_update(None, "foreign_keys", true)?;
        let db = Db {
            conn: Mutex::new(conn),
        };
        db.run_migrations()?;
        Ok(db)
    }

    /// Opens an in-memory database and runs migrations. Used by tests and by
    /// any embedded/ephemeral deployment mode.
    pub fn open_memory() -> Result<Db> {
        let conn = Connection::open_in_memory()?;
        // See `open`: FK enforcement is per-connection and defaults OFF.
        conn.pragma_update(None, "foreign_keys", true)?;
        let db = Db {
            conn: Mutex::new(conn),
        };
        db.run_migrations()?;
        Ok(db)
    }

    /// Reads `PRAGMA user_version`.
    pub fn user_version(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let v: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        Ok(v)
    }

    /// Applies the full schema DDL in a single transaction if `user_version`
    /// is below 1, then sets `user_version = 1`. Idempotent: running it again
    /// once at version 1 is a no-op.
    pub fn run_migrations(&self) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version < 1 {
            let tx = conn.transaction()?;
            // PRAGMA user_version does not accept bound parameters, but the
            // value here is a fixed schema version, not user input. It's set
            // inside the same transaction as the DDL so a crash between
            // "tables created" and "version bumped" can't happen — either
            // both land or neither does, keeping run_migrations idempotent.
            tx.execute_batch(SCHEMA_V1)?;
            tx.execute_batch("PRAGMA user_version = 1")?;
            tx.commit()?;
        }
        Ok(())
    }

    /// Inserts a new segment and its declared CIDRs in one transaction.
    ///
    /// Only IPv4 is supported (v1, master-spec is IPv4-only) — enforced by
    /// the `Ipv4Net` parameter type, so no non-IPv4 CIDR can reach this
    /// function. For each CIDR, runs the overlap check against every
    /// already-registered CIDR belonging to a *different* segment (a fresh
    /// segment never conflicts with itself). On the first conflict, the
    /// whole transaction is rolled back and `Err(OverlapError)` names the
    /// existing segment. Returns the new segment's id.
    pub fn insert_segment(&self, name: &str, cidrs: &[Ipv4Net]) -> Result<i64> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        tx.execute("INSERT INTO segment (name) VALUES (?1)", params![name])?;
        let segment_id = tx.last_insert_rowid();

        // Accumulates the CIDRs already accepted in *this* call so each
        // incoming CIDR is also checked against its siblings — the DB query
        // below only sees rows of *other* segments, so without this a single
        // declaration could nest two overlapping CIDRs (e.g. 10.0.0.0/16 and
        // 10.0.1.0/24) undetected.
        let mut accepted: Vec<Ipv4Net> = Vec::with_capacity(cidrs.len());

        for cidr in cidrs {
            // First: self-overlap within the incoming set.
            if accepted
                .iter()
                .any(|prev| cidr.contains(&prev.network()) || prev.contains(&cidr.network()))
            {
                tx.rollback()?;
                return Err(anyhow::Error::new(OverlapError {
                    conflicting_segment: name.to_string(),
                }));
            }

            let conflict: Option<(String, String)> = {
                let mut stmt = tx.prepare(
                    "SELECT c.cidr, s.name \
                     FROM cidr c JOIN segment s ON s.id = c.segment_id \
                     WHERE c.segment_id != ?1",
                )?;
                let mut rows = stmt.query(params![segment_id])?;
                let mut found = None;
                while let Some(row) = rows.next()? {
                    let existing_cidr_str: String = row.get(0)?;
                    let existing_segment: String = row.get(1)?;
                    let existing: Ipv4Net = existing_cidr_str.parse()?;
                    if cidr.contains(&existing.network()) || existing.contains(&cidr.network()) {
                        found = Some((existing_cidr_str, existing_segment));
                        break;
                    }
                }
                found
            };

            if let Some((_, conflicting_segment)) = conflict {
                tx.rollback()?;
                return Err(anyhow::Error::new(OverlapError { conflicting_segment }));
            }

            tx.execute(
                "INSERT INTO cidr (segment_id, cidr) VALUES (?1, ?2)",
                params![segment_id, cidr.to_string()],
            )?;
            accepted.push(*cidr);
        }

        tx.commit()?;
        Ok(segment_id)
    }

    /// Appends one row to `audit_log` (master-spec §4.5, C-8).
    pub fn audit(&self, actor: &str, action: &str, entity: &str, diff_json: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let ts = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)?;
        conn.execute(
            "INSERT INTO audit_log (ts, actor, action, entity, diff_json) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![ts, actor, action, entity, diff_json],
        )?;
        Ok(())
    }

    /// Returns the total number of rows in `audit_log` (test/introspection
    /// helper).
    pub fn count_audit(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))?;
        Ok(count)
    }

    /// Inserts one `enrollment_token` row. `secret_hash` is the sha256 (hex)
    /// of the token's random secret — the raw secret itself is never
    /// persisted anywhere, only its hash, so a stolen DB backup can't be used
    /// to mint enrollments. `bound_cidrs` is a plain comma-joined string
    /// (cycle-2 stand-in; no query currently needs it structured).
    #[allow(clippy::too_many_arguments)]
    pub fn insert_enrollment_token(
        &self,
        id: &str,
        secret_hash: &str,
        kind: &str,
        bound_cidrs: &str,
        rebind_segment_id: Option<i64>,
        expires_at: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO enrollment_token (id, secret_hash, kind, bound_cidrs, rebind_segment_id, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, secret_hash, kind, bound_cidrs, rebind_segment_id, expires_at],
        )?;
        Ok(())
    }
}
