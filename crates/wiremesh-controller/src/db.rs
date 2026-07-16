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
use rusqlite::{params, Connection, OptionalExtension, Transaction};

/// Increments the persisted `state_revision` counter and returns the NEW
/// value, using `tx` so the bump commits atomically with whatever mutation
/// `tx` is carrying — a rolled-back mutation therefore never advances the
/// revision. Every projection-affecting mutation ([`Db::insert_segment`],
/// [`Db::enroll_gateway`], and — as later tasks land them — key rotate /
/// drain / revoke / policy apply) must call this inside its own transaction.
fn bump_revision_tx(tx: &Transaction<'_>) -> rusqlite::Result<u64> {
    tx.execute(
        "UPDATE state_revision SET revision = revision + 1 WHERE id = 0",
        [],
    )?;
    let rev: i64 = tx.query_row(
        "SELECT revision FROM state_revision WHERE id = 0",
        [],
        |row| row.get(0),
    )?;
    Ok(rev as u64)
}

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
    id              INTEGER PRIMARY KEY,
    segment_id      INTEGER NOT NULL REFERENCES segment(id),
    name            TEXT NOT NULL UNIQUE,
    status          TEXT NOT NULL,
    backend         TEXT NOT NULL,
    last_seen       TEXT,
    -- Last policy version this gateway acked via `Sync.Report` (Task 8).
    -- NULL until the gateway's first Report call. The full `policy_status`
    -- history table above already exists for a later task's ack-log
    -- surfacing (`fabricctl policy status`); this column is the minimal
    -- "does the controller know what this gateway last applied" fact T8
    -- needs today.
    applied_version INTEGER
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

-- Single-row monotonic counter backing the Sync snapshot's `revision`
-- (master-spec: the projection revision must survive a controller restart,
-- else a reconnecting gateway comparing against a stale baseline would
-- mis-diff — see T8 delta stream / T9 fail-static resync). `id = 0` pins it
-- to exactly one row; `revision` starts at 0 and is bumped IN THE SAME
-- TRANSACTION as every projection-affecting mutation, so a rolled-back
-- mutation never advances it.
CREATE TABLE state_revision (
    id       INTEGER PRIMARY KEY CHECK (id = 0),
    revision INTEGER NOT NULL
);
INSERT INTO state_revision (id, revision) VALUES (0, 0);
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

/// Distinguishes *why* [`Db::enroll_gateway`] failed, so the gRPC layer
/// (Task 5's `EnrollmentSvc`) can map each case to the right `tonic::Status`
/// code without string-sniffing an `anyhow::Error`.
#[derive(Debug)]
pub enum EnrollError {
    /// No `enrollment_token` row matches: wrong secret, wrong kind, expired,
    /// or already used. Deliberately a single variant that doesn't say
    /// which — telling a caller which of those applies would help an
    /// attacker fish for valid-but-not-quite-right tokens.
    InvalidToken,
    /// The declared cidrs don't all resolve to exactly one already
    /// registered segment.
    NoMatchingSegment,
    /// The declared cidrs don't match the set the token was minted bound to
    /// (or a `gateway` token was minted with an empty, unscoped bound set):
    /// the token is authorized only for its own segment's cidrs, so it can't
    /// be redeemed into a different segment by declaring that segment's
    /// cidrs. Kept distinct from `InvalidToken` so the gRPC layer can pick
    /// the mapping (this task maps it to `PermissionDenied`).
    BoundCidrMismatch,
    /// Anything else — a genuine DB/storage error.
    Other(anyhow::Error),
}

impl std::fmt::Display for EnrollError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrollError::InvalidToken => {
                write!(f, "invalid, expired, wrong-kind, or already-used enrollment token")
            }
            EnrollError::NoMatchingSegment => {
                write!(f, "no segment is registered for the declared cidrs")
            }
            EnrollError::BoundCidrMismatch => write!(
                f,
                "declared cidrs are outside the token's minted bound_cidrs scope"
            ),
            EnrollError::Other(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for EnrollError {}

impl From<rusqlite::Error> for EnrollError {
    fn from(e: rusqlite::Error) -> Self {
        EnrollError::Other(e.into())
    }
}

/// Result of a successful [`Db::enroll_gateway`] call.
pub struct EnrollOutcome {
    pub segment_id: i64,
    pub gateway_id: i64,
}

/// One row of [`Db::list_other_gateways`] — an enrolled gateway's identity
/// and the segment it belongs to. Feeds `routes::peers_of`'s full-mesh
/// projection (Task 7).
pub struct GatewayRow {
    pub id: i64,
    pub segment_id: i64,
    pub segment_name: String,
}

/// The enrolled gateway a Sync mTLS client cert's subject CN resolved to
/// (see [`Db::find_gateway_by_name`]) — used to turn "the peer cert with
/// this CN" into "gateway id N in segment S" for the projection.
pub struct GatewayIdentity {
    pub id: i64,
    pub segment_id: i64,
    pub segment_name: String,
}

/// One row of [`Db::active_keys_for_gateway`]: `(epoch, pubkey, state)`.
/// Cycle-2's Sync projection only reads `state = 'active'` rows (key
/// management/rotation is Task 11) — this task's tests always see an empty
/// `Vec` since nothing populates `gateway_key` yet.
pub type GatewayKeyRow = (i64, String, String);

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

        // Projection-affecting mutation: a new segment (and its CIDRs) can
        // change any gateway's peer allowed_ips, so bump the persisted
        // revision in this same transaction — a rollback above returns early
        // and never reaches here.
        bump_revision_tx(&tx)?;

        tx.commit()?;
        Ok(segment_id)
    }

    /// Reads the persisted Sync-projection revision (the single
    /// `state_revision` row). Starts at 0 on a fresh DB and only ever
    /// increases — every projection-affecting mutation bumps it in its own
    /// transaction (see [`bump_revision_tx`]). Sourcing the snapshot's
    /// `revision` from here (rather than an in-process counter) is what makes
    /// it survive a controller restart.
    pub fn current_revision(&self) -> Result<u64> {
        let conn = self.conn.lock().unwrap();
        let rev: i64 = conn.query_row(
            "SELECT revision FROM state_revision WHERE id = 0",
            [],
            |row| row.get(0),
        )?;
        Ok(rev as u64)
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

    /// Redeems a single-use `enrollment_token` for a signed gateway
    /// certificate, ALL in one transaction: validates the token (right
    /// kind, unexpired, unused), enforces that the declared `cidrs` match the
    /// set the token was minted bound to (`bound_cidrs`), resolves the
    /// segment that owns every declared `cidrs` entry, inserts the `gateway`
    /// row, records the `certificate`, marks the token `used_at`, and appends
    /// an audit entry.
    ///
    /// Holding the connection mutex for the whole operation (same pattern as
    /// [`Db::insert_segment`]) is what makes the token's single-use
    /// guarantee atomic: there is no window where two concurrent calls with
    /// the same secret can both observe the row as unused — the second one
    /// either blocks on the mutex until the first commits (and then sees
    /// `used_at` already set), or its own `UPDATE ... WHERE used_at IS NULL`
    /// affects zero rows, which is treated as `InvalidToken` too.
    ///
    /// Callers pass the already-signed certificate's `cert_serial` /
    /// `issuer_handle` / `cert_not_after` — signing itself is pure crypto
    /// with no DB dependency, so it happens outside this transaction (in the
    /// gRPC handler), before this call.
    #[allow(clippy::too_many_arguments)]
    pub fn enroll_gateway(
        &self,
        secret_hash: &str,
        kind: &str,
        cidrs: &[Ipv4Net],
        gateway_name: &str,
        cert_serial: &str,
        issuer_handle: &str,
        cert_not_after: &str,
        now: &str,
    ) -> Result<EnrollOutcome, EnrollError> {
        if cidrs.is_empty() {
            return Err(EnrollError::NoMatchingSegment);
        }

        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        let token_row: Option<(String, String)> = {
            let mut stmt = tx.prepare(
                "SELECT id, bound_cidrs FROM enrollment_token \
                 WHERE secret_hash = ?1 AND kind = ?2 AND used_at IS NULL AND expires_at > ?3",
            )?;
            let mut rows = stmt.query(params![secret_hash, kind, now])?;
            match rows.next()? {
                // bound_cidrs is NULL-able in the schema; treat NULL as "" so
                // the T4 decode contract (""→[]) applies uniformly.
                Some(row) => Some((row.get(0)?, row.get::<_, Option<String>>(1)?.unwrap_or_default())),
                None => None,
            }
        };

        let Some((token_id, bound_cidrs_raw)) = token_row else {
            tx.rollback()?;
            return Err(EnrollError::InvalidToken);
        };

        // Authorization scope: the declared `cidrs` must match the CIDR set
        // this token was minted bound to (MintToken stored them, comma-joined,
        // in `bound_cidrs`). Decoded through the canonical T4 decoder
        // (`decode_bound_cidrs`: ""→[]). A `gateway` token with an EMPTY
        // bound set is unscoped and rejected outright — it would otherwise be
        // a bearer credential for every segment. (`rebind` tokens legitimately
        // carry empty bound_cidrs and steer by `rebind_segment_id` instead,
        // but only `gateway`-kind tokens reach this method today; rebind is
        // Task 10.) Comparison is set-based over parsed `Ipv4Net` values so
        // it's order- and formatting-insensitive but still exact (no
        // subnet-of slack). Checked BEFORE marking the token used, and a
        // mismatch rolls the transaction back, so a rejected enroll does NOT
        // consume the single-use token — same discipline as NoMatchingSegment.
        let bound: std::collections::BTreeSet<Ipv4Net> = {
            let decoded = crate::services::admin::decode_bound_cidrs(&bound_cidrs_raw);
            let mut set = std::collections::BTreeSet::new();
            for c in decoded {
                let net: Ipv4Net = c.parse().map_err(|e| {
                    EnrollError::Other(anyhow::anyhow!(
                        "stored bound_cidr {c:?} is not valid IPv4: {e}"
                    ))
                })?;
                set.insert(net);
            }
            set
        };
        if bound.is_empty() {
            tx.rollback()?;
            return Err(EnrollError::BoundCidrMismatch);
        }
        let declared: std::collections::BTreeSet<Ipv4Net> = cidrs.iter().copied().collect();
        if declared != bound {
            tx.rollback()?;
            return Err(EnrollError::BoundCidrMismatch);
        }

        // Resolve the segment that owns EVERY declared cidr — all of them
        // must belong to the same, already-registered segment (cycle-2
        // scope: the segment pre-exists; a `rebind` token's segment
        // exemption is Task 10).
        let mut segment_id: Option<i64> = None;
        for cidr in cidrs {
            let found: Option<i64> = tx
                .query_row(
                    "SELECT segment_id FROM cidr WHERE cidr = ?1",
                    params![cidr.to_string()],
                    |row| row.get(0),
                )
                .optional()?;
            match (found, segment_id) {
                (None, _) => {
                    tx.rollback()?;
                    return Err(EnrollError::NoMatchingSegment);
                }
                (Some(sid), None) => segment_id = Some(sid),
                (Some(sid), Some(existing)) if sid != existing => {
                    tx.rollback()?;
                    return Err(EnrollError::NoMatchingSegment);
                }
                _ => {}
            }
        }
        let segment_id =
            segment_id.expect("cidrs is non-empty: loop above always sets segment_id or returns early");

        tx.execute(
            "INSERT INTO gateway (segment_id, name, status, backend, last_seen) \
             VALUES (?1, ?2, 'active', 'wireguard', NULL)",
            params![segment_id, gateway_name],
        )?;
        let gateway_id = tx.last_insert_rowid();

        tx.execute(
            "INSERT INTO certificate (serial, subject_kind, subject_id, issuer_handle, not_after) \
             VALUES (?1, 'gateway', ?2, ?3, ?4)",
            params![cert_serial, gateway_id, issuer_handle, cert_not_after],
        )?;

        // `AND used_at IS NULL` is redundant given the SELECT above already
        // filtered on it under the same held lock, but it costs nothing and
        // means a future refactor that weakens the lock discipline fails
        // loudly (via the `updated != 1` check) instead of silently
        // double-spending a token.
        let updated = tx.execute(
            "UPDATE enrollment_token SET used_at = ?1 WHERE id = ?2 AND used_at IS NULL",
            params![now, token_id],
        )?;
        if updated != 1 {
            tx.rollback()?;
            return Err(EnrollError::InvalidToken);
        }

        tx.execute(
            "INSERT INTO audit_log (ts, actor, action, entity, diff_json) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                now,
                "enrollment-token",
                "enroll",
                format!("gateway/{gateway_name}"),
                format!(r#"{{"segment_id":{segment_id},"gateway_id":{gateway_id}}}"#),
            ],
        )?;

        // Projection-affecting mutation: a newly enrolled gateway becomes a
        // peer in every other gateway's full-mesh snapshot, so bump the
        // persisted revision in this same transaction. Any early return above
        // rolls back without reaching here, so a rejected enroll doesn't
        // advance the revision.
        bump_revision_tx(&tx)?;

        tx.commit()?;
        Ok(EnrollOutcome { segment_id, gateway_id })
    }

    /// The other N-1 enrolled gateways (every `gateway` row except
    /// `exclude_gateway_id`), each with the segment it belongs to. Used by
    /// `routes::peers_of` to build the full-mesh peer set for a Sync
    /// snapshot. Ordered by id for deterministic output.
    pub fn list_other_gateways(&self, exclude_gateway_id: i64) -> Result<Vec<GatewayRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT g.id, g.segment_id, s.name \
             FROM gateway g JOIN segment s ON s.id = g.segment_id \
             WHERE g.id != ?1 \
             ORDER BY g.id",
        )?;
        let rows = stmt
            .query_map(params![exclude_gateway_id], |row| {
                Ok(GatewayRow {
                    id: row.get(0)?,
                    segment_id: row.get(1)?,
                    segment_name: row.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Every CIDR registered to `segment_id`, sorted for deterministic
    /// output — becomes a peer's `allowed_ips` in the Sync projection.
    pub fn cidrs_for_segment(&self, segment_id: i64) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT cidr FROM cidr WHERE segment_id = ?1 ORDER BY cidr")?;
        let rows = stmt
            .query_map(params![segment_id], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// `gateway_key` rows with `state = 'active'` for `gateway_id`, as
    /// `(epoch, pubkey, state)` — becomes a peer's `keys` in the Sync
    /// projection. Empty until Task 11 populates `gateway_key`.
    pub fn active_keys_for_gateway(&self, gateway_id: i64) -> Result<Vec<GatewayKeyRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT epoch, pubkey, state FROM gateway_key \
             WHERE gateway_id = ?1 AND state = 'active' \
             ORDER BY epoch",
        )?;
        let rows = stmt
            .query_map(params![gateway_id], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Serial numbers of every `certificate` row with `revoked_at NOT NULL`,
    /// sorted for deterministic output — the Sync snapshot's
    /// `revoked_serials`.
    pub fn revoked_serials(&self) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT serial FROM certificate WHERE revoked_at IS NOT NULL ORDER BY serial")?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Records the policy version `gateway_id` has applied and acked via
    /// `Sync.Report` (Task 8) — just the `gateway.applied_version` column;
    /// the richer `policy_status` history table is a later task's scope
    /// (this task's brief only requires the controller remember each
    /// gateway's last-applied version). Errors if `gateway_id` doesn't
    /// exist (the caller already resolved it from the mTLS peer cert, so
    /// that should never happen in practice).
    pub fn set_applied_version(&self, gateway_id: i64, applied_version: u64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let updated = conn.execute(
            "UPDATE gateway SET applied_version = ?1 WHERE id = ?2",
            params![applied_version as i64, gateway_id],
        )?;
        if updated != 1 {
            anyhow::bail!(
                "Report: no gateway row with id {gateway_id} to record applied_version on"
            );
        }
        Ok(())
    }

    /// Resolves an enrolled gateway by its `gateway.name` — the same value
    /// `EnrollmentSvc` derives deterministically from the enrollment token
    /// (`gw-<secret_hash_hex>`) and stamps as the issued leaf cert's subject
    /// CN. This is how Sync's mTLS layer turns "the peer cert with this CN"
    /// into a gateway identity: it never trusts a client-supplied id, only
    /// the CN pulled off the cert tonic/rustls already validated chains to
    /// the CA.
    pub fn find_gateway_by_name(&self, name: &str) -> Result<Option<GatewayIdentity>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT g.id, g.segment_id, s.name \
             FROM gateway g JOIN segment s ON s.id = g.segment_id \
             WHERE g.name = ?1",
            params![name],
            |row| {
                Ok(GatewayIdentity {
                    id: row.get(0)?,
                    segment_id: row.get(1)?,
                    segment_name: row.get(2)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }
}
