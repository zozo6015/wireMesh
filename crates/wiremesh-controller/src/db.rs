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
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension, Transaction};

/// Increments the persisted `state_revision` counter and returns the NEW
/// value, using `tx` so the bump commits atomically with whatever mutation
/// `tx` is carrying — a rolled-back mutation therefore never advances the
/// revision. Every projection-affecting mutation ([`Db::insert_segment`],
/// [`Db::enroll_gateway`], and — as later tasks land them — key rotate /
/// drain / revoke / policy apply) must call this inside its own transaction.
/// (Task 15) Generates a fresh random per-gateway `observe_key`: 32 random
/// bytes, hex-encoded (64 hex chars) — same "raw random bytes, hex encoded"
/// shape `services::admin::mint_token`'s enrollment-token secret uses,
/// just kept as a plain string end-to-end (unlike that secret, this key
/// itself — not a hash of it — is what the MAC verifier needs, since the
/// controller must recompute the exact same MAC the gateway did).
fn generate_observe_key() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

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
    applied_version INTEGER,
    -- (Task 15) Random per-gateway secret, generated at enrollment and
    -- handed to the gateway exactly once (in `EnrollResponse.observe_key`),
    -- that authenticates this gateway's UDP observation probes — see
    -- `crate::observe`. Nullable only because SQLite requires a column to
    -- accept NULL absent a DEFAULT; every row inserted by `enroll_gateway`
    -- always supplies one.
    observe_key     TEXT,
    -- (Task 15) The `ip:port` the controller's UDP observation endpoint most
    -- recently observed a verified probe from this gateway arrive from —
    -- surfaced to peers as this gateway's candidate endpoint
    -- (`crate::routes`/`crate::projection`). NULL until the gateway's first
    -- successful probe.
    candidate_endpoint TEXT
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

/// Shared insert body behind [`Db::insert_segment`] AND [`Db::apply_fabric`]
/// (Task 14): inserts one `segment` row plus its declared CIDRs, enforcing
/// the CIDR-overlap invariant against every OTHER already-registered
/// segment's CIDRs (and against siblings within this same call, so a single
/// declaration can't nest two overlapping CIDRs of its own undetected). Does
/// NOT bump the revision or commit — callers own the surrounding
/// transaction's lifecycle (a fresh one per call for `insert_segment`, a
/// shared one spanning the whole apply for `apply_fabric`) precisely so
/// `apply_fabric` can batch several of these plus a revision bump into ONE
/// atomic unit. On error, the caller is responsible for rolling back the
/// transaction — this function only returns `Err`, it never rolls back
/// itself, since a caller batching multiple calls (`apply_fabric`) needs to
/// roll back the WHOLE transaction, not just this segment's partial writes.
fn insert_segment_tx(tx: &Transaction<'_>, name: &str, cidrs: &[Ipv4Net]) -> Result<i64> {
    tx.execute("INSERT INTO segment (name) VALUES (?1)", params![name])?;
    let segment_id = tx.last_insert_rowid();

    let mut accepted: Vec<Ipv4Net> = Vec::with_capacity(cidrs.len());

    for cidr in cidrs {
        // First: self-overlap within the incoming set.
        if accepted
            .iter()
            .any(|prev| cidr.contains(&prev.network()) || prev.contains(&cidr.network()))
        {
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
            return Err(anyhow::Error::new(OverlapError { conflicting_segment }));
        }

        tx.execute(
            "INSERT INTO cidr (segment_id, cidr) VALUES (?1, ?2)",
            params![segment_id, cidr.to_string()],
        )?;
        accepted.push(*cidr);
    }

    Ok(segment_id)
}

/// Result of a successful [`Db::apply_fabric`] call — the mirror of
/// `wiremesh_proto::v1::ApplyDiff` on the DB layer (kept as a separate type
/// so `crate::db` doesn't depend on the proto crate). `updated_segments` and
/// `deleted_segments` are always `0` in cycle-2 (create-only scope — see
/// `apply_fabric`'s doc comment); kept as fields now (rather than added
/// later) so the proto shape and `AdminSvc::apply`'s mapping don't need to
/// change again once update/delete diffing lands.
#[derive(Debug, Clone, Copy, Default)]
pub struct ApplyOutcome {
    pub created_segments: u32,
    pub updated_segments: u32,
    pub deleted_segments: u32,
    pub policy_updated: bool,
}

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
    /// the mapping (this task maps it to `PermissionDenied`). Also used for
    /// a `rebind` token (Task 10) whose `rebind_segment_id` doesn't match
    /// the segment the declared cidrs actually resolve to — same
    /// "authorized for one segment, tried to redeem into another" shape.
    BoundCidrMismatch,
    /// (Task 10) A `gateway`-kind token declared cidrs that resolve to a
    /// segment which already has an active gateway. This is the
    /// one-gateway-per-segment invariant's enforcement point (a self-overlap
    /// on the *segment*, not the raw CIDR ranges — see `insert_segment`'s
    /// `OverlapError` for the CIDR-range flavor of the same idea): only an
    /// explicit `rebind` token — minted bound to that exact `segment_id` —
    /// is allowed to replace the incumbent gateway. Mapped by the gRPC layer
    /// to `AlreadyExists`, mirroring `CreateSegment`'s `OverlapError`
    /// mapping.
    SegmentAlreadyBound,
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
            EnrollError::SegmentAlreadyBound => write!(
                f,
                "segment already has an active gateway; use a rebind token to replace it"
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
    /// (Task 10) The `issuer_handle`(s) of any gateway cert(s) this call
    /// revoked in the DB as part of a `rebind` — empty for an ordinary
    /// `gateway`-kind enrollment. The caller (`EnrollmentSvc`) uses these to
    /// also call `CertificateIssuer::revoke` for each, best-effort — see
    /// that call site's comment for why the DB's `revoked_at` (already
    /// committed by the time this is returned), not that call, is
    /// authoritative.
    pub revoked_issuer_handles: Vec<String>,
    /// (Task 15) The random `observe_key` freshly generated and stored for
    /// this gateway — the caller (`EnrollmentSvc`) returns it to the gateway
    /// once, in `EnrollResponse.observe_key`. See `crate::observe`'s module
    /// doc comment for how it's used.
    pub observe_key: String,
}

/// One row of [`Db::list_other_gateways`] — an enrolled gateway's identity
/// and the segment it belongs to. Feeds `routes::peers_of`'s full-mesh
/// projection (Task 7).
pub struct GatewayRow {
    pub id: i64,
    pub segment_id: i64,
    pub segment_name: String,
    /// (Task 15) This peer's most recently observed candidate endpoint
    /// (`gateway.candidate_endpoint`), if the controller's UDP observation
    /// endpoint has ever recorded one for it.
    pub candidate_endpoint: Option<String>,
}

/// The enrolled gateway a Sync mTLS client cert's subject CN resolved to
/// (see [`Db::find_gateway_by_name`]) — used to turn "the peer cert with
/// this CN" into "gateway id N in segment S" for the projection.
pub struct GatewayIdentity {
    pub id: i64,
    pub segment_id: i64,
    pub segment_name: String,
}

/// One row of [`Db::active_keys_for_gateway`] / [`Db::all_keys_for_gateway`]:
/// `(epoch, pubkey, state)`.
pub type GatewayKeyRow = (i64, String, String);

/// Result of a successful [`Db::rotate_key`] call: the new epoch and its
/// (placeholder) pubkey — always inserted with `state = 'pending'`.
pub struct RotateKeyOutcome {
    pub epoch: i64,
    pub pubkey: String,
}

/// Result of a successful [`Db::drain_gateway`] call: the serial(s) of every
/// `certificate` row this drain revoked (ordinarily exactly one — a gateway's
/// current leaf cert — but this tolerates more than one still-unrevoked row).
/// Fed into the `GatewayDrained` `ChangeEvent`'s `revoked_serials`, mirroring
/// how already-connected peers learn a rebind's revocation via
/// `revoked_serials` in the projection.
pub struct DrainOutcome {
    pub revoked_serials: Vec<String>,
}

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
        // A second, independent connection to this same file (e.g.
        // `wiremesh-testkit::TestController::gateway_exists` opening its own
        // read-only-in-spirit `Db::open` against the live controller's DB
        // file) would otherwise get an immediate `SQLITE_BUSY` if it ever
        // raced a writer's in-flight transaction — SQLite's default
        // busy-timeout is 0. 5s comfortably covers any of this controller's
        // (short, single-statement-batch) transactions.
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
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

        let segment_id = match insert_segment_tx(&tx, name, cidrs) {
            Ok(id) => id,
            Err(e) => {
                tx.rollback()?;
                return Err(e);
            }
        };

        // Projection-affecting mutation: a new segment (and its CIDRs) can
        // change any gateway's peer allowed_ips, so bump the persisted
        // revision in this same transaction — the early return above never
        // reaches here.
        bump_revision_tx(&tx)?;

        tx.commit()?;
        Ok(segment_id)
    }

    /// (Task 14) Diffs a parsed `fabric.yaml`'s `segments:` list (and,
    /// separately, its optional `policy:` source) against current DB state
    /// and applies every ACTUAL change in one transaction — this is the
    /// engine behind `Admin.Apply`.
    ///
    /// **Scope (cycle-2 / this task):** CREATE-only for segments — a
    /// declared segment whose `name` doesn't already exist is inserted (same
    /// CIDR-overlap invariant as [`Db::insert_segment`], enforced via the
    /// shared [`insert_segment_tx`] helper); a declared segment whose `name`
    /// ALREADY exists is treated as a no-op (its CIDRs are not diffed/
    /// updated, and it is never deleted). Update/delete diffing is
    /// deliberately partial — see the task report for what's deferred.
    ///
    /// **Idempotence is the load-bearing contract:** nothing is written at
    /// all — no `INSERT`, no audit row, no revision bump — unless at least
    /// one segment was actually created or the policy source actually
    /// changed. That's why every existing-name check and the policy
    /// source-comparison happen BEFORE any mutation: a second, identical
    /// apply must produce a transaction with zero writes in it, which is
    /// what makes "zero new audit rows" true rather than merely arranged to
    /// look true.
    ///
    /// `policy_yaml`, if `Some`, is stored as `policy_version.source_yaml`
    /// and compiled via the STUB [`crate::apply::compile_policy`] (always
    /// `"[]"`, empty IR v0) — but only as a NEW `policy_version` row (version
    /// = previous max + 1, or 1 if none exist yet) when `policy_yaml` differs
    /// from the latest stored `source_yaml`. `None`/identical-to-latest never
    /// touches the `policy_version` table at all.
    pub fn apply_fabric(
        &self,
        segments: &[(String, Vec<Ipv4Net>)],
        policy_yaml: Option<&str>,
        actor: &str,
        now: &str,
    ) -> Result<ApplyOutcome> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        let existing_names: std::collections::HashSet<String> = {
            let mut stmt = tx.prepare("SELECT name FROM segment")?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            rows.collect::<rusqlite::Result<_>>()?
        };

        // (entity, diff_json) pairs, accumulated so audit rows are only
        // actually written once we know the apply as a whole isn't empty.
        let mut created_segments = 0u32;
        let mut audit_rows: Vec<(&'static str, String, String)> = Vec::new();

        for (name, cidrs) in segments {
            if existing_names.contains(name) {
                // Already present: cycle-2 scope is create + no-op-on-match
                // (see the doc comment above) — not an update, not an error.
                continue;
            }
            match insert_segment_tx(&tx, name, cidrs) {
                Ok(_id) => {}
                Err(e) => {
                    tx.rollback()?;
                    return Err(e);
                }
            }
            created_segments += 1;
            let cidr_strs: Vec<String> = cidrs.iter().map(|c| c.to_string()).collect();
            audit_rows.push((
                "apply-create-segment",
                format!("segment/{name}"),
                format!(r#"{{"name":"{name}","cidrs":{cidr_strs:?}}}"#),
            ));
        }

        // Policy stub seam: only touched when a `policy:` stanza was
        // actually declared AND its source text differs from whatever is
        // currently the latest `policy_version.source_yaml` (a fresh DB has
        // none, which counts as "differs").
        let mut policy_updated = false;
        if let Some(source_yaml) = policy_yaml {
            let latest: Option<(i64, String)> = tx
                .query_row(
                    "SELECT version, source_yaml FROM policy_version \
                     ORDER BY version DESC LIMIT 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;

            let changed = match &latest {
                Some((_, existing_source)) => existing_source != source_yaml,
                None => true,
            };

            if changed {
                let new_version = latest.map(|(v, _)| v + 1).unwrap_or(1);
                let compiled_ir = crate::apply::compile_policy(source_yaml);
                tx.execute(
                    "INSERT INTO policy_version (version, source_yaml, compiled_ir, created_by, created_at) \
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![new_version, source_yaml, compiled_ir, actor, now],
                )?;
                policy_updated = true;
                audit_rows.push((
                    "apply-policy",
                    format!("policy_version/{new_version}"),
                    format!(r#"{{"version":{new_version}}}"#),
                ));
            }
        }

        if created_segments == 0 && !policy_updated {
            // True no-op: nothing was written above (every branch that
            // writes also increments one of these), so there is nothing to
            // audit and no revision to bump — roll back the (empty, but
            // still-open) transaction rather than committing a no-op write.
            tx.rollback()?;
            return Ok(ApplyOutcome {
                created_segments: 0,
                updated_segments: 0,
                deleted_segments: 0,
                policy_updated: false,
            });
        }

        for (action, entity, diff_json) in audit_rows {
            tx.execute(
                "INSERT INTO audit_log (ts, actor, action, entity, diff_json) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![now, actor, action, entity, diff_json],
            )?;
        }

        // Projection-affecting mutation (new segment(s)/policy change both
        // qualify), so bump the persisted revision in this same transaction
        // — see `bump_revision_tx`'s doc comment. Only reached when at least
        // one real change happened, per the early return above.
        bump_revision_tx(&tx)?;

        tx.commit()?;
        Ok(ApplyOutcome {
            created_segments,
            updated_segments: 0,
            deleted_segments: 0,
            policy_updated,
        })
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
    /// kind, unexpired, unused), enforces authorization scope appropriate to
    /// the token's own `kind` (see below), resolves the segment that owns
    /// every declared `cidrs` entry, inserts the `gateway` row, records the
    /// `certificate`, marks the token `used_at`, and appends an audit entry.
    ///
    /// The token's `kind` (`gateway` or `rebind`; `relay` is out of this
    /// method's scope — Task 5's slice) is read from the matched row itself
    /// rather than supplied by the caller, so this one method handles both
    /// shapes uniformly:
    ///
    /// - **`gateway`**: the declared `cidrs` must exactly match the token's
    ///   minted `bound_cidrs` set (a `gateway` token minted with an EMPTY
    ///   bound set is unscoped and rejected outright — it would otherwise be
    ///   a bearer credential for every segment). The resolved segment must
    ///   NOT already have an active gateway — this is the
    ///   one-gateway-per-segment invariant (`EnrollError::SegmentAlreadyBound`,
    ///   the "self-overlap" a `rebind` token exists to get past).
    /// - **`rebind`** (Task 10): `bound_cidrs` is ignored (expected empty —
    ///   MintToken never populates it for this kind); authorization instead
    ///   requires the resolved segment's id to equal the token's minted
    ///   `rebind_segment_id` exactly (`EnrollError::BoundCidrMismatch`
    ///   otherwise) — so a rebind token minted for segment A can never be
    ///   redeemed against segment B by declaring B's cidrs, even though
    ///   nothing else about the request looks different from a legitimate
    ///   rebind of A. Exempted from the `SegmentAlreadyBound` check (that's
    ///   the whole point), and every currently-active gateway row for that
    ///   segment is: (1) has its still-unrevoked `certificate` row(s) marked
    ///   `revoked_at = now` (pushing the serial onto the `revoked_serials`
    ///   denylist the Sync projection reads), and (2) is itself marked
    ///   `status = 'replaced'` so it stops counting as "active" for both a
    ///   future `SegmentAlreadyBound` check and the Sync full-mesh peer list.
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

        let token_row: Option<(String, String, String, Option<i64>)> = {
            let mut stmt = tx.prepare(
                "SELECT id, kind, bound_cidrs, rebind_segment_id FROM enrollment_token \
                 WHERE secret_hash = ?1 AND used_at IS NULL AND expires_at > ?2 \
                 AND kind IN ('gateway', 'rebind')",
            )?;
            let mut rows = stmt.query(params![secret_hash, now])?;
            match rows.next()? {
                // bound_cidrs is NULL-able in the schema; treat NULL as "" so
                // the T4 decode contract (""→[]) applies uniformly.
                Some(row) => Some((
                    row.get(0)?,
                    row.get(1)?,
                    row.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    row.get(3)?,
                )),
                None => None,
            }
        };

        let Some((token_id, kind, bound_cidrs_raw, rebind_segment_id)) = token_row else {
            tx.rollback()?;
            return Err(EnrollError::InvalidToken);
        };
        let is_rebind = kind == "rebind";

        // Authorization scope: a `gateway` token's declared `cidrs` must
        // match the CIDR set it was minted bound to (MintToken stored them,
        // comma-joined, in `bound_cidrs`, decoded via the canonical T4
        // decoder: ""→[]). Comparison is set-based over parsed `Ipv4Net`
        // values so it's order- and formatting-insensitive but still exact
        // (no subnet-of slack). Checked BEFORE marking the token used, and a
        // mismatch rolls the transaction back, so a rejected enroll does NOT
        // consume the single-use token — same discipline as
        // `NoMatchingSegment`.
        //
        // A `rebind` token carries no bound_cidrs at all (its scope is the
        // segment id, checked further down once `segment_id` is resolved) —
        // this block is entirely skipped for it.
        if !is_rebind {
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
        }

        // Resolve the segment that owns EVERY declared cidr — all of them
        // must belong to the same, already-registered segment (cycle-2
        // scope: the segment pre-exists).
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

        // Per-kind scope/occupancy check, now that the target segment is
        // known:
        let mut revoked_issuer_handles: Vec<String> = Vec::new();
        if is_rebind {
            // A rebind token is only authorized for the ONE segment it was
            // minted bound to — declaring a DIFFERENT (even if real,
            // registered) segment's cidrs must not let it claim that
            // segment instead. This is what stops a rebind token for
            // segment A from being redeemed against segment B.
            if rebind_segment_id != Some(segment_id) {
                tx.rollback()?;
                return Err(EnrollError::BoundCidrMismatch);
            }

            // Replace every currently-active gateway on this segment:
            // revoke its still-unrevoked cert(s) and mark it no longer
            // active. Ordinarily there is exactly one (the
            // one-gateway-per-segment invariant an ordinary `gateway` token
            // enforces below) — this loops defensively rather than
            // assuming exactly one row.
            let old_gateway_ids: Vec<i64> = {
                let mut stmt = tx.prepare(
                    "SELECT id FROM gateway WHERE segment_id = ?1 AND status = 'active'",
                )?;
                let rows = stmt.query_map(params![segment_id], |row| row.get::<_, i64>(0))?;
                rows.collect::<rusqlite::Result<Vec<_>>>()?
            };
            for old_gateway_id in old_gateway_ids {
                let certs_to_revoke: Vec<(String, String)> = {
                    let mut stmt = tx.prepare(
                        "SELECT serial, issuer_handle FROM certificate \
                         WHERE subject_kind = 'gateway' AND subject_id = ?1 AND revoked_at IS NULL",
                    )?;
                    let rows = stmt.query_map(params![old_gateway_id], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                    rows
                };
                for (serial, handle) in certs_to_revoke {
                    tx.execute(
                        "UPDATE certificate SET revoked_at = ?1 WHERE serial = ?2",
                        params![now, serial],
                    )?;
                    revoked_issuer_handles.push(handle);
                }
                tx.execute(
                    "UPDATE gateway SET status = 'replaced' WHERE id = ?1",
                    params![old_gateway_id],
                )?;
            }
        } else {
            // Ordinary `gateway` token: the resolved segment must not
            // already have an active gateway (one-gateway-per-segment) — an
            // explicit `rebind` token is the only sanctioned way to replace
            // one.
            let occupied: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM gateway WHERE segment_id = ?1 AND status = 'active')",
                params![segment_id],
                |row| row.get(0),
            )?;
            if occupied {
                tx.rollback()?;
                return Err(EnrollError::SegmentAlreadyBound);
            }
        }

        // (Task 15) A fresh random observe_key for this gateway's UDP
        // observation probes — generated here (not by the caller) since it's
        // pure DB-row bookkeeping with no crypto dependency, mirroring how
        // `rotate_key`'s placeholder pubkey is generated inline too.
        let observe_key = generate_observe_key();

        tx.execute(
            "INSERT INTO gateway (segment_id, name, status, backend, last_seen, observe_key) \
             VALUES (?1, ?2, 'active', 'wireguard', NULL, ?3)",
            params![segment_id, gateway_name, observe_key],
        )?;
        let gateway_id = tx.last_insert_rowid();

        tx.execute(
            "INSERT INTO certificate (serial, subject_kind, subject_id, issuer_handle, not_after) \
             VALUES (?1, 'gateway', ?2, ?3, ?4)",
            params![cert_serial, gateway_id, issuer_handle, cert_not_after],
        )?;

        // (Task 11) Bookkeeping baseline: every enrolled gateway gets an
        // epoch-0 `active` GATEWAY_KEY row so a later `RotateKey` always has
        // something to rotate FROM. The pubkey here is a placeholder, NOT a
        // real WireGuard public key — cycle-2 is bookkeeping only (no real
        // WireGuard/data-plane; see the module doc comment and the Task 11
        // brief). A real gateway-generated pubkey lands in cycle 4.
        tx.execute(
            "INSERT INTO gateway_key (gateway_id, epoch, pubkey, state) VALUES (?1, 0, ?2, 'active')",
            params![gateway_id, format!("placeholder-pubkey-gw{gateway_id}-epoch0")],
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
                if is_rebind { "rebind" } else { "enroll" },
                format!("gateway/{gateway_name}"),
                format!(r#"{{"segment_id":{segment_id},"gateway_id":{gateway_id}}}"#),
            ],
        )?;

        // Projection-affecting mutation: a newly enrolled gateway becomes a
        // peer in every other gateway's full-mesh snapshot (and a rebind
        // additionally changes the revoked-serials denylist), so bump the
        // persisted revision in this same transaction. Any early return above
        // rolls back without reaching here, so a rejected enroll doesn't
        // advance the revision.
        bump_revision_tx(&tx)?;

        tx.commit()?;
        Ok(EnrollOutcome {
            segment_id,
            gateway_id,
            revoked_issuer_handles,
            observe_key,
        })
    }

    /// The other N-1 *active* enrolled gateways (every `status = 'active'`
    /// `gateway` row except `exclude_gateway_id`), each with the segment it
    /// belongs to. Used by `routes::peers_of` to build the full-mesh peer
    /// set for a Sync snapshot. Ordered by id for deterministic output.
    ///
    /// Excludes `status = 'replaced'` rows (Task 10's rebind: the gateway a
    /// rebind superseded) so a superseded gateway — whose cert is already on
    /// the `revoked_serials` denylist — stops appearing as a mesh peer too,
    /// rather than lingering as a dead entry every other gateway keeps
    /// trying to route to.
    pub fn list_other_gateways(&self, exclude_gateway_id: i64) -> Result<Vec<GatewayRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT g.id, g.segment_id, s.name, g.candidate_endpoint \
             FROM gateway g JOIN segment s ON s.id = g.segment_id \
             WHERE g.id != ?1 AND g.status = 'active' \
             ORDER BY g.id",
        )?;
        let rows = stmt
            .query_map(params![exclude_gateway_id], |row| {
                Ok(GatewayRow {
                    id: row.get(0)?,
                    segment_id: row.get(1)?,
                    segment_name: row.get(2)?,
                    candidate_endpoint: row.get(3)?,
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
    /// `(epoch, pubkey, state)`. Not currently called by the Sync projection
    /// (see [`Db::all_keys_for_gateway`], which [`crate::routes::peers_of`]
    /// uses instead so a peer's `pending`/`retiring` epochs are visible
    /// too) — kept as a narrower query for any future caller that only
    /// wants the currently-in-use key.
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

    /// ALL `gateway_key` rows (any state — `pending`, `active`, `retiring`)
    /// for `gateway_id`, as `(epoch, pubkey, state)`. (Task 11) This is what
    /// [`crate::routes::peers_of`] now reads for a peer's `keys` in the Sync
    /// projection: a peer must see a gateway's mid-rotation `pending` epoch
    /// too, not just its currently-`active` one, so an already-connected
    /// Sync.Watch stream's Delta reflects the same state a fresh snapshot
    /// would. Also backs the Admin `DebugKeyStates` RPC / testkit's
    /// `debug_key_states` accessor — a debug-only view into the rotation
    /// state machine.
    pub fn all_keys_for_gateway(&self, gateway_id: i64) -> Result<Vec<GatewayKeyRow>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT epoch, pubkey, state FROM gateway_key \
             WHERE gateway_id = ?1 \
             ORDER BY epoch",
        )?;
        let rows = stmt
            .query_map(params![gateway_id], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// (Task 11) Starts a make-before-break key-epoch rotation for
    /// `gateway_id`: finds the gateway's current highest `gateway_key`
    /// epoch (every enrolled gateway has at least an epoch-0 `active` row —
    /// see `enroll_gateway`'s bookkeeping baseline — but this defensively
    /// tolerates a gap/legacy row set by falling back to epoch 0 if none
    /// exists yet), inserts a NEW row at `epoch = max + 1` with
    /// `state = 'pending'` and a placeholder pubkey (a real gateway-supplied
    /// pubkey is cycle 4's scope — see the module doc comment), appends an
    /// audit entry, and bumps the persisted revision — all in ONE
    /// transaction, so a caller observing success can rely on every side
    /// effect (including the revision bump the Sync projection depends on)
    /// having landed together, and a crash mid-rotation can't leave a
    /// pending epoch un-audited or un-revisioned.
    ///
    /// Full make-before-break completion (an ack from the gateway advancing
    /// `n+1` to `active` and `n` to `retiring`, then removing `n`) is NOT
    /// implemented here — this is cycle-2's bookkeeping slice: "pending
    /// epoch created, persisted, and delta'd to peers." See the Task 11
    /// brief/report for what's deferred to cycle 4's real WireGuard
    /// handshake-driven ack path.
    pub fn rotate_key(&self, gateway_id: i64, now: &str) -> Result<RotateKeyOutcome> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM gateway WHERE id = ?1)",
            params![gateway_id],
            |row| row.get(0),
        )?;
        if !exists {
            tx.rollback()?;
            anyhow::bail!("RotateKey: no gateway row with id {gateway_id} to rotate a key for");
        }

        let max_epoch: Option<i64> = tx.query_row(
            "SELECT MAX(epoch) FROM gateway_key WHERE gateway_id = ?1",
            params![gateway_id],
            |row| row.get(0),
        )?;
        let new_epoch = max_epoch.map(|e| e + 1).unwrap_or(0);
        let pubkey = format!("placeholder-pubkey-gw{gateway_id}-epoch{new_epoch}");

        tx.execute(
            "INSERT INTO gateway_key (gateway_id, epoch, pubkey, state) \
             VALUES (?1, ?2, ?3, 'pending')",
            params![gateway_id, new_epoch, pubkey],
        )?;

        tx.execute(
            "INSERT INTO audit_log (ts, actor, action, entity, diff_json) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                now,
                "unix-socket",
                "key-rotate",
                format!("gateway/{gateway_id}"),
                format!(r#"{{"epoch":{new_epoch}}}"#),
            ],
        )?;

        // Projection-affecting mutation: a new pending epoch changes what
        // this gateway's peers see in their `keys` list, so bump the
        // persisted revision in this same transaction (see `bump_revision_tx`'s
        // doc comment). The early `tx.rollback()` above never reaches here.
        bump_revision_tx(&tx)?;

        tx.commit()?;
        Ok(RotateKeyOutcome { epoch: new_epoch, pubkey })
    }

    /// (Task 12, G-7) Drains `gateway_id`: revokes every still-unrevoked
    /// `certificate` row of its (`revoked_at = now`), marks its `gateway` row
    /// `status = 'removed'` (dropping it out of
    /// [`Db::list_other_gateways`]'s `status = 'active'` filter — the same
    /// mechanism `enroll_gateway`'s rebind path uses for a `'replaced'`
    /// gateway — rather than deleting the row outright, which would require
    /// also cascading the delete through `gateway_key`/`certificate`/
    /// `policy_status` under `foreign_keys = ON`), appends an audit entry,
    /// and bumps the persisted revision — ALL in one transaction, so a
    /// caller observing success can rely on every side effect having landed
    /// together.
    ///
    /// Cycle-2 doesn't track real per-peer withdrawal acks (see the Task 12
    /// brief/report for what's deferred): this method does the atomic
    /// "mark removed + revoke" mutation the caller (`AdminSvc::drain`)
    /// publishes a `GatewayDrained` `ChangeEvent` from immediately after —
    /// the "ack-wait (or 5s)" the master-spec describes is a bounded, best-
    /// effort window in the RPC handler, not gating this DB mutation.
    ///
    /// Errors (rather than silently no-op'ing) if no `gateway` row with this
    /// id exists at all, so `AdminSvc::drain` can map that to `NotFound`.
    /// Draining an already-`removed` gateway is NOT an error — it's treated
    /// as idempotent (only still-unrevoked certs get touched, so a second
    /// call revokes nothing further and returns an empty `revoked_serials`)
    /// rather than surfacing a confusing "no such gateway" for a gateway
    /// that unambiguously did exist a moment ago.
    pub fn drain_gateway(&self, gateway_id: i64, now: &str) -> Result<DrainOutcome> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM gateway WHERE id = ?1)",
            params![gateway_id],
            |row| row.get(0),
        )?;
        if !exists {
            tx.rollback()?;
            anyhow::bail!("Drain: no gateway row with id {gateway_id} to drain");
        }

        let certs_to_revoke: Vec<String> = {
            let mut stmt = tx.prepare(
                "SELECT serial FROM certificate \
                 WHERE subject_kind = 'gateway' AND subject_id = ?1 AND revoked_at IS NULL",
            )?;
            let rows = stmt.query_map(params![gateway_id], |row| row.get::<_, String>(0))?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        for serial in &certs_to_revoke {
            tx.execute(
                "UPDATE certificate SET revoked_at = ?1 WHERE serial = ?2",
                params![now, serial],
            )?;
        }

        tx.execute(
            "UPDATE gateway SET status = 'removed' WHERE id = ?1",
            params![gateway_id],
        )?;

        tx.execute(
            "INSERT INTO audit_log (ts, actor, action, entity, diff_json) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                now,
                "unix-socket",
                "drain",
                format!("gateway/{gateway_id}"),
                format!(r#"{{"gateway_id":{gateway_id},"revoked_serials":{certs_to_revoke:?}}}"#),
            ],
        )?;

        // Projection-affecting mutation: the drained gateway must vanish
        // from every peer's full-mesh view and its cert(s) must join the
        // revoked-serials denylist, so bump the persisted revision in this
        // same transaction (see `bump_revision_tx`'s doc comment). The early
        // `tx.rollback()` above never reaches here.
        bump_revision_tx(&tx)?;

        tx.commit()?;
        Ok(DrainOutcome {
            revoked_serials: certs_to_revoke,
        })
    }

    /// (Task 16) Revokes a single `certificate` row by `serial`: stamps
    /// `revoked_at = now` (idempotent — a serial that's already revoked
    /// keeps its ORIGINAL `revoked_at`, and the `UPDATE ... WHERE revoked_at
    /// IS NULL` guard below simply touches zero rows the second time), audits
    /// it (`action = "revoke"`, `entity = certificate/<serial>`), and bumps
    /// the persisted revision — all in ONE transaction, mirroring
    /// [`Db::drain_gateway`]'s "mutate + audit + bump" shape.
    ///
    /// Returns `false` (rather than erroring) if no `certificate` row with
    /// this serial exists at all, so `AdminSvc::revoke_cert` can map that to
    /// `NotFound` — no mutation, no audit row, no revision bump in that case.
    pub fn revoke_cert(&self, serial: &str, now: &str) -> Result<bool> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM certificate WHERE serial = ?1)",
            params![serial],
            |row| row.get(0),
        )?;
        if !exists {
            tx.rollback()?;
            return Ok(false);
        }

        tx.execute(
            "UPDATE certificate SET revoked_at = ?1 WHERE serial = ?2 AND revoked_at IS NULL",
            params![now, serial],
        )?;

        tx.execute(
            "INSERT INTO audit_log (ts, actor, action, entity, diff_json) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                now,
                "unix-socket",
                "revoke",
                format!("certificate/{serial}"),
                "{}",
            ],
        )?;

        // Projection-affecting mutation (the serial joins/stays in the
        // revoked-serials denylist), so bump the persisted revision in this
        // same transaction (see `bump_revision_tx`'s doc comment). The early
        // `tx.rollback()` above never reaches here.
        bump_revision_tx(&tx)?;

        tx.commit()?;
        Ok(true)
    }

    /// (Task 12 testkit accessor) `true` iff a `gateway` row with this id
    /// exists AND is currently `status = 'active'` — `false` both for an id
    /// that never existed and for one that's `'removed'` (drained) or
    /// `'replaced'` (superseded by a rebind). Backs
    /// `wiremesh-testkit::TestController::gateway_exists`.
    pub fn gateway_is_active(&self, gateway_id: i64) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let active: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM gateway WHERE id = ?1 AND status = 'active')",
            params![gateway_id],
            |row| row.get(0),
        )?;
        Ok(active)
    }

    /// Resolves an enrolled gateway by its DB `id` (the same shape
    /// [`Db::find_gateway_by_name`] returns, just keyed by id instead of
    /// name) — used after [`Db::rotate_key`] to re-read the segment identity
    /// needed to build the `ChangeEvent`/`Delta` the Admin `RotateKey` RPC
    /// publishes.
    pub fn gateway_identity_by_id(&self, gateway_id: i64) -> Result<Option<GatewayIdentity>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT g.id, g.segment_id, s.name \
             FROM gateway g JOIN segment s ON s.id = g.segment_id \
             WHERE g.id = ?1",
            params![gateway_id],
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

    /// (Task 13) Every registered segment with its CIDRs, ordered by id —
    /// backs `Admin.ListSegments` / `fabricctl segment list`.
    pub fn list_segments(&self) -> Result<Vec<(i64, String, Vec<String>)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id, name FROM segment ORDER BY id")?;
        let segments: Vec<(i64, String)> = stmt
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(stmt);

        let mut out = Vec::with_capacity(segments.len());
        for (id, name) in segments {
            let mut cstmt = conn.prepare("SELECT cidr FROM cidr WHERE segment_id = ?1 ORDER BY cidr")?;
            let cidrs = cstmt
                .query_map(params![id], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            out.push((id, name, cidrs));
        }
        Ok(out)
    }

    /// (Task 13) Deletes a segment and its `cidr` rows in one transaction.
    /// Refuses (returns `Err`, message contains `"has associated gateway"`
    /// so `AdminSvc::delete_segment` can map it to `FailedPrecondition`) if
    /// any `gateway` row (any status — a foreign key would otherwise block
    /// this at the DB level anyway) still references `segment_id`: an
    /// operator must drain/replace those first. Also errors (message
    /// contains `"no segment row"`, mapped to `NotFound`) if the id doesn't
    /// exist.
    pub fn delete_segment(&self, segment_id: i64) -> Result<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM segment WHERE id = ?1)",
            params![segment_id],
            |row| row.get(0),
        )?;
        if !exists {
            tx.rollback()?;
            anyhow::bail!("DeleteSegment: no segment row with id {segment_id}");
        }

        let has_gateway: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM gateway WHERE segment_id = ?1)",
            params![segment_id],
            |row| row.get(0),
        )?;
        if has_gateway {
            tx.rollback()?;
            anyhow::bail!(
                "DeleteSegment: segment {segment_id} has associated gateway row(s); \
                 drain them before deleting the segment"
            );
        }

        tx.execute("DELETE FROM cidr WHERE segment_id = ?1", params![segment_id])?;
        tx.execute("DELETE FROM segment WHERE id = ?1", params![segment_id])?;

        bump_revision_tx(&tx)?;
        tx.commit()?;
        Ok(())
    }

    /// (Task 13) Inserts a new `relay` row (`status = 'active'`, unseen
    /// yet). Returns the new relay's id. A duplicate `name` surfaces as a
    /// `rusqlite::Error` (UNIQUE constraint) — `AdminSvc::register_relay`
    /// maps that to `AlreadyExists`, mirroring `insert_segment`'s pattern.
    pub fn insert_relay(&self, name: &str, endpoint: &str) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO relay (name, endpoint, status, last_seen) VALUES (?1, ?2, 'active', NULL)",
            params![name, endpoint],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// (Task 13) Every registered relay, ordered by id.
    pub fn list_relays(&self) -> Result<Vec<(i64, String, String, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt =
            conn.prepare("SELECT id, name, endpoint, status FROM relay ORDER BY id")?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// (Task 13) Inserts a new `api_token` row. `secret_hash` is the sha256
    /// (hex) of the token's random secret — same never-store-the-raw-secret
    /// discipline as [`Db::insert_enrollment_token`]. `role` is stored
    /// verbatim (`"admin"` or `"read-only"`; validated by the gRPC layer
    /// before this call). `expires_at` is `None` for cycle-2's API
    /// tokens — no TTL/renewal path yet (mirrors how `RevokeApiToken` is the
    /// only way to invalidate one early).
    pub fn insert_api_token(
        &self,
        id: &str,
        name: &str,
        role: &str,
        secret_hash: &str,
        expires_at: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO api_token (id, name, role, secret_hash, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, name, role, secret_hash, expires_at],
        )?;
        Ok(())
    }

    /// (Task 13) Marks the `api_token` row named `name` revoked (`revoked_at
    /// = now`). Returns `false` (rather than erroring) if no such row
    /// exists — `AdminSvc::revoke_api_token` maps that to `NotFound`.
    /// Idempotent: revoking an already-revoked token just re-stamps
    /// `revoked_at` and still returns `true`.
    pub fn revoke_api_token(&self, name: &str, now: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let updated = conn.execute(
            "UPDATE api_token SET revoked_at = ?1 WHERE name = ?2",
            params![now, name],
        )?;
        Ok(updated > 0)
    }

    /// (Task 13) The `role` of the unrevoked, unexpired `api_token` row
    /// whose `secret_hash` matches, if any — the sole lookup the bearer-auth
    /// middleware (`crate::auth`) performs per TCP Admin request. `None`
    /// covers "no such token", "revoked", and "expired" uniformly (same
    /// non-disclosure posture as `EnrollError::InvalidToken`: a caller can't
    /// distinguish which).
    pub fn find_active_api_token_role(&self, secret_hash: &str, now: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT role FROM api_token \
             WHERE secret_hash = ?1 AND revoked_at IS NULL \
             AND (expires_at IS NULL OR expires_at > ?2)",
            params![secret_hash, now],
            |row| row.get(0),
        )
        .optional()
        .map_err(Into::into)
    }

    /// (Task 13; Task 16 adds `action`/`actor`/`entity` filters) Most-recent-
    /// first `audit_log` rows, up to `limit` (clamped to at least 1) — backs
    /// `Admin.AuditQuery` / `fabricctl audit query`/`audit export`.
    ///
    /// Each of `action`/`actor`/`entity` is an optional EXACT-match filter:
    /// `None` (or, at the RPC layer, an empty string — see
    /// `AdminSvc::audit_query`) means "don't filter on this column"; every
    /// filter that IS supplied is ANDed together. Exact match (rather than a
    /// `LIKE`/substring match) is deliberate: `action` values are a small
    /// fixed vocabulary ("create"/"mint"/"revoke"/"drain"/...), so exact
    /// match is unambiguous and lets a caller filter precisely (e.g.
    /// `action = "revoke"` — see `tests/revoke_audit.rs`) without a wildcard
    /// character convention this cycle doesn't otherwise need.
    pub fn audit_query(
        &self,
        limit: i64,
        action: Option<&str>,
        actor: Option<&str>,
        entity: Option<&str>,
    ) -> Result<Vec<(i64, String, String, String, String, String)>> {
        let conn = self.conn.lock().unwrap();
        let limit = limit.max(1);

        let mut sql = String::from(
            "SELECT id, ts, actor, action, entity, diff_json FROM audit_log WHERE 1=1",
        );
        // Boxed so `action`/`actor`/`entity` (each borrowed `&str`, live only
        // for this call) and `limit` (an owned `i64`) can share one
        // dynamically-built parameter list.
        let mut bound: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if let Some(a) = action {
            sql.push_str(" AND action = ?");
            bound.push(Box::new(a.to_string()));
        }
        if let Some(a) = actor {
            sql.push_str(" AND actor = ?");
            bound.push(Box::new(a.to_string()));
        }
        if let Some(e) = entity {
            sql.push_str(" AND entity = ?");
            bound.push(Box::new(e.to_string()));
        }
        sql.push_str(" ORDER BY id DESC LIMIT ?");
        bound.push(Box::new(limit));

        let mut stmt = conn.prepare(&sql)?;
        let params_refs: Vec<&dyn rusqlite::ToSql> = bound.iter().map(|b| b.as_ref()).collect();
        let rows = stmt
            .query_map(params_refs.as_slice(), |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// (Task 13) Every `gateway` row (any status) with the segment name it
    /// belongs to and its last-acked `applied_version` — backs
    /// `Admin.ListGateways`, making T8's `Sync.Report` bookkeeping
    /// (`Db::set_applied_version`) observable from the Admin surface for the
    /// first time. Ordered by id.
    pub fn list_gateways(&self) -> Result<Vec<(i64, String, String, String, Option<i64>)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT g.id, g.name, s.name, g.status, g.applied_version \
             FROM gateway g JOIN segment s ON s.id = g.segment_id \
             ORDER BY g.id",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
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

    /// (Task 15) The `observe_key` issued to `gateway_id` at enrollment, if
    /// it currently exists AND is `status = 'active'` — `None` for an
    /// unknown gateway_id and for one that's been drained/replaced, so a
    /// probe claiming a stale/superseded identity can never authenticate
    /// (mirrors `gateway_is_active`'s active-only posture). This is the
    /// controller's UDP observation endpoint's sole lookup for verifying a
    /// probe's MAC — see `crate::observe`.
    pub fn gateway_observe_key(&self, gateway_id: i64) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT observe_key FROM gateway WHERE id = ?1 AND status = 'active'",
            params![gateway_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()
        .map(|opt| opt.flatten())
        .map_err(Into::into)
    }

    /// (Task 15) Records `addr` (a UDP `ip:port` string, as observed on the
    /// wire by `crate::observe`) as `gateway_id`'s candidate endpoint —
    /// last-observed-wins (cycle-2 keeps exactly one candidate per gateway;
    /// see `crate::projection::build_snapshot`/`crate::routes::peers_of` for
    /// how it's surfaced to peers). Only touches an ACTIVE gateway row (same
    /// posture as `gateway_observe_key`) — errors if `gateway_id` doesn't
    /// currently resolve to one, so the caller (which already verified the
    /// probe's MAC against an active gateway's key moments earlier) can treat
    /// that as an internal inconsistency rather than silently no-op'ing.
    /// Bumps the persisted revision in the same transaction, since this
    /// changes what every OTHER gateway's projection shows. Returns the new
    /// revision.
    pub fn set_candidate_endpoint(&self, gateway_id: i64, addr: &str) -> Result<u64> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        let updated = tx.execute(
            "UPDATE gateway SET candidate_endpoint = ?1 WHERE id = ?2 AND status = 'active'",
            params![addr, gateway_id],
        )?;
        if updated != 1 {
            tx.rollback()?;
            anyhow::bail!(
                "set_candidate_endpoint: no active gateway row with id {gateway_id}"
            );
        }

        let revision = bump_revision_tx(&tx)?;
        tx.commit()?;
        Ok(revision)
    }
}
