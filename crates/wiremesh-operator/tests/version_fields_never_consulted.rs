//! (B10 / X-6) In Phase B the four version fields are **stored and never
//! consulted**. This is the guard that keeps it that way.
//!
//! `client_version`, `max_ir_schema`, `controller_version` and
//! `min_supported_version` are populated, put on the wire, and written to the
//! DB — and **nothing branches on them**. Reading one to gate a Watch, flag a
//! laggard, colour `fabricctl gateway list`, or refuse an apply is Phase C
//! (X-6), deliberately not v1.0. The failure mode this prevents is the quiet
//! one: a gate arrives in an unrelated PR, every functional test still passes
//! because the values are well-formed, and a fabric refuses to serve a
//! perfectly healthy pre-1.0 gateway.
//!
//! # Why the allowlist is HARDCODED, when this directory's other guard is not
//!
//! `release_version_stamping.rs` argues at length that its sets must be
//! DERIVED and never hardcoded, because a second copy of a discoverable fact
//! drifts from the first — and that is right *there*, where the truth lives in
//! workflows, the Dockerfile and the manifests.
//!
//! It does not apply here, and the difference is worth stating because a
//! reader who knows that file will otherwise flag this as the same
//! anti-pattern. **"Which occurrences are legitimate" is a human judgement
//! recorded nowhere else in the repo.** There is no source of truth to derive
//! from; a derived version would be "the sites that exist", which is vacuously
//! true of any tree and would never fail. The hardcoded list IS the tripwire.
//!
//! # This guard is STRICTER than the property it protects
//!
//! The property is "nothing branches on these fields". A text scan cannot see
//! branching, so this reds on ANY occurrence outside the allowlist — including
//! a harmless read. That is deliberate for a tripwire, and it is why the
//! failure message below distinguishes the two cases rather than accusing the
//! author of adding a gate.
//!
//! # In-module tests are OUT OF SCOPE, by construction
//!
//! The scan stops at each `src/` file's first `#[cfg(test)]` marker — the same
//! N4 marker that divides implementer-owned code from test-writer-owned code
//! everywhere else in this repo.
//!
//! This is not a convenience. The property is *"no production code branches on
//! these fields"*, and a test that names one is not production code: it is
//! usually a struct literal that MUST name every field, because the proto
//! additions are additive and Rust has no partial initialisation. Those fills
//! are mechanical and unavoidable, they arrive with every future field, and
//! allowlisting them would mean an entry per test fixture — a list that grows
//! without bound, that nobody can audit, and that would eventually be deleted
//! wholesale for being noise. Excluding the block keeps the allowlist small
//! enough to read, which is the only property that makes it a tripwire.
//!
//! What this gives up: a GATE written inside an in-module test would not be
//! caught. That is acceptable — a gate in a `#[cfg(test)]` block does not ship.
//!
//! # Known limits, stated so nobody mistakes this for proof
//!
//! It is a source-text scan. It catches the realistic regression (someone
//! writes `if info.max_ir_schema < N`) and not an obfuscated one (the
//! identifier reached through a macro, a re-export under another name, or
//! `concat!`). Comment lines are stripped, so documenting the rule — which the
//! proto files and `wiremesh-enroll` already do at length — cannot trip it.

use std::collections::BTreeSet;
use std::path::Path;

/// The four fields, exactly as spelled in Rust.
const FIELDS: &[&str] = &[
    "client_version",
    "max_ir_schema",
    "controller_version",
    "min_supported_version",
];

/// Crate source roots in scope. `fabricctl` is here with ZERO expected
/// occurrences: §5.1 defers the `gateway list` flag to Phase C, and the
/// gateway-list command is inline in its `main.rs` rather than a `list`
/// function, so "no occurrences anywhere in the crate" is the assertion — not
/// "no occurrences in some file I happened to look at".
const SCOPE: &[&str] = &[
    "crates/wiremesh-controller/src",
    "crates/wiremesh-gateway/src",
    "crates/wiremesh-relay/src",
    "crates/fabricctl/src",
];

/// Every `(path, enclosing item)` where one of [`FIELDS`] may legitimately
/// appear: the sites that POPULATE, THREAD or STORE the values.
///
/// MEASURED at 13 sites / 28 occurrences after wire-dev's population commit,
/// by running this file's own scanner over the tree — not copied from a
/// prediction (the estimate beforehand was 11, and the difference is real:
/// `main`'s boot log, `version.rs` itself, and the split of the writer across
/// `db.rs`/`db_async.rs` were not in it).
///
/// Note what is NOT here: the two `run_enroll` call sites. They pass the
/// value POSITIONALLY into `wiremesh_enroll::enroll`, so they never name the
/// identifier and this scan cannot see them. That is a known limit, not an
/// omission — a site that BRANCHES on one of these fields has to name it.
///
/// **To whoever a red run sends here:** adding an entry is correct if your site
/// populates, threads or stores. It is NOT correct if your site READS one to
/// decide something — that is the Phase-C gate this guard exists to catch, and
/// the answer is to defer it, not to widen the list.
const ALLOWED: &[(&str, &str)] = &[
    // -- schema -----------------------------------------------------------
    ("crates/wiremesh-controller/src/db.rs", "SCHEMA_V4"),
    // -- storage: the write path and its normalisation ---------------------
    (
        "crates/wiremesh-controller/src/db.rs",
        "set_gateway_reported_version",
    ),
    (
        "crates/wiremesh-controller/src/db_async.rs",
        "set_gateway_reported_version",
    ),
    ("crates/wiremesh-controller/src/services/sync.rs", "watch"),
    (
        "crates/wiremesh-controller/src/services/enrollment.rs",
        "enroll",
    ),
    // -- read-and-surface: no flagging, no filtering, no colouring ---------
    ("crates/wiremesh-controller/src/db.rs", "list_gateways"),
    (
        "crates/wiremesh-controller/src/services/admin.rs",
        "list_gateways",
    ),
    // -- the controller's own pair, stamped onto both snapshot builders ----
    (
        "crates/wiremesh-controller/src/projection.rs",
        "build_snapshot",
    ),
    (
        "crates/wiremesh-controller/src/projection.rs",
        "build_relay_revocation_snapshot",
    ),
    (
        "crates/wiremesh-controller/src/version.rs",
        "min_supported_version",
    ),
    ("crates/wiremesh-controller/src/main.rs", "main"),
    // -- clients populating their own values --------------------------------
    ("crates/wiremesh-gateway/src/sync.rs", "watch"),
    ("crates/wiremesh-relay/src/lib.rs", "run_sync"),
];

/// Repo root, by the SAME mechanism `release_version_stamping.rs` and
/// `crd_manifest_freshness.rs` use — one way to find the root across all three,
/// so none of them can drift from the others.
const REPO_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

/// Every `(relative path, enclosing item, line)` in scope mentioning a field,
/// with comment lines stripped.
fn occurrences(root: &Path) -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    for dir in SCOPE {
        let base = root.join(dir);
        let mut stack = vec![base.clone()];
        let mut files = Vec::new();
        while let Some(d) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&d) else {
                continue;
            };
            for e in entries.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    files.push(p);
                }
            }
        }
        files.sort();
        for f in files {
            let rel = f
                .strip_prefix(root)
                .expect("scanned file is under the repo root")
                .to_string_lossy()
                .replace('\\', "/");
            let text = std::fs::read_to_string(&f).expect("reading a source file");
            let mut item = "<module scope>".to_string();
            let mut attr_depth = 0i32;
            for line in text.lines() {
                let trimmed = line.trim_start();
                // STOP at the file's first `#[cfg(test)]`. Everything below it
                // is the in-module test block, which is out of scope BY
                // CONSTRUCTION — see the header. Not `continue`: a marker means
                // the rest of the file is tests, so there is nothing further to
                // scan.
                if trimmed.starts_with("#[cfg(test)]") {
                    break;
                }
                // Comment-stripped: documenting the rule must not trip it, and
                // the proto/enroll sources document it at length.
                if trimmed.starts_with("//") {
                    continue;
                }
                // Attribute bodies are skipped for the SAME reason, and it is
                // not a convenience: a `reason = "..."` string inside an
                // `#[expect(...)]` is prose that cannot branch on anything, so
                // it is documentation in every sense that matters here. Two
                // such strings exist today — `db.rs`'s and `db_async.rs`'s
                // `#[expect(clippy::type_complexity)]` both spell out the
                // 7-tuple row including `max_ir_schema`.
                //
                // Skipping them also avoids MIS-ATTRIBUTION, which is the
                // sharper reason. Attributes precede the item they annotate,
                // so a nearest-preceding-`fn` scan credits them to the item
                // ABOVE — those two land on `audit_query` and `revoke_cert`,
                // which touch neither field. An allowlist entry naming them
                // would be a lie a later reader could not audit.
                if attr_depth == 0 && (trimmed.starts_with("#[") || trimmed.starts_with("#![")) {
                    attr_depth = 1;
                }
                if attr_depth > 0 {
                    attr_depth += line.matches('[').count() as i32
                        - line.matches(']').count() as i32
                        - if trimmed.starts_with("#[") || trimmed.starts_with("#![") {
                            1
                        } else {
                            0
                        };
                    if attr_depth <= 0 {
                        attr_depth = 0;
                    }
                    continue;
                }
                if let Some(name) = item_name(trimmed) {
                    item = name;
                }
                if FIELDS.iter().any(|f| line.contains(f)) {
                    out.push((rel.clone(), item.clone(), line.trim().to_string()));
                }
            }
        }
    }
    out
}

/// The name of the `fn`/`const`/`static` a line declares, if it declares one.
///
/// Visibility is stripped first: `pub`, `pub(crate)`, `pub(super)` and
/// `pub(in path)` all precede the keyword, and missing one would attribute an
/// occurrence to the PREVIOUS item — which would either hide a real site under
/// an allowlisted neighbour or report a legitimate one under the wrong name.
fn item_name(trimmed: &str) -> Option<String> {
    let mut rest = trimmed;
    if let Some(after) = rest.strip_prefix("pub") {
        rest = match after.strip_prefix('(') {
            // `pub(crate)`, `pub(super)`, `pub(in some::path)`
            Some(vis) => vis.split_once(')')?.1,
            None => after,
        }
        .trim_start();
    }
    let rest = rest.strip_prefix("async ").unwrap_or(rest);
    for kw in ["fn ", "const ", "static "] {
        if let Some(after) = rest.strip_prefix(kw) {
            let name: String = after
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                return Some(name);
            }
        }
    }
    None
}

#[test]
fn no_code_outside_the_allowlist_touches_the_version_fields() {
    let root = Path::new(REPO_ROOT);
    let allowed: BTreeSet<(String, String)> = ALLOWED
        .iter()
        .map(|(f, i)| ((*f).to_string(), (*i).to_string()))
        .collect();

    let unexpected: Vec<_> = occurrences(root)
        .into_iter()
        .filter(|(f, i, _)| !allowed.contains(&(f.clone(), i.clone())))
        .collect();

    if unexpected.is_empty() {
        return;
    }

    let mut msg = String::from(
        "code outside the allowlist mentions a B10 version field.\n\n\
         In Phase B these four fields are STORED AND NEVER CONSULTED. Two cases, and they \
         need different answers:\n\n\
           * a new site that POPULATES, THREADS or STORES a value — legitimate; add it to \
             ALLOWED in this file, by (path, enclosing item);\n\
           * a site that READS one to DECIDE something — a Watch-open gate, an apply-time \
             laggard check, a `fabricctl gateway list` flag, a log line that branches — that \
             is Phase C (X-6) and must not ship in v1.0. Defer it; do not widen the list.\n\n\
         This guard is stricter than the property: it cannot see branching, so it reds on any \
         occurrence at all.\n\nUnexpected sites:\n",
    );
    for (f, i, line) in &unexpected {
        msg.push_str(&format!("  {f}::{i}\n      {line}\n"));
    }
    panic!("{msg}");
}

/// The allowlist must not rot into a list of places that no longer exist.
///
/// A stale entry is not harmless: it silently re-permits a site if code ever
/// returns to that `(file, item)` under a different purpose — which is exactly
/// how an allowlist stops being a tripwire.
#[test]
fn every_allowlist_entry_still_names_a_real_occurrence() {
    let root = Path::new(REPO_ROOT);
    let seen: BTreeSet<(String, String)> = occurrences(root)
        .into_iter()
        .map(|(f, i, _)| (f, i))
        .collect();
    let stale: Vec<_> = ALLOWED
        .iter()
        .filter(|(f, i)| !seen.contains(&((*f).to_string(), (*i).to_string())))
        .collect();
    assert!(
        stale.is_empty(),
        "these allowlist entries no longer match any occurrence: {stale:?}. Remove them. A \
         stale entry silently re-permits its (file, item) if code ever returns there for an \
         unrelated reason, which is how an allowlist quietly stops being a tripwire"
    );
}
