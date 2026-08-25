//! The two committed CRD bundles must be byte-identical to what `crdgen`
//! renders RIGHT NOW.
//!
//! # Why this test exists
//!
//! `crdgen` prints to stdout and nothing else: no `build.rs`, no CI step, no
//! Makefile. Both YAML bundles are hand-mirrored, so keeping them current has
//! always been a thing someone had to remember. Someone didn't — commit
//! `c7a4814` regenerated `deploy/operator/crds/` and left the Helm copy behind,
//! dropping four properties (`observeEndpoint`, `syncEndpoint` on
//! `WiremeshGateway`; `storageClass`, `storageSize` on `WiremeshRelay`).
//!
//! The failure that causes is SILENT. A CRD schema is structural with no
//! `x-kubernetes-preserve-unknown-fields`, so an apiserver PRUNES unknown spec
//! fields rather than rejecting them. On a cluster built by a first-time `helm
//! install`, `kubectl patch wiremeshgateways … observeEndpoint …` prints
//! `patched` and does nothing at all. That is the documented step 6.3 of
//! `docs/runbooks/controller-migration-to-fi.md`.
//!
//! # Why it calls `render_crd_yaml()` instead of rebuilding the string here
//!
//! This test asserts a property of what the BINARY emits. If it reimplemented
//! `bin/crdgen.rs`'s render loop, the two could drift and the test would go on
//! passing while the binary emitted something else — which is the exact class
//! of bug this test exists to prevent. So the binary and this test must share
//! one rendering function. `bin/crdgen.rs` is a one-line wrapper over
//! `render_crd_yaml()`; this calls the same function.
//!
//! Shelling out to `cargo run --bin crdgen` would also work in principle and is
//! deliberately NOT done: it is slow, and a test that invokes cargo while cargo
//! holds the build lock can deadlock.
//!
//! # Byte equality, on purpose
//!
//! The comparison is against the raw file contents with no trim, no YAML
//! re-parse, and no normalization. The failure mode being guarded is "someone
//! hand-edited the generated YAML"; every normalization step is a way for a
//! hand-edit to slip through.
//!
//! # Two assertions, not three
//!
//! There is deliberately no third "the two files equal each other" assertion.
//! If A == generated and B == generated then A == B by transitivity, and a
//! third check would only fire simultaneously with the other two and add noise
//! to the output.
//!
//! **But byte-identity between the two files is a CHOICE, not a law.** A Helm
//! chart may one day need chart-specific annotations on its CRDs — most likely
//! `helm.sh/resource-policy: keep`, which stops `helm uninstall` from deleting
//! CRDs and taking every CR with them. Neither file carries any such annotation
//! today (verified: the only difference between them is the four missing
//! properties above). If one ever does, the right change is to make the Helm
//! assertion a STRUCTURAL comparison — not to delete it.
//!
//! # Two pinned assumptions
//!
//! Both are load-bearing for byte equality, and both are currently true by
//! accident of how the code is written rather than by any enforcement:
//!
//! 1. **Document order** is deterministic only because `crd::all_crds()`
//!    returns an explicit `vec![Controller, Segment, Policy, Gateway, Relay]`.
//!    Refactoring it to iterate a `HashMap` would make this test flaky — a
//!    genuinely nondeterministic failure that looks like a bad test. The order
//!    itself is pinned by `crd::tests::crdgen_emits_five_cluster_scoped_crds`.
//! 2. **Property order within a document** is alphabetical only because
//!    `schemars` is built WITHOUT its `preserve_order` feature, so schema
//!    properties live in a `BTreeMap`. Enabling that feature switches them to
//!    struct-declaration order, at which point reordering two fields in a spec
//!    struct silently rewrites both YAML files.
//!
//! No cluster, no privilege, no netns — ordinary `cargo test -p
//! wiremesh-operator`.

use std::collections::BTreeMap;

/// The generated bundle committed for `kubectl apply` (and the copy
/// `docs/operator.md` points upgraders at).
const OPERATOR_CRDS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../deploy/operator/crds/wiremesh-crds.yaml"
);
/// The Helm chart's own copy. A chart must be self-contained, so this is a
/// second physical file rather than a symlink.
const HELM_CRDS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../deploy/helm/wiremesh-operator/crds/wiremesh-crds.yaml"
);

/// Repo-root-relative names, for failure messages (the `concat!` paths above
/// are absolute and full of `../..`).
const OPERATOR_CRDS_DISPLAY: &str = "deploy/operator/crds/wiremesh-crds.yaml";
const HELM_CRDS_DISPLAY: &str = "deploy/helm/wiremesh-operator/crds/wiremesh-crds.yaml";

/// Printed verbatim at the end of every failure so the reader never has to go
/// look it up. Regenerates the source-of-truth copy and mirrors it into the
/// chart. Run from the REPO ROOT — not a worktree (the worktree mount breaks
/// the cached enforcer build script).
const REGENERATE_HINT: &str = "\
to regenerate, from the repo root:

    ./dev.sh run \"cargo run -q -p wiremesh-operator --bin crdgen\" \\
      > deploy/operator/crds/wiremesh-crds.yaml
    cp deploy/operator/crds/wiremesh-crds.yaml \\
      deploy/helm/wiremesh-operator/crds/wiremesh-crds.yaml

BEFORE regenerating, confirm the ONLY difference is the one you expect —
regenerating blindly can bake an unrelated, unreviewed schema change into the
same commit as the drift fix.";

#[test]
fn operator_crd_bundle_matches_crdgen() {
    let generated = render();
    assert_bundle_matches(&generated, OPERATOR_CRDS, OPERATOR_CRDS_DISPLAY);
}

#[test]
fn helm_crd_bundle_matches_crdgen() {
    let generated = render();
    assert_bundle_matches(&generated, HELM_CRDS, HELM_CRDS_DISPLAY);
}

/// One test per file (rather than one test with two assertions) so that a
/// failure names the file in its own right, and so a stale first file cannot
/// mask a stale second one.
fn render() -> String {
    wiremesh_operator::crd::render_crd_yaml()
        .expect("rendering the CRD bundle must not fail (it is pure serialization)")
}

fn assert_bundle_matches(generated: &str, path: &str, display: &str) {
    let on_disk = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read the committed CRD bundle {display}: {e}"));
    if generated == on_disk {
        return;
    }
    panic!("{}", describe_mismatch(generated, &on_disk, display));
}

/// Build an ACTIONABLE failure message.
///
/// A bare `assert_eq!` on two ~400-line strings dumps both in full and buries
/// the one line that matters. This reports the first divergence with context,
/// the size of the gap, and — the part that turns a failure into a work order —
/// the names of any schema properties the file is missing.
///
/// Hand-rolled on purpose: a line diff good enough for this job is ~30 lines,
/// and a whole diffing dependency (`similar`, `pretty_assertions`) to render it
/// is not worth the build cost.
fn describe_mismatch(generated: &str, on_disk: &str, display: &str) -> String {
    let want: Vec<&str> = generated.lines().collect();
    let got: Vec<&str> = on_disk.lines().collect();

    let mut out = String::new();
    out.push_str(&format!(
        "{display} is NOT what `crdgen` renders — the committed CRD bundle is stale \
         (or was hand-edited).\n\n"
    ));

    out.push_str(&format!(
        "  generated: {} lines\n  on disk:   {} lines  ({:+})\n\n",
        want.len(),
        got.len(),
        got.len() as i64 - want.len() as i64,
    ));

    // First divergence, with a little leading context so the reader can see
    // which CRD and which block they are looking at.
    if let Some(i) = (0..want.len().max(got.len())).find(|&i| want.get(i) != got.get(i)) {
        out.push_str(&format!("first difference at line {}:\n", i + 1));
        for c in i.saturating_sub(3)..i {
            out.push_str(&format!("   {:>4} | {}\n", c + 1, want[c]));
        }
        out.push_str(&format!(
            "  generated {:>4} | {}\n",
            i + 1,
            want.get(i).copied().unwrap_or("<end of file>")
        ));
        out.push_str(&format!(
            "  on disk   {:>4} | {}\n\n",
            i + 1,
            got.get(i).copied().unwrap_or("<end of file>")
        ));
    }

    // Which schema properties are missing from the file? This is what makes the
    // failure a work order rather than a puzzle. Counted as a MULTISET, because
    // a name like `storageClass` legitimately appears once per kind that has
    // one — the interesting fact is that the file has FEWER of them, not that
    // the name is absent entirely.
    let missing = missing_property_names(&want, &got);
    if !missing.is_empty() {
        out.push_str(
            "schema properties present in the generated bundle but MISSING from this file:\n",
        );
        for (name, n) in &missing {
            if *n == 1 {
                out.push_str(&format!("  - {name}\n"));
            } else {
                out.push_str(&format!("  - {name}  (x{n})\n"));
            }
        }
        out.push('\n');
    }

    out.push_str(REGENERATE_HINT);
    out
}

/// Multiset difference over "bare key" lines — an indented identifier followed
/// by a colon and nothing else, which is how a schema property opens in the
/// generated YAML (`              observeEndpoint:`).
///
/// Deliberately a count comparison rather than a set membership test: the Helm
/// bundle is missing the RELAY's `storageClass`/`storageSize` while still
/// carrying the controller's and the gateway's, so "is this name present
/// anywhere" would report nothing missing at all.
fn missing_property_names<'a>(want: &[&'a str], got: &[&'a str]) -> Vec<(&'a str, usize)> {
    let mut counts: BTreeMap<&str, i64> = BTreeMap::new();
    for line in want.iter().filter_map(|l| bare_key(l)) {
        *counts.entry(line).or_default() += 1;
    }
    for line in got.iter().filter_map(|l| bare_key(l)) {
        *counts.entry(line).or_default() -= 1;
    }
    counts
        .into_iter()
        .filter(|&(_, n)| n > 0)
        .map(|(name, n)| (name, n as usize))
        .collect()
}

/// `"              observeEndpoint:"` -> `Some("observeEndpoint")`. Anything
/// with a value after the colon, a list item, or a non-identifier key is not a
/// property opener and yields `None`.
fn bare_key(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    if trimmed.len() == line.len() {
        return None; // top-level key, never a schema property
    }
    let name = trimmed.strip_suffix(':')?;
    let mut chars = name.chars();
    let first = chars.next()?;
    if !first.is_ascii_alphabetic() {
        return None;
    }
    if !chars.all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some(name)
}
