//! Every artifact this project ships must be stamped with the release version
//! before it is built — and the set of crates `scripts/set-version.sh` stamps
//! must equal the set of crates that ship something.
//!
//! # Why this test exists
//!
//! Every binary reports its version from `env!("CARGO_PKG_VERSION")` — whatever
//! its crate's `Cargo.toml` said **at compile time** (see
//! `crates/wiremesh-controller/src/cli.rs`, `fabricctl`'s `#[command(version)]`,
//! and `crates/fabricctl/tests/cli_help_version.rs` which pins that behaviour).
//! All eleven workspace crates are hardcoded `version = "0.1.0"` in git. The
//! real version exists ONLY transiently inside a CI job, written by
//! `scripts/set-version.sh` immediately before the build.
//!
//! That design is fine. What is not fine is that nothing checked it held, and
//! it stopped holding in two separate places:
//!
//! 1. **`scripts/set-version.sh` enumerates four crates by name** — `fabricctl`,
//!    `wiremesh-controller`, `wiremesh-gateway`, `wiremesh-relay`.
//!    `wiremesh-operator` is not among them, yet it is built and published as a
//!    container image (the `component:` matrix in `container-images.yml` lists
//!    `operator`). `wiremesh-operator --version` reports `0.1.0` on every
//!    release, forever.
//!
//! 2. **`.github/workflows/container-images.yml` never calls the script at
//!    all.** `release.yml` calls it three times (once per build job) so the
//!    tarball/.deb/.rpm/.msi/.pkg binaries are stamped — but the container
//!    workflow compiles from unstamped source on `push: branches: [main]` AND
//!    on `push: tags: ['v*']`. So *every* published image — controller,
//!    gateway, relay, fabricctl and operator alike — reports `0.1.0`. This is
//!    strictly broader than (1): fixing the script's crate list alone leaves
//!    all five images wrong.
//!
//! The operator-visible consequence of both is the same and it is nasty
//! because it is silent: an operator triaging a fabric cannot tell which build
//! is running. `wiremesh-controller --version` says `0.1.0` on a v0.9.2 image,
//! on a v0.4.0 image, and on a locally built one. Every "which version are you
//! on?" answer in every future incident is wrong, and the rollback decision
//! that depends on it is made blind.
//!
//! # The sets are DERIVED, never hardcoded
//!
//! A test that hardcoded "the shipped components are controller, gateway,
//! relay, fabricctl, operator" would be a second list capable of exactly the
//! drift it is meant to catch — the `set-version.sh` bug wearing a different
//! hat. So both sides are computed from the sources of truth:
//!
//! * **The shipped set** comes from three places, unioned:
//!   - the `component:` matrix in `container-images.yml`, resolved through the
//!     `deploy/docker/Dockerfile` stage of the same name to the binaries that
//!     stage copies out of `builder`, then to the crate that declares each
//!     binary as a `[[bin]]` (or owns it implicitly via `src/main.rs`);
//!   - the Dockerfile's `export` stage — the exact binary list
//!     `release.yml`'s `linux-binaries` job extracts and packages;
//!   - every `cargo build … -p <crate>` in `release.yml` (the macOS and Windows
//!     jobs, which do not go through the Dockerfile at all).
//!
//!   This is what makes the image/binary/crate naming mismatches a non-issue:
//!   the image component is bare (`relay`), the packaged binary is renamed
//!   (`release.yml` ships `relay` as `wiremesh-relay`), and one crate owns
//!   three binaries (`relay`, `mkcerts`, `wiremesh-relay-enroll` all belong to
//!   `wiremesh-relay`). Resolving *through* the Dockerfile and the `[[bin]]`
//!   tables means no mapping table lives in this file.
//!
//! * **The stamped set** is obtained by RUNNING `scripts/set-version.sh` — not
//!   by parsing its `for crate in …` line. The script is copied into a throwaway
//!   temp tree together with every workspace member's `Cargo.toml`, run there
//!   with a sentinel version, and the result read back. The temp tree is deleted
//!   before the helper returns; the real repo is never touched and never
//!   dirtied.
//!
//!   Running it rather than parsing it is deliberate and buys three things a
//!   parser cannot: it survives any restructuring of the script (an array, a
//!   `find`, a loop over `crates/*/`), it proves the rewrite actually LANDS
//!   rather than that a name appears in a list, and it lets
//!   `set_version_rewrites_exactly_the_package_version_it_claims` compare the
//!   script's own stdout ("what it claims") against the file contents ("what it
//!   did"). The script's `:30` self-check only proves the version STRING is
//!   present somewhere in the file afterwards — which a substitution into the
//!   wrong line would also satisfy.
//!
//! # Why a workflow-level assertion too
//!
//! Defect (2) is invisible to any assertion about the script alone: the script
//! can be perfect and still never be called. So
//! `every_job_that_compiles_a_shipped_binary_stamps_the_version_first` walks
//! every workflow's jobs and requires that a job which compiles workspace
//! source (a `cargo build`, or any build of `deploy/docker/Dockerfile`) runs
//! `scripts/set-version.sh` at an EARLIER step index. Same job, not merely the
//! same workflow: stamping edits the checkout, and each job gets its own
//! runner and its own checkout, so a stamp in job A does nothing for job B.
//!
//! The `builder` job in `container-images.yml` is included on purpose even
//! though it pushes nothing. `builder` is where `cargo build --release
//! --workspace` actually runs; the five runtime stages only `COPY` out of it.
//! An unstamped `builder` cache is at best wasted work (stamping in `images`
//! invalidates the cached layer and rebuilds anyway, since `Cargo.toml` is part
//! of the build context) and at worst, the day someone makes `images` consume
//! the builder's binaries directly, it silently ships `0.1.0` again.
//!
//! `codeql.yml` is correctly not flagged: both its languages use `build-mode:
//! none` and its only `run:` step is a commented-out placeholder that echoes
//! and exits. It compiles nothing, so it needs no stamp.
//!
//! Known blind spot, stated rather than papered over: the classifier reads
//! `run:` and `uses:` in the workflow file itself. A build hidden behind a
//! composite action (`uses: ./.github/actions/…`) or a Makefile target would
//! not be recognised. Nothing in this repo does that today; if something starts
//! to, extend `build_reason()`.
//!
//! # The Helm chart is deliberately NOT in scope
//!
//! `deploy/helm/wiremesh-operator/Chart.yaml` carries the same `0.1.0`
//! placeholder (`version: 0.1.0` / `appVersion: "0.1.0"`) and nothing rewrites
//! it either — but stamping it here would fix nothing a user can see. Nothing
//! packages or publishes the chart (`release.yml` attaches tarballs, `.deb`,
//! `.rpm`, `.msi` and `.pkg` — there is no `helm package`, no chart repo and no
//! index), so a CI-side stamp lives and dies inside the job and anyone
//! installing from a git checkout still gets `0.1.0`. It was written, reviewed
//! and removed by owner decision; see `docs/BACKLOG.md` item 32, which also
//! records the `image.tag: "latest"` question that has to be settled with it.
//! Do not re-add a chart assertion here without the publishing half.
//!
//! # Why this test lives in `wiremesh-operator`
//!
//! The invariant is repo-wide, so no crate is a perfect home; a dedicated
//! `release-invariants` crate would be, but adding one edits the workspace
//! `Cargo.toml`, which is outside a test author's remit. Among existing crates
//! `wiremesh-operator` is the best fit on three counts: it already owns the
//! only precedent for a test that reads repo files outside its own crate
//! (`tests/crd_manifest_freshness.rs`, whose `concat!(env!("CARGO_MANIFEST_DIR"),
//! "/../..")` repo-root mechanism this file reuses verbatim rather than
//! inventing a second one); and it is the crate that defect (1) leaves
//! unstamped. It also already depends on `serde_yaml`, so the workflows can be
//! parsed structurally without touching any `Cargo.toml`.
//!
//! No cluster, no privilege, no netns — ordinary `cargo test -p
//! wiremesh-operator`. It shells out to `bash` (which runs `perl`), both of
//! which the Linux dev container and the macOS host already provide.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

/// Repo root, reached the same way `tests/crd_manifest_freshness.rs` reaches
/// `deploy/**` — one mechanism for both tests, so neither can drift.
const REPO_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");

const SET_VERSION_SH: &str = "scripts/set-version.sh";
const DOCKERFILE: &str = "deploy/docker/Dockerfile";
const CONTAINER_WF: &str = ".github/workflows/container-images.yml";
const RELEASE_WF: &str = ".github/workflows/release.yml";
const WORKFLOW_DIR: &str = ".github/workflows";

/// The version handed to `set-version.sh` in the throwaway tree. Must satisfy
/// the script's own `MAJOR.MINOR.PATCH[-prerelease]` regex, and must be
/// something no real manifest could already contain.
const SENTINEL: &str = "9.9.9-stampcheck";

// ===========================================================================
// The tests
// ===========================================================================

/// The one that is red today because of defect (1).
#[test]
fn every_shipped_crate_is_stamped_by_set_version() {
    let run = run_set_version();
    let shipped = shipped_crates();

    let missing: Vec<(&String, &BTreeSet<String>)> = shipped
        .iter()
        .filter(|(name, _)| !run.stamped.contains(*name))
        .collect();
    if missing.is_empty() {
        return;
    }

    let mut msg = String::new();
    msg.push_str(
        "scripts/set-version.sh does not stamp every crate that ships an artifact, so a \
         RELEASED BINARY WILL REPORT THE WRONG VERSION.\n\n\
         Every binary prints env!(\"CARGO_PKG_VERSION\") — its crate's committed \
         Cargo.toml version, which is the 0.1.0 placeholder unless set-version.sh \
         rewrote it first. For the crates below it never does, so `--version`, and \
         every log line and metric label carrying the build version, says 0.1.0 on \
         every release forever. Whoever is mid-incident cannot tell v0.9.2 from \
         v0.4.0 and cannot decide whether to roll back.\n\n\
         UNSTAMPED, but shipped:\n\n",
    );
    for (name, reasons) in &missing {
        msg.push_str(&format!("  {name}\n"));
        for r in reasons.iter() {
            msg.push_str(&format!("      ships as: {r}\n"));
        }
    }
    msg.push_str(&format!(
        "\nstamped by {SET_VERSION_SH} today: {}\n",
        joined(&run.stamped)
    ));
    msg.push_str(&format!(
        "shipped (derived from {CONTAINER_WF}, {DOCKERFILE} and {RELEASE_WF}): {}\n\n",
        joined(&shipped.keys().cloned().collect::<BTreeSet<String>>())
    ));
    msg.push_str(
        "fix: make scripts/set-version.sh rewrite the [package] version of every crate \
         listed above (today it enumerates four crate names in a `for crate in …` loop). \
         Do NOT satisfy this test by removing an artifact from the release.\n",
    );
    panic!("{msg}");
}

/// The reverse direction, as its own test so a stale entry is reported in its
/// own right instead of being masked by — or masking — the failure above.
///
/// Green today. It goes red if a crate is dropped from the release while its
/// name stays in the script, which is harmless at runtime but means the script
/// exits 1 (`set-version: crates/<gone>/Cargo.toml not found`) the moment the
/// crate directory disappears, breaking every release job at once.
#[test]
fn set_version_stamps_no_crate_that_ships_nothing() {
    let run = run_set_version();
    let shipped = shipped_crates();

    let extra: Vec<&String> = run
        .stamped
        .iter()
        .filter(|c| !shipped.contains_key(*c))
        .collect();
    assert!(
        extra.is_empty(),
        "scripts/set-version.sh stamps {} — crate(s) that ship no artifact this test can \
         find in {CONTAINER_WF}, {DOCKERFILE} or {RELEASE_WF}.\n\n\
         Either the crate stopped shipping (drop it from the script — and note the \
         script exits 1 the moment its directory is gone, which fails EVERY release \
         build job, not just one), or it ships through a path this test does not know \
         about (extend shipped_crates() so the invariant covers it).\n\n\
         stamped: {}\nshipped: {}",
        joined(
            &extra
                .iter()
                .map(|s| (*s).clone())
                .collect::<BTreeSet<String>>()
        ),
        joined(&run.stamped),
        joined(&shipped.keys().cloned().collect::<BTreeSet<String>>()),
    );
}

/// The one that is red today because of defect (2) — the broader half.
#[test]
fn every_job_that_compiles_a_shipped_binary_stamps_the_version_first() {
    let mut offenders: Vec<String> = Vec::new();
    let mut builds_seen = 0usize;

    for wf in workflow_files() {
        let doc = read_yaml(&wf);
        let jobs = match doc["jobs"].as_mapping() {
            Some(m) => m,
            None => continue,
        };
        for (job_key, job) in jobs.iter() {
            let job_name = job_key.as_str().unwrap_or("<non-string job id>");
            let steps = match job["steps"].as_sequence() {
                Some(s) => s,
                None => continue,
            };

            let first_build = steps
                .iter()
                .enumerate()
                .find_map(|(i, s)| build_reason(s).map(|r| (i, r)));
            let first_stamp = steps.iter().position(is_stamp_step);

            let (build_idx, why) = match first_build {
                Some(v) => v,
                None => continue,
            };
            builds_seen += 1;

            match first_stamp {
                Some(stamp_idx) if stamp_idx < build_idx => {}
                Some(stamp_idx) => offenders.push(format!(
                    "  {wf} :: job `{job_name}`\n      {why} at step #{build_idx}, but runs \
                     {SET_VERSION_SH} only at step #{stamp_idx} — AFTER the build, so the \
                     compiled binary carries the placeholder version.",
                )),
                None => offenders.push(format!(
                    "  {wf} :: job `{job_name}`\n      {why} and never runs {SET_VERSION_SH} \
                     at all — every binary it produces reports the 0.1.0 placeholder.",
                )),
            }
        }
    }

    // Anti-vacuity: release.yml alone has three compiling jobs. If the
    // classifier matches nothing the workflows were restructured and this test
    // would otherwise pass by finding no work to do.
    assert!(
        builds_seen >= 3,
        "build_reason() recognised only {builds_seen} compiling job(s) across {WORKFLOW_DIR} — \
         it recognised none or nearly none, which means the workflows changed shape and this \
         test is now passing vacuously rather than proving anything. Update build_reason() to \
         match how the workflows compile today."
    );

    assert!(
        offenders.is_empty(),
        "A CI job compiles a shipped binary WITHOUT stamping the release version first, so \
         the artifact it publishes self-reports the 0.1.0 placeholder.\n\n{}\n\n\
         Stamping is per-JOB, not per-workflow: each job gets its own runner and its own \
         checkout, so `bash scripts/set-version.sh <version>` must run in the same job, \
         before the build step.\n\n\
         For container-images.yml that also means deciding what version to stamp on each \
         trigger — the tag for `push: tags: ['v*']`, and something honest and \
         non-colliding (e.g. 0.0.0-<short-sha>) for main/PR builds. Any of those is \
         better than shipping a number that is simply false.\n\n\
         Note this covers the `builder` job too: `cargo build --release --workspace` runs \
         inside the builder stage, and the runtime stages only COPY from it.",
        offenders.join("\n\n"),
    );
}

/// Defect-adjacent, and the one the brief calls "set-version.sh actually
/// rewrites what it claims".
///
/// The script's own check at `:30` is `grep -qF "\"$VERSION\""` — it proves the
/// version string exists SOMEWHERE in the file afterwards. That is satisfied by
/// a substitution into the wrong line. The perl one-liner replaces the first
/// line matching `^version\s*=\s*"`, which is the `[package]` version only by
/// convention. The moment a crate adopts `version.workspace = true` (which does
/// NOT match that regex, because of the `.`) or grows a `[dependencies.foo]`
/// section with its own line-anchored `version = "…"`, the script would rewrite
/// a DEPENDENCY's version requirement, its self-check would still pass, and the
/// crate would ship the placeholder while CI reported success.
///
/// So: what the script says on stdout must equal what changed on disk, and the
/// only line it changed in each crate must be the `[package]` version.
#[test]
fn set_version_rewrites_exactly_the_package_version_it_claims() {
    let run = run_set_version();

    assert!(
        !run.claimed.is_empty(),
        "could not read which crates {SET_VERSION_SH} claims to have stamped from its \
         stdout (expected lines like `set wiremesh-gateway version -> {SENTINEL}`).\n\n\
         stdout was:\n{}\n\n\
         If the script's progress output was reformatted, update claimed_from_stdout() in \
         this test. Do not delete the check — comparing the script's claim against the \
         file contents is what catches a substitution that lands on the wrong line.",
        run.stdout,
    );

    assert_eq!(
        run.claimed,
        run.stamped,
        "{SET_VERSION_SH} reports success for a different set of crates than it actually \
         rewrote.\n\n  claims to have stamped: {}\n  actually carries {SENTINEL} as its \
         [package] version: {}\n\nA crate it claims but did not stamp ships the 0.1.0 \
         placeholder while the release job prints a green `set <crate> version -> …` line.",
        joined(&run.claimed),
        joined(&run.stamped),
    );

    for (crate_name, changes) in &run.changed_lines {
        let stamped = run.stamped.contains(crate_name);
        if !stamped {
            assert!(
                changes.is_empty(),
                "{SET_VERSION_SH} modified crates/{crate_name}/Cargo.toml without stamping \
                 its [package] version. It rewrote: {changes:?}\n\n\
                 That is a substitution landing on the wrong line — most likely a \
                 dependency's version requirement — which silently changes the build while \
                 leaving the crate on the placeholder version.",
            );
            continue;
        }
        assert_eq!(
            changes.len(),
            1,
            "{SET_VERSION_SH} changed {} line(s) in crates/{crate_name}/Cargo.toml; exactly \
             one — the [package] version — must change.\n\nchanged: {changes:?}",
            changes.len(),
        );
        let (idx, before, after) = &changes[0];
        assert!(
            section_of_line(&run.manifests_before[crate_name], *idx) == "[package]",
            "{SET_VERSION_SH} rewrote line {} of crates/{crate_name}/Cargo.toml, which is in \
             section {:?} — NOT [package].\n\n  before: {before}\n  after:  {after}\n\n\
             The script replaces the first line matching ^version = \"…\"; in this manifest \
             that line is no longer the [package] version, so the crate keeps the 0.1.0 \
             placeholder (and a dependency requirement was corrupted instead). The script's \
             own grep self-check cannot see this, because the version string IS present in \
             the file afterwards — just in the wrong place.",
            idx + 1,
            section_of_line(&run.manifests_before[crate_name], *idx),
        );
        assert!(
            after.contains(SENTINEL),
            "crates/{crate_name}/Cargo.toml's [package] version line does not carry the \
             requested version after stamping.\n\n  before: {before}\n  after:  {after}",
        );
    }
}

/// Not a version invariant, but the shipped-set derivation above walks
/// `component:` → Dockerfile stage, and both matrices must name the same
/// components or a component gets built per-arch and never tagged (or tagged
/// with no digests to stitch). Cheap to pin here, where the parsing already
/// exists.
#[test]
fn container_image_matrices_agree_and_every_component_has_a_dockerfile_stage() {
    let doc = read_yaml(CONTAINER_WF);
    let images = matrix_components(&doc, "images");
    let merge = matrix_components(&doc, "merge");
    assert_eq!(
        images, merge,
        "{CONTAINER_WF}'s `images` and `merge` job matrices list different components. \
         `images` builds and pushes per-arch digests; `merge` stitches them into the \
         tagged multi-arch manifest. A component in only one of them is either built and \
         never published under a usable tag, or has a manifest job with no digests to \
         assemble (which fails the release).",
    );

    let stages = dockerfile_stage_binaries();
    let orphans: Vec<&String> = images.iter().filter(|c| !stages.contains_key(*c)).collect();
    assert!(
        orphans.is_empty(),
        "{CONTAINER_WF} builds component(s) {orphans:?} but {DOCKERFILE} has no stage of \
         that name — those image builds fail outright. Known stages: {:?}",
        stages.keys().collect::<Vec<_>>(),
    );
}

// ===========================================================================
// Deriving the SHIPPED set
// ===========================================================================

/// crate name -> the artifact(s) that make it shipped, for the failure message.
///
/// Whoever reads a failure is mid-release, so every entry says which artifact
/// and by which chain it was derived — not just "this crate is shipped".
fn shipped_crates() -> BTreeMap<String, BTreeSet<String>> {
    let bins = bin_to_crate();
    let stages = dockerfile_stage_binaries();
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    let mut add = |crate_name: String, reason: String| {
        out.entry(crate_name).or_default().insert(reason);
    };

    // (a) container images
    let container = read_yaml(CONTAINER_WF);
    for component in matrix_components(&container, "images") {
        let stage_bins = stages.get(&component).unwrap_or_else(|| {
            panic!(
                "{CONTAINER_WF} builds image component `{component}` but {DOCKERFILE} has no \
                 stage named `{component}` — cannot derive which crate that image ships. \
                 (container_image_matrices_agree_and_every_component_has_a_dockerfile_stage \
                 reports this in its own right.)"
            )
        });
        assert!(
            !stage_bins.is_empty(),
            "{DOCKERFILE} stage `{component}` copies no binary out of `builder`, so the \
             image ships nothing this test can attribute to a crate. Either the stage \
             changed shape or dockerfile_stage_binaries() needs updating."
        );
        for b in stage_bins {
            add(
                crate_of_bin(&bins, b, &format!("{DOCKERFILE} stage `{component}`")),
                format!(
                    "container image ghcr.io/<owner>/wiremesh-{component} \
                     ({CONTAINER_WF} matrix component `{component}` -> {DOCKERFILE} stage \
                     `{component}` -> binary `{b}`)"
                ),
            );
        }
    }

    // (b) the release tarballs / .deb / .rpm — exactly the Dockerfile `export`
    // stage, which release.yml's linux-binaries job extracts wholesale.
    let export = stages.get("export").unwrap_or_else(|| {
        panic!(
            "{DOCKERFILE} has no `export` stage — that stage is what {RELEASE_WF}'s \
             linux-binaries job extracts (`--target export`) and packages. Update \
             dockerfile_stage_binaries() or shipped_crates() if the release stopped using it."
        )
    });
    for b in export {
        add(
            crate_of_bin(&bins, b, &format!("{DOCKERFILE} stage `export`")),
            format!(
                "Linux release binary `{b}` (tarballs + .deb/.rpm; {DOCKERFILE} `export` \
                 stage -> {RELEASE_WF} linux-binaries/linux-packages)"
            ),
        );
    }

    // (c) the macOS and Windows jobs, which never touch the Dockerfile.
    let members: BTreeSet<String> = workspace_members().into_iter().map(|(n, _)| n).collect();
    let release = read_yaml(RELEASE_WF);
    if let Some(jobs) = release["jobs"].as_mapping() {
        for (job_key, job) in jobs.iter() {
            let job_name = job_key.as_str().unwrap_or("<job>").to_string();
            let steps = match job["steps"].as_sequence() {
                Some(s) => s,
                None => continue,
            };
            for step in steps {
                let run = match step["run"].as_str() {
                    Some(r) if r.contains("cargo build") => r,
                    _ => continue,
                };
                for c in cargo_package_flags(run) {
                    assert!(
                        members.contains(&c),
                        "{RELEASE_WF} job `{job_name}` runs `cargo build … -p {c}`, but {c} is \
                         not a workspace member. Either the workflow names a crate that no \
                         longer exists (the release job fails), or cargo_package_flags() \
                         mis-parsed the command."
                    );
                    add(
                        c,
                        format!("built directly by {RELEASE_WF} job `{job_name}` (cargo build -p)"),
                    );
                }
            }
        }
    }

    assert!(
        out.len() >= 4,
        "shipped_crates() derived only {} crate(s) ({:?}) — the release ships more than that, \
         so the derivation is broken and every assertion built on it would pass vacuously.",
        out.len(),
        out.keys().collect::<Vec<_>>(),
    );
    out
}

fn crate_of_bin(bins: &BTreeMap<String, String>, bin: &str, whence: &str) -> String {
    bins.get(bin).cloned().unwrap_or_else(|| {
        panic!(
            "{whence} ships a binary named `{bin}`, but no workspace crate declares a \
                 [[bin]] with that name and none owns it implicitly via src/main.rs. Known \
                 binaries: {:?}",
            bins.keys().collect::<Vec<_>>()
        )
    })
}

/// `-p foo -p bar` / `--package foo` out of a `cargo build` command line.
fn cargo_package_flags(run: &str) -> Vec<String> {
    let toks: Vec<&str> = run.split_whitespace().collect();
    let mut out = Vec::new();
    for (i, t) in toks.iter().enumerate() {
        if *t == "-p" || *t == "--package" {
            if let Some(next) = toks.get(i + 1) {
                out.push((*next).to_string());
            }
        } else if let Some(v) = t.strip_prefix("--package=") {
            out.push(v.to_string());
        }
    }
    out
}

// ===========================================================================
// Reading the repo: Cargo, Docker, workflows
// ===========================================================================

/// `(crate name, repo-relative directory)` for every workspace member.
/// Read from the root manifest's `members = [...]`, so `exclude`d trees (the
/// standalone `wiremesh-enforcer-ebpf` aya workspace) are correctly absent.
fn workspace_members() -> Vec<(String, String)> {
    let text = read(&repo("Cargo.toml"), "Cargo.toml");
    // Anchor on the `members` KEY, not the first place that substring appears.
    // A bare `text.find("members")` would just as happily match `default-members`
    // (which cargo allows alongside `members`, and which lists a SUBSET — so the
    // shipped-set derivation below would quietly go blind to whatever it omits)
    // or the word inside one of this manifest's comments. Require the line to
    // start with `members` and the next non-space character to be `=`.
    let start = text
        .char_indices()
        .filter(|&(i, _)| i == 0 || text.as_bytes()[i - 1] == b'\n')
        .map(|(i, _)| (i, text[i..].trim_start_matches([' ', '\t'])))
        .find(|(_, line)| {
            line.strip_prefix("members")
                .is_some_and(|rest| rest.trim_start().starts_with('='))
        })
        .map(|(i, _)| i)
        .expect("root Cargo.toml must declare a workspace `members = [...]` key");
    let open = start
        + text[start..]
            .find('[')
            .expect("workspace members must be a list");
    let close = open
        + text[open..]
            .find(']')
            .expect("unterminated workspace members list");
    let mut out = Vec::new();
    for raw in text[open + 1..close].split(',') {
        let dir = raw.trim().trim_matches('"').trim();
        if dir.is_empty() {
            continue;
        }
        let manifest = read(
            &repo(&format!("{dir}/Cargo.toml")),
            &format!("{dir}/Cargo.toml"),
        );
        let name = section_value(&manifest, "[package]", "name")
            .unwrap_or_else(|| panic!("{dir}/Cargo.toml has no [package] name"));
        out.push((name, dir.to_string()));
    }
    assert!(
        !out.is_empty(),
        "parsed zero workspace members out of the root Cargo.toml"
    );
    out
}

/// binary name -> crate that produces it. Explicit `[[bin]]` entries plus the
/// implicit `src/main.rs` bin (named after the package), which is how
/// `wiremesh-controller` and `wiremesh-operator` get their binaries.
fn bin_to_crate() -> BTreeMap<String, String> {
    let mut map: BTreeMap<String, String> = BTreeMap::new();
    for (name, dir) in workspace_members() {
        let manifest = read(
            &repo(&format!("{dir}/Cargo.toml")),
            &format!("{dir}/Cargo.toml"),
        );
        let mut section = String::new();
        for line in manifest.lines() {
            let t = line.trim();
            if t.starts_with('[') {
                section = t.to_string();
                continue;
            }
            if section == "[[bin]]" {
                if let Some(bin) = kv_string(t, "name") {
                    insert_bin(&mut map, bin, &name);
                }
            }
        }
        if repo(&format!("{dir}/src/main.rs")).exists() {
            insert_bin(&mut map, name.clone(), &name);
        }
    }
    map
}

fn insert_bin(map: &mut BTreeMap<String, String>, bin: String, crate_name: &str) {
    if let Some(prev) = map.insert(bin.clone(), crate_name.to_string()) {
        assert_eq!(
            prev, crate_name,
            "two workspace crates ({prev} and {crate_name}) both produce a binary named \
             `{bin}` — the shipped-set derivation cannot tell which crate an artifact of \
             that name came from, and `cargo build --workspace` would overwrite one with \
             the other in target/release."
        );
    }
}

/// Dockerfile stage -> the binaries it copies out of the `builder` stage.
/// Line continuations are joined first: the `export` stage's `COPY --from=builder`
/// spans seven lines.
fn dockerfile_stage_binaries() -> BTreeMap<String, Vec<String>> {
    let text = read(&repo(DOCKERFILE), DOCKERFILE);
    let mut stages: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current: Option<String> = None;

    for line in logical_lines(&text) {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let toks: Vec<&str> = t.split_whitespace().collect();
        if toks[0].eq_ignore_ascii_case("FROM") {
            current = toks
                .iter()
                .position(|x| x.eq_ignore_ascii_case("AS"))
                .and_then(|i| toks.get(i + 1))
                .map(|s| (*s).to_string());
            if let Some(name) = &current {
                stages.entry(name.clone()).or_default();
            }
            continue;
        }
        if toks[0].eq_ignore_ascii_case("COPY") && t.contains("--from=builder") {
            if let Some(stage) = current.clone() {
                let entry = stages.entry(stage).or_default();
                for tok in &toks {
                    if let Some(bin) = tok.strip_prefix("/out/") {
                        if !bin.is_empty() {
                            entry.push(bin.to_string());
                        }
                    }
                }
            }
        }
    }

    assert!(
        stages.len() > 1,
        "parsed {} stage(s) out of {DOCKERFILE} — the parser is not seeing the file's shape, \
         which would make every derivation built on it vacuous.",
        stages.len()
    );
    stages
}

/// Join backslash line continuations into logical lines.
fn logical_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for raw in text.lines() {
        let t = raw.trim_end();
        if t.trim_start().starts_with('#') && cur.is_empty() {
            out.push(t.to_string());
            continue;
        }
        match t.strip_suffix('\\') {
            Some(head) => {
                cur.push_str(head);
                cur.push(' ');
            }
            None => {
                cur.push_str(t);
                out.push(std::mem::take(&mut cur));
            }
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn workflow_files() -> Vec<String> {
    let dir = repo(WORKFLOW_DIR);
    let mut out: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("cannot list {WORKFLOW_DIR}: {e}"))
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.ends_with(".yml") || n.ends_with(".yaml"))
        .map(|n| format!("{WORKFLOW_DIR}/{n}"))
        .collect();
    out.sort();
    assert!(
        !out.is_empty(),
        "no workflow files found under {WORKFLOW_DIR}"
    );
    out
}

/// Does this step compile workspace source into a shipped binary? Returns the
/// human-readable reason, which goes straight into the failure message.
fn build_reason(step: &serde_yaml::Value) -> Option<String> {
    if let Some(run) = step["run"].as_str() {
        if run.contains("cargo build") {
            return Some("runs `cargo build`".to_string());
        }
        if run.contains(DOCKERFILE) && run.contains("build") {
            return Some(format!("runs a docker build of {DOCKERFILE}"));
        }
    }
    if let Some(uses) = step["uses"].as_str() {
        if uses.starts_with("docker/build-push-action")
            && step["with"]["file"].as_str() == Some(DOCKERFILE)
        {
            let target = step["with"]["target"].as_str().unwrap_or("<default>");
            return Some(format!(
                "builds {DOCKERFILE} (target `{target}`) via docker/build-push-action"
            ));
        }
    }
    None
}

fn is_stamp_step(step: &serde_yaml::Value) -> bool {
    step["run"]
        .as_str()
        .map(|r| r.contains("set-version.sh"))
        .unwrap_or(false)
}

fn matrix_components(doc: &serde_yaml::Value, job: &str) -> Vec<String> {
    let seq = doc["jobs"][job]["strategy"]["matrix"]["component"]
        .as_sequence()
        .unwrap_or_else(|| {
            panic!(
                "{CONTAINER_WF} job `{job}` has no strategy.matrix.component list — the \
                 shipped image set is derived from it, so this test cannot run until \
                 matrix_components() is taught the new shape."
            )
        });
    seq.iter()
        .map(|v| {
            v.as_str()
                .unwrap_or_else(|| {
                    panic!("{CONTAINER_WF} job `{job}` matrix component is not a string")
                })
                .to_string()
        })
        .collect()
}

// ===========================================================================
// Running set-version.sh in a throwaway tree
// ===========================================================================

struct StampRun {
    /// Crates whose `[package]` version is the sentinel after the run.
    stamped: BTreeSet<String>,
    /// Crates the script's own stdout says it stamped.
    claimed: BTreeSet<String>,
    stdout: String,
    /// crate -> (line index, before, after) for every line the script changed.
    changed_lines: BTreeMap<String, Vec<(usize, String, String)>>,
    manifests_before: BTreeMap<String, String>,
}

static NONCE: AtomicU32 = AtomicU32::new(0);

/// Copy the script and every workspace member's `Cargo.toml` into a temp tree;
/// run the script there; read the result back; delete the tree. The real repo is
/// never written to — running the script in place would dirty the working tree
/// with a fake version, which is exactly the kind of accident that gets
/// committed.
fn run_set_version() -> StampRun {
    let dir = std::env::temp_dir().join(format!(
        "wiremesh-set-version-{}-{}",
        std::process::id(),
        NONCE.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    mkdir(&dir.join("scripts"));
    copy_into(&repo(SET_VERSION_SH), &dir.join(SET_VERSION_SH));

    let members = workspace_members();
    let mut manifests_before: BTreeMap<String, String> = BTreeMap::new();
    for (name, rel) in &members {
        mkdir(&dir.join(rel));
        let src = repo(&format!("{rel}/Cargo.toml"));
        copy_into(&src, &dir.join(format!("{rel}/Cargo.toml")));
        manifests_before.insert(name.clone(), read(&src, &format!("{rel}/Cargo.toml")));
    }

    let out = Command::new("bash")
        .arg(SET_VERSION_SH)
        .arg(SENTINEL)
        .current_dir(&dir)
        .output()
        .unwrap_or_else(|e| panic!("cannot run `bash {SET_VERSION_SH} {SENTINEL}`: {e}"));
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        out.status.success(),
        "`bash {SET_VERSION_SH} {SENTINEL}` exited {:?} in a clean copy of the repo's \
         manifests. It must succeed for a valid version — a failure here breaks EVERY \
         release build job.\n\nstdout:\n{stdout}\nstderr:\n{stderr}",
        out.status.code(),
    );

    let mut stamped = BTreeSet::new();
    let mut changed_lines: BTreeMap<String, Vec<(usize, String, String)>> = BTreeMap::new();
    for (name, rel) in &members {
        let after = read(
            &dir.join(format!("{rel}/Cargo.toml")),
            &format!("{rel}/Cargo.toml (stamped)"),
        );
        let before = &manifests_before[name];
        if section_value(&after, "[package]", "version").as_deref() == Some(SENTINEL) {
            stamped.insert(name.clone());
        }
        changed_lines.insert(name.clone(), diff_lines(before, &after));
    }

    let _ = std::fs::remove_dir_all(&dir);

    StampRun {
        stamped,
        claimed: claimed_from_stdout(&stdout),
        stdout,
        changed_lines,
        manifests_before,
    }
}

/// `set wiremesh-gateway version -> 9.9.9-stampcheck` -> `wiremesh-gateway`.
fn claimed_from_stdout(stdout: &str) -> BTreeSet<String> {
    stdout
        .lines()
        .filter_map(|l| {
            let t = l.trim();
            let rest = t.strip_prefix("set ")?;
            let name = rest.split_whitespace().next()?;
            if rest.contains("version") {
                Some(name.to_string())
            } else {
                None
            }
        })
        .collect()
}

fn diff_lines(before: &str, after: &str) -> Vec<(usize, String, String)> {
    let b: Vec<&str> = before.lines().collect();
    let a: Vec<&str> = after.lines().collect();
    (0..b.len().max(a.len()))
        .filter(|i| b.get(*i) != a.get(*i))
        .map(|i| {
            (
                i,
                b.get(i).copied().unwrap_or("<absent>").to_string(),
                a.get(i).copied().unwrap_or("<absent>").to_string(),
            )
        })
        .collect()
}

// ===========================================================================
// Small parsers
// ===========================================================================

fn repo(rel: &str) -> PathBuf {
    Path::new(REPO_ROOT).join(rel)
}

fn read(path: &Path, display: &str) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {display} ({}): {e}", path.display()))
}

fn read_yaml(rel: &str) -> serde_yaml::Value {
    let text = read(&repo(rel), rel);
    serde_yaml::from_str(&text).unwrap_or_else(|e| panic!("{rel} is not parseable YAML: {e}"))
}

fn mkdir(p: &Path) {
    std::fs::create_dir_all(p).unwrap_or_else(|e| panic!("cannot create {}: {e}", p.display()));
}

fn copy_into(src: &Path, dst: &Path) {
    std::fs::copy(src, dst)
        .unwrap_or_else(|e| panic!("cannot copy {} -> {}: {e}", src.display(), dst.display()));
}

/// `key = "value"` at the start of a trimmed TOML line.
fn kv_string(line: &str, key: &str) -> Option<String> {
    let rest = line.strip_prefix(key)?;
    let rest = rest.trim_start().strip_prefix('=')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// The value of `key` inside a named TOML section.
fn section_value(manifest: &str, want_section: &str, key: &str) -> Option<String> {
    let mut section = String::new();
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            section = t.to_string();
            continue;
        }
        if section == want_section {
            if let Some(v) = kv_string(t, key) {
                return Some(v);
            }
        }
    }
    None
}

/// Which TOML section a given 0-based line index falls in.
fn section_of_line(manifest: &str, idx: usize) -> String {
    let mut section = String::from("<no section>");
    for (i, line) in manifest.lines().enumerate() {
        let t = line.trim();
        if i == idx {
            return section;
        }
        if t.starts_with('[') {
            section = t.to_string();
        }
    }
    section
}

fn joined(set: &BTreeSet<String>) -> String {
    if set.is_empty() {
        "<none>".to_string()
    } else {
        set.iter().cloned().collect::<Vec<_>>().join(", ")
    }
}

/// (B10) Every crate under `crates/` that reads its own `CARGO_PKG_VERSION`
/// must be one `scripts/set-version.sh` stamps.
///
/// # The defect this generalises from
///
/// `wiremesh-enroll` builds the `EnrollRequest` for BOTH the gateway and the
/// relay. `env!` expands at its DEFINITION site, so an `env!("CARGO_PKG_VERSION")`
/// there would stamp every gateway and every relay with `wiremesh-enroll`'s
/// own version — a crate the script does not stamp, so it would ship as a
/// permanent `"0.1.0"`. That is worse than reporting nothing: being non-empty
/// it stores as a real value instead of the honest NULL, in the one field
/// whose entire purpose is detecting version skew. B10's fix makes
/// `client_version` a caller-supplied parameter; this asserts the macro has
/// not crept back in beside it.
///
/// # Why the CLASS and not the instance
///
/// Stated narrowly ("`wiremesh-enroll/src` contains no `CARGO_PKG_VERSION`")
/// it would pass while the identical defect appeared in the next shared crate.
/// The invariant is **readers ⊆ stamped**, and it is ONE-DIRECTIONAL on
/// purpose: `fabricctl` is stamped and contains no literal read (clap's
/// `#[command(version)]` reads the macro implicitly), so an equality would red
/// on a correct tree.
///
/// The stamped set is obtained by RUNNING the script, never by parsing its
/// `for crate in …` line — see this file's header for the three reasons.
///
/// # Comments COUNT, and that is deliberate
///
/// This scans raw text — a mention inside a `//` comment is a read as far as
/// this guard is concerned. That sounds too strict and is exactly right,
/// because the strictness lands only where it should:
///
///   * in a STAMPED crate a comment is harmless and tolerated —
///     `wiremesh-relay/src/enroll.rs`'s `ENROLL_BIN` doc comment names the
///     macro while reasoning about this very hazard, and its crate is stamped,
///     so it never trips;
///   * in an UNSTAMPED crate any mention at all reds — which is the property
///     wanted for `wiremesh-enroll`, a crate that ships no `[[bin]]`, can
///     never be stamped, and must not so much as name the macro it is
///     forbidden to use.
///
/// The case that settled it: `wiremesh-enroll/src/lib.rs` briefly carried a
/// doc comment asserting *"the string `CARGO_PKG_VERSION` appears nowhere
/// under `crates/wiremesh-enroll/src/`"* — a sentence that falsified itself by
/// containing the key. A comment-aware guard would have let that stand; this
/// one forces the comment to describe the macro without spelling it.
#[test]
fn every_crate_that_reads_its_own_version_is_stamped() {
    let run = run_set_version();
    let root = std::path::Path::new(REPO_ROOT);

    let mut readers: BTreeSet<String> = BTreeSet::new();
    let mut stack = vec![root.join("crates")];
    while let Some(d) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                // `tests/` is out of scope: a test naming the macro is not a
                // binary reporting a version.
                if p.file_name().is_some_and(|n| n == "tests" || n == "target") {
                    continue;
                }
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let text = std::fs::read_to_string(&p).expect("reading a source file");
                // Raw text, comments included — see the doc comment above.
                let reads = text.contains("CARGO_PKG_VERSION");
                if reads {
                    let rel = p
                        .strip_prefix(root.join("crates"))
                        .expect("scanned file is under crates/");
                    if let Some(krate) = rel.components().next() {
                        readers.insert(krate.as_os_str().to_string_lossy().to_string());
                    }
                }
            }
        }
    }

    let unstamped: Vec<&String> = readers.iter().filter(|c| !run.stamped.contains(*c)).collect();
    assert!(
        unstamped.is_empty(),
        "these crates read their own `CARGO_PKG_VERSION` but are NOT stamped by \
         scripts/set-version.sh: {unstamped:?}. Such a crate reports a version it can never \
         receive — it ships the `0.1.0` placeholder forever, and any value derived from it \
         (an enrolled client's `client_version`, a `--version` line) is a confident wrong \
         answer. Either add the crate to the script, or — if it ships nothing, as \
         `wiremesh-enroll` does with no `[[bin]]` at all — have its CALLER pass the value in \
         as a parameter. Stamped set (obtained by RUNNING the script): {:?}",
        run.stamped
    );
}

