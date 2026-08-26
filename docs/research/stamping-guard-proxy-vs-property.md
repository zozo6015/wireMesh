# The stamping guard flagged a job that builds nothing — a substring proxy for a property

**Found:** 2026-08-26, on PR3's `cold-build.yml`.
**Status:** guard defect (test-side), no product change. Fixed on
`test/stamping-guard-build-verb`.
**Subject:** `crates/wiremesh-operator/tests/release_version_stamping.rs`,
`every_job_that_compiles_a_shipped_binary_stamps_the_version_first` and its classifier
`build_reason()`.

## What fired

`every_job_that_compiles_a_shipped_binary_stamps_the_version_first` requires that any
job compiling a shipped binary runs `scripts/set-version.sh` at an earlier step index.
On PR3 it flagged `cold-build.yml`'s `toolchain-parity` job as such a build.

`toolchain-parity` compiles nothing. Its parity step (PR3 later added a second,
stamping step — see "The predicted repair already happened" below):

- `grep`s the first `FROM` line out of `dev/Dockerfile`;
- `grep`s the first `FROM … AS builder` line out of `deploy/docker/Dockerfile`;
- `docker run`s each of those **already-built** base images to print `rustc --version`;
- compares the two strings and fails if they differ.

No `docker build`, no `docker buildx build`, no `cargo build`, no
`build-push-action`. It produces no artifact at all, so there is nothing for a version
stamp to be stamped into.

## Why

The classifier's `run:` arm was:

```rust
if run.contains(DOCKERFILE) && run.contains("build") {
    return Some(format!("runs a docker build of {DOCKERFILE}"));
}
```

`toolchain-parity`'s run block satisfies both halves. `DOCKERFILE`
(`deploy/docker/Dockerfile`) appears because the job greps it. And `"build"` appears
**three times, none of them a build**:

| # | Occurrence | What it actually is |
|---|---|---|
| 1 | `grep -m1 '^FROM .* AS builder' deploy/docker/Dockerfile` | the word `builder` inside a grep PATTERN — it matches a Dockerfile STAGE NAME |
| 2 | `…dev/Dockerfile's FROM tag and the release builder digest.` | prose inside an `::error::` message |
| 3 | `…resolve at each image's last COLD build --` | prose inside a comment |

So the predicate did not detect a build. It detected **a file path and an English
word**, and both were present for reasons that have nothing to do with building.

## The general rule

**A substring proxy for a property fires on prose about the property.** That is not an
edge case; it is the normal outcome, and it gets more likely the better the file is
commented. `build` is a common English word, `deploy/docker/Dockerfile` is a path any
job that *inspects* the release image must name, and this repo's workflows carry long
explanatory comments by house style — so the proxy was most likely to misfire precisely
where the documentation is best.

The failure mode is worse than a plain false positive, because of what a green guard
invites next. The demand it makes — "this job must run `set-version.sh` first" — is
satisfiable. Someone under time pressure can add a stamp step to a job that compiles
nothing, and the guard goes green having caused a meaningless step to exist, while the
underlying classifier is still wrong for the next job that greps a Dockerfile.

This is the same class as two findings already recorded on this project: an `#[expect]`
that never fired, and a guard that scanned test code instead of production code. In all
three, a check's *stated* premise ("this job builds a shipped binary") and its *actual*
premise ("this text contains a path and a word") differ, and nothing notices until the
conditions change.

## The fix

Require an actual build **verb** in the `run:` arm, never the bare token:

```rust
const DOCKER_BUILD_VERBS: [&str; 2] = ["docker buildx build", "docker build"];

if run.contains("cargo build") { … }                       // unchanged
if run.contains(DOCKERFILE) {
    if let Some(verb) = DOCKER_BUILD_VERBS.iter().find(|v| run.contains(**v)) {
        return Some(format!("runs `{verb}` of {DOCKERFILE}"));
    }
}
```

**Correction (reviewer, 2026-08-26).** An earlier revision of this note claimed
`docker build` "is not a substring of `docker buildx build`" and that a list without the
buildx entry would have created a false negative on `release.yml`'s `linux-binaries`
job. **That is wrong.** `docker buildx build`[0..12] *is* `docker build`, so
`"docker build"` alone matches both spellings and coverage was never at risk. The claim
was asserted from reading rather than from running a two-line check — the same failure
mode this whole note is about, made while writing it.

What the buildx entry actually buys is the **message**. `.iter().find` returns the first
matching verb, so listing the longer form first makes the reported reason read
``runs `docker buildx build` of deploy/docker/Dockerfile`` rather than the vaguer
``runs `docker build` of …``. That is worth having — the reason string is what a release
engineer reads in a failure, under time pressure, and it should name the command that is
actually there — but it is a legibility win, not a coverage one.

The `uses:` arm is untouched: it already required
`docker/build-push-action` **and** `with.file == deploy/docker/Dockerfile`, which is a
structural test rather than a substring one, and it never misfired.

### What still classifies as a build (nothing lost)

| Workflow | Job | Matched by |
|---|---|---|
| `release.yml` | `linux-binaries` | `docker buildx build` + the Dockerfile |
| `release.yml` | macOS job | `cargo build` |
| `release.yml` | Windows job | `cargo build` |
| `container-images.yml` | `builder` | `build-push-action` + `with.file` |
| `container-images.yml` | `images` | `build-push-action` + `with.file` |

The existing anti-vacuity assertion (`builds_seen >= 3`) is unchanged and still
satisfied with margin.

## The tests

**`a_run_block_that_only_mentions_the_dockerfile_in_a_grep_is_not_a_build`** — the
negative case, built from PR3's actual `toolchain-parity` parity step (text unchanged; only
the YAML indentation is re-rooted so the fixture is a standalone step mapping,
including all three `build` occurrences). Asserts `build_reason(&step) == None`.

**RED before the classifier change, by construction.** Under the old predicate,
`run.contains(DOCKERFILE)` is true (the grep names it) and `run.contains("build")` is
true (three times), so `build_reason` returns `Some(..)` and the `== None` assertion
fails. This is not a hypothetical: it is the exact input that produced the real
misclassification on PR3.

**`a_run_block_that_really_buildx_builds_the_dockerfile_is_still_a_build`** — the twin
that keeps the negative honest. A `build_reason()` that returned `None` for everything
would satisfy the negative case perfectly *and disarm the entire guard*. This one feeds
it `release.yml`'s real `linux-binaries` step and requires both a `Some` and that the
reason names `docker buildx build`. Green before and after; its job is to fail if the
tightening ever goes one notch too far.

Together they bracket the predicate from both sides, which a single test cannot do:
one fails if it is too loose, the other if it is too tight.

## Residual blind spot — and it already has a live near-miss

The verb check is still a substring test, just a far narrower one. A `run:` block whose
own text contains the literal `docker build` or `cargo build` in a shell comment or an
`echo` would still be misclassified.

**This is not hypothetical.** PR3's `cold-build.yml` contains, at the `toolchain-parity`
job, a comment reading *"there is no `cargo build`, no `docker build` and no
build-push-action anywhere in it"* — both literals, in a passage whose entire purpose is
to say the job does not build. It is safe today by a mechanism nobody chose: those are
**YAML** comments, and `serde_yaml` strips them before `step["run"]` is ever read. Move
the same sentence three lines down into a `run: |` block, as a `#` shell comment or an
`echo`, and it fires.

The `cargo build` arm is the sharper edge of this. Unlike the Dockerfile arm it has **no
second condition at all** — no path guard, nothing — so the bare literal `cargo build`
anywhere in any `run:` block classifies that step as a build. A step that echoes
`"run cargo build locally to reproduce"` in a failure hint is enough.

Closing this properly means parsing the shell rather than the YAML, which is a different
order of complexity than this guard warrants. Recorded so the next person who hits it
recognises the shape instead of rediscovering it.

## The predicted repair already happened

This note argues above that the real damage of a satisfiable false demand is that
someone satisfies it. PR3 did: `toolchain-parity` carries a step

```yaml
- name: stamp a non-colliding version (see note above)
  run: bash scripts/set-version.sh "0.0.0-parity-$(git rev-parse --short HEAD)"
```

added purely to placate this guard, under sixteen lines of comment that state plainly
*"THIS JOB COMPILES NOTHING"* and *"The precision fix belongs to the guard, not here."*
That was the right call at the time — the guard was wrong and the workaround was honest
and documented, which is far better than an exception list. But it is exactly the
outcome predicted: a version stamped into a job with no artifact to stamp it into.

With the classifier tightened, that step and its apologia are **no longer required**.
Removing them is `cold-build.yml`'s call, not this branch's; noted so the option is not
lost.

## Filed follow-up: the `cold` job is excluded by accident, not by intent

`cold-build.yml`'s `cold` job DOES build `deploy/docker/Dockerfile` via
`docker/build-push-action`, and the `uses:` arm does not classify it — its
`with.file` is `${{ matrix.file }}`, an unresolved expression, and the arm tests exact
equality against the literal path.

The fix is **not** "resolve the expression". That job is `push: false`, `load: false`
and ships nothing — it exists to prove the Dockerfiles still build from scratch — so
teaching the classifier to see through the matrix would re-create precisely the
over-firing this branch removes, this time demanding a stamp from a cold *build*. The
follow-up is to make the exclusion **intentional**: exempt steps that publish nothing
(`push: false`), or classify on whether the step produces a shipped artifact rather than
on whether it compiles. Until then it is excluded for the wrong reason, and a matrix
that grew a pushing entry would still be missed.

## Verification

Per the project's agent workflow rules the runs belong to the qa agent, not the test
author: `./dev.sh run 'cargo test -p wiremesh-operator --test release_version_stamping'` (from the repo root — all cargo runs go through the dev container). To see the
RED directly, revert only the `build_reason()` hunk and run the negative test alone —
it fails with `Some("runs a docker build of deploy/docker/Dockerfile")` against `None`.
