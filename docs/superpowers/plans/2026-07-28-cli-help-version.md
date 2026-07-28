# CLI --help / --version across all components — plan

**Motivation:** live-deployment diagnostics gap — `wiremesh-gateway --help` /
`--version` produce nothing; an operator can't discover flags or confirm the
running version without the source. Every shipped binary must answer
`-h`/`--help` (a full usage manual) and `-V`/`--version` (the crate version).

**Owner decision (2026-07-28):** lightweight — KEEP the hand-rolled parsers
(do NOT migrate to clap); FULL manual depth (every flag, required/optional,
defaults, the env-file mechanism, a usage example). Ships per release-every-fix.

**Branch:** `feat/cli-help-version`.

## Scope — per binary

Hand-rolled (add handling): `wiremesh-gateway`, `wiremesh-controller`,
`wiremesh-operator`, `wiremesh-enroll` (bins: `wiremesh-gateway enroll` shares
this crate? verify — enroll is a subcommand of the gateway/relay bins + the
`wiremesh-relay-enroll` bin). clap (VERIFY only, fix if missing):
`fabricctl`, `wiremesh-relay`.

Requirements for each hand-rolled binary:
- `-V` / `--version` → prints `<binname> <CARGO_PKG_VERSION>` to stdout, exit 0.
- `-h` / `--help` → prints a full usage manual to stdout, exit 0:
  - one-line synopsis (`Usage: <bin> [SUBCOMMAND] [FLAGS]`),
  - a short description of the component,
  - EVERY flag: name, value placeholder, required/optional, default, one-line
    description (source the descriptions from the existing config.rs doc
    comments — they're already rich),
  - subcommands where they exist (gateway `enroll`; operator `idle` /
    `operator-admin <op>`),
  - the env-file / `GATEWAY_ARGS` / `RELAY_ARGS` deployment mechanism note,
  - at least one concrete usage example.
- `--help`/`--version` must be recognized BEFORE required-flag validation, at
  the very top of arg handling, so they work with no other args and never
  error. Must also work as the first token and (reasonably) anywhere.
- Exit code 0 for help/version (not the error path).
- Version constant: `env!("CARGO_PKG_VERSION")` (compile-time, per-crate).

clap binaries (`fabricctl`, `wiremesh-relay`): confirm `#[command(version)]`
(or `version = ...`) is set so `--version` prints the crate version, and
`--help` renders. If `version` is absent (clap does NOT emit `--version`
without it), add it. Add a top-level `about`/`long_about` if thin.

## Constraints

- Do NOT change any existing flag semantics or the normal run/enroll paths —
  the netns tests spawn the gateway with exact args and must stay green.
- Match the hand-rolled style; no new deps (clap not added to the hand-rolled
  crates). Rich doc comments citing this as a diagnostics feature.
- The gateway subcommand dispatch (`enroll` vs run) must still route correctly;
  `--help`/`--version` intercept before that dispatch.

## Test surface (author writes; separate agent)

Per binary, an integration test that runs the actual built binary (or the
arg-parse entry as a unit where a full spawn is heavy) and asserts:
- `--version` and `-V` stdout contains the crate version (`env!("CARGO_PKG_VERSION")`).
- `--help` and `-h` stdout is non-empty, exit 0, and contains the binary's key
  flag names (e.g. gateway: `--controller-sync`, `--observe`, `--tun`,
  `--wg-port`, `--state-dir`; enroll subcommand mentioned).
- required-flag validation is NOT triggered by `--help`/`--version` (no error).
- (clap bins) `--version` contains the crate version.
Where the crate exposes a pure `parse`/help-render fn, prefer asserting on that
(as the hostname cycle did) to avoid spawning; otherwise a spawned-binary test.

## Execution

Single wave (small, mechanical, low risk): test-author → implementer →
dedicated runner (full workspace build + the gateway netns mesh_milestone as a
non-regression guard, since the gateway main changed) → reviewer → CodeRabbit
→ PR → release.
