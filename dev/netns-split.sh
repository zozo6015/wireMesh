#!/usr/bin/env bash
# dev/netns-split.sh — the single source of truth for how the gateway's
# netns-gated integration tests are split across CI jobs.
#
# WHY THIS EXISTS. Two of `.github/workflows/ci.yml`'s jobs run subsets of
# `crates/wiremesh-gateway/tests/`, and both subsets are load-bearing:
#
#   * `throughput_bench` is EXCLUDED entirely. It shells out to `iperf3` and
#     records Mbit/s; it asserts nothing (its own header says the G-2 floor
#     needs a real 4-vCPU VM — see `crates/wiremesh-gateway/bench.md`), so in
#     CI it is pure cost.
#   * the rotation suites run ALONE on their own runner. That set is
#     `key_rotation.rs`, `rotation_slot_quarantine_netns.rs` and B2's
#     `rotation_wedge.rs` -- the last uses key_rotation's EXACT topology (two
#     real gateway processes, one controller, bridge + four netns), so it
#     carries the same contention profile and belongs beside it. NOTE the
#     catch-all below would have put it in the gateway bucket silently: a new
#     gated file lands somewhere safe, but not necessarily somewhere RIGHT.
#     `key_rotation.rs`'s
#     `direct_rotation_is_zero_drop` fails ~42% under host load
#     (`docs/research/flake-direct-rotation-zero-drop.md`: gap 2 in isolation,
#     gap 3 of an allowed 3 inside the full suite). Container load is the
#     variable, so isolation is the fix — NOT a widened tolerance, NOT a
#     retry.
#
# Spelling those subsets inline in YAML would mean a newly added gated test
# file silently runs in NO job, which looks identical to passing. So the lists
# live here and `check` fails loudly if a gated file is in neither.
#
# Gating is detected by a `#![cfg(feature = "netns-tests")]` INNER ATTRIBUTE AT
# COLUMN 0 — never by a plain substring match. `tests/punch_endpoint_driven.rs`
# names the attribute inside a `//!` doc comment while being a plain unit test
# with zero `Command::new` and zero sockets; a substring grep counts it as
# gated and is wrong. That miscount is already recorded in the shipped docs.
set -euo pipefail

cd "$(dirname "$0")/.."
TESTS_DIR="crates/wiremesh-gateway/tests"

# Rotation done-bars: their own runner (see above).
ROTATION=(key_rotation rotation_slot_quarantine_netns rotation_wedge)
# Excluded from CI entirely: measures, asserts nothing.
EXCLUDED=(throughput_bench)

gated() {
  grep -l '^#!\[cfg(feature = "netns-tests")\]' "$TESTS_DIR"/*.rs \
    | xargs -n1 basename | sed 's/\.rs$//' | sort
}

in_list() { local n="$1"; shift; local e; for e in "$@"; do [ "$e" = "$n" ] && return 0; done; return 1; }

case "${1:-}" in
  rotation)
    for t in "${ROTATION[@]}"; do printf -- '--test %s ' "$t"; done; echo
    ;;
  gateway)
    while read -r t; do
      in_list "$t" "${ROTATION[@]}" && continue
      in_list "$t" "${EXCLUDED[@]}" && continue
      printf -- '--test %s ' "$t"
    done < <(gated); echo
    ;;
  check)
    # Every name in ROTATION/EXCLUDED must still exist and still be gated — a
    # rename would otherwise silently drop that file out of CI, which looks
    # exactly like it passing. The `gateway` bucket is the catch-all, so a
    # NEWLY added gated file cannot go unrun; this guards the other direction.
    fail=0
    all=()
    while read -r t; do all+=("$t"); done < <(gated)
    for t in "${ROTATION[@]}" "${EXCLUDED[@]}"; do
      in_list "$t" "${all[@]}" || {
        echo "netns-split: '$t' is named in this script but is not a gated test file in $TESTS_DIR — renamed, or its #![cfg(feature = \"netns-tests\")] was removed?" >&2
        fail=1
      }
    done
    # SECOND GUARD (added after `rotation_wedge.rs` landed in the gateway
    # bucket silently). The catch-all guarantees a new gated file runs
    # SOMEWHERE; it does not guarantee it runs in the RIGHT job. The criterion
    # that matters is "is this a rotation done-bar", because those are the
    # suites `direct_rotation_is_zero_drop`'s ~42%-under-load flake lives in
    # and the reason `netns-rotation` gets a runner to itself.
    #
    # This checks a PROXY for that criterion -- the file name mentioning
    # `rotation` -- because the real property (topology: two real gateway
    # processes plus a controller) does not discriminate: `mesh_milestone.rs`
    # has the same shape and belongs in the gateway job. So it is NECESSARY,
    # NOT SUFFICIENT: it catches the case that actually happened (a rotation
    # PR adding a `rotation_*` done-bar), and it CANNOT catch a rotation
    # done-bar under some other name. If you add one, add it to ROTATION by
    # hand -- this guard will not remind you.
    for t in "${all[@]}"; do
      case "$t" in
        *rotation*)
          in_list "$t" "${ROTATION[@]}" || {
            echo "netns-split: '$t' looks like a rotation done-bar but is not in ROTATION." >&2
            echo "netns-split: rotation suites run alone on their own runner (design 6.3);" >&2
            echo "netns-split: the catch-all would put it in the CONTENDED gateway job." >&2
            fail=1
          } ;;
      esac
    done

    printf 'netns-split: %d gated test files\n' "${#all[@]}"
    printf '  rotation : %s\n' "${ROTATION[*]}"
    printf '  excluded : %s\n' "${EXCLUDED[*]}"
    printf '  gateway  : %s\n' "$("$0" gateway)"
    [ "$fail" -eq 0 ]
    ;;
  *)
    echo "usage: dev/netns-split.sh {gateway|rotation|check}" >&2; exit 1 ;;
esac
